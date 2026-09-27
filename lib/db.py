#!/usr/bin/env python3
"""SQLite state store for AutoBounty."""
import json, os, sqlite3, threading, time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS programs(
  name TEXT PRIMARY KEY, platform TEXT, policy TEXT,
  scope TEXT NOT NULL, exclusions TEXT NOT NULL, rps INTEGER DEFAULT 10,
  last_recon_at INTEGER, last_scan_at INTEGER, enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS hosts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL, host TEXT NOT NULL, source TEXT,
  status INTEGER, title TEXT, tech TEXT, ip TEXT, cdn INTEGER,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  scanned_at INTEGER, in_scope INTEGER DEFAULT 1,
  url TEXT,                    -- exact live endpoint httpx found (scheme+port)
  UNIQUE(program, host)
);
CREATE INDEX IF NOT EXISTS idx_hosts_program ON hosts(program);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL, host TEXT NOT NULL,
  template_id TEXT NOT NULL, template_name TEXT, severity TEXT NOT NULL,
  description TEXT, raw TEXT, type TEXT,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  seen_count INTEGER DEFAULT 1,
  status TEXT DEFAULT 'new',      -- new | triaged | reported | duplicate | noise
  report_path TEXT, alert_sent INTEGER DEFAULT 0,
  UNIQUE(program, host, template_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE TABLE IF NOT EXISTS revenue(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  amount_usd REAL NOT NULL,
  source TEXT,
  note TEXT,
  ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phase TEXT, started_at INTEGER, ended_at INTEGER, status TEXT, detail TEXT
);
"""


class DB:
    _lock = threading.Lock()

    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")       # concurrent readers + 1 writer
        self.conn.execute("PRAGMA busy_timeout=30000")     # wait instead of 'database is locked'
        self.conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self.conn.executescript(_SCHEMA)
            self._migrate()
            self.conn.commit()

    def _migrate(self):
        """Lightweight additive migrations for the live DB."""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(hosts)")}
        if "url" not in cols:
            self.conn.execute("ALTER TABLE hosts ADD COLUMN url TEXT")

    def log_run(self, phase, status, detail="", started_at=None):
        now = int(time.time())
        with self._lock:
            self.conn.execute(
                "INSERT INTO runs(phase,started_at,ended_at,status,detail) VALUES(?,?,?,?,?)",
                (phase, started_at or now, now, status, detail[:500]))
            self.conn.commit()

    # ---- programs -------------------------------------------------------
    def upsert_program(self, p):
        with self._lock:
            self.conn.execute(
                "INSERT INTO programs(name,platform,policy,scope,exclusions,rps,enabled) "
                "VALUES(?,?,?,?,?,?,1) ON CONFLICT(name) DO UPDATE SET "
                "platform=excluded.platform,policy=excluded.policy,scope=excluded.scope,"
                "exclusions=excluded.exclusions,rps=excluded.rps",
                (p["name"], p["platform"], p["policy"],
                 json.dumps(p["scope"]), json.dumps(p.get("exclusions", [])), p.get("rps", 10)))
            self.conn.commit()

    def programs(self, enabled_only=True):
        q = "SELECT * FROM programs"
        if enabled_only:
            q += " WHERE enabled=1"
        return [dict(r) for r in self.conn.execute(q)]

    def touch_program(self, name, field):
        with self._lock:
            self.conn.execute(f"UPDATE programs SET {field}=? WHERE name=?",
                              (int(time.time()), name))
            self.conn.commit()

    # ---- hosts ----------------------------------------------------------
    def upsert_host(self, program, host, source, in_scope=True):
        now = int(time.time())
        with self._lock:
            self.conn.execute(
                "INSERT INTO hosts(program,host,source,first_seen,last_seen,in_scope) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(program,host) DO UPDATE SET "
                "last_seen=excluded.last_seen, source=excluded.source",
                (program, host, source, now, now, 1 if in_scope else 0))
            self.conn.commit()

    def unscanned_hosts(self, program, limit=None):
        q = ("SELECT * FROM hosts WHERE program=? AND in_scope=1 "
             "AND scanned_at IS NULL ORDER BY last_seen DESC")
        if limit:
            q += f" LIMIT {int(limit)}"
        return [dict(r) for r in self.conn.execute(q, (program,))]

    def live_hosts(self, program=None):
        q = "SELECT * FROM hosts WHERE in_scope=1 AND status IS NOT NULL AND status < 500"
        if program:
            q += " AND program=?"
            return [dict(r) for r in self.conn.execute(q, (program,))]
        return [dict(r) for r in self.conn.execute(q)]

    def all_hosts(self, program):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM hosts WHERE program=? AND in_scope=1", (program,))]

    def mark_hosts_scanned(self, program, hosts):
        now = int(time.time())
        with self._lock:
            self.conn.executemany(
                "UPDATE hosts SET scanned_at=? WHERE program=? AND host=?",
                [(now, program, h) for h in hosts])
            self.conn.commit()

    def set_host_meta(self, program, host, status, title, tech, ip, cdn, url=None):
        with self._lock:
            self.conn.execute(
                "UPDATE hosts SET status=?,title=?,tech=?,ip=?,cdn=?,url=? "
                "WHERE program=? AND host=?",
                (status, title, tech, ip, 1 if cdn else 0, url, program, host))
            self.conn.commit()

    # ---- findings -------------------------------------------------------
    def upsert_finding(self, program, host, template_id, template_name,
                       severity, description, raw, type_):
        now = int(time.time())
        with self._lock:
            cur = self.conn.execute(
                "SELECT id,status,first_seen,seen_count FROM findings "
                "WHERE program=? AND host=? AND template_id=?",
                (program, host, template_id))
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE findings SET last_seen=?, seen_count=seen_count+1, raw=? WHERE id=?",
                    (now, raw, row["id"]))
                self.conn.commit()
                return row["id"], False
            cur = self.conn.execute(
                "INSERT INTO findings(program,host,template_id,template_name,severity,"
                "description,raw,type,first_seen,last_seen,status) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,'new')",
                (program, host, template_id, template_name, severity,
                 description, raw, type_, now, now))
            self.conn.commit()
            return cur.lastrowid, True

    def finding(self, fid):
        return dict(self.conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())

    def findings_by_status(self, status):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM findings WHERE status=? ORDER BY first_seen DESC", (status,))]

    def set_finding_status(self, fid, status, report_path=None, alert=False):
        with self._lock:
            self.conn.execute(
                "UPDATE findings SET status=?, report_path=COALESCE(?,report_path), "
                "alert_sent=? WHERE id=?",
                (status, report_path, 1 if alert else None, fid))
            self.conn.commit()

    # ---- revenue --------------------------------------------------------
    def log_revenue(self, amount_usd, source="", note=""):
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO revenue(amount_usd,source,note,ts) VALUES(?,?,?,?)",
                (float(amount_usd), source, note, int(time.time())))
            self.conn.commit()
            return cur.lastrowid

    def revenue_total(self):
        row = self.conn.execute(
                "SELECT COALESCE(SUM(amount_usd),0) t, COUNT(*) c FROM revenue").fetchone()
        return row["t"], row["c"]

    def revenue_recent(self, limit=5):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM revenue ORDER BY ts DESC LIMIT ?", (limit,))]

    # ------------------------------------------------- state exchange
    # The runners (GitHub Actions / HF Space / Termux) share progress through a
    # compact JSON file committed to the repo. The 200k+ host candidate table is
    # regenerable; findings and per-host scan progress are not.

    def export_state(self, path):
        live = [dict(r) for r in self.conn.execute(
            "SELECT program,host,url,status,title,tech,first_seen,last_seen,"
            "scanned_at,in_scope FROM hosts WHERE status IS NOT NULL AND status < 500")]
        findings = [dict(r) for r in self.conn.execute("SELECT * FROM findings")]
        progs = {r["name"]: {"last_recon_at": r["last_recon_at"],
                            "last_scan_at": r["last_scan_at"],
                            "enabled": r["enabled"]}
                 for r in self.conn.execute("SELECT * FROM programs")}
        revenue = [dict(r) for r in self.conn.execute("SELECT * FROM revenue")]
        self.conn.execute("CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT)")
        kv = {r["key"]: r["value"] for r in self.conn.execute("SELECT * FROM kv")}
        import json as _json
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w") as f:
            _json.dump({"live_hosts": live, "findings": findings,
                        "programs": progs, "revenue": revenue, "kv": kv,
                        "exported_at": int(time.time())}, f, default=str)
        return len(live), len(findings)

    def import_state(self, path):
        import json as _json
        if not os.path.exists(path):
            return 0, 0
        with open(path) as f:
            s = _json.load(f)
        for p in s.get("programs", {}).items():
            name, meta = p
            self.conn.execute(
                "UPDATE programs SET last_recon_at=?, last_scan_at=?, enabled=? "
                "WHERE name=?",
                (meta.get("last_recon_at"), meta.get("last_scan_at"),
                 int(meta.get("enabled", 1)), name))
        for h in s.get("live_hosts", []):
            self.conn.execute(
                "INSERT OR IGNORE INTO hosts(program,host,source,first_seen,last_seen,"
                "in_scope,status,title,tech,scanned_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (h["program"], h["host"], "state-import",
                 int(h["first_seen"]), int(h["last_seen"]), 1,
                 h.get("status"), h.get("title"), h.get("tech"),
                 int(h["scanned_at"]) if h.get("scanned_at") else None))
        for f_ in s.get("findings", []):
            self.conn.execute(
                "INSERT OR IGNORE INTO findings(program,host,template_id,template_name,"
                "severity,description,raw,type,first_seen,last_seen,seen_count,status,"
                "report_path,alert_sent) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f_["program"], f_["host"], f_["template_id"], f_.get("template_name"),
                 f_["severity"], f_.get("description"), f_.get("raw"), f_.get("type"),
                 int(f_["first_seen"]), int(f_["last_seen"]), int(f_.get("seen_count") or 1),
                 f_.get("status") or "new", f_.get("report_path"),
                 int(f_.get("alert_sent") or 0)))
        for r in s.get("revenue", []):
            self.conn.execute(
                "INSERT OR IGNORE INTO revenue(amount_usd,source,note,ts) VALUES(?,?,?,?)",
                (float(r["amount_usd"]), r.get("source"), r.get("note"), int(r["ts"])))
        self.conn.execute("CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT)")
        for k, v in (s.get("kv") or {}).items():
            self.conn.execute(
                "INSERT OR IGNORE INTO kv(key,value) VALUES(?,?)", (k, str(v)))
        self.conn.commit()
        return len(s.get("live_hosts", [])), len(s.get("findings", []))

    def stats(self):
        out = {}
        for row in self.conn.execute(
                "SELECT severity, COUNT(*) c FROM findings WHERE status NOT IN ('noise') "
                "GROUP BY severity"):
            out[row["severity"]] = row["c"]
        out["hosts"] = self.conn.execute(
            "SELECT COUNT(*) c FROM hosts WHERE in_scope=1").fetchone()["c"]
        out["programs"] = self.conn.execute(
            "SELECT COUNT(*) c FROM programs WHERE enabled=1").fetchone()["c"]
        return out
