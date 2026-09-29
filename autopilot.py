#!/usr/bin/env python3
"""
AutoBounty — autonomous authorized bug-bounty pipeline.
Loop: recon -> scan -> triage -> report -> notify, forever, self-healing.

Owner control via Telegram (the bot token already on this box):
  /status   current state      /stats   finding counts
  /findings latest findings    /pause   pause the work loop
  /resume   resume             /scan    force a scan cycle now
"""
import json, os, sys, time, threading, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from db import DB
import scope as scopelib
import recon, scan, triage, report, notify

BASE = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(BASE, "config.yaml")

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_lock = threading.Lock()


class AutoBounty:
    def __init__(self):
        self.cfg = scopelib.load_config(CFG_PATH)
        self.db = DB(self.cfg["runner"]["state_db"])
        import jobs
        jobs.ensure(self.db)
        scopelib.load_programs(self.cfg, self.db)   # seed programs from config.yaml
        self.paused = threading.Event()
        self.force_scan = threading.Event()
        self.cycle = 0

    # -------------------------------------------------------------- control
    def owner_chat(self):
        c = os.environ.get("TELEGRAM_CHAT_ID")
        if c:
            return c
        try:
            r = self.db.conn.execute(
                "SELECT value FROM kv WHERE key='owner_chat'").fetchone()
        except Exception:
            r = None
        return r["value"] if r else None

    def set_owner_chat(self, cid):
        self.db.conn.execute(
            "CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT)")
        self.db.conn.execute(
            "INSERT INTO kv(key,value) VALUES('owner_chat',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (cid,))
        self.db.conn.commit()

    def bot_thread(self):
        """Long-poll Telegram for owner commands."""
        import requests, time as _t
        token = (os.environ.get("AUTOBOUNTY_BOT_TOKEN")
                 or os.environ.get("TELEGRAM_BOT_TOKEN"))
        if not token:
            return
        # ensure kv exists up-front so owner_chat() can never crash
        try:
            self.db.conn.execute(
                "CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT)")
            self.db.conn.commit()
        except Exception:
            pass
        base = f"https://api.telegram.org/bot{token}"
        offset = 0
        hb = os.path.join(self.cfg["runner"].get("state_dir", "data"),
                          "bot_heartbeat.txt")
        while True:
            try:
                with open(hb, "w") as f:   # liveness heartbeat for ops
                    f.write(str(int(time.time())))
                r = requests.get(f"{base}/getUpdates",
                                 params={"offset": offset, "timeout": 25},
                                 timeout=35)
                if r.status_code != 200:
                    _t.sleep(10)
                    continue
                for upd in r.json().get("result", []):
                    msg = upd.get("message") or upd.get("edited_message")
                    if not msg or msg.get("from", {}).get("is_bot"):
                        offset = upd["update_id"] + 1   # discard non-message
                        continue
                    cid = str(msg["chat"]["id"])
                    try:
                        cur = self.owner_chat()
                        if cur is None:
                            # ANY first message bootstraps the owner (Telegram bots
                            # cannot initiate conversations, so this is the only way
                            # to learn where to send reports).
                            self.set_owner_chat(cid)
                            notify.send(
                                "✅ *AutoBounty* reporting channel established.\n"
                                "You are now the owner. Commands: /status /stats "
                                "/findings /revenue /pause /resume /scan", cid)
                        elif cur == cid:
                            self.handle_command(
                                msg.get("text", "").strip().split(), cid)
                        # else: someone else's message -> ignore (no bootstrap)
                    except Exception:
                        pass
                    # advance offset only AFTER processing, so a transient
                    # failure retries the update instead of swallowing it
                    offset = upd["update_id"] + 1
            except Exception:
                _t.sleep(10)

    def handle_command(self, argv, cid):
        cmd = (argv[0] if argv else "/help").lstrip("/!").lower()
        if cmd == "status":
            st = "PAUSED" if self.paused.is_set() else "RUNNING"
            import jobs
            jstat = jobs.stats(self.db)
            s = self.db.stats()
            notify.send(
                f"🤖 *AutoBounty* — {st}\nCycle: {self.cycle}  Cycle hosts: {s.get('hosts',0)}\n"
                f"Findings: " + "  ".join(f"{k.upper()}:{v}" for k, v in s.items()
                                             if k not in ("hosts", "programs")) + "\n"
                f"Jobs: " + "  ".join(f"{k}:{v}" for k, v in jstat.items()), cid)
        elif cmd == "stats":
            s = self.db.stats()
            notify.send("📊 ```" + json.dumps(s, indent=1) + "```", cid)
        elif cmd == "findings":
            rows = self.db.conn.execute(
                "SELECT * FROM findings WHERE status NOT IN ('noise') "
                "ORDER BY first_seen DESC LIMIT 10").fetchall()
            if not rows:
                notify.send("No findings yet.", cid)
            else:
                txt = []
                for r in rows:
                    e = {"critical": "🔴", "high": "🟠",
                         "medium": "🟡", "low": "🔵"}.get(r["severity"], "⚪")
                    txt.append(f"{e} {r['severity'].upper()} {r['host']} — "
                               f"{r['template_name'] or r['template_id']}")
                notify.send("Latest findings:\n" + "\n".join(txt), cid)
        elif cmd == "revenue":
            # /revenue            -> show ledger
            # /revenue 250 Tesla  -> log a collected $250 payout
            if len(argv) >= 2:
                try:
                    amt = float(argv[1])
                    note = " ".join(argv[2:])
                    self.db.log_revenue(amt, "telegram", note)
                    notify.send(f"💰 Logged ${amt:.2f} collected"
                                + (f" ({note})" if note else ""), cid)
                    return
                except ValueError:
                    pass
            total, cnt = self.db.revenue_total()
            recent = self.db.revenue_recent(3)
            msg = [f"💰 *Revenue collected:* ${total:,.2f} across {cnt} payouts"]
            for r in recent:
                msg.append(f"  • ${r['amount_usd']:.2f} — {r['note'] or r['source']}")
            notify.send("\n".join(msg) or "No payouts logged yet.", cid)
        elif cmd == "pause":
            self.paused.set()
            notify.send("⏸ Work loop paused. Use /resume to continue.", cid)
        elif cmd == "resume":
            self.paused.clear()
            notify.send("▶ Resumed.", cid)
        elif cmd == "scan":
            self.force_scan.set()
            notify.send("⏩ Scan cycle queued.", cid)
        else:
            notify.send("Commands: /status /stats /findings /revenue "
                        "/pause /resume /scan", cid)

    # ------------------------------------------------- periodic progress
    def progress_report(self):
        """15-minute progress report to the owner, incl. collected revenue."""
        import jobs
        while True:
            interval = self.cfg["notify"].get("progress_interval_minutes", 15) * 60
            time.sleep(interval)
            try:
                s = self.db.stats()
                jstat = jobs.stats(self.db)
                total_usd, n_payouts = self.db.revenue_total()
                est = self.estimate_value()
                sev_txt = "  ".join(f"{k.upper()}:{v}" for k, v in sorted(s.items())
                                    if k not in ("hosts", "programs")) or "none"
                job_txt = "  ".join(f"{k}:{v}" for k, v in jstat.items()) or "idle"
                notify.send(
                    f"🕐 *AutoBounty progress* (cycle {self.cycle})\n"
                    f"*Programs:* {s.get('programs',0)}  *Hosts:* {s.get('hosts',0)}\n"
                    f"*Findings:* {sev_txt}\n"
                    f"*Jobs:* {job_txt}\n"
                    f"💰 *Revenue collected:* ${total_usd:,.2f} ({n_payouts} payouts)\n"
                    f"📈 *Est. potential (not collected):* ${est:,.0f}")
            except Exception as e:
                print("[report] error:", e, flush=True)

    def estimate_value(self):
        """Conservative potential value of REVIEWED findings only."""
        anchors = self.cfg.get("economics", {}).get("est_bounty_usd", {})
        total = 0.0
        for row in self.db.conn.execute(
                "SELECT severity, COUNT(*) c FROM findings "
                "WHERE status IN ('triaged','confirmed') GROUP BY severity"):
            total += anchors.get(row["severity"], 0) * row["c"]
        return total

    # -------------------------------------------------------------- phases
    def phase_recon(self):
        if getattr(self, "skip_recon", False):
            print("[recon] skipped (--no-recon)", flush=True)
            return 0
        programs = self.db.programs()
        every_h = self.cfg["recon"].get("recon_every_hours", 12)
        total_hosts = 0
        for p in programs:
            if self.paused.is_set():
                return total_hosts
            # re-enumerate a program at most once per recon_every_hours
            if p.get("last_recon_at") and (time.time() - p["last_recon_at"]) < every_h * 3600:
                continue
            t0 = time.time()
            n_seed = recon.seed_hosts(self.db, p)
            n_sub = recon.enumerate_subdomains(self.db, p, self.cfg)
            n_probe = recon.resolve_and_probe(
                self.db, p, self.cfg,
                self.cfg["recon"]["max_hosts_per_program"])
            total_hosts += n_probe
            self.db.touch_program(p["name"], "last_recon_at")
            self.db.log_run("recon", "ok",
                            f"{p['name']}: seed={n_seed} subs={n_sub} probed={n_probe} "
                            f"({time.time()-t0:.0f}s)", started_at=int(t0))
            print(f"[recon] {p['name']}: +{n_sub} subdomains, {n_probe} live hosts",
                  flush=True)
            time.sleep(5)
        return total_hosts

    def phase_scan(self):
        """Scan the least-recently-scanned live hosts in bounded batches so coverage
        accumulates across cycles even on this low-power box."""
        programs = self.db.programs()
        new_all = []
        batch = self.cfg["scan"].get("scan_batch", 25)
        for p in programs:
            if self.paused.is_set():
                return new_all
            # backfill-probe a BOUNDED slice of unprobed hosts. The old code fed
            # the entire unprobed list (350k+ hosts) to one dnsx+httpx pair, which
            # always timed out and discarded everything -> scans never happened.
            max_backfill = int(self.cfg["recon"].get("max_hosts_per_program", 400))
            n_unprobed = self.db.conn.execute(
                "SELECT COUNT(*) c FROM hosts WHERE program=? AND in_scope=1 "
                "AND status IS NULL", (p["name"],)).fetchone()["c"]
            if n_unprobed:
                print(f"[scan] {p['name']}: backfill-probing {min(n_unprobed, max_backfill)} "
                      f"of {n_unprobed} unprobed hosts", flush=True)
                recon.resolve_and_probe(self.db, p, self.cfg, max_backfill)
            # pick the oldest-scanned live hosts (NULL scanned_at sorts first)
            rows = self.db.conn.execute(
                "SELECT * FROM hosts WHERE program=? AND in_scope=1 AND status IS NOT NULL "
                "AND status < 500 ORDER BY scanned_at IS NULL DESC, scanned_at ASC "
                f"LIMIT {int(batch)}", (p["name"],)).fetchall()
            hosts = [r["host"] for r in rows]
            if not hosts:
                continue
            t0 = time.time()
            new = scan.scan_hosts(self.db, p, self.cfg, hosts)
            self.db.mark_hosts_scanned(p["name"], hosts)
            self.db.touch_program(p["name"], "last_scan_at")
            self.db.log_run("scan", "ok",
                            f"{p['name']}: {len(hosts)} hosts, {len(new)} new findings "
                            f"({time.time()-t0:.0f}s)", started_at=int(t0))
            new_all += new
            time.sleep(3)
        return new_all

    def phase_triage(self, new_findings):
        """Enqueue LLM work for the sub-agents; never block the scan loop."""
        import jobs
        min_alert = _SEV_RANK.get(self.cfg["notify"]["alert_min_severity"], 3)
        q = 0
        for fid, sev in new_findings:
            f = self.db.finding(fid)
            status, note = triage.rule_triage(f)
            if status == "noise":
                self.db.set_finding_status(fid, "noise")
                continue
            _, added = jobs.enqueue(self.db, "triage", {"finding_id": fid})
            q += added
            _, added = jobs.enqueue(self.db, "draft", {"finding_id": fid})
            q += added
            if _SEV_RANK.get(f["severity"], 0) >= 2:
                _, added = jobs.enqueue(self.db, "verify", {"finding_id": fid})
                q += added
            # instant owner alert for high+ (report follows from the sub-agent)
            if _SEV_RANK.get(f["severity"], 0) >= min_alert or triage.sensitive_boost(f):
                if notify.alert_finding(f, "(report drafting in progress)"):
                    self.db.conn.execute(
                        "UPDATE findings SET alert_sent=1 WHERE id=?", (fid,))
                    self.db.conn.commit()
        report.write_index(self.db, self.cfg)
        return q

    # -------------------------------------------------------------- loop
    def _save_state(self):
        """Snapshot to state.json after each phase so a job timeout still leaves
        committable progress on the runner."""
        try:
            sf = os.path.join(self.cfg["runner"].get("state_dir", "data"), "state.json")
            live, found = self.db.export_state(sf)
            print(f"[state] snapshot {live} live hosts, {found} findings", flush=True)
        except Exception as e:
            print("[state] export error:", e, flush=True)

    def cycle_once(self):
        self.cycle += 1
        print(f"\n=== AutoBounty cycle {self.cycle} "
              f"@ {datetime.datetime.now().isoformat()} ===", flush=True)
        try:
            self.phase_recon()
        except Exception as e:
            self.db.log_run("recon", "error", repr(e))
            print("[recon] ERROR", e, flush=True)
        self._save_state()
        try:
            new = self.phase_scan()
        except Exception as e:
            self.db.log_run("scan", "error", repr(e))
            print("[scan] ERROR", e, flush=True)
            new = []
        self._save_state()
        try:
            q = self.phase_triage(new)
            print(f"[enqueue] {q} LLM jobs queued for sub-agents", flush=True)
        except Exception as e:
            self.db.log_run("triage", "error", repr(e))
            print("[triage] ERROR", e, flush=True)
        try:
            notify.alert_summary(self.db.stats())
        except Exception:
            pass
        try:
            sf = os.path.join(self.cfg["runner"].get("state_dir", "data"), "state.json")
            live, found = self.db.export_state(sf)
            print(f"[state] exported {live} live hosts, {found} findings", flush=True)
        except Exception as e:
            print("[state] export error:", e, flush=True)

    def prune_state(self):
        """Keep the committed state small enough for git: drop unprobed candidate
        hosts we never managed to reach. Findings and live hosts are always kept."""
        cutoff = int(time.time()) - 3 * 86400
        before = self.db.conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
        self.db.conn.execute(
            "DELETE FROM hosts WHERE status IS NULL AND last_seen < ?", (cutoff,))
        self.db.conn.commit()
        after = self.db.conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
        print(f"[prune] hosts {before} -> {after}", flush=True)

    def run(self, once=False, skip_recon=False):
        self.skip_recon = skip_recon
        state_file = os.path.join(self.cfg["runner"].get("state_dir", "data"),
                                  "state.json")
        self.db.import_state(state_file)          # merge progress from other runners
        threading.Thread(target=self.bot_thread, daemon=True).start()
        if not once:
            threading.Thread(target=self.progress_report, daemon=True).start()
        if once:
            self.cycle_once()
            self.prune_state()
            live, found = self.db.export_state(state_file)
            print(f"[state] exported {live} live hosts, {found} findings", flush=True)
            return
        interval = self.cfg["runner"]["phase_interval_minutes"] * 60
        while True:
            while self.paused.is_set() and not self.force_scan.is_set():
                time.sleep(15)
            self.force_scan.clear()
            self.cycle_once()
            # wait for next cycle (interruptible)
            deadline = time.time() + interval
            while time.time() < deadline:
                if self.force_scan.is_set():
                    break
                time.sleep(10)


if __name__ == "__main__":
    once = "--once" in sys.argv
    ab = AutoBounty()
    ab.run(once=once, skip_recon="--no-recon" in sys.argv)
