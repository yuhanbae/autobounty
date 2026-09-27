#!/usr/bin/env python3
"""Job queue for the AutoBounty sub-agents. Workers poll this table and execute
LLLM tasks in parallel processes, so scanning never blocks on LLM latency."""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))


def ensure(db):
    db.conn.execute("""
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,            -- triage | draft | verify | research | enrich
  payload TEXT NOT NULL,         -- JSON
  status TEXT DEFAULT 'pending', -- pending | running | done | failed
  result TEXT,                   -- JSON output
  worker TEXT,
  attempts INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER
)""")
    db.conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
    db.conn.commit()


def enqueue(db, kind, payload, dedupe=True):
    """Enqueue a job; with dedupe=True, skip if an identical pending job exists."""
    ensure(db)
    now = int(time.time())
    body = json.dumps(payload, sort_keys=True)
    if dedupe:
        row = db.conn.execute(
            "SELECT id FROM jobs WHERE kind=? AND payload=? AND status IN ('pending','running')",
            (kind, body)).fetchone()
        if row:
            return row["id"], False
    cur = db.conn.execute(
        "INSERT INTO jobs(kind,payload,status,created_at) VALUES(?,?,?,?)",
        (kind, body, "pending", now))
    db.conn.commit()
    return cur.lastrowid, True


def claim(db, worker, kinds, timeout_s=300):
    """Atomically claim one pending job (of the given kinds) for a worker."""
    ensure(db)
    placeholders = ",".join("?" for _ in kinds)
    row = db.conn.execute(
        f"SELECT * FROM jobs WHERE status='pending' AND kind IN ({placeholders}) "
        f"ORDER BY created_at ASC LIMIT 1", kinds).fetchone()
    if not row:
        return None
    now = int(time.time())
    db.conn.execute(
        "UPDATE jobs SET status='running', worker=?, started_at=?, attempts=attempts+1 "
        "WHERE id=? AND status='pending'", (worker, now, row["id"]))
    db.conn.commit()
    return dict(row)


def complete(db, job_id, result, ok=True):
    db.conn.execute(
        "UPDATE jobs SET status=?, result=?, finished_at=? WHERE id=?",
        ("done" if ok else "failed",
         json.dumps(result)[:20000] if result is not None else None,
         int(time.time()), job_id))
    db.conn.commit()


def stale_running(db, max_age_s=900):
    """Reclaim jobs whose worker died."""
    ensure(db)
    cutoff = int(time.time()) - max_age_s
    db.conn.execute(
        "UPDATE jobs SET status='pending', worker=NULL WHERE status='running' "
        "AND started_at < ?", (cutoff,))
    db.conn.commit()


def stats(db):
    return {r["status"]: r["c"] for r in db.conn.execute(
        "SELECT status, COUNT(*) c FROM jobs GROUP BY status")}
