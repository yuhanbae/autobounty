#!/usr/bin/env python3
"""Submission pipeline: turn a triaged finding into tracked money.

Flow:  reported finding -> format_submission (paste-ready per platform) ->
       queue_submission (status=queued) -> [owner] submit -> mark_submission
       -> accepted -> paid -> db.log_revenue() (REAL money, only here).

No fake money: revenue is logged ONLY when a submission is marked 'paid' with a
real amount. HackerOne (11/14 programs) has NO public hunter submission API, so
those stay a fast manual copy/paste flow ('/submit' prints the paste-ready text).
Bugcrowd/Intigriti auto-submit adapters exist but are DEFAULT-OFF (submit.autosubmit)
and require the owner's API credentials + an explicit run -- no silent blasting.
"""
import json, os, re, time, sys
sys.path.insert(0, os.path.dirname(__file__))
import money, enrich

_CVSS_PLACEHOLDER = "<!-- fill after manual CVSS calc -->"
_CWE_PLACEHOLDER = "<!-- CWE -->"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER, program TEXT, platform TEXT, severity TEXT,
  ev_usd REAL, title TEXT, package_path TEXT,
  status TEXT DEFAULT 'queued',   -- queued|submitted|triaged|accepted|duplicate|paid
  submitted_at INTEGER, resolved_at INTEGER, payout_usd REAL,
  ext_ref TEXT, note TEXT
);
"""


def ensure_schema(db):
    db.conn.execute(_SCHEMA)
    db.conn.commit()


def _platform_of(finding):
    p = (finding.get("platform") or "").lower()
    if "bugcrowd" in p:
        return "bugcrowd"
    if "hackerone" in p:
        return "hackerone"
    if "github" in p:
        return "github"
    return "generic"


def _sev_word(sev):
    return (sev or "medium").upper()


def format_submission(cfg, finding, report_body=None):
    """Return (title, markdown) paste-ready fields. Never invents facts — PoC and
    claims come from stored evidence; CVSS/CWE stay human-filled placeholders."""
    host = finding.get("host")
    prog = finding.get("program")
    sev = _sev_word(finding.get("severity"))
    tname = finding.get("template_name") or finding.get("template_id")
    platform = _platform_of(finding)
    title = f"{sev} — {tname} on {host} ({prog})"
    body = report_body or (
        "## Summary\n"
        "Automated authorized scan of an in-scope asset reported "
        f"`{finding.get('template_id')}` on `{host}`.\n\n"
    )
    cwe = _CWE_PLACEHOLDER
    cvss = _CVSS_PLACEHOLDER
    if platform == "bugcrowd":
        body_out = (f"**Title:** {title}\n\n"
                    f"**Priority (crowd P1..P4):** <!-- map {sev} here -->\n\n"
                    f"{body}\n\n**Affected asset:** `{host}`\n\n"
                    f"**Weakness / CWE:** {cwe}\n\n**CVSS:** {cvss}\n\n"
                    "**Attachments / PoC:** <!-- attach raw evidence -->\n")
    elif platform == "github":
        body_out = (f"{body}\n\n**Affected asset:** `{host}`\n\n"
                    f"**Severity:** {sev}\n\n**Weakness / CWE:** {cwe}\n\n"
                    f"**CVSS:** {cvss}\n")
    else:  # hackerone / generic
        body_out = (f"## Summary\n{body}\n\n## Affected Asset\n`{host}`\n\n"
                    f"## Severity\n{sev}  (CVSS: {cvss})\n\n"
                    f"## Weakness (CWE)\n{cwe}\n\n"
                    "## Steps to Reproduce\n1. See stored scanner evidence (attached below).\n"
                    "2. Confirm manually against the in-scope asset before submitting.\n\n"
                    "## Remediation\n<!-- standard fix for this template class -->\n")
    return title, body_out


def _safe(s):
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in (s or ""))


def queue_submission(db, cfg, finding):
    """Create/refresh a submission package + queue row for a reported finding.
    Returns the new submission id, or None if already queued."""
    ensure_schema(db)
    exists = db.conn.execute(
        "SELECT id FROM submissions WHERE finding_id=? AND status IN "
        "('queued','submitted','triaged','accepted')", (finding["id"],)).fetchone()
    if exists:
        return None
    import report as reportlib
    # prefer the already-drafted report body if present
    body = None
    if finding.get("report_path") and os.path.exists(finding["report_path"]):
        try:
            body = open(finding["report_path"]).read()
        except Exception:
            body = None
    title, md = format_submission(cfg, finding, body)
    platform = _platform_of(finding)
    reports_dir = cfg["runner"]["reports_dir"]
    sub_dir = os.path.join(reports_dir, "submissions")
    os.makedirs(sub_dir, exist_ok=True)
    pkg = os.path.join(
        sub_dir, f"SUB{_safe(platform)}_{_safe(finding['program'])}_"
                 f"{_safe(str(finding['host']))}_{_safe(finding['template_id'])}.md")
    ev = money.expected_value(cfg, finding)
    suggestions = enrich.enrich(finding)
    md = enrich.enrich_package_text(md, suggestions)
    md += ("\n\n---\n\n### App-submission metadata (AutoBounty *suggested* \u2014 verify before submitting)\n"
           f"- **Suggested CWE:** {suggestions['cwe']}\n"
           f"- **Suggested CVSS v3.1:** {suggestions['cvss']}\n"
           f"- **Suggested PoC / evidence:**\n{suggestions['poc']}\n")
    with open(pkg, "w") as f:
        f.write(f"# {title}\n\nPlatform: {finding.get('platform') or platform} | "
                f"Program: {finding['program']} | EV(potential): ${ev}\n\n{md}\n")
    cur = db.conn.execute(
        "INSERT INTO submissions(finding_id,program,platform,severity,ev_usd,title,"
        "package_path,status) VALUES(?,?,?,?,?,?,?,'queued')",
        (finding["id"], finding["program"], finding.get("platform") or platform,
         finding.get("severity"), ev, title, pkg))
    db.conn.commit()
    return cur.lastrowid


def queue_new_reports(db, cfg):
    """Queue every currently-reported finding not yet queued. Returns (n_new, ranked)."""
    ensure_schema(db)
    ranked = money.rank_queue(db, cfg)
    n = 0
    for f in ranked:
        sid = queue_submission(db, cfg, f)
        if sid:
            n += 1
    return n, ranked


def list_queue(db, status="queued", limit=20):
    ensure_schema(db)
    return [dict(r) for r in db.conn.execute(
        "SELECT * FROM submissions WHERE status=? ORDER BY ev_usd DESC LIMIT ?",
        (status, limit)).fetchall()]


def mark_submission(db, sid, status, ext_ref=None, amount_usd=None, note=""):
    """Advance a submission. Logging REAL revenue happens ONLY on status=='paid'
    with an amount — anything else just updates state (no fake payouts)."""
    ensure_schema(db)
    now = int(time.time())
    row = db.conn.execute("SELECT * FROM submissions WHERE id=?", (sid,)).fetchone()
    if not row:
        raise ValueError(f"no submission {sid}")
    db.conn.execute(
        "UPDATE submissions SET status=?, ext_ref=COALESCE(?,ext_ref), note=?, "
        "submitted_at=COALESCE(submitted_at, ?), resolved_at=?, payout_usd=? "
        "WHERE id=?",
        (status, ext_ref, note, now if status in ("submitted", "triaged", "accepted",
         "paid", "duplicate") else None, now if status in ("accepted", "paid",
         "duplicate") else None, amount_usd, sid))
    db.conn.commit()
    if status == "paid":
        amt = amount_usd if amount_usd is not None else (row["payout_usd"] or 0)
        if amt and amt > 0:
            # the ONLY place money is recorded
            return db.log_revenue(amt, row["program"], note or f"submission #{sid}")
    return None


# ---- enrichment + money-strict gate ----------------------------------
def enrich_package(db, cfg, sid):
    """(Re)fill CVSS/CWE/PoC placeholders in an existing queued package."""
    row = db.conn.execute("SELECT * FROM submissions WHERE id=?", (sid,)).fetchone()
    if not row or not row["package_path"] or not os.path.exists(row["package_path"]):
        return None
    f = db.finding(row["finding_id"]) if row["finding_id"] else None
    if not f:
        return None
    s = enrich.enrich(f)
    txt = open(row["package_path"]).read()          # read BEFORE opening 'w' (which truncates)
    new = enrich.enrich_package_text(txt, s)
    if new.strip():
        open(row["package_path"], "w").write(new)
    return s


def qualifies_for_submit(finding):
    """Money-strict auto gate: only high/critical, and never informational tech noise."""
    sev = (finding.get("severity") or "").lower()
    if sev not in ("high", "critical"):
        return False
    return money.hard_dedup(None, finding) is None


# ---- optional auto-submit (self-activating on a platform token) ----------
def platform_token(platform):
    """The moment a real token appears in the environment, that platform can auto-submit."""
    p = (platform or "").lower()
    if p == "bugcrowd":
        return os.environ.get("BUGCROWD_TOKEN")
    if p == "intigriti":
        return os.environ.get("INTIGRITI_TOKEN")
    return None   # hackerone/github -> never auto (no public hunter submission API)


def autosubmit_enabled(cfg):
    s = cfg.get("submit", {}) or {}
    return bool(s.get("autosubmit")) and not s.get("dry_run", True)


def autosubmit(cfg, finding, sid, platform=None):
    """Autonomously submit if: a real token exists for the platform AND autosubmit is
    enabled (autosubmit:true + dry_run:false). Otherwise returns a dry-run plan. Never
    fabricates a submission — real HTTP requires a real token + enablement."""
    platform = platform or _platform_of(finding)
    if platform not in ("bugcrowd", "intigriti"):
        return {"skipped": f"{platform} has no public hunter submission API "
                           f"— human submits via /submit"}
    tok = platform_token(platform)
    title, md = format_submission(cfg, finding)
    payload = {"title": title, "markdown": md, "finding": finding}
    if not tok:
        return {"skipped": f"no {platform} token in env — set {platform.upper()}_TOKEN to enable"}
    if not qualifies_for_submit(finding):
        return {"skipped": "below money-strict threshold (needs high/critical, dedup-clean)"}
    if not autosubmit_enabled(cfg):
        return {"dry_run": True, "would_submit": title, "platform": platform,
                "note": "autosubmit requires submit.autosubmit:true + dry_run:false"}
    if platform == "bugcrowd":
        return submit_bugcrowd(cfg, payload, {"bugcrowd_token": tok})
    if platform == "intigriti":
        return submit_intigriti(cfg, payload, {"intigriti_token": tok})
    return {"skipped": f"{platform} has no public hunter submission API — human submits"}


def submit_intigriti(cfg, payload, creds):
    import requests
    if not autosubmit_enabled(cfg):
        return {"dry_run": True, "would_submit": payload.get("title")}
    tok = creds.get("intigriti_token")
    if not tok:
        return {"error": "missing intigriti_token"}
    r = requests.post("https://api.intigriti.com/core/researcher/submission",
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
        json={"title": payload["title"], "description": payload["markdown"]}, timeout=30)
    return {"status": r.status_code, "ref": r.text[:200]}


def submit_bugcrowd(cfg, payload, creds):
    """Bugcrowd submission adapter. Real HTTP only if enabled + dry_run off."""
    import requests
    if not autosubmit_enabled(cfg):
        return {"dry_run": True, "would_submit": payload.get("title")}
    tok = creds.get("bugcrowd_token")
    if not tok:
        return {"error": "missing bugcrowd_token"}
    r = requests.post(
        "https://api.bugcrowd.com/submissions",
        headers={"Authorization": f"Token {tok}", "Content-Type": "application/json"},
        json={"title": payload["title"], "description": payload["markdown"],
              "bugcrowd_program_id": creds["bugcrowd_program_id"]},
        timeout=30)
    return {"status": r.status_code, "ref": r.text[:200]}
