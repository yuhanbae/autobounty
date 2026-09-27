#!/usr/bin/env python3
"""Reporting: professional finding reports + submission-ready index."""
import json, os, sys, datetime
sys.path.insert(0, os.path.dirname(__file__))

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def write_finding_report(db, cfg, finding, body_md):
    reports_dir = cfg["runner"]["reports_dir"]
    os.makedirs(reports_dir, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in finding["host"])
    fname = (f"{finding['severity'].upper()}_{safe}_"
             f"{finding['template_id'].replace('/', '_')}.md")
    path = os.path.join(reports_dir, fname)
    header = f"""<!--
AutoBounty finding report
Program : {finding['program']}
Host    : {finding['host']}
Template: {finding['template_id']}
Severity: {finding['severity']}
First seen: {_utc()}
Status  : {finding['status']}
NOTE: Verify manually before submitting to the program. This draft was generated
from scanner evidence only.
-->
"""
    with open(path, "w") as f:
        f.write(header + "\n" + body_md + "\n")
    return path


def write_index(db, cfg):
    """Rolling submission-ready index + executive digest of all triaged findings."""
    reports_dir = cfg["runner"]["reports_dir"]
    os.makedirs(reports_dir, exist_ok=True)
    rows = db.conn.execute(
        "SELECT * FROM findings WHERE status NOT IN ('noise') "
        "ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, first_seen DESC"
    ).fetchall()
    lines = ["# AutoBounty — Triaged Findings Index", "", f"Generated {_utc()}", ""]

    sev_counts = {}
    for r in rows:
        sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1
    if sev_counts:
        lines += ["## Risk Summary", "",
                  "| Severity | Count |", "|---|---|"]
        for s in ("critical", "high", "medium", "low", "info"):
            if sev_counts.get(s):
                lines.append(f"| {s.upper()} | {sev_counts[s]} |")
        lines.append("")

    for r in rows:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
            r["severity"], "⚪")
        rp = os.path.basename(r["report_path"]) if r["report_path"] else "—"
        lines.append(f"- {emoji} **[{r['severity'].upper()}]** {r['host']} — "
                     f"{r['template_name'] or r['template_id']} "
                     f"`{r['status']}` [{rp}]({rp})")
    idx = os.path.join(reports_dir, "INDEX.md")
    with open(idx, "w") as f:
        f.write("\n".join(lines) + "\n")
    jidx = os.path.join(reports_dir, "findings.json")
    with open(jidx, "w") as f:
        json.dump([dict(r) for r in rows], f, indent=2, default=str)
    return idx, sev_counts
