#!/usr/bin/env python3
"""Money orientation: expected-value ranking + hard duplicate suppression.

Optimizes for *money*, not finding volume. A finding's expected value (EV) is
its potential bounty (from config economics) x a per-program payout-tier weight
x a confidence factor derived from how the finding has held up across cycles.
The rank_queue() list is what a human should submit first; hard_dedup() keeps
near-certain dupes/noise from ever reaching the submission queue (duplicates are
the #1 reason automated bounty work nets $0 and burns triager goodwill).
"""
import json, re

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# severity -> baseline multiplier on the configured median bounty for that sev
_BASE = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1, "info": 0.0}


def _program_tier(cfg, program):
    """Per-program payout weight. Larger, well-paying programs rank higher."""
    tiers = (cfg.get("submit", {}) or {}).get("tier_usd", {}) or {}
    return float(tiers.get(program, 1.0))


def expected_value(cfg, finding):
    """expected USD value of THIS finding, if it is real + accepted.

    Potentially confusing name — this is an EXPECTED value (potential), not real
    money. Real money only ever comes from submission being paid (revenue table).
    """
    sev = (finding.get("severity") or "").lower()
    base_cfg = (cfg.get("economics", {}) or {}).get("est_bounty_usd", {}) or {}
    base = float(_BASE.get(sev, 0.0)) * float(base_cfg.get(sev, 0) or 0)
    tier = _program_tier(cfg, finding.get("program"))
    # confidence: a finding re-confirmed across cycles is more likely real than a
    # one-shot hit; clamp so this nudges EV, never fabricates it.
    seen = float(finding.get("seen_count") or 1)
    conf = min(1.5, 0.8 + 0.1 * seen)
    return round(base * tier * conf, 2)


def rank_queue(db, cfg, limit=50, exclude_programs=None):
    """Findings worth submitting, ordered by expected value desc.

    Excludes noise/duplicate/'new' (un-triaged) and SelfTest (owned lab, no
    bounty). Requires a drafted report OR at least medium severity.
    """
    rows = db.conn.execute(
        "SELECT f.*, p.platform FROM findings f JOIN programs p ON p.name=f.program "
        "WHERE f.status IN ('triaged','reported','confirmed') AND f.severity!='info'").fetchall()
    out = []
    for r in rows:
        f = dict(r)
        if exclude_programs and f["program"] in exclude_programs:
            continue
        if f["program"] in ("SelfTest", "self-test", "selftest"):
            continue
        f["ev_usd"] = expected_value(cfg, f)
        out.append(f)
    out.sort(key=lambda x: x["ev_usd"], reverse=True)
    return out[:limit]


def hard_dedup(cfg, finding):
    """Stricter suppression than triage.rule_triage: return a reason string if
    this finding should be treated as noise/duplicate for MONEY purposes, else
    None. Public programs are hammered, so the bar for spending reviewer attention
    is high — over-reporting duplicates actively harms earnings."""
    tid = (finding.get("template_id") or "")
    sev = (finding.get("severity") or "").lower()
    desc = (finding.get("description") or "")
    # repeated identical hits across cycles that never produced a unique host-level
    # difference are the classic duplicate pattern on big programs.
    if int(finding.get("seen_count") or 1) > 1 and sev in ("low", "info"):
        return "low-severity repeat across cycles"
    if re.search(r"(tech-detect|wappalyzer|favicon|robots-txt|securitytxt|"
                 r"x-powered-by|cdn-cname|ip-origin|^detect-)", tid):
        return "informational tech fingerprint"
    if sev == "info":
        return "informational severity"
    return None
