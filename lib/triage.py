#!/usr/bin/env python3
"""Triage: rule-based dedupe/noise-filter + LLM-assisted report drafting
via the fast remote Atria API (no local model — too slow)."""
import json, os, re, sys, time
sys.path.insert(0, os.path.dirname(__file__))

# Template IDs that are overwhelmingly false positives on public programs.
NOISE_PATTERNS = [
    r"tech-detect", r"wappalyzer", r"favicon", r"cdN-cname", r"ip-origin",
    r"^detect-", r"robots-txt$", r"securitytxt", r"x-powered-by",
    r"^dashboard-detect", r"^login-panel", r"^external-service",
]

# Findings worth reporting even at low severity when a sensitive path is exposed.
SENSITIVE_HINTS = ["/.env", "/.git/", "id_rsa", "backup", "dump.sql", "config.php.bak",
                   "wp-config.php.bak", "/.aws/", "credentials", "/actuator/env",
                   "/graphql", "/.well-known/private"]


def rule_triage(finding):
    """Return (status, note). status in noise|new|triaged."""
    tpl = (finding.get("template_id") or "").lower()
    name = (finding.get("template_name") or "").lower()
    blob = tpl + " " + name
    for pat in NOISE_PATTERNS:
        if re.search(pat, blob):
            return "noise", f"noise pattern {pat}"
    return None, None


def sensitive_boost(finding):
    raw = (finding.get("raw") or "").lower()
    host = (finding.get("host") or "").lower()
    blob = raw + " " + host
    return any(s in blob for s in SENSITIVE_HINTS)


# ---------------------------------------------------------------- LLM
import llm


def atria_chat(messages, tries=2, timeout=90):
    return llm.ask(messages, tier="fast", timeout=timeout) if tries else None


DRAFT_PROMPT = """You are a senior application security report writer for a bug bounty
submission. Given the raw scanner evidence, produce a professional finding report in
MARKDOWN ONLY (no preamble). Use exactly these sections:

## Title
(Concise, severity-aware)

## Summary
(2-3 sentences: what the issue is, why it matters, worst case. Business impact.)

## Affected Asset
(the host)

## Severity Rationale
(one short paragraph; map to CVSS 3.1 qualitative rating)

## Reproduction Steps
(numbered, copy-pasteable, using curl where applicable; include the exact unauthenticated
request path. Do NOT invent parameters that are not in the evidence.)

## Impact
(what an attacker gains; be honest and do not exaggerate)

## Remediation
(concrete fixes)

## References
(CWE / OWASP links if applicable)

Rules: never invent facts not supported by the evidence; never claim unauthenticated
access if the evidence shows otherwise; keep it under 700 words."""


def draft_report(finding):
    ev = {
        "host": finding.get("host"),
        "template_id": finding.get("template_id"),
        "template_name": finding.get("template_name"),
        "severity": finding.get("severity"),
        "description": finding.get("description"),
        "raw_evidence": json.loads(finding.get("raw") or "{}"),
        "program": finding.get("program"),
    }
    # high/critical findings get the deep tier (NIM) for stronger analysis
    tier = "deep" if finding.get("severity") in ("high", "critical") else "fast"
    text = llm.ask([
        {"role": "system", "content": DRAFT_PROMPT},
        {"role": "user", "content": "Evidence JSON:\n" + json.dumps(ev, indent=2)[:6000]},
    ], tier=tier, max_tokens=2000)
    if not text:
        # Fall back to a deterministic template-based draft (never fake evidence).
        text = _fallback_draft(finding)
    return text


def _fallback_draft(finding):
    return f"""## Title
{finding.get("template_name") or finding.get("template_id")} on {finding.get("host")}

## Summary
An automated security scan of an asset within the scope of the {finding.get("program")}
bug bounty program identified a potential **{finding.get("severity")}** severity issue
of type `{finding.get("template_id")}`. This class of issue can expose the affected
service to unauthorized access or information disclosure. Further manual verification
is recommended to confirm exploitability in the production context.

## Affected Asset
`{finding.get("host")}`

## Severity Rationale
Rated **{finding.get("severity")}** by the detection template based on the response
observed during testing. Final rating is subject to manual confirmation.

## Reproduction Steps
1. Send an unauthenticated request to the affected endpoint on `{finding.get("host")}`.
2. Observe the response that matches the detection signature
   (`{finding.get("template_id")}`).
3. Confirm the issue is reproducible before submission.

## Impact
Depends on the specific vulnerability class. Potential impacts include information
disclosure, unauthorized access, or security misconfiguration that an attacker could
chain with other issues.

## Remediation
Apply the vendor/configuration fix appropriate to the detected issue class. Restrict
access to sensitive endpoints and remove the detected exposure.

## References
- {finding.get("description") or 'See template references'}
"""
