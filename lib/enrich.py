#!/usr/bin/env python3
"""Submission enrichment: fill CVSS/CWE/PoC placeholders so a human submission is
copy-paste-ready and more likely to be accepted (the real money gate).

Everything here is a SUGGESTION derived from stored evidence — clearly labelled, never
presented as verified fact. Deterministic + fast; optional LLM polish via lib/llm if a
deep tier key is present (best-effort, short timeout, degrades to heuristics)."""
import os, re, json

# template-id fragment -> (CWE id, CWE name)
_CWE_MAP = [
    (r"default-login|default_credential|default-logins", "CWE-1391", "Use of Weak Credentials"),
    (r"exposure|exposed|leak|disclosure|backup|\.env|\.git|directory-listing",
     "CWE-200", "Exposure of Sensitive Information"),
    (r"unauth|missing-auth|no-auth|unauthenticated", "CWE-306",
     "Missing Authentication for Critical Function"),
    (r"misconfig|misconfiguration", "CWE-16", "Configuration"),
    (r"open-redirect", "CWE-601", "URL Redirection to Untrusted Site"),
    (r"xss|cross-site", "CWE-79", "Cross-site Scripting"),
    (r"sqli|sql-injection", "CWE-89", "SQL Injection"),
    (r"ssrf", "CWE-918", "Server-Side Request Forgery"),
    (r"takeover", "CWE-350", "Improper Handling of Trusted Configuration"),
    (r"cve-", "CWE-1035", "Vendor CVE (see CVE record)"),
]

# severity -> conservative suggested CVSS v3.1 base score + vector skeleton
_CVSS = {
    "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high":     (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "medium":   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low":      (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "info":     (0.0, ""),
}


def suggest_cwe(template_id):
    t = (template_id or "").lower()
    for pat, cwe, name in _CWE_MAP:
        if re.search(pat, t):
            return cwe, name
    return "CWE-200", "Information Exposure (template unclassified — confirm)"


def suggest_cvss(severity):
    return _CVSS.get((severity or "").lower(), (0.0, ""))


def _evidence_lines(finding, limit=12):
    raw = finding.get("raw") or ""
    out = []
    try:
        v = json.loads(raw)
        def walk(x):
            if isinstance(x, dict):
                for k, val in x.items():
                    if k in ("matched-at", "host", "matcher-name", "type", "info",
                             "extracted-results", "request", "curl-command") and \
                            isinstance(val, (str, int)) and val:
                        out.append(f"{k}: {str(val)[:160]}")
                    else:
                        walk(val)
            elif isinstance(x, list):
                for i in x[:6]:
                    walk(i)
        walk(v)
    except Exception:
        for ln in raw.splitlines()[:limit]:
            if ln.strip():
                out.append(ln.strip()[:160])
    seen, uniq = set(), []
    for l in out:
        if l not in seen:
            seen.add(l); uniq.append(l)
    return uniq[:limit]


def enrich(finding):
    """Return dict of suggested fields for a finding (evidence-grounded, labelled)."""
    cwe, cwe_name = suggest_cwe(finding.get("template_id"))
    score, vector = suggest_cvss(finding.get("severity"))
    ev = _evidence_lines(finding)
    poc = ["Reproduce against the in-scope asset, then attach the exact request/response:"]
    for e in ev[:6]:
        poc.append(f"- {e}")
    poc.append("- (attach nuclei command + full response body as PoC)")
    return {
        "cwe": f"{cwe} — {cwe_name} (suggested — confirm)",
        "cvss": (f"{vector}  (base {score:.1f}) — suggested from severity; confirm with "
                 "manual CVSS calculation") if vector else "<!-- CVSS: manual calc required -->",
        "poc": "\n".join(poc),
    }


def enrich_package_text(pkg_text, suggestions):
    t = pkg_text
    if "<!-- CWE -->" in t:
        t = t.replace("<!-- CWE -->", suggestions["cwe"])
    if "<!-- fill after manual CVSS calc -->" in t:
        t = t.replace("<!-- fill after manual CVSS calc -->", suggestions["cvss"])
    # inject a PoC section if the package lacks a concrete one
    if "## Attachments / PoC" in t and "<!-- attach raw evidence -->" in t:
        t = t.replace("<!-- attach raw evidence -->", "\n" + suggestions["poc"])
    if "## Steps to Reproduce\n1. See stored" in t and "<!-- PoC" not in t:
        t = t.replace(
            "3. Confirm the issue is reproducible before submission.\n",
            "3. Confirm the issue is reproducible before submission.\n\n"
            "### Suggested PoC / evidence (verify before submitting)\n"
            + suggestions["poc"] + "\n")
    return t
