#!/usr/bin/env python3
"""Scanning: nuclei (non-destructive template set) over live in-scope hosts.
Results are STREAMED and persisted as they arrive, so a timeout never loses work."""
import json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from recon import tool
from scope import in_scope

TPL_DIR = os.path.expanduser("~/nuclei-templates")
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _parse_host(j):
    h = (j.get("host") or j.get("matched-at") or "")
    return h.split("//")[-1].split("/")[0].split(":")[0].lower()


def scan_hosts(db, program, cfg, hosts, tag="nuclei"):
    """Run nuclei over `hosts`; return list of (finding_id, severity) for NEW ones."""
    if not hosts:
        return []
    if not os.path.isdir(TPL_DIR):
        print("[scan] templates missing, skipping", flush=True)
        return []
    nuclei = tool("nuclei")
    if not nuclei:
        print("[scan] nuclei not installed", flush=True)
        return []

    sc = cfg["scan"]
    # nuclei with -l only tries ports 80/443 on bare hostnames. Scan the exact
    # live endpoints httpx discovered (scheme + non-standard ports) when we have them.
    rows = {r["host"]: (r["url"] or None)
            for r in db.conn.execute(
                "SELECT host,url FROM hosts WHERE program=?", (program["name"],))}
    targets = []
    for h in hosts:
        u = rows.get(h)
        targets.append(u if u else h)
    targets = [t for t in targets if t]

    # per-program politeness: nuclei rate limit = the program's declared rps x 2
    rps = min(sc.get("nuclei_rps", 80), (program.get("rps") or 10) * 2)
    cmd = [
        nuclei,
        "-t", TPL_DIR,
        "-l", "-",
        "-j",                       # nuclei v3: -j / -jsonl (the old -json flag is gone)
        "-o", "-",
        "-tags", ",".join(sc["tags"]),
        "-etags", ",".join(sc["exclude_tags"]),
        "-severity", ",".join(sc["severity"]),
        "-rl", str(rps),
        "-c", str(sc["nuclei_concurrency"]),
        "-bs", "15",
        "-timeout", "12",
        "-no-color",
        "-silent",
        "-ni",                      # no interactsh OAST -> offline triage
    ]
    scope = json.loads(program["scope"])
    excl = json.loads(program["exclusions"])
    drop = sc.get("drop_templates", [])
    new_ids = []
    deadline = time.time() + sc["timeout_seconds"]

    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        proc.stdin.write("\n".join(targets) + "\n")
        proc.stdin.close()
        for line in proc.stdout:                    # STREAM: persist each finding live
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                j = json.loads(line)
            except Exception:
                continue
            fid, sev = _handle_line(db, program, j, scope, excl, drop)
            if fid:
                new_ids.append((fid, sev))
        proc.wait(timeout=max(30, deadline - time.time()))
    except subprocess.TimeoutExpired:
        proc.kill()
        print("[scan] nuclei killed at timeout (partial results kept)", flush=True)
    except Exception as e:
        print("[scan] error:", e, flush=True)
    return new_ids


def _handle_line(db, program, j, scope, excl, drop):
    host = _parse_host(j)
    if not host or not in_scope(host, scope, excl):
        return None, None
    tpl = j.get("template-id") or j.get("templateID") or ""
    if any(d in tpl for d in drop):
        return None, None
    sev = (j.get("info", {}).get("severity") or "info").lower()
    if sev not in _SEV_ORDER:
        sev = "info"
    name = j.get("info", {}).get("name") or tpl
    er = j.get("extracted-results")
    desc = (j.get("info", {}).get("description")
            or (er[0] if isinstance(er, list) and er else ""))
    fid, is_new = db.upsert_finding(
        program["name"], host, tpl, name, sev,
        str(desc or name)[:2000], json.dumps(j)[:4000], j.get("type", "http"))
    if is_new:
        rank = _SEV_ORDER.get(sev, 0)
        flag = "🔴" if rank >= 3 else ("🟠" if rank == 2 else "🟡")
        print(f"[scan] {flag} NEW {sev.upper():8s} {host}  {name}", flush=True)
        return fid, sev
    return None, None
