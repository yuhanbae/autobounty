#!/usr/bin/env python3
"""Recon: scope seeding -> passive subdomain enumeration -> resolution -> HTTP probing.
Every discovered host is scope-checked before it is stored or probed."""
import json, os, shutil, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from scope import in_scope, split_host


def tool(name):
    """Resolve a ProjectDiscovery tool, preferring our own Go installs.
    (The system `httpx` on Termux is the python HTTP client, not PD httpx!)"""
    go_bin = os.path.join(os.path.expanduser("~/go/bin"), name)
    if os.path.exists(go_bin):
        return go_bin
    p = shutil.which(name)
    return p


def run(cmd, stdin_data=None, timeout=900, capture_err=False):
    try:
        p = subprocess.run(cmd, input=stdin_data, capture_output=True,
                           text=True, timeout=timeout)
        if capture_err and (p.stderr or '').strip():
            print(f"[cmd] {os.path.basename(cmd[0])} stderr: "
                  f"{p.stderr.strip()[:400]}", flush=True)
        return p.stdout or "", p.returncode
    except subprocess.TimeoutExpired:
        return "", 124


def seed_hosts(db, program):
    """Apex domains from the program's declared scope are the seed set."""
    scope = json.loads(program["scope"])
    n = 0
    for rule in scope:
        host = rule.lstrip("*.").lower()
        if not host:
            continue
        db.upsert_host(program["name"], host, "scope")
        n += 1
    return n


def enumerate_subdomains(db, program, cfg):
    """Passive enumeration per apex domain; only in-scope results are kept."""
    scope = json.loads(program["scope"])
    excl = json.loads(program["exclusions"])
    apex = sorted({r.lstrip("*.").lower() for r in scope if r and "." in r})
    sf = tool("subfinder")
    if not sf:
        return 0
    args = list(cfg["recon"].get("subfinder_args", []))
    found = 0
    for a in apex:
        out, rc = run([sf] + args + ["-d", a, "-o", "-"], timeout=1500)
        if rc == 124:
            continue
        for line in out.splitlines():
            h = line.strip().lower()
            if not h or h == a:
                continue
            if in_scope(h, scope, excl):
                db.upsert_host(program["name"], h, "subfinder")
                found += 1
        time.sleep(1)
    return found


def resolve_and_probe(db, program, cfg, max_hosts):
    """dnsx resolve -> httpx probe, for hosts we have not probed yet."""
    scope = json.loads(program["scope"])
    excl = json.loads(program["exclusions"])
    hosts = [h["host"] for h in db.all_hosts(program["name"])][:max_hosts]
    hosts = [h for h in hosts if in_scope(h, scope, excl)]
    if not hosts:
        return 0

    # dnsx: resolve, keep only resolving names
    dnsx = tool("dnsx")
    resolved = set(hosts)
    if dnsx:
        out, _ = run([dnsx] + cfg["recon"].get("dnsx_args", []) + ["-l", "-"],
                     stdin_data="\n".join(hosts), timeout=1200)
        alive = {split_host(l.split()[0]) for l in out.splitlines() if l.strip()}
        if alive:
            resolved = {h for h in hosts if h in alive} or set(hosts)

    # httpx: probe + metadata
    httpx = tool("httpx")
    if not httpx:
        return 0
    cmd = ([httpx, "-l", "-", "-json", "-rl", str(cfg["recon"].get("httpx_rps", 40)),
            "-threads", str(cfg["recon"].get("httpx_threads", 10))]
           + cfg["recon"].get("httpx_args", []))
    out, _ = run(cmd, stdin_data="\n".join(sorted(resolved)), timeout=1800)
    probed = 0
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        host = split_host(j.get("url", ""))
        if not host or not in_scope(host, scope, excl):
            continue
        db.set_host_meta(program["name"], host,
                         j.get("status_code"),
                         (j.get("title") or "")[:200],
                         ",".join(j.get("technologies", []) or [])[:300],
                         (j.get("host") or "")[:120],
                         bool(j.get("cdn")),
                         url=(j.get("url") or "")[:300])
        probed += 1
    return probed
