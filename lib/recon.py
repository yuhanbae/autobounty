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


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _probe_chunk(httpx, cfg, hosts, timeout):
    """httpx one chunk; return list of parsed json records (may be partial)."""
    cmd = ([httpx, "-l", "-", "-json", "-rl", str(cfg["recon"].get("httpx_rps", 40)),
            "-threads", str(cfg["recon"].get("httpx_threads", 10))]
           + cfg["recon"].get("httpx_args", []))
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
    except Exception as e:
        print("[probe] spawn failed:", e, flush=True)
        return []
    recs = []
    deadline = time.time() + timeout
    killed = False
    try:
        proc.stdin.write("\n".join(hosts) + "\n")
        proc.stdin.close()
        for line in proc.stdout:                  # STREAM: results survive a timeout
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                recs.append(json.loads(line))
            except Exception:
                pass
            if not killed and time.time() > deadline:
                killed = True
                proc.kill()                      # stop the crawl, keep what we have
    except Exception:
        pass
    finally:
        try:
            proc.kill()
        except Exception:
            pass
    return recs


def _resolve_chunk(dnsx, cfg, hosts, timeout):
    """dnsx one chunk; returns resolving hosts, or None if the tool failed / timed out.
    Never blocks probing: caller falls back to probing the raw host list."""
    if not dnsx:
        return None
    out, rc = run([dnsx] + cfg["recon"].get("dnsx_args", []) + ["-l", "-"],
                  stdin_data="\n".join(hosts), timeout=timeout)
    if rc == 124 or not out.strip():
        return None
    return {split_host(l.split()[0]) for l in out.splitlines() if l.strip()}


def resolve_and_probe(db, program, cfg, max_hosts):
    """dnsx resolve -> httpx probe, in CHUNKS so a slow/dead batch can never
    throw away the whole program's progress (that treadmill stalled the pipeline
    for 2 days: one timeout = all output discarded = probed=0 forever)."""
    scope = json.loads(program["scope"])
    excl = json.loads(program["exclusions"])
    hosts = [h["host"] for h in db.all_hosts(program["name"])][:max_hosts]
    hosts = [h for h in hosts if in_scope(h, scope, excl)]
    if not hosts:
        return 0

    httpx = tool("httpx")
    if not httpx:
        print("[probe] httpx unavailable", flush=True)
        return 0
    dnsx = tool("dnsx")

    chunk_n = int(cfg["recon"].get("probe_chunk", 200))
    per_host_budget = 1.6 / max(1, int(cfg["recon"].get("httpx_rps", 40)))
    probed_hosts = set()
    for i, chunk in enumerate(_chunks(hosts, chunk_n)):
        # dnsx is a HINT only: on timeout we probe the raw chunk (httpx resolves).
        alive = _resolve_chunk(dnsx, cfg, chunk, timeout=120)
        targets = sorted({h for h in chunk if alive is None or h in alive} or chunk)
        if not targets:
            continue
        timeout = max(120, int(len(targets) * per_host_budget) + 60)
        recs = _probe_chunk(httpx, cfg, targets, timeout)
        for j in recs:
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
            probed_hosts.add(host)
        print(f"[probe] {program['name']}: chunk {i + 1} "
              f"({len(targets)} targets -> {len(probed_hosts)} live so far)", flush=True)
    return len(probed_hosts)
