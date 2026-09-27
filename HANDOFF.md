# AutoBounty — GOAL / TODO / CHECKPOINT

**Purpose of this file:** any agent (human or AI) can pick up the task from here.
Read this first, then `README.md`, then check live state with the commands below.

---

## 🎯 GOAL

Build and operate an **autonomous passive-income machine** that earns bug bounty
rewards by continuously recon-scanning **authorized public bug bounty programs**,
triaging results, and producing submission-ready vulnerability reports — running
24/7 on this Termux/Android box at ~3 CPU threads.

Success criteria:
1. Pipeline runs unattended, self-healing, forever.
2. Recon coverage accumulates across cycles (never resets).
3. Real findings get triaged into professional reports in `reports/`.
4. Owner gets 15-minute Telegram progress reports incl. collected revenue.
5. **Honest accounting:** collected revenue is `$0.00` until a real payout lands.
   Estimated *potential* value is labeled separately and never mixed with collected.

---

## ✅ CHECKPOINT — state as of 2026-09-27 17:25 WIB

**Pipeline VERIFIED end to end** against a self-owned deliberately vulnerable
server (127.0.0.1:8899, `vulntest/server.py`):

**Live and running** (verified by `ps`):

| Component | PID | Log |
|---|---|---|
| supervisor (`run.sh`) | 31927 | `logs/supervisor.log` |
| autopilot | 31932 | `logs/autopilot.log` |
| sub-agent 1 (triage/draft/verify/research) | 32033 | `logs/agent-1.log` |
| sub-agent 2 | 32038 | `logs/agent-2.log` |
| sub-agent 3 | 32043 | `logs/agent-3.log` |

**Verified working (with evidence):**
- Toolchain: subfinder v2.16.0, dnsx, httpx, nuclei v3.11.1, katana built into
  `~/go/bin` (Go 1.27). Templates sparse-checked out to `~/nuclei-templates` (85M).
- Scope authorization gate: unit-tested (7/7 pass) — no host is touched unless it
  matches an explicit scope rule and no exclusion.
- Recon: subfinder on `tesla.com` → **1,647** in-scope hosts; `github.com` →
  **44,532**. DB currently holds **46,193** hosts across **13** programs.
- httpx probe: **429** probed → **352** live, metadata (status/title/tech) stored.
- Sub-agent job queue: end-to-end verified — a `research` job for Tesla completed,
  **20** in-scope LLM-suggested hosts added.
- LLM tiers healthy: `fast` (agnes-3.0-flash, ~1-7s) ✓, `deep` (NIM kimi-k3, ~92s) ✓,
  `image` (agnes-image-2.5-flash, ~11s) ✓.
- nuclei streaming output: fixed (see "Hard-won lessons") — findings now persist
  as they arrive rather than being lost on timeout.

**Current numbers:** findings = 2 (both lab/self-test, triaged as noise because
localhost), revenue collected = **$0.00**, jobs done = 28, hosts ≈ 57k,
programs = 13 enabled (SelfTest disabled, kept as evidence).

### End-to-end verification (2026-09-27)

- `vulntest/server.py` (self-owned, localhost) exposes `/.git/config` and `/.env`.
- `scan.scan_hosts` found BOTH: 🔴 HIGH `generic-env` (.env with AWS/DB/Stripe
  secrets) and 🟠 MEDIUM `git-config`.
- Sub-agents triaged and drafted: `reports/MEDIUM_127.0.0.1_git-config.md`
  (professional quality: CVSS rationale, copy-paste curl repro, CWE/OWASP refs).
- The triage layer correctly marked the localhost findings as **noise**
  (`127.0.0.1` = dev environment) — proof the noise filter exercises judgement.

**In flight:** autopilot cycle 1 — recon across all 13 programs (subfinder `-all`
is slow on large zones like github.com), then httpx probing, then nuclei batches.

---

## 🔧 Environment facts (do not re-discover these)

- Termux on Android, **no root**, no `/dev/tun`, **no `/tmp`** (read-only `/`).
- CPU cap: **3 threads** (project rule). Network I/O concurrency (httpx threads)
  is separate and set to 10.
- `~/.pi/agent/auth.json` holds keys: `agnes`, `nvidia`.
- Telegram bot token is in the env: **@supixxxbot**. First person to message the
  bot with a command becomes the owner (stored in `kv` table).
- NVIDIA NIM: only these chat models work on this account — `moonshotai/kimi-k3`,
  `nvidia/nemotron-3-super-120b-a12b`, `nvidia/nemotron-3.5-lightning-30b-a3b`,
  `z-ai/glm-5.3`, `z-ai/glm-5.3-flash`, `openai/gpt-oss-20b`.
  **`meta/muse-glimmer-30b` is NOT provisioned** — 404 on both chat and images
  endpoints. `deepseek-ai/deepseek-v4.1-flash` times out (~350s).
- **Local LLM removed by decision** — the Vulkan qwen2.5-1.5b ran at only
  ~8 tok/s, too slow to be useful. All inference is remote via `lib/llm.py`.

### Hard-won lessons (cost real time — read before touching tool wrappers)

1. **nuclei v3 flag changes:** `-json` is **gone** → use `-j`. `-templates-dir`
   is **gone** → use `-t <dir>`. `-no-interactsh` is **gone** → use `-ni`.
   Getting these wrong makes nuclei exit instantly with empty output.
2. **subfinder v2.16:** `-passive` flag removed (it is passive by default).
   `subfinder -d x -all -silent` yields ~915 hosts on tesla.com.
3. **The system `httpx` on Termux is the PYTHON HTTP client**, not ProjectDiscovery's.
   `lib/recon.py:tool()` resolves `~/go/bin/` first — never call bare `httpx`.
4. **pkill/self-match trap:** `pkill -f <pattern>` matches the shell running it
   whenever the pattern text appears in the command line (even with `[_]` tricks).
   Kill by **PID** from `ps -eo pid,args`.
5. **Background processes** only survive across tool calls if started with
   `setsid nohup ... < /dev/null & disown` in a command that returns fast.
6. **Buffered stdout disappears** when a process is killed by timeout. Always run
   long jobs with `python3 -u` and log to a file.
8. **nuclei tag names are NOT the directory names.** The template tag is
   `exposure` (singular), `vuln`, `misconfig` — while the directories are
   `http/exposures/`, `http/vulnerabilities/`, `http/misconfiguration/`.
   Filtering by `-tags exposures` loads 356 templates and **silently misses
   git-config** (tagged `exposure`). Verify real tags with `nuclei -tgl`.
   Also `dos`, `brute-force`, `intranet` are NOT valid tags (harmless in
   `-etags`, but they exclude nothing).
9. **nuclei `-l -` only probes ports 80/443 on bare hostnames.** Scan the exact
   live URL httpx discovered (scheme + port) — stored in `hosts.url` — or you
   will silently miss every service on a non-standard port.
10. **A streaming read loop blocks forever** if the child never exits; put the
    deadline watchdog *around* the read, not after it (see `scan.scan_hosts`).

---

## 📋 TODO — ordered by value

### ✅ Done this session
- [x] nuclei tag-name bug (the silent finding-killer) — fixed and verified.
- [x] nuclei v3 flag fixes (`-j`, `-t`, `-ni`).
- [x] Scan the exact live URL httpx found (`hosts.url`), not bare hostnames.
- [x] Streaming scan output so timeouts never lose findings.
- [x] SQLite WAL + busy_timeout for the 4-process fleet.
- [x] `ask_json` (temperature 0 + JSON extraction) — agnes-3.0-flash was
      leaking chain-of-thought and silently destroying structured output.
- [x] Revenue ledger (`revenue` table) + 15-min Telegram progress reports.
- [x] End-to-end verification against a self-owned vulnerable target.
- [x] Recon runs at most once per 12 h per program, not every cycle.

### Now / next
- [ ] **Confirm the first REAL (non-lab) finding.** After cycle 1 recon finishes,
      the scan phase runs with the corrected tags; watch for `[scan] 🔴/🟠 NEW`
      in `logs/autopilot.log` and a report appearing in `reports/`.
- [ ] **Throughput is the binding constraint.** ~6,237 templates at a program's
      polite rps means a 15-host batch takes most of the 1500 s window. If
      coverage stalls, either raise program `rps` in config (these are
      well-provisioned, WAF-fronted programs) or split the tag set across cycles
      (cycle A = `cve`, cycle B = `exposure,misconfig`, ...) so each run is a
      tractable subset.
- [ ] **Enqueue `research` jobs again after recon** — LLM-suggested in-scope
      hosts added 291 last time; re-run whenever new programs are added.

### Soon
- [ ] **Faster deep tier.** NIM kimi-k3 takes ~92s; consider
      `z-ai/glm-5.3-flash` for `verify` jobs to keep the queue moving.
- [ ] **Submission tracker:** extend `findings.status` with `submitted` +
      `program_report_id`, and add a `/submit <id>` Telegram command that stamps
      the report as sent to the program.
- [ ] **Dedupe across hosts:** same template on 50 hosts of one program should
      become ONE reportable finding (platform-wide misconfig).
- [ ] **Screenshot evidence** for web findings (katana is built; or
      `lib/llm.py:image()` for rendered visuals) to strengthen reports.

### Later / optional
- [ ] Add more authorized programs (Bugcrowd/Intigriti public programs) to
      `config.yaml` — each needs its policy URL and exact scope.
- [ ] Chaos-data integration (`projectdiscovery/chaos-data`) to bootstrap
      subdomains for matching programs instead of re-enumerating.
- [ ] A second income rail: the **@supixxxbot** AI digital-goods store (Telegram
      Stars checkout) using the same `lib/llm.py:image()` engine. Scope change —
      only pursue if bug bounty proves slow.

### Known risks
- [ ] Large zones (github.com 45k, shopify 46k, yahoo 55k, slack 39k hosts) make
      a full recon cycle long. `scan_batch: 15` means coverage accumulates; do
      NOT raise the batch without watching CPU and program rps limits.
- [ ] **Coverage may be incomplete per cycle** — with 6,237 templates a batch can
      hit the 1500 s timeout before every template runs. Streaming keeps partial
      results, but templates late in the order may get starved; the tag-rotation
      TODO above is the fix.
- [ ] `revenue` is $0.00 and will stay $0 until a human submits a triaged report
      and a payout lands. Log it with `/revenue <usd> <note>` in Telegram.
- [ ] The `.env`/`.git` findings on `127.0.0.1` are from the self-owned
      `vulntest/server.py` lab target — **pipeline evidence, not bounty
      earnings**. SelfTest is disabled in production scanning.

---

## 🕹️ Live commands (copy-paste)

```bash
cd ~/bb
# state
python3 -c "import sys;sys.path.insert(0,'lib');from db import DB;import jobs;d=DB('data/autobounty.db');jobs.ensure(d);print(d.stats());print(jobs.stats(d));print(d.revenue_total())"

# logs
tail -f logs/autopilot.log logs/agent-1.log logs/supervisor.log

# LLM health (both tiers + image)
python3 -u lib/llm.py

# restart the whole stack (safe: kills by PID, then relaunches)
for p in $(ps -eo pid,args|grep -E 'run.sh|autopilot.py|subagent.py'|grep -v grep|awk '{print $1}'); do kill -9 $p; done; sleep 3
setsid nohup bash run.sh > logs/supervisor.log 2>&1 < /dev/null & disown

# enqueue LLM research for every program
python3 -c "
import sys;sys.path.insert(0,'lib');sys.path.insert(0,'.')
import jobs, scope as s
from db import DB
cfg=s.load_config('config.yaml'); db=DB(cfg['runner']['state_db'])
for p in db.programs(): jobs.enqueue(db,'research',{'program':p['name']}); print('queued',p['name'])"
```

**Owner control:** message **@supixxxbot** → `/status /stats /findings /revenue
/pause /resume /scan`. Progress report auto-posts every 15 minutes.

---

## 💰 Revenue model — honest accounting

- `revenue` table records **only real collected payouts**, entered via
  `/revenue <usd> <note>` in Telegram.
- `estimate_value()` computes **potential** value of reviewed findings using
  conservative public-program bounties (critical $5k / high $1.5k / medium $400 /
  low $100). This is an estimate of *pipeline value*, never reported as collected.
- The 15-minute Telegram report always shows both lines separately.
