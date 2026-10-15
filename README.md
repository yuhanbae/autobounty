# AutoBounty — Autonomous Bug Bounty Pipeline

An always-on, autonomous vulnerability-research pipeline that hunts for
reportable findings in **authorized public bug bounty programs** and produces
submission-ready reports. Runs 24/7 on a Termux/Android box.

## How it earns

Public bug bounty programs (HackerOne, Bugcrowd, GitHub Security) may pay for
confirmed, in-scope vulnerabilities. AutoBounty automates recon, non-destructive
scanning, triage, and report drafts. A human must verify policy scope, reproduce
each issue, and submit it. Acceptance and payout are never guaranteed; this is
not passive or predictable income.

## Architecture

```
                 ┌─────────────────────────────────────────────┐
                 │                 AUTOPILOT                    │
                 │  recon -> scan -> enqueue(triage) -> report  │
                 └───────────────┬─────────────────────────────┘
                                 │ SQLite job queue
       ┌────────────┬────────────┼────────────┬─────────────┐
   sub-agent 1   sub-agent 2   sub-agent 3   (scale out)
       triage       draft         verify
       research     (report)      (deep NIM)
```

- **autopilot.py** — the loop. Recon (subfinder → dnsx → httpx) over declared
  program scope, nuclei scanning in bounded batches (coverage accumulates across
  cycles), then enqueues LLM work. Also runs a Telegram
  bot so the owner can control it: `/status /stats /findings /pause /resume /scan`.
- **subagent.py** — LLM workers that pull jobs from the queue, so scanning
  never blocks on model latency. Run several in parallel.
- **lib/scope.py** — strict authorization gate. **No host is ever touched**
  unless it matches an explicit in-scope rule and no exclusion rule.
- **lib/recon.py** — ProjectDiscovery tool wrappers (subfinder/dnsx/httpx).
- **lib/scan.py** — nuclei runner. Results are **streamed** and persisted as
  they arrive, so a timeout never loses work.
- **lib/triage.py** — rule-based noise filter + LLM classification + report
  drafting.
- **lib/llm.py** — tiered model access with automatic fallthrough:
  - `fast` → agnes-3.0-flash (~1-7s) — bulk triage & report drafting
  - `deep` → NVIDIA NIM kimi-k3 / nemotron (~45-90s) — high/critical verification
  - `image` → agnes-image-2.5-flash — evidence/asset rendering
- **lib/report.py** — professional finding reports + a rolling INDEX.md +
  findings.json for submission tracking.
- **lib/notify.py** — Telegram alerts for new high/critical findings.

## Toolchain

ProjectDiscovery tools built from source (Go 1.27):

```
subfinder v2.16.0   dnsx   httpx   nuclei v3.11.1   katana
templates: ~/nuclei-templates (sparse checkout of http/dns/ssl/network/code/
           cves/vulnerabilities/exposures/misconfiguration)
```

## Ethics / legality

- Only programs with an explicit public policy permitting security research.
- Every request is scope-checked against the program's declared scope first.
- Non-destructive template set only (`-etags intrusive,dos,brute-force,intranet`).
- Rate-limited per program; respects a global CPU ceiling of 3 threads.
- No OAST callbacks (`-ni`), so nothing phones home to third parties.

## Operating

```bash
bash run.sh                     # supervisor: autopilot + 3 sub-agents, forever
tail -f logs/autopilot.log      # main loop
tail -f logs/agent-*.log        # sub-agent LLM workers
```

Then message **@supixxxxbot** on Telegram (first person to send a command
becomes the owner) with `/status` to watch it work and `/findings` to list
triaged findings. Reports land in `reports/` as they are produced.

## GitHub Actions

The scheduled workflow processes one due program's recon and one live host's
scan per cycle to keep runs below the Actions timeout. It caches ProjectDiscovery
tools and the Nuclei template checkout; passive enumeration is time-bounded per
apex so one slow source cannot monopolize a run. Configure `AUTOBOUNTY_STATE_KEY` as a
GitHub Actions secret before enabling the workflow; the workflow encrypts the
state and report archive and commits only `data/state.enc`. Findings and scanner
logs are not printed to public workflow logs. Keep the key private and back it
up securely; losing it makes the saved state unrecoverable.

The workflow does not submit reports. Review each report against the program's
current policy, manually reproduce the issue, remove secrets or personal data,
and submit through the program's official platform.

## Findings index

`reports/INDEX.md` — severity-sorted list of every triaged finding with a link
to its full report. `reports/findings.json` is the machine-readable version for
submission tracking.
