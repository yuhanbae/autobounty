# AutoBounty — Deployment Guide

## Quick Start (Any Platform)

```bash
# 1. Clone
git clone https://github.com/yuhanbae/autobounty
cd autobounty

# 2. Configure
cp .env.example .env
# Edit .env with your API keys

# 3. Deploy (choose one)
./deploy.sh railway   # Railway (recommended, free tier)
./deploy.sh fly       # Fly.io
./deploy.sh docker    # Local Docker
./deploy.sh vps       # Systemd on VPS
./deploy.sh local     # Run directly (Termux/VPS)
```

---

## Platform Quick Reference

| Platform | Free Tier | Docker | Persistent | Setup Time |
|----------|-----------|--------|------------|------------|
| **Railway** | 500 hrs/mo | ✅ | ✅ | 2 min |
| **Fly.io** | 3 VMs free | ✅ | ✅ | 3 min |
| **Render** | 750 hrs/mo | ✅ | ❌ sleeps | 3 min |
| **Oracle Cloud** | Always free | ✅ | ✅ | 10 min |
| **VPS + systemd** | $3-5/mo | ✅ | ✅ | 5 min |

---

## Railway (Recommended)

```bash
# 1. Install CLI
curl -fsSL https://railway.app/install.sh | bash
export PATH="$HOME/.railway/bin:$PATH"

# 3. Deploy
export RAILWAY_TOKEN="your_token"
./deploy.sh railway
```

**Set variables in Railway dashboard:**
- `AGNES_API_KEY`
- `NVIDIA_API_KEY`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID` (after messaging bot)
- `GIT_REPO_URL=https://x-access-token:<GH_PAT>@github.com/yuhanbae/autobounty`

---

## Fly.io

```bash
# 1. Install CLI
curl -L https://fly.io/install.sh | sh
export PATH="$HOME/.fly/bin:$PATH"

# 2. Authenticate
flyctl auth login  # or set FLY_API_TOKEN

# 3. Deploy
flyctl launch --dockerfile hf-space/Dockerfile --name autobounty
flyctl secrets set AGNES_API_KEY=... NVIDIA_API_KEY=... TELEGRAM_BOT_TOKEN=...
flyctl deploy
```

---

## Local / VPS (systemd)

```bash
# 1. Clone & configure
git clone https://github.com/yuhanbae/autobounty
cd autobounty
cp .env.example .env
# edit .env

# 3. Install as systemd service (needs sudo)
sudo cp autobounty.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now autobounty

# 4. Monitor
journalctl -u autobounty -f
```

---

## Docker Compose (Any Docker Host)

```bash
docker compose up -d --build
docker compose logs -f
```

---

## Required Secrets

| Variable | Source | Purpose |
|----------|--------|---------|
| `AGNES_API_KEY` | apihub.agnes-ai.com | Image/video + LLM |
| `NVIDIA_API_KEY` | integrate.api.nvidia.com | Deep LLM tier |
| `TELEGRAM_BOT_TOKEN` | @BotFather | Notifications & control |
| `TELEGRAM_CHAT_ID` | Auto-captured | Owner notifications |
| `RAILWAY_TOKEN` / `FLY_API_TOKEN` | Platform dashboards | Deployment |
| `GITHUB_TOKEN` | GitHub Settings | Actions secrets, git push |

---

## Telegram Bot Setup

1. Message `@BotFather` → `/newbot` → get token
2. Add token to `.env` as `TELEGRAM_BOT_TOKEN`
3. **Message `@supixxxxbot` once** (any text) → becomes owner
4. Commands: `/status`, `/stats`, `/findings`, `/revenue`, `/pause`, `/resume`, `/scan`

---

## Verification

```bash
# Check logs
docker compose logs -f autopilot
# or
journalctl -u autobounty -f

# Verify pipeline
python3 -c "
import sys; sys.path.insert(0,'lib')
from db import DB
d=DB('data/autobounty.db')
print('Hosts:', d.conn.execute('select count(*) from hosts').fetchone()[0])
print('Live:', d.conn.execute('select count(*) from hosts where status is not null and status<500').fetchone()[0])
print('Findings:', d.conn.execute('select count(*) from findings').fetchone()[0])
"
```

---

## Revenue Tracking

```bash
# Log a payout (via Telegram bot)
/revenue 1500 "GitLab RCE CVE-2024-XXXX"

# Check collected
/revenue
```

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  GitHub Actions │────▶│   GitHub Repo    │◀───│  Railway / Fly  │
│  (scheduled)    │     │  (state.json)    │    │  (persistent)   │
└─────────────────┘     └────────┬─────────┘    └─────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
             ┌─────────────┐           ┌─────────────┐
             │  Sub-agent  │           │  Sub-agent  │
             │  (triage)   │           │  (draft)    │
             └─────────────┘           └─────────────┘
                    │                         │
                    └───────────┬─────────────┘
                                ▼
                       ┌─────────────────┐
                       │   Reports Dir   │
                       │  (INDEX.md,     │
                       │   *.md, JSON)   │
                       └─────────────────┘
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `railway: command not found` | `export PATH="$HOME/.railway/bin:$PATH"` |
| `flyctl auth login` fails | Set `FLY_API_TOKEN` env var |
| `docker compose up` fails | Check `.env` has all required keys |
| No Telegram alerts | Message `@supixxxxbot` once first |
| No findings yet | Normal — first real hit takes days/weeks |

---

## Security

- `.env` is in `.gitignore` — never committed
- GitHub Actions secrets store keys securely
- `data/autobounty.db` is gitignored; only `state.json` committed
- All external calls use TLS

---

## License

MIT — Use freely for authorized bug bounty hunting only.