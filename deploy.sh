#!/usr/bin/env bash
# AutoBounty — Multi-platform deployment script
# Usage: ./deploy.sh [railway|fly|render|docker|vps]
# Prereqs: docker, git, and platform CLIs (railway, flyctl, etc.)

set -euo pipefail

REPO="https://github.com/yuhanbae/autobounty"
PROJECT="autobounty"

usage() {
  cat <<EOF
Usage: $0 [railway|fly|render|docker|vps|local]

  railway  - Deploy to Railway (needs RAILWAY_TOKEN or `railway login`)
  fly      - Deploy to Fly.io (needs FLY_API_TOKEN or `flyctl auth login`)
  render   - Deploy to Render (connect GitHub repo in dashboard)
  docker   - Build & run locally with docker compose
  vps      - Install systemd service on a VPS (needs sudo)
  local    - Run directly on this machine (Termux/VPS)

Environment variables (set in shell or .env):
  AGNES_API_KEY
  NVIDIA_API_KEY
  TELEGRAM_BOT_TOKEN
  TELEGRAM_CHAT_ID (optional, auto-captured from first bot message)
  RAILWAY_TOKEN      (Railway project token)
  FLY_API_TOKEN      (Fly.io personal access token)
  GITHUB_TOKEN       (for GitHub Actions secrets)
EOF
}

# Load .env if present
if [[ -f .env ]]; then
  set -a; source .env; set +a
fi

deploy_railway() {
  echo "=== Deploying to Railway ==="
  if [[ -z "${RAILWAY_TOKEN:-}" ]]; then
    echo "RAILWAY_TOKEN not set. Run 'railway login' or set RAILWAY_TOKEN env var."
    exit 1
  fi
  railway up --detach
  echo "Deployed. View logs: railway logs"
}

deploy_fly() {
  echo "=== Deploying to Fly.io ==="
  if [[ -z "${FLY_API_TOKEN:-}" ]]; then
    echo "FLY_API_TOKEN not set. Run 'flyctl auth login' or set FLY_API_TOKEN."
    exit 1
  fi
  flyctl deploy --dockerfile hf-space/Dockerfile --app "$PROJECT" --region auto
  echo "Deployed. View logs: flyctl logs -a $PROJECT"
}

deploy_render() {
  echo "=== Render Deployment ==="
  echo "1. Go to https://dashboard.render.com"
  echo "2. New → Web Service → Connect repo: $REPO"
  echo "3. Runtime: Docker | Plan: Free"
  echo "4. Add env vars: AGNES_API_KEY, NVIDIA_API_KEY, TELEGRAM_BOT_TOKEN"
  echo "5. Deploy"
}

deploy_docker() {
  echo "=== Local Docker Compose ==="
  docker compose -f docker-compose.yml up -d --build
  echo "Running. Logs: docker compose logs -f"
}

deploy_vps() {
  echo "=== Installing systemd service on VPS ==="
  sudo cp autobounty.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now autobounty
  echo "Service started. Logs: journalctl -u autobounty -f"
}

deploy_local() {
  echo "=== Running locally (Termux/VPS) ==="
  bash run.sh
}

case "${1:-help}" in
  railway) deploy_railway ;;
  fly) deploy_fly ;;
  render) deploy_render ;;
  docker) deploy_docker ;;
  vps) deploy_vps ;;
  local) deploy_local ;;
  *) usage; exit 1 ;;
esac