#!/usr/bin/env bash
# AutoBounty supervisor: keeps the autopilot + N sub-agents alive forever.
# Usage: bash run.sh            (detached; logs to logs/)
set -u
cd "$(dirname "$0")"
export PATH="$HOME/go/bin:$PATH"
# Dedicated bot for autobounty reports (falls back to TELEGRAM_BOT_TOKEN)
export AUTOBOUNTY_BOT_TOKEN="${AUTOBOUNTY_BOT_TOKEN:-8921167672:AAFBjdlPlGgnBfJ2uCaAIE8ysh0aIpdOPHc}"
LOGS=logs
mkdir -p "$LOGS"

AGENTS=${AGENTS:-3}
PROCS=()

start() {  # start <type> <logfile> <args...>
  local type="$1" log="$2"; shift 2
  setsid nohup "$@" > "$LOGS/$log" 2>&1 < /dev/null &
  disown
  PROCS+=("$type:$!")
  echo "[supervisor] started $type pid $! -> $LOGS/$log"
}

is_alive() { kill -0 "$1" 2>/dev/null; }

echo "[supervisor] $(date) — launching AutoBounty (1 autopilot + $AGENTS sub-agents)"
start autopilot  autopilot.log python3 -u autopilot.py
sleep 3
for i in $(seq 1 "$AGENTS"); do
  start "agent-$i" "agent-$i.log" python3 -u subagent.py "agent-$i" triage draft verify research
  sleep 1
done

echo "[supervisor] all launched; watching"
while true; do
  sleep 60
  NEW=()
  for p in "${PROCS[@]}"; do
    type="${p%%:*}"; pid="${p##*:}"
    if is_alive "$pid"; then
      NEW+=("$p")
    else
      echo "[supervisor] $type (pid $pid) DIED — restarting"
      case "$type" in
        autopilot) start autopilot autopilot.log python3 -u autopilot.py ;;
        agent-*)   start "$type" "$type.log" python3 -u subagent.py "$type" triage draft verify research ;;
      esac
    fi
  done
  PROCS=("${NEW[@]}")
done
