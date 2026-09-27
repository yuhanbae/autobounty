#!/usr/bin/env bash
# Serve the local LLM on the Mali-G615 GPU via the llama.cpp Vulkan backend.
# The `vulkan` tier in lib/llm.py talks to this; if it is not running, the tier
# silently falls through to the remote providers, so nothing breaks without it.
#
# Benchmark on this device (qwen2.5-1.5b Q4_K_M, -ngl 99):
#   prompt processing 3.66 tok/s | generation 8.17 tok/s
# Competitive only for SHORT jobs (triage classification), not report drafting.
set -euo pipefail
MODEL="${1:-$HOME/qwen2.5-1.5b-q4km.gguf}"
PORT="${2:-8080}"
exec llama-server -m "$MODEL" -ngl 99 -c 4096 --port "$PORT" \
     --no-display-prompt --cache-reuse 256
