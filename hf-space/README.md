---
title: AutoBounty Runner
emoji: 🛰️
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 8080
pinned: false
license: mit
---

# AutoBounty — HuggingFace Space runner

A free, persistent compute node for the [AutoBounty](https://github.com/yuhanbae/autobounty)
autonomous bug-bounty pipeline. This Space runs the autopilot loop in parallel with
the GitHub Actions runner and the local Termux box.

## How to deploy

1. Create a new Space (SDK: **Docker**).
2. Set these Space **secrets** (Repository → Settings → Secrets and variables):
   - `AGNES_API_KEY`
   - `NVIDIA_API_KEY`
   - `TELEGRAM_BOT_TOKEN`
   - `HF_EXTRAGIT` — a clone URL with an embedded token for the state repo,
     e.g. `https://x-access-token:<PAT>@github.com/yuhanbae/autobounty`
3. Copy the contents of this directory into the Space repo.
4. Rebuild. The Space pulls accumulated state from the GitHub repo on build,
   runs the autopilot loop forever, and pushes findings back.

## Why a Space

Free persistent CPU compute that supplements the GitHub Actions runners. All three
nodes (Actions / Space / Termux) share state through the git repo, so coverage
accumulates in parallel and no node is a single point of failure.
