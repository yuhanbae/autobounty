#!/usr/bin/env bash
# Autonomous bug-bounty toolchain install (ProjectDiscovery). Detached-safe.
set -euxo pipefail
cd "$HOME"
export GOFLAGS=-mod=mod
for repo in \
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
  github.com/projectdiscovery/httpx/cmd/httpx@latest \
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
  github.com/projectdiscovery/katana/cmd/katana@latest ; do
    echo "[install] $repo"
    go install -v "$repo" || echo "[FAIL] $repo"
done
echo "[done] installs"
# templates
if [[ ! -d nuclei-templates/.git ]]; then
  rm -rf nuclei-templates
  git clone --depth 1 --filter=blob:none --sparse https://github.com/projectdiscovery/nuclei-templates.git
  cd nuclei-templates && git sparse-checkout set http dns ssl network code cves vulnerabilities exposures misconfiguration
fi
echo "[done] all"
