#!/usr/bin/env bash
# Undo host_dns_enable.sh, run T's ~herokuapp.com included (same privileges:
# an active local session, or sudo). A missing bridge has nothing to revert.
set -euo pipefail

if ! id=$(docker network inspect -f '{{.Id}}' redamon_uslab 2>/dev/null); then
    echo "[*] redamon_uslab does not exist: nothing to revert"
    exit 0
fi
BR="br-${id:0:12}"
if ! ip link show "$BR" >/dev/null 2>&1; then
    echo "[*] $BR is gone: nothing to revert"
    exit 0
fi
resolvectl revert "$BR"
echo "[*] reverted the DNS settings of $BR (lab zones and ~herokuapp.com no longer routed)"
