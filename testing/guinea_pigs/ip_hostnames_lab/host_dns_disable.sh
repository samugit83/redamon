#!/usr/bin/env bash
# Undo host_dns_enable.sh: the lab zones, ~lab-agency.gov and the reverse zone
# of 192.88.98.0/24 are no longer routed to the lab DNS. Same privileges as
# host_dns_enable.sh: without a password prompt only after the one-time polkit
# rule in testing/guinea_pigs/README.md. A missing bridge has nothing to revert.
set -euo pipefail

if ! id=$(docker network inspect -f '{{.Id}}' redamon_iphn_lab 2>/dev/null); then
    echo "[*][HostDns] redamon_iphn_lab does not exist: nothing to revert"
    exit 0
fi
BR="br-${id:0:12}"
if ! ip link show "$BR" >/dev/null 2>&1; then
    echo "[*][HostDns] $BR is gone: nothing to revert"
    exit 0
fi
resolvectl revert "$BR"
resolvectl flush-caches 2>/dev/null || true
echo "[*][HostDns] reverted the DNS settings of $BR (lab zones and ~lab-agency.gov no longer routed)"
