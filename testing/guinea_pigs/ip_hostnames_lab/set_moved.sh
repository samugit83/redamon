#!/usr/bin/env bash
# Point moved.example-a.test at a target (.10) or at the outsider (.99): rows E8
# (live re-check between two runs) and E21 (agent replay after a DNS change).
#
#   ./set_moved.sh 10|99
#
# Re-renders the zones with a higher SOA serial (CoreDNS's file plugin reloads
# only then, within 5 s) and waits until the lab DNS answers the new address.
# The record's TTL is 1 s, so the host resolver follows within a second; a
# `resolvectl flush-caches` makes it immediate.
set -euo pipefail
cd "$(dirname "$0")"

case "${1:-}" in
    10|99) target=$1 ;;
    *) echo "usage: $0 10|99" >&2; exit 2 ;;
esac
if ! ip route get 192.88.98.10 | grep -q ' dev br-'; then
    echo "[!][Moved] 192.88.98.10 does not route through a docker bridge: the lab is down" >&2
    exit 1
fi

python3 -I gen_lab.py --dns-only --moved "$target"
for _ in $(seq 1 15); do
    got=$(docker run --rm --network redamon_iphn_lab iphn-tools:local \
          dig +short +time=1 +tries=1 @192.88.98.53 moved.example-a.test A || true)
    if [ "$got" = "192.88.98.$target" ]; then
        echo "[+][Moved] moved.example-a.test -> 192.88.98.$target (lab DNS)"
        exit 0
    fi
    sleep 1
done
echo "[!][Moved] the lab DNS still answers '$got' for moved.example-a.test" >&2
exit 1
