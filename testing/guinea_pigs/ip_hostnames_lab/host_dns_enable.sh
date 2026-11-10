#!/usr/bin/env bash
# Route ONLY the lab zones to the lab DNS (192.88.98.53), on the lab bridge link only:
#   ~example-a.test ~example-b.test ~lab-c.example ~lab-agency.gov ~98.88.192.in-addr.arpa
# lab-agency.gov is a .gov name: while this is in force the WHOLE host resolves
# it (and the reverse zone of 192.88.98.0/24) from the lab, until
# host_dns_disable.sh (down.sh runs it).
#
# Recon and its scan containers use network_mode=host and resolve through the
# host's systemd-resolved stub (127.0.0.53); dnspython ignores /etc/hosts. The
# per-link setting is lost when the bridge is recreated: run this again after
# every ./up.sh that recreated the network. polkit lets the user of an active
# local session change per-link DNS without sudo; over SSH it needs sudo, which
# this script never tries on its own.
set -euo pipefail

if ! ip route get 192.88.98.10 | grep -q ' dev br-'; then
    echo "[!][HostDns] 192.88.98.10 does not route through a docker bridge: run ./up.sh first" >&2
    exit 1
fi
BR="br-$(docker network inspect -f '{{.Id}}' redamon_iphn_lab | cut -c1-12)"
# NetworkManager adopts Docker bridges as "connected (externally)" and can push
# its own (empty) DNS for the link to resolved, silently undoing the lines
# below. Runtime only: Docker owns this bridge, and NM forgets it on restart.
if command -v nmcli >/dev/null 2>&1; then
    nmcli device set "$BR" managed no 2>/dev/null || true
fi
domains=('~example-a.test' '~example-b.test' '~lab-c.example' '~lab-agency.gov' '~98.88.192.in-addr.arpa')
resolvectl dns "$BR" 192.88.98.53
resolvectl domain "$BR" "${domains[@]}"
# Never the default route: every other name keeps using the normal resolvers.
resolvectl default-route "$BR" false
# The zones are unsigned and .test has no delegation, so DNSSEC validation on
# this link could only turn lab answers into failures.
resolvectl dnssec "$BR" no
resolvectl flush-caches 2>/dev/null || true
echo "[*][HostDns] $BR: DNS 192.88.98.53 for ${domains[*]}"

ok=0
for _ in $(seq 1 10); do
    fwd=$(resolvectl query app.example-a.test 2>/dev/null || true)
    rev=$(resolvectl query 192.88.98.10 2>/dev/null || true)
    gov=$(resolvectl query portal.lab-agency.gov 2>/dev/null || true)
    if echo "$fwd" | grep -q '192.88.98.10' \
            && echo "$rev" | grep -q 'web.example-a.test' && echo "$rev" | grep -q 'app.example-a.test' \
            && echo "$gov" | grep -q '192.88.98.10'; then
        ok=1; break
    fi
    sleep 1
done
if [ "$ok" = 1 ]; then
    echo "[+][HostDns] app.example-a.test -> 192.88.98.10 through the host resolver"
    echo "[+][HostDns] 192.88.98.10 -> web.example-a.test and app.example-a.test (both PTRs)"
    echo "[+][HostDns] portal.lab-agency.gov -> 192.88.98.10 (the .gov fixture stays in the lab)"
    exit 0
fi
echo "[!][HostDns] the lab names do not resolve through the host resolver:" >&2
echo "$fwd" "$rev" "$gov" | sed 's/^/    /' >&2
exit 1
