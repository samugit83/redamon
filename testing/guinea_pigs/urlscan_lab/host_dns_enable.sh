#!/usr/bin/env bash
# Route ONLY the lab zones to the lab DNS (192.88.97.53), on the lab bridge link only.
# With UL_TAKEOVER_DNS=1, also ~herokuapp.com for run T: that changes how the WHOLE
# host resolves *.herokuapp.com until host_dns_disable.sh (down.sh always runs it).
#
# Recon and its scan containers use network_mode=host and resolve through the
# host's systemd-resolved stub (127.0.0.53); dnspython ignores /etc/hosts. The
# per-link setting is lost when the bridge is recreated, so up.sh runs this
# after every start. polkit lets the user of an active local session change
# per-link DNS without sudo; over SSH it needs sudo, which this script never
# tries on its own.
set -euo pipefail

BR="br-$(docker network inspect -f '{{.Id}}' redamon_uslab | cut -c1-12)"
# NetworkManager adopts Docker bridges as "connected (externally)" and can push
# its own (empty) DNS for the link to resolved, silently undoing the lines
# below. Runtime only: Docker owns this bridge, and NM forgets it on restart.
if command -v nmcli >/dev/null 2>&1; then
    nmcli device set "$BR" managed no 2>/dev/null || true
fi
domains=('~uslab.test' '~uslab-other.test')
if [ "${UL_TAKEOVER_DNS:-0}" = "1" ]; then
    domains+=('~herokuapp.com')
fi
resolvectl dns "$BR" 192.88.97.53
resolvectl domain "$BR" "${domains[@]}"
# Never the default route: every other name keeps using the normal resolvers.
resolvectl default-route "$BR" false
# The zones are unsigned and .test has no delegation, so DNSSEC validation on
# this link could only turn lab answers into failures.
resolvectl dnssec "$BR" no
echo "[*] $BR: DNS 192.88.97.53 for ${domains[*]}"

for _ in $(seq 1 10); do
    if resolvectl query app.uslab.test 2>/dev/null | grep -q '192.88.97.10'; then
        echo "[+] app.uslab.test resolves to 192.88.97.10 through the host resolver"
        if [ "${UL_TAKEOVER_DNS:-0}" = "1" ]; then
            if resolvectl query brokenapp.herokuapp.com 2>/dev/null | grep -q '192.88.97.10'; then
                echo "[+] run T: brokenapp.herokuapp.com resolves to the lab (192.88.97.10)"
            else
                echo "[!] run T: brokenapp.herokuapp.com does not resolve to the lab" >&2
                exit 1
            fi
        fi
        exit 0
    fi
    sleep 1
done
echo "[!] app.uslab.test does not resolve through the host resolver" >&2
exit 1
