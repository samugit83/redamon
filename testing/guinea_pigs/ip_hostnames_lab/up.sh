#!/usr/bin/env bash
# Bring the IP-hostnames lab up:
#   recon image prefix check -> gen_lab.py -> urlscan fixture check -> compose up
#   -> intra on redamon-network (address read back into the zone) -> routing gate
#   -> smoke checks from INSIDE the lab network -> capture check.
#
#   ./up.sh                 reuse generated/ (certificates kept), re-render zones and fixtures
#   ./up.sh --regen-certs   new CA and certificates
#
# Idempotent. Never touches the redamon-* containers and never changes the host
# DNS: host_dns_enable.sh is a separate step that needs the maintainer's OK
# (README, "Host DNS").
set -euo pipefail
cd "$(dirname "$0")"

gen_args=()
[ "${1:-}" = "--regen-certs" ] && gen_args+=(--regen-certs)

# recon's SSRF guard (is_url_safe_to_probe) drops private and reserved
# addresses: the lab is useless unless the recon image's Python calls it global.
if ! docker image inspect redamon-recon >/dev/null 2>&1; then
    echo "[!][Up] the redamon-recon image is missing: build the stack first" >&2
    exit 1
fi
docker run --rm --entrypoint python redamon-recon -c '
import ipaddress, sys
bad = [a for a in ("192.88.98.10", "192.88.98.12", "192.88.98.13", "192.88.98.40", "192.88.98.99")
       if not ipaddress.ip_address(a).is_global or ipaddress.ip_address(a).is_private
       or ipaddress.ip_address(a).is_reserved]
sys.exit("[!][Up] not global in the recon image: %s" % bad if bad else 0)'
echo "[+][Up] 192.88.98.0/24 is global for the recon image's Python"

python3 -I gen_lab.py "${gen_args[@]}"
python3 -I ../urlscan_lab/fake_urlscan/check_fixtures.py \
    --fixtures generated/fixtures/visits.json --meta generated/fixtures/meta.json

export IPHN_UID="$(id -u)" IPHN_GID="$(id -g)"
docker compose -p iphn up -d --build

# E10's private target lives on redamon-network, whose subnet compose does not
# pin and where other labs hold fixed addresses: read the address Docker gave
# it and write it into the zone, never a hard-coded one.
intra_ip=""
if docker network inspect redamon-network >/dev/null 2>&1; then
    docker compose -p iphn --profile intra up -d intra
    for _ in $(seq 1 20); do
        intra_ip=$(docker network inspect redamon-network \
            -f '{{range .Containers}}{{if eq .Name "iphn-intra"}}{{.IPv4Address}}{{end}}{{end}}' | cut -d/ -f1)
        [ -n "$intra_ip" ] && break
        sleep 1
    done
    [ -n "$intra_ip" ] || { echo "[!][Up] iphn-intra has no address on redamon-network" >&2; exit 1; }
    echo "[+][Up] iphn-intra on redamon-network: $intra_ip"
else
    echo "[-][Up] redamon-network does not exist (RedAmon stack down): no intra target, row E10 unavailable"
fi
python3 -I gen_lab.py --dns-only --intra-ip "$intra_ip"
# A re-rendered zone is reloaded within 5 s anyway; the restart makes it now.
docker restart iphn-dns >/dev/null

if ip route get 192.88.98.10 | grep -q ' dev br-'; then
    echo "[+][Up] routing gate: $(ip route get 192.88.98.10 | head -1)"
else
    echo "[!][Up] 192.88.98.10 does not route through the lab bridge. Do NOT scan." >&2
    exit 1
fi

moved=$(python3 -c 'import json; print(json.load(open("generated/lab.json"))["moved"])')
smoke=(docker run --rm -i --network redamon_iphn_lab --ip 192.88.98.250
       -e INTRA_IP="$intra_ip" -e MOVED="$moved" iphn-tools:local sh -s)
ready=0
for _ in $(seq 1 20); do
    if docker run --rm --network redamon_iphn_lab iphn-tools:local \
            sh -c 'dig +short +time=1 +tries=1 @192.88.98.53 app.example-a.test A | grep -qx 192.88.98.10 \
                   && curl -sk -m 2 -o /dev/null https://192.88.98.10/ && curl -s -m 2 -o /dev/null http://192.88.98.30/__lab/health \
                   && curl -sk -m 2 -o /dev/null https://192.88.98.40/'; then
        ready=1; break
    fi
    sleep 1
done
[ "$ready" = 1 ] || { echo "[!][Up] the lab services do not answer" >&2; exit 1; }

"${smoke[@]}" < smoke.sh

if [ -n "$intra_ip" ]; then
    got=$(docker run --rm --network redamon-network iphn-tools:local \
          curl -sk -m 5 --resolve "intra.example-a.test:443:$intra_ip" https://intra.example-a.test/ | tr -d '\r\n')
    [ "$got" = "VHOST=intra.example-a.test" ] || { echo "[!][Up] intra answered '$got'" >&2; exit 1; }
    echo "[+][Smoke] intra.example-a.test on $intra_ip -> $got"
fi

# The capture: the smoke script's marked request to the outsider must be in it.
for _ in $(seq 1 10); do
    n=$(python3 -I iphn_lab.py pcap-count generated/pcap/outsider.pcap --src 192.88.98.250 --dst 192.88.98.99)
    [ "$n" -gt 0 ] && break
    sleep 1
done
[ "$n" -gt 0 ] || { echo "[!][Up] the outsider capture recorded no packet from the smoke client" >&2; exit 1; }
h=$(python3 -I iphn_lab.py hits-count iphn-outsider --client 192.88.98.250)
echo "[+][Smoke] outsider capture: $n packet(s) from 192.88.98.250; hit log: $h request(s)"

br="br-$(docker network inspect -f '{{.Id}}' redamon_iphn_lab | cut -c1-12)"
echo "[+][Up] lab up on bridge $br (192.88.98.0/24)."
echo "    Next (needs the maintainer's OK: it changes how the host resolves the lab zones):"
echo "      ./host_dns_enable.sh"
echo "    then: python3 e2e_ip_hostnames.py --plan    and    python3 e2e_ip_hostnames.py --rows E0"
