#!/usr/bin/env bash
# Bring the nested-wildcard lab up: shared network, certificates, containers.
# Idempotent. The host DNS hookup is separate (host_dns_enable.sh).
set -euo pipefail
cd "$(dirname "$0")"

NET=redamon_sc_lab

if ! docker network inspect "$NET" >/dev/null 2>&1; then
    # The supply-chain compose project owns this network. A plain
    # `docker network create` would lack its compose labels, and that project
    # would then refuse the network ("incorrect label") and break its harness.
    echo "[*] Creating $NET through the supply_chain_target compose project"
    docker compose -f ../supply_chain_target/docker-compose.yml up --no-start
fi

mkdir -p certs
gen_cert() {
    local name=$1 cn=$2 san=$3
    if [ -s "certs/$name.crt" ] && [ -s "certs/$name.key" ]; then
        return
    fi
    echo "[*] Generating certs/$name.crt"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 -sha256 \
        -subj "/CN=$cn/O=RedAmon nwlab" \
        -addext "subjectAltName=$san" \
        -keyout "certs/$name.key" -out "certs/$name.crt" 2>/dev/null
    # nginx's master reads the key as root, but the bind mount is read-only and
    # owned by the invoking user, so make it readable inside the container.
    chmod 0644 "certs/$name.key"
}

# web1 deliberately omits the apex, cdn, js-only.v2.api and the eu.corp names:
# an ENUMERATE *.api group may learn only v1/v2/admin.v1/internal.v1 from it,
# and an EXACT group must inject nothing.
gen_cert web1 api.nwlab.test \
    "DNS:api.nwlab.test,DNS:v1.api.nwlab.test,DNS:v2.api.nwlab.test,DNS:admin.v1.api.nwlab.test,DNS:internal.v1.api.nwlab.test,DNS:www.nwlab.test,DNS:shop.nwlab.test,DNS:mail.nwlab.test,DNS:secret.nwlab.test"
gen_cert web2 nwlab-two.test \
    "DNS:nwlab-two.test,DNS:www.nwlab-two.test,DNS:portal.nwlab-two.test,DNS:api.nwlab-two.test,DNS:v1.api.nwlab-two.test,DNS:v2.api.nwlab-two.test"
# Scenario WC: web1 serves this one for wild.nwlab.test. The lab has no brute
# force, so these SANs are how names under the DNS wildcard reach the scan:
# four that exist only through *.wild (dropped) and real.wild (kept).
gen_cert wild wild.nwlab.test \
    "DNS:wild.nwlab.test,DNS:real.wild.nwlab.test,DNS:admin.wild.nwlab.test,DNS:dev.wild.nwlab.test,DNS:vpn.wild.nwlab.test,DNS:staging.wild.nwlab.test"

# E2E-B hosts: web3 is the RoE-excluded address of edge and mixed; web5 and
# web6 are the two addresses of two.nwlab.test.
gen_cert web3 edge.nwlab.test "DNS:edge.nwlab.test,DNS:mixed.nwlab.test"
# late-edge (on the excluded web3) is in no other certificate: a late name on
# an RoE-excluded address (B-LATEROE).
gen_cert two two.nwlab.test "DNS:two.nwlab.test,DNS:late-edge.nwlab.test"

# Runtime state, gitignored: the captures and lab_toggle.sh's includes. Made
# here so Docker never creates them root-owned.
mkdir -p out/pcap out/extra/web4 out/extra/web5

docker compose up -d --build

echo "[*] Routing gate (must name a br- device, never the uplink):"
if ip route get 192.88.99.60 | grep -q ' dev br-'; then
    ip route get 192.88.99.60 | head -1
else
    echo "[!] 192.88.99.60 does not route through the lab bridge. Do NOT scan." >&2
    exit 1
fi
echo "[*] Lab up. Next: ./host_dns_enable.sh (once per network creation), then the preflight in README.md."
