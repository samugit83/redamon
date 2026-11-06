#!/usr/bin/env bash
# Bring the urlscan lab up:
#   gen_lab.py -> check_fixtures.py -> recon image prefix check -> compose up
#   -> routing gate -> host_dns_enable.sh -> smoke checks.
#
#   ./up.sh                    reuse generated/ when it exists (same tokens), else generate it
#   ./up.sh --regen            new tokens, certificates and fixtures (the old folder is moved aside)
#   UL_TAKEOVER_DNS=1 ./up.sh  run T: the takeover CNAMEs in the lab zone and ~herokuapp.com
#                              routed to the lab DNS (the WHOLE host, until ./down.sh)
#
# Idempotent. Never touches the redamon-* containers; the orchestrator's lab
# hooks are a separate, manual step (README "Run it").
set -euo pipefail
cd "$(dirname "$0")"

regen=0
[ "${1:-}" = "--regen" ] && regen=1
tk=()
[ "${UL_TAKEOVER_DNS:-0}" = "1" ] && tk=(--takeover)

if [ "$regen" = 1 ] || [ ! -f generated/lab.json ]; then
    python3 -I gen_lab.py "${tk[@]}"
else
    python3 -I gen_lab.py --dns-only "${tk[@]}"
fi
python3 -I fake_urlscan/check_fixtures.py

# recon's SSRF guard (is_url_safe_to_probe) drops private and reserved
# addresses: the lab is useless unless the recon image's Python calls it global.
if ! docker image inspect redamon-recon >/dev/null 2>&1; then
    echo "[!] the redamon-recon image is missing: build the stack first" >&2
    exit 1
fi
docker run --rm --entrypoint python redamon-recon -c '
import ipaddress, sys
bad = [a for a in ("192.88.97.10", "192.88.97.40", "192.88.97.41", "192.88.97.98")
       if not ipaddress.ip_address(a).is_global or ipaddress.ip_address(a).is_private
       or ipaddress.ip_address(a).is_reserved]
sys.exit("[!] not global in the recon image: %s" % bad if bad else 0)'
echo "[+] 192.88.97.0/24 is global for the recon image's Python"

export USLAB_UID="$(id -u)" USLAB_GID="$(id -g)"
docker compose -p uslab up -d
# A regenerated zone is reloaded within 5 s anyway; the restart makes it now.
docker compose -p uslab restart dns >/dev/null 2>&1

if ip route get 192.88.97.10 | grep -q ' dev br-'; then
    echo "[+] routing gate: $(ip route get 192.88.97.10 | head -1)"
else
    echo "[!] 192.88.97.10 does not route through the lab bridge. Do NOT scan." >&2
    exit 1
fi

./host_dns_enable.sh

# Smoke, on hosts that may receive requests only (never .20, .98, .99):
# run_lab.py truncates the hit logs before every run anyway.
code=000
for _ in $(seq 1 20); do
    code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' http://192.88.97.30/__lab/health || true)
    [ "$code" = 200 ] && break
    sleep 1
done
[ "$code" = 200 ] || { echo "[!] the fake urlscan does not answer" >&2; exit 1; }
echo "[+] fake urlscan: $(curl -s -m 3 http://192.88.97.30/__lab/health)"
for url in https://app.uslab.test/ https://www.uslab.test/; do
    code=000
    for _ in $(seq 1 20); do
        code=$(curl -sk -o /dev/null -m 3 -w '%{http_code}' "$url" || true)
        [ "$code" = 200 ] && break
        sleep 1
    done
    echo "    $url -> $code"
    [ "$code" = 200 ] || { echo "[!] $url does not answer" >&2; exit 1; }
done
echo "[+] lab up. Next: python3 run_lab.py --prepare --schedules-paused (README, Run it)"
