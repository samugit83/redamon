#!/usr/bin/env bash
# Bring the JS secret lab up.
#
# Order matters: the canary starts first, because .12's connection strings are
# written with the canary's real address on redamon-trufflehog-net, and that
# address is known only once it runs. Then gen_lab.py writes every site, then
# the four lab hosts start. Re-running it regenerates the sites (fixed seed, so
# the same bytes) and leaves running hosts serving the new files.
set -euo pipefail

cd "$(dirname "$0")"
NET=redamon-trufflehog-net

# The orchestrator's own definition (container_manager._ensure_trufflehog_network):
# a plain bridge with no fixed subnet. Never removed by down.sh: it is shared.
if ! docker network inspect "$NET" >/dev/null 2>&1; then
  echo "[*] creating $NET (plain bridge, as the orchestrator does)"
  docker network create --driver bridge "$NET" >/dev/null
fi

docker compose up -d canary

ip=""
for _ in $(seq 1 30); do
  ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" jslab-canary 2>/dev/null || true)
  [ -n "$ip" ] && break
  sleep 1
done
if [ -z "$ip" ]; then
  echo "[!] the canary has no address on $NET" >&2
  exit 1
fi
echo "[*] canary jslab-canary at $ip on $NET"

python3 -I gen_lab.py --canary-ip "$ip"

docker compose up -d app-modern vendor-only ssrf-bait clean-control

for host in 10 11 12 14; do
  code=000
  for _ in $(seq 1 20); do
    code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "http://192.88.96.$host/" || true)
    [ "$code" = 200 ] && break
    sleep 1
  done
  echo "    http://192.88.96.$host/ -> $code"
  [ "$code" = 200 ] || { echo "[!] 192.88.96.$host does not answer" >&2; exit 1; }
done
echo "[+] lab up: .10 app-modern, .11 vendor-only, .12 ssrf-bait, .14 clean-control; canary $ip"
