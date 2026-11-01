#!/usr/bin/env bash
# Take the JS secret lab down: the four hosts, the canary and the lab network.
# redamon-trufflehog-net is shared with the orchestrator and stays (it is
# external to this compose project). A leftover E3 host .15 is removed too;
# its folder under _local/ is the E3 cleanup's to delete.
set -euo pipefail

cd "$(dirname "$0")"

if docker inspect jslab-app-realkeys >/dev/null 2>&1; then
  echo "[!] removing a leftover real-key host .15 (jslab-app-realkeys): finish the E3 cleanup"
  docker rm -f jslab-app-realkeys >/dev/null
fi

docker compose down --remove-orphans
echo "[+] lab down (generated/ kept; delete it to start from nothing)"
