#!/usr/bin/env bash
#
# Live check of GHSA-3cjg-8cp8-j269 against the running stack: the Kali terminal
# (:8016) refuses the reporter's proof of concept from every place the advisory
# names, and still opens for the agent's bearer.
#
#   1. a host process, 127.0.0.1:8016            -> no shell (connection refused once
#                                                   compose stops publishing it, else 401)
#   2. a throwaway container on redamon-network  -> 401 (no token, the proxy's query
#                                                   without a token, a wrong token)
#   3. a throwaway container on pentest-net      -> 401
#   4. a throwaway host-network container        -> no shell
#   5. control, inside the agent container with the agent's own MCP_AUTH_TOKEN:
#      no identity -> 400; token + identity -> a shell that runs the payload, and
#      whose environment holds none of MCP_AUTH_TOKEN, TUNNEL_AUTH_TOKEN,
#      SCANNER_API_KEY, INTERNAL_API_KEY (only a count is printed).
#
# Each probe is the advisory's client: no init frame, one command that writes a
# marker file in the sandbox's /tmp. A probe passes only when the handshake was
# refused AND the marker does not exist in kali-sandbox afterwards, so a refusal
# that still ran the command cannot pass. The control's marker is removed.
#
# Read-only for the stack: no rebuild, no restart, no fixture; the throwaway
# containers run the agent image with --rm. The token never leaves the agent
# container and is never printed.
#
# Needs docker and running agent + kali-sandbox containers; prints SKIP and exits
# 0 otherwise. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/ghsa_3cjg_terminal_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! docker compose version >/dev/null 2>&1; then
  echo "SKIP: docker compose unavailable"
  exit 0
fi
KALI="$(docker compose ps --status running -q kali-sandbox 2>/dev/null | head -1)"
AGENT="$(docker compose ps --status running -q agent 2>/dev/null | head -1)"
if [ -z "$KALI" ] || [ -z "$AGENT" ]; then
  echo "SKIP: needs running agent and kali-sandbox containers (docker compose ps)"
  exit 0
fi
IMAGE="$(docker inspect -f '{{.Config.Image}}' "$AGENT")"
KALI_NETS="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$KALI")"
BRIDGE_NET="$(tr ' ' '\n' <<< "$KALI_NETS" | grep -m1 -x 'redamon-network' || true)"
PENTEST_NET="$(tr ' ' '\n' <<< "$KALI_NETS" | grep -m1 'pentest-net' || true)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
RUN_ID="$(date +%s)$$"

cat > "$TMP/probe.py" <<'PY'
import asyncio
import os
import re
import sys

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus

url, mode, marker = sys.argv[1], sys.argv[2], sys.argv[3]
token = os.environ.get("MCP_AUTH_TOKEN", "")
identity = "?user_id=ghsa-3cjg-live&project_id=ghsa-3cjg-live"
path, headers = {
    "none": ("", {}),
    "identity": (identity, {}),
    "wrong": (identity, {"Authorization": "Bearer ghsa-3cjg-not-the-agents-token"}),
    "bearer-noid": ("", {"Authorization": f"Bearer {token}"}),
    "bearer": (identity, {"Authorization": f"Bearer {token}"}),
}[mode]
if mode.startswith("bearer") and not token:
    print("STATUS no-agent-token")
    sys.exit(0)
payload = (f"id > {marker}; echo LEAKED=$(env | grep -cE "
           "'^(MCP_AUTH_TOKEN|TUNNEL_AUTH_TOKEN|SCANNER_API_KEY|INTERNAL_API_KEY)=') END\n")
done = re.compile(rb"LEAKED=(\d+) END")


async def main():
    try:
        async with websockets.connect(url + path, additional_headers=headers, open_timeout=8) as ws:
            await ws.send(payload)
            out, loop = b"", asyncio.get_running_loop()
            end = loop.time() + (20 if mode == "bearer" else 3)
            while loop.time() < end and not done.search(out):
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                except ConnectionClosed:
                    break
                out += msg if isinstance(msg, bytes) else msg.encode()
            found = done.search(out)
            print("STATUS 101 LEAKED", found.group(1).decode() if found else "?")
    except InvalidStatus as exc:
        print("STATUS", exc.response.status_code)
    except (OSError, asyncio.TimeoutError):
        print("STATUS refused")


asyncio.run(main())
PY

PASS=0; FAIL=0
check() { # name ok-flag [detail]
  if [ "$2" -eq 1 ]; then PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"
  else FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s%s\n' "$1" "${3:+ ($3)}"; fi
}
marker_exists() { docker exec "$KALI" test -e "$1"; }

# refused <label> <status> <marker>: the handshake was refused and nothing ran.
refused() {
  local label="$1" status="$2" marker="$3" ok=1 why=""
  case "$status" in "STATUS 101"*|"") ok=0; why="handshake: ${status:-no answer}" ;; esac
  if marker_exists "$marker"; then
    ok=0; why="${why:+$why; }the payload RAN in kali-sandbox"
    docker exec "$KALI" rm -f "$marker"
  fi
  check "$label -> ${status#STATUS }" "$ok" "$why"
}

in_net() { # network url mode marker: probe from a throwaway container
  docker run --rm -i --network "$1" --entrypoint python "$IMAGE" - "$2" "$3" "$4" \
    < "$TMP/probe.py" 2>/dev/null | tail -1
}

echo "== 1. host process: 127.0.0.1:8016 =="
code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  'http://127.0.0.1:8016/' 2>/dev/null)"
case "$code" in
  000) check "not published on the host (connection refused)" 1 ;;
  401) check "published on the host, but refuses without the bearer (401); recreate kali-sandbox to unpublish it" 1 ;;
  *)   check "host loopback answered $code" 0 "expected refused or 401" ;;
esac

if [ -n "$BRIDGE_NET" ]; then
  echo "== 2. a co-resident container on $BRIDGE_NET =="
  for mode in none identity wrong; do
    m="/tmp/ghsa_3cjg_live_${RUN_ID}_bridge_$mode"
    refused "PoC ($mode)" "$(in_net "$BRIDGE_NET" ws://kali-sandbox:8016 "$mode" "$m")" "$m"
  done
else
  check "kali-sandbox is on redamon-network" 0 "networks: $KALI_NETS"
fi

if [ -n "$PENTEST_NET" ]; then
  echo "== 3. a container on $PENTEST_NET =="
  m="/tmp/ghsa_3cjg_live_${RUN_ID}_pentest"
  refused "PoC (none)" "$(in_net "$PENTEST_NET" ws://kali-sandbox:8016 none "$m")" "$m"
else
  echo "  (kali-sandbox is on no pentest-net network: step 3 not applicable)"
fi

echo "== 4. a host-network container: 127.0.0.1:8016 =="
m="/tmp/ghsa_3cjg_live_${RUN_ID}_hostnet"
refused "PoC (none)" "$(in_net host ws://127.0.0.1:8016 none "$m")" "$m"

echo "== 5. control: the agent's own bearer, from the agent container =="
agent_probe() { docker exec -i "$AGENT" python - "$@" < "$TMP/probe.py" 2>/dev/null | tail -1; }
m="/tmp/ghsa_3cjg_live_${RUN_ID}_noid"
out="$(agent_probe ws://kali-sandbox:8016 bearer-noid "$m")"
ok=0; [ "$out" = "STATUS 400" ] && ! marker_exists "$m" && ok=1
check "the bearer without the proxy's identity -> ${out#STATUS }" "$ok" "expected 400 and nothing run"
docker exec "$KALI" rm -f "$m"

m="/tmp/ghsa_3cjg_live_${RUN_ID}_control"
out="$(agent_probe ws://kali-sandbox:8016 bearer "$m")"
ok=0; case "$out" in "STATUS 101"*) marker_exists "$m" && ok=1 ;; esac
check "the bearer + identity opens a shell that runs the payload -> ${out#STATUS }" "$ok" \
  "the control must reach a shell, or the refusals above prove nothing"
leaked="${out##* }"
ok=0; [ "$leaked" = "0" ] && ok=1
check "that shell's environment holds no service credential (count: $leaked)" "$ok"
docker exec "$KALI" rm -f "$m"

echo
printf 'GHSA-3cjg live: \033[0;32m%d passed\033[0m, ' "$PASS"
if [ "$FAIL" -gt 0 ]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; fi
printf '0 failed\n'
