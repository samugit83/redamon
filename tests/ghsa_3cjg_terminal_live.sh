#!/usr/bin/env bash
#
# Live check of GHSA-3cjg-8cp8-j269 against the running stack: a person's Kali sandbox's
# terminal (:8016) refuses the reporter's proof of concept from every place that can reach
# it, and still opens for that instance's bearer, which only the agent holds.
#
#   1. the host                            -> nothing of the sandbox is published: 127.0.0.1:8016
#                                             refused, and no port bound but the optional pool port
#   2. redamon-network                     -> the sandbox is not on it (its own redamon-sbx-<key>
#                                             is its only network), and a throwaway container
#                                             there gets no shell from the sandbox's address
#   3. pentest-net                         -> the same
#   4. a throwaway host-network container  -> no shell at 127.0.0.1:8016; the host routes to the
#                                             sandbox's address, which answers 401 (no token, the
#                                             proxy's query without a token, a wrong token)
#   5. inside the agent container, the one guest that dials the sandbox by name: 401 for the
#      same three; the instance's bearer without the proxy's identity -> 400; bearer + identity
#      -> a shell that runs the payload, and whose environment holds none of MCP_AUTH_TOKEN,
#      TUNNEL_AUTH_TOKEN, SCANNER_API_KEY, INTERNAL_API_KEY (only a count is printed); and the
#      old shared name kali-sandbox resolves to nothing there, while the sandbox's own does.
#
# The sandbox is g1-alice's, of the group-1 seed (synthetic accounts: run
# `python3 tests/kali_sandbox_seed_live.py` first), found by its labels, this stack's owner
# label among them. When none runs, the orchestrator starts it with her own projects, and
# this run stops it at the end.
#
# Each probe is the advisory's client: no init frame, one command that writes a
# marker file in the sandbox's /tmp. A probe passes only when the handshake was
# refused AND the marker does not exist in the sandbox afterwards, so a refusal
# that still ran the command cannot pass. The control's marker is removed.
#
# No rebuild, no restart; the throwaway containers run the agent image with --rm. The
# instance's token is read with docker inspect and reaches only the agent's probe, in its
# environment; the orchestrator's key reaches curl on stdin. Neither is ever printed or put
# on a command line.
#
# Needs docker, python3 and a running agent container; prints SKIP and exits 0 otherwise.
# Once they are there, a missing seed state is a FAIL. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/ghsa_3cjg_terminal_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! docker compose version >/dev/null 2>&1; then
  echo "SKIP: docker compose unavailable"
  exit 0
fi
AGENT="$(docker compose ps --status running -q agent 2>/dev/null | head -1)"
if [ -z "$AGENT" ]; then
  echo "SKIP: needs a running agent container (docker compose ps agent)"
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 is not installed (it reads the seed's state)"
  exit 0
fi
# The orchestrator labels each sandbox it starts with its own compose project: this stack's.
STACK_OWNER="$(docker ps --filter 'name=^redamon-recon-orchestrator$' --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | head -1)"
if [ -z "$STACK_OWNER" ]; then
  echo "FAIL: no compose project on a running redamon-recon-orchestrator: this stack's sandboxes cannot be told apart"
  exit 1
fi

env_value() { # KEY: from the environment, else the repo-root .env; never printed
  if [ -n "${!1:-}" ]; then printf '%s' "${!1}"; return; fi
  grep -m1 "^$1=" "$ROOT/.env" 2>/dev/null | cut -d= -f2- | sed "s/^[\"']//; s/[\"']\$//"
}
# The orchestrator's API, called as the webapp calls it. The key reaches curl on stdin. Prints
# the answer's body, then its HTTP status on a line of its own.
orch_call() { # method path [json-body]
  local key port args=(-s -m 300 -K - -X "$1" -H 'Content-Type: application/json' -w '\n%{http_code}')
  [ -n "${3:-}" ] && args+=(--data-binary "$3")
  key="$(env_value ORCHESTRATOR_API_KEY)"
  port="$(env_value RECON_ORCH_PORT | grep -xE '[0-9]+' || echo 8010)"
  printf 'header = "X-Orchestrator-Key: %s"\n' "${key:-changeme}" | curl "${args[@]}" "http://127.0.0.1:$port$2"
}
# The person's running sandbox (own view) of this stack, found by its labels. Newest first: an
# instance being replaced comes after the one replacing it.
own_sandbox() { # user-id
  docker ps --filter label=redamon.sandbox=1 --filter "label=redamon.sandbox.user=$1" \
    --filter label=redamon.sandbox.view=own --filter "label=redamon.sandbox.owner=$STACK_OWNER" \
    --format '{{.Names}}' 2>/dev/null | head -1
}
# The person's sandbox started (or found) and waited for -> "<HTTP status> <state> <fresh 0|1>".
# The answer holds the instance's tokens: only those three fields are kept.
ensure_sandbox() { # user-id project-id,...
  local p list="" out state
  for p in ${2//,/ }; do list+="${list:+,}\"$p\""; done
  out="$(orch_call POST /sandboxes/ensure \
    "{\"user_id\":\"$1\",\"view\":\"own\",\"projects\":[$list],\"need_project\":null,\"wait\":true,\"touch\":false}")"
  state="$(printf '%s' "$out" | grep -o '"state": *"[a-z_]*"' | head -1 | sed 's/.*"\([a-z_]*\)"$/\1/')"
  printf '%s %s %s\n' "${out##*$'\n'}" "${state:--}" "$(printf '%s' "$out" | grep -q '"fresh": *true' && echo 1 || echo 0)"
}
# SBX: the person's running sandbox. When none runs the orchestrator starts it, and
# SBX_FRESH=1 has the clean-up stop it again.
use_sandbox() { # user-id project-id,...
  local code state fresh
  SBX="$(own_sandbox "$1")"
  [ -n "$SBX" ] && return 0
  read -r code state fresh < <(ensure_sandbox "$1" "$2")
  [ "$fresh" = 1 ] && SBX_FRESH=1
  SBX="$(own_sandbox "$1")"
  [ "$code" = 200 ] && [ "$state" = running ] && [ -n "$SBX" ] && return 0
  echo "FAIL: the orchestrator did not start the person's sandbox (HTTP ${code:-none}, state ${state:--})"
  return 1
}
stop_sandbox() { # user-id -> HTTP status
  local out
  out="$(orch_call POST "/sandboxes/$1/stop" '{"reason":"operator"}')"
  echo "${out##*$'\n'}"
}
sandbox_env() { # container KEY: that variable of its Config.Env, to compare or send, never to print
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null | sed -n "s/^$2=//p" | head -1
}
# g1-alice of the group-1 seed -> "<user id> <her own project ids, comma-separated>". The state
# file also holds passwords and tokens: only the ids are read.
G1_STATE="${G1_STATE:-${TMPDIR:-/tmp}/g1-live-state.json}"
seed_person() {
  python3 -I -c '
import json, re, sys
s = json.load(open(sys.argv[1]))
ids = [s["alice"]["id"], s["projects"]["PA"], s["projects"]["PS"]]
if all(isinstance(i, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", i) for i in ids):
    print(ids[0], ",".join(ids[1:]))' "$G1_STATE" 2>/dev/null
}

TMP="$(mktemp -d)"
USER_ID=""; PROJECTS=""; SBX=""; SBX_FRESH=0; TOKEN=""
cleanup() {
  TOKEN=""
  [ "$SBX_FRESH" = 1 ] && echo "  (the sandbox this run started is stopped: HTTP $(stop_sandbox "$USER_ID"))"
  rm -rf "$TMP"
}
trap cleanup EXIT
RUN_ID="$(date +%s)$$"

if ! read -r USER_ID PROJECTS < <(seed_person); then
  echo "FAIL: no g1 seed state at $G1_STATE: run python3 tests/kali_sandbox_seed_live.py first (same G1_STATE or TMPDIR)"
  exit 1
fi
use_sandbox "$USER_ID" "$PROJECTS" || exit 1
TOKEN="$(sandbox_env "$SBX" MCP_AUTH_TOKEN)"
IMAGE="$(docker inspect -f '{{.Config.Image}}' "$AGENT")"
SBX_NETS="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$SBX")"
# The contract's sandbox_key(user id, "own"): the first 16 hex of the id's SHA-256.
SBX_NET="redamon-sbx-$(printf '%s' "$USER_ID" | sha256sum | cut -c1-16)"
SBX_IP="$(docker inspect -f "{{with index .NetworkSettings.Networks \"$SBX_NET\"}}{{.IPAddress}}{{end}}" "$SBX")"
STACK="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$AGENT")"
PENTEST_NET="$(docker network ls --filter label=com.docker.compose.network=pentest-net \
  --filter "label=com.docker.compose.project=$STACK" --format '{{.Name}}' | head -1)"
echo "== the sandbox: $SBX (g1-alice's own) =="

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
    print("STATUS no-instance-token")
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
marker_exists() { docker exec "$SBX" test -e "$1"; }

# refused <label> <status> <marker>: the handshake was refused and nothing ran.
refused() {
  local label="$1" status="$2" marker="$3" ok=1 why=""
  case "$status" in "STATUS 101"*|"") ok=0; why="handshake: ${status:-no answer}" ;; esac
  if marker_exists "$marker"; then
    ok=0; why="${why:+$why; }the payload RAN in the sandbox"
    docker exec "$SBX" rm -f "$marker"
  fi
  check "$label -> ${status#STATUS }" "$ok" "$why"
}
# refused_401 <label> <status> <marker>: where the probe reaches the terminal, only the bearer
# check's 401 counts: a connection error there would prove nothing.
refused_401() {
  local label="$1" status="$2" marker="$3" ok=1 why=""
  [ "$status" = "STATUS 401" ] || { ok=0; why="expected 401, got ${status:-no answer}"; }
  if marker_exists "$marker"; then
    ok=0; why="${why:+$why; }the payload RAN in the sandbox"
    docker exec "$SBX" rm -f "$marker"
  fi
  check "$label -> ${status#STATUS }" "$ok" "$why"
}

in_net() { # network url mode marker: probe from a throwaway container
  docker run --rm -i --network "$1" --entrypoint python "$IMAGE" - "$2" "$3" "$4" \
    < "$TMP/probe.py" 2>/dev/null | tail -1
}

echo "== 1. the host: nothing of the sandbox is published =="
code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  'http://127.0.0.1:8016/' 2>/dev/null)"
case "$code" in
  000) check "8016 not published on the host (connection refused)" 1 ;;
  *)   check "host loopback 8016 answered $code" 0 "expected connection refused: no sandbox publishes its terminal" ;;
esac
# Only the pool port (KALI_SANDBOX_PORT_POOL, the reverse-shell listener) may be bound on the host.
bound="$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}' "$SBX")"
pool="$(docker inspect -f '{{index .Config.Labels "redamon.sandbox.port"}}' "$SBX")"
ok=0
case "$bound" in
  "") ok=1 ;;
  "$pool/tcp ") [ -n "$pool" ] && ok=1 ;;
esac
check "no port of the sandbox is published but its pool port (${pool:-none})" "$ok" "published: $bound"

echo "== 2. redamon-network =="
ok=1; case " $SBX_NETS " in *" redamon-network "*) ok=0 ;; esac
check "the sandbox is not on redamon-network" "$ok" "networks: $SBX_NETS"
ok=0; [ "$SBX_NETS" = "$SBX_NET " ] && [ -n "$SBX_IP" ] && ok=1
check "its only network is its own $SBX_NET" "$ok" "networks: $SBX_NETS"
if [ -n "$SBX_IP" ]; then
  m="/tmp/ghsa_3cjg_live_${RUN_ID}_bridge"
  refused "PoC (none) from redamon-network to the sandbox's address" \
    "$(in_net redamon-network "ws://$SBX_IP:8016" none "$m")" "$m"
fi

if [ -n "$PENTEST_NET" ]; then
  echo "== 3. $PENTEST_NET =="
  ok=1; case " $SBX_NETS " in *" $PENTEST_NET "*) ok=0 ;; esac
  check "the sandbox is not on $PENTEST_NET" "$ok" "networks: $SBX_NETS"
  if [ -n "$SBX_IP" ]; then
    m="/tmp/ghsa_3cjg_live_${RUN_ID}_pentest"
    refused "PoC (none) from $PENTEST_NET to the sandbox's address" \
      "$(in_net "$PENTEST_NET" "ws://$SBX_IP:8016" none "$m")" "$m"
  fi
else
  echo "  (this stack has no pentest-net network: step 3 not applicable)"
fi

echo "== 4. a host-network container =="
m="/tmp/ghsa_3cjg_live_${RUN_ID}_hostnet"
refused "PoC (none) at 127.0.0.1:8016" "$(in_net host ws://127.0.0.1:8016 none "$m")" "$m"
# The host routes to every bridge network, so a host process reaches the sandbox's address.
if [ -n "$SBX_IP" ]; then
  for mode in none identity wrong; do
    m="/tmp/ghsa_3cjg_live_${RUN_ID}_hostaddr_$mode"
    refused_401 "PoC ($mode) at the sandbox's address" "$(in_net host "ws://$SBX_IP:8016" "$mode" "$m")" "$m"
  done
fi

echo "== 5. inside the agent container, by the sandbox's name =="
agent_probe() {
  MCP_AUTH_TOKEN="$TOKEN" docker exec -e MCP_AUTH_TOKEN -i "$AGENT" python - "$@" < "$TMP/probe.py" 2>/dev/null | tail -1
}
for mode in none identity wrong; do
  m="/tmp/ghsa_3cjg_live_${RUN_ID}_agent_$mode"
  refused_401 "PoC ($mode)" "$(agent_probe "ws://$SBX:8016" "$mode" "$m")" "$m"
done
# No sandbox answers to the shared name any more: a name the agent still dialled would reach
# whichever sandbox claimed it. The sandbox's own name resolving is the control (DNS works here).
# getent exits 2 for a name it does not know; any other failure (no getent) proves nothing.
resolved="$(docker exec "$AGENT" getent hosts kali-sandbox 2>/dev/null)"; rc=$?
ok=0; [ "$rc" = 2 ] && [ -z "$resolved" ] && ok=1
check "inside the agent, kali-sandbox resolves to nothing (getent exit $rc)" "$ok" "${resolved:+resolved: $resolved}"
resolved="$(docker exec "$AGENT" getent hosts "$SBX" 2>/dev/null)"; rc=$?
ok=0; [ "$rc" = 0 ] && [ -n "$resolved" ] && ok=1
check "inside the agent, the sandbox's own name resolves (control, getent exit $rc)" "$ok"

m="/tmp/ghsa_3cjg_live_${RUN_ID}_noid"
out="$(agent_probe "ws://$SBX:8016" bearer-noid "$m")"
ok=0; [ "$out" = "STATUS 400" ] && ! marker_exists "$m" && ok=1
check "the instance's bearer without the proxy's identity -> ${out#STATUS }" "$ok" "expected 400 and nothing run"
docker exec "$SBX" rm -f "$m"

m="/tmp/ghsa_3cjg_live_${RUN_ID}_control"
out="$(agent_probe "ws://$SBX:8016" bearer "$m")"
ok=0; case "$out" in "STATUS 101"*) marker_exists "$m" && ok=1 ;; esac
check "the instance's bearer + identity opens a shell that runs the payload -> ${out#STATUS }" "$ok" \
  "the control must reach a shell, or the refusals above prove nothing"
leaked="${out##* }"
ok=0; [ "$leaked" = "0" ] && ok=1
check "that shell's environment holds no service credential (count: $leaked)" "$ok"
docker exec "$SBX" rm -f "$m"
TOKEN=""

echo
printf 'GHSA-3cjg live: \033[0;32m%d passed\033[0m, ' "$PASS"
if [ "$FAIL" -gt 0 ]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; fi
printf '0 failed\n'
