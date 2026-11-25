#!/usr/bin/env bash
#
# Live check of GHSA-w454-6hwp-fm58 against a REAL msfconsole: inside one person's Kali
# sandbox, one of the projects it serves cannot list, drive, kill or re-link another one's
# Metasploit session through the sandbox's console, and the console passes to the next
# project only empty and restarted. No console is shared by every project of the instance
# any more: each sandbox has its own, shared by the projects its person may use (their own
# and those shared with them), so the per-project lease is checked there.
#
# tests/ghsa_w454_msf_lease_live.py is fed on stdin to that sandbox, where it starts a
# second Metasploit server from the mounted mcp/servers on loopback ports 18003/18013 with
# its own msfconsole and a 20 s idle window, plays two projects against it with a loopback
# reverse shell as the only "target", and kills it. The sandbox's own console, sessions and
# ports are never touched, so it needs no restart: it tests the mounted source, which is
# what a new sandbox loads.
#
# The sandbox is g1-alice's, of the group-1 seed (synthetic accounts: run
# `python3 tests/kali_sandbox_seed_live.py` first), found by its labels. When none runs, the
# orchestrator starts it with her own projects, and this run stops it at the end. The
# orchestrator's key reaches curl on stdin, never a command line or the output.
#
# Needs docker, python3 and a running recon orchestrator (it starts the sandboxes); prints
# SKIP and exits 0 when one is missing. Once they are there, a missing seed state is a FAIL.
# As a *_live.sh it is never in the gate. Takes 3-6 minutes (two msfconsole starts).
#
# Run:  bash tests/ghsa_w454_msf_lease_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! (cd "$ROOT" && docker compose ps --status running -q recon-orchestrator 2>/dev/null | grep -q .); then
  echo "SKIP: no running recon-orchestrator container, which starts the sandboxes (docker compose ps recon-orchestrator)"
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 is not installed (it reads the seed's state)"
  exit 0
fi
# The orchestrator labels each sandbox it starts with its own compose project: this stack's.
STACK_OWNER="$(docker ps --filter 'name=^redamon-recon-orchestrator$' --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | head -1)"
if [ -z "$STACK_OWNER" ]; then
  echo "FAIL  no compose project on a running redamon-recon-orchestrator: this stack's sandboxes cannot be told apart"
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
stop_sandbox() { # user-id -> HTTP status
  local out
  out="$(orch_call POST "/sandboxes/$1/stop" '{"reason":"operator"}')"
  echo "${out##*$'\n'}"
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

USER_ID=""; PROJECTS=""; SBX_FRESH=0
cleanup() {
  [ "$SBX_FRESH" = 1 ] && echo "INFO  the sandbox this run started is stopped: HTTP $(stop_sandbox "$USER_ID")"
}
trap cleanup EXIT

if ! read -r USER_ID PROJECTS < <(seed_person); then
  echo "FAIL  no g1 seed state at $G1_STATE: run python3 tests/kali_sandbox_seed_live.py first (same G1_STATE or TMPDIR)"
  exit 1
fi
SBX="$(own_sandbox "$USER_ID")"
if [ -z "$SBX" ]; then
  read -r code state fresh < <(ensure_sandbox "$USER_ID" "$PROJECTS")
  [ "$fresh" = 1 ] && SBX_FRESH=1
  SBX="$(own_sandbox "$USER_ID")"
  if [ "$code" != 200 ] || [ "$state" != running ] || [ -z "$SBX" ]; then
    echo "FAIL  the orchestrator did not start g1-alice's sandbox (HTTP ${code:-none}, state ${state:--})"
    exit 1
  fi
fi
echo "INFO  in g1-alice's sandbox $SBX"

# Its MCP_AUTH_TOKEN is the instance's own, in the environment docker exec gives the script.
docker exec -i "$SBX" python3 - < "$ROOT/tests/ghsa_w454_msf_lease_live.py"
