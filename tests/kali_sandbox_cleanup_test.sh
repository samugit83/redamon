#!/usr/bin/env bash
# =============================================================================
# redamon.sh handles the per-user Kali sandboxes the orchestrator spawns (group 1,
# WI-S06-4). Compose does not manage them, so:
#   - remove_spawned_containers (purge) removes every container labelled
#     redamon.sandbox=1, by label and never by name, so the shared `redamon-kali`
#     and other plans' containers are never caught; down and clean first ask the
#     orchestrator to stop them all, then STOP (never remove) what is left
#     (--stop-sandboxes), so the next adoption holds each one's reverse-shell pool
#     port for its person (G-04);
#   - purge also removes the sandboxes' output, template copies and port holds
#     under mcp/output (G-31);
#   - purge also removes the labelled sandbox networks (endpoints disconnected
#     first) and the nuclei templates volume, whose name has no <project>_ prefix;
#   - status lists them in a block of their own;
#   - install|update|up tag <project>-kali-sandbox:latest as
#     redamon-kali-sandbox:latest once, only when the fixed tag is missing (TD-29).
# Run:  bash tests/kali_sandbox_cleanup_test.sh
#
# redamon.sh is sourced (its BASH_SOURCE guard stops the dispatch) with `docker`
# stubbed, as tests/redamon_build_test.sh does. cmd_purge and cmd_status are
# never run here: they delete and migrate files of the real checkout. Their calls
# to the helpers are read from `declare -f`. Exits 77 (the gate's "cannot run")
# when redamon.sh is missing.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$REPO_ROOT/redamon.sh" ]] || { echo "CANNOT RUN: $REPO_ROOT/redamon.sh is missing"; exit 77; }

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }
assert_contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi; }
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3' in: $2)"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
info() { :; }
warn() { :; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CALLS="$TMP/calls"
# What the stubbed daemon holds.
SPAWNED_IDS=""          # answer to the name-filtered `ps -aq`
SANDBOX_IDS=""          # answer to the label-filtered `ps -aq`
SANDBOX_ROWS=""         # answer to the label-filtered `ps -a --format`
SANDBOX_NETS=""         # answer to the label-filtered `network ls -q`
NET_ENDPOINTS=""        # answer to `network inspect` (container ids)
IMAGES=""               # images `image inspect` finds

# Another RedAmon stack on the same daemon (a test stack, M-b) owns these; a
# label filter without the owner would see them too.
OTHER_IDS="other01"
OTHER_ROWS="    redamon-kali-fedcba9876543210-ffffff  (Up 1 minute)"
OTHER_NETS="othernet01"
OWNER_FILTER="label=redamon.sandbox.owner=myproj"
export COMPOSE_PROJECT_NAME=myproj

docker() {
    printf '%s\n' "$*" >> "$CALLS"
    local mine=0
    [[ " $* " == *" $OWNER_FILTER "* ]] && mine=1
    case "$1 ${2:-}" in
        "ps -aq"|"ps -q")
            if [[ "$*" == *"label=redamon.sandbox=1"* ]]; then
                [[ -n "$SANDBOX_IDS" ]] && printf '%s\n' $SANDBOX_IDS
                [[ $mine -eq 1 ]] || printf '%s\n' $OTHER_IDS
            else
                [[ -n "$SPAWNED_IDS" ]] && printf '%s\n' $SPAWNED_IDS
            fi ;;
        "ps -a")
            if [[ "$*" == *"label=redamon.sandbox=1"* ]]; then
                [[ -n "$SANDBOX_ROWS" ]] && printf '%s\n' "$SANDBOX_ROWS"
                [[ $mine -eq 1 ]] || printf '%s\n' "$OTHER_ROWS"
            fi ;;
        "network ls")
            [[ -n "$SANDBOX_NETS" ]] && printf '%s\n' $SANDBOX_NETS
            [[ $mine -eq 1 ]] || printf '%s\n' $OTHER_NETS ;;
        "network inspect")
            printf '%s\n' "$NET_ENDPOINTS" ;;
        "image inspect")
            [[ " $IMAGES " == *" $3 "* ]] || return 1 ;;
    esac
    return 0
}
reset() {
    : > "$CALLS"
    SPAWNED_IDS=""; SANDBOX_IDS=""; SANDBOX_ROWS=""; SANDBOX_NETS=""; NET_ENDPOINTS=""; IMAGES=""
}
calls() { cat "$CALLS"; }
line_of() { grep -nF -- "$1" "$CALLS" | head -n1 | cut -d: -f1; }

# =============================================================================
section "remove_spawned_containers removes the sandboxes by label"
reset
SPAWNED_IDS="ai01"
SANDBOX_IDS="sbx01 sbx02"
remove_spawned_containers
rm_line="$(grep -E '^rm -f' "$CALLS")"
assert_contains "the AI and capture containers are still removed" "$rm_line" "ai01"
assert_contains "a sandbox is removed" "$rm_line" "sbx01"
assert_contains "every sandbox is removed" "$rm_line" "sbx02"
assert_contains "sandboxes are selected by their label" "$(calls)" "ps -aq --filter label=redamon.sandbox=1"
assert_contains "and by this stack's owner label" "$(grep '^ps -aq' "$CALLS" | grep 'redamon.sandbox=1')" "$OWNER_FILTER"
assert_not_contains "another stack's sandbox is left alone" "$rm_line" "other01"
assert_not_contains "no name filter could catch the shared container" "$(calls)" "name=redamon-kali"
assert_not_contains "no filter names the Kali image" "$(calls)" "ancestor="

reset
remove_spawned_containers
assert_eq "nothing to remove: no docker rm" "$(grep -c '^rm' "$CALLS")" "0"

reset
export COMPOSE_PROJECT_NAME=otherstack
SANDBOX_IDS="sbx01"
remove_spawned_containers
assert_not_contains "the owner is this stack's compose project" "$(calls)" "$OWNER_FILTER"
assert_contains "read from compose_project_name" "$(calls)" "label=redamon.sandbox.owner=otherstack"
export COMPOSE_PROJECT_NAME=myproj

reset
SANDBOX_IDS="sbx09"
remove_spawned_containers
assert_eq "sandboxes alone are removed" "$(grep -E '^rm -f' "$CALLS")" "rm -f sbx09"

# The comment above the filter list names the sandboxes.
comment="$(awk '/^SPAWNED_CONTAINER_NAME_FILTERS=/ { exit } { print }' "$REPO_ROOT/redamon.sh" | tail -n 20)"
assert_contains "the comment above the filters names the sandboxes" "$comment" "redamon.sandbox=1"

# =============================================================================
section "purge removes the sandbox networks and the templates volume"
reset
SANDBOX_NETS="net01 net02"
NET_ENDPOINTS="lab01 agent01"
_purge_kali_sandbox_resources
assert_contains "every endpoint is disconnected first" "$(calls)" "network disconnect -f net01 lab01"
assert_contains "the agent too" "$(calls)" "network disconnect -f net02 agent01"
assert_contains "the labelled networks are selected by label" "$(calls)" "network ls -q --filter label=redamon.sandbox=1"
assert_contains "and by this stack's owner label" "$(grep '^network ls' "$CALLS")" "$OWNER_FILTER"
assert_not_contains "another stack's network is left alone" "$(calls)" "othernet01"
assert_contains "a network is removed" "$(calls)" "network rm net01"
assert_contains "every network is removed" "$(calls)" "network rm net02"
d="$(line_of 'network disconnect -f net01')"; r="$(line_of 'network rm net01')"
if [[ -n "$d" && -n "$r" && "$d" -lt "$r" ]]; then pass "disconnect before rm"; else fail "disconnect before rm ($d, $r)"; fi
assert_contains "the templates volume is removed" "$(calls)" "volume rm redamon-kali-nuclei-templates"

reset
_purge_kali_sandbox_resources
assert_eq "no sandbox network: no network rm" "$(grep -c '^network rm' "$CALLS")" "0"
assert_contains "the volume is still removed" "$(calls)" "volume rm redamon-kali-nuclei-templates"

purge_body="$(declare -f cmd_purge)"
spawned_at="$(grep -n 'remove_spawned_containers' <<< "$purge_body" | head -n1 | cut -d: -f1)"
sandbox_at="$(grep -n '_purge_kali_sandbox_resources' <<< "$purge_body" | head -n1 | cut -d: -f1)"
if [[ -n "$spawned_at" && -n "$sandbox_at" && "$spawned_at" -lt "$sandbox_at" ]]; then
    pass "cmd_purge removes the sandboxes before their networks"
else
    fail "cmd_purge removes the sandboxes before their networks (containers at '$spawned_at', networks at '$sandbox_at')"
fi
for f in cmd_down cmd_clean; do
    body="$(declare -f "$f")"
    assert_contains "$f stops the spawned containers" "$body" "remove_spawned_containers --stop-sandboxes"
    assert_not_contains "$f never removes a sandbox" "$(grep -E 'remove_spawned_containers *;?$' <<< "$body")" "remove_spawned_containers"
    post_at="$(grep -n '_sandbox_stop_all_post' <<< "$body" | head -n1 | cut -d: -f1)"
    stop_at="$(grep -n 'remove_spawned_containers --stop-sandboxes' <<< "$body" | head -n1 | cut -d: -f1)"
    if [[ -n "$post_at" && -n "$stop_at" && "$post_at" -lt "$stop_at" ]]; then
        pass "$f asks the orchestrator to stop them first"
    else
        fail "$f asks the orchestrator to stop them first (post at '$post_at', stop at '$stop_at')"
    fi
done
assert_not_contains "cmd_purge removes the sandboxes" "$purge_body" "--stop-sandboxes"
out_at="$(grep -n '_purge_kali_sandbox_output' <<< "$purge_body" | head -n1 | cut -d: -f1)"
if [[ -n "$out_at" && -n "$sandbox_at" && "$sandbox_at" -lt "$out_at" ]]; then
    pass "cmd_purge removes the sandboxes' output after the sandboxes"
else
    fail "cmd_purge removes the sandboxes' output after the sandboxes (resources at '$sandbox_at', output at '$out_at')"
fi

# =============================================================================
section "down and clean stop the sandboxes, so their pool ports stay held (G-04)"
reset
SPAWNED_IDS="ai01"
SANDBOX_IDS="sbx01 sbx02"
remove_spawned_containers --stop-sandboxes
assert_contains "the AI containers are still removed" "$(grep -E '^rm -f' "$CALLS")" "ai01"
assert_not_contains "no sandbox is removed" "$(grep -E '^rm -f' "$CALLS")" "sbx0"
assert_contains "every sandbox is stopped" "$(grep -E '^stop ' "$CALLS")" "sbx01 sbx02"
assert_not_contains "another stack's sandbox is left alone" "$(grep -E '^stop ' "$CALLS")" "other01"

# The orchestrator's stop-all, reached only with the key, and only while a sandbox runs.
FAKE="$TMP/checkout"; mkdir -p "$FAKE"
CURLS="$TMP/curls"
curl() { printf '%s\n' "$*" >> "$CURLS"; return 0; }
( SCRIPT_DIR="$FAKE"; : > "$CURLS"; reset; SANDBOX_IDS="sbx01"; _sandbox_stop_all_post; echo "rc=$?" > "$TMP/rc" )
assert_eq "no .env key: no call" "$(cat "$CURLS")" ""
assert_eq "and a failure the caller ignores" "$(cat "$TMP/rc")" "rc=1"
printf 'ORCHESTRATOR_API_KEY=k123\nRECON_ORCH_PORT=8011\n' > "$FAKE/.env"
( SCRIPT_DIR="$FAKE"; : > "$CURLS"; reset; _sandbox_stop_all_post )
assert_eq "no sandbox running: no call" "$(cat "$CURLS")" ""
( SCRIPT_DIR="$FAKE"; : > "$CURLS"; reset; SANDBOX_IDS="sbx01"; _sandbox_stop_all_post )
posted="$(cat "$CURLS")"
assert_contains "stop-all on the orchestrator's port" "$posted" "http://127.0.0.1:8011/sandboxes/stop-all"
assert_contains "with the orchestrator key" "$posted" "X-Orchestrator-Key: k123"
assert_contains "as an operator stop" "$posted" '{"reason":"operator"}'
assert_contains "bounded" "$posted" "--max-time"
unset -f curl

# =============================================================================
section "purge removes the sandboxes' output, template copies and port holds (G-31)"
OUT="$FAKE/mcp/output"
mkdir -p "$OUT/users/aaaa" "$OUT/templates/bbbb" "$OUT/keep"
touch "$OUT/users/aaaa/scan.txt" "$OUT/.sandbox-port-holds.json" "$OUT/.sandbox-port-holds.json.prev" "$OUT/n.py"
SUDOS="$TMP/sudos"; : > "$SUDOS"
sudo() { printf '%s\n' "$*" >> "$SUDOS"; return 0; }
( SCRIPT_DIR="$FAKE"; _purge_kali_sandbox_output )
for gone in users templates .sandbox-port-holds.json .sandbox-port-holds.json.prev; do
    if [[ ! -e "$OUT/$gone" ]]; then pass "purge removes mcp/output/$gone"; else fail "purge removes mcp/output/$gone"; fi
done
if [[ -e "$OUT/n.py" && -d "$OUT/keep" ]]; then pass "anything else in mcp/output is kept"; else fail "anything else in mcp/output is kept"; fi
assert_eq "no sudo when a plain rm works" "$(cat "$SUDOS")" ""
unset -f sudo

# =============================================================================
section "the shared container's other knobs are named as ignored too (G-39)"
# They reached its environment or moved its published ports; a sandbox's environment
# is fixed by the contract and it publishes none of those ports.
RET="$TMP/retired"; mkdir -p "$RET"
printf '%s\n' MSF_AUTO_UPDATE=true NUCLEI_AUTO_UPDATE=false MSF_PROJECT_LEASE_IDLE_S=60 \
    MCP_NETWORK_RECON_PORT=9000 MCP_NUCLEI_PORT=9002 MCP_METASPLOIT_PORT=9003 MCP_NMAP_PORT=9004 \
    MCP_PLAYWRIGHT_PORT=9005 MCP_SERVER_TOKEN=keep TERMINAL_MAX_SESSIONS=4 > "$RET/.env"
info() { printf 'INFO %s\n' "$*"; }
out="$(SCRIPT_DIR="$RET"; _RETIRED_KALI_NOTED=""; _env_note_retired_kali_keys)"
info() { :; }
for k in MSF_AUTO_UPDATE NUCLEI_AUTO_UPDATE MSF_PROJECT_LEASE_IDLE_S MCP_NETWORK_RECON_PORT \
         MCP_NUCLEI_PORT MCP_METASPLOIT_PORT MCP_NMAP_PORT MCP_PLAYWRIGHT_PORT; do
    assert_contains "$k is named as ignored" "$out" "$k in .env is ignored"
done
assert_contains "a port knob says why" "$out" "MCP_NMAP_PORT in .env is ignored: it moved a port of the shared Kali container"
assert_contains "an update knob says why" "$out" "MSF_AUTO_UPDATE in .env is ignored: a sandbox never updates itself"
assert_not_contains "a key still in use is not named" "$out" "MCP_SERVER_TOKEN"
assert_not_contains "the terminal cap still reaches each sandbox" "$out" "TERMINAL_MAX_SESSIONS"

# =============================================================================
section "status lists the sandboxes in a block of their own"
reset
SANDBOX_ROWS="    redamon-kali-0123456789abcdef-a1b2c3  (Up 4 minutes (healthy))"
out="$(_status_kali_sandboxes)"
assert_contains "the block's title" "$out" "Kali sandboxes (one per person, orchestrator-spawned)"
assert_contains "the container and its status" "$out" "redamon-kali-0123456789abcdef-a1b2c3  (Up 4 minutes (healthy))"
assert_contains "names and status only" "$(calls)" "--format"
assert_not_contains "no environment is read" "$(calls)" "inspect"
assert_not_contains "only this stack's sandboxes" "$out" "redamon-kali-fedcba9876543210-ffffff"
reset
assert_eq "no sandbox: no block" "$(_status_kali_sandboxes)" ""
status_body="$(declare -f cmd_status)"
assert_contains "cmd_status prints the block" "$status_body" "_status_kali_sandboxes"
assert_contains "the AI Attack Surface block stays" "$status_body" "AI Attack Surface (on-demand, orchestrator-spawned):"

# =============================================================================
section "the fixed Kali image tag (TD-29)"
export COMPOSE_PROJECT_NAME=myclone
reset
IMAGES="redamon-kali-sandbox:latest myclone-kali-sandbox:latest"
_kali_image_tag_once
assert_eq "the fixed tag exists: nothing is tagged" "$(grep -c '^tag ' "$CALLS")" "0"

reset
IMAGES="myclone-kali-sandbox:latest"
_kali_image_tag_once
assert_eq "missing: the project's image is tagged" "$(grep '^tag ' "$CALLS")" \
    "tag myclone-kali-sandbox:latest redamon-kali-sandbox:latest"

reset
IMAGES=""
_kali_image_tag_once
assert_eq "neither exists: nothing is tagged" "$(grep -c '^tag ' "$CALLS")" "0"

export COMPOSE_PROJECT_NAME=redamon
reset
IMAGES=""
_kali_image_tag_once
assert_eq "project redamon: nothing to tag" "$(grep -c '^tag ' "$CALLS")" "0"
unset COMPOSE_PROJECT_NAME

reset
_kali_image_tag_once
assert_not_contains "it touches no container" "$(calls)" "rm"

hook="$(grep -E '^[[:space:]]*install\|update\|up\)' "$REPO_ROOT/redamon.sh" | grep 'export_resource_caps' || true)"
assert_contains "install, update and up run it" "$hook" "_kali_image_tag_once"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
