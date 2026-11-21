#!/usr/bin/env bash
# =============================================================================
# redamon.sh handles the per-user Kali sandboxes the orchestrator spawns (group 1,
# WI-S06-4). Compose does not manage them, so:
#   - remove_spawned_containers (down, clean, purge) removes every container
#     labelled redamon.sandbox=1, by label and never by name, so the shared
#     `redamon-kali` and other plans' containers are never caught;
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
        "ps -aq")
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
    assert_contains "$f removes the spawned containers" "$(declare -f "$f")" "remove_spawned_containers"
done

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
