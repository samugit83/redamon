#!/usr/bin/env bash
# =============================================================================
# `redamon.sh update` deletes the Tradecraft 1.x page cache volume once (T9.4):
# _old_page_cache_volume_remove_once, with docker stubbed (no daemon needed):
#   volume present -> removed, marker written;  second run -> nothing;
#   volume in use  -> a warning, exit 0, no marker (the next update tries again);
#   no volume      -> the marker only.  .env is never touched (R-001).
# Run:  bash tests/tradecraft_cache_volume_test.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the script (the BASH_SOURCE guard prevents command dispatch), then relax -e so a
# failing assertion does not abort the run (tests/redamon_preflight_test.sh's pattern).
# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }

WARNED=""; INFOED=""
info() { INFOED+="$*"$'\n'; }
warn() { WARNED+="$*"$'\n'; }
error() { :; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# The marker and a stand-in .env live in a scratch folder, never the checkout's.
OLD_PAGE_CACHE_MARKER="$TMP/.tradecraft-cache-removed"
printf 'SECRET=keep-me\n' > "$TMP/.env"
ENV_BEFORE="$(cat "$TMP/.env")"

# docker stub: VOLUME present|absent|in-use; records every call.
VOLUME=present; CALLS=""
docker() {
    CALLS+="$*"$'\n'
    case "$1 $2" in
        "volume inspect") [[ "$VOLUME" != absent ]] ;;
        "volume rm") if [[ "$VOLUME" == in-use ]]; then return 1; fi; VOLUME=absent; return 0 ;;
        *) return 0 ;;
    esac
}

reset() { CALLS=""; WARNED=""; INFOED=""; rm -f "$OLD_PAGE_CACHE_MARKER"; }

printf '\n\033[1m== the volume is there ==\033[0m\n'
reset; VOLUME=present
_old_page_cache_volume_remove_once; rc=$?
assert_eq "exit 0" "$rc" "0"
assert_eq "the volume is removed" "$VOLUME" "absent"
[[ "$CALLS" == *"volume rm redamon_tradecraft_cache"* ]] && pass "it removes redamon_tradecraft_cache" || fail "no rm of the volume: $CALLS"
[[ -f "$OLD_PAGE_CACHE_MARKER" ]] && pass "the marker is written" || fail "no marker"
[[ "$INFOED" == *"Removed the old Tradecraft page cache"* ]] && pass "it says so" || fail "no info line"

printf '\n\033[1m== a second run ==\033[0m\n'
CALLS=""; VOLUME=present
_old_page_cache_volume_remove_once; rc=$?
assert_eq "exit 0" "$rc" "0"
assert_eq "nothing is asked of docker" "$CALLS" ""
assert_eq "a volume made later is left alone" "$VOLUME" "present"

printf '\n\033[1m== the volume is in use ==\033[0m\n'
reset; VOLUME=in-use
_old_page_cache_volume_remove_once; rc=$?
assert_eq "exit 0" "$rc" "0"
[[ "$WARNED" == *"still in use"* ]] && pass "a warning" || fail "no warning"
[[ ! -f "$OLD_PAGE_CACHE_MARKER" ]] && pass "no marker: the next update tries again" || fail "marker written"
VOLUME=present; _old_page_cache_volume_remove_once
assert_eq "the next run removes it" "$VOLUME" "absent"

printf '\n\033[1m== no volume ==\033[0m\n'
reset; VOLUME=absent
_old_page_cache_volume_remove_once; rc=$?
assert_eq "exit 0" "$rc" "0"
[[ -f "$OLD_PAGE_CACHE_MARKER" ]] && pass "the marker only" || fail "no marker"
[[ "$CALLS" != *"volume rm"* ]] && pass "no rm" || fail "an rm without a volume"

printf '\n\033[1m== wiring ==\033[0m\n'
assert_eq ".env untouched" "$(cat "$TMP/.env")" "$ENV_BEFORE"
body="$(declare -f cmd_update)"
[[ "$body" == *"_old_page_cache_volume_remove_once"* ]] && pass "cmd_update calls it" || fail "cmd_update does not call it"
# After the stack is recreated (the agent no longer mounts the volume): after the health check.
before="${body%%_old_page_cache_volume_remove_once*}"
[[ "$before" == *"verify_core_running"* ]] && pass "after the recreate and its health check" || fail "called before the recreate"
grep -q '^\.tradecraft-cache-removed$' "$REPO_ROOT/.gitignore" && pass "the marker is gitignored" || fail "the marker is not gitignored"
! grep -q 'tradecraft_cache' "$REPO_ROOT/docker-compose.yml" && pass "Compose no longer mounts or declares the volume" || fail "Compose still names the volume"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
