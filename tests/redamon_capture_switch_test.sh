#!/usr/bin/env bash
# =============================================================================
# The HTTP Traffic Capture master switch redamon.sh reads on update and up
# (`_capture_master_switch_on`, which decides whether ensure_capture_proxy_running
# starts the orchestrator-spawned proxy).
#
# Before the identity switch every account's user_settings row holds a copy of the
# setting and one enabled row is enough. With RBAC_IDENTITY_ENABLED on, the setting
# lives in the instance settings row (step 2.4), so the switch also reads
# instance_settings.capture_proxy_enabled; a database without that table (before the
# webapp's first boot on this version) answers from the user rows alone.
#
# Pure unit test: `docker` is stubbed (it answers each psql query from fixtures and
# records the queries), no daemon needed.
# Run:  bash tests/redamon_capture_switch_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e
# The stub below reads its stdin as docker does; the suite's own stdin may never close.
exec < /dev/null

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_true()  { if eval "$2"; then pass "$1"; else fail "$1 (cmd: $2)"; fi; }
assert_false() { if eval "$2"; then fail "$1 (cmd unexpectedly true: $2)"; else pass "$1"; fi; }

QUERIES="$(mktemp)"
trap 'rm -f "$QUERIES"' EXIT
# What psql prints for each table: t, f, an empty line (no row / NULL), or "missing"
# (the table does not exist: psql prints an error on stderr and nothing on stdout).
USER_ROWS=""; INSTANCE_ROW=""
docker() {
    local sql="${*: -1}"
    printf '%s\n' "$sql" >> "$QUERIES"
    # `docker compose exec -T` forwards stdin, as this does: an exec left on the caller's
    # stdin eats its input (a read loop, a prompt answered by a pipe).
    cat > /dev/null
    case "$sql" in
        *user_settings*)     printf '%s\n' "$USER_ROWS" ;;
        *instance_settings*) if [ "$INSTANCE_ROW" = missing ]; then
                                 echo 'ERROR:  relation "instance_settings" does not exist' >&2; return 1
                             fi
                             printf '%s\n' "$INSTANCE_ROW" ;;
        *) return 1 ;;
    esac
}

case_() {
    USER_ROWS="$1"; INSTANCE_ROW="$2"; : > "$QUERIES"
}

echo "== a user row on is enough, as before (no instance read needed) =="
case_ t missing
assert_true  "user rows t -> on" "_capture_master_switch_on"
assert_false "the instance table is not read when a user row is on" "grep -q instance_settings \"\$QUERIES\""

echo "== the capture switch reads the instance row =="
case_ f t
assert_true  "user rows f, instance row t -> on" "_capture_master_switch_on"
case_ "" t
assert_true  "no user row, instance row t -> on" "_capture_master_switch_on"
assert_true  "it reads the singleton by its id" "grep -qF \"FROM instance_settings WHERE id = 'instance'\" \"\$QUERIES\""

echo "== off when neither says on =="
case_ f f
assert_false "user rows f, instance row f -> off" "_capture_master_switch_on"
case_ "" ""
assert_false "no user row, no instance row -> off" "_capture_master_switch_on"

echo "== a database without the instance table answers from the user rows =="
case_ f missing
assert_false "user rows f, no table -> off (the error is not read as on)" "_capture_master_switch_on"
case_ "" missing
assert_false "nothing at all -> off" "_capture_master_switch_on"

echo "== every query keeps stdin =="
case_ f t
LEFT="$(printf 'first\nsecond\n' | { _capture_master_switch_on; IFS= read -r line; printf '%s' "$line"; })"
assert_true  "no exec reads the caller's stdin" "[ \"\$LEFT\" = first ]"

echo "== the call sites =="
assert_true  "ensure_capture_proxy_running asks it first" \
    "grep -A1 '^ensure_capture_proxy_running()' \"$REPO_ROOT/redamon.sh\" | grep -q '_capture_master_switch_on || return 0'"

echo
echo "-----------------------------------------"
printf 'redamon capture switch: \033[0;32m%d passed\033[0m, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
