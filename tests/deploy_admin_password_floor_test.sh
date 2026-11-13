#!/usr/bin/env bash
# =============================================================================
# deploy.sh init refuses an admin password under the webapp's 12-character
# floor (HD-12), as redamon.sh does, instead of warning and creating the admin;
# and one over bcrypt's 72 bytes, which create-admin.mjs refuses only after the
# whole build has run on the server.
#
# Extracts preflight_validate (and the helpers it calls) from deploy.sh and runs
# it in a subshell with a minimal https-ip environment: no SSH, no network.
# The numbers themselves are held equal to webapp/scripts/lib/password-policy.json
# by webapp/src/lib/authz/passwordPolicy.drift.test.ts.
#
# Run: bash tests/deploy_admin_password_floor_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/tooling/deploy/single-host/deploy.sh"
ENV_EXAMPLE="$REPO_ROOT/tooling/deploy/single-host/.env.example"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

echo "== static =="
grep -qE '^MIN_ADMIN_PASSWORD_LEN=12$' "$DEPLOY" \
  && pass "deploy.sh defines MIN_ADMIN_PASSWORD_LEN=12" || fail "no MIN_ADMIN_PASSWORD_LEN=12 in deploy.sh"
grep -qE '^MAX_ADMIN_PASSWORD_BYTES=72$' "$DEPLOY" \
  && pass "deploy.sh defines MAX_ADMIN_PASSWORD_BYTES=72" || fail "no MAX_ADMIN_PASSWORD_BYTES=72 in deploy.sh"
grep -qE '^ADMIN_PASSWORD=.*72 bytes' "$ENV_EXAMPLE" \
  && pass ".env.example names the 72-byte bound" || fail ".env.example does not name the 72-byte bound"
if grep -qi 'no app-layer' "$DEPLOY" "$ENV_EXAMPLE"; then
  fail "a stale 'no app-layer login lockout' claim is left (the webapp has one since S11)"
else
  pass "no stale 'no app-layer lockout' claim"
fi

PREFLIGHT_SRC="$(awk '/^preflight_validate\(\) \{/,/^\}/' "$DEPLOY")"
HELPERS_SRC="$(grep -E '^(c_reset=|log\(\)|ok\(\)|warn\(\)|die\(\)|hr\(\)|is_true\(\)|MIN_ADMIN_PASSWORD_LEN=|MAX_ADMIN_PASSWORD_BYTES=)' "$DEPLOY")"
[[ -n "$PREFLIGHT_SRC" ]] && pass "preflight_validate extracted" || fail "preflight_validate not found"

# Runs preflight_validate for MODE and ADMIN_PASSWORD; prints its exit code,
# keeps its stderr in $ERR_FILE.
ERR_FILE="$(mktemp)"; trap 'rm -f "$ERR_FILE"' EXIT
run_preflight() {
  local mode="$1" password="$2"
  (
    set +u
    eval "$HELPERS_SRC"
    eval "$PREFLIGHT_SRC"
    MODE="$mode"
    HOST_IP="203.0.113.10"; ACCESS_MODE="https-ip"; TLS_MODE="self-signed"; NEED_CERTBOT="false"
    GATE_MODE="none"; MCP_SERVER_ENABLED="false"; AGENT_IN_THE_LOOP_ENABLED="false"
    OPERATOR_ALLOW_CIDRS="10.0.0.0/8"; REMOTE_USER="op"
    ADMIN_NAME="Admin"; ADMIN_EMAIL="admin@example.test"; ADMIN_PASSWORD="$password"
    preflight_validate >/dev/null 2>"$ERR_FILE"
  )
  echo "$?"
}

echo "== init =="
rc="$(run_preflight init "$(printf 'a%.0s' {1..11})")"
[[ "$rc" != "0" ]] && pass "11 characters: init refused (exit $rc)" || fail "11 characters: init went on"
grep -q 'at least 12 characters' "$ERR_FILE" \
  && pass "the refusal names the 12-character floor" || fail "refusal text: $(cat "$ERR_FILE")"

rc="$(run_preflight init "$(printf 'a%.0s' {1..12})")"
[[ "$rc" == "0" ]] && pass "12 characters: preflight passes" || fail "12 characters refused: $(cat "$ERR_FILE")"

rc="$(run_preflight init "")"
[[ "$rc" != "0" ]] && pass "empty password: still refused" || fail "empty password accepted"

rc="$(run_preflight init "$(printf 'a%.0s' {1..72})")"
[[ "$rc" == "0" ]] && pass "72 bytes: preflight passes" || fail "72 bytes refused: $(cat "$ERR_FILE")"

rc="$(run_preflight init "$(printf 'a%.0s' {1..73})")"
[[ "$rc" != "0" ]] && pass "73 bytes: init refused (exit $rc)" || fail "73 bytes: init went on"
grep -q 'at most 72 bytes' "$ERR_FILE" \
  && pass "the refusal names the 72-byte bound" || fail "refusal text: $(cat "$ERR_FILE")"

# Bytes, not characters: 37 two-byte characters are 74 bytes. Whatever locale the
# operator's shell runs in must not turn this into a character count.
rc="$(LC_ALL=C.UTF-8 run_preflight init "$(printf 'é%.0s' {1..37})")"
[[ "$rc" != "0" ]] && pass "37 x 'é' (74 bytes): refused" || fail "37 x 'é' (74 bytes) accepted"
rc="$(LC_ALL=C.UTF-8 run_preflight init "$(printf 'é%.0s' {1..36})")"
[[ "$rc" == "0" ]] && pass "36 x 'é' (72 bytes): passes" || fail "36 x 'é' refused: $(cat "$ERR_FILE")"

echo "== other modes keep their behaviour =="
# Only init creates the admin from .env; harden/update never read ADMIN_PASSWORD here.
rc="$(run_preflight update "short")"
[[ "$rc" == "0" ]] && pass "update with a short .env password is not refused" || fail "update refused: $(cat "$ERR_FILE")"

echo ""
echo "-----------------------------------------"
echo "deploy admin password bounds: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]]
