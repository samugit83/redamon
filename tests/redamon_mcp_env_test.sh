#!/usr/bin/env bash
# =============================================================================
# Inbound MCP server: env wiring + the enable preflight.
# Run:  bash tests/redamon_mcp_env_test.sh
#
# WHY THIS MATTERS, twice over:
#
# 1. THE WEBAPP HAS NO env_file. A variable set only in .env never reaches it,
#    so MCP_SERVER_ENABLED must also be listed in the webapp's compose
#    `environment:` block. That exact class of bug is already recorded for the
#    orchestrator (CHANGELOG 6.2.7); this pins it for the MCP knobs before it
#    can happen a third time.
#
# 2. THE AGENT'S AUTH FAILS OPEN with no INTERNAL_API_KEY (llm_guard `_key_ok`),
#    and the base compose publishes the agent on 0.0.0.0:8090. Enabling an
#    internet-reachable inbound surface in that state would rest the whole
#    graph-isolation story on a check that is not running, so redamon.sh
#    refuses rather than warns.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO_ROOT/docker-compose.yml"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
hasF()   { if grep -qF "$2" "$1"; then ok "$3"; else bad "$3" "absent" "$2"; fi; }

echo "== every MCP knob is in the webapp compose environment block =="
# The webapp block runs from `  webapp:` to the next top-level service key.
WEBAPP_BLOCK="$(awk '/^  webapp:/{f=1} f&&/^  [a-z_-]+:$/&&!/^  webapp:/{f=0} f' "$COMPOSE")"
for var in MCP_SERVER_ENABLED MCP_TOKEN_RETENTION_DAYS MCP_RATE_READ_PER_MIN \
           MCP_RATE_QUERY_PER_MIN MCP_RATE_WRITE_PER_MIN MCP_RATE_MUTE_PER_MIN MCP_RATE_START_PER_WINDOW \
           MCP_RATE_START_WINDOW_MS MCP_LLM_DAILY_BUDGET; do
    if grep -qE "^[[:space:]]+${var}:" <<<"$WEBAPP_BLOCK"; then
        ok "$var reaches the webapp"
    else
        bad "$var reaches the webapp" "absent from the environment block" "present"
    fi
done

echo
echo "== the flag defaults OFF =="
if grep -qE '^[[:space:]]+MCP_SERVER_ENABLED: \$\{MCP_SERVER_ENABLED:-false\}' <<<"$WEBAPP_BLOCK"; then
    ok "compose default is false"
else
    bad "compose default is false" "not :-false" ':${MCP_SERVER_ENABLED:-false}'
fi
# The tuning knobs pass through EMPTY so unset keeps the code default, never a
# compose-invented one that would drift from the documented fallback.
for var in MCP_TOKEN_RETENTION_DAYS MCP_LLM_DAILY_BUDGET MCP_RATE_READ_PER_MIN; do
    if grep -qE "^[[:space:]]+${var}: \\\$\\{${var}:-\\}" <<<"$WEBAPP_BLOCK"; then
        ok "$var passes through empty"
    else
        bad "$var passes through empty" "has a compose-side default" "\${$var:-}"
    fi
done

echo
echo "== ensure_auth_secrets writes the switch explicitly =="
D="$(mktemp -d)"
( cd "$REPO_ROOT" && ENVDIR="$D" bash -c '
    set -uo pipefail
    source ./redamon.sh
    set +e
    info(){ :; }; warn(){ :; }; error(){ :; }; success(){ :; }
    SCRIPT_DIR="$ENVDIR"
    ensure_auth_secrets
' >/dev/null 2>&1 )
hasF "$D/.env" "MCP_SERVER_ENABLED=false" "the switch is written, and written OFF"
eq "written exactly once" "$(grep -c '^MCP_SERVER_ENABLED=' "$D/.env")" "1"
hasF "$D/.env" "AGENT_IN_THE_LOOP_ENABLED=false" "the Agent in the Loop switch is written OFF"
eq "loop switch written exactly once" "$(grep -c '^AGENT_IN_THE_LOOP_ENABLED=' "$D/.env")" "1"

# A second run must not duplicate it, nor re-disable an operator's opt-in.
sed -i 's/^MCP_SERVER_ENABLED=false/MCP_SERVER_ENABLED=true/' "$D/.env"
sed -i 's/^AGENT_IN_THE_LOOP_ENABLED=false/AGENT_IN_THE_LOOP_ENABLED=true/' "$D/.env"
( cd "$REPO_ROOT" && ENVDIR="$D" bash -c '
    set -uo pipefail
    source ./redamon.sh
    set +e
    info(){ :; }; warn(){ :; }; error(){ :; }; success(){ :; }
    SCRIPT_DIR="$ENVDIR"
    ensure_auth_secrets
' >/dev/null 2>&1 )
eq "still exactly one entry" "$(grep -c '^MCP_SERVER_ENABLED=' "$D/.env")" "1"
hasF "$D/.env" "MCP_SERVER_ENABLED=true" "an operator's opt-in is not reverted"
eq "still exactly one loop switch" "$(grep -c '^AGENT_IN_THE_LOOP_ENABLED=' "$D/.env")" "1"
hasF "$D/.env" "AGENT_IN_THE_LOOP_ENABLED=true" "an operator's loop opt-in is not reverted"
rm -rf "$D"

echo
echo "== the Agent in the Loop switch reaches both services, default OFF =="
AGENT_BLOCK="$(awk '/^  agent:/{f=1} f&&/^  [a-z_-]+:$/&&!/^  agent:/{f=0} f' "$COMPOSE")"
for blk in AGENT_BLOCK WEBAPP_BLOCK; do
    if grep -qE '^[[:space:]]+AGENT_IN_THE_LOOP_ENABLED: \$\{AGENT_IN_THE_LOOP_ENABLED:-false\}' <<<"${!blk}"; then
        ok "${blk%_BLOCK} gets AGENT_IN_THE_LOOP_ENABLED, default false"
    else
        bad "${blk%_BLOCK} gets AGENT_IN_THE_LOOP_ENABLED" "absent or not :-false" ':${AGENT_IN_THE_LOOP_ENABLED:-false}'
    fi
done
grep -qE '^[[:space:]]+MCP_RATE_LOOP_PER_MIN: ' <<<"$WEBAPP_BLOCK" \
    && ok "MCP_RATE_LOOP_PER_MIN reaches the webapp" \
    || bad "MCP_RATE_LOOP_PER_MIN reaches the webapp" "absent" "present"

echo
echo "== the preflight refuses to enable MCP on a fail-open agent =="
run_preflight() {   # run_preflight <enabled> <internal_key> -> exit code
    local dir; dir="$(mktemp -d)"
    printf 'MCP_SERVER_ENABLED=%s\nINTERNAL_API_KEY=%s\n' "$1" "$2" > "$dir/.env"
    ( cd "$REPO_ROOT" && ENVDIR="$dir" bash -c '
        set -uo pipefail
        source ./redamon.sh
        set +e
        info(){ :; }; warn(){ :; }; error(){ :; }; success(){ :; }
        SCRIPT_DIR="$ENVDIR"
        mcp_server_preflight
    ' >/dev/null 2>&1 )
    local rc=$?
    rm -rf "$dir"
    return $rc
}

run_preflight true "" ; eq "enabled + no INTERNAL_API_KEY refuses" "$?" "1"
run_preflight true changeme ; eq "enabled + 'changeme' refuses" "$?" "1"
run_preflight true "$(printf 'a%.0s' {1..64})" ; eq "enabled + a real key passes" "$?" "0"
# Disabled is always fine: the preflight guards ENABLING, not running.
run_preflight false "" ; eq "disabled + no key is fine" "$?" "0"
run_preflight false changeme ; eq "disabled + 'changeme' is fine" "$?" "0"

echo
echo "== the route path cannot collide with the outbound plugin namespace =="
# A PUBLIC_PATHS entry of '/api/mcp' would expose the outbound admin routes,
# because the middleware matches `pathname.startsWith(p + '/')`.
MW="$REPO_ROOT/webapp/src/middleware.ts"
if grep -qE "PUBLIC_PATHS.*'/api/mcp'" "$MW"; then
    bad "PUBLIC_PATHS does not contain '/api/mcp'" "present" "absent"
else
    ok "PUBLIC_PATHS does not contain the bare '/api/mcp'"
fi
hasF "$MW" "'/api/mcp-server'" "PUBLIC_PATHS contains '/api/mcp-server'"

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
