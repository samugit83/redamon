#!/usr/bin/env bash
# =============================================================================
# `./redamon.sh update` applies a changed .env to the running services.
#
# An update with nothing to pull used to return at "Already up to date", and one
# that rebuilt some images recreated only those. A switch changed in .env by hand,
# or seeded by a single-host deploy (AGENT_IN_THE_LOOP_ENABLED,
# WORKSPACE_URL_IMPORT_ENABLED), then reached its container only at the next
# release that rebuilt it. The deploy cannot recreate a service itself: the
# agent's config also holds values only redamon.sh computes (HOST_LAN_IP, the CPU
# caps, the GPU overlay), so a bare compose call recreates it wrongly every time.
#
# Hermetic: sources redamon.sh with docker and the side-effect functions stubbed.
# Run:  bash tests/redamon_update_env_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/redamon.sh"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

apply_env() {   # apply_env <running services> [preflight rc]: the calls made, one per line
    ( cd "$REPO_ROOT"
      # shellcheck disable=SC1090
      source "$SCRIPT"; set +e
      LOG="$W/log"; : > "$LOG"; RUNNING=" $1 "; PREFLIGHT_RC="${2:-0}"
      _service_running()     { [[ "$RUNNING" == *" $1 "* ]]; }
      docker()               { echo "docker $*" >> "$LOG"; }
      ensure_auth_secrets()  { echo "ensure_auth_secrets" >> "$LOG"; }
      mcp_server_preflight() { echo "mcp_server_preflight" >> "$LOG"; return "$PREFLIGHT_RC"; }
      _plugins_prepare()     { echo "_plugins_prepare" >> "$LOG"; }
      export_resource_caps() { echo "export_resource_caps" >> "$LOG"; }
      plugins_converge()     { echo "plugins_converge" >> "$LOG"; }
      info() { :; }
      _update_apply_env; echo "rc=$?" >> "$LOG" ) >/dev/null 2>&1
    echo "rc=$?" >> "$W/log"
    cat "$W/log"
}

echo "== nothing to pull: the running services get the current .env =="
out="$(apply_env "postgres neo4j agent webapp")"
want=$'ensure_auth_secrets\nmcp_server_preflight\n_plugins_prepare\nexport_resource_caps\ndocker compose up -d --no-deps postgres neo4j agent webapp\nplugins_converge\nrc=0\nrc=0'
[[ "$out" == "$want" ]] && ok "secrets, preflight, overlays and caps first, then one compose up of the running services" \
    || bad "the calls" "$(tr '\n' '|' <<<"$out")" "$(tr '\n' '|' <<<"$want")"
grep -q -- '--no-deps' <<<"$out" && ok "--no-deps: a stopped dependency is not started" || bad "--no-deps" "absent" "present"
grep -q -- '--force-recreate' <<<"$out" && bad "no forced recreate" "--force-recreate" "absent" \
    || ok "no --force-recreate: compose recreates only a service whose config changed"

out="$(apply_env "agent")"
grep -qx 'docker compose up -d --no-deps agent' <<<"$out" && ok "a stopped service stays stopped" \
    || bad "only the running services" "$(tr '\n' '|' <<<"$out")" "up -d --no-deps agent"
! grep -q plugins_converge <<<"$out" && ok "no plugin convergence without a running webapp" \
    || bad "no plugin convergence without the webapp" "called" "not called"

out="$(apply_env "")"
[[ "$out" == $'rc=0\nrc=0' ]] && ok "a stack that is down is left alone, secrets untouched" \
    || bad "a stopped stack" "$(tr '\n' '|' <<<"$out")" "no call"

out="$(apply_env "agent webapp" 1)"
! grep -q 'docker compose up' <<<"$out" && ok "a failing MCP preflight recreates nothing" \
    || bad "the preflight gates the recreate" "$(tr '\n' '|' <<<"$out")" "no compose up"
grep -qx 'rc=1' <<<"$out" && ok "and the update fails" || bad "the update fails" "$(tr '\n' '|' <<<"$out")" "rc=1"

echo
echo "== the call sites in cmd_update =="
UPDATE_BODY="$(awk '/^cmd_update\(\) \{/{on=1} on{print} on&&/^}/{exit}' "$SCRIPT")"
up_to_date="$(awk '/if \[\[ "\$old_head" == "\$new_head" \]\]; then/{on=1} on{print} on&&/^        fi$/{exit}' <<<"$UPDATE_BODY")"
apply_line="$(grep -n '_update_apply_env' <<<"$up_to_date" | head -1 | cut -d: -f1)"
return_line="$(grep -n '^ *return$' <<<"$up_to_date" | head -1 | cut -d: -f1)"
[[ -n "$apply_line" && -n "$return_line" && "$apply_line" -lt "$return_line" ]] \
    && ok "\"Already up to date\" applies the .env before it returns" \
    || bad "the up-to-date path applies the .env" "apply=$apply_line return=$return_line" "apply before return"
restart_line="$(grep -n 'Restarting rebuilt services' <<<"$UPDATE_BODY" | head -1 | cut -d: -f1)"
converge_line="$(grep -n '^ *_converge_running_core$' <<<"$UPDATE_BODY" | head -1 | cut -d: -f1)"
prepare_line="$(grep -n '_plugins_prepare || exit 1' <<<"$UPDATE_BODY" | head -1 | cut -d: -f1)"
[[ -n "$converge_line" && -n "$restart_line" && "$converge_line" -gt "$restart_line" ]] \
    && ok "an update that rebuilt some images also converges the others" \
    || bad "the partial-rebuild path converges" "restart=$restart_line converge=$converge_line" "after the restarts"
[[ -n "$prepare_line" && -n "$converge_line" && "$prepare_line" -lt "$converge_line" ]] \
    && ok "with the plugins overlay already in COMPOSE_FILE" \
    || bad "the overlay is loaded first" "prepare=$prepare_line converge=$converge_line" "prepare first"

echo
echo "redamon update env suite: passed $PASS, failed $FAIL"
[[ "$FAIL" -eq 0 ]]
