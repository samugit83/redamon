#!/usr/bin/env bash
# =============================================================================
# Agent Workspace URL import on a single-host deploy.
# Run:  bash tests/deploy_workspace_env_test.sh
#
# WHY THIS MATTERS: URL import makes the server fetch public URLs a signed-in user
# names. An operator of a public host must be able to turn it off from the deploy's
# own .env, so the switch has to pass every hop: .env.example, build_deploy_env, the
# init AND update seeds (before redamon.sh runs), then the agent's compose block.
# Static: no SSH, no Docker.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$REPO_ROOT/tooling/deploy/single-host"
DEPLOY="$DEPLOY_DIR/deploy.sh"
OVERLAY="$DEPLOY_DIR/compose/docker-compose.prod.yml"
ENV_EXAMPLE="$DEPLOY_DIR/.env.example"
COMPOSE="$REPO_ROOT/docker-compose.yml"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }

# A function's text; cmd_* bodies run to the next top-level cmd_* or banner comment,
# because their remote heredocs define functions of their own.
body_of() {
    if [[ "$1" == cmd_* ]]; then
        awk -v f="$1" '$0 ~ "^"f"\\(\\) \\{" {on=1; print; next}
                       on && (/^cmd_[a-z_]+\(\) \{/ || /^# ={20,}/) {exit} on {print}' "$DEPLOY"
    else
        awk -v f="$1" '$0 ~ "^"f"\\(\\) \\{" {on=1} on {print} on && /^}/ {exit}' "$DEPLOY"
    fi
}

echo "== the URL import switch reaches the agent =="
grep -qE '^WORKSPACE_URL_IMPORT_ENABLED=' "$ENV_EXAMPLE" && ok ".env.example documents WORKSPACE_URL_IMPORT_ENABLED" \
    || bad ".env.example documents the switch" "absent" "WORKSPACE_URL_IMPORT_ENABLED="
body_of build_deploy_env | grep -qw WORKSPACE_URL_IMPORT_ENABLED && ok "build_deploy_env ships it" \
    || bad "build_deploy_env ships it" "absent" "in the key list"
for fn in cmd_init cmd_update; do
    body="$(body_of "$fn")"
    seed_line="$(grep -nF 'seed WORKSPACE_URL_IMPORT_ENABLED "\${WORKSPACE_URL_IMPORT_ENABLED}"' <<<"$body" | head -1 | cut -d: -f1)"
    run_line="$(grep -nE 'drive_install|\./redamon\.sh (install|update)' <<<"$body" | head -1 | cut -d: -f1)"
    [[ -n "$seed_line" ]] && ok "$fn seeds it" || bad "$fn seeds it" "absent" 'seed WORKSPACE_URL_IMPORT_ENABLED'
    if [[ -n "$seed_line" && -n "$run_line" && "$seed_line" -lt "$run_line" ]]; then
        ok "$fn seeds it before redamon.sh runs"
    else
        bad "$fn seeds it before redamon.sh runs" "seed=$seed_line run=$run_line" "seed first"
    fi
done
AGENT_BLOCK="$(awk '/^  agent:/{f=1; next} f&&/^  [a-z_-]+:$/{f=0} f' "$COMPOSE")"
grep -qE '^ +WORKSPACE_URL_IMPORT_ENABLED: \$\{WORKSPACE_URL_IMPORT_ENABLED:-true\}' <<<"$AGENT_BLOCK" \
    && ok "the agent's compose block passes it, on by default" \
    || bad "the agent's compose block passes it" "absent" 'WORKSPACE_URL_IMPORT_ENABLED: ${WORKSPACE_URL_IMPORT_ENABLED:-true}'
! grep -q 'WORKSPACE_URL_IMPORT_ENABLED' "$OVERLAY" && ok "the prod overlay does not pin it" \
    || bad "the prod overlay does not pin it" "present" "absent"

echo
echo "== the init and update remote scripts still parse =="
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
for fn in cmd_init cmd_update; do
    # Render each heredoc that seeds the switch as deploy.sh renders it (local variables
    # expanded), then parse it.
    heredoc="$(awk '/^  remote <<EOF$/{on=1; buf=""; next}
                   on&&/^EOF$/{if (buf ~ /seed WORKSPACE_URL_IMPORT_ENABLED/) {printf "%s", buf; exit} on=0; next}
                   on{buf=buf $0 "\n"}' <<<"$(body_of "$fn")")"
    rendered="$( PREAMBLE='set -euo pipefail'; REMOTE_TMP=/tmp/x; APP_DIR=redamon; NPROC=4
                 eval "cat <<EOF
$heredoc
EOF" 2>&1 )"
    if [[ -n "$heredoc" ]] && bash -n <<<"$rendered" 2>"$W/parse.err"; then
        ok "the rendered $fn script is valid bash"
    else
        bad "the rendered $fn script parses" "$(head -c 300 "$W/parse.err" 2>/dev/null)" "no syntax error"
    fi
done

echo
echo "== an update writes the operator's value into the server .env =="
# The update heredoc's own seed() and seed line, unescaped, run in a scratch checkout.
update_body="$(body_of cmd_update)"
{ grep -E '^seed\(\) \{' <<<"$update_body" | head -1
  grep -F 'seed WORKSPACE_URL_IMPORT_ENABLED' <<<"$update_body"
} | sed 's/\\\$/$/g; s/\\"/"/g' > "$W/seed.sh"
seed_into() {   # seed_into <existing server .env text> <operator value>: the resulting line
    mkdir -p "$W/app"; printf '%s' "$1" > "$W/app/.env"
    ( cd "$W/app" && WORKSPACE_URL_IMPORT_ENABLED="$2" bash -c 'set -euo pipefail; source "$0"' "$W/seed.sh" )
    grep '^WORKSPACE_URL_IMPORT_ENABLED=' "$W/app/.env" || echo "(absent)"
}
[[ "$(seed_into $'INTERNAL_API_KEY=x\n' false)" == "WORKSPACE_URL_IMPORT_ENABLED=false" ]] \
    && ok "false is written into a server .env that lacks it" || bad "false is written" "$(seed_into $'INTERNAL_API_KEY=x\n' false)" "=false"
[[ "$(seed_into $'WORKSPACE_URL_IMPORT_ENABLED=false\n' true)" == "WORKSPACE_URL_IMPORT_ENABLED=true" ]] \
    && ok "a later true replaces it" || bad "a later true replaces it" "$(seed_into $'WORKSPACE_URL_IMPORT_ENABLED=false\n' true)" "=true"
[[ "$(seed_into $'INTERNAL_API_KEY=x\n' '')" == "(absent)" ]] \
    && ok "empty leaves the server .env alone (the app default, on)" || bad "empty is a no-op" "$(seed_into $'INTERNAL_API_KEY=x\n' '')" "(absent)"
[[ "$(grep -c '^WORKSPACE_URL_IMPORT_ENABLED=' "$W/app/.env")" -le 1 ]] && ok "never written twice" \
    || bad "never written twice" "$(grep -c '^WORKSPACE_URL_IMPORT_ENABLED=' "$W/app/.env")" "1"

echo
echo "deploy workspace env suite: passed $PASS, failed $FAIL"
[[ "$FAIL" -eq 0 ]]
