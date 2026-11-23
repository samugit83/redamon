#!/usr/bin/env bash
# =============================================================================
# No per-user Kali sandbox variable is ever required (group 1, master plan §7).
# Run:  bash tests/kali_sandbox_no_required_env_test.sh
#
# The three KALI_SANDBOX_* variables are optional knobs of the recon orchestrator,
# with their defaults in recon_orchestrator/sandbox_contract.py:
#   - in the compose files each appears once, in the recon-orchestrator
#     `environment:` block, as an empty pass-through `${VAR:-}` (the orchestrator
#     has no env_file, so that line is the only way a value reaches it), and in
#     no other service or overlay;
#   - redamon.sh never writes one (no line of it that is not a comment names one,
#     but the list of retired keys it removes from .env, the switch's among them);
#   - the single-host deploy forwards each and seeds it only when the operator set
#     it: one empty default each, `seed VAR "\${VAR}"` (seed skips an empty value),
#     and no line that assigns one a value;
#   - .env.example names each, on commented lines only;
#   - the contract names exactly these three, so a fourth variable joins this list
#     on purpose, and the temporary switch KALI_SANDBOX_MODE is named nowhere.
# It also checks the three host folders the orchestrator binds into sandboxes are
# mounted into the orchestrator (it reads their host paths from Docker's mount table).
#
# Each rule is also run against a copy with a planted violation, so a parser that
# stops reading the files cannot pass. Exits 77 (the gate's "cannot run") when a
# file it reads is missing. awk only.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO_ROOT/docker-compose.yml"
ENV_EXAMPLE="$REPO_ROOT/.env.example"
REDAMON_SH="$REPO_ROOT/redamon.sh"
DEPLOY_SH="$REPO_ROOT/tooling/deploy/single-host/deploy.sh"
CONTRACT="$REPO_ROOT/recon_orchestrator/sandbox_contract.py"

for f in "$COMPOSE" "$ENV_EXAMPLE" "$REDAMON_SH" "$DEPLOY_SH" "$CONTRACT"; do
    [[ -f "$f" ]] || { echo "CANNOT RUN: $f is missing"; exit 77; }
done
command -v awk >/dev/null 2>&1 || { echo "CANNOT RUN: awk is not installed"; exit 77; }

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

VARS="KALI_SANDBOX_IDLE_MINUTES KALI_SANDBOX_MAX_CONCURRENT KALI_SANDBOX_PORT_POOL"

# Every compose file but the base: the root overlays, the single-host deploy
# overlay and the orchestrator's standalone file.
OVERLAYS=()
for f in "$REPO_ROOT"/docker-compose*.yml "$REPO_ROOT"/tooling/deploy/single-host/compose/*.yml \
         "$REPO_ROOT"/recon_orchestrator/docker-compose*.yml; do
    [[ -f "$f" && "$f" != "$COMPOSE" ]] && OVERLAYS+=("$f")
done

# "<service>|<block>|<line>" for every line that is not a comment and names a
# KALI_SANDBOX_* variable (services at two spaces, their keys at four).
compose_mentions() {
    awk '
        /^[^ #]/ { top = $0; svc = ""; blk = "" }
        top ~ /^services:/ && /^  [A-Za-z0-9_.-]+:/ { svc = $1; sub(/:.*/, "", svc); blk = "" }
        /^    [A-Za-z0-9_.-]+:/ { blk = $1; sub(/:.*/, "", blk) }
        /^[[:space:]]*#/ { next }
        /KALI_SANDBOX_[A-Z0-9_]/ { print svc "|" blk "|" $0 }
    ' "$1"
}

# Violations of the compose rule in the base file (one per line; empty when it holds).
compose_violations() {
    local m svc blk line v ok found=""
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        svc="${m%%|*}"; m="${m#*|}"; blk="${m%%|*}"; line="${m#*|}"
        ok=""
        for v in $VARS; do
            if [[ "$svc" == "recon-orchestrator" && "$blk" == "environment" && "$line" == "      $v: \${$v:-}" ]]; then
                ok="$v"
            fi
        done
        if [[ -n "$ok" ]]; then found+="$ok"$'\n'; else echo "not an empty pass-through of the orchestrator: [$svc/$blk] $line"; fi
    done < <(compose_mentions "$1")
    for v in $VARS; do
        n="$(grep -cxF "$v" <<< "$found")"
        [[ "$n" == "1" ]] || echo "$v is in the orchestrator environment $n times, not once"
    done
}

# Violations in an overlay: it names no KALI_SANDBOX_* variable at all.
overlay_violations() {
    compose_mentions "$1" | sed "s|^|$(basename "$1"): |"
}

# A line that is not a comment and names a KALI_SANDBOX_* variable.
script_violations() {
    awk '/^[[:space:]]*#/ { next } /KALI_SANDBOX_[A-Z0-9_]/ { print FILENAME ":" FNR ": " $0 }' "$1"
}

# .env.example: each variable on a commented line; none set by an uncommented one.
env_example_violations() {
    local v
    for v in $VARS; do
        grep -qE "^[[:space:]]*#[[:space:]]*$v=" "$1" || echo "$v is not documented as a commented line"
    done
    grep -nE '^[[:space:]]*(export[[:space:]]+)?KALI_SANDBOX_[A-Z0-9_]*[[:space:]]*=' "$1" \
        | sed 's/^/uncommented: /'
    grep -n 'KALI_SANDBOX_MODE' "$1" | sed 's/^/the removed switch: /'
}

# deploy.sh: one empty default per variable, a seed of its own value in init and in
# update, a seed() that skips an empty value, and nothing that gives one a value.
deploy_violations() {
    local v n
    for v in $VARS; do
        n="$(grep -oF ": \"\${$v:=}\"" "$1" | wc -l | tr -d ' ')"
        [[ "$n" == "1" ]] || echo "$v has $n empty default declarations, not 1"
        n="$(grep -cxF "seed $v \"\\\${$v}\"" "$1")"
        [[ "$n" == "2" ]] || echo "$v is seeded from its own value $n times, not 2 (init and update)"
    done
    awk '/^[[:space:]]*#/ { next }
         /KALI_SANDBOX_[A-Z0-9_]*=|KALI_SANDBOX_[A-Z0-9_]*:=[^}]|KALI_SANDBOX_MODE/ { print FILENAME ":" FNR ": " $0 }
         /^seed KALI_SANDBOX_/ && $0 !~ /^seed (KALI_SANDBOX_[A-Z_]+) "\\\$\{KALI_SANDBOX_[A-Z_]+\}"$/ { print FILENAME ":" FNR ": " $0 }' "$1"
    grep -E '^seed\(\) \{' "$1" | grep -vF '[ -z "\$v" ] && return 0;' | sed 's/^/a seed() that does not skip an empty value: /'
    [[ -n "$(grep -E '^seed\(\) \{' "$1")" ]] || echo "no seed() found"
}

# The orchestrator mounts each host folder a sandbox binds a part of.
mount_violations() {
    local mounts want
    mounts="$(awk '
        /^  recon-orchestrator:$/ { inside = 1; next }
        inside && /^  [A-Za-z0-9_.-]+:/ { exit }
        inside && /^    volumes:/ { vol = 1; next }
        inside && vol && /^    [A-Za-z0-9_.-]+:/ { vol = 0 }
        inside && vol && /^      - / { print }
    ' "$1")"
    for want in "      - ./agentic/agent-workspace:/app/agent-workspace" \
                "      - ./mcp/output:/app/mcp-output" \
                "      - ./mcp/servers:/app/mcp-servers:ro"; do
        grep -qxF -- "$want" <<< "$mounts" || echo "missing orchestrator mount:${want#      -}"
    done
}

report() {  # <label> <violations>
    if [[ -z "$2" ]]; then pass "$1"; else fail "$1"; printf '%s\n' "$2" | sed 's/^/        /' | head -20; fi
}
expect_caught() {  # <label> <violations>
    if [[ -n "$2" ]]; then pass "$1"; else fail "$1 (a planted violation was not found)"; fi
}

section "the contract names exactly these variables"
contract_vars="$(grep -oE '"KALI_SANDBOX_[A-Z0-9_]+"' "$CONTRACT" | tr -d '"' | sort -u | tr '\n' ' ')"
want_vars="$(tr ' ' '\n' <<< "$VARS" | sort -u | tr '\n' ' ')"
if [[ "$contract_vars" == "$want_vars" ]]; then pass "contract variables: $contract_vars"
else fail "contract variables differ: contract=[$contract_vars] test=[$want_vars]"; fi

section "compose: an empty pass-through of the orchestrator only"
report "docker-compose.yml" "$(compose_violations "$COMPOSE")"
for f in "${OVERLAYS[@]}"; do
    report "${f#"$REPO_ROOT"/} names none" "$(overlay_violations "$f")"
done
report "the orchestrator mounts the three sandbox host folders" "$(mount_violations "$COMPOSE")"

section "nothing writes or seeds one"
# The one line of redamon.sh that may name one: the list of retired keys it removes
# from .env (KALI_SANDBOX_MODE, the switch).
report "redamon.sh" "$(script_violations "$REDAMON_SH" | grep -vE ':[0-9]+: _RETIRED_KALI_KEYS=\(')"
retired="$(grep -E '^_RETIRED_KALI_KEYS=\(' "$REDAMON_SH")"
if [[ "$retired" == *" KALI_SANDBOX_MODE "* || "$retired" == *"(KALI_SANDBOX_MODE "* ]]; then
    pass "redamon.sh removes the retired switch from .env"
else
    fail "redamon.sh does not list KALI_SANDBOX_MODE among the keys it removes from .env"
fi
report "tooling/deploy/single-host/deploy.sh seeds each only when set" "$(deploy_violations "$DEPLOY_SH")"
DEPLOY_ENV="$REPO_ROOT/tooling/deploy/single-host/.env.example"
if [[ -f "$DEPLOY_ENV" ]]; then
    report "tooling/deploy/single-host/.env.example sets none" \
        "$(grep -nE '^[[:space:]]*(export[[:space:]]+)?KALI_SANDBOX_[A-Z0-9_]*[[:space:]]*=' "$DEPLOY_ENV")"
fi
report ".env.example documents each, commented" "$(env_example_violations "$ENV_EXAMPLE")"

section "planted violations are caught"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
sed 's|^      KALI_SANDBOX_MAX_CONCURRENT: \${KALI_SANDBOX_MAX_CONCURRENT:-}$|      KALI_SANDBOX_MAX_CONCURRENT: ${KALI_SANDBOX_MAX_CONCURRENT:?set it}|' "$COMPOSE" > "$TMP/required.yml"
expect_caught "a required orchestrator value" "$(compose_violations "$TMP/required.yml")"
sed 's|^      KALI_SANDBOX_IDLE_MINUTES: \${KALI_SANDBOX_IDLE_MINUTES:-}$|      KALI_SANDBOX_IDLE_MINUTES: 20|' "$COMPOSE" > "$TMP/pinned.yml"
expect_caught "a value pinned in compose" "$(compose_violations "$TMP/pinned.yml")"
awk '{ print } /^  agent:$/ { a = 1 } a && /^    environment:$/ { print "      KALI_SANDBOX_PORT_POOL: ${KALI_SANDBOX_PORT_POOL:-}"; a = 0 }' \
    "$COMPOSE" > "$TMP/agent.yml"
expect_caught "a variable handed to another service" "$(compose_violations "$TMP/agent.yml")"
grep -vF '      KALI_SANDBOX_PORT_POOL: ${KALI_SANDBOX_PORT_POOL:-}' "$COMPOSE" > "$TMP/dropped.yml"
expect_caught "a variable dropped from the orchestrator" "$(compose_violations "$TMP/dropped.yml")"
printf 'services:\n  webapp:\n    environment:\n      KALI_SANDBOX_IDLE_MINUTES: 5\n' > "$TMP/overlay.yml"
expect_caught "an overlay that sets one" "$(overlay_violations "$TMP/overlay.yml")"
printf 'cmd_up() {\n    echo "KALI_SANDBOX_IDLE_MINUTES=5" >> .env\n}\n' > "$TMP/script.sh"
expect_caught "a script that writes one" "$(script_violations "$TMP/script.sh")"
expect_caught "deploy.sh writing one" "$(deploy_violations "$TMP/script.sh")"
sed 's|^seed KALI_SANDBOX_IDLE_MINUTES .*|seed KALI_SANDBOX_IDLE_MINUTES 20|' "$DEPLOY_SH" > "$TMP/deploy-pinned.sh"
expect_caught "deploy.sh seeding a fixed value" "$(deploy_violations "$TMP/deploy-pinned.sh")"
sed 's|: "\${KALI_SANDBOX_PORT_POOL:=}"|: "${KALI_SANDBOX_PORT_POOL:=4500-4509}"|' "$DEPLOY_SH" > "$TMP/deploy-default.sh"
expect_caught "deploy.sh defaulting one to a value" "$(deploy_violations "$TMP/deploy-default.sh")"
grep -vE '^seed KALI_SANDBOX_MAX_CONCURRENT ' "$DEPLOY_SH" > "$TMP/deploy-unseeded.sh"
expect_caught "deploy.sh no longer seeding one" "$(deploy_violations "$TMP/deploy-unseeded.sh")"
sed 's|\[ -z "\\\$v" \] && return 0; ||' "$DEPLOY_SH" > "$TMP/deploy-seedall.sh"
expect_caught "a seed() that writes an empty value" "$(deploy_violations "$TMP/deploy-seedall.sh")"
printf '# KALI_SANDBOX_MODE=\n' >> "$TMP/env.example.mode"; cat "$ENV_EXAMPLE" >> "$TMP/env.example.mode"
expect_caught "the removed switch documented again" "$(env_example_violations "$TMP/env.example.mode")"
sed 's|^# KALI_SANDBOX_IDLE_MINUTES=|KALI_SANDBOX_IDLE_MINUTES=|' "$ENV_EXAMPLE" > "$TMP/env.example"
expect_caught "an uncommented .env.example line" "$(env_example_violations "$TMP/env.example")"
grep -vF -- '- ./mcp/output:/app/mcp-output' "$COMPOSE" > "$TMP/nomount.yml"
expect_caught "a missing orchestrator mount" "$(mount_violations "$TMP/nomount.yml")"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
