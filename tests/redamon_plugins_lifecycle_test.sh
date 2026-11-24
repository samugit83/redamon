#!/usr/bin/env bash
# =============================================================================
# Plugin platform in redamon.sh: install, update, up, up dev, down, clean,
# purge and status (master plan R-75 to R-79; owner decision 2026-10-12).
# Run:  bash tests/redamon_plugins_lifecycle_test.sh
#
# WHY THIS MATTERS: the platform always runs. Every install, update and up builds
# the runner, loads the overlay that wires the webapp to it and starts the runner
# and the proxy. A host that cannot run the platform (an Engine older than 28.0.0,
# which has no `gateway_mode_ipv4: isolated`; a weak internal key or plugin
# secret; a runner image that does not build; plugin networks Docker refuses; too
# little memory) is refused with the cause named, before any core service is
# (re)created, so nobody is left with a Plugins page that has nothing behind it.
# An update stopped after its pull says how to resume it, since a plain rerun
# would find nothing new to build.
#
# The real cmd_* functions run against a stubbed `docker` (a bash function that
# logs every call with the COMPOSE_FILE it would see), a stubbed `git`, a stubbed
# compose_build, and no-op stand-ins for the helpers that need a daemon. No
# Docker, no network.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e
# The real gate, for the section that runs it (every other section stubs it).
eval "_real_$(declare -f preflight_ram_gate)"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
has()   { if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1" "absent" "$2"; fi; }
hasnt() { if grep -qF -- "$2" <<<"$3"; then bad "$1" "present" "absent: $2"; else ok "$1"; fi; }
section() { printf '\n== %s ==\n' "$1"; }

# A space in the path on purpose: checkouts live in such directories, and a compose file
# path that is word-split breaks `up dev` there.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/redamon plugins.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
SCRIPT_DIR="$WORK"
# Resolved from SCRIPT_DIR when redamon.sh was sourced, so it must follow it here.
UPDATE_PENDING_FILE="$WORK/.update-pending"
CALLS="$WORK/calls.log"
MSGS="$WORK/messages.log"

info()    { echo "INFO $*" >> "$MSGS"; }
success() { echo "OK $*" >> "$MSGS"; }
warn()    { echo "WARN $*" >> "$MSGS"; }
error()   { echo "ERROR $*" >> "$MSGS"; }
print_banner() { :; }
record() { echo "$* | CF=${COMPOSE_FILE:-}" >> "$CALLS"; }

# --- stubs: the daemon side --------------------------------------------------
STUB_ENGINE="29.8.0"
STUB_RUNNER_IMAGE=present        # present | missing
STUB_RUNNER_BUILD_RC=0
STUB_PLUGINS_CREATE_RC=0         # what `compose ... up --no-start` (the plugin resources) returns
STUB_CONVERGE_RC=0               # what the profile `up -d plugin-runner plugin-gateway` returns
STUB_WEBAPP_NETS=""              # the running webapp's networks, one per line; "fail": inspect fails
docker() {
    record "docker $*"
    [[ "$1" == compose && "$*" == *--no-start* ]] && return "$STUB_PLUGINS_CREATE_RC"
    [[ "$1" == compose && "$*" == *"up -d"*"plugin-runner plugin-gateway"* ]] && return "$STUB_CONVERGE_RC"
    [[ "$1" == compose && "$*" == *"ps -q webapp"* ]] && { echo webapp-id; return 0; }
    case "$1" in
        version) [[ "$*" == *Server.Version* ]] && printf '%s\n' "$STUB_ENGINE"; return 0 ;;
        inspect)
            if [[ "$*" == *NetworkSettings.Networks* ]]; then
                [[ "$STUB_WEBAPP_NETS" == fail ]] && return 1
                [[ -n "$STUB_WEBAPP_NETS" ]] && printf '%s\n' "$STUB_WEBAPP_NETS"
            fi
            return 0 ;;
        image)
            if [[ "$2" == inspect && "$*" == *redamon-plugin-runner* ]]; then
                [[ "$STUB_RUNNER_IMAGE" == present ]]; return
            fi
            # The Kali image refreshed today: update's daily Metasploit refresh
            # (_kali_msf_refresh) has nothing to build here.
            [[ "$2" == inspect && "$*" == *redamon.msf_refresh* ]] && date -u +%Y%m%d
            return 0 ;;
    esac
    return 0
}
compose_build() {
    record "compose_build $*"
    if [[ "$*" == *plugin-runner* ]]; then
        if [[ "$STUB_RUNNER_BUILD_RC" -eq 0 ]]; then STUB_RUNNER_IMAGE=present; fi
        return "$STUB_RUNNER_BUILD_RC"
    fi
    return 0
}
STUB_CHANGED=""
STUB_ANCESTOR_RC=0               # what `git merge-base --is-ancestor` returns
git() {
    case "$*" in
        *"rev-parse HEAD"*) echo "newhead" ;;
        *"diff --name-only"*) printf '%s\n' "$STUB_CHANGED" ;;
        *"merge-base --is-ancestor"*) return "$STUB_ANCESTOR_RC" ;;
        *) : ;;
    esac
    return 0
}
_update_pull() { record "PULL"; }
# The update's re-exec of the pulled script: recorded, and the run ends there.
exec() { record "EXEC REDAMON_UPDATE_FROM=${REDAMON_UPDATE_FROM:-} $*"; exit 0; }
PENDING="$UPDATE_PENDING_FILE"
for fn in _migrate_reorg_layout _migrate_legacy_kbase_flag _kb_export_env _gpu_export_env \
          check_prerequisites setup_zram ensure_tool_images ensure_volume_ownership ensure_osv_db \
          ensure_sca_intel ensure_db_secrets ensure_gvm_secret pull_gvm_images ensure_admin \
          ensure_capture_proxy_running _reconcile_capture_if_running export_version \
          _assert_checkout_writable _warn_root_owned_runtime_files reconcile_gvm_admin_password \
          prune_stale_build_cache export_resource_caps _restore_runtime_tracked_files; do
    eval "$fn() { :; }"
done
preflight_ram_gate() { return 0; }
preflight_disk_gate() { return 0; }
ensure_core_images() { return 0; }
verify_core_running() { return 0; }
_service_running() { return 0; }
is_gvm_enabled() { return 1; }
is_kb_enabled() { return 1; }
get_version() { echo "6.0.0"; }

# fresh <env lines...>: a clean run with this .env
fresh() {
    : > "$CALLS"; : > "$MSGS"
    printf '%s\n' "$@" > "$WORK/.env"
    unset COMPOSE_FILE PLUGINS_FAIL_REASON REDAMON_UPDATE_FROM
    PLUGINS_READY=false; PLUGINS_COMPOSE_ARGS=""; GPU_COMPOSE_ARGS=""; PLUGINS_IMAGE_REBUILT=false
    STUB_ENGINE="29.8.0"; STUB_RUNNER_IMAGE=present; STUB_RUNNER_BUILD_RC=0; STUB_CHANGED=""
    STUB_PLUGINS_CREATE_RC=0; STUB_CONVERGE_RC=0; STUB_WEBAPP_NETS="redamon-network"$'\n'"redamon-plugins-edge"
    STUB_ANCESTOR_RC=0; rm -f "$PENDING"
}
STRONG="INTERNAL_API_KEY=$(printf 'a%.0s' {1..64})"
KEYS=("PLUGIN_RUNNER_KEY=$(printf 'b%.0s' {1..64})" "PLUGIN_CALL_TOKEN_SECRET=$(printf 'c%.0s' {1..64})")

calls()       { cat "$CALLS"; }
core_up()     { grep -E '^docker compose .*up -d .*webapp' "$CALLS" | head -1; }
compose_ups() { grep -E '^docker compose .*up( |$)' "$CALLS" | grep -v -- '--no-start'; }
plugin_ups()  { grep -E '^docker compose .*up .*plugin-(runner|gateway)' "$CALLS" | grep -v -- '--no-start'; }
plugin_creates() { grep -E '^docker compose .*up --no-start .*plugin-runner' "$CALLS"; }
line_of()     { grep -nE "$1" "$CALLS" | head -1 | cut -d: -f1; }
n()           { wc -l | tr -d ' '; }

# =============================================================================
section "(vi) appending keys never glues them onto an operator's last line (R-79)"
printf 'MCP_SERVER_ENABLED=true' > "$WORK/.env"
( ensure_auth_secrets ) >/dev/null 2>&1
eq "the operator's last line is byte-identical" "$(sed -n 1p "$WORK/.env")" "MCP_SERVER_ENABLED=true"
eq "no key was glued onto it" "$(grep -c 'truePLUGIN\|trueAUTH' "$WORK/.env")" "0"
eq "every line is a KEY=value line" "$(grep -cvE '^[A-Z_]+=' "$WORK/.env")" "0"
for k in PLUGIN_RUNNER_KEY PLUGIN_CALL_TOKEN_SECRET; do
    eq "$k appended once on its own line" "$(grep -c "^$k=" "$WORK/.env")" "1"
done
eq "the runner key is 64 hex characters" "$(grep '^PLUGIN_RUNNER_KEY=' "$WORK/.env" | cut -d= -f2 | grep -cE '^[0-9a-f]{64}$')" "1"
before="$(cat "$WORK/.env")"
( ensure_auth_secrets ) >/dev/null 2>&1
eq "a second run changes nothing" "$(cat "$WORK/.env")" "$before"
printf '' > "$WORK/.env"
( ensure_auth_secrets ) >/dev/null 2>&1
eq "an empty .env gets no leading blank line" "$(head -c1 "$WORK/.env" | grep -c '^$')" "0"

# =============================================================================
section "(iv) an old clone's end state: no plugin keys, no runner image (R-77)"
fresh "$STRONG"
STUB_RUNNER_IMAGE=missing
( cmd_up ) >/dev/null 2>&1; rc=$?
eq "up exits 0" "$rc" "0"
eq "up seeds both keys" "$(grep -cE '^PLUGIN_(RUNNER_KEY|CALL_TOKEN_SECRET)=[0-9a-f]{64}$' "$WORK/.env")" "2"
eq "the runner image is built once" "$(grep -c '^compose_build build plugin-runner' "$CALLS")" "1"
has "the core up loads the overlay" "docker-compose.plugins.yml" "$(core_up)"
eq "one profile up of both services" "$(plugin_ups | grep -c 'plugin-runner plugin-gateway')" "1"
[[ "$(line_of 'compose_build build plugin-runner')" -lt "$(line_of '^docker compose .*up -d .*webapp')" ]] \
    && ok "the image is built before the core up" || bad "build order" "after" "before"

section "an .env from a release with a switch: plugins run whatever it said"
for line in "PLUGINS_ENABLED=false" "export PLUGINS_ENABLED=0" "PLUGINS_ENABLED=true"; do
    fresh "$STRONG" "$line" "${KEYS[@]}"
    ( set -e; cmd_up ) >/dev/null 2>&1; rc=$?
    eq "$line: up exits 0 under set -e" "$rc" "0"
    has "$line: the core up loads the overlay" "docker-compose.plugins.yml" "$(core_up)"
    eq "$line: the runner and the proxy start" "$(plugin_ups | grep -c 'plugin-runner plugin-gateway')" "1"
    eq "$line: the line is gone from .env" "$(grep -c 'PLUGINS_ENABLED' "$WORK/.env")" "0"
done

# =============================================================================
section "(v) a host that cannot run the platform is refused before any core up (R-78)"
check_refused() {   # label, then the .env lines; EXPECT_CAUSE names the cause
    local label="$1"; shift
    fresh "$@"
    STUB_ENGINE="${ENGINE_FOR_CASE-29.8.0}"
    ( cmd_up ) >/dev/null 2>&1; local rc=$?
    [[ "$rc" -ne 0 ]] && ok "$label: up fails" || bad "$label: up fails" "exit 0" "non-zero"
    eq "$label: no compose up of any service" "$(compose_ups | n)" "0"
    eq "$label: exactly one error line names the cause" "$(grep '^ERROR' "$MSGS" | grep -c -- "$EXPECT_CAUSE")" "1"
}
ENGINE_FOR_CASE=27.5.1 EXPECT_CAUSE="27.5.1" check_refused "Engine 27.5.1" "$STRONG" "${KEYS[@]}"
eq "Engine 27.5.1: refused before the secrets are even touched" "$(grep -c '^AUTH_SECRET=' "$WORK/.env")" "0"
ENGINE_FOR_CASE=garbage EXPECT_CAUSE="Docker Engine" check_refused "an unparseable Engine version" "$STRONG" "${KEYS[@]}"
ENGINE_FOR_CASE="" EXPECT_CAUSE="daemon running" check_refused "an unreadable Engine (daemon down)" "$STRONG" "${KEYS[@]}"
EXPECT_CAUSE="INTERNAL_API_KEY" check_refused "INTERNAL_API_KEY=changeme" "INTERNAL_API_KEY=changeme" "${KEYS[@]}"
# An empty key (a .env copied from an older .env.example) is generated, not a reason.
for empty in "PLUGIN_RUNNER_KEY=" "PLUGIN_CALL_TOKEN_SECRET="; do
    fresh "$STRONG" "$empty"
    ( set -e; cmd_up ) >/dev/null 2>&1; rc=$?
    eq "$empty: up exits 0" "$rc" "0"
    eq "$empty: generated" "$(grep -cE "^${empty}[0-9a-f]{64}\$" "$WORK/.env")" "1"
    has "$empty: plugins come on" "docker-compose.plugins.yml" "$(core_up)"
done
fresh "$STRONG" "${KEYS[@]}"
STUB_RUNNER_IMAGE=missing; STUB_RUNNER_BUILD_RC=1
( cmd_up ) >/dev/null 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && ok "a runner image that does not build: up fails" || bad "runner build fails: up" "exit 0" "non-zero"
eq "a runner image that does not build: no compose up" "$(compose_ups | n)" "0"
eq "a runner image that does not build: the refusal names it" "$(grep '^ERROR' "$MSGS" | grep -c 'could not be built')" "1"
fresh "$STRONG" "${KEYS[@]}"
STUB_ENGINE=28.0.0
( cmd_up ) >/dev/null 2>&1; rc=$?
eq "Engine 28.0.0 exactly is enough" "$rc:$(core_up | grep -c plugins.yml)" "0:1"

# =============================================================================
section "(iii) Engine 28.1.0: the overlay before the core up, the profile after"
fresh "$STRONG" "${KEYS[@]}"
STUB_ENGINE=28.1.0
( cmd_up ) >/dev/null 2>&1
has "the overlay is in COMPOSE_FILE at the core up" "docker-compose.plugins.yml" "$(core_up)"
has "the overlay keeps the base file first" "CF=$WORK/docker-compose.yml:$WORK/docker-compose.plugins.yml" "$(core_up)"
[[ "$(line_of '^docker compose .*up -d .*webapp')" -lt "$(line_of 'up -d plugin-runner plugin-gateway')" ]] \
    && ok "the profile up comes after the core up" || bad "profile up order" "before" "after"
has "the profile up names the profile" "--profile plugins up -d plugin-runner plugin-gateway" "$(plugin_ups)"
hasnt "a plain up does not force a recreate" "force-recreate" "$(plugin_ups)"

COMPOSE_FILE_BEFORE="docker-compose.yml:/srv/overlay/docker-compose.prod.yml"
fresh "$STRONG" "${KEYS[@]}"
export COMPOSE_FILE="$COMPOSE_FILE_BEFORE"
( cmd_up ) >/dev/null 2>&1
has "a deploy's exported COMPOSE_FILE keeps its production overlay first" \
    "CF=$COMPOSE_FILE_BEFORE:$WORK/docker-compose.plugins.yml" "$(core_up)"
unset COMPOSE_FILE

fresh "$STRONG" "${KEYS[@]}"
_plugins_prepare >/dev/null 2>&1; _plugins_prepare >/dev/null 2>&1
eq "preparing twice adds the overlay once" "$(tr ':' '\n' <<<"${COMPOSE_FILE:-}" | grep -c plugins.yml)" "1"
eq "and runs the preflight once" "$(plugin_creates | n)" "1"
unset COMPOSE_FILE

section "the plugin services not starting fails the command"
fresh "$STRONG" "${KEYS[@]}"
STUB_CONVERGE_RC=1
( cmd_up ) >/dev/null 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && ok "up fails" || bad "converge fails: up" "exit 0" "non-zero"
eq "no 'ready' banner, no admin prompt: the error is the last word" "$(grep -c '^ERROR.*plugin services did not start' "$MSGS")" "1"

# =============================================================================
section "(i) update across a docker-compose.yml change (R-76)"
fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED=$'docker-compose.yml\nwebapp/src/app/page.tsx'
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1; rc=$?
eq "update exits 0" "$rc" "0"
eq "the runner image is built once" "$(grep -c '^compose_build build plugin-runner' "$CALLS")" "1"
eq "the core build does not name it" "$(grep '^compose_build build ' "$CALLS" | grep -v '^compose_build build plugin-runner' | grep -c plugin-runner)" "0"
has "the converge recreates both after the rebuild" "--profile plugins up -d --force-recreate plugin-runner plugin-gateway" "$(plugin_ups)"
eq "only the converge names them in an up" "$(plugin_ups | n)" "1"
eq "the per-service restart loop never names the runner" "$(grep -cE '^docker compose up -d --no-deps (--force-recreate )?plugin' "$CALLS")" "0"
has "the core recreate sees the overlay" "docker-compose.plugins.yml" "$(core_up)"

section "(i') update of plugin code only: rebuild the runner, recreate the pair"
fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="services/plugin_runner/supervisor/app.py"
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1
eq "the runner image is rebuilt" "$(grep -c '^compose_build build plugin-runner' "$CALLS")" "1"
eq "no core image is rebuilt for it" "$(grep '^compose_build' "$CALLS" | grep -vc plugin-runner)" "0"
has "the converge recreates both" "--profile plugins up -d --force-recreate plugin-runner plugin-gateway" "$(plugin_ups)"

section "(i'') an update that changed nothing of the platform builds nothing of it"
fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="agentic/api.py"
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1
eq "no runner build when the image exists and its sources did not change" "$(grep -c '^compose_build build plugin-runner' "$CALLS")" "0"
has "the pair is still converged, without a recreate" "--profile plugins up -d plugin-runner plugin-gateway" "$(plugin_ups)"
fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="agentic/api.py"; STUB_RUNNER_IMAGE=missing
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1
eq "a missing image is built even if nothing changed" "$(grep -c '^compose_build build plugin-runner' "$CALLS")" "1"

# =============================================================================
section "(ii) the same update with the runner build failing (X30)"
fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="docker-compose.yml"; STUB_RUNNER_BUILD_RC=1
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && ok "update fails" || bad "update with a failing runner build" "exit 0" "non-zero"
eq "no service is recreated" "$(compose_ups | n)" "0"
eq "one error names the fix" "$(grep '^ERROR' "$MSGS" | grep -c 'docker compose build plugin-runner')" "1"
has "and says a rerun finishes the update" "run ./redamon.sh update" "$(cat "$MSGS")"
eq "the pre-pull commit is kept for that rerun" "$(cat "$PENDING" 2>/dev/null)" "oldhead"

section "(ii') an update on an old Engine"
fresh "$STRONG" "${KEYS[@]}"
STUB_ENGINE=27.5.1
( cmd_update ) >/dev/null 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && ok "a current copy fails" || bad "update on 27.5.1" "exit 0" "non-zero"
eq "before the pull" "$(grep -c '^PULL' "$CALLS")" "0"
hasnt "with nothing to resume" "it finishes this update" "$(cat "$MSGS")"
eq "and no unfinished-update marker" "$([[ -e "$PENDING" ]] && echo present || echo absent)" "absent"
fresh "$STRONG" "${KEYS[@]}"
STUB_ENGINE=27.5.1; STUB_CHANGED="docker-compose.yml"
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && ok "the re-exec'd copy (after an older release pulled) fails" || bad "re-exec on 27.5.1" "exit 0" "non-zero"
eq "before building anything" "$(grep -c '^compose_build' "$CALLS")" "0"
has "and says a rerun finishes the update once Docker is upgraded" "run ./redamon.sh update" "$(cat "$MSGS")"
eq "the pre-pull commit is kept for that rerun" "$(cat "$PENDING" 2>/dev/null)" "oldhead"

# =============================================================================
section "up dev passes the overlay with its own -f files"
fresh "$STRONG" "${KEYS[@]}"
( cmd_up_dev ) >/dev/null 2>&1; rc=$?
eq "up dev exits 0" "$rc" "0"
has "the dev up lists the plugins overlay after the dev file, relative like the dev files" \
    "-f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.plugins.yml up -d" "$(core_up)"
has "up dev starts the profile with the same files" \
    "-f docker-compose.plugins.yml --profile plugins up -d plugin-runner plugin-gateway" "$(plugin_ups)"
fresh "$STRONG" "${KEYS[@]}"
STUB_ENGINE=27.5.1
( cmd_up_dev ) >/dev/null 2>&1; rc=$?
eq "up dev on an old Engine fails before any up" "$([[ $rc -ne 0 ]] && echo refused):$(compose_ups | n)" "refused:0"

section "install: the full build, then the runner in its own call; either failing stops it (ix)"
fresh "$STRONG" "${KEYS[@]}"
( cmd_install ) >/dev/null 2>&1; rc=$?
eq "install exits 0" "$rc" "0"
eq "the full build is the first build" "$(grep '^compose_build' "$CALLS" | head -1 | cut -d'|' -f1 | sed 's/ *$//')" \
   "compose_build --profile tools --profile capture build"
eq "the runner is built in its own call" "$(grep -c '^compose_build build plugin-runner' "$CALLS")" "1"
fresh "$STRONG" "${KEYS[@]}"
STUB_RUNNER_BUILD_RC=1
( cmd_install ) >/dev/null 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && ok "install fails when the runner build fails" || bad "install with a failing runner build" "exit 0" "non-zero"
eq "and starts nothing" "$(compose_ups | n)" "0"
fresh "$STRONG" "${KEYS[@]}"
STUB_ENGINE=27.5.1
( cmd_install ) >/dev/null 2>&1; rc=$?
eq "install on an old Engine fails before building anything" \
   "$([[ $rc -ne 0 ]] && echo refused):$(grep -c '^compose_build' "$CALLS")" "refused:0"
install_body="$(sed -n '/^cmd_install()/,/^}/p' "$REPO_ROOT/redamon.sh")"
has "install keeps its fatal build line byte for byte" $'\n    compose_build --profile tools --profile capture build\n' "$install_body"

# =============================================================================
section "(ix) down, clean and purge pass the plugins profile"
for fn in cmd_down cmd_clean cmd_purge; do
    body="$(sed -n "/^$fn()/,/^}/p" "$REPO_ROOT/redamon.sh")"
    eq "$fn: every compose down passes --profile plugins" \
       "$(grep -E 'docker compose .*down' <<<"$body" | grep -vc -- '--profile plugins')" "0"
    has "$fn: has a compose down" "down" "$(grep -E 'docker compose .*down' <<<"$body")"
done
has "purge removes volumes, so the plugins volume goes too" "--profile plugins down --volumes" \
    "$(sed -n '/^cmd_purge()/,/^}/p' "$REPO_ROOT/redamon.sh")"

# =============================================================================
section "(viii) where the platform is checked, prepared and converged, per command (S2)"
for fn in cmd_install cmd_update cmd_up cmd_up_dev; do
    body="$(sed -n "/^$fn()/,/^}/p" "$REPO_ROOT/redamon.sh")"
    eq "$fn checks the Engine exactly once" "$(grep -c '^ *require_plugin_engine' <<<"$body")" "1"
    eq "$fn prepares exactly once" "$(grep -c '^ *_plugins_prepare' <<<"$body")" "1"
    eq "$fn converges exactly once" "$(grep -c '^ *plugins_converge' <<<"$body")" "1"
    e="$(grep -n '^ *require_plugin_engine' <<<"$body" | cut -d: -f1)"
    p="$(grep -n '^ *_plugins_prepare' <<<"$body" | cut -d: -f1)"
    s="$(grep -n '^ *ensure_auth_secrets' <<<"$body" | cut -d: -f1)"
    b="$(grep -nE '^ *(compose_build|ensure_tool_images)' <<<"$body" | head -1 | cut -d: -f1)"
    u="$(grep -nE 'docker compose .*up -d|gvm_up_or_diagnose ' <<<"$body" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -v plugins | head -1 | cut -d: -f1)"
    [[ -n "$e" && -n "$b" && "$e" -lt "$b" ]] && ok "$fn: the Engine before any build" || bad "$fn order" "engine=$e build=$b" "engine first"
    [[ -n "$p" && -n "$s" && "$s" -lt "$p" ]] && ok "$fn: prepare after ensure_auth_secrets" || bad "$fn order" "p=$p s=$s" "secrets first"
    [[ -n "$u" && "$p" -lt "$u" ]] && ok "$fn: prepare before the first compose up" || bad "$fn order" "p=$p up=$u" "prepare first"
    eq "$fn: a failed prepare or converge stops it" \
       "$(grep -cE '^ *(_plugins_prepare|plugins_converge)\b.*\|\| exit 1$' <<<"$body")" "2"
done
for fn in cmd_kb_build cmd_kb_update cmd_kb_rebuild cmd_kb_stats _kb_bootstrap; do
    body="$(sed -n "/^$fn()/,/^}/p" "$REPO_ROOT/redamon.sh")"
    eq "$fn neither prepares nor converges" "$(grep -cE '_plugins_prepare|plugins_converge' <<<"$body")" "0"
done
up_body="$(sed -n '/^cmd_update()/,/^}/p' "$REPO_ROOT/redamon.sh")"
p="$(grep -n '^ *_plugins_prepare' <<<"$up_body" | cut -d: -f1)"
x="$(grep -n 'exec bash' <<<"$up_body" | cut -d: -f1)"
e="$(grep -n '^ *require_plugin_engine' <<<"$up_body" | cut -d: -f1)"
l="$(grep -n '^ *_update_pull' <<<"$up_body" | cut -d: -f1)"
[[ "$x" -lt "$p" ]] && ok "update prepares only after the re-exec of the pulled script" || bad "update order" "p=$p exec=$x" "after"
[[ -n "$e" && -n "$l" && "$e" -lt "$l" ]] && ok "update checks the Engine before the pull" || bad "update order" "engine=$e pull=$l" "before"
map="$(sed -n '/^_map_core_changes()/,/^}/p' "$REPO_ROOT/redamon.sh")"
eq "the runner is never in _map_core_changes" "$(grep -c 'plugin' <<<"$map")" "0"
eq "the runner is never in the literal rebuild_core list" "$(grep -E 'rebuild_core=\(' <<<"$up_body" | grep -c plugin)" "0"

# =============================================================================
section "memory governor and CPU caps"
fresh "$STRONG"
has "the runner spec is always budgeted" "$_MEM_SPEC_PLUGINS" "$(_mem_specs)"
is_gvm_enabled() { return 0; }
has "with GVM too" "$_MEM_SPEC_PLUGINS" "$(_mem_specs)"
is_gvm_enabled() { return 1; }
eq "the spec is a burst-tier PLUGIN_RUNNER" "$(cut -d: -f1,4 <<<"$_MEM_SPEC_PLUGINS")" "PLUGIN_RUNNER:b"
has "the managed vars include PLUGIN_RUNNER_MEM" "PLUGIN_RUNNER_MEM" "$(_mem_managed_vars)"
BUILD_NCPU=1; unset PLUGIN_RUNNER_CPUS
_export_cpu_cap PLUGIN_RUNNER_CPUS 2
eq "the runner CPU cap is clamped to the cores" "${PLUGIN_RUNNER_CPUS:-}" "1"
has "export_cpu_caps covers the runner" "PLUGIN_RUNNER_CPUS 2" "$(sed -n '/^export_cpu_caps()/,/^}/p' "$REPO_ROOT/redamon.sh")"
eq "status maps the runner's container to its spec" "$(sed -n '/^_status_expected_mb()/,/^}/p' "$REPO_ROOT/redamon.sh" | grep -c 'plugin-runner) key=PLUGIN_RUNNER')" "1"

# =============================================================================
section "status names the services' state, or why the host cannot run them"
plain() { sed 's/\x1b\[[0-9;]*m//g' | tr -s ' '; }
fresh "$STRONG" "${KEYS[@]}"
STUB_ENGINE=27.5.1
out="$(_status_plugins_report | plain)"
has "a host that cannot run it: says so" "PLUGINS: cannot run (" "$out"
has "and names the cause" "27.5.1" "$out"
eq "status builds nothing" "$(grep -c '^compose_build' "$CALLS")" "0"
fresh "$STRONG" "${KEYS[@]}"
STUB_RUNNER_IMAGE=missing
has "an unbuilt image: says how to build it" "./redamon.sh up builds it" "$(_status_plugins_report | plain)"
eq "and status still builds nothing" "$(grep -c '^compose_build' "$CALLS")" "0"
fresh "$STRONG" "${KEYS[@]}"
out="$(_status_plugins_report | plain)"
has "a host that can: the services' state" "PLUGINS: runner:" "$out"
has "status asks compose for the two services" "--profile plugins ps" "$(calls)"

# =============================================================================
section "(xi) secrets the webapp would refuse are refused here, with the cause named"
SHORT="$(printf 'c%.0s' {1..31})"; SAME="$(printf 'd%.0s' {1..40})"
EXPECT_CAUSE="PLUGIN_RUNNER_KEY is empty" check_refused "a runner key left as changeme" \
    "$STRONG" "PLUGIN_RUNNER_KEY=changeme" "${KEYS[1]}"
EXPECT_CAUSE="PLUGIN_CALL_TOKEN_SECRET is empty" check_refused "a token secret left as changeme" \
    "$STRONG" "${KEYS[0]}" "PLUGIN_CALL_TOKEN_SECRET=changeme"
EXPECT_CAUSE="32" check_refused "a token secret of 31 characters" \
    "$STRONG" "${KEYS[0]}" "PLUGIN_CALL_TOKEN_SECRET=$SHORT"
EXPECT_CAUSE="equals AUTH_SECRET" check_refused "a token secret equal to AUTH_SECRET" \
    "$STRONG" "${KEYS[0]}" "PLUGIN_CALL_TOKEN_SECRET=$SAME" "AUTH_SECRET=$SAME"
# The runner holds its key: a runner escape must not yield the key that signs call tokens.
EXPECT_CAUSE="equals PLUGIN_RUNNER_KEY" check_refused "a token secret equal to the runner key" \
    "$STRONG" "PLUGIN_RUNNER_KEY=$SAME" "PLUGIN_CALL_TOKEN_SECRET=$SAME"
EXPECT_CAUSE="equals INTERNAL_API_KEY" check_refused "a token secret equal to INTERNAL_API_KEY" \
    "INTERNAL_API_KEY=$SAME" "${KEYS[0]}" "PLUGIN_CALL_TOKEN_SECRET=$SAME"
EXPECT_CAUSE="equals AGENT_WS_TICKET_SECRET" check_refused "a token secret equal to AGENT_WS_TICKET_SECRET" \
    "$STRONG" "${KEYS[0]}" "PLUGIN_CALL_TOKEN_SECRET=$SAME" "AGENT_WS_TICKET_SECRET=$SAME"
# Compose's reading of .env decides what the containers get, so the preflight reads it the
# same way: the last assignment wins, quotes and an inline comment are not part of the value.
EXPECT_CAUSE="PLUGIN_RUNNER_KEY is empty" check_refused "a strong runner key overridden by a later changeme" \
    "$STRONG" "${KEYS[@]}" "PLUGIN_RUNNER_KEY=changeme"
fresh "$STRONG" "PLUGIN_RUNNER_KEY=\"$(printf 'e%.0s' {1..64})\" # quoted" "${KEYS[1]}"
( set -e; cmd_up ) >/dev/null 2>&1; rc=$?
eq "a quoted runner key with an inline comment is accepted" "$rc" "0"

# =============================================================================
section "(xii) Docker refusing the plugin networks or volume: refused before the core up (R-78)"
fresh "$STRONG" "${KEYS[@]}"
STUB_PLUGINS_CREATE_RC=1
( cmd_up ) >/dev/null 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && ok "up fails" || bad "networks refused: up" "exit 0" "non-zero"
eq "the plugin resources were tried once" "$(plugin_creates | n)" "1"
eq "no compose up of any service" "$(compose_ups | n)" "0"
eq "one error names the cause" "$(grep '^ERROR' "$MSGS" | grep -c 'plugin networks')" "1"
fresh "$STRONG" "${KEYS[@]}"
( set -e; cmd_up ) >/dev/null 2>&1
[[ -n "$(line_of 'up [-]-no-start')" && "$(line_of 'up [-]-no-start')" -lt "$(line_of '^docker compose .*up -d .*webapp')" ]] \
    && ok "the resources are created before the core up" || bad "create order" "after or absent" "before"

# =============================================================================
section "(xiii) a docker-compose.override.yml (dev mode) stays loaded with the overlay"
fresh "$STRONG" "${KEYS[@]}"
: > "$WORK/docker-compose.override.yml"
( set -e; cmd_up ) >/dev/null 2>&1
has "base, override, then the plugins overlay" \
    "CF=$WORK/docker-compose.yml:$WORK/docker-compose.override.yml:$WORK/docker-compose.plugins.yml" "$(core_up)"
rm -f "$WORK/docker-compose.override.yml"

# =============================================================================
section "(xiv) a host whose memory cannot also hold the runner is refused"
preflight_ram_gate() { _real_preflight_ram_gate; }
detect_build_resources() { BUILD_MEM_MB=6300; BUILD_RES_SOURCE=stub; }
fresh "$STRONG" "${KEYS[@]}"
allocate_memory() { if [[ " $(_mem_specs) " == *" $_MEM_SPEC_PLUGINS "* ]]; then _ALLOC_SHORTFALL_MB=137; return 1; fi; return 0; }
( set -e; cmd_up ) >/dev/null 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && ok "up fails" || bad "short only of the runner: up" "exit 0" "non-zero"
eq "nothing started" "$(compose_ups | n)" "0"
eq "one refusal names memory" "$(grep -c '^ERROR Insufficient memory' "$MSGS")" "1"
preflight_ram_gate() { return 0; }

# =============================================================================
section "(xv) update: a running webapp without the plugin wiring is recreated onto it"
# update recreates only what it rebuilds or restarts, so a webapp created without the
# overlay (a plain `docker compose up`, or a release that loaded it only on request) would
# otherwise stay off the plugin network.
restarts()  { grep -E '^docker compose up -d --no-deps --force-recreate (webapp|recon-orchestrator) ' "$CALLS"; }
restarted() { restarts | grep -c "force-recreate $1 "; }

fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="agentic/api.py"; STUB_WEBAPP_NETS=$'redamon-network\nredamon-orchestrator-net'
( set -e; REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1; rc=$?
eq "an unwired webapp: update exits 0 under set -e" "$rc" "0"
eq "the webapp is recreated once" "$(restarted webapp)" "1"
has "onto the overlay" "docker-compose.plugins.yml" "$(restarts | grep 'force-recreate webapp ')"
eq "the orchestrator is not touched for it" "$(restarted recon-orchestrator)" "0"
[[ -n "$(line_of 'force-recreate webapp ')" \
   && "$(line_of 'force-recreate webapp ')" -lt "$(line_of 'up -d plugin-runner plugin-gateway')" ]] \
    && ok "the webapp joins the plugin network before the runner starts" || bad "recreate order" "after" "before"

fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="agentic/api.py"
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1
eq "a webapp already on plugins-edge is left alone" "$(restarts | n)" "0"

fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="docker-compose.plugins.yml"
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1
eq "an overlay-only release: the webapp is recreated" "$(restarted webapp)" "1"
has "onto the overlay" "docker-compose.plugins.yml" "$(restarts | grep 'force-recreate webapp ')"
eq "the orchestrator, which the overlay does not touch, is not" "$(restarted recon-orchestrator)" "0"

fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="webapp/src/app/page.tsx"; STUB_WEBAPP_NETS="redamon-network"
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1
eq "a webapp being rebuilt anyway is not recreated a second time" "$(restarted webapp)" "0"
eq "its rebuild recreates it once" "$(grep -cE '^docker compose up -d --no-deps webapp ' "$CALLS")" "1"

fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="agentic/api.py"; STUB_WEBAPP_NETS="redamon-network"
_service_running() { return 1; }
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1
_service_running() { return 0; }
eq "a stack that is down stays down" "$(restarts | n)" "0"

fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="agentic/api.py"; STUB_WEBAPP_NETS=fail
( set -e; REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1; rc=$?
eq "an unreadable webapp: update exits 0 under set -e" "$rc" "0"
eq "and is recreated onto the overlay rather than left unwired" "$(restarted webapp)" "1"

# =============================================================================
section "(xvi) an update that stopped after its pull is finished by the next plain update"
exists() { [[ -e "$1" ]] && echo present || echo absent; }
fresh "$STRONG" "${KEYS[@]}"
echo "oldhead" > "$PENDING"
( cmd_update ) >/dev/null 2>&1; rc=$?
eq "the rerun hands over to the pulled script" "$rc" "0"
has "diffing from where the stopped update started, though HEAD did not move" \
    "EXEC REDAMON_UPDATE_FROM=oldhead bash $WORK/redamon.sh update" "$(calls)"
has "and says so" "Finishing the update that started at oldhead" "$(cat "$MSGS")"
hasnt "instead of 'Already up to date'" "Already up to date" "$(cat "$MSGS")"

fresh "$STRONG" "${KEYS[@]}"
echo "elsewhere" > "$PENDING"; STUB_ANCESTOR_RC=1
( cmd_update ) >/dev/null 2>&1
eq "a marker outside this checkout's history is dropped" "$(exists "$PENDING")" "absent"
has "with a warning" "stale unfinished-update marker" "$(cat "$MSGS")"
has "and the update finds nothing to do" "Already up to date" "$(cat "$MSGS")"
eq "without handing over" "$(grep -c '^EXEC' "$CALLS")" "0"
# The real warn prints to stdout; inside the command substitution that reads the marker,
# a warning on stdout would be taken for the commit to diff from.
echo "elsewhere" > "$PENDING"
eq "the stale-marker warning never reaches the captured commit" \
   "$( warn() { echo "[WARN] $*"; }; _update_pending_base newhead 2>/dev/null )" ""
STUB_ANCESTOR_RC=0; echo "oldhead" > "$PENDING"
eq "a valid marker yields exactly its commit" \
   "$( warn() { echo "[WARN] $*"; }; info() { echo "[INFO] $*"; }; _update_pending_base newhead 2>/dev/null )" "oldhead"
rm -f "$PENDING"

fresh "$STRONG" "${KEYS[@]}"
( cmd_update ) >/dev/null 2>&1
has "no marker, nothing pulled: already up to date" "Already up to date" "$(cat "$MSGS")"

fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="agentic/api.py"
( set -e; REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1; rc=$?
eq "a finished update exits 0" "$rc" "0"
eq "and removes the marker" "$(exists "$PENDING")" "absent"

fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="agentic/api.py"; STUB_CONVERGE_RC=1
( REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1
eq "an update whose plugin services did not start keeps the marker" "$(cat "$PENDING" 2>/dev/null)" "oldhead"

fresh "$STRONG" "${KEYS[@]}"
echo "oldhead" > "$PENDING"
( cmd_install ) >/dev/null 2>&1; rc=$?
eq "install finishes it too (every image rebuilt): exits 0" "$rc" "0"
eq "and removes the marker" "$(exists "$PENDING")" "absent"

fresh "$STRONG" "${KEYS[@]}"
echo "oldhead" > "$PENDING"
( cmd_up ) >/dev/null 2>&1; rc=$?
eq "up with an unfinished update still starts" "$rc" "0"
eq "but warns once that the images may be older than the code" "$(grep -c '^WARN An update stopped before it finished' "$MSGS")" "1"
eq "and leaves the marker for update to finish" "$(exists "$PENDING")" "present"
fresh "$STRONG" "${KEYS[@]}"
( cmd_up ) >/dev/null 2>&1
eq "no marker: no warning" "$(grep -c 'An update stopped' "$MSGS")" "0"

# =============================================================================
section "(xvii) an update of a stopped stack starts no plugin service"
fresh "$STRONG" "${KEYS[@]}"
STUB_CHANGED="services/plugin_runner/supervisor/app.py"
_service_running() { return 1; }
( set -e; REDAMON_UPDATE_FROM=oldhead cmd_update ) >/dev/null 2>&1; rc=$?
_service_running() { return 0; }
eq "update exits 0" "$rc" "0"
eq "the runner image is still rebuilt" "$(grep -c '^compose_build build plugin-runner' "$CALLS")" "1"
eq "but neither plugin service is started" "$(plugin_ups | n)" "0"
eq "and the update counts as finished" "$(exists "$PENDING")" "absent"

# =============================================================================
section "(xviii) the INTERNAL_API_KEY refusal names a fix that works"
# ensure_auth_secrets generates the key only when its line is missing, so a weak value
# is fixed by deleting the line, not by rerunning install.
fresh "INTERNAL_API_KEY=changeme" "${KEYS[@]}"
( cmd_up ) >/dev/null 2>&1
has "delete the line" "INTERNAL_API_KEY is unset or 'changeme' (delete the line; the next ./redamon.sh up generates it)" "$(cat "$MSGS")"

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
