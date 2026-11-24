#!/usr/bin/env bash
# =============================================================================
# `./redamon.sh update` and the Kali sandbox image, which every person's sandbox
# starts from:
#   - a Kali image that does not build leaves the shared container redamon-kali
#     running, lets the rest of the update finish, keeps the unfinished-update
#     marker and ends non-zero naming the build, so a deploy cannot read the update
#     as done; a failure of any other tool image only warns, as it always did;
#   - an update with nothing to pull is a completed update too: it refreshes the
#     image's Metasploit layers once a day (never with --preview);
#   - an update with nothing to pull while this checkout's redamon-kali still
#     exists means the images predate the code (a manual `git pull`): it recreates
#     nothing, names the rebuild, and ends non-zero; `up` then removes the container;
#   - the shared container's *_HOST_PORT keys left in .env are named as ignored.
#
# redamon.sh is sourced (its BASH_SOURCE guard stops the dispatch); the real
# cmd_update and cmd_up run against a stubbed `docker`, `git` and `compose_build`,
# under redamon.sh's own `set -euo pipefail`. No Docker, no network.
# Run:  bash tests/redamon_update_kali_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()    { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()   { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()    { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
has()   { if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1" "absent" "$2"; fi; }
hasnt() { if grep -qF -- "$2" <<<"$3"; then bad "$1" "present" "absent: $2"; else ok "$1"; fi; }
section() { printf '\n== %s ==\n' "$1"; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export W REPO_ROOT

cat > "$W/stubs.sh" <<'STUBS'
# shellcheck disable=SC1091
source "$REPO_ROOT/redamon.sh"
set +e
SCRIPT_DIR="$W"
UPDATE_PENDING_FILE="$W/.update-pending"
LOG="$W/calls.log"
record() { echo "$*" >> "$LOG"; }
info()    { echo "INFO $*"; }
success() { echo "OK $*"; }
warn()    { echo "WARN $*"; }
error()   { echo "ERROR $*"; }
print_banner() { :; }
for fn in _assert_checkout_writable _warn_root_owned_runtime_files _migrate_reorg_layout \
          _migrate_legacy_kbase_flag _kb_export_env _gpu_export_env _gpu_compose_overlay \
          check_prerequisites require_plugin_engine _restore_runtime_tracked_files \
          preflight_ram_gate preflight_disk_gate export_version ensure_auth_secrets \
          ensure_wiki_checkout mcp_server_preflight ensure_volume_ownership ensure_db_secrets \
          ensure_gvm_secret ensure_osv_db ensure_sca_intel _map_plugin_consumers \
          export_resource_caps reconcile_gvm_admin_password verify_core_running \
          _confirm_root _urlscan_backfill_once _old_page_cache_volume_remove_once \
          ensure_core_images setup_zram ensure_tool_images _ensure_pentest_net; do
    eval "$fn() { :; }"
done
_plugins_build_runner() { record "PLUGINS_BUILD"; }
_plugins_prepare() { record "PLUGINS_PREPARE"; }
_update_preview() { record "PREVIEW"; return 0; }
_update_apply_env() { record "APPLY_ENV"; }
ensure_admin() { record "ENSURE_ADMIN"; }
is_gvm_enabled() { return 1; }
is_kb_enabled() { return 1; }
get_version() { echo "9.9.9"; }
_disk_free_gb() { echo 500; }
_update_pull() { record "PULL"; }
git() {
    case "$*" in
        *"rev-parse HEAD"*) echo newhead ;;
        *"diff --name-only"*) printf '%s\n' ${STUB_CHANGED:-} ;;
        *"merge-base --is-ancestor"*) return 0 ;;
    esac
    return 0
}
# The re-exec of the pulled script: recorded, and the run ends there.
exec() { record "EXEC REDAMON_UPDATE_FROM=${REDAMON_UPDATE_FROM:-} $*"; exit 0; }
_service_running() { [[ " ${STUB_RUNNING:-postgres webapp agent} " == *" $1 "* ]]; }
docker() {
    record "docker $*"
    case "$1 ${2:-}" in
        "container inspect")
            [[ "${STUB_SHARED:-1}" == 1 && "${*: -1}" == redamon-kali ]] || return 1
            echo "/redamon-kali ${STUB_SHARED_PROJECT:-kaliupd}" ;;
        "image inspect")
            if [[ "$*" == *redamon-kali-sandbox:latest* ]]; then
                [[ "${STUB_KALI_IMAGE:-1}" == 1 ]] || return 1
                [[ "$*" == *msf_refresh* ]] && printf '%s\n' "${STUB_MSF_LABEL-}"
            fi ;;
    esac
    return 0
}
# A build fails when it names an image listed in STUB_BUILD_FAILS.
compose_build() {
    record "compose_build $* STAMP=${MSF_REFRESH_STAMP:-} NOPRUNE=${REDAMON_NO_AUTO_PRUNE:-}"
    local img
    for img in ${STUB_BUILD_FAILS:-}; do
        [[ " $* " == *" $img "* ]] && return 1
    done
    return 0
}
_converge_running_core()        { record "RESTART converge"; }
plugins_converge()              { record "RESTART plugins_converge"; }
_reconcile_capture_if_running() { record "RESTART capture_refresh"; }
ensure_capture_proxy_running()  { record "RESTART capture_start"; }
STUBS

TODAY="$(date -u +%Y%m%d)"
# update [--pulled] <cmd_update args...>: OUT and RC set. --pulled runs the re-exec'd
# copy (the pull already happened); without it, an update with nothing to pull.
update() {
    local from=""
    [[ "${1:-}" == --pulled ]] && { from=oldhead; shift; }
    : > "$W/calls.log"; rm -f "$W/.update-pending"
    OUT="$( (
        # shellcheck disable=SC1091
        source "$W/stubs.sh"; set -euo pipefail
        if [[ -n "$from" ]]; then export REDAMON_UPDATE_FROM="$from"; else unset REDAMON_UPDATE_FROM; fi
        cmd_update "$@"
    ) 2>&1 </dev/null)"; RC=$?
}
calls()   { cat "$W/calls.log"; }
count()   { grep -cE -- "$1" "$W/calls.log"; }
pending() { if [[ -f "$W/.update-pending" ]]; then cat "$W/.update-pending"; else echo absent; fi; }
RM='^docker rm -f redamon-kali$'
KALI_ALONE='^compose_build --profile tools build kali-sandbox STAMP= '
MSF="^compose_build --profile tools build kali-sandbox STAMP=$TODAY "

export COMPOSE_PROJECT_NAME=kaliupd
export STUB_SHARED=1 STUB_SHARED_PROJECT=kaliupd STUB_KALI_IMAGE=1 STUB_MSF_LABEL="$TODAY" \
       STUB_BUILD_FAILS="" STUB_CHANGED="" STUB_RUNNING="postgres webapp agent"

# =============================================================================
section "a Kali image that does not build fails the update, after the rest of it"
STUB_CHANGED=mcp/kali-sandbox/Dockerfile STUB_BUILD_FAILS=kali-sandbox update --pulled
[[ "$RC" -ne 0 ]] && ok "the update ends non-zero" || bad "a failed Kali build" "exit 0" "non-zero"
eq "redamon-kali is kept: no sandbox can start from the new image yet" "$(count "$RM")" "0"
has "the services this release did not rebuild still pick up the .env" "RESTART converge" "$(calls)"
has "the plugin services are still converged" "RESTART plugins_converge" "$(calls)"
has "the admin check still runs" "ENSURE_ADMIN" "$(calls)"
has "and the capture proxy is reconciled" "RESTART capture_start" "$(calls)"
hasnt "no success is announced" "OK Updated to" "$OUT"
has "the error names the build" "docker compose --profile tools build kali-sandbox" "$OUT"
has "and the rerun that finishes the update" "run ./redamon.sh update again" "$OUT"
has "it is the last word" "ERROR" "$(tail -n4 <<<"$OUT")"
eq "the unfinished-update marker stays for that rerun" "$(pending)" "oldhead"
eq "no daily Metasploit refresh on top of the failed build" "$(count "$MSF")" "0"

STUB_KALI_IMAGE=0 STUB_CHANGED=webapp/src/app/page.tsx STUB_BUILD_FAILS=kali-sandbox update --pulled
[[ "$RC" -ne 0 ]] && ok "a missing Kali image that does not build fails it too" || bad "a missing Kali image that fails" "exit 0" "non-zero"
eq "and keeps redamon-kali" "$(count "$RM")" "0"
has "after restarting what it rebuilt" "docker compose up -d --no-deps webapp" "$(calls)"

STUB_CHANGED="mcp/kali-sandbox/Dockerfile scanners/wcvs/Dockerfile" STUB_BUILD_FAILS="wcvs kali-sandbox" update --pulled
[[ "$RC" -ne 0 ]] && ok "both failing: the update ends non-zero" || bad "both tool builds fail" "exit 0" "non-zero"
eq "and keeps redamon-kali" "$(count "$RM")" "0"

section "another tool image that does not build only warns, as before"
STUB_CHANGED="mcp/kali-sandbox/Dockerfile scanners/wcvs/Dockerfile" STUB_BUILD_FAILS=wcvs update --pulled
eq "the update exits 0" "$RC" "0"
has "with a warning naming the build" "WARN One or more tool images failed to build" "$OUT"
eq "the Kali image is built alone to learn which one failed" "$(count "$KALI_ALONE")" "1"
has "without pruning the failed image's partial cache" "NOPRUNE=1" "$(grep -E "$KALI_ALONE" "$W/calls.log")"
eq "it built, so redamon-kali goes" "$(count "$RM")" "1"
eq "and the update is finished" "$(pending)" "absent"
has "and announced" "OK Updated to v9.9.9!" "$OUT"

STUB_CHANGED=scanners/wcvs/Dockerfile STUB_BUILD_FAILS=wcvs update --pulled
eq "without the Kali image in the build: exits 0" "$RC" "0"
eq "and builds nothing more" "$(count "$KALI_ALONE")" "0"

STUB_CHANGED="mcp/kali-sandbox/Dockerfile scanners/wcvs/Dockerfile" update --pulled
eq "nothing fails: exits 0" "$RC" "0"
eq "no second build of the Kali image" "$(count "$KALI_ALONE")" "0"
eq "redamon-kali goes" "$(count "$RM")" "1"

# =============================================================================
section "nothing to pull: the daily Metasploit refresh"
STUB_SHARED=0 STUB_MSF_LABEL=20000101 update
eq "the update exits 0" "$RC" "0"
has "says it is up to date" "Already up to date" "$OUT"
eq "an older label: one refresh build" "$(count "$MSF")" "1"
l_apply="$(grep -n '^APPLY_ENV$' "$W/calls.log" | head -n1 | cut -d: -f1)"
l_msf="$(grep -nE "$MSF" "$W/calls.log" | head -n1 | cut -d: -f1)"
[[ -n "$l_apply" && -n "$l_msf" && "$l_apply" -lt "$l_msf" ]] \
    && ok "after the .env reached the services" || bad "apply < refresh" "apply=$l_apply refresh=$l_msf" "ascending"
STUB_SHARED=0 STUB_MSF_LABEL="$TODAY" update
eq "today's label: no refresh build" "$(count "$MSF")" "0"
STUB_SHARED=0 STUB_MSF_LABEL=20000101 update --preview
eq "never with --preview" "$(count "$MSF")" "0"
eq "which still exits 0" "$RC" "0"

# =============================================================================
section "nothing to pull, and this checkout's redamon-kali is still here"
STUB_MSF_LABEL=20000101 update
[[ "$RC" -ne 0 ]] && ok "the update ends non-zero" || bad "an update over images older than the code" "exit 0" "non-zero"
eq "redamon-kali is not removed" "$(count "$RM")" "0"
hasnt "the .env is not applied: nothing is recreated from the old images" "APPLY_ENV" "$(calls)"
eq "no service is started or recreated" "$(count '^docker compose (.* )?up|^RESTART')" "0"
eq "and nothing is built" "$(count '^compose_build')" "0"
hasnt "it does not claim to be up to date" "Already up to date" "$OUT"
has "it says the images predate the checkout" "the images predate this checkout" "$OUT"
for cmd in "docker compose build agent webapp" "docker compose --profile tools build kali-sandbox" "./redamon.sh up"; do
    has "it names: $cmd" "ERROR     $cmd" "$OUT"
done
STUB_MSF_LABEL=20000101 update --preview
[[ "$RC" -ne 0 ]] && ok "--preview says so as well" || bad "--preview over images older than the code" "exit 0" "non-zero"
eq "and removes nothing" "$(count "$RM")" "0"
STUB_SHARED_PROJECT=other-stack STUB_MSF_LABEL=20000101 update
eq "another compose project's redamon-kali: up to date as usual" "$RC" "0"
has "the .env is applied" "APPLY_ENV" "$(calls)"
eq "and that container is left alone" "$(count "$RM")" "0"

# The rerun after a failed Kali build is not this branch: the marker hands it over.
: > "$W/calls.log"; echo oldhead > "$W/.update-pending"
OUT="$( ( source "$W/stubs.sh"; set -euo pipefail; unset REDAMON_UPDATE_FROM; cmd_update ) 2>&1 </dev/null)"
has "after a failed Kali build the next update finishes it" "EXEC REDAMON_UPDATE_FROM=oldhead bash $W/redamon.sh update" "$(calls)"
hasnt "instead of refusing" "the images predate this checkout" "$OUT"

section "the commands it names end with up, which removes redamon-kali"
: > "$W/calls.log"
OUT="$( ( source "$W/stubs.sh"; set -euo pipefail; cmd_up ) 2>&1 </dev/null)"; RC=$?
eq "up exits 0" "$RC" "0"
eq "and removes this checkout's redamon-kali" "$(count "$RM")" "1"
l_rm="$(grep -nE "$RM" "$W/calls.log" | head -n1 | cut -d: -f1)"
l_up="$(grep -nE '^docker compose up -d' "$W/calls.log" | head -n1 | cut -d: -f1)"
[[ -n "$l_rm" && -n "$l_up" && "$l_rm" -lt "$l_up" ]] \
    && ok "before it starts the stack" || bad "rm < up" "rm=$l_rm up=$l_up" "ascending"

# =============================================================================
section "the shared container's port keys in .env are named as ignored"
# Earlier .env.example files documented these three: they moved the host side of the
# shared container's published ports, and nothing reads them now.
printf 'MSF_PROGRESS_HOST_PORT=18013\nexport HYDRA_PROGRESS_HOST_PORT=18014\nNGROK_API_HOST_PORT=14040\n' > "$W/.env"
before="$(cksum < "$W/.env")"
OUT="$( ( source "$W/stubs.sh"; _env_note_retired_kali_keys; _env_note_retired_kali_keys ) 2>&1 )"
for k in MSF_PROGRESS_HOST_PORT HYDRA_PROGRESS_HOST_PORT NGROK_API_HOST_PORT; do
    eq "$k is named once per run" "$(grep -c "^INFO $k in .env is ignored" <<<"$OUT")" "1"
done
has "with the reason that fits a port" "no person's sandbox publishes that port" "$OUT"
eq ".env is left byte for byte" "$(cksum < "$W/.env")" "$before"
printf 'NGROK_API_HOST_PORT=\n' > "$W/.env"
OUT="$( ( source "$W/stubs.sh"; _env_note_retired_kali_keys ) 2>&1 )"
eq "a bare placeholder is not named" "$OUT" ""
rm -f "$W/.env"

echo
printf 'redamon update kali suite: passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
