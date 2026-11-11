#!/usr/bin/env bash
# =============================================================================
# `./redamon.sh update` previews what the new release changes for the accounts of
# this install (webapp/scripts/rbac-upgrade-preview.mjs) after the build and before
# any service restarts (HD-31, DV-32):
#   - in a terminal it asks "Continue? [Y/n]"; No stops before the first restart and
#     keeps the unfinished-update marker, so the next `update` finishes it;
#   - anything else (the single-host deploy pipes its remote script into the shell,
#     a CI job, `update | tee`) prints and continues, and never reads stdin;
#   - a report that changes nothing for anyone asks nothing;
#   - `update --preview` pulls and builds, prints, and restarts nothing; with nothing
#     to pull it says so and stops; the flag survives the re-exec of the pulled script.
#
# The real cmd_update runs against a stubbed `docker` (a bash function logging every
# call), a stubbed `git` and no-op stand-ins for the helpers that need a daemon, under
# the same `set -euo pipefail` as redamon.sh. The terminal cases run through a real
# pseudo-terminal (python3), so the interactive check itself is exercised.
# No Docker, no network. Run:  bash tests/redamon_rbac_preview_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/redamon.sh"
PREVIEW_JS="$REPO_ROOT/webapp/scripts/rbac-upgrade-preview.mjs"
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
          preflight_disk_gate preflight_ram_gate export_version ensure_auth_secrets \
          mcp_server_preflight ensure_volume_ownership ensure_db_secrets ensure_gvm_secret \
          ensure_osv_db ensure_sca_intel _plugins_build_runner _map_plugin_consumers \
          export_resource_caps reconcile_gvm_admin_password verify_core_running ensure_admin \
          _urlscan_backfill_once; do
    eval "$fn() { :; }"
done
_plugins_prepare() { record "PLUGINS_PREPARE"; }
is_gvm_enabled() { return 1; }
get_version() { echo "9.9.9"; }
_map_core_changes() { rebuild_core=(${STUB_REBUILD:-}); }
_map_tool_changes() { rebuild_capture="${STUB_CAPTURE:-false}"; }
PULLED=false
_update_pull() { record "PULL"; [[ "${STUB_PULL_MOVES:-false}" == true ]] && PULLED=true; return 0; }
git() {
    case "$*" in
        *"rev-parse HEAD"*) if [[ "$PULLED" == true || -n "${REDAMON_UPDATE_FROM:-}" ]]; then echo newhead; else echo oldhead; fi ;;
        *"diff --name-only"*) echo "webapp/src/app/page.tsx" ;;
    esac
    return 0
}
# The re-exec of the pulled script: recorded, and the run ends there.
exec() { record "EXEC REDAMON_UPDATE_FROM=${REDAMON_UPDATE_FROM:-} $*"; exit 0; }
_service_running() { [[ " ${STUB_RUNNING:-postgres webapp} " == *" $1 "* ]]; }
docker() {
    record "docker $*"
    if [[ "$*" == *rbac-upgrade-preview.mjs* ]]; then
        # Reads whatever stdin it is given, as `docker compose run` without -T would.
        cat >/dev/null
        echo "FAKE PREVIEW: upg-member-a@e2e.local keeps the Kali terminal"
        return "${STUB_PREVIEW_RC:-10}"
    fi
    return 0
}
compose_build() { record "compose_build $*"; return 0; }
# Everything that restarts a running service, beside `docker compose up`.
_converge_running_core()       { record "RESTART converge"; }
plugins_converge()             { record "RESTART plugins_converge"; }
_reconcile_capture_if_running() { record "RESTART capture_refresh"; }
ensure_capture_proxy_running() { record "RESTART capture_start"; }
_update_apply_env()            { record "APPLY_ENV"; }
STUBS

# run <stdin text> <cmd_update args...>: a re-exec'd update (the pull already happened),
# stdin a pipe. Prints the output; RC holds the exit status.
fresh() { : > "$W/calls.log"; rm -f "$W/.update-pending"; }
run() {
    local input="$1"; shift
    fresh
    OUT="$(printf '%s' "$input" | (
        # shellcheck disable=SC1091
        source "$W/stubs.sh"; set -euo pipefail
        REDAMON_UPDATE_FROM=oldhead cmd_update "$@"
        left=""; read -r left || true; echo "LEFTOVER=$left"
    ) 2>&1)"; RC=$?
}
calls()    { cat "$W/calls.log"; }
line_of()  { grep -nF -- "$1" "$W/calls.log" | head -1 | cut -d: -f1; }
restarts() { grep -E '^docker compose (.* )?up( |$)|^RESTART' "$W/calls.log"; }
pending()  { [[ -f "$W/.update-pending" ]] && cat "$W/.update-pending" || echo absent; }
PREVIEW_CALL="docker compose run --rm --no-deps -T --entrypoint node webapp scripts/rbac-upgrade-preview.mjs"

export STUB_REBUILD=webapp STUB_PREVIEW_RC=10 STUB_RUNNING="postgres webapp" STUB_CAPTURE=false STUB_PULL_MOVES=false

# =============================================================================
section "non-interactive continues"
run $'n\n'
eq "update exits 0" "$RC" "0"
eq "the preview runs once, from the image just built, as a one-off container" "$(grep -cxF "$PREVIEW_CALL" "$W/calls.log")" "1"
has "its report is printed" "FAKE PREVIEW" "$OUT"
hasnt "nothing is asked" "Continue?" "$OUT"
p="$(line_of "$PREVIEW_CALL")"; b="$(line_of 'compose_build build webapp')"; u="$(line_of 'docker compose up -d --no-deps webapp')"
[[ -n "$b" && -n "$p" && -n "$u" && "$b" -lt "$p" && "$p" -lt "$u" ]] \
    && ok "after the build and before the restart" || bad "order build < preview < restart" "build=$b preview=$p restart=$u" "ascending"
has "the update goes on to restart the webapp" "docker compose up -d --no-deps webapp" "$(calls)"
eq "stdin is never read: what the deploy pipes in is still there" "$(grep '^LEFTOVER=' <<<"$OUT")" "LEFTOVER=n"
eq "a finished update removes the unfinished-update marker" "$(pending)" "absent"

section "a report that changes nothing for anyone, a failing report, no database"
STUB_PREVIEW_RC=0 run ""
eq "nothing changes: exits 0" "$RC" "0"
has "and restarts" "docker compose up -d --no-deps webapp" "$(calls)"
STUB_PREVIEW_RC=1 run ""
eq "the preview fails: the update still exits 0" "$RC" "0"
has "with a warning" "The upgrade preview did not run (exit 1)" "$OUT"
has "and restarts" "docker compose up -d --no-deps webapp" "$(calls)"
STUB_RUNNING="webapp" run ""
eq "the database is down: no preview container" "$(grep -cF rbac-upgrade-preview "$W/calls.log")" "0"
has "said so" "Upgrade preview skipped: the database is not running" "$OUT"
eq "and the update goes on" "$RC" "0"
STUB_REBUILD="agent" run ""
eq "the webapp was not rebuilt: nothing to preview" "$(grep -cF rbac-upgrade-preview "$W/calls.log")" "0"

# =============================================================================
section "--preview never restarts"
STUB_CAPTURE=true run $'n\n' --preview
eq "exits 0" "$RC" "0"
eq "the preview runs" "$(grep -cxF "$PREVIEW_CALL" "$W/calls.log")" "1"
has "the images are built" "compose_build build webapp" "$(calls)"
eq "no service is restarted or recreated" "$(restarts | wc -l | tr -d ' ')" "0"
hasnt "the capture proxy is not refreshed" "capture_refresh" "$(calls)"
hasnt "the plugins overlay is not prepared" "PLUGINS_PREPARE" "$(calls)"
hasnt "no prune" "image prune" "$(calls)"
hasnt "nothing is asked" "Continue?" "$OUT"
has "it says what was done and how to apply it" "Preview only: the images are built and nothing was restarted" "$OUT"
eq "the marker stays, so the next update finishes this one" "$(pending)" "oldhead"

STUB_REBUILD="agent" run "" --preview
eq "without a webapp rebuild: exits 0" "$RC" "0"
has "says there is nothing to preview" "does not change the webapp" "$OUT"
eq "and restarts nothing" "$(restarts | wc -l | tr -d ' ')" "0"
STUB_PREVIEW_RC=1 run "" --preview
[[ "$RC" -ne 0 ]] && ok "a preview that cannot run fails --preview" || bad "--preview without a report" "exit 0" "non-zero"
eq "and restarts nothing" "$(restarts | wc -l | tr -d ' ')" "0"
STUB_RUNNING="webapp" run "" --preview
[[ "$RC" -ne 0 ]] && ok "no database: --preview fails" || bad "--preview without a database" "exit 0" "non-zero"
eq "and restarts nothing" "$(restarts | wc -l | tr -d ' ')" "0"

# =============================================================================
section "the parser, the up-to-date return and the re-exec"
fresh
OUT="$( ( source "$W/stubs.sh"; set -euo pipefail; cmd_update --bogus ) 2>&1)"; RC=$?
eq "an unknown flag is still refused" "$RC" "1"
has "by name" "Unknown flag: --bogus" "$OUT"

fresh
OUT="$( ( source "$W/stubs.sh"; set -euo pipefail; cmd_update --preview ) </dev/null 2>&1)"; RC=$?
eq "nothing to pull: --preview exits 0" "$RC" "0"
has "says it is up to date" "Already up to date" "$OUT"
has "and that there is nothing to preview" "Nothing to preview" "$OUT"
hasnt "the .env is not applied to the running services" "APPLY_ENV" "$(calls)"
fresh
( source "$W/stubs.sh"; set -euo pipefail; cmd_update ) </dev/null >/dev/null 2>&1
has "without --preview the up-to-date path still applies the .env" "APPLY_ENV" "$(calls)"

fresh
( source "$W/stubs.sh"; set -euo pipefail; STUB_PULL_MOVES=true cmd_update --preview ) </dev/null >/dev/null 2>&1
has "the pulled script is re-executed with --preview" "EXEC REDAMON_UPDATE_FROM=oldhead bash $W/redamon.sh update --preview" "$(calls)"
eq "and nothing ran before it but the pull" "$(grep -vE '^(PULL|EXEC )' "$W/calls.log" | wc -l | tr -d ' ')" "0"

# =============================================================================
section "the call site and its contract with the script"
BODY="$(awk '/^cmd_update\(\) \{/{on=1} on{print} on&&/^}/{exit}' "$SCRIPT")"
n() { grep -nF -- "$1" <<<"$BODY" | head -1 | cut -d: -f1; }
[[ "$(n 'compose_build build "${rebuild_core[@]}"')" -lt "$(n '_update_preview "$preview_only"')" \
   && "$(n '_update_preview "$preview_only"')" -lt "$(n '_plugins_prepare || exit 1')" \
   && "$(n '_plugins_prepare || exit 1')" -lt "$(n 'Restarting rebuilt services')" ]] \
    && ok "cmd_update: core build < preview < plugin overlay < restarts" || bad "the call site order" "out of order" "build < preview < prepare < restart"
FN="$(awk '/^_update_preview\(\) \{/{on=1} on{print} on&&/^}/{exit}' "$SCRIPT")"
has "the one-off container keeps stdin closed" "$PREVIEW_CALL </dev/null" "$(sed 's/^ *//' <<<"$FN")"
grep -qE '^export const REVIEW_EXIT = 10$' "$PREVIEW_JS" && grep -qE '^        10\) ;;$' <<<"$FN" \
    && ok "the script's REVIEW_EXIT (10) is the status redamon.sh asks on" || bad "REVIEW_EXIT agreement" "differs" "10 on both sides"
grep -qE '^export const NOTHING_CHANGES_EXIT = 0$' "$PREVIEW_JS" && grep -qE '^        0\) return 0 ;;$' <<<"$FN" \
    && ok "and NOTHING_CHANGES_EXIT (0) asks nothing" || bad "NOTHING_CHANGES_EXIT agreement" "differs" "0 on both sides"
HELP_OUT="$(cd "$REPO_ROOT" && ./redamon.sh help 2>/dev/null || true)"
has "help lists update --preview" "update --preview" "$HELP_OUT"
has "and says --preview still pulls the checkout" "the checkout IS pulled" "$HELP_OUT"

# =============================================================================
section "in a terminal: interactive No stops before restart"
# Runs cmd_update on a fresh pseudo-terminal, answers each "<prompt>" "<keys>" pair once
# the prompt appears, and prints what the terminal showed and then EXIT=<status>. Gives
# up after 20 s so a prompt that loops cannot hang the gate.
on_tty() {
    python3 - "$@" <<'PY'
import os, pty, select, sys, time
args, pairs = sys.argv[1], sys.argv[2:]
code = ('source "$W/stubs.sh"; set -euo pipefail\n'
        'REDAMON_UPDATE_FROM=oldhead cmd_update ' + args)
env = dict(os.environ, INPUTRC="/dev/null", TERM="xterm")
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("bash", ["bash", "--norc", "--noprofile", "-c", code], env)
screen, pending, deadline = b"", b"", time.time() + 20
def pump():
    global screen, pending
    if not select.select([fd], [], [], 0.05)[0]:
        return True
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        return False
    screen += chunk; pending += chunk
    return bool(chunk)
for prompt, keys in zip(pairs[0::2], pairs[1::2]):
    while os.fsencode(prompt) not in pending and time.time() < deadline and pump():
        pass
    pending = pending.split(os.fsencode(prompt), 1)[-1]
    try:
        os.write(fd, os.fsencode(keys))
    except OSError:
        break
while time.time() < deadline and pump():
    pass
if time.time() >= deadline:
    os.kill(pid, 9)
_, status = os.waitpid(pid, 0)
sys.stdout.write(screen.decode(errors="replace"))
sys.stdout.write("\nEXIT=%d\n" % (os.WEXITSTATUS(status) if os.WIFEXITED(status) else 255))
PY
}

if command -v python3 >/dev/null 2>&1; then
    fresh; export STUB_CAPTURE=true
    SCREEN="$(on_tty "" "Continue? [Y/n]" $'n\r')"
    has "the question is asked" "Continue? [Y/n]" "$SCREEN"
    [[ "$(grep -n 'FAKE PREVIEW' <<<"$SCREEN" | head -1 | cut -d: -f1)" -lt "$(grep -n 'Continue?' <<<"$SCREEN" | head -1 | cut -d: -f1)" ]] \
        && ok "after the report" || bad "the question follows the report" "before" "after"
    eq "No: nothing restarts" "$(restarts | wc -l | tr -d ' ')" "0"
    hasnt "not even the capture proxy" "capture_refresh" "$(calls)"
    has "the update says it stopped" "Update stopped before any service restarted" "$SCREEN"
    has "and how to finish it" "Run ./redamon.sh update to finish it" "$SCREEN"
    has "it exits non-zero" "EXIT=1" "$SCREEN"
    eq "the marker stays for the next update" "$(pending)" "oldhead"

    fresh
    SCREEN="$(on_tty "" "Continue? [Y/n]" $'\r')"
    has "Enter (the default, yes) continues" "docker compose up -d --no-deps webapp" "$(calls)"
    has "and refreshes the capture proxy before the restarts" "RESTART capture_refresh" "$(calls)"
    [[ "$(line_of 'RESTART capture_refresh')" -lt "$(line_of 'docker compose up -d --no-deps webapp')" ]] \
        && ok "capture refresh < core restart" || bad "capture refresh order" "after" "before the core restart"
    has "and exits 0" "EXIT=0" "$SCREEN"
    export STUB_CAPTURE=false

    fresh
    SCREEN="$(STUB_PREVIEW_RC=0 on_tty "")"
    hasnt "nothing changes for anyone: no question, even in a terminal" "Continue?" "$SCREEN"
    has "and the update goes on" "docker compose up -d --no-deps webapp" "$(calls)"

    fresh
    SCREEN="$(on_tty "--preview")"
    hasnt "--preview in a terminal asks nothing" "Continue?" "$SCREEN"
    eq "and restarts nothing" "$(restarts | wc -l | tr -d ' ')" "0"
    has "and exits 0" "EXIT=0" "$SCREEN"
else
    echo "  SKIP  needs python3 to drive the question through a pseudo-terminal"
fi

echo
echo "redamon rbac preview suite: passed $PASS, failed $FAIL"
[[ "$FAIL" -eq 0 ]]
