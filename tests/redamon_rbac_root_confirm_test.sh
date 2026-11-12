#!/usr/bin/env bash
# =============================================================================
# `./redamon.sh update` confirms the instance's Root after ensure_admin
# (_confirm_root, feature document §14.4 step 2; ID-09):
#   - RBAC_IDENTITY_ENABLED off in .env: one information line, nothing read;
#   - a confirmed Root: one line naming it;
#   - the Root chosen at boot is the only admin with a password: confirmed;
#   - several admins, in a terminal: listed, Enter confirms the proposal, a number
#     chooses another, n decides later;
#   - several admins, not in a terminal (the single-host deploy, CI): ADMIN_EMAIL
#     from the environment, else from .env, chooses when it names an admin; otherwise
#     Root is kept and the way to change it printed;
#   - nothing here can stop the update, and stdin (the deploy's piped script) is
#     never read.
# The choice is carried out by webapp/scripts/set-root.mjs (ROOT_EMAIL, passed with
# exec -e), which confirms the current Root or moves Root; tests/rbac_scripts_db_test.sh
# proves the scripts on Postgres.
#
# `docker` is a stub reading the check-root.mjs answer from the test; the terminal
# cases run on a real pseudo-terminal (python3). No Docker, no network.
# Run:  bash tests/redamon_rbac_root_confirm_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/redamon.sh"
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
info()    { echo "INFO $*"; }
success() { echo "OK $*"; }
warn()    { echo "WARN $*"; }
error()   { echo "ERROR $*"; }
docker() {
    echo "docker $*" >> "$W/calls.log"
    # Whatever stdin the call is given is read, as `docker compose exec` without
    # a redirect would: a call that is not given </dev/null eats the deploy's script.
    cat >/dev/null
    case "$*" in
        *check-root.mjs*) printf '%b' "${STUB_CHECK:-}"; return "${STUB_CHECK_RC:-0}" ;;
        *set-root.mjs*)   echo "SET-ROOT ran"; return "${STUB_SET_RC:-0}" ;;
    esac
    return 0
}
STUBS

# check-root.mjs --lines records: root<TAB>email<TAB>confirmed|unconfirmed<TAB>rule, candidate<TAB>email.
ROOT_A_UNCONFIRMED='root\ta@x.test\tunconfirmed\tautomatic\n'
CANDS_ABC='candidate\ta@x.test\ncandidate\tBee@x.test\ncandidate\tc@x.test\n'

# run <.env text> [VAR=value ...]: _confirm_root under set -euo pipefail with stdin a
# pipe holding one line; OUT holds the output, RC the status.
run() {
    local envtext="$1"; shift
    printf '%b' "$envtext" > "$W/.env"
    : > "$W/calls.log"
    OUT="$(printf 'piped-line\n' | env "$@" bash -c '
        source "$W/stubs.sh"; set -euo pipefail
        _confirm_root
        echo "[update continued]"
        left=""; read -r left || true; echo "LEFTOVER=$left"' 2>&1)"; RC=$?
}
calls()    { cat "$W/calls.log"; }
set_root_calls() { grep -F 'set-root.mjs' "$W/calls.log"; }
CHECK_CALL="docker compose exec -T webapp node scripts/check-root.mjs --lines"
ON='RBAC_IDENTITY_ENABLED=true\n'

# =============================================================================
section "switch off prints one line"
for envtext in '' 'RBAC_IDENTITY_ENABLED=\n' 'RBAC_IDENTITY_ENABLED=false\n' 'RBAC_IDENTITY_ENABLED=0\n' \
               'RBAC_IDENTITY_ENABLED=maybe\n'; do
    run "$envtext" -u ADMIN_EMAIL STUB_CHECK="$ROOT_A_UNCONFIRMED$CANDS_ABC"
    label="${envtext%\\n}"; label="${label:-no line}"
    eq "$label: exits 0" "$RC" "0"
    eq "$label: one line, then the update goes on" \
        "$(grep -vE '^\[update continued\]$|^LEFTOVER=' <<<"$OUT" | wc -l | tr -d ' ')" "1"
    has "$label: it names the switch" "RBAC_IDENTITY_ENABLED is off" "$OUT"
    eq "$label: nothing is read from the database" "$(calls)" ""
done
for value in true TRUE 1 yes ' yes ' '"true"'; do
    run "RBAC_IDENTITY_ENABLED=$value\n" -u ADMIN_EMAIL STUB_CHECK='root\ta@x.test\tconfirmed\thost\ncandidate\ta@x.test\n'
    eq "RBAC_IDENTITY_ENABLED=$value reads on, as lib/authz/flags.ts does" "$(grep -cxF "$CHECK_CALL" "$W/calls.log")" "1"
done

# =============================================================================
section "a confirmed Root"
run "$ON" -u ADMIN_EMAIL STUB_CHECK='root\ta@x.test\tconfirmed\thost\ncandidate\ta@x.test\ncandidate\tb@x.test\n'
eq "exits 0" "$RC" "0"
has "names it" "INFO Root: a@x.test (confirmed)." "$OUT"
eq "changes nothing" "$(set_root_calls)" ""

# =============================================================================
section "one candidate confirmed"
run "$ON" -u ADMIN_EMAIL STUB_CHECK="${ROOT_A_UNCONFIRMED}candidate\ta@x.test\n"
eq "exits 0" "$RC" "0"
eq "set-root.mjs confirms it, the email passed with exec -e" "$(set_root_calls)" \
    "docker compose exec -T -e ROOT_EMAIL=a@x.test webapp node scripts/set-root.mjs"
has "the operator is told which account and why" "a@x.test, the only admin with a password" "$OUT"
has "the script's own report is shown" "SET-ROOT ran" "$OUT"
eq "stdin is never read" "$(grep '^LEFTOVER=' <<<"$OUT")" "LEFTOVER=piped-line"

run "$ON" -u ADMIN_EMAIL STUB_CHECK='root\tgone@x.test\tunconfirmed\tautomatic\ncandidate\tb@x.test\n'
eq "a Root that is no candidate is never replaced on its own" "$(set_root_calls)" ""
has "it says why" "gone@x.test is not an admin with a password" "$OUT"
has "and how to choose" "./redamon.sh set-root <email>" "$OUT"

run "$ON" -u ADMIN_EMAIL STUB_CHECK='candidate\tb@x.test\n'
eq "no Root yet and one admin: nothing is assigned by the update" "$(set_root_calls)" ""
has "it says there is no Root yet" "No Root is chosen yet" "$OUT"

run "$ON" -u ADMIN_EMAIL STUB_CHECK=''
eq "no admin with a password: exits 0" "$RC" "0"
has "it points at create-admin" "./redamon.sh create-admin" "$OUT"
eq "and changes nothing" "$(set_root_calls)" ""

# =============================================================================
section "non-interactive ADMIN_EMAIL"
run "$ON" ADMIN_EMAIL=bee@X.test STUB_CHECK="$ROOT_A_UNCONFIRMED$CANDS_ABC"
eq "exits 0" "$RC" "0"
eq "ADMIN_EMAIL naming an admin (any case) chooses it, stored spelling passed with exec -e" "$(set_root_calls)" \
    "docker compose exec -T -e ROOT_EMAIL=Bee@x.test webapp node scripts/set-root.mjs"
has "it says ADMIN_EMAIL chose it" "ADMIN_EMAIL" "$OUT"
eq "stdin is never read" "$(grep '^LEFTOVER=' <<<"$OUT")" "LEFTOVER=piped-line"

run "${ON}ADMIN_EMAIL=c@x.test\n" -u ADMIN_EMAIL STUB_CHECK="$ROOT_A_UNCONFIRMED$CANDS_ABC"
eq "ADMIN_EMAIL from .env when the environment has none" "$(set_root_calls)" \
    "docker compose exec -T -e ROOT_EMAIL=c@x.test webapp node scripts/set-root.mjs"
run "${ON}ADMIN_EMAIL=c@x.test\n" ADMIN_EMAIL=a@x.test STUB_CHECK="$ROOT_A_UNCONFIRMED$CANDS_ABC"
eq "the environment wins over .env (deploy.sh exports deploy.env)" "$(set_root_calls)" \
    "docker compose exec -T -e ROOT_EMAIL=a@x.test webapp node scripts/set-root.mjs"
run "$ON" ADMIN_EMAIL=b@x.test STUB_CHECK="${CANDS_ABC/Bee/b}"
eq "with no Root yet, ADMIN_EMAIL chooses one" "$(set_root_calls)" \
    "docker compose exec -T -e ROOT_EMAIL=b@x.test webapp node scripts/set-root.mjs"

# =============================================================================
section "non-interactive without it keeps and prints"
run "$ON" -u ADMIN_EMAIL STUB_CHECK="$ROOT_A_UNCONFIRMED$CANDS_ABC"
eq "exits 0" "$RC" "0"
eq "Root is kept: set-root.mjs never runs" "$(set_root_calls)" ""
has "it says Root stays unconfirmed" "a@x.test was chosen automatically and is not confirmed yet" "$OUT"
has "and how to change it" "./redamon.sh set-root <email>" "$OUT"
hasnt "nothing is asked" "Enter = confirm" "$OUT"
run "$ON" ADMIN_EMAIL=member@x.test STUB_CHECK="$ROOT_A_UNCONFIRMED$CANDS_ABC"
eq "ADMIN_EMAIL naming no admin: Root is kept" "$(set_root_calls)" ""
has "and the operator is told" "ADMIN_EMAIL (member@x.test) is not an admin with a password" "$OUT"

# =============================================================================
section "nothing stops the update"
run "$ON" -u ADMIN_EMAIL STUB_CHECK="" STUB_CHECK_RC=1
eq "check-root.mjs failing: the update goes on" "$RC|$(grep -c '^\[update continued\]$' <<<"$OUT")" "0|1"
has "with a warning" "Root check did not run (exit 1)" "$OUT"
run "$ON" -u ADMIN_EMAIL STUB_CHECK="${ROOT_A_UNCONFIRMED}candidate\ta@x.test\n" STUB_SET_RC=1
eq "set-root.mjs failing: the update goes on" "$RC|$(grep -c '^\[update continued\]$' <<<"$OUT")" "0|1"
has "with the command to retry" "./redamon.sh set-root a@x.test" "$OUT"

# =============================================================================
section "interactive pick"
# Runs _confirm_root on a fresh pseudo-terminal and answers each "<prompt>" "<keys>"
# pair once the prompt appears; prints the screen. Gives up after 20 s.
on_tty() {
    python3 - "$@" <<'PY'
import os, pty, select, sys, time
pairs = sys.argv[1:]
code = 'source "$W/stubs.sh"; set -euo pipefail; _confirm_root; echo "[update continued]"'
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
os.waitpid(pid, 0)
sys.stdout.write(screen.decode(errors="replace"))
PY
}
tty_run() {
    printf '%b' "$ON" > "$W/.env"; : > "$W/calls.log"
    OUT="$(env -u ADMIN_EMAIL STUB_CHECK="$1" bash -c 'shift; on_tty "$@"' _ "$@" 2>&1)"
}
export -f on_tty
if command -v python3 >/dev/null 2>&1; then
    ENTER=$'\r'
    PROMPT="decide later: "
    tty_run "$ROOT_A_UNCONFIRMED$CANDS_ABC" "$PROMPT" "2$ENTER"
    has "the admins are listed, oldest first, the proposal marked" "1) a@x.test  (chosen automatically, not confirmed)" "$OUT"
    has "...with the others numbered" "3) c@x.test" "$OUT"
    has "choosing another says what it does" "signs it and the current Root out" "$OUT"
    eq "a number chooses that admin" "$(set_root_calls)" \
        "docker compose exec -T -e ROOT_EMAIL=Bee@x.test webapp node scripts/set-root.mjs"
    has "and the update goes on" "[update continued]" "$OUT"

    tty_run "$ROOT_A_UNCONFIRMED$CANDS_ABC" "$PROMPT" "$ENTER"
    eq "Enter confirms the proposal" "$(set_root_calls)" \
        "docker compose exec -T -e ROOT_EMAIL=a@x.test webapp node scripts/set-root.mjs"

    tty_run "$ROOT_A_UNCONFIRMED$CANDS_ABC" "$PROMPT" "9$ENTER" "$PROMPT" "x$ENTER" "$PROMPT" "3$ENTER"
    eq "an answer out of range asks again, then the number counts" "$(set_root_calls)" \
        "docker compose exec -T -e ROOT_EMAIL=c@x.test webapp node scripts/set-root.mjs"

    tty_run "$ROOT_A_UNCONFIRMED$CANDS_ABC" "$PROMPT" "n$ENTER"
    eq "n decides later: nothing changes" "$(set_root_calls)" ""
    has "...and says how to choose later" "./redamon.sh set-root <email>" "$OUT"

    tty_run "$CANDS_ABC" "$PROMPT" "$ENTER" "$PROMPT" "1$ENTER"
    has "with no Root yet there is no proposal" "A number = choose that admin" "$OUT"
    eq "...Enter alone chooses nothing, a number does" "$(set_root_calls)" \
        "docker compose exec -T -e ROOT_EMAIL=a@x.test webapp node scripts/set-root.mjs"
else
    echo "  SKIP  needs python3 to drive the prompt through a pseudo-terminal"
fi

# =============================================================================
section "the call site"
BODY="$(awk '/^cmd_update\(\) \{/{on=1} on{print} on&&/^}/{exit}' "$SCRIPT")"
n() { grep -nE -- "$1" <<<"$BODY" | head -1 | cut -d: -f1; }
a="$(n '^    ensure_admin$')"; c="$(n '^    _confirm_root$')"; u="$(n '^    _urlscan_backfill_once$')"; p="$(n '_update_preview "\$preview_only"')"
[[ -n "$a" && -n "$c" && -n "$u" && -n "$p" && "$p" -lt "$a" && "$a" -lt "$c" && "$c" -lt "$u" ]] \
    && ok "cmd_update: preview < ensure_admin < _confirm_root < the rest" \
    || bad "call site order" "preview=$p ensure_admin=$a _confirm_root=$c urlscan=$u" "ascending"
eq "_confirm_root runs once per update" "$(grep -cE '^    _confirm_root$' <<<"$BODY")" "1"
FN="$(awk '/^_confirm_root\(\) \{/{on=1} on{print} on&&/^}/{exit}' "$SCRIPT")"
eq "every docker call in _confirm_root keeps stdin closed" \
    "$(grep -E '\bdocker compose' <<<"$FN" | grep -vc '</dev/null')" "0"

echo
echo "-----------------------------------------"
printf 'Root confirmation suite: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
