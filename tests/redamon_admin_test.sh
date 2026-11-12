#!/usr/bin/env bash
# =============================================================================
# Test suite for the admin-account creation logic in redamon.sh (issue #156).
#   - _wait_for_webapp        -> returns 0 when healthy, 1 on timeout (no dead-end)
#   - _admin_exists           -> parses check-admin.mjs count robustly
#   - _prompt_and_create_admin-> non-interactive env path + min-length gate,
#                                FORCE_PROMOTE pass-through, exit-3 refusal
#                                that does not abort the caller
#   - ensure_admin            -> actionable skip message (points at create-admin)
#   - cmd_create_admin        -> standalone recovery command (upsert = safe re-run)
#   - cmd_set_root            -> `set-root <email>`: ROOT_EMAIL to set-root.mjs, its exit code kept
#   - dispatch + help wiring   for `create-admin` and `set-root`
#   - interactive prompts      -> arrow keys edit the line, never reach the value (issue #210)
#
# Pure unit tests: `docker`/`sleep` are stubbed, no daemon needed, CI-friendly.
# Run:  bash tests/redamon_admin_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the script (BASH_SOURCE guard prevents command dispatch).
# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_true()  { if eval "$2"; then pass "$1"; else fail "$1 (cmd: $2)"; fi; }
assert_false() { if eval "$2"; then fail "$1 (cmd unexpectedly true: $2)"; else pass "$1"; fi; }
assert_eq()    { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }

# Keep the polling loops instant.
sleep() { :; }

echo "== _wait_for_webapp: healthy immediately -> 0 =="
docker() { return 0; }   # wget --spider succeeds on the first probe
_wait_for_webapp 5; assert_eq "returns 0 when webapp answers" "$?" "0"
unset -f docker

echo "== _wait_for_webapp: never healthy -> 1 (times out, no hang) =="
docker() { return 1; }   # health probe always fails
_wait_for_webapp 3; assert_eq "returns 1 after the retry budget" "$?" "1"
unset -f docker

echo "== _admin_exists: count parsing =="
# check-admin.mjs prints the admin count on stdout (via `docker compose exec`).
docker() { echo "1"; return 0; }
assert_true  "count 1 -> admin exists"        "_admin_exists"
docker() { echo "3"; return 0; }
assert_true  "count 3 -> admin exists"        "_admin_exists"
docker() { echo "0"; return 0; }
assert_false "count 0 -> no admin"            "_admin_exists"
docker() { echo ""; return 0; }
assert_false "empty output -> no admin (fresh DB / error)" "_admin_exists"
unset -f docker

echo "== _prompt_and_create_admin: non-interactive env path passes values through =="
# Stub docker to CAPTURE the args create-admin.mjs is invoked with, so we can
# prove the env-provided name/email/password are forwarded verbatim.
# Stub records the exec args into a file (a plain `CAP=$*` would be lost because
# the call runs inside `$(...)`, a subshell). Read the file back afterwards.
CAPFILE="$(mktemp)"
docker() { echo "$*" > "$CAPFILE"; return 0; }
ADMIN_NAME="Alice" ADMIN_EMAIL="alice@example.com" ADMIN_PASSWORD="supersecret123" \
  out="$(_prompt_and_create_admin 2>&1)"; rc=$?
CAP="$(cat "$CAPFILE")"
assert_eq   "non-interactive call succeeds"          "$rc" "0"
assert_true "invokes create-admin.mjs"               "echo \"\$CAP\" | grep -q 'scripts/create-admin.mjs'"
assert_true "forwards ADMIN_NAME"                    "echo \"\$CAP\" | grep -q 'ADMIN_NAME=Alice'"
assert_true "forwards ADMIN_EMAIL"                   "echo \"\$CAP\" | grep -q 'ADMIN_EMAIL=alice@example.com'"
assert_true "forwards ADMIN_PASSWORD"                "echo \"\$CAP\" | grep -q 'ADMIN_PASSWORD=supersecret123'"
rm -f "$CAPFILE"; unset -f docker; unset ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD

echo "== _prompt_and_create_admin: non-interactive rejects a too-short password =="
docker() { return 0; }
ADMIN_NAME="Bob" ADMIN_EMAIL="bob@example.com" ADMIN_PASSWORD="short" \
  out="$(_prompt_and_create_admin 2>&1)"; rc=$?
assert_eq   "exits non-zero on weak env password"   "$rc" "1"
assert_true "explains the minimum length"           "echo \"\$out\" | grep -qi 'too short'"
assert_false "did NOT reach create-admin.mjs"       "echo \"\$out\" | grep -q 'Admin user ready'"
unset -f docker; unset ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD

echo "== _prompt_and_create_admin: FORCE_PROMOTE reaches create-admin.mjs only when set =="
CAPFILE="$(mktemp)"
docker() { echo "$*" > "$CAPFILE"; return 0; }
unset FORCE_PROMOTE
ADMIN_NAME="Alice" ADMIN_EMAIL="alice@example.com" ADMIN_PASSWORD="supersecret123" \
  out="$(_prompt_and_create_admin 2>&1)"; rc=$?
assert_eq    "without FORCE_PROMOTE the call succeeds"   "$rc" "0"
assert_false "without FORCE_PROMOTE nothing is forwarded" "grep -q 'FORCE_PROMOTE' '$CAPFILE'"
FORCE_PROMOTE=1 ADMIN_NAME="Alice" ADMIN_EMAIL="alice@example.com" ADMIN_PASSWORD="supersecret123" \
  out="$(_prompt_and_create_admin 2>&1)"; rc=$?
assert_eq    "with FORCE_PROMOTE=1 the call succeeds"    "$rc" "0"
assert_true  "forwards FORCE_PROMOTE=1 with exec -e"     "grep -q -- '-e FORCE_PROMOTE=1 ' '$CAPFILE'"
assert_true  "still forwards the admin's email"          "grep -q 'ADMIN_EMAIL=alice@example.com' '$CAPFILE'"
rm -f "$CAPFILE"; unset -f docker; unset ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD FORCE_PROMOTE

echo "== _prompt_and_create_admin: exit 3 prints the refusal and redamon.sh does not abort =="
# create-admin.mjs exits 3 when the email belongs to a member and FORCE_PROMOTE is
# not set. Under redamon.sh's `set -e` a bare non-zero exec ended install/update/up
# (ensure_admin calls this) right there; the caller must go on, told how to promote.
docker() {
    echo 'REFUSED: "bob@example.com": account exists as a member; set FORCE_PROMOTE=1 to promote it. Nothing was changed.' >&2
    return 3
}
ADMIN_NAME="Bob" ADMIN_EMAIL="bob@example.com" ADMIN_PASSWORD="supersecret123" \
  out="$( (set -e; _prompt_and_create_admin; echo '[caller continued]') 2>&1 )"; rc=$?
assert_eq    "a refusal does not fail the caller"         "$rc" "0"
assert_true  "the caller goes on under set -e"            "echo \"\$out\" | grep -qF '[caller continued]'"
assert_true  "the script's refusal reaches the operator"  "echo \"\$out\" | grep -q 'account exists as a member'"
assert_true  "redamon.sh says how to promote on purpose"  "echo \"\$out\" | grep -qF 'FORCE_PROMOTE=1 ./redamon.sh create-admin'"
assert_false "no false 'Admin user ready'"                "echo \"\$out\" | grep -q 'Admin user ready'"
unset -f docker; unset ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD

echo "== _prompt_and_create_admin: any other failure still stops, with a message =="
docker() { echo 'ERROR: Failed to create admin user: connection refused' >&2; return 1; }
ADMIN_NAME="Bob" ADMIN_EMAIL="bob@example.com" ADMIN_PASSWORD="supersecret123" \
  out="$( (set -e; _prompt_and_create_admin; echo '[caller continued]') 2>&1 )"; rc=$?
assert_eq    "the script's exit code is kept"             "$rc" "1"
assert_false "the caller does not go on"                  "echo \"\$out\" | grep -qF '[caller continued]'"
assert_true  "redamon.sh names the failed script"         "echo \"\$out\" | grep -q 'create-admin.mjs failed'"
assert_false "no false 'Admin user ready'"                "echo \"\$out\" | grep -q 'Admin user ready'"
unset -f docker; unset ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD

echo "== ensure_admin: webapp never ready -> actionable skip (points at create-admin) =="
docker() { return 1; }   # health probe never succeeds -> _wait_for_webapp fails
out="$(ensure_admin 2>&1)"; rc=$?
assert_eq   "ensure_admin returns (does not abort the caller)" "$rc" "0"
assert_true "tells the user to run create-admin" "echo \"\$out\" | grep -q './redamon.sh create-admin'"
assert_false "no cryptic dead-end 'skipping admin check'" "echo \"\$out\" | grep -qi 'skipping admin check'"
unset -f docker

echo "== cmd_create_admin: existing admin -> warns it will add/reset (upsert is safe) =="
# Stub the heavy prerequisites so we exercise only the command's own logic.
print_banner() { :; }
check_prerequisites() { :; }
_wait_for_webapp() { return 0; }
_admin_exists() { return 0; }              # pretend an admin already exists
_prompt_and_create_admin() { echo "[prompt ran]"; }
out="$(cmd_create_admin 2>&1)"; rc=$?
assert_eq   "cmd_create_admin succeeds"              "$rc" "0"
assert_true "warns an admin already exists"          "echo \"\$out\" | grep -qi 'admin user already exists'"
assert_true "explains add-new-or-reset semantics"    "echo \"\$out\" | grep -qiE 'reset|add a new'"
assert_true "still proceeds to the prompt"           "echo \"\$out\" | grep -q '\[prompt ran\]'"
unset -f print_banner check_prerequisites _wait_for_webapp _admin_exists _prompt_and_create_admin

echo "== cmd_create_admin: says a member's email needs FORCE_PROMOTE, admin or not =="
print_banner() { :; }
check_prerequisites() { :; }
_wait_for_webapp() { return 0; }
_prompt_and_create_admin() { echo "[prompt ran]"; }
for exists in 0 1; do
    _admin_exists() { return "$exists"; }
    out="$(cmd_create_admin 2>&1)"
    assert_true "admin exists=$((1 - exists)): names FORCE_PROMOTE=1 before the prompt" \
        "echo \"\$out\" | grep -q 'FORCE_PROMOTE=1'"
done
unset -f print_banner check_prerequisites _wait_for_webapp _admin_exists _prompt_and_create_admin

echo "== cmd_create_admin: webapp down -> clear error, non-zero exit =="
print_banner() { :; }
check_prerequisites() { :; }
_wait_for_webapp() { return 1; }           # never comes up
out="$(cmd_create_admin 2>&1)"; rc=$?
assert_eq   "exits non-zero when webapp is down"     "$rc" "1"
assert_true "tells the operator to start the stack"  "echo \"\$out\" | grep -q './redamon.sh up'"
unset -f print_banner check_prerequisites _wait_for_webapp

echo "== cmd_set_root: needs an email, passes it with exec -e, keeps the script's exit code =="
# set-root.mjs makes the account the confirmed Root (break-glass). The .env read for the
# switch note is a scratch one: the test never reads the checkout's real .env.
print_banner() { :; }
check_prerequisites() { :; }
_wait_for_webapp() { return 0; }
SR_DIR="$(mktemp -d)"; SR_SAVED_DIR="$SCRIPT_DIR"; SCRIPT_DIR="$SR_DIR"
CAPFILE="$(mktemp)"
docker() { echo "$*" >> "$CAPFILE"; return 0; }
out="$(cmd_set_root 2>&1)"; rc=$?
assert_eq    "no email: exits 1"                                "$rc" "1"
assert_true  "no email: prints the usage"                       "echo \"\$out\" | grep -qF './redamon.sh set-root <email>'"
assert_eq    "no email: nothing is run"                         "$(cat "$CAPFILE")" ""
out="$(cmd_set_root root@example.com 2>&1)"; rc=$?
assert_eq    "an email: exits 0"                                "$rc" "0"
assert_eq    "runs set-root.mjs with ROOT_EMAIL passed by exec -e" "$(cat "$CAPFILE")" \
    "compose exec -T -e ROOT_EMAIL=root@example.com webapp node scripts/set-root.mjs"
assert_true  "says moving Root signs both accounts out"         "echo \"\$out\" | grep -q 'signs it and the previous Root out'"
assert_true  "switch off: says Root takes effect once RBAC_IDENTITY_ENABLED is on" \
    "echo \"\$out\" | grep -q 'RBAC_IDENTITY_ENABLED is off'"
echo 'RBAC_IDENTITY_ENABLED=true' > "$SR_DIR/.env"
out="$(cmd_set_root root@example.com 2>&1)"
assert_false "switch on: no switch note"                        "echo \"\$out\" | grep -q 'RBAC_IDENTITY_ENABLED'"
docker() { echo 'ERROR: "nopass@example.com" has no password' >&2; return 1; }
out="$( (set -e; cmd_set_root nopass@example.com; echo '[caller continued]') 2>&1 )"; rc=$?
assert_eq    "a refusal keeps the script's exit code"           "$rc" "1"
assert_false "and stops there"                                  "echo \"\$out\" | grep -qF '[caller continued]'"
assert_true  "the script's reason reaches the operator"         "echo \"\$out\" | grep -q 'has no password'"
_wait_for_webapp() { return 1; }
out="$(cmd_set_root root@example.com 2>&1)"; rc=$?
assert_eq    "webapp down: exits 1"                             "$rc" "1"
assert_true  "webapp down: tells the operator to start the stack" "echo \"\$out\" | grep -q './redamon.sh up'"
SCRIPT_DIR="$SR_SAVED_DIR"; rm -rf "$SR_DIR"; rm -f "$CAPFILE"
unset -f print_banner check_prerequisites _wait_for_webapp docker

echo "== dispatch + help wiring for create-admin =="
SRC="$REPO_ROOT/redamon.sh"
assert_true "dispatch has a create-admin) arm"       "grep -qE '^\s*create-admin\)\s*cmd_create_admin' '$SRC'"
assert_true "cmd_create_admin is defined"            "grep -q '^cmd_create_admin()' '$SRC'"
# Capture FIRST, then grep. Piping the script straight into `grep -q` is a race:
# grep exits the instant it matches and closes the pipe, `redamon.sh help` is
# still writing its ~40 lines and dies with SIGPIPE (141), and `set -o pipefail`
# then reports the whole pipeline as failed. On an idle box the writer finishes
# first and it passes; under load it loses the race. Measured before this fix:
# 40/40 pass serially, 14/24 FAIL when run concurrently.
HELP_OUT="$(cd "$REPO_ROOT" && ./redamon.sh help 2>/dev/null || true)"
assert_true "help lists create-admin"                "echo \"\$HELP_OUT\" | grep -qi 'create-admin'"
assert_true "dispatch has a set-root) arm passing the email" "grep -qE '^\s*set-root\)\s*shift; cmd_set_root \"\\\$@\"' '$SRC'"
assert_true "cmd_set_root is defined"                "grep -q '^cmd_set_root()' '$SRC'"
assert_true "help lists set-root <email>"            "echo \"\$HELP_OUT\" | grep -q 'set-root <email>'"

# Runs bash code ($1) on a fresh pseudo-terminal: the prompts read /dev/tty, so
# only a real terminal shows what a person's keys turn into. $2 is typed before
# anything is on screen (keys pressed while the stack starts); each later
# "<prompt>" "<keys>" pair answers that prompt once it appears. Prints what the
# terminal showed; gives up after 20 s so a prompt that loops cannot hang the gate.
_type_at_tty() {
    python3 - "$@" <<'PY'
import os, pty, select, sys, time

code, typeahead, pairs = sys.argv[1], sys.argv[2], sys.argv[3:]
# INPUTRC=/dev/null: the operator's own ~/.inputrc (vi mode, rebinds) must not
# change what the keys below mean.
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
    except OSError:  # EIO once the child has exited and closed the terminal
        return False
    screen += chunk
    pending += chunk
    return bool(chunk)

os.write(fd, os.fsencode(typeahead))
for prompt, keys in zip(pairs[0::2], pairs[1::2]):
    while os.fsencode(prompt) not in pending and time.time() < deadline and pump():
        pass
    # Drop output up to this prompt, so a prompt that repeats (Confirm password)
    # is matched against the next copy, not this one.
    pending = pending.split(os.fsencode(prompt), 1)[-1]
    try:
        os.write(fd, os.fsencode(keys))
    except OSError:  # the child already exited; the asserts report what is missing
        break
while time.time() < deadline and pump():
    pass
if time.time() >= deadline:
    os.kill(pid, 9)
os.waitpid(pid, 0)
sys.stdout.write(screen.decode(errors="replace"))
PY
}

echo "== prompts: arrow keys edit the line, never reach the value (issue #210) =="
# Up pressed while the stack starts, then Left used to fix a typo in the email and
# inside the hidden password. Without `read -e` the kernel hands bash those keys
# as raw escape bytes ($'\e[D'...), which create-admin.mjs stores as typed: an
# email or password no browser login can ever match.
if command -v python3 >/dev/null 2>&1; then
    UP=$'\e[A'; LEFT=$'\e[D'; ENTER=$'\r'
    EMAIL_KEYS="admin@example.tst${LEFT}${LEFT}e${ENTER}"          # -> admin@example.test
    PASS_KEYS="correct-horse-batery${LEFT}${LEFT}${LEFT}t${ENTER}"  # -> correct-horse-battery
    CAPFILE="$(mktemp)"
    CHILD_PRELUDE='unset ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD
source "$REPO_ROOT/redamon.sh"; set +e
docker() { printf "%q\n" "$@" > "$CAPFILE"; }
'
    export REPO_ROOT CAPFILE

    SCREEN="$(_type_at_tty "${CHILD_PRELUDE}_prompt_and_create_admin" "${UP}${UP}" \
        "Admin name:" "Alice${ENTER}" "Admin email:" "$EMAIL_KEYS" \
        "Admin password:" "$PASS_KEYS" "Confirm password:" "$PASS_KEYS")"
    assert_true "admin: early arrows do not reach ADMIN_NAME"        "grep -qx 'ADMIN_NAME=Alice' '$CAPFILE'"
    assert_true "admin: Left fixes the email instead of storing \\e[D" "grep -qx 'ADMIN_EMAIL=admin@example.test' '$CAPFILE'"
    assert_true "admin: Left fixes the hidden password too"           "grep -qx 'ADMIN_PASSWORD=correct-horse-battery' '$CAPFILE'"
    assert_false "admin: the password is never shown on screen"       "grep -q 'horse' <<< \"\$SCREEN\""

    : > "$CAPFILE"
    SCREEN="$(_type_at_tty "${CHILD_PRELUDE}cmd_reset_password" "${UP}" \
        "User email:" "$EMAIL_KEYS" "New password:" "$PASS_KEYS" "Confirm password:" "$PASS_KEYS")"
    assert_true "reset: early arrows do not reach RESET_EMAIL"        "grep -qx 'RESET_EMAIL=admin@example.test' '$CAPFILE'"
    assert_true "reset: Left fixes the hidden password"               "grep -qx 'RESET_PASSWORD=correct-horse-battery' '$CAPFILE'"
    assert_false "reset: the password is never shown on screen"       "grep -q 'horse' <<< \"\$SCREEN\""
    rm -f "$CAPFILE"; export -n CAPFILE
else
    echo "  SKIP  needs python3 to drive the prompts through a pseudo-terminal"
fi

echo "== every prompt in redamon.sh and deploy.sh reads through readline (issue #210) =="
# The guard for prompts the pty run above does not reach (confirmations, the KB
# question, deploy.sh): a new prompted read without -e brings the bug back.
PROMPTED_READ='\bread +(-[a-zA-Z]+ +)*-[a-zA-Z]*p\b'
for f in "$SRC" "$REPO_ROOT/tooling/deploy/single-host/deploy.sh"; do
    BARE="$(grep -nE "$PROMPTED_READ" "$f" | grep -vE '\bread +(-[a-zA-Z]+ +)*-[a-zA-Z]*e')"
    assert_eq "no prompted read without -e in ${f#"$REPO_ROOT"/}" "$BARE" ""
done
assert_true "the guard's pattern does find the prompts" \
    "grep -E \"\$PROMPTED_READ\" '$SRC' | grep -q 'Admin name:'"

echo
echo "-----------------------------------------"
printf 'Admin suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
