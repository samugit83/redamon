#!/usr/bin/env bash
# =============================================================================
# Test suite for the `./redamon.sh update` git path: _upstream_ref,
# _restore_runtime_tracked_files, _has_local_only_commits,
# _diverged_by_runtime_scribbles_only, _update_pull, _assert_checkout_writable.
#
# The feature: recon/ is bind mounted rw into the spawned recon container and
# add_mitre.py re-downloads the MITRE database into a GIT-TRACKED directory, so
# scanning dirties the working tree and `pull --ff-only` refuses. Issue #185: the
# old handler reported EVERY pull failure as "the working tree has local changes"
# (even with a provably clean tree) and told users to `git commit -am`, which is
# precisely what makes the divergence permanent.
#
# Real git repos in a temp dir; no network, no Docker daemon. Run:
#   bash tests/redamon_update_pull_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }
assert_contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi; }
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3' in: $2)"; fi; }
# NOTE: label is $1 and MUST be shifted off before running the command, or the
# label itself is executed and an unknown command "fails" -- a false green.
assert_true()  { local l="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$l -> true"; else fail "$l (expected true)"; fi; }
assert_false() { local l="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$l (expected false)"; else pass "$l -> false"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

command -v git >/dev/null 2>&1 || { echo "SKIP: git not installed"; exit 0; }

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

# The two tracked paths recon rewrites on a cache miss, and a file that is NOT one.
RUNTIME_FILE="recon/main_recon_modules/data/mitre_db/database/CVE-2026.jsonl"
RUNTIME_FILE2="recon/main_recon_modules/data/wappalyzer_cache/technologies.json"
USER_FILE="agentic/api.py"

git_q() { git -C "$1" -c user.email=t@example.invalid -c user.name=t -c commit.gpgsign=false "${@:2}"; }

# A remote + a clone of it, with the remote one release ahead. Returns the clone
# path on stdout; every test starts from this same known-good shape.
make_pair() {
    local root="$SANDBOX/$1" up="$SANDBOX/$1/upstream" clone="$SANDBOX/$1/clone"
    rm -rf "$root"; mkdir -p "$root"
    git init -q --initial-branch=master "$up" >/dev/null 2>&1
    mkdir -p "$up/$(dirname "$RUNTIME_FILE")" "$up/$(dirname "$RUNTIME_FILE2")" \
             "$up/$(dirname "$USER_FILE")"
    printf 'shipped-cve-data\n'  > "$up/$RUNTIME_FILE"
    printf 'shipped-wappalyzer\n' > "$up/$RUNTIME_FILE2"
    printf 'shipped-source\n'    > "$up/$USER_FILE"
    printf '1.0.0\n'             > "$up/VERSION"
    git_q "$up" add -A >/dev/null 2>&1
    git_q "$up" commit -qm base >/dev/null 2>&1
    git clone -q "$up" "$clone" >/dev/null 2>&1
    # upstream ships a new release the clone does not have yet
    printf '1.1.0\n' > "$up/VERSION"
    git_q "$up" commit -qam release-1.1.0 >/dev/null 2>&1
    echo "$clone"
}

# Simulate a scan: the recon container rewrites the tracked MITRE database.
scribble() { printf 'refreshed-cve-data\n' > "$1/$RUNTIME_FILE"; }
# ...and the Wappalyzer fingerprint cache, the second path with the same problem.
scribble2() { printf 'refreshed-wappalyzer\n' > "$1/$RUNTIME_FILE2"; }

# Capture a function that may `exit`, without taking the test runner down.
run_capture() { OUT="$( "$@" 2>&1 )"; RC=$?; }

# Run a function under the SAME `set -euo pipefail` redamon.sh really executes
# with. This suite runs `set +e` so one failed assertion does not abort the file,
# which means run_capture CANNOT observe an errexit abort - and that is exactly
# the class of bug that shipped green here (a bare `x="$(fn)"` whose git call
# failed killed the update with no output at all). Route every production-
# critical path through this, not only through run_capture.
# __END__ is printed only if the function returned instead of aborting.
run_strict() {
    STRICT_OUT="$(bash -c '
        set -euo pipefail
        source "$1"
        SCRIPT_DIR="$2"
        TORCH_VARIANT_MARKER="$2/.torch-variant"
        shift 2
        "$@"
        printf "__END__"
    ' _ "$REPO_ROOT/redamon.sh" "$SCRIPT_DIR" "$@" 2>&1)"
    STRICT_RC=$?
}

# ============================================================================
section "unit: _upstream_ref"
# ============================================================================
SCRIPT_DIR="$(make_pair upstream_ref)"
assert_eq "clone resolves its tracking branch" "$(_upstream_ref)" "origin/master"

git_q "$SCRIPT_DIR" branch --unset-upstream >/dev/null 2>&1
assert_eq "falls back to origin/master with no tracking branch" "$(_upstream_ref)" "origin/master"

git_q "$SCRIPT_DIR" remote remove origin >/dev/null 2>&1
assert_false "fails when there is no remote at all (zip install)" _upstream_ref

# ============================================================================
section "unit: _restore_runtime_tracked_files"
# ============================================================================
SCRIPT_DIR="$(make_pair restore)"
info() { :; }   # silence the "Restoring ..." line for the rest of the run

scribble "$SCRIPT_DIR"; scribble2 "$SCRIPT_DIR"
assert_true "a scan dirties the tracked runtime data" \
    test -n "$(git -C "$SCRIPT_DIR" status --porcelain --untracked-files=no)"
_restore_runtime_tracked_files
assert_eq "restore leaves a clean tree" \
    "$(git -C "$SCRIPT_DIR" status --porcelain --untracked-files=no)" ""
assert_eq "restore puts the shipped MITRE content back" \
    "$(cat "$SCRIPT_DIR/$RUNTIME_FILE")" "shipped-cve-data"
# The Wappalyzer cache is the SECOND tracked directory recon re-downloads into
# (http_probe.py, 24h TTL). It was missing from RUNTIME_TRACKED_PATHS entirely.
assert_eq "restore covers the Wappalyzer cache too" \
    "$(cat "$SCRIPT_DIR/$RUNTIME_FILE2")" "shipped-wappalyzer"

# Regression (#185): RUNTIME_TRACKED_PATHS listed ONLY the .last_update marker,
# which is gitignored and therefore untracked -- the restore was dead code while
# the 15 tracked files beside it were the ones the container actually rewrote.
printf 'edited-by-user\n' > "$SCRIPT_DIR/$USER_FILE"
_restore_runtime_tracked_files
assert_eq "restore NEVER touches a real source file" \
    "$(cat "$SCRIPT_DIR/$USER_FILE")" "edited-by-user"
git_q "$SCRIPT_DIR" checkout -- "$USER_FILE" >/dev/null 2>&1

# ============================================================================
section "unit: divergence classification"
# ============================================================================
SCRIPT_DIR="$(make_pair classify)"
assert_false "a merely-behind clone has no local-only commits" _has_local_only_commits origin/master

scribble "$SCRIPT_DIR"
git_q "$SCRIPT_DIR" commit -qam 'local changes' >/dev/null 2>&1
assert_true  "committing the scribble diverges the clone" _has_local_only_commits origin/master
assert_true  "the divergence is classified as runtime-only" \
    _diverged_by_runtime_scribbles_only origin/master

printf 'my own patch\n' >> "$SCRIPT_DIR/$USER_FILE"
git_q "$SCRIPT_DIR" commit -qam 'my work' >/dev/null 2>&1
assert_false "one real edit in the range disqualifies auto-recovery" \
    _diverged_by_runtime_scribbles_only origin/master

# ============================================================================
section "regression #185: diverged by committed runtime scribbles self-heals"
# ============================================================================
SCRIPT_DIR="$(make_pair heal)"
scribble "$SCRIPT_DIR"
git_q "$SCRIPT_DIR" commit -qam 'local changes' >/dev/null 2>&1

# The exact reported state: tree provably CLEAN, pull --ff-only impossible.
assert_eq "tree is clean, so 'local changes' was always the wrong diagnosis" \
    "$(git -C "$SCRIPT_DIR" status --porcelain --untracked-files=no)" ""

run_capture _update_pull
assert_eq "_update_pull succeeds instead of stranding the user" "$RC" "0"
assert_eq "checkout is fast-forwarded onto the new release" \
    "$(cat "$SCRIPT_DIR/VERSION")" "1.1.0"
assert_eq "HEAD now matches origin/master" \
    "$(git -C "$SCRIPT_DIR" rev-parse HEAD)" "$(git -C "$SCRIPT_DIR" rev-parse origin/master)"
assert_contains "it says what it discarded" "$OUT" "Recovered"

# ============================================================================
section "regression #185: real local commits are refused, never reset"
# ============================================================================
SCRIPT_DIR="$(make_pair refuse)"
printf 'my own patch\n' >> "$SCRIPT_DIR/$USER_FILE"
git_q "$SCRIPT_DIR" commit -qam 'my work' >/dev/null 2>&1
BEFORE="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

run_capture _update_pull
assert_eq "refuses rather than guessing" "$RC" "1"
assert_eq "the user's commit is still there" "$(git -C "$SCRIPT_DIR" rev-parse HEAD)" "$BEFORE"
assert_contains "names the real cause" "$OUT" "commits that origin/master does not"
assert_contains "offers a way to keep the work" "$OUT" "branch my-changes"
assert_not_contains "does not claim the clean tree has local changes" \
    "$OUT" "working tree has local changes"

# ============================================================================
section "regression #185: a dirty tree is never told to commit"
# ============================================================================
SCRIPT_DIR="$(make_pair dirty)"
# The dirty file must be one the incoming release ALSO changes, or git happily
# fast-forwards around it -- a local edit only blocks a pull when it would be
# overwritten. VERSION is what the fixture's new release touches.
printf 'work in progress\n' > "$SCRIPT_DIR/VERSION"

run_capture _update_pull
assert_eq "refuses on a genuinely dirty tree" "$RC" "1"
assert_contains "reports the right cause" "$OUT" "working tree has local changes"
assert_contains "lists the offending file" "$OUT" "VERSION"
assert_contains "offers stash" "$OUT" "stash"
# The advice that CAUSED #185. It must never come back.
assert_not_contains "never suggests committing local changes" "$OUT" "commit -am"

# ============================================================================
section "unit: _assert_checkout_writable"
# ============================================================================
SCRIPT_DIR="$(make_pair writable)"
TORCH_VARIANT_MARKER="$SCRIPT_DIR/.torch-variant"
printf 'cpu' > "$TORCH_VARIANT_MARKER"
run_capture _assert_checkout_writable
assert_eq "a normal user-owned checkout passes" "$RC" "0"

chmod a-w "$TORCH_VARIANT_MARKER"
if [[ -w "$TORCH_VARIANT_MARKER" ]]; then
    # Running as root: chmod cannot make anything unwritable, so the negative
    # case is unobservable here. Skipping beats a false green.
    echo "  SKIP unwritable-marker case (running as root)"
else
    run_capture _assert_checkout_writable
    assert_eq "an unwritable file aborts the update" "$RC" "1"
    assert_contains "points at the sudo chown fix" "$OUT" "chown -R"
fi
chmod u+w "$TORCH_VARIANT_MARKER"

# ============================================================================
section "regression: a runtime file this user cannot rewrite"
# ============================================================================
# On a real install the recon container creates recon/.../wappalyzer_cache as
# ROOT inside a user-owned checkout, so `git checkout --` cannot restore it and
# `git pull` cannot replace it. The old code swallowed that with `|| true` and
# the user landed back on the pull error with no way to act on it.
SCRIPT_DIR="$(make_pair unwritable)"
scribble2 "$SCRIPT_DIR"
chmod a-w "$SCRIPT_DIR/$(dirname "$RUNTIME_FILE2")" "$SCRIPT_DIR/$RUNTIME_FILE2"
if [[ -w "$SCRIPT_DIR/$RUNTIME_FILE2" ]]; then
    echo "  SKIP unrestorable-file cases (running as root: chmod cannot deny us)"
else
    run_capture _restore_runtime_tracked_files
    assert_eq "a failed restore aborts instead of failing silently" "$RC" "1"
    assert_contains "names the path it could not restore" "$OUT" "wappalyzer_cache"
    assert_contains "gives the chown that actually fixes it" "$OUT" "chown -R"

    # Same file left CLEAN but root-owned: nothing is broken yet, so this must
    # warn and let the update proceed rather than block it.
    chmod u+w "$SCRIPT_DIR/$(dirname "$RUNTIME_FILE2")" "$SCRIPT_DIR/$RUNTIME_FILE2"
    printf 'shipped-wappalyzer\n' > "$SCRIPT_DIR/$RUNTIME_FILE2"
    assert_eq "the file is clean again" \
        "$(git -C "$SCRIPT_DIR" status --porcelain --untracked-files=no)" ""
    chmod a-w "$SCRIPT_DIR/$RUNTIME_FILE2"
    run_capture _warn_root_owned_runtime_files
    assert_eq "a clean-but-unwritable file does NOT block the update" "$RC" "0"
    assert_contains "but it is flagged early" "$OUT" "$RUNTIME_FILE2"
    assert_contains "with the fix" "$OUT" "chown -R"
fi
chmod -R u+w "$SCRIPT_DIR" 2>/dev/null

# ============================================================================
section "regression: errexit - a failing 'git status' must not kill the update"
# ============================================================================
# BUG: `dirty="$(_dirty_tracked_files)"` was a bare assignment. _dirty_tracked_files
# swallows stderr and returns git's status, so under redamon.sh's own
# `set -euo pipefail` a failing `git status` aborted _update_pull instantly:
# exit 128, ZERO output, and cmd_update died before printing anything at all.
# `git status` really can fail while refs still resolve - a corrupt index, or
# another git process (an IDE, a hook) holding .git/index.lock while status
# tries to refresh it.
SCRIPT_DIR="$(make_pair errexit)"
git_q "$SCRIPT_DIR" commit -q --allow-empty -m 'local changes' >/dev/null 2>&1
printf 'GARBAGE-NOT-AN-INDEX' > "$SCRIPT_DIR/.git/index"
assert_true  "refs still resolve" \
    git -C "$SCRIPT_DIR" rev-parse --verify --quiet origin/master
assert_false "but git status is broken" \
    git -C "$SCRIPT_DIR" status --porcelain --untracked-files=no

run_strict _update_pull
assert_eq "exits 1 (a diagnosed refusal), not 128 (an errexit abort)" "$STRICT_RC" "1"
assert_contains "and still tells the user what is wrong" \
    "$STRICT_OUT" "Could not pull updates"
assert_not_contains "never dies silently" "$STRICT_OUT" "__END__"

# ============================================================================
section "regression: the auto-heal must not trigger a spurious image rebuild"
# ============================================================================
# BUG: after `git reset --hard`, cmd_update still diffed from the DISCARDED
# commit, so changed_files contained the reverted runtime paths. Those match
# `^recon/` (redamon.sh, rebuild_tools+=(recon)) and rebuild the heavy recon
# image a release never touched - and a non-empty rebuild list also arms
# preflight_disk_gate's 40 GB floor, which ABORTS the update on a small host.
SCRIPT_DIR="$(make_pair rebuildmap)"
scribble "$SCRIPT_DIR"
git_q "$SCRIPT_DIR" commit -qam 'local changes' >/dev/null 2>&1
DISCARDED="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

# NOT run_capture here: it evaluates the function in a command-substitution
# subshell, where a global assignment cannot propagate back. The handshake with
# cmd_update is the whole point of this test, so call it in THIS shell (the heal
# path returns, it does not exit) and send its output to a file.
UPDATE_BASE_HEAD=""
_update_pull > "$SANDBOX/heal.log" 2>&1
RC=$?
assert_eq "the heal still succeeds" "$RC" "0"
assert_true "it publishes the pre-divergence base for cmd_update" test -n "$UPDATE_BASE_HEAD"
# What cmd_update will actually feed to its changed-file -> service map.
MAPPED="$(git -C "$SCRIPT_DIR" diff --name-only "${UPDATE_BASE_HEAD:-$DISCARDED}" HEAD)"
assert_contains "the real release change is still mapped" "$MAPPED" "VERSION"
assert_not_contains "the reverted runtime path is NOT mapped (no recon rebuild)" \
    "$MAPPED" "recon/"

# ============================================================================
section "security: the reset guard cannot be prefix-confused"
# ============================================================================
# _diverged_by_runtime_scribbles_only is what authorises `reset --hard`. It
# prefix-matches paths, so a sibling directory or a traversal must NOT pass.
# git refuses "." / ".." as tree entries, so the traversal case is unreachable
# through git output today - it is asserted anyway because a destructive gate
# must not rely on an invariant enforced by someone else.
SCRIPT_DIR="$(make_pair guard)"
# Calls the REAL guard. An earlier version of this helper reimplemented the
# match here; a mutation run proved it useless - deleting the traversal check
# from redamon.sh left every assertion green.
guard_says() { _is_runtime_tracked_path "$1" && echo authorises || echo refuses; }
assert_eq "a real runtime file authorises"        "$(guard_says "$RUNTIME_FILE")" "authorises"
assert_eq "the second runtime file authorises"    "$(guard_says "$RUNTIME_FILE2")" "authorises"
assert_eq "a SIBLING dir does not"                "$(guard_says "recon/main_recon_modules/data/mitre_db_evil/payload.py")" "refuses"
assert_eq "a suffixed name does not"              "$(guard_says "recon/main_recon_modules/data/mitre_dbX")" "refuses"
assert_eq "a traversal out of the runtime dir does not" \
    "$(guard_says "recon/main_recon_modules/data/mitre_db/../../../../agentic/api.py")" "refuses"
assert_eq "a case-variant does not"               "$(guard_says "recon/main_recon_modules/data/MITRE_DB/x")" "refuses"
assert_eq "ordinary source does not"              "$(guard_says "$USER_FILE")" "refuses"

# End to end through the real function: a commit mixing a runtime file with a
# sibling-directory file must NOT be auto-reset.
scribble "$SCRIPT_DIR"
mkdir -p "$SCRIPT_DIR/recon/main_recon_modules/data/mitre_db_evil"
printf 'mine\n' > "$SCRIPT_DIR/recon/main_recon_modules/data/mitre_db_evil/payload.py"
git_q "$SCRIPT_DIR" add -A >/dev/null 2>&1
git_q "$SCRIPT_DIR" commit -qm 'local changes' >/dev/null 2>&1
HEAD_BEFORE="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"
assert_false "the mixed commit is NOT classified as runtime-only" \
    _diverged_by_runtime_scribbles_only origin/master
run_strict _update_pull
assert_eq "so the update refuses" "$STRICT_RC" "1"
assert_eq "and the commit survives untouched" \
    "$(git -C "$SCRIPT_DIR" rev-parse HEAD)" "$HEAD_BEFORE"

# ============================================================================
section "safety: REDAMON_NO_AUTO_RESET opts out of the destructive recovery"
# ============================================================================
SCRIPT_DIR="$(make_pair optout)"
scribble "$SCRIPT_DIR"
git_q "$SCRIPT_DIR" commit -qam 'local changes' >/dev/null 2>&1
HEAD_BEFORE="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"
REDAMON_NO_AUTO_RESET=1 run_strict _update_pull
assert_eq "refuses to heal when opted out" "$STRICT_RC" "1"
assert_eq "history is untouched" "$(git -C "$SCRIPT_DIR" rev-parse HEAD)" "$HEAD_BEFORE"
assert_contains "and says how to do it by hand" "$STRICT_OUT" "reset --hard origin/master"

# ============================================================================
section "error paths: the remaining _update_pull branches"
# ============================================================================
# Fallback pull: no tracking branch, so `pull --ff-only` fails and only the
# explicit `pull --ff-only origin master` can succeed.
SCRIPT_DIR="$(make_pair fallback)"
git_q "$SCRIPT_DIR" branch --unset-upstream >/dev/null 2>&1
run_strict _update_pull
assert_eq "falls back to 'origin master' when there is no tracking branch" "$STRICT_RC" "0"
assert_eq "and really did update" "$(cat "$SCRIPT_DIR/VERSION")" "1.1.0"

# No remote at all: a zip download, not a clone. Must say so instead of blaming
# the user's files, and must not claim a divergence it cannot compute.
SCRIPT_DIR="$(make_pair noremote)"
git_q "$SCRIPT_DIR" remote remove origin >/dev/null 2>&1
run_strict _update_pull
assert_eq "refuses cleanly with no remote" "$STRICT_RC" "1"
assert_contains "names the real cause" "$STRICT_OUT" "no upstream to pull from"
assert_contains "tells them how to install properly" "$STRICT_OUT" "git clone"
assert_not_contains "does not invent local changes" "$STRICT_OUT" "working tree has local changes"

# Unreachable remote, clean tree, no local commits: nothing to diagnose, so show
# git's own words rather than guessing.
SCRIPT_DIR="$(make_pair unreachable)"
git_q "$SCRIPT_DIR" remote set-url origin "https://127.0.0.1:1/nope.git" >/dev/null 2>&1
GIT_TERMINAL_PROMPT=0 run_strict _update_pull
assert_eq "refuses on a network failure" "$STRICT_RC" "1"
assert_contains "surfaces git's own message" "$STRICT_OUT" "git said"
assert_not_contains "does not blame local changes" "$STRICT_OUT" "working tree has local changes"
assert_not_contains "does not blame a divergence" "$STRICT_OUT" "commits that"

# ============================================================================
section "safety: an unreadable working tree must never authorise reset --hard"
# ============================================================================
# The errexit fix turns a failed `git status` into an empty $dirty. Empty must
# NOT be read as "clean": that would let the destructive auto-heal run while
# uncommitted user work sat in a tree we could not see. "Cannot tell" has to
# refuse. This is the guard, not a side effect - assert it directly.
SCRIPT_DIR="$(make_pair unreadable)"
scribble "$SCRIPT_DIR"
git_q "$SCRIPT_DIR" commit -qam 'local changes' >/dev/null 2>&1
HEAD_BEFORE="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"
printf 'GARBAGE-NOT-AN-INDEX' > "$SCRIPT_DIR/.git/index"
# The scribble-only classifier still says yes (it is a tree-to-tree diff and
# needs no index), so ONLY the unreadable-tree guard can stop the reset.
assert_true "the commit still classifies as runtime-only" \
    _diverged_by_runtime_scribbles_only origin/master
run_strict _update_pull
assert_eq "refuses instead of healing blind" "$STRICT_RC" "1"
assert_eq "HEAD is untouched - nothing was destroyed" \
    "$(git -C "$SCRIPT_DIR" rev-parse HEAD)" "$HEAD_BEFORE"
assert_contains "warns the tree could not be read, before suggesting reset" \
    "$STRICT_OUT" "could not be read"

# ============================================================================
section "errexit: the happy paths must survive set -euo pipefail too"
# ============================================================================
# Structural guard for the whole feature, not one bug: every function cmd_update
# calls as a BARE statement must return 0 on its success path, or errexit kills
# the update mid-flight.
SCRIPT_DIR="$(make_pair strict)"
run_strict _assert_checkout_writable
assert_contains "_assert_checkout_writable returns on a clean checkout" "$STRICT_OUT" "__END__"
run_strict _warn_root_owned_runtime_files
assert_contains "_warn_root_owned_runtime_files returns when nothing is root-owned" \
    "$STRICT_OUT" "__END__"
run_strict _restore_runtime_tracked_files
assert_contains "_restore_runtime_tracked_files returns on a clean tree" "$STRICT_OUT" "__END__"
scribble "$SCRIPT_DIR"
run_strict _restore_runtime_tracked_files
assert_contains "_restore_runtime_tracked_files returns after actually restoring" \
    "$STRICT_OUT" "__END__"
run_strict _update_pull
assert_eq "_update_pull fast-forwards cleanly under errexit" "$STRICT_RC" "0"
assert_contains "and returns rather than aborting" "$STRICT_OUT" "__END__"

printf '\n'
if [[ $FAIL -eq 0 ]]; then
    printf '\033[0;32mAll %d assertions passed\033[0m\n' "$PASS"
    exit 0
fi
printf '\033[0;31m%d failed, %d passed\033[0m\n' "$FAIL" "$PASS"
exit 1
