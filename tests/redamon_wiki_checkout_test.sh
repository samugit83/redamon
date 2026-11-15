#!/usr/bin/env bash
# =============================================================================
# ensure_wiki_checkout in redamon.sh (AI Navigator plan §8.13): install and update
# fill an empty redamon.wiki submodule, a failing fetch warns and goes on, and a
# wiki someone works in (on a branch, or with an edit) is left exactly as it was.
# The update's local-change check ignores the submodule's pointer.
#
# Local repositories only (file:// submodule), no network. Run:
#   bash tests/redamon_wiki_checkout_test.sh
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

# A submodule over file:// needs the protocol allowed; set for this process only.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=protocol.file.allow GIT_CONFIG_VALUE_0=always
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

g() { git -c init.defaultBranch=master "$@" >/dev/null 2>&1; }

# The upstream wiki and a main repository recording it as redamon.wiki.
g init "$WORK/wiki-upstream"
echo "# Home" > "$WORK/wiki-upstream/Home.md"
g -C "$WORK/wiki-upstream" add Home.md
g -C "$WORK/wiki-upstream" commit -m wiki
g init "$WORK/main-upstream"
g -C "$WORK/main-upstream" submodule add "file://$WORK/wiki-upstream" redamon.wiki
g -C "$WORK/main-upstream" commit -m main

fresh_clone() {  # a clone made the way README used to say: no submodules
    rm -rf "$WORK/clone"
    g clone "file://$WORK/main-upstream" "$WORK/clone"
    SCRIPT_DIR="$WORK/clone"
}

echo "== an empty submodule is filled =="
fresh_clone
assert_eq "starts empty" "$([[ -f "$SCRIPT_DIR/redamon.wiki/Home.md" ]] && echo filled || echo empty)" "empty"
out="$(ensure_wiki_checkout 2>&1)"; rc=$?
assert_eq "exit 0" "$rc" "0"
assert_eq "filled" "$([[ -f "$SCRIPT_DIR/redamon.wiki/Home.md" ]] && echo filled || echo empty)" "filled"

echo "== a failing fetch warns and exits 0 =="
fresh_clone
git -C "$SCRIPT_DIR" config -f .gitmodules submodule.redamon.wiki.url "file://$WORK/does-not-exist"
out="$(ensure_wiki_checkout 2>&1)"; rc=$?
assert_eq "exit 0" "$rc" "0"
assert_eq "warned" "$(grep -c 'Could not fetch the documentation' <<<"$out")" "1"

echo "== a wiki on a branch with an extra commit is left as it was =="
fresh_clone
ensure_wiki_checkout >/dev/null 2>&1
g -C "$SCRIPT_DIR/redamon.wiki" checkout -b work
echo "draft" > "$SCRIPT_DIR/redamon.wiki/Draft.md"
g -C "$SCRIPT_DIR/redamon.wiki" add Draft.md
g -C "$SCRIPT_DIR/redamon.wiki" commit -m draft
before="$(git -C "$SCRIPT_DIR/redamon.wiki" rev-parse HEAD)"
out="$(ensure_wiki_checkout 2>&1)"
assert_eq "same commit" "$(git -C "$SCRIPT_DIR/redamon.wiki" rev-parse HEAD)" "$before"
assert_eq "same branch" "$(git -C "$SCRIPT_DIR/redamon.wiki" symbolic-ref --short HEAD)" "work"
assert_eq "said so" "$(grep -c 'has local work' <<<"$out")" "1"

echo "== a wiki with an uncommitted edit is left as it was =="
fresh_clone
ensure_wiki_checkout >/dev/null 2>&1
echo "edit" >> "$SCRIPT_DIR/redamon.wiki/Home.md"
ensure_wiki_checkout >/dev/null 2>&1
assert_eq "edit kept" "$(tail -n1 "$SCRIPT_DIR/redamon.wiki/Home.md")" "edit"

echo "== the update's local-change check ignores the submodule pointer =="
assert_eq "no dirty file" "$(_dirty_tracked_files)" ""
echo "x" >> "$SCRIPT_DIR/.gitmodules"
assert_eq "a real edit still counts" "$(_dirty_tracked_files | grep -c gitmodules)" "1"

echo ""
echo "PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
