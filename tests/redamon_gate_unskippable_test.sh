#!/usr/bin/env bash
# =============================================================================
# The gate must not be able to go green having run nothing.
#
# Two silent skips used to exist in `cmd_test`, and both mattered:
#
#   _test_run_webapp   returned 0 when webapp/node_modules was absent
#   _test_run_section  returned 0 when the section's image was not built
#
# The second is the wider hole: a missing `redamon-recon` image skipped every
# runtime test that protects the engagement rate ceiling. Most of the recon
# settings registry's enforcement is TypeScript, so the first skip made the rest
# of that layer unverified too.
#
# These suites assert the SKIP-IS-A-FAILURE behaviour directly, by calling the
# helpers with their inputs missing. They run on the host with no image and no
# node_modules, which is exactly the situation they describe.
#
# Run:  bash tests/redamon_gate_unskippable_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1 ($2)"; else fail "$1 (got='$2' expected='$3')"; fi; }
assert_contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# Keep the helpers' own output capturable rather than silenced: several
# assertions below are about WHAT it prints.

# =============================================================================
section "T26: a missing input fails the unit tier"
# =============================================================================

out="$(_test_missing_input demo "the demo image is not built" "build it" unit 2>&1)"
rc=$?
assert_eq "unit tier returns non-zero" "$rc" "1"
assert_contains "names the section" "$out" "demo"
assert_contains "says it cannot run" "$out" "CANNOT RUN"
assert_contains "gives the fix" "$out" "build it"
assert_contains "names the opt-out" "$out" "REDAMON_TEST_ALLOW_MISSING"

out="$(_test_missing_input demo "not built" "build it" all 2>&1)"
assert_eq "all tier also fails" "$?" "1"

out="$(_test_missing_input demo "not built" "build it" coverage 2>&1)"
assert_eq "coverage tier also fails" "$?" "1"

# The narrower tiers are not the gate, so a missing input there is a skip.
out="$(_test_missing_input demo "not built" "build it" live 2>&1)"
assert_eq "live tier still skips" "$?" "0"

# =============================================================================
section "T26: the opt-out is deliberate, named, and loud"
# =============================================================================

out="$(REDAMON_TEST_ALLOW_MISSING=demo _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "an allowed section returns 0" "$?" "0"
assert_contains "but prints SKIPPED" "$out" "SKIPPED"
assert_contains "and names the opt-out that allowed it" "$out" "REDAMON_TEST_ALLOW_MISSING"

out="$(REDAMON_TEST_ALLOW_MISSING=other _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "a DIFFERENT section in the opt-out does not allow this one" "$?" "1"

out="$(REDAMON_TEST_ALLOW_MISSING=all _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "'all' allows any section" "$?" "0"

out="$(REDAMON_TEST_ALLOW_MISSING="webapp, demo ,recon" _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "a comma list tolerates spaces" "$?" "0"

# An empty opt-out is not an opt-out. This is the case a CI config reaches by
# exporting the variable unset, and it must not silently open the gate.
out="$(REDAMON_TEST_ALLOW_MISSING= _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "an empty opt-out still fails" "$?" "1"

# =============================================================================
section "T26: the real call sites route through it"
# =============================================================================

# webapp: node_modules absent -> non-zero for the gate tier.
_saved_dir="$SCRIPT_DIR"
SCRIPT_DIR="$(mktemp -d)"
out="$(_test_run_webapp unit 2>&1)"
assert_eq "_test_run_webapp fails when vitest is absent" "$?" "1"
assert_contains "names npm ci as the fix" "$out" "npm ci"

out="$(_test_run_webapp live 2>&1)"
assert_eq "_test_run_webapp still skips outside the gate tiers" "$?" "0"

# shell suites: no tests/*_test.sh -> non-zero for the gate tier.
out="$(_test_run_shell unit 2>&1)"
assert_eq "_test_run_shell fails when no suites are found" "$?" "1"
rmdir "$SCRIPT_DIR" 2>/dev/null
SCRIPT_DIR="$_saved_dir"

# section: an image that cannot exist -> non-zero for the gate tier.
if command -v docker >/dev/null 2>&1; then
    out="$(_test_run_section demo redamon-no-such-image-xyz /repo /repo tests . "" unit 2>&1)"
    assert_eq "_test_run_section fails on an unbuilt image" "$?" "1"
    assert_contains "names the image" "$out" "redamon-no-such-image-xyz"
else
    pass "docker absent, section-image case not exercised (helper covered above)"
fi

# =============================================================================
section "a shell suite that cannot run fails the shell section (exit 77)"
# =============================================================================
# Suites used to print SKIP and succeed when python3, PyYAML or git was missing,
# and _test_run_shell printed "ok" for them: green, checking nothing.

_saved_dir="$SCRIPT_DIR"
SCRIPT_DIR="$(mktemp -d)"
mkdir -p "$SCRIPT_DIR/tests"
printf '#!/usr/bin/env bash\necho "  ok   one check"\nexit 0\n' > "$SCRIPT_DIR/tests/fine_test.sh"
printf '#!/usr/bin/env bash\necho "  CANNOT RUN  needs the demo tool"\nexit %s\n' \
    "$_TEST_SHELL_CANNOT_RUN" > "$SCRIPT_DIR/tests/demo_test.sh"

assert_eq "the cannot-run code is the conventional 77" "$_TEST_SHELL_CANNOT_RUN" "77"

out="$(_test_run_shell unit 2>&1)"
assert_eq "a suite exiting 77 fails the shell section" "$?" "1"
assert_contains "it is reported as unable to run, not ok" "$out" "CANNOT RUN"
assert_contains "it names the suite" "$out" "demo_test.sh"
assert_contains "it carries the suite's own reason" "$out" "needs the demo tool"
assert_contains "it names the opt-out" "$out" "REDAMON_TEST_ALLOW_MISSING=demo_test.sh"
assert_eq "it is never printed as ok" "$(grep -c 'ok.*demo_test.sh' <<< "$out")" "0"
assert_contains "the suite that ran is still ok" "$out" "fine_test.sh"

for allow in shell demo_test.sh demo_test all; do
    out="$(REDAMON_TEST_ALLOW_MISSING="$allow" _test_run_shell unit 2>&1)"
    assert_eq "REDAMON_TEST_ALLOW_MISSING=$allow lets it pass" "$?" "0"
    assert_contains "  ...and prints SKIPPED" "$out" "SKIPPED"
done
out="$(REDAMON_TEST_ALLOW_MISSING=webapp _test_run_shell unit 2>&1)"
assert_eq "an opt-out naming something else does not" "$?" "1"

out="$(_test_run_shell live 2>&1)"
assert_eq "outside the gate tiers it is a skip" "$?" "0"

# The opt-out excuses a suite that could not run, never one that failed.
printf '#!/usr/bin/env bash\nexit 1\n' > "$SCRIPT_DIR/tests/demo_test.sh"
out="$(REDAMON_TEST_ALLOW_MISSING=shell _test_run_shell unit 2>&1)"
assert_eq "a failing suite still fails with the opt-out" "$?" "1"
assert_contains "and is reported as FAIL" "$out" "FAIL"

rm -rf "$SCRIPT_DIR"
SCRIPT_DIR="$_saved_dir"

# Every suite that stops early because a gate prerequisite (python3, PyYAML,
# git) is missing must say so with 77, not with exit 0.
silent_skips="$(awk '
    FNR == 1 { prev = "" }
    function prereq(s) { return s ~ /SKIP/ && s ~ /(python3|[Pp][Yy][Yy][Aa][Mm][Ll]|(^|[^a-z])git([^a-z]|$))/ }
    (prereq($0) && /exit 0/) || (prereq(prev) && /^[[:space:]]*exit 0/) { print FILENAME ":" FNR }
    { prev = $0 }' "$REPO_ROOT"/tests/*_test.sh)"
assert_eq "no shell suite exits 0 after a SKIP for python3, PyYAML or git" "$silent_skips" ""

# =============================================================================
section "T27: the runner reports an executed-test count"
# =============================================================================

runner="$REPO_ROOT/tooling/scripts/pytest_isolated.py"
if command -v python3 >/dev/null 2>&1; then
    out="$(python3 -c "
import sys
sys.path.insert(0, '$REPO_ROOT/tooling/scripts')
from pytest_isolated import tests_executed
print(tests_executed('==== 12 passed, 3 skipped in 1.2s ===='))
print(tests_executed('==== 4 failed, 20 passed in 2s ===='))
print(tests_executed('nothing here'))
" 2>&1)"
    assert_eq "a summary line is counted" "$(echo "$out" | sed -n 1p)" "12"
    assert_eq "failures count as executed" "$(echo "$out" | sed -n 2p)" "24"
    assert_eq "no summary means zero" "$(echo "$out" | sed -n 3p)" "0"
    assert_contains "the runner prints the count" "$(grep -c 'TESTS EXECUTED' "$runner")" "1"
    assert_contains "the runner names files that collected nothing" \
        "$(grep -c 'collected NO tests' "$runner")" "1"
else
    fail "python3 unavailable; cannot check the runner"
fi

printf '\n\033[1mresult:\033[0m %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
