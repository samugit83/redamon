#!/usr/bin/env bash
# =============================================================================
# The live route matrix runner's switch tags (tests/rbac_matrix_live.sh):
#   - a row tagged identity:on|off or permissions:on|off runs only while the
#     webapp's switch is so, and is a SKIP naming the switch otherwise;
#   - the permissions switch reads off while the identity switch is off, as the
#     webapp's own flags.ts chain does (permissions requires identity), so the
#     PE-28 equivalence runs (step 3.2: identity on, permissions on and off)
#     select the rows the webapp really serves;
#   - sharing:on|off the same for RBAC_SHARING_ENABLED, which reads off while
#     the permissions switch is off (step 4.1: the Phase 4 rows written before
#     a share can exist skip until the switch is on);
#   - on/true/1/yes in any case and with spaces are on, anything else is off;
#   - the switches are read from the webapp container once per run, and not at
#     all when no selected row needs them.
# A copy of the runner runs in a throwaway tree with `docker` and `curl` stubs on
# PATH and an unreachable BASE_URL: no stack, no network, no fixture account.
# Run:  bash tests/rbac_matrix_runner_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$REPO_ROOT/tests/rbac_matrix_live.sh"
PASS=0; FAIL=0
ok()    { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()   { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()    { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
has()   { if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1" "absent" "$2"; fi; }
section() { printf '\n== %s ==\n' "$1"; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
T="$W/root"
mkdir -p "$T/tests/fixtures/rbac_matrix" "$T/webapp/scripts" "$T/testing/e2e" "$W/bin"
cp "$RUNNER" "$T/tests/rbac_matrix_live.sh"
echo 'SEED' > "$T/webapp/scripts/e2e-rbac-seed.mjs"
echo 'CLEANUP' > "$T/webapp/scripts/e2e-rbac-cleanup.mjs"
printf '%s\n' \
  $'t-plain\t3.2\tanon\tGET\t/api/t/plain\t-\t200\treq:PE-28' \
  $'t-perm-on\t3.2\tanon\tGET\t/api/t/perm-on\t-\t200\tpermissions:on' \
  $'t-perm-off\t3.2\tanon\tGET\t/api/t/perm-off\t-\t200\treq:PE-28 permissions:off' \
  $'t-both-on\t3.2\tanon\tGET\t/api/t/both-on\t-\t200\tidentity:on permissions:on' \
  $'t-id-off\t3.2\tanon\tGET\t/api/t/id-off\t-\t200\tidentity:off' \
  > "$T/tests/fixtures/rbac_matrix/t.tsv"
printf '%s\n' $'u-revoked\t3.2\tmember_a_revoked\tGET\t/api/t/revoked\t-\t200\tpermissions:on' \
  > "$T/tests/fixtures/rbac_matrix/u.tsv"
printf '%s\n' \
  $'s-plain\t4.1\tanon\tGET\t/api/s/plain\t-\t200\treq:HD-27' \
  $'s-share-on\t4.1\tanon\tGET\t/api/s/share-on\t-\t200\treq:HD-27 sharing:on' \
  $'s-share-off\t4.1\tanon\tGET\t/api/s/share-off\t-\t200\tsharing:off' \
  > "$T/tests/fixtures/rbac_matrix/s.tsv"

# docker: the webapp's switches come from FAKE_* through the runner's own in-container
# command (run here by sh), the seed prints the keys the runner requires, every call is logged.
cat > "$W/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >> "$STUB_LOG"
case "$*" in
  *"ps --status running"*) echo fake-webapp ;;
  *" postgres "*) sed -n "s/.*where id = '\([^']*\)'.*/\1/p" ;;
  *" webapp sh -c "*)
    script=""; prev=""
    for a in "$@"; do [ "$prev" = -c ] && script="$a"; prev="$a"; done
    echo "switches-read" >> "$STUB_LOG"
    env -i PATH="$PATH" RBAC_IDENTITY_ENABLED="${FAKE_IDENTITY-}" RBAC_PERMISSIONS_ENABLED="${FAKE_PERMISSIONS-}" \
      RBAC_SHARING_ENABLED="${FAKE_SHARING-}" RBAC_AUTHZ_CACHE_MS="${FAKE_CACHE_MS-}" sh -c "$script" ;;
  *" node "*)
    if grep -q SEED; then
      printf 'PA_ID=pa\nPB_ID=pb\nMEMBER_A_ID=ma\nMEMBER_B_ID=mb\nADMIN_A_ID=aa\nRBAC_PASSWORD=pw\n'
    fi ;;
  *) echo "unexpected docker call" >&2; exit 1 ;;
esac
STUB
# curl: every request answers 200; the URL of each row's request is logged.
cat > "$W/bin/curl" <<'STUB'
#!/usr/bin/env bash
url=""; prev=""
for a in "$@"; do
  case "$prev" in
    -o) [ "$a" = /dev/null ] || : > "$a" ;;
    -D) printf 'HTTP/1.1 200 OK\r\n' > "$a" ;;
  esac
  prev="$a"; url="$a"
done
case "$url" in */api/health) ;; *) echo "request ${url#*://*/}" >> "$STUB_LOG" ;; esac
printf 200
STUB
printf '#!/usr/bin/env bash\necho "sleep $*" >> "$STUB_LOG"\n' > "$W/bin/sleep"
chmod +x "$W/bin/docker" "$W/bin/curl" "$W/bin/sleep"

# run <identity> <permissions> [row filter] [matrix file] [cache ms] [sharing]: OUT holds the
# output, RC the status, LOG the stub calls.
run() {
  : > "$W/calls.log"
  OUT="$(cd "$W" && PATH="$W/bin:$PATH" STUB_LOG="$W/calls.log" BASE_URL=http://rbac-runner-test.invalid \
    FAKE_IDENTITY="$1" FAKE_PERMISSIONS="$2" FAKE_CACHE_MS="${5:-5000}" FAKE_SHARING="${6:-}" RBAC_MATRIX_ROWS="${3:-}" \
    bash "$T/tests/rbac_matrix_live.sh" "${4:-t}" 2>&1)"; RC=$?
  LOG="$(cat "$W/calls.log")"
}
line()     { grep -E "^(PASS|SKIP|FAIL) +$1 " <<<"$OUT" | head -1; }
verdict()  { line "$1" | awk '{print $1}'; }
requests() { grep '^request ' <<<"$LOG" | sed 's/^request //' | tr '\n' ' '; }
reads()    { grep -c '^switches-read$' <<<"$LOG"; }

# =============================================================================
section "identity on, permissions on"
run true true
eq "exit 0" "$RC" "0"
eq "untagged row runs" "$(verdict t-plain)" "PASS"
eq "permissions:on runs" "$(verdict t-perm-on)" "PASS"
eq "permissions:off skips" "$(verdict t-perm-off)" "SKIP"
has "the skip names the switch and its state" "(permissions switch on)" "$(line t-perm-off)"
eq "identity:on permissions:on runs" "$(verdict t-both-on)" "PASS"
eq "identity:off skips" "$(verdict t-id-off)" "SKIP"
has "the identity skip still names its switch" "(identity switch on)" "$(line t-id-off)"
eq "only the selected rows reach the webapp" "$(requests)" "api/t/plain api/t/perm-on api/t/both-on "
has "result line" "== RESULT: 3 passed, 0 failed, 2 skipped ==" "$OUT"
eq "the switches are read once" "$(reads)" "1"

section "identity on, permissions off (the PE-28 off half)"
run true ""
eq "untagged row runs" "$(verdict t-plain)" "PASS"
eq "permissions:on skips" "$(verdict t-perm-on)" "SKIP"
has "the skip says off" "(permissions switch off)" "$(line t-perm-on)"
eq "permissions:off runs" "$(verdict t-perm-off)" "PASS"
eq "identity:on permissions:on skips on the permissions switch" "$(verdict t-both-on)" "SKIP"
has "named" "(permissions switch off)" "$(line t-both-on)"
eq "identity:off skips" "$(verdict t-id-off)" "SKIP"
has "result line" "== RESULT: 2 passed, 0 failed, 3 skipped ==" "$OUT"
eq "the switches are read once" "$(reads)" "1"

section "identity off: the permissions switch reads off, whatever it says"
run false true
eq "permissions:on skips" "$(verdict t-perm-on)" "SKIP"
has "named off" "(permissions switch off)" "$(line t-perm-on)"
eq "permissions:off runs" "$(verdict t-perm-off)" "PASS"
eq "identity:off runs" "$(verdict t-id-off)" "PASS"
eq "identity:on permissions:on skips" "$(verdict t-both-on)" "SKIP"
has "result line" "== RESULT: 3 passed, 0 failed, 2 skipped ==" "$OUT"

section "values: on/true/1/yes in any case are on, anything else off"
run ' YES ' 1
eq "' YES ' and 1: permissions:on runs" "$(verdict t-perm-on)" "PASS"
eq "' YES ' and 1: identity:off skips" "$(verdict t-id-off)" "SKIP"
run TRUE On
eq "On is not a value the webapp knows: permissions reads off" "$(verdict t-perm-on)" "SKIP"
run true maybe
eq "maybe: permissions:off runs" "$(verdict t-perm-off)" "PASS"
run 0 true
eq "identity 0: permissions:on skips" "$(verdict t-perm-on)" "SKIP"

section "no selected row needs a switch: none is read"
run true true '^t-plain$'
eq "the row runs" "$(verdict t-plain)" "PASS"
eq "no switch read" "$(reads)" "0"
has "result line" "== RESULT: 1 passed, 0 failed, 0 skipped ==" "$OUT"

section "the cache bound still comes from the same read"
run true true '' u 1500
eq "a revoked actor's row runs" "$(verdict u-revoked)" "PASS"
eq "each SQL change waits the 1500 ms bound, rounded up, plus 1 s" "$(grep '^sleep ' <<<"$LOG" | tr '\n' ' ')" "sleep 3 sleep 3 "
eq "the switches and the bound are read once" "$(reads)" "1"
run true true '' u ''
eq "no bound set: 5 s, plus 1 s" "$(grep -m1 '^sleep ' <<<"$LOG")" "sleep 6"

section "the sharing switch (step 4.1)"
run true true '' s 5000 true
eq "sharing on: untagged row runs" "$(verdict s-plain)" "PASS"
eq "sharing on: sharing:on runs" "$(verdict s-share-on)" "PASS"
eq "sharing on: sharing:off skips" "$(verdict s-share-off)" "SKIP"
has "the skip names the sharing switch" "(sharing switch on)" "$(line s-share-off)"
eq "the switches are read once" "$(reads)" "1"
run true true '' s 5000 ''
eq "sharing unset: sharing:on skips" "$(verdict s-share-on)" "SKIP"
has "named off" "(sharing switch off)" "$(line s-share-on)"
eq "sharing unset: sharing:off runs" "$(verdict s-share-off)" "PASS"
eq "the skipped row never reaches the webapp" "$(requests)" "api/s/plain api/s/share-off "
run true '' '' s 5000 true
eq "permissions off: sharing reads off, whatever it says" "$(verdict s-share-on)" "SKIP"
has "named off" "(sharing switch off)" "$(line s-share-on)"
run false true '' s 5000 true
eq "identity off: permissions and sharing read off" "$(verdict s-share-off)" "PASS"
run true true '' u 1500 true
eq "the cache bound still parses after the sharing value" "$(grep '^sleep ' <<<"$LOG" | tr '\n' ' ')" "sleep 3 sleep 3 "

section "the runner documents the tag"
HEADER="$(sed -n '1,/^set -uo pipefail/p' "$RUNNER")"
has "permissions:on | permissions:off in the row format" "permissions:on | permissions:off" "$HEADER"
has "and the chain" "RBAC_PERMISSIONS_ENABLED" "$HEADER"
has "sharing:on | sharing:off in the row format" "sharing:on | sharing:off" "$HEADER"
has "and its chain" "RBAC_SHARING_ENABLED" "$HEADER"

echo
echo "-----------------------------------------"
printf 'Matrix runner suite: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
