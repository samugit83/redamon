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
#     a share can exist skip until the switch is on), and also while Root's
#     sharing policy is not enabled: sharing is in force only with both
#     (sharingPolicy.ts), so with the switch on and the policy still `{}` the
#     owner-only rows run; the policy is read once, by psql, only when a selected
#     row needs it, and an unreadable policy fails the rows that need it;
#   - sharingwrite:on|off the same for RBAC_SHARING_WRITE_ENABLED (step 5.2), which
#     reads off while sharing is not in force, and also while Root's policy does
#     not allow write (`maxLevel` "write", maxShareLevel); both policy reads happen
#     once, only when a selected row needs them;
#   - the runner's own policy SQL, run in the stack's postgres image (a throwaway
#     container, skipped without Docker or the image), reads each stored policy as
#     parseSharingPolicy does: a missing `maxLevel` is write (SHARING_POLICY_DEFAULTS),
#     so `{"enabled":true}` with the write switch on is write sharing in force;
#   - governance:on|off the same for RBAC_GOVERNANCE_ENABLED (step 6.13), which
#     reads off while the permissions switch is off (flags.ts: governance requires
#     permissions, not sharing) and reads no policy;
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

W="$(mktemp -d)"; PG=""
trap 'rm -rf "$W"; [ -z "$PG" ] || docker rm -f "$PG" >/dev/null 2>&1' EXIT
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
printf '%s\n' \
  $'v-plain\t4.3\tanon\tGET\t/api/v/plain\t-\t200\treq:SH-21' \
  $'v-share-on\t4.3\tanon\tGET\t/api/v/share-on\t-\t200\tsharing:on' \
  $'v-share-on-2\t4.3\tanon\tGET\t/api/v/share-on-2\t-\t200\tsharing:on' \
  $'v-share-off\t4.3\tanon\tGET\t/api/v/share-off\t-\t200\tsharing:off' \
  > "$T/tests/fixtures/rbac_matrix/v.tsv"
printf '%s\n' \
  $'w-plain\t5.2\tanon\tGET\t/api/w/plain\t-\t200\treq:SH-02' \
  $'w-write-on\t5.2\tanon\tGET\t/api/w/write-on\t-\t200\treq:SH-02 sharing:on sharingwrite:on' \
  $'w-write-off\t5.2\tanon\tGET\t/api/w/write-off\t-\t200\tsharing:on sharingwrite:off' \
  $'w-write-only\t5.2\tanon\tGET\t/api/w/write-only\t-\t200\tsharingwrite:on' \
  > "$T/tests/fixtures/rbac_matrix/w.tsv"
printf '%s\n' \
  $'g-plain\t6.13\tanon\tGET\t/api/g/plain\t-\t200\treq:GV-01' \
  $'g-gov-on\t6.13\tanon\tGET\t/api/g/gov-on\t-\t200\treq:GV-01 governance:on' \
  $'g-gov-off\t6.13\tanon\tGET\t/api/g/gov-off\t-\t200\tgovernance:off' \
  $'g-gov-share-on\t6.13\tanon\tGET\t/api/g/gov-share-on\t-\t200\tgovernance:on sharing:on' \
  > "$T/tests/fixtures/rbac_matrix/g.tsv"

# docker: the webapp's switches come from FAKE_* through the runner's own in-container
# command (run here by sh), the seed prints the keys the runner requires, every call is logged.
# Root's sharing policy is FAKE_POLICY (on by default; FAIL makes psql fail), or, with
# REAL_PG set, the runner's SQL runs in that throwaway postgres container.
cat > "$W/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >> "$STUB_LOG"
case "$*" in
  *"ps --status running"*) echo fake-webapp ;;
  *" postgres "*)
    sql="$(cat)"
    if [ -n "${REAL_PG:-}" ] && grep -q sharing_policy <<<"$sql"; then
      if grep -q rbac-write-policy <<<"$sql"; then echo "write-policy-read" >> "$STUB_LOG"; else echo "policy-read" >> "$STUB_LOG"; fi
      printf '%s\n' "$sql" | "$REAL_DOCKER" exec -i "$REAL_PG" psql -X -q -t -A -v ON_ERROR_STOP=1 -h 127.0.0.1 -U postgres
    elif grep -q rbac-write-policy <<<"$sql"; then
      echo "write-policy-read" >> "$STUB_LOG"
      [ "${FAKE_WRITE_POLICY-on}" = FAIL ] && exit 1
      printf '%s\n' "${FAKE_WRITE_POLICY-on}"
    elif grep -q sharing_policy <<<"$sql"; then
      echo "policy-read" >> "$STUB_LOG"
      [ "${FAKE_POLICY-on}" = FAIL ] && exit 1
      printf '%s\n' "${FAKE_POLICY-on}"
    else
      sed -n "s/.*where id = '\([^']*\)'.*/\1/p" <<<"$sql"
    fi ;;
  *" webapp sh -c "*)
    script=""; prev=""
    for a in "$@"; do [ "$prev" = -c ] && script="$a"; prev="$a"; done
    echo "switches-read" >> "$STUB_LOG"
    env -i PATH="$PATH" RBAC_IDENTITY_ENABLED="${FAKE_IDENTITY-}" RBAC_PERMISSIONS_ENABLED="${FAKE_PERMISSIONS-}" \
      RBAC_SHARING_ENABLED="${FAKE_SHARING-}" RBAC_SHARING_WRITE_ENABLED="${FAKE_SHARING_WRITE-}" \
      RBAC_GOVERNANCE_ENABLED="${FAKE_GOVERNANCE-}" RBAC_AUTHZ_CACHE_MS="${FAKE_CACHE_MS-}" sh -c "$script" ;;
  *" node "*)
    if grep -q SEED; then
      printf 'PA_ID=pa\nPB_ID=pb\nMEMBER_A_ID=ma\nMEMBER_B_ID=mb\nADMIN_A_ID=aa\nRBAC_PASSWORD=pw\n'
    fi ;;
  *) echo "unexpected docker call" >&2; exit 1 ;;
esac
STUB
# curl: every request answers 200 with an empty body; the URL of each row's request is logged.
# A row's request (not the health probe or a sign-in) answers FAKE_STATUS with the body in the file
# FAKE_BODY when they are set.
cat > "$W/bin/curl" <<'STUB'
#!/usr/bin/env bash
url=""; prev=""; out=""; row=1
for a in "$@"; do
  case "$prev" in
    -o) [ "$a" = /dev/null ] || out="$a" ;;
    -D) printf 'HTTP/1.1 200 OK\r\n' > "$a" ;;
  esac
  case "$a" in */api/health|*/api/auth/login) row="" ;; esac
  prev="$a"; url="$a"
done
if [ -n "$out" ]; then
  if [ -n "$row" ] && [ -n "${FAKE_BODY:-}" ]; then cat "$FAKE_BODY" > "$out"; else : > "$out"; fi
fi
case "$url" in */api/health) ;; *) echo "request ${url#*://*/}" >> "$STUB_LOG" ;; esac
if [ -n "$row" ]; then printf '%s' "${FAKE_STATUS:-200}"; else printf 200; fi
STUB
printf '#!/usr/bin/env bash\necho "sleep $*" >> "$STUB_LOG"\n' > "$W/bin/sleep"
chmod +x "$W/bin/docker" "$W/bin/curl" "$W/bin/sleep"

# run <identity> <permissions> [row filter] [matrix file] [cache ms] [sharing] [policy] [write] [write policy] [governance]:
# OUT holds the output, RC the status, LOG the stub calls.
run() {
  : > "$W/calls.log"
  OUT="$(cd "$W" && PATH="$W/bin:$PATH" STUB_LOG="$W/calls.log" BASE_URL=http://rbac-runner-test.invalid \
    FAKE_IDENTITY="$1" FAKE_PERMISSIONS="$2" FAKE_CACHE_MS="${5:-5000}" FAKE_SHARING="${6:-}" RBAC_MATRIX_ROWS="${3:-}" \
    FAKE_POLICY="${7-on}" FAKE_SHARING_WRITE="${8:-}" FAKE_WRITE_POLICY="${9-on}" FAKE_GOVERNANCE="${10:-}" \
    REAL_PG="${REAL_PG:-}" REAL_DOCKER="${REAL_DOCKER:-}" \
    bash "$T/tests/rbac_matrix_live.sh" "${4:-t}" 2>&1)"; RC=$?
  LOG="$(cat "$W/calls.log")"
}
line()     { grep -E "^(PASS|SKIP|FAIL) +$1 " <<<"$OUT" | head -1; }
verdict()  { line "$1" | awk '{print $1}'; }
requests() { grep '^request ' <<<"$LOG" | sed 's/^request //' | tr '\n' ' '; }
reads()    { grep -c '^switches-read$' <<<"$LOG"; }
policy_reads() { grep -c '^policy-read$' <<<"$LOG"; }
write_policy_reads() { grep -c '^write-policy-read$' <<<"$LOG"; }

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

section "Root's sharing policy (4.3 review finding 6): the tag follows the effective state"
run true true '' v 5000 true off
eq "switch on, policy off: exit 0" "$RC" "0"
eq "switch on, policy off: untagged row runs" "$(verdict v-plain)" "PASS"
eq "switch on, policy off: the owner-only sharing:off row runs" "$(verdict v-share-off)" "PASS"
eq "switch on, policy off: sharing:on skips" "$(verdict v-share-on)" "SKIP"
has "the skip names the policy, not the switch alone" "(sharing switch on, Root's policy off)" "$(line v-share-on)"
eq "the skipped rows never reach the webapp" "$(requests)" "api/v/plain api/v/share-off "
eq "the policy is read once for three tagged rows" "$(policy_reads)" "1"
has "result line" "== RESULT: 2 passed, 0 failed, 2 skipped ==" "$OUT"
run true true '' v 5000 true on
eq "switch on, policy on: sharing:on runs" "$(verdict v-share-on)" "PASS"
eq "switch on, policy on: sharing:off skips" "$(verdict v-share-off)" "SKIP"
has "named as before" "(sharing switch on)" "$(line v-share-off)"
eq "read once" "$(policy_reads)" "1"
run true true '' v 5000 '' on
eq "switch off: sharing:off runs whatever the policy" "$(verdict v-share-off)" "PASS"
eq "switch off: the policy is not read" "$(policy_reads)" "0"
run true '' '' v 5000 true on
eq "permissions off: the policy is not read" "$(policy_reads)" "0"
run true true '^v-plain$' v 5000 true on
eq "no tagged row selected: the policy is not read" "$(policy_reads)" "0"
run true true '' v 5000 true FAIL
eq "policy unreadable: the tagged rows fail" "$(verdict v-share-on) $(verdict v-share-off)" "FAIL FAIL"
has "and say why" "could not read Root's sharing policy" "$(line v-share-off)"
eq "policy unreadable: untagged row still runs" "$(verdict v-plain)" "PASS"
eq "policy unreadable: exit 1" "$RC" "1"
eq "policy unreadable: read once" "$(policy_reads)" "1"
run true true '' v 5000 true 'garbage'
eq "an answer that is neither on nor off fails the tagged rows" "$(verdict v-share-on)" "FAIL"
run true true '' v 5000 true ''
eq "an empty answer fails them too (the query always returns one row)" "$(verdict v-share-off)" "FAIL"

section "write sharing (step 5.2): the sharingwrite tag follows the effective state"
run true true '' w 5000 true on true on
eq "all on, policy at write: sharingwrite:on runs" "$(verdict w-write-on)" "PASS"
eq "all on, policy at write: sharingwrite:off skips" "$(verdict w-write-off)" "SKIP"
has "named" "(sharingwrite switch on)" "$(line w-write-off)"
eq "the write policy is read once for two tagged rows" "$(write_policy_reads)" "1"
run true true '' w 5000 true on true off
eq "Root's policy at read: sharingwrite:on skips" "$(verdict w-write-on)" "SKIP"
has "the skip names the policy" "(sharingwrite switch on, Root's policy off)" "$(line w-write-on)"
eq "Root's policy at read: the write-off row runs" "$(verdict w-write-off)" "PASS"
run true true '' w 5000 true off true on
eq "sharing policy off: write is not in force either" "$(verdict w-write-on)" "SKIP"
run true true '' w 5000 true on '' on
eq "write switch unset: sharingwrite:off runs" "$(verdict w-write-off)" "PASS"
eq "write switch unset: no write policy read" "$(write_policy_reads)" "0"
run true true '' w 5000 '' on true on
eq "sharing switch off: the write switch reads off, whatever it says" "$(verdict w-write-on)" "SKIP"
has "named off" "(sharing switch off)" "$(line w-write-on)"
eq "a row tagged sharingwrite:on alone skips too (the chain, not the sharing tag)" "$(verdict w-write-only)" "SKIP"
has "named as the write switch, off" "(sharingwrite switch off)" "$(line w-write-only)"
run true true '' w 5000 true on true FAIL
eq "write policy unreadable: the write rows fail" "$(verdict w-write-on) $(verdict w-write-off)" "FAIL FAIL"
eq "write policy unreadable: the untagged row runs" "$(verdict w-plain)" "PASS"
run true true '' u 1500 true on true on
eq "the cache bound still parses after the write value" "$(grep '^sleep ' <<<"$LOG" | tr '\n' ' ')" "sleep 3 sleep 3 "

section "the governance switch (step 6.13): governance:on|off follows RBAC_GOVERNANCE_ENABLED"
run true true '' g 5000 '' on '' on true
eq "governance on: exit 0" "$RC" "0"
eq "governance on: untagged row runs" "$(verdict g-plain)" "PASS"
eq "governance on: governance:on runs" "$(verdict g-gov-on)" "PASS"
eq "governance on: governance:off skips" "$(verdict g-gov-off)" "SKIP"
has "the skip names the governance switch" "(governance switch on)" "$(line g-gov-off)"
eq "governance on, sharing unset: a row that also needs sharing skips on it" "$(verdict g-gov-share-on)" "SKIP"
has "named as the sharing switch" "(sharing switch off)" "$(line g-gov-share-on)"
eq "only the selected rows reach the webapp" "$(requests)" "api/g/plain api/g/gov-on "
eq "the switches are read once" "$(reads)" "1"
eq "no policy is read for governance" "$(policy_reads) $(write_policy_reads)" "0 0"
has "result line" "== RESULT: 2 passed, 0 failed, 2 skipped ==" "$OUT"
run true true '' g 5000 '' on '' on ''
eq "governance unset: governance:on skips" "$(verdict g-gov-on)" "SKIP"
has "named off" "(governance switch off)" "$(line g-gov-on)"
eq "governance unset: governance:off runs" "$(verdict g-gov-off)" "PASS"
run true '' '' g 5000 '' on '' on true
eq "permissions off: governance reads off, whatever it says" "$(verdict g-gov-on)" "SKIP"
has "named off" "(governance switch off)" "$(line g-gov-on)"
eq "permissions off: governance:off runs" "$(verdict g-gov-off)" "PASS"
run false true '' g 5000 '' on '' on true
eq "identity off: permissions and governance read off" "$(verdict g-gov-off)" "PASS"
eq "identity off: governance:on skips" "$(verdict g-gov-on)" "SKIP"
run true true '' g 5000 true on '' on true
eq "governance and sharing on, policy on: the combined row runs" "$(verdict g-gov-share-on)" "PASS"
eq "read once" "$(policy_reads)" "1"
run true true '' g 5000 true off '' on true
eq "Root's sharing policy off: the combined row skips on sharing" "$(verdict g-gov-share-on)" "SKIP"
has "named as the policy" "(sharing switch on, Root's policy off)" "$(line g-gov-share-on)"
eq "Root's sharing policy off: governance:on still runs (governance reads no policy)" "$(verdict g-gov-on)" "PASS"
run true true '' g 5000 '' on '' on ' Yes '
eq "' Yes ' is on" "$(verdict g-gov-on)" "PASS"
run true true '' g 5000 '' on '' on 'On'
eq "On is not a value the webapp knows: governance reads off" "$(verdict g-gov-off)" "PASS"
run true true '^g-plain$' g 5000 '' on '' on true
eq "no tagged row selected: no switch read" "$(reads)" "0"
run true true '' u 1500 true on true on true
eq "the cache bound still parses after the governance value" "$(grep '^sleep ' <<<"$LOG" | tr '\n' ' ')" "sleep 3 sleep 3 "

section "the console pages with governance off (p6.tsv as committed): Next's not-found page, never the console"
# The admin layout's notFound() streams under the root <Suspense> after a 200 (S0 red, 2026-11-13), so the
# rows accept 200 or 404 and decide on the body. The bodies hold the markers a real answer of each kind
# carries: the digest notFound() leaves, Next's not-found text (in every page's payload, so not a marker),
# and, when the layout renders the console, its client reference and its loading state.
cp "$REPO_ROOT/tests/fixtures/rbac_matrix/p6.tsv" "$T/tests/fixtures/rbac_matrix/p6.tsv"
NOT_FOUND_PAGE='<meta name="robots" content="noindex"/><title>404: This page could not be found.</title><h1 class="next-error-h1">404</h1><h2>This page could not be found.</h2><script>self.__next_f.push([1,"a:E{\"digest\":\"NEXT_HTTP_ERROR_FALLBACK;404\"}\n"])</script>'
CONSOLE_REF='<script>self.__next_f.push([1,"7:I[749583,[\"/_next/static/chunks/e2db446e.js\"],\"AdminConsole\"]\n"])</script>'
printf '%s' "$NOT_FOUND_PAGE" > "$W/body.soft404"
printf '%s<div><p role="status">Loading the admin console…</p></div><h2>This page could not be found.</h2>' "$CONSOLE_REF" > "$W/body.console"
printf '<nav aria-label="Admin console"><p aria-hidden="true">Admin console</p></nav>%s' "$NOT_FOUND_PAGE" > "$W/body.console_around_404"
printf '%s%s' "$CONSOLE_REF" "$NOT_FOUND_PAGE" > "$W/body.console_ref_only"
: > "$W/body.empty"
OFF_ROWS='^p6-page-admin(-users|-instance)?-off$'
ON_ROWS='^p6-page-admin(-instance)?-on$'
page_rows() { # body status rows governance -> OUT
  FAKE_BODY="$W/body.$1" FAKE_STATUS="$2"; export FAKE_BODY FAKE_STATUS
  run true true "$3" p6 5000 '' on '' on "$4"
  unset FAKE_BODY FAKE_STATUS
}
page_rows soft404 200 "$OFF_ROWS" ''
eq "off, the soft 404 (200 + the not-found page): the three rows pass" \
  "$(verdict p6-page-admin-off) $(verdict p6-page-admin-users-off) $(verdict p6-page-admin-instance-off)" "PASS PASS PASS"
has "result line" "== RESULT: 3 passed, 0 failed, 0 skipped ==" "$OUT"
page_rows soft404 404 "$OFF_ROWS" ''
eq "off, a real 404 with the same page: pass" "$(verdict p6-page-admin-off) $(verdict p6-page-admin-users-off)" "PASS PASS"
page_rows console 200 "$OFF_ROWS" ''
eq "mutation: the console rendered (200, its loading state): the three rows fail" \
  "$(verdict p6-page-admin-off) $(verdict p6-page-admin-users-off) $(verdict p6-page-admin-instance-off)" "FAIL FAIL FAIL"
has "and say the not-found digest is missing" "body lacks NEXT_HTTP_ERROR_FALLBACK" "$(line p6-page-admin-off)"
page_rows console_around_404 200 "$OFF_ROWS" ''
eq "mutation: the console's shell around a not-found (gate moved into a page): fail" "$(verdict p6-page-admin-off)" "FAIL"
has "on the console's markup" "body contains Admin console" "$(line p6-page-admin-off)"
page_rows console_ref_only 200 "$OFF_ROWS" ''
eq "mutation: the not-found digest but the console's client reference in the payload: fail" "$(verdict p6-page-admin-users-off)" "FAIL"
has "on the reference" "body contains AdminConsole" "$(line p6-page-admin-users-off)"
page_rows empty 200 "$OFF_ROWS" ''
eq "mutation: a 200 with no not-found page (status alone no longer passes): fail" "$(verdict p6-page-admin-instance-off)" "FAIL"
has "on the body" "body lacks NEXT_HTTP_ERROR_FALLBACK" "$(line p6-page-admin-instance-off)"
page_rows soft404 500 "$OFF_ROWS" ''
eq "mutation: another status with the not-found page: fail" "$(verdict p6-page-admin-off)" "FAIL"
has "on the status" "expected 200|404, got 500" "$(line p6-page-admin-off)"
page_rows console 200 "$ON_ROWS" true
eq "on, the console rendered: the two rows pass" "$(verdict p6-page-admin-on) $(verdict p6-page-admin-instance-on)" "PASS PASS"
page_rows soft404 200 "$ON_ROWS" true
eq "mutation: on but the not-found page (the switch not read on): the two rows fail" \
  "$(verdict p6-page-admin-on) $(verdict p6-page-admin-instance-on)" "FAIL FAIL"
has "on the body" "body lacks AdminConsole" "$(line p6-page-admin-on)"
page_rows soft404 200 "$ON_ROWS" ''
eq "governance off: the on rows skip" "$(verdict p6-page-admin-on)" "SKIP"

section "Root's stored policy through the runner's own SQL (Phase 7 kickoff: no maxLevel means write)"
# The stubbed answers above cannot catch a wrong query. Here each policy is stored in a
# throwaway container of the stack's own postgres image (never pulled, no network) and the
# runner's SQL reads it, so every case is parseSharingPolicy + maxShareLevel on that value.
if command -v docker >/dev/null 2>&1 && docker image inspect postgres:16-alpine >/dev/null 2>&1; then
  PG="rbac-runner-test-pg-$$"
  docker run -d --rm --network none --name "$PG" -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16-alpine >/dev/null 2>&1 || PG=""
fi
pg_ready=""
if [ -n "$PG" ]; then
  # The image's init server listens on no TCP port, so a TCP answer is the final server.
  for _ in $(seq 1 120); do
    docker exec "$PG" pg_isready -q -h 127.0.0.1 -U postgres 2>/dev/null && { pg_ready=1; break; }
    sleep 0.5
  done
fi
pg() { docker exec -i "$PG" psql -X -q -t -A -v ON_ERROR_STOP=1 -h 127.0.0.1 -U postgres; }
if [ -n "$pg_ready" ] && echo "create table instance_settings (id text primary key, sharing_policy jsonb not null default '{}');" | pg; then
  REAL_PG="$PG"; REAL_DOCKER="$(command -v docker)"
  store() { # the stored policy as JSON, or NOROW for no instance row
    { echo "delete from instance_settings;"
      [ "$1" = NOROW ] || printf "insert into instance_settings (id, sharing_policy) values ('instance', '%s'::jsonb);\n" "$1"
    } | pg
  }
  # policy_case <stored policy> <write switch> <want w-write-on> <want w-write-off> <want w-write-only> [what]
  policy_case() {
    store "$1"
    run true true '' w 5000 true '' "$2" ''
    eq "${6:-$1}, write switch '${2:-unset}': sharing:on sharingwrite:on / sharing:on sharingwrite:off / sharingwrite:on" \
      "$(verdict w-write-on) $(verdict w-write-off) $(verdict w-write-only)" "$3 $4 $5"
  }
  policy_case '{"enabled":true}' true PASS SKIP PASS "no maxLevel (the 5.2b form)"
  has "the sharingwrite:off row is skipped as write in force" "(sharingwrite switch on)" "$(line w-write-off)"
  eq "each policy query read once" "$(policy_reads) $(write_policy_reads)" "1 1"
  policy_case '{"enabled":true,"maxLevel":"write"}' true PASS SKIP PASS
  policy_case '{"enabled":true,"maxLevel":"read"}' true SKIP PASS SKIP
  has "capped at read: the skip names the policy" "(sharingwrite switch on, Root's policy off)" "$(line w-write-on)"
  policy_case '{"enabled":true}' '' SKIP PASS SKIP "no maxLevel"
  has "write switch off: the skip names the switch" "(sharingwrite switch off)" "$(line w-write-on)"
  eq "write switch off: the write policy is not read" "$(write_policy_reads)" "0"
  policy_case '{"enabled":true,"maxLevel":"write"}' false SKIP PASS SKIP
  policy_case '{"enabled":true,"maxLevel":"read"}' '' SKIP PASS SKIP
  policy_case '{"enabled":true,"defaultExpiryDays":30,"membersMayGrantExploit":true,"adminsSeeAllShares":false}' true PASS SKIP PASS \
    "every other setting valid, no maxLevel"
  policy_case '{"enabled":true,"defaultExpiryDays":null}' true PASS SKIP PASS
  policy_case '{"enabled":true,"aFutureSetting":"x"}' true PASS SKIP PASS "an unknown setting is ignored, no maxLevel"
  policy_case '{"maxLevel":"write"}' true SKIP SKIP SKIP "enabled missing (default false)"
  policy_case '{"enabled":false}' true SKIP SKIP SKIP
  policy_case '{}' true SKIP SKIP SKIP
  policy_case NOROW true SKIP SKIP SKIP "no instance row (the defaults)"
  policy_case '{"enabled":true,"maxLevel":"admin"}' true SKIP SKIP SKIP "an invalid maxLevel: the whole policy reads as the defaults"
  policy_case '{"enabled":true,"maxLevel":null}' true SKIP SKIP SKIP
  policy_case '{"enabled":true,"defaultExpiryDays":0}' true SKIP SKIP SKIP "another setting invalid, no maxLevel"
  policy_case '{"enabled":true,"defaultExpiryDays":1.5}' true SKIP SKIP SKIP
  policy_case '{"enabled":true,"membersMayGrantExploit":"yes"}' true SKIP SKIP SKIP
  policy_case '{"enabled":"true"}' true SKIP SKIP SKIP "enabled as a string"
  policy_case '[{"enabled":true}]' true SKIP SKIP SKIP "not an object"
  store '{"enabled":true,"maxLevel":"read"}'
  run true true '' v 5000 true '' true ''
  eq "capped at read is still sharing in force: sharing:on runs, sharing:off skips" \
    "$(verdict v-share-on) $(verdict v-share-off)" "PASS SKIP"
  unset REAL_PG REAL_DOCKER
else
  printf '  skip %s (%s)\n' "the runner's policy SQL against stored policies" \
    "needs Docker and the local postgres:16-alpine image (the stack's own); never pulled here"
fi

section "the runner documents the tag"
HEADER="$(sed -n '1,/^set -uo pipefail/p' "$RUNNER")"
has "permissions:on | permissions:off in the row format" "permissions:on | permissions:off" "$HEADER"
has "and the chain" "RBAC_PERMISSIONS_ENABLED" "$HEADER"
has "sharing:on | sharing:off in the row format" "sharing:on | sharing:off" "$HEADER"
has "and its chain" "RBAC_SHARING_ENABLED" "$HEADER"
has "and Root's policy" "instance_settings.sharing_policy" "$HEADER"
has "sharingwrite:on | sharingwrite:off in the row format" "sharingwrite:on | sharingwrite:off" "$HEADER"
has "and its switch" "RBAC_SHARING_WRITE_ENABLED" "$HEADER"
has "and the maxLevel default" "a policy without \`maxLevel\` allows write" "$HEADER"
has "governance:on | governance:off in the row format" "governance:on | governance:off" "$HEADER"
has "and its switch" "RBAC_GOVERNANCE_ENABLED" "$HEADER"

echo
echo "-----------------------------------------"
printf 'Matrix runner suite: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
