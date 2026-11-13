#!/usr/bin/env bash
#
# Live check of device sessions (RBAC step 6.10: GV-17, UI-09; E2E-P6-08's route half), run against
# the LIVE stack, in whichever state the webapp's RBAC_GOVERNANCE_ENABLED is (read from its container,
# with the identity and permissions switches it needs).
#
# Switch on: rbac-member-c signs in from two browsers, which writes two user_sessions rows; each
# browser lists both, itself marked current; one browser revokes the other, which is refused at its
# next request (401 session_ended) while the first goes on; a second revoke changes nothing; one
# user.session_revoked row names the session and never its address or browser. Then rbac-admin-a
# revokes the first browser through /api/users/<id>/sessions/<sid> (audited by the admin); a member
# asking the admin route is refused; the admin's own account on it is 400 own_account. A sign-out ends
# its browser's row (ended_by sign_out) and the copied cookie is refused.
#
# Switch off: the four routes answer 404 and a sign-in writes no row.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local), removed with their
# audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C (their user_sessions rows go with the accounts).
# Both scripts are fed to the webapp container on stdin. Response bodies and the fixture password are
# never printed. user_sessions and audit_log are read through psql in the postgres container.
#
# Needs the stack up (webapp on :3000); prints SKIP and exits 0 when it is not. As a *_live.sh it is
# never in the gate.
#
# Run:  bash tests/rbac_device_sessions_live.sh            (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"

health="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
if [ "$health" != 200 ]; then
  echo "SKIP: RedAmon webapp not answering at $BASE/api/health (got ${health:-nothing})"
  exit 0
fi
for svc in webapp postgres; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done

TMP="$(mktemp -d)"
CLEANED_UP=0
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

switch_on() { # raw env value -> 0 when on, parsed as webapp/src/lib/authz/flags.ts does
  case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in true|1|yes) return 0 ;; *) return 1 ;; esac
}
envs="$(cd "$ROOT" && docker compose exec -T webapp sh -c 'printf "%s|%s|%s" "${RBAC_IDENTITY_ENABLED:-}" "${RBAC_PERMISSIONS_ENABLED:-}" "${RBAC_GOVERNANCE_ENABLED:-}"' 2>/dev/null)"
IFS='|' read -r ENV_ID ENV_PERM ENV_GOV <<< "$envs"
GOVERNANCE=off
switch_on "$ENV_ID" && switch_on "$ENV_PERM" && switch_on "$ENV_GOV" && GOVERNANCE=on
echo "== Governance switch (with identity and permissions): $GOVERNANCE =="

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in ADMIN_A_EMAIL ADMIN_A_ID MEMBER_C_EMAIL MEMBER_C_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
safe_id "${SEED[MEMBER_C_ID]}" && safe_id "${SEED[ADMIN_A_ID]}" || { echo "unexpected fixture id"; exit 1; }
C="${SEED[MEMBER_C_ID]}"
A="${SEED[ADMIN_A_ID]}"

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
login() { # email jar -> http code; the body lands in $TMP/body
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -c "$2" -A 'rbac-live/6.10' -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
call() { # jar method path [json-body] -> http code; body in $TMP/body, headers in $TMP/headers
  local jar="$1" method="$2" path="$3"
  local args=(-s -m 70 -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -X "$method" -b "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}
field() { # python expression on the JSON body `b` -> printed value (never the whole body)
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$TMP/body" "$1" 2>/dev/null || true
}
rows() { # the member's live device session rows
  printf "select count(*) from user_sessions where user_id = '%s' and revoked_at is null;\n" "$C" | db_sql
}

if [ "$GOVERNANCE" = off ]; then
  echo "== Switch off: no device session is written, the routes do not exist =="
  before="$(printf "select count(*) from information_schema.tables where table_name = 'user_sessions';\n" | db_sql)"
  n0=0; [ "$before" = 1 ] && n0="$(rows)"
  J="$TMP/jar.off"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$J")"; ok=0; [ "$code" = 200 ] && ok=1
  check "the member signs in -> $code" "$ok"
  n1=0; [ "$before" = 1 ] && n1="$(rows)"
  ok=0; [ "$n0" = "$n1" ] && ok=1; check "the sign-in wrote no user_sessions row ($n0 -> $n1)" "$ok"
  ADMIN="$TMP/jar.admin"; login "${SEED[ADMIN_A_EMAIL]}" "$ADMIN" > /dev/null
  for spec in "$J GET /api/account/sessions" "$J DELETE /api/account/sessions/nosuch" \
              "$ADMIN GET /api/users/$C/sessions" "$ADMIN DELETE /api/users/$C/sessions/nosuch"; do
    read -r jar method path <<< "$spec"
    code="$(call "$jar" "$method" "$path")"; ok=0; [ "$code" = 404 ] && ok=1
    check "$method $path -> $code (404)" "$ok"
  done
else
  echo "== Two browsers, one revoked =="
  n0="$(rows)"
  B1="$TMP/jar.b1"; B2="$TMP/jar.b2"
  c1="$(login "${SEED[MEMBER_C_EMAIL]}" "$B1")"; c2="$(login "${SEED[MEMBER_C_EMAIL]}" "$B2")"
  ok=0; [ "$c1$c2" = 200200 ] && [ "$(rows)" = $((n0 + 2)) ] && ok=1
  check "the member signs in from two browsers: two live rows ($c1 $c2)" "$ok" "rows $(rows), before $n0"

  code="$(call "$B2" GET /api/account/sessions)"
  S2="$(field "[s['id'] for s in b['sessions'] if s['current']][0]")"
  code1="$(call "$B1" GET /api/account/sessions)"
  S1="$(field "[s['id'] for s in b['sessions'] if s['current']][0]")"
  listed="$(field "sorted(s['id'] for s in b['sessions'] if s['state'] == 'active')")"
  ok=0; [ "$code$code1" = 200200 ] && safe_id "$S1" && safe_id "$S2" && [ "$S1" != "$S2" ] \
    && [ "$(field "sum(1 for s in b['sessions'] if s['current'])")" = 1 ] && [[ "$listed" == *"$S1"* && "$listed" == *"$S2"* ]] && ok=1
  check "each browser lists both, itself current ($code $code1)" "$ok"
  safe_id "$S1" && safe_id "$S2" || { echo "FAIL  no session ids: cannot go on"; exit 1; }

  code="$(call "$B1" DELETE "/api/account/sessions/$S2")"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('changed')")" = True ] && ok=1
  check "browser 1 revokes browser 2 -> $code" "$ok"
  code="$(call "$B2" GET /api/auth/me)"
  ok=0; [ "$code" = 401 ] && [ "$(field "b.get('code')")" = session_ended ] && ok=1
  check "browser 2 is refused at its next request -> $code session_ended" "$ok"
  code="$(call "$B1" GET /api/auth/me)"; ok=0; [ "$code" = 200 ] && ok=1
  check "browser 1 goes on -> $code" "$ok"
  code="$(call "$B1" DELETE "/api/account/sessions/$S2")"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('changed')")" = False ] && [ "$(field "b.get('state')")" = revoked ] && ok=1
  check "a second revoke changes nothing -> $code" "$ok"
  n="$(printf "select count(*) from audit_log where action = 'user.session_revoked' and actor_id = '%s' and target_id = '%s' and after->>'sessionId' = '%s' and after::text not like '%%rbac-live%%';\n" "$C" "$C" "$S2" | db_sql)"
  ok=0; [ "$n" = 1 ] && ok=1; check "one user.session_revoked row by the member, naming the session, not its browser" "$ok" "got $n"

  echo "== The admin side =="
  ADMIN="$TMP/jar.admin"
  code="$(login "${SEED[ADMIN_A_EMAIL]}" "$ADMIN")"; [ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-admin-a answered $code"; exit 1; }
  code="$(call "$ADMIN" GET "/api/users/$C/sessions")"
  ok=0; [ "$code" = 200 ] && [ "$(field "[s['state'] for s in b['sessions'] if s['id'] == '$S2'][0]")" = revoked ] && ok=1
  check "rbac-admin-a lists the member's sessions, the revoked one revoked -> $code" "$ok"
  code="$(call "$ADMIN" DELETE "/api/users/$C/sessions/$S1")"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('changed')")" = True ] && ok=1
  check "rbac-admin-a revokes browser 1 -> $code" "$ok"
  code="$(call "$B1" GET /api/auth/me)"; ok=0; [ "$code" = 401 ] && ok=1
  check "browser 1 is refused -> $code" "$ok"
  n="$(printf "select count(*) from audit_log where action = 'user.session_revoked' and actor_id = '%s' and target_id = '%s' and after->>'by' = 'admin';\n" "$A" "$C" | db_sql)"
  ok=0; [ "$n" = 1 ] && ok=1; check "one user.session_revoked row by the admin" "$ok" "got $n"
  B3="$TMP/jar.b3"; login "${SEED[MEMBER_C_EMAIL]}" "$B3" > /dev/null
  code="$(call "$B3" GET "/api/users/$C/sessions")"; ok=0; [ "$code" = 403 ] && ok=1
  check "the member on the admin route -> $code (403)" "$ok"
  code="$(call "$ADMIN" GET "/api/users/$A/sessions")"
  ok=0; [ "$code" = 400 ] && [ "$(field "b.get('code')")" = own_account ] && ok=1
  check "the admin's own account on the admin route -> $code own_account" "$ok"

  echo "== Sign-out ends its row =="
  cp "$B3" "$TMP/jar.copy"
  code="$(call "$B3" GET /api/account/sessions)"; S3="$(field "[s['id'] for s in b['sessions'] if s['current']][0]")"
  code="$(call "$B3" POST /api/auth/logout '{}')"; ok=0; [ "$code" = 200 ] && ok=1
  check "browser 3 signs out -> $code" "$ok"
  ended="$(printf "select coalesce(ended_by, '-') from user_sessions where id = '%s';\n" "$S3" | db_sql)"
  ok=0; safe_id "$S3" && [ "$ended" = sign_out ] && ok=1; check "its row is ended_by sign_out" "$ok" "got $ended"
  code="$(call "$TMP/jar.copy" GET /api/auth/me)"; ok=0; [ "$code" = 401 ] && ok=1
  check "a copy of its cookie is refused -> $code" "$ok"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
