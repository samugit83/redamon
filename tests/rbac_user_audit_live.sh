#!/usr/bin/env bash
#
# Live check of the user-administration audit (RBAC step 1.5, HD-14), run against the
# LIVE stack: an admin creates, edits, promotes, demotes, resets and deletes a throwaway
# account through the real routes, and audit_log must then hold exactly those six rows
# for it, in order, each with the admin as actor and no password or hash in it. Then the
# act-as end row must name its target (and a DELETE without the cookie must write none),
# and a logout row must name the account that signed out.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local) plus the
# throwaway rbac-audit-throwaway@e2e.local, all removed with their audit rows by
# e2e-rbac-cleanup.mjs, even on Ctrl-C. Both scripts are fed to the webapp container on
# stdin. Response bodies and the fixture passwords are never printed. audit_log and
# act_as_audit are read through psql in the postgres container (SQL on stdin).
#
# Needs the stack up (webapp on :3000); prints SKIP and exits 0 when it is not. As a
# *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_user_audit_live.sh            (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
THROWAWAY_EMAIL='rbac-audit-throwaway@e2e.local'
RENAMED_EMAIL='rbac-audit-renamed@e2e.local'
THROWAWAY_PASSWORD='rbac-audit-first-passphrase'
RESET_PASSWORD='rbac-audit-reset-passphrase'

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

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in ADMIN_A_EMAIL ADMIN_A_ID MEMBER_A_ID MEMBER_B_EMAIL MEMBER_B_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}

login() { # email jar -> http code
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
call() { # jar method path [json-body] -> http code; the body lands in $TMP/body, never printed
  local jar="$1" method="$2" path="$3"
  local args=(-s -m 70 -o "$TMP/body" -w '%{http_code}' -X "$method" -b "$jar" -c "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}

ADMIN_JAR="$TMP/jar.admin"
code="$(login "${SEED[ADMIN_A_EMAIL]}" "$ADMIN_JAR")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-admin-a answered $code"; exit 1; }

# ---- six administrative actions on one throwaway account ------------------------------
echo "== User administration =="
code="$(call "$ADMIN_JAR" POST /api/users \
  "{\"name\":\"RBAC Audit Throwaway\",\"email\":\"$THROWAWAY_EMAIL\",\"password\":\"$THROWAWAY_PASSWORD\",\"role\":\"standard\"}")"
TID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("id",""))' "$TMP/body" 2>/dev/null || true)"
ok=0; [ "$code" = 201 ] && safe_id "$TID" && ok=1
check "create the throwaway account -> $code" "$ok"
[ "$ok" = 1 ] || exit 1

code="$(call "$ADMIN_JAR" PUT "/api/users/$TID" "{\"name\":\"RBAC Audit Renamed\",\"email\":\"$RENAMED_EMAIL\"}")"
ok=0; [ "$code" = 200 ] && ok=1; check "edit its name and email -> $code" "$ok"
code="$(call "$ADMIN_JAR" PUT "/api/users/$TID" '{"role":"admin"}')"
ok=0; [ "$code" = 200 ] && ok=1; check "promote it -> $code" "$ok"
code="$(call "$ADMIN_JAR" PUT "/api/users/$TID" "{\"role\":\"standard\",\"stepUpPassword\":\"${SEED[RBAC_PASSWORD]}\"}")"
ok=0; [ "$code" = 200 ] && ok=1; check "demote it (another admin: step-up) -> $code" "$ok"
code="$(call "$ADMIN_JAR" PUT "/api/users/$TID/password" "{\"newPassword\":\"$RESET_PASSWORD\"}")"
ok=0; [ "$code" = 200 ] && ok=1; check "reset its password -> $code" "$ok"
code="$(call "$ADMIN_JAR" DELETE "/api/users/$TID")"
ok=0; [ "$code" = 200 ] && ok=1; check "delete it -> $code" "$ok"

printf "select action || chr(9) || coalesce(actor_id, '-') || chr(9) || coalesce(source, '') || chr(9) || coalesce(before::text, '') || chr(9) || coalesce(after::text, '') from audit_log where target_type = 'user' and target_id = '%s' order by created_at, id;\n" "$TID" \
  | db_sql > "$TMP/rows" || true
want=(user.create user.update user.role_changed user.role_changed user.credentials_reset user.delete)
mapfile -t got < <(cut -f1 "$TMP/rows")
ok=0; [ "${got[*]:-}" = "${want[*]}" ] && ok=1
check "audit_log holds exactly the six rows, in order" "$ok" "got: ${got[*]:-none}"
ok=1; while IFS=$'\t' read -r _ actor source _ _; do
  [ "$actor" = "${SEED[ADMIN_A_ID]}" ] && [ "$source" = api ] || ok=0
done < "$TMP/rows"
check "every row: actor = the admin, source api" "$ok"
# Step 2.1 (AU-01, AU-08): the actor's email is snapshotted; nobody was acted for here.
printf "select coalesce(actor_email, '-') || chr(9) || coalesce(on_behalf_of_user_id, '-') from audit_log where target_type = 'user' and target_id = '%s' order by created_at, id;\n" "$TID" \
  | db_sql > "$TMP/actor_cols" || true
ok=0; [ "$(wc -l < "$TMP/actor_cols")" -eq 6 ] && ok=1
while IFS=$'\t' read -r email onbehalf; do
  [ "$email" = "${SEED[ADMIN_A_EMAIL]}" ] && [ "$onbehalf" = - ] || ok=0
done < "$TMP/actor_cols"
check "every row: actor_email = the admin's address, no on_behalf_of_user_id" "$ok" "got: $(tr '\t\n' ', ' < "$TMP/actor_cols")"
ok=1
for s in "$THROWAWAY_PASSWORD" "$RESET_PASSWORD" "${SEED[RBAC_PASSWORD]}" '$2a$' '$2b$' '$2y$' '"password"' 'stepUpPassword'; do
  grep -qF -- "$s" "$TMP/rows" && ok=0
done
check "no password, hash or step-up field in any row" "$ok"
row() { sed -n "${1}p" "$TMP/rows"; }
has() { [[ "$(row "$1")" == *"$2"* ]]; }
ok=0; has 1 "\"email\": \"$THROWAWAY_EMAIL\"" && has 1 '"passwordless": false' && has 1 '"role": "standard"' && ok=1
check "user.create: email, role, passwordless" "$ok"
ok=0; has 2 "\"email\": \"$THROWAWAY_EMAIL\"" && has 2 "\"email\": \"$RENAMED_EMAIL\"" && has 2 '"name": "RBAC Audit Renamed"' && ok=1
check "user.update: name and email before and after" "$ok"
ok=0; [[ "$(row 3 | cut -f4,5)" == $'{"role": "standard"}\t{"role": "admin"}' ]] && [[ "$(row 4 | cut -f4,5)" == $'{"role": "admin"}\t{"role": "standard"}' ]] && ok=1
check "user.role_changed: standard->admin, then admin->standard" "$ok"
ok=0; has 5 '"revokedMcpTokens": 0' && ok=1; check "user.credentials_reset: revoked token count" "$ok"
ok=0; has 6 "\"email\": \"$RENAMED_EMAIL\"" && has 6 '"ownedProjectCount": 0' && has 6 '"role": "standard"' && ok=1
check "user.delete: email, role, owned project count" "$ok"

# ---- act-as end names its target; no cookie, no row -----------------------------------
echo "== Act-as end =="
safe_id "${SEED[ADMIN_A_ID]}" || exit 1
ends() { printf "select count(*) from act_as_audit where admin_id = '%s' and event = 'end' and target_user_id = '%s';\n" "${SEED[ADMIN_A_ID]}" "$1" | db_sql; }
all_ends() { printf "select count(*) from act_as_audit where admin_id = '%s' and event = 'end';\n" "${SEED[ADMIN_A_ID]}" | db_sql; }
before_all="$(all_ends)"
code="$(call "$ADMIN_JAR" POST /api/auth/act-as "{\"targetUserId\":\"${SEED[MEMBER_A_ID]}\"}")"
ok=0; [ "$code" = 200 ] && ok=1; check "act as rbac-member-a -> $code" "$ok"
code="$(call "$ADMIN_JAR" DELETE /api/auth/act-as)"
ok=0; [ "$code" = 200 ] && [ "$(ends "${SEED[MEMBER_A_ID]}")" = 1 ] && ok=1
check "stop acting: one end row naming rbac-member-a -> $code" "$ok"
code="$(call "$ADMIN_JAR" DELETE /api/auth/act-as)"
ok=0; [ "$code" = 200 ] && [ "$(all_ends)" = "$((before_all + 1))" ] && ok=1
check "a DELETE with no act-as cookie writes no row -> $code" "$ok"

# ---- logout names who signed out --------------------------------------------------------
echo "== Logout =="
MEMBER_JAR="$TMP/jar.member"
code="$(login "${SEED[MEMBER_B_EMAIL]}" "$MEMBER_JAR")"
[ "$code" = 200 ] || check "sign-in as rbac-member-b -> $code" 0
safe_id "${SEED[MEMBER_B_ID]}" || exit 1
code="$(call "$MEMBER_JAR" POST /api/auth/logout)"
n="$(printf "select count(*) from audit_log where action = 'auth.logout' and actor_id = '%s' and actor_email = '%s';\n" "${SEED[MEMBER_B_ID]}" "${SEED[MEMBER_B_EMAIL]}" | db_sql)"
ok=0; [ "$code" = 200 ] && [ "$n" = 1 ] && ok=1
check "auth.logout row with actor rbac-member-b and its email -> $code" "$ok" "rows: ${n:-?}"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
