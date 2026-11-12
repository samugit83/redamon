#!/usr/bin/env bash
#
# Live check of must-change passwords (RBAC step 2.8: ID-17, ID-20), run against the LIVE
# stack, in whichever state the webapp's RBAC_IDENTITY_ENABLED is (read from its container).
#
# Switch on: an admin sets rbac-member-c a temporary password ("require a change", the
# default): the account is flagged and its version raised, so its open cookie is refused.
# Signed in with the temporary password, the member reaches only the change page: other pages
# go to /account?changePassword=1, other APIs answer 403 must_change_password, while /account,
# /api/auth/me and the password policy answer. Its own change clears the flag and re-issues
# the cookie, which then reaches everything. An admin who unticks the choice sets a password
# that is not temporary. Each reset has its audit row. Since step 2.10 an admin's reset of an
# account that has signed in before carries a reason, and every reset, unticked or not, raises
# the session version (a reset ends every session of the account).
#
# Switch off: the same reset flags nothing and raises no version, the member signs in into the
# whole app, and the password policy route answers 404.
#
# Not here (unit-tested, src/app/api/auth/login/route.mustChange.test.ts): Root's short-password
# prompt, which would change the real instance settings row; this script writes fixtures only.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local), removed with
# their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C. Both scripts are fed to the webapp
# container on stdin. Response bodies and every password are never printed. The users and
# audit_log tables are read through psql in the postgres container, SQL on stdin.
#
# Needs the stack up (webapp on :3000); prints SKIP and exits 0 when it is not. As a
# *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_must_change_live.sh            (BASE_URL overrides :3000)
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

env_line="$(cd "$ROOT" && docker compose exec -T webapp sh -c 'printf "%s" "${RBAC_IDENTITY_ENABLED:-}"' 2>/dev/null)"
case "$(printf '%s' "$env_line" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
  true|1|yes) IDENTITY=on ;;
  *) IDENTITY=off ;;
esac
echo "== Identity switch: $IDENTITY =="

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
# Passwords this run sets: long, mixed, never on the deny list, never printed.
TEMP_PW="Temp-orchid-$RANDOM$RANDOM-paddle"
TEMP2_PW="Second-orchid-$RANDOM$RANDOM-paddle"
OWN_PW="Own-orchid-$RANDOM$RANDOM-paddle"

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
login() { # email password jar -> http code; the body lands in $TMP/body
  python3 -c 'import json,sys; print(json.dumps({"email": sys.argv[1], "password": sys.argv[2]}))' "$1" "$2" > "$TMP/login.json"
  curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -c "$3" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
call() { # jar method path [json-body] -> http code; body in $TMP/body, headers in $TMP/headers.
  # The jar is also written back, so a cookie the answer re-issues is the one used next.
  local jar="$1" method="$2" path="$3"
  local args=(-s -m 70 -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -X "$method" -b "$jar" -c "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}
field() { # python expression on the JSON body `b` -> printed value (never the whole body)
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$TMP/body" "$1" 2>/dev/null || true
}
json_pw() { # key value [key value ...] -> a JSON object (values may hold any character)
  python3 -c 'import json,sys; a=sys.argv[1:]; print(json.dumps({a[i]: (a[i+1] == "true" if a[i+1] in ("true", "false") else a[i+1]) for i in range(0, len(a), 2)}))' "$@"
}
account() { # flag|version raised by n
  printf "select must_change_password::text || '|+' || (session_version - %s) from users where id = '%s';\n" "$SV0" "$C" | db_sql
}
reset_rows() { # rows of user.credentials_reset by the admin on the member, with mustChangePassword true
  printf "select count(*) from audit_log where action = 'user.credentials_reset' and target_id = '%s' and actor_id = '%s' and after->>'mustChangePassword' = 'true';\n" "$C" "${SEED[ADMIN_A_ID]}" | db_sql
}

SV0="$(printf "select session_version from users where id = '%s';\n" "$C" | db_sql)"
[[ "$SV0" =~ ^[0-9]+$ ]] || { echo "FAIL  could not read the member's session version"; exit 1; }

ADMIN="$TMP/jar.admin"
code="$(login "${SEED[ADMIN_A_EMAIL]}" "${SEED[RBAC_PASSWORD]}" "$ADMIN")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-admin-a answered $code"; exit 1; }
C_OLD="$TMP/jar.c_old"
code="$(login "${SEED[MEMBER_C_EMAIL]}" "${SEED[RBAC_PASSWORD]}" "$C_OLD")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-member-c answered $code"; exit 1; }

if [ "$IDENTITY" = off ]; then
  echo "== Switch off: no must-change =="
  code="$(call "$ADMIN" PUT "/api/users/$C/password" "$(json_pw newPassword "$TEMP_PW" requirePasswordChange true)")"
  ok=0; [ "$code" = 200 ] && ok=1; check "an admin sets the member's password -> $code" "$ok"
  ok=0; [ "$(account)" = 'false|+0' ] && ok=1; check "no flag, no version raised (Phase 1)" "$ok" "got: $(account)"
  C1="$TMP/jar.c1"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$TEMP_PW" "$C1")"
  ok=0; [ "$code" = 200 ] && [ "$(field "'mustChangePassword' in b")" = False ] && ok=1
  check "the member signs in with it, nothing says it must change -> $code" "$ok"
  code="$(call "$C1" GET /api/projects)"; ok=0; [ "$code" = 200 ] && ok=1
  check "and reaches the API -> $code" "$ok"
  code="$(call "$C1" GET /api/auth/password-policy)"; ok=0; [ "$code" = 404 ] && ok=1
  check "the password policy route does not exist -> $code" "$ok"
else
  probe="$(curl -s -m 30 -o /dev/null -w '%{http_code}' -b "$C_OLD" "$BASE/api/auth/password-policy")"
  if [ "$probe" = 404 ]; then
    echo "SKIP: this webapp image predates step 2.8 (no /api/auth/password-policy with the identity switch on)"
    exit 0
  fi
  echo "== A temporary password =="
  code="$(call "$C_OLD" GET /api/auth/me)"; ok=0; [ "$code" = 200 ] && ok=1; check "control: the member's cookie works -> $code" "$ok"
  code="$(call "$ADMIN" PUT "/api/users/$C/password" "$(json_pw newPassword "$TEMP_PW" reason "RBAC live check: temporary password")")"
  ok=0; [ "$code" = 200 ] && ok=1; check "an admin sets a temporary password (require a change: the default) -> $code" "$ok"
  ok=0; [ "$(account)" = 'true|+1' ] && ok=1; check "flagged, session version raised" "$ok" "got: $(account)"
  ok=0; [ "$(reset_rows)" = 1 ] && ok=1; check "one user.credentials_reset row by the admin says mustChangePassword" "$ok"
  code="$(call "$C_OLD" GET /api/auth/me)"; ok=0; [ "$code" = 401 ] && ok=1
  check "the member's open cookie is refused at once -> $code" "$ok"

  echo "== Held on the change page =="
  C1="$TMP/jar.c1"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$TEMP_PW" "$C1")"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('mustChangePassword')")" = True ] && ok=1
  check "the member signs in with the temporary password; the answer says it must change -> $code" "$ok"
  code="$(call "$C1" GET /api/projects)"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('code')")" = must_change_password ] && ok=1
  check "another API answers 403 must_change_password -> $code" "$ok"
  code="$(call "$C1" GET /graph)"
  ok=0; [ "$code" = 307 ] && grep -qiE '^location: .*/account\?changePassword=1' "$TMP/headers" && ok=1
  check "another page goes to /account?changePassword=1 -> $code" "$ok"
  code="$(call "$C1" GET /account)"; ok=0; [ "$code" = 200 ] && ok=1
  check "the change page loads -> $code" "$ok"
  code="$(call "$C1" GET /api/auth/me)"; ok=0; [ "$code" = 200 ] && ok=1
  check "/api/auth/me answers -> $code" "$ok"
  code="$(call "$C1" GET /api/auth/password-policy)"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('rules')")" = True ] && ok=1
  check "the password policy answers, rules on -> $code" "$ok"
  code="$(call "$C1" PUT "/api/users/$C/password" "$(json_pw currentPassword "$TEMP_PW" newPassword "password1234")")"
  ok=0; [ "$code" = 400 ] && [ "$(field "b.get('code')")" = password_common ] && ok=1
  check "a common password is refused by the policy -> $code" "$ok"

  echo "== The member's own change =="
  code="$(call "$C1" PUT "/api/users/$C/password" "$(json_pw currentPassword "$TEMP_PW" newPassword "$OWN_PW")")"
  ok=0; [ "$code" = 200 ] && grep -qiE '^set-cookie: redamon-auth=[^;]+' "$TMP/headers" && ok=1
  check "its own change succeeds and re-issues the login cookie -> $code" "$ok"
  ok=0; [ "$(account)" = 'false|+1' ] && ok=1; check "the flag is cleared, no further version raised" "$ok" "got: $(account)"
  code="$(call "$C1" GET /api/projects)"; ok=0; [ "$code" = 200 ] && ok=1
  check "the re-issued cookie reaches the API -> $code" "$ok"
  code="$(call "$C1" GET /graph)"; ok=0; [ "$code" = 200 ] && ok=1
  check "and the pages -> $code" "$ok"

  echo "== Unticked: not temporary =="
  code="$(call "$ADMIN" PUT "/api/users/$C/password" "$(json_pw newPassword "$TEMP2_PW" requirePasswordChange false reason "RBAC live check: unticked")")"
  ok=0; [ "$code" = 200 ] && [ "$(account)" = 'false|+2' ] && ok=1
  check "an admin sets a password without the choice: no flag; the version rises (a reset) -> $code" "$ok" "got: $(account)"
  C2="$TMP/jar.c2"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$TEMP2_PW" "$C2")"
  ok=0; [ "$code" = 200 ] && [ "$(field "'mustChangePassword' in b")" = False ] && ok=1
  check "the member signs in into the whole app -> $code" "$ok"
  code="$(call "$C2" GET /api/projects)"; ok=0; [ "$code" = 200 ] && ok=1
  check "and reaches the API -> $code" "$ok"
  ok=0; [ "$(reset_rows)" = 1 ] && ok=1; check "only the first reset says mustChangePassword" "$ok"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
