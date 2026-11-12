#!/usr/bin/env bash
#
# Live check of account status (RBAC step 2.3: ID-13, ID-21, UP-05), run against the LIVE
# stack, in whichever state the webapp's RBAC_IDENTITY_ENABLED is (read from its container).
#
# Switch on: an admin disables rbac-member-c, whose open cookie is refused at once, whose
# sign-in gets the generic answer (audited auth.login.disabled) and whose MCP token is
# revoked; the password waits on hold; a second disable changes nothing. Enabled again, the
# member signs in with the same password. Then an admin signs the member out everywhere (the
# new cookie refused), and the member signs itself out everywhere from one browser (the other
# browser's cookie refused, this one cleared). Each change has its audit row by the admin.
#
# Switch off: disable, revoke-sessions and revoke-all answer 404; an account disabled while
# the switch was on (made so by SQL here) stays out (its version was raised, its password is
# empty, the sign-in is an ordinary failure), and enable, which stays open, restores it.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local), removed with
# their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C (the fixture MCP token this script
# inserts goes with its account). Both scripts are fed to the webapp container on stdin.
# Response bodies and the fixture password are never printed. The users, mcp_access_tokens
# and audit_log tables are read (and, switch off, one account written) through psql in the
# postgres container, SQL on stdin.
#
# Needs the stack up (webapp on :3000); prints SKIP and exits 0 when it is not. As a
# *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_account_status_live.sh            (BASE_URL overrides :3000)
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

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
login() { # email jar -> http code; the body lands in $TMP/body
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
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
account() { # the member's status|set or empty password|held or no password on hold|version raised by n
  printf "select status || '|' || case when password = '' then 'empty' else 'set' end || '|' || case when password_on_hold = '' then 'none' else 'held' end || '|+' || (session_version - %s) from users where id = '%s';\n" "$SV0" "$C" | db_sql
}
audit_count() { # action -> rows of that action naming the member as target
  printf "select count(*) from audit_log where action = '%s' and target_id = '%s';\n" "$1" "$C" | db_sql
}

# Versions are compared with the one the member starts with (a re-used fixture may not be at 0).
SV0="$(printf "select session_version from users where id = '%s';\n" "$C" | db_sql)"
[[ "$SV0" =~ ^[0-9]+$ ]] || { echo "FAIL  could not read the member's session version"; exit 1; }

ADMIN="$TMP/jar.admin"
code="$(login "${SEED[ADMIN_A_EMAIL]}" "$ADMIN")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-admin-a answered $code"; exit 1; }
C1="$TMP/jar.c1"
code="$(login "${SEED[MEMBER_C_EMAIL]}" "$C1")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-member-c answered $code"; exit 1; }

if [ "$IDENTITY" = off ]; then
  echo "== Switch off: the routes that change status or sessions do not exist =="
  code="$(call "$ADMIN" POST "/api/users/$C/disable" '{}')"; ok=0; [ "$code" = 404 ] && ok=1
  check "disable -> $code (404)" "$ok"
  code="$(call "$ADMIN" POST "/api/users/$C/revoke-sessions" '{}')"; ok=0; [ "$code" = 404 ] && ok=1
  check "revoke-sessions -> $code (404)" "$ok"
  code="$(call "$C1" POST /api/auth/sessions/revoke-all '{}')"; ok=0; [ "$code" = 404 ] && ok=1
  check "revoke-all -> $code (404)" "$ok"
  ok=0; [ "$(account)" = 'active|set|none|+0' ] && ok=1; check "the member is untouched" "$ok" "got: $(account)"

  echo "== Switch off: an account disabled while the switch was on is restored by enable =="
  printf "update users set status = 'disabled', password_on_hold = password, password = '', session_version = session_version + 1 where id = '%s' and status = 'active' returning id;\n" "$C" \
    | db_sql > "$TMP/upd"
  ok=0; [ "$(cat "$TMP/upd")" = "$C" ] && ok=1; check "disabled by SQL, as the switch-on route does" "$ok"
  code="$(call "$C1" GET /api/auth/me)"; ok=0; [ "$code" = 401 ] && ok=1
  check "its open cookie is refused (the session version is compared whatever the switch) -> $code" "$ok"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$TMP/jar.c2")"
  ok=0; [ "$code" = 401 ] && [ "$(field "b.get('error')")" = 'Invalid email or password' ] && ok=1
  check "its sign-in gets the generic answer -> $code" "$ok"
  ok=0; [ "$(audit_count auth.login.disabled)" = 0 ] && ok=1
  check "no auth.login.disabled row with the switch off (the empty password is an ordinary failure)" "$ok"
  code="$(call "$ADMIN" POST "/api/users/$C/enable" '{}')"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('changed')")" = True ] && ok=1
  check "enable stays open and restores it -> $code" "$ok"
  ok=0; [ "$(account)" = 'active|set|none|+1' ] && [ "$(audit_count user.enable)" = 1 ] && ok=1
  check "active, the password back, one user.enable row" "$ok" "got: $(account)"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$TMP/jar.c3")"; ok=0; [ "$code" = 200 ] && ok=1
  check "the member signs in with the same password -> $code" "$ok"
else
  echo "== Disable =="
  printf "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, scopes) values ('rbac-acct-status-token', '%s', 'rbac-acct-status', 'rbac-tok', md5(random()::text) || md5(random()::text), '{recon:read}') returning id;\n" "$C" \
    | db_sql > "$TMP/tok"
  ok=0; [ "$(cat "$TMP/tok")" = rbac-acct-status-token ] && ok=1; check "a fixture MCP token for the member (never usable: random hash)" "$ok"
  code="$(call "$C1" GET /api/auth/me)"; ok=0; [ "$code" = 200 ] && ok=1; check "control: the member's cookie works -> $code" "$ok"

  code="$(call "$ADMIN" POST "/api/users/$C/disable" '{}')"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('changed')")" = True ] && [ "$(field "b.get('tokensRevoked')")" = 1 ] && ok=1
  check "an admin disables rbac-member-c -> $code" "$ok"
  ok=0; [ "$(field "'closed' in b['agent']['sockets'] and 'stopped' in b['agent']['runs']")" = True ] && ok=1
  check "the agent confirmed the runs stopped and the sockets closed" "$ok" "agent part: $(field "sorted(b.get('agent', {}).get('sockets', {}))")"
  ok=0; [ "$(account)" = 'disabled|empty|held|+1' ] && ok=1
  check "disabled, password emptied and on hold, session version raised" "$ok" "got: $(account)"
  n="$(printf "select count(*) from mcp_access_tokens where id = 'rbac-acct-status-token' and revoked_at is not null;\n" | db_sql)"
  ok=0; [ "$n" = 1 ] && ok=1; check "its MCP token is revoked" "$ok"
  code="$(call "$C1" GET /api/auth/me)"; ok=0; [ "$code" = 401 ] && ok=1
  check "its open cookie is refused at once -> $code" "$ok"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$TMP/jar.c2")"
  ok=0; [ "$code" = 401 ] && [ "$(field "b.get('error')")" = 'Invalid email or password' ] && ok=1
  check "its sign-in gets the generic answer -> $code" "$ok"
  ok=0; [ "$(audit_count user.disable)" = 1 ] && [ "$(audit_count auth.login.disabled)" = 1 ] && ok=1
  check "one user.disable row and one auth.login.disabled row" "$ok"
  n="$(printf "select count(*) from audit_log where action = 'user.disable' and target_id = '%s' and actor_id = '%s' and actor_email = '%s' and position('\$2' in coalesce(after::text, '')) = 0;\n" "$C" "${SEED[ADMIN_A_ID]}" "${SEED[ADMIN_A_EMAIL]}" | db_sql)"
  ok=0; [ "$n" = 1 ] && ok=1; check "user.disable names the admin and its email, and holds no hash" "$ok"
  code="$(call "$ADMIN" POST "/api/users/$C/disable" '{}')"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('changed')")" = False ] && [ "$(audit_count user.disable)" = 1 ] && [ "$(account)" = 'disabled|empty|held|+1' ] && ok=1
  check "the same disable again changes nothing -> $code" "$ok"

  echo "== Enable =="
  code="$(call "$ADMIN" POST "/api/users/$C/enable" '{}')"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('changed')")" = True ] && ok=1
  check "an admin enables it -> $code" "$ok"
  ok=0; [ "$(account)" = 'active|set|none|+1' ] && [ "$(audit_count user.enable)" = 1 ] && ok=1
  check "active, the password back, one user.enable row" "$ok" "got: $(account)"
  C3="$TMP/jar.c3"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$C3")"; ok=0; [ "$code" = 200 ] && ok=1
  check "the member signs in with the same password -> $code" "$ok"

  echo "== Sign out everywhere =="
  code="$(call "$ADMIN" POST "/api/users/$C/revoke-sessions" '{}')"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('revoked')")" = True ] && ok=1
  check "an admin signs the member out everywhere -> $code" "$ok"
  code="$(call "$C3" GET /api/auth/me)"; ok=0; [ "$code" = 401 ] && ok=1
  check "the member's new cookie is refused -> $code" "$ok"
  ok=0; [ "$(account)" = 'active|set|none|+2' ] && [ "$(audit_count user.sessions_revoked)" = 1 ] && ok=1
  check "still active, version raised again, one user.sessions_revoked row" "$ok" "got: $(account)"

  C4="$TMP/jar.c4"; C5="$TMP/jar.c5"
  code4="$(login "${SEED[MEMBER_C_EMAIL]}" "$C4")"; code5="$(login "${SEED[MEMBER_C_EMAIL]}" "$C5")"
  ok=0; [ "$code4$code5" = 200200 ] && ok=1; check "the member signs in from two browsers -> $code4 $code5" "$ok"
  code="$(call "$C4" POST /api/auth/sessions/revoke-all '{}')"
  ok=0; [ "$code" = 200 ] && grep -qiE '^set-cookie: redamon-auth=;.*max-age=0' "$TMP/headers" && ok=1
  check "sign out everywhere from one browser: done, and its cookie cleared -> $code" "$ok"
  code="$(call "$C5" GET /api/auth/me)"; ok=0; [ "$code" = 401 ] && ok=1
  check "the other browser's cookie is refused -> $code" "$ok"
  n="$(printf "select count(*) from audit_log where action = 'user.sessions_revoked' and target_id = '%s' and actor_id = '%s';\n" "$C" "$C" | db_sql)"
  ok=0; [ "$n" = 1 ] && [ "$(account)" = 'active|set|none|+3' ] && ok=1
  check "a user.sessions_revoked row by the member itself; the account stays active" "$ok"
  code="$(login "${SEED[MEMBER_C_EMAIL]}" "$TMP/jar.c6")"; ok=0; [ "$code" = 200 ] && ok=1
  check "the member can sign in again -> $code" "$ok"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
