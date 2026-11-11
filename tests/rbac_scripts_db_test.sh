#!/usr/bin/env bash
# =============================================================================
# Host account scripts on real Postgres: create-admin and reset-password intent
# =============================================================================
# webapp/scripts/create-admin.mjs and reset-password.mjs run as the host operator
# (`./redamon.sh create-admin`, `reset-password`, deploy.sh bootstrap_admin), so no
# route test reaches them. This runs THIS checkout's copy of each script (sent on
# stdin, so a stale webapp image cannot hide a change) inside the webapp container,
# against copies of the users, mcp_access_tokens and audit_log tables in a
# throwaway schema (`rbac_scripts_<pid>`, dropped on exit). No real row is read or
# written.
#
#   create-admin never promotes a member unless FORCE_PROMOTE=1 (exit 3, nothing
#   written); resetting an existing admin's password revokes its MCP tokens, but a
#   re-run with the unchanged password (deploy.sh init) leaves everything alone.
#   reset-password never promotes (PROMOTE_ADMIN -> exit 2), meets the 12-character
#   floor, and revokes the account's MCP tokens in the password transaction.
#   Both find an account the way sign-in does (exact email, else the one account
#   equal to it ignoring case) and write an audit row with source 'system'.
#
# Requires the stack's postgres and webapp containers:
#   docker compose up -d postgres webapp
# Usage: bash tests/rbac_scripts_db_test.sh
# =============================================================================
set -uo pipefail

cd "$(dirname "$0")/.."

PSQL=(docker compose exec -T postgres psql -U "${POSTGRES_USER:-redamon}" -d "${POSTGRES_DB:-redamon}" -qtAX -v ON_ERROR_STOP=1)

pass=0
fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; echo "        $2"; fail=$((fail + 1)); }
q()   { "${PSQL[@]}" -c "$1" 2>&1; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2' got '$3'"; fi; }
expect_has() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1" "output lacks '$2': $3" ;; esac; }

echo "== Host account scripts: DB integration =="

if ! q "select 1" >/dev/null 2>&1; then
  echo "  SKIP  postgres container not reachable (docker compose up -d postgres)"
  exit 0
fi
if ! docker compose exec -T webapp true >/dev/null 2>&1; then
  echo "  SKIP  webapp container not running: the scripts need its node, Prisma client and bcryptjs"
  exit 0
fi
if [ "$(q "select count(*) from pg_tables where schemaname = 'public'
            and tablename in ('users', 'mcp_access_tokens', 'audit_log')")" != "3" ]; then
  echo "  SKIP  users / mcp_access_tokens / audit_log absent (start a webapp to push the schema)"
  exit 0
fi

S="rbac_scripts_$$"
cleanup() { q "DROP SCHEMA IF EXISTS $S CASCADE" >/dev/null 2>&1; }
trap cleanup EXIT
q "CREATE SCHEMA $S;
   CREATE TABLE $S.users (LIKE public.users INCLUDING ALL);
   CREATE TABLE $S.mcp_access_tokens (LIKE public.mcp_access_tokens INCLUDING ALL);
   CREATE TABLE $S.audit_log (LIKE public.audit_log INCLUDING ALL);" >/dev/null

# Prisma's `schema` parameter sets the connection's search_path to the throwaway
# schema alone, so the scripts' raw lookups and model writes both land there. The
# real DATABASE_URL (it holds the password) is only ever expanded inside the container.
SCHEMA_URL_SH='u="$DATABASE_URL"
case "$u" in *\?*) u="$u&schema=$RBAC_TEST_SCHEMA" ;; *) u="$u?schema=$RBAC_TEST_SCHEMA" ;; esac
DATABASE_URL="$u" exec node --input-type=module -'

# run_script <create-admin|reset-password> [KEY=VALUE ...]: sets OUT (stdout+stderr) and RC.
run_script() {
  local script=$1 kv
  shift
  local -a envs=(-e "RBAC_TEST_SCHEMA=$S")
  for kv in "$@"; do envs+=(-e "$kv"); done
  OUT=$(docker compose exec -T "${envs[@]}" webapp sh -c "$SCHEMA_URL_SH" <"webapp/scripts/$script.mjs" 2>&1)
  RC=$?
}
bhash()  { docker compose exec -T -e "P=$1" webapp node -e \
  "process.stdout.write(require('bcryptjs').hashSync(process.env.P, 4))"; }
bcheck() { docker compose exec -T -e "P=$1" -e "H=$2" webapp node -e \
  "process.stdout.write(String(require('bcryptjs').compareSync(process.env.P, process.env.H)))"; }
hash_of()  { q "select password from $S.users where id = '$1'"; }
role_of()  { q "select role from $S.users where id = '$1'"; }
live_tokens() { q "select count(*) from $S.mcp_access_tokens where user_id = '$1' and revoked_at is null"; }
audits()   { q "select coalesce(string_agg(action || '/' || source || '/' || coalesce(actor_id, '-'), ' '
                order by action), '') from $S.audit_log where target_id = '$1'"; }
add_token() { # id user [revoked_at-sql]
  q "insert into $S.mcp_access_tokens (id, user_id, name, token_prefix, token_hash, revoked_at)
     values ('$1', '$2', '$1', 'rdmn_mcp_$1', 'hash_$1_$$', ${3:-null})" >/dev/null
}
add_user() { # id email role hash
  q "insert into $S.users (id, name, email, password, role, updated_at)
     values ('$1', 'rbac scripts $1', '$2', '$4', '$3', now())" >/dev/null
}

P="rbacscr$$"
E="rbac-scripts-$$"
PW_M='member-old-passphrase'
PW_A='admin-same-passphrase'
PW_B='admin-new-passphrase-2'
PW_R='reset-old-passphrase'
PW_NEW='brand-new-passphrase-1'

add_user "${P}m" "$E-member@e2e.local" standard "$(bhash "$PW_M")"
add_user "${P}a" "$E-admin@e2e.local" admin "$(bhash "$PW_A")"
# Created before emails were stored lowercase: still found when typed in lowercase.
add_user "${P}r" "Rbac-Scripts-$$-Reset@E2E.local" standard "$(bhash "$PW_R")"
add_user "${P}o" "$E-other@e2e.local" standard "$(bhash "$PW_M")"
# Two legacy accounts differing only in case: a third spelling names neither.
add_user "${P}t1" "$E-twin@e2e.local" admin "$(bhash "$PW_A")"
add_user "${P}t2" "RBAC-SCRIPTS-$$-TWIN@e2e.local" standard "$(bhash "$PW_M")"
for u in m a r o t1 t2; do add_token "${P}tok_$u" "${P}$u"; done
add_token "${P}tok_a2" "${P}a"
add_token "${P}tok_rold" "${P}r" "now() - interval '5 days'"
MEMBER_HASH=$(hash_of "${P}m")
ADMIN_HASH=$(hash_of "${P}a")
RESET_HASH=$(hash_of "${P}r")

# -------------------------------------------------------------------------------
echo
echo "-- create-admin: a new email creates an admin, stored lowercase --"
run_script create-admin "ADMIN_NAME=New Admin" "ADMIN_EMAIL=Rbac-Scripts-$$-New@E2E.local" "ADMIN_PASSWORD=$PW_NEW"
expect_eq "a new email exits 0" "0" "$RC"
NEW_ID=$(q "select id from $S.users where lower(email) = '$E-new@e2e.local'")
expect_eq "the account is stored with its email lowercased" \
  "$E-new@e2e.local|admin" "$(q "select email || '|' || role from $S.users where id = '$NEW_ID'")"
expect_eq "the stored hash verifies the password" "true" "$(bcheck "$PW_NEW" "$(hash_of "$NEW_ID")")"
expect_eq "the creation is audited as user.create by the system" "user.create/system/-" "$(audits "$NEW_ID")"
run_script create-admin "ADMIN_NAME=New Admin" "ADMIN_EMAIL=$E-new@e2e.local" "ADMIN_PASSWORD=$PW_NEW"
expect_eq "re-running it with the same password exits 0" "0" "$RC"
expect_eq "...and adds no second account" "1" "$(q "select count(*) from $S.users where lower(email) = '$E-new@e2e.local'")"

# -------------------------------------------------------------------------------
echo
echo "-- create-admin refuses to promote a member --"
run_script create-admin "ADMIN_NAME=Taken Over" "ADMIN_EMAIL=$E-member@e2e.local" "ADMIN_PASSWORD=$PW_NEW"
expect_eq "a member's email exits 3" "3" "$RC"
expect_has "it says how to promote on purpose" "account exists as a member; set FORCE_PROMOTE=1 to promote it" "$OUT"
expect_eq "the member is still a member" "standard" "$(role_of "${P}m")"
expect_eq "its password is untouched" "$MEMBER_HASH" "$(hash_of "${P}m")"
expect_eq "its name is untouched" "rbac scripts ${P}m" "$(q "select name from $S.users where id = '${P}m'")"
expect_eq "its MCP token is still live" "1" "$(live_tokens "${P}m")"
expect_eq "nothing is audited for a refusal" "" "$(audits "${P}m")"
run_script create-admin "ADMIN_NAME=Taken Over" "ADMIN_EMAIL=$E-member@e2e.local" "ADMIN_PASSWORD=$PW_NEW" "FORCE_PROMOTE=0"
expect_eq "FORCE_PROMOTE=0 is not consent" "3" "$RC"

echo
echo "-- FORCE_PROMOTE promotes --"
run_script create-admin "ADMIN_NAME=Promoted Member" "ADMIN_EMAIL=$E-member@e2e.local" "ADMIN_PASSWORD=$PW_NEW" "FORCE_PROMOTE=1"
expect_eq "FORCE_PROMOTE=1 exits 0" "0" "$RC"
expect_eq "the member is now an admin" "admin" "$(role_of "${P}m")"
expect_eq "its password is the new one" "true" "$(bcheck "$PW_NEW" "$(hash_of "${P}m")")"
expect_eq "its MCP tokens are revoked (minted as a member, they would act as an admin)" "0" "$(live_tokens "${P}m")"
expect_eq "the promotion and the reset are audited by the system" \
  "user.credentials_reset/system/- user.role_changed/system/-" "$(audits "${P}m")"
expect_eq "the role change records before and after" "standard>admin" \
  "$(q "select (before->>'role') || '>' || (after->>'role') from $S.audit_log
        where target_id = '${P}m' and action = 'user.role_changed'")"

# -------------------------------------------------------------------------------
echo
echo "-- create-admin with the unchanged password keeps the admin's MCP tokens --"
run_script create-admin "ADMIN_NAME=rbac scripts ${P}a" "ADMIN_EMAIL=$E-admin@e2e.local" "ADMIN_PASSWORD=$PW_A"
expect_eq "an unchanged password exits 0" "0" "$RC"
expect_eq "the stored hash is not rewritten" "$ADMIN_HASH" "$(hash_of "${P}a")"
expect_eq "both MCP tokens stay live" "2" "$(live_tokens "${P}a")"
expect_eq "nothing is audited" "" "$(audits "${P}a")"

echo
echo "-- create-admin on an existing admin with a new password revokes its MCP tokens --"
run_script create-admin "ADMIN_NAME=rbac scripts ${P}a" "ADMIN_EMAIL=$E-admin@e2e.local" "ADMIN_PASSWORD=$PW_B"
expect_eq "a new password exits 0" "0" "$RC"
expect_eq "the password is the new one" "true" "$(bcheck "$PW_B" "$(hash_of "${P}a")")"
expect_eq "every live MCP token of the admin is revoked" "0" "$(live_tokens "${P}a")"
expect_eq "it stays an admin" "admin" "$(role_of "${P}a")"
expect_eq "the reset is audited by the system" "user.credentials_reset/system/-" "$(audits "${P}a")"
expect_eq "the audit row counts the revoked tokens" "2" \
  "$(q "select after->>'revokedMcpTokens' from $S.audit_log where target_id = '${P}a'")"

# -------------------------------------------------------------------------------
echo
echo "-- reset-password refuses PROMOTE_ADMIN --"
run_script reset-password "RESET_EMAIL=rbac-scripts-$$-reset@e2e.local" "RESET_PASSWORD=$PW_NEW" "PROMOTE_ADMIN=true"
expect_eq "PROMOTE_ADMIN exits 2" "2" "$RC"
expect_has "it says promotion moved" "promotion is no longer done by reset-password" "$OUT"
expect_eq "the account keeps its role" "standard" "$(role_of "${P}r")"
expect_eq "...and its password" "$RESET_HASH" "$(hash_of "${P}r")"
expect_eq "...and its live MCP token" "1" "$(live_tokens "${P}r")"

echo
echo "-- reset-password refuses 11 characters --"
run_script reset-password "RESET_EMAIL=rbac-scripts-$$-reset@e2e.local" "RESET_PASSWORD=elevenchars"
expect_eq "an 11-character password exits 1" "1" "$RC"
expect_has "it names the floor" "at least 12 characters" "$OUT"
expect_eq "the password is untouched" "$RESET_HASH" "$(hash_of "${P}r")"

echo
echo "-- reset-password revokes MCP tokens --"
run_script reset-password "RESET_EMAIL=rbac-scripts-$$-reset@e2e.local" "RESET_PASSWORD=$PW_NEW"
expect_eq "a reset exits 0" "0" "$RC"
expect_eq "the lowercase spelling found the legacy mixed-case account" "true" "$(bcheck "$PW_NEW" "$(hash_of "${P}r")")"
expect_eq "it is not promoted" "standard" "$(role_of "${P}r")"
expect_eq "every live MCP token is revoked" "0" "$(live_tokens "${P}r")"
expect_eq "an already-revoked token keeps its original revoked_at" "t" \
  "$(q "select revoked_at < now() - interval '1 day' from $S.mcp_access_tokens where id = '${P}tok_rold'")"
expect_eq "the reset is audited by the system" "user.credentials_reset/system/-" "$(audits "${P}r")"
expect_eq "the audit row counts only the token it revoked" "1" \
  "$(q "select after->>'revokedMcpTokens' from $S.audit_log where target_id = '${P}r'")"

# -------------------------------------------------------------------------------
echo
echo "-- two accounts differing only in case: a third spelling names neither --"
TWIN_HASHES=$(q "select string_agg(password, ',' order by id) from $S.users where id in ('${P}t1', '${P}t2')")
run_script create-admin "ADMIN_NAME=Twin" "ADMIN_EMAIL=Rbac-Scripts-$$-Twin@e2e.local" "ADMIN_PASSWORD=$PW_NEW"
expect_eq "create-admin refuses an ambiguous email" "1" "$RC"
expect_has "it asks for the exact email" "differ only in case" "$OUT"
run_script reset-password "RESET_EMAIL=Rbac-Scripts-$$-Twin@e2e.local" "RESET_PASSWORD=$PW_NEW"
expect_eq "reset-password refuses an ambiguous email" "1" "$RC"
expect_eq "neither twin is changed and no third account appears" "2|$TWIN_HASHES|2" \
  "$(q "select count(*) || '|' || string_agg(u.password, ',' order by u.id) || '|' || sum((t.revoked_at is null)::int)
        from $S.users u join $S.mcp_access_tokens t on t.user_id = u.id where lower(u.email) = '$E-twin@e2e.local'")"
run_script reset-password "RESET_EMAIL=RBAC-SCRIPTS-$$-TWIN@e2e.local" "RESET_PASSWORD=$PW_NEW"
expect_eq "the exact spelling of one twin resets that one" "0|true|standard" \
  "$RC|$(bcheck "$PW_NEW" "$(hash_of "${P}t2")")|$(role_of "${P}t2")"

# -------------------------------------------------------------------------------
echo
echo "-- what no script may touch --"
expect_eq "an uninvolved account's MCP token stays live" "1" "$(live_tokens "${P}o")"
expect_eq "no audit row holds a hash or a password" "0" \
  "$(q "select count(*) from $S.audit_log where coalesce(before::text, '') || coalesce(after::text, '')
        ~ '\\\$2[aby]\\\$|$PW_NEW|$PW_B|$PW_A|$PW_M'")"
expect_eq "every audit row is the system's" "0" \
  "$(q "select count(*) from $S.audit_log where source <> 'system' or actor_id is not null")"
expect_eq "nothing reached the real tables" "0|0" \
  "$(q "select (select count(*) from public.users where email ilike 'rbac-scripts-$$-%') || '|' ||
               (select count(*) from public.audit_log where target_id like '${P}%')")"

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
