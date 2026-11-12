#!/usr/bin/env bash
# =============================================================================
# Host account scripts on real Postgres: create-admin, reset-password, set-root,
# check-root and check-admin
# =============================================================================
# The webapp/scripts/*.mjs host scripts run as the host operator (`./redamon.sh
# create-admin`, `reset-password`, `set-root`, `update`, deploy.sh bootstrap_admin),
# so no route test reaches them. This runs THIS checkout's copy of each script (sent
# with the scripts it imports, so a stale webapp image cannot hide a change) inside the webapp
# container, against a throwaway schema (`rbac_scripts_<pid>`, dropped on exit) that
# the image's Prisma CLI creates from THIS checkout's schema.prisma, so the test does
# not depend on what the live database was last pushed with. No real row is read or
# written.
#
#   create-admin never promotes a member unless FORCE_PROMOTE=1 (exit 3, nothing
#   written); resetting an existing admin's password revokes its MCP tokens, but a
#   re-run with the unchanged password (deploy.sh init) leaves everything alone.
#   reset-password never promotes (PROMOTE_ADMIN -> exit 2), meets the 12-character
#   floor, and revokes the account's MCP tokens in the password transaction.
#   Both find an account the way sign-in does (exact email, else the one account
#   equal to it ignoring case) and write an audit row with source 'system'.
#   A host reset ends every session of the account (session version + 1) and makes a
#   disabled or invited account usable again. A new admin is the confirmed Root when
#   the instance has none; set-root moves Root (both accounts signed out, the new
#   Root's MCP tokens revoked) or confirms the Root chosen at boot; check-root prints
#   who is Root and who could be. On an instance whose settings row no boot has filled
#   yet, the script that records Root creates the row with the tunnel and capture values
#   in force in the user rows (what the boot's backfill copies), never schema defaults.
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

S="rbac_scripts_$$"
cleanup() { q "DROP SCHEMA IF EXISTS $S CASCADE" >/dev/null 2>&1; }
trap cleanup EXIT

# Prisma's `schema` parameter sets the connection's search_path to the throwaway
# schema alone, so the scripts' raw lookups and model writes both land there. The
# real DATABASE_URL (it holds the password) is only ever expanded inside the container.
SCHEMA_URL='u="$DATABASE_URL"
case "$u" in *\?*) u="$u&schema=$RBAC_TEST_SCHEMA" ;; *) u="$u?schema=$RBAC_TEST_SCHEMA" ;; esac'

PUSH_OUT=$(docker compose exec -T -e "RBAC_TEST_SCHEMA=$S" webapp sh -c "$SCHEMA_URL"'
f=$(mktemp); cat >"$f"
DATABASE_URL="$u" CHECKPOINT_DISABLE=1 ./node_modules/.bin/prisma db push --schema "$f" --skip-generate
rc=$?; rm -f "$f"; exit $rc' <webapp/prisma/schema.prisma 2>&1)
if [ $? -ne 0 ] || [ "$(q "select count(*) from pg_tables where schemaname = '$S'
                            and tablename in ('users', 'mcp_access_tokens', 'audit_log',
                                              'instance_settings', 'user_invites')")" != "5" ]; then
  echo "  FAIL  could not create the throwaway schema from webapp/prisma/schema.prisma"
  echo "$PUSH_OUT" | tail -5 | sed 's/^/        /'
  exit 1
fi

# run_script <script> [KEY=VALUE ... [-- ARG ...]]: runs webapp/scripts/<script>.mjs,
# environment first, then its command-line arguments; sets OUT (stdout+stderr) and RC.
# Every checkout script travels with it (a script imports its siblings, e.g. the instance
# settings backfill) into a folder of its own under the image's /app/scripts, where their
# bare imports resolve to the image's node_modules; the folder is removed after the run.
run_script() {
  local script=$1 kv
  shift
  local -a envs=(-e "RBAC_TEST_SCHEMA=$S")
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=(-e "$1"); shift; done
  [ "${1:-}" = "--" ] && shift
  OUT=$( (cd webapp/scripts && tar -cf - ./*.mjs) | docker compose exec -T "${envs[@]}" webapp sh -c "$SCHEMA_URL"'
d=$(mktemp -d /app/scripts/.rbac-scripts-test.XXXXXX) || exit 97
tar -xf - -C "$d" || { rm -rf "$d"; exit 97; }
DATABASE_URL="$u" node "$d/$0.mjs" "$@"; rc=$?
rm -rf "$d"; exit $rc' "$script" "$@" 2>&1)
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
add_user() { # id email role hash [status] [held hash]
  q "insert into $S.users (id, name, email, password, role, status, password_on_hold, updated_at)
     values ('$1', 'rbac scripts $1', '$2', '$4', '$3', '${5:-active}', '${6:-}', now())" >/dev/null
}
sv_of()     { q "select session_version from $S.users where id = '$1'"; }
status_of() { q "select status || '|' || (password_on_hold = '') || '|' || must_change_password from $S.users where id = '$1'"; }
# Root as the singleton stores it: <user id or ->|<confirmed true/false>|<rule or ->.
root_of()   { q "select coalesce(root_user_id, '-') || '|' || (root_confirmed_at is not null) || '|' ||
                 coalesce(root_assigned_by, '-') from $S.instance_settings where id = 'instance'"; }
id_of()     { q "select id from $S.users where email = '$1'"; }

P="rbacscr$$"
E="rbac-scripts-$$"

# -------------------------------------------------------------------------------
echo
echo "-- an empty database: check-root, then create-admin makes a confirmed Root --"
run_script check-root
expect_eq "check-root on an empty database exits 0" "0" "$RC"
expect_eq "...and prints no Root and no candidate" '{"root":null,"candidates":[]}' "$OUT"
run_script create-admin "ADMIN_NAME=First Admin" "ADMIN_EMAIL=$E-first@e2e.local" "ADMIN_PASSWORD=first-admin-passphrase"
expect_eq "create-admin on an empty DB exits 0" "0" "$RC"
FIRST_ID=$(id_of "$E-first@e2e.local")
expect_eq "create-admin on an empty DB makes a confirmed Root" "$FIRST_ID|true|install" "$(root_of)"
expect_has "it says the account is Root" "Root" "$OUT"
expect_eq "the Root assignment and the creation are audited by the system" \
  "root.set_by_host/system/- user.create/system/-" "$(audits "$FIRST_ID")"
expect_eq "the assignment names the rule" "install" \
  "$(q "select after->>'rule' from $S.audit_log where target_id = '$FIRST_ID' and action = 'root.set_by_host'")"
expect_eq "a new account starts at session version 0" "0" "$(sv_of "$FIRST_ID")"
run_script check-root
expect_eq "check-root names the Root and the one candidate" \
  "{\"root\":{\"email\":\"$E-first@e2e.local\",\"confirmed\":true,\"rule\":\"install\"},\"candidates\":[\"$E-first@e2e.local\"]}" "$OUT"
run_script create-admin "ADMIN_NAME=Second Admin" "ADMIN_EMAIL=$E-second@e2e.local" "ADMIN_PASSWORD=second-admin-passphrase"
SECOND_ID=$(id_of "$E-second@e2e.local")
expect_eq "create-admin with a Root present makes a plain admin" "0|admin|$FIRST_ID|true|install" \
  "$RC|$(role_of "$SECOND_ID")|$(root_of)"
expect_eq "...audited as a creation only" "user.create/system/-" "$(audits "$SECOND_ID")"
run_script check-admin
expect_eq "check-admin counts the Root among the admins with a password" "2" "$OUT"

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
expect_eq "its sessions are untouched" "0" "$(sv_of "${P}m")"
run_script create-admin "ADMIN_NAME=Taken Over" "ADMIN_EMAIL=$E-member@e2e.local" "ADMIN_PASSWORD=$PW_NEW" "FORCE_PROMOTE=0"
expect_eq "FORCE_PROMOTE=0 is not consent" "3" "$RC"

echo
echo "-- FORCE_PROMOTE promotes --"
run_script create-admin "ADMIN_NAME=Promoted Member" "ADMIN_EMAIL=$E-member@e2e.local" "ADMIN_PASSWORD=$PW_NEW" "FORCE_PROMOTE=1"
expect_eq "FORCE_PROMOTE=1 exits 0" "0" "$RC"
expect_eq "the member is now an admin" "admin" "$(role_of "${P}m")"
expect_eq "its password is the new one" "true" "$(bcheck "$PW_NEW" "$(hash_of "${P}m")")"
expect_eq "its MCP tokens are revoked (minted as a member, they would act as an admin)" "0" "$(live_tokens "${P}m")"
expect_eq "its sessions end once (session version + 1)" "1" "$(sv_of "${P}m")"
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
expect_eq "its sessions stay valid" "0" "$(sv_of "${P}a")"
expect_eq "nothing is audited" "" "$(audits "${P}a")"

echo
echo "-- create-admin on an existing admin with a new password revokes its MCP tokens --"
run_script create-admin "ADMIN_NAME=rbac scripts ${P}a" "ADMIN_EMAIL=$E-admin@e2e.local" "ADMIN_PASSWORD=$PW_B"
expect_eq "a new password exits 0" "0" "$RC"
expect_eq "the password is the new one" "true" "$(bcheck "$PW_B" "$(hash_of "${P}a")")"
expect_eq "every live MCP token of the admin is revoked" "0" "$(live_tokens "${P}a")"
expect_eq "an existing admin's reset also bumps its session version" "1" "$(sv_of "${P}a")"
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
expect_eq "...and its sessions" "0" "$(sv_of "${P}r")"

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
expect_eq "reset-password bumps the session version" "1" "$(sv_of "${P}r")"
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
echo "-- set-root moves Root and bumps both --"
PW_ROOT='root-move-passphrase'
add_user "${P}ra" "$E-root-a@e2e.local" admin "$(bhash "$PW_ROOT")"
add_user "${P}rm" "$E-root-member@e2e.local" standard "$(bhash "$PW_ROOT")"
add_user "${P}rn" "$E-root-managed@e2e.local" standard ""
add_token "${P}tok_ra" "${P}ra"
add_token "${P}tok_rm" "${P}rm"
add_token "${P}tok_first" "$FIRST_ID"
q "update $S.instance_settings set pending_root_transfer_to = '$SECOND_ID',
     pending_root_transfer_expires = now() + interval '1 day' where id = 'instance'" >/dev/null
RA_HASH=$(hash_of "${P}ra")
run_script set-root "ROOT_EMAIL=$E-root-a@e2e.local"
expect_eq "set-root of an admin exits 0" "0" "$RC"
expect_eq "set-root moves Root to it, confirmed, set by the host" "${P}ra|true|host" "$(root_of)"
expect_eq "its sessions end (session version + 1)" "1" "$(sv_of "${P}ra")"
expect_eq "the previous Root's sessions end too" "1" "$(sv_of "$FIRST_ID")"
expect_eq "the previous Root stays an admin" "admin" "$(role_of "$FIRST_ID")"
expect_eq "the new Root's MCP tokens are revoked" "0" "$(live_tokens "${P}ra")"
expect_eq "the previous Root's MCP tokens are not" "1" "$(live_tokens "$FIRST_ID")"
expect_eq "its password is untouched" "$RA_HASH" "$(hash_of "${P}ra")"
expect_eq "a pending Root transfer is cancelled" "-|-" \
  "$(q "select coalesce(pending_root_transfer_to, '-') || '|' || coalesce(pending_root_transfer_expires::text, '-')
        from $S.instance_settings")"
expect_eq "the move is audited by the system" "root.set_by_host/system/-" "$(audits "${P}ra")"
expect_eq "the audit row names both Roots, the rule and the revoked tokens" "$FIRST_ID|${P}ra|host|1" \
  "$(q "select (before->>'rootUserId') || '|' || (after->>'rootUserId') || '|' || (after->>'rule') || '|' ||
               (after->>'revokedMcpTokens') from $S.audit_log where target_id = '${P}ra' and action = 'root.set_by_host'")"
expect_has "it says who is Root now" "$E-root-a@e2e.local" "$OUT"

echo
echo "-- set-root of a member makes it an admin first --"
run_script set-root -- "$E-root-member@e2e.local"
expect_eq "set-root <email> (the argument form) exits 0" "0" "$RC"
expect_eq "the member is an admin and Root" "admin|${P}rm|true|host" "$(role_of "${P}rm")|$(root_of)"
expect_eq "its sessions end and its MCP tokens are revoked" "1|0" "$(sv_of "${P}rm")|$(live_tokens "${P}rm")"
expect_eq "the Root it replaced is signed out" "2" "$(sv_of "${P}ra")"
expect_eq "the promotion and the move are audited" "root.set_by_host/system/- user.role_changed/system/-" "$(audits "${P}rm")"

echo
echo "-- set-root refuses a passwordless account and an unknown email --"
run_script set-root "ROOT_EMAIL=$E-root-managed@e2e.local"
expect_eq "set-root refuses a passwordless account" "1" "$RC"
expect_has "it says why" "no password" "$OUT"
expect_eq "Root and the account are unchanged" "${P}rm|true|host|standard|0" \
  "$(root_of)|$(role_of "${P}rn")|$(sv_of "${P}rn")"
run_script set-root "ROOT_EMAIL=$E-nobody@e2e.local"
expect_eq "an unknown email exits 1" "1" "$RC"
expect_has "and is named" "No user found" "$OUT"
run_script set-root
expect_eq "no email at all exits 1" "1" "$RC"
expect_eq "Root is unchanged" "${P}rm|true|host" "$(root_of)"
expect_eq "nothing is audited for a refusal" "" "$(audits "${P}rn")"

echo
echo "-- set-root of the Root chosen at boot confirms it, nothing else --"
q "update $S.instance_settings set root_user_id = '${P}ra', root_confirmed_at = null, root_assigned_by = 'automatic'" >/dev/null
add_token "${P}tok_ra2" "${P}ra"
SV_BEFORE="$(sv_of "${P}ra")|$(sv_of "${P}rm")"
run_script set-root "ROOT_EMAIL=$E-root-a@e2e.local"
expect_eq "confirming exits 0" "0" "$RC"
expect_eq "Root is confirmed and keeps its rule" "${P}ra|true|automatic" "$(root_of)"
expect_eq "nobody is signed out" "$SV_BEFORE" "$(sv_of "${P}ra")|$(sv_of "${P}rm")"
expect_eq "its MCP token stays live" "1" "$(live_tokens "${P}ra")"
expect_eq "the confirmation is audited by the system" "root.confirmed_by_host/system/- root.set_by_host/system/-" \
  "$(audits "${P}ra")"
run_script set-root "ROOT_EMAIL=$E-root-a@e2e.local"
expect_eq "the confirmed Root again exits 0" "0" "$RC"
expect_has "and says nothing changed" "nothing changed" "$OUT"
expect_eq "no further audit row, nobody signed out" "root.confirmed_by_host/system/- root.set_by_host/system/-|$SV_BEFORE" \
  "$(audits "${P}ra")|$(sv_of "${P}ra")|$(sv_of "${P}rm")"

echo
echo "-- check-root --lines, the form redamon.sh reads --"
run_script check-root -- --lines
expect_eq "--lines exits 0" "0" "$RC"
expect_eq "one root line, then every admin with a password, oldest first" \
  "$(q "select string_agg(l, E'\n' order by o) from (
          select 0 as o, E'root\t$E-root-a@e2e.local\tconfirmed\tautomatic' as l
          union all
          select row_number() over (order by created_at, id), E'candidate\t' || email
            from $S.users where role = 'admin' and password <> '') x")" "$OUT"

# -------------------------------------------------------------------------------
echo
echo "-- host resets make a disabled or invited account usable --"
PW_HELD='held-old-passphrase'
add_user "${P}d" "$E-disabled@e2e.local" admin "" disabled "$(bhash "$PW_HELD")"
add_user "${P}i" "$E-invited@e2e.local" standard "" invited
add_user "${P}d2" "$E-disabled-two@e2e.local" admin "" disabled "$(bhash "$PW_HELD")"
q "update $S.users set must_change_password = true where id = '${P}d'" >/dev/null
q "insert into $S.user_invites (id, user_id, kind, token_hash, expires_at, created_by_id, used_at) values
     ('${P}inv_open', '${P}i', 'invite', 'h_open_$$', now() + interval '1 day', '$FIRST_ID', null),
     ('${P}inv_used', '${P}i', 'reset', 'h_used_$$', now() + interval '1 day', '$FIRST_ID', now())" >/dev/null
run_script reset-password "RESET_EMAIL=$E-disabled@e2e.local" "RESET_PASSWORD=$PW_NEW"
expect_eq "reset-password of a disabled account exits 0" "0" "$RC"
expect_eq "reset-password of a disabled account sets it active and clears the held hash" \
  "active|true|false" "$(status_of "${P}d")"
expect_eq "the new password verifies, the role is kept, its sessions end" "true|admin|1" \
  "$(bcheck "$PW_NEW" "$(hash_of "${P}d")")|$(role_of "${P}d")|$(sv_of "${P}d")"
expect_eq "the re-enabling and the reset are audited" "user.credentials_reset/system/- user.enabled_by_host/system/-" \
  "$(audits "${P}d")"
expect_eq "the enabling row records the status change" "disabled>active" \
  "$(q "select (before->>'status') || '>' || (after->>'status') from $S.audit_log
        where target_id = '${P}d' and action = 'user.enabled_by_host'")"
run_script reset-password "RESET_EMAIL=$E-invited@e2e.local" "RESET_PASSWORD=$PW_NEW"
expect_eq "reset-password of an invited account sets it active" "0|active|true|false" "$RC|$(status_of "${P}i")"
expect_eq "its open link is cancelled, the used one left alone" "inv_open:true inv_used:false" \
  "$(q "select string_agg(replace(id, '${P}', '') || ':' || (cancelled_at is not null), ' ' order by id)
        from $S.user_invites where user_id = '${P}i'")"
expect_eq "the reset row counts the cancelled link" "1" \
  "$(q "select after->>'cancelledLinks' from $S.audit_log where target_id = '${P}i' and action = 'user.credentials_reset'")"
run_script create-admin "ADMIN_NAME=Disabled Two" "ADMIN_EMAIL=$E-disabled-two@e2e.local" "ADMIN_PASSWORD=$PW_NEW"
expect_eq "create-admin of a disabled admin resets it (it has no password to compare)" \
  "0|active|true|false|1" "$RC|$(status_of "${P}d2")|$(sv_of "${P}d2")"
expect_eq "...audited as an enabling and a reset" "user.credentials_reset/system/- user.enabled_by_host/system/-" \
  "$(audits "${P}d2")"

# -------------------------------------------------------------------------------
echo
echo "-- a Root id that names no account reads as no Root --"
q "update $S.instance_settings set root_user_id = 'rbac-gone-account', root_confirmed_at = now(), root_assigned_by = 'host'" >/dev/null
run_script check-root
expect_has "check-root prints no Root" '{"root":null,' "$OUT"
run_script create-admin "ADMIN_NAME=After Gone" "ADMIN_EMAIL=$E-after-gone@e2e.local" "ADMIN_PASSWORD=$PW_NEW"
expect_eq "a new admin then becomes the confirmed Root" "0|$(id_of "$E-after-gone@e2e.local")|true|install" "$RC|$(root_of)"

echo
echo "-- a database without instance_settings: no Root, nothing else breaks --"
q "alter table $S.instance_settings rename to instance_settings_hidden" >/dev/null
run_script check-root
expect_eq "check-root exits 0" "0" "$RC"
expect_has "...and prints no Root" '{"root":null,' "$OUT"
run_script create-admin "ADMIN_NAME=No Table" "ADMIN_EMAIL=$E-no-table@e2e.local" "ADMIN_PASSWORD=$PW_NEW"
expect_eq "create-admin still creates the admin" "0|admin" "$RC|$(role_of "$(id_of "$E-no-table@e2e.local")")"
expect_has "and says no Root was recorded" "no instance_settings table" "$OUT"
SV_BEFORE=$(sv_of "${P}ra")
run_script set-root "ROOT_EMAIL=$E-root-a@e2e.local"
expect_eq "set-root refuses, changing nothing" "1|$SV_BEFORE" "$RC|$(sv_of "${P}ra")"
q "alter table $S.instance_settings_hidden rename to instance_settings" >/dev/null

echo
echo "-- a host command before any boot filled the instance settings: the values in force, not defaults --"
# An upgrade's first `update`, or a boot whose instance settings backfill failed, leaves no
# row. With the identity switch on the readers take any row as the truth, so a row of
# schema defaults would read an empty tunnel and the default capture policy.
q "delete from $S.instance_settings" >/dev/null
TUNNEL_TOKEN="fake-ngrok-token-$$"
add_user "${P}tu" "$E-tunnel@e2e.local" standard "$(bhash "$PW_NEW")"
add_user "${P}ca" "$E-capture@e2e.local" admin "$(bhash "$PW_NEW")"
q "insert into $S.user_settings (id, user_id, updated_at, tunnels_enabled, ngrok_authtoken)
   values ('${P}s-tu', '${P}tu', now(), true, '$TUNNEL_TOKEN')" >/dev/null
q "insert into $S.user_settings (id, user_id, updated_at, capture_proxy_store_bodies, capture_proxy_port,
     capture_proxy_body_rules, capture_egress_block_private, sca_intel_ignore_suffixes)
   values ('${P}s-ca', '${P}ca', now() + interval '1 hour', false, 9191,
     '{\"text/html\": \"skip\"}', false, 'example.test')" >/dev/null
# <tunnels on>|<token>|<tunnel source>|<store bodies>|<port>|<body rules>|<block private>|<suffixes>|<capture source>|<admin-written>
settings_of() { q "select tunnels_enabled || '|' || ngrok_authtoken || '|' || coalesce(tunnel_source_user_id, '-') || '|' ||
                 capture_proxy_store_bodies || '|' || capture_proxy_port || '|' || capture_proxy_body_rules::text || '|' ||
                 capture_egress_block_private || '|' || sca_intel_ignore_suffixes || '|' ||
                 coalesce(capture_source_user_id, '-') || '|' || (updated_by_id is not null)
               from $S.instance_settings where id = 'instance'"; }
IN_FORCE="true|$TUNNEL_TOKEN|${P}tu|false|9191|{\"text/html\": \"skip\"}|false|example.test|${P}ca|false"
# Every capture, egress and SCA column of the admin row saved last against the instance row.
capture_drift() { q "select count(*) || '|' || count(*) filter (where to_jsonb(i) -> e.key is distinct from e.value)
                      from $S.instance_settings i, $S.user_settings c, jsonb_each(to_jsonb(c)) e
                      where c.user_id = '${P}ca' and (e.key like 'capture\\_%' or e.key = 'sca_intel_ignore_suffixes')"; }
markers() { q "select count(*) from $S.audit_log where action = 'system.rbac_instance_settings_backfill'"; }

run_script create-admin "ADMIN_NAME=Before Boot" "ADMIN_EMAIL=$E-before-boot@e2e.local" "ADMIN_PASSWORD=$PW_NEW"
expect_eq "create-admin with no settings row makes the new admin the confirmed Root" \
  "0|$(id_of "$E-before-boot@e2e.local")|true|install" "$RC|$(root_of)"
expect_eq "...in a row holding the tunnel and capture values in force, with their sources" "$IN_FORCE" "$(settings_of)"
expect_eq "...every capture, egress and SCA value of the admin row saved last" "24|0" "$(capture_drift)"
expect_eq "...and no backfill marker: the next boot still fills the row and records it" "0" "$(markers)"

q "delete from $S.instance_settings" >/dev/null
run_script set-root "ROOT_EMAIL=$E-capture@e2e.local"
expect_eq "set-root with no settings row moves Root" "0|${P}ca|true|host" "$RC|$(root_of)"
expect_eq "...in a row holding the tunnel and capture values in force, with their sources" "$IN_FORCE" "$(settings_of)"
expect_eq "...every capture, egress and SCA value of the admin row saved last" "24|0" "$(capture_drift)"
expect_eq "...and no backfill marker" "0" "$(markers)"

q "update $S.instance_settings set ngrok_authtoken = 'admin-set-$$', capture_proxy_port = 9292,
     updated_by_id = '${P}ca'" >/dev/null
run_script set-root "ROOT_EMAIL=$E-before-boot@e2e.local"
expect_eq "set-root with the row present moves Root" "0|$(id_of "$E-before-boot@e2e.local")|true|host" "$RC|$(root_of)"
expect_eq "...and keeps the row's tunnel and capture values" "admin-set-$$|9292|true" \
  "$(q "select ngrok_authtoken || '|' || capture_proxy_port || '|' || (updated_by_id is not null)
        from $S.instance_settings where id = 'instance'")"

echo
echo "-- two create-admin at once on an instance without Root: one Root --"
q "delete from $S.instance_settings" >/dev/null
for n in 1 2; do
  run_script create-admin "ADMIN_NAME=Race $n" "ADMIN_EMAIL=$E-race-$n@e2e.local" "ADMIN_PASSWORD=$PW_NEW" &
done
wait
RACE="'$E-race-1@e2e.local', '$E-race-2@e2e.local'"
expect_eq "both admins are created" "2" \
  "$(q "select count(*) from $S.users where email in ($RACE) and role = 'admin'")"
expect_eq "exactly one of them is the confirmed Root" "1|true|install" \
  "$(q "select count(*) || '|' || bool_and(s.root_confirmed_at is not null) || '|' || min(s.root_assigned_by)
        from $S.instance_settings s join $S.users u on u.id = s.root_user_id where u.email in ($RACE)")"
expect_eq "one Root assignment is audited" "1" \
  "$(q "select count(*) from $S.audit_log where action = 'root.set_by_host'
        and target_id in (select id from $S.users where email in ($RACE))")"

# -------------------------------------------------------------------------------
echo
echo "-- what no script may touch --"
expect_eq "an uninvolved account's MCP token stays live" "1" "$(live_tokens "${P}o")"
expect_eq "no audit row holds a hash, a password or the tunnel token" "0" \
  "$(q "select count(*) from $S.audit_log where coalesce(before::text, '') || coalesce(after::text, '')
        ~ '\\\$2[aby]\\\$|$PW_NEW|$PW_B|$PW_A|$PW_M|$PW_ROOT|$PW_HELD|admin-passphrase|$TUNNEL_TOKEN'")"
expect_eq "every audit row is the system's" "0" \
  "$(q "select count(*) from $S.audit_log where source <> 'system' or actor_id is not null")"
expect_eq "nothing reached the real tables" "0|0" \
  "$(q "select (select count(*) from public.users where email ilike 'rbac-scripts-$$-%') || '|' ||
               (select count(*) from public.audit_log where target_id like '${P}%'
                  or target_id in (select id from $S.users))")"
if [ "$(q "select count(*) from pg_tables where schemaname = 'public' and tablename = 'instance_settings'")" = "1" ]; then
  expect_eq "...nor the real Root" "0" \
    "$(q "select count(*) from public.instance_settings where root_user_id in (select id from $S.users)")"
fi

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
