#!/usr/bin/env bash
#
# Live check of the host Root commands (RBAC step 2.7, ID-08 / ID-09), run against the
# LIVE stack with the image's own scripts: `./redamon.sh set-root` moves Root to a
# seeded admin and on to a second one (each move signing out the new Root and the one
# it replaced, and revoking the new Root's MCP tokens), check-root.mjs reports it, a
# second set-root of the same account changes nothing, and update's _confirm_root
# (sourced from redamon.sh with the identity switch on in a scratch .env) keeps an
# unconfirmed Root without ADMIN_EMAIL and confirms it, signing nobody out, when
# ADMIN_EMAIL names it. Then the singleton is put back as it was.
#
# Fixtures are synthetic (rbac-step27-a/b@e2e.local, fake passphrases) and are removed
# with their audit rows by webapp/scripts/e2e-rbac-cleanup.mjs, even on Ctrl-C. A Root
# that is a real account is never touched: the check then prints SKIP, because moving
# Root signs the previous Root out.
#
# Needs the stack up with a webapp image that holds scripts/set-root.mjs and a database
# with instance_settings (step 2.1 schema); prints SKIP and exits 0 otherwise. As a
# *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_set_root_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
A_EMAIL='rbac-step27-a@e2e.local'
B_EMAIL='rbac-step27-b@e2e.local'

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; echo "        $2"; fail=$((fail + 1)); }
expect_eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2' got '$3'"; fi; }
expect_has() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1" "output lacks '$2'" ;; esac; }
q() { docker compose exec -T postgres sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<<"$1" 2>&1; }

for svc in webapp postgres; do
  if ! docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .; then
    echo "SKIP: no running $svc container"; exit 0
  fi
done
if ! docker compose exec -T webapp test -f scripts/set-root.mjs 2>/dev/null; then
  echo "SKIP: the webapp image has no scripts/set-root.mjs (rebuild it from a HEAD with step 2.7)"; exit 0
fi
if [ "$(q "select to_regclass('public.instance_settings') is not null")" != t ]; then
  echo "SKIP: the database has no instance_settings table (step 2.1 schema not pushed yet)"; exit 0
fi
CURRENT_ROOT="$(q "select coalesce(root_user_id, '') from instance_settings where id = 'instance'")"
if [ -n "$CURRENT_ROOT" ] && [ "${CURRENT_ROOT#rbac-step27-}" = "$CURRENT_ROOT" ]; then
  echo "SKIP: this instance has a Root that is not a fixture; moving it would sign that account out"; exit 0
fi

# The singleton as it is now, put back at the end; no row: removed again.
RESTORE_SQL="$(q "select format('update instance_settings set root_user_id = %L, root_confirmed_at = %L,
    root_assigned_by = %L, pending_root_transfer_to = %L, pending_root_transfer_expires = %L, updated_at = %L
    where id = ''instance''', root_user_id, root_confirmed_at, root_assigned_by, pending_root_transfer_to,
    pending_root_transfer_expires, updated_at) from instance_settings where id = 'instance'")"
[ -n "$RESTORE_SQL" ] || RESTORE_SQL="delete from instance_settings where id = 'instance'"

CLEANED_UP=0
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Restoring the singleton and removing the fixtures =="
  q "$RESTORE_SQL" >/dev/null || echo "  restore failed: run by hand: $RESTORE_SQL"
  docker compose exec -T -w /app webapp node --input-type=module - <webapp/scripts/e2e-rbac-cleanup.mjs | sed 's/^/  /' \
    || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

HASH="$(docker compose exec -T -e P='rbac-step27-fake-passphrase' webapp node -e \
  "process.stdout.write(require('bcryptjs').hashSync(process.env.P, 4))")"
q "insert into users (id, name, email, password, role, updated_at, created_at) values
     ('rbac-step27-a', 'rbac step27 a', '$A_EMAIL', '$HASH', 'admin', now(), now() + interval '1 second'),
     ('rbac-step27-b', 'rbac step27 b', '$B_EMAIL', '$HASH', 'admin', now(), now() + interval '2 seconds');
   insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash) values
     ('rbac-step27-tok-a', 'rbac-step27-a', 'rbac-step27', 'rdmn_mcp_rbac27a', 'rbac-step27-fake-hash-a'),
     ('rbac-step27-tok-b', 'rbac-step27-b', 'rbac-step27', 'rdmn_mcp_rbac27b', 'rbac-step27-fake-hash-b');" >/dev/null
sv()   { q "select session_version from users where id = '$1'"; }
live() { q "select count(*) from mcp_access_tokens where user_id = '$1' and revoked_at is null"; }
root() { q "select root_user_id || '|' || (root_confirmed_at is not null) || '|' || root_assigned_by
            from instance_settings where id = 'instance'"; }

echo "== ./redamon.sh set-root moves Root to a seeded admin =="
OUT="$(./redamon.sh set-root "$A_EMAIL" 2>&1)"; RC=$?
expect_eq "set-root exits 0" "0" "$RC"
expect_eq "Root is A, confirmed, set by the host" "rbac-step27-a|true|host" "$(root)"
expect_eq "A is signed out and its MCP token revoked" "1|0" "$(sv rbac-step27-a)|$(live rbac-step27-a)"
expect_eq "B is untouched" "0|1" "$(sv rbac-step27-b)|$(live rbac-step27-b)"
expect_eq "the move is audited by the system" "root.set_by_host/system" \
  "$(q "select string_agg(action || '/' || source, ' ') from audit_log where target_id = 'rbac-step27-a'")"
OUT="$(docker compose exec -T webapp node scripts/check-root.mjs </dev/null 2>&1)"
expect_has "check-root names A as the confirmed Root" "\"root\":{\"email\":\"$A_EMAIL\",\"confirmed\":true,\"rule\":\"host\"}" "$OUT"
expect_has "...and B among the candidates" "\"$B_EMAIL\"" "$OUT"

echo "== and on to the second one =="
OUT="$(./redamon.sh set-root "$B_EMAIL" 2>&1)"; RC=$?
expect_eq "set-root exits 0" "0" "$RC"
expect_eq "Root is B" "rbac-step27-b|true|host" "$(root)"
expect_eq "B and the Root it replaced are signed out, B's token revoked" "1|2|0" \
  "$(sv rbac-step27-b)|$(sv rbac-step27-a)|$(live rbac-step27-b)"
OUT="$(./redamon.sh set-root "$B_EMAIL" 2>&1)"; RC=$?
expect_eq "set-root of the confirmed Root exits 0" "0" "$RC"
expect_has "...and changes nothing" "nothing changed" "$OUT"
expect_eq "nobody is signed out" "1|2" "$(sv rbac-step27-b)|$(sv rbac-step27-a)"

echo "== update's _confirm_root with the switch on (scratch .env) =="
q "update instance_settings set root_user_id = 'rbac-step27-a', root_confirmed_at = null, root_assigned_by = 'automatic'
   where id = 'instance'" >/dev/null
SCRATCH="$(mktemp -d)"
printf 'RBAC_IDENTITY_ENABLED=true\n' >"$SCRATCH/.env"
confirm_root() { # [ADMIN_EMAIL]: _confirm_root non-interactive, the scratch .env
  env -u ADMIN_EMAIL ${1:+ADMIN_EMAIL="$1"} SCRATCH="$SCRATCH" ROOT_DIR="$ROOT" bash -c '
    cd "$ROOT_DIR"; source ./redamon.sh; set +e; SCRIPT_DIR="$SCRATCH"; _confirm_root' </dev/null 2>&1
}
OUT="$(confirm_root)"
expect_eq "without ADMIN_EMAIL the automatic Root is kept unconfirmed" "rbac-step27-a|false|automatic" "$(root)"
expect_has "...and the way to change it is printed" "./redamon.sh set-root <email>" "$OUT"
OUT="$(confirm_root "$A_EMAIL")"
expect_eq "ADMIN_EMAIL naming it confirms it" "rbac-step27-a|true|automatic" "$(root)"
expect_eq "...signing nobody out" "2|1" "$(sv rbac-step27-a)|$(sv rbac-step27-b)"
expect_has "...and says so" "Root confirmed" "$OUT"
rm -rf "$SCRATCH"

echo
echo "== RESULT: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
