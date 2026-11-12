#!/usr/bin/env bash
#
# Live check of step 2.5 (Root: ID-02, ID-04, ID-06, ID-09, ID-10) on a DISPOSABLE instance:
# the upgrade harness's `serve several_admins` (tests/rbac_upgrade_live.sh: its own Postgres
# and the image's webapp on 127.0.0.1:3901, fake secrets), first with RBAC_IDENTITY_ENABLED=true,
# then with it off. The running stack is never touched, and no real account is ever Root here.
#
# The scenario: three admins (upg-admin-c the oldest) and one member, one password for all.
# Switch on, it checks that:
#   - the boot chose upg-admin-c, automatic and unconfirmed, with one marker row;
#   - /api/auth/me gives each account its type and every admin the unconfirmed Root, with the
#     day it was chosen (the header banner's data); a member gets no Root;
#   - another admin's demote, edit, disable, password reset, sign-out, act-as and delete of
#     Root each answer 403 root_protected, change nothing (its projects stay) and are audited;
#   - Root's own deletion is the 400 every account gets; its own demotion is refused;
#   - `set-root` in the instance's webapp confirms it (nobody signed out), the admins' answer
#     then reads confirmed (no banner), and the protections still hold.
# Switch off: the boot still chose upg-admin-c (ready the day the switch goes on), but
# /api/auth/me carries no account type or Root, and the routes answer as after Phase 1
# (act-as of another admin asks for the password, disable does not exist); nothing refused.
#
# Needs Docker and the images the harness needs (redamon-webapp:latest built from a commit
# that has step 2.5, postgres:16-alpine, redamon-webapp:rbac-7.7.2); SKIPs (exit 0) without
# them or when port 3901 is taken. The harness's own scenario check prints a FAIL for the
# instance settings marker line under the switch on (its expected file is written for the
# switch off); this script reads what it checks itself.
#
# Run: bash tests/rbac_root_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT=3901
BASE="http://127.0.0.1:$PORT"
IMAGE="${RBAC_UPGRADE_IMAGE:-redamon-webapp:latest}"
# The harness's fixture password (tests/fixtures/rbac_upgrade/README.md).
FIXTURE_PASSWORD=rbac-upgrade-pass-0001
ROOT_EMAIL=upg-admin-c@e2e.local

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  PASS  $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

skip() { echo "SKIP: $1"; exit 0; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || skip "docker unavailable"
docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "image $IMAGE missing"
docker run --rm --entrypoint sh "$IMAGE" -c 'test -f scripts/backfill-rbac-root.mjs' >/dev/null 2>&1 \
  || skip "image $IMAGE predates step 2.5 (no scripts/backfill-rbac-root.mjs)"
code="$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
[ "$code" = 000 ] || skip "port $PORT already answers ($code): stop that server first"

WORK="$(mktemp -d)"
HPID=""
stop_serve() {
  [ -n "$HPID" ] || return 0
  pkill -TERM -P "$HPID" sleep 2>/dev/null
  kill -TERM "$HPID" 2>/dev/null
  wait "$HPID" 2>/dev/null
  HPID=""
}
trap 'stop_serve; rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

serve() { # on|off: boots the disposable instance; sets HPID, PG, WEB
  local log="$WORK/serve-$1.log" switch=false
  [ "$1" = on ] && switch=true
  RBAC_IDENTITY_ENABLED=$switch bash "$ROOT/tests/rbac_upgrade_live.sh" serve several_admins > "$log" 2>&1 &
  HPID=$!
  echo "== booting the disposable instance (scenario several_admins, identity switch $1)"
  for _ in $(seq 1 600); do
    grep -q '^== Serving scenario' "$log" && break
    kill -0 "$HPID" 2>/dev/null || { echo "the harness stopped:"; tail -n 30 "$log"; exit 1; }
    grep -q '^SKIP' "$log" && { cat "$log"; exit 0; }
    sleep 1
  done
  grep -q '^== Serving scenario' "$log" || { echo "the instance did not come up"; tail -n 30 "$log"; exit 1; }
  PG="rbac-upg-$HPID-pg"; WEB="rbac-upg-$HPID-web"
}
sql() { docker exec -i "$PG" psql -X -q -t -A -U postgres -d redamon -c "$1" 2>/dev/null; }
id_of() { sql "SELECT id FROM users WHERE email = '$1'"; }

login() { # email jar -> code
  curl -s -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    --data-binary "{\"email\":\"$1\",\"password\":\"$FIXTURE_PASSWORD\"}"
}
call() { # jar method path [json] -> code; the body in $WORK/body (never printed whole)
  local args=(-s -m 60 -o "$WORK/body" -w '%{http_code}' -X "$2" -b "$1" -c "$1" -H "Origin: $BASE")
  [ $# -ge 4 ] && args+=(-H 'Content-Type: application/json' --data-binary "$4")
  curl "${args[@]}" "$BASE$3"
}
field() { python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$WORK/body" "$1" 2>/dev/null || true; }
refused() { # label jar method path [json]: 403 root_protected
  local code
  code="$(call "${@:2}")"
  eq "$1 -> 403 root_protected" "$code $(field "b.get('code')")" "403 root_protected"
}
me() { call "$1" GET /api/auth/me >/dev/null; }
cache_wait() { sleep 6; } # RBAC_AUTHZ_CACHE_MS is blank in the serve instance: 5 s

# ---- switch on ----------------------------------------------------------------------------
serve on
C="$(id_of "$ROOT_EMAIL")"; A_ID="$(id_of upg-admin-a@e2e.local)"
[[ "$C" =~ ^[A-Za-z0-9_-]+$ ]] && [[ "$A_ID" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected fixture ids"; exit 1; }

echo "== the boot chose the oldest admin with a password"
eq "Root is upg-admin-c, unconfirmed, automatic" \
  "$(sql "SELECT (SELECT email FROM users WHERE id = root_user_id), root_confirmed_at IS NOT NULL, root_assigned_by FROM instance_settings")" \
  "$ROOT_EMAIL|f|automatic"
eq "one marker: oldest of 3" \
  "$(sql "SELECT count(*), max(after->>'rule'), max(after->>'candidateCount') FROM audit_log WHERE action = 'system.rbac_root_assigned'")" \
  "1|oldest_admin|3"

ADMIN="$WORK/a.jar"; ROOTJ="$WORK/c.jar"; MEMBER="$WORK/m.jar"
eq "admin A signs in" "$(login upg-admin-a@e2e.local "$ADMIN")" 200
eq "Root (admin C) signs in" "$(login "$ROOT_EMAIL" "$ROOTJ")" 200
eq "member A signs in" "$(login upg-member-a@e2e.local "$MEMBER")" 200

echo "== /api/auth/me: the account type and, for admins, the unconfirmed Root"
me "$ADMIN"
eq "admin A: type admin; Root C unconfirmed, with the day it was chosen" \
  "$(field "[b.get('accountType'), b['rbac']['root']['email'], b['rbac']['root']['confirmed'], len(b['rbac']['root']['chosenAt'] or '') > 0]")" \
  "['admin', '$ROOT_EMAIL', False, True]"
me "$ROOTJ"
eq "Root: type root" "$(field "b.get('accountType')")" root
me "$MEMBER"
eq "member: type member, no rbac block" "$(field "[b.get('accountType'), 'rbac' in b]")" "['member', False]"

echo "== another admin acting on Root: refused, nothing changes"
HASH0="$(sql "SELECT md5(password) || '|' || session_version FROM users WHERE id = '$C'")"
refused "demote" "$ADMIN" PUT "/api/users/$C" '{"role":"standard"}'
refused "edit the sign-in address" "$ADMIN" PUT "/api/users/$C" '{"email":"rbac-step25-taken@e2e.local"}'
refused "disable" "$ADMIN" POST "/api/users/$C/disable" '{}'
refused "reset the password" "$ADMIN" PUT "/api/users/$C/password" '{"newPassword":"rbac-step25-new-pass-0001"}'
refused "sign out everywhere" "$ADMIN" POST "/api/users/$C/revoke-sessions" '{}'
refused "act as" "$ADMIN" POST /api/auth/act-as "{\"targetUserId\":\"$C\"}"
refused "delete" "$ADMIN" DELETE "/api/users/$C" '{}'
eq "Root unchanged: admin, active, same email, password and session version" \
  "$(sql "SELECT role, status, email, md5(password) || '|' || session_version FROM users WHERE id = '$C'")" \
  "admin|active|$ROOT_EMAIL|$HASH0"
eq "Root's project still there" "$(sql "SELECT count(*) FROM projects WHERE user_id = '$C'")" 1
if grep -q $'\tredamon-act-as\t' "$ADMIN" 2>/dev/null; then fail "no act-as cookie was set"; else pass "no act-as cookie was set"; fi
eq "each refusal audited, by admin A, on Root" \
  "$(sql "SELECT string_agg(after->>'attempted', ',' ORDER BY created_at) FROM audit_log WHERE action = 'rbac.root_protected_refused' AND actor_id = '$A_ID' AND target_id = '$C'")" \
  "role_change,edit,disable,reset_password,revoke_sessions,act_as,delete"

echo "== Root on its own account"
code="$(call "$ROOTJ" DELETE "/api/users/$C" '{}')"
eq "Root's self-deletion -> 400, as for everyone" "$code" 400
refused "Root's own demotion" "$ROOTJ" PUT "/api/users/$C" '{"role":"standard"}'
eq "Root still admin" "$(sql "SELECT role FROM users WHERE id = '$C'")" admin

echo "== set-root confirms it; the banner data then reads confirmed"
out="$(docker exec "$WEB" node scripts/set-root.mjs "$ROOT_EMAIL" 2>&1 </dev/null)"
eq "set-root of the automatic Root -> Root confirmed" "$(grep -c 'Root confirmed' <<<"$out")" 1
eq "confirmed, rule kept, nobody signed out" \
  "$(sql "SELECT root_confirmed_at IS NOT NULL, root_assigned_by, (SELECT session_version FROM users WHERE id = '$C') FROM instance_settings")" \
  "t|automatic|0"
cache_wait
me "$ADMIN"
eq "admin A: Root confirmed (no banner)" "$(field "b['rbac']['root']['confirmed']")" True
refused "act as a confirmed Root" "$ADMIN" POST /api/auth/act-as "{\"targetUserId\":\"$C\"}"
stop_serve
for _ in $(seq 1 60); do
  [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)" = 000 ] && break
  sleep 1
done

# ---- switch off ---------------------------------------------------------------------------
serve off
C="$(id_of "$ROOT_EMAIL")"
[[ "$C" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected fixture id"; exit 1; }
echo "== switch off: the Root is chosen, but nothing reads it"
eq "the boot still chose upg-admin-c" \
  "$(sql "SELECT (SELECT email FROM users WHERE id = root_user_id), root_assigned_by FROM instance_settings")" \
  "$ROOT_EMAIL|automatic"
ADMIN="$WORK/a-off.jar"
eq "admin A signs in" "$(login upg-admin-a@e2e.local "$ADMIN")" 200
me "$ADMIN"
eq "/api/auth/me as after Phase 1: no account type, no Root" \
  "$(field "['accountType' in b, sorted(b['rbac'].keys())]")" "[False, ['compat', 'legacyGrantsPending']]"
code="$(call "$ADMIN" POST /api/auth/act-as "{\"targetUserId\":\"$C\"}")"
eq "act-as of another admin asks for the password (Phase 1)" "$code $(field "b.get('code')")" "403 step_up_required"
eq "disable does not exist (Phase 1)" "$(call "$ADMIN" POST "/api/users/$C/disable" '{}')" 404
eq "nothing refused as root_protected" "$(sql "SELECT count(*) FROM audit_log WHERE action = 'rbac.root_protected_refused'")" 0

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
