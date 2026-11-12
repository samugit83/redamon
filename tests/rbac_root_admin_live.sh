#!/usr/bin/env bash
#
# Live check of step 2.6 (only Root manages admins, role changes, the Root transfer: ID-03,
# ID-05, ID-07, PE-08, ID-25) on a DISPOSABLE instance: the upgrade harness's
# `serve several_admins` (tests/rbac_upgrade_live.sh: its own Postgres and the image's webapp on
# 127.0.0.1:3901, fake secrets), first with RBAC_IDENTITY_ENABLED=true, then with it off. The
# running stack is never touched, and no real account is ever Root here (on the dev stack the
# Root is the owner's own account, so a transfer cannot be tried there).
#
# The scenario: three admins (upg-admin-c the oldest, chosen Root by the boot) and one member,
# one password for all. Switch on, it checks that:
#   - an admin, and the unconfirmed Root, are refused root_only when creating an admin or
#     promoting the member; set-root then confirms Root C;
#   - an admin is refused root_only on another admin (demote, disable), before any password;
#   - the confirmed Root promotes the member with its password (not without), the member's
#     session version rises and its old cookie is refused; Root demotes it back;
#   - the security policy of the instance settings is Root's: admin A refused, Root with its
#     password changes the password minimum;
#   - Root offers Root to admin A with its password; GET tells A (forYou) and nobody else;
#     A's accept needs A's password; then Root is A (confirmed, by transfer), both session
#     versions rose, both old cookies are refused, one root.transfer row; signing in again,
#     A is root and C an admin, and another admin cannot list A's MCP tokens (root_protected);
#   - A offers Root to C: C declines, A offers again and cancels: both audited, Root stays A.
# Switch off: the transfer routes answer 404, an admin creates an admin with no password asked
# and demotes another admin with its own password, as after Phase 1; nothing is bumped.
#
# Needs Docker and the images the harness needs (redamon-webapp:latest built from a commit that
# has step 2.6, postgres:16-alpine, redamon-webapp:rbac-7.7.2); SKIPs (exit 0) without them or
# when port 3901 is taken.
#
# Run: bash tests/rbac_root_admin_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT=3901
BASE="http://127.0.0.1:$PORT"
IMAGE="${RBAC_UPGRADE_IMAGE:-redamon-webapp:latest}"
# The harness's fixture password (tests/fixtures/rbac_upgrade/README.md).
PW=rbac-upgrade-pass-0001
C_EMAIL=upg-admin-c@e2e.local
A_EMAIL=upg-admin-a@e2e.local
B_EMAIL=upg-admin-b@e2e.local
M_EMAIL=upg-member-a@e2e.local

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  PASS  $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

skip() { echo "SKIP: $1"; exit 0; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || skip "docker unavailable"
docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "image $IMAGE missing"
docker run --rm --entrypoint sh "$IMAGE" -c 'test -d .next/server/app/api/root/transfer' >/dev/null 2>&1 \
  || skip "image $IMAGE predates step 2.6 (no /api/root/transfer)"
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
sv() { sql "SELECT session_version FROM users WHERE email = '$1'"; }

login() { # email jar -> code
  curl -s -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    --data-binary "{\"email\":\"$1\",\"password\":\"$PW\"}"
}
call() { # jar method path [json] -> code; the body in $WORK/body (never printed whole)
  local args=(-s -m 60 -o "$WORK/body" -w '%{http_code}' -X "$2" -b "$1" -c "$1" -H "Origin: $BASE")
  [ $# -ge 4 ] && args+=(-H 'Content-Type: application/json' --data-binary "$4")
  curl "${args[@]}" "$BASE$3"
}
field() { python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$WORK/body" "$1" 2>/dev/null || true; }
answer() { # label expected-"code status" jar method path [json]
  local label="$1" want="$2" code
  shift 2
  code="$(call "$@")"
  eq "$label -> $want" "$code $(field "b.get('code')")" "$want"
}
cache_wait() { sleep 6; } # RBAC_AUTHZ_CACHE_MS is blank in the serve instance: 5 s
copy_jar() { cp "$1" "$2"; }

# ---- switch on ----------------------------------------------------------------------------
serve on
C="$(id_of "$C_EMAIL")"; A="$(id_of "$A_EMAIL")"; B="$(id_of "$B_EMAIL")"; M="$(id_of "$M_EMAIL")"
for v in "$C" "$A" "$B" "$M"; do [[ "$v" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected fixture ids"; exit 1; }; done

CJ="$WORK/c.jar"; AJ="$WORK/a.jar"; MJ="$WORK/m.jar"
eq "Root C, admin A and member A sign in" "$(login "$C_EMAIL" "$CJ") $(login "$A_EMAIL" "$AJ") $(login "$M_EMAIL" "$MJ")" "200 200 200"
NEW_ADMIN='{"name":"RBAC step 2.6","email":"rbac-step26-new-admin@e2e.local","password":"rbac-step26-admin-pass-0001","role":"admin"'

echo "== before the host confirms it, Root C has no Root power"
answer "admin A creates an admin" "403 root_only" "$AJ" POST /api/users "$NEW_ADMIN,\"stepUpPassword\":\"$PW\"}"
answer "unconfirmed Root C creates an admin" "403 root_only" "$CJ" POST /api/users "$NEW_ADMIN,\"stepUpPassword\":\"$PW\"}"
answer "unconfirmed Root C promotes the member" "403 root_only" "$CJ" PUT "/api/users/$M" "{\"role\":\"admin\",\"stepUpPassword\":\"$PW\"}"
out="$(docker exec "$WEB" node scripts/set-root.mjs "$C_EMAIL" 2>&1 </dev/null)"
eq "set-root confirms Root C" "$(grep -c 'Root confirmed' <<<"$out")" 1
cache_wait

echo "== an admin acts on members only"
answer "admin A demotes admin B (with its password)" "403 root_only" "$AJ" PUT "/api/users/$B" "{\"role\":\"standard\",\"stepUpPassword\":\"$PW\"}"
answer "admin A disables admin B" "403 root_only" "$AJ" POST "/api/users/$B/disable" '{}'
answer "admin A promotes the member" "403 root_only" "$AJ" PUT "/api/users/$M" "{\"role\":\"admin\",\"stepUpPassword\":\"$PW\"}"
eq "admin B and the member unchanged" "$(sql "SELECT string_agg(role || ':' || status || ':' || session_version, ',' ORDER BY email) FROM users WHERE id IN ('$B', '$M')")" "admin:active:0,standard:active:0"

echo "== the confirmed Root, with its password"
M_OLD="$WORK/m-old.jar"; copy_jar "$MJ" "$M_OLD"
answer "Root C promotes the member without its password" "403 step_up_required" "$CJ" PUT "/api/users/$M" '{"role":"admin"}'
eq "Root C promotes the member with it" "$(call "$CJ" PUT "/api/users/$M" "{\"role\":\"admin\",\"stepUpPassword\":\"$PW\"}")" 200
eq "the member is an admin, its session version raised" "$(sql "SELECT role || ':' || session_version FROM users WHERE id = '$M'")" "admin:1"
eq "its cookie from before the promotion is refused" "$(call "$M_OLD" GET /api/users)" 401
eq "role change audited with the new version" \
  "$(sql "SELECT count(*) FROM audit_log WHERE action = 'user.role_changed' AND target_id = '$M' AND actor_id = '$C' AND after->>'sessionVersion' = '1'")" 1
eq "Root C demotes it back" "$(call "$CJ" PUT "/api/users/$M" "{\"role\":\"standard\",\"stepUpPassword\":\"$PW\"}")" 200
eq "Root C creates an admin" "$(call "$CJ" POST /api/users "$NEW_ADMIN,\"stepUpPassword\":\"$PW\"}")" 201

echo "== the security policy is Root's"
answer "admin A changes the password minimum" "403 root_only" "$AJ" PUT /api/admin/instance-settings "{\"passwordMinLength\":14,\"stepUpPassword\":\"$PW\"}"
eq "Root C changes it with its password" "$(call "$CJ" PUT /api/admin/instance-settings "{\"passwordMinLength\":14,\"stepUpPassword\":\"$PW\"}")" 200
eq "stored" "$(sql "SELECT password_min_length FROM instance_settings")" 14

echo "== the Root transfer"
answer "admin A offers Root" "403 root_only" "$AJ" POST /api/root/transfer "{\"targetUserId\":\"$B\",\"stepUpPassword\":\"$PW\"}"
answer "Root C offers Root to the member" "400 target_not_admin" "$CJ" POST /api/root/transfer "{\"targetUserId\":\"$M\",\"stepUpPassword\":\"$PW\"}"
eq "Root C offers Root to admin A" "$(call "$CJ" POST /api/root/transfer "{\"targetUserId\":\"$A\",\"stepUpPassword\":\"$PW\"}")" 200
call "$AJ" GET /api/root/transfer >/dev/null
eq "admin A is told, by Root C" "$(field "[b['offer']['forYou'], b['offer']['fromEmail']]")" "[True, '$C_EMAIL']"
BJ="$WORK/b.jar"; login "$B_EMAIL" "$BJ" >/dev/null
call "$BJ" GET /api/root/transfer >/dev/null
eq "admin B is told nothing" "$(field "b['offer']")" None
answer "admin A accepts without its password" "403 step_up_required" "$AJ" POST /api/root/transfer/accept '{}'
C_OLD="$WORK/c-old.jar"; copy_jar "$CJ" "$C_OLD"; A_OLD="$WORK/a-old.jar"; copy_jar "$AJ" "$A_OLD"
SV_C="$(sv "$C_EMAIL")"; SV_A="$(sv "$A_EMAIL")"
eq "admin A accepts with it" "$(call "$AJ" POST /api/root/transfer/accept "{\"stepUpPassword\":\"$PW\"}")" 200
eq "Root is A, confirmed, by transfer; no offer left" \
  "$(sql "SELECT (SELECT email FROM users WHERE id = root_user_id), root_confirmed_at IS NOT NULL, root_assigned_by, pending_root_transfer_to IS NULL FROM instance_settings")" \
  "$A_EMAIL|t|transfer|t"
eq "both session versions rose by one" "$(sv "$C_EMAIL") $(sv "$A_EMAIL")" "$((SV_C+1)) $((SV_A+1))"
eq "C stays an admin" "$(sql "SELECT role FROM users WHERE id = '$C'")" admin
eq "both old cookies are refused" "$(call "$C_OLD" GET /api/users) $(call "$A_OLD" GET /api/users)" "401 401"
eq "one root.transfer row, by A, naming C before" \
  "$(sql "SELECT count(*), max(actor_id), max(before->>'rootUserId') FROM audit_log WHERE action = 'root.transfer'")" "1|$A|$C"
eq "both sign in again" "$(login "$A_EMAIL" "$AJ") $(login "$C_EMAIL" "$CJ")" "200 200"
call "$AJ" GET /api/auth/me >/dev/null; TYPE_A="$(field "b.get('accountType')")"
call "$CJ" GET /api/auth/me >/dev/null; TYPE_C="$(field "b.get('accountType')")"
eq "A is root, C an admin" "$TYPE_A $TYPE_C" "root admin"
answer "admin B lists the new Root's MCP tokens" "403 root_protected" "$BJ" GET "/api/users/$A/mcp-tokens"

echo "== declining and cancelling"
eq "Root A offers Root to C" "$(call "$AJ" POST /api/root/transfer "{\"targetUserId\":\"$C\",\"stepUpPassword\":\"$PW\"}")" 200
eq "C declines" "$(call "$CJ" POST /api/root/transfer/cancel '{}') $(field "b.get('by')")" "200 recipient"
eq "Root A offers again" "$(call "$AJ" POST /api/root/transfer "{\"targetUserId\":\"$C\",\"stepUpPassword\":\"$PW\"}")" 200
eq "Root A cancels" "$(call "$AJ" POST /api/root/transfer/cancel '{}') $(field "b.get('by')")" "200 root"
answer "C has nothing left to accept" "409 no_transfer_offer" "$CJ" POST /api/root/transfer/accept "{\"stepUpPassword\":\"$PW\"}"
eq "declined and cancelled audited; Root stays A" \
  "$(sql "SELECT (SELECT count(*) FROM audit_log WHERE action = 'root.transfer_declined') || ',' || (SELECT count(*) FROM audit_log WHERE action = 'root.transfer_cancelled') || ',' || (SELECT email FROM users WHERE id = root_user_id) FROM instance_settings")" \
  "1,1,$A_EMAIL"
stop_serve
for _ in $(seq 1 60); do
  [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)" = 000 ] && break
  sleep 1
done

# ---- switch off ---------------------------------------------------------------------------
serve off
B="$(id_of "$B_EMAIL")"
[[ "$B" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected fixture id"; exit 1; }
AJ="$WORK/a-off.jar"
eq "admin A signs in" "$(login "$A_EMAIL" "$AJ")" 200
echo "== switch off: Phase 1 rules, no transfer"
eq "the transfer routes do not exist" \
  "$(call "$AJ" GET /api/root/transfer) $(call "$AJ" POST /api/root/transfer '{}') $(call "$AJ" POST /api/root/transfer/accept '{}') $(call "$AJ" POST /api/root/transfer/cancel '{}')" \
  "404 404 404 404"
eq "admin A creates an admin, no password asked" "$(call "$AJ" POST /api/users "$NEW_ADMIN}")" 201
answer "admin A demotes admin B without its password" "403 step_up_required" "$AJ" PUT "/api/users/$B" '{"role":"standard"}'
eq "admin A demotes admin B with it" "$(call "$AJ" PUT "/api/users/$B" "{\"role\":\"standard\",\"stepUpPassword\":\"$PW\"}")" 200
eq "nothing bumped" "$(sv "$B_EMAIL")" 0

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
