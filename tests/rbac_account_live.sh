#!/usr/bin/env bash
#
# Live check of step 2.11 (email change, session lifetimes, My account: ID-24, ID-25, ID-30,
# UI-09; E2E-P2-09) on a DISPOSABLE instance: the upgrade harness's `serve several_admins`
# (tests/rbac_upgrade_live.sh: its own Postgres and the image's webapp on 127.0.0.1:3901, fake
# secrets), first with RBAC_IDENTITY_ENABLED=true, then with it off. The running stack is never
# touched: the idle check sets the instance's adminIdleMinutes by SQL, which only a disposable
# instance may have changed.
#
# Switch on, it checks that:
#   - a member's login cookie lives 168 h and an admin's 12 h (Max-Age), the admin's token
#     carrying its idle limit and last activity;
#   - the member's own email change is refused without its current password (nothing written) and
#     done with it: stored lowercased, one user.email_changed row, a notice; the next sign-in with
#     the new address answers the notice once; My activity lists the change and the notice;
#   - an admin changing the member's email needs its own password, and the notice names the admin;
#   - with adminIdleMinutes = 1, an admin idle for 65 s is sent to /login (page) and refused 401
#     session_ended (API), the cookie cleared; another admin signed in under a 2-minute limit is
#     still in after the same 65 s and is handed a refreshed cookie, but not again a moment later.
# Switch off: the own email changes without a password (Phase 1), every login cookie lives 7 days
# with no idle claim, and My activity answers 404.
#
# Needs Docker and the images the harness needs (redamon-webapp:latest built from a commit that
# has step 2.11, postgres:16-alpine, redamon-webapp:rbac-7.7.2); SKIPs (exit 0) without them or
# when port 3901 is taken. Takes about 2 minutes (one 65 s idle wait).
#
# Run: bash tests/rbac_account_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT=3901
BASE="http://127.0.0.1:$PORT"
IMAGE="${RBAC_UPGRADE_IMAGE:-redamon-webapp:latest}"
# The harness's fixture password (tests/fixtures/rbac_upgrade/README.md).
PW=rbac-upgrade-pass-0001
A_EMAIL=upg-admin-a@e2e.local
B_EMAIL=upg-admin-b@e2e.local
M_EMAIL=upg-member-a@e2e.local
M_NEW=upg-member-a.moved@e2e.local

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  PASS  $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

skip() { echo "SKIP: $1"; exit 0; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || skip "docker unavailable"
docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "image $IMAGE missing"
docker run --rm --entrypoint sh "$IMAGE" -c 'test -d .next/server/app/api/account/activity' >/dev/null 2>&1 \
  || skip "image $IMAGE predates step 2.11 (no /api/account/activity)"
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

serve() { # on|off: boots the disposable instance; sets HPID, PG
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
  PG="rbac-upg-$HPID-pg"
}
sql() { docker exec -i "$PG" psql -X -q -t -A -U postgres -d redamon -c "$1" 2>/dev/null; }
id_of() { sql "SELECT id FROM users WHERE email = '$1'"; }

login() { # email jar -> code; the answer's body in $WORK/body, headers in $WORK/headers
  curl -s -m 30 -o "$WORK/body" -D "$WORK/headers" -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary "{\"email\":\"$1\",\"password\":\"$PW\"}"
}
call() { # jar method path [json] -> code; body in $WORK/body, headers in $WORK/headers (never printed whole)
  local args=(-s -m 60 -o "$WORK/body" -D "$WORK/headers" -w '%{http_code}' -X "$2" -b "$1" -c "$1" -H "Origin: $BASE")
  [ $# -ge 4 ] && args+=(-H 'Content-Type: application/json' --data-binary "$4")
  curl "${args[@]}" "$BASE$3"
}
field() { python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$WORK/body" "$1" 2>/dev/null || true; }
max_age() { grep -i '^set-cookie: redamon-auth=' "$WORK/headers" | grep -oiE 'max-age=[0-9]+' | head -1 | cut -d= -f2; }
sets_auth() { grep -qi '^set-cookie: redamon-auth=[^;]' "$WORK/headers" && echo yes || echo no; }
claims() { # jar python-expr -> value from the login token's payload (never the token)
  python3 - "$1" "$2" <<'PY' 2>/dev/null || true
import base64, json, sys
tok = next(l.split('\t')[6].strip() for l in open(sys.argv[1]) if '\tredamon-auth\t' in l)
p = tok.split('.')[1]
c = json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))
print(eval(sys.argv[2]))
PY
}

# ---- switch on ----------------------------------------------------------------------------
serve on
A="$(id_of "$A_EMAIL")"; B="$(id_of "$B_EMAIL")"; M="$(id_of "$M_EMAIL")"
for v in "$A" "$B" "$M"; do [[ "$v" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected fixture ids"; exit 1; }; done

echo "== session lifetimes"
MJ="$WORK/m.jar"; AJ="$WORK/a.jar"
eq "member signs in, cookie 168 h" "$(login "$M_EMAIL" "$MJ") $(max_age)" "200 604800"
eq "member token: no idle claim, lives 168 h" "$(claims "$MJ" "('idl' in c, c['exp'] - c['iat'])")" "(False, 604800)"
eq "admin A signs in, cookie 12 h" "$(login "$A_EMAIL" "$AJ") $(max_age)" "200 43200"
eq "admin token: adm, idl 60, lat = iat, lives 12 h" "$(claims "$AJ" "(c.get('adm'), c.get('idl'), c.get('lat') == c['iat'], c['exp'] - c['iat'])")" "(1, 60, True, 43200)"

echo "== the member changes its own sign-in email"
eq "without its current password -> 403 step_up_required" \
  "$(call "$MJ" PUT "/api/users/$M" "{\"email\":\"$M_NEW\"}") $(field "b.get('code')")" "403 step_up_required"
eq "nothing written" "$(sql "SELECT email FROM users WHERE id = '$M'")|$(sql "SELECT count(*) FROM audit_log WHERE action = 'user.email_changed'")" "$M_EMAIL|0"
eq "with it -> 200" "$(call "$MJ" PUT "/api/users/$M" "{\"email\":\"UPG-member-a.MOVED@e2e.local\",\"currentPassword\":\"$PW\"}")" 200
eq "stored lowercased, one row, one notice by the account itself" \
  "$(sql "SELECT email || '|' || (SELECT count(*) FROM audit_log WHERE action = 'user.email_changed' AND target_id = '$M' AND actor_id = '$M') || '|' || jsonb_array_length(pending_notices) || '|' || (pending_notices->-1->>'type') || '|' || (pending_notices->-1->>'self') FROM users WHERE id = '$M'")" \
  "$M_NEW|1|1|email_changed|true"
M2="$WORK/m2.jar"
eq "signs in with the new address; the notice is answered once" \
  "$(login "$M_NEW" "$M2") $(field "[n['type'] for n in b.get('notices', [])]")" "200 ['email_changed']"
eq "the next sign-in has no notice" "$(login "$M_NEW" "$M2") $(field "len(b.get('notices', []))")" "200 0"
eq "My activity lists the change and the shown notice" \
  "$(call "$M2" GET /api/account/activity) $(field "[e['details'].get('to') for e in b['events'] if e['action'] == 'user.email_changed']") $(field "[bool(n['shownAt']) for n in b['notices']]")" \
  "200 ['$M_NEW'] [True]"
eq "the old address no longer signs in" "$(login "$M_EMAIL" "$WORK/old.jar")" 401

echo "== an admin changes the member's email"
eq "without its own password -> 403 step_up_required" \
  "$(call "$AJ" PUT "/api/users/$M" "{\"email\":\"$M_EMAIL\"}") $(field "b.get('code')")" "403 step_up_required"
eq "with it -> 200, the notice names the admin" \
  "$(call "$AJ" PUT "/api/users/$M" "{\"email\":\"$M_EMAIL\",\"stepUpPassword\":\"$PW\"}") $(sql "SELECT (pending_notices->-1->'by'->>'email') || '|' || (pending_notices->-1->>'self') FROM users WHERE id = '$M'")" \
  "200 $A_EMAIL|false"

echo "== the admin idle timeout (adminIdleMinutes set by SQL on this disposable instance)"
BJ="$WORK/b.jar"; A2="$WORK/a2.jar"
sql "UPDATE instance_settings SET admin_idle_minutes = 1" >/dev/null
eq "admin B signs in under a 1-minute limit" "$(login "$B_EMAIL" "$BJ") $(claims "$BJ" "c.get('idl')")" "200 1"
sql "UPDATE instance_settings SET admin_idle_minutes = 2" >/dev/null
eq "admin A signs in again under a 2-minute limit" "$(login "$A_EMAIL" "$A2") $(claims "$A2" "c.get('idl')")" "200 2"
echo "  (waiting 65 s without activity)"
sleep 65
code="$(curl -s -m 30 -o /dev/null -D "$WORK/headers" -w '%{http_code}' -b "$BJ" "$BASE/graph")"
eq "idle admin B: a page goes to /login" "$code $(grep -i '^location:' "$WORK/headers" | tr -d '\r' | sed 's/^[Ll]ocation: //')" "307 $BASE/login"
eq "idle admin B: an API answers 401 session_ended" "$(call "$BJ" GET /api/auth/me) $(field "b.get('code')")" "401 session_ended"
eq "admin A (2-minute limit) is still in and gets a refreshed cookie" "$(call "$A2" GET /api/auth/me) $(sets_auth)" "200 yes"
eq "the refreshed token keeps its expiry and moves lat" "$(claims "$A2" "(c['exp'] - c['iat'], c['lat'] > c['iat'])")" "(43200, True)"
eq "a moment later: no new cookie" "$(call "$A2" GET /api/auth/me) $(sets_auth)" "200 no"
sql "UPDATE instance_settings SET admin_idle_minutes = 60" >/dev/null
stop_serve
for _ in $(seq 1 60); do
  [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)" = 000 ] && break
  sleep 1
done

# ---- switch off ---------------------------------------------------------------------------
serve off
M="$(id_of "$M_EMAIL")"; [[ "$M" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected fixture id"; exit 1; }
MJ="$WORK/m-off.jar"; AJ="$WORK/a-off.jar"
echo "== switch off: Phase 1"
eq "admin A signs in, cookie 7 days, no lifetime claim" \
  "$(login "$A_EMAIL" "$AJ") $(max_age) $(claims "$AJ" "sorted(c)")" "200 604800 ['exp', 'iat', 'role', 'sub', 'sv']"
eq "member signs in, cookie 7 days" "$(login "$M_EMAIL" "$MJ") $(max_age)" "200 604800"
eq "the own email changes without a password" "$(call "$MJ" PUT "/api/users/$M" "{\"email\":\"$M_NEW\"}")" 200
eq "a user.update row, no user.email_changed, no notice" \
  "$(sql "SELECT (SELECT count(*) FROM audit_log WHERE action = 'user.update' AND target_id = '$M') || '|' || (SELECT count(*) FROM audit_log WHERE action = 'user.email_changed') || '|' || jsonb_array_length(pending_notices) FROM users WHERE id = '$M'")" \
  "1|0|0"
eq "My activity does not exist" "$(call "$MJ" GET /api/account/activity)" 404

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
