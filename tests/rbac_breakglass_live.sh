#!/usr/bin/env bash
#
# Live check of step 4.14 (oversight and Root's break-glass: SH-18, SH-47, DV-24; E2E P4-08's
# break-glass half) on a DISPOSABLE instance: the upgrade harness's `serve several_admins`
# (tests/rbac_upgrade_live.sh: its own Postgres and the image's webapp on 127.0.0.1:3901, fake
# secrets), first with RBAC_IDENTITY_ENABLED, RBAC_PERMISSIONS_ENABLED and RBAC_SHARING_ENABLED on
# and Root's sharing policy enabled by SQL, then with every switch off. The running stack is never
# touched: break-glass needs the confirmed Root, and the shared instance's Root is unconfirmed.
#
# The scenario: three admins (upg-admin-c the oldest, chosen Root by the boot), one member with a
# project, one password for all. Switch on, it checks that:
#   - admin A (Full admin) lists the member's project in "All projects (oversight)", reads it at Read
#     twice (one project.oversee row), and is refused its traffic (raw data) and break-glass;
#   - the unconfirmed Root C holds no projects:administer; set-root confirms it;
#   - Root C needs its password, a reason and at most 240 minutes; then 201, one ProjectBreakGlass
#     row, one project.breakglass row, a break_glass notice in the member's account;
#   - Root C reads the traffic (raw data) and my-access says break_glass; the member's next sign-in
#     shows the notice and the project's activity lists the oversight and break-glass rows;
#   - Root C closes it (project.breakglass.end) and is back to oversight; a second one expires
#     (expires_at moved into the past by SQL) and gives nothing at once.
# Switch off: the break-glass routes and the oversight list answer 404, and admin A gets 404 on the
# member's project (no oversight), as before Phase 4.
#
# Needs Docker and the images the harness needs (redamon-webapp:latest built from a commit that
# has step 4.14, postgres:16-alpine, redamon-webapp:rbac-7.7.2); SKIPs (exit 0) without them or
# when port 3901 is taken.
#
# Run: bash tests/rbac_breakglass_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT=3901
BASE="http://127.0.0.1:$PORT"
IMAGE="${RBAC_UPGRADE_IMAGE:-redamon-webapp:latest}"
# The harness's fixture password (tests/fixtures/rbac_upgrade/README.md).
PW=rbac-upgrade-pass-0001
C_EMAIL=upg-admin-c@e2e.local
A_EMAIL=upg-admin-a@e2e.local
M_EMAIL=upg-member-a@e2e.local

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  PASS  $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

skip() { echo "SKIP: $1"; exit 0; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || skip "docker unavailable"
docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "image $IMAGE missing"
docker run --rm --entrypoint sh "$IMAGE" -c 'test -d ".next/server/app/api/projects/[id]/breakglass"' >/dev/null 2>&1 \
  || skip "image $IMAGE predates step 4.14 (no /api/projects/[id]/breakglass)"
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
  RBAC_IDENTITY_ENABLED=$switch RBAC_PERMISSIONS_ENABLED=$switch RBAC_SHARING_ENABLED=$switch \
    bash "$ROOT/tests/rbac_upgrade_live.sh" serve several_admins > "$log" 2>&1 &
  HPID=$!
  echo "== booting the disposable instance (scenario several_admins, switches $1)"
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

login() { # email jar -> code; the answer in $WORK/body
  curl -s -o "$WORK/body" -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
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
count() { sql "SELECT count(*) FROM audit_log WHERE action = '$1' AND project_id = '$P'"; }

# ---- switches on --------------------------------------------------------------------------
serve on
C="$(id_of "$C_EMAIL")"; A="$(id_of "$A_EMAIL")"; M="$(id_of "$M_EMAIL")"
P="$(sql "SELECT id FROM projects WHERE user_id = '$M' ORDER BY created_at LIMIT 1")"
for v in "$C" "$A" "$M" "$P"; do [[ "$v" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected fixture ids"; exit 1; }; done
eq "Root's sharing policy enabled" "$(sql "UPDATE instance_settings SET sharing_policy = '{\"enabled\":true}' RETURNING sharing_policy->>'enabled'")" true
cache_wait

CJ="$WORK/c.jar"; AJ="$WORK/a.jar"; MJ="$WORK/m.jar"
eq "Root C, admin A and the member sign in" "$(login "$C_EMAIL" "$CJ") $(login "$A_EMAIL" "$AJ") $(login "$M_EMAIL" "$MJ")" "200 200 200"

echo "== oversight: admin A reads the member's project at Read, audited once a day"
eq "the oversight list names the project by oversight" \
  "$(call "$AJ" GET /api/projects/oversight) $(field "[r['myAccess']['via'] for r in b if r['id'] == '$P']")" "200 ['oversight']"
eq "admin A reads the project twice" "$(call "$AJ" GET "/api/projects/$P") $(call "$AJ" GET "/api/projects/$P")" "200 200"
eq "one project.oversee row by A" "$(sql "SELECT count(*) FROM audit_log WHERE action = 'project.oversee' AND actor_id = '$A' AND project_id = '$P'")" 1
answer "admin A reads its traffic (raw data)" "403 forbidden" "$AJ" GET "/api/traffic/$P"
answer "admin A opens break-glass" "403 forbidden" "$AJ" POST "/api/projects/$P/breakglass" "{\"reason\":\"rbac\",\"durationMinutes\":5,\"stepUpPassword\":\"$PW\"}"

echo "== break-glass is the confirmed Root's"
answer "the unconfirmed Root C opens it" "403 forbidden" "$CJ" POST "/api/projects/$P/breakglass" "{\"reason\":\"rbac\",\"durationMinutes\":5,\"stepUpPassword\":\"$PW\"}"
out="$(docker exec "$WEB" node scripts/set-root.mjs "$C_EMAIL" 2>&1 </dev/null)"
eq "set-root confirms Root C" "$(grep -c 'Root confirmed' <<<"$out")" 1
cache_wait
answer "Root C without its password" "403 step_up_required" "$CJ" POST "/api/projects/$P/breakglass" '{"reason":"rbac live check","durationMinutes":5}'
answer "Root C without a reason" "400 invalid_field" "$CJ" POST "/api/projects/$P/breakglass" "{\"durationMinutes\":5,\"stepUpPassword\":\"$PW\"}"
answer "Root C for 241 minutes" "400 invalid_field" "$CJ" POST "/api/projects/$P/breakglass" "{\"reason\":\"rbac live check\",\"durationMinutes\":241,\"stepUpPassword\":\"$PW\"}"
eq "nothing opened yet" "$(sql "SELECT count(*) FROM project_break_glass")" 0
eq "Root C with a reason and its password" \
  "$(call "$CJ" POST "/api/projects/$P/breakglass" "{\"reason\":\"rbac live check\",\"durationMinutes\":5,\"stepUpPassword\":\"$PW\"}") $(field "b['breakGlass']['durationMinutes']")" "201 5"
eq "one break-glass row for C on the project" "$(sql "SELECT count(*) FROM project_break_glass WHERE user_id = '$C' AND project_id = '$P' AND expires_at > now()")" 1
eq "one project.breakglass row by C" "$(sql "SELECT count(*) || ':' || max(actor_id) FROM audit_log WHERE action = 'project.breakglass' AND project_id = '$P'")" "1:$C"
eq "the member holds a break_glass notice" "$(sql "SELECT pending_notices::text LIKE '%\"break_glass\"%' FROM users WHERE id = '$M'")" t
eq "Root C reads the traffic (raw data)" "$(call "$CJ" GET "/api/traffic/$P")" 200
eq "my-access says break-glass" "$(call "$CJ" GET "/api/projects/$P/my-access") $(field "b['myAccess']['via']")" "200 break_glass"

echo "== the owner is told and sees it"
eq "the member's next sign-in shows the notice" "$(login "$M_EMAIL" "$MJ") $(field "[n['type'] for n in b.get('notices', [])]")" "200 ['break_glass']"
eq "the activity lists the oversight and break-glass rows" \
  "$(call "$MJ" GET "/api/projects/$P/activity?group=oversight") $(field "sorted({e['action'] for e in b['events']})")" \
  "200 ['project.breakglass', 'project.oversee']"

echo "== it ends"
eq "Root C closes it" "$(call "$CJ" DELETE "/api/projects/$P/breakglass") $(field "b.get('closed')")" "200 1"
eq "project.breakglass.end written, no row left" "$(count project.breakglass.end):$(sql "SELECT count(*) FROM project_break_glass")" "1:0"
answer "Root C reads the traffic again" "403 forbidden" "$CJ" GET "/api/traffic/$P"
answer "closing again" "404 no_break_glass" "$CJ" DELETE "/api/projects/$P/breakglass"
eq "Root C opens another" "$(call "$CJ" POST "/api/projects/$P/breakglass" "{\"reason\":\"rbac live check 2\",\"durationMinutes\":5,\"stepUpPassword\":\"$PW\"}")" 201
eq "Root C reads the traffic" "$(call "$CJ" GET "/api/traffic/$P")" 200
sql "UPDATE project_break_glass SET expires_at = now() - interval '1 second' WHERE user_id = '$C'" >/dev/null
answer "past its expiry it gives nothing at once" "403 forbidden" "$CJ" GET "/api/traffic/$P"
eq "and my-access is oversight again" "$(call "$CJ" GET "/api/projects/$P/my-access") $(field "b['myAccess']['via']")" "200 oversight"
stop_serve
for _ in $(seq 1 60); do
  [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)" = 000 ] && break
  sleep 1
done

# ---- switches off -------------------------------------------------------------------------
serve off
M="$(id_of "$M_EMAIL")"
P="$(sql "SELECT id FROM projects WHERE user_id = '$M' ORDER BY created_at LIMIT 1")"
[[ "$P" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected fixture id"; exit 1; }
CJ="$WORK/c-off.jar"; AJ="$WORK/a-off.jar"
eq "Root C and admin A sign in" "$(login "$C_EMAIL" "$CJ") $(login "$A_EMAIL" "$AJ")" "200 200"
echo "== switches off: no oversight, no break-glass"
eq "the break-glass routes and the oversight list do not exist" \
  "$(call "$CJ" POST "/api/projects/$P/breakglass" "{\"reason\":\"rbac\",\"durationMinutes\":5,\"stepUpPassword\":\"$PW\"}") $(call "$CJ" DELETE "/api/projects/$P/breakglass") $(call "$AJ" GET /api/projects/oversight)" \
  "404 404 404"
eq "admin A gets 404 on the member's project" "$(call "$AJ" GET "/api/projects/$P")" 404
eq "nothing opened, nothing audited" "$(sql "SELECT count(*) FROM project_break_glass")|$(sql "SELECT count(*) FROM audit_log WHERE action IN ('project.oversee', 'project.breakglass', 'project.breakglass.end')")" "0|0"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
