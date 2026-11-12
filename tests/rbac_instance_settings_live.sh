#!/usr/bin/env bash
#
# Live check of step 2.4 (instance settings, ID-32..34) on a DISPOSABLE instance: the
# upgrade harness's `serve tunnel_rows` (tests/rbac_upgrade_live.sh: its own Postgres and the
# image's webapp on 127.0.0.1:3901, fake secrets, no agent, sandbox or orchestrator) with
# RBAC_IDENTITY_ENABLED=true. The running stack is never touched: the capture proxy and the
# tunnel other sessions use stay as they are.
#
# The scenario: two members whose rows configure tunnels (member B's, enabled and saved
# last, is the one in force) and two admins whose capture settings differ (admin B's, saved
# last, in force). It checks that, with the switch on:
#   - the boot backfill filled the instance row from exactly those rows;
#   - the readers answer the instance row (capture-config source "instance");
#   - an admin's TrafficMind change through /api/admin/instance-settings behaves as before
#     for the proxy config, and a downgrade-style read of the user rows shows it mirrored
#     into the source row (admin B), the other admin's row untouched;
#   - the tunnel switch, changed there, is mirrored into the tunnel source row (member B);
#     the sandbox being absent, the save answers with a warning, never a failure;
#   - the user settings PUT refuses a real change with 409; the `tunnels` legacy holder
#     (member A, granted by the backfill) changes the tunnel but not the capture policy;
#   - the audit names fields, never a credential; the sync refuses a call without the
#     sandbox's bearer (the serve instance has no TUNNEL_AUTH_TOKEN: every call refused).
#
# The harness's own scenario check prints a FAIL for the marker line (its expected file is
# written for the switch off); this script reads the instance row itself.
#
# Needs Docker and the images the harness needs (redamon-webapp:latest built from a commit
# that has step 2.4, postgres:16-alpine, redamon-webapp:rbac-7.7.2); SKIPs (exit 0) without
# them or when port 3901 is taken.
#
# Run: bash tests/rbac_instance_settings_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT=3901
BASE="http://127.0.0.1:$PORT"
IMAGE="${RBAC_UPGRADE_IMAGE:-redamon-webapp:latest}"
# The harness's fixtures and fake key (tests/rbac_upgrade_live.sh, tests/fixtures/rbac_upgrade).
FIXTURE_PASSWORD=rbac-upgrade-pass-0001
FAKE_INTERNAL_API_KEY=rbac-upgrade-fake-internal-key-0001

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  PASS  $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
has() { if grep -qF -- "$3" <<<"$2"; then pass "$1"; else fail "$1 (lacks '$3')"; fi; }
lacks() { if grep -qF -- "$3" <<<"$2"; then fail "$1 (has '$3')"; else pass "$1"; fi; }

skip() { echo "SKIP: $1"; exit 0; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || skip "docker unavailable"
docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "image $IMAGE missing"
docker run --rm --entrypoint sh "$IMAGE" -c 'test -f scripts/backfill-rbac-instance-settings.mjs' >/dev/null 2>&1 \
  || skip "image $IMAGE predates step 2.4 (no scripts/backfill-rbac-instance-settings.mjs)"
code="$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
[ "$code" = 000 ] || skip "port $PORT already answers ($code): stop that server first"

WORK="$(mktemp -d)"
LOG="$WORK/serve.log"
RBAC_IDENTITY_ENABLED=true bash "$ROOT/tests/rbac_upgrade_live.sh" serve tunnel_rows > "$LOG" 2>&1 &
HPID=$!
stop_serve() {
  pkill -TERM -P "$HPID" sleep 2>/dev/null
  kill -TERM "$HPID" 2>/dev/null
  wait "$HPID" 2>/dev/null
  rm -rf "$WORK"
}
trap stop_serve EXIT

echo "== booting the disposable instance (scenario tunnel_rows, identity switch on)"
for _ in $(seq 1 600); do
  grep -q '^== Serving scenario' "$LOG" && break
  kill -0 "$HPID" 2>/dev/null || { echo "the harness stopped:"; tail -n 30 "$LOG"; exit 1; }
  grep -q '^SKIP' "$LOG" && { cat "$LOG"; exit 0; }
  sleep 1
done
grep -q '^== Serving scenario' "$LOG" || { echo "the instance did not come up"; tail -n 30 "$LOG"; exit 1; }
PG="rbac-upg-$HPID-pg"
sql() { docker exec -i "$PG" psql -X -q -t -A -U postgres -d redamon -c "$1" 2>/dev/null; }

login() { # email jar
  curl -s -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    --data-binary "{\"email\":\"$1\",\"password\":\"$FIXTURE_PASSWORD\"}"
}
put() { # jar path json -> "code body"
  curl -s -w '\n%{http_code}' -b "$1" -X PUT "$BASE$2" -H "Origin: $BASE" -H 'Content-Type: application/json' --data-binary "$3"
}
internal_get() { printf 'header = "X-Internal-Key: %s"\n' "$FAKE_INTERNAL_API_KEY" | curl -s -K - "$BASE$1"; }

ADMIN="$WORK/admin.jar"; MEMBER="$WORK/member.jar"
eq "admin B signs in" "$(login upg-admin-b@e2e.local "$ADMIN")" 200
eq "member A (tunnels legacy holder) signs in" "$(login upg-member-a@e2e.local "$MEMBER")" 200

echo "== the backfill filled the instance row from the rows in force"
eq "tunnel from member B, enabled, its chisel URL" \
  "$(sql "SELECT tunnels_enabled, chisel_server_url, (SELECT email FROM users WHERE id = tunnel_source_user_id) FROM instance_settings")" \
  "t|https://chisel.upg.test:8443|upg-member-b@e2e.local"
eq "capture from admin B: off, 30 days, no bodies" \
  "$(sql "SELECT capture_proxy_enabled, capture_proxy_retention_days, capture_proxy_store_bodies, (SELECT email FROM users WHERE id = capture_source_user_id) FROM instance_settings")" \
  "f|30|f|upg-admin-b@e2e.local"

echo "== the readers answer the instance row"
cfg="$(internal_get /api/internal/capture-config)"
has "capture-config source instance" "$cfg" '"source":"instance"'
has "capture-config enabled false" "$cfg" '"enabled":false'
body="$(curl -s -b "$ADMIN" "$BASE/api/admin/instance-settings")"
has "admin reads the instance settings" "$body" '"canManageCapture":true'
has "chisel URL shown" "$body" 'https://chisel.upg.test:8443'
lacks "the ngrok token is masked" "$body" 'upg-fake-ngrok-token-0001'

echo "== TrafficMind behaves as before for an admin; the downgrade-style read shows the mirror"
out="$(put "$ADMIN" /api/admin/instance-settings '{"captureEgressBlockPrivate":false,"captureProxyRetentionDays":21}')"
eq "admin PUT capture -> 200" "${out##*$'\n'}" 200
cfg="$(internal_get /api/internal/capture-config)"
has "the proxy config follows: block_private false" "$cfg" '"block_private":false'
eq "instance row written, by admin B" \
  "$(sql "SELECT capture_egress_block_private, capture_proxy_retention_days, (SELECT email FROM users WHERE id = updated_by_id) FROM instance_settings")" \
  "f|21|upg-admin-b@e2e.local"
eq "mirrored into the capture source row (admin B), as a 7.7.x reader would read it" \
  "$(sql "SELECT s.capture_egress_block_private, s.capture_proxy_retention_days FROM user_settings s JOIN users u ON u.id = s.user_id WHERE u.email = 'upg-admin-b@e2e.local'")" \
  "f|21"
eq "the 7.7.x rule (admin row saved last) now reads admin B's mirrored row" \
  "$(sql "SELECT u.email, s.capture_egress_block_private FROM user_settings s JOIN users u ON u.id = s.user_id WHERE u.role = 'admin' ORDER BY s.updated_at DESC LIMIT 1")" \
  "upg-admin-b@e2e.local|f"
eq "admin A's row untouched" \
  "$(sql "SELECT s.capture_egress_block_private, s.capture_proxy_retention_days FROM user_settings s JOIN users u ON u.id = s.user_id WHERE u.email = 'upg-admin-a@e2e.local'")" \
  "t|14"

echo "== the tunnel: changed at the instance, mirrored into its source row"
out="$(put "$ADMIN" /api/admin/instance-settings '{"tunnelsEnabled":false}')"
eq "admin PUT tunnel off -> 200 (no sandbox here: a warning, not a failure)" "${out##*$'\n'}" 200
has "the save names the unapplied push" "$out" 'kali_sandbox'
eq "instance and member B's row both off" \
  "$(sql "SELECT (SELECT tunnels_enabled FROM instance_settings), (SELECT s.tunnels_enabled FROM user_settings s JOIN users u ON u.id = s.user_id WHERE u.email = 'upg-member-b@e2e.local')")" \
  "f|f"

echo "== the user settings PUT refuses a real change"
ADMIN_ID="$(sql "SELECT id FROM users WHERE email = 'upg-admin-b@e2e.local'")"
out="$(put "$ADMIN" "/api/users/$ADMIN_ID/settings" '{"captureEgressBlockPrivate":true}')"
eq "user route capture change -> 409" "${out##*$'\n'}" 409
has "with its code" "$out" 'moved_to_instance_settings'

echo "== the tunnels legacy holder (OQ-R3 (a))"
out="$(put "$MEMBER" /api/admin/instance-settings '{"captureEgressBlockPrivate":true}')"
eq "member A capture change -> 403" "${out##*$'\n'}" 403
out="$(put "$MEMBER" /api/admin/instance-settings '{"ngrokAuthtoken":"upg-fake-ngrok-token-0002"}')"
eq "member A tunnel credential change -> 200" "${out##*$'\n'}" 200
eq "audit: three changes, the right named, no credential" \
  "$(sql "SELECT count(*), count(*) FILTER (WHERE after->>'tunnelVia' = 'legacy'), count(*) FILTER (WHERE after::text LIKE '%upg-fake-ngrok%') FROM audit_log WHERE action = 'instance.settings_changed'")" \
  "3|1|0"

echo "== the tunnel sync takes only the sandbox's bearer"
eq "sync without a bearer -> 401" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/global/tunnel-config/sync")" 401
eq "sync with a bearer while the token is unset -> 401" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer anything' "$BASE/api/global/tunnel-config/sync")" 401

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
