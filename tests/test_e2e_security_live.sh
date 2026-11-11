#!/usr/bin/env bash
# =============================================================================
# LIVE end-to-end security tests for the remediation set (S6, I1, I19/S14).
# Drives the REAL running stack: real login cookie, real ws-ticket, real
# WebSocket handshake + hijack attempt, real cross-tenant read, real :8015 auth,
# and the settings->DB tunnel activation gate.
#
# Skips cleanly (exit 0) when the stack is down, so it is safe in the aggregate
# suite. Creates and DELETES its own throwaway users.
#
#   bash tests/test_e2e_security_live.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! curl -sf http://localhost:8090/health >/dev/null 2>&1 || ! curl -sf http://localhost:3000/api/health >/dev/null 2>&1; then
  echo "[skip] stack not up (agent :8090 / webapp :3000 unreachable) — skipping live E2E"
  exit 0
fi

FAIL=0

# --- Test fixtures. S2/E2 (commit 135c077) removed the internal-key bypass on
# user CRUD, so these live tests can no longer mint their throwaway users via
# `x-internal-key`. That user is pure scaffolding (the security behaviour under
# test is exercised over HTTP), so seed/remove it directly in the DB instead. ---
PW='Test1234!'
PWHASH="$(docker compose exec -T webapp node -e "process.stdout.write(require('bcryptjs').hashSync(process.argv[1],10))" "$PW" | tr -d '\r\n')"
seed_user() { # $1=email  $2=role(default standard) -> prints the new user id
  local email="$1" role="${2:-standard}" uid="u_e2e_$(openssl rand -hex 8)"
  # Values inlined directly: bash does not re-expand a variable's value, so the
  # bcrypt hash's `$` characters reach psql intact. Inputs here are test-local.
  docker compose exec -T postgres psql -U redamon -d redamon -tA \
    -c "INSERT INTO users (id,name,email,updated_at,password,role) VALUES ('$uid','e2e','$email',CURRENT_TIMESTAMP,'$PWHASH','$role');" >/dev/null
  echo "$uid"
}
seed_project() { # $1=user_id -> prints the new project id (owned by that user)
  local uid="$1" pid="p_e2e_$(openssl rand -hex 8)"
  # ownership_token is NOT NULL and only Prisma fills it, so a raw insert brings its own.
  docker compose exec -T postgres psql -U redamon -d redamon -tA \
    -c "INSERT INTO projects (id,user_id,name,ownership_token,updated_at) VALUES ('$pid','$uid','e2e',gen_random_uuid()::text,CURRENT_TIMESTAMP);" >/dev/null
  echo "$pid"
}
# Deleting the user cascades to its projects (projects_user_id_fkey ON DELETE CASCADE).
del_user() { docker compose exec -T postgres psql -U redamon -d redamon -tA -c "DELETE FROM users WHERE id='$1';" >/dev/null 2>&1; }

echo "#### S6 (WS ticket auth + hijack) + I1 (cross-tenant read) — inside agent container ####"
S6_EMAIL="e2e_$(openssl rand -hex 6)@redamon.local"
S6_UID="$(seed_user "$S6_EMAIL" standard)"
# ws-ticket is scoped to a project the effective user owns (requireProjectAccess),
# so the throwaway user needs a project of its own to mint a ticket against.
S6_PID="$(seed_project "$S6_UID")"
if ! docker compose exec -T -e E2E_EMAIL="$S6_EMAIL" -e E2E_PW="$PW" -e E2E_PID="$S6_PID" agent python - < tests/e2e_s6_i1.py; then
  FAIL=1
fi
del_user "$S6_UID"

echo
echo "#### S3/S4 (/ws/kali-terminal + /ws/cypherfix-* ticket + same-origin gate) ####"
# Runs inside the agent container (has websockets + AGENT_WS_TICKET_SECRET); mints
# a valid ticket locally and asserts unticketed/cross-origin are rejected and a
# valid ticket is accepted, for all three endpoints.
if docker compose exec -T agent python3 - < agentic/tests/live_ws_endpoints_probe.py; then
  echo ">> S3/S4 WS gate: OK"
else
  echo ">> S3/S4 WS gate: FAILURES ABOVE"; FAIL=1
fi

echo
echo "#### I19/S14 (:8015 bearer auth, boot force-down, settings activation gate) ####"
TOKEN=$(docker compose exec -T webapp printenv TUNNEL_AUTH_TOKEN | tr -d '\r\n')
pass=0; total=0
chk(){ total=$((total+1)); if [ "$1" = "$2" ]; then echo "PASS  $3  ($1)"; pass=$((pass+1)); else echo "FAIL  $3  (got '$1' want '$2')"; FAIL=1; fi; }

c=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8015/tunnel/configure -H 'Content-Type: application/json' -H "Authorization: Bearer WRONGTOKEN" -d '{}'); chk "$c" 401 ":8015 wrong token -> 401"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8015/tunnel/configure -H 'Content-Type: application/json' -d '{}'); chk "$c" 401 ":8015 no token -> 401"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8015/tunnel/configure -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" -d '{}'); chk "$c" 200 ":8015 correct token -> 200"
c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8015/health); chk "$c" 200 ":8015 /health open -> 200"
c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8015/tunnel/status); chk "$c" 401 ":8015 /tunnel/status no token -> 401"

body=$(curl -s -X POST http://localhost:3000/api/global/tunnel-config/sync)
if echo "$body" | grep -q '"configured":false'; then chk 1 1 "boot sync forces tunnels down"; else chk 0 1 "boot sync forces down [$body]"; fi

EMAIL="e2e_i19_$(openssl rand -hex 4)@redamon.local"
USERID="$(seed_user "$EMAIL" standard)"
JAR=$(mktemp)
curl -s -c "$JAR" -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}" >/dev/null
curl -s -b "$JAR" -X PUT "http://localhost:3000/api/users/$USERID/settings" -H 'Content-Type: application/json' -d '{"tunnelsEnabled":true}' >/dev/null
en=$(docker compose exec -T postgres psql -U redamon -d redamon -tA -c "SELECT tunnels_enabled FROM user_settings WHERE user_id='$USERID';" 2>/dev/null | tr -d '[:space:]')
chk "$en" "t" "settings enable -> DB tunnels_enabled=true"
curl -s -b "$JAR" -X PUT "http://localhost:3000/api/users/$USERID/settings" -H 'Content-Type: application/json' -d '{"tunnelsEnabled":false}' >/dev/null
dis=$(docker compose exec -T postgres psql -U redamon -d redamon -tA -c "SELECT tunnels_enabled FROM user_settings WHERE user_id='$USERID';" 2>/dev/null | tr -d '[:space:]')
chk "$dis" "f" "settings disable -> DB tunnels_enabled=false"
del_user "$USERID"
rm -f "$JAR"

echo
echo "I19 live: $pass/$total"
echo
if [ "$FAIL" -eq 0 ]; then echo ">> LIVE E2E ALL GREEN"; else echo ">> LIVE E2E FAILURES ABOVE"; fi
exit $FAIL
