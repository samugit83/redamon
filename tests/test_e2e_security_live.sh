#!/usr/bin/env bash
# =============================================================================
# LIVE end-to-end security tests for the remediation set (S6, I1, I19/S14).
# Drives the REAL running stack: real login cookie, real ws-ticket, real
# WebSocket handshake + hijack attempt, real cross-tenant read, real :8015 auth
# in a person's own Kali sandbox, and the settings->DB tunnel activation gate.
# Tunnels are per person: a person's tunnel is their own user settings row, run in
# their own sandbox, whatever RBAC_IDENTITY_ENABLED says (read from the webapp
# container). With the switch on, the instance settings route still gates the unused
# instance tunnel, proved by requests it refuses after (holder) or at (member) its
# access check, so the instance row is never switched.
#
# :8015 is published nowhere: it is called from inside the agent container, a guest
# of the sandbox's network, with that instance's tokens, read with docker inspect and
# sent on stdin, never printed. The orchestrator's key reaches curl on stdin.
#
# Skips cleanly (exit 0) when the stack is down, so it is safe in the aggregate
# suite. Creates and DELETES its own throwaway users, and stops the sandboxes it
# makes them start.
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
# The orchestrator labels each sandbox it starts with its own compose project: this stack's.
STACK_OWNER="$(docker ps --filter 'name=^redamon-recon-orchestrator$' --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | head -1)"
if [ -z "$STACK_OWNER" ]; then
  echo "FAIL  no compose project on a running redamon-recon-orchestrator: this stack's sandboxes cannot be told apart"
  exit 1
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

env_value() { # KEY: from the environment, else the repo-root .env; never printed
  if [ -n "${!1:-}" ]; then printf '%s' "${!1}"; return; fi
  grep -m1 "^$1=" "$REPO_ROOT/.env" 2>/dev/null | cut -d= -f2- | sed "s/^[\"']//; s/[\"']\$//"
}
# The orchestrator's API, called as the webapp calls it. The key reaches curl on stdin. Prints
# the answer's body, then its HTTP status on a line of its own.
orch_call() { # method path [json-body]
  local key port args=(-s -m 300 -K - -X "$1" -H 'Content-Type: application/json' -w '\n%{http_code}')
  [ -n "${3:-}" ] && args+=(--data-binary "$3")
  key="$(env_value ORCHESTRATOR_API_KEY)"
  port="$(env_value RECON_ORCH_PORT | grep -xE '[0-9]+' || echo 8010)"
  printf 'header = "X-Orchestrator-Key: %s"\n' "${key:-changeme}" | curl "${args[@]}" "http://127.0.0.1:$port$2"
}
# The person's running sandbox (own view) of this stack, found by its labels. Newest first: an
# instance being replaced comes after the one replacing it.
own_sandbox() { # user-id
  docker ps --filter label=redamon.sandbox=1 --filter "label=redamon.sandbox.user=$1" \
    --filter label=redamon.sandbox.view=own --filter "label=redamon.sandbox.owner=$STACK_OWNER" \
    --format '{{.Names}}' 2>/dev/null | head -1
}
# The person's sandbox started (or found) and waited for -> "<HTTP status> <state> <fresh 0|1>".
# The answer holds the instance's tokens: only those three fields are kept.
ensure_sandbox() { # user-id project-id,...
  local p list="" out state
  for p in ${2//,/ }; do list+="${list:+,}\"$p\""; done
  out="$(orch_call POST /sandboxes/ensure \
    "{\"user_id\":\"$1\",\"view\":\"own\",\"projects\":[$list],\"need_project\":null,\"wait\":true,\"touch\":false}")"
  state="$(printf '%s' "$out" | grep -o '"state": *"[a-z_]*"' | head -1 | sed 's/.*"\([a-z_]*\)"$/\1/')"
  printf '%s %s %s\n' "${out##*$'\n'}" "${state:--}" "$(printf '%s' "$out" | grep -q '"fresh": *true' && echo 1 || echo 0)"
}
# A throwaway user's sandboxes and output folders go before the user does, as an account
# deletion takes them (the one stop reason that also deletes the folders); else they idle on.
retire_sandboxes_of() { # user-id
  local out
  out="$(orch_call POST "/sandboxes/$1/stop" '{"reason":"account_deleted"}')"
  echo "(the throwaway user's sandboxes and output folders removed: HTTP ${out##*$'\n'})"
}
sandbox_env() { # container KEY: that variable of its Config.Env, to compare or send, never to print
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null | sed -n "s/^$2=//p" | head -1
}

echo "#### S6 (WS ticket auth + hijack) + I1 (cross-tenant read) — inside agent container ####"
S6_EMAIL="e2e_$(openssl rand -hex 6)@redamon.local"
S6_UID="$(seed_user "$S6_EMAIL" standard)"
# ws-ticket is scoped to a project the effective user owns (requireProjectAccess),
# so the throwaway user needs a project of its own to mint a ticket against.
S6_PID="$(seed_project "$S6_UID")"
if ! docker compose exec -T -e E2E_EMAIL="$S6_EMAIL" -e E2E_PW="$PW" -e E2E_PID="$S6_PID" agent python - < tests/e2e_s6_i1.py; then
  FAIL=1
fi
# A chat ticket's mint warms its person's sandbox.
retire_sandboxes_of "$S6_UID"
del_user "$S6_UID"

echo
echo "#### S3/S4 (/ws/kali-terminal + /ws/cypherfix-* ticket + same-origin gate) ####"
# Runs inside the agent container (has websockets + AGENT_WS_TICKET_SECRET); mints
# a valid ticket locally and asserts unticketed/cross-origin are rejected and a
# valid ticket is accepted, for all three endpoints. Each socket checks at connect
# that the ticket's tenant owns its project, so the valid ticket names a throwaway
# user and a project it owns.
WS_UID="$(seed_user "e2e_$(openssl rand -hex 6)@redamon.local" standard)"
WS_PID="$(seed_project "$WS_UID")"
if docker compose exec -T -e E2E_UID="$WS_UID" -e E2E_PID="$WS_PID" agent python3 - < agentic/tests/live_ws_endpoints_probe.py; then
  echo ">> S3/S4 WS gate: OK"
else
  echo ">> S3/S4 WS gate: FAILURES ABOVE"; FAIL=1
fi
# The accepted terminal ticket starts that user's own sandbox.
retire_sandboxes_of "$WS_UID"
del_user "$WS_UID"

echo
echo "#### I19/S14 (a person's sandbox's :8015 bearer auth, no tunnel at start, settings activation gate) ####"
pass=0; total=0
chk(){ total=$((total+1)); if [ "$1" = "$2" ]; then echo "PASS  $3  ($1)"; pass=$((pass+1)); else echo "FAIL  $3  (got '$1' want '$2')"; FAIL=1; fi; }

# A throwaway person's own sandbox, started by the orchestrator with that person's own projects:
# none, so no project folder is made for it.
T_UID="$(seed_user "e2e_t_$(openssl rand -hex 6)@redamon.local" standard)"
read -r code state _ < <(ensure_sandbox "$T_UID" "")
SBX="$(own_sandbox "$T_UID")"
chk "$code $state $([ -n "$SBX" ] && echo found)" "200 running found" "the orchestrator starts a person's own sandbox, found by its labels"
declare -A P=()
if [ -n "$SBX" ]; then
  T_TOKEN="$(sandbox_env "$SBX" TUNNEL_AUTH_TOKEN)"
  M_TOKEN="$(sandbox_env "$SBX" MCP_AUTH_TOKEN)"
  # token_urlsafe values: anything else is not embedded in the probe below.
  ok=0; [[ "$T_TOKEN" =~ ^[A-Za-z0-9_-]{20,}$ && "$M_TOKEN" =~ ^[A-Za-z0-9_-]{20,}$ && "$T_TOKEN" != "$M_TOKEN" ]] && ok=1
  chk "$ok" 1 "the instance holds its own two tokens (TUNNEL_AUTH_TOKEN, MCP_AUTH_TOKEN), distinct"
  if [ "$ok" = 1 ]; then
    while read -r tag name value; do
      [ "$tag" = PROBE ] && P[$name]="$value"
    done < <({ printf 'SANDBOX = "%s"\nTUNNEL_TOKEN = "%s"\nMCP_TOKEN = "%s"\n' "$SBX" "$T_TOKEN" "$M_TOKEN"
               cat <<'PY'
import json
import urllib.error
import urllib.request


def call(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"http://{SANDBOX}:8015{path}", data=data, method=method, headers=headers)  # noqa: F821
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            return res.status, json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}


status, now = call("GET", "/tunnel/status", TUNNEL_TOKEN)  # noqa: F821
idle = status == 200 and not any((now.get(k) or {}).get("active") for k in ("ngrok", "chisel"))
print("PROBE start_idle", int(idle))
print("PROBE configure_wrong", call("POST", "/tunnel/configure", "WRONGTOKEN", {})[0])
print("PROBE configure_none", call("POST", "/tunnel/configure", None, {})[0])
print("PROBE configure_right", call("POST", "/tunnel/configure", TUNNEL_TOKEN, {})[0])  # noqa: F821
print("PROBE health", call("GET", "/health")[0])
print("PROBE status_none", call("GET", "/tunnel/status")[0])
# The agent holds the MCP token: it may read or stop a tunnel, never start one. The stop with the
# same token on the same route must pass, or the start's refusal proves nothing.
start = {"chiselServerUrl": "http://e2e-tunnel.invalid:8443", "chiselAuth": "e2e:not-a-secret"}
print("PROBE start_mcp", call("POST", "/tunnel/configure", MCP_TOKEN, start)[0])  # noqa: F821
print("PROBE stop_mcp", call("POST", "/tunnel/configure", MCP_TOKEN, {})[0])  # noqa: F821
PY
             } | docker compose exec -T agent python3 - 2>/dev/null)
  fi
  T_TOKEN=""; M_TOKEN=""
fi
chk "${P[configure_wrong]:-none}" 401 ":8015 wrong token -> 401"
chk "${P[configure_none]:-none}" 401 ":8015 no token -> 401"
chk "${P[configure_right]:-none}" 200 ":8015 the instance's tunnel token -> 200"
chk "${P[health]:-none}" 200 ":8015 /health open -> 200"
chk "${P[status_none]:-none}" 401 ":8015 /tunnel/status no token -> 401"
chk "${P[start_idle]:-none}" 1 "a new sandbox runs no tunnel (ngrok and chisel inactive)"
chk "${P[start_mcp]:-none}" 401 ":8015 a tunnel start with the instance's MCP token (the agent's) -> 401"
chk "${P[stop_mcp]:-none}" 200 ":8015 a tunnel stop with the same token -> 200 (control)"
retire_sandboxes_of "$T_UID"
del_user "$T_UID"

# F-23 (ID-33), per person: a person's tunnel reaches their sandbox only by the agent's push to its
# :8015, and no route hands a tunnel config out: the boot sync's path is no longer public (the
# middleware refuses an anonymous call), and a signed-in admin finds no route there.
SYNC=http://localhost:3000/api/global/tunnel-config/sync
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$SYNC")
chk "$c" 401 "boot sync path without a bearer -> 401 (not public)"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer not-the-tunnel-token' "$SYNC")
chk "$c" 401 "boot sync path with a bearer -> 401 (not public)"
ADM_EMAIL="e2e_sync_$(openssl rand -hex 4)@redamon.local"
ADM_UID="$(seed_user "$ADM_EMAIL" admin)"
ADM_JAR=$(mktemp)
c=$(curl -s -o /dev/null -w '%{http_code}' -c "$ADM_JAR" -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d "{\"email\":\"$ADM_EMAIL\",\"password\":\"$PW\"}")
chk "$c" 200 "a throwaway admin signs in"
c=$(curl -s -o /dev/null -w '%{http_code}' -b "$ADM_JAR" -X POST -H 'Origin: http://localhost:3000' "$SYNC")
chk "$c" 404 "boot sync path with a signed-in admin's session -> 404 (no such route)"
del_user "$ADM_UID"
rm -f "$ADM_JAR"

# HD-06 with per-person tunnels: only an admin, the member holding the `tunnels` legacy grant,
# or a pre-upgrade account under the escape hatch turns a tunnel on, their own (the instance
# tunnel's rule). The activation checks run as a legacy holder (the grant set by SQL, as the
# upgrade backfill records it, and with RBAC_PERMISSIONS_ENABLED on the override the
# permissions-on conversion turns it into); a plain member is refused before anything is written.
env_line="$(docker compose exec -T webapp sh -c 'printf "%s" "${RBAC_IDENTITY_ENABLED:-}"' 2>/dev/null)"
case "$(printf '%s' "$env_line" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
  true|1|yes) IDENTITY=on ;;
  *) IDENTITY=off ;;
esac
echo "(identity switch $IDENTITY)"
env_line="$(docker compose exec -T webapp sh -c 'printf "%s" "${RBAC_PERMISSIONS_ENABLED:-}"' 2>/dev/null)"
case "$(printf '%s' "$env_line" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
  true|1|yes) PERMISSIONS=on ;;
  *) PERMISSIONS=off ;;
esac
# flags.ts: the permissions switch requires the identity switch and reads off without it.
[ "$IDENTITY" = on ] || PERMISSIONS=off
echo "(permissions switch $PERMISSIONS)"
BODY=$(mktemp)
put_json() { # jar url json -> "<http code> <the answer's code field>"
  local c
  c=$(curl -s -o "$BODY" -w '%{http_code}' -b "$1" -X PUT "$2" -H 'Content-Type: application/json' -d "$3")
  echo "$c $(grep -o '"code":"[a-z_]*"' "$BODY" | head -1 | cut -d'"' -f4)"
}
# A digest of the whole instance settings row (updated_at included): equal = nothing written.
instance_row() { docker compose exec -T postgres psql -U redamon -d redamon -tA -c "SELECT md5(i::text) FROM instance_settings i;" 2>/dev/null | tr -d '[:space:]'; }
EMAIL="e2e_i19_$(openssl rand -hex 4)@redamon.local"
USERID="$(seed_user "$EMAIL" standard)"
docker compose exec -T postgres psql -U redamon -d redamon -tA -c "UPDATE users SET legacy_grants = ARRAY['tunnels'] WHERE id='$USERID';" >/dev/null
if [ "$PERMISSIONS" = on ]; then
  # From the first boot with the permissions switch on (step 3.15) the column no longer counts:
  # the holder gets what that conversion writes for a kept grant, an override grant of
  # platform:tunnels ending in 90 days. Written before it signs in, so no cache holds it.
  n=$(docker compose exec -T postgres psql -U redamon -d redamon -qtA -c \
    "INSERT INTO user_permission_overrides (user_id, permission, effect, expires_at, reason, granted_by_id)
       VALUES ('$USERID', 'platform:tunnels', 'grant', (now() AT TIME ZONE 'UTC') + interval '90 days', 'kept from 7.7.x', 'system');
     SELECT count(*) FROM user_permission_overrides WHERE user_id = '$USERID' AND permission = 'platform:tunnels' AND effect = 'grant';" \
    2>/dev/null | tail -1 | tr -d '[:space:]')
  chk "$n" 1 "the legacy tunnels holder holds the converted override (permissions on)"
fi
JAR=$(mktemp)
curl -s -c "$JAR" -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}" >/dev/null
# The user settings row is the holder's own tunnel whatever the identity switch, so it is taken
# here, never moved to the instance settings. The save pushes it to the holder's own sandbox,
# which it starts.
curl -s -b "$JAR" -X PUT "http://localhost:3000/api/users/$USERID/settings" -H 'Content-Type: application/json' -d '{"tunnelsEnabled":true}' >/dev/null
en=$(docker compose exec -T postgres psql -U redamon -d redamon -tA -c "SELECT tunnels_enabled FROM user_settings WHERE user_id='$USERID';" 2>/dev/null | tr -d '[:space:]')
chk "$en" "t" "settings enable (legacy tunnels holder) -> DB tunnels_enabled=true (its own tunnel)"
curl -s -b "$JAR" -X PUT "http://localhost:3000/api/users/$USERID/settings" -H 'Content-Type: application/json' -d '{"tunnelsEnabled":false}' >/dev/null
dis=$(docker compose exec -T postgres psql -U redamon -d redamon -tA -c "SELECT tunnels_enabled FROM user_settings WHERE user_id='$USERID';" 2>/dev/null | tr -d '[:space:]')
chk "$dis" "f" "settings disable (legacy tunnels holder) -> DB tunnels_enabled=false"
if [ "$IDENTITY" = on ]; then
  before="$(instance_row)"
  # A tunnel field that is not text is refused after the access check: the holder passes the gate.
  chk "$(put_json "$JAR" http://localhost:3000/api/admin/instance-settings '{"tunnelsEnabled":true,"chiselServerUrl":42}')" "400 invalid_field" \
    "instance enable (legacy tunnels holder) passes the tunnel gate -> 400 invalid_field"
  ok=0; [ -n "$before" ] && [ "$(instance_row)" = "$before" ] && ok=1
  chk "$ok" 1 "the instance settings row is unchanged"
fi
retire_sandboxes_of "$USERID"
del_user "$USERID"
rm -f "$JAR"

M_EMAIL="e2e_i19m_$(openssl rand -hex 4)@redamon.local"
M_USERID="$(seed_user "$M_EMAIL" standard)"
M_JAR=$(mktemp)
curl -s -c "$M_JAR" -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d "{\"email\":\"$M_EMAIL\",\"password\":\"$PW\"}" >/dev/null
# Refused at the person's own tunnel too, whatever the identity switch.
chk "$(put_json "$M_JAR" "http://localhost:3000/api/users/$M_USERID/settings" '{"tunnelsEnabled":true}')" "403 tunnels_admin_only" \
  "settings enable (member without the grant) -> 403 tunnels_admin_only"
if [ "$IDENTITY" = on ]; then
  before="$(instance_row)"
  chk "$(put_json "$M_JAR" http://localhost:3000/api/admin/instance-settings '{"tunnelsEnabled":true}')" "403 forbidden" \
    "instance enable (member without the grant) -> 403 forbidden"
  ok=0; [ -n "$before" ] && [ "$(instance_row)" = "$before" ] && ok=1
  chk "$ok" 1 "the refused instance enable wrote nothing"
fi
en=$(docker compose exec -T postgres psql -U redamon -d redamon -tA -c "SELECT count(*) FROM user_settings WHERE user_id='$M_USERID' AND tunnels_enabled;" 2>/dev/null | tr -d '[:space:]')
chk "$en" "0" "refused enable wrote nothing"
chk "$(own_sandbox "$M_USERID")" "" "the refused member's enable started no sandbox"
# HD-05, GHSA-wgxp-vq94-73h8: the reporter's proof of concept against the live stack. Account A
# holds synthetic tunnel values, switched on by SQL (the route answers a person's own row only
# while their tunnel is on) but with no chisel URL and never pushed, so no tunnel starts and the
# agent's chisel lookup finds no host; member M, unrelated to A, asks the global route with their
# own cookie, naming A. Up to 7.7.2 M got A's values; now only the internal key reads them. No
# answer body is printed: the internal key's could hold a real tunnel credential.
A_EMAIL="e2e_ghsa_a_$(openssl rand -hex 4)@redamon.local"
A_USERID="$(seed_user "$A_EMAIL" standard)"
MARK="GHSA-WGXP-$(openssl rand -hex 6)"
docker compose exec -T postgres psql -U redamon -d redamon -tA \
  -c "INSERT INTO user_settings (id,user_id,updated_at,tunnels_enabled,ngrok_authtoken,chisel_auth) VALUES ('us_e2e_$(openssl rand -hex 8)','$A_USERID',CURRENT_TIMESTAMP,true,'NGROK-TEST-$MARK','e2e:CHISEL-TEST-$MARK');" >/dev/null
internal_tunnel_config() { # [query] -> HTTP status; the body lands in $BODY, never printed
  docker compose exec -T webapp printenv INTERNAL_API_KEY | tr -d '\r\n' | sed 's/^/header = "X-Internal-Key: /; s/$/"/' \
    | curl -s -o "$BODY" -w '%{http_code}' -K - "http://localhost:3000/api/global/tunnel-config${1:-}"
}
c=$(curl -s -o "$BODY" -w '%{http_code}' -b "$M_JAR" "http://localhost:3000/api/global/tunnel-config?userId=$A_USERID")
chk "$c" 404 "tunnel-config with a member's session, naming account A -> 404"
leak=0; grep -q "$MARK" "$BODY" && leak=1
chk "$leak" 0 "the member's answer holds none of account A's tunnel values"
c=$(internal_tunnel_config "?userId=$A_USERID")
chk "$c" 200 "tunnel-config with the internal key -> 200"
# Positive control: the internal key naming A reads A's own row, which proves the member's 404 is
# the gate and not an empty answer. Tunnels are per person, so this holds whatever the switches.
seen=0; grep -q "NGROK-TEST-$MARK" "$BODY" && seen=1
chk "$seen" 1 "the internal key reads account A's values (the member's 404 is the gate)"
c=$(internal_tunnel_config)
leak=0; grep -q "$MARK" "$BODY" && leak=1
chk "$c $leak" "200 0" "tunnel-config with the internal key and no person -> nobody's values"
: > "$BODY"
del_user "$A_USERID"
del_user "$M_USERID"
rm -f "$M_JAR" "$BODY"

echo
echo "I19 live: $pass/$total"
echo
if [ "$FAIL" -eq 0 ]; then echo ">> LIVE E2E ALL GREEN"; else echo ">> LIVE E2E FAILURES ABOVE"; fi
exit $FAIL
