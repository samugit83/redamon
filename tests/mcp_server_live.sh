#!/usr/bin/env bash
# =============================================================================
# L8 LIVE CHECK — the inbound MCP server against the RUNNING system.
# Run:  bash tests/mcp_server_live.sh
#
# Config that parses is not config that works. Two things can only be proven
# against a live system, and both have already bitten this repo in other forms:
#
#   ROW 2  MCP_SERVER_ENABLED must actually REACH the webapp container. The
#          webapp has NO env_file, so a value set in .env alone is inert
#          (CHANGELOG 6.2.7 records this exact class of bug on the
#          orchestrator). tests/redamon_mcp_env_test.sh asserts the compose TEXT
#          lists it; only this asserts the running process honours it.
#
#   ROW 10 MCP_DISABLED_TOOLS must actually WITHDRAW a tool from the running
#          server. It is the only per-tool rollback lever; every other MCP knob
#          reaching the process has been proven inert at least once in this
#          repo's history (MCP_KALI_EXEC_ENABLED shipped unreachable). A lever
#          that parses and does nothing is worse than no lever, because it is
#          reached for during an incident.
#
#   ROW 11 The expanded surface must actually be SERVED over real HTTP with a
#          real bearer. The contract test uses the SDK's in-memory transport, so
#          it cannot see the route, the Accept-header enforcement, or a payload
#          that grew past a limit when the tool count more than doubled.
#
#   ROW 3  The nginx `location = /api/mcp-server` must actually be the block
#          that handles the request. A prefix block would silently fall through
#          to `location /api/` with the wrong rate zone and the Basic-auth gate.
#          tests/deploy_mcp_nginx_test.sh proves the config RENDERS and parses;
#          only this proves a real request lands in the right block.
#
# This test MUTATES state (it toggles the flag and restarts the webapp) and
# RESTORES it on exit. It is live-tier: not part of `redamon.sh test unit`.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1
ENV_FILE="$REPO_ROOT/.env"
WEBAPP_URL="${REDAMON_TEST_WEBAPP_URL:-http://localhost:3000}"
RPC='{"jsonrpc":"2.0","method":"tools/list","id":1}'
# The SDK enforces the MCP spec's Accept header even in JSON mode.
ACCEPT='Accept: application/json, text/event-stream'

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
skip() { SKIP=$((SKIP+1)); printf '  skip %s (%s)\n' "$1" "$2"; }
eq()   { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

need() { command -v "$1" >/dev/null 2>&1; }
if ! need docker || ! docker compose ps >/dev/null 2>&1; then
    echo "skip: docker/compose unavailable"; exit 0
fi
if ! docker compose ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx webapp; then
    echo "skip: the webapp container is not running (this is a LIVE check)"; exit 0
fi

# --- restore whatever we change, however we exit -------------------------------
ORIGINAL_FLAG="$(grep '^MCP_SERVER_ENABLED=' "$ENV_FILE" 2>/dev/null || true)"
ORIGINAL_DISABLED="$(grep '^MCP_DISABLED_TOOLS=' "$ENV_FILE" 2>/dev/null || true)"
NGINX_NAME="redamon-mcp-live-nginx-$$"
WORK="$REPO_ROOT/.mcp-live-check.$$"
# Every restart below is `up -d --no-deps webapp`: only the webapp's env changes, and without
# --no-deps compose may recreate postgres and neo4j under the other sessions using the stack.

cleanup() {
    docker rm -f "$NGINX_NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
    sed -i '/^MCP_DISABLED_TOOLS=/d' "$ENV_FILE"
    if [[ -n "$ORIGINAL_DISABLED" ]]; then
        printf '%s\n' "$ORIGINAL_DISABLED" >> "$ENV_FILE"
    fi
    docker compose exec -T postgres psql -U "${POSTGRES_USER:-redamon}" \
        -d "${POSTGRES_DB:-redamon}" -qtAc \
        "delete from mcp_access_tokens where id='mcp-live-check'" >/dev/null 2>&1 || true
    if [[ -n "$ORIGINAL_FLAG" ]]; then
        sed -i "s|^MCP_SERVER_ENABLED=.*|${ORIGINAL_FLAG}|" "$ENV_FILE"
    else
        sed -i '/^MCP_SERVER_ENABLED=/d' "$ENV_FILE"
    fi
    docker compose up -d --no-deps webapp >/dev/null 2>&1 || true
}
trap cleanup EXIT

set_flag() {   # set_flag true|false  -> writes .env and restarts the webapp
    if grep -q '^MCP_SERVER_ENABLED=' "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^MCP_SERVER_ENABLED=.*|MCP_SERVER_ENABLED=$1|" "$ENV_FILE"
    else
        printf '\nMCP_SERVER_ENABLED=%s\n' "$1" >> "$ENV_FILE"
    fi
    docker compose up -d --no-deps webapp >/dev/null 2>&1
    for _ in $(seq 1 40); do
        [[ "$(curl -s -o /dev/null -w '%{http_code}' "$WEBAPP_URL/api/health" 2>/dev/null)" == "200" ]] && return 0
        sleep 1
    done
    return 1
}

mcp_status() {  # mcp_status [extra curl args...] -> HTTP code
    curl -s -o /dev/null -w '%{http_code}' -X POST "$WEBAPP_URL/api/mcp-server" \
        -H 'Content-Type: application/json' -H "$ACCEPT" "$@" -d "$RPC"
}

mcp_body() {    # mcp_body [extra curl args...] -> response body
    curl -s -X POST "$WEBAPP_URL/api/mcp-server" \
        -H 'Content-Type: application/json' -H "$ACCEPT" "$@" -d "$RPC"
}

# The surface is advertised by tools/list, so counting its entries is the only
# honest way to ask the RUNNING server what it serves.
tool_count() { python3 -c '
import json,sys
raw = sys.stdin.read()
# Streamable HTTP may answer as SSE; take the data frame if so.
for line in raw.splitlines():
    if line.startswith("data: "):
        raw = line[6:]
        break
try:
    print(len(json.loads(raw)["result"]["tools"]))
except Exception:
    print(-1)
'; }

has_tool() {  # has_tool <body> <name> -> yes|no
    python3 -c '
import json,sys
raw, want = sys.argv[1], sys.argv[2]
for line in raw.splitlines():
    if line.startswith("data: "):
        raw = line[6:]
        break
try:
    names = [t["name"] for t in json.loads(raw)["result"]["tools"]]
except Exception:
    print("parse-error"); sys.exit()
print("yes" if want in names else "no")
' "$1" "$2"; }

set_disabled() {  # set_disabled <csv> -> writes .env and restarts the webapp
    sed -i '/^MCP_DISABLED_TOOLS=/d' "$ENV_FILE"
    printf 'MCP_DISABLED_TOOLS=%s\n' "$1" >> "$ENV_FILE"
    docker compose up -d --no-deps webapp >/dev/null 2>&1
    for _ in $(seq 1 40); do
        [[ "$(curl -s -o /dev/null -w '%{http_code}' "$WEBAPP_URL/api/health" 2>/dev/null)" == "200" ]] && return 0
        sleep 1
    done
    return 1
}

# =============================================================================
echo "== ROW 2: the flag reaches the running container =="
# =============================================================================
if ! set_flag false; then
    bad "webapp came back after restart (flag=false)" "unhealthy" "healthy"
else
    IN_CONTAINER="$(docker compose exec -T webapp printenv MCP_SERVER_ENABLED 2>/dev/null | tr -d '\r')"
    eq "container env matches .env (false)" "$IN_CONTAINER" "false"
    # Disabled must look like the route does not exist: a 401 would confirm to an
    # unauthenticated prober that the surface is there and only the token is missing.
    eq "disabled -> 404" "$(mcp_status)" "404"
    eq "disabled -> 404 even WITH a bearer" \
       "$(mcp_status -H 'Authorization: Bearer rdmn_mcp_probe')" "404"
fi

if ! set_flag true; then
    bad "webapp came back after restart (flag=true)" "unhealthy" "healthy"
else
    IN_CONTAINER="$(docker compose exec -T webapp printenv MCP_SERVER_ENABLED 2>/dev/null | tr -d '\r')"
    eq "container env matches .env (true)" "$IN_CONTAINER" "true"
    # The flag reaching the process is the whole point: the route now exists and
    # answers on its own terms (credential required) instead of 404.
    eq "enabled -> 401 without a token" "$(mcp_status)" "401"

    # A real token proves the full path, not just the flag. Minted directly and
    # deleted below, so the test creates no lasting credential.
    TOKEN="rdmn_mcp_$(openssl rand -hex 24)"
    HASH="$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)"
    UID_ROW="$(docker compose exec -T postgres psql -U "${POSTGRES_USER:-redamon}" \
        -d "${POSTGRES_DB:-redamon}" -qtAc 'select id from users order by created_at limit 1' 2>/dev/null | tr -d '\r')"
    if [[ -z "$UID_ROW" ]]; then
        skip "enabled -> 200 with a valid token" "no user row to attach a token to"
    else
        docker compose exec -T postgres psql -U "${POSTGRES_USER:-redamon}" -d "${POSTGRES_DB:-redamon}" -qtAc \
          "insert into mcp_access_tokens (id,user_id,name,token_prefix,token_hash,scopes,created_at)
           values ('mcp-live-check','$UID_ROW','live check','${TOKEN:0:17}','$HASH',ARRAY['recon:read'],now())
           on conflict (id) do update set token_hash='$HASH', revoked_at=null, expires_at=null" >/dev/null 2>&1
        eq "enabled -> 200 with a valid token" \
           "$(mcp_status -H "Authorization: Bearer $TOKEN")" "200"
        docker compose exec -T postgres psql -U "${POSTGRES_USER:-redamon}" -d "${POSTGRES_DB:-redamon}" \
          -qtAc "delete from mcp_access_tokens where id='mcp-live-check'" >/dev/null 2>&1
        docker compose exec -T postgres psql -U "${POSTGRES_USER:-redamon}" -d "${POSTGRES_DB:-redamon}" \
          -qtAc "delete from audit_log where source='mcp'" >/dev/null 2>&1
    fi
fi

# =============================================================================
echo
echo "== ROWS 10 + 11: the served surface, and the per-tool rollback lever =="
# =============================================================================
# Needs the server ON and a real credential. The token is minted here and
# deleted on exit, and every call below is tools/list - a read.
MCP_TOOL_COUNT_EXPECTED=30

TOKEN="rdmn_mcp_$(openssl rand -hex 24)"
HASH="$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)"
UID_ROW="$(docker compose exec -T postgres psql -U "${POSTGRES_USER:-redamon}" \
    -d "${POSTGRES_DB:-redamon}" -qtAc 'select id from users order by created_at limit 1' 2>/dev/null | tr -d '\r')"

if [[ -z "$UID_ROW" ]]; then
    skip "rows 10+11" "no user row to attach a token to"
elif ! set_disabled ""; then
    bad "webapp came back with MCP_DISABLED_TOOLS empty" "unhealthy" "healthy"
else
    docker compose exec -T postgres psql -U "${POSTGRES_USER:-redamon}" -d "${POSTGRES_DB:-redamon}" -qtAc \
      "insert into mcp_access_tokens (id,user_id,name,token_prefix,token_hash,scopes,created_at)
       values ('mcp-live-check','$UID_ROW','live check','${TOKEN:0:17}','$HASH',ARRAY['recon:read'],now())
       on conflict (id) do update set token_hash='$HASH', revoked_at=null, expires_at=null" >/dev/null 2>&1

    AUTH="Authorization: Bearer $TOKEN"

    # ROW 11: the whole surface reaches a real client over real HTTP.
    eq "tools/list answers 200 with a real bearer" "$(mcp_status -H "$AUTH")" "200"
    BODY_ALL="$(mcp_body -H "$AUTH")"
    eq "the running server serves every tool" \
       "$(printf '%s' "$BODY_ALL" | tool_count)" "$MCP_TOOL_COUNT_EXPECTED"

    # The SDK enforces the spec's Accept header; a client sending only JSON is
    # refused, which is how this surface failed its first live test.
    eq "a request without the SSE Accept is refused" \
       "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$WEBAPP_URL/api/mcp-server" \
            -H 'Content-Type: application/json' -H 'Accept: application/json' \
            -H "$AUTH" -d "$RPC")" "406"

    # ROW 10: the lever has to reach the process, not merely parse.
    if ! set_disabled "list_findings,queue_recon"; then
        bad "webapp came back with MCP_DISABLED_TOOLS set" "unhealthy" "healthy"
    else
        eq "MCP_DISABLED_TOOLS reaches the container" \
           "$(docker compose exec -T webapp printenv MCP_DISABLED_TOOLS 2>/dev/null | tr -d '\r')" \
           "list_findings,queue_recon"
        BODY_CUT="$(mcp_body -H "$AUTH")"
        # ABSENT, not advertised-and-refusing: a client that can see a tool
        # plans around it and retries.
        eq "a withdrawn tool is absent from tools/list" \
           "$(has_tool "$BODY_CUT" list_findings)" "no"
        eq "the second withdrawn tool is absent too" \
           "$(has_tool "$BODY_CUT" queue_recon)" "no"
        eq "an untouched tool is still served" \
           "$(has_tool "$BODY_CUT" graph_summary)" "yes"
        eq "exactly the named tools were withdrawn" \
           "$(printf '%s' "$BODY_CUT" | tool_count)" "$((MCP_TOOL_COUNT_EXPECTED - 2))"
    fi

    # A name matching no tool must not stop the server starting: this is an
    # emergency lever, and a typo turning a narrow withdrawal into a total
    # outage is the failure it must not have.
    if set_disabled "no_such_tool_at_all"; then
        eq "an unknown name is ignored, the surface is intact" \
           "$(mcp_body -H "$AUTH" | tool_count)" "$MCP_TOOL_COUNT_EXPECTED"
    else
        bad "an unknown name is ignored" "webapp unhealthy" "healthy"
    fi

    set_disabled "" >/dev/null 2>&1
fi

# =============================================================================
echo
echo "== ROW 3: a real request lands in the exact-match nginx block =="
# =============================================================================
# Discriminator: the mcp location carries add_header directives, which SUPPRESS
# inheritance of the server-level ones. So a response routed through it lacks
# Permissions-Policy, while anything handled by `location /api/` still has it.
# That is the trap the block exists to work around, used here as proof of which
# block ran.
DEPLOY="$REPO_ROOT/tooling/deploy/single-host"

render() {   # render <GATE_MODE> [MCP_EDGE_ALLOW_BEARER]
    ( cd "$REPO_ROOT" && \
      GATE_MODE="$1" MCP_EDGE_ALLOW_BEARER="${2:-false}" OPERATOR_ALLOW_CIDRS="0.0.0.0/0" \
      SERVER_NAME=localhost SSL_CERT_REMOTE=/c.pem SSL_KEY_REMOTE=/k.pem \
      CSP_CONNECT="'self'" CSP_HEADER_NAME=Content-Security-Policy \
      WS_AUTH_REQUEST="" REDIRECT_HOST=localhost TLS_MODE=selfsigned \
      HTTP_PORT=8081 HTTPS_PORT=8443 \
      _NGINX_MOD="$DEPLOY/modules/nginx.sh" _TMPL="$DEPLOY/nginx/redamon.conf.tmpl" \
      bash -c '
        set -uo pipefail
        is_true() { [[ "$(printf "%s" "${1:-}" | tr "[:upper:]" "[:lower:]")" == "true" || "${1:-}" == "1" ]]; }
        source "$_NGINX_MOD"
        _render_template "$_TMPL"
      ' 2>/dev/null )
}

start_nginx() {   # start_nginx <conf-file>
    docker rm -f "$NGINX_NAME" >/dev/null 2>&1 || true
    cp "$1" "$WORK/redamon.conf"
    # --network host so the config's proxy_pass 127.0.0.1:3000 reaches the
    # host-published webapp, exactly as it does on a single-host deploy.
    docker run -d --name "$NGINX_NAME" --network host \
        -v "$WORK/redamon.conf:/etc/nginx/conf.d/redamon.conf:ro" \
        -v "$WORK/snip:/etc/nginx/snippets:ro" \
        -v "$WORK/c.pem:/c.pem:ro" -v "$WORK/k.pem:/k.pem:ro" \
        -v "$WORK/htpasswd:/etc/nginx/.redamon_htpasswd:ro" \
        nginx:alpine >/dev/null 2>&1 || return 1
    for _ in $(seq 1 25); do
        curl -sk -o /dev/null "https://localhost:8443/api/health" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

hdr() {   # hdr <path> <header-name> -> the header value, or empty
    curl -sk -D - -o /dev/null "https://localhost:8443$2" 2>/dev/null \
        | tr -d '\r' | grep -i "^$1:" | head -1 | cut -d' ' -f2-
}
code() {  # code <path> [method]
    curl -sk -o /dev/null -w '%{http_code}' -X "${2:-GET}" "https://localhost:8443$1" \
        -H 'Content-Type: application/json' -H "$ACCEPT" -d "$RPC" 2>/dev/null
}

mkdir -p "$WORK/snip"
cp "$DEPLOY/nginx/snippets/security-headers.conf" "$WORK/snip/redamon-security-headers.conf" 2>/dev/null
cp "$DEPLOY/nginx/snippets/proxy-common.conf"     "$WORK/snip/redamon-proxy-common.conf"     2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1
# htpasswd: user "op", password "op" (apr1 hash), for the basic_auth pass below.
printf 'op:$apr1$xyz12345$1sQK9rn3Jp5wNBXW0dXhP0\n' > "$WORK/htpasswd"

render ip_allowlist > "$WORK/ip.conf"
if ! grep -qF 'location = /api/mcp-server {' "$WORK/ip.conf"; then
    bad "the vhost rendered with the MCP block" "absent" "an exact-match block"
elif ! start_nginx "$WORK/ip.conf"; then
    skip "nginx in front of the live webapp" "could not start (port 8443 busy, or no host networking)"
    docker logs "$NGINX_NAME" 2>&1 | tail -3 | sed 's/^/       /'
else
    # Control: a path handled by `location /api/` inherits the server headers.
    CONTROL="$(hdr Permissions-Policy /api/health)"
    if [[ -n "$CONTROL" ]]; then
        ok "control: /api/health is handled by location /api/ (has Permissions-Policy)"
        SUBJECT="$(hdr Permissions-Policy /api/mcp-server)"
        if [[ -z "$SUBJECT" ]]; then
            ok "/api/mcp-server is handled by the EXACT-MATCH block (headers not inherited)"
        else
            bad "/api/mcp-server is handled by the exact-match block" \
                "inherited server headers -> fell through to location /api/" "own add_header set"
        fi
        # The block re-emits the ones it must; losing these is the trap it works around.
        for h in Strict-Transport-Security X-Frame-Options Cache-Control; do
            V="$(hdr "$h" /api/mcp-server)"
            if [[ -n "$V" ]]; then ok "$h re-emitted on /api/mcp-server"
            else bad "$h re-emitted on /api/mcp-server" "absent" "present"; fi
        done
    else
        skip "exact-match discrimination" "no Permissions-Policy on the control path"
    fi
fi

# The gate decision, live: under basic_auth the MCP block is 403 while the rest
# of /api/ is a 401 Basic challenge. Different codes prove different blocks ran.
render basic_auth > "$WORK/basic.conf"
if start_nginx "$WORK/basic.conf"; then
    eq "basic_auth: /api/mcp-server -> 403 (closed by default)" "$(code /api/mcp-server POST)" "403"
    C="$(code /api/health GET)"
    if [[ "$C" == "401" ]]; then
        ok "basic_auth: /api/health -> 401 (different block, so the 403 was ours)"
    else
        bad "basic_auth: /api/health -> 401" "$C" "401"
    fi
else
    skip "basic_auth gate live" "nginx could not start"
fi

render basic_auth true > "$WORK/bearer.conf"
if start_nginx "$WORK/bearer.conf"; then
    C="$(code /api/mcp-server POST)"
    if [[ "$C" != "403" ]]; then
        ok "MCP_EDGE_ALLOW_BEARER=true opens the endpoint (got $C, not 403)"
    else
        bad "MCP_EDGE_ALLOW_BEARER=true opens the endpoint" "403" "not 403"
    fi
else
    skip "MCP_EDGE_ALLOW_BEARER live" "nginx could not start"
fi

echo
printf 'passed %d, failed %d, skipped %d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
