#!/usr/bin/env bash
# =============================================================================
# LIVE replay of GHSA-j3r5-x2gg-2hgv against the running stack: "Authenticated users
# can run arbitrary MCP stdio commands in the shared agent container".
#
# Up to 7.7.2 a standard member's POST /api/mcp/test with a stdio draft and no userId
# reached the agent, which ran the command as root and answered the stderr of a re-run
# that inherited the agent's environment: the reporter read INTERNAL_API_KEY back.
#
# A throwaway member M sends the reporter's body with a real login cookie. The child
# also creates a marker in the agent container's /tmp, so "refused" is proven to spawn
# nothing, and an administrator's identical request (which must run it) proves the
# marker would catch a spawn and that the child it starts reads no agent credential.
# Also checked: saving the server, a server naming an agent variable as its bearer, and
# a stdio server already saved for M never reaching the agent's settings fetch.
#
# Skips cleanly (exit 0) when the stack is down. Creates and DELETES its own users and
# marker. No answer body or credential is printed.
#
#   bash tests/test_ghsa_j3r5_live.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
WEB=http://localhost:3000

if ! curl -sf http://localhost:8090/health >/dev/null 2>&1 || ! curl -sf "$WEB/api/health" >/dev/null 2>&1; then
  echo "[skip] stack not up (agent :8090 / webapp :3000 unreachable) - skipping GHSA-j3r5 live replay"
  exit 0
fi

FAIL=0; pass=0; total=0
chk() { total=$((total+1)); if [ "$1" = "$2" ]; then echo "PASS  $3"; pass=$((pass+1)); else echo "FAIL  $3  (got '$1' want '$2')"; FAIL=1; fi; }
psql_q() { docker compose exec -T postgres psql -U redamon -d redamon -tA -c "$1" 2>/dev/null | tr -d '[:space:]'; }

PW="GhsaJ3r5-$(openssl rand -hex 8)"
PWHASH="$(docker compose exec -T webapp node -e "process.stdout.write(require('bcryptjs').hashSync(process.argv[1],10))" "$PW" | tr -d '\r\n')"
seed_user() { # $1=email $2=role -> the new user id
  local uid="u_e2e_$(openssl rand -hex 8)"
  docker compose exec -T postgres psql -U redamon -d redamon -tA \
    -c "INSERT INTO users (id,name,email,updated_at,password,role) VALUES ('$uid','e2e','$1',CURRENT_TIMESTAMP,'$PWHASH','$2');" >/dev/null
  echo "$uid"
}
login() { # $1=email $2=cookie jar -> the HTTP status
  curl -s -o /dev/null -w '%{http_code}' -c "$2" -X POST "$WEB/api/auth/login" \
    -H 'Content-Type: application/json' -d "{\"email\":\"$1\",\"password\":\"$PW\"}"
}

M_EMAIL="e2e_j3r5_m_$(openssl rand -hex 4)@redamon.local"; M_ID="$(seed_user "$M_EMAIL" standard)"
A_EMAIL="e2e_j3r5_a_$(openssl rand -hex 4)@redamon.local"; A_ID="$(seed_user "$A_EMAIL" admin)"
M_JAR=$(mktemp); A_JAR=$(mktemp); BODY=$(mktemp)
MARK="/tmp/ghsa-j3r5-$(openssl rand -hex 6)"
cleanup() {
  docker compose exec -T agent rm -f "$MARK" >/dev/null 2>&1
  docker compose exec -T postgres psql -U redamon -d redamon -tA \
    -c "DELETE FROM users WHERE id IN ('$M_ID','$A_ID');" >/dev/null 2>&1
  rm -f "$M_JAR" "$A_JAR" "$BODY"
}
trap cleanup EXIT

spawned() { if docker compose exec -T agent test -e "$MARK"; then echo yes; else echo no; fi; }
answer_code() { grep -o '"code":"[a-z_]*"' "$BODY" | head -1 | cut -d'"' -f4; }
# Whether the last answer holds the agent's INTERNAL_API_KEY; the key stays in this pipe.
holds_master_key() {
  docker compose exec -T agent printenv INTERNAL_API_KEY | tr -d '\r\n' | {
    read -r k || true
    if [ -n "$k" ] && grep -qF -f <(printf '%s' "$k") "$BODY"; then echo yes; else echo no; fi
  }
}
send() { # $1=jar $2=path $3=json -> the HTTP status; the answer lands in $BODY
  curl -s -o "$BODY" -w '%{http_code}' -b "$1" -X POST "$WEB$2" -H 'Content-Type: application/json' -H "Origin: $WEB" -d "$3"
}

# The advisory's draft, verbatim, after one added statement that records the spawn.
CODE="import os,sys;open('$MARK','a').write('ran');sys.stderr.write(os.environ.get('INTERNAL_API_KEY','missing'));sys.exit(1)"
POC_SERVER="{\"id\":\"diag\",\"name\":\"diag\",\"transport\":\"stdio\",\"command\":\"python3\",\"args\":[\"-c\",\"$CODE\"]}"

echo "#### GHSA-j3r5-x2gg-2hgv: a member's stdio draft ####"
chk "$(login "$M_EMAIL" "$M_JAR")" 200 "member signs in"
chk "$(login "$A_EMAIL" "$A_JAR")" 200 "administrator signs in"

c=$(send "$M_JAR" /api/mcp/test "{\"server\":$POC_SERVER}")
chk "$c $(answer_code)" "403 stdio_admin_only" "the reporter's request (member, no userId) -> 403 stdio_admin_only"
chk "$(holds_master_key)" no "the member's answer holds no INTERNAL_API_KEY"
chk "$(spawned)" no "the agent started nothing"

c=$(send "$M_JAR" /api/mcp/test "{\"server\":$POC_SERVER,\"userId\":\"$M_ID\"}")
chk "$c $(answer_code)" "403 stdio_admin_only" "the same, naming their own userId -> 403"
c=$(send "$M_JAR" /api/mcp/test "{\"server\":$POC_SERVER,\"userId\":\"$A_ID\"}")
chk "$c" 403 "the same, naming the administrator's userId -> 403"
chk "$(spawned)" no "still nothing started"

c=$(send "$M_JAR" "/api/users/$M_ID/mcp" "$POC_SERVER")
chk "$c $(answer_code)" "403 stdio_admin_only" "the member saving it -> 403 stdio_admin_only"
chk "$(psql_q "SELECT count(*) FROM user_settings WHERE user_id='$M_ID' AND mcp_servers::text LIKE '%\"diag\"%';")" 0 \
  "nothing saved for the member"

c=$(send "$M_JAR" /api/mcp/test '{"server":{"id":"collector","name":"collector","transport":"streamable_http","url":"http://127.0.0.1:9/mcp","auth":{"type":"bearer","token_env_var":"INTERNAL_API_KEY"}}}')
chk "$c $(answer_code)" "422 token_env_var_refused" "a draft naming INTERNAL_API_KEY as its bearer -> 422"

# A stdio server already saved for the member (as a save before the fix left it), beside an
# HTTP one, and the settings fetch the agent makes at each run, with the internal key.
POC_SQL="${POC_SERVER//\'/\'\'}"
docker compose exec -T postgres psql -U redamon -d redamon -tA -c "INSERT INTO user_settings (id,user_id,updated_at,mcp_servers) VALUES ('us_e2e_$(openssl rand -hex 8)','$M_ID',CURRENT_TIMESTAMP,'[$POC_SQL,{\"id\":\"web-j3r5\",\"name\":\"web\",\"transport\":\"streamable_http\",\"url\":\"http://127.0.0.1:9/mcp\"}]'::jsonb) ON CONFLICT (user_id) DO UPDATE SET mcp_servers=EXCLUDED.mcp_servers;" >/dev/null
P_ID="p_e2e_$(openssl rand -hex 8)"
docker compose exec -T postgres psql -U redamon -d redamon -tA \
  -c "INSERT INTO projects (id,user_id,name,ownership_token,updated_at) VALUES ('$P_ID','$M_ID','e2e',gen_random_uuid()::text,CURRENT_TIMESTAMP);" >/dev/null
c=$(docker compose exec -T webapp printenv INTERNAL_API_KEY | tr -d '\r\n' | sed 's/^/header = "X-Internal-Key: /; s/$/"/' \
  | curl -s -o "$BODY" -w '%{http_code}' -K - "$WEB/api/projects/$P_ID?includeSkillContent=true")
chk "$c" 200 "the agent's settings fetch for the member's project -> 200"
seen=no; grep -q '"web-j3r5"' "$BODY" && seen=yes
chk "$seen" yes "it carries the member's HTTP server"
seen=no; grep -q '"diag"' "$BODY" && seen=yes
chk "$seen" no "it leaves out the member's saved stdio server"

echo
echo "#### control: the administrator's identical request runs ####"
c=$(send "$A_JAR" /api/mcp/test "{\"server\":$POC_SERVER}")
chk "$c" 200 "the administrator's request reaches the agent -> 200"
chk "$(spawned)" yes "the agent started the command (the marker catches a spawn)"
key=$(holds_master_key)
chk "$key" no "the administrator's answer holds no INTERNAL_API_KEY"
said=no; grep -q 'stderr: missing' "$BODY" && said=yes
chk "$said" yes "the child read no INTERNAL_API_KEY (stderr: missing)"
# Another outcome (a busy agent can answer a timeout) is shown so it can be told apart,
# and only once the answer is known to hold no master key.
[ "$said" = no ] && [ "$key" = no ] && echo "      agent said: $(grep -o '"error":"[^"]*"' "$BODY" | head -1 | cut -c1-300)"

echo
echo "GHSA-j3r5 live: $pass/$total"
if [ "$FAIL" -eq 0 ]; then echo ">> GHSA-j3r5 LIVE ALL GREEN"; else echo ">> GHSA-j3r5 LIVE FAILURES ABOVE"; fi
exit $FAIL
