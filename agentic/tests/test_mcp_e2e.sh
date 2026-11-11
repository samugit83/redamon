#!/usr/bin/env bash
# End-to-end smoke test for the MCP plugin feature.
#
# Exercises the full chain: webapp HTTP CRUD + zod validation → DB write →
# webapp triggers agent /mcp/reload → agent re-registers TOOL_REGISTRY +
# MultiServerMCPClient → /mcp/manifest reflects the change.
#
# Pre-conditions: docker compose up; user with id `cmnxhb92m0000qp01u89ic4x5`
# exists; INTERNAL_API_KEY env var is set inside webapp.
#
# Run from repo root:  bash agentic/tests/test_mcp_e2e.sh

set -euo pipefail

# Helper: red/green dots, fail loudly on the first miss.
ok()   { echo -e "\033[32m✓\033[0m $*"; }
fail() { echo -e "\033[31m✗\033[0m $*"; exit 1; }

# Resolve the internal API key from the webapp container so we don't need
# the caller to know it.
KEY=$(docker compose exec -T webapp printenv INTERNAL_API_KEY 2>/dev/null | tr -d '\r')
USER=$(docker compose exec -T postgres psql -U redamon -d redamon -t -c "select id from users limit 1;" 2>/dev/null | xargs)
[ -n "$KEY" ] || fail "INTERNAL_API_KEY missing in webapp"
[ -n "$USER" ] || fail "no user found in DB"
ok "bootstrap: KEY/USER resolved (user=$USER)"

WEBAPP="http://localhost:3000"
AGENT="http://localhost:8090"

# Cleanup any leftover from prior runs.
curl -s -X DELETE -H "x-internal-key: $KEY" \
  "$WEBAPP/api/users/$USER/mcp/e2e_test_srv" >/dev/null || true

# 1) Baseline: agent reports system MCPs. The agent's /mcp/* routes take the
#    master key only (step 1.9).
manifest_baseline=$(curl -s -H "x-internal-key: $KEY" "$AGENT/mcp/manifest")
sys_count=$(echo "$manifest_baseline" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["system_server_ids"]))')
[ "$sys_count" = "5" ] || fail "expected 5 system server ids, got $sys_count"
ok "baseline: 5 system MCP servers loaded"

# 2) Add a user MCP via webapp HTTP.
add_resp=$(curl -s -X POST -H "x-internal-key: $KEY" -H 'Content-Type: application/json' \
  "$WEBAPP/api/users/$USER/mcp" -d '{
    "id":"e2e_test_srv",
    "name":"E2E test",
    "description":"Created by test_mcp_e2e.sh",
    "enabled":true,
    "transport":"sse",
    "url":"http://kali-sandbox:8004/sse",
    "default_phases":["informational","exploitation"],
    "tools":[{
      "name":"e2e_check_tool",
      "purpose":"unit-test only",
      "when_to_use":"never in prod",
      "args_format":"\"x\":\"y\"",
      "description":"Used by test_mcp_e2e.sh"
    }]
  }')
echo "$add_resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("server",{}).get("id")=="e2e_test_srv", f"unexpected: {d}"' \
  || fail "add returned unexpected payload: $add_resp"
ok "create: user MCP server e2e_test_srv created"

# Give the async reload a beat.
sleep 3

# 3) Verify agent's manifest now lists the user server.
manifest_after_add=$(curl -s -H "x-internal-key: $KEY" "$AGENT/mcp/manifest")
ids=$(echo "$manifest_after_add" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(s["id"] for s in d["servers"]))')
echo "$ids" | grep -q 'e2e_test_srv' || fail "agent manifest missing e2e_test_srv: $ids"
ok "agent reload: e2e_test_srv visible in /mcp/manifest"

# 4) Verify the manifest tool entry is in the prompt registry (read via the
#    agent's own state — through the /mcp/manifest body the tool is listed).
tool_count=$(echo "$manifest_after_add" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=next(s for s in d["servers"] if s["id"]=="e2e_test_srv"); print(len(s["tools"]))')
[ "$tool_count" = "1" ] || fail "expected 1 tool in e2e_test_srv, got $tool_count"
ok "manifest: e2e_check_tool registered"

# 5) The webapp /api/mcp/manifest is a signed-in account's own servers (step 1.9):
#    it no longer proxies the agent, and the internal key alone is no account.
webapp_manifest_status=$(curl -s -o /dev/null -w '%{http_code}' -H "x-internal-key: $KEY" "$WEBAPP/api/mcp/manifest")
[ "$webapp_manifest_status" = "401" ] || fail "webapp manifest answered $webapp_manifest_status without a session"
ok "webapp manifest: needs a signed-in account (401 for the internal key alone)"

# 6) Update: enable=false, expect manifest to still list it but with enabled=false.
upd_resp=$(curl -s -X PUT -H "x-internal-key: $KEY" -H 'Content-Type: application/json' \
  "$WEBAPP/api/users/$USER/mcp/e2e_test_srv" -d '{
    "id":"e2e_test_srv","name":"E2E test","description":"updated","enabled":false,
    "transport":"sse","url":"http://kali-sandbox:8004/sse",
    "default_phases":["informational"],
    "tools":[{
      "name":"e2e_check_tool","purpose":"x","when_to_use":"y",
      "args_format":"\"x\":\"y\"","description":"d"
    }]
  }')
echo "$upd_resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=d["server"]; assert s["enabled"] is False' \
  || fail "update did not flip enabled to false: $upd_resp"
sleep 2
ok "update: enabled flipped to false (write succeeded)"

# 7) Reject schema-invalid update (missing when_to_use on a tool).
bad_resp=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "x-internal-key: $KEY" -H 'Content-Type: application/json' \
  "$WEBAPP/api/users/$USER/mcp/e2e_test_srv" -d '{
    "id":"e2e_test_srv","name":"x","transport":"sse","url":"http://kali-sandbox:8004/sse",
    "tools":[{"name":"t","purpose":"x","when_to_use":"","args_format":"x","description":"d"}]
  }')
[ "$bad_resp" = "400" ] || fail "expected 400 on invalid update, got $bad_resp"
ok "validation: malformed tool spec rejected with 400"

# 8) Reject system-id collision.
collide_resp=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "x-internal-key: $KEY" -H 'Content-Type: application/json' \
  "$WEBAPP/api/users/$USER/mcp" -d '{
    "id":"nmap","name":"colliding","transport":"sse","url":"http://x/y","tools":[]
  }')
[ "$collide_resp" = "400" ] || fail "expected 400 on system id collision, got $collide_resp"
ok "validation: system id collision rejected"

# 9) Test endpoint: returns ok=false on unreachable URL.
unreach=$(curl -s -X POST -H 'Content-Type: application/json' \
  -H "x-internal-key: $KEY" \
  "$WEBAPP/api/mcp/test" -d '{
    "id":"oops","name":"oops","transport":"streamable_http","enabled":true,
    "url":"http://nope.invalid:65535/mcp","tools":[]
  }')
echo "$unreach" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["ok"] is False' \
  || fail "test endpoint should return ok=false: $unreach"
ok "test: unreachable URL returns ok=false"

# 10) Cleanup: delete and verify removed.
curl -s -X DELETE -H "x-internal-key: $KEY" \
  "$WEBAPP/api/users/$USER/mcp/e2e_test_srv" >/dev/null
sleep 2
final=$(curl -s "$AGENT/mcp/manifest" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(s["id"] for s in d["servers"]))')
echo "$final" | grep -q 'e2e_test_srv' && fail "e2e_test_srv still present after delete: $final"
ok "delete: e2e_test_srv removed from agent manifest"

echo
echo -e "\033[32mAll e2e checks passed.\033[0m"
