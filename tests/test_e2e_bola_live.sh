#!/usr/bin/env bash
#
# Authenticated two-user BOLA E2E against the LIVE stack (enforcement ON).
#
# Proves per-user isolation end-to-end with real login sessions:
#   - a standard user cannot read another user's project / graph / export
#   - a standard user's project list is scoped to themselves
#   - an admin NOT simulating sees only their own data (no see-all)
#   - an admin simulating user A sees A's project, but pasting user B's project
#     URL while simulating A is BLOCKED (the operator-reported impersonation bug)
#   - a standard user cannot call the admin-only act-as endpoint
#
# and every case of the hardening phase (RBAC Phase 1, TS-04), once for a new member
# (A and B: created by the seed, after the upgrade, holding no grant) and once for a
# legacy holder (L: the kali_terminal, shell_sessions and tunnels grants an upgrade
# records for a member who had the shared tools):
#   - shell sessions (F-01): a new member's list holds nothing of anyone else's and a
#     session or job outside it is 404 before the console; L sees what an admin sees
#   - tunnel read (F-04): the credentials answer the internal key only, L included
#   - tunnel write (F-05): a new member's change is 403 tunnels_admin_only; L's passes the
#     tunnel check (the request then fails the GitHub Enterprise host check, so nothing is
#     written or pushed to the sandbox)
#   - template overwrite (F-07): A's template cannot be replaced or deleted by B, nor by L
#     (no grant opens every template)
#   - emergency stop scope (F-06): a press by a new member or by L stops only their own
#     runs (none); a press is sent only after the scope answered "own", and no admin ever
#     presses it here (that would stop every user's runs on the shared stack)
#   - MCP reload (F-02): refused to both (an admin's reload is never sent)
#   - terminal ticket (F-03): refused to a new member, issued to L on L's own project only
#   - NF-14: a stdio MCP server test is refused to both, nothing spawned
#   - NF-15: the browser's read of a project with includeSkillContent=true carries no
#     MCP servers and no bearer (both hold a disabled server with a known fake bearer)
# Real sessions, jobs and terminals are out of reach here (manual checkpoint M4,
# tests/rbac_kali_terminal_live.sh); the escape hatch never applies to these accounts.
#
# Requires the stack up (webapp on :3000). Seeds + cleans up its own fixtures, before
# and after the run; the fixture scripts are fed to the webapp container on stdin, so
# they work against an image built before they changed. Response bodies are never printed.
#
# Run: bash tests/test_e2e_bola_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
TMP="$(mktemp -d)"
fixture_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
trap 'rm -rf "$TMP"; fixture_node e2e-bola-cleanup.mjs >/dev/null 2>&1 || true' EXIT

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ # desc expected actual
  if [ "$2" = "$3" ]; then ok "$1 -> $3"; else bad "$1 (expected $2, got $3)"; fi
}

login() { # email jarfile
  curl -s -o /dev/null -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"e2epass123\"}"
}
code() { # jarfile method url [data]
  local jar="$1" method="$2" url="$3" data="${4:-}"
  if [ -n "$data" ]; then
    curl -s -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -X "$method" \
      -H 'Content-Type: application/json' -d "$data" "$BASE$url"
  else
    curl -s -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -X "$method" "$BASE$url"
  fi
}
body() { curl -s -b "$1" "$BASE$2"; }

echo "== Removing an earlier run's fixtures =="
# A fresh account every run: the escape hatch covers only accounts older than the upgrade.
fixture_node e2e-bola-cleanup.mjs | sed 's/^/  /'
[ "${PIPESTATUS[0]}" -eq 0 ] || { echo "cleanup failed"; exit 1; }

echo "== Seeding fixtures =="
SEED="$(fixture_node e2e-bola-seed.mjs)" || { echo "seed failed"; exit 1; }
echo "$SEED"
eval "$SEED"
[ -n "${PA_ID:-}" ] && [ -n "${PB_ID:-}" ] && [ -n "${PL_ID:-}" ] && [ -n "${L_ID:-}" ] && [ -n "${MCP_BEARER:-}" ] \
  || { echo "seed did not yield the project and account ids"; exit 1; }

echo "== Logging in =="
login bola-a@e2e.local     "$TMP/a.jar"
login bola-b@e2e.local     "$TMP/b.jar"
login bola-admin@e2e.local "$TMP/admin.jar"
login bola-legacy@e2e.local "$TMP/l.jar"
# sanity: A is authenticated
check "user A session established" 200 "$(code "$TMP/a.jar" GET /api/auth/me)"
check "legacy holder L session established" 200 "$(code "$TMP/l.jar" GET /api/auth/me)"

echo "== Standard-user isolation =="
check "A reads OWN project"                200 "$(code "$TMP/a.jar" GET "/api/projects/$PA_ID")"
check "A reads B's project -> blocked"     404 "$(code "$TMP/a.jar" GET "/api/projects/$PB_ID")"
check "A reads B's graph -> blocked"       404 "$(code "$TMP/a.jar" GET "/api/graph?projectId=$PB_ID")"
check "A exports B's project -> blocked"   404 "$(code "$TMP/a.jar" GET "/api/projects/$PB_ID/export")"
check "A deletes B's project -> blocked"   404 "$(code "$TMP/a.jar" DELETE "/api/projects/$PB_ID")"
check "A purges B's chains -> blocked"     404 "$(code "$TMP/a.jar" POST "/api/projects/$PB_ID/purge-orphan-chains")"

# A's project list must contain PA and NOT PB
LIST="$(body "$TMP/a.jar" /api/projects)"
if echo "$LIST" | grep -q "$PA_ID"; then ok "A's project list includes own PA"; else bad "A's list missing PA"; fi
if echo "$LIST" | grep -q "$PB_ID"; then bad "A's project list LEAKS B's PB"; else ok "A's project list excludes B's PB"; fi

echo "== A3-cont resources (conversations / remediations / presets) =="
check "A lists B's conversations -> blocked"        404 "$(code "$TMP/a.jar" GET "/api/conversations?projectId=$PB_ID")"
check "A reads B's conversation by-session -> blocked" 404 "$(code "$TMP/a.jar" GET "/api/conversations/by-session/$CONV_B_SESSION")"
check "A lists B's remediations -> blocked"          404 "$(code "$TMP/a.jar" GET "/api/remediations?projectId=$PB_ID")"
check "A reads B's remediation by id -> blocked"     404 "$(code "$TMP/a.jar" GET "/api/remediations/$REM_B_ID")"
check "A reads B's report list -> blocked"           404 "$(code "$TMP/a.jar" GET "/api/projects/$PB_ID/reports")"
check "A reads B's graph-views -> blocked"           404 "$(code "$TMP/a.jar" GET "/api/graph-views?projectId=$PB_ID")"
check "A deletes B's preset by id -> blocked"        404 "$(code "$TMP/a.jar" DELETE "/api/presets/$PRESET_B_ID")"
# A's preset list must exclude B's preset
PLIST="$(body "$TMP/a.jar" /api/presets)"
if echo "$PLIST" | grep -q "$PRESET_B_ID"; then bad "A's preset list LEAKS B's preset"; else ok "A's preset list excludes B's preset"; fi
# Mute Rules presets: a user's own, 404 to anyone else exactly like a missing id
check "A reads B's mute-rules preset -> blocked"     404 "$(code "$TMP/a.jar" GET "/api/mute-rule-presets/$MUTE_PRESET_B_ID")"
check "A renames B's mute-rules preset -> blocked"   404 "$(code "$TMP/a.jar" PATCH "/api/mute-rule-presets/$MUTE_PRESET_B_ID" '{"name":"taken"}')"
check "A deletes B's mute-rules preset -> blocked"   404 "$(code "$TMP/a.jar" DELETE "/api/mute-rule-presets/$MUTE_PRESET_B_ID")"
MPLIST="$(body "$TMP/a.jar" /api/mute-rule-presets)"
if echo "$MPLIST" | grep -q "$MUTE_PRESET_B_ID"; then bad "A's mute-rules preset list LEAKS B's preset"; else ok "A's mute-rules preset list excludes B's preset"; fi
check "B reads OWN mute-rules preset (the 404s are real)" 200 "$(code "$TMP/b.jar" GET "/api/mute-rule-presets/$MUTE_PRESET_B_ID")"

echo "== A5 resources (scan / analytics / workspace / user-scoped) =="
check "A starts a scan on B's project -> blocked"   404 "$(code "$TMP/a.jar" POST "/api/recon/$PB_ID/start")"
check "A reads B's scan status -> blocked"          404 "$(code "$TMP/a.jar" GET "/api/recon/$PB_ID/status")"
check "A reads B's analytics vulns -> blocked"      404 "$(code "$TMP/a.jar" GET "/api/analytics/vulnerabilities?projectId=$PB_ID")"
check "A reads B's redzone secrets -> blocked"      404 "$(code "$TMP/a.jar" GET "/api/analytics/redzone/secrets?projectId=$PB_ID")"
check "A lists B's workspace files -> blocked"      404 "$(code "$TMP/a.jar" GET "/api/agent/workspace/list?projectId=$PB_ID&path=/")"
check "A reads B's MCP servers -> blocked"          403 "$(code "$TMP/a.jar" GET "/api/users/$B_ID/mcp")"
check "A reads B's attack-skills -> blocked"        403 "$(code "$TMP/a.jar" GET "/api/users/$B_ID/attack-skills")"

echo "== API usage report (sends a user's plaintext keys to providers) =="
# The seeded users have no keys, so no provider is ever called: an owner POST
# answers 400 no_keys, and a refused cross-user POST never reaches the keys.
B_USAGE_BEFORE="$(body "$TMP/b.jar" "/api/users/$B_ID/settings/api-usage")"
check "A reads B's api-usage report -> blocked"     403 "$(code "$TMP/a.jar" GET "/api/users/$B_ID/settings/api-usage")"
check "A runs B's api-usage check -> blocked"       403 "$(code "$TMP/a.jar" POST "/api/users/$B_ID/settings/api-usage" '{"overwrite":true,"ignoreRunningScans":true}')"
B_USAGE_AFTER="$(body "$TMP/b.jar" "/api/users/$B_ID/settings/api-usage")"
if [ -n "$B_USAGE_BEFORE" ] && [ "$B_USAGE_BEFORE" = "$B_USAGE_AFTER" ]; then ok "B's api-usage state unchanged by A's POST"; else bad "B's api-usage state changed (or unreadable) after A's POST"; fi
check "B reads OWN api-usage (the 403s are real)"   200 "$(code "$TMP/b.jar" GET "/api/users/$B_ID/settings/api-usage")"

echo "== Admin scoping + impersonation =="
check "admin (not simulating) reads A's project -> blocked (no see-all)" 404 "$(code "$TMP/admin.jar" GET "/api/projects/$PA_ID")"
check "admin (not simulating) reads A's api-usage -> blocked" 403 "$(code "$TMP/admin.jar" GET "/api/users/$A_ID/settings/api-usage")"
check "admin (not simulating) runs A's api-usage -> blocked"  403 "$(code "$TMP/admin.jar" POST "/api/users/$A_ID/settings/api-usage" '{"overwrite":true}')"
check "admin acts-as A"                                    200 "$(code "$TMP/admin.jar" POST /api/auth/act-as "{\"targetUserId\":\"$A_ID\"}")"
check "admin simulating A reads A's project"              200 "$(code "$TMP/admin.jar" GET "/api/projects/$PA_ID")"
check "admin simulating A pastes B's project -> BLOCKED"  404 "$(code "$TMP/admin.jar" GET "/api/projects/$PB_ID")"
check "admin simulating A reads A's api-usage"            200 "$(code "$TMP/admin.jar" GET "/api/users/$A_ID/settings/api-usage")"
check "admin simulating A reads B's api-usage -> BLOCKED" 403 "$(code "$TMP/admin.jar" GET "/api/users/$B_ID/settings/api-usage")"
check "admin stops simulating"                            200 "$(code "$TMP/admin.jar" DELETE /api/auth/act-as)"
check "admin (stopped) reads A's project -> blocked again" 404 "$(code "$TMP/admin.jar" GET "/api/projects/$PA_ID")"

echo "== Owner path still works (non-breaking) =="
check "A reads OWN analytics vulns"                 200 "$(code "$TMP/a.jar" GET "/api/analytics/vulnerabilities?projectId=$PA_ID")"
check "A reads OWN redzone secrets"                 200 "$(code "$TMP/a.jar" GET "/api/analytics/redzone/secrets?projectId=$PA_ID")"
check "A reads OWN scan status"                     200 "$(code "$TMP/a.jar" GET "/api/recon/$PA_ID/status")"
check "A lists OWN remediations"                    200 "$(code "$TMP/a.jar" GET "/api/remediations?projectId=$PA_ID")"
check "A lists OWN conversations"                   200 "$(code "$TMP/a.jar" GET "/api/conversations?projectId=$PA_ID")"
check "A lists OWN graph-views"                     200 "$(code "$TMP/a.jar" GET "/api/graph-views?projectId=$PA_ID")"
check "A reads OWN api-usage report"                200 "$(code "$TMP/a.jar" GET "/api/users/$A_ID/settings/api-usage")"
check "A runs OWN api-usage check (no keys saved)"  400 "$(code "$TMP/a.jar" POST "/api/users/$A_ID/settings/api-usage" '{}')"
# legacy agent/files download (no projectId) must NOT be blocked by the project guard
FILES_CODE="$(code "$TMP/a.jar" GET "/api/agent/files?path=/tmp/nonexistent")"
if [ "$FILES_CODE" = "400" ]; then bad "legacy agent/files (no projectId) wrongly 400-blocked"; else ok "legacy agent/files (no projectId) not project-guard-blocked -> $FILES_CODE"; fi

echo "== ws-ticket is scoped to the effective user's project =="
check "A mints a ws-ticket for OWN project"        200 "$(code "$TMP/a.jar" POST /api/agent/ws-ticket "{\"projectId\":\"$PA_ID\",\"sessionId\":\"s1\"}")"
check "A mints a ws-ticket for B's project -> blocked" 404 "$(code "$TMP/a.jar" POST /api/agent/ws-ticket "{\"projectId\":\"$PB_ID\",\"sessionId\":\"s1\"}")"

echo "== Privilege: standard user cannot impersonate =="
check "A calls admin-only act-as -> 403" 403 "$(code "$TMP/a.jar" POST /api/auth/act-as "{\"targetUserId\":\"$B_ID\"}")"

# ---- RBAC Phase 1 hardening (TS-04): each case for a new member and for a legacy holder ----
req() { # jar method url [json-body] -> http code; the body lands in $TMP/body, never printed
  local jar="$1" method="$2" url="$3"
  local args=(-s -m 60 -o "$TMP/body" -w '%{http_code}' -b "$jar" -c "$jar" -X "$method" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$url"
}
has() { grep -qF -- "$1" "$TMP/body"; }
json() { # python expression over `b` (the parsed body of the last request) -> printed value
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$TMP/body" "$1" 2>/dev/null
}
check_body() { # desc expected-code actual-code [has:<text> | lacks:<text>]...
  local desc="$1" want="$2" got="$3" why="" c
  shift 3
  [ "$got" = "$want" ] || why="expected $want, got $got"
  for c in "$@"; do
    case "$c" in
      has:*)   has "${c#has:}" || why="${why:+$why; }body lacks ${c#has:}" ;;
      lacks:*) ! has "${c#lacks:}" || why="${why:+$why; }body has ${c#lacks:}" ;;
    esac
  done
  if [ -z "$why" ]; then ok "$desc -> $got"; else bad "$desc ($why)"; fi
}
TPL_DIR='bola-e2e'   # e2e-bola-cleanup.mjs removes this folder and its rows
TPL="$TPL_DIR/x.yaml"
upload() { # jar template-id [overwrite] -> http code; uploads x.yaml into $TPL_DIR
  printf 'id: %s\ninfo:\n  name: BOLA %s\n  severity: info\n' "$2" "$2" > "$TMP/x.yaml"
  local args=(-s -m 60 -o "$TMP/body" -w '%{http_code}' -X POST -b "$1" -c "$1" -H "Origin: $BASE"
    -F "file=@$TMP/x.yaml;filename=x.yaml" -F "subdir=$TPL_DIR")
  [ "${3:-}" = overwrite ] && args+=(-F overwrite=true)
  curl "${args[@]}" "$BASE/api/nuclei-templates"
}
SESSION_COUNTS="[len(b.get(k) or []) for k in ('sessions', 'jobs', 'non_msf_sessions')]"

echo "== F-01 shell sessions are per project (HD-01, HD-02) =="
c="$(req "$TMP/a.jar" GET /api/agent/sessions)"; counts="$(json "$SESSION_COUNTS")"
if [ "$c" = 200 ] && [ "$counts" = "[0, 0, 0]" ]; then
  ok "new member A's session list holds no session, job or listener of anyone else -> 200"
else
  bad "new member A's session list (expected 200 and [0, 0, 0] sessions/jobs/listeners, got $c ${counts:-unparsed})"
fi
check_body "new member A kills a session outside its view -> 404 before the console" 404 "$(req "$TMP/a.jar" POST /api/agent/sessions/999999/kill)"
check_body "new member A kills a job -> 404 before the console"                     404 "$(req "$TMP/a.jar" POST /api/agent/jobs/999999/kill)"
# The legacy shell_sessions grant opens every session and job: L's list is the admin's.
# The agent may refresh its list between the two reads, so a mismatch is read again once.
same=0
for _ in 1 2; do
  lc="$(req "$TMP/l.jar" GET /api/agent/sessions)"; lcounts="$(json "$SESSION_COUNTS")"
  ac="$(req "$TMP/admin.jar" GET /api/agent/sessions)"; acounts="$(json "$SESSION_COUNTS")"
  if [ "$lc" = 200 ] && [ "$ac" = 200 ] && [ -n "$lcounts" ] && [ "$lcounts" = "$acounts" ]; then same=1; break; fi
  sleep 2
done
if [ "$same" = 1 ]; then ok "legacy holder L's session list is the admin's (every session, job and listener: $lcounts)"
else bad "legacy holder L's session list (got $lc ${lcounts:-unparsed}, the admin's $ac ${acounts:-unparsed})"; fi
check_body "legacy holder L kills a session the console does not hold -> 404" 404 "$(req "$TMP/l.jar" POST /api/agent/sessions/999999/kill)"

echo "== F-04 / F-05 the tunnel is the admins' (HD-05, HD-06) =="
TUNNEL_CHANGE='{"chiselServerUrl":"http://127.0.0.1:9","githubEnterpriseHost":"127.0.0.1"}'
check_body "new member A reads the tunnel credentials -> 404"                  404 "$(req "$TMP/a.jar" GET /api/global/tunnel-config)"
check_body "legacy holder L reads the tunnel credentials -> 404 (internal key only)" 404 "$(req "$TMP/l.jar" GET /api/global/tunnel-config)"
check_body "new member B changes the tunnel -> 403 tunnels_admin_only"         403 "$(req "$TMP/b.jar" PUT "/api/users/$B_ID/settings" "$TUNNEL_CHANGE")" has:tunnels_admin_only
check_body "legacy holder L passes the tunnel check (then refused by the GitHub Enterprise host check)" 400 \
  "$(req "$TMP/l.jar" PUT "/api/users/$L_ID/settings" "$TUNNEL_CHANGE")" "has:GitHub Enterprise Host" lacks:tunnels_admin_only
check_body "B's settings: tunnel controls not offered, nothing written"        200 "$(req "$TMP/b.jar" GET "/api/users/$B_ID/settings")" \
  'has:"canManageTunnels":false' 'lacks:"chiselServerUrl":"http://127.0.0.1:9"'
check_body "L's settings: tunnel controls offered, nothing written"            200 "$(req "$TMP/l.jar" GET "/api/users/$L_ID/settings")" \
  'has:"canManageTunnels":true' 'lacks:"chiselServerUrl":"http://127.0.0.1:9"'

echo "== F-07 a Nuclei template is its owner's (HD-08) =="
check_body "new member A uploads $TPL"                                         200 "$(upload "$TMP/a.jar" bola-x)"
check_body "new member B overwrites A's template -> 409"                       409 "$(upload "$TMP/b.jar" bola-x-by-b overwrite)" 'has:"code":"template_owned_by_other"'
check_body "legacy holder L overwrites A's template -> 409 (no grant opens every template)" 409 \
  "$(upload "$TMP/l.jar" bola-x-by-l overwrite)" 'has:"code":"template_owned_by_other"'
check_body "new member B deletes A's template -> 403"                          403 "$(req "$TMP/b.jar" DELETE "/api/nuclei-templates?path=$TPL")" has:platform:nuclei_templates_all
check_body "legacy holder L deletes A's template -> 403"                       403 "$(req "$TMP/l.jar" DELETE "/api/nuclei-templates?path=$TPL")" has:platform:nuclei_templates_all
check_body "B's template list leaves A's out"                                  200 "$(req "$TMP/b.jar" GET /api/nuclei-templates)" "lacks:\"$TPL\""
check_body "L's template list leaves A's out"                                  200 "$(req "$TMP/l.jar" GET /api/nuclei-templates)" "lacks:\"$TPL\""
c="$(req "$TMP/a.jar" GET /api/nuclei-templates)"
if [ "$c" = 200 ] && [ "$(json "[(t['id'], t['ownership']) for t in b['templates'] if t['path'] == '$TPL']")" = "[('bola-x', 'own')]" ]; then
  ok "A's template is still A's own file, unreplaced -> 200"
else
  bad "A's template after the refused overwrites (expected A's own bola-x, got $c)"
fi
check_body "A deletes its own template"                                        200 "$(req "$TMP/a.jar" DELETE "/api/nuclei-templates?path=$TPL")" "lacks:\"$TPL\""

echo "== F-06 a member's PAUSE ALL stops only their own runs (HD-07) =="
estop() { # jar who: a press is sent only once the scope answered "own"
  local c
  c="$(req "$1" GET /api/agent/emergency-stop-all)"
  check_body "$2 asks whose runs PAUSE ALL stops -> own" 200 "$c" 'has:"scope":"own"'
  if [ "$c" = 200 ] && has '"scope":"own"'; then
    check_body "$2 presses PAUSE ALL -> its own runs only (none running)" 200 "$(req "$1" POST /api/agent/emergency-stop-all)" \
      'has:"scope":"own"' 'has:"stopped":0'
  else
    bad "$2 presses PAUSE ALL: not sent, its scope was not own (a press could stop every user's runs)"
  fi
}
estop "$TMP/a.jar" "new member A"
estop "$TMP/l.jar" "legacy holder L (no grant opens the instance-wide stop)"

echo "== F-02 the shared agent's MCP reload is the admins' (HD-03) =="
check_body "new member A reloads the agent's MCP tools -> 403"   403 "$(req "$TMP/a.jar" POST /api/mcp/reload '{}')"
check_body "legacy holder L reloads the agent's MCP tools -> 403" 403 "$(req "$TMP/l.jar" POST /api/mcp/reload '{}')"

echo "== F-03 a terminal ticket needs the terminal grant (HD-04, HD-25) =="
check_body "new member A asks a Kali terminal ticket for its own project -> 403" 403 \
  "$(req "$TMP/a.jar" POST /api/agent/ws-ticket "{\"projectId\":\"$PA_ID\",\"sessionId\":\"bola-ws\",\"socket\":\"kali-terminal\"}")" \
  has:platform:kali_terminal 'lacks:"ticket"'
check_body "legacy holder L gets a Kali terminal ticket for its own project" 200 \
  "$(req "$TMP/l.jar" POST /api/agent/ws-ticket "{\"projectId\":\"$PL_ID\",\"sessionId\":\"bola-ws\",\"socket\":\"kali-terminal\"}")" \
  'has:"ticket":"'
check_body "legacy holder L asks a terminal ticket for A's project -> 404" 404 \
  "$(req "$TMP/l.jar" POST /api/agent/ws-ticket "{\"projectId\":\"$PA_ID\",\"sessionId\":\"bola-ws\",\"socket\":\"kali-terminal\"}")" \
  'lacks:"ticket"'

echo "== NF-14 a member's stdio MCP server is never run =="
STDIO_TEST='{"server":{"id":"bola-probe","name":"bola probe","enabled":true,"transport":"stdio","command":"id"}}'
check_body "new member A tests a stdio MCP server -> 403, nothing spawned"   403 "$(req "$TMP/a.jar" POST /api/mcp/test "$STDIO_TEST")" has:stdio_admin_only
check_body "legacy holder L tests a stdio MCP server -> 403, nothing spawned" 403 "$(req "$TMP/l.jar" POST /api/mcp/test "$STDIO_TEST")" has:stdio_admin_only

echo "== NF-15 the browser never gets the raw MCP servers =="
check_body "new member A's project read with includeSkillContent: no MCP servers, no bearer" 200 \
  "$(req "$TMP/a.jar" GET "/api/projects/$PA_ID?includeSkillContent=true")" lacks:userMcpServers "lacks:$MCP_BEARER"
check_body "legacy holder L's project read with includeSkillContent: no MCP servers, no bearer" 200 \
  "$(req "$TMP/l.jar" GET "/api/projects/$PL_ID?includeSkillContent=true")" lacks:userMcpServers "lacks:$MCP_BEARER"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
