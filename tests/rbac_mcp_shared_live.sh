#!/usr/bin/env bash
#
# Live check RM:p4-mcp-shared (RBAC step 4.10, SH-42; E2E P4-07): an MCP token reaches a project
# shared with its user only when it opted in; then only the read tools answer there, the tenant is
# the owner, and a revoked share fails the next call. Against the LIVE stack.
#
# It seeds the matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs: rbac-PSHARED owned by
# rbac-member-c, shared at Read with rbac-viewer and rbac-viewer-tmp and with Raw data & files with
# rbac-viewer-raw) and one Domain node on PSHARED under the owner's tenant (cypher-shell in the neo4j
# container), signs the collaborators in and mints their tokens through the token route (the
# password step included). Then, over POST /api/mcp-server:
#   viewer, token without the opt-in:   list_projects has no PSHARED; graph_summary is Project not found
#   viewer, opted-in token:             list_projects has PSHARED with myAccess read; graph_summary
#                                        answers; update_recon_settings and a question are refused
#                                        with their reason; raw Cypher needs Raw data
#   viewer-raw, opted-in token:         raw Cypher returns the owner's Domain node
#   viewer-tmp, opted-in token:         answers, then its share row is deleted: Project not found
#   the opt-in without the password:    the mint answers 401
# With sharing not in force (RBAC_SHARING_ENABLED off, or Root's policy disabled) every collaborator
# token, opted in or not, lists no PSHARED and gets Project not found on it.
#
# Needs the stack up (webapp on :3000, postgres, neo4j) and MCP_SERVER_ENABLED=true in the webapp
# (a local install sets it); prints SKIP and exits 0 otherwise. The trap deletes the Domain node and
# runs e2e-rbac-cleanup.mjs (the fixture accounts go, and their tokens with them), even on a failure
# or Ctrl-C. Token values, passwords and response bodies are never printed.
#
# As a *_live.sh it is never in the gate.
# Run:  bash tests/rbac_mcp_shared_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
MARK="rbac-mcp-shared-$$.test"

health="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
if [ "$health" != 200 ]; then
  echo "SKIP: RedAmon webapp not answering at $BASE/api/health (got ${health:-nothing})"
  exit 0
fi
for svc in webapp postgres neo4j; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done
mcp_on="$(cd "$ROOT" && docker compose exec -T webapp sh -c 'printf "%s" "${MCP_SERVER_ENABLED:-}"' 2>/dev/null)"
case "$(printf '%s' "$mcp_on" | tr '[:upper:]' '[:lower:]')" in
  true|1|yes) ;;
  *) echo "SKIP: MCP_SERVER_ENABLED is not on in the webapp"; exit 0 ;;
esac

TMP="$(mktemp -d)"
CLEANED_UP=0
PROJECT_ID=''
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
webapp_node() { (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"; }
db_sql() {
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
cypher() {
  (cd "$ROOT" && docker compose exec -T neo4j \
    sh -c 'cypher-shell -u neo4j -p "${NEO4J_AUTH#neo4j/}" --format plain') 2>/dev/null
}
switch_on() {
  case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in true|1|yes) return 0 ;; *) return 1 ;; esac
}

cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  if [ -n "$PROJECT_ID" ] && safe_id "$PROJECT_ID"; then
    printf "MATCH (d:Domain {project_id: '%s', name: '%s'}) DETACH DELETE d;\n" "$PROJECT_ID" "$MARK" | cypher > /dev/null || true
  fi
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

env="$(cd "$ROOT" && docker compose exec -T webapp sh -c \
  'printf "%s|%s|%s" "${RBAC_IDENTITY_ENABLED:-}" "${RBAC_PERMISSIONS_ENABLED:-}" "${RBAC_SHARING_ENABLED:-}"' 2>/dev/null)"
IFS='|' read -r sw_identity sw_permissions sw_sharing <<< "$env"
policy="$(printf "select coalesce(sharing_policy->>'enabled', 'false') from instance_settings limit 1;\n" | db_sql | tail -n 1)"
IN_FORCE=0
switch_on "${sw_identity:-}" && switch_on "${sw_permissions:-}" && switch_on "${sw_sharing:-}" \
  && [ "$policy" = true ] && IN_FORCE=1
if [ "$IN_FORCE" = 1 ]; then
  echo "== sharing in force: an opted-in token reads the shared project, and only reads it =="
else
  echo "== sharing not in force: no collaborator token reaches the shared project =="
fi

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in MEMBER_C_ID PSHARED_ID VIEWER_EMAIL VIEWER_ID VIEWER_RAW_EMAIL VIEWER_RAW_ID VIEWER_TMP_EMAIL VIEWER_TMP_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
PROJECT_ID="${SEED[PSHARED_ID]}"
OWNER_ID="${SEED[MEMBER_C_ID]}"
safe_id "$PROJECT_ID" && safe_id "$OWNER_ID" || { echo "unexpected seed ids"; PROJECT_ID=''; exit 1; }
printf "CREATE (:Domain {name: '%s', user_id: '%s', project_id: '%s'});\n" "$MARK" "$OWNER_ID" "$PROJECT_ID" | cypher > /dev/null
seeded="$(printf "MATCH (d:Domain {project_id: '%s', name: '%s'}) RETURN count(d) AS n;\n" "$PROJECT_ID" "$MARK" | cypher | tail -n 1)"
[ "$seeded" = 1 ] || { echo "FAIL  the Domain node was not written (got ${seeded:-nothing})"; exit 1; }

PASS=0; FAIL=0
check() { if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi; }
sign_in() { # email jar
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  [ "$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json")" = 200 ]
}
mint() { # jar user-id opt-in(true|false) with-password(1|0) out-file -> http code; the plaintext lands in out-file
  python3 - "$1" "$2" "$3" "$4" "${SEED[RBAC_PASSWORD]}" > "$TMP/mint.json" <<'PY'
import json, sys
_, _jar, _uid, opt, with_pw, pw = sys.argv
body = {"name": "rbac-mcp-shared", "scopes": ["recon:read", "graph:cypher", "recon:settings"], "expiresInDays": 30,
        "includeSharedProjects": opt == "true"}
if with_pw == "1":
    body["password"] = pw
print(json.dumps(body))
PY
  local code
  code="$(curl -s -m 30 -o "$TMP/mint.out" -w '%{http_code}' -b "$1" -X POST "$BASE/api/users/$2/mcp-tokens" \
    -H "Origin: $BASE" -H 'Content-Type: application/json' --data-binary @"$TMP/mint.json")"
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("plaintext",""))' "$TMP/mint.out" > "$5" 2>/dev/null || : > "$5"
  echo "$code"
}
tool() { # token-file tool-name json-args -> writes the tool result text to $TMP/result, prints error|ok
  python3 - "$2" "$3" > "$TMP/rpc.json" <<'PY'
import json, sys
print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": sys.argv[1], "arguments": json.loads(sys.argv[2])}}))
PY
  curl -s -m 120 -o "$TMP/rpc.out" -X POST "$BASE/api/mcp-server" -H "Authorization: Bearer $(cat "$1")" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary @"$TMP/rpc.json"
  python3 - "$TMP/rpc.out" "$TMP/result" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
for line in raw.splitlines():
    if line.startswith("data: "):
        raw = line[6:]
        break
try:
    res = json.loads(raw)["result"]
    open(sys.argv[2], "w").write("".join(c.get("text", "") for c in res.get("content", [])))
    print("error" if res.get("isError") else "ok")
except Exception:
    open(sys.argv[2], "w").write("")
    print("unparsed")
PY
}
lists_shared() { # -> yes|no, from the last list_projects result
  python3 -c 'import json,sys; p=json.load(open(sys.argv[1])).get("projects",[]); print("yes" if any(x.get("id")==sys.argv[2] for x in p) else "no")' \
    "$TMP/result" "$PROJECT_ID" 2>/dev/null || echo "?"
}
shared_level() {
  python3 -c 'import json,sys; p=json.load(open(sys.argv[1])).get("projects",[]); print(next(((x.get("myAccess") or {}).get("level","-") for x in p if x.get("id")==sys.argv[2]), "-"))' \
    "$TMP/result" "$PROJECT_ID" 2>/dev/null || echo "?"
}

for who in VIEWER VIEWER_RAW VIEWER_TMP; do
  sign_in "${SEED[${who}_EMAIL]}" "$TMP/jar.$who" || { check "sign in as $who" 0; exit 1; }
done
P="{\"projectId\":\"$PROJECT_ID\"}"

code="$(mint "$TMP/jar.VIEWER" "${SEED[VIEWER_ID]}" false 1 "$TMP/tok.plain")"
check "the viewer mints a token without the opt-in" "$([ "$code" = 201 ] && [ -s "$TMP/tok.plain" ] && echo 1 || echo 0)" "got $code"
code="$(mint "$TMP/jar.VIEWER" "${SEED[VIEWER_ID]}" true 1 "$TMP/tok.opted")"
check "the viewer mints an opted-in token with the password" "$([ "$code" = 201 ] && [ -s "$TMP/tok.opted" ] && echo 1 || echo 0)" "got $code"
code="$(mint "$TMP/jar.VIEWER_RAW" "${SEED[VIEWER_RAW_ID]}" true 1 "$TMP/tok.raw")"
check "the raw viewer mints an opted-in token" "$([ "$code" = 201 ] && echo 1 || echo 0)" "got $code"
code="$(mint "$TMP/jar.VIEWER_TMP" "${SEED[VIEWER_TMP_ID]}" true 1 "$TMP/tok.tmp")"
check "the tmp viewer mints an opted-in token" "$([ "$code" = 201 ] && echo 1 || echo 0)" "got $code"
code="$(mint "$TMP/jar.VIEWER" "${SEED[VIEWER_ID]}" true 0 "$TMP/tok.nopw")"
check "the opt-in without the password is refused (401)" "$([ "$code" = 401 ] && echo 1 || echo 0)" "got $code"

r="$(tool "$TMP/tok.plain" list_projects '{}')"
check "token without the opt-in: list_projects has no shared project" "$([ "$r" = ok ] && [ "$(lists_shared)" = no ] && echo 1 || echo 0)" "got $r"
r="$(tool "$TMP/tok.plain" graph_summary "$P")"
check "token without the opt-in: graph_summary on it is Project not found" "$([ "$r" = error ] && grep -qx 'Project not found' "$TMP/result" && echo 1 || echo 0)" "got $r"

if [ "$IN_FORCE" = 1 ]; then
  r="$(tool "$TMP/tok.opted" list_projects '{}')"
  check "opted-in token: list_projects has the shared project at read" "$([ "$r" = ok ] && [ "$(lists_shared)" = yes ] && [ "$(shared_level)" = read ] && echo 1 || echo 0)" "got $r, level $(shared_level)"
  r="$(tool "$TMP/tok.opted" graph_summary "$P")"
  check "opted-in token: graph_summary answers on the shared project" "$([ "$r" = ok ] && echo 1 || echo 0)" "got $r"
  r="$(tool "$TMP/tok.opted" update_recon_settings "{\"projectId\":\"$PROJECT_ID\",\"settings\":{\"naabuEnabled\":false}}")"
  check "opted-in token: a write tool is refused for its Read access" "$([ "$r" = error ] && grep -q 'Read access' "$TMP/result" && echo 1 || echo 0)" "got $r"
  r="$(tool "$TMP/tok.opted" query_graph "{\"projectId\":\"$PROJECT_ID\",\"question\":\"which domains exist?\"}")"
  check "opted-in token: a natural-language question is refused (the owner's model key)" "$([ "$r" = error ] && grep -q 'model key' "$TMP/result" && echo 1 || echo 0)" "got $r"
  r="$(tool "$TMP/tok.opted" query_graph "{\"projectId\":\"$PROJECT_ID\",\"cypher\":\"MATCH (d:Domain) RETURN d\"}")"
  check "opted-in token without Raw data: raw Cypher is refused" "$([ "$r" = error ] && grep -q 'Raw data' "$TMP/result" && echo 1 || echo 0)" "got $r"
  r="$(tool "$TMP/tok.raw" query_graph "{\"projectId\":\"$PROJECT_ID\",\"cypher\":\"MATCH (d:Domain) RETURN d\"}")"
  check "opted-in token with Raw data: raw Cypher returns the owner's node" "$([ "$r" = ok ] && grep -qF "$MARK" "$TMP/result" && echo 1 || echo 0)" "got $r"
  r="$(tool "$TMP/tok.tmp" graph_summary "$P")"
  check "the tmp viewer's token answers before the revoke" "$([ "$r" = ok ] && echo 1 || echo 0)" "got $r"
  printf "delete from project_collaborators where project_id = '%s' and user_id = '%s';\n" "$PROJECT_ID" "${SEED[VIEWER_TMP_ID]}" | db_sql > /dev/null
  r="$(tool "$TMP/tok.tmp" graph_summary "$P")"
  check "revoked share: the next call is Project not found" "$([ "$r" = error ] && grep -qx 'Project not found' "$TMP/result" && echo 1 || echo 0)" "got $r"
else
  for t in opted raw tmp; do
    r="$(tool "$TMP/tok.$t" list_projects '{}')"
    check "$t token: list_projects has no shared project while sharing is not in force" "$([ "$r" = ok ] && [ "$(lists_shared)" = no ] && echo 1 || echo 0)" "got $r"
    r="$(tool "$TMP/tok.$t" graph_summary "$P")"
    check "$t token: graph_summary on it is Project not found" "$([ "$r" = error ] && grep -qx 'Project not found' "$TMP/result" && echo 1 || echo 0)" "got $r"
  done
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
