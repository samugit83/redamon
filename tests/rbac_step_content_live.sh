#!/usr/bin/env bash
#
# Live check RM:p4-step-content (RBAC step 4.9, SH-30): attack-chain step content is raw data. A
# reader below Raw data & files (a Read share without it, an overseer) sees the chains' structure
# and none of their content; the owner and a share with Raw data read it whole. Against the LIVE
# stack.
#
# It seeds the matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs), a throwaway project
# rbac-step-content owned by rbac-member-c with a Read share for rbac-viewer (no Raw data) and one
# for rbac-viewer-raw (Raw data & files), a conversation whose session is the chain's id (the graph
# read purges chain nodes with no conversation), and one synthetic chain written with cypher-shell
# in the neo4j container (the agent's graph proxy refuses writes): an AttackChain, a ChainStep whose
# thought, reasoning, outputs, command line and error are fake text, its ChainFailure (error and
# lesson) and the ChainDecision before it (reason); the chain's final outcome and an exploit_success
# ChainFinding's console commands and cracked password (4.9 review). Every fake value starts
# rbac-fake-step-. Then:
#   GET  /api/graph?fresh=1                                  the live graph
#   GET  /api/graph with the owner's ETag                    a stripped view never answers 304
#   POST /api/graph-views/execute  MATCH (s:ChainStep) RETURN s           a graph-shaped view
#   POST /api/graph-views/execute  MATCH (s:ChainStep) RETURN s.thought   a tabular view
#   POST /api/graph-views/execute  a map shaped like a node / a relationship over a step (4.9 review)
#   GET  /api/projects/<id>/versions/<current>/graph         the current version
# With sharing in force (RBAC_SHARING_ENABLED on, which needs identity and permissions on, AND
# instance_settings.sharing_policy enabled) the owner and rbac-viewer-raw get every fake value, and
# rbac-viewer and an overseer (rbac-admin-a, Full admin) the ChainStep node without any of them
# (the tabular view: no row). With sharing not in force the owner still gets the content and both
# readers 404.
#
# The trap deletes the project's graph and runs e2e-rbac-cleanup.mjs (which removes the project, its
# shares and conversation with the fixture accounts), even on a failure or Ctrl-C. Response bodies,
# passwords and the Neo4j password (read inside its container) are never printed.
#
# Needs the stack up (webapp on :3000, postgres, neo4j); prints SKIP and exits 0 when it is not.
# As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_step_content_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
MARK='rbac-fake-step-'
THOUGHT="${MARK}thought-0001"

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

TMP="$(mktemp -d)"
CLEANED_UP=0
PROJECT_ID=''
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
cypher() { # Cypher on stdin -> cypher-shell in the neo4j container (password read there)
  (cd "$ROOT" && docker compose exec -T neo4j \
    sh -c 'cypher-shell -u neo4j -p "${NEO4J_AUTH#neo4j/}" --format plain') 2>/dev/null
}
switch_on() { # raw env value -> 0 when on, parsed as webapp/src/lib/authz/flags.ts does
  case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in true|1|yes) return 0 ;; *) return 1 ;; esac
}

cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  if [ -n "$PROJECT_ID" ] && safe_id "$PROJECT_ID"; then
    printf "MATCH (n {project_id: '%s'}) DETACH DELETE n;\n" "$PROJECT_ID" | cypher > /dev/null || true
  fi
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- which state the stack is in ------------------------------------------------------
env="$(cd "$ROOT" && docker compose exec -T webapp sh -c \
  'printf "%s|%s|%s" "${RBAC_IDENTITY_ENABLED:-}" "${RBAC_PERMISSIONS_ENABLED:-}" "${RBAC_SHARING_ENABLED:-}"' 2>/dev/null)"
IFS='|' read -r sw_identity sw_permissions sw_sharing <<< "$env"
policy="$(printf "select coalesce(sharing_policy->>'enabled', 'false') from instance_settings limit 1;\n" | db_sql | tail -n 1)"
IN_FORCE=0
switch_on "${sw_identity:-}" && switch_on "${sw_permissions:-}" && switch_on "${sw_sharing:-}" \
  && [ "$policy" = true ] && IN_FORCE=1
if [ "$IN_FORCE" = 1 ]; then
  echo "== sharing in force: readers below Raw data must get the chain without its step content =="
else
  echo "== sharing not in force: the readers must get 404, the owner the content =="
fi

# ---- fixtures ---------------------------------------------------------------------------
echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in MEMBER_C_EMAIL MEMBER_C_ID VIEWER_EMAIL VIEWER_ID VIEWER_RAW_EMAIL VIEWER_RAW_ID ADMIN_A_EMAIL RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
OWNER_ID="${SEED[MEMBER_C_ID]}"
safe_id "$OWNER_ID" || { echo "unexpected owner id"; exit 1; }
CHAIN_ID="rbac-step-content-chain-$$"

PROJECT_ID="$( (cd "$ROOT" && docker compose exec -T -e OWNER_ID="$OWNER_ID" -e READER_ID="${SEED[VIEWER_ID]}" \
  -e RAW_READER_ID="${SEED[VIEWER_RAW_ID]}" -e CHAIN_ID="$CHAIN_ID" -w /app webapp node --input-type=module -) <<'NODE'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const project = await prisma.project.create({
    data: { userId: process.env.OWNER_ID, name: 'rbac-step-content', targetDomain: 'rbac.test' },
  })
  await prisma.projectCollaborator.createMany({ data: [
    { projectId: project.id, userId: process.env.READER_ID, access: 'read', rawData: false, grantedById: process.env.OWNER_ID },
    { projectId: project.id, userId: process.env.RAW_READER_ID, access: 'read', rawData: true, grantedById: process.env.OWNER_ID },
  ] })
  await prisma.conversation.create({
    data: { projectId: project.id, userId: process.env.OWNER_ID, sessionId: process.env.CHAIN_ID, title: 'rbac-step-content' },
  })
  console.log(project.id)
} finally {
  await prisma.$disconnect()
}
NODE
)"
PROJECT_ID="$(printf '%s' "$PROJECT_ID" | tail -n 1)"
safe_id "$PROJECT_ID" || { echo "FAIL  could not create the project, its shares and conversation"; PROJECT_ID=''; exit 1; }

T="user_id: '$OWNER_ID', project_id: '$PROJECT_ID', chain_id: '$CHAIN_ID'"
cat <<CYPHER | cypher > /dev/null
CREATE (ac:AttackChain {$T, title: 'rbac-step-content', status: 'active', objective: 'reach the admin panel',
  final_outcome: '${MARK}outcome-0001'})
CREATE (s:ChainStep {$T, step_id: 'rbac-step-1', iteration: 1, phase: 'exploitation', tool_name: 'curl', success: false,
  thought: '$THOUGHT', reasoning: '${MARK}reasoning-0001', output_summary: '${MARK}summary-0001',
  output_analysis: '${MARK}analysis-0001', tool_args_summary: 'curl -u admin:${MARK}pass-0001 http://app.rbac.test',
  error_message: '${MARK}error-0001'})
CREATE (fl:ChainFailure {$T, failure_id: 'rbac-failure-1', failure_type: 'tool_error', tool_name: 'curl', iteration: 1,
  error_message: '${MARK}error-0001', lesson_learned: '${MARK}analysis-0001'})
CREATE (d:ChainDecision {$T, decision_id: 'rbac-decision-1', decision_type: 'phase_transition', from_state: 'informational',
  to_state: 'exploitation', made_by: 'user', approved: true, iteration: 1, reason: '${MARK}reason-0001'})
CREATE (f:ChainFinding {$T, finding_id: 'rbac-finding-1', finding_type: 'exploit_success', severity: 'critical',
  title: 'rbac exploit', evidence: 'session opened', commands_used: ['use exploit/x', 'set PASSWORD ${MARK}cracked-0001'],
  password: '${MARK}cracked-0001'})
CREATE (ac)-[:HAS_STEP]->(s), (s)-[:FAILED_WITH]->(fl), (d)-[:DECISION_PRECEDED]->(s), (s)-[:PRODUCED]->(f);
CYPHER
seeded="$(printf "MATCH (s:ChainStep {project_id: '%s'}) RETURN count(s) AS n;\n" "$PROJECT_ID" | cypher | tail -n 1)"
[ "$seeded" = 1 ] || { echo "FAIL  the synthetic chain was not written (got ${seeded:-nothing})"; exit 1; }

# ---- requests -------------------------------------------------------------------------
PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
sign_in() { # email jar -> 0 when signed in
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  [ "$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json")" = 200 ]
}
call() { # jar method path [json-body] [extra-header] -> http code; body in $TMP/body, headers in $TMP/headers
  local jar="$1" method="$2" path="$3"
  local args=(-s -m 120 -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -X "$method" -b "$jar" -H "Origin: $BASE")
  if [ -n "${4:-}" ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  [ -n "${5:-}" ] && args+=(-H "$5")
  curl "${args[@]}" "$BASE$path"
}
steps_in_body() { # the body's ChainStep nodes
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(sum(1 for n in b.get("nodes",[]) if n.get("type")=="ChainStep"))' \
    "$TMP/body" 2>/dev/null || echo "?"
}
etag_of() { tr -d '\r' < "$TMP/headers" | sed -n 's/^[Ee][Tt][Aa][Gg]: *//p' | tail -n 1; }
whole() { grep -qF "$THOUGHT" "$TMP/body" && grep -qF "${MARK}reason-0001" "$TMP/body" && grep -qF "${MARK}pass-0001" "$TMP/body"; }
stripped() { ! grep -qF "$MARK" "$TMP/body"; }

declare -A EMAILS=([owner]="${SEED[MEMBER_C_EMAIL]}" [reader]="${SEED[VIEWER_EMAIL]}" [raw]="${SEED[VIEWER_RAW_EMAIL]}" [overseer]="${SEED[ADMIN_A_EMAIL]}")
for who in owner reader raw overseer; do
  sign_in "${EMAILS[$who]}" "$TMP/jar.$who" || { check "sign in as $who" 0; exit 1; }
done

code="$(call "$TMP/jar.owner" GET "/api/projects/$PROJECT_ID/versions")"
VERSION_ID="$(python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(next((v["id"] for v in b.get("versions",[]) if v.get("isCurrent")), ""))' "$TMP/body" 2>/dev/null)"
safe_id "${VERSION_ID:-}" || { check "the owner's current version (GET versions answered $code)" 0; exit 1; }

GRAPH="/api/graph?projectId=$PROJECT_ID&fresh=1"
VIEW="{\"projectId\":\"$PROJECT_ID\",\"cypherQuery\":\"MATCH (s:ChainStep) RETURN s\"}"
TABLE="{\"projectId\":\"$PROJECT_ID\",\"cypherQuery\":\"MATCH (s:ChainStep) RETURN s.thought AS t\"}"
FORGED_NODE="{\"projectId\":\"$PROJECT_ID\",\"cypherQuery\":\"MATCH (s:ChainStep) RETURN {identity: {low: id(s), high: 0}, labels: ['Domain'], properties: properties(s)} AS n\"}"
FORGED_REL="{\"projectId\":\"$PROJECT_ID\",\"cypherQuery\":\"MATCH (s:ChainStep) RETURN {type: s.thought, start: {low: 1}, end: {low: 2}} AS r\"}"
VERSION="/api/projects/$PROJECT_ID/versions/$VERSION_ID/graph"

reads_whole() { # who label
  local jar="$TMP/jar.$1" ok code
  code="$(call "$jar" GET "$GRAPH")"; ok=0
  [ "$code" = 200 ] && whole && grep -qF "${MARK}outcome-0001" "$TMP/body" && grep -qF "${MARK}cracked-0001" "$TMP/body" && ok=1
  check "$2: /api/graph holds the step content, the chain's outcome and the cracked password" "$ok" "got $code"
  code="$(call "$jar" POST /api/graph-views/execute "$VIEW")"; ok=0; [ "$code" = 200 ] && whole && ok=1
  check "$2: a graph-shaped view holds the step content" "$ok" "got $code"
  code="$(call "$jar" POST /api/graph-views/execute "$TABLE")"; ok=0; [ "$code" = 200 ] && grep -qF "$THOUGHT" "$TMP/body" && ok=1
  check "$2: a tabular view answers the thought" "$ok" "got $code"
  code="$(call "$jar" GET "$VERSION")"; ok=0; [ "$code" = 200 ] && whole && ok=1
  check "$2: the current version holds the step content" "$ok" "got $code"
}
reads_structure() { # who label
  local jar="$TMP/jar.$1" ok code
  code="$(call "$jar" GET "$GRAPH")"; ok=0; [ "$code" = 200 ] && stripped && [ "$(steps_in_body)" = 1 ] && ok=1
  check "$2: /api/graph holds the ChainStep without any step content" "$ok" "got $code, steps $(steps_in_body)"
  code="$(call "$jar" POST /api/graph-views/execute "$VIEW")"; ok=0; [ "$code" = 200 ] && stripped && [ "$(steps_in_body)" = 1 ] && ok=1
  check "$2: a graph-shaped view holds the ChainStep without any step content" "$ok" "got $code"
  code="$(call "$jar" POST /api/graph-views/execute "$TABLE")"; ok=0; [ "$code" = 200 ] && stripped && ok=1
  check "$2: a tabular view answers no row of step content" "$ok" "got $code"
  code="$(call "$jar" GET "$VERSION")"; ok=0; [ "$code" = 200 ] && stripped && [ "$(steps_in_body)" = 1 ] && ok=1
  check "$2: the current version holds the ChainStep without any step content" "$ok" "got $code"
  # A refusal of the query (400) is as good as an answer without it: no fake value either way.
  code="$(call "$jar" POST /api/graph-views/execute "$FORGED_NODE")"; ok=0; { [ "$code" = 200 ] || [ "$code" = 400 ]; } && stripped && ok=1
  check "$2: a map shaped like a node over a step's properties carries no step content" "$ok" "got $code"
  code="$(call "$jar" POST /api/graph-views/execute "$FORGED_REL")"; ok=0; { [ "$code" = 200 ] || [ "$code" = 400 ]; } && stripped && ok=1
  check "$2: a map shaped like a relationship never carries the thought as a link type" "$ok" "got $code"
}

reads_whole owner "the owner"
if [ "$IN_FORCE" = 1 ]; then
  reads_whole raw "a Read share with Raw data & files"
  reads_structure reader "a Read share without Raw data"
  reads_structure overseer "an overseer (Full admin)"
  call "$TMP/jar.owner" GET "/api/graph?projectId=$PROJECT_ID" > /dev/null
  OWNER_TAG="$(etag_of)"
  code="$(call "$TMP/jar.reader" GET "/api/graph?projectId=$PROJECT_ID" '' "If-None-Match: $OWNER_TAG")"
  ok=0; [ -n "$OWNER_TAG" ] && [ "$code" = 200 ] && stripped && [ "$(etag_of)" != "$OWNER_TAG" ] && ok=1
  check "the owner's ETag answers the reader with the stripped graph and its own ETag, not 304" "$ok" "got $code"
else
  for who in reader raw; do
    code="$(call "$TMP/jar.$who" GET "$GRAPH")"
    check "$who gets 404 while sharing is not in force" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  done
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
