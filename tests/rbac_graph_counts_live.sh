#!/usr/bin/env bash
#
# Live check RM:p4-graph-counts (RBAC step 4.6, SH-07, NF-10): a read collaborator sees the
# owner's graph, node for node, against the LIVE stack.
#
# It seeds the matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs), a throwaway project
# rbac-graph-counts owned by rbac-member-c with a Read share (no Raw data) for rbac-member-b,
# and three synthetic Domain nodes (one.rbac.test, two.rbac.test, three.rbac.test), each with a
# Subdomain that BELONGS_TO it (the graph screen draws only connected nodes), carrying the
# owner's user_id and the project's project_id. They are written with cypher-shell in the neo4j
# container, because the agent's graph proxy refuses writes. Then, through the routes:
#   GET  /api/graph?fresh=1                 Domain and Subdomain nodes named *.rbac.test
#   GET  /api/analytics/graph-overview      the Domain and Subdomain label counts
#   POST /api/graph-views/execute           MATCH (d:Domain) RETURN d
# With sharing in force (RBAC_SHARING_ENABLED on, which needs identity and permissions on, AND
# instance_settings.sharing_policy enabled) the owner, the collaborator and an overseer
# (rbac-admin-a, Full admin) must get the same counts, 3 of each; rbac-member-a (no share) gets
# 404; the collaborator's text-to-cypher and node delete answer 403. With sharing not in force the
# owner still gets 3 of each and the collaborator 404 on every read (no share is read).
#
# The trap deletes the project's graph and runs e2e-rbac-cleanup.mjs (which removes the project,
# its share and every fixture account), even on a failure or Ctrl-C. Response bodies, passwords
# and the Neo4j password (read inside its container) are never printed.
#
# Needs the stack up (webapp on :3000, postgres, neo4j); prints SKIP and exits 0 when it is not.
# As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_graph_counts_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
DOMAINS=(one two three)

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
# flags.ts: each switch requires the one before it; then Root's policy (sharingPolicy.ts).
switch_on "${sw_identity:-}" && switch_on "${sw_permissions:-}" && switch_on "${sw_sharing:-}" \
  && [ "$policy" = true ] && IN_FORCE=1
if [ "$IN_FORCE" = 1 ]; then
  echo "== sharing in force (switches on, policy enabled): the collaborator must see the owner's counts =="
else
  echo "== sharing not in force (a switch off or the policy disabled): the collaborator must get 404 =="
fi

# ---- fixtures ---------------------------------------------------------------------------
echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in MEMBER_A_EMAIL MEMBER_B_EMAIL MEMBER_B_ID MEMBER_C_EMAIL MEMBER_C_ID ADMIN_A_EMAIL RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
OWNER_ID="${SEED[MEMBER_C_ID]}"
safe_id "$OWNER_ID" || { echo "unexpected owner id"; exit 1; }

PROJECT_ID="$( (cd "$ROOT" && docker compose exec -T -e OWNER_ID="$OWNER_ID" -e READER_ID="${SEED[MEMBER_B_ID]}" \
  -w /app webapp node --input-type=module -) <<'NODE'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const project = await prisma.project.create({
    data: { userId: process.env.OWNER_ID, name: 'rbac-graph-counts', targetDomain: 'rbac.test' },
  })
  await prisma.projectCollaborator.create({
    data: { projectId: project.id, userId: process.env.READER_ID, access: 'read', grantedById: process.env.OWNER_ID },
  })
  console.log(project.id)
} finally {
  await prisma.$disconnect()
}
NODE
)"
PROJECT_ID="$(printf '%s' "$PROJECT_ID" | tail -n 1)"
safe_id "$PROJECT_ID" || { echo "FAIL  could not create the project and its share"; PROJECT_ID=''; exit 1; }

{
  for d in "${DOMAINS[@]}"; do
    printf "CREATE (:Subdomain {name: 'www.%s.rbac.test', user_id: '%s', project_id: '%s'})-[:BELONGS_TO {user_id: '%s', project_id: '%s'}]->(:Domain {name: '%s.rbac.test', user_id: '%s', project_id: '%s'});\n" \
      "$d" "$OWNER_ID" "$PROJECT_ID" "$OWNER_ID" "$PROJECT_ID" "$d" "$OWNER_ID" "$PROJECT_ID"
  done
} | cypher > /dev/null
seeded="$(printf "MATCH (d:Domain {project_id: '%s'}) RETURN count(d) AS n;\n" "$PROJECT_ID" | cypher | tail -n 1)"
[ "$seeded" = 3 ] || { echo "FAIL  the three Domain nodes were not written (got ${seeded:-nothing})"; exit 1; }

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
call() { # jar method path [json-body] -> http code; the body lands in $TMP/body, never printed
  local jar="$1" method="$2" path="$3"
  local args=(-s -m 120 -o "$TMP/body" -w '%{http_code}' -X "$method" -b "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}
count_nodes() { # the body's graph nodes of a type named *.rbac.test
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(sum(1 for n in b.get("nodes",[]) if n.get("type")==sys.argv[2] and str(n.get("name","")).endswith(".rbac.test")))' \
    "$TMP/body" "$1" 2>/dev/null || echo "?"
}
count_label() { # the overview's count of a label
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(next((c["count"] for c in b.get("nodeCounts",[]) if c.get("label")==sys.argv[2]), 0))' \
    "$TMP/body" "$1" 2>/dev/null || echo "?"
}
counts_of() { # jar -> "graph=<d>/<s> overview=<d>/<s> execute=<d>", or the first status that was not 200
  local jar="$1" code out=""
  code="$(call "$jar" GET "/api/graph?projectId=$PROJECT_ID&fresh=1")"
  [ "$code" = 200 ] || { echo "status=$code"; return; }
  out="graph=$(count_nodes Domain)/$(count_nodes Subdomain)"
  code="$(call "$jar" GET "/api/analytics/graph-overview?projectId=$PROJECT_ID")"
  [ "$code" = 200 ] || { echo "status=$code"; return; }
  out="$out overview=$(count_label Domain)/$(count_label Subdomain)"
  code="$(call "$jar" POST /api/graph-views/execute "{\"projectId\":\"$PROJECT_ID\",\"cypherQuery\":\"MATCH (d:Domain) RETURN d\"}")"
  [ "$code" = 200 ] || { echo "status=$code"; return; }
  echo "$out execute=$(count_nodes Domain)"
}

declare -A JARS=([owner]="${SEED[MEMBER_C_EMAIL]}" [reader]="${SEED[MEMBER_B_EMAIL]}" [overseer]="${SEED[ADMIN_A_EMAIL]}" [stranger]="${SEED[MEMBER_A_EMAIL]}")
for who in owner reader overseer stranger; do
  sign_in "${JARS[$who]}" "$TMP/jar.$who" || { check "sign in as $who" 0; exit 1; }
done

EXPECTED='graph=3/3 overview=3/3 execute=3'
owner="$(counts_of "$TMP/jar.owner")"
check "the owner reads its graph: $owner" "$([ "$owner" = "$EXPECTED" ] && echo 1 || echo 0)" "expected $EXPECTED"

reader="$(counts_of "$TMP/jar.reader")"
stranger="$(counts_of "$TMP/jar.stranger")"
check "a member the project is not shared with gets 404" "$([ "$stranger" = status=404 ] && echo 1 || echo 0)" "got $stranger"
if [ "$IN_FORCE" = 1 ]; then
  check "the read collaborator gets the owner's counts: $reader" "$([ "$reader" = "$owner" ] && [ "$reader" = "$EXPECTED" ] && echo 1 || echo 0)" "owner: $owner"
  overseer="$(counts_of "$TMP/jar.overseer")"
  check "an overseer (Full admin) gets the owner's counts: $overseer" "$([ "$overseer" = "$owner" ] && echo 1 || echo 0)" "owner: $owner"
  code="$(call "$TMP/jar.reader" POST /api/agent/text-to-cypher "{\"question\":\"list domains\",\"project_id\":\"$PROJECT_ID\"}")"
  ok=0; [ "$code" = 403 ] && grep -qF 'agent:assistants' "$TMP/body" && ok=1
  check "the collaborator's text-to-cypher answers 403 agent:assistants (no model call)" "$ok" "got $code"
  code="$(call "$TMP/jar.reader" DELETE "/api/graph?projectId=$PROJECT_ID&nodeId=0")"
  ok=0; [ "$code" = 403 ] && grep -qF 'graph:edit' "$TMP/body" && ok=1
  check "the collaborator's node delete answers 403 graph:edit" "$ok" "got $code"
  left="$(printf "MATCH (d:Domain {project_id: '%s'}) RETURN count(d) AS n;\n" "$PROJECT_ID" | cypher | tail -n 1)"
  check "the owner's three Domain nodes are all still there" "$([ "$left" = 3 ] && echo 1 || echo 0)" "got ${left:-?}"
else
  check "the collaborator gets 404 while sharing is not in force" "$([ "$reader" = status=404 ] && echo 1 || echo 0)" "got $reader"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
