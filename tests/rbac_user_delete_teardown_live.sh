#!/usr/bin/env bash
#
# Live re-run of experiment E1 (RBAC step 1.7, HD-11, F-10) against the LIVE stack: an
# admin deletes an account whose project holds an engagement authorization, a graph node
# and a recon output file. Before step 1.7 that answered 500 P2003 and deleted nothing;
# now each project goes through the project-delete teardown first, so the delete answers
# 200 and leaves no user, project, authorization row, graph node or file behind, while
# the authorization record survives in engagement_authorization_archive with the reason
# user_deleted, and the user.delete audit row lists the project.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local) plus the
# throwaway rbac-teardown-owner@e2e.local, its project rbac-teardown-project (target
# rbac.test), one authorization record, one Domain node and one recon_<id>.json. The
# trap removes all of them, the archive row included, even on a failure or Ctrl-C, then
# runs e2e-rbac-cleanup.mjs. Response bodies, passwords and the Neo4j password (read
# inside its container) are never printed.
#
# Needs the stack up (webapp on :3000, postgres, neo4j, recon-orchestrator); prints SKIP
# and exits 0 when it is not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_user_delete_teardown_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
OWNER_EMAIL='rbac-teardown-owner@e2e.local'
OWNER_PASSWORD='rbac-teardown-owner-passphrase'
OUTPUT_DIR='/app/recon/output'

health="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
if [ "$health" != 200 ]; then
  echo "SKIP: RedAmon webapp not answering at $BASE/api/health (got ${health:-nothing})"
  exit 0
fi
for svc in webapp postgres neo4j recon-orchestrator; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done

TMP="$(mktemp -d)"
CLEANED_UP=0
OWNER_ID=''
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
orch_sh() { # command [args]: a shell command in the recon-orchestrator container
  (cd "$ROOT" && docker compose exec -T recon-orchestrator sh -c "$1" sh "${@:2}") 2>/dev/null
}
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  if [ -n "$PROJECT_ID" ] && safe_id "$PROJECT_ID"; then
    # A failed run leaves the project and its authorization: delete the record through
    # the trigger's one exemption (the archiving flag for this project), as the route
    # does, so e2e-rbac-cleanup.mjs can remove the project and the account.
    printf "begin;\nselect set_config('redamon.archiving_project', '%s', true);\ndelete from engagement_authorizations where project_id = '%s';\ncommit;\ndelete from engagement_authorization_archive where project_id = '%s';\n" \
      "$PROJECT_ID" "$PROJECT_ID" "$PROJECT_ID" | db_sql > /dev/null || echo "  authorization cleanup failed for $PROJECT_ID"
    printf "MATCH (n {project_id: '%s'}) DETACH DELETE n;\n" "$PROJECT_ID" | cypher > /dev/null || true
    orch_sh 'rm -f "$1/recon_$2.json"' "$OUTPUT_DIR" "$PROJECT_ID" || true
  fi
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in ADMIN_A_EMAIL ADMIN_A_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
call() { # jar method path [json-body] -> http code; the body lands in $TMP/body, never printed
  local jar="$1" method="$2" path="$3"
  local args=(-s -m 120 -o "$TMP/body" -w '%{http_code}' -X "$method" -b "$jar" -c "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}

ADMIN_JAR="$TMP/jar.admin"
printf '{"email":"%s","password":"%s"}' "${SEED[ADMIN_A_EMAIL]}" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
code="$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$ADMIN_JAR" -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/login.json")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-admin-a answered $code"; exit 1; }

# ---- the account, its project, an authorization, a graph node, a file -----------------
echo "== Fixtures of the account to delete =="
code="$(call "$ADMIN_JAR" POST /api/users \
  "{\"name\":\"RBAC Teardown Owner\",\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PASSWORD\",\"role\":\"standard\"}")"
OWNER_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("id",""))' "$TMP/body" 2>/dev/null || true)"
ok=0; [ "$code" = 201 ] && safe_id "$OWNER_ID" && ok=1
check "create the account -> $code" "$ok"
[ "$ok" = 1 ] || exit 1

PROJECT_ID="$( (cd "$ROOT" && docker compose exec -T -e OWNER_ID="$OWNER_ID" -w /app webapp node --input-type=module -) <<'NODE'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const project = await prisma.project.create({
    data: { userId: process.env.OWNER_ID, name: 'rbac-teardown-project', targetDomain: 'rbac.test' },
  })
  await prisma.engagementAuthorization.create({
    data: {
      projectId: project.id, documentSha256: '0'.repeat(64), documentKind: 'internal_ticket',
      issuedAt: new Date(), recordedVia: 'ui', recordedByUserId: process.env.OWNER_ID,
      summary: 'synthetic RBAC teardown fixture',
    },
  })
  console.log(project.id)
} finally {
  await prisma.$disconnect()
}
NODE
)"
PROJECT_ID="$(printf '%s' "$PROJECT_ID" | tail -n 1)"
safe_id "$PROJECT_ID" || { check "create the project and its authorization" 0; exit 1; }

printf "MERGE (d:Domain {name: 'rbac-teardown.rbac.test', user_id: '%s', project_id: '%s'}) RETURN count(d) AS n;\n" \
  "$OWNER_ID" "$PROJECT_ID" | cypher > /dev/null
orch_sh 'printf "{}" > "$1/recon_$2.json"' "$OUTPUT_DIR" "$PROJECT_ID"

count_sql() { db_sql | tail -n 1; }
graph_nodes() { printf "MATCH (n {project_id: '%s'}) RETURN count(n) AS n;\n" "$PROJECT_ID" | cypher | tail -n 1; }
file_there() { orch_sh 'test -e "$1/recon_$2.json" && echo yes || echo no' "$OUTPUT_DIR" "$PROJECT_ID"; }
authorizations() { printf "select count(*) from engagement_authorizations where project_id = '%s';\n" "$PROJECT_ID" | count_sql; }

ok=0
[ "$(authorizations)" = 1 ] && [ "$(graph_nodes)" = 1 ] && [ "$(file_there)" = yes ] && ok=1
check "fixtures in place: one authorization, one graph node, one recon file" "$ok"
[ "$ok" = 1 ] || exit 1

# ---- E1: the admin deletes the account -------------------------------------------------
echo "== Delete the account =="
code="$(call "$ADMIN_JAR" DELETE "/api/users/$OWNER_ID")"
ok=0; [ "$code" = 200 ] && ok=1
check "DELETE /api/users/<owner> answers 200 (E1 answered 500 P2003)" "$ok" "got $code"

n="$(printf "select count(*) from users where id = '%s';\n" "$OWNER_ID" | count_sql)"
ok=0; [ "$n" = 0 ] && ok=1; check "the account is gone" "$ok" "rows: ${n:-?}"
n="$(printf "select count(*) from projects where id = '%s' or user_id = '%s';\n" "$PROJECT_ID" "$OWNER_ID" | count_sql)"
ok=0; [ "$n" = 0 ] && ok=1; check "no project of the account is left" "$ok" "rows: ${n:-?}"
n="$(authorizations)"
ok=0; [ "$n" = 0 ] && ok=1; check "no live authorization row is left" "$ok" "rows: ${n:-?}"
n="$(printf "select count(*) || ':' || coalesce(string_agg(archived_reason, ','), '') from engagement_authorization_archive where project_id = '%s';\n" "$PROJECT_ID" | count_sql)"
ok=0; [ "$n" = '1:user_deleted' ] && ok=1
check "the authorization record is archived, reason user_deleted" "$ok" "got: ${n:-?}"
n="$(graph_nodes)"
ok=0; [ "$n" = 0 ] && ok=1; check "no graph node of the project is left" "$ok" "nodes: ${n:-?}"
n="$(file_there)"
ok=0; [ "$n" = no ] && ok=1; check "the project's recon output file is gone" "$ok" "present: ${n:-?}"

printf "select action || chr(9) || coalesce(before::text, '') || chr(9) || coalesce(after::text, '') from audit_log where target_type = 'user' and target_id = '%s' and action like 'user.delete%%' order by created_at, id;\n" "$OWNER_ID" \
  | db_sql > "$TMP/rows" || true
mapfile -t got < <(cut -f1 "$TMP/rows")
ok=0
[ "${got[*]:-}" = user.delete ] && grep -qF "\"projectsDeleted\": [\"$PROJECT_ID\"]" "$TMP/rows" \
  && grep -qF '"ownedProjectCount": 1' "$TMP/rows" && ok=1
check "one user.delete row: ownedProjectCount 1, projectsDeleted names the project" "$ok" "got: ${got[*]:-none}"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
