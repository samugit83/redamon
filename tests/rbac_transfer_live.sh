#!/usr/bin/env bash
#
# Live check E2E-P5-08 (RBAC step 5.12, SH-15, DV-15, DV-40): a project's owner offers it to a
# collaborator with their password, the collaborator accepts with theirs, and the project moves
# everywhere at once, against the LIVE stack (webapp, agent, Postgres, Neo4j).
#
# It seeds the matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs) and a throwaway project
# rbac-transfer owned by rbac-member-c ("A" of the matrix row) with a Read share for rbac-member-b
# ("B"), the owner's consent to spend the project's credentials, a schedule of A's, a fake CypherFix
# GitHub token, and synthetic graph nodes under A (Domain rbac-transfer-<i>.test, written through the
# agent's own driver). Then, through the routes:
#   GET  /api/projects/[id]/transfer            A's view (owner), B's (recipient), member-a's (404)
#   POST /api/projects/[id]/transfer            A offers, first without the password (refused)
#   POST /api/projects/[id]/transfer/accept     B accepts, first with a wrong password (refused)
#   GET  /api/projects/transfers                B's banner feed: the offer, then the re-pick list
# With write sharing in force (identity, permissions, sharing and the write sharing switch on, and
# instance_settings.sharing_policy enabled at maxLevel write): B owns the project, A is a co-owner
# with Manage, B's share is gone, A's schedule paused (ownership_transferred), the consent cleared,
# the token cleared and listed for B to re-pick, every synthetic node under B and none under A, the
# offer completed with its audit rows, and a second accept finds no offer. With write sharing not in
# force: every transfer route answers 404.
#
# The trap runs e2e-rbac-cleanup.mjs (the fixture accounts and their projects, which take the offer,
# shares, schedule and policy with them) and deletes the synthetic nodes, even on a failure or
# Ctrl-C. Response bodies and passwords are never printed.
#
# Needs the stack up (webapp on :3000, postgres, redamon-agent, redamon-neo4j) with the webapp and
# the agent built from step 5.12b or later; prints SKIP and exits 0 when it is not. As a *_live.sh it
# is never in the gate.
#
# Run:  bash tests/rbac_transfer_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
NODES=5

health="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
if [ "$health" != 200 ]; then
  echo "SKIP: RedAmon webapp not answering at $BASE/api/health (got ${health:-nothing})"
  exit 0
fi
for svc in webapp postgres; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done
for c in redamon-agent redamon-neo4j; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || { echo "SKIP: container $c is not running"; exit 0; }
done

TMP="$(mktemp -d)"
CLEANED_UP=0
PROJECT_ID=""
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
graph() { # op project [owner] -> runs in the agent with its own Neo4j driver; prints one value
  docker exec -i -e OP="$1" -e PID="$2" -e OWNER="${3:-}" -e NODES="$NODES" redamon-agent python3 - <<'PY' 2>/dev/null
import os
from neo4j import GraphDatabase
driver = GraphDatabase.driver(os.environ["NEO4J_URI"], auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]))
op, pid, owner = os.environ["OP"], os.environ["PID"], os.environ.get("OWNER", "")
with driver.session() as s:
    if op == "seed":
        for i in range(int(os.environ["NODES"])):
            s.run("MERGE (d:Domain {name: $n, user_id: $u, project_id: $p}) SET d.updated_at = datetime()",
                  n=f"rbac-transfer-{i}.test", u=owner, p=pid)
        print("ok")
    elif op == "count":
        print(s.run("MATCH (n {project_id: $p, user_id: $u}) RETURN count(n) AS c", p=pid, u=owner).single()["c"])
    elif op == "drop":
        s.run("MATCH (n {project_id: $p}) DETACH DELETE n", p=pid)
        print("ok")
driver.close()
PY
}
switch_on() { # raw env value -> 0 when on, parsed as webapp/src/lib/authz/flags.ts does
  case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in true|1|yes) return 0 ;; *) return 1 ;; esac
}

cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  if [ -n "$PROJECT_ID" ]; then graph drop "$PROJECT_ID" >/dev/null || echo "  graph cleanup failed: MATCH (n {project_id: '$PROJECT_ID'}) DETACH DELETE n"; fi
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- which state the stack is in ------------------------------------------------------
env="$(cd "$ROOT" && docker compose exec -T webapp sh -c \
  'printf "%s|%s|%s|%s" "${RBAC_IDENTITY_ENABLED:-}" "${RBAC_PERMISSIONS_ENABLED:-}" "${RBAC_SHARING_ENABLED:-}" "${RBAC_SHARING_WRITE_ENABLED:-}"' 2>/dev/null)"
IFS='|' read -r sw_identity sw_permissions sw_sharing sw_write <<< "$env"
policy="$(printf "select coalesce(sharing_policy->>'enabled', 'false') || '|' || coalesce(sharing_policy->>'maxLevel', 'write') from instance_settings limit 1;\n" | db_sql | tail -n 1)"
IN_FORCE=0
switch_on "${sw_identity:-}" && switch_on "${sw_permissions:-}" && switch_on "${sw_sharing:-}" && switch_on "${sw_write:-}" \
  && [ "$policy" = 'true|write' ] && IN_FORCE=1
if [ "$IN_FORCE" = 1 ]; then
  echo "== write sharing in force: offer, accept, the project moves everywhere =="
else
  echo "== write sharing not in force (a switch off, or the policy disabled or at read): every transfer route 404 =="
fi

# ---- fixtures ---------------------------------------------------------------------------
echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in MEMBER_A_EMAIL MEMBER_B_EMAIL MEMBER_B_ID MEMBER_C_EMAIL MEMBER_C_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
OWNER_ID="${SEED[MEMBER_C_ID]}"
TAKER_ID="${SEED[MEMBER_B_ID]}"
safe_id "$OWNER_ID" && safe_id "$TAKER_ID" || { echo "unexpected fixture ids"; exit 1; }

ids="$( (cd "$ROOT" && docker compose exec -T -e OWNER_ID="$OWNER_ID" -e TAKER_ID="$TAKER_ID" \
  -w /app webapp node --input-type=module -) <<'NODE'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const owner = process.env.OWNER_ID, taker = process.env.TAKER_ID
  const project = await prisma.project.create({
    data: { userId: owner, name: 'rbac-transfer', targetDomain: 'rbac.test', cypherfixGithubToken: 'ghp_rbacLiveFakeToken000000000000000000' },
  })
  await prisma.projectCollaborator.create({ data: { projectId: project.id, userId: taker, access: 'read', grantedById: owner } })
  await prisma.projectAccessPolicy.create({ data: { projectId: project.id, ownerCredentialConsentAt: new Date(), ownerCredentialConsentById: owner } })
  const schedule = await prisma.scanSchedule.create({
    data: { projectId: project.id, userId: owner, label: 'rbac-transfer nightly', mode: 'interval', intervalMinutes: 1440, enabled: true, nextRunAt: new Date(Date.now() + 86_400_000) },
  })
  console.log(`${project.id} ${schedule.id}`)
} finally {
  await prisma.$disconnect()
}
NODE
)"
read -r PROJECT_ID SCHEDULE_ID <<< "$(printf '%s' "$ids" | tail -n 1)"
for v in "${PROJECT_ID:-}" "${SCHEDULE_ID:-}"; do
  safe_id "$v" || { echo "FAIL  could not create the project, its share and schedule"; PROJECT_ID=""; exit 1; }
done
[ "$(graph seed "$PROJECT_ID" "$OWNER_ID")" = ok ] || { echo "FAIL  could not write the synthetic graph nodes"; exit 1; }

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
  local args=(-s -m 600 -o "$TMP/body" -w '%{http_code}' -X "$method" -b "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}
body_field() { # dotted path into the JSON body -> its value (or ?)
  python3 -c 'import json,sys
b=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    b=b.get(k) if isinstance(b,dict) else (b[int(k)] if isinstance(b,list) and k.isdigit() and int(k)<len(b) else None)
print(json.dumps(b))' "$TMP/body" "$1" 2>/dev/null || echo "?"
}
with_password() { # extra-json -> the body with the fixture password (written to a file, never printed)
  python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["stepUpPassword"]=sys.argv[2]; print(json.dumps(b))' "$1" "${SEED[RBAC_PASSWORD]}"
}

declare -A JARS=([owner]="${SEED[MEMBER_C_EMAIL]}" [taker]="${SEED[MEMBER_B_EMAIL]}" [stranger]="${SEED[MEMBER_A_EMAIL]}")
for who in owner taker stranger; do
  sign_in "${JARS[$who]}" "$TMP/jar.$who" || { check "sign in as $who" 0; exit 1; }
done
T="/api/projects/$PROJECT_ID/transfer"

if [ "$IN_FORCE" = 1 ]; then
  code="$(call "$TMP/jar.owner" GET "$T")"
  check "A sees the transfer section as the owner, no offer yet" "$([ "$code" = 200 ] && [ "$(body_field role)" = '"owner"' ] && [ "$(body_field offer)" = null ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.owner" POST "$T" "{\"toUserId\":\"$TAKER_ID\",\"oldOwnerRole\":\"co-owner\"}")"
  check "an offer without the password is refused (403 step_up_required)" "$([ "$code" = 403 ] && [ "$(body_field code)" = '"step_up_required"' ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" POST "$T" "$(with_password "{\"toUserId\":\"$TAKER_ID\",\"oldOwnerRole\":\"leave\"}")")"
  check "B cannot offer A's project (403)" "$([ "$code" = 403 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.owner" POST "$T" "$(with_password "{\"toUserId\":\"$TAKER_ID\",\"oldOwnerRole\":\"co-owner\"}")")"
  check "A offers the project to B with the password (201, pending)" "$([ "$code" = 201 ] && [ "$(body_field offer.status)" = '"pending"' ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.stranger" GET "$T")"
  check "a member without access gets 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" GET "/api/projects/transfers")"
  check "B's banner feed holds the offer" "$([ "$code" = 200 ] && [ "$(body_field incoming.0.project.id)" = "\"$PROJECT_ID\"" ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" POST "$T/accept" '{"stepUpPassword":"not-the-password"}')"
  check "an accept with a wrong password is refused (403 step_up_failed)" "$([ "$code" = 403 ] && [ "$(body_field code)" = '"step_up_failed"' ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" POST "$T/accept" "$(with_password '{}')")"
  check "B accepts with the password (200)" "$([ "$code" = 200 ] && [ "$(body_field transferred.to)" = "\"$TAKER_ID\"" ] && echo 1 || echo 0)" "got $code $(body_field code)"

  owner_now="$(printf "select user_id from projects where id = '%s';\n" "$PROJECT_ID" | db_sql | tail -n 1)"
  check "Postgres: B owns the project" "$([ "$owner_now" = "$TAKER_ID" ] && echo 1 || echo 0)" "got ${owner_now:-?}"
  # A boolean joined to text casts as 'true'/'false', not psql's t/f display: spell the flags out.
  shares="$(printf "select user_id || ':' || access || ':' || case when manage then 't' else 'f' end from project_collaborators where project_id = '%s' order by user_id;\n" "$PROJECT_ID" | db_sql | tr '\n' ' ')"
  check "A is a co-owner with Manage; B's share is gone" "$([ "$shares" = "$OWNER_ID:write:t " ] && echo 1 || echo 0)" "got $shares"
  sched="$(printf "select case when enabled then 't' else 'f' end || ':' || coalesce(paused_reason, '') from scan_schedules where id = '%s';\n" "$SCHEDULE_ID" | db_sql | tail -n 1)"
  check "A's schedule paused (ownership_transferred)" "$([ "$sched" = 'f:ownership_transferred' ] && echo 1 || echo 0)" "got ${sched:-?}"
  consent="$(printf "select owner_credential_consent_at is null from project_access_policies where project_id = '%s';\n" "$PROJECT_ID" | db_sql | tail -n 1)"
  check "the consent (A's keys) is cleared" "$([ "$consent" = t ] && echo 1 || echo 0)" "got ${consent:-?}"
  token="$(printf "select cypherfix_github_token = '' from projects where id = '%s';\n" "$PROJECT_ID" | db_sql | tail -n 1)"
  check "A's GitHub token is cleared" "$([ "$token" = t ] && echo 1 || echo 0)" "got ${token:-?}"
  status="$(printf "select status from project_transfers where project_id = '%s';\n" "$PROJECT_ID" | db_sql | tail -n 1)"
  check "the offer is completed" "$([ "$status" = completed ] && echo 1 || echo 0)" "got ${status:-?}"
  rows="$(printf "select string_agg(action, ',' order by action) from audit_log where project_id = '%s' and action like 'project.transfer.%%';\n" "$PROJECT_ID" | db_sql | tail -n 1)"
  check "audit rows: offer, accept, completed" "$([ "$rows" = 'project.transfer.accept,project.transfer.completed,project.transfer.offer' ] && echo 1 || echo 0)" "got ${rows:-?}"

  under_b="$(graph count "$PROJECT_ID" "$TAKER_ID")"
  under_a="$(graph count "$PROJECT_ID" "$OWNER_ID")"
  check "graph: every synthetic node under B ($NODES), none under A" "$([ "$under_b" = "$NODES" ] && [ "$under_a" = 0 ] && echo 1 || echo 0)" "got B=$under_b A=$under_a"

  code="$(call "$TMP/jar.taker" GET "$T")"
  check "B (the owner now) sees the token to re-pick" "$([ "$code" = 200 ] && [ "$(body_field cleared.cleared.0.field)" = '"cypherfixGithubToken"' ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" POST "$T/accept" "$(with_password '{}')")"
  check "a second accept finds no offer (409 no_transfer_offer)" "$([ "$code" = 409 ] && [ "$(body_field code)" = '"no_transfer_offer"' ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" POST "$T/acknowledge" '{}')"
  check "B dismisses the re-pick list (200)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code"
  echo "E2E-P5-08: graph nodes moved $NODES, Postgres owner $TAKER_ID, A co-owner"
else
  code="$(call "$TMP/jar.owner" GET "$T")"
  check "GET transfer answers 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.owner" POST "$T" "$(with_password "{\"toUserId\":\"$TAKER_ID\",\"oldOwnerRole\":\"co-owner\"}")")"
  check "the offer answers 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" POST "$T/accept" "$(with_password '{}')")"
  check "accept answers 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" GET "/api/projects/transfers")"
  check "the banner feed answers 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  owner_now="$(printf "select user_id from projects where id = '%s';\n" "$PROJECT_ID" | db_sql | tail -n 1)"
  check "A still owns the project" "$([ "$owner_now" = "$OWNER_ID" ] && echo 1 || echo 0)" "got ${owner_now:-?}"
fi

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
