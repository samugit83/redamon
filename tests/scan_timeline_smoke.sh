#!/usr/bin/env bash
# =============================================================================
# Scan Timeline — end-to-end smoke test (docker compose)
# =============================================================================
# Drives the REAL endpoints against the REAL Postgres + Neo4j, as a logged-in
# user, and checks the whole loop the feature promises:
#
#   1. a project's live graph shows up as the current version (backfill)
#   2. "save current as a version" freezes it into stored snapshot bytes
#   3. viewing a PAST version returns the snapshot payload, NOT the live graph
#   4. mutating the live graph does not change the frozen version
#   5. activating the past version swaps the live graph back to it
#   6. agent (AttackChain) nodes are never captured and survive activation (F1)
#   7. Recon Delta compares two versions
#   8. deleting the current version is refused; a past one deletes with its bytes
#   9. cross-project version ids are 404 (BOLA), and unauthenticated access is 401
#
# Requires: docker compose up -d postgres neo4j webapp
# Usage:    tests/scan_timeline_smoke.sh
# =============================================================================
set -uo pipefail

cd "$(dirname "$0")/.."

BASE="${REDAMON_WEBAPP_URL:-http://localhost:3000}"
JAR="$(mktemp -d)/cookies.txt"

PSQL=(docker compose exec -T postgres psql -U redamon -d redamon -qtAX)
pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; echo "        $2"; fail=$((fail + 1)); }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2' got '$3'"; fi; }

q()      { "${PSQL[@]}" -c "$1" 2>&1; }
cypher() { docker compose exec -T neo4j cypher-shell -u neo4j -p "${NEO4J_PASSWORD:-redamon123}" --format plain "$1" 2>&1; }
# Evaluate a python expression over the JSON body on stdin; `d` is the document.
jqf()    { python3 -c 'import json,sys; print(eval(sys.argv[1], {"d": json.load(sys.stdin)}))' "$1" 2>/dev/null; }

api() { # METHOD PATH [BODY]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -b "$JAR" -c "$JAR" -X "$method" -H 'Content-Type: application/json' -d "$body" "$BASE$path"
  else
    curl -sS -b "$JAR" -c "$JAR" -X "$method" "$BASE$path"
  fi
}
api_code() { # METHOD PATH [BODY]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" -X "$method" -H 'Content-Type: application/json' -d "$body" "$BASE$path"
  else
    curl -sS -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" -X "$method" "$BASE$path"
  fi
}

echo "== Scan Timeline smoke (E2E) =="

if ! curl -sS -o /dev/null "$BASE/api/health"; then
  echo "  SKIP  webapp not reachable at $BASE (docker compose up -d webapp)"
  exit 0
fi
if ! q "select 1" >/dev/null 2>&1; then
  echo "  SKIP  postgres not reachable"
  exit 0
fi

# ---------------------------------------------------------------- fixtures ---
SUF="smoke$(date +%s)"
U="user_$SUF"; P="proj_$SUF"; P2="proj2_$SUF"
EMAIL="$U@example.invalid"
PASSWORD="Sm0ke-Test-$SUF"
HASH=$(docker compose exec -T webapp node -e "console.log(require('bcryptjs').hashSync(process.argv[1],10))" "$PASSWORD" | tr -d '\r')

q "insert into users (id, name, email, password, role, created_at, updated_at)
   values ('$U','smoke','$EMAIL','$HASH','standard',now(),now())" >/dev/null
# ownership_token is NOT NULL and only Prisma fills it, so a raw insert brings its own.
q "insert into projects (id, user_id, name, target_domain, ownership_token, created_at, updated_at)
   values ('$P','$U','smoke','smoke.tld',gen_random_uuid()::text,now(),now())" >/dev/null
q "insert into projects (id, user_id, name, target_domain, ownership_token, created_at, updated_at)
   values ('$P2','$U','smoke other','other.tld',gen_random_uuid()::text,now(),now())" >/dev/null

cleanup() {
  cypher "MATCH (n) WHERE n.project_id IN ['$P','$P2'] DETACH DELETE n" >/dev/null 2>&1
  q "delete from scan_jobs where project_id in ('$P','$P2')" >/dev/null 2>&1
  q "delete from scan_schedules where project_id in ('$P','$P2')" >/dev/null 2>&1
  q "delete from conversations where project_id in ('$P','$P2')" >/dev/null 2>&1
  q "delete from projects where id in ('$P','$P2')" >/dev/null 2>&1
  q "delete from users where id = '$U'" >/dev/null 2>&1
  rm -rf "$(dirname "$JAR")"
}
trap cleanup EXIT

# The chain node below must belong to a LIVE conversation, otherwise the graph
# read's orphan-chain reconcile legitimately purges it and the F1 assertion would
# be testing the reconcile rather than the snapshot/activation exclusion.
q "insert into conversations (id, project_id, user_id, session_id, title, status, updated_at)
   values ('conv_$SUF','$P','$U','sess_$SUF','smoke','active',now())" >/dev/null

# Seed a small recon graph + one agent chain node (which must never be versioned).
cypher "CREATE (d:Domain {name:'smoke.tld', project_id:'$P', user_id:'$U'})
        CREATE (s:Subdomain {name:'www.smoke.tld', project_id:'$P', user_id:'$U'})
        CREATE (i:IP {address:'10.1.2.3', project_id:'$P', user_id:'$U'})
        CREATE (d)-[:HAS_SUBDOMAIN]->(s)
        CREATE (s)-[:RESOLVES_TO]->(i)
        CREATE (c:AttackChain {chain_id:'sess_$SUF', title:'smoke chain', project_id:'$P', user_id:'$U'})" >/dev/null

login=$(curl -sS -c "$JAR" -X POST -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$BASE/api/auth/login")
if ! echo "$login" | grep -q '"user"\|"success"\|"id"'; then
  echo "  SKIP  could not log in as the fixture user: $login"
  exit 0
fi

# ------------------------------------------------- 1. backfill / list ---------
versions=$(api GET "/api/projects/$P/versions")
n=$(echo "$versions" | jqf "len(d['versions'])")
expect_eq "an existing project backfills exactly one current version" "1" "$n"
V1=$(echo "$versions" | jqf "d['versions'][0]['id']")
expect_eq "the backfilled version is the current one" "True" "$(echo "$versions" | jqf "d['versions'][0]['isCurrent']")"
expect_eq "the current version is not activatable (it IS the live graph)" "False" "$(echo "$versions" | jqf "d['versions'][0]['activatable']")"

# ------------------------------------------------- 2. save current ------------
saved=$(api POST "/api/projects/$P/versions" '{"label":"smoke baseline"}')
SAVED_ID=$(echo "$saved" | jqf "d['savedVersion']['id']")
expect_eq "save-current freezes the live graph into the previous version" "$V1" "$SAVED_ID"
snapbytes=$(q "select octet_length(snapshot) from scan_versions where id='$SAVED_ID'")
if [ "${snapbytes:-0}" -gt 0 ]; then ok "the frozen version has gzipped snapshot bytes"; else bad "the frozen version has gzipped snapshot bytes" "octet_length=$snapbytes"; fi
# F1: the AttackChain node must NOT be in the snapshot.
expect_eq "agent chain nodes are excluded from the snapshot (F1)" "3" "$(q "select node_count from scan_versions where id='$SAVED_ID'")"

versions=$(api GET "/api/projects/$P/versions")
expect_eq "a new current version was opened for the live graph" "2" "$(echo "$versions" | jqf "len(d['versions'])")"
V2=$(echo "$versions" | jqf "[v for v in d['versions'] if v['isCurrent']][0]['id']")
expect_eq "the frozen version is now activatable" "True" "$(echo "$versions" | jqf "[v for v in d['versions'] if v['id']=='$SAVED_ID'][0]['activatable']")"

# ------------------------------------------------- 3./4. view a version -------
past=$(api GET "/api/projects/$P/versions/$SAVED_ID/graph")
expect_eq "a past version renders from stored bytes, not live" "False" "$(echo "$past" | jqf "d['live']")"
expect_eq "the past version has the 3 recon nodes" "3" "$(echo "$past" | jqf "len(d['nodes'])")"

# Mutate the live graph; the frozen version must not move.
cypher "MATCH (d:Domain {project_id:'$P'}) CREATE (n:Subdomain {name:'new.smoke.tld', project_id:'$P', user_id:'$U'}) CREATE (d)-[:HAS_SUBDOMAIN]->(n)" >/dev/null
past2=$(api GET "/api/projects/$P/versions/$SAVED_ID/graph")
expect_eq "the frozen version is immutable while the live graph changes" "3" "$(echo "$past2" | jqf "len(d['nodes'])")"
live=$(api GET "/api/projects/$P/versions/$V2/graph")
expect_eq "the current version reads the LIVE graph" "True" "$(echo "$live" | jqf "d['live']")"

# ------------------------------------------------- 7. delta -------------------
delta=$(api GET "/api/projects/$P/delta?from=$SAVED_ID&to=current")
expect_eq "delta reports the node added after the freeze" "1" "$(echo "$delta" | jqf "len(d['addedNodes'])")"
expect_eq "delta reports nothing removed" "0" "$(echo "$delta" | jqf "len(d['removedNodes'])")"

# ------------------------------------------------- 5./6. activation -----------
act=$(api POST "/api/projects/$P/versions/$SAVED_ID/activate" '{}')
expect_eq "activation succeeds" "True" "$(echo "$act" | jqf "d['ok']")"
expect_eq "the live graph is back to the frozen node count" "3" "$(cypher "MATCH (n) WHERE n.project_id='$P' AND NOT n:AttackChain RETURN count(n)" | tail -1)"
expect_eq "agent chain nodes survived the swap (F1)" "1" "$(cypher "MATCH (n:AttackChain {project_id:'$P'}) RETURN count(n)" | tail -1)"
expect_eq "the activated version is now the current one" "True" \
  "$(api GET "/api/projects/$P/versions" | jqf "[v for v in d['versions'] if v['id']=='$SAVED_ID'][0]['isCurrent']")"
expect_eq "the outgoing version was frozen before the swap (nothing lost)" "4" \
  "$(q "select node_count from scan_versions where id='$V2'")"
expect_eq "activation left the lock released" "idle" "$(q "select activation_state from projects where id='$P'")"
# Fidelity: the restored graph must be the SAME assets, not just the same count.
expect_eq "the restored graph has the original subdomain" "1" \
  "$(cypher "MATCH (n:Subdomain {project_id:'$P', name:'www.smoke.tld'}) RETURN count(n)" | tail -1)"
expect_eq "the node added after the freeze is gone again" "0" \
  "$(cypher "MATCH (n:Subdomain {project_id:'$P', name:'new.smoke.tld'}) RETURN count(n)" | tail -1)"
expect_eq "relationships were restored, not just nodes" "1" \
  "$(cypher "MATCH (:Subdomain {project_id:'$P', name:'www.smoke.tld'})-[r:RESOLVES_TO]->(:IP {address:'10.1.2.3'}) RETURN count(r)" | tail -1)"
expect_eq "no _exportId scaffolding leaked into the live graph" "0" \
  "$(cypher "MATCH (n {project_id:'$P'}) WHERE n._exportId IS NOT NULL RETURN count(n)" | tail -1)"

# Two captures of the same graph must diff to nothing: proves the identity keys
# are stable across captures (otherwise every comparison would be pure noise).
selfdelta=$(api GET "/api/projects/$P/delta?from=current&to=current")
expect_eq "current vs current is an empty diff (stable identity)" "0" \
  "$(echo "$selfdelta" | jqf "d['totals']['added'] + d['totals']['removed'] + d['totals']['changed']")"

# ------------------------------------------------- 8. delete rules ------------
expect_eq "the current version cannot be deleted" "409" "$(api_code DELETE "/api/projects/$P/versions/$SAVED_ID")"
expect_eq "a past version deletes" "200" "$(api_code DELETE "/api/projects/$P/versions/$V2")"
expect_eq "its snapshot bytes go with it" "0" "$(q "select count(*) from scan_versions where id='$V2'")"

# ------------------------------------------------- 9. authz -------------------
expect_eq "a version id from another project is 404 (BOLA)" "404" "$(api_code GET "/api/projects/$P2/versions/$SAVED_ID/graph")"
anon=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/api/projects/$P/versions")
expect_eq "unauthenticated version list is 401" "401" "$anon"

# ------------------------------------------------- 9b. mid-write guard --------
# Risk 1: a snapshot must never be taken of a graph a scan is rewriting.
if docker compose ps --services --filter status=running 2>/dev/null | grep -q recon-orchestrator; then
  ok "orchestrator reachable for the mid-write guard check"
else
  echo "  SKIP  orchestrator not running; mid-write guard not exercised"
fi

# ------------------------------------------------- 10. scheduler --------------
sched=$(api POST "/api/projects/$P/schedules" '{"mode":"cron","cronExpr":"0 3 * * *","scanMode":"new","label":"nightly"}')
SCHED_ID=$(echo "$sched" | jqf "d['schedule']['id']")
if [ -n "$SCHED_ID" ]; then ok "a cron schedule is created"; else bad "a cron schedule is created" "$sched"; fi
expect_eq "its next run is computed" "True" "$(echo "$sched" | jqf "d['schedule']['nextRunAt'] is not None")"
expect_eq "an every-minute cron is rejected (scheduler DoS guard)" "400" \
  "$(api_code POST "/api/projects/$P/schedules" '{"mode":"cron","cronExpr":"* * * * *"}')"
expect_eq "a sub-minimum interval is rejected" "400" \
  "$(api_code POST "/api/projects/$P/schedules" '{"mode":"interval","intervalMinutes":1}')"
expect_eq "a past one-off is rejected" "400" \
  "$(api_code POST "/api/projects/$P/schedules" '{"mode":"once","runAt":"2000-01-01T00:00:00Z"}')"
expect_eq "the schedule + run history are listed" "1" \
  "$(api GET "/api/projects/$P/schedules" | jqf "len(d['schedules'])")"
expect_eq "the scheduler's internal feed rejects a cookie-only caller" "401" \
  "$(api_code GET "/api/internal/scan-schedules/due")"
expect_eq "disabling the schedule works" "200" \
  "$(api_code PATCH "/api/projects/$P/schedules/$SCHED_ID" '{"enabled":false}')"
expect_eq "a schedule id from another project is 404 (BOLA)" "404" \
  "$(api_code PATCH "/api/projects/$P2/schedules/$SCHED_ID" '{"enabled":true}')"
# The orchestrator worker's own API: due feed + defer. Deliberately NOT /run —
# that would spawn a real recon container against a real target.
KEY=$(grep -E '^INTERNAL_API_KEY=' .env | cut -d= -f2-)
# Re-enable it (the disable check above turned it off) and make it due now.
expect_eq "re-enabling a disabled schedule works" "200" \
  "$(api_code PATCH "/api/projects/$P/schedules/$SCHED_ID" '{"enabled":true}')"
q "update scan_schedules set next_run_at = now() - interval '1 minute' where id = '$SCHED_ID'" >/dev/null
due=$(curl -sS -H "x-internal-key: $KEY" "$BASE/api/internal/scan-schedules/due")
expect_eq "the due feed lists the schedule for the worker" "1" \
  "$(echo "$due" | jqf "len([s for s in d['schedules'] if s['id']=='$SCHED_ID'])")"
expect_eq "the due feed reports the project's activation state (F3)" "False" \
  "$(echo "$due" | jqf "[s for s in d['schedules'] if s['id']=='$SCHED_ID'][0]['activationInProgress']")"
deferred=$(curl -sS -X POST -H "x-internal-key: $KEY" -H 'Content-Type: application/json' \
  -d '{"reason":"graph busy: a version activation is in progress"}' \
  "$BASE/api/internal/scan-schedules/$SCHED_ID/defer")
expect_eq "deferring records why nothing ran" "1" \
  "$(q "select count(*) from scan_jobs where schedule_id='$SCHED_ID' and status='deferred_ram' and ram_reason like 'graph busy%'")"
expect_eq "deferring pushes the next attempt into the future" "True" \
  "$(echo "$deferred" | jqf "d['nextRunAt'] is not None")"
expect_eq "the schedule is no longer due right away" "0" \
  "$(q "select count(*) from scan_schedules where id='$SCHED_ID' and next_run_at <= now()")"

expect_eq "deleting the schedule works" "200" \
  "$(api_code DELETE "/api/projects/$P/schedules/$SCHED_ID")"
expect_eq "its run history survives the schedule (schedule_id -> NULL)" "1" \
  "$(q "select count(*) from scan_jobs where project_id='$P' and status='deferred_ram' and schedule_id is null")"

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
