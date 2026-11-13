#!/usr/bin/env bash
#
# Live check of step 5.11 (SH-40, OQ-35): a second person writing a project is refused, naming who
# holds it, and the ProjectWriters route names them; with sharing not in force nothing changes.
#
# It seeds the matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs) and a throwaway project
# rbac-writers owned by rbac-member-c with NO target (so a start the check failed to refuse ends in
# the start path's own 400, never in a real scan). The other person's live writer is a TriageRun row
# (status running, fresh heartbeat) whose actor is rbac-member-b: a writer the check reads from the
# database, with no agent, model or scan needed. Then, as the owner:
#   GET  /api/projects/<id>/writers          names member-b's triage run (by email, never the id)
#   POST /api/agent/ws-ticket {socket:agent}  409 project_writer_busy naming member-b
#   POST /api/recon/<id>/start                409 project_writer_busy (before any version is frozen)
#   POST /api/gvm/<id>/start                  409 project_writer_busy
# then the run is marked completed and the ticket is minted (200), the writers list is empty.
# With sharing not in force (a switch off, or instance_settings.sharing_policy not enabled) the
# ticket is minted with the run live and the writers route answers 404 (DV-30).
#
# The trap deletes the run and runs e2e-rbac-cleanup.mjs (the project and every fixture account),
# even on a failure or Ctrl-C. Response bodies and passwords are never printed.
#
# Needs the stack up (webapp on :3000, postgres); prints SKIP and exits 0 when it is not.
# As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_writers_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"

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
switch_on() { # raw env value -> 0 when on, parsed as webapp/src/lib/authz/flags.ts does
  case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in true|1|yes) return 0 ;; *) return 1 ;; esac
}

cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  if [ -n "$PROJECT_ID" ] && safe_id "$PROJECT_ID"; then
    printf "DELETE FROM triage_runs WHERE project_id = '%s';\n" "$PROJECT_ID" | db_sql > /dev/null || true
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
  echo "== sharing in force: a second writer must be refused, naming them =="
else
  echo "== sharing not in force: nothing may change (DV-30) =="
fi

# ---- fixtures ---------------------------------------------------------------------------
echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in MEMBER_B_EMAIL MEMBER_B_ID MEMBER_C_EMAIL MEMBER_C_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
OWNER_ID="${SEED[MEMBER_C_ID]}"
OTHER_ID="${SEED[MEMBER_B_ID]}"
safe_id "$OWNER_ID" && safe_id "$OTHER_ID" || { echo "unexpected fixture ids"; exit 1; }

PROJECT_ID="$( (cd "$ROOT" && docker compose exec -T -e OWNER_ID="$OWNER_ID" -w /app webapp node --input-type=module -) <<'NODE'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const project = await prisma.project.create({ data: { userId: process.env.OWNER_ID, name: 'rbac-writers', targetDomain: '' } })
  console.log(project.id)
} finally {
  await prisma.$disconnect()
}
NODE
)"
PROJECT_ID="$(printf '%s' "$PROJECT_ID" | tail -n 1)"
safe_id "$PROJECT_ID" || { echo "FAIL  could not create the project"; PROJECT_ID=''; exit 1; }

RUN_ID="rbac-writers-run"
start_other_writer() {
  printf "INSERT INTO triage_runs (id, project_id, actor_user_id, status, started_at, heartbeat_at) VALUES ('%s', '%s', '%s', 'running', now(), now()) ON CONFLICT (id) DO UPDATE SET status = 'running', heartbeat_at = now();\n" \
    "$RUN_ID" "$PROJECT_ID" "$OTHER_ID" | db_sql > /dev/null
}
end_other_writer() {
  printf "UPDATE triage_runs SET status = 'completed', finished_at = now() WHERE id = '%s';\n" "$RUN_ID" | db_sql > /dev/null
}

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
has() { grep -qF -- "$1" "$TMP/body"; }

JAR="$TMP/jar.owner"
sign_in "${SEED[MEMBER_C_EMAIL]}" "$JAR" || { check "sign in as the owner" 0; exit 1; }
TICKET="{\"projectId\":\"$PROJECT_ID\",\"sessionId\":\"rbac-writers-session\",\"socket\":\"agent\"}"
OTHER_EMAIL="${SEED[MEMBER_B_EMAIL]}"

start_other_writer
if [ "$IN_FORCE" = 1 ]; then
  code="$(call "$JAR" GET "/api/projects/$PROJECT_ID/writers")"
  ok=0; [ "$code" = 200 ] && has '"kind":"triage"' && has "$OTHER_EMAIL" && ! has "$OTHER_ID" && ok=1
  check "the writers route names the other person's triage run by email, never by id" "$ok" "got $code"

  code="$(call "$JAR" POST /api/agent/ws-ticket "$TICKET")"
  ok=0; [ "$code" = 409 ] && has '"code":"project_writer_busy"' && has "$OTHER_EMAIL" && has 'a triage run' && ok=1
  check "the owner's agent ticket: 409 project_writer_busy naming the other person" "$ok" "got $code"

  code="$(call "$JAR" POST "/api/recon/$PROJECT_ID/start" '{"mode":"new"}')"
  ok=0; [ "$code" = 409 ] && has '"code":"project_writer_busy"' && has "$OTHER_EMAIL" && ok=1
  check "the owner's full recon start: 409 project_writer_busy" "$ok" "got $code"
  frozen="$(printf "select count(*) from scan_versions where project_id = '%s';\n" "$PROJECT_ID" | db_sql | tail -n 1)"
  check "no version was frozen for the refused start" "$([ "${frozen:-x}" = 0 ] && echo 1 || echo 0)" "got ${frozen:-?}"

  code="$(call "$JAR" POST "/api/gvm/$PROJECT_ID/start" '{}')"
  ok=0; [ "$code" = 409 ] && has '"code":"project_writer_busy"' && ok=1
  check "the owner's GVM start: 409 project_writer_busy" "$ok" "got $code"

  end_other_writer
  code="$(call "$JAR" POST /api/agent/ws-ticket "$TICKET")"
  check "once the other run ended the owner's ticket is minted" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$JAR" GET "/api/projects/$PROJECT_ID/writers")"
  ok=0; [ "$code" = 200 ] && has '"writers":[]' && ok=1
  check "and the writers list is empty" "$ok" "got $code"
else
  code="$(call "$JAR" POST /api/agent/ws-ticket "$TICKET")"
  check "sharing not in force: the owner's ticket is minted with the other run live" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$JAR" GET "/api/projects/$PROJECT_ID/writers")"
  check "sharing not in force: the writers route does not exist (404)" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$JAR" POST "/api/recon/$PROJECT_ID/start" '{"mode":"new"}')"
  ok=0; [ "$code" != 409 ] && ! has 'project_writer_busy' && ok=1
  check "sharing not in force: the full recon start is not refused as a second writer" "$ok" "got $code"
fi

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
