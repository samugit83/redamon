#!/usr/bin/env bash
#
# Live check of step 5.9 (SH-11, SH-12, SH-41; the queued-scan, schedule and socket half of E2E
# P5-04): losing access stops the person's live work on the project. On the running stack:
#
# It seeds the matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs) and a throwaway project
# rbac-revocation owned by rbac-member-c with NO target, shared at Read with rbac-member-b; then, as
# member-b's deferred work on it: a queued full recon (not_before an hour away, so the queue worker
# never takes it first) and a schedule (next run in 30 days, so the scheduler never fires it). Then
# the owner revokes the share:
#   DELETE /api/projects/<id>/collaborators/<member-b>   200, socketsClosed true
# and the check reads that member-b's job is cancelled (actor_no_access) and the schedule paused
# (paused_reason actor_no_access), each with its audit row, the owner holds a schedule_paused notice,
# the webapp logged `[rbac] revocation reason=share_revoked` and the agent answered the run stop and
# the socket close for member-b on that project. A second revoke answers 404 and writes nothing.
# With sharing not in force (a switch off, or instance_settings.sharing_policy not enabled) the share
# routes answer 404 and member-b's work stays as it was (DV-30).
#
# The live agent run of P5-04 (a scripted stub run that stops and whose socket closes) is the
# browser row of phase_07_e2e_matrix.md; here the agent is asked and its log lines are read.
#
# The trap runs e2e-rbac-cleanup.mjs (the project, its job and schedule cascade with it, and every
# fixture account), even on a failure or Ctrl-C. Response bodies and passwords are never printed.
#
# Needs the stack up (webapp on :3000, postgres, agent); prints SKIP and exits 0 when it is not.
# As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_revocation_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"

health="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
if [ "$health" != 200 ]; then
  echo "SKIP: RedAmon webapp not answering at $BASE/api/health (got ${health:-nothing})"
  exit 0
fi
for svc in webapp postgres agent; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done

TMP="$(mktemp -d)"
CLEANED_UP=0
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
one() { printf '%s\n' "$1" | db_sql | tail -n 1; }
switch_on() { # raw env value -> 0 when on, parsed as webapp/src/lib/authz/flags.ts does
  case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in true|1|yes) return 0 ;; *) return 1 ;; esac
}

cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
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
policy="$(one "select coalesce(sharing_policy->>'enabled', 'false') from instance_settings limit 1;")"
IN_FORCE=0
switch_on "${sw_identity:-}" && switch_on "${sw_permissions:-}" && switch_on "${sw_sharing:-}" \
  && [ "$policy" = true ] && IN_FORCE=1
if [ "$IN_FORCE" = 1 ]; then
  echo "== sharing in force: a revoke must stop the person's work on the project =="
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

ids="$( (cd "$ROOT" && docker compose exec -T -e OWNER_ID="$OWNER_ID" -e OTHER_ID="$OTHER_ID" -w /app webapp node --input-type=module -) <<'NODE'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
const { OWNER_ID: owner, OTHER_ID: other } = process.env
try {
  const project = await prisma.project.create({ data: { userId: owner, name: 'rbac-revocation', targetDomain: '' } })
  await prisma.projectCollaborator.create({ data: { projectId: project.id, userId: other, access: 'read', grantedById: owner } })
  const job = await prisma.jobQueue.create({
    data: {
      projectId: project.id, userId: other, kind: 'full_recon', payload: { mode: 'new' }, settingsHash: 'rbac-revocation',
      envelopeBytes: 0n, notBefore: new Date(Date.now() + 3_600_000),
    },
  })
  const schedule = await prisma.scanSchedule.create({
    data: {
      projectId: project.id, userId: other, label: 'rbac-revocation nightly', mode: 'interval', intervalMinutes: 1440,
      scanMode: 'new', enabled: true, nextRunAt: new Date(Date.now() + 30 * 86_400_000),
    },
  })
  console.log(`${project.id} ${job.id} ${schedule.id}`)
} finally {
  await prisma.$disconnect()
}
NODE
)"
read -r PROJECT_ID JOB_ID SCHEDULE_ID <<< "$(printf '%s' "$ids" | tail -n 1)"
for v in "${PROJECT_ID:-}" "${JOB_ID:-}" "${SCHEDULE_ID:-}"; do
  safe_id "$v" || { echo "FAIL  could not create the project, its share, job and schedule"; exit 1; }
done

# ---- requests -------------------------------------------------------------------------
PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
eq() { check "$1" "$([ "$2" = "$3" ] && echo 1 || echo 0)" "got '$2', want '$3'"; }
sign_in() { # email jar -> 0 when signed in
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  [ "$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json")" = 200 ]
}
call() { # jar method path -> http code; the body lands in $TMP/body, never printed
  curl -s -m 120 -o "$TMP/body" -w '%{http_code}' -X "$2" -b "$1" -H "Origin: $BASE" "$BASE$3"
}
has() { grep -qF -- "$1" "$TMP/body"; }
job_state() { one "select status || '|' || blocked_code from job_queue where id = '$JOB_ID';"; }
schedule_state() { one "select enabled || '|' || coalesce(paused_reason, '') from scan_schedules where id = '$SCHEDULE_ID';"; }
audits() { one "select count(*) from audit_log where project_id = '$PROJECT_ID' and action in ('job_queue.cancelled', 'scan_schedule.paused');"; }

JAR="$TMP/jar.owner"
sign_in "${SEED[MEMBER_C_EMAIL]}" "$JAR" || { check "sign in as the owner" 0; exit 1; }
REVOKE="/api/projects/$PROJECT_ID/collaborators/$OTHER_ID"

if [ "$IN_FORCE" = 1 ]; then
  code="$(call "$JAR" DELETE "$REVOKE")"
  ok=0; [ "$code" = 200 ] && has '"socketsClosed":true' && ok=1
  check "the owner revokes member-b's share: 200, the agent confirmed the close" "$ok" "got $code"
  eq "member-b's queued scan is cancelled (actor_no_access)" "$(job_state)" "canceled|actor_no_access"
  eq "member-b's schedule is paused for lost access" "$(schedule_state)" "f|actor_no_access"
  eq "one job_queue.cancelled and one scan_schedule.paused row" "$(audits)" 2
  eq "the owner holds a schedule_paused notice" \
    "$(one "select pending_notices::text like '%\"schedule_paused\"%' from users where id = '$OWNER_ID';")" t
  logs="$(cd "$ROOT" && docker compose logs --no-color --since "$STARTED_AT" webapp 2>&1)"
  check "the webapp logged the revocation" \
    "$(grep -qF "[rbac] revocation reason=share_revoked user=$OTHER_ID project=$PROJECT_ID" <<< "$logs" && echo 1 || echo 0)"
  check "and no revocation step failed" \
    "$(grep -qF "[rbac] revocation step failed" <<< "$logs" && echo 0 || echo 1)"
  agent_logs="$(cd "$ROOT" && docker compose logs --no-color --since "$STARTED_AT" agent 2>&1)"
  check "the agent stopped member-b's runs on the project" \
    "$(grep -qF "[rbac] stop-for user=$OTHER_ID projects=1" <<< "$agent_logs" && echo 1 || echo 0)"
  check "the agent closed member-b's sockets on the project" \
    "$(grep -qF "[rbac] ws close user=$OTHER_ID project=$PROJECT_ID" <<< "$agent_logs" && echo 1 || echo 0)"

  code="$(call "$JAR" DELETE "$REVOKE")"
  ok=0; [ "$code" = 404 ] && has '"code":"no_such_share"' && ok=1
  check "the same revoke again: 404 no_such_share" "$ok" "got $code"
  eq "and nothing more is written" "$(audits)" 2
else
  code="$(call "$JAR" DELETE "$REVOKE")"
  eq "sharing not in force: the revoke route does not exist (404)" "$code" 404
  eq "member-b's queued scan is untouched" "$(job_state)" "queued|"
  eq "member-b's schedule is untouched" "$(schedule_state)" "t|"
fi

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
