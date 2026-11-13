#!/usr/bin/env bash
#
# Live check E2E-P5-09 (RBAC step 5.13, SH-16, SH-17): an admin deletes a member who owns a shared
# project, against the LIVE stack (webapp, Postgres; the agent for the revocation's stop and close).
#
# It seeds the matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs) and a throwaway member
# rbac-delete-target@e2e.local who owns rbac-delete-shared (shared at Read + Write with rbac-member-b),
# rbac-delete-solo (unshared), and holds a Write + Run scans share of rbac-delete-host (rbac-member-c's)
# with a queued scan there (not before tomorrow, so the queue never starts it). Then, as rbac-admin-a:
#   GET    /api/users/[id]/deletion-plan     the plan: shared, unshared, the share held elsewhere
#   DELETE /api/users/[id]                   refused while the shared project is unresolved (409)
#   POST   /api/users/[id]/deletion-plan     offer the shared project to member-b (password), then
#   POST   /api/projects/[id]/transfer/accept  member-b accepts it (their password)
#   DELETE /api/users/[id]                   the account goes: the solo project torn down, the
#                                            transferred one kept under member-b, the share on the host
#                                            project gone, the queued scan cancelled (account_deleted)
# and admin-a's forced transfer is refused (projects:administer is the confirmed Root's). With
# ROOT_EMAIL and ROOT_PASSWORD set (the disposable instance only: read from the environment, never
# printed), Root also forces a second shared project to member-b without an acceptance.
# With write sharing not in force: the plan answers 404 and the DELETE tears every project down as
# Phase 1 did.
#
# The trap runs e2e-rbac-cleanup.mjs and deletes the throwaway account with its projects, even on a
# failure or Ctrl-C. Response bodies and passwords are never printed.
#
# Needs the stack up (webapp on :3000, postgres) with the webapp built from step 5.13 or later; prints
# SKIP and exits 0 when it is not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_user_deletion_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
TARGET_EMAIL='rbac-delete-target@e2e.local'

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
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
drop_target() {
  (cd "$ROOT" && docker compose exec -T -e TARGET_EMAIL="$TARGET_EMAIL" -w /app webapp node --input-type=module -) <<'NODE' 2>/dev/null
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const user = await prisma.user.findUnique({ where: { email: process.env.TARGET_EMAIL }, select: { id: true } })
  if (user) {
    await prisma.project.deleteMany({ where: { userId: user.id } })
    await prisma.user.delete({ where: { id: user.id } })
  }
  await prisma.project.deleteMany({ where: { name: { in: ['rbac-delete-shared', 'rbac-delete-forced', 'rbac-delete-solo', 'rbac-delete-host'] } } })
} finally {
  await prisma.$disconnect()
}
NODE
}

cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  drop_target || echo "  cleanup failed: delete $TARGET_EMAIL and the rbac-delete-* projects by hand"
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
WIZARD=0
switch_on "${sw_identity:-}" && switch_on "${sw_permissions:-}" && switch_on "${sw_sharing:-}" && switch_on "${sw_write:-}" && WIZARD=1
IN_FORCE=0
[ "$WIZARD" = 1 ] && [ "$policy" = 'true|write' ] && IN_FORCE=1
if [ "$IN_FORCE" = 1 ]; then
  echo "== write sharing in force: the deletion plan resolves the shared project before the delete =="
elif [ "$WIZARD" = 1 ]; then
  echo "SKIP: the write switch is on but Root's policy is not {enabled, maxLevel write}: set it, or switch the write switch off"
  exit 0
else
  echo "== write sharing switched off: no plan, the DELETE tears every project down as Phase 1 did =="
fi

# ---- fixtures ---------------------------------------------------------------------------
echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in ADMIN_A_EMAIL MEMBER_B_EMAIL MEMBER_B_ID MEMBER_C_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
TAKER_ID="${SEED[MEMBER_B_ID]}"
HOST_OWNER_ID="${SEED[MEMBER_C_ID]}"
safe_id "$TAKER_ID" && safe_id "$HOST_OWNER_ID" || { echo "unexpected fixture ids"; exit 1; }
drop_target

ids="$( (cd "$ROOT" && docker compose exec -T -e TARGET_EMAIL="$TARGET_EMAIL" -e TAKER_ID="$TAKER_ID" -e HOST_OWNER_ID="$HOST_OWNER_ID" \
  -w /app webapp node --input-type=module -) <<'NODE'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const taker = process.env.TAKER_ID, hostOwner = process.env.HOST_OWNER_ID
  const target = await prisma.user.create({ data: { email: process.env.TARGET_EMAIL, name: 'RBAC Delete Target', role: 'standard', password: '' } })
  const shared = await prisma.project.create({ data: { userId: target.id, name: 'rbac-delete-shared', targetDomain: 'rbac.test' } })
  const forced = await prisma.project.create({ data: { userId: target.id, name: 'rbac-delete-forced', targetDomain: 'rbac.test' } })
  const solo = await prisma.project.create({ data: { userId: target.id, name: 'rbac-delete-solo', targetDomain: 'rbac.test' } })
  const host = await prisma.project.create({ data: { userId: hostOwner, name: 'rbac-delete-host', targetDomain: 'rbac.test' } })
  for (const p of [shared, forced]) {
    await prisma.projectCollaborator.create({ data: { projectId: p.id, userId: taker, access: 'write', grantedById: target.id } })
  }
  await prisma.projectCollaborator.create({ data: { projectId: host.id, userId: target.id, access: 'write', runScans: true, grantedById: hostOwner } })
  const job = await prisma.jobQueue.create({
    data: { projectId: host.id, userId: target.id, kind: 'full_recon', payload: {}, settingsHash: 'rbac-live', envelopeBytes: 0,
      status: 'queued', notBefore: new Date(Date.now() + 86_400_000) },
  })
  console.log(`${target.id} ${shared.id} ${forced.id} ${solo.id} ${host.id} ${job.id}`)
} finally {
  await prisma.$disconnect()
}
NODE
)"
read -r TARGET_ID SHARED_ID FORCED_ID SOLO_ID HOST_ID JOB_ID <<< "$(printf '%s' "$ids" | tail -n 1)"
for v in "${TARGET_ID:-}" "${SHARED_ID:-}" "${FORCED_ID:-}" "${SOLO_ID:-}" "${HOST_ID:-}" "${JOB_ID:-}"; do
  safe_id "$v" || { echo "FAIL  could not create the throwaway account and its projects"; exit 1; }
done

# ---- requests -------------------------------------------------------------------------
PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
sign_in() { # email password-file jar -> 0 when signed in
  python3 -c 'import json,sys; print(json.dumps({"email": sys.argv[1], "password": open(sys.argv[2]).read()}))' "$1" "$2" > "$TMP/login.json"
  [ "$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$3" -X POST "$BASE/api/auth/login" \
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
with_password() { # extra-json password-file -> the body with that password (written to a file, never printed)
  python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["stepUpPassword"]=open(sys.argv[2]).read(); print(json.dumps(b))' "$1" "$2"
}
q() { printf "$1\n" "${@:2}" | db_sql | tail -n 1; }

printf '%s' "${SEED[RBAC_PASSWORD]}" > "$TMP/pw.fixture"
sign_in "${SEED[ADMIN_A_EMAIL]}" "$TMP/pw.fixture" "$TMP/jar.admin" || { check "sign in as admin-a" 0; exit 1; }
sign_in "${SEED[MEMBER_B_EMAIL]}" "$TMP/pw.fixture" "$TMP/jar.taker" || { check "sign in as member-b" 0; exit 1; }
PLAN="/api/users/$TARGET_ID/deletion-plan"

if [ "$IN_FORCE" = 1 ]; then
  code="$(call "$TMP/jar.admin" GET "$PLAN")"
  shared_ids="$(body_field plan.sharedProjects | python3 -c 'import json,sys; print(",".join(sorted(p["id"] for p in json.load(sys.stdin) or [])))' 2>/dev/null)"
  check "the plan lists the two shared projects" "$([ "$code" = 200 ] && [ "$shared_ids" = "$(printf '%s\n%s\n' "$SHARED_ID" "$FORCED_ID" | sort | paste -sd,)" ] && echo 1 || echo 0)" "got $code $shared_ids"
  check "the plan lists the unshared project and the share held on the host project" \
    "$([ "$(body_field plan.unsharedProjects.0.id)" = "\"$SOLO_ID\"" ] && [ "$(body_field plan.memberships.0.project.id)" = "\"$HOST_ID\"" ] && echo 1 || echo 0)"
  code="$(call "$TMP/jar.admin" DELETE "/api/users/$TARGET_ID")"
  check "the DELETE is refused while a shared project is unresolved (409 deletion_plan_unresolved)" \
    "$([ "$code" = 409 ] && [ "$(body_field code)" = '"deletion_plan_unresolved"' ] && echo 1 || echo 0)" "got $code"
  check "nothing was torn down" "$([ "$(q "select count(*) from projects where user_id = '%s';" "$TARGET_ID")" = 3 ] && echo 1 || echo 0)"

  code="$(call "$TMP/jar.admin" POST "$PLAN" "{\"action\":\"offer\",\"projectId\":\"$SHARED_ID\",\"toUserId\":\"$TAKER_ID\"}")"
  check "an offer without the password is refused (403 step_up_required)" "$([ "$code" = 403 ] && [ "$(body_field code)" = '"step_up_required"' ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.admin" POST "$PLAN" "$(with_password "{\"action\":\"force\",\"projectId\":\"$FORCED_ID\",\"toUserId\":\"$TAKER_ID\"}" "$TMP/pw.fixture")")"
  check "admin-a cannot force a transfer (403: projects:administer is the confirmed Root's)" "$([ "$code" = 403 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.admin" POST "$PLAN" "$(with_password "{\"action\":\"offer\",\"projectId\":\"$SHARED_ID\",\"toUserId\":\"$TAKER_ID\"}" "$TMP/pw.fixture")")"
  check "admin-a offers the shared project to member-b (201, pending, the owner leaves)" \
    "$([ "$code" = 201 ] && [ "$(body_field offer.status)" = '"pending"' ] && [ "$(body_field offer.oldOwnerRole)" = '"leave"' ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.taker" POST "/api/projects/$SHARED_ID/transfer/accept" "$(with_password '{}' "$TMP/pw.fixture")")"
  check "member-b accepts it (200)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code $(body_field code)"
  check "Postgres: member-b owns it" "$([ "$(q "select user_id from projects where id = '%s';" "$SHARED_ID")" = "$TAKER_ID" ] && echo 1 || echo 0)"

  if [ -n "${ROOT_EMAIL:-}" ] && [ -n "${ROOT_PASSWORD:-}" ]; then
    printf '%s' "$ROOT_PASSWORD" > "$TMP/pw.root"
    sign_in "$ROOT_EMAIL" "$TMP/pw.root" "$TMP/jar.root" || { check "sign in as Root" 0; exit 1; }
    code="$(call "$TMP/jar.root" POST "$PLAN" "$(with_password "{\"action\":\"force\",\"projectId\":\"$FORCED_ID\",\"toUserId\":\"$TAKER_ID\"}" "$TMP/pw.root")")"
    check "Root forces the second shared project to member-b (200)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code $(body_field code)"
    check "the forced offer is recorded (forced, completed, audited project.transfer.forced)" \
      "$([ "$(q "select forced || ':' || status from project_transfers where project_id = '%s' order by created_at desc limit 1;" "$FORCED_ID")" = 't:completed' ] \
        && [ "$(q "select count(*) from audit_log where project_id = '%s' and action = 'project.transfer.forced';" "$FORCED_ID")" = 1 ] && echo 1 || echo 0)"
    ANYWAY='[]'
  else
    echo "  (no ROOT_EMAIL/ROOT_PASSWORD: the second shared project is deleted anyway instead of forced)"
    ANYWAY="[\"$FORCED_ID\"]"
  fi

  code="$(call "$TMP/jar.admin" DELETE "/api/users/$TARGET_ID" "{\"deleteAnyway\":$ANYWAY}")"
  check "the DELETE goes through once every shared project is resolved (200)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code $(body_field code)"
  check "the account is gone" "$([ "$(q "select count(*) from users where id = '%s';" "$TARGET_ID")" = 0 ] && echo 1 || echo 0)"
  check "the unshared project is torn down, the transferred one kept under member-b" \
    "$([ "$(q "select count(*) from projects where id = '%s';" "$SOLO_ID")" = 0 ] && [ "$(q "select user_id from projects where id = '%s';" "$SHARED_ID")" = "$TAKER_ID" ] && echo 1 || echo 0)"
  check "memberships gone after: the share on the host project ended with the account" \
    "$([ "$(q "select count(*) from project_collaborators where project_id = '%s';" "$HOST_ID")" = 0 ] && echo 1 || echo 0)"
  check "the queued scan on the host project is cancelled (account_deleted)" \
    "$([ "$(q "select status || ':' || blocked_code from job_queue where id = '%s';" "$JOB_ID")" = 'canceled:actor_no_access' ] && echo 1 || echo 0)"
  check "the user.delete audit row names what was deleted anyway" \
    "$([ "$(q "select (after->'deletedAnyway')::text from audit_log where action = 'user.delete' and target_id = '%s' order by created_at desc limit 1;" "$TARGET_ID")" = "$(printf '%s' "$ANYWAY" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))')" ] && echo 1 || echo 0)"
  logs="$(cd "$ROOT" && docker compose logs --since "$STARTED" webapp 2>/dev/null)"
  check "the webapp logged the revocation of the deleted account" \
    "$(printf '%s' "$logs" | grep -q "\[rbac\] revocation reason=account_deleted user=$TARGET_ID" && echo 1 || echo 0)"
  echo "E2E-P5-09: plan resolved, account $TARGET_ID deleted, shared project kept under member-b"
else
  code="$(call "$TMP/jar.admin" GET "$PLAN")"
  check "the deletion plan answers 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.admin" DELETE "/api/users/$TARGET_ID")"
  check "the DELETE answers 200 without a plan (Phase 1 teardown)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code $(body_field code)"
  check "every project of the account is torn down, the shared ones included" \
    "$([ "$(q "select count(*) from projects where id in ('%s', '%s', '%s');" "$SHARED_ID" "$FORCED_ID" "$SOLO_ID")" = 0 ] && echo 1 || echo 0)"
fi

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
