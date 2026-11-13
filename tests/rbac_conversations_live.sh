#!/usr/bin/env bash
#
# Live check E2E-P5-07 (RBAC step 5.8, SH-22, OQ-07): conversations are private to their author,
# shared read-only on the author's choice, and readable by the owner and co-owners only under the
# owner's "co-owners see every conversation", against the LIVE stack.
#
# It seeds the matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs), a throwaway project
# rbac-conversations owned by rbac-member-c ("A" of the matrix row) with a Read + Write share and Use
# AI agent for rbac-member-b ("B"), the owner's consent to spend the project's credentials, and two
# conversations written straight to Postgres (one each; no agent run, no model call). Then, through
# the routes:
#   GET  /api/conversations/[id] and ?projectId=   B's conversation for A
#   POST /api/conversations/[id]/share             B shares it, later stops
#   PATCH /api/conversations/[id]                  A's write to B's conversation
#   GET|POST /api/conversations/policy             A turns "co-owners see every conversation" on
# With write sharing in force (identity, permissions, sharing and the write sharing switch on, and
# instance_settings.sharing_policy enabled at maxLevel write): B's conversation is hidden from A,
# then readable and read-only once B shares it, hidden again once B stops, and readable again under
# A's policy; rbac-member-a (no share) gets 404 throughout. With write sharing not in force: hidden
# from A, and the share and policy routes answer 404.
#
# The trap runs e2e-rbac-cleanup.mjs (the fixture accounts and their projects, which take the
# conversations, the share rows and the policy row with them), even on a failure or Ctrl-C. Response
# bodies and passwords are never printed.
#
# Needs the stack up (webapp on :3000, postgres) with a webapp image built from step 5.8 or later;
# prints SKIP and exits 0 when it is not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_conversations_live.sh       (BASE_URL overrides :3000)
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
# flags.ts: each switch requires the one before it; then Root's policy (sharingPolicy.ts, maxShareLevel).
switch_on "${sw_identity:-}" && switch_on "${sw_permissions:-}" && switch_on "${sw_sharing:-}" && switch_on "${sw_write:-}" \
  && [ "$policy" = 'true|write' ] && IN_FORCE=1
if [ "$IN_FORCE" = 1 ]; then
  echo "== write sharing in force: private, then shared read-only, then the owner's policy =="
else
  echo "== write sharing not in force (a switch off, or the policy disabled or at read): private, routes 404 =="
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
WRITER_ID="${SEED[MEMBER_B_ID]}"
safe_id "$OWNER_ID" && safe_id "$WRITER_ID" || { echo "unexpected fixture ids"; exit 1; }

ids="$( (cd "$ROOT" && docker compose exec -T -e OWNER_ID="$OWNER_ID" -e WRITER_ID="$WRITER_ID" \
  -w /app webapp node --input-type=module -) <<'NODE'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const owner = process.env.OWNER_ID, writer = process.env.WRITER_ID
  const project = await prisma.project.create({ data: { userId: owner, name: 'rbac-conversations', targetDomain: 'rbac.test' } })
  await prisma.projectCollaborator.create({
    data: { projectId: project.id, userId: writer, access: 'write', useAgent: true, grantedById: owner },
  })
  await prisma.projectAccessPolicy.create({
    data: { projectId: project.id, ownerCredentialConsentAt: new Date(), ownerCredentialConsentById: owner },
  })
  const mine = await prisma.conversation.create({ data: { projectId: project.id, userId: owner, sessionId: `rbac-conv-owner-${project.id}`, title: 'owner session' } })
  const theirs = await prisma.conversation.create({ data: { projectId: project.id, userId: writer, sessionId: `rbac-conv-writer-${project.id}`, title: 'writer session' } })
  console.log(`${project.id} ${mine.id} ${theirs.id}`)
} finally {
  await prisma.$disconnect()
}
NODE
)"
read -r PROJECT_ID OWN_CONV WRITER_CONV <<< "$(printf '%s' "$ids" | tail -n 1)"
for v in "${PROJECT_ID:-}" "${OWN_CONV:-}" "${WRITER_CONV:-}"; do
  safe_id "$v" || { echo "FAIL  could not create the project, its share and the conversations"; exit 1; }
done

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
  local args=(-s -m 60 -o "$TMP/body" -w '%{http_code}' -X "$method" -b "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}
body_field() { # dotted path into the JSON body -> its value (or ?)
  python3 -c 'import json,sys
b=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): b=b.get(k) if isinstance(b,dict) else None
print(json.dumps(b))' "$TMP/body" "$1" 2>/dev/null || echo "?"
}
listed() { # jar -> 1 when the writer's conversation is in the owner's list
  [ "$(call "$1" GET "/api/conversations?projectId=$PROJECT_ID")" = 200 ] || { echo "?"; return; }
  python3 -c 'import json,sys; print(1 if any(c.get("id")==sys.argv[2] for c in json.load(open(sys.argv[1]))) else 0)' "$TMP/body" "$WRITER_CONV" 2>/dev/null || echo "?"
}

declare -A JARS=([owner]="${SEED[MEMBER_C_EMAIL]}" [writer]="${SEED[MEMBER_B_EMAIL]}" [stranger]="${SEED[MEMBER_A_EMAIL]}")
for who in owner writer stranger; do
  sign_in "${JARS[$who]}" "$TMP/jar.$who" || { check "sign in as $who" 0; exit 1; }
done

code="$(call "$TMP/jar.owner" GET "/api/conversations/$WRITER_CONV")"
check "B's conversation is hidden from A (404)" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
l="$(listed "$TMP/jar.owner")"
check "A's list does not hold B's conversation" "$([ "$l" = 0 ] && echo 1 || echo 0)" "got $l"
code="$(call "$TMP/jar.owner" GET "/api/conversations/$OWN_CONV")"
check "A reads A's own conversation (200)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code"

if [ "$IN_FORCE" = 1 ]; then
  code="$(call "$TMP/jar.writer" POST "/api/conversations/$WRITER_CONV/share" '{"shared":true}')"
  check "B shares B's conversation (200)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.owner" GET "/api/conversations/$WRITER_CONV")"
  ro="$(body_field access.readOnly)"
  check "A opens it read-only (200, access.readOnly true)" "$([ "$code" = 200 ] && [ "$ro" = true ] && echo 1 || echo 0)" "got $code readOnly=$ro"
  l="$(listed "$TMP/jar.owner")"
  check "A's list holds it" "$([ "$l" = 1 ] && echo 1 || echo 0)" "got $l"
  code="$(call "$TMP/jar.owner" PATCH "/api/conversations/$WRITER_CONV" '{"title":"changed by the owner"}')"
  check "A cannot write it (404)" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.stranger" GET "/api/conversations/$WRITER_CONV")"
  check "a member without a share gets 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.writer" POST "/api/conversations/$WRITER_CONV/share" '{"shared":false}')"
  check "B stops sharing (200)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.owner" GET "/api/conversations/$WRITER_CONV")"
  check "B's conversation is hidden from A again (404)" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.writer" POST "/api/conversations/policy?projectId=$PROJECT_ID" '{"managersSeeAllConversations":true}')"
  check "B cannot set the policy (403)" "$([ "$code" = 403 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.owner" POST "/api/conversations/policy?projectId=$PROJECT_ID" '{"managersSeeAllConversations":true}')"
  check "A turns on co-owners see every conversation (200)" "$([ "$code" = 200 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.writer" GET "/api/conversations/policy?projectId=$PROJECT_ID")"
  v="$(body_field managersSeeAllConversations)"
  check "B sees the policy on" "$([ "$code" = 200 ] && [ "$v" = true ] && echo 1 || echo 0)" "got $code $v"
  code="$(call "$TMP/jar.owner" GET "/api/conversations/$WRITER_CONV")"
  check "the policy shows B's conversation to A, read-only (200)" "$([ "$code" = 200 ] && [ "$(body_field access.readOnly)" = true ] && echo 1 || echo 0)" "got $code"
  rows="$(printf "select count(*) from audit_log where project_id = '%s' and action in ('conversation.share','conversation.unshare','project.conversations_policy');\n" "$PROJECT_ID" | db_sql | tail -n 1)"
  check "each change wrote its audit row (3)" "$([ "$rows" = 3 ] && echo 1 || echo 0)" "got ${rows:-?}"
else
  code="$(call "$TMP/jar.writer" POST "/api/conversations/$WRITER_CONV/share" '{"shared":true}')"
  check "the share route answers 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
  code="$(call "$TMP/jar.owner" GET "/api/conversations/policy?projectId=$PROJECT_ID")"
  check "the policy route answers 404" "$([ "$code" = 404 ] && echo 1 || echo 0)" "got $code"
fi

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
