#!/usr/bin/env bash
#
# Live check of RBAC step 1.18 (HD-29, HD-30, HD-32; E2E row P0-10, API part), run against
# the LIVE stack after the webapp and agent are rebuilt:
#   - a member is refused the legacy access review (403) and gets no `rbac` block from
#     /api/auth/me; an admin gets it, and sees the fixture holder's two grants pending;
#   - no request adds a grant: action `add` is 400, keeping a grant the account lacks 409;
#   - Keep writes one rbac.legacy_grant.keep row; Remove of the Kali terminal grant writes
#     one rbac.legacy_grant.remove row and closes the holder's OPEN terminal (close 4403,
#     watched from inside the agent container by tests/rbac_legacy_review_live_ws.py);
#     the holder is then refused a new terminal ticket; a second Remove changes nothing.
#     The terminal runs in the holder's own Kali sandbox: found by its labels, or started by
#     the orchestrator with the holder's own project before the ticket is minted, so the
#     shell answers within the socket check's 20 s; the clean-up removes the holder's
#     sandboxes and output folders (account_deleted) before it deletes the accounts;
#   - the "What changed" card: a member 403, the admin's dismissal is one row and sticks.
#
# Decisions are made only on fixture accounts: keep_all and remove_all are never sent,
# since they would decide the grants of this stack's real members. Fixtures are synthetic
# (webapp/scripts/e2e-rbac-seed.mjs: rbac-*@e2e.local) and removed with their audit rows by
# e2e-rbac-cleanup.mjs, even on Ctrl-C. Response bodies, tickets and cookies are never
# printed; the admin's listing also names real members, so it is only parsed, in Python.
#
# Needs the stack up (webapp on :3000, agent, postgres; the holder's terminal starts its own
# Kali sandbox on demand); prints SKIP and exits 0 when it is not. As a *_live.sh it is never in
# the gate.
#
# Run:  bash tests/rbac_legacy_review_live.sh            (BASE_URL overrides :3000)
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
# The orchestrator labels each sandbox it starts with its own compose project: this stack's.
STACK_OWNER="$(docker ps --filter 'name=^redamon-recon-orchestrator$' --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | head -1)"
if [ -z "$STACK_OWNER" ]; then
  echo "FAIL  no compose project on a running redamon-recon-orchestrator: this stack's sandboxes cannot be told apart"
  exit 1
fi

TMP="$(mktemp -d)"
CLEANED_UP=0
WS_PID=""
SBX=""; SBX_USER=""
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
env_value() { # KEY: from the environment, else the repo-root .env; never printed
  if [ -n "${!1:-}" ]; then printf '%s' "${!1}"; return; fi
  grep -m1 "^$1=" "$ROOT/.env" 2>/dev/null | cut -d= -f2- | sed "s/^[\"']//; s/[\"']\$//"
}
# The orchestrator's API, called as the webapp calls it. The key reaches curl on stdin. Prints
# the answer's body, then its HTTP status on a line of its own.
orch_call() { # method path [json-body]
  local key port args=(-s -m 300 -K - -X "$1" -H 'Content-Type: application/json' -w '\n%{http_code}')
  [ -n "${3:-}" ] && args+=(--data-binary "$3")
  key="$(env_value ORCHESTRATOR_API_KEY)"
  port="$(env_value RECON_ORCH_PORT | grep -xE '[0-9]+' || echo 8010)"
  printf 'header = "X-Orchestrator-Key: %s"\n' "${key:-changeme}" | curl "${args[@]}" "http://127.0.0.1:$port$2"
}
# The person's running sandbox (own view) of this stack, found by its labels. Newest first: an
# instance being replaced comes after the one replacing it.
own_sandbox() { # user-id
  docker ps --filter label=redamon.sandbox=1 --filter "label=redamon.sandbox.user=$1" \
    --filter label=redamon.sandbox.view=own --filter "label=redamon.sandbox.owner=$STACK_OWNER" \
    --format '{{.Names}}' 2>/dev/null | head -1
}
# The person's sandbox started (or found) and waited for -> "<HTTP status> <state> <fresh 0|1>".
# The answer holds the instance's tokens: only those three fields are kept.
ensure_sandbox() { # user-id project-id,...
  local p list="" out state
  for p in ${2//,/ }; do list+="${list:+,}\"$p\""; done
  out="$(orch_call POST /sandboxes/ensure \
    "{\"user_id\":\"$1\",\"view\":\"own\",\"projects\":[$list],\"need_project\":null,\"wait\":true,\"touch\":false}")"
  state="$(printf '%s' "$out" | grep -o '"state": *"[a-z_]*"' | head -1 | sed 's/.*"\([a-z_]*\)"$/\1/')"
  printf '%s %s %s\n' "${out##*$'\n'}" "${state:--}" "$(printf '%s' "$out" | grep -q '"fresh": *true' && echo 1 || echo 0)"
}
# The fixture cleanup deletes the accounts by SQL, which the orchestrator never hears of: the
# holder's sandboxes (its terminal uses one) and output folders go first, as an account deletion
# takes them (the one stop reason that also deletes the folders).
retire_sandboxes_of() { # user-id
  local out
  out="$(orch_call POST "/sandboxes/$1/stop" '{"reason":"account_deleted"}')"
  echo "  a fixture person's sandboxes and output folders removed: HTTP ${out##*$'\n'}"
}
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  [ -n "$WS_PID" ] && kill "$WS_PID" 2>/dev/null
  echo "== Cleaning up fixtures =="
  [ -n "$SBX_USER" ] && retire_sandboxes_of "$SBX_USER"
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
for k in ADMIN_A_EMAIL ADMIN_A_ID MEMBER_A_EMAIL MEMBER_A_ID MEMBER_B_EMAIL MEMBER_B_ID PB_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
for k in ADMIN_A_ID MEMBER_A_ID MEMBER_B_ID PB_ID; do safe_id "${SEED[$k]}" || { echo "unexpected $k"; exit 1; }; done
ADMIN="${SEED[ADMIN_A_ID]}"; HOLDER="${SEED[MEMBER_B_ID]}"; NEWBIE="${SEED[MEMBER_A_ID]}"
SBX_USER="$HOLDER"

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
login() { # email jar -> http code
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
call() { # jar method path [json-body] -> http code; the body lands in $TMP/body, never printed
  local args=(-s -m 30 -o "$TMP/body" -w '%{http_code}' -X "$2" -b "$1" -H "Origin: $BASE")
  if [ -n "${4:-}" ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$3"
}
body_has() { grep -qF -- "$1" "$TMP/body"; }
py_body() { # python expression over `b` (the parsed body) -> printed value
  python3 -c "import json,sys; b=json.load(open(sys.argv[1])); print($1)" "$TMP/body" 2>/dev/null
}
grants_of() { printf "select array_to_string(legacy_grants, ',') from users where id = '%s';\n" "$1" | db_sql; }
rows_of() { # action grant -> count of decisions on the holder by the fixture admin
  printf "select count(*) from audit_log where action = '%s' and actor_id = '%s' and target_type = 'user' and target_id = '%s' and after->>'grant' = '%s';\n" \
    "$1" "$ADMIN" "$HOLDER" "$2" | db_sql
}
mint_terminal() { # jar -> http code; the ticket lands in $TMP/body
  printf '{"projectId":"%s","sessionId":"rbac-live-118","socket":"kali-terminal"}' "${SEED[PB_ID]}" > "$TMP/req"
  curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -X POST -b "$1" -H "Origin: $BASE" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/req" "$BASE/api/agent/ws-ticket"
}

granted="$(printf "update users set legacy_grants = array['kali_terminal','shell_sessions'] where id = '%s' returning id;\n" "$HOLDER" | db_sql)"
ok=0; [ "$granted" = "$HOLDER" ] && ok=1
check "member B holds kali_terminal and shell_sessions (set by SQL, as the backfill would)" "$ok"
[ "$ok" = 1 ] || exit 1

ADMIN_JAR="$TMP/jar.admin"; NEW_JAR="$TMP/jar.new"; HOLDER_JAR="$TMP/jar.holder"
for pair in "${SEED[ADMIN_A_EMAIL]}:$ADMIN_JAR" "${SEED[MEMBER_A_EMAIL]}:$NEW_JAR" "${SEED[MEMBER_B_EMAIL]}:$HOLDER_JAR"; do
  code="$(login "${pair%%:*}" "${pair#*:}")"
  [ "$code" = 200 ] || { echo "FAIL  sign-in as ${pair%%:*} answered $code"; exit 1; }
done

echo "== Who reviews =="
code="$(call "$NEW_JAR" GET /api/admin/legacy-grants)"
ok=0; [ "$code" = 403 ] && body_has '"code":"forbidden"' && ok=1
check "a member is refused the review -> $code" "$ok"
code="$(call "$NEW_JAR" POST /api/admin/legacy-grants "{\"action\":\"remove\",\"userId\":\"$HOLDER\",\"grant\":\"kali_terminal\"}")"
ok=0; [ "$code" = 403 ] && ok=1
check "a member cannot decide -> $code" "$ok"
code="$(call "$NEW_JAR" GET /api/auth/me)"
ok=0; [ "$code" = 200 ] && ! body_has '"rbac"' && ok=1
check "a member's /api/auth/me has no rbac block" "$ok"
code="$(call "$ADMIN_JAR" GET /api/auth/me)"
v="$(py_body 'isinstance(b["rbac"]["compat"], bool) and isinstance(b["rbac"]["legacyGrantsPending"], int) and b["rbac"]["legacyGrantsPending"] >= 2')"
ok=0; [ "$code" = 200 ] && [ "$v" = True ] && ok=1
check "the admin's /api/auth/me carries rbac.compat and the pending count" "$ok"
code="$(call "$ADMIN_JAR" GET /api/admin/legacy-grants)"
v="$(py_body "[g['state'] for h in b['holders'] if h['id'] == '$HOLDER' for g in h['grants']] == ['pending', 'pending']")"
ok=0; [ "$code" = 200 ] && [ "$v" = True ] && ok=1
check "the admin's review lists member B with both grants pending" "$ok"

echo "== No add path =="
code="$(call "$ADMIN_JAR" POST /api/admin/legacy-grants "{\"action\":\"add\",\"userId\":\"$NEWBIE\",\"grant\":\"kali_terminal\"}")"
ok=0; [ "$code" = 400 ] && body_has invalid_action && [ -z "$(grants_of "$NEWBIE")" ] && ok=1
check "action add -> $code, member A still holds nothing" "$ok"
code="$(call "$ADMIN_JAR" POST /api/admin/legacy-grants "{\"action\":\"keep\",\"userId\":\"$NEWBIE\",\"grant\":\"kali_terminal\"}")"
ok=0; [ "$code" = 409 ] && body_has not_held && [ -z "$(grants_of "$NEWBIE")" ] && ok=1
check "keeping a grant member A never held -> $code" "$ok"

echo "== Keep =="
code="$(call "$ADMIN_JAR" POST /api/admin/legacy-grants "{\"action\":\"keep\",\"userId\":\"$HOLDER\",\"grant\":\"shell_sessions\"}")"
ok=0; [ "$code" = 200 ] && body_has '"changed":true' && [ "$(rows_of rbac.legacy_grant.keep shell_sessions)" = 1 ] && ok=1
check "Keep the shell sessions grant -> $code, one rbac.legacy_grant.keep row" "$ok"

echo "== Remove closes the open terminal =="
# Warm before the mint: the ticket lives 60 s, a cold sandbox start can take longer.
SBX="$(own_sandbox "$SBX_USER")"
if [ -z "$SBX" ]; then
  read -r code state _ < <(ensure_sandbox "$SBX_USER" "${SEED[PB_ID]}")
  SBX="$(own_sandbox "$SBX_USER")"
  ok=0; [ "$code" = 200 ] && [ "$state" = running ] && [ -n "$SBX" ] && ok=1
  check "the orchestrator starts member B's sandbox with its own project -> $code ${state:--}" "$ok"
fi
code="$(mint_terminal "$HOLDER_JAR")"
T_LEGACY="$(python3 -c 'import json,sys; t=json.load(open(sys.argv[1])).get("ticket"); print(t if isinstance(t,str) else "")' "$TMP/body" 2>/dev/null)"
ok=0; [ "$code" = 200 ] && [ -n "$T_LEGACY" ] && ok=1
check "member B gets a terminal ticket while it holds the grant -> $code" "$ok"
if [ "$ok" = 1 ]; then
  { printf 'T_LEGACY = "%s"\nLEGACY_ID = "%s"\nLEGACY_PID = "%s"\n' "$T_LEGACY" "$HOLDER" "${SEED[PB_ID]}"
    cat "$ROOT/tests/rbac_legacy_review_live_ws.py"
  } | (cd "$ROOT" && docker compose exec -T agent python3 -) > "$TMP/ws.out" 2>&1 &
  WS_PID=$!
  T_LEGACY=""
  for _ in $(seq 1 60); do
    grep -q '^OPEN$' "$TMP/ws.out" 2>/dev/null && break
    kill -0 "$WS_PID" 2>/dev/null || break
    sleep 0.5
  done
  if grep -q '^OPEN$' "$TMP/ws.out" 2>/dev/null; then
    code="$(call "$ADMIN_JAR" POST /api/admin/legacy-grants "{\"action\":\"remove\",\"userId\":\"$HOLDER\",\"grant\":\"kali_terminal\"}")"
    ok=0; [ "$code" = 200 ] && body_has '"changed":true' && body_has '"terminal":{"closed":' && ! body_has '"closed":0' && ok=1
    check "Remove Kali terminal -> $code, the agent reports the terminal closed" "$ok"
  else
    check "the terminal opened before the removal" 0
  fi
  wait "$WS_PID" 2>/dev/null
  WS_PID=""
  grep -E '^(PASS|FAIL)  ' "$TMP/ws.out"
  if read -r _ ws_pass ws_fail < <(grep '^RESULT_WS ' "$TMP/ws.out"); then
    PASS=$((PASS + ws_pass)); FAIL=$((FAIL + ws_fail))
  else
    # Only the exception's class: a traceback line can quote a URL with a ticket in it.
    check "the socket check ran to the end" 0 "$(grep -oE '^[A-Za-z_.]*(Error|Exception)' "$TMP/ws.out" | tail -1)"
  fi
fi

ok=0; [ "$(grants_of "$HOLDER")" = shell_sessions ] && ok=1
check "member B now holds only the kept grant" "$ok"
ok=0; [ "$(rows_of rbac.legacy_grant.remove kali_terminal)" = 1 ] && ok=1
check "one rbac.legacy_grant.remove row (after.grant = kali_terminal) by the admin" "$ok"
code="$(mint_terminal "$HOLDER_JAR")"
ok=0; [ "$code" = 403 ] && ! body_has '"ticket"' && ok=1
check "member B is refused a new terminal ticket -> $code" "$ok"
code="$(call "$ADMIN_JAR" POST /api/admin/legacy-grants "{\"action\":\"remove\",\"userId\":\"$HOLDER\",\"grant\":\"kali_terminal\"}")"
ok=0; [ "$code" = 200 ] && body_has '"changed":false' && [ "$(rows_of rbac.legacy_grant.remove kali_terminal)" = 1 ] && ok=1
check "the same removal again changes nothing -> $code" "$ok"
code="$(call "$ADMIN_JAR" POST /api/admin/legacy-grants "{\"action\":\"keep\",\"userId\":\"$HOLDER\",\"grant\":\"kali_terminal\"}")"
ok=0; [ "$code" = 409 ] && grep -q '^shell_sessions$' <<< "$(grants_of "$HOLDER")" && ok=1
check "keeping the removed grant -> $code, it is not given back" "$ok"

echo "== What changed in this update =="
code="$(call "$NEW_JAR" GET /api/admin/whats-new)"
ok=0; [ "$code" = 403 ] && ok=1
check "a member is refused the update notes -> $code" "$ok"
code="$(call "$ADMIN_JAR" GET /api/admin/whats-new)"
ok=0; [ "$code" = 200 ] && body_has '"dismissed":false' && ok=1
check "the fixture admin has not dismissed the card -> $code" "$ok"
code="$(call "$ADMIN_JAR" POST /api/admin/whats-new '{"action":"dismiss"}')"
ok=0; [ "$code" = 200 ] && body_has '"changed":true' && ok=1
check "Got it -> $code" "$ok"
code="$(call "$ADMIN_JAR" GET /api/admin/whats-new)"
n="$(printf "select count(*) from audit_log where action = 'rbac.whats_new_dismissed' and actor_id = '%s';\n" "$ADMIN" | db_sql)"
ok=0; [ "$code" = 200 ] && body_has '"dismissed":true' && [ "$n" = 1 ] && ok=1
check "the card stays dismissed, one rbac.whats_new_dismissed row" "$ok"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
