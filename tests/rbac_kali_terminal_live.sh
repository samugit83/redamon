#!/usr/bin/env bash
#
# Live check of RBAC step 1.14 (HD-04, HD-25, NF-04, DV-21; E2E row P0-07, API part), run
# against the LIVE stack after the webapp and agent are rebuilt:
#   - a member created after the upgrade (no legacy grant) is refused a terminal ticket, while
#     the same member's chat ticket is minted; a legacy holder (grant set by SQL, as this stack
#     holds one: the override the legacy grants' conversion writes once it has run, else the
#     legacy_grants column) gets one, and audit_log records agent.terminal_opened for it, naming
#     that path as its `via`;
#   - inside the agent container (tests/rbac_kali_terminal_live_ws.py): the chat ticket does
#     not open /ws/kali-terminal, the terminal ticket does not open /ws/cypherfix-triage, the
#     holder's own Kali sandbox's terminal refuses an upgrade without its instance's bearer, the
#     holder's shell runs as the ticket's user and project whatever the init frame says, and the
#     master-key POST /ws/close ends the holder's open terminal with close 4403.
# The holder's sandbox is found by its labels; when none runs the orchestrator starts it with the
# holder's own project before the tickets are minted (they live 60 s). The clean-up removes both
# members' sandboxes and output folders (account_deleted) before it deletes the accounts.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-* projects),
# removed with their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C; both are fed to the
# webapp container on stdin. Tickets reach the agent container on stdin too, never on a command
# line, and are never printed; nor are response bodies, passwords or terminal output. The grant
# is written through psql in the postgres container (SQL on stdin). The orchestrator's key
# reaches curl on stdin.
#
# Needs the stack up (webapp on :3000, agent, postgres; a sandbox starts on demand); prints SKIP
# and exits 0 when it is not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_kali_terminal_live.sh            (BASE_URL overrides :3000)
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
SBX=""; SBX_USER=""; RETIRE=""
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
# How a holder of the legacy kali_terminal grant holds it on this stack (legacyOverrides.ts): once
# the first boot with the permissions switch on has converted the legacy grants (its marker row
# exists), only override grants count, a kept grant being the override written below; before that,
# or with the switch off, the legacy_grants column counts. -> override | legacy
legacy_grant_path() {
  local flags marker
  flags="$( (cd "$ROOT" && docker compose exec -T webapp \
    sh -c 'printf "%s %s" "${RBAC_IDENTITY_ENABLED:-}" "${RBAC_PERMISSIONS_ENABLED:-}"') 2>/dev/null | tr '[:upper:]' '[:lower:]')"
  marker="$(printf "select count(*) from audit_log where action = 'system.rbac_legacy_overrides_backfill';\n" | db_sql)"
  # flags.ts: the permissions switch reads off without the identity switch.
  if [[ "$flags" =~ ^[[:space:]]*(true|1|yes)[[:space:]]+(true|1|yes)[[:space:]]*$ ]] && [[ "$marker" =~ ^[1-9][0-9]*$ ]]; then
    echo override
  else
    echo legacy
  fi
}
grant_kali_terminal() { # user-id via -> the user id once the grant is written
  if [ "$2" = override ]; then
    printf "insert into user_permission_overrides (user_id, permission, effect, expires_at, reason, granted_by_id) values ('%s', 'platform:kali_terminal', 'grant', (now() at time zone 'UTC') + interval '90 days', 'kept from 7.7.x', 'system') on conflict (user_id, permission) do nothing returning user_id;\n" "$1" | db_sql
  else
    printf "update users set legacy_grants = array['kali_terminal'] where id = '%s' returning id;\n" "$1" | db_sql
  fi
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
# The fixture cleanup deletes the accounts by SQL, which the orchestrator never hears of: their
# sandboxes (the ticket mints warm them, the terminal uses one) and output folders go first, as an
# account deletion takes them (the one stop reason that also deletes the folders).
retire_sandboxes_of() { # user-id
  local out
  out="$(orch_call POST "/sandboxes/$1/stop" '{"reason":"account_deleted"}')"
  echo "  a fixture person's sandboxes and output folders removed: HTTP ${out##*$'\n'}"
}
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  for u in $RETIRE; do retire_sandboxes_of "$u"; done
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
for k in MEMBER_A_EMAIL MEMBER_A_ID MEMBER_B_EMAIL MEMBER_B_ID PA_ID PB_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
for k in MEMBER_A_ID MEMBER_B_ID PA_ID PB_ID; do safe_id "${SEED[$k]}" || { echo "unexpected $k"; exit 1; }; done
RETIRE="${SEED[MEMBER_A_ID]} ${SEED[MEMBER_B_ID]}"

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
login() { # email jar -> http code
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
mint() { # jar project socket -> http code; the body lands in $TMP/body, never printed
  printf '{"projectId":"%s","sessionId":"rbac-live-114","socket":"%s"}' "$2" "$3" > "$TMP/req"
  curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -X POST -b "$1" -H "Origin: $BASE" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/req" "$BASE/api/agent/ws-ticket"
}
ticket_of_body() {
  python3 -c 'import json,sys; t=json.load(open(sys.argv[1])).get("ticket"); print(t if isinstance(t,str) else "")' "$TMP/body" 2>/dev/null
}

NEW_JAR="$TMP/jar.new"; LEGACY_JAR="$TMP/jar.legacy"
code="$(login "${SEED[MEMBER_A_EMAIL]}" "$NEW_JAR")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-member-a answered $code"; exit 1; }
code="$(login "${SEED[MEMBER_B_EMAIL]}" "$LEGACY_JAR")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-member-b answered $code"; exit 1; }

echo "== The holder's sandbox (member B's own, by its labels) =="
SBX_USER="${SEED[MEMBER_B_ID]}"
SBX="$(own_sandbox "$SBX_USER")"
if [ -z "$SBX" ]; then
  read -r code state _ < <(ensure_sandbox "$SBX_USER" "${SEED[PB_ID]}")
  SBX="$(own_sandbox "$SBX_USER")"
  ok=0; [ "$code" = 200 ] && [ "$state" = running ] && [ -n "$SBX" ] && ok=1
  check "the orchestrator starts member B's sandbox with its own project -> $code ${state:--}" "$ok"
else
  echo "  member B's sandbox already runs"
fi

echo "== Tickets (webapp) =="
code="$(mint "$NEW_JAR" "${SEED[PA_ID]}" kali-terminal)"
ok=0; [ "$code" = 403 ] && grep -q '"permission":"platform:kali_terminal"' "$TMP/body" && ! grep -q '"ticket"' "$TMP/body" && ok=1
check "a new member is refused a terminal ticket -> $code" "$ok"
code="$(mint "$LEGACY_JAR" "${SEED[PB_ID]}" kali-terminal)"
ok=0; [ "$code" = 403 ] && ok=1
check "member B is refused too, before it holds the grant -> $code" "$ok"

GRANT_VIA="$(legacy_grant_path)"
granted="$(grant_kali_terminal "${SEED[MEMBER_B_ID]}" "$GRANT_VIA")"
ok=0; [ "$granted" = "${SEED[MEMBER_B_ID]}" ] && ok=1
check "member B made a legacy kali_terminal holder by SQL, as this stack holds one: $GRANT_VIA" "$ok"
[ "$ok" = 1 ] || exit 1

code="$(mint "$NEW_JAR" "${SEED[PA_ID]}" agent)"
T_AGENT="$(ticket_of_body)"
ok=0; [ "$code" = 200 ] && [ -n "$T_AGENT" ] && ok=1
check "the new member still gets a chat ticket -> $code" "$ok"
code="$(mint "$LEGACY_JAR" "${SEED[PB_ID]}" kali-terminal)"
T_LEGACY="$(ticket_of_body)"
ok=0; [ "$code" = 200 ] && [ -n "$T_LEGACY" ] && ok=1
check "the legacy holder gets a terminal ticket -> $code" "$ok"
code="$(mint "$NEW_JAR" "${SEED[PA_ID]}" rbac-bogus)"
ok=0; [ "$code" = 400 ] && grep -q unknown_socket "$TMP/body" && ok=1
check "an unknown socket -> $code" "$ok"

row="$(printf "select count(*) || chr(9) || coalesce(max(after->>'via'), '') from audit_log where action = 'agent.terminal_opened' and actor_id = '%s' and target_type = 'project' and target_id = '%s';\n" "${SEED[MEMBER_B_ID]}" "${SEED[PB_ID]}" | db_sql)"
ok=0; [ "$row" = "1"$'\t'"$GRANT_VIA" ] && ok=1
check "audit_log: one agent.terminal_opened for the holder, via $GRANT_VIA" "$ok" "got: ${row:-none}"
row="$(printf "select count(*) from audit_log where action = 'agent.terminal_opened' and actor_id = '%s';\n" "${SEED[MEMBER_A_ID]}" | db_sql)"
ok=0; [ "$row" = 0 ] && ok=1
check "audit_log: no terminal row for the refused member" "$ok" "got: ${row:-none}"

echo "== Sockets (agent container) =="
if [ -z "$T_AGENT" ] || [ -z "$T_LEGACY" ]; then
  check "socket checks need both tickets" 0
else
  # The sandbox's container name resolves inside the agent, a guest of the sandbox's network.
  { printf 'T_AGENT = "%s"\nT_LEGACY = "%s"\nLEGACY_ID = "%s"\nLEGACY_PID = "%s"\nKALI_WS = "%s"\n' \
      "$T_AGENT" "$T_LEGACY" "${SEED[MEMBER_B_ID]}" "${SEED[PB_ID]}" "${SBX:+ws://$SBX:8016}"
    cat "$ROOT/tests/rbac_kali_terminal_live_ws.py"
  } | (cd "$ROOT" && docker compose exec -T agent python3 -) > "$TMP/ws.out" 2>&1
  grep -E '^(PASS|FAIL)  ' "$TMP/ws.out"
  if read -r _ ws_pass ws_fail < <(grep '^RESULT_WS ' "$TMP/ws.out"); then
    PASS=$((PASS + ws_pass)); FAIL=$((FAIL + ws_fail))
  else
    # Only the exception's class: a traceback line can quote a URL with a ticket in it.
    check "the socket checks ran to the end" 0 "$(grep -oE '^[A-Za-z_.]*(Error|Exception)' "$TMP/ws.out" | tail -1)"
  fi
fi
T_AGENT=""; T_LEGACY=""

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
