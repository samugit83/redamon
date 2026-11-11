#!/usr/bin/env bash
#
# Live check of RBAC step 1.14 (HD-04, HD-25, NF-04, DV-21; E2E row P0-07, API part), run
# against the LIVE stack after the webapp and agent are rebuilt and kali-sandbox restarted:
#   - a member created after the upgrade (no legacy grant) is refused a terminal ticket, while
#     the same member's chat ticket is minted; a legacy holder (grant set by SQL) gets one, and
#     audit_log records agent.terminal_opened for it;
#   - inside the agent container (tests/rbac_kali_terminal_live_ws.py): the chat ticket does
#     not open /ws/kali-terminal, the terminal ticket does not open /ws/cypherfix-triage, the
#     sandbox's terminal refuses an upgrade without the agent's bearer, the holder's shell runs
#     as the ticket's user and project whatever the init frame says, and the master-key
#     POST /ws/close ends the holder's open terminal with close 4403.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-* projects),
# removed with their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C; both are fed to the
# webapp container on stdin. Tickets reach the agent container on stdin too, never on a command
# line, and are never printed; nor are response bodies, passwords or terminal output. The grant
# is written through psql in the postgres container (SQL on stdin).
#
# Needs the stack up (webapp on :3000, agent, kali-sandbox, postgres); prints SKIP and exits 0
# when it is not. As a *_live.sh it is never in the gate.
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
for svc in webapp postgres agent kali-sandbox; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done

TMP="$(mktemp -d)"
CLEANED_UP=0
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
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

echo "== Tickets (webapp) =="
code="$(mint "$NEW_JAR" "${SEED[PA_ID]}" kali-terminal)"
ok=0; [ "$code" = 403 ] && grep -q '"permission":"platform:kali_terminal"' "$TMP/body" && ! grep -q '"ticket"' "$TMP/body" && ok=1
check "a new member is refused a terminal ticket -> $code" "$ok"
code="$(mint "$LEGACY_JAR" "${SEED[PB_ID]}" kali-terminal)"
ok=0; [ "$code" = 403 ] && ok=1
check "member B is refused too, before it holds the grant -> $code" "$ok"

granted="$(printf "update users set legacy_grants = array['kali_terminal'] where id = '%s' returning id;\n" "${SEED[MEMBER_B_ID]}" | db_sql)"
ok=0; [ "$granted" = "${SEED[MEMBER_B_ID]}" ] && ok=1
check "the kali_terminal legacy grant set on member B by SQL" "$ok"
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
ok=0; [ "$row" = $'1\tlegacy' ] && ok=1
check "audit_log: one agent.terminal_opened for the holder, via legacy" "$ok" "got: ${row:-none}"
row="$(printf "select count(*) from audit_log where action = 'agent.terminal_opened' and actor_id = '%s';\n" "${SEED[MEMBER_A_ID]}" | db_sql)"
ok=0; [ "$row" = 0 ] && ok=1
check "audit_log: no terminal row for the refused member" "$ok" "got: ${row:-none}"

echo "== Sockets (agent container) =="
if [ -z "$T_AGENT" ] || [ -z "$T_LEGACY" ]; then
  check "socket checks need both tickets" 0
else
  { printf 'T_AGENT = "%s"\nT_LEGACY = "%s"\nLEGACY_ID = "%s"\nLEGACY_PID = "%s"\n' \
      "$T_AGENT" "$T_LEGACY" "${SEED[MEMBER_B_ID]}" "${SEED[PB_ID]}"
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
