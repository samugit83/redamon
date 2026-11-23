#!/usr/bin/env bash
#
# Live check of RBAC step 1.15 (HD-18, HD-19, HD-21, NF-01, NF-12; E2E row P0-09, terminal half),
# run against the LIVE stack after the agent is rebuilt:
#   - the holder's own Kali sandbox: no process holds SCANNER_API_KEY (experiment E3 repeated over
#     /proc/*/environ, PID 1 included), and PID 1's only *_KEY/_TOKEN names are its instance's two
#     inbound tokens and its sandbox key. The sandbox is found by its labels; when none runs the
#     orchestrator starts it with the holder's own project, and the clean-up removes the holder's
#     sandboxes and output folders (account_deleted) before it deletes the accounts;
#   - inside the agent container (tests/rbac_run_credential_live_ws.py): /graph/exec,
#     /text-to-cypher and /traffic/exec refuse the bare scanner key; the master key and a graph
#     run credential open /graph/exec; an expired credential and a traffic one are refused with
#     their codes; a credential whose run no open terminal holds is refused
#     (`run_credential_closed`); a traffic credential of another run than its ctx tag is
#     refused (`run_credential_ctx_mismatch`); a legacy holder's terminal shell has no service
#     key and holds its run credential, and `redagraph types` / `redagraph ls Domain` answer
#     with it, as does a copy of it presented from outside the shell's environment;
#   - that copy is refused once the terminal has closed (it dies with the socket, not after
#     12 hours);
#   - the agent logged `[rbac] run credential refused reason=expired`.
# The kali_shell half of P0-09 is the step-0.7 scripted stub run `kali-shell-env`, which must now
# print 0 (see the step's progress-log entry for the command).
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-* projects),
# removed with their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C; both are fed to the
# webapp container on stdin. The ticket reaches the agent container on stdin, never on a command
# line, and is never printed; nor are credentials, keys or terminal output. The terminal grant is
# written through psql in the postgres container (SQL on stdin). The orchestrator's key reaches
# curl on stdin.
#
# Needs the stack up (webapp on :3000, agent, postgres; a sandbox starts on demand); prints SKIP
# and exits 0 when it is not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_run_credential_live.sh            (BASE_URL overrides :3000)
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
CRED_FILE=""
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
# holder's sandboxes (the terminal uses one) and output folders go first, as an account deletion
# takes them (the one stop reason that also deletes the folders).
retire_sandboxes_of() { # user-id
  local out
  out="$(orch_call POST "/sandboxes/$1/stop" '{"reason":"account_deleted"}')"
  echo "  a fixture person's sandboxes and output folders removed: HTTP ${out##*$'\n'}"
}
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  [ -n "${CRED_FILE:-}" ] && [ -n "$SBX" ] && docker exec "$SBX" rm -f "$CRED_FILE" >/dev/null 2>&1
  echo "== Cleaning up fixtures =="
  [ -n "$SBX_USER" ] && retire_sandboxes_of "$SBX_USER"
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in MEMBER_B_EMAIL MEMBER_B_ID PB_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
for k in MEMBER_B_ID PB_ID; do [[ "${SEED[$k]}" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected $k"; exit 1; }; done

# The sandbox the holder's terminal runs in: member B's own.
echo "== The holder's sandbox holds no scanner key (E3 repeated) =="
SBX_USER="${SEED[MEMBER_B_ID]}"
SBX="$(own_sandbox "$SBX_USER")"
if [ -z "$SBX" ]; then
  read -r code state _ < <(ensure_sandbox "$SBX_USER" "${SEED[PB_ID]}")
  SBX="$(own_sandbox "$SBX_USER")"
  ok=0; [ "$code" = 200 ] && [ "$state" = running ] && [ -n "$SBX" ] && ok=1
  check "the orchestrator starts member B's sandbox with its own project -> $code ${state:--}" "$ok"
  [ "$ok" = 1 ] || exit 1
fi
# Names only: the values never leave the container.
holders="$(docker exec "$SBX" sh -c \
  'n=0; for e in /proc/[0-9]*/environ; do tr "\0" "\n" < "$e" 2>/dev/null | grep -q "^SCANNER_API_KEY=" && n=$((n+1)); done; echo $n')"
ok=0; [ "$holders" = 0 ] && ok=1
check "no process of the sandbox holds SCANNER_API_KEY -> ${holders:-?}" "$ok"
# REDAMON_SANDBOX_KEY is the person's key (a hash of the user id, no secret): exact names, not a count.
pid1="$(docker exec "$SBX" sh -c \
  'tr "\0" "\n" < /proc/1/environ | cut -d= -f1 | grep -E "_(KEY|TOKEN|SECRET|PASSWORD)$" | sort | tr "\n" " "')"
ok=0; [ "$pid1" = "MCP_AUTH_TOKEN REDAMON_SANDBOX_KEY TUNNEL_AUTH_TOKEN " ] && ok=1
check "PID 1 keeps only its instance's two inbound tokens and its key -> ${pid1:-?}" "$ok"

granted="$(printf "update users set legacy_grants = array['kali_terminal'] where id = '%s' returning id;\n" "${SEED[MEMBER_B_ID]}" | db_sql)"
ok=0; [ "$granted" = "${SEED[MEMBER_B_ID]}" ] && ok=1
check "the kali_terminal legacy grant set on member B by SQL" "$ok"
[ "$ok" = 1 ] || exit 1

JAR="$TMP/jar"
printf '{"email":"%s","password":"%s"}' "${SEED[MEMBER_B_EMAIL]}" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
code="$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$JAR" -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/login.json")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-member-b answered $code"; exit 1; }
printf '{"projectId":"%s","sessionId":"rbac-live-115","socket":"kali-terminal"}' "${SEED[PB_ID]}" > "$TMP/req"
code="$(curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -X POST -b "$JAR" -H "Origin: $BASE" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/req" "$BASE/api/agent/ws-ticket")"
T_TERM="$(python3 -c 'import json,sys; t=json.load(open(sys.argv[1])).get("ticket"); print(t if isinstance(t,str) else "")' "$TMP/body" 2>/dev/null)"
ok=0; [ "$code" = 200 ] && [ -n "$T_TERM" ] && ok=1
check "the legacy holder gets a terminal ticket -> $code" "$ok"

echo "== Routes and the terminal (agent container) =="
if [ -z "$T_TERM" ]; then
  check "the agent-side checks need the terminal ticket" 0
else
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Inside the holder's sandbox: where the terminal's shell copies its credential (never printed).
  CRED_FILE="/tmp/rbac-live-115-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  { printf 'T_TERM = "%s"\nHOLDER_ID = "%s"\nHOLDER_PID = "%s"\nCRED_FILE = "%s"\n' \
      "$T_TERM" "${SEED[MEMBER_B_ID]}" "${SEED[PB_ID]}" "$CRED_FILE"
    cat "$ROOT/tests/rbac_run_credential_live_ws.py"
  } | (cd "$ROOT" && docker compose exec -T agent python3 -) > "$TMP/ws.out" 2>&1
  grep -E '^(PASS|FAIL)  ' "$TMP/ws.out"
  if read -r _ ws_pass ws_fail < <(grep '^RESULT_WS ' "$TMP/ws.out"); then
    PASS=$((PASS + ws_pass)); FAIL=$((FAIL + ws_fail))
  else
    # Only the exception's class: a traceback line can quote a URL with a ticket in it.
    check "the agent-side checks ran to the end" 0 "$(grep -oE '^[A-Za-z_.]*(Error|Exception)' "$TMP/ws.out" | tail -1)"
  fi
  # The terminal has closed: the same copy, presented again from the sandbox, is refused.
  # Status and code only; the file is removed whatever the answer. Looked up again by its
  # labels: the terminal's shell wrote the copy in whichever instance served it.
  SBX="$(own_sandbox "$SBX_USER")"
  after="$(docker exec -e CRED_FILE="$CRED_FILE" "${SBX:-no-running-sandbox}" sh -c '
    [ -s "$CRED_FILE" ] || { echo missing; exit 0; }
    url="${REDAMON_AGENT_URL:-http://agent:8080}/graph/exec"; out=/tmp/rbac-live-115-after.$$
    for i in 1 2 3 4 5 6 7 8 9 10; do
      code=$(curl -s -o "$out" -w "%{http_code}" -H "X-Redamon-Run: $(cat "$CRED_FILE")" \
        -H "Content-Type: application/json" -d "{\"op\":\"types\",\"user_id\":\"x\",\"project_id\":\"y\"}" "$url")
      [ "$code" != 200 ] && break; sleep 1
    done
    echo "$code $(grep -o "run_credential_[a-z_]*" "$out" | head -1)"; rm -f "$CRED_FILE" "$out"')"
  ok=0; [ "$after" = "401 run_credential_closed" ] && ok=1
  check "the copy is refused once the terminal has closed -> ${after:-?}" "$ok"
  logged="$(cd "$ROOT" && docker compose logs --since "$since" agent 2>/dev/null | grep -c '\[rbac\] run credential refused reason=expired')"
  ok=0; [ "${logged:-0}" -ge 1 ] && ok=1
  check "the agent logged the refused expired credential -> ${logged:-0}" "$ok"
fi
T_TERM=""

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
