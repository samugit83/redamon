#!/usr/bin/env bash
#
# Live check of RBAC step 1.15 (HD-18, HD-19, HD-21, NF-01, NF-12; E2E row P0-09, terminal half),
# run against the LIVE stack after the agent is rebuilt and kali-sandbox recreated (compose
# dropped its SCANNER_API_KEY):
#   - kali-sandbox: no process holds SCANNER_API_KEY (experiment E3 repeated over /proc/*/environ,
#     PID 1 included);
#   - inside the agent container (tests/rbac_run_credential_live_ws.py): /graph/exec,
#     /text-to-cypher and /traffic/exec refuse the bare scanner key; the master key and a graph
#     run credential open /graph/exec; an expired credential and a traffic one are refused with
#     their codes; a legacy holder's terminal shell has no service key and holds its run
#     credential, and `redagraph types` / `redagraph ls Domain` answer with it;
#   - the agent logged `[rbac] run credential refused reason=expired`.
# The kali_shell half of P0-09 is the step-0.7 scripted stub run `kali-shell-env`, which must now
# print 0 (see the step's progress-log entry for the command).
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-* projects),
# removed with their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C; both are fed to the
# webapp container on stdin. The ticket reaches the agent container on stdin, never on a command
# line, and is never printed; nor are credentials, keys or terminal output. The terminal grant is
# written through psql in the postgres container (SQL on stdin).
#
# Needs the stack up (webapp on :3000, agent, kali-sandbox, postgres); prints SKIP and exits 0
# when it is not. As a *_live.sh it is never in the gate.
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

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}

echo "== The sandbox holds no scanner key (E3 repeated) =="
# Names only: the values never leave the container.
holders="$(cd "$ROOT" && docker compose exec -T kali-sandbox sh -c \
  'n=0; for e in /proc/[0-9]*/environ; do tr "\0" "\n" < "$e" 2>/dev/null | grep -q "^SCANNER_API_KEY=" && n=$((n+1)); done; echo $n')"
ok=0; [ "$holders" = 0 ] && ok=1
check "no kali-sandbox process holds SCANNER_API_KEY -> ${holders:-?}" "$ok"
pid1="$(cd "$ROOT" && docker compose exec -T kali-sandbox sh -c \
  'tr "\0" "\n" < /proc/1/environ | cut -d= -f1 | grep -cE "_(KEY|TOKEN|SECRET|PASSWORD)$"')"
ok=0; [ "$pid1" = 2 ] && ok=1
check "PID 1 keeps only the two inbound tokens (MCP_AUTH_TOKEN, TUNNEL_AUTH_TOKEN) -> ${pid1:-?}" "$ok"

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
  { printf 'T_TERM = "%s"\nHOLDER_ID = "%s"\nHOLDER_PID = "%s"\n' "$T_TERM" "${SEED[MEMBER_B_ID]}" "${SEED[PB_ID]}"
    cat "$ROOT/tests/rbac_run_credential_live_ws.py"
  } | (cd "$ROOT" && docker compose exec -T agent python3 -) > "$TMP/ws.out" 2>&1
  grep -E '^(PASS|FAIL)  ' "$TMP/ws.out"
  if read -r _ ws_pass ws_fail < <(grep '^RESULT_WS ' "$TMP/ws.out"); then
    PASS=$((PASS + ws_pass)); FAIL=$((FAIL + ws_fail))
  else
    # Only the exception's class: a traceback line can quote a URL with a ticket in it.
    check "the agent-side checks ran to the end" 0 "$(grep -oE '^[A-Za-z_.]*(Error|Exception)' "$TMP/ws.out" | tail -1)"
  fi
  logged="$(cd "$ROOT" && docker compose logs --since "$since" agent 2>/dev/null | grep -c '\[rbac\] run credential refused reason=expired')"
  ok=0; [ "${logged:-0}" -ge 1 ] && ok=1
  check "the agent logged the refused expired credential -> ${logged:-0}" "$ok"
fi
T_TERM=""

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
