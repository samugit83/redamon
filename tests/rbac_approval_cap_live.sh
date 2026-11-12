#!/usr/bin/env bash
#
# Live check of RBAC step 3.9b (SH-34, IM-09, AU-02 part), run against the LIVE stack after the
# agent and the webapp are rebuilt from a HEAD that holds the step:
#   - the webapp mints an `agent` ticket with `cap` (member A on its project PA: all four agent
#     permissions, whether RBAC_PERMISSIONS_ENABLED is off or on with A never assigned a set), and
#     a ticket for another socket without one;
#   - inside the agent container (tests/rbac_approval_cap_live_ws.py): tickets with a narrower
#     `cap` are refused the approval, the dangerous-tool confirmation and the Fireteam member
#     confirmation with `permission_required` naming the permission, and the webapp's ticket is
#     not;
#   - the Fireteam answer of the webapp's ticket is saved with its actor (`{"sub": A}`), and the
#     agent logged `[rbac] decision refused`;
#   - POST /api/internal/agent/decisions answers 401 without the internal key and 200 with it,
#     the middleware lets it through without an off-allowlist line, and the audit row names the
#     admin who answered as actor and the member in on_behalf_of_user_id.
# E2E row P3-05 (a Recon operator refused in a scripted stub run) is the Chrome DevTools row of
# phase_07_e2e_matrix.md; this script needs no switch flip and no stub run.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-* projects),
# removed with their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C; both are fed to the
# webapp container on stdin. The ticket reaches the agent container on stdin, never on a command
# line, and is never printed; nor are keys.
#
# Needs the stack up (webapp on :3000, agent, postgres); prints SKIP and exits 0 when it is not.
# As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_approval_cap_live.sh            (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
CAP_ALL='["agent:approve_phase","agent:approve_dangerous","agent:fireteam","agent:kali_exec"]'
LIVE_SESSION="rbac-live-39b-audit"

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
claim() { # ticket-file name: the JSON of one claim of the ticket's payload (no signature check), or "absent"
  python3 -c '
import base64, json, sys
t = open(sys.argv[1]).read().strip().split(".")[1]
p = json.loads(base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))
print(json.dumps(p[sys.argv[2]], separators=(",", ":")) if sys.argv[2] in p else "absent")' "$1" "$2" 2>/dev/null
}

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in MEMBER_A_EMAIL MEMBER_A_ID MEMBER_B_ID ADMIN_A_ID PA_ID PB_ID CONV_PA_SESSION RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
for k in MEMBER_A_ID MEMBER_B_ID ADMIN_A_ID PA_ID PB_ID CONV_PA_SESSION; do
  [[ "${SEED[$k]}" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected $k"; exit 1; }
done

echo "== The webapp mints the cap =="
JAR="$TMP/jar"
printf '{"email":"%s","password":"%s"}' "${SEED[MEMBER_A_EMAIL]}" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
code="$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$JAR" -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/login.json")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-member-a answered $code"; exit 1; }
mint() { # socket out-file -> http status; the ticket goes to the file, never to the terminal
  printf '{"projectId":"%s","sessionId":"%s","socket":"%s"}' "${SEED[PA_ID]}" "${SEED[CONV_PA_SESSION]}" "$1" > "$TMP/req"
  local status
  status="$(curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -X POST -b "$JAR" -H "Origin: $BASE" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/req" "$BASE/api/agent/ws-ticket")"
  python3 -c 'import json,sys; t=json.load(open(sys.argv[1])).get("ticket"); print(t if isinstance(t,str) else "")' \
    "$TMP/body" > "$2" 2>/dev/null
  echo "$status"
}
code="$(mint agent "$TMP/t_agent")"
cap="$(claim "$TMP/t_agent" cap)"
ok=0; [ "$code" = 200 ] && [ "$cap" = "$CAP_ALL" ] && ok=1
check "member A's agent ticket carries all four agent permissions -> $code cap=${cap:-?}" "$ok"
code="$(mint cypherfix-triage "$TMP/t_triage")"
cap="$(claim "$TMP/t_triage" cap)"
ok=0; [ "$code" = 200 ] && [ "$cap" = absent ] && ok=1
check "a cypherfix-triage ticket carries no cap -> $code cap=${cap:-?}" "$ok"

echo "== The agent refuses what the cap lacks (agent container) =="
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ ! -s "$TMP/t_agent" ]; then
  check "the agent-side checks need the agent ticket" 0
else
  { printf 'T_AGENT = "%s"\nMEMBER_ID = "%s"\nPROJECT_ID = "%s"\nSESSION_ID = "%s"\n' \
      "$(cat "$TMP/t_agent")" "${SEED[MEMBER_A_ID]}" "${SEED[PA_ID]}" "${SEED[CONV_PA_SESSION]}"
    cat "$ROOT/tests/rbac_approval_cap_live_ws.py"
  } | (cd "$ROOT" && docker compose exec -T agent python3 -) > "$TMP/ws.out" 2>&1
  grep -E '^(PASS|FAIL)  ' "$TMP/ws.out"
  if read -r _ ws_pass ws_fail < <(grep '^RESULT_WS ' "$TMP/ws.out"); then
    PASS=$((PASS + ws_pass)); FAIL=$((FAIL + ws_fail))
  else
    check "the agent-side checks ran to the end" 0 "$(grep -oE '^[A-Za-z_.]*(Error|Exception)' "$TMP/ws.out" | tail -1)"
  fi
fi
rm -f "$TMP/t_agent" "$TMP/t_triage"
refused="$(cd "$ROOT" && docker compose logs --since "$since" agent 2>/dev/null | grep -c '\[rbac\] decision refused permission=agent:approve_phase')"
ok=0; [ "${refused:-0}" -ge 1 ] && ok=1
check "the agent logged the refused approval -> ${refused:-0}" "$ok"
actor=""
for _ in 1 2 3 4 5 6 7 8 9 10; do # the agent saves through an ordered queue: give it a moment
  actor="$(printf "select m.data->'actor' from chat_messages m join conversations c on c.id = m.conversation_id where c.session_id = '%s' and m.type = 'fireteam_member_confirmation_response' order by m.created_at desc limit 1;\n" \
    "${SEED[CONV_PA_SESSION]}" | db_sql | tr -d ' ')"
  [ -n "$actor" ] && break
  sleep 1
done
ok=0; [ "$actor" = "{\"sub\":\"${SEED[MEMBER_A_ID]}\"}" ] && ok=1
check "the accepted Fireteam answer is saved with its actor -> ${actor:-none}" "$ok"

echo "== The audit route =="
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
decision() { # with-key|without-key -> http status of the POST, from inside the webapp container
  (cd "$ROOT" && docker compose exec -T -e MODE="$1" -e BODY="$2" webapp node -e '
    const headers = { "Content-Type": "application/json" }
    if (process.env.MODE === "with-key") headers["X-Internal-Key"] = process.env.INTERNAL_API_KEY || ""
    fetch("http://localhost:3000/api/internal/agent/decisions", { method: "POST", headers, body: process.env.BODY })
      .then(r => console.log(r.status), e => console.log("error " + e.name))')
}
body="$(printf '{"kind":"approval","sessionId":"%s","projectId":"%s","userId":"%s","actorId":"%s","decision":"approve"}' \
  "$LIVE_SESSION" "${SEED[PB_ID]}" "${SEED[MEMBER_B_ID]}" "${SEED[ADMIN_A_ID]}")"
code="$(decision without-key "$body")"
ok=0; [ "$code" = 401 ] && ok=1
check "no internal key -> ${code:-?}" "$ok"
code="$(decision with-key "$body")"
ok=0; [ "$code" = 200 ] && ok=1
check "the internal key -> ${code:-?}" "$ok"
row="$(printf "select actor_id, coalesce(on_behalf_of_user_id, '-'), coalesce(project_id, '-'), coalesce(permission, '-'), target_type from audit_log where action = 'agent.approval' and target_id = '%s' order by created_at desc limit 1;\n" \
  "$LIVE_SESSION" | db_sql)"
want="${SEED[ADMIN_A_ID]}|${SEED[MEMBER_B_ID]}|${SEED[PB_ID]}|agent:approve_phase|agent_session"
ok=0; [ "$row" = "$want" ] && ok=1
check "the audit row names the admin as actor, on behalf of the member -> ${row:-none}" "$ok"
offlist="$(cd "$ROOT" && docker compose logs --since "$since" webapp 2>/dev/null | grep -c 'off-allowlist POST /api/internal/agent/decisions')"
ok=0; [ "${offlist:-0}" = 0 ] && ok=1
check "the route is on the internal-key allowlist (no off-allowlist line) -> ${offlist:-0}" "$ok"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
