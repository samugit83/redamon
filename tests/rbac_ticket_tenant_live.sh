#!/usr/bin/env bash
#
# Live check of RBAC step 5.3 (SH-33, SH-34, SH-38), run against the LIVE stack after the agent
# and the webapp are rebuilt from a HEAD that holds the step:
#   - the webapp names the project's owner as `ten` in every ticket it mints, beside `sub` (member A
#     on its project PA, the three project sockets: chat, CypherFix triage and CodeFix; a Kali
#     terminal ticket also needs platform:kali_terminal, so the terminal's tenant is checked in the
#     agent container below, with a ticket that check signs itself);
#   - inside the agent container (tests/rbac_ticket_tenant_live_ws.py), with tickets it signs
#     itself (a collaborator mints no agent ticket from the webapp until step 5.6 opens Use AI
#     agent): an empty `ten` is refused; a collaborator's chat socket on A's project opens, and a
#     close for the collaborator ends it and leaves A's open; a session stop without user_id is
#     accepted; the collaborator's Kali terminal shell runs as A (REDAMON_USER_ID), and only a
#     close for the collaborator ends it;
#   - a ticket names a session that is new or the person's own on its project (5.3 review): member B
#     asking a ticket on its own project PB for member A's conversation session on PA gets 403
#     `session_not_yours`.
# The run by a collaborator whose attack chain lands under the owner (RM:p5-graph-counts) needs
# the owner's stub-LLM provider (M9) and a collaborator with Use AI agent (step 5.6): pending.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-* projects),
# removed by e2e-rbac-cleanup.mjs, even on Ctrl-C; both are fed to the webapp container on stdin.
# Tickets reach the agent container on stdin, never on a command line, and are never printed;
# nor are keys or terminal output.
#
# Needs the stack up (webapp on :3000, agent, kali-sandbox, postgres); prints SKIP and exits 0
# when it is not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_ticket_tenant_live.sh            (BASE_URL overrides :3000)
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
claim() { # ticket-file name: one claim of the ticket's payload as JSON (no signature check), or "absent"
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
for k in MEMBER_A_EMAIL MEMBER_A_ID MEMBER_B_EMAIL MEMBER_B_ID PA_ID PB_ID CONV_PA_SESSION RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
for k in MEMBER_A_ID MEMBER_B_ID PA_ID PB_ID CONV_PA_SESSION; do
  [[ "${SEED[$k]}" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected $k"; exit 1; }
done

echo "== The webapp names the owner as ten =="
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
for socket in agent cypherfix-triage cypherfix-codefix; do
  code="$(mint "$socket" "$TMP/t")"
  ten="$(claim "$TMP/t" ten)"; sub="$(claim "$TMP/t" sub)"
  ok=0; [ "$code" = 200 ] && [ "$ten" = "\"${SEED[MEMBER_A_ID]}\"" ] && [ "$sub" = "\"${SEED[MEMBER_A_ID]}\"" ] && ok=1
  check "member A's $socket ticket names A as ten and sub -> $code" "$ok"
done
rm -f "$TMP/t"

echo "== A ticket's session is new or the person's own on its project (5.3 review) =="
JAR_B="$TMP/jar_b"
printf '{"email":"%s","password":"%s"}' "${SEED[MEMBER_B_EMAIL]}" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
code="$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$JAR_B" -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/login.json")"
if [ "$code" != 200 ]; then
  check "sign-in as rbac-member-b" 0 "answered $code"
else
  printf '{"projectId":"%s","sessionId":"%s","socket":"agent"}' "${SEED[PB_ID]}" "${SEED[CONV_PA_SESSION]}" > "$TMP/req"
  code="$(curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -X POST -b "$JAR_B" -H "Origin: $BASE" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/req" "$BASE/api/agent/ws-ticket")"
  ok=0; [ "$code" = 403 ] && grep -q '"session_not_yours"' "$TMP/body" && ! grep -q '"ticket"' "$TMP/body" && ok=1
  check "member B gets no ticket on PB for member A's PA session -> $code" "$ok"
  rm -f "$TMP/body"
fi

echo "== The agent splits tenant and person (agent container) =="
{ printf 'OWNER_ID = "%s"\nOWNER_PID = "%s"\nCOLLAB_ID = "%s"\nSESSION_ID = "%s"\n' \
    "${SEED[MEMBER_A_ID]}" "${SEED[PA_ID]}" "${SEED[MEMBER_B_ID]}" "rbac-live-53-${RANDOM}"
  cat "$ROOT/tests/rbac_ticket_tenant_live_ws.py"
} | (cd "$ROOT" && docker compose exec -T agent python3 -) > "$TMP/ws.out" 2>&1
grep -E '^(PASS|FAIL)  ' "$TMP/ws.out"
if read -r _ ws_pass ws_fail < <(grep '^RESULT_WS ' "$TMP/ws.out"); then
  PASS=$((PASS + ws_pass)); FAIL=$((FAIL + ws_fail))
else
  check "the agent-side checks ran to the end" 0 "$(grep -oE '^[A-Za-z_.]*(Error|Exception)' "$TMP/ws.out" | tail -1)"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
