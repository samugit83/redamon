#!/usr/bin/env bash
#
# Live check of RBAC step 5.4 (SH-34, SH-41 mid-session part, IM-09), run against the LIVE stack
# after the agent and the webapp are rebuilt from a HEAD that holds the step:
#   - POST /api/internal/agent/authorize-decision answers 401 without the internal key, 400 for a
#     malformed check, 200 {allowed: true} for the owner of the project, and 403 naming the
#     permission and `project_not_visible` for a member the project is not shared with, whose
#     refusal leaves an `agent.decision_refused` audit row naming that member; the middleware lets
#     it through without an off-allowlist line;
#   - inside the agent container (tests/rbac_decision_check_live_ws.py): a socket whose ticket's
#     `cap` still holds all four agent permissions, for a member with no access to the project, is
#     refused each answer at decision time (`permission_required`, `reason: project_not_visible`),
#     and the owner's is not; the agent logged `[rbac] decision refused at decision time`.
# Any switch state: an owner passes and a stranger is refused whatever the RBAC switches.
# E2E row P5-03 (a collaborator's toggle added and removed) is the Chrome DevTools row of
# phase_07_e2e_matrix.md, after step 5.6 opens the run toggles.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-* projects),
# removed with their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C; both are fed to the
# webapp container on stdin. Tickets are signed inside the agent container and never printed;
# nor are keys.
#
# Needs the stack up (webapp on :3000, agent, postgres); prints SKIP and exits 0 when it is not.
# As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_decision_check_live.sh            (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
LIVE_SESSION="rbac-live-54-check"

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
for k in MEMBER_A_ID MEMBER_B_ID PA_ID CONV_PA_SESSION; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
  [[ "${SEED[$k]}" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected $k"; exit 1; }
done

echo "== The decision route =="
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ask() { # with-key|without-key body -> "<status> <body>" of the POST, from inside the webapp container
  (cd "$ROOT" && docker compose exec -T -e MODE="$1" -e BODY="$2" webapp node -e '
    const headers = { "Content-Type": "application/json" }
    if (process.env.MODE === "with-key") headers["X-Internal-Key"] = process.env.INTERNAL_API_KEY || ""
    fetch("http://localhost:3000/api/internal/agent/authorize-decision", { method: "POST", headers, body: process.env.BODY })
      .then(async r => console.log(r.status + " " + JSON.stringify(await r.json().catch(() => null))), e => console.log("error " + e.name))')
}
body() { printf '{"kind":"%s","userId":"%s","projectId":"%s","sessionId":"%s"}' "$1" "$2" "${SEED[PA_ID]}" "$LIVE_SESSION"; }

out="$(ask without-key "$(body approval "${SEED[MEMBER_A_ID]}")")"
ok=0; [ "${out%% *}" = 401 ] && ok=1
check "no internal key -> ${out%% *}" "$ok"
out="$(ask with-key '{"kind":"anything"}')"
ok=0; [[ "$out" == '400 '*invalid_decision_check* ]] && ok=1
check "a malformed check -> $out" "$ok"
out="$(ask with-key "$(body approval "${SEED[MEMBER_A_ID]}")")"
ok=0; [ "$out" = '200 {"allowed":true}' ] && ok=1
check "the owner may approve on their project -> $out" "$ok"
out="$(ask with-key "$(body codefix_push "${SEED[MEMBER_A_ID]}")")"
ok=0; [ "$out" = '200 {"allowed":true}' ] && ok=1
check "the owner may push a CodeFix branch (Manage) -> $out" "$ok"
out="$(ask with-key "$(body tool_confirmation "${SEED[MEMBER_B_ID]}")")"
ok=0; [[ "$out" == '403 '*'"permission":"agent:approve_dangerous"'*'"reason":"project_not_visible"'* ]] && ok=1
check "a member the project is not shared with is refused, naming why -> $out" "$ok"
row="$(printf "select actor_id, coalesce(on_behalf_of_user_id, '-'), coalesce(project_id, '-'), coalesce(permission, '-'), after->>'reason' from audit_log where action = 'agent.decision_refused' and target_id = '%s' order by created_at desc limit 1;\n" \
  "$LIVE_SESSION" | db_sql)"
want="${SEED[MEMBER_B_ID]}|-|${SEED[PA_ID]}|agent:approve_dangerous|project_not_visible"
ok=0; [ "$row" = "$want" ] && ok=1
check "the refusal is audited naming the member -> ${row:-none}" "$ok"
offlist="$(cd "$ROOT" && docker compose logs --since "$since" webapp 2>/dev/null | grep -c 'off-allowlist POST /api/internal/agent/authorize-decision')"
ok=0; [ "${offlist:-0}" = 0 ] && ok=1
check "the route is on the internal-key allowlist (no off-allowlist line) -> ${offlist:-0}" "$ok"

echo "== The agent asks it when an answer comes (agent container) =="
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
WS_OUT="$( { printf 'OWNER_ID = "%s"\nSTRANGER_ID = "%s"\nPROJECT_ID = "%s"\nSESSION_ID = "%s"\n' \
    "${SEED[MEMBER_A_ID]}" "${SEED[MEMBER_B_ID]}" "${SEED[PA_ID]}" "${SEED[CONV_PA_SESSION]}"
  cat "$ROOT/tests/rbac_decision_check_live_ws.py"
} | (cd "$ROOT" && docker compose exec -T agent python3 -) 2>&1)"
grep -E '^(PASS|FAIL)  ' <<< "$WS_OUT"
if read -r _ ws_pass ws_fail < <(grep '^RESULT_WS ' <<< "$WS_OUT"); then
  PASS=$((PASS + ws_pass)); FAIL=$((FAIL + ws_fail))
else
  check "the agent-side checks ran to the end" 0 "$(grep -oE '^[A-Za-z_.]*(Error|Exception)' <<< "$WS_OUT" | tail -1)"
fi
refused="$(cd "$ROOT" && docker compose logs --since "$since" agent 2>/dev/null | grep -c '\[rbac\] decision refused at decision time')"
ok=0; [ "${refused:-0}" -ge 4 ] && ok=1
check "the agent logged each refusal -> ${refused:-0}" "$ok"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
