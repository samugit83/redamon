#!/usr/bin/env bash
#
# Live check of RBAC step 1.16 (HD-20, HD-21 LLM part, NF-01, NF-08, NF-16), run against the LIVE
# stack after the webapp and the agent are rebuilt and the orchestrator restarted:
#   - inside the agent container (tests/rbac_job_credential_live_checks.py), which holds the
#     master and scanner keys: the bare scanner key reads no settings, no project and ingests
#     nothing; the key with the owner's job credential reads the settings unmasked and its own
#     project, and nothing of another tenant or project; the agent's /llm/* and /jev/* refuse the
#     bare key and a body naming another user, and run with the credential;
#   - the orchestrator refuses a start without a credential and one with a forged credential
#     (403 job_credential_missing / _bad_signature), before any container;
#   - a real partial recon (Shodan, one phase) started by rbac-member-a on rbac-PA (target
#     rbac.test, a reserved name nothing resolves): its container holds REDAMON_JOB_CREDENTIAL
#     and SCANNER_API_KEY but no INTERNAL_API_KEY (names only), it loads the project settings
#     with the credential (its log reaches "Roots:" and never "Cannot load the project
#     settings"), and the webapp logged no `[rbac] job credential refused` meanwhile.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-* projects),
# removed with their audit rows by e2e-rbac-cleanup.mjs, even on Ctrl-C. Keys stay inside the
# containers or are read inline from .env into curl's config on stdin; nothing secret is printed.
#
# Needs the stack up (webapp on :3000, agent, recon-orchestrator, postgres); prints SKIP and exits 0
# when it is not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_job_credential_live.sh            (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
ORCH="${ORCHESTRATOR_URL:-http://127.0.0.1:8010}"

health="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
if [ "$health" != 200 ]; then
  echo "SKIP: RedAmon webapp not answering at $BASE/api/health (got ${health:-nothing})"
  exit 0
fi
for svc in webapp postgres agent recon-orchestrator; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done

TMP="$(mktemp -d)"
CLEANED_UP=0
RUN_ID=""
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
env_key() { grep -m1 "^$1=" "$ROOT/.env" 2>/dev/null | cut -d= -f2- | tr -d '"'"'"; }
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  if [ -n "$RUN_ID" ]; then
    curl -s -m 30 -o /dev/null -X POST -b "$TMP/jar" -H "Origin: $BASE" \
      "$BASE/api/recon/${SEED[PA_ID]}/partial/$RUN_ID/stop" || true
  fi
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

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in MEMBER_A_EMAIL MEMBER_A_ID MEMBER_B_ID PA_ID PB_ID RBAC_PASSWORD A_TAVILY_SECRET; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
for k in MEMBER_A_ID MEMBER_B_ID PA_ID PB_ID; do [[ "${SEED[$k]}" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unexpected $k"; exit 1; }; done

echo "== Scanner routes with and without the job credential (agent container) =="
{ printf 'MEMBER_A_ID = "%s"\nMEMBER_B_ID = "%s"\nPA_ID = "%s"\nPB_ID = "%s"\nA_TAVILY_SECRET = "%s"\n' \
    "${SEED[MEMBER_A_ID]}" "${SEED[MEMBER_B_ID]}" "${SEED[PA_ID]}" "${SEED[PB_ID]}" "${SEED[A_TAVILY_SECRET]}"
  cat "$ROOT/tests/rbac_job_credential_live_checks.py"
} | (cd "$ROOT" && docker compose exec -T agent python3 -) > "$TMP/in.out" 2>&1
grep -E '^(PASS|FAIL)  ' "$TMP/in.out"
if read -r _ in_pass in_fail < <(grep '^RESULT_IN ' "$TMP/in.out"); then
  PASS=$((PASS + in_pass)); FAIL=$((FAIL + in_fail))
else
  check "the agent-side checks ran to the end" 0 "$(grep -oE '^[A-Za-z_.]*(Error|Exception)' "$TMP/in.out" | tail -1)"
fi

echo "== The orchestrator refuses a start without a valid credential =="
orch_key="$(env_key ORCHESTRATOR_API_KEY)"
if [ -z "$orch_key" ]; then
  check "ORCHESTRATOR_API_KEY is set in .env" 0
else
  for case in missing forged; do
    if [ "$case" = missing ]; then cred=""; else cred=',"job_credential":"eyJhdWQiOiJzY2FuIn0.AAAA"'; fi
    printf '{"project_id":"%s","user_id":"%s","webapp_api_url":"http://webapp:3000"%s}' \
      "${SEED[PA_ID]}" "${SEED[MEMBER_A_ID]}" "$cred" > "$TMP/start.json"
    code="$(printf 'header = "X-Orchestrator-Key: %s"\n' "$orch_key" | curl -K - -s -m 30 -o "$TMP/body" -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' --data-binary @"$TMP/start.json" \
      "$ORCH/supply-chain/${SEED[PA_ID]}/start")"
    got="$(grep -oE 'job_credential_[a-z_]+' "$TMP/body" | head -1)"
    want=job_credential_missing; [ "$case" = forged ] && want=job_credential_bad_signature
    ok=0; [ "$code" = 403 ] && [ "$got" = "$want" ] && ok=1
    check "orchestrator: a start with a $case credential is refused -> $code $got" "$ok"
  done
fi
orch_key=""

echo "== A partial recon runs with its credential (rbac-PA, rbac.test, Shodan) =="
printf '{"email":"%s","password":"%s"}' "${SEED[MEMBER_A_EMAIL]}" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
code="$(curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$TMP/jar" -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/login.json")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-member-a answered $code"; exit 1; }
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '{"tool_id":"Shodan","graph_inputs":{"domains":["rbac.test"]},"include_graph_targets":true}' > "$TMP/req"
code="$(curl -s -m 120 -o "$TMP/body" -w '%{http_code}' -X POST -b "$TMP/jar" -H "Origin: $BASE" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/req" "$BASE/api/recon/${SEED[PA_ID]}/partial")"
RUN_ID="$(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get("run_id"); print(v if isinstance(v,str) else "")' "$TMP/body" 2>/dev/null)"
ok=0; [ "$code" = 200 ] && [[ "$RUN_ID" =~ ^[0-9a-f-]{36}$ ]] && ok=1
check "the partial recon started -> $code" "$ok" "$(grep -oE '"(error|code)":"[^"]{0,120}"' "$TMP/body" | head -2 | tr '\n' ' ')"
if [ "$ok" = 1 ]; then
  name="redamon-partial-recon-${SEED[PA_ID]}-${RUN_ID:0:8}"
  names=""; : > "$TMP/run.log"
  for _ in $(seq 1 90); do
    # Names only; the values never leave the container.
    n="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$name" 2>/dev/null | cut -d= -f1 \
      | grep -E '^(REDAMON_JOB_CREDENTIAL|SCANNER_API_KEY|INTERNAL_API_KEY)$' | sort | tr '\n' ' ')"
    [ -n "$n" ] && names="$n"
    docker logs "$name" > "$TMP/run.now" 2>&1 && cp "$TMP/run.now" "$TMP/run.log"
    state="$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null)"
    [ -n "$names" ] && [ "$state" = exited ] && break
    sleep 2
  done
  ok=0; [ "$names" = "REDAMON_JOB_CREDENTIAL SCANNER_API_KEY " ] && ok=1
  check "the container holds the credential and the scanner key, no master key -> ${names:-none}" "$ok"
  loaded=0; grep -qF '[*][Partial Recon] Roots:' "$TMP/run.log" && loaded=1
  refused=0; grep -qF 'Cannot load the project settings' "$TMP/run.log" && refused=1
  ok=0; [ "$loaded" = 1 ] && [ "$refused" = 0 ] && ok=1
  check "the container loaded its project settings with the credential (log)" "$ok"
  logged="$(cd "$ROOT" && docker compose logs --since "$since" webapp 2>/dev/null | grep -c '\[rbac\] job credential refused')"
  ok=0; [ "${logged:-0}" = 0 ] && ok=1
  check "the webapp refused no job credential during the run -> ${logged:-0}" "$ok"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
