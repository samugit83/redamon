#!/usr/bin/env bash
#
# Live integration + smoke + regression test for the Phase 0 HTTP traffic
# capture feature, against the running stack (webapp on :3000).
#
# Reuses the BOLA two-user harness (scripts/e2e-bola-seed.mjs) to prove:
#   INGEST (scanner-key writer, with its scan's job credential since step 1.16):
#     - bad key -> 401; the bare key, or a credential of another project -> 403
#       job_credential_required; capture-disabled project -> 202 no-op
#     - tenant fields stamped from the project OWNER, never the request body
#     - Content-Length overflow is clamped to int4 (batch not lost)
#     - passive-signal fields persist as sent
#   READ (JWT, per-user):
#     - owner reads own traffic (200); cross-user read/detail/facets -> 404
#     - a row is never returned under another project's path
#     - list is owner-scoped (no cross-tenant leak)
#     - unparseable date filter -> 200 (regression), unauth -> 401
#
# Seeds + cleans up its own fixtures (seed cleanup cascades captured rows).
#
# Run: bash tests/test_traffic_capture_live.sh
set -uo pipefail

BASE="${BASE_URL:-http://localhost:3000}"
DC="docker compose"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; \
  $DC exec -T postgres psql -U redamon -d redamon -tAc "DELETE FROM captured_http_transactions WHERE run_id LIKE '"'"'ttest-live-%'"'"';" >/dev/null 2>&1 || true; \
  $DC exec -T webapp node scripts/e2e-bola-cleanup.mjs >/dev/null 2>&1 || true' EXIT

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1 -> $3"; else bad "$1 (expected $2, got $3)"; fi; }
contains(){ if echo "$2" | grep -q "$3"; then ok "$1"; else bad "$1 (missing '$3')"; fi; }
excludes(){ if echo "$2" | grep -q "$3"; then bad "$1 (LEAKED '$3')"; else ok "$1"; fi; }

login() { curl -s -o /dev/null -c "$2" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$1\",\"password\":\"e2epass123\"}"; }
gcode() { curl -s -o /dev/null -w '%{http_code}' -b "$1" "$BASE$2"; }
gbody() { curl -s -b "$1" "$BASE$2"; }
psql_() { $DC exec -T postgres psql -U redamon -d redamon -tAc "$1"; }

# scanner ingest POST (X-Internal-Key: SCANNER_API_KEY, X-Redamon-Job: the job credential of a scan of
# that project: the headers recon/helpers/traffic_capture.py sends through scan_auth_headers())
cred_for() { case "$1" in "$PA_ID") printf '%s' "$JOB_PA" ;; "$PB_ID") printf '%s' "$JOB_PB" ;; esac; }
ingest_code() { curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/traffic/$1/ingest" -H "X-Internal-Key: $KEY" -H "X-Redamon-Job: $(cred_for "$1")" -H 'Content-Type: application/json' -d "$2"; }
ingest_body() { curl -s -X POST "$BASE/api/traffic/$1/ingest" -H "X-Internal-Key: $KEY" -H "X-Redamon-Job: $(cred_for "$1")" -H 'Content-Type: application/json' -d "$2"; }
# A job credential (aud scan, the project's owner as tenant), minted in the agent container with the
# webapp's key derivation, as tests/rbac_job_credential_live_checks.py does.
mint_job() { # owner-id project-id -> credential
  $DC exec -T -e JOB_TEN="$1" -e JOB_PID="$2" agent python3 -c 'import os, time, machine_credential as mc
key = mc.derive_key(os.environ["INTERNAL_API_KEY"], mc.JOB_CREDENTIAL_LABEL)
print(mc.mint({"aud": "scan", "ten": os.environ["JOB_TEN"], "pid": os.environ["JOB_PID"], "job": "ttest-live", "exp": int(time.time()) + 3600}, key))' | tr -d '\r\n'
}

echo "== Preconditions =="
KEY="$($DC exec -T recon-orchestrator sh -c 'echo $SCANNER_API_KEY' | tr -d '\r\n')"
[ -n "$KEY" ] && [ "$KEY" != "changeme" ] || { echo "SCANNER_API_KEY unset/changeme; cannot run"; exit 1; }

echo "== Seeding fixtures =="
SEED="$($DC exec -T webapp node scripts/e2e-bola-seed.mjs)" || { echo "seed failed"; exit 1; }
eval "$SEED"
[ -n "${PA_ID:-}" ] && [ -n "${PB_ID:-}" ] && [ -n "${A_ID:-}" ] && [ -n "${B_ID:-}" ] || { echo "seed vars missing"; exit 1; }

JOB_PA="$(mint_job "$A_ID" "$PA_ID")"; JOB_PB="$(mint_job "$B_ID" "$PB_ID")"
[ -n "$JOB_PA" ] && [ -n "$JOB_PB" ] || { echo "could not mint a job credential in the agent container"; exit 1; }

login bola-a@e2e.local "$TMP/a.jar"
login bola-b@e2e.local "$TMP/b.jar"

TXN='{"tool":"httpx","host":"HOSTVAL","scheme":"https","port":443,"path":"/login","query":"?next=/admin","method":"GET","statusCode":200,"respBody":"<html>hi</html>","respBodySize":13,"respContentType":"text/html","respHeaders":{"server":"nginx","set-cookie":"sid=1"},"hasSetCookie":true,"securityHeadersMissing":["content-security-policy","x-frame-options"],"cookieFlagIssues":[{"cookie":"sid","missing":["HttpOnly","Secure","SameSite"]}],"responseTimeMs":42,"respBodySha":"abc123","startedAt":"2026-07-19T10:00:00Z"}'

echo "== INGEST auth + gate =="
check "bad scanner key -> 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/traffic/$PA_ID/ingest" -H "X-Internal-Key: WRONG" -H 'Content-Type: application/json' -d '{"transactions":[]}')"
R="$(curl -s -w ' %{http_code}' -X POST "$BASE/api/traffic/$PA_ID/ingest" -H "X-Internal-Key: $KEY" -H 'Content-Type: application/json' -d '{"transactions":[]}')"
check "bare scanner key (no job credential) -> 403" 403 "${R##* }"
contains "bare scanner key refusal names the job credential" "$R" '"code":"job_credential_required"'
R="$(curl -s -w ' %{http_code}' -X POST "$BASE/api/traffic/$PB_ID/ingest" -H "X-Internal-Key: $KEY" -H "X-Redamon-Job: $JOB_PA" -H 'Content-Type: application/json' -d '{"transactions":[]}')"
check "PA's job credential on PB's ingest -> 403" 403 "${R##* }"
contains "PA's credential on PB refused as another project" "$R" '"reason":"project_mismatch"'
# capture is disabled by default on the seeded project
DISABLED_RESP="$(ingest_body "$PA_ID" '{"source":"recon","transactions":[{"host":"x.test","scheme":"https","path":"/"}]}')"
contains "capture-disabled project no-ops" "$DISABLED_RESP" '"stored":0'

echo "== Enable capture on PA + PB =="
psql_ "UPDATE projects SET capture_proxy_enabled=true WHERE id IN ('$PA_ID','$PB_ID');" >/dev/null

echo "== INGEST tenant stamping (forged userId ignored) =="
PA_TXN="$(echo "$TXN" | sed 's/HOSTVAL/pa.e2e.example/')"
R="$(ingest_body "$PA_ID" "{\"source\":\"recon\",\"runId\":\"ttest-live-pa\",\"userId\":\"ATTACKER\",\"projectId\":\"OTHER\",\"transactions\":[$PA_TXN]}")"
contains "PA ingest stored 1" "$R" '"stored":1'
STAMPED="$(psql_ "SELECT user_id FROM captured_http_transactions WHERE run_id='ttest-live-pa' LIMIT 1;" | tr -d '\r\n ')"
check "PA row stamped to OWNER (A), not ATTACKER" "$A_ID" "$STAMPED"

PB_TXN="$(echo "$TXN" | sed 's/HOSTVAL/pb.e2e.example/')"
ingest_body "$PB_ID" "{\"source\":\"recon\",\"runId\":\"ttest-live-pb\",\"transactions\":[$PB_TXN]}" >/dev/null

echo "== INGEST int4 clamp (Content-Length overflow must not lose the batch) =="
HUGE='{"tool":"httpx","host":"huge.e2e.example","scheme":"https","port":443,"path":"/big","method":"GET","statusCode":200,"respBodySize":9999999999999,"respHeaders":{},"startedAt":"2026-07-19T10:00:00Z"}'
check "huge Content-Length batch -> 201" 201 "$(ingest_code "$PA_ID" "{\"source\":\"recon\",\"runId\":\"ttest-live-pa\",\"transactions\":[$HUGE]}")"
CLAMPED="$(psql_ "SELECT resp_body_size FROM captured_http_transactions WHERE run_id='ttest-live-pa' AND host='huge.e2e.example';" | tr -d '\r\n ')"
check "resp_body_size clamped to INT4_MAX" "2147483647" "$CLAMPED"

echo "== INGEST persists passive-signal fields =="
SIG="$(psql_ "SELECT has_set_cookie FROM captured_http_transactions WHERE run_id='ttest-live-pa' AND host='pa.e2e.example';" | tr -d '\r\n ')"
check "has_set_cookie persisted" "t" "$SIG"

echo "== READ tenant isolation (JWT) =="
check "A reads OWN traffic list -> 200"           200 "$(gcode "$TMP/a.jar" "/api/traffic/$PA_ID")"
check "A reads B's traffic list -> 404"           404 "$(gcode "$TMP/a.jar" "/api/traffic/$PB_ID")"
check "B reads A's traffic list -> 404"           404 "$(gcode "$TMP/b.jar" "/api/traffic/$PA_ID")"
check "A reads B's facets -> 404"                 404 "$(gcode "$TMP/a.jar" "/api/traffic/$PB_ID/facets")"
check "A reads OWN facets -> 200"                 200 "$(gcode "$TMP/a.jar" "/api/traffic/$PA_ID/facets")"
check "unauth list -> 401"                        401 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/traffic/$PA_ID")"

echo "== READ list is owner-scoped + regression: invalid date filter =="
A_LIST="$(gbody "$TMP/a.jar" "/api/traffic/$PA_ID?pageSize=200")"
contains "A's list includes own host"  "$A_LIST" "pa.e2e.example"
excludes "A's list excludes B's host"  "$A_LIST" "pb.e2e.example"
check "REGRESSION: garbage ?from -> 200 not 500" 200 "$(gcode "$TMP/a.jar" "/api/traffic/$PA_ID?from=not-a-date")"

echo "== READ detail cross-tenant + row-in-project =="
PA_ROW_ID="$(psql_ "SELECT id FROM captured_http_transactions WHERE run_id='ttest-live-pa' AND host='pa.e2e.example' LIMIT 1;" | tr -d '\r\n ')"
PB_ROW_ID="$(psql_ "SELECT id FROM captured_http_transactions WHERE run_id='ttest-live-pb' LIMIT 1;" | tr -d '\r\n ')"
check "A reads OWN row detail -> 200"                 200 "$(gcode "$TMP/a.jar" "/api/traffic/$PA_ID/$PA_ROW_ID")"
check "A reads own row under B's project path -> 404" 404 "$(gcode "$TMP/a.jar" "/api/traffic/$PB_ID/$PA_ROW_ID")"
check "A reads B's row under OWN project path -> 404" 404 "$(gcode "$TMP/a.jar" "/api/traffic/$PA_ID/$PB_ROW_ID")"
check "B reads B's own row detail -> 200"             200 "$(gcode "$TMP/b.jar" "/api/traffic/$PB_ID/$PB_ROW_ID")"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
