#!/usr/bin/env bash
#
# Live integration test for the Phase 1/2 /traffic additions against the running
# stack: offloaded-body read-path, CSV/JSON export, batch delete (ids + filter)
# with ref-counted body GC, and the internal maintenance (retention/quota/GC) route.
#
# Reuses the BOLA two-user seed + login helpers. Seeds + cleans up its own fixtures.
# Run: bash tests/test_traffic_phase2_live.sh
set -uo pipefail

BASE="${BASE_URL:-http://localhost:3000}"
DC="docker compose"
TMP="$(mktemp -d)"
OKEY="$($DC exec -T recon-orchestrator sh -c 'printf %s "$ORCHESTRATOR_API_KEY"')"
IKEY="$($DC exec -T recon-orchestrator sh -c 'printf %s "$INTERNAL_API_KEY"')"
SHA="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
# Stop the proxy on exit only when this run started it: a proxy that was already up
# serves the stack's own captures, and its stop removes it without bringing it back.
PROXY_WAS_RUNNING="$(docker inspect -f '{{.State.Running}}' redamon-capture-proxy 2>/dev/null || echo false)"

trap 'rm -rf "$TMP"; \
  [ "$PROXY_WAS_RUNNING" = true ] || curl -s -X POST "http://127.0.0.1:8010/capture-proxy/stop" -H "X-Orchestrator-Key: '"$OKEY"'" >/dev/null 2>&1 || true; \
  $DC exec -T webapp node scripts/e2e-bola-cleanup.mjs >/dev/null 2>&1 || true' EXIT

PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1 -> $3"; else bad "$1 (expected $2, got $3)"; fi; }
contains(){ if echo "$2" | grep -q "$3"; then ok "$1"; else bad "$1 (missing '$3')"; fi; }
login(){ curl -s -o /dev/null -c "$2" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$1\",\"password\":\"e2epass123\"}"; }
gcode(){ curl -s -o /dev/null -w '%{http_code}' -b "$1" "$BASE$2"; }
gbody(){ curl -s -b "$1" "$BASE$2"; }
psql_(){ $DC exec -T postgres psql -U redamon -d redamon -tAc "$1"; }

echo "== Preconditions =="
[ -n "$IKEY" ] && [ "$IKEY" != "changeme" ] || { echo "INTERNAL_API_KEY unset"; exit 1; }

echo "== Ensure the bodies volume is writable by all capture components =="
# The named volume's owner depends on which container created it first; a one-time
# root chmod makes it shared-writable (proxy writes, webapp reads + GCs). In a real
# deploy this is done once at provisioning.
docker run --rm -v redamon_capture_bodies:/b alpine sh -c 'chmod 777 /b' >/dev/null 2>&1 || true

echo "== Start capture proxy =="
# A start recreates the pair, so a proxy that is already up is left as it is.
if [ "$PROXY_WAS_RUNNING" = true ]; then
  echo "already running, left as it is"
else
  curl -s -X POST "http://127.0.0.1:8010/capture-proxy/start" -H "X-Orchestrator-Key: $OKEY" -o /dev/null -w "start %{http_code}\n"
  sleep 3
fi

echo "== Seed + login =="
SEED="$($DC exec -T webapp node scripts/e2e-bola-seed.mjs)" || { echo "seed failed"; exit 1; }
eval "$SEED"
login bola-a@e2e.local "$TMP/a.jar"
psql_ "UPDATE projects SET capture_proxy_enabled=true WHERE id='$PA_ID';" >/dev/null

echo "== Write an offloaded body blob (root, via the shared volume) =="
docker run --rm -v redamon_capture_bodies:/b alpine sh -c "printf 'OFFLOADED-BODY-MARKER-XYZ' > /b/$SHA && chmod 666 /b/$SHA" >/dev/null 2>&1

echo "== Create rows: 1 inline (webapp ingest) + 1 offloaded (SQL, as the proxy ingest would) =="
# The agent's path (internal key): the bare scanner key writes only with its scan's job
# credential (X-Redamon-Job, HD-20), which this run has none of.
ING='{"source":"recon","runId":"ttest-p2","transactions":[{"tool":"httpx","host":"p2b.example","scheme":"https","port":443,"path":"/b","method":"GET","statusCode":500,"respHeaders":{},"respBody":"inline","respBodySize":6,"startedAt":"2026-07-19T10:00:00Z"}]}'
contains "webapp ingest inline row" "$(curl -s -X POST "$BASE/api/traffic/$PA_ID/ingest" -H "X-Internal-Key: $IKEY" -H 'Content-Type: application/json' -d "$ING")" '"stored":1'
# Offloaded row (resp_body_ref -> disk blob), stamped to PA's owner (A_ID).
psql_ "INSERT INTO captured_http_transactions (id, project_id, user_id, source, run_id, tool, method, scheme, host, port, path, req_headers, resp_headers, resp_body_ref, resp_body_size, status_code, started_at) VALUES ('ttest-p2-off', '$PA_ID', '$A_ID', 'recon', 'ttest-p2', 'katana', 'GET', 'https', 'p2a.example', 443, '/a', '{}', '{}', '$SHA', 25, 200, now());" >/dev/null

echo "== Offloaded-body read-path =="
ROWID="ttest-p2-off"
DETAIL="$(gbody "$TMP/a.jar" "/api/traffic/$PA_ID/$ROWID")"
contains "detail resolves offloaded body from disk" "$DETAIL" "OFFLOADED-BODY-MARKER-XYZ"

echo "== Export =="
check "export CSV -> 200" 200 "$(gcode "$TMP/a.jar" "/api/traffic/$PA_ID/export?format=csv")"
contains "CSV contains a host" "$(gbody "$TMP/a.jar" "/api/traffic/$PA_ID/export?format=csv")" "p2a.example"
check "export JSON -> 200" 200 "$(gcode "$TMP/a.jar" "/api/traffic/$PA_ID/export?format=json")"
check "cross-user export -> 404" 404 "$(gcode "$TMP/a.jar" "/api/traffic/$PB_ID/export?format=csv")"

echo "== Batch delete (filter) + body GC =="
DEL="$(curl -s -b "$TMP/a.jar" -X DELETE "$BASE/api/traffic/$PA_ID" -H 'Content-Type: application/json' -d '{"filter":{"statusClass":"5xx"}}')"
contains "delete-all-matching 5xx removed 1" "$DEL" '"deleted":1'
check "remaining rows after filter-delete" "1" "$(psql_ "SELECT count(*) FROM captured_http_transactions WHERE run_id='ttest-p2';" | tr -d '\r\n ')"

echo "== Batch delete (ids): row removed; fresh blob SPARED by GC grace window =="
DEL2="$(curl -s -b "$TMP/a.jar" -X DELETE "$BASE/api/traffic/$PA_ID" -H 'Content-Type: application/json' -d "{\"ids\":[\"$ROWID\"]}")"
contains "delete-by-id removed 1" "$DEL2" '"deleted":1'
contains "freshly-written blob spared (grace window)" "$DEL2" '"blobsDeleted":0'
BLOB_LEFT="$(docker run --rm -v redamon_capture_bodies:/b alpine sh -c "ls /b/$SHA 2>/dev/null | wc -l" | tr -d '\r\n ')"
check "blob still present right after delete (grace)" "1" "$BLOB_LEFT"

echo "== Age the orphaned blob, then the maintenance orphan sweep GCs it =="
docker run --rm -v redamon_capture_bodies:/b alpine touch -d '2020-01-01' "/b/$SHA" >/dev/null 2>&1
curl -s -o /dev/null -X POST "$BASE/api/traffic/maintenance" -H "X-Internal-Key: $IKEY" -d '{}'
BLOB_LEFT2="$(docker run --rm -v redamon_capture_bodies:/b alpine sh -c "ls /b/$SHA 2>/dev/null | wc -l" | tr -d '\r\n ')"
check "aged orphan blob swept by maintenance" "0" "$BLOB_LEFT2"

echo "== Maintenance route (internal key) =="
check "maintenance -> 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/traffic/maintenance" -H "X-Internal-Key: $IKEY" -d '{}')"
check "maintenance unauth -> 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/traffic/maintenance")"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
