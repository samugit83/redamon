#!/usr/bin/env bash
#
# Experiment E10 (RBAC step 5.11, OQ-35): do an agent run and a scan writing ONE project at once
# cause a constraint violation, a deadlock or a lost update in Neo4j? Its answer sets
# SECOND_WRITER_POLICY in webapp/src/lib/authz/projectWriters.ts: 'refuse' (a second person's start
# answers 409 project_writer_busy) until three clean rounds are recorded, then 'notice'.
#
# The writers are the real code with synthetic input (tests/rbac_e10_writers_live_driver.py, run in
# the agent container, where graph_db and the agent's chain writer both live): the scan's
# update_graph_from_port_scan, one host per call, and the agent's chain writer, an AttackChain and
# its ChainSteps bridged to the IPs and Ports the scan is writing meanwhile. Synthetic tenant
# (user rbac-e10-owner, projects rbac-e10-*), hosts *.e10.rbac.test on 198.51.100.0/24: nothing is
# scanned, no account or project row is created.
#
#   baseline  the scan writer alone on rbac-e10-base: its node and relationship counts
#   round 1-3 both writers at once on rbac-e10-p (cleared before each round), then:
#             - neither writer met an error (constraint, deadlock, transient, any other)
#             - the scan's counts equal the baseline (no lost update)
#             - every ChainStep written is there, chained step to step, under one AttackChain
#             - no IP, Port or Service exists twice (no MERGE race)
#
# Prints PASS/FAIL per check and a final line `E10 RESULT: SAFE ...` or `E10 RESULT: UNSAFE: ...`.
# Exit 0 when the experiment ran, whatever it found (the result is a record, not a gate); exit 1
# when a writer could not run. The trap deletes every rbac-e10-* node, even on Ctrl-C.
#
# Needs the stack up (agent, neo4j); prints SKIP and exits 0 when it is not. Never in the gate.
#
# Run:  bash tests/rbac_e10_writers_live.sh     (E10_HOSTS=40 E10_STEPS=120 E10_ROUNDS=3 override)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOSTS="${E10_HOSTS:-40}"
STEPS="${E10_STEPS:-120}"
ROUNDS="${E10_ROUNDS:-3}"
OWNER="rbac-e10-owner"
BASE_PID="rbac-e10-base"
PID="rbac-e10-p"

for svc in agent neo4j; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done
[[ "$HOSTS" =~ ^[0-9]+$ && "$STEPS" =~ ^[0-9]+$ && "$ROUNDS" =~ ^[0-9]+$ ]] || { echo "E10_HOSTS, E10_STEPS and E10_ROUNDS are numbers"; exit 1; }

TMP="$(mktemp -d)"
cypher() { # Cypher on stdin -> cypher-shell in the neo4j container (password read there)
  (cd "$ROOT" && docker compose exec -T neo4j \
    sh -c 'cypher-shell -u neo4j -p "${NEO4J_AUTH#neo4j/}" --format plain') 2>/dev/null
}
clear_graph() { # project id
  printf "MATCH (n {project_id: '%s'}) DETACH DELETE n;\n" "$1" | cypher > /dev/null
}
cleanup() {
  printf "MATCH (n) WHERE n.project_id STARTS WITH 'rbac-e10-' DETACH DELETE n;\n" | cypher > /dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

writer() { # mode project-id out-file
  { printf 'MODE = "%s"\nUSER_ID = "%s"\nPROJECT_ID = "%s"\nHOSTS = "%s"\nSTEPS = "%s"\n' "$1" "$OWNER" "$2" "$HOSTS" "$STEPS"
    cat "$ROOT/tests/rbac_e10_writers_live_driver.py"
  } | (cd "$ROOT" && docker compose exec -T -w /app agent python3 -) > "$3" 2>&1
}
field() { # out-file python-expression-over-r
  python3 -c 'import json,sys
line=[l for l in open(sys.argv[1]) if l.startswith("E10_WRITER ")]
r=json.loads(line[-1][len("E10_WRITER "):]) if line else {"crashed":"no output"}
print(eval(sys.argv[2]))' "$1" "$2" 2>/dev/null || echo "?"
}
counts() { # project id -> "IP=.. Port=.. Service=.. HAS_PORT=.. RUNS_SERVICE=.."
  printf "%s\n" \
    "MATCH (n:IP {project_id: '$1'}) WITH count(n) AS ip" \
    "MATCH (p:Port {project_id: '$1'}) WITH ip, count(p) AS port" \
    "MATCH (s:Service {project_id: '$1'}) WITH ip, port, count(s) AS svc" \
    "OPTIONAL MATCH (:IP {project_id: '$1'})-[h:HAS_PORT]->(:Port {project_id: '$1'}) WITH ip, port, svc, count(h) AS hp" \
    "OPTIONAL MATCH (:Port {project_id: '$1'})-[r:RUNS_SERVICE]->(:Service {project_id: '$1'})" \
    "RETURN 'IP=' + ip + ' Port=' + port + ' Service=' + svc + ' HAS_PORT=' + hp + ' RUNS_SERVICE=' + count(r) AS c;" \
    | cypher | tail -n 1 | tr -d '"'
}
one() { cypher | tail -n 1 | tr -d '"'; }

PASS=0; FAIL=0; UNSAFE=()
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}

printf "MATCH (n) WHERE n.project_id STARTS WITH 'rbac-e10-' DETACH DELETE n;\n" | cypher > /dev/null

echo "== Baseline: the scan writer alone ($HOSTS hosts) =="
writer scan "$BASE_PID" "$TMP/base.out"
if [ "$(field "$TMP/base.out" 'r.get("crashed","")')" != "" ]; then
  echo "the scan writer could not run: $(field "$TMP/base.out" 'r.get("crashed")')"; exit 1
fi
BASELINE="$(counts "$BASE_PID")"
echo "  baseline: $BASELINE (writer errors: $(field "$TMP/base.out" 'r["errors"]'))"
[ "$(field "$TMP/base.out" 'len(r["errors"])')" = 0 ] || { echo "the scan writer fails alone: no concurrency result possible"; exit 1; }

for round in $(seq 1 "$ROUNDS"); do
  echo "== Round $round: the scan and the agent's chain writer at once on one project =="
  clear_graph "$PID"
  writer chain "$PID" "$TMP/chain.$round" &
  chain_pid=$!
  writer scan "$PID" "$TMP/scan.$round" &
  scan_pid=$!
  wait "$chain_pid" "$scan_pid"
  for w in scan chain; do
    crashed="$(field "$TMP/$w.$round" 'r.get("crashed","")')"
    if [ -n "$crashed" ]; then echo "the $w writer could not run: $crashed"; exit 1; fi
  done

  scan_errors="$(field "$TMP/scan.$round" 'json.dumps(r["errors"], sort_keys=True)')"
  chain_errors="$(field "$TMP/chain.$round" 'json.dumps(r["errors"], sort_keys=True)')"
  check "round $round: the scan writer met no error" "$([ "$scan_errors" = '{}' ] && echo 1 || echo 0)" "$scan_errors"
  check "round $round: the chain writer met no error" "$([ "$chain_errors" = '{}' ] && echo 1 || echo 0)" "$chain_errors"
  [ "$scan_errors" = '{}' ] || UNSAFE+=("round $round scan errors $scan_errors")
  [ "$chain_errors" = '{}' ] || UNSAFE+=("round $round chain errors $chain_errors")

  got="$(counts "$PID")"
  check "round $round: the scan's nodes and relationships equal the baseline ($got)" "$([ "$got" = "$BASELINE" ] && echo 1 || echo 0)" "baseline $BASELINE"
  [ "$got" = "$BASELINE" ] || UNSAFE+=("round $round lost or extra scan writes: $got vs $BASELINE")

  written="$(field "$TMP/chain.$round" 'r["done"]')"
  steps="$(printf "MATCH (s:ChainStep {project_id: '%s'}) RETURN count(s) AS n;\n" "$PID" | one)"
  links="$(printf "MATCH (:ChainStep {project_id: '%s'})-[r:NEXT_STEP]->(:ChainStep {project_id: '%s'}) RETURN count(r) AS n;\n" "$PID" "$PID" | one)"
  chains="$(printf "MATCH (c:AttackChain {project_id: '%s'}) RETURN count(c) AS n;\n" "$PID" | one)"
  ok=0; [ "$steps" = "$written" ] && [ "$written" = "$STEPS" ] && [ "$links" = $((STEPS - 1)) ] && [ "$chains" = 1 ] && ok=1
  check "round $round: every ChainStep is there, chained, under one AttackChain (steps=$steps links=$links chains=$chains)" "$ok" "written $written of $STEPS"
  [ "$ok" = 1 ] || UNSAFE+=("round $round chain steps $steps/$written of $STEPS, links $links, chains $chains")

  dups=0
  for key in "IP) WITH i.address AS a" "Port) WITH i.number AS n, i.protocol AS pr, i.ip_address AS a" \
             "Service) WITH i.name AS n, i.port_number AS pn, i.ip_address AS a"; do
    label="${key%%)*}"; group="${key#*) }"
    d="$(printf "MATCH (i:%s {project_id: '%s'}) %s, count(*) AS c WHERE c > 1 RETURN count(*) AS n;\n" "$label" "$PID" "$group" | one)"
    if [[ "$d" =~ ^[0-9]+$ ]] && [ "$dups" != "?" ]; then dups=$((dups + d)); else dups="?"; fi
  done
  check "round $round: no IP, Port or Service exists twice" "$([ "$dups" = 0 ] && echo 1 || echo 0)" "duplicated keys: ${dups:-?}"
  [ "$dups" = 0 ] || UNSAFE+=("round $round duplicated keys $dups")
done

echo "== $PASS passed, $FAIL failed =="
if [ "${#UNSAFE[@]}" -eq 0 ]; then
  echo "E10 RESULT: SAFE ($ROUNDS rounds, $HOSTS hosts, $STEPS chain steps each: no constraint error, deadlock or lost update)"
else
  echo "E10 RESULT: UNSAFE: $(IFS='; '; echo "${UNSAFE[*]}")"
fi
exit 0
