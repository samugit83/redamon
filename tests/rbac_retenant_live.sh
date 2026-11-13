#!/usr/bin/env bash
#
# Live re-tenant of a synthetic project (RBAC step 5.12, SH-15) and experiment E9
# (constraint errors, counts, time) against the LIVE Neo4j. The unit test
# (tests/test_graph_retenant.py) proves the orchestration against a fake graph;
# this proves the Cypher on a real one:
#   - every label the schema lists moves, with equal counts under the new owner
#     and none left under the old; a legacy label is swept; a muted finding, a
#     stamped relationship and the project's relationship count survive;
#   - a sibling project of the same owner and a reference CVE are untouched;
#   - the same transfer twice moves nothing; the reverse call restores the owner;
#   - a twin under the new owner is refused before anything moves.
#
# Data is synthetic (ids rbac-retenant-<random>, a CVE-0000-<random> node) and
# deleted at the end, even on a failure. Prints E9 lines with the time and counts.
#
# Source of graph_db:
#   baked (default)  the running redamon-agent's image copy: needs the agent
#                    rebuilt after the mixin landed; a stale image is a FAIL
#   tree             a one-off redamon-agent container with this checkout mounted
#                    on redamon-network (E9 before a rebuild)
# Needs redamon-agent and redamon-neo4j running; prints SKIP and exits 0 when
# they are not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_retenant_live.sh
#       RETENANT_LIVE_SOURCE=tree bash tests/rbac_retenant_live.sh
#       RETENANT_LIVE_BULK=50000 bash tests/rbac_retenant_live.sh   (bulk Endpoint nodes, default 12000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${RETENANT_LIVE_SOURCE:-baked}"
BULK="${RETENANT_LIVE_BULK:-12000}"

skip() { echo "SKIP: $1"; exit 0; }
command -v docker >/dev/null 2>&1 || skip "docker unavailable"
docker info >/dev/null 2>&1 || skip "docker daemon unreachable"
for c in redamon-agent redamon-neo4j; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] \
    || skip "container $c is not running"
done
[[ "$BULK" =~ ^[0-9]+$ ]] || { echo "RETENANT_LIVE_BULK must be a number"; exit 2; }

case "$SOURCE" in
  baked)
    if ! docker exec redamon-agent python3 -c 'import graph_db.mixins.tenancy_mixin' >/dev/null 2>&1; then
      echo "FAIL: the running agent's graph_db has no tenancy_mixin: rebuild the agent image"
      echo "      from this tree and recreate it, or run with RETENANT_LIVE_SOURCE=tree"
      exit 1
    fi
    run_py() { docker exec -i -e RETENANT_LIVE_BULK="$BULK" redamon-agent python3 -; }
    ;;
  tree)
    run_py() {
      # The password is read from the running agent into the docker CLI's
      # environment only; it is never printed.
      NEO4J_PASSWORD="$(docker exec redamon-agent printenv NEO4J_PASSWORD)" \
        docker run --rm -i --network redamon-network -v "$ROOT:/repo:ro" -w /repo \
          -e PYTHONPATH=/repo -e PYTHONDONTWRITEBYTECODE=1 -e RETENANT_LIVE_BULK="$BULK" \
          -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD \
          --entrypoint python3 redamon-agent -
    }
    ;;
  *) echo "RETENANT_LIVE_SOURCE must be baked or tree (got: $SOURCE)"; exit 2 ;;
esac

echo "graph re-tenant of a synthetic project (graph_db: $SOURCE, bulk: $BULK)"
run_py <<'PY'
import os
import sys
import time
import uuid

from graph_db import Neo4jClient
from graph_db.mixins.tenancy_mixin import TENANT_LABELS, RetenantError
from graph_db.schema_keys import KEY_CONSTRAINTS

BULK = int(os.environ.get("RETENANT_LIVE_BULK", "12000"))
TAG = uuid.uuid4().hex[:12]
PID, CTL = f"rbac-retenant-{TAG}", f"rbac-retenant-ctl-{TAG}"
OLD, NEW = f"rbac-retenant-old-{TAG}", f"rbac-retenant-new-{TAG}"
CVE = f"CVE-0000-{TAG}"
KEYS = {k["label"]: [p for p in k["key_properties"] if p not in ("user_id", "project_id")]
        for k in KEY_CONSTRAINTS}
REFS = ("CVE", "Capec", "MitreData")
NOT_REF = " OR ".join(f"n:`{label}`" for label in REFS)

passed = failed = 0


def check(name, ok, got=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name} (got: {got})")


def one(session, query, **params):
    row = session.run(query, **params).single()
    return row[0] if row else None


def create(session, label, uid, pid, n, tag="", extra_labels=()):
    labels = ":".join(f"`{x}`" for x in (label, *extra_labels))
    for start in range(0, n, 5000):
        rows = [{k: f"{label}-{k}-{pid}-{tag}{i}" for k in KEYS.get(label, [])}
                for i in range(start, min(n, start + 5000))]
        session.run(f"UNWIND $rows AS row CREATE (n:{labels}) "
                    "SET n += row, n.user_id = $uid, n.project_id = $pid, n.updated_at = datetime()",
                    rows=rows, uid=uid, pid=pid)


def count_label(session, label, uid, pid):
    return one(session, f"MATCH (n:`{label}` {{user_id: $uid, project_id: $pid}}) RETURN count(n)",
               uid=uid, pid=pid)


def count_project(session, uid, pid):
    return one(session, f"MATCH (n) WHERE n.user_id = $uid AND n.project_id = $pid "
                        f"AND NOT ({NOT_REF}) RETURN count(n)", uid=uid, pid=pid)


def count_rels(session, pid):
    return one(session, "MATCH (a)-[r]->() WHERE a.project_id = $pid RETURN count(r)", pid=pid)


client = Neo4jClient()
try:
    with client.driver.session() as s:
        for label in TENANT_LABELS:
            create(s, label, OLD, PID, 2)
            create(s, label, OLD, CTL, 1)
        create(s, "Endpoint", OLD, PID, BULK, tag="bulk")  # volume for E9's time
        create(s, "Vulnerability", OLD, PID, 1, tag="muted", extra_labels=("Muted",))
        s.run("CREATE (n:GithubFinding {id: $id, user_id: $uid, project_id: $pid})",
              id=f"legacy-{TAG}", uid=OLD, pid=PID)
        s.run("CREATE (c:CVE {id: $cve})", cve=CVE)
        s.run("""
            MATCH (d:Domain {user_id: $uid, project_id: $pid}) WITH d LIMIT 1
            MATCH (s:Subdomain {user_id: $uid, project_id: $pid}) WITH d, s LIMIT 1
            MATCH (i:IP {user_id: $uid, project_id: $pid}) WITH d, s, i LIMIT 1
            MATCH (t:Technology {user_id: $uid, project_id: $pid}) WITH d, s, i, t LIMIT 1
            MATCH (c:CVE {id: $cve})
            CREATE (d)-[:HAS_SUBDOMAIN]->(s)
            CREATE (s)-[:RESOLVES_TO {user_id: $uid, project_id: $pid, record_type: 'A'}]->(i)
            CREATE (t)-[:HAS_KNOWN_CVE]->(c)
        """, uid=OLD, pid=PID, cve=CVE)

        before = {label: count_label(s, label, OLD, PID) for label in TENANT_LABELS}
        total_before = count_project(s, OLD, PID)
        rels_before = count_rels(s, PID)
        ctl_before = count_project(s, OLD, CTL)

    try:
        started = time.monotonic()
        result = client.retenant_project(PID, OLD, NEW)
        wall_ms = int((time.monotonic() - started) * 1000)
        error = None
    except RetenantError as exc:
        result, error = None, exc
    check("the transfer completes (no constraint error)", error is None,
          f"{getattr(error, 'code', '')} {error}")
    if result is None:
        sys.exit(1)
    print(f"  E9: moved {result['total_nodes']} node(s) across {len(result['nodes'])} label(s) "
          f"+ {result['relationships']} relationship(s) in {result['elapsed_ms']} ms "
          f"({wall_ms} ms wall); unlisted {result['unlisted']}; constraint errors: none")

    with client.driver.session() as s:
        moved_wrong = {label: (count_label(s, label, NEW, PID), before[label])
                       for label in TENANT_LABELS
                       if count_label(s, label, NEW, PID) != before[label]
                       or count_label(s, label, OLD, PID) != 0}
        check(f"all {len(TENANT_LABELS)} labels: equal counts under the new owner, none under the old",
              not moved_wrong, moved_wrong)
        check("no node of the project left under the old owner",
              count_project(s, OLD, PID) == 0, count_project(s, OLD, PID))
        check(f"the new owner holds all {total_before} nodes",
              count_project(s, NEW, PID) == total_before, count_project(s, NEW, PID))
        check("the legacy label is swept and reported", result["unlisted"] == {"GithubFinding": 1},
              result["unlisted"])
        muted = one(s, "MATCH (n:Vulnerability:Muted {project_id: $pid}) RETURN collect(n.user_id)",
                    pid=PID)
        check("the muted finding moved and is still muted", muted == [NEW], muted)
        check("the project's relationship count is unchanged", count_rels(s, PID) == rels_before,
              f"{count_rels(s, PID)} vs {rels_before}")
        stamp = one(s, "MATCH ()-[r:RESOLVES_TO {project_id: $pid}]->() RETURN collect(r.user_id)",
                    pid=PID)
        check("the stamped relationship names the new owner", stamp == [NEW], stamp)
        cve = s.run("MATCH (c:CVE {id: $cve}) RETURN c.user_id IS NULL AND c.project_id IS NULL "
                    "AS clean, COUNT { (c)<-[:HAS_KNOWN_CVE]-() } AS links", cve=CVE).single()
        check("the reference CVE is untouched and still linked",
              cve is not None and cve["clean"] and cve["links"] == 1, dict(cve) if cve else None)
        check("the sibling project of the old owner is untouched",
              count_project(s, OLD, CTL) == ctl_before, count_project(s, OLD, CTL))

    again = client.retenant_project(PID, OLD, NEW)
    check("the same transfer twice moves nothing", again["total_nodes"] == 0
          and again["relationships"] == 0, again["total_nodes"])

    back = client.retenant_project(PID, NEW, OLD)
    with client.driver.session() as s:
        check("the reverse call puts every node back under the old owner",
              count_project(s, OLD, PID) == total_before and count_project(s, NEW, PID) == 0,
              f"old {count_project(s, OLD, PID)} new {count_project(s, NEW, PID)}")
        print(f"  E9: run back moved {back['total_nodes']} node(s) in {back['elapsed_ms']} ms")
        s.run("MATCH (d:Domain {user_id: $old, project_id: $pid}) WITH d LIMIT 1 "
              "CREATE (:Domain {name: d.name, user_id: $new, project_id: $pid})",
              old=OLD, new=NEW, pid=PID)
    try:
        client.retenant_project(PID, OLD, NEW)
        code = None
    except RetenantError as exc:
        code = exc.code
    with client.driver.session() as s:
        check("a twin under the new owner is refused before anything moves",
              code == "retenant_conflict" and count_project(s, OLD, PID) == total_before,
              f"{code}, old {count_project(s, OLD, PID)}")
finally:
    with client.driver.session() as s:
        while one(s, "MATCH (n) WHERE n.project_id IN $pids WITH n LIMIT 5000 "
                     "DETACH DELETE n RETURN count(n)", pids=[PID, CTL]):
            pass
        s.run("MATCH (c:CVE {id: $cve}) DETACH DELETE c", cve=CVE)
        left = one(s, "MATCH (n) WHERE n.project_id IN $pids OR n.id = $cve RETURN count(n)",
                   pids=[PID, CTL], cve=CVE)
    check("the synthetic data is deleted", left == 0, left)
    client.close()

print(f"\n== RESULT: {passed} passed, {failed} failed ==")
sys.exit(1 if failed else 0)
PY
