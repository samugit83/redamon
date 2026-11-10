#!/usr/bin/env python3
"""Re-key web-cache-deception findings to an id that holds across runs. DRY RUN BY DEFAULT.

WHY

The native deception probe (recon/cache_scan/deception.py) plants the signed-in
page under a random marker (`/account/rdmn1a2b3c.css`) and used to write that
plant URL as the finding's URL, so the Vulnerability id built from it
(graph_db/mixins/cache_mixin.py `cache_vuln_id`) changed on every run. Each run
wrote a new node and the prune deleted the previous one, or kept it as stale when
a person had muted or judged it, leaving behind everything that named it:

  - the `:Muted` label and the mute properties on the node;
  - the Priority Board layers (`triage_*`), a person's DECISION included;
  - the agent's proof edges `(:ChainFinding)-[:CONFIRMS]->(finding)`;
  - `NodeFilterExemption.nodeKey`, `Remediation.findingIds`,
    `CapturedHttpTransaction.findingId` in Postgres.

The writer now keys the finding on the page and the URL shape that leaked
(`/account` + `static-suffix:/.css`) and keeps the plant URL in `poc_link`.

WHAT IT DOES

For every native deception finding (`cache_technique: 'cache_deception'`,
`detection_mode: 'deception'`) whose id is still keyed on a plant URL, it reads
the page, the delimiter and the suffix back from that URL and works out the id
the writer now writes. A project can hold several old nodes for one new id: the
last run's, plus the stale ones a person muted or judged. They collapse to one:

  - the KEEPER is the node a scan already wrote under the new id; when there is
    none (the upgrade order: run this before the first scan on the new release),
    it is the most recently written old node, renamed in place, so its evidence,
    layers, mute, `stale_since` and CONFIRMS edges stay as they were; it takes
    the page as its endpoint and the shape as `cache_param`, as the writer does;
  - every other old node, most recent first, is merged onto the keeper and
    deleted: its triage layers move as ONE block, and only when they rank higher
    than the keeper's (a person's decision, then a review, then the rules:
    dns_finding_rekey._block_rank), so of two decisions the keeper's or the most
    recent one wins; its mute moves, with its provenance, only onto an unmuted
    keeper; its CONFIRMS edges are re-created on the keeper;
  - the Postgres rows naming an old id are pointed at the new one;
  - the keeper hangs off the page's Endpoint when recon has one, and the
    throwaway Endpoints the old writer created at a `/` plant path are deleted
    when nothing but deception findings and their BaseURL hang on them (partial
    recon reads Endpoints as targets and would probe them). A finding still on
    one keeps its BaseURL edge.

It never computes a score and never writes `updated_at`; the next publish
recombines.

  # what it would do, per project, changing nothing (the default)
  python tooling/scripts/cache_deception_rekey.py --all

  # after a Neo4j and Postgres backup, with the services stopped
  docker compose stop agent webapp recon-orchestrator
  python tooling/scripts/cache_deception_rekey.py --all --apply
  docker compose start agent webapp recon-orchestrator

It needs the Neo4j driver and psycopg (DATABASE_URL); the agent image has both.
Inside a container `localhost` is not the stack, so point the services check at
it, or `--apply` cannot see them running:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL -e AGENT_URL=http://agent:8080 -e WEBAPP_API_URL=http://webapp:3000 \\
    -e RECON_ORCHESTRATOR_URL=http://recon-orchestrator:8010 \\
    --entrypoint python redamon-agent tooling/scripts/cache_deception_rekey.py --all

Idempotent: a second run finds nothing to re-key. Run it again after a project
import or a scan-version restore brings plant-keyed deception findings back.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from graph_db.mixins.cache_mixin import cache_vuln_id  # noqa: E402
from tooling.scripts.netlas_finding_rekey import _carried  # noqa: E402
from tooling.scripts.triage_graph_migrate import services_are_up  # noqa: E402

TECHNIQUE = "cache_deception"

#: The plant path the probe used to write as the finding's URL: the page path, a
#: delimiter, "rdmn" and six hex digits, a static suffix. Read with urlsplit:
#: urlparse moves a `;x.css` tail out of the path into `params`.
_PLANT_PATH = re.compile(
    r"^(?P<page>.*)(?P<delimiter>[/;])rdmn[0-9a-f]{6}(?P<suffix>\.css|\.js|\.jpg)$")

#: A throwaway Endpoint the old writer MERGEd. Only the `/` shape made one: the
#: writer reads the path with urlparse, which ends a `;` plant at the page.
PLANT_ENDPOINT_PATH = r".*/rdmn[0-9a-f]{6}\.(css|js|jpg)"

PROJECTS = """
    SELECT id, user_id
      FROM projects
     {scope}
     ORDER BY created_at
"""

OLD_FINDINGS = """
MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
WHERE v.source = 'cache_poisoning' AND v.cache_technique = 'cache_deception'
  AND v.detection_mode = 'deception' AND v.endpoint IS NOT NULL
RETURN v.id AS id, v.endpoint AS endpoint, v.cache_header AS cache_header,
       v.cache_param AS cache_param, toString(v.updated_at) AS seen
ORDER BY id
"""

READ_NODES = """
MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
WHERE v.id IN $ids
RETURN v.id AS id, v:Muted AS muted, properties(v) AS props
"""

RENAME = """
MATCH (v:Vulnerability {id: $old, user_id: $uid, project_id: $pid})
SET v.id = $new, v.vulnerability_id = $new, v.endpoint = $endpoint, v.matched_at = $endpoint,
    v.cache_param = $cache_param
"""

MERGE_ONTO_NEW = """
MATCH (keep:Vulnerability {id: $new, user_id: $uid, project_id: $pid})
{remove}SET keep += $carried
FOREACH (_ IN CASE WHEN $mute THEN [1] ELSE [] END | SET keep:Muted)
RETURN count(keep) AS n
"""

COPY_PROOF = """
MATCH (old:Vulnerability {id: $old, user_id: $uid, project_id: $pid})
MATCH (new:Vulnerability {id: $new, user_id: $uid, project_id: $pid})
MATCH (cf:ChainFinding {user_id: $uid, project_id: $pid})-[r:CONFIRMS]->(old)
MERGE (cf)-[r2:CONFIRMS]->(new)
SET r2 += properties(r)
RETURN count(r2) AS n
"""

DELETE_OLD = """
MATCH (v:Vulnerability {id: $old, user_id: $uid, project_id: $pid})
DETACH DELETE v
"""

# Only an Endpoint recon already has: the script never invents an asset.
REPARENT = """
MATCH (v:Vulnerability {id: $new, user_id: $uid, project_id: $pid})
OPTIONAL MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $baseurl,
                            user_id: $uid, project_id: $pid})
FOREACH (_ IN CASE WHEN e IS NULL THEN [] ELSE [1] END | MERGE (e)-[:HAS_VULNERABILITY]->(v))
RETURN count(e) AS n
"""

_PLANTS = """
MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
WHERE e.source = 'cache_poisoning' AND e.path =~ $plant_path
  AND NOT EXISTS {
    MATCH (e)-[r]-(x)
    WHERE NOT (type(r) = 'HAS_ENDPOINT' AND x:BaseURL)
      AND NOT (type(r) = 'HAS_VULNERABILITY' AND x:Vulnerability
               AND x.source = 'cache_poisoning' AND x.cache_technique = 'cache_deception')
  }
"""

PLANT_ENDPOINTS = _PLANTS + """
RETURN e.baseurl AS baseurl, e.path AS path
ORDER BY baseurl, path
"""

DELETE_PLANTS = _PLANTS + """
DETACH DELETE e
RETURN count(*) AS n
"""


def new_vector(delimiter: str, suffix: str) -> str:
    """recon/cache_scan/deception.py `deception_vector`. Not imported: recon.helpers
    pulls the scan dependencies (dnspython) the agent image this runs in lacks.
    recon/tests/test_cache_deception.py holds the two to the same id."""
    return f"static-suffix:{delimiter}{suffix}"


def plan_finding(uid: str, pid: str, node_id: str, endpoint, vector) -> dict | None:
    """The stable id one old deception finding moves to, or None when its id is
    not keyed on a plant URL (already moved, or written some other way)."""
    endpoint = str(endpoint or "")
    parts = urlsplit(endpoint)
    match = _PLANT_PATH.match(parts.path)
    if match is None:
        return None
    if cache_vuln_id(uid, pid, TECHNIQUE, endpoint, vector or "vector") != node_id:
        return None
    page_url = urlunsplit(parts._replace(path=match["page"].rstrip("/") or "/"))
    cache_param = new_vector(match["delimiter"], match["suffix"])
    new_id = cache_vuln_id(uid, pid, TECHNIQUE, page_url, cache_param)
    if new_id == node_id:
        return None
    return {"old_id": node_id, "new_id": new_id, "page_url": page_url, "cache_param": cache_param}


def plan_project(session, project: dict) -> dict:
    """The re-keys one project needs, one per new id. Reads the graph; writes nothing."""
    uid, pid = project["user_id"], project["id"]
    groups: dict[str, dict] = {}
    for row in session.run(OLD_FINDINGS, uid=uid, pid=pid):
        plan = plan_finding(uid, pid, str(row["id"]), row["endpoint"],
                            row["cache_header"] or row["cache_param"])
        if plan is None:
            continue
        group = groups.setdefault(plan["new_id"], {
            "new_id": plan["new_id"], "page_url": plan["page_url"],
            "cache_param": plan["cache_param"], "old": []})
        group["old"].append({"old_id": plan["old_id"], "seen": str(row["seen"] or "")})
    for group in groups.values():
        # Most recently written first (an ISO timestamp sorts as text), the id
        # breaking ties, so the keeper and the merge order never depend on the read.
        group["old"].sort(key=lambda o: o["old_id"])
        group["old"].sort(key=lambda o: o["seen"], reverse=True)
    plants = [{"baseurl": r["baseurl"], "path": r["path"]}
              for r in session.run(PLANT_ENDPOINTS, uid=uid, pid=pid, plant_path=PLANT_ENDPOINT_PATH)]
    return {"rekeys": [groups[k] for k in sorted(groups)], "plants": plants}


def rekey_graph(session, uid: str, pid: str, rekey: dict) -> list[str]:
    """Collapse one group's old nodes onto the new id. One outcome per old node,
    in `rekey["old"]` order: 'renamed', 'merged' or 'gone'."""
    new_id = rekey["new_id"]
    old_ids = [o["old_id"] for o in rekey["old"]]
    present = {r["id"] for r in session.run(READ_NODES, uid=uid, pid=pid, ids=[new_id] + old_ids)}
    keeper = new_id in present
    outcomes = []
    for old_id in old_ids:
        if old_id not in present:
            outcomes.append("gone")
            continue
        if not keeper:
            session.run(RENAME, uid=uid, pid=pid, old=old_id, new=new_id,
                        endpoint=rekey["page_url"], cache_param=rekey["cache_param"])
            keeper = True
            outcomes.append("renamed")
            continue
        # Read again for each node: an earlier merge may have muted the keeper or
        # given it a better block.
        pair = {r["id"]: r for r in session.run(READ_NODES, uid=uid, pid=pid, ids=[old_id, new_id])}
        carried, cleared, mute = _carried(pair[old_id], pair[new_id])
        remove = f"REMOVE {', '.join('keep.' + p for p in cleared)}\n" if cleared else ""
        session.run(MERGE_ONTO_NEW.replace("{remove}", remove), uid=uid, pid=pid,
                    new=new_id, carried=carried, mute=mute)
        session.run(COPY_PROOF, uid=uid, pid=pid, old=old_id, new=new_id)
        session.run(DELETE_OLD, uid=uid, pid=pid, old=old_id)
        outcomes.append("merged")
    if keeper:
        page = urlsplit(rekey["page_url"])
        session.run(REPARENT, uid=uid, pid=pid, new=new_id, path=page.path or "/",
                    baseurl=f"{page.scheme}://{page.netloc}")
    return outcomes


def rekey_postgres(cursor, pid: str, rekey: dict) -> None:
    """Point every row that names an old id of the group at the new one."""
    for old in rekey["old"]:
        params = {"pid": pid, "old": old["old_id"], "new": rekey["new_id"],
                  "label": "Vulnerability", "row_id": f"c{uuid.uuid4().hex[:24]}"}
        # (project_id, label, node_key) is unique: an exemption the new id already
        # has makes the copy redundant.
        cursor.execute(
            """
            INSERT INTO node_filter_exemptions
                   (id, project_id, label, node_key, created_by, real_actor_user_id)
            SELECT %(row_id)s, project_id, label, %(new)s, created_by, real_actor_user_id
              FROM node_filter_exemptions
             WHERE project_id = %(pid)s AND label = %(label)s AND node_key = %(old)s
            ON CONFLICT (project_id, label, node_key) DO NOTHING
            """, params)
        cursor.execute(
            """
            DELETE FROM node_filter_exemptions
             WHERE project_id = %(pid)s AND label = %(label)s AND node_key = %(old)s
            """, params)
        cursor.execute(
            """
            UPDATE remediations r
               SET finding_ids = CASE WHEN %(new)s = ANY(r.finding_ids)
                                      THEN array_remove(r.finding_ids, %(old)s)
                                      ELSE array_replace(r.finding_ids, %(old)s, %(new)s) END
             WHERE r.project_id = %(pid)s AND %(old)s = ANY(r.finding_ids)
            """, params)
        cursor.execute(
            """
            UPDATE captured_http_transactions
               SET finding_id = %(new)s
             WHERE project_id = %(pid)s AND finding_id = %(old)s
            """, params)


def run(conn, driver, project_id: str | None, apply: bool, out=print) -> dict:
    """Plan every project and, with `apply`, re-key it. Returns the plan per project."""
    if project_id is not None and not project_id.strip():
        raise ValueError("a blank project id; pass --all to mean every project")
    with conn.cursor() as cur:
        cur.execute(PROJECTS.format(scope="WHERE id = %(pid)s" if project_id else ""),
                    {"pid": project_id} if project_id else {})
        cols = [c[0] for c in cur.description]
        projects = [dict(zip(cols, row)) for row in cur.fetchall()]

    summary = {}
    suffix = "" if apply else " (dry run)"
    with driver.session() as session:
        for project in projects:
            pid, uid = project["id"], project["user_id"]
            plan = plan_project(session, project)
            for r in plan["rekeys"]:
                olds = ", ".join(o["old_id"] for o in r["old"])
                out(f"[cache deception rekey] {pid}: {olds} -> {r['new_id']}{suffix}")
            for p in plan["plants"]:
                out(f"[cache deception rekey] {pid}: plant Endpoint {p['baseurl']}{p['path']} "
                    f"deleted{suffix}")
            outcomes, deleted = [], 0
            if apply and (plan["rekeys"] or plan["plants"]):
                # Postgres first: a run that dies after it re-plans the same
                # re-keys (the graph still holds the old ids) and its updates
                # are no-ops the second time.
                with conn.cursor() as cur:
                    for r in plan["rekeys"]:
                        rekey_postgres(cur, pid, r)
                conn.commit()
                for r in plan["rekeys"]:
                    outcomes.extend(rekey_graph(session, uid, pid, r))
                row = session.run(DELETE_PLANTS, uid=uid, pid=pid,
                                  plant_path=PLANT_ENDPOINT_PATH).single()
                deleted = int(row["n"]) if row else 0
            if plan["rekeys"] or plan["plants"]:
                summary[pid] = {**plan, "outcomes": outcomes, "plants_deleted": deleted}
                old_count = sum(len(r["old"]) for r in plan["rekeys"])
                counted = ", ".join(f"{outcomes.count(o)} {o}" for o in ("renamed", "merged", "gone")
                                    if outcomes.count(o))
                if apply and plan["plants"]:
                    counted = ", ".join(filter(None, (counted, f"{deleted} plant Endpoint(s) deleted")))
                out(f"[cache deception rekey] {pid}: {old_count} finding(s) to re-key onto "
                    f"{len(plan['rekeys'])} id(s), {len(plan['plants'])} plant Endpoint(s)"
                    + (f"; done: {counted}" if counted else ""))
    total = sum(len(r["old"]) for p in summary.values() for r in p["rekeys"])
    out(f"[cache deception rekey] {'re-keyed' if apply else 'would re-key'} {total} finding(s) "
        f"in {len(summary)} project(s)")
    return summary


def _connect():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise SystemExit("DATABASE_URL is not set: the fix items and exemptions live in Postgres.")
    try:
        import psycopg
    except ImportError:
        raise SystemExit("psycopg is required. Run this in the agent image (see the docstring).")
    return psycopg.connect(url)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--project", help="one project id")
    target.add_argument("--all", action="store_true", help="every project")
    ap.add_argument("--apply", action="store_true", help="write; without it this only lists")
    ap.add_argument("--force", action="store_true",
                    help="skip the services-are-down check. Do not.")
    args = ap.parse_args(argv)
    if args.project is not None and not args.project.strip():
        ap.error("--project is blank (an unset variable?); pass --all to mean every project")

    if args.apply:
        up = [] if args.force else services_are_up()
        if up:
            print("REFUSING: these services are still running: " + ", ".join(up), file=sys.stderr)
            print("A scan writing during the re-key would create the new ids under it.",
                  file=sys.stderr)
            return 2

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "")))
    try:
        with _connect() as conn:
            run(conn, driver, None if args.all else args.project, args.apply)
    finally:
        driver.close()
    if not args.apply:
        print("Nothing was changed. Re-run with --apply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
