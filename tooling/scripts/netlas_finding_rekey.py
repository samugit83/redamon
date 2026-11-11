#!/usr/bin/env python3
"""Re-key Netlas CVE findings to one per IP and port. DRY RUN BY DEFAULT.

WHY

A Netlas CVE was written as `Vulnerability {id: <the bare CVE id>}` under the
Service it was seen on, so one CVE on N IPs was ONE node per project. The
writer now keys it `netlas-<cve>-<ip>-<port>`, under the IP
(graph_db/mixins/osint_mixin.py `netlas_vuln_id`). The old node names no IP,
and a passive CVE is pruned only on the IPs its lookup decided
(recon/helpers/passive_cve_coverage.py), so no scan with Netlas on ever prunes
it: it stays beside the new findings for ever, and everything that names its
old id stays on it instead of following the finding:

  - the `:Muted` label and the mute properties on the node;
  - the Priority Board layers (`triage_*`), a person's DECISION included;
  - the agent's proof edges `(:ChainFinding)-[:CONFIRMS]->(finding)`;
  - `NodeFilterExemption.nodeKey`, `Remediation.findingIds`,
    `CapturedHttpTransaction.findingId` in Postgres.

WHAT IT DOES

For every Netlas finding still keyed on a bare CVE id, from the IP and port of
the Services it hangs off:
  - one (IP, port)    -> renamed in place (the upgrade order: run this before
    the first scan on the new release), so every layer, the mute, `stale_since`
    and the CONFIRMS edges stay exactly as they were; it gains `target_ip`,
    `target_port`, `cve_ids` and the IP as its parent;
  - several           -> one finding per (IP, port), each a copy of the old node
    with its mute, its layers (a person's DECISION included: it was about this
    CVE on all of them) and its CONFIRMS edges; listed in the output;
  - no Service parent -> nothing to re-key it to. Listed; `--apply` deletes it
    as a scan's prune would have, keeping (stamped `stale_since`) one a person
    muted or judged or the agent proved. Postgres rows naming it are left, as
    the prune leaves them.
When a scan already wrote a new id, the old node's triage layers move onto it
as one block and the mute with its provenance (as
tooling/scripts/triage_graph_migrate.py merges duplicates), its CONFIRMS edges
are re-created there, and the old node is deleted. It never computes a score
and never writes `updated_at`; the next publish recombines.

  # what it would do, per project, changing nothing (the default)
  python tooling/scripts/netlas_finding_rekey.py --all

  # after a Neo4j and Postgres backup, with the services stopped
  docker compose stop agent webapp recon-orchestrator
  python tooling/scripts/netlas_finding_rekey.py --all --apply
  docker compose start agent webapp recon-orchestrator

It needs the Neo4j driver and psycopg (DATABASE_URL); the agent image has both.
Inside a container `localhost` is not the stack, so point the services check at
it, or `--apply` cannot see them running:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL -e AGENT_URL=http://agent:8080 -e WEBAPP_API_URL=http://webapp:3000 \\
    -e RECON_ORCHESTRATOR_URL=http://recon-orchestrator:8010 \\
    --entrypoint python redamon-agent tooling/scripts/netlas_finding_rekey.py --all

Idempotent: a second run finds nothing to re-key, and lists again only the
unattributable findings it kept. Run it again after a project import or a
scan-version restore brings bare-id Netlas findings back.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from graph_db.mixins.osint_mixin import netlas_vuln_id  # noqa: E402
from graph_db.node_filters.guards import GUARD_KEEP_CHECK  # noqa: E402
from tooling.scripts.dns_finding_rekey import _block_rank  # noqa: E402
from tooling.scripts.triage_graph_migrate import (  # noqa: E402
    MUTE_PROPS, MUTE_PROVENANCE_PROPS, TRIAGE_PROPS, services_are_up,
)

PROJECTS = """
    SELECT id, user_id
      FROM projects
     {scope}
     ORDER BY created_at
"""

# What a scan's prune keeps rather than deletes (base_mixin.prune_unseen_findings):
# an operator's own mute, and the guards a rule-mute respects.
_KEPT_BY_PRUNE = ("((n:Muted AND NOT coalesce(n.muted_by, '') STARTS WITH 'rule:')\n"
                  f"  OR ({GUARD_KEEP_CHECK}))")

OLD_FINDINGS = """
MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
WHERE v.source = 'netlas' AND v.id =~ '(?i)CVE-[0-9]{4}-[0-9]{4,}'
OPTIONAL MATCH (svc:Service {user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v)
WITH v, [t IN collect(DISTINCT {ip: svc.ip_address, port: svc.port_number})
         WHERE t.ip IS NOT NULL AND t.port IS NOT NULL] AS targets
WITH v AS n, targets
RETURN n.id AS id, targets, """ + _KEPT_BY_PRUNE + """ AS kept
ORDER BY id
"""

READ_NODES = """
MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
WHERE v.id IN $ids
RETURN v.id AS id, v:Muted AS muted, properties(v) AS props
"""

# The IP becomes the parent; the Service edge goes only once it has one, so the
# finding is never left without a parent.
_REPARENT = """
WITH v
OPTIONAL MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
FOREACH (_ IN CASE WHEN i IS NULL THEN [] ELSE [1] END | MERGE (i)-[:HAS_VULNERABILITY]->(v))
WITH v, i
OPTIONAL MATCH (:Service)-[stale:HAS_VULNERABILITY]->(v)
WHERE i IS NOT NULL
DELETE stale
WITH DISTINCT v
OPTIONAL MATCH (c:CVE {id: $cve})
FOREACH (_ IN CASE WHEN c IS NULL THEN [] ELSE [1] END | MERGE (v)-[:INCLUDES_CVE]->(c))
RETURN count(v) AS n
"""

RENAME = """
MATCH (v:Vulnerability {id: $old, user_id: $uid, project_id: $pid})
SET v.id = $new, v.target_ip = $ip, v.target_port = $port,
    v.cves = coalesce(v.cves, [$cve]), v.cve_ids = coalesce(v.cve_ids, [$cve])
""" + _REPARENT

CREATE_COPY = """
CREATE (v:Vulnerability)
SET v = $props
FOREACH (_ IN CASE WHEN $muted THEN [1] ELSE [] END | SET v:Muted)
""" + _REPARENT

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

# The prune a scan no longer runs on these, done once. The Service check is
# repeated because the plan was read earlier: a row a Service now attributes is
# a re-key, never a delete.
DELETE_UNATTRIBUTABLE = """
MATCH (n:Vulnerability {user_id: $uid, project_id: $pid})
WHERE n.id IN $ids AND n.source = 'netlas'
  AND NOT EXISTS {
    MATCH (svc:Service {user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(n)
    WHERE svc.ip_address IS NOT NULL AND svc.port_number IS NOT NULL }
// The write lock before the mute is read, as the prune takes it: a mute that
// commits in between is then kept, not deleted with the node.
SET n._prune_lock = true
REMOVE n._prune_lock
WITH n, """ + _KEPT_BY_PRUNE + """ AS keep
FOREACH (_ IN CASE WHEN keep THEN [1] ELSE [] END |
  SET n.stale_since = coalesce(n.stale_since, datetime()))
WITH collect(CASE WHEN keep THEN NULL ELSE n END) AS doomed,
     count(CASE WHEN keep THEN 1 END) AS kept
FOREACH (d IN doomed | DETACH DELETE d)
RETURN size(doomed) AS deleted, kept
"""


def plan_project(session, project: dict) -> dict:
    """The re-keys one project needs. Reads the graph; writes nothing."""
    uid, pid = project["user_id"], project["id"]
    rekeys, unmapped = [], []
    for row in session.run(OLD_FINDINGS, uid=uid, pid=pid):
        cve = str(row["id"]).upper()
        pairs = sorted({(str(t["ip"]), int(t["port"])) for t in row["targets"] or []
                        if t.get("ip") and str(t.get("port", "")).isdigit()})
        if not pairs:
            unmapped.append({"old_id": row["id"], "kept": bool(row.get("kept"))})
            continue
        rekeys.append({"old_id": row["id"], "cve": cve, "targets": [
            {"ip": ip, "port": port, "new_id": netlas_vuln_id(cve, ip, port)}
            for ip, port in pairs]})
    return {"rekeys": rekeys, "unmapped": unmapped}


def _carried(old: dict, new: dict) -> tuple[dict, list, bool]:
    """What moves from the old node onto an existing new one: the triage block
    as one unit when the old one ranks higher, and the mute when only the old
    one carries one. As dns_finding_rekey.rekey_graph."""
    old_props, new_props = dict(old["props"] or {}), dict(new["props"] or {})
    take_old = _block_rank(old_props) < _block_rank(new_props)
    carried = {p: old_props[p] for p in TRIAGE_PROPS if take_old and old_props.get(p) is not None}
    cleared = [p for p in TRIAGE_PROPS if take_old and p in new_props]
    inherits_mute = bool(old["muted"]) and not new["muted"]
    if inherits_mute:
        carried.update({p: old_props[p] for p in MUTE_PROPS if old_props.get(p) is not None})
    else:
        for p in MUTE_PROVENANCE_PROPS:
            carried.pop(p, None)
    return carried, cleared, inherits_mute


def rekey_graph(session, uid: str, pid: str, rekey: dict) -> str:
    """Move one old finding to its new id(s): 'renamed', 'split', 'merged' or 'gone'."""
    ids = [rekey["old_id"]] + [t["new_id"] for t in rekey["targets"]]
    nodes = {r["id"]: r for r in session.run(READ_NODES, uid=uid, pid=pid, ids=ids)}
    old = nodes.get(rekey["old_id"])
    if old is None:
        return "gone"
    targets = rekey["targets"]
    base = {"uid": uid, "pid": pid, "cve": rekey["cve"]}

    if len(targets) == 1 and targets[0]["new_id"] not in nodes:
        t = targets[0]
        session.run(RENAME, **base, old=rekey["old_id"], new=t["new_id"], ip=t["ip"], port=t["port"])
        return "renamed"

    for t in targets:
        new = nodes.get(t["new_id"])
        if new is None:
            props = dict(old["props"] or {})
            props.update(id=t["new_id"], target_ip=t["ip"], target_port=t["port"],
                         cves=props.get("cves") or [rekey["cve"]],
                         cve_ids=props.get("cve_ids") or [rekey["cve"]])
            session.run(CREATE_COPY, **base, props=props, muted=bool(old["muted"]),
                        ip=t["ip"])
        else:
            carried, cleared, mute = _carried(old, new)
            remove = f"REMOVE {', '.join('keep.' + p for p in cleared)}\n" if cleared else ""
            session.run(MERGE_ONTO_NEW.replace("{remove}", remove), uid=uid, pid=pid,
                        new=t["new_id"], carried=carried, mute=mute)
        session.run(COPY_PROOF, uid=uid, pid=pid, old=rekey["old_id"], new=t["new_id"])
    session.run(DELETE_OLD, uid=uid, pid=pid, old=rekey["old_id"])
    return "merged" if all(t["new_id"] in nodes for t in targets) else "split"


def rekey_postgres(cursor, pid: str, rekey: dict) -> None:
    """Point every row that names the old id at its new one(s)."""
    new_ids = [t["new_id"] for t in rekey["targets"]]
    params = {"pid": pid, "old": rekey["old_id"], "label": "Vulnerability", "new_ids": new_ids,
              "first": new_ids[0],
              "targets": json.dumps([{"id": t["new_id"], "ip": t["ip"], "port": t["port"]}
                                     for t in rekey["targets"]])}
    # (project_id, label, node_key) is unique: an exemption a new id already
    # has makes the copy redundant.
    for new_id in new_ids:
        cursor.execute(
            """
            INSERT INTO node_filter_exemptions
                   (id, project_id, label, node_key, created_by, real_actor_user_id)
            SELECT %(row_id)s, project_id, label, %(new)s, created_by, real_actor_user_id
              FROM node_filter_exemptions
             WHERE project_id = %(pid)s AND label = %(label)s AND node_key = %(old)s
            ON CONFLICT (project_id, label, node_key) DO NOTHING
            """, {**params, "new": new_id, "row_id": f"c{uuid.uuid4().hex[:24]}"})
    cursor.execute(
        """
        DELETE FROM node_filter_exemptions
         WHERE project_id = %(pid)s AND label = %(label)s AND node_key = %(old)s
        """, params)
    cursor.execute(
        """
        UPDATE remediations r
           SET finding_ids = array_remove(r.finding_ids, %(old)s) || ARRAY(
                 SELECT n FROM unnest(%(new_ids)s::text[]) WITH ORDINALITY AS t(n, i)
                  WHERE NOT n = ANY(r.finding_ids) ORDER BY i)
         WHERE r.project_id = %(pid)s AND %(old)s = ANY(r.finding_ids)
        """, params)
    # A captured request goes to the finding on the IP (and port) it was sent to.
    cursor.execute(
        """
        UPDATE captured_http_transactions t
           SET finding_id = coalesce(
                 (SELECT m.id FROM jsonb_to_recordset(%(targets)s::jsonb) AS m(id text, ip text, port int)
                   WHERE m.ip IN (t.target_ip, t.host) AND m.port = t.port LIMIT 1),
                 (SELECT m.id FROM jsonb_to_recordset(%(targets)s::jsonb) AS m(id text, ip text, port int)
                   WHERE m.ip IN (t.target_ip, t.host) LIMIT 1),
                 %(first)s)
         WHERE t.project_id = %(pid)s AND t.finding_id = %(old)s
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
            for u in plan["unmapped"]:
                action = ("keep, stamped stale (a person muted or judged it, or the agent "
                          "proved it)" if u["kept"] else "delete")
                out(f"[netlas rekey] {pid}: {u['old_id']} hangs off no Service with an IP and "
                    f"port, and no scan prunes it -> {action}{suffix}")
            for r in plan["rekeys"]:
                news = ", ".join(t["new_id"] for t in r["targets"])
                many = (f"  (one finding per IP: the mute and the decision go to each)"
                        if len(r["targets"]) > 1 else "")
                out(f"[netlas rekey] {pid}: {r['old_id']} -> {news}{suffix}{many}")
            outcomes = []
            if apply and plan["rekeys"]:
                # Postgres first: a run that dies after it re-plans the same
                # re-keys (the graph still holds the old ids) and its updates
                # are no-ops the second time.
                with conn.cursor() as cur:
                    for r in plan["rekeys"]:
                        rekey_postgres(cur, pid, r)
                conn.commit()
                for r in plan["rekeys"]:
                    outcomes.append(rekey_graph(session, uid, pid, r))
            removed = None
            if apply and plan["unmapped"]:
                record = next(iter(session.run(
                    DELETE_UNATTRIBUTABLE, uid=uid, pid=pid,
                    ids=[u["old_id"] for u in plan["unmapped"]])), None)
                removed = {"deleted": int(record["deleted"] or 0) if record else 0,
                           "kept": int(record["kept"] or 0) if record else 0}
            if plan["rekeys"] or plan["unmapped"]:
                summary[pid] = {**plan, "outcomes": outcomes}
                if removed is not None:
                    summary[pid]["unattributable"] = removed
                split = sum(1 for r in plan["rekeys"] if len(r["targets"]) > 1)
                done = [f"{outcomes.count(o)} {o}"
                        for o in ("renamed", "split", "merged", "gone") if outcomes.count(o)]
                if removed:
                    done += [f"{removed['deleted']} deleted"] if removed["deleted"] else []
                    done += [f"{removed['kept']} kept stale"] if removed["kept"] else []
                out(f"[netlas rekey] {pid}: {len(plan['rekeys'])} to re-key "
                    f"({len(plan['rekeys']) - split} on one IP, {split} on several), "
                    f"{len(plan['unmapped'])} unattributable"
                    + (f"; done: {', '.join(done)}" if done else ""))
    total = sum(len(p["rekeys"]) for p in summary.values())
    unattributable = sum(len(p["unmapped"]) for p in summary.values())
    out(f"[netlas rekey] {'re-keyed' if apply else 'would re-key'} {total} finding(s) "
        f"in {len(summary)} project(s)"
        + (f"; {unattributable} unattributable" if unattributable else ""))
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
