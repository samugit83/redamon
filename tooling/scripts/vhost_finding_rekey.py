#!/usr/bin/env python3
"""Re-key VHost/SNI findings to their collision-free ids. DRY RUN BY DEFAULT.

WHY

A VHost/SNI finding was keyed `vhost_sni_<hostname>_<ip>_<port>_<layer>` with
every character of the hostname outside [a-z0-9], and of the IP outside
[0-9.], folded to "_" (recon/main_recon_modules/vhost_sni_enum.py). So
`dev-api.example.com` and `dev.api.example.com` on one IP and port were ONE
Vulnerability node, and so were `2001:db8::a` and `2001:db8::b`. The writer now
keys it on a hash of the exact hostname, IP, port and layer (`finding_id`). The
next full scan writes the new ids and prunes an old node nobody touched; a
muted or human-judged one is kept as stale, and everything that names its old
id would be left behind:

  - the `:Muted` label and the mute properties on the node;
  - the Priority Board layers (`triage_*`), a person's DECISION included;
  - the agent's proof edges `(:ChainFinding)-[:CONFIRMS]->(finding)`;
  - `NodeFilterExemption.nodeKey`, `Remediation.findingIds`,
    `CapturedHttpTransaction.findingId` in Postgres.

WHAT IT DOES

For every vhost_sni_enum finding whose id is the old folded form of its own
stored `hostname`, `ip`, `port` and `layer`, the new id is computed from those
same stored values. The rule for a node two names (or two addresses) collided
on: it moves to the id of the hostname and IP it STORES, which is the one its
name, description and URL show, so it is what a person muted or judged. The
mute and the decision stay with that name only; they are NOT copied to the
other name, a different application nobody was shown. The other name comes
back at the next scan as a new finding with no mute and no decision; this
script lists it ("also collided with ...") so a person can re-apply theirs.
Its Subdomain (or IP) edge to the moved node is dropped, so the old node no
longer hangs off a name it is not about.

A node whose stored values do not reproduce its id is left alone and listed;
the next full scan prunes it.

A re-key renames the node's id in place when no node holds the new id yet (the
upgrade order: run this before the first scan on the new release), so every
layer, the mute, `stale_since` and the CONFIRMS edges stay exactly as they
were. When a scan already wrote the new id, the triage layers move as one block
from one node and the mute with its provenance (as
tooling/scripts/triage_graph_migrate.py merges duplicates), the CONFIRMS edges
are re-created there, and the old node is deleted. It never computes a score
and never writes `updated_at`; the next publish recombines.

  # what it would do, per project, changing nothing (the default)
  python tooling/scripts/vhost_finding_rekey.py --all

  # after a Neo4j and Postgres backup, with the services stopped
  docker compose stop agent webapp recon-orchestrator
  python tooling/scripts/vhost_finding_rekey.py --all --apply
  docker compose start agent webapp recon-orchestrator

It needs the Neo4j driver and psycopg (DATABASE_URL); the agent image has both.
Inside a container `localhost` is not the stack, so point the services check at
it, or `--apply` cannot see them running:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL -e AGENT_URL=http://agent:8080 -e WEBAPP_API_URL=http://webapp:3000 \\
    -e RECON_ORCHESTRATOR_URL=http://recon-orchestrator:8010 \\
    --entrypoint python redamon-agent tooling/scripts/vhost_finding_rekey.py --all

Idempotent: a second run finds nothing to re-key. Run it again after a project
import or a scan-version restore brings folded ids back.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.scripts.dns_finding_rekey import READ_PAIR, RENAME, rekey_postgres  # noqa: E402
from tooling.scripts.netlas_finding_rekey import (  # noqa: E402
    COPY_PROOF, DELETE_OLD, MERGE_ONTO_NEW, _carried,
)
from tooling.scripts.triage_graph_migrate import services_are_up  # noqa: E402

PROJECTS = """
    SELECT id, user_id
      FROM projects
     {scope}
     ORDER BY created_at
"""

# Every parent the writer links (vhost_sni_mixin.py): the hostname's Subdomain,
# or its Domain when the name is the org root, and the IP that served it.
OLD_FINDINGS = """
MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
WHERE v.source = 'vhost_sni_enum'
OPTIONAL MATCH (p {user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v)
WHERE p:Subdomain OR p:Domain OR p:IP
WITH v, collect(DISTINCT CASE WHEN p:IP THEN {kind: 'ip', key: p.address}
                              WHEN p IS NOT NULL THEN {kind: 'name', key: p.name} END) AS parents
RETURN v.id AS id, v.hostname AS hostname, v.ip AS ip, v.port AS port, v.layer AS layer,
       parents
ORDER BY id
"""

DROP_SIBLING_EDGES = """
MATCH (v:Vulnerability {id: $new, user_id: $uid, project_id: $pid})
MATCH (p {user_id: $uid, project_id: $pid})-[r:HAS_VULNERABILITY]->(v)
WHERE ((p:Subdomain OR p:Domain) AND p.name IN $names) OR (p:IP AND p.address IN $addrs)
DELETE r
RETURN count(r) AS n
"""


def _fold_host(hostname: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", str(hostname).lower())


def _fold_ip(ip: str) -> str:
    return re.sub(r"[^0-9.]", "_", str(ip))


def old_finding_id(hostname, ip, port, layer) -> str:
    """The folded id earlier releases wrote."""
    return f"vhost_sni_{_fold_host(hostname)}_{_fold_ip(ip)}_{port}_{str(layer).lower()}"


def new_finding_id(hostname, ip, port, layer) -> str:
    """The id `vhost_sni_enum.finding_id` writes (pinned to it by a recon test)."""
    host = str(hostname or "").strip().lower().rstrip(".")
    addr = str(ip or "").strip()
    try:
        addr = ipaddress.ip_address(addr).compressed
    except ValueError:
        addr = addr.lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        pass
    key = f"{host}|{addr}|{port}|{str(layer or '').lower()}"
    return "vhost_sni_" + hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:20]


def _same_ip(a, b) -> bool:
    try:
        return ipaddress.ip_address(str(a)) == ipaddress.ip_address(str(b))
    except ValueError:
        return str(a).lower() == str(b).lower()


def siblings(parents, hostname: str, ip: str) -> dict:
    """The parents that are another name or address the old id collided with:
    they differ from what the node stores but fold to the same id part."""
    names, addrs = set(), set()
    for p in parents or []:
        key = p.get("key")
        if not key:
            continue
        if p.get("kind") == "ip":
            if not _same_ip(key, ip) and _fold_ip(key) == _fold_ip(ip):
                addrs.add(str(key))
        elif str(key).lower() != hostname and _fold_host(key) == _fold_host(hostname):
            names.add(str(key))
    return {"names": sorted(names), "addrs": sorted(addrs)}


def plan_project(session, project: dict) -> dict:
    """The re-keys one project needs. Reads the graph; writes nothing."""
    uid, pid = project["user_id"], project["id"]
    rekeys, unmapped = [], []
    for row in session.run(OLD_FINDINGS, uid=uid, pid=pid):
        hostname, ip, port, layer = row["hostname"], row["ip"], row["port"], row["layer"]
        if not hostname or not ip or port is None or not layer:
            unmapped.append({"old_id": row["id"], "reason": "it stores no hostname, ip, port or layer"})
            continue
        hostname = str(hostname).strip().lower()
        if new_finding_id(hostname, ip, port, layer) == row["id"]:
            continue
        if old_finding_id(hostname, ip, port, layer) != row["id"]:
            unmapped.append({"old_id": row["id"],
                             "reason": "its stored hostname, ip, port and layer do not explain its id"})
            continue
        rekeys.append({"old_id": row["id"], "new_id": new_finding_id(hostname, ip, port, layer),
                       "hostname": hostname, "ip": str(ip), "port": port, "layer": layer,
                       "siblings": siblings(row["parents"], hostname, str(ip))})
    return {"rekeys": rekeys, "unmapped": unmapped}


def rekey_graph(session, uid: str, pid: str, rekey: dict) -> str:
    """Move one finding to its new id. Returns 'renamed', 'merged' or 'gone'."""
    nodes = {r["id"]: r for r in session.run(
        READ_PAIR, uid=uid, pid=pid, old=rekey["old_id"], new=rekey["new_id"])}
    old, new = nodes.get(rekey["old_id"]), nodes.get(rekey["new_id"])
    if old is None:
        return "gone"
    if new is None:
        session.run(RENAME, uid=uid, pid=pid, old=rekey["old_id"], new=rekey["new_id"])
        sib = rekey.get("siblings") or {}
        if sib.get("names") or sib.get("addrs"):
            session.run(DROP_SIBLING_EDGES, uid=uid, pid=pid, new=rekey["new_id"],
                        names=sib.get("names") or [], addrs=sib.get("addrs") or [])
        return "renamed"
    carried, cleared, mute = _carried(old, new)
    remove = f"REMOVE {', '.join('keep.' + p for p in cleared)}\n" if cleared else ""
    session.run(MERGE_ONTO_NEW.replace("{remove}", remove), uid=uid, pid=pid,
                new=rekey["new_id"], carried=carried, mute=mute)
    session.run(COPY_PROOF, uid=uid, pid=pid, old=rekey["old_id"], new=rekey["new_id"])
    # DETACH: the old node's sibling edges go with it.
    session.run(DELETE_OLD, uid=uid, pid=pid, old=rekey["old_id"])
    return "merged"


def _shown(value) -> str:
    """Target-derived text, printable and short."""
    return ascii(str(value))[1:-1][:120]


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
                out(f"[vhost rekey] {pid}: {_shown(u['old_id'])}: {u['reason']}; left alone, "
                    f"the next full scan prunes it")
            for r in plan["rekeys"]:
                out(f"[vhost rekey] {pid}: {_shown(r['hostname'])} on {_shown(r['ip'])}:{r['port']} "
                    f"{r['layer']}  {r['old_id']} -> {r['new_id']}{suffix}")
                others = r["siblings"]["names"] + r["siblings"]["addrs"]
                if others:
                    out(f"[vhost rekey] {pid}:   also collided with "
                        f"{', '.join(_shown(o) for o in others)}: its edge is dropped, and it "
                        f"returns at the next scan as its own finding without this mute or decision")
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
            if plan["rekeys"] or plan["unmapped"]:
                summary[pid] = {**plan, "outcomes": outcomes}
                collided = sum(1 for r in plan["rekeys"]
                               if r["siblings"]["names"] or r["siblings"]["addrs"])
                counted = ", ".join(f"{outcomes.count(o)} {o}"
                                    for o in ("renamed", "merged", "gone") if outcomes.count(o))
                out(f"[vhost rekey] {pid}: {len(plan['rekeys'])} to re-key "
                    f"({collided} with a collided name or address), "
                    f"{len(plan['unmapped'])} left alone"
                    + (f"; done: {counted}" if counted else ""))
    total = sum(len(p["rekeys"]) for p in summary.values())
    out(f"[vhost rekey] {'re-keyed' if apply else 'would re-key'} {total} finding(s) "
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
