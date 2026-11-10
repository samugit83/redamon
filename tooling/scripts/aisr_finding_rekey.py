#!/usr/bin/env python3
"""Re-key AI Surface MCP YARA findings to one per rule. DRY RUN BY DEFAULT.

WHY

An MCP YARA finding was keyed `aisr_<sha256(type|base_url|path|tool)>`
(recon/main_recon_modules/ai_surface_recon.py `_mk_finding`). Every rule that
fired on a server's instructions is an `mcp_prompt_injection` with no tool, and
a rule pack can hold several rules of one threat type for a tool, so those
rules shared ONE node holding the last-written rule's name, severity and
evidence. The writer now adds the rule name to the key. The next full scan
writes the new ids and prunes an old node nobody touched; a muted or
human-judged one is kept as stale, and everything that names its old id would
be left behind:

  - the `:Muted` label and the mute properties on the node;
  - the Priority Board layers (`triage_*`), a person's DECISION included;
  - the agent's proof edges `(:ChainFinding)-[:CONFIRMS]->(finding)`;
  - `NodeFilterExemption.nodeKey`, `Remediation.findingIds`,
    `CapturedHttpTransaction.findingId` in Postgres.

WHAT IT DOES

For every ai_surface_recon YARA finding still keyed without its rule:
  - the rule is the one the node's stored `name` gives ("MCP server
    instructions: <rule>" or "MCP tool '<tool>': <rule>"): the last rule
    written, whose severity and evidence the node shows, so it is what a person
    muted or judged. The old node moves to THAT rule's id only. The other rules
    it absorbed come back at the next scan as new findings, with no mute and no
    decision;
  - the base URL and MCP path come from the Endpoint (or the BaseURL and the
    MCP probe paths) it hangs off, and must reproduce the old id exactly. A
    name that names no rule, or a parent that does not explain the id, leaves
    the node alone (listed); the next full scan prunes it.

A re-key renames the node's id in place when no node holds the new id yet (the
upgrade order: run this before the first scan on the new release), so every
layer, the mute, `stale_since` and the CONFIRMS edges stay exactly as they
were. When a scan already wrote the new id, the triage layers move as one block
from one node and the mute with its provenance (as
tooling/scripts/triage_graph_migrate.py merges duplicates), the CONFIRMS edges
are re-created there, and the old node is deleted. It never computes a score
and never writes `updated_at`; the next publish recombines.

  # what it would do, per project, changing nothing (the default)
  python tooling/scripts/aisr_finding_rekey.py --all

  # after a Neo4j and Postgres backup, with the services stopped
  docker compose stop agent webapp recon-orchestrator
  python tooling/scripts/aisr_finding_rekey.py --all --apply
  docker compose start agent webapp recon-orchestrator

It needs the Neo4j driver and psycopg (DATABASE_URL); the agent image has both.
Inside a container `localhost` is not the stack, so point the services check at
it, or `--apply` cannot see them running:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL -e AGENT_URL=http://agent:8080 -e WEBAPP_API_URL=http://webapp:3000 \\
    -e RECON_ORCHESTRATOR_URL=http://recon-orchestrator:8010 \\
    --entrypoint python redamon-agent tooling/scripts/aisr_finding_rekey.py --all

Idempotent: a second run finds nothing to re-key. Run it again after a project
import or a scan-version restore brings rule-less ids back.
"""
from __future__ import annotations

import argparse
import hashlib
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

#: The finding kinds a YARA hit is written as (`_MCP_THREAT_MAP` in
#: ai_surface_recon.py). `mcp_annotation_mismatch` has no rule; its id never moved.
YARA_TYPES = ("mcp_tool_poisoning", "mcp_prompt_injection", "mcp_data_exfiltration",
              "mcp_command_injection", "mcp_code_execution", "mcp_credential_harvesting")

SERVER_PREFIX = "MCP server instructions: "
TOOL_PREFIX = "MCP tool '"
#: A YARA rule identifier. The tool name before it is target-controlled and may
#: hold anything, so the rule is read from the end and must be an identifier.
RULE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")

PROJECTS = """
    SELECT id, user_id
      FROM projects
     {scope}
     ORDER BY created_at
"""

OLD_FINDINGS = """
MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
WHERE v.source = 'ai_surface_recon' AND v.id STARTS WITH 'aisr_' AND v.type IN $types
OPTIONAL MATCH (parent {user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v)
WITH v, collect(DISTINCT CASE
         WHEN parent:Endpoint THEN {baseurl: parent.baseurl, path: parent.path}
         WHEN parent:BaseURL THEN {baseurl: parent.url, path: null}
       END) AS parents
RETURN v.id AS id, v.type AS type, v.name AS name, parents
ORDER BY id
"""


def old_finding_id(ftype, base_url, path, tool) -> str:
    """The rule-less id earlier releases wrote."""
    return "aisr_" + hashlib.sha256(f"{ftype}|{base_url}|{path}|{tool}".encode()).hexdigest()[:16]


def new_finding_id(ftype, base_url, path, tool, rule) -> str:
    """The id `_mk_finding` writes for a YARA hit (pinned to it by a recon test)."""
    return "aisr_" + hashlib.sha256(
        f"{ftype}|{base_url}|{path}|{tool}|{rule}".encode()).hexdigest()[:16]


def parse_name(name) -> tuple[str | None, str] | None:
    """(tool, rule) from a stored finding name; None when it names no rule."""
    name = str(name or "")
    if name.startswith(SERVER_PREFIX):
        tool, rule = None, name[len(SERVER_PREFIX):]
    elif name.startswith(TOOL_PREFIX) and "': " in name:
        tool, rule = name[len(TOOL_PREFIX):].rsplit("': ", 1)
    else:
        return None
    return (tool, rule) if RULE_NAME.fullmatch(rule) else None


def _mcp_probe_paths() -> list[str]:
    """recon's MCP probe paths, loaded by path: importing the recon.helpers
    package would pull in the scan dependencies this script does not need."""
    import importlib.util
    path = REPO_ROOT / "recon" / "helpers" / "ai_signal_catalog.py"
    spec = importlib.util.spec_from_file_location("_rekey_ai_signal_catalog", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return list(module.AI_MCP_PROBE_PATHS)


def _where(parents, probe_paths) -> list[tuple[str, str]]:
    out = []
    for p in parents or []:
        base = p.get("baseurl")
        if not base:
            continue
        for path in ([p["path"]] if p.get("path") else probe_paths):
            if (base, path) not in out:
                out.append((base, path))
    return out


def plan_project(session, project: dict, probe_paths) -> dict:
    """The re-keys one project needs. Reads the graph; writes nothing."""
    uid, pid = project["user_id"], project["id"]
    rekeys, unmapped = [], []
    for row in session.run(OLD_FINDINGS, uid=uid, pid=pid, types=list(YARA_TYPES)):
        parsed = parse_name(row["name"])
        if parsed is None:
            unmapped.append({"old_id": row["id"], "reason": "its name names no rule"})
            continue
        tool, rule = parsed
        where = _where(row["parents"], probe_paths)
        if any(new_finding_id(row["type"], b, p, tool, rule) == row["id"] for b, p in where):
            continue
        hit = next(((b, p) for b, p in where
                    if old_finding_id(row["type"], b, p, tool) == row["id"]), None)
        if hit is None:
            unmapped.append({"old_id": row["id"],
                             "reason": "no Endpoint or BaseURL parent explains its id"})
            continue
        rekeys.append({"old_id": row["id"], "type": row["type"], "tool": tool, "rule": rule,
                       "new_id": new_finding_id(row["type"], hit[0], hit[1], tool, rule)})
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
        return "renamed"
    carried, cleared, mute = _carried(old, new)
    remove = f"REMOVE {', '.join('keep.' + p for p in cleared)}\n" if cleared else ""
    session.run(MERGE_ONTO_NEW.replace("{remove}", remove), uid=uid, pid=pid,
                new=rekey["new_id"], carried=carried, mute=mute)
    session.run(COPY_PROOF, uid=uid, pid=pid, old=rekey["old_id"], new=rekey["new_id"])
    session.run(DELETE_OLD, uid=uid, pid=pid, old=rekey["old_id"])
    return "merged"


def run(conn, driver, project_id: str | None, apply: bool, probe_paths=None,
        out=print) -> dict:
    """Plan every project and, with `apply`, re-key it. Returns the plan per project."""
    if project_id is not None and not project_id.strip():
        raise ValueError("a blank project id; pass --all to mean every project")
    probe_paths = _mcp_probe_paths() if probe_paths is None else probe_paths
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
            plan = plan_project(session, project, probe_paths)
            for u in plan["unmapped"]:
                out(f"[aisr rekey] {pid}: {u['old_id']}: {u['reason']}; left alone, "
                    f"the next full scan prunes it")
            for r in plan["rekeys"]:
                # ascii(): the tool name is the target's text, never echoed raw.
                on = "server instructions" if r["tool"] is None else f"tool {ascii(r['tool'])[:80]}"
                out(f"[aisr rekey] {pid}: {r['type']} {r['rule']} on {on}  "
                    f"{r['old_id']} -> {r['new_id']}{suffix}")
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
                server = sum(1 for r in plan["rekeys"] if r["tool"] is None)
                counted = ", ".join(f"{outcomes.count(o)} {o}"
                                    for o in ("renamed", "merged", "gone") if outcomes.count(o))
                out(f"[aisr rekey] {pid}: {len(plan['rekeys'])} to re-key "
                    f"({server} on server instructions, {len(plan['rekeys']) - server} on tools), "
                    f"{len(plan['unmapped'])} left alone"
                    + (f"; done: {counted}" if counted else ""))
    total = sum(len(p["rekeys"]) for p in summary.values())
    out(f"[aisr rekey] {'re-keyed' if apply else 'would re-key'} {total} finding(s) "
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
