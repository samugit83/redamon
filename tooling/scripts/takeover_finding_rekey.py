#!/usr/bin/env python3
"""Re-key subdomain-takeover findings whose provider the writer now names otherwise. DRY RUN BY DEFAULT.

WHY

A takeover finding is keyed `takeover_<sha1(hostname|provider|method)>`
(recon/helpers/takeover_helpers.py `finding_id`), so a change in how the
provider is derived moves the id. Two did (recon audit S-23, S-24):

  - an Amazon-issued certificate (ACM: every AWS service and every customer's
    own name) named the provider `aws-s3` when nothing else named one. It now
    names the family, `aws`;
  - the generic Nuclei DNS detections `detect-dangling-cname` and
    `dns-saas-service-detection` kept their template's name (`dangling-cname`,
    `dns-saas`) as the provider even when the CNAME or the certificate named
    the real one. That one now replaces it.

The next full scan writes the new ids and prunes an old node nobody touched; a
muted or human-judged one is kept as stale, and everything that names its old
id would be left behind:

  - the `:Muted` label and the mute properties on the node;
  - the Priority Board layers (`triage_*`), a person's DECISION included;
  - the agent's proof edges `(:ChainFinding)-[:CONFIRMS]->(finding)`;
  - `NodeFilterExemption.nodeKey`, `Remediation.findingIds`,
    `CapturedHttpTransaction.findingId` in Postgres.

WHAT IT DOES

For every takeover_scan finding keyed on `aws-s3`, `dangling-cname` or
`dns-saas`, the provider today's writer derives is recomputed from what the
node stores, with the writer's own tables (takeover_helpers.py):

  - `dangling-cname` / `dns-saas`: the provider of the stored `cname_target`,
    else the certificate's (`cert_provider`, an Amazon issuer read as `aws`);
  - `aws-s3`: moves to `aws` only when the certificate's issuer alone named S3:
    the stored CNAME and the certificate's subject name no S3 endpoint, and no
    tool in `tool_raw` named S3 (a tool that did still writes the old id).
    A node whose `tool_raw` cannot be read (cut at 50 KB) is left alone and
    listed; a full scan that no longer writes its id prunes it.

A node whose stored hostname, provider and method do not reproduce its id is
left alone and listed. The fields the next scan rewrites (`takeover_provider`,
`cert_provider`, `name`) are not touched.

A re-key renames the node's id in place when no node holds the new id yet (the
upgrade order: run this before the first scan on the new release), so every
layer, the mute, `stale_since` and the CONFIRMS edges stay exactly as they
were. When a scan already wrote the new id, the triage layers move as one block
from one node and the mute with its provenance (as
tooling/scripts/triage_graph_migrate.py merges duplicates), the CONFIRMS edges
are re-created there, and the old node is deleted. It never computes a score
and never writes `updated_at`; the next publish recombines.

  # what it would do, per project, changing nothing (the default)
  python tooling/scripts/takeover_finding_rekey.py --all

  # after a Neo4j and Postgres backup, with the services stopped
  docker compose stop agent webapp recon-orchestrator
  python tooling/scripts/takeover_finding_rekey.py --all --apply
  docker compose start agent webapp recon-orchestrator

It needs the Neo4j driver and psycopg (DATABASE_URL); the agent image has both.
Inside a container `localhost` is not the stack, so point the services check at
it, or `--apply` cannot see them running:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL -e AGENT_URL=http://agent:8080 -e WEBAPP_API_URL=http://webapp:3000 \\
    -e RECON_ORCHESTRATOR_URL=http://recon-orchestrator:8010 \\
    --entrypoint python redamon-agent tooling/scripts/takeover_finding_rekey.py --all

Idempotent: a second run finds nothing to re-key. Run it again after a project
import or a scan-version restore brings the old ids back.
"""
from __future__ import annotations

import argparse
import json
import os
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


def _load_takeover_helpers():
    """recon's takeover tables, loaded by path: importing the recon.helpers
    package would pull in the scan dependencies this script does not need."""
    import importlib.util
    path = REPO_ROOT / "recon" / "helpers" / "takeover_helpers.py"
    spec = importlib.util.spec_from_file_location("_rekey_takeover_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


th = _load_takeover_helpers()

S3 = "aws-s3"
AWS = "aws"
GENERIC_DETECTIONS = ("dangling-cname", "dns-saas")

PROJECTS = """
    SELECT id, user_id
      FROM projects
     {scope}
     ORDER BY created_at
"""

OLD_FINDINGS = """
MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
WHERE v.source = 'takeover_scan' AND v.takeover_provider IN $providers
RETURN v.id AS id, v.hostname AS hostname, v.takeover_provider AS provider,
       v.takeover_method AS method, v.cname_target AS cname_target,
       v.cert_provider AS cert_provider, v.cert_issuer AS cert_issuer,
       v.cert_subject_cn AS cert_subject_cn, v.tool_raw AS tool_raw
ORDER BY id
"""

_NORMALIZERS = {
    "subjack": th.normalize_subjack_result,
    "nuclei_takeover": th.normalize_nuclei_takeover,
    "baddns": th.normalize_baddns_finding,
}


def new_cert_provider(row) -> str | None:
    """The certificate's provider as the writer names it now. Only the Amazon
    issuer changed (`aws-s3` -> `aws`); a certificate whose subject names an
    S3 endpoint is S3's own and was named by it, not by the issuer."""
    stored = row.get("cert_provider")
    if stored != S3 or th.provider_from_cname(row.get("cert_subject_cn")):
        return stored
    return AWS if th.provider_from_cert(row.get("cert_issuer"), []) == AWS else stored


def tool_providers(tool_raw) -> list[str] | None:
    """The provider each tool named before the CNAME and certificate checks,
    from the stored raw rows; None when they cannot be read."""
    try:
        raw_by_source = json.loads(tool_raw) if tool_raw else None
    except (TypeError, ValueError):
        return None
    if not isinstance(raw_by_source, dict) or not raw_by_source:
        return None
    out = []
    for source, raw in raw_by_source.items():
        normalize = _NORMALIZERS.get(source)
        try:
            norm = normalize(raw) if normalize else None
        except Exception:  # noqa: BLE001 - a row the normalizer rejects is unreadable
            norm = None
        if not norm:
            return None
        out.append((norm.get("takeover_provider") or "").lower())
    return out


def derive_provider(placeholder: str, row) -> str:
    """What the writer makes of a placeholder: the CNAME's provider, else the
    certificate's (run_subdomain_takeover, steps 3 and 3a2)."""
    return (th.provider_from_cname(row.get("cname_target"))
            or new_cert_provider(row) or placeholder)


def new_provider(row) -> tuple[str | None, str | None]:
    """(the provider today's writer derives, why the node is left alone)."""
    provider = row["provider"]
    if provider in GENERIC_DETECTIONS:
        return derive_provider(provider, row), None
    # aws-s3: a CNAME or a certificate that names S3 still names it.
    if th.provider_from_cname(row.get("cname_target")) == S3 or new_cert_provider(row) != AWS:
        return provider, None
    tools = tool_providers(row.get("tool_raw"))
    if tools is None:
        return None, "its tool_raw cannot be read, so whether a tool named S3 is unknown"
    if S3 in tools:
        return provider, None
    if not all(th.is_placeholder_provider(p) for p in tools):
        return None, "a tool named another provider, which its stored provider does not show"
    return derive_provider("unknown", row), None


def plan_project(session, project: dict) -> dict:
    """The re-keys one project needs. Reads the graph; writes nothing."""
    uid, pid = project["user_id"], project["id"]
    rekeys, unmapped = [], []
    for row in session.run(OLD_FINDINGS, uid=uid, pid=pid, providers=[S3, *GENERIC_DETECTIONS]):
        row = dict(row)
        hostname, method = row.get("hostname"), row.get("method") or "cname"
        if not hostname:
            unmapped.append({"old_id": row["id"], "reason": "it stores no hostname"})
            continue
        provider, reason = new_provider(row)
        if reason:
            unmapped.append({"old_id": row["id"], "reason": reason})
            continue
        new_id = th.finding_id(hostname, provider, method)
        if new_id == row["id"]:
            continue
        if th.finding_id(hostname, row["provider"], method) != row["id"]:
            unmapped.append({"old_id": row["id"],
                             "reason": "its stored hostname, provider and method do not explain its id"})
            continue
        rekeys.append({"old_id": row["id"], "new_id": new_id, "hostname": hostname,
                       "method": method, "old_provider": row["provider"],
                       "new_provider": provider})
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
                out(f"[takeover rekey] {pid}: {_shown(u['old_id'])}: {u['reason']}; left alone, "
                    f"a full scan that no longer writes this id prunes it")
            for r in plan["rekeys"]:
                out(f"[takeover rekey] {pid}: {_shown(r['hostname'])} ({r['method']}) "
                    f"{_shown(r['old_provider'])} -> {_shown(r['new_provider'])}  "
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
                counted = ", ".join(f"{outcomes.count(o)} {o}"
                                    for o in ("renamed", "merged", "gone") if outcomes.count(o))
                out(f"[takeover rekey] {pid}: {len(plan['rekeys'])} to re-key, "
                    f"{len(plan['unmapped'])} left alone"
                    + (f"; done: {counted}" if counted else ""))
    total = sum(len(p["rekeys"]) for p in summary.values())
    out(f"[takeover rekey] {'re-keyed' if apply else 'would re-key'} {total} finding(s) "
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
