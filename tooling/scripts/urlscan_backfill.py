#!/usr/bin/env python3
"""Mask the urlscan values earlier releases stored in clear. DRY RUN BY DEFAULT.

WHY

New scans store every urlscan URL masked (values ``***``, path tokens
``{token}``), keep quarantined links out of every request list, and record a
visit's address as history (HISTORICALLY_RESOLVED_TO), not as current DNS. A
project that is never re-run keeps what older releases wrote: urlscan
``Endpoint.full_url`` and ``Parameter.sample_value`` with real tokens, Endpoints
for leaked reset links that a partial run would request, and ``RESOLVES_TO``
edges to addresses urlscan saw years ago, which partial recon reads as current
DNS. Every past recon JSON file keeps the raw URLs and stays downloadable.

WHAT IT DOES (once; a marker records it)

Graph, per project:
  - a urlscan ``Endpoint.full_url`` -> masked;
  - every ``Parameter.sample_value`` (only urlscan wrote it) -> removed;
  - an Endpoint only urlscan wrote, whose URL the quarantine
    (recon/helpers/url_leaks.py) holds -> DETACH DELETEd with its urlscan
    Parameters (the next scan writes it masked and quarantined); one another
    source also wrote -> ``quarantined = true``, its full_url and parameter
    values removed;
  - a ``RESOLVES_TO`` edge with neither ``record_type`` nor ``source`` (the DNS
    writers always set record_type; urlscan's old writer set nothing) ->
    ``source = 'legacy_unknown'``, so it no longer counts as current DNS;
  - an ``IP`` urlscan wrote that no relationship holds any more -> deleted.
Recon JSON files (every ``*.json`` at the top of the output folder):
  - query values masked in ``urlscan.entries[].url``, ``urlscan.urls_with_paths``,
    ``urlscan.external_domains[].url``, the aggregated external domains'
    ``redirect_*_urls``, ``resource_enum.discovered_urls`` and ``archived_urls``;
  - written atomically (a temporary file, then a rename), with NO backup copy:
    a backup would keep the tokens.

It logs counts, never a value. Run inside the recon image (it needs
recon.helpers.url_leaks; graph_db must not import recon):

  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -v "$PWD/recon/output:/data/recon-output" \\
    -e PYTHONPATH=/repo:/repo/recon -e NEO4J_URI -e NEO4J_USER -e NEO4J_PASSWORD \\
    --entrypoint python redamon-recon tooling/scripts/urlscan_backfill.py --apply

./redamon.sh update runs it once with --apply.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

GRAPH_MARKER = "urlscan-backfill-v1"
JSON_MARKER = ".urlscan_backfill_v1"
#: Written next to the JSON marker once the graph part is done, so
#: ./redamon.sh update can skip starting a container on every later update.
GRAPH_DONE_FILE = ".urlscan_backfill_graph_v1"
DEFAULT_OUTPUT = "/data/recon-output"
_BATCH = 500


def _url_leaks():
    from recon.helpers import url_leaks
    return url_leaks


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def _marker_applied(session) -> bool:
    try:
        row = session.run("MATCH (m:RedamonSchemaMigration {id: $id}) RETURN count(m) AS c",
                          id=GRAPH_MARKER).single()
        return bool(row and row["c"])
    except Exception:  # noqa: BLE001 - redoing the work is idempotent; skipping is not
        return False


def _mark_applied(session) -> None:
    session.run("MERGE (m:RedamonSchemaMigration {id: $id}) ON CREATE SET m.applied_at = datetime()",
                id=GRAPH_MARKER)


def _projects(session) -> list:
    rows = session.run(
        "MATCH (n) WHERE (n:Endpoint OR n:Subdomain OR n:IP) AND n.user_id IS NOT NULL "
        "AND n.project_id IS NOT NULL RETURN DISTINCT n.user_id AS uid, n.project_id AS pid")
    return [(r["uid"], r["pid"]) for r in rows]


def plan_endpoint(row: dict) -> tuple:
    """('delete' | 'quarantine' | 'mask' | 'keep', new_full_url) for one urlscan Endpoint."""
    ul = _url_leaks()
    full_url = row.get("full_url") or ""
    url = full_url or f"{row.get('baseurl') or ''}{row.get('path') or ''}"
    held = ul.inspect_url(url)["quarantined"] if url else False
    if not held and row.get("baseurl") and row.get("path"):
        held = ul.inspect_url(f"{row['baseurl']}{row['path']}")["quarantined"]
    others = [s for s in (row.get("sources") or []) if str(s).lower() != "urlscan"]
    if held:
        return ("quarantine" if others else "delete"), None
    if full_url:
        masked = ul.mask_url(full_url)
        if masked and masked != full_url:
            return "mask", masked
    return "keep", None


def backfill_project(session, uid: str, pid: str, *, apply: bool) -> dict:
    counts = {"endpoints_masked": 0, "endpoints_deleted": 0, "endpoints_quarantined": 0,
              "sample_values_removed": 0, "edges_marked_legacy": 0, "orphan_ips_deleted": 0}
    rows = session.run(
        "MATCH (e:Endpoint {user_id: $uid, project_id: $pid}) WHERE e.source = 'urlscan' "
        "RETURN elementId(e) AS eid, e.baseurl AS baseurl, e.path AS path, "
        "e.full_url AS full_url, e.sources AS sources", uid=uid, pid=pid)
    for row in [dict(r) for r in rows]:
        action, masked = plan_endpoint(row)
        if action == "keep":
            continue
        counts[{"mask": "endpoints_masked", "delete": "endpoints_deleted",
                "quarantine": "endpoints_quarantined"}[action]] += 1
        if not apply:
            continue
        if action == "mask":
            session.run("MATCH (e:Endpoint {user_id: $uid, project_id: $pid}) WHERE elementId(e) = $eid "
                        "SET e.full_url = $url", eid=row["eid"], url=masked, uid=uid, pid=pid)
        elif action == "delete":
            session.run("MATCH (e:Endpoint {user_id: $uid, project_id: $pid}) WHERE elementId(e) = $eid "
                        "OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter {source: 'urlscan'}) "
                        "DETACH DELETE p, e", eid=row["eid"], uid=uid, pid=pid)
        else:
            session.run("MATCH (e:Endpoint {user_id: $uid, project_id: $pid}) WHERE elementId(e) = $eid "
                        "SET e.quarantined = true, e.quarantine_reasons = ['backfill'] REMOVE e.full_url "
                        "WITH e OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter) "
                        "REMOVE p.sample_value, p.sample_values", eid=row["eid"], uid=uid, pid=pid)

    count_or_write = [
        ("sample_values_removed",
         "MATCH (p:Parameter {user_id: $uid, project_id: $pid}) WHERE p.sample_value IS NOT NULL",
         "REMOVE p.sample_value", "p"),
        ("edges_marked_legacy",
         "MATCH (:Subdomain {user_id: $uid, project_id: $pid})-[r:RESOLVES_TO]->(:IP) "
         "WHERE r.record_type IS NULL AND r.source IS NULL",
         "SET r.source = 'legacy_unknown'", "r"),
        ("orphan_ips_deleted",
         "MATCH (i:IP {user_id: $uid, project_id: $pid}) WHERE i.urlscan_enriched = true AND NOT (i)--()",
         "DELETE i", "i"),
    ]
    for key, match, write, var in count_or_write:
        if apply:
            row = session.run(f"{match} WITH {var} {write} RETURN count(*) AS n", uid=uid, pid=pid).single()
        else:
            row = session.run(f"{match} RETURN count({var}) AS n", uid=uid, pid=pid).single()
        counts[key] = int((row or {}).get("n", 0) or 0) if row is not None else 0
    return counts


def backfill_graph(driver, *, apply: bool) -> dict:
    with driver.session() as session:
        if _marker_applied(session):
            return {"skipped": "already applied"}
        totals: dict = {}
        projects = _projects(session)
        for uid, pid in projects:
            for k, v in backfill_project(session, uid, pid, apply=apply).items():
                totals[k] = totals.get(k, 0) + v
        totals["projects"] = len(projects)
        if apply:
            _mark_applied(session)
        return totals


# ---------------------------------------------------------------------------
# Recon JSON files
# ---------------------------------------------------------------------------

def _mask_list(values, mask) -> tuple:
    if not isinstance(values, list):
        return values, 0
    out, changed = [], 0
    for v in values:
        if isinstance(v, str):
            m = mask(v) or v
            changed += m != v
            out.append(m)
        else:
            out.append(v)
    return out, changed


def mask_recon_document(doc: dict) -> int:
    """Mask a recon JSON document in place; the number of values changed."""
    ul = _url_leaks()
    mask = ul.mask_url
    changed = 0
    if not isinstance(doc, dict):
        return 0
    urlscan = doc.get("urlscan")
    if isinstance(urlscan, dict):
        for entry in urlscan.get("entries") or []:
            if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                m = mask(entry["url"]) or entry["url"]
                changed += m != entry["url"]
                entry["url"] = m
        for row in urlscan.get("urls_with_paths") or []:
            if not isinstance(row, dict):
                continue
            if isinstance(row.get("full_url"), str):
                m = mask(row["full_url"]) or row["full_url"]
                changed += m != row["full_url"]
                row["full_url"] = m
            params = row.get("params")
            if isinstance(params, dict):
                for name, value in list(params.items()):
                    if value != "***":
                        params[name] = "***"
                        changed += 1
        for ed in urlscan.get("external_domains") or []:
            if isinstance(ed, dict) and isinstance(ed.get("url"), str) and ed["url"]:
                parts = ed["url"].split("/")
                origin = "/".join(parts[:3]) if len(parts) >= 3 else ed["url"]
                changed += origin != ed["url"]
                ed["url"] = origin
    for key in ("external_domains_aggregated", "external_domains"):
        for ed in doc.get(key) or []:
            if not isinstance(ed, dict):
                continue
            for field in ("redirect_from_urls", "redirect_to_urls"):
                ed[field], n = _mask_list(ed.get(field), mask)
                changed += n
    resource_enum = doc.get("resource_enum")
    if isinstance(resource_enum, dict):
        for field in ("discovered_urls", "archived_urls"):
            resource_enum[field], n = _mask_list(resource_enum.get(field), mask)
            changed += n
    return changed


def _write_atomic(path: Path, doc: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh)
        os.chmod(tmp, path.stat().st_mode & 0o777)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def backfill_json(output_dir: Path, *, apply: bool) -> dict:
    marker = output_dir / JSON_MARKER
    if marker.exists():
        return {"skipped": "already applied"}
    counts = {"files": 0, "files_changed": 0, "values_masked": 0, "files_unreadable": 0}
    for path in sorted(output_dir.glob("*.json")):
        counts["files"] += 1
        try:
            doc = json.loads(path.read_text())
        except Exception:  # noqa: BLE001 - a half-written or foreign file is left as it is
            counts["files_unreadable"] += 1
            continue
        n = mask_recon_document(doc)
        if n:
            counts["files_changed"] += 1
            counts["values_masked"] += n
            if apply:
                _write_atomic(path, doc)
    if apply:
        marker.write_text("applied\n")
    return counts


# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    parser.add_argument("--output-dir", default=os.environ.get("RECON_OUTPUT_PATH") or DEFAULT_OUTPUT)
    parser.add_argument("--skip-graph", action="store_true")
    parser.add_argument("--skip-json", action="store_true")
    args = parser.parse_args(argv)
    mode = "apply" if args.apply else "dry run"
    rc = 0
    if not args.skip_json:
        out = Path(args.output_dir)
        if out.is_dir():
            print(f"[urlscan-backfill] recon JSON ({mode}): {backfill_json(out, apply=args.apply)}")
        else:
            print(f"[urlscan-backfill] recon JSON: no output folder at {out}, skipped")
    if not args.skip_graph:
        try:
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver(
                os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "")))
            try:
                print(f"[urlscan-backfill] graph ({mode}): {backfill_graph(driver, apply=args.apply)}")
            finally:
                driver.close()
            out = Path(args.output_dir)
            if args.apply and out.is_dir():
                (out / GRAPH_DONE_FILE).write_text("applied\n")
        except Exception as e:  # noqa: BLE001 - never print a value; the class says enough
            print(f"[urlscan-backfill] graph: failed ({type(e).__name__}); run it again by hand")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
