"""graph_diff — read-only diff between two points of a project's Scan Timeline.

Agent tool. Mirrors the semantics of the webapp Recon Delta
(``webapp/src/lib/reconDelta.ts``): nodes are matched across versions by a
per-label IDENTITY KEY over natural properties — never by internal ids, which
are not stable across versions. Past versions are read from the
``scan_versions`` table (column ``snapshot`` = gzip of JSON
``{nodes, relationships}``, the export-fidelity shape ``lib/scanSnapshot.ts``
writes); the live side is captured read-only from Neo4j with the same
session-label exclusion the snapshot capture uses.

READ-ONLY by construction: the only Cypher this module carries is a
MATCH/RETURN (see LIVE_CAPTURE_CYPHER); it never issues a write operation and
never writes anything anywhere. ``tests/test_graph_diff.py`` enforces this by
scanning the module source for write-operation keywords.

The pure functions (identity keys, compute_diff, summarize) depend on the
stdlib only, so unit tests import this module without langchain / psycopg;
those imports happen lazily inside the loader and the tool factory.
"""
from __future__ import annotations

import gzip
import json
import re
from datetime import date, datetime, time as dt_time
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Semantics mirrored from the webapp (see module docstring for the sources).
# ---------------------------------------------------------------------------

# ``SESSION_LABELS`` in lib/scanSnapshot.ts: agent-run labels that are never
# part of a recon version and must not reach a diff either.
SESSION_LABELS = [
    "AttackChain", "ChainStep", "ChainFinding", "ChainDecision", "ChainFailure",
]

_MUTED_LABEL = "Muted"

# Identity properties per node label, mirrored from IDENTITY_KEYS in
# lib/reconDelta.ts. A node matches across versions when every listed property
# that is present matches.
IDENTITY_KEYS: dict[str, list[str]] = {
    "Domain": ["name"],
    "Subdomain": ["name"],
    "IP": ["address"],
    "Port": ["ip_address", "number", "protocol"],
    "Service": ["ip_address", "port_number", "name"],
    # `version` is deliberately NOT identity: a version bump is a CHANGE.
    "Technology": ["name"],
    "BaseURL": ["url"],
    "URL": ["url"],
    "Endpoint": ["url", "method", "path"],
    "Parameter": ["url", "name", "position"],
    "Vulnerability": ["template_id", "matched_at", "name"],
    "CVE": ["id"],
    "MitreData": ["cwe_id"],
    "Capec": ["capec_id"],
    "Certificate": ["cert_key", "fingerprint_sha256", "serial"],
    "Header": ["url", "name"],
    "DNSRecord": ["name", "type", "value"],
    "Email": ["address"],
    "Secret": ["value", "file"],
    "JsReconFinding": ["url", "type", "value"],
}

# Generic fallbacks when a label has no explicit identity (lib/reconDelta.ts).
FALLBACK_KEYS = ["name", "address", "url", "id", "value", "title", "domain", "subdomain"]

# Properties that change on every scan without meaning anything changed —
# mirrored from VOLATILE_PROPERTIES in lib/reconDelta.ts (plus the triage and
# mute families, matched by prefix here so the exact triage property list of
# the webapp cannot drift out from under us).
_VOLATILE_EXPLICIT = frozenset({
    "_exportId", "created_at", "createdAt", "updated_at", "updatedAt",
    "last_seen", "lastSeen", "first_seen", "firstSeen",
    "discovered_at", "discoveredAt", "timestamp",
    "scan_id", "scanId", "run_id", "runId", "recon_run_id",
    "scan_time", "scanned_at",
    "recon_coverage_at", "recon_coverage_gaps", "recon_skipped_hosts",
    "recon_nuclei_truncated", "recon_coverage_roots", "recon_coverage_run",
    "scan_timestamp", "port_scan_timestamp", "http_probe_timestamp",
    "resource_enum_timestamp", "vuln_scan_timestamp", "gvm_scan_timestamp",
    "openapi_source_status", "muted_at", "stale_since",
})
_VOLATILE_PREFIXES = ("triage_", "muted")


def functional_label(labels: list[str]) -> str:
    """Primary functional label — mirrors functionalLabel in scanSnapshot.ts."""
    for label in labels or []:
        if label != _MUTED_LABEL:
            return label
    return "Unknown"


def is_volatile(prop: str) -> bool:
    if prop in _VOLATILE_EXPLICIT:
        return True
    return prop.startswith(_VOLATILE_PREFIXES)


def _identity_props(label: str) -> list[str]:
    return IDENTITY_KEYS.get(label) or FALLBACK_KEYS


def normalize_value(value: Any) -> Any:
    """JSON-normalize a Neo4j/live value so snapshot and live compare equal."""
    if isinstance(value, (datetime, date, dt_time)):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [normalize_value(v) for v in value]
    if isinstance(value, dict):
        return {str(k): normalize_value(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def node_identity(label: str, props: dict[str, Any]) -> tuple:
    """Stable identity tuple for a node within its label (identity props only)."""
    out = []
    for key in _identity_props(label):
        if key in props:
            out.append((key, normalize_value(props[key])))
    return tuple(out)


def stable_props(props: dict[str, Any]) -> dict[str, Any]:
    """Properties minus the volatile ones, normalized for comparison."""
    return {
        k: normalize_value(v)
        for k, v in (props or {}).items()
        if not is_volatile(k)
    }


def _display_name(label: str, props: dict[str, Any]) -> str:
    for key in ("name", "address", "url", "id", "value", "title"):
        if props.get(key):
            return str(props[key])
    return label


def _index_nodes(payload: dict[str, Any]) -> dict[tuple, dict[str, Any]]:
    """Index snapshot nodes by (label, identity). Last write wins on collision
    (duplicate identities inside one version are a data issue, not a diff one)."""
    index: dict[tuple, dict[str, Any]] = {}
    for node in payload.get("nodes", []):
        labels = node.get("labels") or []
        props = node.get("properties") or {}
        label = functional_label(labels)
        index[(label, node_identity(label, props))] = {
            "props": props,
            "export_id": node.get("_exportId"),
        }
    return index


def _index_rels(payload: dict[str, Any], node_index: dict[tuple, dict[str, Any]]) -> dict[tuple, str]:
    """Index relationships by (type, identity(start), identity(end)).

    A relationship whose endpoint cannot be resolved (dangling export id in a
    hand-made fixture) falls back to the raw export ids so it still diffs."""
    by_export: dict[str, tuple] = {}
    for (label, ident), info in node_index.items():
        if info.get("export_id"):
            by_export[info["export_id"]] = (label, ident)
    out: dict[tuple, str] = {}
    for rel in payload.get("relationships", []):
        # Live-captured relationships carry precomputed endpoint identity keys
        # (they never had export ids); snapshot relationships resolve through
        # the export-id map, with the raw id as a dangling-fixture fallback.
        start = rel.get("_start_key") or by_export.get(rel.get("startExportId"), ("_", (str(rel.get("startExportId") or ""),)))
        end = rel.get("_end_key") or by_export.get(rel.get("endExportId"), ("_", (str(rel.get("endExportId") or ""),)))
        out[(rel.get("type") or "RELATED", start, end)] = rel.get("type") or "RELATED"
    return out


def compute_diff(payload_a: dict[str, Any], payload_b: dict[str, Any], max_examples: int = 3) -> dict[str, Any]:
    """Diff two snapshot payloads (a = older/"from", b = newer/"to").

    Pure function: no I/O. Returns added/removed/changed nodes grouped by
    label with counts, examples and changed field names, plus relationship
    add/remove counts by type, plus a compact summary ordered by activity.
    """
    idx_a = _index_nodes(payload_a)
    idx_b = _index_nodes(payload_b)

    added: dict[str, list] = {}
    removed: dict[str, list] = {}
    changed: dict[str, list] = {}

    for key, info_b in idx_b.items():
        label = key[0]
        if key not in idx_a:
            added.setdefault(label, []).append(_display_name(label, info_b["props"]))
            continue
        old = stable_props(idx_a[key]["props"])
        new = stable_props(info_b["props"])
        if old != new:
            fields = sorted({k for k in old.keys() | new.keys() if old.get(k) != new.get(k)})
            changed.setdefault(label, []).append({
                "identity": _display_name(label, info_b["props"]),
                "fields": fields,
            })
    for key, info_a in idx_a.items():
        if key not in idx_b:
            removed.setdefault(key[0], []).append(_display_name(key[0], info_a["props"]))

    rels_a = _index_rels(payload_a, idx_a)
    rels_b = _index_rels(payload_b, idx_b)
    rel_added: dict[str, int] = {}
    rel_removed: dict[str, int] = {}
    for key in rels_b:
        if key not in rels_a:
            rel_added[key[0]] = rel_added.get(key[0], 0) + 1
    for key in rels_a:
        if key not in rels_b:
            rel_removed[key[0]] = rel_removed.get(key[0], 0) + 1

    by_label = {}
    for label, names in added.items():
        by_label.setdefault(label, {"label": label, "added": 0, "removed": 0, "changed": 0})
        by_label[label]["added"] = len(names)
    for label, names in removed.items():
        by_label.setdefault(label, {"label": label, "added": 0, "removed": 0, "changed": 0})
        by_label[label]["removed"] = len(names)
    for label, items in changed.items():
        by_label.setdefault(label, {"label": label, "added": 0, "removed": 0, "changed": 0})
        by_label[label]["changed"] = len(items)
    for entry in by_label.values():
        entry["total"] = entry["added"] + entry["removed"] + entry["changed"]
    by_label_sorted = sorted(by_label.values(), key=lambda e: (-e["total"], e["label"]))

    def _clip(bucket: dict[str, list]) -> dict[str, dict]:
        return {
            label: {"count": len(items), "examples": items[:max_examples]}
            for label, items in sorted(bucket.items())
        }

    totals = {
        "nodes_added": sum(len(v) for v in added.values()),
        "nodes_removed": sum(len(v) for v in removed.values()),
        "nodes_changed": sum(len(v) for v in changed.values()),
        "relationships_added": sum(rel_added.values()),
        "relationships_removed": sum(rel_removed.values()),
    }
    return {
        "nodes": {"added": _clip(added), "removed": _clip(removed), "changed": _clip(changed)},
        "relationships": {"added": dict(sorted(rel_added.items())), "removed": dict(sorted(rel_removed.items()))},
        "summary": {
            "totals": totals,
            "by_label": by_label_sorted,
            "side_a": {"nodes": len(idx_a), "relationships": len(rels_a)},
            "side_b": {"nodes": len(idx_b), "relationships": len(rels_b)},
        },
    }


def one_line_summary(diff: dict[str, Any]) -> str:
    t = diff["summary"]["totals"]
    return (
        f"Graph delta: +{t['nodes_added']} new, -{t['nodes_removed']} removed, "
        f"~{t['nodes_changed']} changed nodes; relationships +{t['relationships_added']}/"
        f"-{t['relationships_removed']}."
    )


# ---------------------------------------------------------------------------
# Loading sides: ScanVersion snapshots (Postgres) and the live graph (Neo4j).
# ---------------------------------------------------------------------------

# The ONLY Cypher in this module: read-only, tenant-scoped, same session-label
# exclusion the webapp snapshot capture uses (lib/scanSnapshot.ts).
LIVE_CAPTURE_CYPHER = (
    "MATCH (n) "
    "WHERE n.user_id = $tenant_user_id AND n.project_id = $tenant_project_id "
    "AND NONE(l IN labels(n) WHERE l IN $session_labels) "
    "RETURN labels(n) AS labels, properties(n) AS props"
)

# Endpoints of in-scope relationships (both endpoints carry the tenant triple
# on entity nodes, so scoping on the start node is sufficient).
LIVE_CAPTURE_RELS_CYPHER = (
    "MATCH (a)-[r]->(b) "
    "WHERE a.user_id = $tenant_user_id AND a.project_id = $tenant_project_id "
    "AND b.user_id = $tenant_user_id AND b.project_id = $tenant_project_id "
    "AND NONE(l IN labels(a) WHERE l IN $session_labels) "
    "RETURN type(r) AS rel_type, labels(a) AS start_labels, properties(a) AS start_props, "
    "labels(b) AS end_labels, properties(b) AS end_props"
)


def capture_live_snapshot(query_fn: Callable[..., Any], user_id: str, project_id: str) -> dict[str, Any]:
    """Capture the live graph as an export-fidelity payload (read-only).

    ``query_fn(cypher, params)`` is any Neo4j query runner returning an
    iterable of mappings with the aliased columns — the agent's graph manager
    (langchain Neo4jGraph.query) and a raw driver session both fit.
    """
    params = {
        "tenant_user_id": user_id,
        "tenant_project_id": project_id,
        "session_labels": SESSION_LABELS,
    }
    nodes = []
    for record in query_fn(LIVE_CAPTURE_CYPHER, params=params):
        labels = list(record.get("labels") or [])
        props = {str(k): normalize_value(v) for k, v in (record.get("props") or {}).items()}
        nodes.append({"labels": labels, "properties": props})

    def _key(labels: list[str], props: dict[str, Any]) -> tuple:
        label = functional_label(labels)
        return (label, node_identity(label, dict(props)))

    relationships = []
    for record in query_fn(LIVE_CAPTURE_RELS_CYPHER, params=params):
        start_props = {str(k): normalize_value(v) for k, v in (record.get("start_props") or {}).items()}
        end_props = {str(k): normalize_value(v) for k, v in (record.get("end_props") or {}).items()}
        relationships.append({
            "type": record.get("rel_type") or "RELATED",
            "_start_key": _key(list(record.get("start_labels") or []), start_props),
            "_end_key": _key(list(record.get("end_labels") or []), end_props),
        })
    return {"nodes": nodes, "relationships": relationships}


def _pg_connect(dsn: Optional[str] = None):
    import os
    import psycopg

    return psycopg.connect(dsn or os.environ["DATABASE_URL"], autocommit=True)


def list_versions(project_id: str, dsn: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
    """Recent ScanVersion rows (newest first) for a project."""
    with _pg_connect(dsn) as conn:
        rows = conn.execute(
            "SELECT id, seq, label, is_current, node_count, link_count, created_at "
            "FROM scan_versions WHERE project_id = %s ORDER BY seq DESC LIMIT %s",
            (project_id, limit),
        ).fetchall()
    return [
        {
            "id": r[0], "seq": r[1], "label": r[2], "is_current": bool(r[3]),
            "node_count": r[4], "link_count": r[5], "created_at": str(r[6]),
        }
        for r in rows
    ]


def load_version_snapshot(project_id: str, version_ref: str, dsn: Optional[str] = None) -> dict[str, Any]:
    """Load a PAST version's snapshot payload by version id or seq number."""
    with _pg_connect(dsn) as conn:
        row = None
        if str(version_ref).isdigit():
            row = conn.execute(
                "SELECT id, seq, label, snapshot FROM scan_versions "
                "WHERE project_id = %s AND seq = %s",
                (project_id, int(version_ref)),
            ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT id, seq, label, snapshot FROM scan_versions "
                "WHERE project_id = %s AND id = %s",
                (project_id, str(version_ref)),
            ).fetchone()
    if row is None:
        raise LookupError(f"ScanVersion '{version_ref}' not found for this project")
    _id, seq, label, blob = row
    if blob is None:
        raise LookupError(
            f"ScanVersion {seq} ('{label}') is the live/current version and has no snapshot; "
            "use 'current' to compare against it"
        )
    payload = json.loads(gzip.decompress(bytes(blob)).decode("utf-8"))
    return {"version": {"id": _id, "seq": seq, "label": label}, "payload": payload}


# ---------------------------------------------------------------------------
# Tool factory (langchain import stays lazy so the module stays unit-testable).
# ---------------------------------------------------------------------------

def build_graph_diff_tool(manager: Optional[Any] = None, dsn: Optional[str] = None) -> Any:
    """Build the ``graph_diff`` agent tool.

    ``manager`` may carry a ``graph`` with a ``query`` (the orchestrator's
    Neo4j manager shape); when it does not, the live side opens its own
    read-only connection from NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD at call
    time — the same env-based setup the graph manager itself uses.
    """
    from langchain_core.tools import tool

    shared_query_fn = getattr(getattr(manager, "graph", None), "query", None)

    def _env_query_fn():
        import os

        from langchain_neo4j import Neo4jGraph

        graph = Neo4jGraph(
            url=os.environ["NEO4J_URI"],
            username=os.environ.get("NEO4J_USER", "neo4j"),
            password=os.environ["NEO4J_PASSWORD"],
        )
        return graph.query

    @tool
    async def graph_diff(mode: str = "last_two", from_version: str = "current",
                         to_version: str = "") -> str:
        """Compare the project graph between two Scan Timeline points.

        mode 'last_two' diffs the live graph against the most recent saved
        version; mode 'versions' takes from_version/to_version, each a version
        id, a seq number, or 'current'. Read-only; returns JSON grouped by
        label with counts, examples and a one-line summary.
        """
        from agent_context import current_user_id, current_project_id
        try:
            user_id = current_user_id.get()
            project_id = current_project_id.get()
            if not user_id or not project_id:
                return json.dumps({"error": "graph_diff requires an active session context"})

            query_fn = shared_query_fn
            if query_fn is None:
                try:
                    query_fn = _env_query_fn()
                except Exception:
                    query_fn = None

            def side(spec: str) -> tuple[dict[str, Any], str]:
                if spec == "current":
                    if query_fn is None:
                        raise RuntimeError("live graph unavailable (no Neo4j session); compare two saved versions instead")
                    return capture_live_snapshot(query_fn, user_id, project_id), "current (live)"
                loaded = load_version_snapshot(project_id, spec, dsn=dsn)
                v = loaded["version"]
                return loaded["payload"], f"v{v['seq']} ({v['label']})"

            if mode == "last_two":
                versions = list_versions(project_id, dsn=dsn, limit=5)
                past = next((v for v in versions if not v["is_current"]), None)
                if past is None:
                    return json.dumps({
                        "error": "no saved scan version yet — nothing to diff against; "
                                 "use mode 'versions' once a snapshot exists",
                        "versions": versions,
                    })
                payload_a, name_a = side(str(past["seq"]))
                payload_b, name_b = side("current")
            elif mode == "versions":
                if not to_version:
                    return json.dumps({"error": "mode 'versions' needs from_version and to_version"})
                payload_a, name_a = side(from_version)
                payload_b, name_b = side(to_version)
            else:
                return json.dumps({"error": f"unknown mode '{mode}' (use 'last_two' or 'versions')"})

            diff = compute_diff(payload_a, payload_b)
            diff["compared"] = {"from": name_a, "to": name_b}
            diff["summary_line"] = one_line_summary(diff)
            return json.dumps(diff)
        except LookupError as exc:
            return json.dumps({"error": str(exc)})
        except Exception as exc:  # surface a readable error, never crash the step
            return json.dumps({"error": f"graph_diff failed: {exc}"})

    return graph_diff
