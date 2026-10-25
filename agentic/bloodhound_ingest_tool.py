"""bloodhound_ingest — import BloodHound collector JSON into the project graph.

Agent tool. DANGEROUS: listed in ``DANGEROUS_TOOLS`` (human
approval per run when the confirmation gate is on) and the tool itself refuses
to run unless called with ``acknowledged=true`` — refusal leaves the graph
untouched, so a rejected approval can never half-apply an import.

Input is a workspace path (validated through ``workspace_fs._resolve_safe``,
same traversal protection as the fs_* tools) to either one collector file or a
directory of them. Supported shapes are the BloodHound 4 collector files
(bloodhound-python / SharpHound): ``*_users.json``, ``*_groups.json``,
``*_computers.json``, each ``{"data": [...], "meta": {...}}``. The ``data``
array is streamed element by element, so a several-hundred-MB SharpHound dump
never loads whole into RAM.

Records are normalised and MERGEd tenant-scoped (``graph-db-writes`` rules:
entity nodes key on the tenant triple): ``ADUser`` / ``ADGroup`` /
``ADComputer`` keyed by the collector's ``ObjectIdentifier`` (SID/GUID) plus
``user_id``/``project_id``, with ``MEMBER_OF`` (principal → group),
``HAS_MEMBER`` (group → principal) and ``HAS_SESSION`` (user → computer)
relationships. Re-running the ingest on the same files is idempotent: MERGE
on the same keys refreshes rather than duplicates.

The tool's response is a COUNTS SUMMARY ONLY (nodes/relationships by type,
records skipped as malformed) — no graph data, no credentials, in the reply.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Iterator, Optional

# ---------------------------------------------------------------------------
# Parsing: stream the collector "data" array without loading the file.
# ---------------------------------------------------------------------------

_KIND_BY_SUFFIX = [
    ("users.json", "user"),
    ("groups.json", "group"),
    ("computers.json", "computer"),
]


def classify_file(name: str) -> Optional[str]:
    lowered = name.lower()
    for suffix, kind in _KIND_BY_SUFFIX:
        if lowered.endswith(suffix):
            return kind
    return None


def iter_data_array(path: str, chunk_size: int = 1 << 20) -> Iterator[dict]:
    """Yield collector records from a file's top-level "data" array.

    Stdlib-only incremental parser: reads the file in chunks, locates the
    "data" array, then decodes one element at a time with raw_decode,
    discarding consumed bytes — peak memory stays near one chunk + record.
    """
    decoder = json.JSONDecoder()
    buf = ""
    started = False
    with open(path, encoding="utf-8", errors="replace") as fh:
        while True:
            piece = fh.read(chunk_size)
            if not piece:
                return
            buf += piece
            if not started:
                marker = buf.find('"data"')
                if marker == -1:
                    # Keep only a tail in case the marker spans chunks.
                    buf = buf[-64:]
                    continue
                bracket = buf.find("[", marker)
                if bracket == -1:
                    continue
                buf = buf[bracket + 1:]
                started = True
            while True:
                stripped = buf.lstrip(" \t\r\n,")
                if not stripped:
                    buf = ""
                    break
                if stripped[0] == "]":
                    return  # end of the data array
                try:
                    obj, end = decoder.raw_decode(stripped)
                except json.JSONDecodeError:
                    buf = stripped
                    break  # incomplete element — read more
                buf = stripped[end:]
                if isinstance(obj, dict):
                    yield obj


_OBJECT_TYPE_TO_LABEL = {
    "User": "ADUser",
    "Group": "ADGroup",
    "Computer": "ADComputer",
}

_LABEL_BY_KIND = {"user": "ADUser", "group": "ADGroup", "computer": "ADComputer"}


def normalize_record(kind: str, record: dict) -> Optional[dict]:
    """Normalize one collector record into node props, or None if malformed.

    Kept properties are flat scalars only (graph-db-writes: no maps in node
    properties). Unknown shapes return None so one malformed record never
    aborts an import — the caller counts it as skipped.
    """
    props_in = record.get("Properties") or {}
    if not isinstance(props_in, dict):
        return None
    oid = record.get("ObjectIdentifier") or props_in.get("objectsid")
    if not oid or not isinstance(oid, str):
        return None
    name = props_in.get("name") or props_in.get("samaccountname")
    if not name:
        return None
    props: dict[str, Any] = {
        "object_identifier": oid,
        "name": str(name),
        "domain": str(props_in.get("domain") or ""),
    }
    for src, dst in (
        ("samaccountname", "sam"),
        ("distinguishedname", "dn"),
        ("description", "description"),
        ("admincount", "admincount"),
        ("enabled", "enabled"),
        ("serviceprincipalnames", "spn"),
        ("operatingsystem", "os"),
        ("haslaps", "haslaps"),
    ):
        value = props_in.get(src)
        if isinstance(value, (str, bool, int, float)):
            props[dst] = value
        elif isinstance(value, list) and value and all(
            isinstance(v, (str, int, float, bool)) for v in value
        ):
            props[dst] = [str(v) for v in value]
    return props


def _edge_endpoint(raw: Any, type_hint: Optional[str] = None) -> Optional[tuple[str, str]]:
    """Resolve an edge endpoint reference to (label, object_identifier)."""
    if isinstance(raw, dict):
        oid = raw.get("ObjectIdentifier")
        label = _OBJECT_TYPE_TO_LABEL.get(raw.get("ObjectType") or type_hint or "", "")
        if oid and label:
            return (label, str(oid))
        return None
    if isinstance(raw, str) and raw:
        # Legacy plain references (DOMAIN\\user or a bare SID) key on the raw
        # value upper-cased, so repeated ingests stay idempotent on them.
        return ("ADUser", raw.upper())
    return None


def extract_edges(kind: str, record: dict) -> list[tuple[str, str, str, str, str]]:
    """Edges carried by one record: (from_label, from_oid, rel, to_label, to_oid)."""
    oid = record.get("ObjectIdentifier")
    if not oid:
        return []
    label = _LABEL_BY_KIND[kind]
    edges: list[tuple[str, str, str, str, str]] = []

    if kind in ("user", "group"):
        for member_of in record.get("MemberOf") or []:
            target = _edge_endpoint(member_of, "Group")
            if target:
                edges.append((label, str(oid), "MEMBER_OF", target[0], target[1]))

    if kind == "group":
        for member in record.get("Members") or []:
            target = _edge_endpoint(member)
            if target:
                edges.append((label, str(oid), "HAS_MEMBER", target[0], target[1]))

    if kind == "computer":
        for session in record.get("Sessions") or []:
            if isinstance(session, dict):
                user = _edge_endpoint(session.get("UserId"), "User")
                if user:
                    edges.append((user[0], user[1], "HAS_SESSION", label, str(oid)))
            elif isinstance(session, str) and session:
                edges.append(("ADUser", session.upper(), "HAS_SESSION", label, str(oid)))
    return edges


# ---------------------------------------------------------------------------
# Graph writes: batched tenant-scoped MERGE (idempotent by key).
# ---------------------------------------------------------------------------

_MERGE_NODE = (
    "UNWIND $rows AS row "
    "MERGE (n:{label} {{object_identifier: row.oid, user_id: $user_id, project_id: $project_id}}) "
    "ON CREATE SET n.source = 'bloodhound_ingest', n.updated_at = datetime() "
    "SET n += row.props "
    "SET n.updated_at = datetime()"
)

# Literal Cypher braces are {{escaped}} because the label/relationship names
# are formatted in (Cypher cannot take them as parameters); endpoints MATCH on
# their label + tenant triple, so an edge to a node that was never ingested
# simply filters out instead of attaching to the wrong node.
_MERGE_EDGE = (
    "UNWIND $rows AS row "
    "MATCH (a:{flabel} {{object_identifier: row.from_oid, user_id: $user_id, project_id: $project_id}}) "
    "MATCH (b:{tlabel} {{object_identifier: row.to_oid, user_id: $user_id, project_id: $project_id}}) "
    "MERGE (a)-[r:{rel}]->(b) "
    "ON CREATE SET r.source = 'bloodhound_ingest'"
)


def _batched(seq: list, size: int) -> Iterator[list]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def ingest_files(run_write: Callable[[str, dict], Any], user_id: str, project_id: str,
                 files: list[tuple[str, str]], batch_size: int = 500) -> dict[str, Any]:
    """Ingest classified files through ``run_write(cypher, params)``.

    Returns the counts summary; never raw records. ``run_write`` executes one
    Cypher statement with params (a neo4j session's run+consume in production,
    a recorder in tests).
    """
    counts: dict[str, int] = {"records": 0, "skipped": 0, "files": 0}
    nodes: dict[str, list[dict]] = {}
    edges: list[dict] = []

    for path, kind in files:
        counts["files"] += 1
        for record in iter_data_array(path):
            counts["records"] += 1
            props = normalize_record(kind, record)
            if props is None:
                counts["skipped"] += 1
                continue
            nodes.setdefault(_LABEL_BY_KIND[kind], []).append(
                {"oid": props.pop("object_identifier"), "props": props}
            )
            for fl, foid, rel, tl, toid in extract_edges(kind, record):
                edges.append({"from_oid": foid, "rel": rel, "to_oid": toid,
                              "from_label": fl, "to_label": tl})

    for label, rows in nodes.items():
        written = 0
        for batch in _batched(rows, batch_size):
            run_write(_MERGE_NODE.format(label=label), {
                "rows": batch, "user_id": user_id, "project_id": project_id,
            })
            written += len(batch)
        counts[f"nodes_{label}"] = written

    # Endpoints are MERGEd above, so MATCH them by label + tenant triple for
    # each (from_label, rel, to_label) combo; an edge whose endpoint was never
    # ingested filters out (counted as queued, attaching to nothing).
    by_combo: dict[tuple[str, str, str], list[dict]] = {}
    for e in edges:
        by_combo.setdefault((e["from_label"], e["rel"], e["to_label"]), []).append(e)
    for (flabel, rel, tlabel), rows in by_combo.items():
        written = 0
        for batch in _batched(rows, batch_size):
            run_write(_MERGE_EDGE.format(flabel=flabel, rel=rel, tlabel=tlabel), {
                "rows": batch, "user_id": user_id, "project_id": project_id,
            })
            written += len(batch)
        counts[f"rels_{rel}"] = counts.get(f"rels_{rel}", 0) + written
    return counts


def _resolve_workspace_path(path: str) -> str:
    from workspace_fs import _resolve_safe

    resolved = _resolve_safe(path)
    if not resolved or not resolved.exists():
        raise FileNotFoundError(f"no such workspace path: {path}")
    return str(resolved)


def collect_files(path: str) -> list[tuple[str, str]]:
    """Expand a workspace path into (absolute path, kind) collector files."""
    resolved = _resolve_workspace_path(path)
    if os.path.isdir(resolved):
        out = []
        for entry in sorted(os.listdir(resolved)):
            kind = classify_file(entry)
            if kind:
                out.append((os.path.join(resolved, entry), kind))
        return out
    kind = classify_file(os.path.basename(resolved))
    if not kind:
        raise ValueError(
            f"{os.path.basename(resolved)} is not a BloodHound collector file "
            "(expected *_users.json / *_groups.json / *_computers.json)"
        )
    return [(resolved, kind)]


# ---------------------------------------------------------------------------
# Tool factory.
# ---------------------------------------------------------------------------

def build_bloodhound_ingest_tool() -> Any:
    from langchain_core.tools import tool

    @tool
    async def bloodhound_ingest(path: str, acknowledged: bool = False) -> str:
        """Import BloodHound collector JSON (users/groups/computers) into the
        project graph as AD nodes.

        Dangerous: requires acknowledged=true and per-run approval. Only run
        when the graph already holds a valid domain credential for the target
        domain (check with query_graph first). Takes a workspace path to one
        collector file or a directory of them; returns a counts summary only.
        """
        import json as _json

        from agent_context import current_user_id, current_project_id

        if not acknowledged:
            return _json.dumps({
                "error": "bloodhound_ingest is a dangerous tool: pass acknowledged=true "
                         "to confirm this import run (approval is also required when the "
                         "tool-confirmation gate is enabled)",
            })
        try:
            user_id = current_user_id.get()
            project_id = current_project_id.get()
            if not user_id or not project_id:
                return _json.dumps({"error": "bloodhound_ingest requires an active session context"})

            files = collect_files(path)
            if not files:
                return _json.dumps({"error": f"no collector files found at {path}"})

            from neo4j import GraphDatabase

            driver = GraphDatabase.driver(
                os.environ["NEO4J_URI"],
                auth=(os.environ.get("NEO4J_USER", "neo4j"),
                      os.environ["NEO4J_PASSWORD"]),
            )
            try:
                with driver.session() as session:
                    def run_write(cypher: str, params: dict) -> None:
                        session.run(cypher, params).consume()

                    counts = ingest_files(run_write, user_id, project_id, files)
            finally:
                driver.close()
            counts["files_ingested"] = [os.path.basename(p) for p, _ in files]
            return _json.dumps(counts)
        except (FileNotFoundError, ValueError) as exc:
            return _json.dumps({"error": str(exc)})
        except Exception as exc:  # readable error, never crash the step
            return _json.dumps({"error": f"bloodhound_ingest failed: {exc}"})

    return bloodhound_ingest
