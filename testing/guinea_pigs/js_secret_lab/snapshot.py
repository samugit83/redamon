#!/usr/bin/env python3
"""Snapshot a project's js_recon graph: every Secret (source js_recon),
JsReconFinding and js_recon Endpoint, muted nodes included, sorted.

    python3 snapshot.py <projectId> <out.json>

Read through cypher-shell inside redamon-neo4j, so the password never leaves
the container and muted nodes (which MCP query_graph hides) are included.
`matched_text`, `context` and `sample` are replaced by sha256[:12]; any other
string property holding one of the project's matched values gets that value
replaced by its hash too. `updated_at` sits in its own column, outside props,
so a diff can tell refreshed nodes from changed ones (scenario E4).
"""
import base64
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

NEO4J = "redamon-neo4j"
PID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HASHED = ("matched_text", "context", "sample")


def sha12(text):
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()[:12]


def check_pid(pid):
    if not PID.match(pid or ""):
        raise SystemExit(f"[!] not a project id: {pid!r}")
    return pid


def cypher_rows(query, pid):
    """Rows of `query`, which must RETURN one column holding
    apoc.text.base64Encode(apoc.convert.toJson(...)): base64 survives
    cypher-shell's plain output untouched, which a quoted string does not."""
    check_pid(pid)
    cmd = ["docker", "exec", "-i", NEO4J, "sh", "-c",
           'cypher-shell -u neo4j -p "${NEO4J_AUTH#neo4j/}" --format plain -P "$1"', "sh",
           f'pid => "{pid}"']
    out = subprocess.run(cmd, input=query, capture_output=True, text=True, timeout=300)
    if out.returncode != 0:
        raise SystemExit(f"[!] cypher-shell failed ({out.returncode}): {out.stderr.strip()[:400]}")
    rows = []
    for line in out.stdout.splitlines()[1:]:
        line = line.strip().strip('"')
        if line:
            rows.append(json.loads(base64.b64decode(line)))
    return rows


SNAPSHOT_QUERY = """
MATCH (n:Secret {project_id: $pid}) WHERE n.source = 'js_recon'
OPTIONAL MATCH (j:JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(n)
WITH n, collect(j.id) AS parents
RETURN apoc.text.base64Encode(apoc.convert.toJson({label: 'Secret', props: properties(n), parents: parents})) AS b
UNION ALL
MATCH (n:JsReconFinding {project_id: $pid})
RETURN apoc.text.base64Encode(apoc.convert.toJson({label: 'JsReconFinding', props: properties(n), parents: []})) AS b
UNION ALL
MATCH (n:Endpoint {project_id: $pid}) WHERE n.source = 'js_recon' OR n.js_recon_source = true
RETURN apoc.text.base64Encode(apoc.convert.toJson({label: 'Endpoint', props: properties(n), parents: []})) AS b
"""


def _scrub(value, secrets):
    if isinstance(value, str):
        for raw in secrets:
            if raw in value:
                value = value.replace(raw, f"<sha12:{sha12(raw)}>")
        return value
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    return value


def take(pid):
    rows = cypher_rows(SNAPSHOT_QUERY, pid)
    # Longest first, so a value inside a longer one is replaced inside its hash, not before it.
    secrets = sorted({r["props"].get("matched_text") for r in rows
                      if r["label"] == "Secret" and len(r["props"].get("matched_text") or "") >= 8},
                     key=len, reverse=True)
    nodes = []
    for r in rows:
        props = dict(r["props"])
        updated = props.pop("updated_at", None)
        for key in HASHED:
            if props.get(key):
                props[key] = "sha12:" + sha12(props[key])
        props = _scrub(props, secrets)
        nodes.append({"label": r["label"], "id": props.get("id"), "updated_at": updated,
                      "parents": sorted(r.get("parents") or []), "props": dict(sorted(props.items()))})
    nodes.sort(key=lambda n: (n["label"], str(n["id"])))
    counts = {}
    for n in nodes:
        counts[n["label"]] = counts.get(n["label"], 0) + 1
    return {"project_id": pid, "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "counts": counts, "nodes": nodes}


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: snapshot.py <projectId> <out.json>")
    snap = take(check_pid(sys.argv[1]))
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=1, sort_keys=False)
        fh.write("\n")
    by_method = {}
    for n in snap["nodes"]:
        if n["label"] == "Secret":
            m = n["props"].get("detection_method") or "regex"
            by_method[m] = by_method.get(m, 0) + 1
    print(f"[+] {sys.argv[2]}: {snap['counts']} (Secret by detection_method: {by_method})")


if __name__ == "__main__":
    main()
