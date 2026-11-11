#!/usr/bin/env python3
"""
redagraph — Tenant-scoped CLI for the RedAmon graph database.

Runs inside kali-sandbox. Reads REDAMON_USER_ID, REDAMON_PROJECT_ID and
REDAMON_RUN_CREDENTIAL from the environment (injected by the terminal server
when launched from the webapp Graph -> Terminal tab) and queries the graph
THROUGH THE AGENT — it holds no Neo4j credentials of its own. The credential is
the terminal connection's: the agent takes the user and project from it, not from
the request body. The agent's `/graph/exec` endpoint
enforces read-only + tenant scoping server-side, so a compromised worker
cannot write, tamper, or escape the tenant filter. Supports raw Cypher,
natural-language questions (text-to-cypher via the agent), and shorthand
commands like `ls <NodeType>`.

Output is plain (one value per line) by default so it composes with grep,
sort, uniq, wc, jq, and shell redirection.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional


def _eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def _require_tenant() -> tuple[str, str]:
    user_id = os.environ.get("REDAMON_USER_ID", "").strip()
    project_id = os.environ.get("REDAMON_PROJECT_ID", "").strip()
    if not user_id or not project_id:
        _eprint(
            "redagraph: no active project. Open the terminal via the webapp "
            "Graph -> Terminal tab so the project context is set."
        )
        sys.exit(2)
    return user_id, project_id


_EXPIRED = "redagraph: the terminal session expired: reopen the terminal."


def _credential_headers() -> Dict[str, str]:
    """The terminal's run credential, which the agent's graph routes require."""
    cred = os.environ.get("REDAMON_RUN_CREDENTIAL", "").strip()
    if not cred:
        _eprint(
            "redagraph: this shell has no graph credential. Open the terminal from the "
            "webapp Graph -> Terminal tab; a shell started any other way cannot query the graph."
        )
        sys.exit(2)
    return {"X-Redamon-Run": cred}


def _refusal(resp) -> tuple:
    """(message, code) of an agent error body: top-level, or nested under FastAPI's `detail`."""
    try:
        body = resp.json()
    except Exception:
        return resp.text, ""
    if isinstance(body, dict) and isinstance(body.get("detail"), dict):
        body = body["detail"]
    if not isinstance(body, dict):
        return resp.text, ""
    return str(body.get("error") or body.get("detail") or resp.text), str(body.get("code") or "")


def _exit_if_credential_refused(resp) -> None:
    if resp.status_code != 401:
        return
    _msg, code = _refusal(resp)
    if code == "run_credential_expired":
        _eprint(_EXPIRED)
    else:
        _eprint(f"redagraph: the agent refused this terminal's credential ({code or 'unauthorized'}): "
                "reopen the terminal.")
    sys.exit(2)


def _agent_post(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """POST a graph operation to the agent's /graph/exec endpoint and return the
    coerced records. The agent holds the Neo4j credentials and enforces read-only
    + tenant scoping; this CLI never touches the database directly."""
    import requests

    agent_url = os.environ.get("REDAMON_AGENT_URL", "http://agent:8080").rstrip("/")
    headers = _credential_headers()
    try:
        resp = requests.post(f"{agent_url}/graph/exec", json=payload, headers=headers, timeout=120)
    except requests.RequestException as e:
        _eprint(f"redagraph: cannot reach agent at {agent_url}: {e}")
        sys.exit(4)

    if resp.status_code == 200:
        return resp.json().get("records", [])
    _exit_if_credential_refused(resp)

    try:
        err = resp.json().get("error", resp.text)
    except Exception:
        err = resp.text
    if resp.status_code == 403:
        _eprint(f"redagraph: {err}")
        sys.exit(3)
    if resp.status_code == 400:
        _eprint(f"redagraph: {err}")
        sys.exit(3)
    _eprint(f"redagraph: agent returned {resp.status_code}: {err}")
    sys.exit(4)


def _to_plain(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str, ensure_ascii=False)
    return str(value)


def _coerce(v: Any) -> Any:
    """Recursively convert Neo4j driver values (Node, Relationship, Path, list)
    into JSON-serialisable primitives so output formats stay clean."""
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, list):
        return [_coerce(x) for x in v]
    if isinstance(v, tuple):
        return [_coerce(x) for x in v]
    if isinstance(v, dict):
        return {k: _coerce(x) for k, x in v.items()}
    # Neo4j Node: has `labels` and supports .items() for properties.
    labels = getattr(v, "labels", None)
    if labels is not None and hasattr(v, "items"):
        return {
            "_kind": "node",
            "labels": sorted(labels) if hasattr(labels, "__iter__") else [str(labels)],
            "properties": {k: _coerce(x) for k, x in v.items()},
        }
    # Neo4j Relationship: has `type` and supports .items().
    rel_type = getattr(v, "type", None)
    if rel_type is not None and hasattr(v, "items") and hasattr(v, "nodes"):
        return {
            "_kind": "relationship",
            "type": str(rel_type),
            "properties": {k: _coerce(x) for k, x in v.items()},
        }
    if hasattr(v, "items"):
        return {k: _coerce(x) for k, x in v.items()}
    return str(v)


def _record_to_dict(record) -> Dict[str, Any]:
    return {key: _coerce(record[key]) for key in record.keys()}


def _node_display(coerced: Any) -> Any:
    """For plain/tsv emit: render a coerced node or relationship as a compact
    `key=value key=value ...` form so all properties survive the trip to text.
    The CLI deliberately does NOT pick a single attribute — that would override
    the user's NL intent (e.g. when they asked "return all attributes").
    Use `redagraph -f json` for full structured output."""
    if isinstance(coerced, dict) and coerced.get("_kind") in ("node", "relationship"):
        props = coerced.get("properties", {})
        return " ".join(f"{k}={_to_plain(v)}" for k, v in props.items())
    return coerced


def _emit(records: List, fmt: str, out) -> None:
    if not records:
        return
    keys = list(records[0].keys())
    rows = [{k: _coerce(r[k]) for k in keys} for r in records]

    if fmt == "json":
        for row in rows:
            out.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")
        return

    if fmt == "tsv":
        out.write("\t".join(keys) + "\n")
        for row in rows:
            out.write("\t".join(_to_plain(_node_display(row[k])) for k in keys) + "\n")
        return

    # plain
    if len(keys) == 1:
        k = keys[0]
        for row in rows:
            out.write(_to_plain(_node_display(row[k])) + "\n")
    else:
        _eprint("\t".join(keys))
        for row in rows:
            out.write("\t".join(_to_plain(_node_display(row[k])) for k in keys) + "\n")


def _execute(cypher: str, user_id: str, project_id: str) -> List[Dict[str, Any]]:
    """Run a labelled, read-only Cypher query via the agent. The agent enforces
    the read-only guard, the labelled-pattern requirement, and the tenant filter
    server-side (op="cypher"), so this CLI cannot bypass them."""
    return _agent_post({
        "op": "cypher",
        "cypher": cypher,
        "user_id": user_id,
        "project_id": project_id,
    })


def cmd_whoami(args, _user_id: str, _project_id: str) -> int:
    print(f"user_id    {_user_id}")
    print(f"project_id {_project_id}")
    print(f"agent_url  {os.environ.get('REDAMON_AGENT_URL', 'http://agent:8080')}")
    return 0


def cmd_types(args, user_id: str, project_id: str) -> int:
    # Fixed, tenant-scoped query runs server-side (the agent owns the Cypher).
    records = _agent_post({"op": "types", "user_id": user_id, "project_id": project_id})
    _emit(records, args.format, sys.stdout)
    return 0


def cmd_schema(args, user_id: str, project_id: str) -> int:
    # Fixed read-only structural query runs server-side.
    records = _agent_post({"op": "schema", "user_id": user_id, "project_id": project_id})
    _emit(records, args.format, sys.stdout)
    return 0


def cmd_ls(args, user_id: str, project_id: str) -> int:
    label = args.node_type
    if not label.isidentifier():
        _eprint(f"redagraph: invalid node type {label!r}")
        return 2
    attr = args.attr
    if not attr.replace("_", "").isalnum():
        _eprint(f"redagraph: invalid attribute {attr!r}")
        return 2

    limit_clause = f" LIMIT {int(args.limit)}" if args.limit else ""
    cypher = (
        f"MATCH (n:{label}) "
        f"RETURN n.{attr} AS {attr} "
        f"ORDER BY {attr}{limit_clause}"
    )
    records = _execute(cypher, user_id, project_id)
    _emit(records, args.format, sys.stdout)
    return 0


def cmd_cypher(args, user_id: str, project_id: str) -> int:
    records = _execute(args.query, user_id, project_id)
    _emit(records, args.format, sys.stdout)
    return 0


def cmd_ask(args, user_id: str, project_id: str) -> int:
    import requests

    agent_url = os.environ.get("REDAMON_AGENT_URL", "http://agent:8080").rstrip("/")
    question = " ".join(args.question) if isinstance(args.question, list) else args.question
    # /text-to-cypher bills the credential's user, whatever the body names.
    headers = _credential_headers()
    try:
        resp = requests.post(
            f"{agent_url}/text-to-cypher",
            json={
                "question": question,
                "user_id": user_id,
                "project_id": project_id,
                # Tell the agent we want scalar values, not whole nodes — so a
                # question like "subdomain names only" yields RETURN s.name.
                "for_graph_view": False,
            },
            headers=headers,
            timeout=120,
        )
    except requests.RequestException as e:
        _eprint(f"redagraph: cannot reach agent at {agent_url}: {e}")
        return 4

    if resp.status_code != 200:
        _exit_if_credential_refused(resp)
        err, _code = _refusal(resp)
        _eprint(f"redagraph: agent returned {resp.status_code}: {err}")
        return 4

    cypher = resp.json().get("cypher", "").strip()
    if not cypher:
        _eprint("redagraph: agent returned empty Cypher")
        return 4

    if args.show:
        _eprint(f"# {cypher}")

    records = _execute(cypher, user_id, project_id)
    _emit(records, args.format, sys.stdout)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redagraph",
        description="Tenant-scoped graph CLI for RedAmon. Read-only.",
    )
    p.add_argument(
        "--format", "-f",
        choices=("plain", "json", "tsv"),
        default="plain",
        help="Output format (default: plain — one value per line for single-column results).",
    )
    p.add_argument(
        "-o", "--output",
        help="Write to FILE instead of stdout (same effect as shell '> FILE').",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("whoami", help="Print active user_id / project_id.")
    sp.set_defaults(func=cmd_whoami)

    sp = sub.add_parser("types", help="List distinct node labels present in this project.")
    sp.set_defaults(func=cmd_types)

    sp = sub.add_parser("schema", help="Dump the live Neo4j schema (labels + relationships).")
    sp.set_defaults(func=cmd_schema)

    sp = sub.add_parser("ls", help="List nodes of a given type, emitting one attribute per line.")
    sp.add_argument("node_type", help="Node label (e.g. Subdomain, Endpoint, IP).")
    sp.add_argument("-a", "--attr", default="name", help="Attribute to emit (default: name).")
    sp.add_argument("--limit", type=int, default=0, help="Max rows (0 = unlimited).")
    sp.set_defaults(func=cmd_ls)

    sp = sub.add_parser("cypher", help="Run a literal Cypher query (read-only).")
    sp.add_argument("query", help="Cypher query (tenant filter is added automatically).")
    sp.set_defaults(func=cmd_cypher)

    sp = sub.add_parser("ask", help="Natural-language question; agent generates the Cypher.")
    sp.add_argument("question", nargs="+", help="Plain-English question about the graph (no need to quote).")
    sp.add_argument("--show", action="store_true", help="Print the generated Cypher to stderr.")
    sp.set_defaults(func=cmd_ask)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    user_id, project_id = _require_tenant()

    if args.output:
        # Replace stdout with the requested file for the duration of the command.
        try:
            f = open(args.output, "w", encoding="utf-8")
        except OSError as e:
            _eprint(f"redagraph: cannot open {args.output}: {e}")
            return 2
        sys.stdout = f
        try:
            return args.func(args, user_id, project_id)
        finally:
            sys.stdout.flush()
            f.close()
    return args.func(args, user_id, project_id)


if __name__ == "__main__":
    sys.exit(main())
