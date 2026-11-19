"""Project-data tools: a manifest and callbacks to the webapp (plan §8.9).

The agent holds no project data. Each call goes to `POST /api/internal/navigator/tools/<name>`
with the master key and the run's navigator credential; the webapp resolves the credential to
its live run and re-authorizes the person, fresh, on every call. Every id the call acts on comes
from that run, never from this request.

Never raises into the graph: a transport error, a 4xx or a 5xx becomes a short tool result the
model can read, `{"ok": false, "code", "message"}`.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Optional

import httpx

from navigator.limits import DATA_ROUTES, RUN_CYPHER_TIMEOUT_S, TOOL_TIMEOUT_S
from navigator.tooling import NavTool, ToolOutcome, as_json

logger = logging.getLogger(__name__)

CREDENTIAL_HEADER = "X-Redamon-Navigator"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,59}$")

#: The trace line each tool shows, built here and never by the model.
SUMMARIES = {
    "graph_summary": "Read the graph summary",
    "list_findings": "Listed findings",
    "list_muted_findings": "Listed muted findings",
    "attack_surface_overview": "Read the attack-surface overview",
    "list_exploit_paths": "Listed exploit paths",
    "blast_radius": "Computed a blast radius",
    "run_cypher": "Ran a graph query",
    "recon_status": "Read the recon status",
    "scan_status": "Read the scanners' status",
    "list_scan_versions": "Listed scan versions",
    "compare_scan_versions": "Compared two scan versions",
    "recon_settings": "Read the recon settings",
    "describe_recon_settings": "Read the recon settings catalog",
    "project_activity": "Read the project activity",
    "list_remediations": "Listed remediations",
    "triage_status": "Read the triage status",
    "list_graph_views": "Listed saved graph views",
    "list_reports": "Listed reports",
    "workspace_tree": "Listed the workspace tree",
    "workspace_list": "Listed a workspace folder",
    "workspace_read": "Read a workspace file",
}


def webapp_url() -> str:
    return os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")


def _headers(credential: str) -> dict:
    return {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", ""), CREDENTIAL_HEADER: credential,
            "Content-Type": "application/json"}


def _summary(name: str, args: dict) -> str:
    base = SUMMARIES.get(name, f"Called {name}")
    if name == "workspace_read" and isinstance(args.get("path"), str):
        return f"{base}: {args['path'][:120]}"
    if name == "workspace_list" and isinstance(args.get("path"), str):
        return f"{base}: {args['path'][:120] or '/'}"
    return base


def _error(code: str, message: str, name: str, args: dict) -> ToolOutcome:
    return ToolOutcome(as_json({"ok": False, "code": code, "message": message}), False,
                       f"{_summary(name, args)} (refused: {code})", error_code=code,
                       detail=args.get("cypher") if name == "run_cypher" and isinstance(args.get("cypher"), str) else None)


async def fetch_manifest(credential: str, client: Optional[httpx.AsyncClient] = None) -> Optional[list[dict]]:
    """The tools this person may use on this project now, or None when the webapp cannot answer."""
    url = f"{webapp_url()}/api/internal/navigator/tools"
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=TOOL_TIMEOUT_S) as c:
                resp = await c.get(url, headers=_headers(credential))
        else:
            resp = await client.get(url, headers=_headers(credential))
    except httpx.HTTPError as exc:
        logger.warning("[navigator] manifest unreachable class=%s", type(exc).__name__)
        return None
    if resp.status_code != 200:
        logger.warning("[navigator] manifest refused status=%s", resp.status_code)
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    tools = body.get("tools") if isinstance(body, dict) else None
    if not isinstance(tools, list):
        return None
    out = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        name, route = t.get("name"), t.get("route")
        params = t.get("parameters")
        if not (isinstance(name, str) and _NAME_RE.match(name) and route in DATA_ROUTES and isinstance(params, dict)):
            continue
        out.append({"name": name, "route": route, "description": str(t.get("description") or "")[:4000],
                    "parameters": params})
    return out


async def call_tool(name: str, args: dict, credential: str, client: Optional[httpx.AsyncClient] = None) -> ToolOutcome:
    url = f"{webapp_url()}/api/internal/navigator/tools/{name}"
    timeout = (RUN_CYPHER_TIMEOUT_S if name == "run_cypher" else TOOL_TIMEOUT_S) + 5
    detail = args.get("cypher") if name == "run_cypher" and isinstance(args.get("cypher"), str) else None
    try:
        payload = json.dumps({"args": args})
        if client is None:
            async with httpx.AsyncClient(timeout=timeout) as c:
                resp = await c.post(url, headers=_headers(credential), content=payload)
        else:
            resp = await client.post(url, headers=_headers(credential), content=payload, timeout=timeout)
    except httpx.TimeoutException:
        return _error("tool_timeout", "The tool took too long.", name, args)
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        logger.warning("[navigator] tool unreachable tool=%s class=%s", name, type(exc).__name__)
        return _error("tool_unreachable", "The project data service could not be reached.", name, args)
    try:
        body = resp.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        return _error("tool_failed", f"The tool answered HTTP {resp.status_code}.", name, args)
    if body.get("ok") is True:
        result = body.get("result")
        return ToolOutcome(as_json(result), True, _summary(name, args), detail=detail)
    code = body.get("code") if isinstance(body.get("code"), str) else "tool_failed"
    message = body.get("message") if isinstance(body.get("message"), str) else "The tool failed."
    return _error(code[:40], message[:500], name, args)


def make_remote_tools(manifest: list[dict], credential: str) -> list[NavTool]:
    tools = []
    for entry in manifest:
        name = entry["name"]

        async def run(args: dict, _name: str = name) -> ToolOutcome:
            return await call_tool(_name, args if isinstance(args, dict) else {}, credential)

        tools.append(NavTool(name, entry["description"], entry["parameters"], entry["route"], run))
    return tools
