"""
Agent-facing read/analyze tools over the captured HTTP-traffic store (plan §10.4).

These are the agent's window into the traffic corpus — the "Burp history" +
sitemap + param analysis + grep + diff + replay-prep. They are NON-MCP,
agent-side tools modeled EXACTLY on `query_graph`: object-level authz comes from
the ContextVars `current_user_id`/`current_project_id` (never from LLM args) and
is injected into every SQL `WHERE` in code, so a prompt-injected "read project X"
cannot cross tenants — the filter is applied by us, not chosen by the model.

All are read-only (SELECT), pull-based (bodies never enter context unless the
agent explicitly fetches one), and their output is wrapped as untrusted by the
executor before it reaches the LLM (§15.6). psycopg3 (already the stack's driver).
"""
from __future__ import annotations

import ast
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import psycopg
from psycopg.rows import dict_row
from langchain_core.tools import tool

from agent_context import current_user_id, current_project_id

logger = logging.getLogger(__name__)

_TABLE = "captured_http_transactions"
_MAX_ROWS = 200          # never dump more than this into the 20k-char context
_MAX_BODY_CHARS = 12000  # cap a single fetched body


def _dsn() -> str:
    return os.environ.get("DATABASE_URL", "")


def _tenant():
    return current_user_id.get(), current_project_id.get()


async def _query(sql: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    async with await psycopg.AsyncConnection.connect(_dsn(), row_factory=dict_row) as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            return await cur.fetchall()


def _summary_line(r: Dict[str, Any]) -> str:
    flags = []
    if r.get("had_auth"): flags.append("auth")
    if r.get("has_set_cookie"): flags.append("set-cookie")
    if r.get("reflected_params"): flags.append("reflected")
    if r.get("is_replay"): flags.append("replay")
    if r.get("blocked"): flags.append("BLOCKED")
    fl = f" [{','.join(flags)}]" if flags else ""
    st = r.get("status_code")
    return (f"{r['id']}  {r.get('method','?'):6} {r.get('status_code') or '---'} "
            f"{r.get('host','?')}{':'+str(r['port']) if r.get('port') not in (80,443,None) else ''}"
            f"{r.get('path','')}{r.get('query') or ''}  "
            f"{r.get('resp_body_size') or 0}b  {r.get('tool') or r.get('source') or ''}{fl}")


# --------------------------------------------------------------------------
# Shared filter parsing for proxy_search (mirrors the /traffic UI filters).
# --------------------------------------------------------------------------
_STATUS_CLASS = {"2xx": (200, 300), "3xx": (300, 400), "4xx": (400, 500), "5xx": (500, 600)}


def _build_search_where(f: Dict[str, Any], params: Dict[str, Any]) -> List[str]:
    where = ["project_id = %(p)s", "user_id = %(u)s"]
    if f.get("host"):
        where.append("host = %(host)s"); params["host"] = str(f["host"])
    if f.get("method"):
        where.append("method = %(method)s"); params["method"] = str(f["method"]).upper()
    if f.get("tool"):
        where.append("tool = %(tool)s"); params["tool"] = str(f["tool"])
    if f.get("source"):
        where.append("source = %(source)s"); params["source"] = str(f["source"])
    if f.get("sessionId"):
        where.append("session_id = %(sid)s"); params["sid"] = str(f["sessionId"])
    if f.get("runId"):
        where.append("run_id = %(rid)s"); params["rid"] = str(f["runId"])
    if f.get("status") is not None:
        where.append("status_code = %(sc)s"); params["sc"] = int(f["status"])
    cls = _STATUS_CLASS.get(str(f.get("statusClass", "")))
    if cls:
        where.append("status_code >= %(scl)s AND status_code < %(sch)s")
        params["scl"], params["sch"] = cls
    if f.get("only5xx"):
        where.append("status_code >= 500 AND status_code < 600")
    if f.get("hasAuth"):
        where.append("had_auth = true")
    if f.get("reflected"):
        where.append("reflected_params = true")
    if f.get("q"):
        where.append("(host ILIKE %(q)s OR path ILIKE %(q)s)"); params["q"] = f"%{f['q']}%"
    if f.get("bodyq"):
        where.append("resp_body ILIKE %(bq)s"); params["bq"] = f"%{f['bodyq']}%"
    return where


def _coerce_json_obj(v) -> Dict[str, Any]:
    """Accept a JSON object as EITHER a dict (langchain/LLMs frequently pass
    structured tool args directly as an object) OR a JSON string. Empty -> {}.
    Prevents the common 'passed a dict, tool wanted a JSON string' first-call
    failure. Raises ValueError/TypeError on anything else (caught by callers)."""
    if isinstance(v, dict):
        return v
    if v is None:
        return {}
    s = str(v).strip()
    if not s:
        return {}
    try:
        obj = json.loads(s)
    except (ValueError, TypeError):
        # The tool schema types this arg as `str`, so a dict the LLM passes gets
        # coerced to a Python repr ({'host': 'x'} with single quotes) that is not
        # valid JSON. literal_eval recovers that safely (objects/lists/scalars only,
        # never code execution).
        obj = ast.literal_eval(s)
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    return obj


@tool
async def proxy_search(filters: str = "") -> str:
    """Search captured HTTP traffic — the Burp-style request history. Returns
    transaction SUMMARIES only (id, method, status, host, path, size, tool, flags),
    never bodies (use proxy_get for a body). `filters` is an optional JSON object:
    {host, method, status, statusClass(2xx|3xx|4xx|5xx), tool, source(recon|agent),
    sessionId, runId, hasAuth, reflected, only5xx, q(url substring),
    bodyq(body substring), limit}."""
    u, p = _tenant()
    if not u or not p:
        return "Error: missing tenant context"
    try:
        f = _coerce_json_obj(filters)
    except (ValueError, TypeError):
        return "Error: `filters` must be a JSON object (or empty)"
    params: Dict[str, Any] = {"p": p, "u": u}
    where = _build_search_where(f, params)
    limit = max(1, min(int(f.get("limit", 100) or 100), _MAX_ROWS))
    sql = (f"SELECT id, started_at, method, host, port, path, query, status_code, "
           f"resp_body_size, tool, source, had_auth, has_set_cookie, reflected_params, "
           f"is_replay, blocked FROM {_TABLE} WHERE {' AND '.join(where)} "
           f"ORDER BY started_at DESC LIMIT {limit}")
    rows = await _query(sql, params)
    if not rows:
        return "No matching transactions."
    return f"{len(rows)} transaction(s):\n" + "\n".join(_summary_line(r) for r in rows)


@tool
async def proxy_get(id: str, part: str = "response") -> str:
    """Fetch the FULL request or response (headers + body) of ONE captured
    transaction by id. `part` = 'request' | 'response' | 'both'. This is how you
    pull a body into context on demand (bodies are never in summaries)."""
    u, p = _tenant()
    if not u or not p:
        return "Error: missing tenant context"
    rows = await _query(
        f"SELECT * FROM {_TABLE} WHERE id = %(id)s AND project_id = %(p)s AND user_id = %(u)s",
        {"id": id, "p": p, "u": u})
    if not rows:
        return "Not found (or not in your project)."
    r = rows[0]
    scheme = r.get("scheme", "http")
    url = f"{scheme}://{r.get('host')}{r.get('path','')}{r.get('query') or ''}"
    out: List[str] = [f"# {r.get('method')} {url}  -> {r.get('status_code')}"]
    part = (part or "response").lower()
    if part in ("request", "both"):
        out.append("## Request headers\n" + json.dumps(r.get("req_headers") or {}, indent=2))
        body = r.get("req_body")
        if r.get("req_body_ref") and not body:
            out.append("## Request body\n[offloaded to disk — not available agent-side]")
        elif body:
            out.append("## Request body\n" + str(body)[:_MAX_BODY_CHARS])
    if part in ("response", "both"):
        out.append("## Response headers\n" + json.dumps(r.get("resp_headers") or {}, indent=2))
        body = r.get("resp_body")
        if r.get("resp_body_ref") and not body:
            out.append("## Response body\n[offloaded to disk — not available agent-side]")
        elif body:
            out.append("## Response body\n" + str(body)[:_MAX_BODY_CHARS])
    return "\n\n".join(out)


@tool
async def proxy_sitemap() -> str:
    """Aggregated attack surface: the distinct endpoints (host + path + method)
    actually OBSERVED in captured traffic, with hit counts and the status codes
    seen. Answers 'what exists', not 'every request'."""
    u, p = _tenant()
    if not u or not p:
        return "Error: missing tenant context"
    rows = await _query(
        f"SELECT host, path, method, count(*) AS hits, "
        f"array_agg(DISTINCT status_code) AS statuses "
        f"FROM {_TABLE} WHERE project_id = %(p)s AND user_id = %(u)s "
        f"GROUP BY host, path, method ORDER BY host, path LIMIT %(lim)s",
        {"p": p, "u": u, "lim": _MAX_ROWS})
    if not rows:
        return "No captured endpoints yet."
    lines = [f"{r['method']:6} {r['host']}{r['path']}  ({r['hits']} hits, status "
             f"{sorted(s for s in r['statuses'] if s is not None)})" for r in rows]
    return f"{len(rows)} distinct endpoint(s):\n" + "\n".join(lines)


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


def _classify_value(v: str) -> str:
    if v.isdigit():
        return "sequential-id"
    if _UUID_RE.match(v):
        return "uuid"
    if _JWT_RE.match(v):
        return "jwt"
    if _B64_RE.match(v):
        return "base64"
    return "string"


@tool
async def proxy_params() -> str:
    """Distinct request PARAMETERS observed across the corpus, with sample values
    and an injectability heuristic (sequential-id / uuid / jwt / base64) — the
    leads for IDOR and injection hunting."""
    u, p = _tenant()
    if not u or not p:
        return "Error: missing tenant context"
    rows = await _query(
        f"SELECT query FROM {_TABLE} WHERE project_id = %(p)s AND user_id = %(u)s "
        f"AND query IS NOT NULL AND query <> '' LIMIT 5000",
        {"p": p, "u": u})
    from urllib.parse import parse_qsl
    params: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        for name, val in parse_qsl((r["query"] or "").lstrip("?")):
            entry = params.setdefault(name, {"samples": set(), "kinds": set()})
            if len(entry["samples"]) < 3 and val:
                entry["samples"].add(val)
            if val:
                entry["kinds"].add(_classify_value(val))
    if not params:
        return "No parameters observed."
    lines = []
    for name, e in sorted(params.items())[:_MAX_ROWS]:
        kinds = ",".join(sorted(e["kinds"])) or "empty"
        samples = ", ".join(list(e["samples"])[:3])
        lines.append(f"{name}  [{kinds}]  e.g. {samples}")
    return f"{len(params)} distinct parameter(s):\n" + "\n".join(lines)


@tool
async def proxy_grep(pattern: str, limit: int = 50) -> str:
    """Substring search across captured RESPONSE bodies (case-insensitive) — find
    reflected input, leaked secrets/keys, stack traces, hardcoded endpoints. Returns
    matching transaction summaries + a short snippet around the first match."""
    u, p = _tenant()
    if not u or not p:
        return "Error: missing tenant context"
    if not pattern:
        return "Error: empty pattern"
    lim = max(1, min(int(limit or 50), _MAX_ROWS))
    rows = await _query(
        f"SELECT id, method, host, path, status_code, resp_body FROM {_TABLE} "
        f"WHERE project_id = %(p)s AND user_id = %(u)s AND resp_body ILIKE %(pat)s "
        f"ORDER BY started_at DESC LIMIT %(lim)s",
        {"p": p, "u": u, "pat": f"%{pattern}%", "lim": lim})
    if not rows:
        return f"No response bodies contain '{pattern}'."
    out = []
    low = pattern.lower()
    for r in rows:
        body = r.get("resp_body") or ""
        i = body.lower().find(low)
        snip = body[max(0, i - 40): i + len(pattern) + 40].replace("\n", " ") if i >= 0 else ""
        out.append(f"{r['id']}  {r['method']} {r['status_code']} {r['host']}{r['path']}\n    …{snip}…")
    return f"{len(rows)} match(es) for '{pattern}':\n" + "\n".join(out)


@tool
async def proxy_diff(id_a: str, id_b: str) -> str:
    """Structural diff of two captured RESPONSES (status, length, headers, body) —
    the detection primitive for boolean-blind SQLi, IDOR, and auth-bypass (compare
    a baseline vs a variant response)."""
    u, p = _tenant()
    if not u or not p:
        return "Error: missing tenant context"
    rows = await _query(
        f"SELECT id, status_code, resp_body_size, resp_headers, resp_body FROM {_TABLE} "
        f"WHERE id = ANY(%(ids)s) AND project_id = %(p)s AND user_id = %(u)s",
        {"ids": [id_a, id_b], "p": p, "u": u})
    by_id = {r["id"]: r for r in rows}
    a, b = by_id.get(id_a), by_id.get(id_b)
    if not a or not b:
        return "One or both transactions not found (or not in your project)."
    out = [f"status:  {a['status_code']}  vs  {b['status_code']}",
           f"length:  {a['resp_body_size']}  vs  {b['resp_body_size']}  (Δ {(b['resp_body_size'] or 0) - (a['resp_body_size'] or 0)})"]
    ha, hb = a.get("resp_headers") or {}, b.get("resp_headers") or {}
    hdr_diff = sorted(set(ha) ^ set(hb))
    if hdr_diff:
        out.append("headers only-in-one: " + ", ".join(hdr_diff))
    ba, bb = (a.get("resp_body") or ""), (b.get("resp_body") or "")
    if ba == bb:
        out.append("body: IDENTICAL")
    else:
        import difflib
        diff = list(difflib.unified_diff(ba.splitlines()[:400], bb.splitlines()[:400],
                                         lineterm="", n=1))[:60]
        out.append("body diff:\n" + ("\n".join(diff) if diff else "(differs, no line-level hunks)"))
    return "\n".join(out)


def _shell_quote(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


@tool
async def proxy_to_curl(id: str) -> str:
    """Render a captured request as a reproducible `curl` command — for a PoC, a
    report, or handoff to kali_shell. Read-only (produces text; sends nothing)."""
    u, p = _tenant()
    if not u or not p:
        return "Error: missing tenant context"
    rows = await _query(
        f"SELECT method, scheme, host, port, path, query, req_headers, req_body "
        f"FROM {_TABLE} WHERE id = %(id)s AND project_id = %(p)s AND user_id = %(u)s",
        {"id": id, "p": p, "u": u})
    if not rows:
        return "Not found (or not in your project)."
    r = rows[0]
    port = r.get("port")
    hostport = f"{r['host']}:{port}" if port not in (80, 443, None) else r["host"]
    url = f"{r.get('scheme','http')}://{hostport}{r.get('path','')}{r.get('query') or ''}"
    parts = [f"curl -i -X {r.get('method','GET')}"]
    for k, v in (r.get("req_headers") or {}).items():
        val = v if isinstance(v, str) else json.dumps(v)
        parts.append(f"-H {_shell_quote(f'{k}: {val}')}")
    if r.get("req_body"):
        parts.append(f"--data-raw {_shell_quote(r['req_body'])}")
    parts.append(_shell_quote(url))
    return " \\\n  ".join(parts)


# --------------------------------------------------------------------------
# proxy_query — constrained analytical query builder (plan §10.6, option 1).
# The LLM picks from an ALLOWLIST; code assembles the SQL with a hard-forced
# tenant scope. No raw SQL string ever reaches the DB -> no injection/escape.
# --------------------------------------------------------------------------
_QUERY_COLUMNS = frozenset({
    "id", "started_at", "source", "run_id", "session_id", "tool", "phase",
    "method", "scheme", "host", "port", "path", "status_code", "resp_body_size",
    "resp_content_type", "response_time_ms", "is_tls", "is_replay",
    "had_auth", "has_set_cookie", "reflected_params", "blocked", "in_scope",
})
_AGG = frozenset({"count", "sum", "avg", "min", "max"})
_NONWORD = re.compile(r"\W")
_OPS = {"=": "=", "!=": "!=", ">": ">", ">=": ">=", "<": "<", "<=": "<=",
        "like": "ILIKE", "is_null": "IS NULL", "not_null": "IS NOT NULL"}


@tool
async def proxy_query(spec: str) -> str:
    """Ad-hoc analytical query over the traffic table — the power-user escape
    hatch for questions the shaped tools don't cover (e.g. counts/group-bys for
    IDOR/BOLA hunting). NOT raw text-to-SQL: `spec` is a JSON object built from an
    ALLOWLIST (raw SQL is NOT accepted), so you do NOT need the DB schema — use only
    the columns below. {
      select: [{col|agg:"count", col?:"id", as?:"n"}...],   // columns or aggregates
      where:  [{col, op, val}...],   // op: = != > >= < <= like is_null not_null
      group_by: [col...], order_by: [{col|as, dir:"asc|desc"}...], limit: N (<=200) }.
    Queryable COLUMNS (nothing else is allowed; bodies + tenant columns are
    deliberately NOT queryable): id, started_at, source, run_id, session_id, tool,
    phase, method, scheme, host, port, path, status_code, resp_body_size,
    resp_content_type, response_time_ms, is_tls, is_replay, had_auth,
    has_set_cookie, reflected_params, blocked, in_scope.
    Aggregations: count, sum, avg, min, max.
    Tenant scope (your project + user) is ALWAYS enforced in code."""
    u, p = _tenant()
    if not u or not p:
        return "Error: missing tenant context"
    try:
        q = _coerce_json_obj(spec)
    except (ValueError, TypeError):
        return "Error: `spec` must be a JSON object"
    params: Dict[str, Any] = {"p": p, "u": u}
    try:
        select_sql = _build_select(q.get("select"))
        where_sql = _build_where(q.get("where"), params)
        group_sql = _build_group(q.get("group_by"))
        order_sql = _build_order(q.get("order_by"))
        limit = max(1, min(int(q.get("limit", 100) or 100), _MAX_ROWS))
    except ValueError as e:
        return f"Error: {e}"
    sql = (f"SELECT {select_sql} FROM {_TABLE} "
           f"WHERE project_id = %(p)s AND user_id = %(u)s{where_sql}"
           f"{group_sql}{order_sql} LIMIT {limit}")
    try:
        rows = await _query(sql, params)
    except Exception as e:  # noqa: BLE001 — surface DB errors to the agent, not a trace
        return f"Query error: {str(e)[:200]}"
    if not rows:
        return "No results."
    keys = list(rows[0].keys())
    out = [" | ".join(keys)] + [" | ".join(str(r.get(k)) for k in keys) for r in rows[:_MAX_ROWS]]
    return "\n".join(out)


def _need_col(c: str) -> str:
    if c not in _QUERY_COLUMNS:
        raise ValueError(f"column '{c}' not allowed")
    return c


def _build_select(sel) -> str:
    if not sel:
        return "*"
    parts = []
    for i, item in enumerate(sel):
        if not isinstance(item, dict):
            raise ValueError("each select item must be an object")
        alias = item.get("as")
        safe_alias = _NONWORD.sub("", str(alias))[:32] if alias else ""
        alias_sql = f' AS "{safe_alias}"' if safe_alias else ""
        if item.get("agg"):
            agg = str(item["agg"]).lower()
            if agg not in _AGG:
                raise ValueError(f"agg '{agg}' not allowed")
            col = item.get("col")
            inner = "*" if (agg == "count" and not col) else _need_col(col)
            parts.append(f"{agg}({inner}){alias_sql}")
        else:
            parts.append(f"{_need_col(item['col'])}{alias_sql}")
    return ", ".join(parts)


def _build_where(conds, params: Dict[str, Any]) -> str:
    if not conds:
        return ""
    parts = []
    for i, c in enumerate(conds):
        if not isinstance(c, dict):
            raise ValueError("each where item must be an object")
        col = _need_col(c["col"])
        op = _OPS.get(str(c.get("op", "=")).lower())
        if not op:
            raise ValueError(f"op '{c.get('op')}' not allowed")
        if op in ("IS NULL", "IS NOT NULL"):
            parts.append(f"{col} {op}")
        else:
            key = f"w{i}"
            val = c.get("val")
            params[key] = f"%{val}%" if op == "ILIKE" else val
            parts.append(f"{col} {op} %({key})s")
    return " AND " + " AND ".join(parts)


def _build_group(cols) -> str:
    if not cols:
        return ""
    return " GROUP BY " + ", ".join(_need_col(c) for c in cols)


def _build_order(order) -> str:
    if not order:
        return ""
    parts = []
    for o in order:
        if not isinstance(o, dict):
            raise ValueError("each order item must be an object")
        # allow ordering by an allowlisted column OR a select alias (validated char set)
        col = o.get("col") or o.get("as")
        if col in _QUERY_COLUMNS:
            ref = col
        elif isinstance(col, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,31}", col):
            ref = f'"{col}"'
        else:
            raise ValueError(f"order_by '{col}' not allowed")
        d = "DESC" if str(o.get("dir", "asc")).lower() == "desc" else "ASC"
        parts.append(f"{ref} {d}")
    return " ORDER BY " + ", ".join(parts)


# --------------------------------------------------------------------------
# Active tools (proxy_replay / proxy_fuzz) — DANGEROUS: they emit live traffic.
# The @tool stubs below exist only for the LLM's schema + phase/danger gating;
# the real work is orchestrated by the executor (_run_active_proxy in tools.py),
# which reads the origin (tenant-scoped), builds the request PINNED to the
# origin's host (no Host-swap scope bypass, §15.5), signs a replay tag, and sends
# it through the worker's execute_curl -> capture proxy.
# --------------------------------------------------------------------------
import shlex  # noqa: E402
from urllib.parse import parse_qsl, urlencode, urlsplit  # noqa: E402

_FUZZ_MAX_PAYLOADS = 50


async def fetch_transaction(txn_id: str) -> Optional[Dict[str, Any]]:
    """Tenant-scoped fetch of one captured transaction (for replay/fuzz origin)."""
    u, p = _tenant()
    if not u or not p:
        return None
    rows = await _query(
        f"SELECT * FROM {_TABLE} WHERE id = %(id)s AND project_id = %(p)s AND user_id = %(u)s",
        {"id": txn_id, "p": p, "u": u})
    return rows[0] if rows else None


def _apply_header_mutations(headers: Dict[str, Any], mutate: Dict[str, Any]) -> Dict[str, str]:
    # Work case-insensitively; the target host is NEVER mutable (scope safety).
    out = {str(k): (v if isinstance(v, str) else json.dumps(v)) for k, v in (headers or {}).items()}
    drop = {str(h).lower() for h in mutate.get("dropHeaders", [])}
    if "cookie" in mutate and not mutate["cookie"]:
        drop.add("cookie")
    out = {k: v for k, v in out.items() if k.lower() not in drop and k.lower() != "host"}
    for k, v in (mutate.get("headers") or {}).items():
        # replace any existing same-name header (case-insensitive)
        out = {kk: vv for kk, vv in out.items() if kk.lower() != str(k).lower()}
        if str(k).lower() != "host":
            out[str(k)] = str(v)
    if mutate.get("cookie"):
        out = {kk: vv for kk, vv in out.items() if kk.lower() != "cookie"}
        out["Cookie"] = str(mutate["cookie"])
    return out


def _origin_url(txn: Dict[str, Any], path: str, query: str) -> str:
    scheme = txn.get("scheme", "http")
    host = txn.get("host")           # PINNED — never taken from mutate
    port = txn.get("port")
    hostport = f"{host}:{port}" if port not in (80, 443, None) else host
    # SCOPE SAFETY (host pin): the path must never re-open the URL authority. A
    # mutate path like "@evil.com/" would turn scheme://host{path} into
    # scheme://host@evil.com/ — curl reads `host` as userinfo and connects to the
    # INJECTED host, defeating the pin (and the capture proxy would forward it,
    # since the egress guard only blocks internal IPs). Forcing a rooted path
    # keeps the authority exactly `hostport`: everything after the first "/" is
    # the path and can no longer name a host.
    p = str(path if path is not None else "/")
    if not p.startswith("/"):
        p = "/" + p
    q = ("?" + query.lstrip("?")) if query else ""
    url = f"{scheme}://{hostport}{p}{q}"
    # Belt-and-braces: the built URL's authority MUST be the pinned host,
    # regardless of any current or future mutate field. Refuse rather than send
    # off-origin.
    if urlsplit(url).netloc != hostport:
        raise ValueError(f"replay host pin violated (built authority differs from pinned {hostport!r})")
    return url


def build_replay_curl(txn: Dict[str, Any], mutate: Dict[str, Any]) -> str:
    """Build a curl arg string for a replay. Host/scheme/port are pinned to the
    origin; method/path/query/params/headers/cookie/body are mutable."""
    method = str(mutate.get("method") or txn.get("method") or "GET").upper()
    path = str(mutate.get("path", txn.get("path") or "/"))
    q = str(mutate.get("query", txn.get("query") or "") or "").lstrip("?")
    if mutate.get("param"):
        pairs = dict(parse_qsl(q))
        pairs.update({str(k): str(v) for k, v in mutate["param"].items()})
        q = urlencode(pairs)
    url = _origin_url(txn, path, q)
    headers = _apply_header_mutations(txn.get("req_headers") or {}, mutate)
    body = mutate.get("body", txn.get("req_body"))
    parts = ["-s", "-i", "-X", method]
    for k, v in headers.items():
        parts += ["-H", f"{k}: {v}"]
    if body:
        parts += ["--data-raw", str(body)]
    parts.append(url)
    return " ".join(shlex.quote(x) for x in parts)


def build_fuzz_curls(txn: Dict[str, Any], insertion_point: str, payloads: List[str]):
    """Yield (payload, curl_args) for each payload substituted into the query
    param `insertion_point`. Capped at _FUZZ_MAX_PAYLOADS."""
    capped = list(payloads)[:_FUZZ_MAX_PAYLOADS]
    for pl in capped:
        args = build_replay_curl(txn, {"param": {insertion_point: pl}})
        yield str(pl), args
    return


@tool
async def proxy_replay(id: str, mutate: str = "") -> str:
    """DANGEROUS — resend a captured request with fields changed, through the
    capture proxy. `mutate` is optional JSON: {method, path, query, param:{k:v},
    headers:{k:v}, dropHeaders:[..], cookie, body}. Supports AUTH-CONTEXT SWAP
    (dropHeaders:["Cookie","Authorization"] or a new cookie) for IDOR/BOLA/priv-esc.
    The request is ALWAYS sent to the ORIGIN transaction's host (it cannot be
    pointed at a different host). Recorded as a new transaction (isReplay)."""
    return "proxy_replay is dispatched by the executor"  # intercepted; never called directly


@tool
async def proxy_fuzz(id: str, insertion_point: str, payloads: str) -> str:
    """DANGEROUS — Burp-Intruder: replay one captured request iterating a payload
    set over `insertion_point` (a query-param name). `payloads` is a JSON array of
    strings (capped). Returns a per-payload status/length summary to spot anomalies.
    Sent to the ORIGIN host only. Forbidden in stealth mode (noisy)."""
    return "proxy_fuzz is dispatched by the executor"  # intercepted; never called directly


ACTIVE_PROXY_TOOL_NAMES = frozenset({"proxy_replay", "proxy_fuzz"})


def build_traffic_active_tools() -> Dict[str, Any]:
    return {"proxy_replay": proxy_replay, "proxy_fuzz": proxy_fuzz}


# All read tools, keyed by name (registered into the executor's _all_tools).
def build_traffic_read_tools() -> Dict[str, Any]:
    return {
        "proxy_search": proxy_search,
        "proxy_get": proxy_get,
        "proxy_sitemap": proxy_sitemap,
        "proxy_params": proxy_params,
        "proxy_grep": proxy_grep,
        "proxy_diff": proxy_diff,
        "proxy_to_curl": proxy_to_curl,
        "proxy_query": proxy_query,
    }


TRAFFIC_READ_TOOL_NAMES = frozenset(build_traffic_read_tools().keys())
