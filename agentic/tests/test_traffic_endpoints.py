"""Server-side enforcement tests for the proxy_brain broker endpoints
(/traffic/exec, /traffic/replay). Handlers are invoked directly (no client);
the DB layer is stubbed so this stays a unit-level check of the enforcement that
must live in the AGENT (a compromised kali worker cannot bypass it).

Covers strategy rows: 9 (fail-closed on missing tag), 8 (off-phase refused),
10 (fail-closed on changeme/unset key), 7 (per-session send budget), 5 (reads
scoped to the tag's tenant). Run in the redamon-agent image with the repo mount
so `import api` (and its graph_db dep) resolve.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import pytest

# The endpoints verify the tag with INTERNAL_API_KEY; set a known one for the
# whole module and sign test tags with it.
KEY = "test-internal-key-proxybrain"
os.environ["INTERNAL_API_KEY"] = KEY

from redamon_ctx import sign_tag  # noqa: E402


def _tag(user_id="u1", project_id="p1", phase="exploitation", key=None):
    return sign_tag({
        "source": "agent", "user_id": user_id, "project_id": project_id,
        "session_id": "s1", "tool": "proxy_brain", "phase": phase,
    }, key or KEY)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _txn(host="target.test", scheme="http", port=80, path="/x", query="id=1"):
    return {"host": host, "scheme": scheme, "port": port, "path": path,
            "query": query, "method": "GET", "req_headers": {}, "req_body": None}


# --- Row 9: missing/empty tag -> 401 (fail closed) -------------------------
def test_exec_missing_ctx_401():
    import api
    resp = _run(api.traffic_exec(api.TrafficExecRequest(ctx="", op="sitemap")))
    assert resp.status_code == 401


def test_replay_missing_ctx_401():
    import api
    resp = _run(api.traffic_replay(api.TrafficReplayRequest(ctx="", op="replay", id="t1")))
    assert resp.status_code == 401


# --- Row 8: active replay refused outside exploitation phases (no sends) ----
def test_replay_informational_phase_403_no_origin_read():
    import api
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn())) as ft:
        resp = _run(api.traffic_replay(api.TrafficReplayRequest(
            ctx=_tag(phase="informational"), op="replay", id="t1")))
    assert resp.status_code == 403
    ft.assert_not_called()  # gate fires before the origin is even read


# --- Row 10: auth fails closed on changeme / unset signing key --------------
def test_verify_ctx_fails_closed_on_changeme_key():
    import api
    with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "changeme"}):
        assert api._verify_traffic_ctx(_tag()) is None


def test_verify_ctx_fails_closed_on_empty_key():
    import api
    with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}):
        assert api._verify_traffic_ctx(_tag()) is None


def test_verify_ctx_rejects_foreign_key_signed_tag():
    import api
    forged = _tag(user_id="victim", project_id="victim_p", key="scanner-scoped-key")
    assert api._verify_traffic_ctx(forged) is None


# --- Row 7: per-session send budget -> 429, sends stop ----------------------
def test_replay_budget_exhausts_then_429():
    import api
    api._TRAFFIC_REPLAY_SENDS.clear()
    tag = _tag()
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn())), \
         mock.patch.dict(os.environ, {"INTERNAL_API_KEY": KEY, "TRAFFIC_REPLAY_BUDGET": "2"}):
        r1 = _run(api.traffic_replay(api.TrafficReplayRequest(ctx=tag, op="replay", id="t1")))
        r2 = _run(api.traffic_replay(api.TrafficReplayRequest(ctx=tag, op="replay", id="t1")))
        r3 = _run(api.traffic_replay(api.TrafficReplayRequest(ctx=tag, op="replay", id="t1")))
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    api._TRAFFIC_REPLAY_SENDS.clear()


# --- Row 5: reads are scoped to the TAG's tenant, never the body ------------
def test_exec_get_scopes_query_to_tag_tenant():
    import api
    import traffic_tools
    captured = {}

    async def _fake_query(sql, params):
        captured["params"] = params
        return []  # id 'X' does not belong to (u1, p1) -> not found

    with mock.patch.object(traffic_tools, "_query", new=_fake_query):
        resp = _run(api.traffic_exec(api.TrafficExecRequest(
            ctx=_tag(user_id="u1", project_id="p1"), op="get", args={"id": "X"})))
    assert resp.status_code == 200
    result = json.loads(resp.body)["result"]
    assert "Not found" in result
    # The query was bound to the tenant from the VERIFIED tag, so another
    # tenant's row can never match.
    assert captured["params"]["p"] == "p1"
    assert captured["params"]["u"] == "u1"


def test_exec_cross_tenant_id_returns_not_found():
    import api
    import traffic_tools

    async def _fake_query(sql, params):
        # Simulate the tenant-scoped SELECT: the row exists but for a DIFFERENT
        # tenant, so a query bound to (u1, p1) returns nothing.
        return [] if (params.get("p") == "p1" and params.get("u") == "u1") else [{"id": "leak"}]

    with mock.patch.object(traffic_tools, "_query", new=_fake_query):
        resp = _run(api.traffic_exec(api.TrafficExecRequest(
            ctx=_tag(user_id="u1", project_id="p1"), op="get", args={"id": "belongs_to_p2"})))
    assert "Not found" in json.loads(resp.body)["result"]
