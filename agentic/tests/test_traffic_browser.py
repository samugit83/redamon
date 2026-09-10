"""Server-side enforcement tests for the /traffic/browser broker endpoint (the
kali `redamon.browser` PREPARE path). Handlers are invoked directly (no client);
the DB layer is stubbed so this stays a unit-level check of the enforcement that
must live in the AGENT — a compromised kali worker cannot bypass phase, budget or
the navigation host-pin.

Mirrors test_traffic_endpoints.py: fail-closed on missing/forged tag, off-phase
refused before the origin is read, origin resolved tenant-scoped, navigation
host-pin, and the per-session action budget. Run in the redamon-agent image with
the repo mount so `import api` resolves.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

KEY = "test-internal-key-browser"
os.environ["INTERNAL_API_KEY"] = KEY

from redamon_ctx import sign_tag  # noqa: E402


def _tag(user_id="u1", project_id="p1", phase="exploitation", key=None):
    return sign_tag({
        "source": "agent", "user_id": user_id, "project_id": project_id,
        "session_id": "s1", "tool": "proxy_brain", "phase": phase,
    }, key or KEY)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _txn(host="target.test", scheme="http", port=80):
    return {"host": host, "scheme": scheme, "port": port, "path": "/x",
            "query": "", "method": "GET", "req_headers": {}, "req_body": None}


def _req(api, **kw):
    return api.TrafficBrowserRequest(**kw)


# --- fail closed: missing tag -> 401 ----------------------------------------
def test_browser_missing_ctx_401():
    import api
    resp = _run(api.traffic_browser(_req(api, ctx="", action="open", origin_id="t1")))
    assert resp.status_code == 401


def test_browser_foreign_key_tag_rejected_401():
    import api
    forged = _tag(user_id="victim", project_id="victim_p", key="scanner-scoped-key")
    resp = _run(api.traffic_browser(_req(api, ctx=forged, action="open", origin_id="t1")))
    assert resp.status_code == 401


# --- off-phase refused BEFORE the origin is read ----------------------------
def test_browser_informational_phase_403_no_origin_read():
    import api
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn())) as ft:
        resp = _run(api.traffic_browser(_req(
            api, ctx=_tag(phase="informational"), action="open", origin_id="t1")))
    assert resp.status_code == 403
    ft.assert_not_called()


# --- open: resolves origin tenant-scoped, returns pinned host + a capture tag -
def test_browser_open_returns_pinned_host_and_tag():
    import api
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn(host="pinned.test"))):
        resp = _run(api.traffic_browser(_req(api, ctx=_tag(), action="open", origin_id="t1")))
    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["origin_host"] == "pinned.test"
    # The capture tag is agent-signed for the browser lineage tool value.
    claims = api._verify_traffic_ctx(body["ctx"])
    assert claims and claims["tool"] == "proxy_brain_browser"
    assert claims["project_id"] == "p1" and claims["user_id"] == "u1"


def test_browser_open_unknown_origin_404():
    import api
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=None)):
        resp = _run(api.traffic_browser(_req(api, ctx=_tag(), action="open", origin_id="ghost")))
    assert resp.status_code == 404


def test_browser_open_is_budgeted():
    # An `open` launches a real chromium, so it must consume budget too — else a
    # loop of open()s could spawn unbounded browsers and OOM the shared container.
    import api
    api._TRAFFIC_BROWSER_ACTIONS.clear()
    tag = _tag()
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn())), \
         mock.patch.dict(os.environ, {"INTERNAL_API_KEY": KEY,
                                      "TRAFFIC_BROWSER_ACTION_BUDGET": "1"}):
        r1 = _run(api.traffic_browser(_req(api, ctx=tag, action="open", origin_id="t1")))
        r2 = _run(api.traffic_browser(_req(api, ctx=tag, action="open", origin_id="t1")))
    assert (r1.status_code, r2.status_code) == (200, 429)
    api._TRAFFIC_BROWSER_ACTIONS.clear()


# --- navigate host-pin: off-origin URL refused ------------------------------
def test_browser_navigate_off_origin_400():
    import api
    api._TRAFFIC_BROWSER_ACTIONS.clear()
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn(host="target.test"))):
        resp = _run(api.traffic_browser(_req(
            api, ctx=_tag(), action="navigate", origin_id="t1",
            url="http://evil.test/steal")))
    assert resp.status_code == 400


def test_browser_navigate_on_origin_200():
    import api
    api._TRAFFIC_BROWSER_ACTIONS.clear()
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn(host="target.test"))):
        resp = _run(api.traffic_browser(_req(
            api, ctx=_tag(), action="navigate", origin_id="t1",
            url="http://target.test/profile")))
    assert resp.status_code == 200
    assert json.loads(resp.body)["ok"] is True
    api._TRAFFIC_BROWSER_ACTIONS.clear()


def test_browser_navigate_off_port_400():
    # Same host, different port -> a different service; the pin must refuse it.
    import api
    api._TRAFFIC_BROWSER_ACTIONS.clear()
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn(host="target.test", port=80))):
        resp = _run(api.traffic_browser(_req(
            api, ctx=_tag(), action="navigate", origin_id="t1",
            url="http://target.test:8443/admin")))
    assert resp.status_code == 400


def test_browser_navigate_off_scheme_400():
    import api
    api._TRAFFIC_BROWSER_ACTIONS.clear()
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn(host="target.test", scheme="http", port=80))):
        resp = _run(api.traffic_browser(_req(
            api, ctx=_tag(), action="navigate", origin_id="t1",
            url="https://target.test/profile")))
    assert resp.status_code == 400


# --- per-session action budget -> 429 ---------------------------------------
def test_browser_action_budget_exhausts_then_429():
    import api
    api._TRAFFIC_BROWSER_ACTIONS.clear()
    tag = _tag()
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn(host="target.test"))), \
         mock.patch.dict(os.environ, {"INTERNAL_API_KEY": KEY,
                                      "TRAFFIC_BROWSER_ACTION_BUDGET": "2"}):
        r1 = _run(api.traffic_browser(_req(api, ctx=tag, action="interact", origin_id="t1")))
        r2 = _run(api.traffic_browser(_req(api, ctx=tag, action="interact", origin_id="t1")))
        r3 = _run(api.traffic_browser(_req(api, ctx=tag, action="interact", origin_id="t1")))
    assert (r1.status_code, r2.status_code, r3.status_code) == (200, 200, 429)
    api._TRAFFIC_BROWSER_ACTIONS.clear()


def test_browser_unknown_action_400():
    import api
    with mock.patch("traffic_tools.fetch_transaction",
                    new=mock.AsyncMock(return_value=_txn())):
        resp = _run(api.traffic_browser(_req(api, ctx=_tag(), action="teleport", origin_id="t1")))
    assert resp.status_code == 400
