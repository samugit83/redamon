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


# --- IP mode (D-21): a replay or browser send goes only to the target IPs -----
# The shared capture proxy holds no project and is bypassed when unreachable,
# so the agent's prepare step checks the origin host: every address it
# resolves to now must be a target IP after the RoE; an IP literal must be one.

TARGETS = ["203.0.113.0/24", "2001:db8::/120", "198.51.100.7"]


def _ip_project(**kw):
    project = {"ipMode": True, "targetIps": list(TARGETS), "authProfile": None}
    project.update(kw)
    return project


def _patches(api, host, project, answer):
    # A read failure in one case must not decide the next case's read.
    api._PROJECT_READ_RETRY_AT.clear()
    resolve = mock.AsyncMock(return_value=list(answer or []))
    fetch = (mock.AsyncMock(side_effect=project) if isinstance(project, BaseException)
             else mock.AsyncMock(return_value=project))
    return resolve, (mock.patch("traffic_tools.fetch_transaction", new=mock.AsyncMock(return_value=_txn(host=host))),
                     mock.patch.object(api, "_cached_project", new=fetch),
                     mock.patch.object(api, "_resolve_origin_host", new=resolve))


def _replay(host, project, answer=None):
    import api
    api._TRAFFIC_REPLAY_SENDS.clear()
    resolve, (p1, p2, p3) = _patches(api, host, project, answer)
    with p1, p2, p3:
        resp = _run(api.traffic_replay(api.TrafficReplayRequest(ctx=_tag(), op="replay", id="t1")))
    return resp, resolve


def _browse(host, project, answer=None, action="open", url=None):
    import api
    api._TRAFFIC_BROWSER_ACTIONS.clear()
    resolve, (p1, p2, p3) = _patches(api, host, project, answer)
    with p1, p2, p3:
        resp = _run(api.traffic_browser(api.TrafficBrowserRequest(
            ctx=_tag(), action=action, origin_id="t1", url=url)))
    return resp, resolve


def _error(resp):
    return json.loads(resp.body)["error"]


def test_capture_replay_to_non_target_refused_in_ip_mode():
    import api
    # An origin host resolving outside the targets: refused, naming host and reason.
    resp, resolve = _replay("app.example.test", _ip_project(), ["203.0.113.10", "192.0.2.50"])
    assert resp.status_code == 403
    assert "app.example.test" in _error(resp) and "outside the project's target IPs" in _error(resp)
    resolve.assert_awaited_once_with("app.example.test")
    assert api._TRAFFIC_REPLAY_SENDS == {}  # a refusal spends no budget

    # An IP-literal origin outside the targets: refused without a lookup.
    resp, resolve = _replay("192.0.2.50", _ip_project())
    assert resp.status_code == 403 and "192.0.2.50" in _error(resp)
    resolve.assert_not_awaited()

    # CIDR and IPv6 targets are admitted, by name and by literal.
    for host, answer in (("app.example.test", ["203.0.113.10", "2001:db8::5"]),
                         ("203.0.113.10", None), ("2001:db8::5", None), ("[2001:DB8::5]", None),
                         ("198.51.100.7", None)):
        resp, _ = _replay(host, _ip_project(), answer)
        assert resp.status_code == 200, host
        assert json.loads(resp.body)["sends"], host

    # A domain-mode project is unchanged: no lookup, no refusal.
    resp, resolve = _replay("elsewhere.test", {"ipMode": False, "targetDomain": "example.test"})
    assert resp.status_code == 200
    resolve.assert_not_awaited()


def test_ip_mode_replay_refuses_what_the_rule_refuses():
    # No answer now; an answer holding a never-scannable address even when listed;
    # the network and broadcast address of a range no scanner ever sent to.
    for host, answer, project in (
            ("gone.example.test", [], _ip_project()),
            ("lo.example.test", ["127.0.0.1"], _ip_project(targetIps=["127.0.0.1"])),
            ("203.0.113.255", None, _ip_project()),
    ):
        resp, _ = _replay(host, project, answer)
        assert resp.status_code == 403, host


def test_an_ip_mode_origin_without_a_host_or_a_lookup_is_refused():
    import api
    # A failed lookup is no answer, not a pass.
    with mock.patch.object(api, "_cached_project", new=mock.AsyncMock(return_value=_ip_project())), \
         mock.patch.object(api, "_resolve_origin_host", new=mock.AsyncMock(side_effect=OSError("no resolver"))):
        refusal = _run(api._ip_mode_send_refusal("p1", "app.example.test"))
        assert refusal and "resolves to no address now" in refusal
        assert "has no host" in _run(api._ip_mode_send_refusal("p1", " [] "))


def test_ip_mode_replay_subtracts_the_roe():
    project = _ip_project(roeExcludedHosts=["203.0.113.128/25", "admin.example.test"])
    assert _replay("203.0.113.10", project)[0].status_code == 200
    resp, _ = _replay("203.0.113.200", project)
    assert resp.status_code == 403 and "rules of engagement" in _error(resp)
    resp, _ = _replay("app.example.test", project, ["203.0.113.10", "203.0.113.130"])
    assert resp.status_code == 403
    resp, resolve = _replay("admin.example.test", project, ["203.0.113.10"])
    assert resp.status_code == 403
    resolve.assert_not_awaited()


def test_an_unreadable_project_row_fails_closed_once_the_agent_saw_ip_mode():
    import project_settings
    project_settings._SEEN_IP_MODE.pop("p1", None)
    try:
        # Never loaded by a session in this process: the domain-mode path.
        assert _replay("elsewhere.test", RuntimeError("webapp down"))[0].status_code == 200
        project_settings._SEEN_IP_MODE["p1"] = True
        resp, _ = _replay("203.0.113.10", RuntimeError("webapp down"))
        assert resp.status_code == 403 and "could not be read" in _error(resp)
        project_settings._SEEN_IP_MODE["p1"] = False
        assert _replay("elsewhere.test", RuntimeError("webapp down"))[0].status_code == 200
    finally:
        project_settings._SEEN_IP_MODE.pop("p1", None)


def test_a_hung_webapp_costs_one_read_not_one_per_action():
    import api
    import project_settings

    async def _hung(_pid):
        await asyncio.sleep(0.2)  # stands in for the read's 10 s timeout
        raise TimeoutError("webapp hung")

    hung = mock.AsyncMock(side_effect=_hung)
    api._PROJECT_READ_RETRY_AT.clear()
    try:
        for seen, allowed in ((False, True), (True, False)):
            project_settings._SEEN_IP_MODE["p1"] = seen
            hung.reset_mock()
            api._PROJECT_READ_RETRY_AT.clear()
            with mock.patch.object(api, "_cached_project", new=hung), \
                 mock.patch.object(api, "_resolve_origin_host", new=mock.AsyncMock(return_value=[])):
                answers = [_run(api._ip_mode_send_refusal("p1", "app.example.test")) for _ in range(5)]
                assert hung.await_count == 1, seen
                # The rule is unchanged: a project last loaded in IP mode stays refused.
                assert all((a is None) is allowed for a in answers), (seen, answers)
                # Once the window has passed, the project is read again.
                api._PROJECT_READ_RETRY_AT["p1"] = 0.0
                _run(api._ip_mode_send_refusal("p1", "app.example.test"))
                assert hung.await_count == 2
    finally:
        project_settings._SEEN_IP_MODE.pop("p1", None)
        api._PROJECT_READ_RETRY_AT.clear()


def test_the_target_set_is_built_once_per_target_list():
    import api
    from recon_settings import ip_hostnames
    api._IP_MODE_TARGET_SETS.clear()
    build = mock.MagicMock(side_effect=ip_hostnames.TargetSet.from_entries)
    with mock.patch.object(ip_hostnames.TargetSet, "from_entries", new=build):
        for _ in range(3):
            assert _replay("203.0.113.10", _ip_project())[0].status_code == 200
        assert _replay("192.0.2.50", _ip_project())[0].status_code == 403
        assert build.call_count == 1
        assert _replay("198.51.100.7", _ip_project(targetIps=["198.51.100.0/24"]))[0].status_code == 200
        assert build.call_count == 2
    for n in range(api._IP_MODE_TARGET_SETS_MAX + 3):
        _run(api._ip_mode_target_set([f"10.0.{n}.1"]))
    assert len(api._IP_MODE_TARGET_SETS) == api._IP_MODE_TARGET_SETS_MAX
    api._IP_MODE_TARGET_SETS.clear()


def test_a_settings_load_records_whether_the_project_is_in_ip_mode():
    import project_settings
    from unittest.mock import MagicMock
    resp = MagicMock()
    resp.json.return_value = {"ipMode": True, "targetIps": ["203.0.113.10"]}
    with mock.patch("requests.get", return_value=resp), \
         mock.patch.dict(os.environ, {"WEBAPP_API_URL": "http://webapp:3000"}):
        project_settings.load_project_settings("p-seen-ip")
    assert project_settings.seen_project_ip_mode("p-seen-ip") is True
    assert project_settings.seen_project_ip_mode("p-never") is None


def test_ip_mode_browser_open_and_navigate_refused_off_target():
    import api
    resp, _ = _browse("app.example.test", _ip_project(), ["192.0.2.50"])
    assert resp.status_code == 403 and "app.example.test" in _error(resp)
    assert api._TRAFFIC_BROWSER_ACTIONS == {}
    resp, _ = _browse("app.example.test", _ip_project(), ["192.0.2.50"], action="navigate",
                      url="http://app.example.test/next")
    assert resp.status_code == 403
    for action in ("interact", "eval"):
        assert _browse("192.0.2.50", _ip_project(), action=action)[0].status_code == 403

    resp, _ = _browse("app.example.test", _ip_project(), ["203.0.113.10"])
    assert resp.status_code == 200 and json.loads(resp.body)["origin_host"] == "app.example.test"
    resp, resolve = _browse("elsewhere.test", {"ipMode": False})
    assert resp.status_code == 200
    resolve.assert_not_awaited()


def test_the_origin_lookup_reads_every_address_canonically():
    import api
    infos = [(10, 1, 6, "", ("2001:DB8::5", 0, 0, 0)), (2, 1, 6, "", ("203.0.113.10", 0)),
             (10, 1, 6, "", ("fe80::1%eth0", 0, 0, 2)), (2, 1, 6, "", ("203.0.113.10", 0))]

    async def _lookup():
        loop = asyncio.get_running_loop()
        with mock.patch.object(loop, "getaddrinfo", new=mock.AsyncMock(return_value=infos)):
            return await api._resolve_origin_host("app.example.test")
    assert _run(_lookup()) == ["2001:db8::5", "203.0.113.10", "fe80::1"]
