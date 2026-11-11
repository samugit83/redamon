"""Regression: AI Surface Recon and JS Recon ignored the RoE ceiling (R-8 part B2b, D3).

Part A built one process-wide request clock (recon/helpers/request_pacer.py).
The last in-process requesters never took a slot of it:

- AI Surface Recon: the chat-shape, MCP handshake, OpenAPI and vector-DB
  probes (a pool of AI_SURFACE_RECON_MAX_WORKERS hosts), the Julius probe-pack
  engine and the MCP SDK's listing calls;
- JS Recon: the JS downloads and source-map fetches (every redirect hop goes
  through ``hop_guard.fetch_hop_by_hop``), the source map's missing-key
  control, the endpoint validation probes (a pool of up to 20), the key
  validators and the npm registry lookups.

Under a 1 rps ceiling each of them alone sent several requests a second.

Now every request they put on the wire takes a slot of that one clock first:
each redirect hop that is sent (a refused hop takes none), whoever sends it;
a 429 pushes every requester's next slot back. The MCP listing's deadline grows
by the time it waited for its slots. With no ceiling nothing waits.

Only the wire is fake: urllib3's ``HTTPConnectionPool._make_request`` for
requests, and httpx2's ``AsyncHTTPTransport.handle_async_request`` for the MCP
SDK, so each module's real request code, redirect loop and SDK client run. The
pacer's clock is frozen and a thread's sleep is recorded as the slot it was
handed, so the wire stamps every request with its slot whatever order the
threads run in. Hosts are under example.test; addresses are RFC 5737.
"""
from __future__ import annotations

import io
import json
import sys
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx2
import pytest
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.response import HTTPResponse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import probe_pack_engine as eng  # noqa: E402
from recon.helpers import request_pacer  # noqa: E402
from recon.helpers.js_recon import dependency, hop_guard, validators  # noqa: E402
from recon.helpers.js_recon import sourcemap as sm  # noqa: E402
from recon.main_recon_modules import ai_surface_recon as ai  # noqa: E402
from recon.main_recon_modules import js_recon as jr  # noqa: E402

T0 = 100.0
JS = "https://app.example.test/static/main.js"
MAP = "https://app.example.test/static/main.js.map"
MCP_URL = "https://mcp.example.test/mcp"
HTML = (404, {"Content-Type": "text/html"}, b"<html>not here</html>")
JS_OK = (200, {"Content-Type": "application/javascript"}, b"var a = 1;\n")
MAP_OK = (200, {"Content-Type": "application/json"}, json.dumps({
    "version": 3, "mappings": "AAAA", "sources": ["webpack:///./src/App.tsx"],
    "sourcesContent": ["export const App = () => null;"]}).encode())
NO_CEILING = [
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
]


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    request_pacer.reset()
    circuit_breaker.reset_registry()
    monkeypatch.setattr(dependency, "_npm_cache", {})
    yield
    request_pacer.reset()
    circuit_breaker.reset_registry()


class SlotClock:
    """A frozen clock. The pacer hands out T0, T0 + 1/C, ... and a thread sleeps
    its slot minus T0, which is kept per thread until the wire reads it."""

    def __init__(self):
        self._local = threading.local()

    def now(self) -> float:
        return T0

    def sleep(self, seconds: float) -> None:
        self._local.at = T0 + seconds

    def stamp(self) -> float:
        at = getattr(self._local, "at", T0)
        self._local.at = T0
        return at


def _mcp_answer(message):
    """A minimal streamable-HTTP MCP server: one JSON answer per JSON-RPC request."""
    method = message.get("method")
    if method == "initialize":
        result = {"protocolVersion": message["params"]["protocolVersion"],
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "fake-mcp", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "description": "Echo a string.",
                             "inputSchema": {"type": "object"}}]}
    elif method == "resources/list":
        result = {"resources": []}
    elif method == "prompts/list":
        result = {"prompts": []}
    else:
        return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "no"}}
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


class Wire:
    """Answers every request requests or the MCP SDK puts on the wire, and records it."""

    def __init__(self, clock: SlotClock):
        self.clock = clock
        self.sent: list = []
        self._lock = threading.Lock()
        self.route = lambda method, url: HTML
        self.mcp_status = None

    def _record(self, method, url):
        with self._lock:
            self.sent.append((self.clock.stamp(), method, url))

    def answer(self, pool, method, path):
        url = f"{pool.scheme}://{pool.host}{path}"
        self._record(method, url)
        status, headers, body = self.route(method, url)
        return HTTPResponse(body=io.BytesIO(body), headers=headers, status=status,
                            preload_content=False, decode_content=False,
                            request_method=method, request_url=url)

    async def answer_mcp(self, request):
        self._record(request.method, str(request.url))
        headers = {"content-type": "application/json", "mcp-session-id": "s-1"}
        if self.mcp_status is not None:
            status, self.mcp_status = self.mcp_status, None
            return httpx2.Response(status, request=request, headers={"Retry-After": "6"})
        if request.method != "POST":
            return httpx2.Response(405, request=request)
        message = json.loads(request.content or b"{}")
        if "id" not in message:
            return httpx2.Response(202, request=request, headers=headers)
        return httpx2.Response(200, request=request, headers=headers,
                               content=json.dumps(_mcp_answer(message)).encode())

    def stamps(self) -> list:
        return [stamp for stamp, _, _ in self.sent]

    def urls(self) -> list:
        return [url for _, _, url in self.sent]


@pytest.fixture
def clock():
    return SlotClock()


@pytest.fixture
def ceiling(clock, monkeypatch):
    def configure(rps):
        request_pacer.configure({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps})
        monkeypatch.setattr(request_pacer._PACER, "_clock", clock.now)
        monkeypatch.setattr(request_pacer._PACER, "_sleep", clock.sleep)
        return clock
    return configure


@pytest.fixture
def wire(clock, monkeypatch):
    w = Wire(clock)

    def _make_request(pool, conn, method, url, *args, **kwargs):
        return w.answer(pool, method, url)

    async def handle_async_request(transport, request):
        return await w.answer_mcp(request)

    monkeypatch.setattr(HTTPConnectionPool, "_make_request", _make_request)
    monkeypatch.setattr(httpx2.AsyncHTTPTransport, "handle_async_request", handle_async_request)
    return w


@pytest.fixture
def public_hosts(monkeypatch):
    """The SSRF guards resolve names; these hosts are reserved and never resolve."""
    allow = lambda *_a, **_k: True  # noqa: E731
    monkeypatch.setattr(jr, "_download_allowed", allow)
    monkeypatch.setattr(jr, "is_url_safe_to_probe", allow)
    monkeypatch.setattr(sm, "is_url_safe_to_probe", allow)


def _one_slot_each(stamps, rps):
    """Every request had a slot of its own on the one clock: T0, T0 + 1/C, ..."""
    assert stamps, "nothing was sent"
    assert sorted(stamps) == pytest.approx([T0 + k / rps for k in range(len(stamps))])


def _ai_combined(hosts=("ai1.example.test", "ai2.example.test")) -> dict:
    return {
        "domain": "example.test",
        "metadata": {"project_id": "r8b2b"},
        "http_probe": {"by_url": {f"https://{h}": {"is_ai_framework_detected": True} for h in hosts}},
        "port_scan": {"by_host": {"vdb.example.test": {"ip": "203.0.113.7", "ports": [6333]}}},
        "resource_enum": {"by_base_url": {}},
    }


def _ai_settings(**extra) -> dict:
    settings = {"AI_SURFACE_RECON_ENABLED": True, "AI_SURFACE_RECON_TIMEOUT": 2,
                "AI_SURFACE_RECON_MAX_WORKERS": 4}
    settings.update(extra)
    return settings


def _endpoints(n, host="api.example.test"):
    return [{"full_url": f"https://{host}/v1/r{i}", "method": "GET"} for i in range(n)]


def _validate(endpoints, workers=4):
    return jr._validate_extracted_endpoints(
        endpoints, {"JS_RECON_VALIDATE_ENDPOINTS": True, "JS_RECON_ENDPOINT_CONCURRENCY": workers},
        jr._ProbeScope(roots=("example.test",)))


def _probe(name, *paths):
    return eng.Probe(name=name, requests=[
        eng.ProbeRequest(path=p, match=[eng.MatchRule(type="status", value=200)]) for p in paths])


@pytest.mark.parametrize("module", [ai, eng, hop_guard, jr, sm, validators, dependency],
                         ids=["ai_surface_recon", "probe_pack_engine", "hop_guard", "js_recon",
                              "sourcemap", "validators", "dependency"])
def test_every_adopter_holds_the_one_process_clock(module):
    """Imported under another name (helpers.request_pacer) it would be a second clock."""
    assert module.request_pacer is sys.modules["recon.helpers.request_pacer"]


# ---------------------------------------------------------------------------
# AI Surface Recon
# ---------------------------------------------------------------------------

class TestAiSurface:
    def test_every_probe_of_a_run_takes_a_slot(self, ceiling, wire):
        """Chat, MCP handshake, OpenAPI, Julius and vector-DB reads, four hosts at once."""
        ceiling(4)
        out = ai.run_ai_surface_recon(_ai_combined(), settings=_ai_settings())
        assert out["ai_surface_recon"]["scan_metadata"]["hosts_analyzed"] == 2
        hosts = {u.split("/")[2] for u in wire.urls()}
        assert {"ai1.example.test", "ai2.example.test", "vdb.example.test"} <= hosts
        assert len(wire.sent) > 20
        _one_slot_each(wire.stamps(), 4)

    def test_the_julius_engine_takes_a_slot_per_request(self, ceiling, wire):
        ceiling(2)
        wire.route = lambda method, url: (200, {}, b'{"models": []}') if url.endswith("/b") else HTML
        probes = [_probe("one", "/a", "/b"), _probe("two", "/c")]
        probes[0].models = {"path": "/b", "extract": ".models[].name"}
        results = eng.run_probe_packs("https://ai.example.test", probes, timeout=2)
        assert [r.name for r in results] == ["one"]
        assert wire.urls() == ["https://ai.example.test/a", "https://ai.example.test/b",
                               "https://ai.example.test/b", "https://ai.example.test/c"]
        _one_slot_each(wire.stamps(), 2)

    def test_each_mcp_listing_request_takes_a_slot(self, ceiling, wire):
        ceiling(2)
        listing = ai._mcp_enumerate(MCP_URL, 5)
        assert listing and [t["name"] for t in listing["tools"]] == ["echo"]
        assert len(wire.sent) >= 5 and set(wire.urls()) == {MCP_URL}
        _one_slot_each(wire.stamps(), 2)

    def test_the_mcp_listing_deadline_grows_by_its_waits(self, wire):
        """A real clock: seven requests at 10 rps wait about 0.6 s, past the 0.4 s
        deadline (timeout * 4), and the listing still completes."""
        request_pacer.configure({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 10})
        sent_at = []
        answer = wire.answer_mcp

        async def timed(request):
            sent_at.append(time.monotonic())
            return await answer(request)

        wire.answer_mcp = timed
        listing = ai._mcp_enumerate(MCP_URL, 0.1)
        assert listing and listing["server_name"] == "fake-mcp"
        gaps = [b - a for a, b in zip(sent_at, sent_at[1:])]
        assert len(sent_at) >= 5 and min(gaps) >= 0.08

    def test_the_latency_baseline_never_counts_the_wait_for_a_slot(self, wire, monkeypatch):
        """The pacer's sleep moves the module's own clock: each probe after the
        first waits 0.5 s for its slot, and none of it is the endpoint's latency."""
        now = [T0]
        request_pacer.configure({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 2})
        monkeypatch.setattr(request_pacer._PACER, "_clock", lambda: now[0])
        monkeypatch.setattr(request_pacer._PACER, "_sleep",
                            lambda seconds: now.__setitem__(0, now[0] + seconds))
        monkeypatch.setattr(ai, "time", types.SimpleNamespace(monotonic=lambda: now[0]))
        cand = {"endpoints": [{"path": f"/v1/p{i}", "iface": "llm-chat"} for i in range(3)],
                "host_is_ai": False}
        out = ai._probe_chat("https://ai.example.test", cand, ai.requests.Session(), 2, True)
        assert len(wire.sent) == 3 and now[0] == pytest.approx(T0 + 1.0)
        assert out["latency_p50_ms"] == 0.0

    def test_a_429_backs_off_every_requester(self, ceiling, wire, public_hosts):
        ceiling(2)
        wire.route = lambda method, url: ((429, {"Retry-After": "5"}, b"") if "/v1/chat" in url
                                          else HTML)
        ai._probe_chat("https://ai.example.test", {"endpoints": [
            {"path": "/v1/chat/completions", "iface": "llm-chat"}], "host_is_ai": False},
            ai.requests.Session(), 2, False)
        _validate(_endpoints(1))
        assert wire.stamps() == pytest.approx([T0, T0 + 5])

    def test_an_mcp_429_backs_off_every_requester(self, ceiling, wire, public_hosts):
        ceiling(2)
        wire.mcp_status = 429
        assert ai._mcp_enumerate(MCP_URL, 5) is None
        _validate(_endpoints(1))
        assert wire.sent[0][0] == pytest.approx(T0)
        assert wire.sent[-1][2] == "https://api.example.test/v1/r0"
        assert wire.sent[-1][0] == pytest.approx(T0 + 6)


# ---------------------------------------------------------------------------
# JS Recon: downloads, source maps, endpoint validation, validators, npm
# ---------------------------------------------------------------------------

class TestJsRecon:
    def test_each_download_hop_takes_a_slot(self, ceiling, wire, public_hosts):
        ceiling(2)
        answers = iter([(302, {"Location": "/static/next.js"}, b""),
                        (301, {"Location": "https://cdn.example.test/main.js"}, b""), JS_OK])
        wire.route = lambda method, url: next(answers)
        resp = jr._safe_redirect_get(JS, timeout=5, headers={}, settings={})
        assert resp is not None and resp.status_code == 200
        assert wire.urls() == [JS, "https://app.example.test/static/next.js",
                               "https://cdn.example.test/main.js"]
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5, T0 + 1.0])

    def test_a_refused_hop_takes_no_slot(self, ceiling, wire, public_hosts):
        ceiling(2)
        wire.route = lambda method, url: ((302, {"Location": "https://blocked.example.test/x.js"}, b"")
                                          if url == JS else HTML)
        settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["blocked.example.test"]}
        assert jr._safe_redirect_get(JS, timeout=5, headers={}, settings=settings) is None
        # The next request of any module takes the slot the refused hop never used.
        _validate(_endpoints(1))
        assert wire.urls() == [JS, "https://api.example.test/v1/r0"]
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])

    def test_a_callers_own_sender_goes_through_the_slot(self, ceiling):
        clock = ceiling(2)
        stamps = []

        class Answer:
            status_code, headers = 200, {}

        def send(method, url, **kwargs):
            stamps.append(clock.stamp())
            return Answer()

        for i in range(3):
            assert hop_guard.fetch_hop_by_hop("GET", f"https://app.example.test/{i}.js", timeout=5,
                                              url_guard=lambda _u: True, send=send) is not None
        assert stamps == pytest.approx([T0, T0 + 0.5, T0 + 1.0])

    def test_a_source_map_fetch_takes_a_slot_per_request_and_hop(self, ceiling, wire, public_hosts):
        ceiling(2)
        answers = iter([(200, {}, b""), (302, {"Location": "/maps/main.js.map"}, b""), MAP_OK])
        wire.route = lambda method, url: next(answers)
        outcome = {}
        assert sm._fetch_sourcemap(MAP, timeout=5, outcome=outcome) is not None
        assert outcome["reason"] == "ok"
        assert [m for _, m, _ in wire.sent] == ["HEAD", "GET", "GET"]
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5, T0 + 1.0])

    def test_the_missing_key_control_takes_a_slot(self, ceiling, wire, public_hosts):
        ceiling(2)
        wire.route = lambda method, url: (403, {}, b"")
        assert sm._missing_key_control(MAP, 5) == "denied"
        assert sm._missing_key_control(MAP, 5) == "denied"
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])

    def test_the_endpoint_pool_holds_the_ceiling_together(self, ceiling, wire, public_hosts):
        """Hittable answers send a catch-all control too; every one takes a slot."""
        ceiling(4)
        wire.route = lambda method, url: (200, {"Content-Type": "text/html"}, b"<html>page</html>")
        endpoints = _validate(_endpoints(8), workers=8)
        assert {e["validation_status"] for e in endpoints} <= {"hittable", "catch_all"}
        assert len(wire.sent) > 8
        _one_slot_each(wire.stamps(), 4)

    def test_a_key_validation_takes_a_slot(self, ceiling, wire, monkeypatch):
        ceiling(2)
        monkeypatch.setattr(validators.time, "sleep", lambda _s: None)
        wire.route = lambda method, url: (401, {"Content-Type": "application/json"}, b"{}")
        assert validators.validate_github("ghp_" + "a" * 36)["state"] == validators.REJECTED
        assert validators.validate_gitlab("glpat-" + "b" * 20)["state"] == validators.REJECTED
        assert [u.split("/")[2] for u in wire.urls()] == ["api.github.com", "gitlab.com"]
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])

    def test_an_npm_lookup_takes_a_slot(self, ceiling, wire):
        ceiling(2)
        assert dependency._check_npm_registry("@example-internal/one", timeout=3) is False
        assert dependency._check_npm_registry("@example-internal/two", timeout=3) is False
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])

    def test_a_429_on_a_hop_backs_off_every_requester(self, ceiling, wire, public_hosts):
        ceiling(2)
        wire.route = lambda method, url: (429, {"Retry-After": "7"}, b"") if url == JS else HTML
        assert jr._safe_redirect_get(JS, timeout=5, headers={}, settings={}).status_code == 429
        ai._probe_openapi("https://ai.example.test", ai.requests.Session(), 2, False, Path("/nonexistent"))
        assert wire.stamps()[:2] == pytest.approx([T0, T0 + 7])


# ---------------------------------------------------------------------------
# The shared back-off rule (cache_scan and graphql_scan use it too)
# ---------------------------------------------------------------------------

class _Urllib3Shaped:
    """A urllib3 response: ``status``, no ``status_code``."""

    def __init__(self, status, headers):
        self.status, self.headers = status, headers


@pytest.mark.parametrize("retry_after,pushed", [
    ("5", 5.0), (None, 1.0), ("soon", 1.0), ("0", 1.0), ("-3", 1.0), ("86400", 30.0), ("inf", 30.0),
], ids=["seconds", "absent", "not_a_number", "zero", "negative", "a_day", "infinite"])
def test_a_429_pushes_the_next_slot_by_its_retry_after_within_bounds(ceiling, retry_after, pushed):
    """Retry-After is the target's to set: at least 1 s, never more than 30 s."""
    ceiling(2)
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    request_pacer.back_off_on_429(_Urllib3Shaped(429, headers))
    assert request_pacer._PACER._next == pytest.approx(T0 + pushed)


def test_an_answer_that_is_not_a_429_pushes_nothing(ceiling):
    ceiling(2)
    for answer in (_Urllib3Shaped(503, {"Retry-After": "9"}), None, object()):
        request_pacer.back_off_on_429(answer)
    assert request_pacer._PACER._next == 0.0


# ---------------------------------------------------------------------------
# One clock for both modules
# ---------------------------------------------------------------------------

def test_ai_surface_and_js_recon_requests_interleave_on_one_clock(ceiling, wire, public_hosts):
    ceiling(5)
    wire.route = lambda method, url: (MAP_OK if url.endswith(".map") else JS_OK
                                      if url.endswith(".js") else HTML)
    session = ai.requests.Session()
    jobs = [
        lambda: jr._safe_redirect_get(JS, timeout=5, headers={}, settings={}),
        lambda: sm._fetch_sourcemap(MAP, timeout=5, outcome={}),
        lambda: _validate(_endpoints(3)),
        lambda: eng.run_probe_packs("https://julius.example.test", [_probe("p", "/x", "/y")], timeout=2),
        lambda: ai._probe_openapi("https://ai.example.test", session, 2, False, Path("/nonexistent")),
        lambda: ai._mcp_enumerate(MCP_URL, 5),
    ]
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        for job in [pool.submit(j) for j in jobs]:
            job.result()
    hosts = {u.split("/")[2] for u in wire.urls()}
    assert hosts == {"app.example.test", "api.example.test", "julius.example.test",
                     "ai.example.test", "mcp.example.test"}
    _one_slot_each(wire.stamps(), 5)


# ---------------------------------------------------------------------------
# No ceiling: nothing waits, a 429 holds nobody back
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
def test_no_ceiling_never_touches_the_clock(settings, wire, public_hosts, monkeypatch):
    request_pacer.configure(settings)
    touched = []
    monkeypatch.setattr(request_pacer._PACER, "_clock", lambda: touched.append("clock") or T0)
    monkeypatch.setattr(request_pacer._PACER, "_sleep", touched.append)
    monkeypatch.setattr(validators.time, "sleep", lambda _s: None)
    wire.route = lambda method, url: (429, {"Retry-After": "9"}, b"") if "/limited" in url else HTML

    ai.run_ai_surface_recon(_ai_combined(("ai.example.test",)), settings=_ai_settings())
    assert ai._mcp_enumerate(MCP_URL, 5) is not None
    jr._safe_redirect_get("https://app.example.test/limited.js", timeout=5, headers={}, settings={})
    sm._fetch_sourcemap(MAP, timeout=5, outcome={})
    _validate(_endpoints(2))
    validators.validate_github("ghp_" + "a" * 36)
    dependency._check_npm_registry("@example-internal/one", timeout=3)

    hosts = {u.split("/")[2] for u in wire.urls()}
    assert {"ai.example.test", "mcp.example.test", "app.example.test", "api.example.test",
            "api.github.com", "registry.npmjs.org"} <= hosts
    assert touched == []
