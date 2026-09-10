"""Unit tests for the kali-side `redamon` SDK's response parser (Row 4).

`redamon._parse_curl` turns the `curl -i` output of a proxied replay into the
Response the agent's proxy_brain code reads as an oracle (.status/.headers/.body).
If it mis-reads the boundary, every replay-based finding is wrong. The SDK lives
in mcp/servers (kali PYTHONPATH); it imports only `requests` + stdlib, so it is
importable in the agent test image once mcp/servers is on the path.
"""
import os
import sys

import pytest

_MCP_SERVERS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "mcp", "servers",
)
if _MCP_SERVERS not in sys.path:
    sys.path.insert(0, _MCP_SERVERS)

import redamon  # noqa: E402


def test_parse_curl_extracts_status_headers_body():
    raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=b\r\n\r\n<html>hi</html>"
    r = redamon._parse_curl(raw, None)
    assert r.status == 200
    assert r.headers["content-type"] == "text/html"
    assert r.headers["set-cookie"] == "a=b"
    assert r.body == "<html>hi</html>"
    assert r.length == len("<html>hi</html>")


def test_parse_curl_empty_body_status_only():
    r = redamon._parse_curl("HTTP/1.1 204 No Content\r\n\r\n", None)
    assert r.status == 204
    assert r.body == ""
    assert r.length == 0


def test_parse_curl_error_output_has_no_status():
    # A curl failure (no HTTP response) must not fabricate a status.
    r = redamon._parse_curl("curl: (7) Failed to connect to host", "1001")
    assert r.status is None
    assert "Failed to connect" in r.body
    assert r.payload == "1001"


def test_parse_curl_carries_payload_label():
    r = redamon._parse_curl("HTTP/1.1 500 Server Error\r\n\r\nSQL syntax error", "1001'")
    assert r.status == 500
    assert "SQL syntax error" in r.body
    assert r.payload == "1001'"


def test_search_accepts_dict_and_kwargs():
    # The skills call redamon.search({...}) (dict); code may also use kwargs. Both
    # must reach the endpoint as endpoint-shaped (camelCase) filters.
    seen = {}
    orig = redamon._read
    redamon._read = lambda op, args=None: seen.update(args or {}) or ""
    try:
        redamon.search({"hasAuth": True, "method": "POST"})
        assert seen == {"hasAuth": True, "method": "POST"}
        seen.clear()
        redamon.search(has_auth=True, host="x")           # snake_case kwargs -> aliased
        assert seen == {"hasAuth": True, "host": "x"}
        seen.clear()
        redamon.search(**{"q": "admin"})
        assert seen == {"q": "admin"}
    finally:
        redamon._read = orig


# --- redamon.browser: client-side host-pin + fail-closed --------------------
def _bare_browser(host="target.test", scheme="http", port=80):
    """A Browser with its pin state set but WITHOUT launching chromium, so the
    pure host-pin helpers can be unit-tested off the browser."""
    b = object.__new__(redamon.Browser)
    b._host, b._scheme, b._port, b._origin_id = host, scheme, port, "t1"
    b._alerts, b._console = [], []
    return b


def test_browser_abs_builds_pinned_url_from_path():
    b = _bare_browser(host="target.test", port=8080)
    assert b._abs("/search") == "http://target.test:8080/search"
    assert b._abs("profile") == "http://target.test:8080/profile"  # rooted
    # A full URL is passed through verbatim (the SERVER re-checks its host).
    assert b._abs("http://evil.test/x") == "http://evil.test/x"


def test_browser_abs_omits_default_port():
    assert _bare_browser(port=80)._abs("/x") == "http://target.test/x"


class _FakePage:
    def __init__(self, url):
        self.url = url


class _RecPage:
    """A fake page that records goto kwargs and lets us simulate where a
    navigation/keypress landed (self.url), for the client-side pin + wait_until."""
    def __init__(self, land_url):
        self.url = land_url
        self.goto_kwargs = None

    def goto(self, url, **kw):
        self.goto_kwargs = kw
        return type("R", (), {"status": 200})()

    def press(self, selector, key, **kw):
        pass


def test_browser_assert_on_origin_dies_off_host():
    b = _bare_browser(host="target.test")
    b._page = _FakePage("http://evil.test/landed")
    with pytest.raises(SystemExit):
        b._assert_on_origin()  # off the pinned host -> fail closed


def test_browser_assert_on_origin_ok_same_host():
    b = _bare_browser(host="target.test")
    b._page = _FakePage("http://target.test/ok")
    b._assert_on_origin()  # no raise


def test_browser_assert_on_origin_dies_off_port_and_scheme():
    # Same host, different port -> off-origin (a redirect to :8443 is a new service).
    b = _bare_browser(host="target.test", scheme="http", port=80)
    b._page = _FakePage("http://target.test:8443/x")
    with pytest.raises(SystemExit):
        b._assert_on_origin()
    # Same host+port, https upgrade -> off-origin.
    b._page = _FakePage("https://target.test/x")
    with pytest.raises(SystemExit):
        b._assert_on_origin()


def test_browser_abs_protocol_relative_stays_on_host():
    # A protocol-relative "//evil.test/x" has no scheme, so it is treated as a path
    # and stays on the pinned host (never reinterpreted as a new authority).
    b = _bare_browser(host="target.test", port=80)
    from urllib.parse import urlsplit
    assert urlsplit(b._abs("//evil.test/x")).hostname == "target.test"


def test_browser_goto_uses_load_not_networkidle(monkeypatch):
    # Regression (bug: goto-hangs-on-spa): networkidle never settles on SPAs /
    # long-poll pages, so goto must wait for "load", not "networkidle".
    b = _bare_browser(host="target.test")
    b._page = _RecPage("http://target.test/x")
    monkeypatch.setattr(b, "_checkin", lambda *a, **k: None)
    status = b.goto("/x")
    assert b._page.goto_kwargs["wait_until"] == "load"
    assert status == 200


def test_browser_press_asserts_on_origin(monkeypatch):
    # Regression (bug: press-skips-origin-assert): pressing Enter can submit a form
    # and navigate off-host, so press must re-check the origin like click/submit.
    b = _bare_browser(host="target.test")
    b._page = _RecPage("http://evil.test/after-enter")  # simulate off-host landing
    monkeypatch.setattr(b, "_checkin", lambda *a, **k: None)
    with pytest.raises(SystemExit):
        b.press("input[name=q]", "Enter")


def test_browser_checkin_navigate_sends_url(monkeypatch):
    b = _bare_browser()
    calls = []
    monkeypatch.setattr(redamon, "_post", lambda path, payload: calls.append((path, payload)) or {"ok": True})
    b._checkin("navigate", url="http://target.test/x")
    assert calls == [("/traffic/browser", {"action": "navigate", "origin_id": "t1", "url": "http://target.test/x"})]


def test_browser_factory_fails_closed_without_ctx(monkeypatch):
    # No REDAMON_CTX -> the open PREPARE cannot be tenant-tagged, so _post's _ctx()
    # fails closed before any network call.
    monkeypatch.delenv("REDAMON_CTX", raising=False)
    with pytest.raises(SystemExit):
        redamon.browser("t1")


def test_browser_concurrent_cap_refuses_before_launch(monkeypatch):
    # At the per-run cap, opening another browser must fail closed WITHOUT even
    # calling the server (no chromium launched), bounding memory in the container.
    def _boom(*a, **k):
        raise AssertionError("_post must not be called once the browser cap is hit")
    monkeypatch.setattr(redamon, "_post", _boom)
    monkeypatch.setattr(redamon.Browser, "_live", redamon.Browser._MAX_LIVE)
    with pytest.raises(SystemExit):
        redamon.browser("t1")
