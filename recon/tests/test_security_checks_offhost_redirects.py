"""L-7: header, cookie, CSP and form checks judge only the host they probe.

check_security_headers, check_cache_control_missing, check_session_cookies,
check_csp_unsafe_inline and check_insecure_form_action used
allow_redirects=True, and _cookies_set_by read every hop. When
shop.example.test 302s to a third-party login page, that page's missing
headers, cookies, CSP and forms were reported on shop.example.test, and the
third party received the requests. Redirects are now followed only while they
stay on the probed host, and the last response from that host is judged.

`FakeWeb` stands in for requests.get and redirects the way requests does when
asked to, so the same test shows the old and the new behaviour; a pair of real
local servers checks cookies across hops. Hosts are example.test / partner.test.
"""
from __future__ import annotations

import http.server
import threading
from unittest import mock
from urllib.parse import urljoin

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from recon.helpers import security_checks as sc
from recon.helpers.user_agent import DEFAULT_BROWSER_UA

HOST = "shop.example.test"
PARTNER = "https://login.partner.test/sso"

BARE_PAGE = "<html><body>welcome</body></html>"
PARTNER_PAGE = ('<html><body><form action="http://login.partner.test/post" method="post">'
                '<input type="password" name="pw"></form></body></html>')
PARTNER_HEADERS = {
    "Content-Security-Policy": "script-src 'self' 'unsafe-inline'",
    "Set-Cookie": "partner_session=xyz; Path=/",
}


def _response(url, status, headers, body):
    resp = requests.Response()
    resp.status_code = status
    resp.headers = CaseInsensitiveDict(headers)
    resp._content = body.encode()
    resp.encoding = "utf-8"
    resp.url = url
    return resp


class FakeWeb:
    """`pages`: url -> (status, headers, body). Unknown URLs get a 404."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    @property
    def requested(self):
        return [c[0] for c in self.calls]

    def get(self, url, *a, allow_redirects=True, **k):
        history = []
        while True:
            self.calls.append((url, allow_redirects, k))
            status, headers, body = self.pages.get(url, (404, {}, "not found"))
            resp = _response(url, status, headers, body)
            location = headers.get("Location")
            if allow_redirects and location and status in (301, 302, 303, 307, 308) \
                    and len(history) < 30:
                history.append(resp)
                url = urljoin(url, location)
                continue
            resp.history = history
            return resp


def _offsite(root):
    """`root` 302s to the partner's login page, which has every problem."""
    return FakeWeb({
        root: (302, {"Location": PARTNER}, ""),
        PARTNER: (200, PARTNER_HEADERS, PARTNER_PAGE),
    })


def _with(web, fn, *args, **kwargs):
    with mock.patch.object(sc.requests, "get", side_effect=web.get):
        return fn(*args, **kwargs)


def _never_reached_partner(web):
    return all("partner.test" not in u for u in web.requested)


class TestAnOffHostRedirectIsNotJudged:
    def test_security_headers(self):
        web = _offsite(f"https://{HOST}")
        assert _with(web, sc.check_security_headers, HOST, port=443, timeout=1) == []
        assert web.requested == [f"https://{HOST}"]

    def test_cache_control(self):
        web = _offsite(f"https://{HOST}")
        assert _with(web, sc.check_cache_control_missing, HOST, port=443, timeout=1) is None
        assert _never_reached_partner(web)

    def test_session_cookies(self):
        web = _offsite(f"https://{HOST}/")
        assert _with(web, sc.check_session_cookies, HOST, timeout=1) == []
        assert _never_reached_partner(web)

    def test_csp_unsafe_inline(self):
        web = _offsite(f"https://{HOST}/")
        assert _with(web, sc.check_csp_unsafe_inline, HOST, timeout=1) is None
        assert _never_reached_partner(web)

    def test_insecure_form_action(self):
        web = _offsite(f"https://{HOST}/")
        assert _with(web, sc.check_insecure_form_action, HOST, timeout=1) == []
        assert _never_reached_partner(web)

    def test_the_runners_send_the_partner_nothing(self):
        web = FakeWeb({u: (302, {"Location": PARTNER}, "")
                       for u in (f"https://{HOST}", f"https://{HOST}/")})
        web.pages[PARTNER] = (200, PARTNER_HEADERS, PARTNER_PAGE)
        with mock.patch.object(sc.requests, "get", side_effect=web.get):
            assert sc.run_security_headers_checks([HOST], {}, timeout=1, max_workers=1) == []
            assert sc.run_app_security_checks([HOST], {}, timeout=1, max_workers=1) == []
            findings = sc.run_auth_checks([HOST], {"login_no_https": False,
                                                   "basic_auth_no_tls": False},
                                          timeout=1, max_workers=1)
        assert findings == []
        assert web.requested and _never_reached_partner(web)

    def test_a_protocol_relative_location_to_another_host_is_off_host(self):
        web = FakeWeb({f"https://{HOST}": (302, {"Location": "//cdn.partner.test/x"}, ""),
                       "https://cdn.partner.test/x": (200, {}, BARE_PAGE)})
        assert _with(web, sc.check_security_headers, HOST, port=443, timeout=1) == []
        assert web.requested == [f"https://{HOST}"]

    def test_a_malformed_location_ends_the_walk_without_raising(self):
        web = FakeWeb({f"https://{HOST}/": (302, {"Location": "http://[bad/x"}, "")})
        web.get = mock.MagicMock(side_effect=lambda url, *a, **k: _response(
            url, 302, {"Location": "http://[bad/x"}, ""))
        assert _with(web, sc.check_csp_unsafe_inline, HOST, timeout=1) is None
        assert web.get.call_count == 1

    def test_a_non_http_location_is_not_followed(self):
        web = FakeWeb({f"https://{HOST}/": (302, {"Location": "ftp://files.example.test/"}, "")})
        assert _with(web, sc.check_insecure_form_action, HOST, timeout=1) == []
        assert web.requested == [f"https://{HOST}/"]


class TestSameHostRedirectsAreStillFollowed:
    def test_a_path_redirect_is_followed_and_the_final_page_judged(self):
        web = FakeWeb({f"https://{HOST}": (302, {"Location": "/home"}, ""),
                       f"https://{HOST}/home": (200, {}, BARE_PAGE)})
        findings = _with(web, sc.check_security_headers, HOST, port=443, timeout=1)
        assert {f["missing_header"] for f in findings} == set(sc.SECURITY_HEADERS)
        assert all(f["url"] == f"https://{HOST}" for f in findings)
        assert web.requested == [f"https://{HOST}", f"https://{HOST}/home"]

    def test_http_to_https_on_the_same_name_is_followed(self):
        web = FakeWeb({f"http://{HOST}": (301, {"Location": f"https://{HOST}/"}, ""),
                       f"https://{HOST}/": (200, {}, BARE_PAGE)})
        assert _with(web, sc.check_cache_control_missing, HOST, port=80, timeout=1)
        assert web.requested == [f"http://{HOST}", f"https://{HOST}/"]

    def test_case_a_trailing_dot_and_another_port_are_the_same_host(self):
        web = FakeWeb({
            f"https://{HOST}/": (302, {"Location": "https://SHOP.Example.test./a"}, ""),
            "https://SHOP.Example.test./a": (302, {"Location": f"https://{HOST}:8443/b"}, ""),
            f"https://{HOST}:8443/b": (200, {"Content-Security-Policy": "default-src 'unsafe-inline'"},
                                       BARE_PAGE),
        })
        assert _with(web, sc.check_csp_unsafe_inline, HOST, timeout=1)["type"] == "csp_unsafe_inline"
        assert len(web.requested) == 3

    def test_every_hop_is_a_single_request_with_the_browser_ua(self):
        web = FakeWeb({f"https://{HOST}/": (302, {"Location": "/home"}, ""),
                       f"https://{HOST}/home": (200, {}, BARE_PAGE)})
        _with(web, sc.check_insecure_form_action, HOST, timeout=1)
        assert [c[1] for c in web.calls] == [False, False]
        assert all(c[2]["headers"]["User-Agent"] == DEFAULT_BROWSER_UA for c in web.calls)

    def test_a_same_host_redirect_loop_ends_with_no_finding(self):
        web = FakeWeb({f"https://{HOST}/": (302, {"Location": "/again"}, ""),
                       f"https://{HOST}/again": (302, {"Location": "/"}, "")})
        assert _with(web, sc.check_csp_unsafe_inline, HOST, timeout=1) is None
        assert len(web.requested) <= 31


class TestCookiesComeFromTheHostsOwnHops:
    def test_a_cookie_the_host_sets_on_its_own_redirect_is_judged(self):
        web = FakeWeb({
            f"https://{HOST}/": (302, {"Location": "/home", "Set-Cookie": "sessionid=1; Path=/"}, ""),
            f"https://{HOST}/home": (302, {"Location": PARTNER}, ""),
            PARTNER: (200, PARTNER_HEADERS, PARTNER_PAGE),
        })
        findings = _with(web, sc.check_session_cookies, HOST, timeout=1)
        assert sorted((f["type"], f["cookie_name"]) for f in findings) == [
            ("session_no_httponly", "sessionid"), ("session_no_secure", "sessionid")]
        assert _never_reached_partner(web)


# ---------------------------------------------------------------------------
# Real servers: cookies ride along same-host hops; the partner sees nothing
# ---------------------------------------------------------------------------

class _Shop(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        if self.path == "/":
            self._reply(302, [("Set-Cookie", "gate=1; Path=/"), ("Location", "/in")])
        elif self.path == "/in" and "gate=1" in (self.headers.get("Cookie") or ""):
            self._reply(302, [("Set-Cookie", "sessionid=abc; Path=/"),
                              ("Location", f"http://127.0.0.1:{self.server.partner_port}/sso")])
        else:
            self._reply(302, [("Location", "/")])

    def _reply(self, status, headers):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _Partner(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.server.seen.append(self.path)
        self.send_response(200)
        self.send_header("Set-Cookie", "partner_session=xyz; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def servers():
    partner = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Partner)
    partner.seen = []
    shop = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Shop)
    shop.partner_port = partner.server_address[1]
    for srv in (partner, shop):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield shop, partner
    for srv in (partner, shop):
        srv.shutdown()
        srv.server_close()


def test_real_hops_carry_cookies_and_stop_before_the_partner(servers):
    shop, partner = servers
    real_get = requests.get

    def routed(url, *a, **k):
        if url.startswith(f"https://{HOST}/"):
            k.pop("verify", None)
            url = f"http://127.0.0.1:{shop.server_address[1]}/" + url.split("/", 3)[3]
        return real_get(url, *a, **k)

    with mock.patch.object(sc.requests, "get", side_effect=routed):
        findings = sc.check_session_cookies(HOST, timeout=5)
    assert sorted((f["type"], f["cookie_name"]) for f in findings) == [
        ("session_no_httponly", "sessionid"), ("session_no_secure", "sessionid")]
    assert partner.seen == []
