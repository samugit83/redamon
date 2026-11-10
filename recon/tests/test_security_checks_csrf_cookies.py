"""S-12a: an anti-CSRF cookie is not a session cookie missing HttpOnly.

check_session_cookies picks session cookies by name fragments, and "token"
is one of them, so csrftoken (Django), XSRF-TOKEN (Angular, Laravel, Spring),
csrf_token and __RequestVerificationToken (ASP.NET) were reported as "Session
Cookie Missing HttpOnly Flag". The double-submit pattern needs the page's
JavaScript to read that cookie and echo it in a header, so HttpOnly would break
it; its absence is the design, not a finding. The Secure rule still applies.

A real http.server on 127.0.0.1 sends the Set-Cookie headers, so requests
builds its cookie jar exactly as on a scan; the check's https://<host>/ is
routed to it. Hosts are under example.test (RFC 2606).
"""
from __future__ import annotations

import http.server
import threading
from unittest import mock

import pytest
import requests

from recon.helpers import security_checks as sc

HOST = "shop.example.test"

CSRF_NAMES = ["csrftoken", "csrf_token", "csrf-token", "_csrf", "XSRF-TOKEN", "X-CSRF-TOKEN",
              "X-XSRF-TOKEN", "__RequestVerificationToken",
              "__RequestVerificationToken_L2FwcA2", "__Host-csrf_token", "YII_CSRF_TOKEN"]

_COOKIES: dict = {}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        self.send_response(200)
        for value in _COOKIES.get(self.path, []):
            self.send_header("Set-Cookie", value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _check(server, cookies):
    _COOKIES["/"] = cookies
    real_get = requests.get

    def routed(url, *a, **k):
        assert url == f"https://{HOST}/", url
        k.pop("verify", None)
        return real_get(f"http://127.0.0.1:{server}/", *a, **k)

    with mock.patch.object(sc.requests, "get", side_effect=routed):
        return sorted((f["type"], f["cookie_name"]) for f in sc.check_session_cookies(HOST, timeout=5))


class TestAntiCsrfCookiesNeedNoHttpOnly:
    @pytest.mark.parametrize("name", CSRF_NAMES)
    def test_a_secure_csrf_cookie_without_httponly_is_silent(self, server, name):
        assert _check(server, [f"{name}=abc123; Path=/; Secure; SameSite=Lax"]) == []

    @pytest.mark.parametrize("name", ["csrftoken", "XSRF-TOKEN"])
    def test_a_csrf_cookie_without_secure_still_gets_the_secure_finding(self, server, name):
        assert _check(server, [f"{name}=abc123; Path=/"]) == [("session_no_secure", name)]


class TestSessionCookiesAreStillJudged:
    def test_a_session_cookie_without_httponly_next_to_a_csrf_cookie_fires(self, server):
        assert _check(server, ["csrftoken=abc; Path=/; Secure",
                               "sessionid=xyz; Path=/; Secure"]) == [
            ("session_no_httponly", "sessionid")]

    @pytest.mark.parametrize("name", ["auth_token", "access_token", "refresh_token", "jwt",
                                      "PHPSESSID", "remember_token"])
    def test_a_token_cookie_that_is_not_anti_csrf_still_fires(self, server, name):
        assert _check(server, [f"{name}=v; Path=/; Secure"]) == [("session_no_httponly", name)]
