"""Session-cookie flags are judged per Set-Cookie header, on every hop.

check_session_cookies read the merged `Set-Cookie` header and passed a cookie
when its name appeared in it and "httponly" appeared anywhere in it, so one
HttpOnly cookie hid every other cookie's missing flag. Cookies set on a
redirect hop were never looked at (only the final response's jar was).

A real http.server on 127.0.0.1 sends the headers, so requests builds its
cookie jar, merged header and redirect history exactly as it does on a scan.
The check addresses https://<host>/; the test routes that to the local server.
"""
from __future__ import annotations

import http.server
import threading
from unittest import mock

import pytest
import requests

from recon.helpers import security_checks as sc

HOST = "shop.example.test"

# path -> (status, [Set-Cookie values], Location or None)
ROUTES = {
    "/mixed": (200, ["sessionid=abc; Path=/", "auth_token=xyz; Path=/; HttpOnly; Secure"], None),
    "/hop": (302, ["PHPSESSID=hop1; path=/"], "/landing"),
    "/landing": (200, [], None),
    "/good": (200, ["sessionid=a; Path=/; Secure; HttpOnly"], None),
    "/bare": (200, ["sessionid=a; Path=/"], None),
    "/names": (200, ["sid=1; Path=/; Secure", "xsid_hint=2; Path=/; Secure; HttpOnly"], None),
    "/case": (200, ["JSESSIONID=1; path=/; secure; httponly"], None),
    "/resets": (302, ["sessionid=old; Path=/"], "/resets-final"),
    "/resets-final": (200, ["sessionid=new; Path=/; Secure; HttpOnly"], None),
    "/cleared": (200, ["sessionid=; Path=/; Max-Age=0",
                       "auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"], None),
    "/nocookie": (200, [], None),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        status, cookies, location = ROUTES.get(self.path, (404, [], None))
        self.send_response(status)
        for value in cookies:
            self.send_header("Set-Cookie", value)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _check(server, path):
    """The check's first request is https://<host>/, served from `path`; the
    redirect hops it follows on the same host are served from their own path."""
    real_get = requests.get

    def routed(url, *a, **k):
        assert url.startswith(f"https://{HOST}/"), url
        k.pop("verify", None)
        local = path if url == f"https://{HOST}/" else "/" + url.split("/", 3)[3]
        return real_get(f"http://127.0.0.1:{server}{local}", *a, **k)

    with mock.patch.object(sc.requests, "get", side_effect=routed):
        return sc.check_session_cookies(HOST, timeout=5)


def _flags(findings):
    return sorted((f["type"], f["cookie_name"]) for f in findings)


class TestEachCookieIsJudgedOnItsOwnHeader:
    def test_an_httponly_cookie_does_not_hide_another_cookies_missing_flag(self, server):
        findings = _check(server, "/mixed")
        assert ("session_no_httponly", "sessionid") in _flags(findings)
        assert ("session_no_httponly", "auth_token") not in _flags(findings)

    def test_secure_is_still_judged_per_cookie(self, server):
        flags = _flags(_check(server, "/mixed"))
        assert ("session_no_secure", "sessionid") in flags
        assert ("session_no_secure", "auth_token") not in flags

    def test_a_cookie_name_inside_another_name_is_not_confused(self, server):
        assert _flags(_check(server, "/names")) == [("session_no_httponly", "sid")]

    def test_attributes_are_case_insensitive(self, server):
        assert _check(server, "/case") == []


class TestRedirectHops:
    def test_a_cookie_set_on_a_redirect_hop_is_checked(self, server):
        assert _flags(_check(server, "/hop")) == [
            ("session_no_httponly", "PHPSESSID"), ("session_no_secure", "PHPSESSID")]

    def test_the_cookie_the_browser_ends_up_with_is_the_one_judged(self, server):
        assert _check(server, "/resets") == []


class TestNormalPathUnchanged:
    def test_a_cookie_with_both_flags_passes(self, server):
        assert _check(server, "/good") == []

    def test_a_bare_session_cookie_gets_both_findings_in_the_same_format(self, server):
        findings = _check(server, "/bare")
        assert _flags(findings) == [("session_no_httponly", "sessionid"),
                                    ("session_no_secure", "sessionid")]
        by_type = {f["type"]: f for f in findings}
        assert by_type["session_no_secure"] == {
            "type": "session_no_secure",
            "severity": "medium",
            "name": "Session Cookie Missing Secure Flag",
            "description": "The session cookie 'sessionid' does not have the Secure flag. "
                           "It can be transmitted over unencrypted HTTP connections.",
            "url": f"https://{HOST}/",
            "hostname": HOST,
            "cookie_name": "sessionid",
            "evidence": "Cookie 'sessionid' missing Secure attribute",
            "recommendation": "Add the Secure flag to all session cookies.",
        }
        assert by_type["session_no_httponly"]["evidence"] == \
            "Cookie 'sessionid' missing HttpOnly attribute"

    def test_a_cleared_cookie_is_not_a_finding(self, server):
        assert _check(server, "/cleared") == []

    def test_no_cookie_no_finding(self, server):
        assert _check(server, "/nocookie") == []
