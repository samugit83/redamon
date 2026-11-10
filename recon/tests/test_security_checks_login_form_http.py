"""L-21: "Login Form Served Over HTTP" needs a password field, and a control.

check_login_no_https fired (High) on any 200 page with a `<form` and the word
"login", so an HTTP catch-all homepage with a search box and a "Login" link,
answering /login with 200, was reported. The check now needs a password
input, and asks the same server for a made-up path (the 03.3 catch-all
control): a catch-all hit is skipped, a real one records "passed", and a
control with no answer keeps the finding as "failed".

The web is faked per URL behind requests.get, so the tests assert both the
result and the URLs the check sent. Hosts are example.test.
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from recon.helpers import catchall
from recon.helpers import security_checks as sc

HOST = "www.example.test"

SEARCH_HOMEPAGE = """<!doctype html><html><head><title>Example shop</title></head><body>
<nav><a href="/login">Login</a> | <a href="/cart">Cart</a></nav>
<form action="/search" method="get"><input type="text" name="q" placeholder="Search">
<button>Go</button></form><p>Welcome to the shop.</p></body></html>"""

SPA_SHELL = """<!doctype html><html><head><title>App</title></head><body>
<div id="root"></div><noscript>Please enable JavaScript to login.</noscript>
<form id="boot"></form><script src="/static/main.3f2a.js"></script></body></html>"""

LOGIN_PAGE = """<!doctype html><html><head><title>Sign in</title></head><body>
<form action="/session" method="post">
<label for="u">User</label><input id="u" type="text" name="username">
<label for="p">Password</label><INPUT id="p" name="pw" Type = 'Password'>
<button type="submit">Sign in</button></form></body></html>"""

NOT_FOUND = "<html><body><h1>404 Not Found</h1></body></html>"


def _response(url, status, body, headers=None):
    resp = requests.Response()
    resp.status_code = status
    resp.headers = CaseInsensitiveDict(headers or {"Content-Type": "text/html"})
    resp._content = body.encode()
    resp.encoding = "utf-8"
    resp.url = url
    return resp


class FakeWeb:
    """requests.get stand-in: `pages` maps a path to (status, body); a path it
    does not list gets `default` (a 404, or the catch-all page)."""

    def __init__(self, pages, default=(404, NOT_FOUND)):
        self.pages = pages
        self.default = default
        self.requested = []

    def get(self, url, *a, **k):
        assert k.get("allow_redirects") is False, url
        self.requested.append(url)
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        status, body = self.pages.get(path, self.default)
        return _response(url, status, body)


@pytest.fixture(autouse=True)
def _fresh_controls(monkeypatch):
    monkeypatch.setattr(sc, "_CONTROL_CACHE", catchall.ControlCache())
    monkeypatch.setattr(sc, "_ROE_EXCLUDED", ())


def _run(web, host=HOST):
    with mock.patch.object(sc.requests, "get", side_effect=web.get):
        return sc.check_login_no_https(host, timeout=1)


def _controls(web):
    return [u for u in web.requested if f"/{catchall.CONTROL_PREFIX}" in u]


class TestAPasswordFieldIsRequired:
    def test_a_catch_all_homepage_with_a_search_box_and_a_login_link_is_silent(self):
        web = FakeWeb({}, default=(200, SEARCH_HOMEPAGE))
        assert _run(web) == []

    def test_an_spa_shell_that_says_login_with_no_password_field_is_silent(self):
        web = FakeWeb({}, default=(200, SPA_SHELL))
        assert _run(web) == []

    def test_a_password_word_outside_an_input_is_not_a_field(self):
        page = '<form><label for="password">Forgot your password?</label>' \
               '<input name="email" type="email" id="password"><button>Login</button></form>'
        web = FakeWeb({"/login": (200, page)})
        assert _run(web) == []

    def test_no_control_is_sent_for_a_page_with_no_password_field(self):
        web = FakeWeb({}, default=(200, SEARCH_HOMEPAGE))
        _run(web)
        assert _controls(web) == []


class TestARealLoginFormFires:
    def test_a_password_form_at_a_login_path_is_a_finding_with_a_passed_control(self):
        web = FakeWeb({"/signin": (200, LOGIN_PAGE)})
        (finding,) = _run(web)
        assert finding["type"] == "login_no_https"
        assert finding["severity"] == "high"
        assert finding["url"] == f"http://{HOST}/signin"
        assert finding["path"] == "/signin"
        assert finding["control_check"] == "passed"
        assert "control_check: passed" in finding["evidence"]

    def test_the_check_stops_at_the_first_form_and_sends_one_control_next_to_it(self):
        web = FakeWeb({"/signin": (200, LOGIN_PAGE)})
        _run(web)
        assert web.requested[:2] == [f"http://{HOST}/login", f"http://{HOST}/signin"]
        (control,) = _controls(web)
        assert control.startswith(f"http://{HOST}/{catchall.CONTROL_PREFIX}")
        assert web.requested[-1] == control

    def test_a_page_every_path_gets_says_nothing_about_a_login_path(self):
        """Plan 03.3's rule, as ip_api_exposed applies it: a catch-all hit is
        skipped, never written as control_check "catch_all"."""
        web = FakeWeb({}, default=(200, LOGIN_PAGE))
        assert _run(web) == []
        assert len(web.requested) == 12 + len(_controls(web))

    def test_one_control_per_prefix_is_shared_by_the_paths_under_it(self):
        web = FakeWeb({}, default=(200, LOGIN_PAGE))
        _run(web)
        prefixes = sorted(c.rsplit("/", 1)[0] for c in _controls(web))
        assert prefixes == sorted(f"http://{HOST}{p}" for p in
                                  ("", "/admin", "/user", "/account", "/members", "/portal"))

    def test_a_real_form_under_another_prefix_of_a_catch_all_host_fires(self):
        admin = ("<!doctype html><html><head><title>Administration</title>"
                 "<link rel=stylesheet href=/admin/static/admin.css></head><body class=admin>"
                 "<header><h1>Back office</h1><p>Authorised staff only. Every access is logged "
                 "and reviewed by the security team.</p></header><main><form method=post "
                 "action=/admin/session><fieldset><legend>Staff credentials</legend>"
                 "<input name=staff_id><input type=password name=secret><input type=checkbox "
                 "name=remember> Remember this device<button>Enter</button></fieldset></form>"
                 "</main><footer>Support: extension 4410</footer></body></html>")
        web = FakeWeb({"/admin/login": (200, admin)}, default=(200, LOGIN_PAGE))
        (finding,) = _run(web)
        assert (finding["path"], finding["control_check"]) == ("/admin/login", "passed")

    def test_the_evidence_is_the_same_on_every_run(self):
        """The control path is random; the Recon Delta diffs evidence."""
        runs = []
        for _ in range(2):
            sc._CONTROL_CACHE = catchall.ControlCache()
            (finding,) = _run(FakeWeb({"/login": (200, LOGIN_PAGE)}))
            runs.append(finding["evidence"])
        assert runs[0] == runs[1] == \
            "Login form with password field found on HTTP; control_check: passed"

    def test_a_control_that_gets_no_answer_keeps_the_finding_as_failed(self):
        web = FakeWeb({"/login": (200, LOGIN_PAGE)})

        def get(url, *a, **k):
            if f"/{catchall.CONTROL_PREFIX}" in url:
                raise requests.ConnectionError("reset")
            return web.get(url, *a, **k)

        with mock.patch.object(sc.requests, "get", side_effect=get):
            (finding,) = sc.check_login_no_https(HOST, timeout=1)
        assert finding["control_check"] == "failed"

    def test_a_host_the_rules_of_engagement_exclude_gets_no_control(self, monkeypatch):
        monkeypatch.setattr(sc, "_ROE_EXCLUDED", ("example.test",))
        web = FakeWeb({"/login": (200, LOGIN_PAGE)})
        (finding,) = _run(web)
        assert _controls(web) == []
        assert finding["control_check"] == "failed"


class TestTheCheckStaysBehindItsToggle:
    def test_switched_off_it_sends_neither_login_probes_nor_a_control(self):
        """Stealth mode and the per-check toggle both arrive as this switch."""
        web = FakeWeb({}, default=(200, LOGIN_PAGE))
        enabled = {"login_no_https": False, "session_no_secure": False,
                   "session_no_httponly": False, "basic_auth_no_tls": False}
        with mock.patch.object(sc.requests, "get", side_effect=web.get):
            assert sc.run_auth_checks([HOST], enabled, timeout=1, max_workers=1) == []
        assert web.requested == []

    def test_switched_on_it_reaches_the_runner(self):
        web = FakeWeb({"/login": (200, LOGIN_PAGE)})
        enabled = {"login_no_https": True, "session_no_secure": False,
                   "session_no_httponly": False, "basic_auth_no_tls": False}
        with mock.patch.object(sc.requests, "get", side_effect=web.get):
            findings = sc.run_auth_checks([HOST], enabled, timeout=1, max_workers=1)
        assert [f["type"] for f in findings] == ["login_no_https"]
