"""The no-rate-limiting check judges, and sends its burst to, the probed host only.

check_no_rate_limiting sent its pre-check GET with allow_redirects=True and its
ten login POSTs with requests' default redirect following. When a login URL
302s to another host (an SSO provider, the apex sending to www), that host got
the GET and ten follow-up requests, and its answers decided a "No Rate Limiting
on Login" finding on the probed host. L-7 gave the header, cookie, CSP and form
checks the on-host walk (_get_on_host); the rate limit check now uses it too:
same-host redirects are still followed, with requests' method rules, and an
off-host hop is never requested.

`FakeWeb` stands in for requests.get/requests.post and follows redirects the
way requests does when asked to, so the same tests show the old and the new
behaviour. Hosts are under example.test / partner.test.
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

HOST = "app.example.test"
LOGIN = f"https://{HOST}/account/login"
SSO = "https://sso.partner.test/authorize"


def _response(url, status, headers, body):
    resp = requests.Response()
    resp.status_code = status
    resp.headers = CaseInsensitiveDict(headers)
    resp._content = body.encode()
    resp.encoding = "utf-8"
    resp.url = url
    # requests fills .cookies from Set-Cookie; a hand-built Response does not.
    name, _, value = headers.get("Set-Cookie", "").split(";")[0].partition("=")
    if name:
        resp.cookies.set(name, value)
    return resp


class FakeWeb:
    """`pages`: (method, url) -> (status, headers, body), or a callable taking
    the call number of that (method, url) and returning one. A GET falls back
    to the POST-less page; anything unknown is a 404."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = []
        self._seen = {}

    @property
    def requested(self):
        return [(m, u) for m, u, _ in self.calls]

    def _answer(self, method, url):
        key = (method, url)
        self._seen[key] = self._seen.get(key, 0) + 1
        page = self.pages.get(key, (404, {}, "not found"))
        return page(self._seen[key]) if callable(page) else page

    def _send(self, method, url, allow_redirects, kwargs):
        history = []
        while True:
            self.calls.append((method, url, {**kwargs, "allow_redirects": allow_redirects}))
            status, headers, body = self._answer(method, url)
            resp = _response(url, status, headers, body)
            location = headers.get("Location")
            if allow_redirects and location and status in (301, 302, 303, 307, 308) \
                    and len(history) < 30:
                history.append(resp)
                if status in (301, 302, 303):
                    method = "GET"
                url = urljoin(url, location)
                continue
            resp.history = history
            return resp

    def get(self, url, *a, allow_redirects=True, **k):
        return self._send("GET", url, allow_redirects, k)

    def post(self, url, *a, allow_redirects=True, **k):
        return self._send("POST", url, allow_redirects, k)


def _run(web, urls=(LOGIN,), hostname=HOST):
    with mock.patch.object(sc.requests, "get", side_effect=web.get), \
         mock.patch.object(sc.requests, "post", side_effect=web.post):
        return sc.check_no_rate_limiting(list(urls), hostname, timeout=1)


def _partner_requests(web):
    return [r for r in web.requested if "partner.test" in r[1]]


LOGIN_PAGE = (200, {}, "<form method=post><input type=password name=password></form>")
REJECTED = (401, {}, "Invalid username or password")


class TestAnOffHostRedirectIsNeverFollowed:
    def test_a_login_page_that_bounces_to_sso_sends_the_sso_host_nothing(self):
        """GET /account/login 302s to the IdP, and so does every POST: the
        IdP used to get 1 GET + 10 follow-ups and its 200 made a finding."""
        web = FakeWeb({("GET", LOGIN): (302, {"Location": SSO}, ""),
                       ("POST", LOGIN): (302, {"Location": SSO}, ""),
                       ("GET", SSO): (200, {}, "<form>Sign in with your company account</form>")})
        assert _run(web) == []
        assert _partner_requests(web) == []

    def test_an_off_host_redirect_on_a_post_is_not_a_processed_attempt(self):
        """The host's own 302 to another host says nothing about whether it
        evaluated the credentials: the burst ends at the first one."""
        web = FakeWeb({("GET", LOGIN): LOGIN_PAGE,
                       ("POST", LOGIN): (302, {"Location": SSO}, "")})
        assert _run(web) == []
        assert web.requested == [("GET", LOGIN), ("POST", LOGIN)]

    def test_an_apex_login_that_redirects_to_www_is_left_to_the_www_pass(self):
        apex_login = "https://example.test/login"
        www_login = "https://www.example.test/login"
        web = FakeWeb({("GET", apex_login): (301, {"Location": www_login}, ""),
                       ("POST", apex_login): (301, {"Location": www_login}, ""),
                       ("GET", www_login): LOGIN_PAGE})
        assert _run(web, urls=[apex_login], hostname="example.test") == []
        assert all(u != www_login for _, u in web.requested)

    def test_every_request_asks_requests_not_to_redirect(self):
        web = FakeWeb({("GET", LOGIN): LOGIN_PAGE, ("POST", LOGIN): REJECTED})
        _run(web)
        assert [c[2]["allow_redirects"] for c in web.calls] == [False] * 11
        assert all(c[2]["headers"]["User-Agent"] == DEFAULT_BROWSER_UA for c in web.calls)
        assert all(c[2]["verify"] is False for c in web.calls)


class TestSameHostRedirectsAreStillFollowed:
    def test_a_failed_login_redirecting_to_its_error_page_is_judged_there(self):
        """POST -> 302 /account/login?error (same host): the landing page is
        what requests judged before, and what is judged now."""
        error_page = f"{LOGIN}?error=1"
        web = FakeWeb({("GET", LOGIN): LOGIN_PAGE,
                       ("POST", LOGIN): (302, {"Location": "/account/login?error=1"}, ""),
                       ("GET", error_page): (200, {}, "Invalid username or password")})
        findings = _run(web)
        assert [f["url"] for f in findings] == [LOGIN]
        assert findings[0]["requests_sent"] == 10
        assert web.requested.count(("POST", LOGIN)) == 10
        assert web.requested.count(("GET", error_page)) == 10

    def test_throttling_shown_on_the_same_host_landing_page_is_still_seen(self):
        error_page = f"{LOGIN}?error=1"
        web = FakeWeb({("GET", LOGIN): LOGIN_PAGE,
                       ("POST", LOGIN): (302, {"Location": "/account/login?error=1"}, ""),
                       ("GET", error_page): lambda n: (200, {}, "Too many login attempts")
                       if n >= 4 else (200, {}, "Invalid username or password")})
        assert _run(web) == []
        assert web.requested.count(("POST", LOGIN)) == 4

    def test_a_307_or_308_on_the_same_host_posts_the_credentials_again(self):
        http_login = f"http://{HOST}/account/login"
        web = FakeWeb({("GET", http_login): (301, {"Location": LOGIN}, ""),
                       ("GET", LOGIN): LOGIN_PAGE,
                       ("POST", http_login): (308, {"Location": LOGIN}, ""),
                       ("POST", LOGIN): REJECTED})
        findings = _run(web, urls=[http_login])
        assert [f["url"] for f in findings] == [http_login]
        posts = [c for c in web.calls if c[0] == "POST" and c[1] == LOGIN]
        assert len(posts) == 10
        assert all(c[2]["data"]["password"] == "test" for c in posts)

    def test_the_pre_check_follows_http_to_https_and_skips_a_final_404(self):
        http_login = f"http://{HOST}/account/login"
        web = FakeWeb({("GET", http_login): (301, {"Location": LOGIN}, "")})
        assert _run(web, urls=[http_login]) == []
        assert web.requested == [("GET", http_login), ("GET", LOGIN)]

    def test_a_cookie_set_on_the_post_redirect_reaches_the_landing_page(self):
        """requests carries a cookie set on a 302 to the next hop; a flash
        message ("too many attempts") often lives in it."""
        error_page = f"{LOGIN}?error=1"
        web = FakeWeb({("GET", LOGIN): LOGIN_PAGE,
                       ("POST", LOGIN): (302, {"Location": "/account/login?error=1",
                                               "Set-Cookie": "flash=locked; Path=/"}, ""),
                       ("GET", error_page): REJECTED})
        _run(web)
        landing = [c for c in web.calls if c[1] == error_page]
        assert landing and all(c[2]["cookies"].get("flash") == "locked" for c in landing)


class TestOnlyTheHostsOwnUrls:
    """S-12a second item: the apex pass used to test its subdomains' login
    URLs (url_host.endswith('.' + host)); 33477eb2 matched the exact host."""

    def test_a_subdomain_login_url_is_burst_only_in_its_own_pass(self):
        sub_login = f"https://{HOST}/login"
        web = FakeWeb({("GET", sub_login): LOGIN_PAGE, ("POST", sub_login): REJECTED})
        recon = {"http_probe": {"by_url": {sub_login: {"url": sub_login}}}}
        with mock.patch.object(sc.requests, "get", side_effect=web.get), \
             mock.patch.object(sc.requests, "post", side_effect=web.post), \
             mock.patch.object(sc, "_host_down", return_value=False):
            findings = sc.run_rate_limit_checks(["example.test", HOST], recon,
                                                {"no_rate_limiting": True}, timeout=1, max_workers=1)
        assert [(f["hostname"], f["url"]) for f in findings] == [(HOST, sub_login)]
        assert web.requested.count(("POST", sub_login)) == 10
        assert {u for _, u in web.requested if HOST in u} == {sub_login}
        # The apex pass found no login URL of its own: it probed its fallback
        # paths, all 404, and never posted.
        assert {m for m, u in web.requested if u.startswith("https://example.test/")} == {"GET"}


# ---------------------------------------------------------------------------
# A real server: the walk's POSTs, method changes and cookies through requests
# ---------------------------------------------------------------------------

class _Login(http.server.BaseHTTPRequestHandler):
    """POST /login 307s to /login2 (the body must follow) and sets a cookie;
    /login2 303s to /error (now a GET), which rejects the credentials."""

    def do_GET(self):  # noqa: N802 - http.server API
        self.server.seen.append(("GET", self.path, "", self.headers.get("Cookie") or ""))
        if self.path == "/login":
            self._reply(200, [], b"<form method=post><input type=password></form>")
        elif self.path == "/error":
            self._reply(200, [], b"Invalid username or password")
        else:
            self._reply(404, [], b"")

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        self.server.seen.append(("POST", self.path, body, self.headers.get("Cookie") or ""))
        if self.path == "/login":
            self._reply(307, [("Location", "/login2"), ("Set-Cookie", "flash=1; Path=/")], b"")
        else:
            self._reply(303, [("Location", "/error")], b"")

    def _reply(self, status, headers, body):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def login_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Login)
    srv.seen = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_real_requests_carry_the_body_on_307_switch_to_get_on_303_and_keep_cookies(login_server):
    real = {"get": requests.get, "post": requests.post}
    local = f"http://127.0.0.1:{login_server.server_address[1]}"

    def routed(method):
        def send(url, *a, **k):
            assert url.startswith(f"https://{HOST}/"), url
            k.pop("verify", None)
            return real[method](local + "/" + url.split("/", 3)[3], *a, **k)
        return send

    with mock.patch.object(sc.requests, "get", side_effect=routed("get")), \
         mock.patch.object(sc.requests, "post", side_effect=routed("post")):
        findings = sc.check_no_rate_limiting([f"https://{HOST}/login"], HOST, timeout=5)

    assert [(f["url"], f["requests_sent"]) for f in findings] == [(f"https://{HOST}/login", 10)]
    seen = login_server.seen
    assert [s for s in seen if s[1] == "/login" and s[0] == "POST"][0][2] == "username=test0&password=test"
    second_hops = [s for s in seen if s[1] == "/login2"]
    assert len(second_hops) == 10
    assert all(m == "POST" and "password=test" in body and cookie == "flash=1"
               for m, _, body, cookie in second_hops)
    landings = [s for s in seen if s[1] == "/error"]
    assert len(landings) == 10 and all(m == "GET" and c == "flash=1" for m, _, _, c in landings)
