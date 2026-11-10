"""ip_api_exposed severity, and IPv6 targets in the direct-IP checks.

ip_api_exposed reported any 401/403 on an API path as a high "API exposed
without TLS", so a default nginx or WAF 403 on a bare IP became a high
finding. A 401/403 is now a finding only when the answer is an API's, and it
is medium: the API is reachable over plain HTTP but asks for credentials.

The direct-IP checks built URLs as f"http://{ip}", which requests rejects for
an IPv6 literal (InvalidURL, a RequestException every check swallows), so an
IPv6 target was never tested. IPv4 URLs must stay byte-identical.

Addresses are RFC 5737 / RFC 3849 documentation ranges.
"""
from __future__ import annotations

import json
from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers import security_checks as sc

V4 = "198.51.100.30"
V6 = "2001:db8::30"


def _resp(status=200, headers=None, text="", url=""):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    r.content = text.encode()
    r.history = []
    r.url = url
    return r


def _api(responses_by_path):
    """requests.get stand-in answering per path; anything else is a plain 404."""
    calls = []

    def get(url, *a, **k):
        calls.append(url)
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        return responses_by_path.get(path, _resp(404, {"Content-Type": "text/html"}, "nf"))

    return get, calls


def _ip_api(responses_by_path, ip=V4):
    get, calls = _api(responses_by_path)
    with mock.patch.object(sc.requests, "get", side_effect=get):
        return sc.check_ip_api_exposed(ip, timeout=1), calls


class TestIpApiExposedSeverity:
    def test_a_json_200_is_still_high_and_unchanged(self):
        f, _ = _ip_api({"/api": _resp(200, {"Content-Type": "application/json"}, '{"ok":1}')})
        assert f == {
            "type": "ip_api_exposed",
            "severity": "high",
            "name": "API Endpoint Exposed on IP",
            "description": f"API endpoint /api is accessible via direct IP {V4} without TLS. "
                           "This exposes the API to interception and WAF bypass attacks.",
            "url": f"http://{V4}/api",
            "matched_ip": V4,
            "path": "/api",
            "status_code": 200,
            "content_type": "application/json",
            "evidence": "API endpoint returned 200 with application/json; control_check: passed",
            "control_check": "passed",
        }

    @pytest.mark.parametrize("status,body", [
        (403, "<html><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></html>"),
        (401, "<html><title>401 Authorization Required</title></html>"),
        (403, "Access denied by WAF policy"),
    ])
    def test_a_non_api_401_or_403_is_not_a_finding(self, status, body):
        every_path = {p: _resp(status, {"Content-Type": "text/html"}, body)
                      for p in ("/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/v1", "/v2")}
        f, calls = _ip_api(every_path)
        assert f is None
        assert len(calls) == 7

    @pytest.mark.parametrize("status", [401, 403])
    def test_a_protected_json_api_is_medium(self, status):
        f, _ = _ip_api({"/api": _resp(status, {"Content-Type": "application/json"},
                                      '{"error":"unauthorized"}')})
        assert f["type"] == "ip_api_exposed" and f["severity"] == "medium"
        assert f["status_code"] == status and f["url"] == f"http://{V4}/api"
        assert f["matched_ip"] == V4 and f["path"] == "/api"
        assert "requires authentication" in f["description"]
        assert "plain HTTP" in f["description"]

    def test_a_json_body_without_a_json_content_type_is_an_api(self):
        f, _ = _ip_api({"/api": _resp(401, {"Content-Type": "text/plain"}, '{"message":"no"}')})
        assert f["severity"] == "medium"

    def test_a_problem_json_content_type_is_an_api(self):
        f, _ = _ip_api({"/api": _resp(403, {"Content-Type": "application/problem+json"}, "")})
        assert f["severity"] == "medium"

    def test_a_bearer_challenge_is_an_api(self):
        f, _ = _ip_api({"/api": _resp(401, {"WWW-Authenticate": 'Bearer realm="api"'}, "")})
        assert f["severity"] == "medium"

    def test_a_waf_403_on_one_path_does_not_hide_an_open_api_on_the_next(self):
        f, _ = _ip_api({
            "/api": _resp(403, {"Content-Type": "text/html"}, "<html>Forbidden</html>"),
            "/api/v1": _resp(200, {"Content-Type": "application/json"}, "{}"),
        })
        assert f["severity"] == "high" and f["path"] == "/api/v1"

    def test_a_cdn_answer_is_still_skipped(self):
        f, _ = _ip_api({"/api": _resp(401, {"CF-RAY": "x", "Content-Type": "application/json"}, "{}")})
        assert f is None


class TestIpv6UrlsAreBracketed:
    def test_the_bare_url_is_what_requests_refuses(self):
        with pytest.raises(requests.exceptions.InvalidURL):
            requests.Request("GET", f"http://{V6}/api").prepare()
        requests.Request("GET", f"http://[{V6}]/api").prepare()

    @pytest.mark.parametrize("ip,expected", [
        (V4, V4), (V6, f"[{V6}]"), ("app.example.test", "app.example.test"),
        (f"[{V6}]", f"[{V6}]"),
    ])
    def test_url_host(self, ip, expected):
        assert sc._url_host(ip) == expected

    def test_direct_ip_http(self):
        get = mock.MagicMock(return_value=_resp(200, {"Server": "nginx"}, "ok"))
        with mock.patch.object(sc.requests, "get", get):
            f = sc.check_direct_ip_http(V6, timeout=1)
        assert {c.args[0] for c in get.call_args_list} == {f"http://[{V6}]"}
        assert f["url"] == f"http://[{V6}]" and f["matched_ip"] == V6

    def test_direct_ip_https(self):
        get = mock.MagicMock(return_value=_resp(200, {"Server": "nginx"}, "ok"))
        with mock.patch.object(sc.requests, "get", get):
            f = sc.check_direct_ip_https(V6, timeout=1)
        assert {c.args[0] for c in get.call_args_list} == {f"https://[{V6}]"}
        assert f["url"] == f"https://[{V6}]"

    def test_ip_api_exposed(self):
        f, calls = _ip_api({"/api": _resp(200, {"Content-Type": "application/json"}, "{}")}, ip=V6)
        assert calls[0] == f"http://[{V6}]/api"
        assert len(calls) == 2 and calls[1].startswith(f"http://[{V6}]/rdm-")   # the catch-all control
        assert f["url"] == f"http://[{V6}]/api" and f["matched_ip"] == V6

    def test_cache_purge(self):
        req = mock.MagicMock(side_effect=[_resp(405), _resp(200)])
        with mock.patch.object(sc.requests, "request", req):
            f = sc.check_cache_purge_exposed(V6, timeout=1)
        assert [c.args[1] for c in req.call_args_list] == [f"http://[{V6}]/"] * 2
        assert f["url"] == f"http://[{V6}]/"

    def test_waf_bypass_origin_urls(self):
        # The edge blocks the probes and serves the site; the origin serves both.
        get = mock.MagicMock(side_effect=lambda url, *a, **k: _resp(
            403 if "example.test" in url and sc._WAF_PROBE_PARAM in url else 200,
            {"Server": "cloudflare"} if "example" in url else {}))
        with mock.patch.object(sc.requests, "get", get):
            f = sc.check_waf_bypass("www.example.test", V6, timeout=1)
        origin_urls = [c.args[0] for c in get.call_args_list if "example.test" not in c.args[0]]
        assert origin_urls and all(u.startswith(f"https://[{V6}]/") for u in origin_urls)
        assert f["url"] == f"https://[{V6}]/" and f["matched_ip"] == V6

    def test_redirect_chain_reads_the_ipv6_host(self):
        get = mock.MagicMock(side_effect=[
            _resp(301, {"Location": f"http://[{V6}]:8080/x"}),
            _resp(200, url=f"http://[{V6}]:8080/x"),
        ])
        with mock.patch.object(sc.requests, "get", get):
            info = sc._analyze_redirect_chain(V6, "http", timeout=1)
        assert get.call_args_list[0].args[0] == f"http://[{V6}]"
        assert info["final_host"] == V6
        assert info["redirects_to_hostname"] is False

    def test_redirect_chain_to_a_hostname_is_unchanged(self):
        get = mock.MagicMock(side_effect=[
            _resp(301, {"Location": "https://www.example.test/"}),
            _resp(200, url="https://www.example.test:8443/"),
        ])
        with mock.patch.object(sc.requests, "get", get):
            info = sc._analyze_redirect_chain(V4, "http", timeout=1)
        assert get.call_args_list[0].args[0] == f"http://{V4}"
        assert info["final_host"] == "www.example.test"
        assert info["redirects_to_hostname"] is True

    def test_host_down_gate_finds_the_ipv6_host(self):
        for scheme in ("https", "http"):
            for _ in range(3):
                cb.host_health.record_failure(f"{scheme}://[{V6}]", requests.ConnectionError("x"))
        assert sc._host_down(V6) is True


class TestIpv4UrlsAreByteIdentical:
    def test_every_direct_ip_url(self):
        def answer(url, *a, **k):
            if "/rdm-" in url:      # the catch-all control: a real API 404s a made-up path
                return _resp(404, {"Content-Type": "application/json"}, '{"error":"not found"}')
            return _resp(200, {"Content-Type": "application/json"}, "{}")
        get = mock.MagicMock(side_effect=answer)
        req = mock.MagicMock(return_value=_resp(405))
        with mock.patch.object(sc.requests, "get", get), \
             mock.patch.object(sc.requests, "request", req):
            sc.check_direct_ip_http(V4, timeout=1)
            sc.check_direct_ip_https(V4, timeout=1)
            sc.check_ip_api_exposed(V4, timeout=1)
            sc.check_cache_purge_exposed(V4, timeout=1)
        urls = [c.args[0] for c in get.call_args_list] + [c.args[1] for c in req.call_args_list]
        controls = [u for u in urls if "/rdm-" in u]
        assert len(controls) == 1 and controls[0].startswith(f"http://{V4}/rdm-")
        assert set(urls) - set(controls) == {f"http://{V4}", f"https://{V4}", f"http://{V4}/api",
                                             f"http://{V4}/", f"https://{V4}/"}


NOT_FOUND = _resp(200, {"Content-Type": "application/json"}, '{"code":"NOT_FOUND"}')
API_PATHS = ("/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/v1", "/v2")


def _catch_all_get(body_by_path=None, default=None):
    """A server answering every path, made-up ones included, with one JSON body."""
    calls = []
    body_by_path = body_by_path or {}

    def get(url, *a, **k):
        calls.append(url)
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        return body_by_path.get(path, default or NOT_FOUND)

    return get, calls


class TestTheCatchAllControl:
    """API Endpoint Exposed on IP (High) used to fire on any 200 + JSON:
    a server answering `200 {"code":"NOT_FOUND"}` to every path tripped it."""

    def test_a_catch_all_json_server_gives_no_finding(self):
        get, calls = _catch_all_get()
        with mock.patch.object(sc.requests, "get", side_effect=get):
            assert sc.check_ip_api_exposed(V4, timeout=1) is None
        hits = [u for u in calls if "/rdm-" not in u]
        assert hits == [f"http://{V4}{p}" for p in API_PATHS]
        # one control per prefix: /rdm-... and /api/rdm-...
        controls = sorted(u.rsplit("/", 1)[0] for u in calls if "/rdm-" in u)
        assert controls == [f"http://{V4}", f"http://{V4}/api"]

    def test_a_real_api_with_a_404_control_is_a_finding_that_passed(self):
        get, calls = _catch_all_get(
            {"/api/v1": _resp(200, {"Content-Type": "application/json"}, '{"service":"orders","version":"2.1"}')},
            default=_resp(404, {"Content-Type": "application/json"}, '{"code":"NOT_FOUND"}'))
        with mock.patch.object(sc.requests, "get", side_effect=get):
            f = sc.check_ip_api_exposed(V4, timeout=1)
        assert f["path"] == "/api/v1" and f["severity"] == "high"
        assert f["control_check"] == "passed"
        assert "control_check: passed" in f["evidence"]

    def test_a_catch_all_on_one_prefix_does_not_hide_a_real_api_on_another(self):
        def answer(url, *a, **k):
            path = "/" + url.split("/", 3)[3]
            if path.startswith("/api/"):
                return NOT_FOUND                        # /api/* is a catch-all router
            if path == "/v1":
                return _resp(200, {"Content-Type": "application/json"}, '{"name":"inventory","v":"1.4"}')
            return _resp(404, {"Content-Type": "text/html"}, "nf")
        with mock.patch.object(sc.requests, "get", side_effect=answer):
            f = sc.check_ip_api_exposed(V4, timeout=1)
        assert f["path"] == "/v1" and f["control_check"] == "passed"

    def test_a_failed_control_keeps_the_finding_and_says_so(self):
        def answer(url, *a, **k):
            if "/rdm-" in url:
                raise requests.ConnectionError("reset")
            return NOT_FOUND
        with mock.patch.object(sc.requests, "get", side_effect=answer):
            f = sc.check_ip_api_exposed(V4, timeout=1)
        assert f["path"] == "/api" and f["severity"] == "high"
        assert f["control_check"] == "failed"
        assert "control_check: failed" in f["evidence"]

    def test_the_control_is_sent_like_the_check(self):
        get = mock.MagicMock(side_effect=lambda url, *a, **k: NOT_FOUND if "/rdm-" not in url
                             else _resp(404, {}, "nf"))
        with mock.patch.object(sc.requests, "get", get):
            sc.check_ip_api_exposed(V4, timeout=1)
        hit, control = get.call_args_list[0], get.call_args_list[1]
        assert "/rdm-" in control.args[0]
        assert control.kwargs == hit.kwargs     # same timeout, headers, no redirects
        assert control.kwargs["allow_redirects"] is False

    def test_the_control_goes_through_host_health(self):
        def answer(url, *a, **k):
            if "/rdm-" in url:
                raise requests.ConnectionError("reset")
            return NOT_FOUND
        with mock.patch.object(sc.requests, "get", side_effect=answer), \
             mock.patch.object(sc, "_hh_failed") as failed, mock.patch.object(sc, "_hh_alive") as alive:
            sc.check_ip_api_exposed(V4, timeout=1)
        assert [c.args[0] for c in failed.call_args_list if "/rdm-" in c.args[0]]
        assert f"http://{V4}/api" in [c.args[0] for c in alive.call_args_list]


# run_direct_ip_checks runs each direct-IP check unless told otherwise.
ONLY_IP_API = {"ip_api_exposed": True, "direct_ip_http": False, "direct_ip_https": False,
               "cache_purge_exposed": False, "waf_bypass": False}


def _recon_with_ip(ip=V4):
    return {"domain": "example.test", "dns": {
        "domain": {}, "subdomains": {"api.example.test": {
            "has_records": True, "ips": {"ipv4": [ip], "ipv6": []}}}}}


class TestTheControlInTheRun:
    def test_the_run_shares_one_control_cache_and_reports_its_size(self, capsys):
        get, calls = _catch_all_get()
        with mock.patch.object(sc.requests, "get", side_effect=get):
            out = sc.run_security_checks(_recon_with_ip(), ONLY_IP_API, timeout=1, max_workers=1)
        assert out["security_checks"]["findings"] == []
        assert len([u for u in calls if "/rdm-" in u]) == 2
        assert "Catch-all control probes sent: 2" in capsys.readouterr().out
        assert sc._CONTROL_CACHE is None        # reset after the run

    def test_an_roe_excluded_host_gets_no_control(self):
        get, calls = _catch_all_get()
        with mock.patch.object(sc.requests, "get", side_effect=get):
            sc.run_security_checks(_recon_with_ip(), ONLY_IP_API, timeout=1, max_workers=1,
                                   roe_excluded_hosts=[V4])
        assert not [u for u in calls if "/rdm-" in u]

    def test_no_control_runs_when_the_check_is_off(self):
        get, calls = _catch_all_get()
        with mock.patch.object(sc.requests, "get", side_effect=get):
            sc.run_security_checks(_recon_with_ip(), {**ONLY_IP_API, "ip_api_exposed": False,
                                                      "direct_ip_http": True}, timeout=1, max_workers=1)
        assert calls and not [u for u in calls if "/rdm-" in u]


CF_CHALLENGE = _resp(403, {"Content-Type": "application/json", "cf-mitigated": "challenge"},
                     '{"error":"challenge"}')
CHALLENGE_PAGE = _resp(403, {"Content-Type": "text/html"},
                       '<html><head><title>Just a moment...</title></head><body>'
                       '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></body></html>')


def _challenge_gaps():
    return [g for g in cb.coverage_report().gaps if g["source"] == "challenge_blocked"]


class TestChallengePages:
    """A bot challenge is the edge's answer, not the target's: it is never a
    finding, and the host is recorded as not really checked."""

    def test_a_challenged_api_path_is_never_a_finding(self):
        """The JSON content type and 403 would otherwise make it a medium."""
        get, calls = _catch_all_get(default=CF_CHALLENGE)
        with mock.patch.object(sc.requests, "get", side_effect=get):
            assert sc.check_ip_api_exposed(V4, timeout=1) is None
        assert calls == [f"http://{V4}/api"]        # the host is challenged: stop probing it

    def test_a_challenged_host_is_one_coverage_gap(self):
        get, _ = _catch_all_get(default=CHALLENGE_PAGE)
        with mock.patch.object(sc.requests, "get", side_effect=get):
            sc.check_ip_api_exposed(V4, timeout=1)
            sc.check_ip_api_exposed(V4, timeout=1)
        gaps = _challenge_gaps()
        assert len(gaps) == 1
        assert (gaps[0]["module"], gaps[0]["reason"], gaps[0]["skipped"]) == ("vuln_scan", V4, 1)
        report = cb.coverage_report()
        assert "security_check" not in report.degraded_sources   # an entry: no prune effect

    def test_a_challenged_control_keeps_the_finding_and_notes_the_host(self):
        def answer(url, *a, **k):
            return CHALLENGE_PAGE if "/rdm-" in url else NOT_FOUND
        with mock.patch.object(sc.requests, "get", side_effect=answer):
            f = sc.check_ip_api_exposed(V4, timeout=1)
        assert f["control_check"] == "failed" and f["evidence"].endswith("control_check: failed")
        assert [g["reason"] for g in _challenge_gaps()] == [V4]

    def test_an_ordinary_403_is_not_a_challenge(self):
        get, _ = _catch_all_get(default=_resp(403, {"Content-Type": "text/html"}, "<h1>Forbidden</h1>"))
        with mock.patch.object(sc.requests, "get", side_effect=get):
            sc.check_ip_api_exposed(V4, timeout=1)
        assert _challenge_gaps() == []
