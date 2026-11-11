"""R-14: a source map is fetched hop by hop through the SSRF, scope and RoE guards.

``_fetch_sourcemap`` checked only the map URL itself with the SSRF guard, then
let requests follow every redirect (HEAD with ``allow_redirects=True``, GET by
default), and an absolute map URL on a third-party or excluded host was
requested like the target's own. The real discovery runs here; only the HTTP
transport (``HTTPAdapter.send``, so requests' own redirect following runs as it
would on the wire) and DNS are faked.
"""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import sourcemap as sm  # noqa: E402

JS = "https://app.example.com/static/js/main.4f2a9c.js"
MAP = JS + ".map"
METADATA = "http://169.254.169.254/latest/meta-data/iam/"
SETTINGS = {"JS_RECON_SOURCE_MAPS": True, "JS_RECON_TIMEOUT": 60}

ADDRESSES = {
    "app.example.com": "93.184.216.34",
    "static.example.com": "93.184.216.34",
    "cdn.vendor.example.net": "93.184.216.35",
    "build.example.com": "10.20.30.40",
    "legacy.example.com": "192.88.97.20",
    "old.example.com": "192.88.97.30",
}

MAP_BODY = json.dumps({
    "version": 3, "mappings": "AAAA",
    "sources": ["webpack:///./src/App.tsx"],
    "sourcesContent": ["export const App = () => null;"],
}).encode()


def _getaddrinfo(host, *args, **kwargs):
    host = str(host).strip("[]")
    try:
        socket.inet_aton(host)
        address = host
    except OSError:
        if host not in ADDRESSES:
            raise socket.gaierror(socket.EAI_NONAME, "unknown name")
        address = ADDRESSES[host]
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]


class _Web:
    """The HTTP transport: ``route(method, url)`` -> (status, headers, body)."""

    def __init__(self, route):
        self.route = route
        self.sent = []
        self.verify = []

    def send(self, adapter, request, **kwargs):
        self.sent.append((request.method, request.url, dict(request.headers)))
        self.verify.append(kwargs.get("verify"))
        status, headers, body = self.route(request.method, request.url)
        resp = requests.Response()
        resp.status_code = status
        resp.headers = CaseInsensitiveDict(headers)
        resp._content = body if request.method != "HEAD" else b""
        resp._content_consumed = True
        resp.url = request.url
        resp.request = request
        resp.encoding = "utf-8"
        return resp

    def urls(self):
        return [url for _, url, _ in self.sent]

    def patched(self):
        return patch.object(HTTPAdapter, "send", new=lambda adapter, request, **kw: self.send(adapter, request, **kw))


def _routes(table):
    def route(method, url):
        return table.get(url, (404, {}, b""))
    return route


def _discover(route, js_files=None, settings=None, **kwargs):
    web = _Web(route)
    files = js_files or [{"url": JS, "content": "x;\n//# sourceMappingURL=main.4f2a9c.js.map", "headers": {}}]
    with web.patched(), \
            patch.object(socket, "getaddrinfo", side_effect=_getaddrinfo):
        rows = sm.discover_and_analyze_sourcemaps([dict(f) for f in files], dict(SETTINGS, **(settings or {})),
                                                  **kwargs)
    return rows, web


def _redirect(location, status=302):
    return (status, {"Location": location}, b"")


# --------------------------------------------------------------------------- discovery


def test_a_map_redirecting_to_cloud_metadata_is_not_followed():
    rows, web = _discover(_routes({MAP: _redirect(METADATA)}))
    assert not [u for u in web.urls() if "169.254.169.254" in u]
    assert web.urls() and set(web.urls()) == {MAP}
    assert rows == []


def test_a_map_redirecting_to_a_private_name_is_not_followed():
    rows, web = _discover(_routes({MAP: _redirect("http://build.example.com/app.js.map")}),
                          in_scope=lambda url: True)
    assert not [u for u in web.urls() if "build.example.com" in u]
    assert rows == []


def test_a_redirect_to_an_out_of_scope_host_is_not_followed():
    vendor = "https://cdn.vendor.example.net/main.4f2a9c.js.map"
    rows, web = _discover(_routes({MAP: _redirect(vendor), vendor: (200, {}, MAP_BODY)}))
    assert vendor not in web.urls()
    assert set(web.urls()) == {MAP}
    assert rows == []


def test_a_redirect_to_an_roe_excluded_host_is_not_followed():
    legacy = "https://legacy.example.com/main.4f2a9c.js.map"
    # The legacy host served JS too, so only the RoE can keep the hop out.
    files = [{"url": JS, "content": "x;\n//# sourceMappingURL=main.4f2a9c.js.map", "headers": {}},
             {"url": "https://legacy.example.com/old.js", "content": "var a;", "headers": {}}]
    rows, web = _discover(_routes({MAP: _redirect(legacy), legacy: (200, {}, MAP_BODY)}), js_files=files,
                          settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["legacy.example.com"]})
    assert not [u for u in web.urls() if "legacy.example.com" in u]
    assert rows == []


def test_a_name_resolving_into_an_roe_cidr_gets_no_request():
    old = "https://old.example.com/main.4f2a9c.js.map"
    files = [{"url": JS, "content": "x;\n//# sourceMappingURL=main.4f2a9c.js.map", "headers": {}},
             {"url": "https://old.example.com/old.js", "content": "var a;", "headers": {}}]
    rows, web = _discover(_routes({MAP: _redirect(old), old: (200, {}, MAP_BODY)}), js_files=files,
                          settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["192.88.97.24/29"]})
    # Neither the redirect nor the guessed map paths of old.js reach the host.
    assert not [u for u in web.urls() if "old.example.com" in u]
    assert rows == []


def test_a_third_party_map_host_is_not_requested_and_is_reported_as_a_reference():
    vendor = "https://cdn.vendor.example.net/main.4f2a9c.js.map"
    files = [{"url": JS, "content": f"x;\n//# sourceMappingURL={vendor}", "headers": {}}]
    rows, web = _discover(_routes({vendor: (200, {}, MAP_BODY)}), js_files=files)
    assert web.urls() == []
    [row] = rows
    assert (row["finding_type"], row["fetch_result"], row["accessible"], row["severity"]) == (
        "source_map_reference", "out_of_scope", False, "info")
    assert row["map_url"] == vendor


def test_a_map_on_another_host_the_run_fetched_js_from_is_fetched():
    static_map = "https://static.example.com/js/main.4f2a9c.js.map"
    files = [{"url": JS, "content": f"x;\n//# sourceMappingURL={static_map}", "headers": {}},
             {"url": "https://static.example.com/js/vendor.js", "content": "var a;", "headers": {}}]
    rows, web = _discover(_routes({static_map: (200, {}, MAP_BODY)}), js_files=files)
    [row] = [r for r in rows if r["js_url"] == JS]
    assert (row["finding_type"], row["map_url"]) == ("source_map_exposure", static_map)


def test_the_callers_scope_admits_a_map_host_that_served_no_js():
    static_map = "https://static.example.com/js/main.4f2a9c.js.map"
    files = [{"url": JS, "content": f"x;\n//# sourceMappingURL={static_map}", "headers": {}}]
    rows, web = _discover(_routes({static_map: (200, {}, MAP_BODY)}), js_files=files,
                          in_scope=lambda url: url.startswith("https://static.example.com/"))
    [row] = rows
    assert row["finding_type"] == "source_map_exposure"


def test_admit_false_keeps_the_map_unfetched():
    rows, web = _discover(_routes({MAP: (200, {}, MAP_BODY)}), admit=lambda url: False)
    assert web.urls() == []
    assert rows == []


def test_an_in_scope_same_host_redirect_still_works():
    moved = "https://app.example.com/assets/main.4f2a9c.js.map"
    rows, web = _discover(_routes({MAP: _redirect(moved, 301), moved: (200, {}, MAP_BODY)}))
    [row] = rows
    assert (row["finding_type"], row["map_url"]) == ("source_map_exposure", MAP)
    assert [(m, u) for m, u, _ in web.sent] == [("HEAD", MAP), ("HEAD", moved), ("GET", MAP), ("GET", moved)]
    # The target's own file: its certificate is not verified on any hop.
    assert web.verify == [False] * 4


def test_a_redirect_loop_stops_at_the_hop_cap():
    def route(method, url):
        n = int(url.rsplit("n=", 1)[1]) if "n=" in url else 0
        return _redirect(f"{MAP}?n={n + 1}")

    rows, web = _discover(route)
    from recon.helpers.js_recon.hop_guard import MAX_REDIRECTS
    assert len(web.sent) == MAX_REDIRECTS + 1
    assert {m for m, _, _ in web.sent} == {"HEAD"}
    assert rows == []


def test_a_redirect_loop_reads_as_unreachable():
    outcome = {}
    web = _Web(lambda method, url: _redirect(url + "x"))
    with web.patched(), \
            patch.object(socket, "getaddrinfo", side_effect=_getaddrinfo):
        assert sm._fetch_sourcemap(MAP, timeout=5, outcome=outcome) is None
    assert outcome["reason"] == "unreachable"


# --------------------------------------------------------------------------- the public function


def _fetch(route, url, **kwargs):
    from recon.helpers.js_recon.hop_guard import fetch_hop_by_hop
    web = _Web(route)
    refusal = {}
    with web.patched(), \
            patch.object(socket, "getaddrinfo", side_effect=_getaddrinfo):
        resp = fetch_hop_by_hop("GET", url, timeout=5, refusal=refusal, **kwargs)
    return resp, refusal, web


@pytest.mark.parametrize("target, reason", [
    (METADATA, "unsafe"),
    ("http://build.example.com/app.js.map", "unsafe"),
    ("ftp://app.example.com/app.js.map", "unsafe"),
    ("https://nowhere.example.com/app.js.map", "unsafe"),
])
def test_the_ssrf_guard_refuses_a_redirect_hop(target, reason):
    resp, refusal, web = _fetch(_routes({MAP: _redirect(target)}), MAP)
    assert resp is None
    assert (refusal["reason"], refusal["url"], refusal["hop"]) == (reason, target, 1)
    assert web.urls() == [MAP]


def test_admit_false_blocks_a_hop():
    blocked = "https://app.example.com/blocked/main.js.map"
    resp, refusal, web = _fetch(_routes({MAP: _redirect(blocked)}), MAP, admit=lambda url: "/blocked/" not in url)
    assert resp is None
    assert (refusal["reason"], refusal["hop"]) == ("not_admitted", 1)
    assert web.urls() == [MAP]


def test_a_predicate_that_raises_refuses_the_hop():
    def broken(url):
        raise RuntimeError("boom")

    resp, refusal, web = _fetch(_routes({MAP: (200, {}, MAP_BODY)}), MAP, admit=broken)
    assert (resp, refusal["reason"], web.urls()) == (None, "not_admitted", [])


def test_scope_refuses_an_out_of_scope_hop_and_none_skips_the_check():
    vendor = "https://cdn.vendor.example.net/m.js.map"
    table = {MAP: _redirect(vendor), vendor: (200, {}, MAP_BODY)}
    resp, refusal, web = _fetch(_routes(table), MAP, in_scope=lambda url: "app.example.com" in url)
    assert (resp, refusal["reason"], web.urls()) == (None, "out_of_scope", [MAP])
    resp, _, web = _fetch(_routes(table), MAP)
    assert resp.status_code == 200 and web.urls() == [MAP, vendor]


def test_the_roe_refuses_a_hop_by_name_and_by_resolved_address():
    for excluded, target in ((["legacy.example.com"], "https://legacy.example.com/m.js.map"),
                             (["192.88.97.24/29"], "https://old.example.com/m.js.map")):
        settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": excluded}
        resp, refusal, web = _fetch(_routes({MAP: _redirect(target)}), MAP, settings=settings)
        assert (resp, refusal["reason"], refusal["url"], web.urls()) == (None, "roe_excluded", target, [MAP])


def test_with_roe_ip_rules_an_unresolvable_hop_is_refused():
    target = "https://nowhere.example.com/m.js.map"
    settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["192.88.97.24/29"]}
    resp, refusal, web = _fetch(_routes({MAP: _redirect(target)}), MAP, settings=settings)
    assert (resp, refusal["reason"], web.urls()) == (None, "roe_excluded", [MAP])


def test_the_hop_cap_is_the_callers():
    resp, refusal, web = _fetch(lambda method, url: _redirect(url + "x"), MAP, max_redirects=2)
    assert (resp, refusal["reason"], len(web.sent)) == (None, "too_many_redirects", 3)


def test_a_303_turns_into_a_get_and_credentials_stay_on_their_host():
    other = "https://static.example.com/m.js.map"
    same = "https://app.example.com/next.js.map"
    table = {MAP: _redirect(same, 303), same: _redirect(other), other: (200, {}, MAP_BODY)}
    from recon.helpers.js_recon.hop_guard import fetch_hop_by_hop
    web = _Web(_routes(table))
    with web.patched(), \
            patch.object(socket, "getaddrinfo", side_effect=_getaddrinfo):
        resp = fetch_hop_by_hop("POST", MAP, timeout=5, headers={"Authorization": "Bearer x", "X-Probe": "1"})
    assert resp.status_code == 200
    assert [(m, u) for m, u, _ in web.sent] == [("POST", MAP), ("GET", same), ("GET", other)]
    assert web.verify == [False] * 3
    assert "Authorization" in web.sent[1][2]
    assert "Authorization" not in web.sent[2][2] and web.sent[2][2].get("X-Probe") == "1"


def test_a_3xx_without_location_is_the_answer():
    resp, refusal, web = _fetch(_routes({MAP: (304, {}, b"")}), MAP)
    assert (resp.status_code, refusal, web.urls()) == (304, {}, [MAP])


def test_a_custom_sender_is_used_for_every_hop():
    moved = "https://app.example.com/moved.js.map"
    seen = []

    def send(method, url, **kwargs):
        seen.append((method, url, kwargs["allow_redirects"]))
        resp = requests.Response()
        resp.status_code, resp.headers = (302, CaseInsensitiveDict({"Location": moved})) if url == MAP else (
            200, CaseInsensitiveDict())
        return resp

    from recon.helpers.js_recon.hop_guard import fetch_hop_by_hop
    with patch.object(socket, "getaddrinfo", side_effect=_getaddrinfo):
        resp = fetch_hop_by_hop("HEAD", MAP, timeout=5, send=send)
    assert resp.status_code == 200
    assert seen == [("HEAD", MAP, False), ("HEAD", moved, False)]
