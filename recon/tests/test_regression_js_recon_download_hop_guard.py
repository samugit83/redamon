"""R-14 (js_recon): a JS download follows its redirects hop by hop through the
SSRF guard and the RoE, and a source map on another host of the run is in
scope.

``_safe_redirect_get`` checked each hop with the address rule alone
(``_download_allowed``), so a bundle that redirected to a host the Rules of
Engagement exclude (by name, or by an address inside an excluded CIDR) was
downloaded from there. A redirect to a public CDN still loads: a JS download
applies no scope of its own. And ``run_js_recon`` gave
``discover_and_analyze_sourcemaps`` no scope, so a map on one of the run's own
hosts that served no JS was reported ``out_of_scope`` instead of fetched. The
real ``run_js_recon`` runs here; only the HTTP transport (``HTTPAdapter.send``,
so requests behaves as on the wire) and DNS are faked.
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

from recon.main_recon_modules import js_recon as jr  # noqa: E402

JS = "https://app.example.com/static/js/main.4f2a9c.js"
METADATA = "http://169.254.169.254/latest/meta-data/iam/"
VENDOR_JS = "https://cdn.vendor.example.net/main.4f2a9c.js"
STATIC_MAP = "https://static.example.com/js/main.4f2a9c.js.map"
VENDOR_MAP = "https://cdn.vendor.example.net/main.4f2a9c.js.map"

RUN_HOSTS = ("app.example.com", "static.example.com")

ADDRESSES = {
    "app.example.com": "93.184.216.34",
    "static.example.com": "93.184.216.34",
    "legacy.example.com": "93.184.216.36",
    "cdn.vendor.example.net": "93.184.216.35",
    "build.example.com": "10.20.30.40",
    "intranet.example.com": "10.20.0.5",
    "old.example.com": "203.0.113.30",
}

SETTINGS = {
    "JS_RECON_TIMEOUT": 60, "JS_RECON_MAX_FILES": 10, "JS_RECON_CONCURRENCY": 2,
    "JS_RECON_SOURCE_MAPS": False, "JS_RECON_VALIDATE_KEYS": False, "JS_RECON_DEPENDENCY_CHECK": False,
    "JS_RECON_TRUFFLEHOG_ENABLED": False, "JS_RECON_VALIDATE_ENDPOINTS": False,
}

JS_BODY = b"var a = 1;\n"
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

    def send(self, adapter, request, **kwargs):
        self.sent.append((request.method, request.url, kwargs.get("verify")))
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


def _js(body=JS_BODY):
    return (200, {"Content-Type": "application/javascript"}, body)


def _redirect(location, status=302):
    return (status, {"Location": location}, b"")


def _combined(js_urls, hosts=RUN_HOSTS):
    return {
        "metadata": {"project_id": ""},
        "domain": "example.com",
        "subdomains": list(hosts),
        "dns": {"subdomains": [{"subdomain": h, "source": "test"} for h in hosts]},
        "resource_enum": {"js_urls": list(js_urls)},
        "http_probe": {"by_url": {}},
    }


def _run(route, js_urls=(JS,), *, hosts=RUN_HOSTS, settings=None):
    web = _Web(route)
    with web.patched(), \
            patch.object(socket, "getaddrinfo", side_effect=_getaddrinfo):
        out = jr.run_js_recon(_combined(js_urls, hosts), dict(SETTINGS, **(settings or {})))
    return out["js_recon"], web


def _analyzed(js):
    return js["scan_metadata"]["js_files_analyzed"]


# --------------------------------------------------------------------------- JS downloads


def test_a_bundle_redirecting_to_cloud_metadata_is_not_followed():
    js, web = _run(_routes({JS: _redirect(METADATA)}))
    assert not [u for u in web.urls() if "169.254.169.254" in u]
    assert web.urls() == [JS]
    assert _analyzed(js) == 0


def test_a_bundle_redirecting_to_a_private_host_off_the_run_is_not_followed():
    private = "http://build.example.com/static/main.js"
    js, web = _run(_routes({JS: _redirect(private), private: _js()}))
    assert web.urls() == [JS]
    assert _analyzed(js) == 0


def test_a_bundle_redirecting_to_a_public_cdn_is_still_followed():
    js, web = _run(_routes({JS: _redirect(VENDOR_JS), VENDOR_JS: _js()}))
    assert web.urls() == [JS, VENDOR_JS]
    assert _analyzed(js) == 1


def test_a_bundle_redirecting_to_an_roe_excluded_host_is_not_followed():
    legacy = "https://legacy.example.com/static/main.js"
    # The legacy host is on the run's target list, so only the RoE keeps it out.
    js, web = _run(_routes({JS: _redirect(legacy), legacy: _js()}),
                   hosts=RUN_HOSTS + ("legacy.example.com",),
                   settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["legacy.example.com"]})
    assert not [u for u in web.urls() if "legacy.example.com" in u]
    assert _analyzed(js) == 0


def test_a_redirect_to_a_name_resolving_into_an_roe_cidr_is_not_followed():
    old = "https://old.example.com/static/main.js"
    js, web = _run(_routes({JS: _redirect(old), old: _js()}),
                   hosts=RUN_HOSTS + ("old.example.com",),
                   settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["203.0.113.24/29"]})
    assert not [u for u in web.urls() if "old.example.com" in u]
    assert web.urls() == [JS]
    assert _analyzed(js) == 0


@pytest.mark.parametrize("moved", [
    "https://app.example.com/static/js/main.4f2a9c.min.js",
    "https://static.example.com/js/main.4f2a9c.js",
])
def test_an_in_scope_redirect_still_downloads(moved):
    js, web = _run(_routes({JS: _redirect(moved, 301), moved: _js()}))
    assert web.urls() == [JS, moved]
    assert _analyzed(js) == 1
    # The target's own file: its certificate is not verified on any hop.
    assert [verify for _, _, verify in web.sent] == [False, False]


def test_a_bundle_on_the_runs_own_private_host_is_still_read():
    intranet = "http://intranet.example.com/static/app.js"
    moved = "http://intranet.example.com/static/app.1234.js"
    js, web = _run(_routes({intranet: _redirect(moved), moved: _js()}), js_urls=[intranet],
                   hosts=("intranet.example.com",))
    assert web.urls() == [intranet, moved]
    assert _analyzed(js) == 1


# --------------------------------------------------------------------------- source maps


def _with_map(map_url):
    return JS_BODY + f"//# sourceMappingURL={map_url}\n".encode()


def test_a_map_on_a_run_host_that_served_no_js_is_fetched():
    js, web = _run(_routes({JS: _js(_with_map(STATIC_MAP)), STATIC_MAP: (200, {}, MAP_BODY)}),
                   settings={"JS_RECON_SOURCE_MAPS": True})
    assert STATIC_MAP in web.urls()
    [row] = js["source_maps"]
    assert (row["finding_type"], row["map_url"], row["js_url"]) == ("source_map_exposure", STATIC_MAP, JS)


def test_a_third_party_map_is_not_requested_and_is_reported_out_of_scope():
    js, web = _run(_routes({JS: _js(_with_map(VENDOR_MAP)), VENDOR_MAP: (200, {}, MAP_BODY)}),
                   settings={"JS_RECON_SOURCE_MAPS": True})
    assert not [u for u in web.urls() if "cdn.vendor.example.net" in u]
    [row] = js["source_maps"]
    assert (row["finding_type"], row["fetch_result"], row["map_url"]) == (
        "source_map_reference", "out_of_scope", VENDOR_MAP)


def test_a_map_on_an_roe_excluded_run_host_is_not_requested():
    legacy_map = "https://legacy.example.com/js/main.4f2a9c.js.map"
    js, web = _run(_routes({JS: _js(_with_map(legacy_map)), legacy_map: (200, {}, MAP_BODY)}),
                   hosts=RUN_HOSTS + ("legacy.example.com",),
                   settings={"JS_RECON_SOURCE_MAPS": True, "ROE_ENABLED": True,
                             "ROE_EXCLUDED_HOSTS": ["legacy.example.com"]})
    assert not [u for u in web.urls() if "legacy.example.com" in u]
    assert not [r for r in js["source_maps"] if r.get("finding_type") == "source_map_exposure"]


# --------------------------------------------------------------------------- the helper's contract


def _get(route, url, **kwargs):
    web = _Web(route)
    with web.patched(), \
            patch.object(socket, "getaddrinfo", side_effect=_getaddrinfo):
        resp = jr._safe_redirect_get(url, timeout=5, headers={"User-Agent": "t"}, **kwargs)
    return resp, web


def test_the_roe_refuses_a_hop_when_given():
    table = {JS: _redirect(VENDOR_JS), VENDOR_JS: _js()}
    resp, web = _get(_routes(table), JS, settings={"ROE_ENABLED": True,
                                                   "ROE_EXCLUDED_HOSTS": ["cdn.vendor.example.net"]})
    assert resp is None and web.urls() == [JS]
    resp, web = _get(_routes(table), JS)
    assert resp.status_code == 200 and web.urls() == [JS, VENDOR_JS]


def test_the_address_rule_refuses_a_private_hop_off_the_run():
    private = "http://build.example.com/static/main.js"
    resp, web = _get(_routes({JS: _redirect(private), private: _js()}), JS)
    assert resp is None and web.urls() == [JS]


def test_a_redirect_with_no_location_leads_nowhere():
    resp, web = _get(_routes({JS: (302, {}, b"")}), JS)
    assert resp is None and web.urls() == [JS]


def test_a_redirect_loop_stops_at_the_hop_cap():
    resp, web = _get(lambda method, url: _redirect(url + "x"), JS, max_redirects=2)
    assert resp is None and len(web.sent) == 3
