"""R-29: JS endpoint deduplication keeps one endpoint per host.

extract_endpoints keyed every file of the run on ``method:path``, so
``fetch("/api/users")`` in a bundle on app.example.com and in one on
admin.example.com collapsed into the first file's entry, and the second host's
Endpoint was never written. When the first one seen was an absolute URL on a
third-party host, the writer dropped it as out of scope and the in-scope
endpoint was lost too. The key now carries the endpoint's origin: the URL's
own, or the source file's for a relative path.

The extraction ``id`` is only this dedup key's hash: the writer derives the
Endpoint node id from base URL, method and path, so no stored id changes.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

sys.modules.setdefault("dotenv", mock.MagicMock())

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402
from recon.helpers.js_recon.endpoints import extract_endpoints  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

APP_JS = "https://app.example.com/static/main.js"
ADMIN_JS = "https://admin.example.com/assets/admin.js"
WWW_JS = "https://www.example.com/js/vendor.js"


def _rest(endpoints, path):
    return [e for e in endpoints if e["path"] == path and e["type"] == "rest"]


class _Result(list):
    def single(self):
        return {"created": True, "linked": 1, "kept": 0, "enriched": 0}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return _Result()


class _Writer(JsReconMixin):
    def __init__(self):
        self.session_obj = _Session()
        self.driver = mock.MagicMock()
        self.driver.session.return_value = self.session_obj


def _written_endpoints(recon_data):
    writer = _Writer()
    stats = writer.update_graph_from_js_recon(recon_data, "u1", "p1")
    merges = {
        (kw["baseurl"], kw["method"], kw["path"])
        for q, kw in writer.session_obj.calls if "MERGE (e:Endpoint" in q
    }
    return merges, stats


def test_the_same_relative_path_on_two_hosts_gives_two_endpoints():
    eps = extract_endpoints([
        {"url": APP_JS, "content": 'fetch("/api/users")'},
        {"url": ADMIN_JS, "content": 'fetch("/api/users")'},
    ], {})
    users = _rest(eps, "/api/users")
    assert sorted(e["source_js"] for e in users) == sorted([APP_JS, ADMIN_JS])
    assert len({e["id"] for e in users}) == 2


def test_each_host_endpoint_reaches_the_writer_under_its_own_base_url():
    eps = extract_endpoints([
        {"url": APP_JS, "content": 'fetch("/api/users")'},
        {"url": ADMIN_JS, "content": 'fetch("/api/users")'},
    ], {})
    merges, stats = _written_endpoints({
        "domain": "example.com",
        "subdomains": ["app.example.com", "admin.example.com"],
        "js_recon": {"endpoints": eps},
    })
    assert ("https://app.example.com", "GET", "/api/users") in merges
    assert ("https://admin.example.com", "GET", "/api/users") in merges
    assert stats["errors"] == []


def test_the_same_path_twice_on_one_host_is_still_one_endpoint():
    eps = extract_endpoints([
        {"url": APP_JS, "content": 'fetch("/api/users")'},
        {"url": "https://app.example.com/static/chunk.js", "content": 'fetch("/api/users")'},
        {"url": "https://APP.example.com/static/other.js", "content": 'fetch("/api/users")'},
    ], {})
    users = _rest(eps, "/api/users")
    assert len(users) == 1
    assert users[0]["source_js"] == APP_JS


def test_method_still_tells_two_endpoints_apart_on_one_host():
    eps = extract_endpoints([
        {"url": APP_JS, "content": 'fetch("/api/users"); axios.post("/api/users", b)'},
    ], {})
    assert sorted(e["method"] for e in _rest(eps, "/api/users")) == ["GET", "POST"]


def test_a_relative_path_keeps_its_source_file_origin():
    eps = extract_endpoints([
        {"url": APP_JS, "content": 'fetch("/api/v1")'},
        {"url": ADMIN_JS, "content": 'fetch("/api/v1")'},
    ], {})
    resolved = {js_recon._resolve_endpoint_candidate_url(e) for e in _rest(eps, "/api/v1")}
    assert resolved == {"https://app.example.com/api/v1", "https://admin.example.com/api/v1"}


def test_a_third_party_absolute_url_no_longer_hides_the_in_scope_endpoint():
    eps = extract_endpoints([
        {"url": WWW_JS, "content": 'fetch("https://tracker.example.net/api/users")'},
        {"url": APP_JS, "content": 'fetch("/api/users")'},
    ], {})
    users = _rest(eps, "/api/users")
    assert {e["base_url"] for e in users} == {"https://tracker.example.net", ""}

    merges, stats = _written_endpoints({
        "domain": "example.com",
        "subdomains": ["www.example.com", "app.example.com"],
        "js_recon": {"endpoints": eps},
    })
    assert ("https://app.example.com", "GET", "/api/users") in merges
    assert not any(base == "https://tracker.example.net" for base, _, _ in merges)
    assert stats["endpoints_out_of_scope"] == 1


def test_an_absolute_url_on_two_hosts_gives_two_endpoints():
    eps = extract_endpoints([
        {"url": APP_JS, "content": 'fetch("https://api.example.com/v2/items")'},
        {"url": ADMIN_JS, "content": 'fetch("https://api.example.org/v2/items")'},
    ], {})
    assert {e["base_url"] for e in _rest(eps, "/v2/items")} == {
        "https://api.example.com", "https://api.example.org"}


def test_relative_routes_and_graphql_paths_keep_one_entry_per_host():
    code = "const r = [{path: '/settings/profile'}]; const g = '/graphql';"
    eps = extract_endpoints([{"url": APP_JS, "content": code}, {"url": ADMIN_JS, "content": code}], {})
    routes = [e for e in eps if e["type"] == "route" and e["path"] == "/settings/profile"]
    graphql = [e for e in eps if e["type"] == "graphql" and e["path"] == "/graphql"]
    assert sorted(e["source_js"] for e in routes) == sorted([APP_JS, ADMIN_JS])
    assert sorted(e["source_js"] for e in graphql) == sorted([APP_JS, ADMIN_JS])


def test_uploaded_files_share_one_pseudo_origin():
    eps = extract_endpoints([
        {"url": "upload://one.js", "content": 'fetch("/api/users")'},
        {"url": "upload://two.js", "content": 'fetch("/api/users")'},
    ], {})
    assert len(_rest(eps, "/api/users")) == 1


SETTINGS = {"JS_RECON_TIMEOUT": 60, "JS_RECON_VALIDATE_KEYS": False, "JS_RECON_SOURCE_MAPS": False,
            "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_TRUFFLEHOG_ENABLED": False}


def _download(urls, work_dir, max_files, *args, **_kw):
    return [{"url": u, "filepath": "", "content": 'fetch("/api/v1")\n', "headers": {}, "size": 20}
            for u in urls]


def test_a_run_writes_one_endpoint_per_host_through_the_pipeline():
    """run_js_recon is also what partial JS Recon calls (js_analysis.run_jsrecon)."""
    combined = {
        "metadata": {"project_id": "p1"},
        "domain": "example.com",
        "subdomains": ["app.example.com", "admin.example.com"],
    }
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=[APP_JS, ADMIN_JS]), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_download), \
            mock.patch.object(js_recon, "_note_unchecked"):
        out = js_recon.run_js_recon(combined, dict(SETTINGS))

    v1 = _rest(out["js_recon"]["endpoints"], "/api/v1")
    assert sorted(e["source_js"] for e in v1) == sorted([APP_JS, ADMIN_JS])

    merges, _ = _written_endpoints(out)
    assert {m for m in merges if m[2] == "/api/v1"} == {
        ("https://app.example.com", "GET", "/api/v1"),
        ("https://admin.example.com", "GET", "/api/v1"),
    }
