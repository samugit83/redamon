"""
Unit tests for the class-10 web-cache-deception probe
recon.cache_scan.deception.deception_probe().

The probe is auth-aware: it runs only with an in-scope auth profile, and confirms a
finding only when a static-suffix URL serves the AUTHENTICATED page from cache to an
UNAUTHENTICATED request.
"""
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.cache_scan import deception


class FakeResponse:
    def __init__(self, body="", headers=None, status=200):
        self.text = body
        self.headers = headers or {}
        self.status_code = status


class DeceptionCacheSession:
    """Static-suffix URL serves the sensitive page (origin ignores the suffix) and the
    cache stores it by extension, then serves it to an anonymous request as a HIT."""

    SENSITIVE = "SENSITIVE dashboard for user=alice"
    ANON = "generic public login page"

    def __init__(self, auth_header="cookie"):
        self.auth_header = auth_header.lower()
        self.store = {}

    def _authed(self, headers):
        return any(k.lower() == self.auth_header for k in (headers or {}))

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        authed = self._authed(headers)
        path = url.split("?", 1)[0]
        is_static = any(path.endswith(ext) or ext in path for ext in (".css", ".js", ".jpg"))
        if is_static:
            if url in self.store:                                   # cache HIT
                return FakeResponse(self.store[url], {"x-cache": "hit", "age": "5"})
            body = self.SENSITIVE if authed else self.ANON          # origin serves base page
            self.store[url] = body                                  # cache stores the static URL
            return FakeResponse(body, {"x-cache": "miss"})
        return FakeResponse(self.SENSITIVE if authed else self.ANON, {"x-cache": "miss"})


class SafeStaticSession(DeceptionCacheSession):
    """Not vulnerable: the origin 404s the static-suffix URL (does not path-confuse)."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        path = url.split("?", 1)[0]
        if any(ext in path for ext in (".css", ".js", ".jpg")):
            return FakeResponse("not found", {"x-cache": "miss"}, status=404)
        authed = self._authed(headers)
        return FakeResponse(self.SENSITIVE if authed else self.ANON, {"x-cache": "miss"})


_SETTINGS = {
    # "." puts shop.test itself in scope; without it only its subdomains get auth.
    "TARGET_DOMAIN": "shop.test", "SUBDOMAIN_LIST": ["."],
    "AUTH_PROFILE": {"authType": "cookie", "authValue": "session=abc", "reconEnabled": True},
}
_URL = "https://shop.test/account"
_ORACLE = {"signals": ["x-cache"]}


def test_deception_confirmed_when_authed_page_leaks_from_cache():
    f = deception.deception_probe(_URL, _ORACLE, DeceptionCacheSession(), _SETTINGS, timeout=2)
    assert f is not None
    assert f["technique"] == "cache_deception"
    assert f["impact"] == "deception"
    assert f["detection_mode"] == "deception"
    assert f["confidence_tier"] == "Confirmed"
    # The finding is about the page; the plant URL that leaked is its reproduction.
    assert f["endpoint_url"] == _URL
    assert f["cache_param"] == "static-suffix:/.css"
    assert re.fullmatch(r"https://shop\.test/account/rdmn[0-9a-f]{6}\.css", f["evidence"]["poc_link"])
    assert f["evidence"]["poc_link"] in f["evidence"]["curl_verify"]


def test_no_finding_without_auth_profile():
    # No session -> deception is unprovable natively -> None.
    assert deception.deception_probe(_URL, _ORACLE, DeceptionCacheSession(), {}, timeout=2) is None


def test_no_finding_when_origin_404s_static_suffix():
    assert deception.deception_probe(_URL, _ORACLE, SafeStaticSession(), _SETTINGS, timeout=2) is None


def test_out_of_scope_host_gets_no_session():
    # The auth profile is scoped to shop.test; a different host gets no auth -> None.
    f = deception.deception_probe("https://other.test/account", _ORACLE,
                                  DeceptionCacheSession(), _SETTINGS, timeout=2)
    assert f is None


class PrivateAccountSession(DeceptionCacheSession):
    """The account page itself is marked `private, no-store` (as nearly every account
    page is), so the cache keeps the base page out; only the static-suffix URL the
    attacker crafts gets stored, which is the whole deception."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        resp = super().get(url, headers, timeout, verify, allow_redirects, **kwargs)
        path = url.split("?", 1)[0]
        if not any(ext in path for ext in (".css", ".js", ".jpg")):
            resp.headers["cache-control"] = "private, no-store"
        return resp


class _GraphSession:
    def __init__(self):
        self.calls = []

    def run(self, query, **params):
        self.calls.append((query, params))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _GraphDriver:
    def __init__(self):
        self.s = _GraphSession()

    def session(self):
        return self.s


def _write(finding, uid="u-wcd", pid="p-wcd"):
    """Run the real cache writer on one finding; returns its (query, params) calls."""
    from graph_db.mixins.cache_mixin import CacheMixin

    writer = CacheMixin()
    writer.driver = _GraphDriver()
    stats = writer.update_graph_from_cache_scan({"cache_scan": {"findings": [finding]}}, uid, pid)
    assert stats["errors"] == [], stats["errors"]
    return writer.driver.s.calls


def test_two_runs_give_the_same_finding_id():
    # R-28: each run plants under a fresh random marker. The finding id must not
    # follow it, or every run orphans the previous node's mute, verdict and fix item.
    ids = []
    for _ in range(2):
        f = deception.deception_probe(_URL, _ORACLE, DeceptionCacheSession(), _SETTINGS, timeout=2)
        assert f is not None
        ids.append(_write(f)[0][1]["id"])
    assert ids[0] == ids[1]


class ShapeCacheSession(DeceptionCacheSession):
    """Only one plant shape (delimiter + suffix) path-confuses; the origin 404s the rest."""

    def __init__(self, delimiter, suffix):
        super().__init__()
        self.shape = re.compile(re.escape(delimiter) + r"rdmn[0-9a-f]{6}" + re.escape(suffix) + "$")

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        path = url.split("?", 1)[0]
        if "rdmn" in path and not self.shape.search(path):
            return FakeResponse("not found", {"x-cache": "miss"}, status=404)
        return super().get(url, headers, timeout, verify, allow_redirects, **kwargs)


def test_the_shape_that_leaked_is_part_of_the_id():
    found = {}
    for delimiter in ("/", ";"):
        for suffix in (".css", ".js"):
            f = deception.deception_probe(_URL, _ORACLE, ShapeCacheSession(delimiter, suffix),
                                          _SETTINGS, timeout=2)
            assert f["cache_param"] == f"static-suffix:{delimiter}{suffix}"
            assert f["endpoint_url"] == _URL
            found[(delimiter, suffix)] = _write(f)[0][1]["id"]
    assert len(set(found.values())) == 4, found


def test_a_trailing_slash_is_the_same_finding():
    # /account and /account/ plant the very same URLs: one test, one finding.
    ids = {_write(deception.deception_probe(u, _ORACLE, DeceptionCacheSession(), _SETTINGS,
                                            timeout=2))[0][1]["id"]
           for u in (_URL, _URL + "/")}
    assert len(ids) == 1


def test_the_writer_hangs_the_finding_off_the_page_not_a_plant_endpoint():
    f = deception.deception_probe(_URL, _ORACLE, DeceptionCacheSession(), _SETTINGS, timeout=2)
    (_, vuln), (wire_query, wire) = _write(f)
    assert "MERGE (e:Endpoint" in wire_query
    assert (wire["baseurl"], wire["path"]) == ("https://shop.test", "/account")
    props = vuln["props"]
    assert (props["endpoint"], props["matched_at"]) == (_URL, _URL)
    assert "rdmn" not in props["id"]
    assert props["poc_link"] == f["evidence"]["poc_link"]
    assert "rdmn" in props["poc_link"]


def test_other_cache_finding_ids_are_unchanged():
    from graph_db.mixins.cache_mixin import cache_vuln_id

    assert (cache_vuln_id("u", "p", "unkeyed_header", "https://shop.test/home?a=1", "X-Forwarded-Host")
            == "cache_u_p_unkeyed_header_https___shop_test__home_X-Forwarded-Host")


def _old_writer_shape(finding):
    """The finding the probe wrote before R-28: the plant URL as its URL and a bare
    "static-suffix" vector. Built from a real probe run's own plant URL."""
    return {**finding, "endpoint_url": finding["evidence"]["poc_link"], "cache_param": "static-suffix"}


def test_the_rekey_script_moves_an_old_finding_to_the_id_a_scan_writes_now():
    from tooling.scripts import cache_deception_rekey as rk

    uid, pid = "u-wcd", "p-wcd"
    for url in (_URL, "https://shop.test/", "https://shop.test/account/"):
        for delimiter, suffix in (("/", ".css"), (";", ".jpg")):
            f = deception.deception_probe(url, _ORACLE, ShapeCacheSession(delimiter, suffix),
                                          _SETTINGS, timeout=2)
            assert f is not None, (url, delimiter, suffix)
            old = _old_writer_shape(f)
            old_id = _write(old, uid, pid)[0][1]["id"]
            plan = rk.plan_finding(uid, pid, old_id, old["endpoint_url"], old["cache_param"])
            assert plan is not None, (url, delimiter)
            assert plan["new_id"] == _write(f, uid, pid)[0][1]["id"], (url, delimiter)
            assert plan["cache_param"] == deception.deception_vector(delimiter, suffix)


def test_scanner_probes_deception_on_a_private_account_page():
    # The oracle rightly finds the private base page not cacheable; the scan must still
    # run the deception probe on it instead of skipping the URL.
    from recon.cache_scan import scanner

    orig_s, orig_w = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
    scanner._build_retry_session = lambda *a, **k: PrivateAccountSession()
    scanner.wcvs_runner.run_wcvs = lambda *a, **k: []
    try:
        rd = {"http_probe": {"by_url": {_URL: {"url": _URL, "status_code": 200}}}, "metadata": {}}
        cs = scanner.run_cache_scan(rd, {**_SETTINGS, "WEB_CACHE_POISON_ENABLED": True})["cache_scan"]
    finally:
        scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_s, orig_w
    assert cs["by_target"][_URL]["oracle"]["cacheable"] is False
    assert [f["impact"] for f in cs["findings"]] == ["deception"]
