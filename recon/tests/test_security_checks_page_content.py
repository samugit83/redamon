"""Item 5, live: the Security Checks' Page Content group.

Reads the titles, Server headers and certificate issuers httpx and tlsx
already collected, against the page_signals catalog, and sends nothing (the
network is cut in every test). One toggle per check type; the full and
partial vuln scans and the certificate-only fallback pass all eight. The
partial builder gives the checks titles, the last hop, the real status and
the certificate. Hosts are example.test.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import security_checks as sc  # noqa: E402
from recon.partial_recon_modules import graph_builders as gb  # noqa: E402

TYPES = ["open_console", "debug_page", "unfinished_installer", "dev_server", "directory_listing",
         "defaced_page", "takeover_error_page", "test_certificate"]


@pytest.fixture(autouse=True)
def _no_network():
    def refuse(*a, **k):
        raise AssertionError("a Page Content check sent a request")
    with mock.patch.object(socket, "create_connection", refuse), \
            mock.patch.object(socket.socket, "connect", refuse), \
            mock.patch("requests.sessions.Session.request", refuse):
        yield


def _entry(url, title="", server="", status=200, final=None, **extra):
    return {"url": url, "host": url.split("/")[2], "status_code": status, "title": title,
            "server": server, "final_url": final or url, **extra}


def _recon(*entries, tlsx=None):
    data = {"http_probe": {"by_url": {e["url"]: e for e in entries}}}
    if tlsx:
        data["tlsx"] = {"by_target": tlsx}
    return data


def _all_on():
    return {t: True for t in TYPES}


EVERY_TYPE = _recon(
    _entry("https://nb.example.test/", "Home Page - Select or create a notebook"),
    _entry("https://err.example.test/", "Whoops! There was an error.", status=500),
    _entry("https://blog.example.test/", "WordPress › Setup Configuration File",
           final="https://blog.example.test/wp-admin/setup-config.php"),
    _entry("https://dev.example.test/", "Dev", "Werkzeug/3.0.1 Python/3.12"),
    _entry("https://files.example.test/", "Index of /"),
    _entry("https://www.example.test/", "Hacked by Someone"),
    _entry("https://gone.example.test/", "No such app", "Heroku", status=404),
    _entry("https://k.example.test/", "ok", tls={"certificate": {
        "issuer": "O=Acme Co,CN=Kubernetes Ingress Controller Fake Certificate"}}),
)


def test_every_type_from_data_already_collected():
    found = {f["type"]: f for f in sc.run_page_content_checks(EVERY_TYPE, _all_on())}
    assert sorted(found) == sorted(TYPES)
    console = found["open_console"]
    assert (console["source"], console["family"], console["problem"]) == (
        "security_check", "open_console", "jupyter_notebook_open")
    assert console["hostname"] == "nb.example.test" and console["severity"] == "critical"
    assert found["takeover_error_page"]["outcome"] == "possible_takeover"
    assert found["takeover_error_page"]["severity"] == "medium"


@pytest.mark.parametrize("off", TYPES)
def test_each_toggle_off_removes_its_type_only(off):
    enabled = {**_all_on(), off: False}
    types = {f["type"] for f in sc.run_page_content_checks(EVERY_TYPE, enabled)}
    assert off not in types and types == set(TYPES) - {off}


def test_paths_and_the_url_use_the_last_hop():
    f, = sc.run_page_content_checks(_recon(_entry(
        "https://blog.example.test/", "WordPress › Setup Configuration File",
        final="https://blog.example.test/wp-admin/setup-config.php")), _all_on())
    assert f["url"] == "https://blog.example.test/wp-admin/setup-config.php"
    # A defacement counts on the root page only: the last hop is a blog post.
    assert sc.run_page_content_checks(_recon(_entry(
        "https://www.example.test/", "Hacked by the cold", final="https://www.example.test/blog/x")),
        _all_on()) == []


def test_an_unknown_status_satisfies_no_status_rule():
    assert sc.run_page_content_checks(_recon(_entry(
        "https://ci.example.test/", "Dashboard [Jenkins]", status_unknown=True)), _all_on()) == []
    assert sc.run_page_content_checks(_recon(_entry(
        "https://ci.example.test/", "Dashboard [Jenkins]", status=401)), _all_on()) == []


def test_a_server_or_a_certificate_is_one_finding_per_host():
    entries = [_entry(f"https://dev.example.test/p{i}", "x", "Werkzeug/3.0.1 Python/3.12") for i in range(5)]
    found = sc.run_page_content_checks(_recon(*entries), _all_on())
    assert [(f["type"], f["url"]) for f in found] == [("dev_server", "https://dev.example.test")]


def test_a_nameless_certificate_is_read_for_its_issuer():
    data = _recon(_entry("https://k.example.test/", "ok", tls={"certificate": {
        "issuer_dn": "CN=TRAEFIK DEFAULT CERT", "issuer_cn": "TRAEFIK DEFAULT CERT"}}))
    f, = sc.run_page_content_checks(data, _all_on())
    assert (f["type"], f["problem"]) == ("test_certificate", "traefik_default_cert")
    # The name checks still skip it: nothing to compare.
    assert sc.run_tls_data_checks(data, {}) == []


def test_tlsx_issuer_and_staging():
    data = _recon(tlsx={"k:443": {"probe_status": True, "host": "stage.example.test", "port": 443,
                                  "subject_cn": "stage.example.test",
                                  "issuer_dn": "CN=(STAGING) Artificial Apricot R3,O=(STAGING) Let's Encrypt",
                                  "issuer_cn": "(STAGING) Artificial Apricot R3"}})
    f, = sc.run_page_content_checks(data, _all_on())
    assert (f["problem"], f["url"], f["hostname"]) == ("letsencrypt_staging", "https://stage.example.test",
                                                       "stage.example.test")


def test_the_certificate_only_fallback_runs_the_issuer_rule():
    data = _recon(_entry("https://k.example.test/", "Home Page - Select or create a notebook", tls={
        "certificate": {"issuer": "CN=Kubernetes Ingress Controller Fake Certificate"}}))
    checks = sc.run_cert_hygiene_checks_only(data, {"test_certificate": True})["security_checks"]
    assert [f["type"] for f in checks["findings"]] == ["test_certificate"]
    assert sc.run_cert_hygiene_checks_only(data, {"test_certificate": False})["security_checks"]["findings"] == []


def test_the_toggles_reach_every_enabled_checks_dict():
    names = {t: key for t, (_f, key) in sc.PAGE_CONTENT_CHECKS.items()}
    assert sorted(names) == sorted(TYPES)
    settings = {key: False for key in names.values()}
    assert sc.page_content_enabled(settings) == {t: False for t in TYPES}
    assert sc.page_content_enabled({}) == {t: True for t in TYPES}
    for rel in ("recon/main_recon_modules/vuln_scan.py", "recon/partial_recon_modules/vulnerability_scanning.py"):
        assert "**page_content_enabled(settings)" in (PROJECT_ROOT / rel).read_text(), rel
    main = (PROJECT_ROOT / "recon" / "main.py").read_text()
    assert '"test_certificate": "SECURITY_CHECK_TEST_CERTIFICATES"' in main


def test_run_security_checks_calls_it_and_the_master_switch_gates_it():
    src = (PROJECT_ROOT / "recon" / "helpers" / "security_checks.py").read_text()
    body = src[src.index("def _run_security_checks"):]
    assert "run_page_content_checks(recon_data, enabled_checks)" in body
    vs = (PROJECT_ROOT / "recon" / "main_recon_modules" / "vuln_scan.py").read_text()
    gate = vs.index("if not SECURITY_CHECK_ENABLED:")
    assert gate < vs.index("**page_content_enabled(settings)")


class _Session:
    def __init__(self, rows):
        self.rows, self.queries = rows, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.queries.append(" ".join(query.split()))
        result = mock.MagicMock()
        rows = self.rows if "probe.title AS title" in query else []
        result.__iter__ = lambda s: iter(rows)
        result.single.return_value = None
        return result


def _build(rows):
    session = _Session(rows)
    client = mock.MagicMock()
    client.verify_connection.return_value = True
    client.driver.session.side_effect = lambda: session
    cls = mock.MagicMock()
    cls.return_value.__enter__ = mock.MagicMock(return_value=client)
    cls.return_value.__exit__ = mock.MagicMock(return_value=False)
    with mock.patch.dict("sys.modules", {"graph_db": mock.MagicMock(Neo4jClient=cls)}), \
            mock.patch.object(gb, "graph_url_scope", return_value=lambda host: True):
        data = gb._build_vuln_scan_data_from_graph(["example.test"], "u1", "p1", include_root_domain=True)
    return data, session.queries


ROW = {"url": "https://ci.example.test", "status_code": 200, "host": "ci.example.test",
       "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None, "server": "Jetty",
       "title": "Dashboard [Jenkins]", "final_url": "https://ci.example.test/", "cname": ["ci.herokuapp.com"],
       "cert": {"issuer": "CN=R11", "issuer_cn": "R11", "subject_cn": "ci.example.test", "san": []}}


class TestPartialBuilder:
    def test_it_reads_title_last_hop_cname_and_certificate(self):
        data, queries = _build([ROW])
        q = next(q for q in queries if "probe.title AS title" in q)
        assert "OPTIONAL MATCH (b)-[:HAS_CERTIFICATE]->(c:Certificate)" in q
        entry = data["http_probe"]["by_url"]["https://ci.example.test"]
        assert (entry["title"], entry["final_url"], entry["cname"]) == (
            "Dashboard [Jenkins]", "https://ci.example.test/", ["ci.herokuapp.com"])
        assert entry["tls"]["certificate"]["issuer_cn"] == "R11"
        assert "status_unknown" not in entry

    def test_the_real_status_a_5xx_kept_an_unknown_one_marked(self):
        data, _ = _build([{**ROW, "url": "https://err.example.test", "host": "err.example.test",
                           "status_code": 500, "title": "Whoops! There was an error."},
                          {**ROW, "url": "https://new.example.test", "host": "new.example.test",
                           "status_code": None}])
        by_url = data["http_probe"]["by_url"]
        assert by_url["https://err.example.test"]["status_code"] == 500
        assert by_url["https://new.example.test"]["status_unknown"] is True
        found = {f["type"] for f in sc.run_page_content_checks(data, _all_on())}
        assert found == {"debug_page"}     # the unknown status is no 200 for Jenkins

    def test_the_target_builders_still_skip_5xx(self):
        from recon.helpers.target_helpers import build_target_urls_from_httpx
        data, _ = _build([{**ROW, "url": "https://err.example.test", "host": "err.example.test",
                           "status_code": 503}, ROW])
        assert build_target_urls_from_httpx(data["http_probe"]) == ["https://ci.example.test"]
