"""Item 5 on urlscan's history and the takeover verdict after httpx.

The URLScan switches check the titles, Server headers and certificates urlscan
already returned (no search, no request): a problem page is one finding per
host, path and problem (per host for a server or a certificate); a
deleted-service page is only collected, and kept after httpx only when this
scan's DNS or live page confirms it. Hosts are example.test; DNS is injected.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import urlscan_enrich as u  # noqa: E402
from recon.main_recon_modules import urlscan_takeover as t  # noqa: E402
from recon.main_recon_modules.subdomain_takeover import _collect_subdomains  # noqa: E402


def _visit(url, title="", server="", status="200", uuid="u1", time="2026-10-01T00:00:00.000Z",
           visibility="public", issuer="", age=None, valid=None, mime="text/html"):
    host = url.split("/")[2]
    page = {"url": url, "domain": host, "ip": "192.88.97.10", "status": status, "title": title,
            "server": server, "mimeType": mime, "tlsIssuer": issuer}
    if age is not None:
        page.update({"tlsAgeDays": age, "tlsValidDays": valid})
    return {"page": page, "task": {"url": url, "time": time, "visibility": visibility, "uuid": uuid}}


def _run(results, **settings):
    base = {"URLSCAN_ENABLED": True}
    base.update(settings)
    with patch.object(u, "_urlscan_search", return_value=u.SearchResults(results)):
        out = u.run_urlscan_enrichment({"domain": "example.test", "metadata": {}}, base)
    return out["urlscan"]


class TestProblemPages:
    def test_a_console_is_a_finding_seen_on_urlscan(self):
        data = _run([_visit("https://nb.example.test/tree", "Home Page - Select or create a notebook")])
        f, = data["problem_pages"]
        assert (f["type"], f["kind"], f["kind_field"]) == ("open_console_seen", "jupyter_notebook_open", "problem")
        assert f["severity"] == "critical"      # the writer caps history at high
        assert f["props"]["family"] == "open_console"
        assert f["props"]["matched"] == "Home Page - Select or create a notebook"
        assert "seen on urlscan" in f["name"] and f["urlscan_scan_id"] == "u1"

    def test_a_dev_server_with_many_paths_is_one_finding(self):
        visits = [_visit(f"https://dev.example.test/p{i}", server="Werkzeug/3.0.1 Python/3.12", uuid=f"u{i}")
                  for i in range(25)]
        data = _run(visits)
        f, = data["problem_pages"]
        assert (f["type"], f["path"], f["url"]) == ("dev_server_seen", "/", "https://dev.example.test/")
        assert f["props"]["sightings"] == 25

    def test_hacked_by_on_a_blog_post_is_nothing(self):
        assert _run([_visit("https://www.example.test/blog/x", "Hacked by the cold, a winter story")])[
            "problem_pages"] == []
        f, = _run([_visit("https://www.example.test/", "Hacked by Someone")])["problem_pages"]
        assert f["type"] == "defaced_page_seen"

    def test_a_listing_title_without_iis_is_not_a_listing(self):
        assert _run([_visit("https://www.example.test/x", "www.example.test - /x")])["problem_pages"] == []
        f, = _run([_visit("https://www.example.test/x/", "www.example.test - /x/",
                          server="Microsoft-IIS/10.0")])["problem_pages"]
        assert f["kind"] == "iis_listing"

    def test_a_401_console_is_nothing(self):
        assert _run([_visit("https://ci.example.test/", "Dashboard [Jenkins]", status="401")])[
            "problem_pages"] == []

    def test_a_test_certificate_is_one_finding_per_host(self):
        data = _run([_visit(f"https://k.example.test/{p}", issuer="Kubernetes Ingress Controller Fake Certificate")
                     for p in ("a", "b")])
        f, = data["problem_pages"]
        assert (f["type"], f["kind"], f["path"]) == ("test_certificate_seen", "kubernetes_ingress_fake_cert", "/")

    def test_only_public_visits_of_target_hosts(self):
        data = _run([_visit("https://nb.example.test/", "Home Page - Select or create a notebook",
                            visibility="unlisted"),
                     _visit("https://other.test/", "Home Page - Select or create a notebook")])
        assert data["problem_pages"] == []

    def test_a_quarantined_visit_keeps_its_scan_a_masked_url_and_the_full_link(self):
        f, = _run([_visit("https://app.example.test/reset?token=abcdefabcdefabcdef1234",
                          "Whoops! There was an error.")])["problem_pages"]
        assert f["urlscan_scan_id"] == "u1" and "abcdef" not in f["url"]
        assert f["props"]["unmasked_url"] == "https://app.example.test/reset?token=abcdefabcdefabcdef1234"

    def test_switches(self):
        visits = [_visit("https://nb.example.test/", "Home Page - Select or create a notebook"),
                  _visit("https://gone.example.test/", "No such app", server="Heroku", status="404")]
        on = _run(visits)
        assert len(on["problem_pages"]) == 1 and len(on["takeover_pages"]) == 1
        off = _run(visits, URLSCAN_PROBLEM_PAGES=False, URLSCAN_TAKEOVER_PAGES=False)
        assert off["problem_pages"] == [] and off["takeover_pages"] == []
        assert len(_run(visits, URLSCAN_PROBLEM_PAGES=False)["takeover_pages"]) == 1


class TestDedupeWithExposedFiles:
    def test_an_installer_found_by_path_and_title_is_one_finding(self):
        data = _run([_visit("https://blog.example.test/wp-admin/setup-config.php",
                            "WordPress › Setup Configuration File")])
        assert [f["type"] for f in data["problem_pages"]] == ["installer_seen"]
        assert [f for f in data["findings"] if f["type"] == "sensitive_file_seen"] == []

    def test_the_path_finding_stays_when_the_title_says_nothing(self):
        data = _run([_visit("https://blog.example.test/wp-admin/setup-config.php", "Blog")])
        assert data["problem_pages"] == []
        assert [f["kind"] for f in data["findings"] if f["type"] == "sensitive_file_seen"] == ["installer"]


class TestTakeoverPagesAreOnlyCollected:
    def test_no_finding_in_group_1(self):
        data = _run([_visit("https://gone.example.test/", "No such app", server="Heroku", status="404")])
        assert [f for f in data["findings"] + data["problem_pages"] if "takeover" in f["type"]] == []
        page, = data["takeover_pages"]
        assert (page["host"], page["provider"], page["outcome"]) == ("gone.example.test", "heroku",
                                                                    "possible_takeover")


def _page(host="gone.example.test", provider="heroku", problem="heroku_no_such_app",
          outcome="possible_takeover"):
    return {"host": host, "provider": provider, "problem": problem, "label": "Heroku",
            "outcome": outcome, "matched": "No such app", "url": f"https://{host}/",
            "first_seen": "2026-09-01", "last_seen": "2026-10-01", "urlscan_scan_id": "s1"}


def _live(title, server="Heroku", status=404, host="gone.example.test"):
    return {host: [{"final_url": f"https://{host}/", "title": title, "server": server, "status": status}]}


class TestVerdict:
    def _decide(self, pages, live, cname, state):
        return t.decide(pages, live, lambda h: cname, lambda c: state)

    def test_still_points_and_healthy_now_is_nothing(self):
        found, hosts = self._decide([_page()], _live("Acme shop"), ["acme.herokuapp.com"], "resolves")
        assert found == [] and hosts == []

    def test_the_same_page_live_keeps_the_rows_outcome(self):
        (f,), hosts = self._decide([_page()], _live("No such app"), ["acme.herokuapp.com"], "resolves")
        assert (f["type"], f["kind"], f["kind_field"]) == ("takeover_page_seen", "heroku", "provider")
        assert (f["props"]["outcome"], f["severity"], f["live"]) == ("possible_takeover", "medium", True)
        assert f["props"]["cname"] == "acme.herokuapp.com" and f["props"]["cname_still_points"] is True
        assert f["props"]["verdict_basis"] == "live_page" and hosts == ["gone.example.test"]

    def test_no_live_page_and_an_nxdomain_target(self):
        (f,), _ = self._decide([_page()], {}, ["acme.herokuapp.com"], "nxdomain")
        assert (f["props"]["outcome"], f["severity"], f["live"]) == ("possible_takeover", "medium", False)
        likely = _page(host="s.example.test", provider="surge", problem="surge_project_not_found",
                       outcome="likely_takeover")
        (g,), _ = self._decide([likely], {}, ["s.surge.sh"], "nxdomain")
        assert (g["props"]["outcome"], g["severity"]) == ("likely_takeover", "high")
        dangling = _page(host="n.example.test", provider="netlify", problem="netlify_site_not_found",
                         outcome="dangling_dns")
        (d,), _ = self._decide([dangling], {}, ["n.netlify.app"], "nxdomain")
        assert d["props"]["outcome"] == "possible_takeover"

    def test_never_probed_and_the_target_resolves_is_nothing(self):
        assert self._decide([_page()], {}, ["acme.herokuapp.com"], "resolves") == ([], [])
        assert self._decide([_page()], {}, ["acme.herokuapp.com"], None) == ([], [])

    def test_no_cname_to_that_provider_is_nothing(self):
        assert self._decide([_page()], _live("No such app"), [], "nxdomain") == ([], [])        # A record
        assert self._decide([_page()], _live("No such app"), None, "nxdomain") == ([], [])      # DNS failed
        assert self._decide([_page()], _live("No such app"), ["x.cloudfront.net"], "nxdomain") == ([], [])

    def test_the_cname_comes_from_the_dns_map_then_httpx_then_one_query(self):
        dns = {"known.example.test": {"records": {"CNAME": ["a.herokuapp.com"]}},
               "arecord.example.test": {"records": {"A": ["192.88.97.10"]}}}
        live = {"probed.example.test": [{"cname": ["p.herokuapp.com"]}]}
        with patch.object(t, "query_cname", return_value=["q.herokuapp.com"]) as q:
            of = t.cname_resolver(dns, live)
            assert of("known.example.test") == ["a.herokuapp.com"]
            assert of("arecord.example.test") == []
            assert of("probed.example.test") == ["p.herokuapp.com"]
            q.assert_not_called()
            assert of("urlscan-only.example.test") == ["q.herokuapp.com"]
            q.assert_called_once_with("urlscan-only.example.test")

    def test_the_full_run_step_writes_findings_and_hosts(self):
        combined = {"urlscan": {"takeover_pages": [_page()]},
                    "dns": {"subdomains": {"gone.example.test": {"records": {"CNAME": ["acme.herokuapp.com"]}}}},
                    "http_probe": {"by_url": {"https://gone.example.test/": {
                        "host": "gone.example.test", "status_code": 404, "title": "No such app",
                        "server": "Heroku", "final_url": "https://gone.example.test/"}}}}
        out = t.run_takeover_verdict(combined, {"URLSCAN_TAKEOVER_PAGES": True})
        assert out["urlscan"]["takeover_hosts"] == ["gone.example.test"]
        assert len(out["urlscan"]["takeover_findings"]) == 1

    def test_off_or_nothing_to_decide_is_a_no_op(self):
        combined = {"urlscan": {"takeover_pages": [_page()]}}
        assert "takeover_findings" not in t.run_takeover_verdict(combined, {"URLSCAN_TAKEOVER_PAGES": False})["urlscan"]
        assert t.run_takeover_verdict({}, {}) == {}


class TestDnsGoesThroughTheBreaker:
    def test_query_and_target_state(self):
        with patch.object(t, "_cname_send", return_value=["a.herokuapp.com"]):
            assert t.query_cname("x.example.test") == ["a.herokuapp.com"]
        with patch.object(t, "_cname_send", side_effect=TimeoutError("DNS timeout")):
            assert t.query_cname("y.example.test") is None
        with patch.object(t, "resolve_cname_target", return_value={"nxdomain": True, "resolves": False}):
            assert t.target_state("gone.herokuapp.com") == "nxdomain"
        with patch.object(t, "resolve_cname_target", return_value={"nxdomain": False, "resolves": False}):
            assert t.target_state("flaky.herokuapp.com") is None


class TestHandOverToSubdomainTakeover:
    def _recon(self, hosts, **meta):
        return {"domain": "example.test", "dns": {"subdomains": {}},
                "metadata": {"scope_mode": "enumerate", "include_root_domain": True, **meta},
                "urlscan": {"takeover_hosts": hosts}}

    def test_a_kept_host_joins_the_list(self):
        assert "gone.example.test" in _collect_subdomains(self._recon(["gone.example.test"]), {})

    def test_outside_the_roe_or_the_scope_it_never_does(self):
        settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["gone.example.test"]}
        assert "gone.example.test" not in _collect_subdomains(self._recon(["gone.example.test"]), settings)
        assert "x.other.test" not in _collect_subdomains(self._recon(["x.other.test"]), {})
        exact = self._recon(["gone.example.test"], scope_mode="exact", subdomain_filter=["www.example.test"])
        assert "gone.example.test" not in _collect_subdomains(exact, {})


class TestWiring:
    SRC = (PROJECT_ROOT / "recon" / "main.py").read_text()

    def test_the_verdict_runs_after_httpx_outside_its_try_and_before_phase_a(self):
        start = self.SRC.index("def run_domain_recon")
        httpx = self.SRC.index("combined_result = run_http_probe(combined_result", start)
        httpx_except = self.SRC.index("_note_phase_error(\"http_probe\")", httpx)
        verdict = self.SRC.index("run_takeover_verdict(combined_result, _settings)", start)
        phase_a = self.SRC.index("_run_phase_a_fan_out(phase_a_tools", start)
        assert httpx_except < verdict < phase_a
        assert self.SRC.count('"update_graph_from_urlscan_takeover"') == 1

    def test_partial_urlscan_and_takeover_read_the_verdict(self):
        osint = (PROJECT_ROOT / "recon" / "partial_recon_modules" / "osint_enrichment.py").read_text()
        assert "run_partial_verdict(pages, live)" in osint
        assert "update_graph_from_urlscan_takeover" in osint
        vs = (PROJECT_ROOT / "recon" / "partial_recon_modules" / "vulnerability_scanning.py").read_text()
        assert "graph_takeover_page_hosts(user_id, project_id)" in vs


@pytest.mark.parametrize("cname,provider", [
    ("bucket.s3.eu-west-1.amazonaws.com", "aws-s3"), ("bucket.s3-us-west-2.amazonaws.com", "aws-s3"),
    ("x.herokudns.com", "heroku"), ("read.uberflip.com", "uberflip"), ("cname.canny.io", "canny"),
    ("hatenablog.com", "hatenablog"), ("www123.wixdns.net", "wix"), ("sites.framer.app", "framer"),
    ("stats.pingdom.com", "pingdom"), ("cname.animaapp.io", "anima"),
])
def test_provider_from_cname_knows_the_catalog_providers(cname, provider):
    from recon.helpers.takeover_helpers import provider_from_cname
    assert provider_from_cname(cname) == provider
