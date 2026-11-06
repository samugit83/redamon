"""S2 / B05 / B06 / B07: readers that turn stored URLs into requests skip
quarantined Endpoints, in partial recon and in the rate-limit check.

Partial recon rebuilds nuclei DAST URLs from every Endpoint -> Parameter and
every e.full_url, and Route Exposure reads every Endpoint path; the
no_rate_limiting check (on by default) sends a GET and ten POSTs to any known
URL that looked like a login. The gate has no Neo4j, so the builders run
against a session that records each query: every Endpoint read must carry the
quarantine predicate.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import graph_builders as gb  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

TOK = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"
_ENDPOINT_READ = re.compile(r"\(e:Endpoint|->\(e:Endpoint")


def _recording_client():
    queries = []
    session = MagicMock()

    def run(query, *a, **kw):
        queries.append(query)
        result = MagicMock()
        result.__iter__.return_value = iter([])
        result.single.return_value = None
        return result
    session.run.side_effect = run
    client = MagicMock()
    client.__enter__.return_value = client
    client.verify_connection.return_value = True
    client.driver.session.return_value.__enter__.return_value = session
    return client, queries


@pytest.mark.parametrize("builder,kwargs", [
    ("_build_vuln_scan_data_from_graph", {}),
    ("_build_route_exposure_data_from_graph", {}),
    ("_build_graphql_data_from_graph", {"settings": {}}),
])
def test_b05_b07_every_endpoint_read_skips_quarantined(builder, kwargs):
    client, queries = _recording_client()
    with patch("graph_db.Neo4jClient", return_value=client):
        getattr(gb, builder)(["example.test"], "u", "p", **kwargs)
    endpoint_reads = [q for q in queries if _ENDPOINT_READ.search(q) and "RETURN" in q
                      and ("e.path" in q or "full_url" in q)]
    assert endpoint_reads, f"{builder} read no Endpoint"
    for q in endpoint_reads:
        assert gb.quarantined("e") in q, q


def test_the_full_url_read_is_filtered():
    client, queries = _recording_client()
    with patch("graph_db.Neo4jClient", return_value=client):
        gb._build_vuln_scan_data_from_graph(["example.test"], "u", "p")
    full_url_reads = [q for q in queries if "e.full_url AS url" in q]
    assert full_url_reads and all(gb.quarantined("e") in q for q in full_url_reads)


@pytest.mark.parametrize("module", [
    "parameter_discovery", "web_crawling", "js_analysis", "supply_chain", "openapi_recon",
    "ai_surface_recon",
])
def test_other_partial_readers_name_the_predicate(module):
    source = (PROJECT_ROOT / "recon" / "partial_recon_modules" / f"{module}.py").read_text()
    assert "quarantined" in source


class TestB06RateLimitCheck:
    def _urls_tested(self, urls, hostname="auth.example.test"):
        sent = []

        def fake_get(url, **kw):
            sent.append(("GET", url))
            r = MagicMock()
            r.status_code = 404
            return r
        with patch.object(sc, "_hh_get", side_effect=fake_get), \
                patch.object(sc, "_hh_post", side_effect=AssertionError("POST")):
            sc.check_no_rate_limiting(urls, hostname, timeout=1)
        return {u for _m, u in sent}

    def test_b06_host_and_query_words_do_not_make_a_login_page(self):
        sent = self._urls_tested(["https://auth.example.test/about",
                                  "https://auth.example.test/page?token=x",
                                  "https://auth.example.test/login"])
        assert "https://auth.example.test/login" in sent
        assert "https://auth.example.test/about" not in sent
        assert "https://auth.example.test/page" not in sent

    def test_b06_quarantined_or_masked_paths_are_never_requested(self):
        sent = self._urls_tested([f"https://auth.example.test/password/reset/{TOK}",
                                  "https://auth.example.test/password/reset/{token}",
                                  f"https://auth.example.test/login?token={TOK}",
                                  "https://auth.example.test/signin"])
        assert sent == {"https://auth.example.test/signin"}

    def test_b06_a_subdomain_url_is_not_retested_in_the_apex_pass(self):
        sent = self._urls_tested(["https://sso.example.test/login"], hostname="example.test")
        assert "https://sso.example.test/login" not in sent

    def test_b06_whole_words_only(self):
        assert sc._is_login_path("/wp-login.php")
        assert sc._is_login_path("/api/v1/sign-in")
        assert not sc._is_login_path("/blog/authors")
        assert not sc._is_login_path("/tokens-of-appreciation/x")

    def test_b06_archive_only_urls_never_reach_the_check(self):
        seen = {}

        def fake_check(urls, hostname, timeout):
            seen[hostname] = sorted(urls)
            return []
        recon = {
            "resource_enum": {
                "discovered_urls": ["https://a.example.test/login",
                                    "https://a.example.test/old/login?x=***",
                                    "https://a.example.test/both/login"],
                "archived_urls": ["https://a.example.test/old/login?x=***"],
            },
            "vuln_scan": {"discovered_urls": {"all_scanned_urls": ["https://a.example.test/old/login?x=1"]}},
            "http_probe": {"by_url": {"https://a.example.test/both/login": {}}},
        }
        with patch.object(sc, "check_no_rate_limiting", side_effect=fake_check), \
                patch.object(sc, "_host_down", return_value=False):
            sc.run_rate_limit_checks(["a.example.test"], recon, {"no_rate_limiting": True})
        assert seen["a.example.test"] == ["https://a.example.test/both/login",
                                          "https://a.example.test/login"]
