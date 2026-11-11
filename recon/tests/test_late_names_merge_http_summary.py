"""B-30: a late probe's results join the run's http_probe whole.

`_merge_http_probe` took by_url, by_host and technologies_found and nothing
else: the late probe's external domains (redirects off the host) were lost, its
servers were never listed, a technology both probes found kept only the late
probe's URLs, and the run's summary still counted the first probe alone, so
the graph's Domain stamp and the reports under-counted live URLs. Both modes
merge through it (domain-mode certificate SAN / JS names, IP-mode selected
names), so domain mode is pinned here too.

Reserved names and documentation addresses only.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import late_names as ln  # noqa: E402

WWW, SAN = "https://www.example.test", "https://san.example.test"


def _run():
    return {"http_probe": {
        "by_url": {WWW: {"host": "www.example.test", "status_code": 200, "is_cdn": False}},
        "by_host": {"www.example.test": {"hostname": "www.example.test", "urls": [WWW], "live_urls": [WWW]}},
        "technologies_found": {"nginx": [WWW]},
        "servers_found": {"nginx/1.25": [WWW]},
        "external_domains": [{"domain": "idp.other.test", "url": "https://idp.other.test/",
                              "redirect_from_url": WWW, "source": "http_probe_redirect"}],
        "summary": {"total_urls_probed": 1, "live_urls": 1, "total_hosts": 1, "by_status_code": {"200": 1},
                    "unique_technologies": ["nginx"], "technology_count": 1, "unique_servers": ["nginx/1.25"],
                    "server_count": 1, "cdn_hosts": 0, "filtered_out_of_scope": 2,
                    "ai_header_matches": 1, "ai_favicon_matches": 0, "ai_title_matches": 0,
                    "ai_wappalyzer_matches": 0},
    }}


def _late():
    return {
        "by_url": {SAN: {"host": "san.example.test", "status_code": 503, "is_cdn": True},
                   SAN + ":8443": {"host": "san.example.test", "status_code": 200, "is_cdn": True}},
        "by_host": {"san.example.test": {"hostname": "san.example.test", "urls": [SAN, SAN + ":8443"],
                                         "live_urls": [SAN + ":8443"]}},
        "technologies_found": {"nginx": [SAN + ":8443"], "php": [SAN + ":8443"]},
        "servers_found": {"nginx/1.25": [SAN + ":8443"]},
        "external_domains": [
            {"domain": "idp.other.test", "url": "https://idp.other.test/", "redirect_from_url": WWW,
             "source": "http_probe_redirect"},
            {"domain": "cdn.other.test", "url": "https://cdn.other.test/", "redirect_from_url": SAN,
             "source": "http_probe_redirect"}],
        "summary": {"total_urls_probed": 2, "live_urls": 1, "filtered_out_of_scope": 1,
                    "ai_header_matches": 0, "ai_favicon_matches": 2, "ai_title_matches": 0,
                    "ai_wappalyzer_matches": 1},
    }


def test_new_urls_are_returned_and_merged():
    run = _run()
    assert sorted(ln._merge_http_probe(run, _late())) == [SAN, SAN + ":8443"]
    assert set(run["http_probe"]["by_url"]) == {WWW, SAN, SAN + ":8443"}
    assert set(run["http_probe"]["by_host"]) == {"www.example.test", "san.example.test"}


def test_url_lists_are_unions_not_replacements():
    run = _run()
    ln._merge_http_probe(run, _late())
    assert run["http_probe"]["technologies_found"] == {"nginx": [WWW, SAN + ":8443"], "php": [SAN + ":8443"]}
    assert run["http_probe"]["servers_found"] == {"nginx/1.25": [WWW, SAN + ":8443"]}


def test_external_domains_are_merged_once():
    run = _run()
    ln._merge_http_probe(run, _late())
    assert [e["domain"] for e in run["http_probe"]["external_domains"]] == ["idp.other.test", "cdn.other.test"]


def test_the_summary_counts_both_probes():
    run = _run()
    ln._merge_http_probe(run, _late())
    s = run["http_probe"]["summary"]
    assert s["total_urls_probed"] == 3
    assert s["live_urls"] == 2
    assert s["total_hosts"] == 2
    assert s["by_status_code"] == {"200": 2, "503": 1}
    assert (s["unique_technologies"], s["technology_count"]) == (["nginx", "php"], 2)
    assert (s["unique_servers"], s["server_count"]) == (["nginx/1.25"], 1)
    assert s["cdn_hosts"] == 1
    assert s["filtered_out_of_scope"] == 3
    assert (s["ai_header_matches"], s["ai_favicon_matches"], s["ai_wappalyzer_matches"]) == (1, 2, 1)


def test_a_run_without_an_earlier_probe_takes_the_late_one():
    run = {}
    ln._merge_http_probe(run, _late())
    s = run["http_probe"]["summary"]
    assert (s["total_urls_probed"], s["live_urls"], s["filtered_out_of_scope"]) == (2, 1, 1)
    assert len(run["http_probe"]["external_domains"]) == 2


def test_the_subset_the_graph_gets_carries_the_runs_summary():
    """The http writer stamps the summary's live URLs on the Domain: the late
    probe's own would replace the run's count with its few."""
    run = {"domain": "example.test", "metadata": {}, "dns": {"subdomains": {
        "san.example.test": {"has_records": True, "ips": {"ipv4": ["192.0.2.12"], "ipv6": []}}}},
        "port_scan": {"by_ip": {"192.0.2.12": {"ports": [443]}}, "by_host": {}}, **_run()}

    def prober(sub, output_file=None, settings=None):
        sub["http_probe"] = _late()

    from unittest.mock import patch
    with patch.object(ln, "give_dns", lambda c, names, s, lookup=None: list(names)):
        sub = ln.scan_late_names(run, ["san.example.test"], {}, probe_http=True, label="SAN",
                                 http_prober=prober)
    assert sub["http_probe"]["summary"] == run["http_probe"]["summary"]
    assert sub["http_probe"]["summary"]["total_urls_probed"] == 3
    assert set(sub["http_probe"]["by_url"]) == {SAN, SAN + ":8443"}


def test_a_merge_never_lowers_the_runs_technology_or_server_counts():
    """http_probe folds Wappalyzer's technologies into each row and the
    summary, never into technologies_found: recounting from that map alone
    dropped them, and Domain.http_probe_technology_count shrank after a late
    merge."""
    run = _run()
    run["http_probe"]["by_url"][WWW]["technologies"] = ["nginx", "WordPress"]
    run["http_probe"]["summary"].update(unique_technologies=["WordPress", "nginx", "jQuery"],
                                        technology_count=3, wappalyzer_additions=2,
                                        unique_servers=["nginx/1.25", "Apache"], server_count=2)
    ln._merge_http_probe(run, _late())
    s = run["http_probe"]["summary"]
    assert s["unique_technologies"] == ["WordPress", "jQuery", "nginx", "php"]
    assert s["technology_count"] == 4
    assert s["unique_servers"] == ["Apache", "nginx/1.25"] and s["server_count"] == 2
    assert s["wappalyzer_additions"] == 2


def test_a_count_with_no_name_list_is_still_the_floor():
    run = _run()
    run["http_probe"]["summary"]["technology_count"] = 9
    ln._merge_http_probe(run, _late())
    assert run["http_probe"]["summary"]["technology_count"] == 9


def test_dropping_a_host_keeps_the_technologies_other_rows_still_show():
    run = _run()
    run["http_probe"]["by_url"][WWW]["technologies"] = ["nginx", "WordPress"]
    ln._merge_http_probe(run, _late())
    ln.drop_http_rows(run["http_probe"], "san.example.test")
    s = run["http_probe"]["summary"]
    # php was only on the dropped host; WordPress (a Wappalyzer find) stays.
    assert s["unique_technologies"] == ["WordPress", "nginx"] and s["technology_count"] == 2


def test_junk_shapes_are_ignored():
    run = _run()
    assert ln._merge_http_probe(run, {"by_url": None, "technologies_found": [], "external_domains": "x"}) == []
    assert run["http_probe"]["by_url"] == _run()["http_probe"]["by_url"]
    assert run["http_probe"]["summary"]["total_urls_probed"] == 1
