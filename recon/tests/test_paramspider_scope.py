"""ParamSpider URLs are scope-filtered before any use (R-15).

``paramspider -d example.com`` returns every archived URL under the domain,
including hosts the run does not scan: a sibling subdomain the RoE excludes,
or a child of a listed host. run_resource_enum used to put those raw URLs into
``discovered_urls`` (nuclei builds its DAST list from it) and into the crawl
graph (``by_base_url``, whose ParamSpider merge accepted any subdomain of a
target host). Only URLs whose host is one of the run's target hosts, and not
RoE-excluded, may reach either; GAU's URLs already pass that filter.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.url_leaks import mask_url  # noqa: E402
from recon.main_recon_modules import resource_enum  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

HOST = "app.example.com"
EXCLUDED_TARGET = "pay.example.com"

IN_SCOPE = f"https://{HOST}/search?q=FUZZ"
SIBLING = "https://www.example.com/item?id=FUZZ"
CHILD = f"https://dev.{HOST}/login?next=FUZZ"
FOREIGN = "https://cdn.example.org/asset?v=FUZZ"
ON_EXCLUDED_TARGET = f"https://{EXCLUDED_TARGET}/checkout?amount=FUZZ"

OUT_OF_SCOPE = (SIBLING, CHILD, FOREIGN)

BASE = {
    "KATANA_ENABLED": False, "HAKRAWLER_ENABLED": False, "GAU_ENABLED": False,
    "PARAMSPIDER_ENABLED": True, "KITERUNNER_ENABLED": False, "JSLUICE_ENABLED": False,
    "FFUF_ENABLED": False, "ARJUN_ENABLED": False, "ZAP_AJAX_SPIDER_ENABLED": False,
    "OPENAPI_ENABLED": False, "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False,
}


def _resource_enum(paramspider_urls, hosts=(HOST,), **settings):
    hosts = list(hosts)
    patches = [
        mock.patch.object(resource_enum, "run_paramspider_discovery",
                          return_value=(list(paramspider_urls), {})),
        mock.patch.object(resource_enum, "_archive_preflight", return_value=None),
        mock.patch.object(resource_enum, "is_docker_installed", return_value=True),
        mock.patch.object(resource_enum, "is_docker_running", return_value=True),
        mock.patch.object(resource_enum, "extract_targets_from_recon",
                          return_value=(set(), set(hosts), {})),
        mock.patch.object(resource_enum, "build_target_urls",
                          return_value=[f"https://{h}/" for h in hosts]),
        mock.patch.object(resource_enum, "pull_ffuf_binary_check", return_value=True),
    ]
    for p in patches:
        p.start()
    try:
        return resource_enum.run_resource_enum(
            {"domain": "example.com"}, settings={**BASE, **settings})["resource_enum"]
    finally:
        for p in patches:
            p.stop()


def _hosts_in(resource_enum_out):
    return set(resource_enum_out["by_base_url"])


@pytest.fixture
def nuclei(monkeypatch):
    """run_vuln_scan with docker and the nuclei passes stubbed; records what
    each pass was handed, read from its targets file."""
    passes = {}

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        targets = Path(output_file).parent / (
            "targets_dast.txt" if label == "DAST" else "targets_detection.txt")
        passes[label] = targets.read_text().split()
        return [], [], 1.0, 0

    monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vs, "is_docker_running", lambda: True)
    monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
    monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon", lambda rd: ([], [HOST], {}))
    monkeypatch.setattr(vs, "build_target_urls",
                        lambda h, i, rd, scan_all_ips=False: [f"https://{HOST}"])
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
    monkeypatch.setattr(vs, "_execute_nuclei_pass", fake_pass)
    return passes


def _dast(resource_enum_out, passes):
    settings = {"NUCLEI_ENABLED": True, "NUCLEI_DAST_MODE": True, "NUCLEI_TAGS": ["cve"],
                "NUCLEI_AUTO_UPDATE_TEMPLATES": False, "CVE_LOOKUP_ENABLED": False,
                "SECURITY_CHECK_ENABLED": False, "NUCLEI_MAX_RUNTIME": 0}
    out = vs.run_vuln_scan({"domain": "example.com", "http_probe": {"by_url": {}},
                            "resource_enum": resource_enum_out}, settings=settings)
    return out["vuln_scan"]["discovered_urls"]["dast_urls_with_params"], passes.get("DAST", [])


class TestFullPipeline:
    def test_out_of_scope_urls_are_not_discovered(self):
        out = _resource_enum([IN_SCOPE, *OUT_OF_SCOPE])
        assert out["discovered_urls"] == [mask_url(IN_SCOPE)]

    def test_out_of_scope_urls_never_reach_the_dast_pass(self, nuclei):
        out = _resource_enum([IN_SCOPE, *OUT_OF_SCOPE])
        reported, handed = _dast(out, nuclei)
        assert reported == [mask_url(IN_SCOPE)]
        assert handed == [mask_url(IN_SCOPE)]

    def test_out_of_scope_urls_are_not_archived_urls(self):
        out = _resource_enum([IN_SCOPE, *OUT_OF_SCOPE])
        assert out["archived_urls"] == [mask_url(IN_SCOPE)]

    def test_a_child_of_a_target_host_gets_no_endpoint(self):
        # The merge's own filter accepts any subdomain of a target host; the
        # run scans its listed hosts only, as GAU's filter does.
        out = _resource_enum([IN_SCOPE, *OUT_OF_SCOPE])
        assert _hosts_in(out) == {f"https://{HOST}"}

    def test_out_of_scope_urls_are_counted(self):
        out = _resource_enum([IN_SCOPE, *OUT_OF_SCOPE])
        stats = out["scan_metadata"]["paramspider_stats"]
        assert stats["paramspider_total"] == 4
        assert stats["paramspider_out_of_scope"] == 3
        assert stats["paramspider_new"] == 1
        assert out["scan_metadata"]["paramspider_urls_found_total"] == 4

    def test_an_roe_excluded_target_host_is_dropped_too(self, nuclei):
        out = _resource_enum([IN_SCOPE, ON_EXCLUDED_TARGET], hosts=(HOST, EXCLUDED_TARGET),
                             ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[EXCLUDED_TARGET])
        assert out["discovered_urls"] == [mask_url(IN_SCOPE)]
        assert EXCLUDED_TARGET not in str(out["by_base_url"])
        _reported, handed = _dast(out, nuclei)
        assert handed == [mask_url(IN_SCOPE)]

    def test_the_roe_list_is_ignored_when_the_roe_is_off(self):
        out = _resource_enum([IN_SCOPE, ON_EXCLUDED_TARGET], hosts=(HOST, EXCLUDED_TARGET),
                             ROE_ENABLED=False, ROE_EXCLUDED_HOSTS=[EXCLUDED_TARGET])
        assert out["discovered_urls"] == sorted([mask_url(IN_SCOPE), mask_url(ON_EXCLUDED_TARGET)])

    def test_host_match_ignores_case_and_port(self):
        upper = "https://APP.Example.com:8443/view?id=FUZZ"
        out = _resource_enum([upper])
        assert out["discovered_urls"] == [mask_url(upper)]

    def test_in_scope_urls_are_unchanged(self):
        second = f"http://{HOST}/old.php?page=FUZZ&lang=FUZZ"
        out = _resource_enum([IN_SCOPE, second])
        assert out["discovered_urls"] == sorted([mask_url(IN_SCOPE), mask_url(second)])
        assert out["scan_metadata"]["paramspider_stats"]["paramspider_out_of_scope"] == 0
