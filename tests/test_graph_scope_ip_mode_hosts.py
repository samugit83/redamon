"""IP mode: the graph writers' scope admits the selected hostnames, and only them (P4).

An IP-mode run's synthetic root (`ip-targets.<project>`) is no parent of a real
name, so classify_host had no answer for a hostname the selection rule chose to
scan: every writer that asks it (the external-domains aggregator's cross-root
branch, the OSINT writers) read it as an ExternalDomain. The run now lists its
selected names in metadata.ip_mode_hosts (name -> org domain); classify_host
admits exactly those, under their org Domain, and leaves every other host as
before (recorded names stay ExternalDomains, invariant I-4).

The finding writers (vuln, resource, JS recon) gate on build_host_scope, which
already reads the run's scope list: a selected name is in it, a recorded one is
not, so a finding on the first is kept and on the second dropped.

Fake sessions record each statement. Documentation ranges and reserved names only.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402
from graph_db.mixins.recon.scope import (  # noqa: E402
    IN_SCOPE, OUT_OF_SCOPE, attach_for_host, build_host_scope, classify_host, host_in_scope,
    scan_root_for_host,
)
from graph_db.mixins.recon.vuln_mixin import VulnMixin  # noqa: E402

T1 = "203.0.113.10"
MOCK = "ip-targets.cmscopeipmodehosts00000001"
APP, SHOP, OLD = "app.example.com", "shop.example.net", "old.example.com"


def _recon(ip_mode=True, hosts=None):
    hosts = {APP: "example.com", SHOP: "example.net"} if hosts is None else hosts
    return {
        "domain": MOCK,
        "subdomains": ["203-0-113-10", *hosts],
        "metadata": {"ip_mode": ip_mode, "root_domain": MOCK, "expanded_ips": [T1],
                     "subdomain_filter": [T1, "203-0-113-10", *hosts], "ip_mode_hosts": dict(hosts)},
    }


class TestClassifyHost(unittest.TestCase):
    def test_a_selected_name_is_in_scope_under_its_org(self):
        self.assertEqual(classify_host(APP, _recon()), (IN_SCOPE, "example.com"))
        self.assertEqual(attach_for_host(SHOP, _recon()), (IN_SCOPE, "example.net"))
        self.assertEqual(scan_root_for_host(APP, _recon()), "example.com")

    def test_any_spelling_of_the_selected_name(self):
        for value in ("APP.Example.com.", f"https://{APP}:8443/login", f"{APP}:443"):
            self.assertEqual(classify_host(value, _recon()), (IN_SCOPE, "example.com"), value)

    def test_a_recorded_name_stays_out_of_scope(self):
        self.assertEqual(classify_host(OLD, _recon()), (OUT_OF_SCOPE, None))
        self.assertEqual(attach_for_host(OLD, _recon()), (OUT_OF_SCOPE, None))

    def test_without_selected_names_nothing_changes(self):
        for recon in (_recon(hosts={}), {**_recon(), "metadata": {"ip_mode": True, "root_domain": MOCK}}):
            self.assertEqual(classify_host(APP, recon), (OUT_OF_SCOPE, None))
        # The synthetic root and the addresses keep their old answers.
        self.assertEqual(classify_host(MOCK, _recon()), (IN_SCOPE, MOCK))
        self.assertEqual(classify_host(T1, _recon()), (OUT_OF_SCOPE, None))

    def test_domain_mode_ignores_the_ip_mode_list(self):
        recon = {"domain": "example.org", "metadata": {"ip_mode": False, "ip_mode_hosts": {APP: "example.com"}}}
        self.assertEqual(classify_host(APP, recon), (OUT_OF_SCOPE, None))
        self.assertEqual(classify_host("www.example.org", recon), (IN_SCOPE, "example.org"))

    def test_an_entry_without_an_org_is_not_admitted(self):
        self.assertEqual(classify_host(APP, _recon(hosts={APP: None})), (OUT_OF_SCOPE, None))


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = {"is_new": True}
        return result


class _Writer(OsintMixin, VulnMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


class TestTheAggregatorOnASelectedName(unittest.TestCase):
    def test_a_redirect_to_a_selected_name_is_its_subdomain_and_a_recorded_one_external(self):
        w = _Writer()
        recon = _recon()
        recon["external_domains_aggregated"] = [
            {"domain": APP, "sources": ["http_probe_redirect"], "redirect_from_urls": [f"https://{T1}/"]},
            {"domain": OLD, "sources": ["http_probe_redirect"], "redirect_from_urls": [f"https://{T1}/"]},
        ]
        w.update_graph_from_external_domains(recon, "u1", "p1")
        subdomain = [p for q, p in w.session.calls if "MERGE (s:Subdomain" in q]
        external = [p for q, p in w.session.calls if "MERGE (ed:ExternalDomain" in q]
        self.assertEqual([(p["name"], p["domain"]) for p in subdomain], [(APP, "example.com")])
        self.assertEqual([p["ed_domain"] for p in external], [OLD])


class TestFindingWritersKeepSelectedNamesOnly(unittest.TestCase):
    def test_the_shared_scope_admits_selected_names_and_targets(self):
        scope = build_host_scope(_recon())
        for host in (APP, f"https://{SHOP}/x", T1):
            self.assertTrue(host_in_scope(host, scope), host)
        self.assertFalse(host_in_scope(OLD, scope))

    def test_the_vuln_writer_keeps_a_selected_names_endpoint_and_drops_a_recorded_ones(self):
        w = _Writer()
        recon = _recon()
        recon["vuln_scan"] = {"discovered_urls": {"dast_urls_with_params": [
            f"https://{APP}/search?q=1", f"https://{OLD}/search?q=1"]}, "by_target": {}}
        w.update_graph_from_vuln_scan(recon, "u1", "p1")
        endpoints = [p["baseurl"] for q, p in w.session.calls if "MERGE (e:Endpoint" in q]
        self.assertEqual(endpoints, [f"https://{APP}"])


if __name__ == "__main__":
    unittest.main()
