"""OSINT writers: a host found while scanning one root may belong to another.

Every OSINT writer decided "in scope" as "equals or ends with recon_data['domain']"
and attached in-scope hosts to that one Domain. A partial run over a Domain
batch (and a full batch run, one group at a time) carries every project root in
recon_data['domains'], so:

  - a host under another project root becomes that root's Subdomain, never an
    ExternalDomain;
  - a host under no root keeps today's out-of-scope branch, linked to the root
    that was being scanned;
  - IP mode is unchanged: its synthetic root is no parent of a real name.

Fixture roots are alpha.test / beta.test / gamma.test only.

Run with:
    python3 -m pytest tests/test_osint_writers_multi_root.py -v
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402

ROOTS = ["alpha.test", "beta.test", "gamma.test"]


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
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def attached(self):
        """{subdomain: root} from every Subdomain -> Domain link issued."""
        return {p["name"]: p["domain"] for q, p in self.session.calls
                if "HAS_SUBDOMAIN" in q and "name" in p}

    def subdomains_merged(self):
        return sorted({p["name"] for q, p in self.session.calls
                       if "MERGE (s:Subdomain" in q and "name" in p})

    def externals(self):
        return {p["ed_domain"]: p.get("domain") for q, p in self.session.calls
                if "ExternalDomain" in q and "ed_domain" in p}


def _recon(key, payload, domain="alpha.test", roots=ROOTS):
    return {"domain": domain, "domains": list(roots), key: payload}


class TestShodan(unittest.TestCase):
    PAYLOAD = {
        "hosts": [],
        "reverse_dns": {"10.0.2.9": ["mail.beta.test", "cdn.thirdparty.example", "www.alpha.test"]},
        "domain_dns": {"subdomains": ["dev"]},
    }

    def test_a_host_under_another_root_joins_that_root(self):
        w = _Writer()
        w.update_graph_from_shodan(_recon("shodan", self.PAYLOAD), "u1", "p1")
        attached = w.attached()
        self.assertEqual(attached["mail.beta.test"], "beta.test")
        self.assertEqual(attached["www.alpha.test"], "alpha.test")
        self.assertNotIn("mail.beta.test", w.externals())

    def test_a_host_under_no_root_stays_external_of_the_scanned_root(self):
        w = _Writer()
        w.update_graph_from_shodan(_recon("shodan", self.PAYLOAD), "u1", "p1")
        self.assertEqual(w.externals(), {"cdn.thirdparty.example": "alpha.test"})

    def test_domain_dns_names_are_built_on_the_scanned_root(self):
        w = _Writer()
        w.update_graph_from_shodan(_recon("shodan", self.PAYLOAD, domain="gamma.test"), "u1", "p1")
        self.assertEqual(w.attached()["dev.gamma.test"], "gamma.test")

    def test_ip_mode_is_unchanged(self):
        w = _Writer()
        payload = {"hosts": [], "reverse_dns": {"192.0.2.10": ["host.example.net"]}}
        w.update_graph_from_shodan(
            _recon("shodan", payload, domain="ip-targets.p1", roots=["ip-targets.p1"]), "u1", "p1")
        self.assertEqual(w.attached(), {})
        self.assertEqual(w.externals(), {"host.example.net": "ip-targets.p1"})

    def test_a_single_root_write_keeps_the_old_scope(self):
        w = _Writer()
        recon = {"domain": "alpha.test", "shodan": self.PAYLOAD}   # no `domains`: legacy
        w.update_graph_from_shodan(recon, "u1", "p1")
        self.assertIn("mail.beta.test", w.externals())
        self.assertEqual(w.attached().get("www.alpha.test"), "alpha.test")


class TestCensys(unittest.TestCase):
    def test_rdns_names_join_their_own_root(self):
        w = _Writer()
        payload = {"hosts": [{"ip": "10.0.2.9",
                              "reverse_dns_names": ["a.beta.test", "z.other.example", "b.gamma.test"]}]}
        w.update_graph_from_censys(_recon("censys", payload), "u1", "p1")
        self.assertEqual(w.attached(), {"a.beta.test": "beta.test", "b.gamma.test": "gamma.test"})


class TestFofa(unittest.TestCase):
    def test_a_host_with_a_port_joins_its_root(self):
        w = _Writer()
        # A FOFA row always has a port; the writer skips a row without one.
        payload = {"results": [{"ip": "10.0.2.9", "port": 8443, "host": "shop.beta.test:8443"},
                               {"ip": "10.0.2.8", "port": 443, "host": "elsewhere.example"}]}
        w.update_graph_from_fofa(_recon("fofa", payload), "u1", "p1")
        self.assertEqual(w.attached(), {"shop.beta.test": "beta.test"})


class TestOtx(unittest.TestCase):
    def test_passive_dns_splits_in_scope_and_external(self):
        w = _Writer()
        payload = {"ip_reports": [{"ip": "10.0.2.9", "passive_dns": [
            {"hostname": "api.gamma.test", "record_type": "A"},
            {"hostname": "tracker.example.org", "record_type": "A"},
        ]}]}
        w.update_graph_from_otx(_recon("otx", payload), "u1", "p1")
        self.assertEqual(w.attached(), {"api.gamma.test": "gamma.test"})
        self.assertEqual(w.externals(), {"tracker.example.org": "alpha.test"})


class TestZoomeye(unittest.TestCase):
    def test_only_names_under_a_root_become_subdomains(self):
        w = _Writer()
        payload = {"results": [{"ip": "10.0.2.9", "hostname": "vpn.beta.test", "rdns": "x.example.net"}]}
        w.update_graph_from_zoomeye(_recon("zoomeye", payload), "u1", "p1")
        self.assertEqual(w.subdomains_merged(), ["vpn.beta.test"])


class TestUrlscanDiscovery(unittest.TestCase):
    PAYLOAD = {
        "results_count": 3,
        "entries": [
            {"domain": "api.beta.test", "ip": "10.0.2.9"},   # under a batch root
            {"domain": "gamma.test", "ip": "10.0.3.9"},       # an apex, never a Subdomain
            {"domain": "cdn.thirdparty.example", "ip": "10.9.9.9"},  # external
        ],
    }

    @staticmethod
    def _attached(w):
        """{subdomain: root} for urlscan's HAS_SUBDOMAIN link (param `subdomain`)."""
        return {p["subdomain"]: p["domain"] for q, p in w.session.calls
                if "HAS_SUBDOMAIN" in q and "subdomain" in p}

    def test_a_host_under_another_root_joins_that_root(self):
        w = _Writer()
        w.update_graph_from_urlscan_discovery(_recon("urlscan", self.PAYLOAD, domain="alpha.test"), "u1", "p1")
        self.assertEqual(self._attached(w).get("api.beta.test"), "beta.test")

    def test_a_root_apex_is_not_made_a_subdomain(self):
        w = _Writer()
        w.update_graph_from_urlscan_discovery(_recon("urlscan", self.PAYLOAD, domain="alpha.test"), "u1", "p1")
        self.assertNotIn("gamma.test", self._attached(w))
        self.assertNotIn("gamma.test", w.externals())   # an apex is neither

    def test_a_host_under_no_root_is_external(self):
        w = _Writer()
        w.update_graph_from_urlscan_discovery(_recon("urlscan", self.PAYLOAD, domain="alpha.test"), "u1", "p1")
        self.assertIn("cdn.thirdparty.example", w.externals())


class TestUncover(unittest.TestCase):
    def test_a_host_joins_its_own_root(self):
        w = _Writer()
        payload = {"hosts": ["shop.beta.test", "www.alpha.test"], "ips": [], "urls": []}
        w.update_graph_from_uncover(_recon("uncover", payload, domain="alpha.test"), "u1", "p1")
        self.assertEqual(w.attached(), {"shop.beta.test": "beta.test", "www.alpha.test": "alpha.test"})


class TestExternalDomains(unittest.TestCase):
    """Each module judged "external" against the one root it scanned, so in a batch
    a host under a sibling root reached the aggregated external list."""

    AGGREGATED = [
        {"domain": "api.beta.test", "sources": ["js_recon"]},   # under a sibling root
        {"domain": "gamma.test", "sources": ["http_probe"]},    # a sibling's apex
        {"domain": "cdn.thirdparty.example", "sources": ["gau"]},
    ]

    def _write(self, recon):
        w = _Writer()
        w.update_graph_from_external_domains(recon, "u1", "p1")
        return w

    def test_a_sibling_roots_host_joins_its_existing_subdomain_and_mints_none(self):
        # A link is no admission (D2): the sibling group's own steps write the
        # names its scope and the RoE admit; the link only joins one of them.
        w = self._write({"domain": "alpha.test", "all_project_roots": ROOTS,
                         "external_domains_aggregated": self.AGGREGATED})
        self.assertEqual(w.attached().get("api.beta.test"), "beta.test")
        self.assertEqual(w.subdomains_merged(), [])
        lookup, = [q for q, p in w.session.calls if p.get("name") == "api.beta.test"]
        self.assertIn("MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})", lookup)

    def test_only_a_foreign_host_is_an_external_domain(self):
        w = self._write({"domain": "alpha.test", "all_project_roots": ROOTS,
                         "external_domains_aggregated": self.AGGREGATED})
        ext = [p["ed_domain"] for q, p in w.session.calls if "MERGE (ed:ExternalDomain" in q]
        self.assertEqual(ext, ["cdn.thirdparty.example"])
        self.assertNotIn("gamma.test", w.attached())   # an apex is its Domain, not a Subdomain

    def test_a_single_domain_project_keeps_every_foreign_host_external(self):
        w = self._write({"domain": "alpha.test", "external_domains_aggregated": self.AGGREGATED})
        ext = [p["ed_domain"] for q, p in w.session.calls if "MERGE (ed:ExternalDomain" in q]
        self.assertEqual(ext, ["api.beta.test", "gamma.test", "cdn.thirdparty.example"])
        self.assertEqual(w.attached(), {})


class TestUncoverQueriedRoot(unittest.TestCase):
    def test_uncover_links_ips_to_the_queried_root_not_the_first(self):
        """Bug: an IP (and an IP-literal URL) fell back to roots[0], so the pass
        for beta.test recorded beta's IPs as alpha.test's (Domain)-[:HAS_IP]."""
        w = _Writer()
        payload = {"hosts": [], "ips": ["10.0.2.9"], "urls": ["http://10.0.2.9:8080/x"]}
        w.update_graph_from_uncover(_recon("uncover", payload, domain="beta.test"), "u1", "p1")
        has_ip = [p["domain"] for q, p in w.session.calls if "HAS_IP" in q]
        ip_urls = [p["domain"] for q, p in w.session.calls if "(d)-[:HAS_BASE_URL]->(u)" in q]
        self.assertEqual(has_ip, ["beta.test"])
        self.assertEqual(ip_urls, ["beta.test"])


class TestFullPipelineParity(unittest.TestCase):
    """The full pipeline scans one Domain-batch group at a time: recon_data has
    `domain` = the group root and no `domains`, but carries the whole batch in
    `all_project_roots` for the writers. A host a group's scan finds under another
    root then becomes that root's Subdomain, exactly as the partial path does."""

    PAYLOAD = {
        "hosts": [],
        "reverse_dns": {"10.0.2.9": ["mail.beta.test", "cdn.thirdparty.example"]},
    }

    def test_a_group_scan_attaches_a_cross_root_host_to_its_root(self):
        w = _Writer()
        recon = {"domain": "alpha.test", "all_project_roots": ROOTS, "shodan": self.PAYLOAD}
        w.update_graph_from_shodan(recon, "u1", "p1")
        self.assertEqual(w.attached().get("mail.beta.test"), "beta.test")
        self.assertNotIn("mail.beta.test", w.externals())

    def test_without_the_field_the_group_only_knows_its_own_root(self):
        # A single-domain project (no batch): a foreign host is external, as before.
        w = _Writer()
        recon = {"domain": "alpha.test", "shodan": self.PAYLOAD}
        w.update_graph_from_shodan(recon, "u1", "p1")
        self.assertIn("mail.beta.test", w.externals())


if __name__ == "__main__":
    unittest.main()
