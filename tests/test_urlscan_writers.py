"""The urlscan graph writers: what reaches Neo4j, with the tenant triple on every
MERGE and no raw value anywhere.

`SET n += $props` hides property names from the hermetic schema scan
(recon/tests/test_graph_writes_documented.py), so these tests assert the names
themselves, on the Cypher and its parameters.

Fixture names are example.test only; tokens are invented.
"""
import json
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402

TOK = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"


class _Session:
    def __init__(self, single=None):
        self.calls = []
        self._single = single

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = self._single
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self, single=None):
        self.session = _Session(single)
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _recon(urlscan):
    base = {"results_count": 1, "entries": [], "urls_with_paths": []}
    base.update(urlscan)
    return {"domain": "example.test", "domains": ["example.test"], "urlscan": base}


class TestQuarantinedEndpoints(unittest.TestCase):
    ROW = {"base_url": "https://auth.example.test", "path": "/password/reset/{token}",
           "masked_url": "https://auth.example.test/password/reset/{token}?lang=***",
           "param_names": ["lang"], "reasons": ["one_time_link", "path_token"], "field": "page"}

    def _write(self, rows):
        w = _Writer(single={"n": 1})
        stats = w.update_graph_from_urlscan_enrichment(_recon({"quarantined_urls": rows}), "u1", "p1")
        return w, stats

    def _quarantine_calls(self, w):
        return [(q, p) for q, p in w.session.calls if "e.quarantined = true" in q]

    def test_flagged_with_a_plain_set_and_no_full_url(self):
        w, stats = self._write([self.ROW])
        (query, params), = self._quarantine_calls(w)
        self.assertIn("REMOVE e.full_url", query)
        self.assertNotIn("ON CREATE SET e.quarantined", query)
        self.assertIn("REMOVE p.sample_value, p.sample_values", query)
        self.assertEqual(params["path"], "/password/reset/{token}")
        self.assertEqual(params["names"], ["lang"])
        self.assertEqual(stats["endpoints_quarantined"], 1)

    def test_tenant_triple_on_every_merge(self):
        w, _ = self._write([self.ROW])
        (query, params), = self._quarantine_calls(w)
        for merge in [line for line in query.splitlines() if "MERGE (" in line and ":" in line
                      and "{" in line]:
            if "Endpoint" in merge or "Parameter" in merge:
                self.assertIn("user_id: $uid", query)
                self.assertIn("project_id: $pid", query)
        self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))

    def test_no_value_reaches_the_graph_without_a_display_link(self):
        w, _ = self._write([dict(self.ROW, masked_url=self.ROW["masked_url"])])
        self.assertNotIn(TOK, json.dumps([p for _q, p in w.session.calls], default=str))

    def test_the_full_links_go_only_to_the_display_fields_newest_first(self):
        old = dict(self.ROW, unmasked_url=f"https://auth.example.test/password/reset/{TOK}?lang=en",
                   scan_time="2026-09-01T00:00:00.000Z")
        new = dict(self.ROW, unmasked_url="https://auth.example.test/password/reset/Zz9?lang=it",
                   scan_time="2026-10-01T00:00:00.000Z")
        w, _ = self._write([old, new])
        calls = self._quarantine_calls(w)
        self.assertEqual(len(calls), 2)
        for query, params in calls:
            self.assertIn("SET e.unmasked_url", query)
            self.assertEqual(params["unmasked_urls"], [new["unmasked_url"], old["unmasked_url"]])
            self.assertEqual(params["path"], "/password/reset/{token}")
            self.assertIn("REMOVE e.full_url", query)



class TestDiscoveryWriter(unittest.TestCase):
    """S5 / B03 / B11 / B13 / B17."""

    ENTRIES = [
        {"domain": "app.example.test", "ip": "192.88.97.98", "scan_time": "2026-10-20T00:00:00.000Z",
         "in_scope": True, "ip_in_scope": True, "asn": "AS64500"},
        {"domain": "app.example.test", "ip": "192.88.97.98", "scan_time": "2026-09-01T00:00:00.000Z",
         "in_scope": True, "ip_in_scope": True},
        {"domain": "lan.example.test", "ip": "10.0.0.5", "in_scope": True, "ip_in_scope": False},
        {"domain": "excluded.example.test", "ip": "192.88.97.20", "in_scope": False, "ip_in_scope": False},
        {"domain": "old.example.test", "ip": "192.88.97.30"},
    ]

    def _write(self):
        w = _Writer(single={"n": 1})
        w.update_graph_from_urlscan_discovery(_recon({"entries": self.ENTRIES}), "u1", "p1")
        return w

    def test_s5_an_address_is_history_with_its_dates_never_current_dns(self):
        w = self._write()
        self.assertFalse([q for q, _p in w.session.calls if "RESOLVES_TO]" in q and "HISTORICALLY" not in q])
        hist = [(q, p) for q, p in w.session.calls if "HISTORICALLY_RESOLVED_TO {source: 'urlscan'}" in q]
        self.assertEqual(len(hist), 1)
        q, p = hist[0]
        self.assertEqual((p["subdomain"], p["ip"]), ("app.example.test", "192.88.97.98"))
        self.assertEqual((p["first"], p["last"]), ("2026-09-01T00:00:00.000Z", "2026-10-20T00:00:00.000Z"))
        # Only through an existing Subdomain: no orphan IP (B11).
        self.assertLess(q.index("MATCH (s:Subdomain"), q.index("MERGE (i:IP"))

    def test_b11_no_ip_for_an_out_of_scope_private_or_untagged_entry(self):
        w = self._write()
        ips = {p.get("ip") for q, p in w.session.calls if "MERGE (i:IP" in q}
        self.assertEqual(ips, {"192.88.97.98"})

    def test_b11_an_out_of_scope_host_gets_no_subdomain(self):
        w = self._write()
        subs = {p["subdomain"] for q, p in w.session.calls if "MERGE (s:Subdomain" in q}
        self.assertNotIn("excluded.example.test", subs)
        self.assertIn("app.example.test", subs)

    def test_b13_b17_unverified_with_a_source(self):
        w = self._write()
        q = next(q for q, _p in w.session.calls if "MERGE (s:Subdomain" in q)
        self.assertIn("s.source = 'urlscan'", q)
        self.assertIn("s.status = 'unverified'", q)
        self.assertNotIn("'resolved'", q)


class TestEnrichmentWriterStoresNoValue(unittest.TestCase):
    """S4 / B10 / B15: names only, the URL masked even on an existing node."""

    def test_no_sample_value_and_full_url_masked_on_match(self):
        w = _Writer(single={"path": "/api"})
        row = {"base_url": "https://app.example.test", "path": "/api",
               "full_url": "https://app.example.test/api?id=***", "params": {"id": "***"}}
        w.update_graph_from_urlscan_enrichment(_recon({"urls_with_paths": [row]}), "u1", "p1")
        endpoint_q = next(q for q, _p in w.session.calls if "MERGE (e:Endpoint" in q and "quarantined" not in q)
        self.assertIn("SET e.full_url = CASE WHEN e.source = 'urlscan' THEN $full_url", endpoint_q)
        param_calls = [(q, p) for q, p in w.session.calls if "MERGE (p:Parameter" in q]
        self.assertTrue(param_calls)
        for q, p in param_calls:
            self.assertNotIn("sample_value =", q)
            self.assertIn("REMOVE p.sample_value", q)
            self.assertNotIn("sample_val", p)

    def test_quarantined_visit_gives_no_screenshot(self):
        w = _Writer(single={"url": "x"})
        entries = [{"url": "https://auth.example.test/reset?token=***", "quarantined": True,
                    "screenshot_url": "https://urlscan.io/screenshots/x.png"},
                   {"url": "https://auth.example.test/about", "screenshot_url": "https://urlscan.io/s/y.png",
                    "tls_issuer": "Lab CA", "tls_valid_days": 90}]
        w.update_graph_from_urlscan_enrichment(_recon({"entries": entries}), "u1", "p1")
        props = [p["props"] for q, p in w.session.calls if "MATCH (bu:BaseURL" in q and "props" in p]
        self.assertEqual(props[0]["urlscan_screenshot_url"], "https://urlscan.io/s/y.png")
        self.assertEqual((props[0]["urlscan_tls_issuer"], props[0]["urlscan_tls_valid_days"]), ("Lab CA", 90))


class TestB03PassiveSourcesAreNotCurrentDns(unittest.TestCase):
    def test_every_passive_writer_stamps_a_source_on_create(self):
        source = open(os.path.join(_REPO, "graph_db", "mixins", "osint_mixin.py")).read()
        for src in ("censys_dns", "fofa_dns", "otx_passive_dns", "zoomeye_dns", "shodan_rdns", "shodan_dns"):
            self.assertIn(f"ON CREATE SET r.timestamp = datetime(), r.source = '{src}'", source)
        self.assertNotIn("MERGE (s)-[:RESOLVES_TO]->(i)", source)


class TestB19ExternalDomainsAreAdditive(unittest.TestCase):
    """A partial urlscan run writes only its own sightings: the aggregated
    writer must add to what a full run recorded, never overwrite it."""

    def test_lists_append_distinct_and_counts_add(self):
        w = _Writer()
        recon = {"domain": "example.test", "domains": ["example.test"],
                 "external_domains_aggregated": [{
                     "domain": "outsider.other.test", "sources": ["urlscan_redirect"],
                     "redirect_from_urls": ["https://app.example.test/go?url=***"],
                     "redirect_to_urls": ["https://outsider.other.test"], "times_seen": 2}]}
        w.update_graph_from_external_domains(recon, "u1", "p1")
        q = next(q for q, _p in w.session.calls if "MERGE (ed:ExternalDomain" in q)
        self.assertIn("ed.sources = coalesce(ed.sources, []) + [x IN $sources WHERE NOT x IN coalesce(ed.sources, [])]", q)
        self.assertIn("ed.times_seen = coalesce(ed.times_seen, 0) + $times_seen", q)
        self.assertNotIn("SET ed.sources = $sources", q)

    def test_full_start_urls_newest_first_capped(self):
        w = _Writer()
        link = "https://app.example.test/go?url=https://outsider.other.test/x"
        recon = {"domain": "example.test", "domains": ["example.test"],
                 "external_domains_aggregated": [{
                     "domain": "outsider.other.test", "sources": ["urlscan_redirect"],
                     "redirect_from_urls": ["https://app.example.test/go?url=***"],
                     "unmasked_redirect_from_urls": [link], "times_seen": 1}]}
        w.update_graph_from_external_domains(recon, "u1", "p1")
        q, p = next((q, p) for q, p in w.session.calls if "MERGE (ed:ExternalDomain" in q)
        self.assertIn("ed.unmasked_redirect_from_urls = ([x IN $unmasked_from", q)
        self.assertIn("[0..25]", q)
        self.assertEqual(p["unmasked_from"], [link])


class TestRedirectWriters(unittest.TestCase):
    """Item 1: written even when the main search returned nothing."""

    def test_start_hosts_become_subdomains_without_an_ip(self):
        w = _Writer(single={"n": 1})
        w.update_graph_from_urlscan_discovery(
            _recon({"results_count": 0, "redirect_start_hosts": ["new.example.test"]}), "u1", "p1")
        q = next(q for q, p in w.session.calls if "MERGE (s:Subdomain" in q and p.get("subdomain") == "new.example.test")
        self.assertIn("s.status = 'unverified'", q)
        self.assertFalse([q for q, _p in w.session.calls if "MERGE (i:IP" in q])

    def test_redirect_endpoint_carries_its_target_and_names_only(self):
        w = _Writer(single={"n": 1})
        row = {"start_url": "https://app.example.test/go?url=***", "base_url": "https://app.example.test",
               "path": "/go", "param_names": ["url"], "end_origin": "https://outsider.other.test",
               "end_domain": "outsider.other.test"}
        w.update_graph_from_urlscan_enrichment(_recon({"results_count": 0, "redirect_entries": [row]}), "u1", "p1")
        q, p = next((q, p) for q, p in w.session.calls if "urlscan_redirect_target" in q)
        self.assertEqual((p["target"], p["names"], p["path"]), ("https://outsider.other.test", ["url"], "/go"))
        self.assertNotIn("sample_value", q.replace("REMOVE p.sample_value", ""))


if __name__ == "__main__":
    unittest.main()


class TestVulnWriterStoresNoParameterValue(unittest.TestCase):
    """B10/B15: the DAST URLs the vuln writer turns into Parameters can be
    urlscan's (masked) or GAU's (raw); neither value is stored, under either name."""

    def test_dast_url_parameters_carry_no_value(self):
        from graph_db.mixins.recon.vuln_mixin import VulnMixin

        class _VulnWriter(VulnMixin):
            def __init__(self):
                self.session = _Session()
                self.driver = MagicMock()
                self.driver.session.return_value = self.session

        w = _VulnWriter()
        recon = {"domain": "example.test", "subdomains": ["app.example.test"],
                 "vuln_scan": {"discovered_urls": {"dast_urls_with_params": [
                     "https://app.example.test/search?q=***&page=***",
                     f"https://app.example.test/account?session={TOK}"]}}}
        w.update_graph_from_vuln_scan(recon, "u1", "p1")
        param_writes = [(q, p) for q, p in w.session.calls if "MERGE (p:Parameter" in q]
        self.assertEqual({p["name"] for _q, p in param_writes}, {"q", "page", "session"})
        for q, p in w.session.calls:
            self.assertNotIn("sample_value", q)
            self.assertNotIn(TOK, json.dumps(p, default=str))
