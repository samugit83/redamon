"""Collecting the score model's inputs: project fact sets, then findings.

The defect this layer replaces: the old scoring queries chained OPTIONAL MATCH,
so a GVM finding hanging off three Technologies plus a Port plus a Subdomain
came back five times, each row scoring differently, and the last write won. One
OSV advisory node hangs off up to eleven Packages in the dev graph.

Two things are worth pinning without a database:

1. The REDUCERS. `build_project_facts` decides what "unknown" means for every
   fact, and getting that backwards (empty set read as "false" rather than as
   "we did not look") silently scores real findings as unreachable.
2. The QUERY TEXT invariants that a database test would catch far too late:
   every finding query excludes muted nodes, no query writes, and every query
   anchors its per-project labels on the tenant.

The Cypher itself is exercised against a real graph by
tests/test_triage_scoring_graph_live.py.

Run: ./agentic/run_tests.sh tests/test_triage_fact_queries.py
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402
from cypherfix_triage.fact_queries import (  # noqa: E402
    FINDING_QUERIES,
    PROJECT_FACT_QUERIES,
    build_project_facts,
    normalise_finding_row,
)


# ---------------------------------------------------------------------------
# Query-text invariants
# ---------------------------------------------------------------------------
class TestQueryInvariants(unittest.TestCase):
    ALL = PROJECT_FACT_QUERIES + FINDING_QUERIES

    WRITE_CLAUSES = re.compile(
        r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV)\b", re.I)

    def test_no_collection_query_writes(self):
        """Steps A to D read only; publishing is Step E, and it is the only
        thing allowed to touch the graph."""
        for query_def in self.ALL:
            with self.subTest(query=query_def["name"]):
                found = self.WRITE_CLAUSES.search(query_def["query"])
                self.assertIsNone(found, f"write clause {found and found.group(0)}")

    def test_every_finding_query_excludes_muted_nodes(self):
        """These run through run_static_query, which deliberately skips
        scope_query, so the `&!Muted` exclusion is absent and hand-written. Miss
        it and a run re-ranks findings an operator already suppressed."""
        for query_def in FINDING_QUERIES:
            with self.subTest(query=query_def["name"]):
                self.assertIn(":Muted", query_def["query"])
                self.assertIn("NOT", query_def["query"])

    def test_every_finding_query_anchors_its_label_on_the_tenant(self):
        for query_def in FINDING_QUERIES:
            with self.subTest(query=query_def["name"]):
                label = query_def["label"]
                self.assertRegex(
                    query_def["query"],
                    rf"{label} \{{user_id: \$userId, project_id: \$projectId\}}",
                )

    def test_every_finding_query_returns_the_columns_the_publisher_needs(self):
        required = ("id", "label", "triage_host", "seen_updated_at",
                    "triage_status", "triage_source")
        for query_def in FINDING_QUERIES:
            for column in required:
                with self.subTest(query=query_def["name"], column=column):
                    self.assertRegex(query_def["query"], rf"AS {column}\b")

    def test_every_fact_query_has_a_reducer(self):
        """A query whose name no reducer reads is collected and thrown away."""
        import inspect
        source = inspect.getsource(build_project_facts)
        for query_def in PROJECT_FACT_QUERIES:
            with self.subTest(query=query_def["name"]):
                self.assertIn(f'"{query_def["name"]}"', source)

    def test_both_base_url_spellings_are_read(self):
        """K8 is mid-migration: HAS_BASEURL and HAS_BASE_URL both exist in live
        graphs, and reading one spelling loses half the hosts."""
        joined = " ".join(q["query"] for q in PROJECT_FACT_QUERIES)
        self.assertIn("HAS_BASE_URL|HAS_BASEURL", joined)

    def test_no_finding_query_uses_optional_match(self):
        """The row-multiplication this layer exists to fix."""
        for query_def in FINDING_QUERIES:
            with self.subTest(query=query_def["name"]):
                self.assertNotIn("OPTIONAL MATCH", query_def["query"])


# ---------------------------------------------------------------------------
# Reducers
# ---------------------------------------------------------------------------
class TestBuildProjectFacts(unittest.TestCase):
    def test_nothing_collected_gives_empty_sets_not_a_crash(self):
        facts = build_project_facts({})
        self.assertEqual(facts.live_hosts, set())
        self.assertEqual(facts.port_hosts, {})

    def test_a_failed_query_leaves_its_fact_unknown(self):
        """A fact set that failed to load must read as 'we do not know', which
        the model turns into the neutral default, not into 'unreachable'."""
        facts = build_project_facts({"live_hosts": []})
        row = {"id": "f1", "source": "nuclei", "severity": "high", "host": "h1"}
        self.assertEqual(sm.score(row, facts).reach.value, sm.REACH_UNKNOWN)

    def test_nulls_from_collect_are_dropped(self):
        facts = build_project_facts(
            {"live_hosts": [{"hosts": [None, "", "a.example", "  "]}]})
        self.assertEqual(facts.live_hosts, {"a.example"})

    def test_every_spelling_of_a_live_host_is_kept(self):
        facts = build_project_facts(
            {"live_hosts": [{"hosts": ["https://a.example", "a.example"]}]})
        self.assertIn("a.example", facts.live_hosts)
        self.assertIn("https://a.example", facts.live_hosts)

    def test_an_active_port_beats_a_passive_sighting_whatever_the_row_order(self):
        rows = [{"host": "1.2.3.4", "how": "passive", "ports": [80]},
                {"host": "1.2.3.4", "how": "active", "ports": [80]}]
        self.assertEqual(build_project_facts({"port_hosts": rows})
                         .port_hosts["1.2.3.4"], "active")
        self.assertEqual(build_project_facts({"port_hosts": rows[::-1]})
                         .port_hosts["1.2.3.4"], "active")

    def test_an_open_database_port_makes_the_host_sensitive(self):
        facts = build_project_facts(
            {"port_hosts": [{"host": "1.2.3.4", "how": "active", "ports": [5432]}]})
        self.assertIn("1.2.3.4", facts.sensitive_hosts)

    def test_a_host_cannot_be_both_live_and_gone(self):
        """The two queries can disagree across a rescan boundary; liveness is
        positive evidence and wins."""
        facts = build_project_facts({
            "live_hosts": [{"hosts": ["a.example"]}],
            "gone_hosts": [{"hosts": ["a.example", "b.example"]}],
        })
        self.assertEqual(facts.gone_hosts, {"b.example"})

    def test_proof_records_cves_finding_ids_and_hosts(self):
        facts = build_project_facts({"proof": [{
            "chain_id": "cf1", "finding_type": "exploit_success",
            "cve_ids": ["cve-2021-1", None], "finding_ids": ["v9"],
            "hosts": ["1.2.3.4"], "target_host": "a.example",
        }]})
        self.assertEqual(facts.proven_cve_ids, {"CVE-2021-1"})
        self.assertEqual(facts.proven_finding_ids, {"v9"})
        self.assertEqual(facts.compromised_hosts, {"1.2.3.4", "a.example"})

    def test_proof_is_kept_per_host_so_it_survives_a_lost_edge(self):
        """X9: an activation can drop the bridge edges while keeping the chain
        nodes, and the proof must not evaporate with them."""
        facts = build_project_facts({"proof": [{
            "chain_id": "cf1", "finding_type": "access_gained",
            "cve_ids": [], "finding_ids": [], "hosts": ["1.2.3.4"],
            "target_host": "",
        }]})
        self.assertEqual(facts.proof_by_host["1.2.3.4"],
                         [{"chain_id": "cf1", "finding_type": "access_gained"}])

    def test_package_exposure_skips_packages_with_no_anchor(self):
        facts = build_project_facts({"package_exposure": [
            {"package": "pkg:npm/a", "exposure": "served"},
            {"package": "pkg:npm/b", "exposure": ""},
        ]})
        self.assertEqual(facts.package_exposure, {"pkg:npm/a": "served"})

    def test_a_login_host_is_also_a_sensitive_host(self):
        facts = build_project_facts({"sensitive_hosts": [
            {"host": "https://a.example", "login": True},
            {"host": "1.2.3.4", "login": False},
        ]})
        self.assertEqual(facts.login_hosts, {"https://a.example"})
        self.assertEqual(facts.sensitive_hosts, {"https://a.example", "1.2.3.4"})


class TestNormaliseFindingRow(unittest.TestCase):
    def test_cve_ids_from_four_property_names_are_merged_and_deduplicated(self):
        """C2: nuclei, shodan and criminalip store `cves`, nmap_nse stores
        `cve_id`, OSV stores `aliases`. The old scorer read only `cve_ids`."""
        row = normalise_finding_row({
            "id": "v1",
            "cve_ids": ["CVE-2021-1", "cve-2021-1", "GHSA-xxxx", None, ""],
        })
        self.assertEqual(row["cve_ids"], ["CVE-2021-1"])

    def test_a_row_with_nothing_in_it_does_not_raise(self):
        row = normalise_finding_row({})
        self.assertEqual(row["cve_ids"], [])
        self.assertEqual(row["host"], "")

    def test_none_is_accepted(self):
        self.assertEqual(normalise_finding_row(None)["cve_ids"], [])

    def test_the_resolved_host_becomes_the_host_the_model_reads(self):
        row = normalise_finding_row({"id": "v1", "triage_host": "a.example"})
        self.assertEqual(row["host"], "a.example")

    def test_a_package_resolved_through_the_graph_fills_in_a_missing_property(self):
        row = normalise_finding_row({
            "id": "v1", "vuln_package": "pkg:npm/a", "vuln_package_version": "1.2.3",
        })
        self.assertEqual(row["package_purl"], "pkg:npm/a")
        self.assertEqual(row["package_version"], "1.2.3")

    def test_a_property_already_set_is_not_overwritten(self):
        row = normalise_finding_row({
            "id": "v1", "package_purl": "pkg:npm/real", "vuln_package": "pkg:npm/other",
        })
        self.assertEqual(row["package_purl"], "pkg:npm/real")


class TestEndToEndOnCollectedRows(unittest.TestCase):
    """A collected row must score without any further massaging."""

    def test_a_collected_github_secret_scores_and_lands_in_track(self):
        row = normalise_finding_row({
            "id": "g1", "label": "GithubSecret", "source": "github_hunt",
            "name": "IP Address (Private)", "severity": "high",
            "secret_type": "IP Address (Private)",
            "detector_name": "IP Address (Private)",
            "triage_host": "acme/repo", "seen_updated_at": "2026-01-01",
        })
        result = sm.score(row, build_project_facts({}))
        self.assertEqual(result.tier, "T4")

    def test_a_collected_advisory_on_a_served_package_outranks_one_in_a_repo(self):
        facts = build_project_facts({"package_exposure": [
            {"package": "pkg:npm/served", "exposure": "served"},
            {"package": "pkg:npm/shipped", "exposure": "repo"},
        ]})
        served = sm.score(normalise_finding_row({
            "id": "o1", "label": "Vulnerability", "source": "osv",
            "severity": "high", "vuln_package": "pkg:npm/served",
            "vuln_package_version": "1.0.0"}), facts)
        shipped = sm.score(normalise_finding_row({
            "id": "o2", "label": "Vulnerability", "source": "osv",
            "severity": "high", "vuln_package": "pkg:npm/shipped",
            "vuln_package_version": "1.0.0"}), facts)
        self.assertGreater(served.score, shipped.score)


class TestTheDetectorFieldsReachTheModel(unittest.TestCase):
    """Strategy row 6. `detector_key` keys a GVM finding on its NVT OID. If the
    vulnerabilities query does not return one, every GVM finding falls back to a
    per-finding key, collects one label each, and the board never learns."""

    def test_the_vulnerabilities_query_returns_the_gvm_oid(self):
        query = next(q for q in FINDING_QUERIES if q["name"] == "vulnerabilities")["query"]
        self.assertIn("coalesce(v.oid, v.nvt_oid) AS oid", query)

    def test_the_oid_produces_a_per_detector_key(self):
        row = normalise_finding_row({"id": "gvm-1", "label": "Vulnerability",
                                     "source": "gvm", "oid": "1.3.6.1.4.1.25623.1.0.9"})
        other = normalise_finding_row({"id": "gvm-2", "label": "Vulnerability",
                                       "source": "gvm", "oid": "1.3.6.1.4.1.25623.1.0.9"})
        self.assertEqual(sm.detector_key(row), sm.detector_key(other))
        self.assertEqual(sm.detector_key(row), "gvm:1.3.6.1.4.1.25623.1.0.9")


if __name__ == "__main__":
    unittest.main()
