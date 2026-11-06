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
    STORED_LAYERS,
    build_project_facts,
    finding_query_by_id,
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

    @staticmethod
    def _aliases(label):
        query = next(q["query"] for q in FINDING_QUERIES if q["label"] == label)
        return set(re.findall(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", query))

    def test_the_vulnerability_query_selects_the_request(self):
        """Without it the reviewer never saw what nuclei sent, and the request's
        redaction never ran on live data."""
        self.assertIn("raw_request", self._aliases("Vulnerability"))

    def test_bundle_fields_the_query_never_selects(self):
        """Every field the evidence bundle prints for a nuclei or GVM finding
        must be selected: a field the query omits is a line that is always
        empty, so neither the built-in reviewer nor an agent ever sees it."""
        wanted = {
            "Vulnerability": {"template_id", "matched_at", "matcher_name", "fuzzing_parameter",
                              "extracted_results", "raw_request", "raw_response",
                              "description", "qod", "qod_type", "cve_ids",
                              "target_port", "solution_type"},
            "ExploitGvm": {"description", "qod", "qod_type", "cve_ids", "target_port"},
        }
        for label, fields in wanted.items():
            with self.subTest(label=label):
                self.assertEqual(fields - self._aliases(label), set())

    def test_no_finding_query_uses_optional_match(self):
        """The row-multiplication this layer exists to fix."""
        for query_def in FINDING_QUERIES:
            with self.subTest(query=query_def["name"]):
                self.assertNotIn("OPTIONAL MATCH", query_def["query"])


class TestGoneHostsQuery(unittest.TestCase):
    """`gone_hosts` drops a host from the board, so it must test what it says.
    The live counterpart is tests/test_fix_fact_queries_graph_live.py."""

    QUERY = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "gone_hosts")["query"]

    def test_resolution_is_read_in_the_direction_the_edge_runs(self):
        # RESOLVES_TO runs Subdomain -> IP, so an outgoing pattern from an IP
        # never matched and the "nothing resolves" clause was always true.
        self.assertRegex(self.QUERY, r"n:Subdomain AND EXISTS \{\s*MATCH \(n\)-\[r:RESOLVES_TO\]->\(:IP\)")
        self.assertRegex(self.QUERY, r"n:IP AND EXISTS \{\s*MATCH \(n\)<-\[r:RESOLVES_TO\]-\(:Subdomain\)")
        self.assertNotIn("MATCH (n)-[:RESOLVES_TO]->()", self.QUERY)

    def test_hosts_the_run_skipped_are_not_gone(self):
        # Read from every org Domain of THIS tenant, never another project's.
        self.assertIn("(d:Domain {user_id: $userId, project_id: $projectId})", self.QUERY)
        self.assertIn("d.recon_skipped_hosts", self.QUERY)
        self.assertRegex(self.QUERY, r"NOT toLower\(coalesce\(n\.name, n\.address, ''\)\) IN skipped")

    def test_skipped_keys_are_normalised_as_the_prune_does(self):
        # circuit_breaker.hostname_of: lower-case, IPv6 brackets and the port
        # stripped, a bare IPv6 literal left whole.
        self.assertIn("toLower(trim(toString(x)))", self.QUERY)
        self.assertIn("WHEN k STARTS WITH '[' THEN substring(split(k, ']')[0], 1)", self.QUERY)
        self.assertIn("WHEN size(split(k, ':')) = 2 THEN split(k, ':')[0]", self.QUERY)


class TestGateFactQueries(unittest.TestCase):
    """Plan 10.4: the facts the reachable-now and attributed gates read."""

    @staticmethod
    def _query(name):
        return next(q for q in PROJECT_FACT_QUERIES if q["name"] == name)["query"]

    def test_skipped_hosts_are_read_as_the_gone_query_reads_them(self):
        """The same keys, normalised the same way: a host the gone query spares
        because the run skipped it is the host the gate calls unknown."""
        skipped, gone = self._query("skipped_hosts"), TestGoneHostsQuery.QUERY
        self.assertIn("(d:Domain {user_id: $userId, project_id: $projectId})", skipped)
        normalise = gone[gone.index("WITH reduce"):gone.index("AS skipped") + len("AS skipped")]
        self.assertIn(normalise, skipped)

    def test_name_ownership_reads_forward_dns_of_this_tenant_only(self):
        query = self._query("name_ownership")
        self.assertIn("(s:Subdomain {user_id: $userId, project_id: $projectId})-[r:RESOLVES_TO]->(ip:IP)", query)
        self.assertIn("r.source IS NULL", query)
        self.assertIn("ip.user_id = $userId AND ip.project_id = $projectId", query)

    def test_the_reducers_build_the_two_facts(self):
        facts = build_project_facts({
            "skipped_hosts": [{"hosts": ["App.Example.com", None, " ", "203.0.113.4"]}],
            "name_ownership": [{"name": "App.example.com", "tags": ["dedicated", None]},
                               {"name": "cdn.example.com", "tags": ["shared_edge"]},
                               {"name": "", "tags": ["dedicated"]}],
        })
        self.assertEqual(facts.skipped_hosts, {"app.example.com", "203.0.113.4"})
        self.assertEqual(facts.name_ownership, {"app.example.com": {"dedicated", ""},
                                                "cdn.example.com": {"shared_edge"}})

    def test_a_failed_read_leaves_both_facts_unknown(self):
        facts = build_project_facts({"skipped_hosts": None, "name_ownership": None})
        self.assertEqual((facts.skipped_hosts, facts.name_ownership), (set(), {}))

    def test_the_finding_rows_carry_what_the_gates_read(self):
        self.assertIn("control_check", TestQueryInvariants._aliases("Vulnerability"))
        self.assertIn("evidence", TestQueryInvariants._aliases("Vulnerability"))
        self.assertIn("control_check", TestQueryInvariants._aliases("JsReconFinding"))
        self.assertIn("public_client_key", TestQueryInvariants._aliases("Secret"))


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


# ---------------------------------------------------------------------------
# The layered model's reads
# ---------------------------------------------------------------------------
class TestTheByIdRender(unittest.TestCase):
    """One finding, read exactly as the run reads it (2.10)."""

    WRITE_CLAUSES = re.compile(
        r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV)\b", re.I)

    def test_every_finding_query_can_be_narrowed_to_one_id(self):
        for query_def in FINDING_QUERIES:
            with self.subTest(query=query_def["name"]):
                cypher = finding_query_by_id(query_def)
                self.assertIn(f"{query_def['id_expr']} = $findingId", cypher)

    def test_the_narrowed_query_keeps_the_tenant_and_the_mute_exclusion(self):
        for query_def in FINDING_QUERIES:
            with self.subTest(query=query_def["name"]):
                cypher = finding_query_by_id(query_def)
                self.assertIn("user_id: $userId, project_id: $projectId", cypher)
                self.assertRegex(cypher, r"NOT \w+:Muted")
                self.assertIsNone(self.WRITE_CLAUSES.search(cypher))

    def test_a_mal_package_is_addressed_by_its_finding_id(self):
        mal = [q for q in FINDING_QUERIES if q["label"] == "MalPackageFinding"][0]
        self.assertIn("coalesce(f.finding_id, f.id) = $findingId", finding_query_by_id(mal))

    def test_the_scope_filters_survive_the_narrowing(self):
        """A board row the run does not score is out of triage scope, not missing."""
        js = [q for q in FINDING_QUERIES if q["label"] == "JsReconFinding"][0]
        self.assertIn("<> 'js_file'", finding_query_by_id(js))
        mal = [q for q in FINDING_QUERIES if q["label"] == "MalPackageFinding"][0]
        self.assertIn("[:FLAGGED_AS]", finding_query_by_id(mal))


class TestStoredLayers(unittest.TestCase):
    Q = STORED_LAYERS["query"]

    def test_it_reads_only(self):
        self.assertIsNone(TestTheByIdRender.WRITE_CLAUSES.search(self.Q))

    def test_it_is_tenant_scoped_and_skips_muted_nodes(self):
        self.assertIn("{user_id: $userId, project_id: $projectId}", self.Q)
        self.assertIn("NOT n:Muted", self.Q)

    def test_it_returns_both_layers_and_the_legacy_cache_key(self):
        for column in ("triage_status", "triage_source", "triage_verdict_channel",
                       "triage_ai_verdict", "triage_ai_channel", "triage_ai_evidence_hash",
                       "triage_ai_prompt_version", "triage_ai_model", "triage_fix_lever",
                       "triage_evidence_hash"):
            with self.subTest(column=column):
                self.assertIn(f"AS {column}", self.Q)

    def test_a_mal_package_joins_on_its_finding_id(self):
        self.assertIn("coalesce(n.finding_id, n.id)", self.Q)


class TestDetectorLearningFilters(unittest.TestCase):
    """C13 / P1: whose clicks may teach this user's detectors."""
    Q = [q for q in PROJECT_FACT_QUERIES if q["name"] == "detector_labels"][0]["query"]

    def test_only_this_user_s_own_decisions_count(self):
        """An imported project keeps its previous owner's decisions."""
        self.assertIn("coalesce(n.triage_verdict_by, n.user_id) = $userId", self.Q)

    def test_only_decisions_made_in_the_app_count(self):
        """An unattended agent over MCP must not retune detectors everywhere."""
        self.assertIn("coalesce(n.triage_verdict_channel, 'app') = 'app'", self.Q)



class TestAgentProofConfidence(unittest.TestCase):
    """A ChainFinding proves a finding only at confidence >= 70; a missing value
    is the writer's default 80. A low-confidence "confirmation" read off a
    status code must not make a finding T1 and immune to review."""

    PROOF = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "proof")["query"]

    def test_the_rule(self):
        for value, counts in ((None, True), (80, True), (70, True), (69, False), (50, False),
                              (0, False), ("85", True), ("40", False), (75.9, True),
                              ("high", True), (100, True)):
            with self.subTest(confidence=value):
                self.assertIs(sm.agent_proof_counts(value), counts)

    def test_the_proof_query_filters_on_the_model_s_threshold(self):
        self.assertIn(
            f"coalesce(toInteger(cf.confidence), {sm.AGENT_CONFIDENCE_DEFAULT}) "
            f">= {sm.PROOF_MIN_AGENT_CONFIDENCE}", self.PROOF)
        self.assertIn("cf.confidence AS confidence", self.PROOF)

    def test_a_low_confidence_proof_row_proves_nothing(self):
        facts = build_project_facts({"proof": [
            {"chain_id": "c1", "finding_type": "vulnerability_confirmed", "confidence": 50,
             "finding_ids": ["f-low"], "hosts": ["h-low"], "cve_ids": ["CVE-2020-0001"]},
            {"chain_id": "c2", "finding_type": "vulnerability_confirmed", "confidence": None,
             "finding_ids": ["f-old"], "hosts": ["h-old"], "cve_ids": []},
            {"chain_id": "c3", "finding_type": "exploit_success", "confidence": 90,
             "finding_ids": ["f-high"], "hosts": [], "cve_ids": []},
        ]})
        self.assertEqual(facts.proven_finding_ids, {"f-old", "f-high"})
        self.assertNotIn("h-low", facts.compromised_hosts)
        self.assertNotIn("CVE-2020-0001", facts.proven_cve_ids)
        self.assertFalse(sm.is_proven({"id": "f-low"}, facts))
        self.assertTrue(sm.is_proven({"id": "f-old"}, facts))
