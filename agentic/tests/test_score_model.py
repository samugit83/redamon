"""The risk model behind the Priority Board (score model v3).

This replaces test_triage_scoring.py's weight-table tests. The old formula
added points per signal; the new one estimates four probabilities and
multiplies them, so the things worth pinning are different: not "does KEV add
800" but "does a bigger factor ever produce a smaller score".

The eight guarantees of the plan's section 3.2.10 are each a test here, three of
them checked over seeded random cases rather than hand-picked ones, because the
failure they guard against (a table edit that makes the model non-monotonic) is
exactly what a hand-picked case misses.

Run: ./agentic/run_tests.sh tests/test_score_model.py
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402


def finding(**kwargs):
    """A minimal open finding; every test states only what it is about."""
    base = {"id": "f1", "label": "Vulnerability", "source": "nuclei",
            "severity": "medium", "host": "h1"}
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# CVSS parsing
# ---------------------------------------------------------------------------
class TestCvssParsing(unittest.TestCase):
    def test_v31_worst_case_is_maximum_impact_and_exploitability(self):
        cvss = sm.parse_cvss_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertGreater(cvss.impact, 0.95)
        self.assertGreater(cvss.exploitability, 0.95)
        self.assertEqual(cvss.version, "3")

    def test_v31_no_impact_is_zero_impact(self):
        cvss = sm.parse_cvss_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(cvss.impact, 0.0)

    def test_v3_local_low_privilege_scores_lower_exploitability(self):
        remote = sm.parse_cvss_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        local = sm.parse_cvss_vector(
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H")
        self.assertLess(local.exploitability, remote.exploitability)
        self.assertAlmostEqual(local.impact, remote.impact)

    def test_v30_parses_the_same_way_as_v31(self):
        v30 = sm.parse_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        v31 = sm.parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertAlmostEqual(v30.impact, v31.impact)

    def test_scope_changed_raises_impact(self):
        unchanged = sm.parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")
        changed = sm.parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L")
        self.assertGreater(changed.impact, unchanged.impact)

    def test_v2_complete_impact_is_maximum(self):
        cvss = sm.parse_cvss_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C")
        self.assertEqual(cvss.version, "2")
        self.assertGreater(cvss.impact, 0.95)

    def test_v2_partial_impact_is_middling(self):
        cvss = sm.parse_cvss_vector("AV:N/AC:M/Au:S/C:P/I:P/A:N")
        self.assertGreater(cvss.impact, 0.2)
        self.assertLess(cvss.impact, 0.7)

    def test_v4_high_impact_parses(self):
        cvss = sm.parse_cvss_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertEqual(cvss.version, "4")
        self.assertGreater(cvss.impact, 0.95)
        self.assertGreater(cvss.exploitability, 0.95)

    def test_v4_takes_the_higher_of_the_two_impact_triads(self):
        """A vulnerability harmless to its own host but devastating downstream
        must not read as harmless."""
        subsequent = sm.parse_cvss_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H")
        self.assertGreater(subsequent.impact, 0.95)

    def test_v4_attack_requirements_lower_exploitability(self):
        without = sm.parse_cvss_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
        with_at = sm.parse_cvss_vector(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H")
        self.assertLess(with_at.exploitability, without.exploitability)

    def test_an_absent_or_nonsense_vector_yields_nothing_rather_than_zero(self):
        for value in (None, "", "not a vector", 42):
            with self.subTest(value=value):
                cvss = sm.parse_cvss_vector(value)
                self.assertIsNone(cvss.impact)
                self.assertIsNone(cvss.exploitability)


# ---------------------------------------------------------------------------
# Normalisers (K10, K24)
# ---------------------------------------------------------------------------
class TestNormalisers(unittest.TestCase):
    def test_confidence_reads_all_four_stored_shapes(self):
        self.assertAlmostEqual(sm.normalise_confidence("high"), 0.9)
        self.assertAlmostEqual(sm.normalise_confidence(85), 0.85)
        self.assertAlmostEqual(sm.normalise_confidence(0.85), 0.85)
        self.assertAlmostEqual(sm.normalise_confidence("malicious"), 1.0)

    def test_confidence_of_nothing_is_none_not_zero(self):
        for value in (None, "", "wat", True, False):
            with self.subTest(value=value):
                self.assertIsNone(sm.normalise_confidence(value))

    def test_severity_reads_words_and_numbers(self):
        self.assertEqual(sm.normalise_severity("HIGH"), "high")
        self.assertEqual(sm.normalise_severity(9.8), "critical")
        self.assertEqual(sm.normalise_severity("moderate"), "moderate")
        self.assertIsNone(sm.normalise_severity("unknown"))


# ---------------------------------------------------------------------------
# C: how the finding was detected
# ---------------------------------------------------------------------------
class TestConfidence(unittest.TestCase):
    def test_a_security_check_is_a_fact(self):
        self.assertEqual(
            sm.confidence(finding(source="security_check", type="missing_hsts"),
                          sm.ProjectFacts()).value, 1.0)

    def test_nuclei_with_extracted_proof_beats_nuclei_without(self):
        proof = sm.confidence(
            finding(matcher_status=True, extracted_results=["root:x:0:0"]),
            sm.ProjectFacts()).value
        bare = sm.confidence(finding(), sm.ProjectFacts()).value
        self.assertEqual(proof, 0.95)
        self.assertEqual(bare, 0.75)

    def test_gvm_qod_bands(self):
        facts = sm.ProjectFacts()
        self.assertEqual(sm.confidence(
            finding(source="gvm", qod=98, qod_type="remote_vul"), facts).value, 0.95)
        self.assertEqual(sm.confidence(
            finding(source="gvm", qod=80, qod_type="remote_banner"), facts).value, 0.75)
        self.assertEqual(sm.confidence(
            finding(source="gvm", qod=30, qod_type="general_note"), facts).value, 0.4)

    def test_an_osv_advisory_needs_a_known_version_to_be_confident(self):
        facts = sm.ProjectFacts()
        self.assertEqual(sm.confidence(
            finding(source="osv", package_version="1.2.3"), facts).value, 0.9)
        self.assertEqual(sm.confidence(finding(source="osv"), facts).value, 0.4)

    def test_a_malicious_package_is_proven(self):
        self.assertEqual(sm.confidence(
            finding(id="MAL-2022-1122", source="osv"), sm.ProjectFacts()).value, 1.0)

    def test_a_guarddog_soft_error_is_almost_nothing(self):
        self.assertEqual(sm.confidence(
            finding(source="guarddog", soft_error=True), sm.ProjectFacts()).value, 0.1)

    def test_an_unvalidated_github_secret_is_a_maybe(self):
        self.assertEqual(sm.confidence(
            finding(label="GithubSecret", source=None,
                    detector_name="AWS"), sm.ProjectFacts()).value, 0.6)

    def test_a_passive_version_guess_is_weak(self):
        for source in ("shodan", "internetdb", "criminalip", "netlas"):
            with self.subTest(source=source):
                self.assertEqual(sm.confidence(
                    finding(source=source), sm.ProjectFacts()).value, 0.4)

    def test_an_unknown_source_gets_the_default_and_a_warning(self):
        result = sm.score(finding(source="brand_new_scanner_9000"))
        self.assertEqual(result.confidence.value, sm.CONFIDENCE_UNKNOWN_SOURCE)
        self.assertTrue(result.warnings)


class TestSourceCoverage(unittest.TestCase):
    """Guarantee 6: every source that writes a finding has a C row.

    A new scanner that ships without one is silently given the default, which is
    how a tool ends up ranked as if it were nuclei. This is the gate that stops
    that, so the list below is maintained deliberately.
    """

    #: Every `source` value written onto a finding-labelled node, from the
    #: writer inventory in graph_db/mixins/ and scanners/.
    FINDING_SOURCES = (
        "nuclei", "gvm", "nmap_nse", "security_check", "osv", "retirejs",
        "sourcemap", "guarddog", "shodan", "shodan_api", "internetdb",
        "criminalip", "netlas", "censys", "fofa", "zoomeye", "uncover",
        "urlscan", "otx", "vulners", "nvd", "wappalyzer", "typosquat",
        "takeover_scan", "cache_poisoning", "graphql_scan", "graphql_cop",
        "ai_surface_recon", "ai_attack", "wcvs", "vuln_scan", "http_probe",
        "origin_discovery", "vhost_sni_enum", "resource_enum", "github_hunt",
        "github", "github_experimental", "git", "filesystem", "trufflehog",
        "jsluice", "js_recon", "agent", "human", "operator", "user", "import",
        "graph", "recon", "finding", "ai", "ai_classifier", "hypothesis",
        "ai_unavailable",
    )

    def test_every_known_finding_source_has_a_confidence_row(self):
        missing = [s for s in self.FINDING_SOURCES
                   if s not in sm.CONFIDENCE_BY_SOURCE]
        self.assertEqual(missing, [])

    def test_no_confidence_row_is_outside_zero_to_one(self):
        for source, value in sm.CONFIDENCE_BY_SOURCE.items():
            with self.subTest(source=source):
                self.assertGreater(value, 0.0)
                self.assertLessEqual(value, 1.0)


# ---------------------------------------------------------------------------
# Class tables
# ---------------------------------------------------------------------------
class TestClassTables(unittest.TestCase):
    def test_a_private_ip_is_an_identifier_not_a_credential(self):
        klass = sm.classify_secret("IP Address (Private)")
        self.assertEqual(klass.name, "identifier")
        self.assertLess(klass.impact, 0.2)

    def test_a_cloud_key_is_a_credential(self):
        self.assertEqual(sm.classify_secret("AWS Access Key").name, "credential")
        self.assertEqual(sm.classify_secret("RSA Private Key").name, "credential")

    def test_a_generic_api_key_sits_between_the_two(self):
        klass = sm.classify_secret("Generic API Key")
        self.assertEqual(klass.name, "generic_secret")
        self.assertLess(klass.impact, sm.SECRET_CLASSES["credential"].impact)
        self.assertGreater(klass.impact, sm.SECRET_CLASSES["identifier"].impact)

    def test_a_missing_header_is_hardening(self):
        for check in ("missing_hsts", "missing_csp", "cache_control_missing"):
            with self.subTest(check=check):
                self.assertEqual(sm.classify_security_check(check).name, "hardening")

    def test_a_dmarc_gap_is_spoofing_not_hardening(self):
        self.assertEqual(sm.classify_security_check("dmarc_missing").name, "spoofing")


# ---------------------------------------------------------------------------
# I, R, L
# ---------------------------------------------------------------------------
class TestImpact(unittest.TestCase):
    def test_an_ungraded_advisory_is_unknown_not_info(self):
        """OSV writes severity 'info' for 'never graded'. All 419 PYSEC
        advisories in the dev graph are that, and the old formula scored them
        near zero."""
        result = sm.score(finding(source="osv", severity="info",
                                  package_version="1.0.0"))
        self.assertEqual(result.impact.value, sm.IMPACT_UNKNOWN)

    def test_ungraded_outranks_graded_low_on_purpose(self):
        """The one place a "higher" severity word scores lower, and it is
        correct: OSV writes `severity: info` to mean "never graded", so it is
        MORE uncertain than a graded low, not less severe."""
        ungraded = sm.score(finding(source="osv", severity="info",
                                    package_version="1.0.0"))
        graded_low = sm.score(finding(source="osv", severity="low",
                                      package_version="1.0.0"))
        self.assertGreater(ungraded.impact.value, graded_low.impact.value)

    def test_a_graded_info_finding_really_is_info(self):
        result = sm.score(finding(source="nuclei", severity="info"))
        self.assertEqual(result.impact.value, sm.SEVERITY_IMPACT["info"])

    def test_a_fingerprint_cannot_carry_high_impact(self):
        result = sm.score(finding(severity="high", tags=["tech", "detect"]))
        self.assertEqual(result.impact.value, sm.SEVERITY_IMPACT["info"])

    def test_a_sensitive_asset_raises_impact_but_never_past_the_cap(self):
        facts = sm.ProjectFacts(sensitive_hosts={"h1"})
        plain = sm.score(finding(severity="high"))
        sensitive = sm.score(finding(severity="high"), facts)
        self.assertGreater(sensitive.impact.value, plain.impact.value)
        self.assertLessEqual(sensitive.impact.value, 1.2)

    def test_the_vector_wins_over_the_severity_word(self):
        result = sm.score(finding(
            severity="low",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertGreater(result.impact.value, 0.9)


class TestReach(unittest.TestCase):
    def test_a_live_endpoint_is_fully_reachable(self):
        facts = sm.ProjectFacts(live_hosts={"h1"})
        self.assertEqual(sm.score(finding(), facts).reach.value, 1.0)

    def test_no_evidence_either_way_is_not_zero(self):
        self.assertEqual(sm.score(finding()).reach.value, sm.REACH_UNKNOWN)

    def test_a_passively_seen_port_is_less_reachable_than_an_actively_scanned_one(self):
        passive = sm.score(finding(), sm.ProjectFacts(port_hosts={"h1": "passive"}))
        active = sm.score(finding(), sm.ProjectFacts(port_hosts={"h1": "active"}))
        self.assertLess(passive.reach.value, active.reach.value)

    def test_a_package_only_in_a_lockfile_is_less_reachable_than_one_served(self):
        served = sm.score(
            finding(source="osv", package_purl="pkg:npm/x"),
            sm.ProjectFacts(package_exposure={"pkg:npm/x": "served"}))
        repo = sm.score(
            finding(source="osv", package_purl="pkg:npm/x"),
            sm.ProjectFacts(package_exposure={"pkg:npm/x": "repo"}))
        self.assertGreater(served.reach.value, repo.reach.value)

    def test_a_local_only_vector_is_barely_reachable(self):
        result = sm.score(finding(
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            sm.ProjectFacts(live_hosts={"h1"}))
        self.assertEqual(result.reach.value, 0.3)

    def test_an_exposed_origin_behind_a_cdn_is_fully_reachable(self):
        facts = sm.ProjectFacts(origin_exposed_hosts={"h1"},
                                cdn_only_hosts={"h1"})
        self.assertEqual(sm.score(finding(), facts).reach.value, 1.0)


class TestLikelihood(unittest.TestCase):
    def test_signals_are_maxed_not_summed(self):
        """KEV + EPSS + a public PoC all say the same thing once."""
        one = sm.score(finding(cisa_kev=True, cve_ids=["CVE-2021-1"]),
                       intel={"CVE-2021-1": {"kev": True}})
        many = sm.score(finding(cisa_kev=True, has_exploit=True,
                                cve_ids=["CVE-2021-1"]),
                        intel={"CVE-2021-1": {"kev": True, "epss_score": 0.9,
                                              "has_poc": True}})
        self.assertLessEqual(many.likelihood.value, 1.0)
        self.assertAlmostEqual(one.likelihood.value, many.likelihood.value)

    def test_kev_beats_a_class_prior(self):
        plain = sm.score(finding())
        kev = sm.score(finding(cisa_kev=True))
        self.assertGreater(kev.likelihood.value, plain.likelihood.value)

    def test_required_user_interaction_lowers_likelihood(self):
        direct = sm.score(finding(
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        needs_victim = sm.score(finding(
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"))
        self.assertLess(needs_victim.likelihood.value, direct.likelihood.value)

    def test_a_compromised_host_raises_likelihood_but_the_modifier_is_capped(self):
        facts = sm.ProjectFacts(
            compromised_hosts={"h1"}, threat_intel_hosts={"h1"},
            credential_hosts={"h1"}, login_hosts={"h1"})
        plain = sm.score(finding(cisa_kev=True))
        hot = sm.score(finding(cisa_kev=True), facts)
        self.assertGreater(hot.likelihood.value, plain.likelihood.value)
        self.assertLessEqual(hot.likelihood.value, 1.0)

    def test_a_database_password_in_the_response_is_a_usable_credential(self):
        plain = sm.score(finding(severity="medium", raw_response="<html>hi</html>"))
        leaked = sm.score(finding(severity="medium",
                                  raw_response="DB_PASSWORD=hunter2"))
        self.assertGreater(leaked.likelihood.value, plain.likelihood.value)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
class TestState(unittest.TestCase):
    def test_a_remediated_finding_is_fixed_and_leaves_the_ranking(self):
        result = sm.score(finding(source="gvm", remediated=True, severity="critical"))
        self.assertEqual(result.state, sm.STATE_FIXED)
        self.assertEqual(result.score, 0.0)

    def test_a_stale_finding_is_fixed(self):
        result = sm.score(finding(stale_since="2026-01-01T00:00:00Z"))
        self.assertEqual(result.state, sm.STATE_FIXED)

    def test_a_dead_credential_is_inactive(self):
        result = sm.score(finding(validation_status="unvalidated",
                                  validated_at="2026-01-01T00:00:00Z"))
        self.assertEqual(result.state, sm.STATE_INACTIVE)

    def test_a_never_tested_credential_is_still_open(self):
        """'unvalidated' with no test time means nobody checked, which is not
        the same as 'checked and dead'."""
        self.assertEqual(
            sm.score(finding(validation_status="unvalidated")).state, sm.STATE_OPEN)

    def test_a_finding_on_a_vanished_host_is_gone(self):
        result = sm.score(finding(), sm.ProjectFacts(gone_hosts={"h1"}))
        self.assertEqual(result.state, sm.STATE_GONE)

    def test_a_human_false_positive_leaves_the_ranked_section(self):
        result = sm.score(finding(triage_status="likely_noise",
                                  triage_source="human"))
        self.assertEqual(result.state, sm.STATE_FALSE_POSITIVE)


# ---------------------------------------------------------------------------
# Tiers and the score
# ---------------------------------------------------------------------------
class TestTiers(unittest.TestCase):
    def test_a_proven_finding_is_always_act_now(self):
        result = sm.score(finding(severity="info", confirmed_exploits=1))
        self.assertEqual(result.tier, "T1")

    def test_kev_confident_and_reachable_is_act_now(self):
        result = sm.score(
            finding(cisa_kev=True, severity="high", matcher_status=True,
                    extracted_results=["x"]),
            sm.ProjectFacts(live_hosts={"h1"}))
        self.assertEqual(result.tier, "T1")

    def test_a_kev_cve_nobody_can_reach_is_not_act_now(self):
        result = sm.score(
            finding(cisa_kev=True, severity="high", source="shodan"),
            sm.ProjectFacts(port_hosts={"h1": "passive"}))
        self.assertNotEqual(result.tier, "T1")

    def test_a_private_ip_github_secret_lands_in_track(self):
        """The single most visible symptom: these used to sit at the top."""
        result = sm.score(finding(
            label="GithubSecret", source=None, severity="high",
            detector_name="IP Address (Private)",
            secret_type="IP Address (Private)"))
        self.assertEqual(result.tier, "T4")

    def test_a_missing_header_lands_in_track(self):
        result = sm.score(
            finding(source="security_check", type="missing_hsts", severity="info"),
            sm.ProjectFacts(live_hosts={"h1"}))
        self.assertEqual(result.tier, "T4")

    def test_the_score_is_tier_first_then_risk(self):
        for tier in ("T1", "T2", "T3", "T4"):
            with self.subTest(tier=tier):
                low = sm.score_for(tier, 0.0)
                high = sm.score_for(tier, 1.0)
                self.assertEqual(low, 25.0 * sm.TIER_LEVELS[tier])
                self.assertEqual(high, low + 25.0)

    def test_the_tier_bands_do_not_overlap(self):
        """Each tier owns a 25-point band, and the bands meet rather than
        overlap. A T3 finding therefore never sorts above a T2 one; the shared
        boundary is unreachable in practice, because a risk of exactly 1.0
        requires C, L, I and R all at 1.0, which is already T1 or T2."""
        self.assertGreaterEqual(sm.score_for("T2", 0.0), sm.score_for("T3", 1.0))
        self.assertGreaterEqual(sm.score_for("T1", 0.0), sm.score_for("T2", 1.0))
        self.assertGreater(sm.score_for("T2", 0.0), sm.score_for("T3", 0.99))

    def test_the_score_stays_on_zero_to_one_hundred(self):
        self.assertEqual(sm.score_for("T4", 0.0), 0.0)
        self.assertEqual(sm.score_for("T1", 1.0), 100.0)


# ---------------------------------------------------------------------------
# The eight guarantees (3.2.10)
# ---------------------------------------------------------------------------
#: The factor-bearing fields the property tests vary, and what "better" means
#: for each. Kept here rather than generated, so a reviewer can see exactly what
#: is being claimed.
_IMPROVEMENTS = [
    ("severity", ["info", "low", "medium", "high", "critical"]),
    ("qod", [10, 50, 80, 98]),
]


class TestGuarantees(unittest.TestCase):
    SEED = 20260911

    def test_1_an_open_proven_finding_is_always_t1(self):
        rng = random.Random(self.SEED)
        for _ in range(200):
            row = finding(
                severity=rng.choice(["info", "low", "medium", "high", "critical"]),
                source=rng.choice(list(sm.CONFIDENCE_BY_SOURCE)),
                confirmed_exploits=1,
            )
            self.assertEqual(sm.score(row).tier, "T1")

    def test_2_a_zero_impact_finding_cannot_leave_track_unless_proven(self):
        facts = sm.ProjectFacts(live_hosts={"h1"}, compromised_hosts={"h1"})
        row = finding(source="nuclei", severity="info",
                      cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                      cisa_kev=True)
        self.assertEqual(sm.score(row, facts).tier, "T4")
        row["confirmed_exploits"] = 1
        self.assertEqual(sm.score(row, facts).tier, "T1")

    def test_3_improving_any_factor_never_lowers_the_score(self):
        rng = random.Random(self.SEED)
        for _ in range(300):
            base = finding(
                # Not osv or internetdb: for those, "info" means "this advisory
                # was never graded", so info -> low is a different fact rather
                # than an improvement of the same one. That case is pinned on
                # its own in test_ungraded_outranks_graded_low_on_purpose.
                source=rng.choice(["nuclei", "gvm", "shodan", "js_recon"]),
                severity=rng.choice(["info", "low", "medium", "high"]),
                package_version=rng.choice([None, "1.0.0"]),
                cve_ids=rng.choice([[], ["CVE-2021-1"]]),
            )
            for field_name, ladder in _IMPROVEMENTS:
                previous = None
                for value in ladder:
                    row = dict(base, **{field_name: value})
                    current = sm.score(row).score
                    if previous is not None:
                        self.assertGreaterEqual(
                            current, previous,
                            f"{field_name}={value} lowered the score: {row}")
                    previous = current

    def test_3b_adding_reachability_never_lowers_the_score(self):
        rng = random.Random(self.SEED + 1)
        for _ in range(200):
            row = finding(
                source=rng.choice(["nuclei", "gvm", "osv"]),
                severity=rng.choice(["low", "medium", "high", "critical"]),
            )
            unknown = sm.score(row, sm.ProjectFacts()).score
            live = sm.score(row, sm.ProjectFacts(live_hosts={"h1"})).score
            self.assertGreaterEqual(live, unknown)

    def test_4_resolved_and_false_positive_findings_are_never_ranked(self):
        for row in (
            finding(remediated=True, severity="critical", confirmed_exploits=1),
            finding(stale_since="2026-01-01", severity="critical"),
            finding(validation_status="unvalidated", validated_at="2026-01-01"),
            finding(triage_status="likely_noise", triage_source="ai"),
        ):
            with self.subTest(row=row):
                result = sm.score(row, sm.ProjectFacts())
                self.assertNotEqual(result.state, sm.STATE_OPEN)
                self.assertEqual(result.score, 0.0)

    def test_5_removing_any_single_fact_never_raises_the_score(self):
        rich = finding(
            source="nuclei", severity="high", matcher_status=True,
            extracted_results=["proof"], cisa_kev=True, cve_ids=["CVE-2021-1"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            package_version="1.0.0",
        )
        facts = sm.ProjectFacts(live_hosts={"h1"}, sensitive_hosts={"h1"})
        intel = {"CVE-2021-1": {"kev": True, "epss_score": 0.9, "has_poc": True}}
        full = sm.score(rich, facts, intel).score
        for key in list(rich):
            if key in ("id", "label", "host"):
                continue
            with self.subTest(removed=key):
                thinner = {k: v for k, v in rich.items() if k != key}
                self.assertLessEqual(sm.score(thinner, facts, intel).score, full)

    def test_7_the_same_inputs_give_the_same_answer(self):
        row = finding(source="gvm", qod=90, cisa_kev=True, severity="high")
        facts = sm.ProjectFacts(live_hosts={"h1"})
        first = sm.score(row, facts)
        second = sm.score(row, facts)
        self.assertEqual(first.score, second.score)
        self.assertEqual(first.tier, second.tier)
        self.assertEqual(first.signals, second.signals)

    def test_8_a_group_is_at_least_its_best_member_and_never_over_one(self):
        rng = random.Random(self.SEED + 2)
        for _ in range(300):
            risks = [rng.random() for _ in range(rng.randint(1, 12))]
            grouped = sm.group_risk(risks)
            self.assertGreaterEqual(grouped + 1e-9, max(risks))
            self.assertLessEqual(grouped, 1.0)

    def test_8b_a_group_of_one_is_exactly_that_member(self):
        self.assertAlmostEqual(sm.group_risk([0.37]), 0.37)

    def test_8c_the_best_tier_in_a_group_wins(self):
        self.assertEqual(sm.best_tier(["T3", "T1", "T4"]), "T1")
        self.assertEqual(sm.best_tier([]), "T4")


# ---------------------------------------------------------------------------
# Robustness: a thin or hostile row must not raise
# ---------------------------------------------------------------------------
class TestNeverRaises(unittest.TestCase):
    def test_an_empty_row_scores(self):
        result = sm.score({})
        self.assertEqual(result.state, sm.STATE_OPEN)
        self.assertGreaterEqual(result.score, 0.0)

    def test_none_scores(self):
        self.assertIsInstance(sm.score(None), sm.ScoreResult)

    def test_wrong_types_everywhere_do_not_raise(self):
        row = {
            "id": 42, "label": None, "source": ["nuclei"], "severity": {},
            "cvss_score": "not a number", "cve_ids": "CVE-2021-1",
            "qod": "high", "tags": "tech", "cisa_kev": "yes",
            "extracted_results": 7, "confidence": object(),
        }
        result = sm.score(row)
        self.assertGreaterEqual(result.score, 0.0)
        self.assertLessEqual(result.score, 100.0)

    def test_the_explanation_reads_as_a_sentence(self):
        result = sm.score(finding(severity="high"))
        self.assertIn("real ", result.explanation)
        self.assertIn("->", result.explanation)

    def test_the_factors_dict_carries_the_evidence_for_each(self):
        stored = sm.score(finding(severity="high")).as_factors_dict()
        self.assertEqual(set(stored), {"C", "L", "I", "R"})
        for factor in stored.values():
            self.assertIn("value", factor)
            self.assertIn("evidence", factor)


# ---------------------------------------------------------------------------
# The worked example from the plan (section 3.8), as a regression
# ---------------------------------------------------------------------------
class TestWorkedExample(unittest.TestCase):
    """Fictional data only: reserved example domains and documentation IPs."""

    def setUp(self):
        self.facts = sm.ProjectFacts(
            live_hosts={"web.example.com"},
            port_hosts={"203.0.113.10": "active"},
            package_exposure={"pkg:npm/lib": "served", "pkg:npm/lib-repo": "repo"},
        )
        self.intel = {"CVE-2021-41773": {"kev": True}}

    def test_the_kev_rce_outranks_everything_else(self):
        rce = sm.score(finding(
            id="F4", source="nuclei", severity="high", host="203.0.113.10",
            cve_ids=["CVE-2021-41773"], matcher_status=True,
            extracted_results=["root:x:0:0"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            self.facts, self.intel)
        private_ip = sm.score(finding(
            id="S1", label="GithubSecret", source=None, severity="high",
            detector_name="IP Address (Private)"), self.facts, self.intel)
        header = sm.score(finding(
            id="G3", source="security_check", type="missing_hsts",
            severity="info", host="web.example.com"), self.facts, self.intel)

        self.assertEqual(rce.tier, "T1")
        self.assertEqual(private_ip.tier, "T4")
        self.assertEqual(header.tier, "T4")
        self.assertGreater(rce.score, private_ip.score)
        self.assertGreater(rce.score, header.score)

    def test_a_served_dependency_outranks_the_same_advisory_in_a_lockfile(self):
        served = sm.score(finding(
            id="O1", source="osv", severity="high", package_version="1.0.0",
            package_purl="pkg:npm/lib", host="web.example.com",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            self.facts)
        in_repo = sm.score(finding(
            id="O2", source="osv", severity="high", package_version="1.0.0",
            package_purl="pkg:npm/lib-repo",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            self.facts)
        self.assertGreater(served.score, in_repo.score)

    def test_the_group_outranks_each_of_its_members(self):
        risks = [0.51, 0.51]
        grouped = sm.group_risk(risks)
        self.assertGreater(sm.score_for("T1", grouped), sm.score_for("T1", 0.51))


class TestProofReadBackFromTheGraph(unittest.TestCase):
    """Strategy row 3. The CONFIRMS edge is only worth writing if the model reads
    it back: the proof fact query collects the confirmed finding ids, the facts
    reducer folds them into `proven_finding_ids`, and `is_proven` turns that into
    C = 1.0 and Act now. A break in any link leaves a demonstrated finding
    wherever its detection confidence put it."""

    def _facts(self, finding_ids):
        from cypherfix_triage.fact_queries import build_project_facts
        return build_project_facts({"proof": [{
            "chain_id": "cf1", "finding_type": "vulnerability_confirmed",
            "cve_ids": [], "finding_ids": finding_ids, "hosts": [],
            "target_host": "",
        }]})

    def test_a_confirmed_finding_scores_as_proven(self):
        row = finding(id="v-proved", source="nuclei", severity="low")
        result = sm.score(row, self._facts(["v-proved"]), {})
        self.assertEqual(result.tier, "T1")
        self.assertEqual(sm.confidence(row, self._facts(["v-proved"])).value, 1.0)

    def test_the_same_finding_without_the_edge_is_not_proven(self):
        """The control: it is the edge doing the work, not the fixture."""
        row = finding(id="v-proved", source="nuclei", severity="low")
        result = sm.score(row, self._facts(["someone-else"]), {})
        self.assertNotEqual(result.tier, "T1")

    def test_nulls_in_the_collected_ids_are_harmless(self):
        """Cypher's collect() leaves Nones in when the OPTIONAL MATCH missed."""
        facts = self._facts([None, "", "v-proved"])
        self.assertEqual(facts.proven_finding_ids, {"v-proved"})


if __name__ == "__main__":
    unittest.main()
