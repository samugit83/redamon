"""Regression tests for the score model's mis-scored findings, plus a guard
that the fixes moved nothing else.

F1  every security_check scored C 1.0, though several only infer the problem
    (an open port, a keyword, a Server header, an AI classifier's opinion);
F2  check types missing from the class table fell back to a hygiene-grade
    misconfig class, so an unauthenticated Redis ranked with a missing DMARC;
F3  public-by-design client keys (Stripe pk, AIza, Sentry DSN, ...) were
    scored as credentials, and a validated browser key reached T1;
F5  a credential a validator tested and the service rejected stayed ranked;
F6  a GitHub finding with no `repository_public` keeps today's reach.

The guard table was computed on the unmodified model (v3.2.0) and is pinned
as literals: a later table edit that moves one of them fails here, not on a
user's board.

Run: ./agentic/run_tests.sh tests/test_fix_triage_scoring.py
"""

import json
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SECURITY_CHECKS_SRC = REPO_ROOT / "recon" / "helpers" / "security_checks.py"
GITHUB_HUNT_SRC = REPO_ROOT / "scanners" / "github_secret_hunt" / "github_secret_hunt.py"
JS_PATTERNS_SRC = REPO_ROOT / "recon" / "helpers" / "js_recon" / "patterns.py"

LIVE = sm.ProjectFacts(live_hosts={"h1"})
INTEL = {"CVE-2021-44228": {"kev": True, "epss_score": 0.97, "has_poc": True}}
HASH = "b" * 40


def check(check_type, severity, **kwargs):
    row = {"id": "x", "label": "Vulnerability", "source": "security_check",
           "host": "h1", "type": check_type, "severity": severity}
    row.update(kwargs)
    return row


def secret(label, source, secret_type, detector=None, **kwargs):
    row = {"id": "s", "label": label, "source": source, "host": "h1",
           "secret_type": secret_type,
           "detector_name": secret_type if detector is None else detector}
    row.update(kwargs)
    return row


def js_secret(secret_type, category, **kwargs):
    fields = {"severity": "critical", "confidence": "high"}
    fields.update(kwargs)
    return secret("Secret", "js_recon", secret_type, category, **fields)


def validation_info(info="", error=""):
    return json.dumps({"status": "invalid", "valid": False, "info": info, "error": error})


def _read(path: Path) -> str:
    if not path.exists():
        raise unittest.SkipTest(f"{path} is not mounted in this container")
    return path.read_text(encoding="utf-8")


def producer_check_types() -> set:
    """Every security_check `type` the recon producers can emit."""
    text = _read(SECURITY_CHECKS_SRC)
    types = set(re.findall(r'"type":\s*"([a-z0-9_]+)"', text))
    types |= set(re.findall(r'_add\(\s*"([a-z0-9_]+)"', text))
    types |= set(re.findall(r'"check_name":\s*"([a-z0-9_]+)"', text))
    # The Page Content checks emit their type from the PAGE_CONTENT_CHECKS table.
    types |= set(re.findall(r'^\s*"([a-z0-9_]+)":\s*\("[a-z_]+",\s*"SECURITY_CHECK_', text, re.M))
    return types


def _python_string_block(text: str, opener: str) -> set:
    """The quoted strings of the tuple or frozenset that starts at `opener`."""
    start = text.index(opener)
    end = text.index(")", start)
    return set(re.findall(r'"([^"]+)"', text[start + len(opener):end]))


def producer_secret_names() -> dict:
    """{producer: {secret_type names}} from the two pattern tables. js_recon
    also writes the names it re-reads a hit under (DERIVED_SECRET_NAMES)."""
    hunt = set(re.findall(r'^\s*"([^"]+)":\s*r["\']', _read(GITHUB_HUNT_SRC), re.M))
    js_src = _read(JS_PATTERNS_SRC)
    js = set(re.findall(r'^\s*\("([^"]+)",\s*r["\']', js_src, re.M))
    js |= _python_string_block(js_src, "DERIVED_SECRET_NAMES = (")
    return {"github_hunt": hunt, "js_recon": js}


def js_public_client_key_names() -> set:
    """js_recon's PUBLIC_CLIENT_KEY_NAMES, read from its source: the recon
    module is not importable in the agent image."""
    return _python_string_block(_read(JS_PATTERNS_SRC), "PUBLIC_CLIENT_KEY_NAMES = frozenset({")


# ---------------------------------------------------------------------------
# F1: per-check-type confidence
# ---------------------------------------------------------------------------
class TestSecurityCheckConfidence(unittest.TestCase):
    #: Checks that saw the condition themselves: these stay facts.
    OBSERVED = ("missing_referrer_policy", "cache_control_missing", "spf_missing",
                "dmarc_missing", "dnssec_missing", "tls_expired", "tls_self_signed",
                "tls_weak_cipher_supported", "redis_no_auth", "zone_transfer",
                "smtp_open_relay", "login_no_https", "basic_auth_no_tls",
                "session_no_secure", "session_no_httponly", "csp_unsafe_inline",
                "insecure_form_action", "direct_ip_http", "direct_ip_https",
                "some_future_check")

    #: Checks that infer the problem from a weaker signal.
    INFERRED = ("admin_port_exposed", "database_exposed", "kubernetes_api_exposed",
                "ip_api_exposed", "no_rate_limiting", "cache_purge_exposed")

    def c_of(self, row, facts=None):
        return sm.confidence(row, facts or sm.ProjectFacts()).value

    def test_observed_checks_keep_a_confidence_of_one(self):
        for check_type in self.OBSERVED:
            with self.subTest(check=check_type):
                self.assertEqual(self.c_of(check(check_type, "medium")), 1.0)

    def test_inferred_checks_get_a_detector_grade_confidence(self):
        for check_type in self.INFERRED:
            with self.subTest(check=check_type):
                value = self.c_of(check(check_type, "high"))
                self.assertLess(value, 1.0)
                self.assertLessEqual(value, sm.DETECTOR_MAX_CONFIDENCE)
                # Still credible enough for T3: the fix ranks them lower, it
                # does not push them off the board.
                self.assertGreaterEqual(value, 0.4)

    def test_an_open_port_is_not_a_fact_about_the_service(self):
        self.assertEqual(self.c_of(check("admin_port_exposed", "medium")), 0.75)
        self.assertEqual(self.c_of(check("database_exposed", "high")), 0.75)

    def test_waf_bypass_confidence_follows_the_detection_method(self):
        def c(method):
            return self.c_of(check("waf_bypass", "high", detection_method=method))
        # The producer now needs a 2xx origin page matching the edge's benign
        # page, so a 302 to login, a 401, a 404 or a 421 is no longer "served".
        self.assertEqual(c("payload_differential"), 0.95)
        self.assertEqual(c("static_headers"), 0.75)
        self.assertEqual(c("ai_classifier"), 0.6)
        self.assertEqual(c("jev_classifier"), 0.6)
        self.assertGreater(c("payload_differential"), c("static_headers"))
        self.assertGreater(c("static_headers"), c("ai_classifier"))

    def test_a_waf_bypass_written_before_the_method_was_stored_keeps_one(self):
        for missing in (None, ""):
            with self.subTest(detection_method=missing):
                self.assertEqual(
                    self.c_of(check("waf_bypass", "high", detection_method=missing)), 1.0)

    def test_an_unknown_detection_method_gets_the_unknown_default(self):
        result = sm.confidence(check("waf_bypass", "high", detection_method="telepathy"),
                               sm.ProjectFacts())
        self.assertEqual(result.value, sm.CONFIDENCE_UNKNOWN_SOURCE)
        self.assertIn("telepathy", result.evidence)

    def test_the_method_is_read_case_insensitively(self):
        self.assertEqual(
            self.c_of(check("waf_bypass", "high", detection_method=" AI_Classifier ")), 0.6)

    def test_the_type_falls_back_to_the_name_as_before(self):
        row = check(None, "high", name="admin_port_exposed")
        self.assertEqual(self.c_of(row), 0.75)

    def test_operator_false_positives_still_lower_an_inferred_check(self):
        row = check("admin_port_exposed", "medium")
        facts = sm.ProjectFacts(detector_labels={"check:admin_port_exposed": {"real": 0, "fp": 10}})
        self.assertAlmostEqual(self.c_of(row, facts), sm.learned_confidence(0.75, 0, 10))
        self.assertLess(self.c_of(row, facts), 0.75)

    def test_operator_false_positives_still_lower_an_observed_check(self):
        facts = sm.ProjectFacts(detector_labels={"check:dmarc_missing": {"real": 0, "fp": 10}})
        self.assertAlmostEqual(self.c_of(check("dmarc_missing", "medium"), facts), 0.5)

    def test_proof_still_wins_over_an_inferred_check(self):
        row = check("database_exposed", "high", id="v-db")
        facts = sm.ProjectFacts(proven_finding_ids={"v-db"})
        result = sm.score(row, facts)
        self.assertEqual(result.confidence.value, 1.0)
        self.assertEqual(result.tier, "T1")

    def test_a_doubtful_review_still_drops_confidence_to_a_quarter(self):
        base = sm.BaseLayer.from_result(
            sm.score(check("waf_bypass", "high", detection_method="static_headers"), LIVE))
        final = sm.combine_layers(base, sm.ReviewLayer("doubtful", HASH), None, HASH)
        self.assertEqual(final.factors["C"]["value"], 0.25)

    def test_every_confidence_override_names_a_real_check(self):
        """A typo in the table would silently leave a heuristic at 1.0."""
        unknown = set(sm.SECURITY_CHECK_CONFIDENCE) - producer_check_types()
        self.assertEqual(unknown, set())

    def test_every_waf_method_the_producer_writes_has_a_row(self):
        text = _read(SECURITY_CHECKS_SRC)
        methods = set(re.findall(r'"detection_method":\s*"([a-z_]+)"', text))
        methods |= set(re.findall(r'detection_method = \(?"([a-z_]+)"', text))
        ai_methods = re.search(r"^_AI_DETECTION_METHODS\s*=\s*\(([^)]*)\)", text, re.M)
        self.assertIsNotNone(ai_methods, "_AI_DETECTION_METHODS moved; update this test")
        methods |= set(re.findall(r'"([a-z_]+)"', ai_methods.group(1)))
        methods.discard("method_differential")      # cache_purge_exposed's, not waf_bypass's
        self.assertTrue({"payload_differential", "static_headers", "ai_classifier",
                         "jev_classifier"} <= methods)
        self.assertEqual(methods - set(sm.WAF_BYPASS_CONFIDENCE), set())


# ---------------------------------------------------------------------------
# F2: every emitted check type has an explicit class
# ---------------------------------------------------------------------------
class TestSecurityCheckClasses(unittest.TestCase):
    HIGH_RISK = ("redis_no_auth", "kubernetes_api_exposed", "database_exposed",
                 "smtp_open_relay", "zone_transfer")
    CLEARTEXT = ("login_no_https", "basic_auth_no_tls")
    LOW_HYGIENE = ("dnssec_missing", "tls_expiring_soon", "csp_unsafe_inline",
                   "tls_wildcard_overbroad", "tls_weak_version_supported",
                   "tls_weak_cipher_supported")

    #: The producers' own severity for each, from recon/helpers/security_checks.py.
    SEVERITY = {
        "redis_no_auth": "critical", "kubernetes_api_exposed": "high",
        "database_exposed": "high", "smtp_open_relay": "high", "zone_transfer": "high",
        "login_no_https": "high", "basic_auth_no_tls": "high", "dnssec_missing": "low",
        "tls_expiring_soon": "low", "csp_unsafe_inline": "medium",
        "tls_wildcard_overbroad": "low", "tls_weak_version_supported": "medium",
        "tls_weak_cipher_supported": "medium", "dmarc_missing": "medium",
    }

    def score_of(self, check_type, facts=LIVE):
        return sm.score(check(check_type, self.SEVERITY[check_type]), facts).score

    def test_every_check_type_a_producer_emits_has_an_explicit_entry(self):
        """A new check must not silently fall back to the generic class."""
        missing = sorted(
            t for t in producer_check_types()
            if t not in sm.SECURITY_CHECK_CLASSES and not t.startswith("missing_"))
        self.assertEqual(missing, [])

    def test_the_extraction_actually_found_the_producers(self):
        """Guards the test above against a regex that matches nothing."""
        found = producer_check_types()
        for expected in ("redis_no_auth", "tls_weak_cipher_supported",
                         "missing_coep", "dnssec_missing", "open_console", "test_certificate"):
            self.assertIn(expected, found)

    def test_an_unauthenticated_redis_outranks_a_missing_dmarc(self):
        for facts in (LIVE, sm.ProjectFacts()):
            with self.subTest(live=bool(facts.live_hosts)):
                redis = self.score_of("redis_no_auth", facts)
                dmarc = self.score_of("dmarc_missing", facts)
                self.assertGreater(redis, dmarc + 5)

    def test_the_three_bands_are_ordered(self):
        high = min(self.score_of(t) for t in self.HIGH_RISK)
        cleartext = [self.score_of(t) for t in self.CLEARTEXT]
        hygiene = max(self.score_of(t) for t in self.LOW_HYGIENE + ("dmarc_missing",))
        self.assertGreater(high, max(cleartext))
        self.assertGreater(min(cleartext), hygiene)

    def test_low_risk_hygiene_stays_at_or_below_dmarc(self):
        dmarc = self.score_of("dmarc_missing")
        for check_type in self.LOW_HYGIENE:
            with self.subTest(check=check_type):
                self.assertLessEqual(self.score_of(check_type), dmarc)

    def test_high_risk_checks_are_not_impact_capped(self):
        for check_type in self.HIGH_RISK:
            with self.subTest(check=check_type):
                self.assertFalse(sm.classify_security_check(check_type).caps_impact)

    def test_an_anonymous_kubernetes_api_outranks_one_that_asks_for_a_login(self):
        anonymous = sm.score(check("kubernetes_api_exposed", "critical"), LIVE).score
        login = sm.score(check("kubernetes_api_exposed", "high"), LIVE).score
        self.assertGreater(anonymous, login)

    def test_the_new_rows_stay_out_of_act_now(self):
        """None of them is proven or KEV-listed, so none may reach T1."""
        for check_type in self.HIGH_RISK + self.CLEARTEXT:
            with self.subTest(check=check_type):
                self.assertNotEqual(sm.score(check(check_type, "critical"), LIVE).tier, "T1")

    def test_pinned_values_for_the_reclassified_checks(self):
        expected = {
            # type: (severity, C, L, I, tier, score on a live host)
            "redis_no_auth": ("critical", 1.0, 0.5, 1.0, "T3", 37.5),
            "kubernetes_api_exposed": ("critical", 0.6, 0.5, 1.0, "T3", 32.5),
            "database_exposed": ("high", 0.75, 0.5, 0.75, "T3", 32.0312),
            "smtp_open_relay": ("high", 1.0, 0.5, 0.75, "T3", 34.375),
            "zone_transfer": ("high", 1.0, 0.5, 0.75, "T3", 34.375),
            "login_no_https": ("high", 1.0, 0.3, 0.5, "T3", 28.75),
            "basic_auth_no_tls": ("high", 1.0, 0.3, 0.5, "T3", 28.75),
            "admin_port_exposed": ("medium", 0.75, 0.3, 0.3, "T3", 26.6875),
            "cache_purge_exposed": ("high", 0.75, 0.3, 0.3, "T3", 26.6875),
            "ip_api_exposed": ("high", 0.6, 0.3, 0.5, "T3", 27.25),
            "no_rate_limiting": ("medium", 0.6, 0.2, 0.3, "T3", 25.9),
        }
        for check_type, (severity, c, l, i, tier, score) in expected.items():
            with self.subTest(check=check_type):
                result = sm.score(check(check_type, severity), LIVE)
                self.assertAlmostEqual(result.confidence.value, c)
                self.assertAlmostEqual(result.likelihood.value, l)
                self.assertAlmostEqual(result.impact.value, i)
                self.assertEqual(result.tier, tier)
                self.assertAlmostEqual(result.score, score, places=4)

    def test_an_unknown_type_still_falls_back_to_misconfig(self):
        klass = sm.classify_security_check("a_check_from_the_future")
        self.assertEqual((klass.name, klass.likelihood, klass.impact, klass.caps_impact),
                         ("misconfig", 0.3, 0.3, True))

    def test_the_unemitted_rows_are_left_as_they_were(self):
        self.assertEqual(sm.classify_security_check("cors_misconfiguration"),
                         sm.FindingClass("misconfig", 0.4, 0.5, caps_impact=True))
        self.assertEqual(sm.classify_security_check("open_redirect"),
                         sm.FindingClass("misconfig", 0.3, 0.3, caps_impact=True))


# ---------------------------------------------------------------------------
# F3: public-by-design client keys
# ---------------------------------------------------------------------------
class TestPublicClientKeys(unittest.TestCase):
    PRODUCER_NAMES = ("GCP API Key", "Firebase API Key", "Segment Write Key",
                      "Amplitude API Key", "New Relic Browser API Token", "Sentry DSN",
                      "Stripe Publishable Key", "Google reCAPTCHA Key", "Mapbox Token",
                      "Algolia App ID", "Algolia Search Key", "Intercom App ID",
                      "Pusher Key", "Clerk Publishable Key", "Mailgun Public Key",
                      "Flutterwave Public Key", "Supabase anon key", "Supabase Publishable Key")

    def test_the_list_is_js_recons_list(self):
        """js_recon writes these at info with the flag; the board must agree on
        every name, or a key the detector calls public is ranked as a secret."""
        self.assertEqual(set(sm.PUBLIC_CLIENT_KEY_TYPES) - {"gcpkey"},
                         {n.lower() for n in js_public_client_key_names()})
        self.assertEqual({n.lower() for n in self.PRODUCER_NAMES},
                         {n.lower() for n in js_public_client_key_names()})

    def test_the_public_names_exist_in_a_producer(self):
        """A rename in a producer would silently turn the rule off."""
        names = producer_secret_names()
        for name in self.PRODUCER_NAMES:
            with self.subTest(name=name):
                self.assertIn(name, names["js_recon"])
        # The GitHub hunt shares most of them; these are js_recon-only.
        hunt_only_missing = {"Intercom App ID", "Algolia Search Key", "Supabase anon key",
                             "Supabase Publishable Key"}
        for name in set(self.PRODUCER_NAMES) - hunt_only_missing:
            with self.subTest(producer="github_hunt", name=name):
                self.assertIn(name, names["github_hunt"])

    def test_every_public_name_is_one_a_producer_writes(self):
        known = {n.lower() for found in producer_secret_names().values() for n in found}
        # jsluice is a Go binary; its AIza key kind is "gcpKey".
        self.assertEqual(set(sm.PUBLIC_CLIENT_KEY_TYPES) - known, {"gcpkey"})

    def test_each_public_family_lands_in_t4(self):
        for name in self.PRODUCER_NAMES:
            for severity in ("info", "critical"):  # critical: a node written before the flag
                with self.subTest(name=name, severity=severity):
                    row = js_secret(name, "js_service", severity=severity,
                                    validation_status="unvalidated")
                    self.assertEqual(sm.score(row, LIVE).tier, "T4")
                    hunt = secret("GithubSecret", "github_hunt", name, severity=severity)
                    self.assertEqual(sm.score(hunt, LIVE).tier, "T4")

    def test_public_keys_are_classed_as_public(self):
        for name in self.PRODUCER_NAMES + ("gcpKey",):
            with self.subTest(name=name):
                self.assertEqual(sm.classify_secret(name, name).name, "public_client_id")
                # js_recon stores the category as the detector.
                self.assertEqual(sm.classify_secret("cloud", name).name, "public_client_id")

    def test_secret_keys_of_the_same_vendors_stay_credentials(self):
        for name in ("Stripe Live Key", "Stripe Secret Key", "Stripe Restricted Key",
                     "Stripe Test Key", "GCP Service Account", "GCP", "Stripe",
                     "Sentry Access Token"):
            with self.subTest(name=name):
                self.assertNotEqual(sm.classify_secret(name, name).name, "public_client_id")
        self.assertEqual(sm.classify_secret("GCP", "GCP").name, "credential")
        self.assertEqual(sm.classify_secret("payment", "Stripe Secret Key").name, "credential")

    def test_only_the_listed_producer_names_are_public(self):
        """Exact names, never substrings: no other producer pattern becomes public."""
        for producer, found in producer_secret_names().items():
            for name in found:
                with self.subTest(producer=producer, name=name):
                    if sm.classify_secret(name, name).name == "public_client_id":
                        self.assertIn(name, self.PRODUCER_NAMES)

    def test_a_browser_key_in_js_is_track_not_act_soon(self):
        """Measured on the dev graph at T2 60.1 before the fix."""
        result = sm.score(js_secret("GCP API Key", "cloud", validation_status="skipped"), LIVE)
        self.assertEqual(result.tier, "T4")
        self.assertLess(result.impact.value, 0.2)

    def test_every_public_key_ranks_below_an_unauthenticated_redis(self):
        redis = sm.score(check("redis_no_auth", "critical"), LIVE).score
        rows = [js_secret(n, "js_service") for n in self.PRODUCER_NAMES]
        rows += [secret("GithubSecret", "github_hunt", n, severity="high")
                 for n in self.PRODUCER_NAMES]
        rows.append(js_secret("GCP API Key", "cloud", validation_status="validated"))
        for row in rows:
            with self.subTest(row=row["secret_type"], label=row["label"],
                              validation=row.get("validation_status")):
                self.assertLess(sm.score(row, LIVE).score, redis)

    def test_a_validated_browser_key_is_a_finding_but_not_credential_grade(self):
        """The Geocoding validator worked: the key is unrestricted, so billing
        abuse is real. Measured at T1 97.5 before the fix."""
        row = js_secret("GCP API Key", "cloud", validation_status="validated")
        result = sm.score(row, LIVE)
        self.assertFalse(result.proven)
        self.assertFalse(sm.is_proven(row, LIVE))
        self.assertEqual(result.tier, "T3")
        self.assertLessEqual(result.impact.value, 0.45)
        self.assertEqual(result.confidence.value, 0.95)
        self.assertNotIn("proven", result.signals)

    def test_no_review_or_person_lifts_a_validated_browser_key_to_t2(self):
        row = js_secret("GCP API Key", "cloud", validation_status="validated")
        base = sm.BaseLayer.from_result(sm.score(row, LIVE))
        review = sm.ReviewLayer("real", HASH, impact_multiplier=1.5,
                                impact_quote="Geocoding API accessible")
        for decision in (None, sm.DecisionLayer("confirmed")):
            with self.subTest(decision=decision):
                final = sm.combine_layers(base, review, decision, HASH)
                self.assertEqual(final.tier, "T3")

    def test_a_validated_secret_key_is_still_proven(self):
        row = js_secret("Stripe Secret Key", "payment", validation_status="validated")
        self.assertTrue(sm.is_proven(row, LIVE))
        self.assertEqual(sm.score(row, LIVE).tier, "T1")


# ---------------------------------------------------------------------------
# F5: a credential tested and rejected leaves the ranking
# ---------------------------------------------------------------------------
class TestRejectedCredentialsAreInactive(unittest.TestCase):
    def state(self, **kwargs):
        return sm.score(js_secret("Stripe Secret Key", "payment", **kwargs), LIVE)

    def test_a_key_the_service_refused_is_inactive(self):
        result = self.state(validation_status="invalid",
                            validation_info=validation_info("status=401"))
        self.assertEqual(result.state, sm.STATE_INACTIVE)
        self.assertEqual(result.score, 0.0)

    def test_a_key_whose_format_the_validator_rejected_is_inactive(self):
        result = self.state(validation_status="invalid",
                            validation_info=validation_info("Token too short", "format_invalid"))
        self.assertEqual(result.state, sm.STATE_INACTIVE)

    def test_a_google_key_denied_for_the_paid_api_stays_a_low_public_key(self):
        # Restricted, not dead: the key still works for the APIs it is meant for.
        result = sm.score(js_secret(
            "GCP API Key", "cloud", validation_status="invalid",
            validation_info=validation_info("Key denied for Geocoding API")), LIVE)
        self.assertEqual(result.state, sm.STATE_OPEN)
        self.assertEqual(result.tier, "T4")

    def test_validation_info_already_decoded_is_read_too(self):
        result = self.state(validation_status="invalid",
                            validation_info={"status": "invalid", "info": "status=401",
                                             "error": ""})
        self.assertEqual(result.state, sm.STATE_INACTIVE)

    def test_an_answer_that_is_not_a_401_is_not_a_rejection(self):
        # 403 is often a live key lacking the probe's scope or SSO grant; a
        # live credential must never be hidden on a guess.
        for info in ("status=403", "status=404", "status=400", "Could not extract key ID", ""):
            with self.subTest(info=info):
                result = self.state(validation_status="invalid",
                                    validation_info=validation_info(info))
                self.assertEqual(result.state, sm.STATE_OPEN)

    def test_a_call_that_never_got_an_answer_is_not_a_verdict(self):
        for error in ("timeout", "ConnectionError", "SSLError",
                      "skipped (circuit open)", "no_key_found", "no_token_found"):
            with self.subTest(error=error):
                result = self.state(validation_status="invalid",
                                    validation_info=validation_info("", error))
                self.assertEqual(result.state, sm.STATE_OPEN)

    def test_a_rate_limit_or_a_server_error_is_not_a_verdict(self):
        for info in ("status=429", "status=500", "status=503"):
            with self.subTest(info=info):
                result = self.state(validation_status="invalid",
                                    validation_info=validation_info(info))
                self.assertEqual(result.state, sm.STATE_OPEN)

    def test_invalid_with_no_readable_detail_keeps_today_s_behaviour(self):
        for info in (None, "", "   ", "not json", "[]", "42"):
            with self.subTest(validation_info=info):
                result = self.state(validation_status="invalid", validation_info=info)
                self.assertEqual(result.state, sm.STATE_OPEN)

    def test_statuses_that_are_not_a_rejection_never_make_it_inactive(self):
        answered = validation_info("status=401")
        for status in ("unvalidated", "unverified", "unknown", "error", "verify_error",
                       "skipped", "incomplete", "format_validated", "", None):
            with self.subTest(status=status):
                result = self.state(validation_status=status, validation_info=answered)
                self.assertEqual(result.state, sm.STATE_OPEN)

    def test_the_legacy_tested_and_dead_rule_still_holds(self):
        result = sm.score(secret("MultiscannerFinding", "trufflehog", "AWS",
                                 validation_status="unvalidated",
                                 validated_at="2026-01-01T00:00:00Z"), LIVE)
        self.assertEqual(result.state, sm.STATE_INACTIVE)

    def test_an_inactive_finding_stays_out_even_after_a_person_says_real(self):
        result = self.state(validation_status="invalid",
                            validation_info=validation_info("status=401"))
        final = sm.combine_layers(sm.BaseLayer.from_result(result), None,
                                  sm.DecisionLayer("confirmed"), "")
        self.assertEqual(final.state, sm.STATE_INACTIVE)
        self.assertEqual(final.score, 0.0)


# ---------------------------------------------------------------------------
# F6: repository_public is read as unknown when it is missing
# ---------------------------------------------------------------------------
class TestRepositoryReach(unittest.TestCase):
    def reach_of(self, **kwargs):
        row = secret("GithubSecret", "github_hunt", "AWS Access Key ID",
                     host="acme/repo", severity="high", **kwargs)
        return sm.score(row, sm.ProjectFacts()).reach.value

    def test_a_missing_value_is_unknown(self):
        self.assertEqual(self.reach_of(), sm.REACH_UNKNOWN)
        self.assertEqual(self.reach_of(repository_public=None), sm.REACH_UNKNOWN)

    def test_a_private_repository_is_not_scored_as_public(self):
        self.assertEqual(self.reach_of(repository_public=False), sm.REACH_UNKNOWN)
        self.assertEqual(self.reach_of(repository_public="false"), sm.REACH_UNKNOWN)

    def test_a_public_repository_is_fully_reachable(self):
        self.assertEqual(self.reach_of(repository_public=True), 1.0)


# ---------------------------------------------------------------------------
# Guard: findings the fixes must not move (computed on the v3.2.0 model)
# ---------------------------------------------------------------------------
#: name: (finding, (state, tier, score) on a live host, the same with no facts)
GUARD = {
    'nuclei_critical_cve_kev': (
        {'cve_ids': ['CVE-2021-44228'], 'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'extracted_results': ['x'], 'host': 'h1', 'id': 'n1', 'label': 'Vulnerability', 'matcher_status': True, 'severity': 'critical', 'source': 'nuclei', 'template_id': 'cve-2021-44228'},
        ('open', 'T1', 96.367),
        ('open', 'T1', 92.0936)),
    'nuclei_critical_plain': (
        {'host': 'h1', 'id': 'n2', 'label': 'Vulnerability', 'severity': 'critical', 'source': 'nuclei'},
        ('open', 'T3', 30.625),
        ('open', 'T3', 29.5)),
    'nuclei_high_misconfig_tag': (
        {'host': 'h1', 'id': 'n3', 'label': 'Vulnerability', 'severity': 'high', 'source': 'nuclei', 'tags': ['network', 'redis', 'unauth', 'exposure']},
        ('open', 'T3', 26.6875),
        ('open', 'T3', 26.35)),
    'gvm_high': (
        {'cvss_score': 7.5, 'host': 'h1', 'id': 'g1', 'label': 'Vulnerability', 'qod': 80, 'qod_type': 'remote_banner', 'severity': 'high', 'source': 'gvm'},
        ('open', 'T3', 29.2188),
        ('open', 'T3', 28.375)),
    'gvm_redis_nopass': (
        {'cvss_vector': 'AV:N/AC:L/Au:N/C:C/I:C/A:C', 'host': 'h1', 'id': 'g2', 'label': 'Vulnerability', 'qod': 99, 'qod_type': 'remote_vul', 'severity': 'critical', 'source': 'gvm'},
        ('open', 'T3', 39.2454),
        ('open', 'T3', 36.3964)),
    'trufflehog_verified_aws': (
        {'detector_name': 'AWS', 'host': 'h1', 'id': 's', 'label': 'MultiscannerFinding', 'secret_type': 'AWS', 'severity': 'high', 'source': 'trufflehog', 'validation_status': 'validated'},
        ('open', 'T1', 93.75),
        ('open', 'T1', 90.0)),
    'trufflehog_unvalidated_aws': (
        {'detector_name': 'AWS', 'host': 'h1', 'id': 's', 'label': 'MultiscannerFinding', 'secret_type': 'AWS', 'severity': 'high', 'source': 'trufflehog', 'validation_status': 'unvalidated'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'trufflehog_verify_error_aws': (
        {'detector_name': 'AWS', 'host': 'h1', 'id': 's', 'label': 'MultiscannerFinding', 'secret_type': 'AWS', 'severity': 'high', 'source': 'trufflehog', 'validation_status': 'verify_error'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'trufflehog_unverified_gcp': (
        {'detector_name': 'GCP', 'host': 'h1', 'id': 's', 'label': 'MultiscannerFinding', 'secret_type': 'GCP', 'severity': 'high', 'source': 'trufflehog', 'validation_status': 'unverified'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'trufflehog_stripe': (
        {'detector_name': 'Stripe', 'host': 'h1', 'id': 's', 'label': 'MultiscannerFinding', 'secret_type': 'Stripe', 'severity': 'high', 'source': 'trufflehog', 'validation_status': 'unverified'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'github_aws_key': (
        {'detector_name': 'AWS Access Key ID', 'host': 'h1', 'id': 's', 'label': 'GithubSecret', 'secret_type': 'AWS Access Key ID', 'severity': 'high', 'source': 'github_hunt'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'github_private_ip': (
        {'detector_name': 'IP Address (Private)', 'host': 'h1', 'id': 's', 'label': 'GithubSecret', 'secret_type': 'IP Address (Private)', 'severity': 'high', 'source': 'github_hunt'},
        ('open', 'T4', 0.3),
        ('open', 'T4', 0.24)),
    'github_stripe_live': (
        {'detector_name': 'Stripe Live Key', 'host': 'h1', 'id': 's', 'label': 'GithubSecret', 'secret_type': 'Stripe Live Key', 'severity': 'high', 'source': 'github_hunt'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'github_gcp_service_account': (
        {'detector_name': 'GCP Service Account', 'host': 'h1', 'id': 's', 'label': 'GithubSecret', 'secret_type': 'GCP Service Account', 'severity': 'high', 'source': 'github_hunt'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'github_gemini': (
        {'detector_name': 'Google Gemini API Key', 'host': 'h1', 'id': 's', 'label': 'GithubSecret', 'secret_type': 'Google Gemini API Key', 'severity': 'high', 'source': 'github_hunt'},
        ('open', 'T3', 28.6),
        ('open', 'T3', 27.88)),
    'github_algolia_api_key': (
        {'detector_name': 'Algolia API Key', 'host': 'h1', 'id': 's', 'label': 'GithubSecret', 'secret_type': 'Algolia API Key', 'severity': 'high', 'source': 'github_hunt'},
        ('open', 'T3', 28.6),
        ('open', 'T3', 27.88)),
    'github_slack_bot': (
        {'detector_name': 'Slack Bot Token', 'host': 'h1', 'id': 's', 'label': 'GithubSecret', 'secret_type': 'Slack Bot Token', 'severity': 'high', 'source': 'github_hunt'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'js_aws_unvalidated': (
        {'confidence': 'high', 'detector_name': 'cloud', 'host': 'h1', 'id': 's', 'label': 'Secret', 'secret_type': 'AWS Access Key ID', 'severity': 'critical', 'source': 'js_recon', 'validation_status': 'incomplete'},
        ('open', 'T2', 60.125),
        ('open', 'T2', 58.1)),
    'js_stripe_secret_validated': (
        {'confidence': 'high', 'detector_name': 'payment', 'host': 'h1', 'id': 's', 'label': 'Secret', 'secret_type': 'Stripe Secret Key', 'severity': 'critical', 'source': 'js_recon', 'validation_status': 'validated'},
        ('open', 'T1', 97.5),
        ('open', 'T1', 93.0)),
    'js_stripe_secret_invalid_legacy': (
        {'confidence': 'high', 'detector_name': 'payment', 'host': 'h1', 'id': 's', 'label': 'Secret', 'secret_type': 'Stripe Secret Key', 'severity': 'critical', 'source': 'js_recon', 'validation_status': 'invalid'},
        ('open', 'T2', 60.125),
        ('open', 'T2', 58.1)),
    'js_stripe_secret_invalid_timeout': (
        {'confidence': 'high', 'detector_name': 'payment', 'host': 'h1', 'id': 's', 'label': 'Secret', 'secret_type': 'Stripe Secret Key', 'severity': 'critical', 'source': 'js_recon', 'validation_info': '{"status": "invalid", "valid": false, "info": "", "error": "timeout"}', 'validation_status': 'invalid'},
        ('open', 'T2', 60.125),
        ('open', 'T2', 58.1)),
    'js_stripe_secret_invalid_429': (
        {'confidence': 'high', 'detector_name': 'payment', 'host': 'h1', 'id': 's', 'label': 'Secret', 'secret_type': 'Stripe Secret Key', 'severity': 'critical', 'source': 'js_recon', 'validation_info': '{"status": "invalid", "valid": false, "info": "status=429", "error": ""}', 'validation_status': 'invalid'},
        ('open', 'T2', 60.125),
        ('open', 'T2', 58.1)),
    # The Firebase web config's apiKey is public by design (plan 05.2): it
    # left T3 for T4 on purpose, as a node written before the flag.
    'js_firebase_api_key': (
        {'confidence': 'medium', 'detector_name': 'cloud', 'host': 'h1', 'id': 's', 'label': 'Secret', 'secret_type': 'Firebase API Key', 'severity': 'high', 'source': 'js_recon', 'validation_status': 'unvalidated'},
        ('open', 'T4', 0.3),
        ('open', 'T4', 0.24)),
    'jsluice_aws': (
        {'detector_name': 'AWSAccessKey', 'host': 'h1', 'id': 's', 'label': 'Secret', 'secret_type': 'AWSAccessKey', 'severity': 'high', 'source': 'jsluice'},
        ('open', 'T3', 31.75),
        ('open', 'T3', 30.4)),
    'unvalidated_no_time': (
        {'detector_name': 'AWS', 'host': 'h1', 'id': 's', 'label': 'MultiscannerFinding', 'secret_type': 'AWS', 'source': 'trufflehog', 'validation_status': 'unvalidated'},
        ('open', 'T3', 33.1),
        ('open', 'T3', 31.48)),
    'unvalidated_with_time': (
        {'detector_name': 'AWS', 'host': 'h1', 'id': 's', 'label': 'MultiscannerFinding', 'secret_type': 'AWS', 'source': 'trufflehog', 'validated_at': '2026-01-01T00:00:00Z', 'validation_status': 'unvalidated'},
        ('inactive', 'T4', 0.0),
        ('inactive', 'T4', 0.0)),
    'osv_high_versioned': (
        {'host': 'h1', 'id': 'o1', 'label': 'Vulnerability', 'package_version': '1.0.0', 'severity': 'high', 'source': 'osv'},
        ('open', 'T3', 30.0625),
        ('open', 'T3', 29.05)),
    'dmarc_missing': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'dmarc_missing'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'spf_missing': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'spf_missing'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'missing_referrer_policy': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'low', 'source': 'security_check', 'type': 'missing_referrer_policy'},
        ('open', 'T4', 0.125),
        ('open', 'T4', 0.1)),
    'missing_coop': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'info', 'source': 'security_check', 'type': 'missing_coop'},
        ('open', 'T4', 0.025),
        ('open', 'T4', 0.02)),
    'cache_control_missing': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'low', 'source': 'security_check', 'type': 'cache_control_missing'},
        ('open', 'T4', 0.125),
        ('open', 'T4', 0.1)),
    'waf_bypass_no_method': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'high', 'source': 'security_check', 'type': 'waf_bypass'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'waf_bypass_origin_medium': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'waf_bypass'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    # C 0.95: the producer requires a 2xx origin page matching the edge's own.
    'waf_bypass_payload_differential': (
        {'detection_method': 'payload_differential', 'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'high', 'source': 'security_check', 'type': 'waf_bypass'},
        ('open', 'T3', 27.1375),
        ('open', 'T3', 26.71)),
    'direct_ip_http_medium': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'direct_ip_http'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'direct_ip_http_info': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'info', 'source': 'security_check', 'type': 'direct_ip_http'},
        ('open', 'T4', 0.15),
        ('open', 'T4', 0.12)),
    'direct_ip_https_medium': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'direct_ip_https'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'cors_misconfiguration': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'cors_misconfiguration'},
        ('open', 'T3', 29.5),
        ('open', 'T3', 28.6)),
    'open_redirect': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'open_redirect'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'unknown_future_check': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'high', 'source': 'security_check', 'type': 'some_future_check'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'tls_expired': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'high', 'source': 'security_check', 'type': 'tls_expired'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'tls_expiring_soon': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'low', 'source': 'security_check', 'type': 'tls_expiring_soon'},
        ('open', 'T3', 26.5),
        ('open', 'T3', 26.2)),
    'tls_self_signed': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'tls_self_signed'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'tls_hostname_mismatch': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'tls_hostname_mismatch'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'tls_weak_version': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'tls_weak_version'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'tls_weak_cipher': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'tls_weak_cipher'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'tls_wildcard_overbroad': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'low', 'source': 'security_check', 'type': 'tls_wildcard_overbroad'},
        ('open', 'T3', 26.5),
        ('open', 'T3', 26.2)),
    'tls_weak_version_supported': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'tls_weak_version_supported'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'tls_weak_cipher_supported': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'tls_weak_cipher_supported'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'session_no_secure': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'session_no_secure'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'session_no_httponly': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'session_no_httponly'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'csp_unsafe_inline': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'medium', 'source': 'security_check', 'type': 'csp_unsafe_inline'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'insecure_form_action': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'high', 'source': 'security_check', 'type': 'insecure_form_action'},
        ('open', 'T3', 27.25),
        ('open', 'T3', 26.8)),
    'dnssec_missing': (
        {'host': 'h1', 'id': 'x', 'label': 'Vulnerability', 'severity': 'low', 'source': 'security_check', 'type': 'dnssec_missing'},
        ('open', 'T3', 26.5),
        ('open', 'T3', 26.2)),
}


class TestUnaffectedFindingsDidNotMove(unittest.TestCase):
    def test_every_guarded_finding_scores_exactly_as_before(self):
        for name, (row, on_live, on_none) in GUARD.items():
            for facts, expected in ((LIVE, on_live), (sm.ProjectFacts(), on_none)):
                with self.subTest(finding=name, live=bool(facts.live_hosts)):
                    result = sm.score(dict(row), facts, INTEL)
                    self.assertEqual((result.state, result.tier), expected[:2])
                    self.assertAlmostEqual(result.score, expected[2], places=4)

    def test_the_model_version_moved_with_the_tables(self):
        self.assertNotEqual(sm.SCORE_MODEL_VERSION, "v3.2.0")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Plan 05.5: a keyword-anchored pattern with a generic value is medium
# ---------------------------------------------------------------------------
def js_pattern(name: str) -> tuple:
    """(severity, confidence, category) of one js_recon pattern, from its source."""
    m = re.search(r'^\s*\("' + re.escape(name) + r'",\s*r"(?:[^"\\]|\\.)*",\s*"(\w+)",\s*"(\w+)",\s*"(\w+)"',
                  _read(JS_PATTERNS_SRC), re.M)
    if m is None:
        raise AssertionError(f"no js_recon pattern named {name}")
    return m.group(1), m.group(2), m.group(3)


class TestKeywordAnchoredConfidence(unittest.TestCase):
    #: Values with no provider prefix, found only by a keyword nearby.
    GENERIC_VALUE = ("AWS Secret Key", "Azure AD Client Secret", "Azure Connection String",
                     "Plaid Secret Key", "GoCardless API Token", "Notion API Token",
                     "Harness API Key", "Basic Auth Header")

    def test_they_are_medium_confidence(self):
        for name in self.GENERIC_VALUE:
            with self.subTest(name=name):
                self.assertEqual(js_pattern(name)[1], "medium")

    def test_an_unvalidated_hit_scores_at_most_t3(self):
        for name in self.GENERIC_VALUE:
            severity, confidence, category = js_pattern(name)
            with self.subTest(name=name):
                row = js_secret(name, category, severity=severity, confidence=confidence,
                                validation_status="unvalidated")
                self.assertIn(sm.score(row, LIVE).tier, ("T3", "T4"))

    def test_high_confidence_was_what_reached_t2(self):
        severity, _, category = js_pattern("AWS Secret Key")
        row = js_secret("AWS Secret Key", category, severity=severity, confidence="high",
                        validation_status="unvalidated")
        self.assertEqual(sm.score(row, LIVE).tier, "T2")

    def test_provider_prefixed_patterns_keep_high(self):
        for name in ("AWS Access Key ID", "GitHub Token Classic", "Slack Bot Token",
                     "Stripe Secret Key", "HashiCorp Terraform Token", "Azure Storage Key"):
            with self.subTest(name=name):
                self.assertEqual(js_pattern(name)[1], "high")


class TestPrivilegedSupabaseKeys(unittest.TestCase):
    """Plan 05.6: a service_role JWT or an sb_secret_ key is a credential."""

    def test_they_are_credentials(self):
        for name in ("Supabase service_role key", "Supabase Secret Key"):
            with self.subTest(name=name):
                self.assertEqual(sm.classify_secret(name, name).name, "credential")
                self.assertEqual(sm.classify_secret("js_service", name).name, "credential")

    def test_the_anon_key_is_public(self):
        self.assertEqual(sm.classify_secret("Supabase anon key", "Supabase anon key").name,
                         "public_client_id")


# ---------------------------------------------------------------------------
# Plan 05.7: the validation states are stored explicitly
# ---------------------------------------------------------------------------
class TestExplicitValidationStates(unittest.TestCase):
    def state(self, label="Secret", **kwargs):
        if label == "Secret":
            return sm.score(js_secret("Stripe Secret Key", "payment", **kwargs), LIVE).state
        return sm.score(secret(label, "trufflehog", "AWS", **kwargs), LIVE).state

    def test_rejected_is_inactive_with_nothing_to_parse(self):
        self.assertEqual(self.state(validation_status="rejected"), sm.STATE_INACTIVE)
        self.assertEqual(self.state(validation_status="Rejected", validation_info="{}"),
                         sm.STATE_INACTIVE)

    def test_a_malformed_value_is_inactive(self):
        self.assertEqual(self.state(validation_status="format_invalid"), sm.STATE_INACTIVE)

    def test_unknown_stays_open_whatever_its_detail_says(self):
        for info in (validation_info("status=401"), validation_info("", "timeout"), None):
            with self.subTest(info=info):
                self.assertEqual(self.state(validation_status="unknown", validation_info=info),
                                 sm.STATE_OPEN)

    def test_legacy_invalid_is_read_as_before(self):
        self.assertEqual(self.state(validation_status="invalid",
                                    validation_info=validation_info("status=401")),
                         sm.STATE_INACTIVE)
        self.assertEqual(self.state(validation_status="invalid",
                                    validation_info=validation_info("", "timeout")),
                         sm.STATE_OPEN)

    def test_a_trufflehog_credential_tested_and_dead_is_inactive(self):
        self.assertEqual(self.state("MultiscannerFinding", validation_status="rejected"),
                         sm.STATE_INACTIVE)

    def test_the_model_version_moved_with_plan_05(self):
        # Public client keys, the credential needles and the explicit states
        # rescore existing findings.
        self.assertNotIn(sm.SCORE_MODEL_VERSION, ("v3.7.0",))
