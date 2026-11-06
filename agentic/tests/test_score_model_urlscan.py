"""S6 on the Priority Board: urlscan history findings (source "urlscan_leak").

Rule rows only: a class row for every type, a per-kind detector key so a
person's "false positive" on one kind teaches nothing about another, a source
confidence well below a confirmed scanner's, and the Secret fact query
resolving a Secret that hangs off a Subdomain.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402
from cypherfix_triage.fact_queries import FINDING_QUERIES  # noqa: E402

TYPES = ["leaked_one_time_link", "sensitive_file_seen", "open_redirect_seen", "takeover_page_seen",
         "open_console_seen", "debug_page_seen", "installer_seen", "dev_server_seen",
         "directory_listing_seen", "defaced_page_seen", "test_certificate_seen"]


def _finding(ftype, kind="", severity="high"):
    return {"id": "x", "label": "Vulnerability", "source": "urlscan_leak", "type": ftype,
            "finding_kind": kind, "severity": severity, "name": ftype}


class TestUrlscanLeakRows(unittest.TestCase):
    def test_every_type_has_a_class_row(self):
        self.assertEqual(sorted(sm.URLSCAN_LEAK_CLASSES), sorted(TYPES))
        for t in TYPES:
            self.assertIs(sm._class_for(_finding(t)), sm.URLSCAN_LEAK_CLASSES[t])

    def test_source_confidence_is_below_a_confirmed_scanner(self):
        self.assertEqual(sm.CONFIDENCE_BY_SOURCE["urlscan_leak"], 0.4)
        self.assertEqual(sm.confidence(_finding("leaked_one_time_link"), sm.ProjectFacts()).value, 0.4)

    def test_a_takeover_page_is_not_exploitable_by_its_name(self):
        f = _finding("takeover_page_seen")
        self.assertFalse(sm._is_exploitable_class(f, sm._class_for(f)))

    def test_detector_keys_are_per_type_and_kind(self):
        listing = sm.detector_key(_finding("directory_listing_seen"))
        reset = sm.detector_key(_finding("leaked_one_time_link", "password_reset"))
        invite = sm.detector_key(_finding("leaked_one_time_link", "invite"))
        env = sm.detector_key(_finding("sensitive_file_seen", "env"))
        config = sm.detector_key(_finding("sensitive_file_seen", "config"))
        self.assertEqual(reset, "urlscan_leak:leaked_one_time_link:password_reset")
        self.assertEqual(len({listing, reset, invite, env, config}), 5)

    def test_an_open_console_ranks_above_a_folder_listing(self):
        console = sm.score(_finding("open_console_seen"))
        listing = sm.score(_finding("directory_listing_seen", severity="medium"))
        self.assertGreater(console.risk, listing.risk)


class TestPageContentChecks(unittest.TestCase):
    """Item 5's live security_check types: classed on the rows they resemble,
    a title-based check below a fact's 1.0, never the generic fallback."""

    TYPES = ("open_console", "debug_page", "unfinished_installer", "dev_server",
             "directory_listing", "defaced_page", "takeover_error_page", "test_certificate")

    def _check(self, ftype, severity="high", **kw):
        return {"id": "x", "label": "Vulnerability", "source": "security_check", "type": ftype,
                "severity": severity, "name": ftype, **kw}

    def test_every_type_has_its_own_row(self):
        for t in self.TYPES:
            self.assertIs(sm.classify_security_check(t), sm.SECURITY_CHECK_CLASSES[t])
        self.assertEqual(sm.SECURITY_CHECK_CLASSES["open_console"].name, "rce")
        self.assertEqual(sm.SECURITY_CHECK_CLASSES["takeover_error_page"].name, "takeover")

    def test_title_based_checks_are_strong_evidence_not_proof(self):
        for t in ("open_console", "unfinished_installer", "debug_page", "directory_listing",
                  "defaced_page", "takeover_error_page"):
            self.assertEqual(sm.SECURITY_CHECK_CONFIDENCE[t][0], 0.75)
        self.assertNotIn("dev_server", sm.SECURITY_CHECK_CONFIDENCE)

    def test_an_open_console_ranks_above_a_missing_header(self):
        console = sm.score(self._check("open_console", "critical"))
        header = sm.score(self._check("missing_referrer_policy", "low"))
        self.assertGreater(console.risk, header.risk)

    def test_a_dangling_name_is_not_an_exploitable_takeover(self):
        dangling = self._check("takeover_error_page", "low", outcome="dangling_dns")
        likely = self._check("takeover_error_page", "high", outcome="likely_takeover")
        klass = sm._class_for(likely)
        self.assertTrue(sm._is_exploitable_class(likely, klass))
        self.assertFalse(sm._is_exploitable_class(dangling, klass))


class TestFactQueries(unittest.TestCase):
    def _query(self, name):
        return next(q["query"] for q in FINDING_QUERIES if q["name"] == name)

    def test_the_takeover_outcome_reaches_the_scorer(self):
        self.assertIn("v.outcome AS outcome", self._query("vulnerabilities"))

    def test_the_kind_reaches_the_scorer(self):
        self.assertIn("coalesce(v.link_kind, v.file_kind, v.problem, v.provider, v.family) AS finding_kind",
                      self._query("vulnerabilities"))

    def test_a_secret_on_a_subdomain_resolves_its_host(self):
        q = " ".join(self._query("secrets").split())
        self.assertIn("head([(sd)-[:HAS_SECRET]->(s) WHERE sd:Subdomain OR sd:Domain | sd.name])", q)


if __name__ == "__main__":
    unittest.main()
