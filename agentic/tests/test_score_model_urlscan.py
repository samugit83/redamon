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


class TestFactQueries(unittest.TestCase):
    def _query(self, name):
        return next(q["query"] for q in FINDING_QUERIES if q["name"] == name)

    def test_the_kind_reaches_the_scorer(self):
        self.assertIn("coalesce(v.link_kind, v.file_kind, v.family) AS finding_kind",
                      self._query("vulnerabilities"))

    def test_a_secret_on_a_subdomain_resolves_its_host(self):
        q = " ".join(self._query("secrets").split())
        self.assertIn("head([(sd)-[:HAS_SECRET]->(s) WHERE sd:Subdomain OR sd:Domain | sd.name])", q)


if __name__ == "__main__":
    unittest.main()
