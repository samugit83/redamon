"""The CVE-lookup payload must survive the Group 6 Phase A fan-out merge.

run_vuln_scan writes the CVE lookup result beside its namespace
(recon_data.update(cve_results) at vuln_scan.py ~1038), but the fan-out used
to store only the namespace: `combined_result[key] = fut.result()` with a
wrapper that returned `snapshot.get("vuln_scan", {})`. technology_cves was
dropped between the wrapper and the merge, so the graph writer
(vuln_mixin.py:703) and the MITRE enrichment (add_mitre.py:1124/1275) — both
of which read the top-level key — never saw a single CVE, and every scan
produced CVE/MitreData/Capec = 0 nodes.

These tests pin the two halves of the fix: the wrapper returns an envelope
(namespace + the allowlisted top-level keys), and _merge_isolated_result
lands that envelope without changing behavior for the five namespace-only
wrappers.

Run: ./redamon.sh test unit   (recon section)
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main import _merge_isolated_result  # noqa: E402
from recon.main_recon_modules.vuln_scan import (  # noqa: E402
    VULN_SCAN_TOP_LEVEL_KEYS,
    run_vuln_scan_isolated,
)

CVES = {"summary": {"total_cves": 2}, "by_technology": {"nginx": {"cves": []}}}


def _fake_run_vuln_scan(recon_data, output_file=None, settings=None):
    """Write what the real run_vuln_scan writes: namespace + top-level CVEs."""
    recon_data["vuln_scan"] = {"findings": ["marker"]}
    recon_data["technology_cves"] = CVES
    return recon_data


class TestWrapperReturnsEnvelope(unittest.TestCase):
    def test_technology_cves_rides_alongside_the_namespace(self):
        with patch("recon.main_recon_modules.vuln_scan.run_vuln_scan",
                   side_effect=_fake_run_vuln_scan):
            envelope = run_vuln_scan_isolated({"domain": "example.com"}, {})
        self.assertEqual(envelope["vuln_scan"], {"findings": ["marker"]})
        self.assertEqual(envelope["technology_cves"], CVES)

    def test_absent_top_level_keys_are_not_published(self):
        # CVE lookup disabled / nothing detected: the envelope must not invent
        # keys, or the merge would plant empty payloads on every scan.
        def namespace_only(recon_data, output_file=None, settings=None):
            recon_data["vuln_scan"] = {"findings": []}
            return recon_data

        with patch("recon.main_recon_modules.vuln_scan.run_vuln_scan",
                   side_effect=namespace_only):
            envelope = run_vuln_scan_isolated({"domain": "example.com"}, {})
        self.assertEqual(list(envelope.keys()), ["vuln_scan"])

    def test_allowlist_covers_every_published_key(self):
        # If someone adds a key to the envelope without allowlisting it, the
        # merge would still land it (setdefault over every extra key); this
        # pins the allowlist as the single place that decision is made.
        self.assertEqual(VULN_SCAN_TOP_LEVEL_KEYS, ("technology_cves",))


class TestMergeIsolatedResult(unittest.TestCase):
    def test_envelope_lands_namespace_and_top_level(self):
        combined = {"domain": "example.com"}
        _merge_isolated_result(
            combined, "vuln_scan",
            {"vuln_scan": {"findings": ["marker"]}, "technology_cves": CVES},
        )
        self.assertEqual(combined["vuln_scan"], {"findings": ["marker"]})
        self.assertEqual(combined["technology_cves"], CVES)

    def test_namespace_only_result_assigns_directly(self):
        # The other five _isolated wrappers still return a bare namespace.
        combined = {"domain": "example.com"}
        _merge_isolated_result(combined, "graphql_scan", {"queries": 1})
        self.assertEqual(combined["graphql_scan"], {"queries": 1})
        self.assertNotIn("technology_cves", combined)

    def test_existing_top_level_value_is_not_clobbered(self):
        # setdefault: a value written earlier in the run must never be
        # reverted by the wrapper's pre-scan deep copy.
        fresh = {"summary": {"total_cves": 0}}
        combined = {"domain": "example.com", "technology_cves": fresh}
        _merge_isolated_result(
            combined, "vuln_scan",
            {"vuln_scan": {}, "technology_cves": CVES},
        )
        self.assertIs(combined["technology_cves"], fresh)


class TestFanOutEndToEnd(unittest.TestCase):
    def test_payload_reaches_combined_result_through_the_real_loop(self):
        """The exact shape of the Group 6 Phase A loop, minus the scanners."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        combined_result = {"domain": "example.com", "metadata": {"modules_executed": []}}
        phase_a_tools = {"vuln_scan": run_vuln_scan_isolated}
        with patch("recon.main_recon_modules.vuln_scan.run_vuln_scan",
                   side_effect=_fake_run_vuln_scan), \
             ThreadPoolExecutor(max_workers=1) as pool:
            futures = {pool.submit(fn, combined_result, {}): key
                       for key, fn in phase_a_tools.items()}
            for fut in as_completed(futures):
                key = futures[fut]
                _merge_isolated_result(combined_result, key, fut.result())
                combined_result["metadata"]["modules_executed"].append(key)

        self.assertIn("vuln_scan", combined_result)
        self.assertIn("technology_cves", combined_result)
        self.assertEqual(combined_result["technology_cves"], CVES)


if __name__ == "__main__":
    unittest.main()
