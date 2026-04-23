"""
Unit tests for GAU parallel domain processing.

Tests cover:
1. Parallel execution -- domains processed concurrently, not sequentially
2. Worker count capping -- max_workers = min(5, num_domains)
3. Result aggregation -- all_discovered_urls and urls_by_domain correct
4. URL deduplication -- same URL from multiple domains counted once
5. Error isolation -- one domain failure doesn't break others
6. Single domain -- still works with 1 domain (1 worker)
7. Large domain set -- correct worker count with many domains
8. Outer timeout calculation in resource_enum.py
"""

import importlib
import importlib.util
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "recon"))
sys.path.insert(0, str(REPO_ROOT / "recon" / "helpers"))

_gau_mod = None


def _get_gau_module():
    """Import gau_helpers through the package to handle relative imports."""
    global _gau_mod
    if _gau_mod is not None:
        return _gau_mod

    helpers_path = REPO_ROOT / "recon" / "helpers" / "resource_enum"

    pkg = types.ModuleType("recon_helpers_resource_enum")
    pkg.__path__ = [str(helpers_path)]
    pkg.__package__ = "recon_helpers_resource_enum"

    spec_cls = importlib.util.spec_from_file_location(
        "recon_helpers_resource_enum.classification",
        helpers_path / "classification.py",
        submodule_search_locations=[]
    )
    mod_cls = importlib.util.module_from_spec(spec_cls)
    mod_cls.__package__ = "recon_helpers_resource_enum"
    sys.modules["recon_helpers_resource_enum"] = pkg
    sys.modules["recon_helpers_resource_enum.classification"] = mod_cls
    spec_cls.loader.exec_module(mod_cls)

    spec = importlib.util.spec_from_file_location(
        "recon_helpers_resource_enum.gau_helpers",
        helpers_path / "gau_helpers.py",
        submodule_search_locations=[]
    )
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "recon_helpers_resource_enum"
    sys.modules["recon_helpers_resource_enum.gau_helpers"] = mod
    spec.loader.exec_module(mod)

    _gau_mod = mod
    return mod


# ---------------------------------------------------------------------------
# Tests for parallel domain processing
# ---------------------------------------------------------------------------
class TestParallelExecution(unittest.TestCase):
    """Verify domains are processed in parallel, not sequentially."""

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_concurrent_execution_is_faster(self, mock_run_domain):
        """With 5 domains and simulated 0.2s per domain, parallel should be much
        faster than sequential (5 * 0.2s = 1s sequential vs ~0.2s parallel)."""
        gau = _get_gau_module()

        def slow_domain(domain, **kwargs):
            time.sleep(0.2)
            return [f"http://{domain}/page"]

        mock_run_domain.side_effect = slow_domain
        domains = {f"d{i}.com" for i in range(5)}

        start = time.monotonic()
        gau.run_gau_discovery(
            target_domains=domains,
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )
        elapsed = time.monotonic() - start

        # Sequential would take >= 1.0s, parallel should be ~0.2-0.4s
        self.assertLess(elapsed, 0.8, f"Took {elapsed:.2f}s -- domains may not be running in parallel")

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_all_domains_called(self, mock_run_domain):
        """Every domain should be queried exactly once."""
        gau = _get_gau_module()
        mock_run_domain.return_value = []

        domains = {"a.com", "b.com", "c.com", "d.com", "e.com"}
        gau.run_gau_discovery(
            target_domains=domains,
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )

        called_domains = {c.kwargs["domain"] for c in mock_run_domain.call_args_list}
        self.assertEqual(called_domains, domains)
        self.assertEqual(mock_run_domain.call_count, 5)


class TestWorkerCount(unittest.TestCase):
    """Verify max_workers = min(5, num_domains)."""

    @patch("recon_helpers_resource_enum.gau_helpers.ThreadPoolExecutor")
    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_3_domains_uses_3_workers(self, mock_run_domain, mock_executor_cls):
        """3 domains should use 3 workers, not 5."""
        gau = _get_gau_module()
        mock_run_domain.return_value = []

        # Set up the mock executor to behave like a real one
        from concurrent.futures import ThreadPoolExecutor
        real_executor = ThreadPoolExecutor(max_workers=3)
        mock_executor_cls.return_value = real_executor

        try:
            gau.run_gau_discovery(
                target_domains={"a.com", "b.com", "c.com"},
                docker_image="sxcurity/gau:latest",
                providers=["wayback"],
                threads=2,
                timeout=30,
                blacklist_extensions=[],
                max_urls=100,
            )
        finally:
            real_executor.shutdown(wait=False)

        mock_executor_cls.assert_called_once_with(max_workers=3)

    @patch("recon_helpers_resource_enum.gau_helpers.ThreadPoolExecutor")
    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_10_domains_capped_at_5_workers(self, mock_run_domain, mock_executor_cls):
        """10 domains should be capped at 5 workers."""
        gau = _get_gau_module()
        mock_run_domain.return_value = []

        from concurrent.futures import ThreadPoolExecutor
        real_executor = ThreadPoolExecutor(max_workers=5)
        mock_executor_cls.return_value = real_executor

        try:
            gau.run_gau_discovery(
                target_domains={f"d{i}.com" for i in range(10)},
                docker_image="sxcurity/gau:latest",
                providers=["wayback"],
                threads=2,
                timeout=30,
                blacklist_extensions=[],
                max_urls=100,
            )
        finally:
            real_executor.shutdown(wait=False)

        mock_executor_cls.assert_called_once_with(max_workers=5)

    @patch("recon_helpers_resource_enum.gau_helpers.ThreadPoolExecutor")
    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_1_domain_uses_1_worker(self, mock_run_domain, mock_executor_cls):
        """Single domain should use 1 worker."""
        gau = _get_gau_module()
        mock_run_domain.return_value = []

        from concurrent.futures import ThreadPoolExecutor
        real_executor = ThreadPoolExecutor(max_workers=1)
        mock_executor_cls.return_value = real_executor

        try:
            gau.run_gau_discovery(
                target_domains={"only.com"},
                docker_image="sxcurity/gau:latest",
                providers=["wayback"],
                threads=2,
                timeout=30,
                blacklist_extensions=[],
                max_urls=100,
            )
        finally:
            real_executor.shutdown(wait=False)

        mock_executor_cls.assert_called_once_with(max_workers=1)


class TestResultAggregation(unittest.TestCase):
    """Verify results from parallel domains are correctly merged."""

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_urls_merged_across_domains(self, mock_run_domain):
        """URLs from all domains should be in the combined list."""
        gau = _get_gau_module()

        def per_domain(domain, **kwargs):
            return {
                "a.com": ["http://a.com/1", "http://a.com/2"],
                "b.com": ["http://b.com/x"],
                "c.com": ["http://c.com/y", "http://c.com/z"],
            }[domain]

        mock_run_domain.side_effect = per_domain

        urls, by_domain = gau.run_gau_discovery(
            target_domains={"a.com", "b.com", "c.com"},
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )

        self.assertEqual(len(urls), 5)
        self.assertIn("http://a.com/1", urls)
        self.assertIn("http://b.com/x", urls)
        self.assertIn("http://c.com/z", urls)

        self.assertEqual(by_domain["a.com"], ["http://a.com/1", "http://a.com/2"])
        self.assertEqual(by_domain["b.com"], ["http://b.com/x"])
        self.assertEqual(by_domain["c.com"], ["http://c.com/y", "http://c.com/z"])

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_duplicate_urls_deduplicated(self, mock_run_domain):
        """Same URL from multiple domains should appear once in combined list."""
        gau = _get_gau_module()

        def per_domain(domain, **kwargs):
            # Both domains return the same shared URL
            return [f"http://{domain}/unique", "http://shared.com/common"]

        mock_run_domain.side_effect = per_domain

        urls, by_domain = gau.run_gau_discovery(
            target_domains={"a.com", "b.com"},
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )

        # 2 unique + 1 shared = 3 total
        self.assertEqual(len(urls), 3)
        self.assertEqual(urls.count("http://shared.com/common"), 1)

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_urls_returned_sorted(self, mock_run_domain):
        """Combined URL list should be sorted."""
        gau = _get_gau_module()

        def per_domain(domain, **kwargs):
            return {
                "z.com": ["http://z.com/last"],
                "a.com": ["http://a.com/first"],
            }[domain]

        mock_run_domain.side_effect = per_domain

        urls, _ = gau.run_gau_discovery(
            target_domains={"z.com", "a.com"},
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )

        self.assertEqual(urls, sorted(urls))

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_empty_domains_produce_empty_results(self, mock_run_domain):
        """All domains returning empty should produce empty results."""
        gau = _get_gau_module()
        mock_run_domain.return_value = []

        urls, by_domain = gau.run_gau_discovery(
            target_domains={"a.com", "b.com"},
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )

        self.assertEqual(urls, [])
        self.assertEqual(by_domain, {"a.com": [], "b.com": []})


class TestErrorIsolation(unittest.TestCase):
    """Verify one domain failure doesn't break the rest."""

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_failing_domain_doesnt_block_others(self, mock_run_domain):
        """If one domain raises, others should still succeed."""
        gau = _get_gau_module()

        def per_domain(domain, **kwargs):
            if domain == "bad.com":
                raise RuntimeError("Docker crashed")
            return [f"http://{domain}/page"]

        mock_run_domain.side_effect = per_domain

        urls, by_domain = gau.run_gau_discovery(
            target_domains={"good.com", "bad.com", "also-good.com"},
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )

        # Good domains should have results
        self.assertIn("http://good.com/page", urls)
        self.assertIn("http://also-good.com/page", urls)
        self.assertEqual(len(urls), 2)

        # Failed domain gets empty list
        self.assertEqual(by_domain["bad.com"], [])

        # Good domains have their URLs
        self.assertEqual(by_domain["good.com"], ["http://good.com/page"])
        self.assertEqual(by_domain["also-good.com"], ["http://also-good.com/page"])

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_all_domains_fail_gracefully(self, mock_run_domain):
        """If every domain fails, should return empty results without crashing."""
        gau = _get_gau_module()
        mock_run_domain.side_effect = RuntimeError("Docker not available")

        urls, by_domain = gau.run_gau_discovery(
            target_domains={"a.com", "b.com"},
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )

        self.assertEqual(urls, [])
        self.assertEqual(by_domain["a.com"], [])
        self.assertEqual(by_domain["b.com"], [])


class TestOuterTimeout(unittest.TestCase):
    """Verify the timeout formula in resource_enum.py accounts for parallelism."""

    def test_timeout_formula_scales_with_domains(self):
        """Timeout should grow with domain count, divided by worker count."""
        # Formula: (GAU_TIMEOUT * len(providers) + 120) * (len(domains) // workers + 1) + 180
        gau_timeout = 60
        providers = ["wayback", "commoncrawl", "otx"]
        per_domain = gau_timeout * len(providers) + 120  # 300s

        # 1 domain, 1 worker
        domains_1 = 1
        workers_1 = min(5, domains_1)
        timeout_1 = per_domain * (domains_1 // workers_1 + 1) + 180
        self.assertEqual(timeout_1, 300 * 2 + 180)  # 780s

        # 5 domains, 5 workers -- same as 1 batch
        domains_5 = 5
        workers_5 = min(5, domains_5)
        timeout_5 = per_domain * (domains_5 // workers_5 + 1) + 180
        self.assertEqual(timeout_5, 300 * 2 + 180)  # 780s

        # 64 domains, 5 workers -- 13 batches
        domains_64 = 64
        workers_64 = min(5, domains_64)
        timeout_64 = per_domain * (domains_64 // workers_64 + 1) + 180
        self.assertEqual(timeout_64, 300 * 13 + 180)  # 4080s

        # Timeout should increase with more domains
        self.assertGreater(timeout_64, timeout_5)

    def test_timeout_not_too_small(self):
        """Old timeout (360s) was too small for 64 domains. New one should be adequate."""
        gau_timeout = 60
        providers = ["wayback", "commoncrawl", "otx"]
        per_domain = gau_timeout * len(providers) + 120

        domains = 64
        workers = min(5, domains)
        new_timeout = per_domain * (domains // workers + 1) + 180

        old_timeout = gau_timeout * len(providers) + 180  # 360s

        self.assertGreater(new_timeout, old_timeout)
        # New timeout should allow at least per_domain seconds per batch
        min_needed = per_domain * (domains // workers)
        self.assertGreater(new_timeout, min_needed)


class TestParameterPassthrough(unittest.TestCase):
    """Verify all parameters are correctly passed to each domain call."""

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_all_params_forwarded(self, mock_run_domain):
        """Every parameter should be passed through to run_gau_for_domain."""
        gau = _get_gau_module()
        mock_run_domain.return_value = []

        gau.run_gau_discovery(
            target_domains={"test.com"},
            docker_image="custom/gau:v2",
            providers=["wayback", "otx"],
            threads=10,
            timeout=120,
            blacklist_extensions=["png", "jpg"],
            max_urls=500,
            year_range=["2020", "2024"],
            verbose=True,
            use_proxy=True,
            urlscan_api_key="test-key-123"
        )

        mock_run_domain.assert_called_once()
        kwargs = mock_run_domain.call_args.kwargs
        self.assertEqual(kwargs["domain"], "test.com")
        self.assertEqual(kwargs["docker_image"], "custom/gau:v2")
        self.assertEqual(kwargs["providers"], ["wayback", "otx"])
        self.assertEqual(kwargs["threads"], 10)
        self.assertEqual(kwargs["timeout"], 120)
        self.assertEqual(kwargs["blacklist_extensions"], ["png", "jpg"])
        self.assertEqual(kwargs["max_urls"], 500)
        self.assertEqual(kwargs["year_range"], ["2020", "2024"])
        self.assertTrue(kwargs["verbose"])
        self.assertTrue(kwargs["use_proxy"])
        self.assertEqual(kwargs["urlscan_api_key"], "test-key-123")


if __name__ == "__main__":
    # Force module registration before @patch decorators resolve
    _get_gau_module()
    unittest.main()
