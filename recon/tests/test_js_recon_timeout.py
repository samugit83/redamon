"""
Regression test for the JS Recon analysis timeout hang.

Before the fix:
    `with ThreadPoolExecutor(...) as executor:` + future.result(timeout=X)
    The TimeoutError fired correctly, but the `with` exit blocked on
    shutdown(wait=True), so the call hung as long as the slowest worker.

After the fix:
    Manual executor, single wall-clock deadline shared across all futures,
    shutdown(wait=False, cancel_futures=True) in `finally`. The function
    returns within ~budget seconds even if a worker is still computing.

Run inside the redamon-recon container:
    docker run --rm -v "$PWD:/app" -w /app redamon-recon:latest \
        python3 -m pytest recon/tests/test_js_recon_timeout.py -v
"""

import os
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from recon.main_recon_modules import js_recon  # noqa: E402


# Budget kept small so the test suite stays fast.
BUDGET_SECONDS = 2
SLACK_SECONDS = 3   # generous slack for slower CI machines
SLOW_WORKER_SLEEP = 30  # longer than budget + slack, must not block the test

# Minimal settings: every analyzer enabled (so we exercise every submit path)
# but every helper is patched below so they return immediately or hang.
SETTINGS = {
    'JS_RECON_TIMEOUT': BUDGET_SECONDS,
    'JS_RECON_REGEX_PATTERNS': True,
    'JS_RECON_SOURCE_MAPS': True,
    'JS_RECON_DEPENDENCY_CHECK': True,
    'JS_RECON_EXTRACT_ENDPOINTS': True,
    'JS_RECON_FRAMEWORK_DETECT': True,
    'JS_RECON_DOM_SINKS': True,
    'JS_RECON_DEV_COMMENTS': True,
    'JS_RECON_AI_SDK_DETECTION_ENABLED': True,
    'JS_RECON_MIN_CONFIDENCE': 'low',
    # Custom hooks left empty so load_custom_* is not called.
}


def _make_js_files(n=3):
    return [
        {'url': f'https://example.test/file{i}.js', 'content': 'var x = 1;', 'size': 10}
        for i in range(n)
    ]


class JsReconTimeoutTest(unittest.TestCase):
    """The fix's behavioural contract."""

    def test_run_analysis_returns_within_budget_when_one_analyzer_hangs(self):
        """
        Patch extract_endpoints to sleep for SLOW_WORKER_SLEEP seconds.
        _run_analysis must return within BUDGET + SLACK regardless.
        """
        def slow_endpoints(js_files, settings):
            time.sleep(SLOW_WORKER_SLEEP)
            return []

        # Fast stubs for everything else. Each must match the real return shape.
        def fast_scan(content, url, **kwargs):
            return ([], {'low_entropy': 0, 'base64_blob': 0, 'binary_context': 0,
                         'repetitive': 0, 'url_whitelist': 0})

        def fast_sourcemaps(js_files, settings, **kwargs):
            return []

        def fast_deps(js_files, settings, **kwargs):
            return []

        def fast_frameworks(content, url, custom_signatures=None):
            return []

        def fast_dom_sinks(content, url):
            return []

        def fast_dev_comments(content, url):
            return []

        def fast_match_ai_sdk(content):
            return []

        with patch.object(js_recon, 'extract_endpoints', side_effect=slow_endpoints), \
             patch.object(js_recon, 'scan_js_content', side_effect=fast_scan), \
             patch.object(js_recon, 'discover_and_analyze_sourcemaps', side_effect=fast_sourcemaps), \
             patch.object(js_recon, 'detect_dependency_confusion', side_effect=fast_deps), \
             patch.object(js_recon, 'detect_frameworks', side_effect=fast_frameworks), \
             patch.object(js_recon, 'detect_dom_sinks', side_effect=fast_dom_sinks), \
             patch.object(js_recon, 'detect_dev_comments', side_effect=fast_dev_comments), \
             patch.object(js_recon, 'match_ai_sdk', side_effect=fast_match_ai_sdk):

            t0 = time.monotonic()
            results = js_recon._run_analysis(_make_js_files(), SETTINGS)
            elapsed = time.monotonic() - t0

        # Hard contract: must return within budget + slack, NOT after the
        # 30s slow worker finishes.
        self.assertLess(
            elapsed,
            BUDGET_SECONDS + SLACK_SECONDS,
            f"_run_analysis took {elapsed:.1f}s, expected < "
            f"{BUDGET_SECONDS + SLACK_SECONDS}s. The timeout is not enforced.",
        )

        # Sanity: fast analyzers completed and their results landed.
        self.assertIn('frameworks', results)
        self.assertIn('dom_sinks', results)
        self.assertIn('dev_comments', results)
        # Slow analyzer (endpoints) timed out -> result key still exists but
        # holds the default empty list because the future never delivered.
        self.assertEqual(results.get('endpoints', []), [])

    def test_run_analysis_returns_full_results_when_no_analyzer_is_slow(self):
        """Sanity: when nothing hangs, every analyzer's result is captured."""
        def fast_scan(content, url, **kwargs):
            return (
                [{'category': 'secret', 'name': 'Test Token',
                  'matched_text': 'sk_test_123', 'source_url': url}],
                {'low_entropy': 0, 'base64_blob': 0, 'binary_context': 0,
                 'repetitive': 0, 'url_whitelist': 0},
            )

        with patch.object(js_recon, 'scan_js_content', side_effect=fast_scan), \
             patch.object(js_recon, 'discover_and_analyze_sourcemaps', return_value=[]), \
             patch.object(js_recon, 'detect_dependency_confusion', return_value=[]), \
             patch.object(js_recon, 'extract_endpoints', return_value=[{'path': '/api/x'}]), \
             patch.object(js_recon, 'detect_frameworks', return_value=[]), \
             patch.object(js_recon, 'detect_dom_sinks', return_value=[]), \
             patch.object(js_recon, 'detect_dev_comments', return_value=[]), \
             patch.object(js_recon, 'match_ai_sdk', return_value=[]):

            t0 = time.monotonic()
            results = js_recon._run_analysis(_make_js_files(), SETTINGS)
            elapsed = time.monotonic() - t0

        self.assertLess(elapsed, 2.0, "fast path should finish well under budget")
        self.assertEqual(results.get('endpoints'), [{'path': '/api/x'}])
        # scan_js_content runs once per js_file (3 files in _make_js_files)
        self.assertEqual(len(results.get('secrets', [])), 3)


class OldBuggyPatternRegressionTest(unittest.TestCase):
    """
    Proof-by-counterexample that the OLD `with` + `future.result(timeout=)`
    pattern really did hang. This locks the bug shape so we don't regress.
    """

    def test_old_with_pattern_blocks_on_shutdown_despite_timeout(self):
        budget = 0.5
        slow_sleep = 4.0

        def slow():
            time.sleep(slow_sleep)
            return 'done'

        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(slow)
            try:
                future.result(timeout=budget)
            except Exception:
                pass
            # Falling off the `with` here calls shutdown(wait=True), which
            # blocks until `slow` finishes.
        elapsed = time.monotonic() - t0

        # The OLD pattern takes at least `slow_sleep` seconds.
        self.assertGreaterEqual(
            elapsed,
            slow_sleep - 0.5,
            "old pattern is expected to block until the slow worker finishes",
        )

    def test_new_pattern_returns_within_budget(self):
        budget = 0.5
        slow_sleep = 4.0

        def slow():
            time.sleep(slow_sleep)
            return 'done'

        t0 = time.monotonic()
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(slow)
            try:
                future.result(timeout=budget)
            except Exception:
                pass
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        elapsed = time.monotonic() - t0

        self.assertLess(
            elapsed,
            budget + 1.0,
            "new pattern must return within budget regardless of slow worker",
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)
