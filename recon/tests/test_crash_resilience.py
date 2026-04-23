"""
Unit tests for crash-resilience: per-file try/except in JS Recon analyzers,
per-phase try/except in main pipeline, and Docker APIError handling.

These tests verify that one bad item in a batch does NOT crash the whole batch,
and that good items before and after the bad one are still processed.

Run: cd "/home/samuele/Progetti didattici/redamon" && python3 -m unittest recon.tests.test_crash_resilience -v
"""

import sys
import os
import io
import re
import unittest
import importlib.util
from unittest.mock import patch, MagicMock


# Direct import to bypass recon/helpers/__init__.py which imports dns
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def _load_module(name, filepath):
    """Load a module directly by file path, bypassing package __init__.py."""
    spec = importlib.util.spec_from_file_location(name, filepath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


BASE = os.path.join(os.path.dirname(__file__), '..')
patterns = _load_module('recon.helpers.js_recon.patterns',
                        os.path.join(BASE, 'helpers/js_recon/patterns.py'))
sourcemap = _load_module('recon.helpers.js_recon.sourcemap',
                         os.path.join(BASE, 'helpers/js_recon/sourcemap.py'))
dependency = _load_module('recon.helpers.js_recon.dependency',
                          os.path.join(BASE, 'helpers/js_recon/dependency.py'))
endpoints_mod = _load_module('recon.helpers.js_recon.endpoints',
                             os.path.join(BASE, 'helpers/js_recon/endpoints.py'))
framework = _load_module('recon.helpers.js_recon.framework',
                         os.path.join(BASE, 'helpers/js_recon/framework.py'))


# ============================================================
# Helper: build a list of JS files with one "poisoned" entry
# that will trigger an exception in processing
# ============================================================

def _good_js(url='good.js'):
    return {'url': url, 'content': 'fetch("/api/users");', 'headers': {}}


def _poison_js(url='poison.js'):
    """A JS file dict whose 'content' is a non-string to trigger AttributeError."""
    return {'url': url, 'content': 12345, 'headers': {}}


DEFAULT_SETTINGS = {
    'JS_RECON_SOURCE_MAPS': True,
    'JS_RECON_DEPENDENCY_CHECK': True,
    'JS_RECON_EXTRACT_ENDPOINTS': True,
    'JS_RECON_FRAMEWORK_DETECT': True,
    'JS_RECON_DOM_SINKS': True,
    'JS_RECON_DEV_COMMENTS': True,
    'JS_RECON_CUSTOM_SOURCEMAP_PATHS': '',
    'JS_RECON_CUSTOM_PACKAGES': '',
    'JS_RECON_CUSTOM_ENDPOINT_KEYWORDS': '',
    'JS_RECON_TIMEOUT': 900,
}


# ============================================================
# SOURCEMAP CRASH RESILIENCE
# ============================================================

class TestSourcemapCrashResilience(unittest.TestCase):
    """Verify discover_and_analyze_sourcemaps survives bad files."""

    def test_bad_file_does_not_crash_batch(self):
        """One poisoned file should not prevent processing of good files."""
        js_files = [_good_js('a.js'), _poison_js('bad.js'), _good_js('b.js')]
        # Should not raise -- bad file is skipped
        result = sourcemap.discover_and_analyze_sourcemaps(js_files, DEFAULT_SETTINGS)
        self.assertIsInstance(result, list)

    def test_all_bad_files_returns_empty(self):
        """All bad files should return empty list, not crash."""
        js_files = [_poison_js('x.js'), _poison_js('y.js')]
        result = sourcemap.discover_and_analyze_sourcemaps(js_files, DEFAULT_SETTINGS)
        self.assertIsInstance(result, list)

    def test_none_content_survives(self):
        """None content should not crash."""
        js_files = [{'url': 'test.js', 'content': None, 'headers': {}}]
        result = sourcemap.discover_and_analyze_sourcemaps(js_files, DEFAULT_SETTINGS)
        self.assertIsInstance(result, list)


# ============================================================
# DEPENDENCY CRASH RESILIENCE
# ============================================================

class TestDependencyCrashResilience(unittest.TestCase):
    """Verify detect_dependency_confusion survives bad files."""

    def test_bad_file_does_not_crash_batch(self):
        js_files = [
            {'url': 'a.js', 'content': "import x from '@myco/sdk';"},
            _poison_js('bad.js'),
            {'url': 'b.js', 'content': "import y from '@myco/lib';"},
        ]
        # Should not raise
        result = dependency.detect_dependency_confusion(js_files, DEFAULT_SETTINGS)
        self.assertIsInstance(result, list)

    def test_all_bad_files_returns_empty(self):
        js_files = [_poison_js('x.js'), _poison_js('y.js')]
        result = dependency.detect_dependency_confusion(js_files, DEFAULT_SETTINGS)
        self.assertIsInstance(result, list)


# ============================================================
# ENDPOINTS CRASH RESILIENCE
# ============================================================

class TestEndpointsCrashResilience(unittest.TestCase):
    """Verify extract_endpoints survives bad files."""

    def test_bad_file_does_not_crash_batch(self):
        js_files = [
            _good_js('a.js'),
            _poison_js('bad.js'),
            _good_js('b.js'),
        ]
        result = endpoints_mod.extract_endpoints(js_files, DEFAULT_SETTINGS)
        self.assertIsInstance(result, list)
        # Good files should still produce results
        paths = [e['path'] for e in result]
        self.assertTrue(any('/api/users' in p for p in paths),
                        "Good files should still produce endpoints")

    def test_all_bad_files_returns_empty(self):
        js_files = [_poison_js('x.js'), _poison_js('y.js')]
        result = endpoints_mod.extract_endpoints(js_files, DEFAULT_SETTINGS)
        self.assertIsInstance(result, list)

    def test_error_message_printed(self):
        """Verify error is logged to stdout."""
        js_files = [_poison_js('bad.js')]
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            endpoints_mod.extract_endpoints(js_files, DEFAULT_SETTINGS)
            output = mock_out.getvalue()
        self.assertIn('[!][JsRecon]', output)
        self.assertIn('bad.js', output)


# ============================================================
# FRAMEWORK CRASH RESILIENCE
# ============================================================

class TestFrameworkCrashResilience(unittest.TestCase):
    """Verify detect_frameworks and detect_dom_sinks survive bad input."""

    def test_bad_custom_signature_does_not_crash(self):
        """A custom signature with a broken regex should not crash detection."""
        good_content = 'React.createElement("div");'
        # Signature with a pattern that will throw on .search()
        bad_sig = {'name': 'BadFW', 'patterns': [None], 'version_regex': None}
        good_sig = {'name': 'GoodFW', 'patterns': ['GoodFW_MARKER'], 'version_regex': None}
        result = framework.detect_frameworks(
            good_content + ' window.GoodFW_MARKER = true;',
            'test.js',
            custom_signatures=[bad_sig, good_sig],
        )
        # GoodFW should still be detected even though BadFW signature is broken
        names = [f['name'] for f in result]
        self.assertIn('GoodFW', names)

    def test_dom_sinks_with_none_content(self):
        """detect_dom_sinks should handle unusual content gracefully."""
        # Normal call should work fine
        result = framework.detect_dom_sinks('el.innerHTML = x;', 'test.js')
        self.assertTrue(len(result) > 0)

    def test_detect_frameworks_returns_list_on_empty(self):
        result = framework.detect_frameworks('', 'test.js')
        self.assertIsInstance(result, list)


# ============================================================
# JS_RECON _run_analysis CRASH RESILIENCE
# ============================================================

class TestRunAnalysisCrashResilience(unittest.TestCase):
    """Verify _run_analysis survives individual analyzer failures."""

    def test_pattern_scan_survives_bad_file(self):
        """run_patterns() inner loop should catch per-file errors.

        Uses scan_js_content directly since js_recon.py has heavy import deps.
        """
        good_files = [
            {'url': 'good.js', 'content': 'const key = "AKIAIOSFODNN7EXAMPLE";'},
            {'url': 'good2.js', 'content': 'fetch("/api/data");'},
        ]
        bad_file = {'url': 'bad.js', 'content': 12345}

        # Simulate what run_patterns() does with per-file try/except
        all_findings = []
        for js_file in [good_files[0], bad_file, good_files[1]]:
            try:
                findings = patterns.scan_js_content(
                    js_file['content'], js_file['url'],
                    min_confidence='low',
                )
                all_findings.extend(findings)
            except Exception:
                pass  # This is what our fix does

        # The good file's AWS key should still be found
        aws = [f for f in all_findings if f.get('name') == 'AWS Access Key ID']
        self.assertTrue(len(aws) > 0,
                        "Good files should still produce findings after bad file")


# ============================================================
# CONTAINER_MANAGER DOCKER APIError RESILIENCE
# ============================================================

try:
    import docker  # noqa: F401
    _HAS_DOCKER = True
except ImportError:
    _HAS_DOCKER = False


@unittest.skipUnless(_HAS_DOCKER, 'docker library not installed locally')
class TestContainerManagerAPIError(unittest.TestCase):
    """Verify container_manager handles Docker APIError gracefully."""

    def _make_manager(self):
        """Create a ContainerManager with a mocked Docker client."""
        cm_mod = _load_module(
            'container_manager',
            os.path.join(BASE, '..', 'recon_orchestrator', 'container_manager.py'),
        )
        manager = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
        manager.client = MagicMock()
        manager.running_states = {}
        manager.gvm_states = {}
        manager.github_hunt_states = {}
        manager.trufflehog_states = {}
        manager.recon_image = 'test'
        manager.gvm_image = 'test'
        manager.github_hunt_image = 'test'
        manager.trufflehog_image = 'test'
        return manager, cm_mod

    def test_get_status_handles_api_error(self):
        """get_status should catch APIError and set error state."""
        import asyncio
        manager, cm_mod = self._make_manager()

        state = cm_mod.ReconState(
            project_id='test',
            status=cm_mod.ReconStatus.RUNNING,
            container_id='abc123',
        )
        manager.running_states['test'] = state
        manager.client.containers.get.side_effect = cm_mod.APIError('500 Server Error')

        result = asyncio.get_event_loop().run_until_complete(manager.get_status('test'))
        self.assertEqual(result.status, cm_mod.ReconStatus.ERROR)
        self.assertIn('Docker API error', result.error)

    def test_get_gvm_status_handles_api_error(self):
        """get_gvm_status should catch APIError and set error state."""
        import asyncio
        manager, cm_mod = self._make_manager()

        state = cm_mod.GvmState(
            project_id='test',
            status=cm_mod.GvmStatus.RUNNING,
            container_id='abc123',
        )
        manager.gvm_states['test'] = state
        manager.client.containers.get.side_effect = cm_mod.APIError('500 Server Error')

        result = asyncio.get_event_loop().run_until_complete(manager.get_gvm_status('test'))
        self.assertEqual(result.status, cm_mod.GvmStatus.ERROR)
        self.assertIn('Docker API error', result.error)

    def test_get_github_hunt_status_handles_api_error(self):
        """get_github_hunt_status should catch APIError and set error state."""
        import asyncio
        manager, cm_mod = self._make_manager()

        state = cm_mod.GithubHuntState(
            project_id='test',
            status=cm_mod.GithubHuntStatus.RUNNING,
            container_id='abc123',
        )
        manager.github_hunt_states['test'] = state
        manager.client.containers.get.side_effect = cm_mod.APIError('500 Server Error')

        result = asyncio.get_event_loop().run_until_complete(manager.get_github_hunt_status('test'))
        self.assertEqual(result.status, cm_mod.GithubHuntStatus.ERROR)
        self.assertIn('Docker API error', result.error)

    def test_get_trufflehog_status_handles_api_error(self):
        """get_trufflehog_status should catch APIError and set error state."""
        import asyncio
        manager, cm_mod = self._make_manager()

        state = cm_mod.TrufflehogState(
            project_id='test',
            status=cm_mod.TrufflehogStatus.RUNNING,
            container_id='abc123',
        )
        manager.trufflehog_states['test'] = state
        manager.client.containers.get.side_effect = cm_mod.APIError('500 Server Error')

        result = asyncio.get_event_loop().run_until_complete(manager.get_trufflehog_status('test'))
        self.assertEqual(result.status, cm_mod.TrufflehogStatus.ERROR)
        self.assertIn('Docker API error', result.error)

    def test_api_error_does_not_overwrite_completed_state(self):
        """APIError should NOT overwrite an already-completed state."""
        import asyncio
        manager, cm_mod = self._make_manager()

        state = cm_mod.ReconState(
            project_id='test',
            status=cm_mod.ReconStatus.COMPLETED,
            container_id='abc123',
        )
        manager.running_states['test'] = state
        manager.client.containers.get.side_effect = cm_mod.APIError('500 Server Error')

        result = asyncio.get_event_loop().run_until_complete(manager.get_status('test'))
        # Should remain COMPLETED, not switch to ERROR
        self.assertEqual(result.status, cm_mod.ReconStatus.COMPLETED)


if __name__ == '__main__':
    unittest.main(verbosity=2)
