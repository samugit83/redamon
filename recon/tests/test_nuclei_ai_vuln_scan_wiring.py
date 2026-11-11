"""
End-to-end wiring test for the AI tag selector inside run_vuln_scan().

Mocks docker/subprocess shims (same pattern as test_nuclei_two_pass.py) so the
test runs in <1s without real network or docker calls. What it actually asserts:

- When NUCLEI_AI_TAGS=False: get_ai_tags is never called (no LLM round-trip).
- When NUCLEI_AI_TAGS=True with empty NUCLEI_TAGS: short-circuit; no LLM call,
  detection pass is skipped (because empty tags + no custom templates).
- When NUCLEI_AI_TAGS=True with populated tags + tech fingerprint: get_ai_tags
  IS called, and the AI's returned tags are the ones passed to nuclei
  (build_nuclei_command receives them, not the user's original list).
- The scan_metadata.tags_ai_selected boolean reflects whether AI actually
  replaced the list (false when AI returned current_tags unchanged).
- Partial-recon shape (no tech in by_url) drives fallback_urls -> HEAD probe.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from recon.main_recon_modules import vuln_scan as vs
    _HAS = True
except ImportError:
    _HAS = False


def _recon_data(with_tech=True):
    by_url = {
        "https://example.com": {
            "url": "https://example.com",
            "host": "example.com",
        }
    }
    if with_tech:
        by_url["https://example.com"]["technologies"] = ["WordPress 6.4", "PHP 8.1"]
        by_url["https://example.com"]["server"] = "Apache/2.4"
    return {
        "domain": "example.com",
        "subdomains": ["example.com"],
        "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}, "has_records": True},
                "subdomains": {}},
        "http_probe": {"by_url": by_url},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
    }


def _base_settings(**overrides):
    s = {
        "NUCLEI_ENABLED": True,
        "NUCLEI_DAST_MODE": False,
        "NUCLEI_SEVERITY": ["critical", "high"],
        "NUCLEI_TEMPLATES": [],
        "NUCLEI_EXCLUDE_TEMPLATES": [],
        "NUCLEI_RATE_LIMIT": 100,
        "NUCLEI_BULK_SIZE": 25,
        "NUCLEI_CONCURRENCY": 25,
        "NUCLEI_TIMEOUT": 10,
        "NUCLEI_RETRIES": 1,
        "NUCLEI_TAGS": ["cve", "xss", "sqli", "rce", "lfi", "ssrf", "xxe", "ssti"],
        "NUCLEI_EXCLUDE_TAGS": [],
        "NUCLEI_NEW_TEMPLATES_ONLY": False,
        "NUCLEI_HEADLESS": False,
        "NUCLEI_SYSTEM_RESOLVERS": True,
        "NUCLEI_FOLLOW_REDIRECTS": True,
        "NUCLEI_MAX_REDIRECTS": 10,
        "NUCLEI_SCAN_ALL_IPS": False,
        "NUCLEI_INTERACTSH": True,
        "NUCLEI_DOCKER_IMAGE": "projectdiscovery/nuclei:latest",
        "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
        "NUCLEI_AI_TAGS": False,
        "AI_PIPELINE_MODEL": "claude-haiku-4-5",
        "KATANA_DEPTH": 2,
        "CVE_LOOKUP_ENABLED": False,
        "SECURITY_CHECK_ENABLED": False,
    }
    s.update(overrides)
    return s


def _pipeline_patches(target_urls=None):
    target_urls = target_urls or ["https://example.com"]
    return [
        patch("recon.main_recon_modules.vuln_scan.is_docker_installed", return_value=True),
        patch("recon.main_recon_modules.vuln_scan.is_docker_running", return_value=True),
        patch("recon.main_recon_modules.vuln_scan.pull_nuclei_docker_image", return_value=None),
        patch("recon.main_recon_modules.vuln_scan.ensure_templates_volume", return_value=True),
        patch("recon.main_recon_modules.vuln_scan.extract_targets_from_recon",
              side_effect=lambda rd, *_a, **_k: ([], ["example.com"], {})),
        patch("recon.main_recon_modules.vuln_scan.build_target_urls",
              side_effect=lambda h, i, r, scan_all_ips=False: target_urls),
    ]


@unittest.skipUnless(_HAS, "recon package not on PYTHONPATH")
class TestVulnScanAIWiring(unittest.TestCase):

    def _start(self, patches):
        for p in patches: p.start()
    def _stop(self, patches):
        for p in patches: p.stop()

    def test_ai_off_never_calls_get_ai_tags(self):
        rd = _recon_data(with_tech=True)
        settings = _base_settings(NUCLEI_AI_TAGS=False)
        patches = _pipeline_patches()
        self._start(patches)
        try:
            with patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)), \
                 patch("recon.helpers.ai_planner.nuclei_tags.get_ai_tags") as ai_mock:
                vs.run_vuln_scan(rd, output_file=None, settings=settings)
            ai_mock.assert_not_called()
            # Original tags survived
            md = rd["vuln_scan"]["scan_metadata"]
            self.assertEqual(md["tags_filter"], settings["NUCLEI_TAGS"])
            self.assertFalse(md["tags_ai_selected"])
        finally:
            self._stop(patches)
        print("PASS: test_ai_off_never_calls_get_ai_tags")

    def test_ai_on_with_tech_calls_get_ai_tags_and_replaces_list(self):
        rd = _recon_data(with_tech=True)
        settings = _base_settings(NUCLEI_AI_TAGS=True)
        patches = _pipeline_patches()
        self._start(patches)
        captured = {}
        def fake_get_ai_tags(**kwargs):
            captured.update(kwargs)
            return ["cve", "wordpress", "apache", "php"]
        try:
            with patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)), \
                 patch("recon.helpers.ai_planner.nuclei_tags.get_ai_tags",
                       side_effect=fake_get_ai_tags) as ai_mock, \
                 patch.object(vs, "build_nuclei_command",
                              return_value=["docker", "run", "fake"]) as cmd_mock:
                vs.run_vuln_scan(rd, output_file=None, settings=settings)
            ai_mock.assert_called_once()
            # Fingerprint passed to AI should include detected wordpress/php/apache
            techs = captured["tech_fingerprint"]["technologies"]
            servers = captured["tech_fingerprint"]["servers"]
            self.assertIn("wordpress 6.4", techs)
            self.assertIn("php 8.1", techs)
            self.assertIn("apache", servers)
            # No fallback_urls because tech IS available
            self.assertIsNone(captured["fallback_urls"])
            # build_nuclei_command must receive the AI-pruned tags, NOT the originals
            cmd_kwargs = cmd_mock.call_args.kwargs
            self.assertEqual(cmd_kwargs["tags"], ["cve", "wordpress", "apache", "php"])
            # Metadata flag flipped on
            md = rd["vuln_scan"]["scan_metadata"]
            self.assertEqual(md["tags_filter"], ["cve", "wordpress", "apache", "php"])
            self.assertTrue(md["tags_ai_selected"])
        finally:
            self._stop(patches)
        print("PASS: test_ai_on_with_tech_calls_get_ai_tags_and_replaces_list")

    def test_ai_on_returns_unchanged_tags_keeps_flag_false(self):
        """If get_ai_tags returns the same list (e.g. fallback because LLM was
        unreachable), tags_ai_selected must stay False."""
        rd = _recon_data(with_tech=True)
        settings = _base_settings(NUCLEI_AI_TAGS=True)
        patches = _pipeline_patches()
        self._start(patches)
        try:
            with patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)), \
                 patch("recon.helpers.ai_planner.nuclei_tags.get_ai_tags",
                       side_effect=lambda **kw: kw["current_tags"]), \
                 patch.object(vs, "build_nuclei_command",
                              return_value=["docker", "run", "fake"]) as cmd_mock:
                vs.run_vuln_scan(rd, output_file=None, settings=settings)
            # Original tags stayed
            cmd_kwargs = cmd_mock.call_args.kwargs
            self.assertEqual(cmd_kwargs["tags"], settings["NUCLEI_TAGS"])
            # Flag is False because AI returned the same list (no replacement)
            md = rd["vuln_scan"]["scan_metadata"]
            self.assertFalse(md["tags_ai_selected"])
        finally:
            self._stop(patches)
        print("PASS: test_ai_on_returns_unchanged_tags_keeps_flag_false")

    def test_ai_on_with_bare_urls_passes_fallback_urls(self):
        """Partial-recon scenario: by_url has no technologies/server, so the
        AI block must hand `target_urls` to the helper as fallback_urls."""
        rd = _recon_data(with_tech=False)  # bare entries
        settings = _base_settings(NUCLEI_AI_TAGS=True)
        patches = _pipeline_patches(target_urls=["https://bare1.example/", "https://bare2.example/"])
        self._start(patches)
        captured = {}
        try:
            with patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)), \
                 patch("recon.helpers.ai_planner.nuclei_tags.get_ai_tags",
                       side_effect=lambda **kw: (captured.update(kw), ["cve"])[1]), \
                 patch.object(vs, "build_nuclei_command",
                              return_value=["docker", "run", "fake"]):
                vs.run_vuln_scan(rd, output_file=None, settings=settings)
            self.assertEqual(captured["fallback_urls"],
                             ["https://bare1.example/", "https://bare2.example/"])
            self.assertEqual(captured["tech_fingerprint"]["technologies"], [])
            self.assertEqual(captured["tech_fingerprint"]["servers"], [])
        finally:
            self._stop(patches)
        print("PASS: test_ai_on_with_bare_urls_passes_fallback_urls")

    def test_ai_on_with_empty_user_tags_skips_ai_call(self):
        """Special case: user emptied NUCLEI_TAGS to use only custom templates.
        AI must NOT run -- there's nothing to prune, and prefilling tags would
        contradict the user's intent."""
        rd = _recon_data(with_tech=True)
        settings = _base_settings(NUCLEI_AI_TAGS=True, NUCLEI_TAGS=[])
        patches = _pipeline_patches()
        self._start(patches)
        try:
            with patch("recon.helpers.ai_planner.nuclei_tags.get_ai_tags") as ai_mock:
                vs.run_vuln_scan(rd, output_file=None, settings=settings)
            ai_mock.assert_not_called()
        finally:
            self._stop(patches)
        print("PASS: test_ai_on_with_empty_user_tags_skips_ai_call")


if __name__ == "__main__":
    unittest.main(verbosity=2, exit=False)
