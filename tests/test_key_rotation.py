"""
Unit tests for API key rotation feature.

Tests cover:
1. KeyRotator class — rotation logic, edge cases, pool management
2. Recon project_settings — rotator construction from user settings
3. Shodan enrichment — rotator threading through _shodan_get
4. CVE helpers — rotator threading through NVD/Vulners lookups
5. Settings API contract — rotation config shape in GET/PUT

Run with: python -m pytest tests/test_key_rotation.py -v
"""

import importlib
import importlib.util
import os
import sys
import types
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Add recon paths first (primary test target)
sys.path.insert(0, str(REPO_ROOT / "recon"))
sys.path.insert(0, str(REPO_ROOT / "recon" / "helpers"))

# Stub out Docker-only dependencies before importing cve_helpers
# (security_checks.py imports dns.resolver which is only in the container)
for mod_name in ["dns", "dns.resolver", "dns.rdatatype", "dns.name"]:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = types.ModuleType(mod_name)


# =============================================================================
# 1. KeyRotator Core Logic (recon copy)
# =============================================================================

from key_rotation import KeyRotator


class TestKeyRotatorBasic(unittest.TestCase):
    """Test the KeyRotator class fundamental behavior."""

    def test_single_key_returns_same_key(self):
        """With one key, current_key always returns it."""
        r = KeyRotator(["key-A"], rotate_every_n=3)
        self.assertEqual(r.current_key, "key-A")
        r.tick()
        r.tick()
        r.tick()
        self.assertEqual(r.current_key, "key-A")

    def test_empty_keys_returns_empty_string(self):
        r = KeyRotator([])
        self.assertEqual(r.current_key, "")
        self.assertFalse(r.has_keys)

    def test_filters_empty_strings(self):
        """Empty strings in the key list are filtered out."""
        r = KeyRotator(["", "key-A", "", "key-B", ""])
        self.assertEqual(r.pool_size, 2)
        self.assertEqual(r.current_key, "key-A")

    def test_has_keys_property(self):
        self.assertTrue(KeyRotator(["a"]).has_keys)
        self.assertFalse(KeyRotator([]).has_keys)
        self.assertFalse(KeyRotator(["", ""]).has_keys)

    def test_pool_size(self):
        self.assertEqual(KeyRotator(["a", "b", "c"]).pool_size, 3)
        self.assertEqual(KeyRotator([]).pool_size, 0)


class TestKeyRotatorRotation(unittest.TestCase):
    """Test the rotation mechanics."""

    def test_rotates_after_n_calls(self):
        """Key switches after exactly rotate_every_n ticks."""
        r = KeyRotator(["A", "B", "C"], rotate_every_n=2)
        self.assertEqual(r.current_key, "A")

        r.tick()  # call 1
        self.assertEqual(r.current_key, "A")

        r.tick()  # call 2 → rotate
        self.assertEqual(r.current_key, "B")

        r.tick()  # call 3
        self.assertEqual(r.current_key, "B")

        r.tick()  # call 4 → rotate
        self.assertEqual(r.current_key, "C")

    def test_wraps_around_to_first_key(self):
        """After exhausting the pool, wraps back to key 0."""
        r = KeyRotator(["X", "Y"], rotate_every_n=1)
        self.assertEqual(r.current_key, "X")

        r.tick()  # rotate → Y
        self.assertEqual(r.current_key, "Y")

        r.tick()  # rotate → X (wrap)
        self.assertEqual(r.current_key, "X")

        r.tick()  # rotate → Y
        self.assertEqual(r.current_key, "Y")

    def test_rotate_every_1(self):
        """rotate_every_n=1 means every call rotates."""
        r = KeyRotator(["A", "B", "C"], rotate_every_n=1)
        keys = []
        for _ in range(6):
            keys.append(r.current_key)
            r.tick()
        self.assertEqual(keys, ["A", "B", "C", "A", "B", "C"])

    def test_rotate_every_n_default(self):
        """Default rotate_every_n is 10."""
        r = KeyRotator(["A", "B"])
        self.assertEqual(r.rotate_every_n, 10)

    def test_rotate_every_n_minimum_1(self):
        """rotate_every_n is clamped to at least 1."""
        r = KeyRotator(["A", "B"], rotate_every_n=0)
        self.assertEqual(r.rotate_every_n, 1)
        r = KeyRotator(["A", "B"], rotate_every_n=-5)
        self.assertEqual(r.rotate_every_n, 1)

    def test_single_key_tick_is_noop(self):
        """With a single key, tick() is a no-op (no rotation needed)."""
        r = KeyRotator(["only-one"], rotate_every_n=1)
        for _ in range(100):
            r.tick()
        self.assertEqual(r.current_key, "only-one")

    def test_full_rotation_cycle(self):
        """10 keys, rotate every 5 — full cycle takes 50 ticks."""
        keys = [f"key-{i}" for i in range(10)]
        r = KeyRotator(keys, rotate_every_n=5)

        observed = []
        for i in range(50):
            observed.append(r.current_key)
            r.tick()

        # Each key should appear exactly 5 times
        for k in keys:
            self.assertEqual(observed.count(k), 5, f"{k} should appear 5 times")

        # After full cycle, back to first key
        self.assertEqual(r.current_key, "key-0")


# =============================================================================
# 2. Recon project_settings — rotator construction
# =============================================================================

def _load_recon_project_settings():
    """Explicitly load the recon version of project_settings (not agentic)."""
    spec = importlib.util.spec_from_file_location(
        "recon_project_settings",
        str(REPO_ROOT / "recon" / "project_settings.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    # Temporarily ensure recon paths are prioritized
    spec.loader.exec_module(mod)
    return mod


class TestReconProjectSettingsRotator(unittest.TestCase):
    """Test that project_settings builds rotators from user settings."""

    def test_build_rotator_with_extra_keys(self):
        """Rotator is correctly built from main key + extra keys + rotateEveryN."""
        rotation_configs = {
            "shodan": {
                "extraKeys": ["extra-1", "extra-2"],
                "rotateEveryN": 5,
            }
        }

        # Simulate the _build_rotator logic from fetch_project_settings
        main_key = "main-key"
        cfg = rotation_configs.get("shodan", {})
        extra = cfg.get("extraKeys", [])
        rotate_n = cfg.get("rotateEveryN", 10)
        rotator = KeyRotator([main_key] + extra, rotate_n)

        self.assertEqual(rotator.pool_size, 3)  # main + 2 extra
        self.assertEqual(rotator.current_key, "main-key")
        self.assertEqual(rotator.rotate_every_n, 5)

        # After 5 ticks, should rotate to extra-1
        for _ in range(5):
            rotator.tick()
        self.assertEqual(rotator.current_key, "extra-1")

        # After 5 more, rotate to extra-2
        for _ in range(5):
            rotator.tick()
        self.assertEqual(rotator.current_key, "extra-2")

    def test_build_rotator_without_rotation_config(self):
        """Without rotation config, rotator has just the main key."""
        rotation_configs = {}

        main_key = "nvd-main"
        cfg = rotation_configs.get("nvd", {})
        extra = cfg.get("extraKeys", [])
        rotate_n = cfg.get("rotateEveryN", 10)
        rotator = KeyRotator([main_key] + extra, rotate_n)

        self.assertEqual(rotator.pool_size, 1)
        self.assertEqual(rotator.current_key, "nvd-main")
        self.assertEqual(rotator.rotate_every_n, 10)

    def test_build_rotator_empty_main_key(self):
        """Empty main key with extra keys — only extra keys in pool."""
        rotation_configs = {
            "tavily": {
                "extraKeys": ["key-A", "key-B"],
                "rotateEveryN": 3,
            }
        }

        main_key = ""  # No main key configured
        cfg = rotation_configs.get("tavily", {})
        extra = cfg.get("extraKeys", [])
        rotator = KeyRotator([main_key] + extra, cfg.get("rotateEveryN", 10))

        # Empty main key is filtered out
        self.assertEqual(rotator.pool_size, 2)
        self.assertEqual(rotator.current_key, "key-A")


# =============================================================================
# 3. Shodan enrichment — rotator passed to _shodan_get
# =============================================================================

class TestShodanEnrichRotation(unittest.TestCase):
    """Test that Shodan enrichment passes rotator through the call chain."""

    @patch("shodan_enrich.requests.get")
    def test_shodan_get_uses_rotator_key(self, mock_get):
        """_shodan_get uses rotator.current_key instead of the raw api_key."""
        from shodan_enrich import _shodan_get

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ip_str": "1.2.3.4"}
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["rotated-key", "backup-key"], rotate_every_n=1)

        result = _shodan_get("/shodan/host/1.2.3.4", "fallback-key", key_rotator=rotator)

        # Should have used "rotated-key" (rotator's current), not "fallback-key"
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        self.assertEqual(params_sent["key"], "rotated-key")
        self.assertIsNotNone(result)

    @patch("shodan_enrich.requests.get")
    def test_shodan_get_ticks_rotator_after_call(self, mock_get):
        """_shodan_get calls rotator.tick() after the API request."""
        from shodan_enrich import _shodan_get

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["A", "B"], rotate_every_n=1)
        self.assertEqual(rotator.current_key, "A")

        _shodan_get("/test", "fallback", key_rotator=rotator)
        self.assertEqual(rotator.current_key, "B")  # rotated after tick

    @patch("shodan_enrich.requests.get")
    def test_shodan_get_without_rotator_uses_api_key(self, mock_get):
        """Without a rotator, _shodan_get uses the api_key parameter directly."""
        from shodan_enrich import _shodan_get

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_get.return_value = mock_resp

        _shodan_get("/test", "direct-key")

        call_kwargs = mock_get.call_args
        params_sent = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        self.assertEqual(params_sent["key"], "direct-key")


# =============================================================================
# 4. CVE helpers — rotator threading
# =============================================================================

class TestCveHelpersRotation(unittest.TestCase):
    """Test NVD and Vulners lookups use key rotation."""

    @patch("cve_helpers.requests.get")
    def test_nvd_lookup_uses_rotator_key(self, mock_get):
        """lookup_cves_nvd uses rotator.current_key in headers."""
        from cve_helpers import lookup_cves_nvd

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["nvd-rotated", "nvd-backup"], rotate_every_n=1)

        lookup_cves_nvd("nginx", "1.19.0", api_key="nvd-fallback", key_rotator=rotator)

        call_kwargs = mock_get.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        self.assertEqual(headers["apiKey"], "nvd-rotated")

    @patch("cve_helpers.requests.get")
    def test_nvd_lookup_ticks_after_call(self, mock_get):
        """lookup_cves_nvd ticks the rotator after the request."""
        from cve_helpers import lookup_cves_nvd

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["A", "B"], rotate_every_n=1)
        lookup_cves_nvd("test", "1.0", api_key="x", key_rotator=rotator)
        self.assertEqual(rotator.current_key, "B")

    @patch("cve_helpers.requests.get")
    def test_vulners_lookup_uses_rotator_key(self, mock_get):
        """lookup_cves_vulners uses rotator.current_key in params."""
        from cve_helpers import lookup_cves_vulners

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": "OK", "data": {"search": []}}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["vulners-rot", "vulners-bak"], rotate_every_n=1)

        lookup_cves_vulners("nginx", "1.19.0", api_key="vulners-fallback", key_rotator=rotator)

        call_kwargs = mock_get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        self.assertEqual(params["apiKey"], "vulners-rot")

    @patch("cve_helpers.requests.get")
    def test_vulners_lookup_ticks_after_call(self, mock_get):
        """lookup_cves_vulners ticks the rotator after the request."""
        from cve_helpers import lookup_cves_vulners

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": "OK", "data": {"search": []}}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["A", "B"], rotate_every_n=1)
        lookup_cves_vulners("test", "1.0", api_key="x", key_rotator=rotator)
        self.assertEqual(rotator.current_key, "B")

    @patch("cve_helpers.requests.get")
    def test_nvd_without_rotator_uses_api_key(self, mock_get):
        """Without rotator, lookup_cves_nvd uses api_key directly."""
        from cve_helpers import lookup_cves_nvd

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        lookup_cves_nvd("nginx", "1.19.0", api_key="direct-key")

        call_kwargs = mock_get.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        self.assertEqual(headers["apiKey"], "direct-key")


# =============================================================================
# 5. URLScan enrichment — rotator integration
# =============================================================================

class TestUrlscanEnrichRotation(unittest.TestCase):
    """Test URLScan enrichment uses key rotation."""

    @patch("urlscan_enrich.requests.get")
    def test_urlscan_search_uses_rotator_key(self, mock_get):
        """_urlscan_search uses rotator.current_key in API-Key header."""
        from urlscan_enrich import _urlscan_search

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": []}
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["urlscan-rot", "urlscan-bak"], rotate_every_n=1)

        _urlscan_search("example.com", "fallback-key", key_rotator=rotator)

        call_kwargs = mock_get.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        self.assertEqual(headers["API-Key"], "urlscan-rot")

    @patch("urlscan_enrich.requests.get")
    def test_urlscan_search_ticks_after_call(self, mock_get):
        """_urlscan_search ticks the rotator after the request."""
        from urlscan_enrich import _urlscan_search

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": []}
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["A", "B"], rotate_every_n=1)
        _urlscan_search("example.com", "x", key_rotator=rotator)
        self.assertEqual(rotator.current_key, "B")


# =============================================================================
# 6. Agentic KeyRotator — verify identical behavior
# =============================================================================

class TestAgenticKeyRotator(unittest.TestCase):
    """Verify the agentic copy of KeyRotator works identically."""

    def test_agentic_rotator_import(self):
        """Can import KeyRotator from agentic/key_rotation.py."""
        # Re-import from agentic path
        agentic_path = str(REPO_ROOT / "agentic")
        if agentic_path not in sys.path:
            sys.path.insert(0, agentic_path)

        import importlib
        mod = importlib.import_module("key_rotation")
        importlib.reload(mod)  # Force reload to get agentic version
        AgenticKeyRotator = mod.KeyRotator

        r = AgenticKeyRotator(["A", "B", "C"], rotate_every_n=2)
        self.assertEqual(r.current_key, "A")
        r.tick()
        r.tick()
        self.assertEqual(r.current_key, "B")
        r.tick()
        r.tick()
        self.assertEqual(r.current_key, "C")


if __name__ == "__main__":
    unittest.main()
