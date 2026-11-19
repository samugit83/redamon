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

# Add recon paths first (primary test target). The gate runs this file in the
# agent image, whose PYTHONPATH has none of them: without main_recon_modules the
# Shodan, CVE and URLScan classes below skip in every run.
sys.path.insert(0, str(REPO_ROOT / "recon" / "main_recon_modules"))
sys.path.insert(0, str(REPO_ROOT / "recon"))
sys.path.insert(0, str(REPO_ROOT / "recon" / "helpers"))

# Stub out Docker-only dependencies before importing cve_helpers
# (security_checks.py imports dns.resolver which is only in the container).
# Only where dnspython is really missing: a stub over the real package breaks
# recon.helpers' own `import dns.zone` in the recon image.
for mod_name in ["dns", "dns.resolver", "dns.rdatatype", "dns.name", "dns.zone", "dns.query", "dns.xfr"]:
    if mod_name not in sys.modules:
        try:
            importlib.import_module(mod_name)
        except ImportError:
            sys.modules[mod_name] = types.ModuleType(mod_name)


# =============================================================================
# 1. KeyRotator Core Logic (recon copy)
# =============================================================================

from key_rotation import KeyRotator


def _importable(name):
    """True if `name` can be imported in this image. Some classes here exercise
    recon-only modules (shodan_enrich, ...) and one exercises the agentic
    orchestrator_helpers copy; each image has only one side, so classes self-skip
    (bucket-2) when their side is not importable rather than hard-failing."""
    import importlib.util
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


_RECON_AVAILABLE = _importable("shodan_enrich")
# Checked by path, not import: with recon first on sys.path, importing the
# orchestrator_helpers package resolves its `project_settings` to recon's copy
# and fails, which skipped the agentic class in every image.
_AGENTIC_KR_PATH = REPO_ROOT / "agentic" / "orchestrator_helpers" / "key_rotation.py"
_AGENTIC_KR_AVAILABLE = _AGENTIC_KR_PATH.is_file()


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


class TestKeyRotatorPool(unittest.TestCase):
    """The lock and mark_bad the recon circuit breakers rely on."""

    def test_concurrent_ticks_rotate_exactly(self):
        from concurrent.futures import ThreadPoolExecutor
        r = KeyRotator(["a", "b", "c"], rotate_every_n=7)
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda _: r.tick(), range(7 * 3 * 50)))
        # 150 full cycles of 3 keys: back to the first, with no lost update.
        self.assertEqual(r.current_key, "a")

    def test_mark_bad_reports_the_configured_position_never_the_value(self):
        r = KeyRotator(["main", "", "extra-1", "extra-2"], rotate_every_n=10)
        self.assertEqual(r.mark_bad("extra-1"), (3, 2))
        self.assertEqual(r.keys, ["main", "extra-2"])

    def test_a_key_already_dropped_is_a_no_op(self):
        r = KeyRotator(["a", "b"], rotate_every_n=10)
        r.mark_bad("a")
        self.assertEqual(r.mark_bad("a"), (0, 1))

    def test_the_pool_is_exhausted_only_after_a_drop(self):
        self.assertFalse(KeyRotator([], rotate_every_n=10).exhausted)
        r = KeyRotator(["only"], rotate_every_n=10)
        self.assertFalse(r.exhausted)
        r.mark_bad("only")
        self.assertTrue(r.exhausted)
        self.assertEqual(r.current_key, "")

    def test_rotation_continues_over_the_remaining_keys(self):
        r = KeyRotator(["a", "b", "c"], rotate_every_n=1)
        r.mark_bad("b")
        seen = []
        for _ in range(4):
            seen.append(r.current_key)
            r.tick()
        self.assertEqual(seen, ["a", "c", "a", "c"])


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


@unittest.skipUnless(_RECON_AVAILABLE, "recon enrichment modules not importable in this image")
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

@unittest.skipUnless(_RECON_AVAILABLE, "recon enrichment modules not importable in this image")
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

@unittest.skipUnless(_RECON_AVAILABLE, "recon enrichment modules not importable in this image")
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
        """lookup_cves_vulners sends rotator.current_key in the X-Api-Key header,
        the only place Vulners accepts it, and never in the query string."""
        from cve_helpers import lookup_cves_vulners

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": "OK", "data": {"search": []}}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        rotator = KeyRotator(["vulners-rot", "vulners-bak"], rotate_every_n=1)

        lookup_cves_vulners("nginx", "1.19.0", api_key="vulners-fallback", key_rotator=rotator)

        call_kwargs = mock_get.call_args
        self.assertEqual(call_kwargs.kwargs["headers"]["X-Api-Key"], "vulners-rot")
        self.assertNotIn("vulners-rot", str(call_kwargs.kwargs["params"]))

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

@unittest.skipUnless(_RECON_AVAILABLE, "recon enrichment modules not importable in this image")
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

@unittest.skipUnless(_AGENTIC_KR_AVAILABLE, "agentic orchestrator_helpers not importable in this image")
class TestAgenticKeyRotator(unittest.TestCase):
    """Verify the agentic copy of KeyRotator works identically."""

    def test_agentic_rotator_import(self):
        """Can import KeyRotator from agentic/orchestrator_helpers/key_rotation.py."""
        spec = importlib.util.spec_from_file_location("agentic_key_rotation", _AGENTIC_KR_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
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
