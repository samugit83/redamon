"""
Unit tests for GAU URLScan API key feature.

Tests cover:
1. _write_gau_config() — .gau.toml generation
2. run_gau_for_domain() — API key passthrough and config mount
3. run_gau_discovery() — API key passthrough
4. _fetch_user_api_key() — generic key fetcher
5. _fetch_urlscan_api_key() — URLScan-specific wrapper
6. DEFAULT_SETTINGS / RUNTIME_ONLY_KEYS consistency
7. resource_enum.py source-level checks
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent

# Add recon to path for project_settings imports
sys.path.insert(0, str(REPO_ROOT / "recon"))

# Import gau_helpers through the package to resolve relative imports
sys.path.insert(0, str(REPO_ROOT / "recon" / "helpers"))
import importlib

# We need to import resource_enum.helpers as a package
# Add the parent so "recon.helpers.resource_enum" can be resolved
_gau_mod = None


def _get_gau_module():
    """Import gau_helpers through the package to handle relative imports."""
    global _gau_mod
    if _gau_mod is not None:
        return _gau_mod

    # Trick: set up the package hierarchy so relative imports work
    helpers_path = REPO_ROOT / "recon" / "helpers" / "resource_enum"

    # Create a minimal package context
    import types
    pkg = types.ModuleType("recon_helpers_resource_enum")
    pkg.__path__ = [str(helpers_path)]
    pkg.__package__ = "recon_helpers_resource_enum"

    # Load classification first (dependency)
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

    # Now load gau_helpers with the package context
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
# Tests for _write_gau_config
# ---------------------------------------------------------------------------
class TestWriteGauConfig(unittest.TestCase):
    """Test .gau.toml config file generation."""

    def test_writes_urlscan_api_key(self):
        """Config file should contain [urlscan] section with the key."""
        gau = _get_gau_module()
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            gau._write_gau_config("my-secret-key-123", tmp)
            config = (tmp / ".gau.toml").read_text()
            self.assertIn("[urlscan]", config)
            self.assertIn('apikey = "my-secret-key-123"', config)

    def test_empty_key_produces_empty_config(self):
        """If key is empty, config should have no [urlscan] section."""
        gau = _get_gau_module()
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            gau._write_gau_config("", tmp)
            config = (tmp / ".gau.toml").read_text()
            self.assertNotIn("[urlscan]", config)
            self.assertNotIn("apikey", config)

    def test_special_chars_in_key(self):
        """API key with special chars should be written correctly."""
        gau = _get_gau_module()
        key = "abc-123_XYZ!@#$%"
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            gau._write_gau_config(key, tmp)
            config = (tmp / ".gau.toml").read_text()
            self.assertIn(f'apikey = "{key}"', config)

    def test_returns_path_object(self):
        """Should return a Path to the created .gau.toml file."""
        gau = _get_gau_module()
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            result = gau._write_gau_config("key", tmp)
            self.assertIsInstance(result, Path)
            self.assertTrue(result.exists())
            self.assertEqual(result.name, ".gau.toml")

    def test_file_ends_with_newline(self):
        """Config file should end with a newline."""
        gau = _get_gau_module()
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            gau._write_gau_config("key", tmp)
            config = (tmp / ".gau.toml").read_text()
            self.assertTrue(config.endswith("\n"))


# ---------------------------------------------------------------------------
# Tests for run_gau_for_domain — Docker cmd config mount
# ---------------------------------------------------------------------------
class TestRunGauForDomain(unittest.TestCase):
    """Test that run_gau_for_domain correctly handles API key config."""

    def _patch_target(self, name):
        return f"recon_helpers_resource_enum.gau_helpers.{name}"

    @patch("recon_helpers_resource_enum.gau_helpers.subprocess.run")
    @patch("recon_helpers_resource_enum.gau_helpers._cleanup_temp_dir")
    @patch("recon_helpers_resource_enum.gau_helpers._create_temp_dir")
    def test_no_config_mount_without_key(self, mock_create, mock_cleanup, mock_run):
        """Without API key, no .gau.toml mount should appear in Docker cmd."""
        gau = _get_gau_module()
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)

        gau.run_gau_for_domain(
            domain="example.com",
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=["png"],
            max_urls=100,
            urlscan_api_key=""
        )

        mock_create.assert_not_called()
        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(str(c) for c in cmd)
        self.assertNotIn(".gau.toml", cmd_str)

    @patch("recon_helpers_resource_enum.gau_helpers.subprocess.run")
    @patch("recon_helpers_resource_enum.gau_helpers._cleanup_temp_dir")
    @patch("recon_helpers_resource_enum.gau_helpers._create_temp_dir")
    def test_config_mount_with_key(self, mock_create, mock_cleanup, mock_run):
        """With API key, .gau.toml should be volume-mounted read-only."""
        gau = _get_gau_module()
        fake_dir = Path(tempfile.mkdtemp())
        mock_create.return_value = fake_dir
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)

        try:
            gau.run_gau_for_domain(
                domain="example.com",
                docker_image="sxcurity/gau:latest",
                providers=["urlscan"],
                threads=2,
                timeout=30,
                blacklist_extensions=[],
                max_urls=100,
                urlscan_api_key="test-key-456"
            )

            mock_create.assert_called_once()
            cmd = mock_run.call_args[0][0]
            cmd_str = " ".join(str(c) for c in cmd)
            self.assertIn(".gau.toml:/root/.gau.toml:ro", cmd_str)

            # Verify config file content
            config_file = fake_dir / ".gau.toml"
            self.assertTrue(config_file.exists())
            content = config_file.read_text()
            self.assertIn('apikey = "test-key-456"', content)

            # Cleanup should be called in finally block
            mock_cleanup.assert_called_once_with(fake_dir)
        finally:
            shutil.rmtree(fake_dir, ignore_errors=True)

    @patch("recon_helpers_resource_enum.gau_helpers.subprocess.run")
    @patch("recon_helpers_resource_enum.gau_helpers._cleanup_temp_dir")
    @patch("recon_helpers_resource_enum.gau_helpers._create_temp_dir")
    def test_cleanup_on_docker_error(self, mock_create, mock_cleanup, mock_run):
        """Config temp dir must be cleaned up even if Docker raises."""
        gau = _get_gau_module()
        fake_dir = Path(tempfile.mkdtemp())
        mock_create.return_value = fake_dir
        mock_run.side_effect = Exception("Docker not found")

        try:
            # _run_gau_docker catches all exceptions internally and returns []
            result = gau.run_gau_for_domain(
                domain="example.com",
                docker_image="sxcurity/gau:latest",
                providers=["urlscan"],
                threads=2,
                timeout=30,
                blacklist_extensions=[],
                max_urls=100,
                urlscan_api_key="test-key"
            )
        except Exception:
            pass

        mock_cleanup.assert_called_once_with(fake_dir)
        shutil.rmtree(fake_dir, ignore_errors=True)

    @patch("recon_helpers_resource_enum.gau_helpers.subprocess.run")
    def test_basic_docker_cmd_structure(self, mock_run):
        """Docker cmd should always include image, threads, timeout, providers."""
        gau = _get_gau_module()
        mock_run.return_value = MagicMock(stdout="http://ex.com/a\nhttp://ex.com/b\n", stderr="", returncode=0)

        result = gau.run_gau_for_domain(
            domain="example.com",
            docker_image="sxcurity/gau:latest",
            providers=["wayback", "commoncrawl"],
            threads=5,
            timeout=60,
            blacklist_extensions=["png"],
            max_urls=10,
        )

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(str(c) for c in cmd)
        self.assertIn("docker run --rm", cmd_str)
        self.assertIn("sxcurity/gau:latest", cmd_str)
        self.assertIn("--threads 5", cmd_str)
        self.assertIn("--timeout 60", cmd_str)
        self.assertIn("--providers wayback,commoncrawl", cmd_str)
        self.assertIn("--blacklist png", cmd_str)
        self.assertIn("example.com", cmd_str)
        # Should return parsed URLs
        self.assertIn("http://ex.com/a", result)
        self.assertIn("http://ex.com/b", result)


# ---------------------------------------------------------------------------
# Tests for run_gau_discovery — API key passthrough
# ---------------------------------------------------------------------------
class TestRunGauDiscovery(unittest.TestCase):
    """Test run_gau_discovery passes urlscan_api_key to per-domain calls."""

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_passes_api_key(self, mock_run_domain):
        """urlscan_api_key should be forwarded to each domain call."""
        gau = _get_gau_module()
        mock_run_domain.return_value = ["http://example.com/page1"]

        gau.run_gau_discovery(
            target_domains={"example.com"},
            docker_image="sxcurity/gau:latest",
            providers=["urlscan"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
            urlscan_api_key="my-key"
        )

        mock_run_domain.assert_called_once()
        kwargs = mock_run_domain.call_args.kwargs
        self.assertEqual(kwargs["urlscan_api_key"], "my-key")

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_default_empty_key(self, mock_run_domain):
        """Without urlscan_api_key, empty string should be passed."""
        gau = _get_gau_module()
        mock_run_domain.return_value = []

        gau.run_gau_discovery(
            target_domains={"example.com"},
            docker_image="sxcurity/gau:latest",
            providers=["wayback"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
        )

        mock_run_domain.assert_called_once()
        kwargs = mock_run_domain.call_args.kwargs
        self.assertEqual(kwargs["urlscan_api_key"], "")

    @patch("recon_helpers_resource_enum.gau_helpers.run_gau_for_domain")
    def test_multiple_domains(self, mock_run_domain):
        """API key should be passed to every domain call."""
        gau = _get_gau_module()
        mock_run_domain.return_value = []

        gau.run_gau_discovery(
            target_domains={"a.com", "b.com", "c.com"},
            docker_image="sxcurity/gau:latest",
            providers=["urlscan"],
            threads=2,
            timeout=30,
            blacklist_extensions=[],
            max_urls=100,
            urlscan_api_key="shared-key"
        )

        self.assertEqual(mock_run_domain.call_count, 3)
        for call in mock_run_domain.call_args_list:
            self.assertEqual(call.kwargs["urlscan_api_key"], "shared-key")


# ---------------------------------------------------------------------------
# Tests for filter_gau_url (existing, sanity check)
# ---------------------------------------------------------------------------
class TestFilterGauUrl(unittest.TestCase):
    """Sanity tests for filter_gau_url."""

    def test_filters_blacklisted(self):
        gau = _get_gau_module()
        self.assertFalse(gau.filter_gau_url("http://example.com/image.png", ["png", "jpg"]))

    def test_passes_non_blacklisted(self):
        gau = _get_gau_module()
        self.assertTrue(gau.filter_gau_url("http://example.com/api/users", ["png", "jpg"]))

    def test_empty_url(self):
        gau = _get_gau_module()
        self.assertFalse(gau.filter_gau_url("", ["png"]))


# ---------------------------------------------------------------------------
# Tests for project_settings — key fetching
# ---------------------------------------------------------------------------
class TestFetchUserApiKey(unittest.TestCase):
    """Test _fetch_user_api_key and wrappers."""

    def _fresh_import(self):
        """Force re-import of project_settings."""
        if "project_settings" in sys.modules:
            del sys.modules["project_settings"]

    @patch("requests.get")
    def test_fetch_urlscan_key_success(self, mock_get):
        """Should return the key from JSON response."""
        self._fresh_import()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"urlscanApiKey": "real-key-789", "shodanApiKey": "x"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        from project_settings import _fetch_urlscan_api_key
        result = _fetch_urlscan_api_key("user-123", "http://localhost:3000")
        self.assertEqual(result, "real-key-789")

        call_url = mock_get.call_args[0][0]
        self.assertIn("internal=true", call_url)
        self.assertIn("user-123", call_url)

    @patch("requests.get")
    def test_fetch_shodan_key_success(self, mock_get):
        """_fetch_shodan_api_key should also use _fetch_user_api_key."""
        self._fresh_import()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"shodanApiKey": "shodan-abc"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        from project_settings import _fetch_shodan_api_key
        result = _fetch_shodan_api_key("user-456", "http://localhost:3000")
        self.assertEqual(result, "shodan-abc")

    @patch("requests.get")
    def test_network_error_returns_empty(self, mock_get):
        """On network error, should return empty string."""
        self._fresh_import()
        mock_get.side_effect = Exception("Connection refused")

        from project_settings import _fetch_user_api_key
        result = _fetch_user_api_key("user-123", "http://localhost:3000", "urlscanApiKey")
        self.assertEqual(result, "")

    @patch("requests.get")
    def test_missing_key_returns_empty(self, mock_get):
        """If key absent from response, return empty string."""
        self._fresh_import()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"shodanApiKey": "some-key"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        from project_settings import _fetch_user_api_key
        result = _fetch_user_api_key("user-123", "http://localhost:3000", "urlscanApiKey")
        self.assertEqual(result, "")


# ---------------------------------------------------------------------------
# Tests for DEFAULT_SETTINGS
# ---------------------------------------------------------------------------
class TestDefaultSettings(unittest.TestCase):
    """Verify URLSCAN_API_KEY is in DEFAULT_SETTINGS."""

    @patch("requests.get")
    def test_urlscan_key_in_defaults(self, _):
        if "project_settings" in sys.modules:
            del sys.modules["project_settings"]
        from project_settings import DEFAULT_SETTINGS
        self.assertIn('URLSCAN_API_KEY', DEFAULT_SETTINGS)
        self.assertEqual(DEFAULT_SETTINGS['URLSCAN_API_KEY'], '')

    @patch("requests.get")
    def test_shodan_key_still_in_defaults(self, _):
        """Ensure existing keys weren't broken."""
        if "project_settings" in sys.modules:
            del sys.modules["project_settings"]
        from project_settings import DEFAULT_SETTINGS
        self.assertIn('SHODAN_API_KEY', DEFAULT_SETTINGS)


# ---------------------------------------------------------------------------
# Source-level checks (no import needed, just read file)
# ---------------------------------------------------------------------------
class TestSourceIntegrity(unittest.TestCase):
    """Static checks on source files for correct wiring."""

    def test_resource_enum_reads_urlscan_key(self):
        source = (REPO_ROOT / "recon" / "resource_enum.py").read_text()
        self.assertIn("URLSCAN_API_KEY = settings.get('URLSCAN_API_KEY', '')", source)

    def test_resource_enum_passes_key_to_gau(self):
        source = (REPO_ROOT / "recon" / "resource_enum.py").read_text()
        idx = source.find("futures['gau'] = executor.submit(")
        self.assertNotEqual(idx, -1, "GAU submit block not found")
        block = source[idx:idx + 500]
        self.assertIn("URLSCAN_API_KEY", block)

    def test_runtime_only_keys_includes_urlscan(self):
        source = (REPO_ROOT / "recon_orchestrator" / "api.py").read_text()
        idx = source.find("RUNTIME_ONLY_KEYS")
        self.assertNotEqual(idx, -1)
        block = source[idx:idx + 300]
        self.assertIn("'URLSCAN_API_KEY'", block)

    def test_prisma_schema_has_urlscan_field(self):
        source = (REPO_ROOT / "webapp" / "prisma" / "schema.prisma").read_text()
        self.assertIn("urlscanApiKey", source)
        self.assertIn("urlscan_api_key", source)

    def test_settings_route_handles_urlscan(self):
        source = (REPO_ROOT / "webapp" / "src" / "app" / "api" / "users" / "[id]" / "settings" / "route.ts").read_text()
        self.assertIn("urlscanApiKey", source)
        # Should appear in fields array, GET defaults, and masking
        self.assertGreater(source.count("urlscanApiKey"), 3)

    def test_settings_page_has_urlscan_field(self):
        source = (REPO_ROOT / "webapp" / "src" / "app" / "settings" / "page.tsx").read_text()
        self.assertIn("URLScan API Key", source)
        self.assertIn("urlscanApiKey", source)

    def test_settings_page_has_badges(self):
        source = (REPO_ROOT / "webapp" / "src" / "app" / "settings" / "page.tsx").read_text()
        self.assertIn("AI Agent", source)
        self.assertIn("Recon Pipeline", source)
        self.assertIn("BADGE_STYLES", source)

    def test_gau_section_has_info_note(self):
        source = (REPO_ROOT / "webapp" / "src" / "components" / "projects" / "ProjectForm" / "sections" / "GauSection.tsx").read_text()
        self.assertIn("GAU works without any API keys", source)
        self.assertIn("Settings", source)
        self.assertIn("Tool API Keys", source)


if __name__ == "__main__":
    unittest.main()
