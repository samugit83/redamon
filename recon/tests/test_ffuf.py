"""
Unit tests for FFuf directory fuzzer integration.

Tests the helper functions, merge logic, smart fuzz targeting,
and settings without making real network calls (all external tools are mocked).
"""

import sys
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ===========================================================================
# FFuf helper function tests
# ===========================================================================

def test_ffuf_build_fuzz_targets_root_only():
    """Build fuzz targets with root URLs only (no base paths)."""
    from recon.helpers.resource_enum.ffuf_helpers import _build_fuzz_targets

    targets = _build_fuzz_targets(
        ["https://example.com", "https://api.example.com"],
        None,
    )
    assert "https://example.com/FUZZ" in targets
    assert "https://api.example.com/FUZZ" in targets
    assert len(targets) == 2
    print("PASS: test_ffuf_build_fuzz_targets_root_only")


def test_ffuf_build_fuzz_targets_with_base_paths():
    """Build fuzz targets with smart base path targeting."""
    from recon.helpers.resource_enum.ffuf_helpers import _build_fuzz_targets

    targets = _build_fuzz_targets(
        ["https://example.com"],
        ["api/v1", "admin"],
    )
    assert "https://example.com/FUZZ" in targets
    assert "https://example.com/api/v1/FUZZ" in targets
    assert "https://example.com/admin/FUZZ" in targets
    assert len(targets) == 3
    print("PASS: test_ffuf_build_fuzz_targets_with_base_paths")


def test_ffuf_build_fuzz_targets_dedup():
    """Duplicate base paths should not create duplicate fuzz targets."""
    from recon.helpers.resource_enum.ffuf_helpers import _build_fuzz_targets

    targets = _build_fuzz_targets(
        ["https://example.com"],
        ["api", "api"],
    )
    api_targets = [t for t in targets if "api/FUZZ" in t]
    assert len(api_targets) == 1
    print("PASS: test_ffuf_build_fuzz_targets_dedup")


def test_ffuf_build_fuzz_targets_trailing_slash():
    """Trailing slashes on URLs and paths should be handled."""
    from recon.helpers.resource_enum.ffuf_helpers import _build_fuzz_targets

    targets = _build_fuzz_targets(
        ["https://example.com/"],
        ["/api/v1/"],
    )
    assert "https://example.com/FUZZ" in targets
    assert "https://example.com/api/v1/FUZZ" in targets
    print("PASS: test_ffuf_build_fuzz_targets_trailing_slash")


def test_ffuf_deduplicate_results():
    """Deduplicate results by URL."""
    from recon.helpers.resource_enum.ffuf_helpers import _deduplicate_results

    results = [
        {"url": "https://example.com/admin", "status": 200},
        {"url": "https://example.com/admin", "status": 200},
        {"url": "https://example.com/login", "status": 301},
    ]
    unique = _deduplicate_results(results)
    assert len(unique) == 2
    urls = [r["url"] for r in unique]
    assert "https://example.com/admin" in urls
    assert "https://example.com/login" in urls
    print("PASS: test_ffuf_deduplicate_results")


def test_ffuf_classify_endpoint():
    """Classify FFuf endpoints by path and response characteristics."""
    from recon.helpers.resource_enum.ffuf_helpers import _classify_ffuf_endpoint

    assert _classify_ffuf_endpoint("/admin/panel", 200, "") == "admin"
    assert _classify_ffuf_endpoint("/wp-admin/", 200, "") == "admin"
    assert _classify_ffuf_endpoint("/.env", 200, "") == "config"
    assert _classify_ffuf_endpoint("/config.yml", 200, "") == "config"
    assert _classify_ffuf_endpoint("/backup.bak", 200, "") == "backup"
    assert _classify_ffuf_endpoint("/db.old", 200, "") == "backup"
    assert _classify_ffuf_endpoint("/api/v1/users", 200, "") == "api"
    assert _classify_ffuf_endpoint("/data", 200, "application/json") == "api"
    assert _classify_ffuf_endpoint("/login", 200, "") == "auth"
    assert _classify_ffuf_endpoint("/secret", 301, "") == "redirect"
    assert _classify_ffuf_endpoint("/forbidden", 403, "") == "forbidden"
    assert _classify_ffuf_endpoint("/images", 200, "text/html") == "directory"
    print("PASS: test_ffuf_classify_endpoint")


def test_ffuf_run_scope_filtering():
    """FFuf results should be scope-filtered against allowed_hosts."""
    from recon.helpers.resource_enum.ffuf_helpers import run_ffuf_discovery

    ffuf_output = {
        "results": [
            {"url": "https://example.com/admin", "status": 200, "length": 100, "words": 10, "lines": 5, "content-type": "text/html", "input": {"FUZZ": "admin"}},
            {"url": "https://evil.com/steal", "status": 200, "length": 50, "words": 5, "lines": 2, "content-type": "text/html", "input": {"FUZZ": "steal"}},
            {"url": "https://example.com/.env", "status": 200, "length": 200, "words": 20, "lines": 10, "content-type": "text/plain", "input": {"FUZZ": ".env"}},
        ]
    }

    with mock.patch("subprocess.run") as mock_run, \
         mock.patch("tempfile.mkdtemp", return_value="/tmp/test_ffuf"), \
         mock.patch("shutil.rmtree"), \
         mock.patch("os.path.exists", return_value=True), \
         mock.patch("builtins.open", mock.mock_open(read_data=json.dumps(ffuf_output))):

        mock_run.return_value = mock.MagicMock(returncode=0)

        results, meta = run_ffuf_discovery(
            target_urls=["https://example.com"],
            wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt",
            threads=10, rate=0, timeout=10, max_time=60,
            match_codes=[200], filter_codes=[], filter_size="",
            extensions=[], recursion=False, recursion_depth=2,
            auto_calibrate=True, custom_headers=[],
            follow_redirects=False,
            allowed_hosts={"example.com"},
        )

    urls = [r["url"] for r in results]
    assert "https://example.com/admin" in urls
    assert "https://example.com/.env" in urls
    assert "https://evil.com/steal" not in urls

    ext_domains = [e["domain"] for e in meta["external_domains"]]
    assert "evil.com" in ext_domains
    print("PASS: test_ffuf_run_scope_filtering")


def test_ffuf_run_builds_correct_command():
    """Verify FFuf command includes all expected CLI flags."""
    from recon.helpers.resource_enum.ffuf_helpers import run_ffuf_discovery

    captured_cmd = {}

    original_run = subprocess.run
    def fake_run(cmd, **kwargs):
        captured_cmd['cmd'] = cmd
        return mock.MagicMock(returncode=0)

    with mock.patch("subprocess.run", side_effect=fake_run), \
         mock.patch("tempfile.mkdtemp", return_value="/tmp/test_ffuf"), \
         mock.patch("shutil.rmtree"), \
         mock.patch("os.path.exists", return_value=False):

        run_ffuf_discovery(
            target_urls=["https://example.com"],
            wordlist="/wordlists/common.txt",
            threads=50, rate=100, timeout=15, max_time=300,
            match_codes=[200, 301], filter_codes=[404],
            filter_size="4242",
            extensions=[".php", ".bak"],
            recursion=True, recursion_depth=3,
            auto_calibrate=True,
            custom_headers=["Cookie: test=1", "Auth: Bearer xyz"],
            follow_redirects=True,
            allowed_hosts={"example.com"},
        )

    cmd = captured_cmd['cmd']
    assert cmd[0] == "ffuf"
    assert "-u" in cmd
    assert "-w" in cmd and "/wordlists/common.txt" in cmd
    assert "-t" in cmd and "50" in cmd
    assert "-rate" in cmd and "100" in cmd
    assert "-timeout" in cmd and "15" in cmd
    assert "-maxtime" in cmd and "300" in cmd
    assert "-mc" in cmd and "200,301" in cmd
    assert "-fc" in cmd and "404" in cmd
    assert "-fs" in cmd and "4242" in cmd
    assert "-e" in cmd and ".php,.bak" in cmd
    assert "-recursion" in cmd
    assert "-recursion-depth" in cmd and "3" in cmd
    assert "-ac" in cmd
    assert "-r" in cmd
    assert "-s" in cmd
    assert "-of" in cmd and "json" in cmd

    h_indices = [i for i, v in enumerate(cmd) if v == "-H"]
    assert len(h_indices) == 2
    print("PASS: test_ffuf_run_builds_correct_command")


def test_ffuf_run_with_proxy():
    """Verify proxy flag is added when use_proxy=True."""
    from recon.helpers.resource_enum.ffuf_helpers import run_ffuf_discovery

    captured_cmd = {}

    def fake_run(cmd, **kwargs):
        captured_cmd['cmd'] = cmd
        return mock.MagicMock(returncode=0)

    with mock.patch("subprocess.run", side_effect=fake_run), \
         mock.patch("tempfile.mkdtemp", return_value="/tmp/test_ffuf"), \
         mock.patch("shutil.rmtree"), \
         mock.patch("os.path.exists", return_value=False):

        run_ffuf_discovery(
            target_urls=["https://example.com"],
            wordlist="/wordlists/common.txt",
            threads=10, rate=0, timeout=10, max_time=60,
            match_codes=[200], filter_codes=[], filter_size="",
            extensions=[], recursion=False, recursion_depth=2,
            auto_calibrate=False, custom_headers=[],
            follow_redirects=False,
            allowed_hosts={"example.com"},
            use_proxy=True,
        )

    cmd = captured_cmd['cmd']
    assert "-x" in cmd
    proxy_idx = cmd.index("-x") + 1
    assert "socks5://127.0.0.1:9050" == cmd[proxy_idx]
    print("PASS: test_ffuf_run_with_proxy")


def test_ffuf_run_timeout_handling():
    """FFuf should handle subprocess timeout gracefully."""
    from recon.helpers.resource_enum.ffuf_helpers import run_ffuf_discovery

    with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ffuf", 60)), \
         mock.patch("tempfile.mkdtemp", return_value="/tmp/test_ffuf"), \
         mock.patch("shutil.rmtree"), \
         mock.patch("os.path.exists", return_value=False):

        results, meta = run_ffuf_discovery(
            target_urls=["https://example.com"],
            wordlist="/wordlists/common.txt",
            threads=10, rate=0, timeout=10, max_time=60,
            match_codes=[200], filter_codes=[], filter_size="",
            extensions=[], recursion=False, recursion_depth=2,
            auto_calibrate=True, custom_headers=[],
            follow_redirects=False,
            allowed_hosts={"example.com"},
        )

    assert results == []
    print("PASS: test_ffuf_run_timeout_handling")


# ===========================================================================
# FFuf merge tests
# ===========================================================================

def test_ffuf_merge_new_base_url():
    """Merging FFuf results into empty existing should create base_url entry."""
    from recon.helpers.resource_enum.ffuf_helpers import merge_ffuf_into_by_base_url

    results = [
        {"url": "https://example.com/admin", "status": 200, "length": 500, "words": 50, "lines": 20, "content_type": "text/html"},
        {"url": "https://example.com/.env", "status": 200, "length": 100, "words": 10, "lines": 5, "content_type": "text/plain"},
    ]

    merged, stats = merge_ffuf_into_by_base_url(results, {})

    assert "https://example.com" in merged
    assert merged["https://example.com"]["base_url"] == "https://example.com"
    assert "/admin" in merged["https://example.com"]["endpoints"]
    assert "/.env" in merged["https://example.com"]["endpoints"]

    admin_ep = merged["https://example.com"]["endpoints"]["/admin"]
    assert admin_ep["sources"] == ["ffuf"]
    assert admin_ep["category"] == "admin"
    assert isinstance(admin_ep["methods"], list)
    assert admin_ep["methods"] == ["GET"]
    assert admin_ep["ffuf_metadata"]["status"] == 200
    assert admin_ep["ffuf_metadata"]["length"] == 500

    env_ep = merged["https://example.com"]["endpoints"]["/.env"]
    assert env_ep["category"] == "config"

    assert stats["ffuf_new"] == 2
    assert stats["ffuf_overlap"] == 0
    assert merged["https://example.com"]["summary"]["total_endpoints"] == 2
    print("PASS: test_ffuf_merge_new_base_url")


def test_ffuf_merge_overlap_adds_source():
    """Overlapping endpoint should add 'ffuf' to sources without duplicating."""
    from recon.helpers.resource_enum.ffuf_helpers import merge_ffuf_into_by_base_url

    existing = {
        "https://example.com": {
            "base_url": "https://example.com",
            "endpoints": {
                "/admin": {
                    "methods": ["GET"],
                    "sources": ["katana"],
                    "category": "admin",
                }
            },
            "summary": {"total_endpoints": 1, "total_parameters": 0, "methods": {"GET": 1}, "categories": {"admin": 1}},
        }
    }

    results = [
        {"url": "https://example.com/admin", "status": 200, "length": 500},
    ]

    merged, stats = merge_ffuf_into_by_base_url(results, existing)

    assert merged["https://example.com"]["endpoints"]["/admin"]["sources"] == ["katana", "ffuf"]
    assert stats["ffuf_overlap"] == 1
    assert stats["ffuf_new"] == 0
    print("PASS: test_ffuf_merge_overlap_adds_source")


def test_ffuf_merge_no_double_source():
    """If ffuf is already in sources, don't add again."""
    from recon.helpers.resource_enum.ffuf_helpers import merge_ffuf_into_by_base_url

    existing = {
        "https://example.com": {
            "base_url": "https://example.com",
            "endpoints": {
                "/admin": {
                    "methods": ["GET"],
                    "sources": ["katana", "ffuf"],
                    "category": "admin",
                }
            },
            "summary": {"total_endpoints": 1, "total_parameters": 0, "methods": {"GET": 1}, "categories": {"admin": 1}},
        }
    }

    results = [{"url": "https://example.com/admin", "status": 200}]

    merged, stats = merge_ffuf_into_by_base_url(results, existing)
    assert merged["https://example.com"]["endpoints"]["/admin"]["sources"] == ["katana", "ffuf"]
    assert stats["ffuf_overlap"] == 1
    print("PASS: test_ffuf_merge_no_double_source")


def test_ffuf_merge_path_normalization():
    """Trailing slashes should be stripped during merge."""
    from recon.helpers.resource_enum.ffuf_helpers import merge_ffuf_into_by_base_url

    results = [
        {"url": "https://example.com/admin/", "status": 200},
    ]

    merged, stats = merge_ffuf_into_by_base_url(results, {})

    assert "/admin" in merged["https://example.com"]["endpoints"]
    assert "/admin/" not in merged["https://example.com"]["endpoints"]
    print("PASS: test_ffuf_merge_path_normalization")


def test_ffuf_merge_summary_update():
    """Summary should be updated correctly with methods and categories."""
    from recon.helpers.resource_enum.ffuf_helpers import merge_ffuf_into_by_base_url

    results = [
        {"url": "https://example.com/admin", "status": 200, "content_type": "text/html"},
        {"url": "https://example.com/api/v1/users", "status": 200, "content_type": "application/json"},
        {"url": "https://example.com/.env", "status": 200, "content_type": "text/plain"},
    ]

    merged, stats = merge_ffuf_into_by_base_url(results, {})

    summary = merged["https://example.com"]["summary"]
    assert summary["total_endpoints"] == 3
    assert summary["methods"]["GET"] == 3
    assert summary["categories"]["admin"] == 1
    assert summary["categories"]["api"] == 1
    assert summary["categories"]["config"] == 1
    print("PASS: test_ffuf_merge_summary_update")


# ===========================================================================
# Settings tests
# ===========================================================================

def test_ffuf_default_settings_exist():
    """All FFUF_* keys should exist in DEFAULT_SETTINGS."""
    from recon.project_settings import DEFAULT_SETTINGS

    expected_keys = [
        'FFUF_ENABLED', 'FFUF_WORDLIST', 'FFUF_THREADS', 'FFUF_RATE',
        'FFUF_TIMEOUT', 'FFUF_MAX_TIME', 'FFUF_MATCH_CODES', 'FFUF_FILTER_CODES',
        'FFUF_FILTER_SIZE', 'FFUF_EXTENSIONS', 'FFUF_RECURSION',
        'FFUF_RECURSION_DEPTH', 'FFUF_AUTO_CALIBRATE', 'FFUF_FOLLOW_REDIRECTS',
        'FFUF_CUSTOM_HEADERS', 'FFUF_SMART_FUZZ',
    ]
    for key in expected_keys:
        assert key in DEFAULT_SETTINGS, f"Missing key: {key}"

    assert DEFAULT_SETTINGS['FFUF_ENABLED'] is False
    assert DEFAULT_SETTINGS['FFUF_THREADS'] == 40
    assert DEFAULT_SETTINGS['FFUF_AUTO_CALIBRATE'] is True
    assert DEFAULT_SETTINGS['FFUF_SMART_FUZZ'] is True
    assert isinstance(DEFAULT_SETTINGS['FFUF_MATCH_CODES'], list)
    assert 200 in DEFAULT_SETTINGS['FFUF_MATCH_CODES']
    print("PASS: test_ffuf_default_settings_exist")


def test_stealth_overrides_disable_ffuf():
    """Stealth mode should disable FFuf."""
    from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides
    import copy

    settings = copy.deepcopy(DEFAULT_SETTINGS)
    settings['FFUF_ENABLED'] = True
    settings['STEALTH_MODE'] = True

    result = apply_stealth_overrides(settings)

    assert result['FFUF_ENABLED'] == False, f"Expected False, got {result['FFUF_ENABLED']}"
    print("PASS: test_stealth_overrides_disable_ffuf")


def test_roe_caps_ffuf_unlimited_rate():
    """RoE should cap FFUF_RATE=0 (unlimited) to the global max RPS."""
    from recon.project_settings import fetch_project_settings

    fake_project = {
        "ffufEnabled": True,
        "ffufRate": 0,
        "roeEnabled": True,
        "roeGlobalMaxRps": 25,
    }

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_project
    mock_resp.raise_for_status = mock.MagicMock()

    with mock.patch("requests.get", return_value=mock_resp):
        settings = fetch_project_settings("test-project", "http://localhost:3000")

    assert settings['FFUF_RATE'] == 25, f"Expected 25, got {settings['FFUF_RATE']}"
    print("PASS: test_roe_caps_ffuf_unlimited_rate")


def test_settings_camelcase_mapping():
    """fetch_project_settings should map FFuf camelCase to SCREAMING_SNAKE_CASE."""
    from recon.project_settings import fetch_project_settings

    fake_project = {
        "ffufEnabled": True,
        "ffufWordlist": "/custom/wordlist.txt",
        "ffufThreads": 80,
        "ffufRate": 50,
        "ffufTimeout": 20,
        "ffufMaxTime": 1200,
        "ffufMatchCodes": [200, 403],
        "ffufFilterCodes": [404],
        "ffufFilterSize": "0",
        "ffufExtensions": [".php", ".bak"],
        "ffufRecursion": True,
        "ffufRecursionDepth": 3,
        "ffufAutoCalibrate": False,
        "ffufFollowRedirects": True,
        "ffufCustomHeaders": ["X-Custom: test"],
        "ffufSmartFuzz": False,
    }

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_project
    mock_resp.raise_for_status = mock.MagicMock()

    with mock.patch("requests.get", return_value=mock_resp):
        settings = fetch_project_settings("test-project", "http://localhost:3000")

    assert settings['FFUF_ENABLED'] is True
    assert settings['FFUF_WORDLIST'] == "/custom/wordlist.txt"
    assert settings['FFUF_THREADS'] == 80
    assert settings['FFUF_RATE'] == 50
    assert settings['FFUF_TIMEOUT'] == 20
    assert settings['FFUF_MAX_TIME'] == 1200
    assert settings['FFUF_MATCH_CODES'] == [200, 403]
    assert settings['FFUF_FILTER_CODES'] == [404]
    assert settings['FFUF_FILTER_SIZE'] == "0"
    assert settings['FFUF_EXTENSIONS'] == [".php", ".bak"]
    assert settings['FFUF_RECURSION'] is True
    assert settings['FFUF_RECURSION_DEPTH'] == 3
    assert settings['FFUF_AUTO_CALIBRATE'] is False
    assert settings['FFUF_FOLLOW_REDIRECTS'] is True
    assert settings['FFUF_CUSTOM_HEADERS'] == ["X-Custom: test"]
    assert settings['FFUF_SMART_FUZZ'] is False
    print("PASS: test_settings_camelcase_mapping")


# ===========================================================================
# Import tests
# ===========================================================================

def test_imports_resolve():
    """All new FFuf exports from __init__.py should be importable."""
    from recon.helpers.resource_enum import (
        run_ffuf_discovery,
        pull_ffuf_binary_check,
        merge_ffuf_into_by_base_url,
    )

    assert callable(run_ffuf_discovery)
    assert callable(pull_ffuf_binary_check)
    assert callable(merge_ffuf_into_by_base_url)
    print("PASS: test_imports_resolve")


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    tests = [fn for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"FAIL: {test_fn.__name__} — {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed}")
    if failed == 0:
        print("All tests passed!")
    else:
        print(f"{failed} test(s) FAILED")
        sys.exit(1)
