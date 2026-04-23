"""
Unit tests for Hakrawler and jsluice integration.

Tests the helper functions, merge logic, and settings without making
real network/Docker calls (all external tools are mocked).
"""

import sys
import json
import subprocess
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ===========================================================================
# Hakrawler helpers tests
# ===========================================================================

def test_hakrawler_run_builds_correct_docker_command():
    """Verify Docker command includes all expected Hakrawler CLI flags."""
    from recon.helpers.resource_enum.hakrawler_helpers import run_hakrawler_crawler

    captured_cmd = {}

    def fake_popen(cmd, **kwargs):
        captured_cmd['cmd'] = cmd
        proc = mock.MagicMock()
        proc.stdin = mock.MagicMock()
        proc.stdout.readline.return_value = ""
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        run_hakrawler_crawler(
            target_urls=["https://example.com"],
            docker_image="jauderho/hakrawler:latest",
            depth=3,
            threads=10,
            timeout=30,
            max_urls=500,
            include_subs=True,
            insecure=True,
            allowed_hosts={"example.com"},
            custom_headers=["Cookie: test=1", "Auth: Bearer xyz"],
            exclude_patterns=[],
            use_proxy=False,
        )

    cmd = captured_cmd['cmd']
    assert "docker" in cmd[0]
    assert "jauderho/hakrawler:latest" in cmd
    assert "-d" in cmd and "3" in cmd
    assert "-t" in cmd and "10" in cmd
    assert "-timeout" in cmd and "30" in cmd
    assert "-u" in cmd
    assert "-insecure" in cmd
    assert "-subs" in cmd
    assert "-h" in cmd
    header_idx = cmd.index("-h") + 1
    assert "Cookie: test=1;;Auth: Bearer xyz" == cmd[header_idx]
    print("PASS: test_hakrawler_run_builds_correct_docker_command")


def test_hakrawler_run_with_proxy():
    """Verify proxy flags are added when use_proxy=True."""
    from recon.helpers.resource_enum.hakrawler_helpers import run_hakrawler_crawler

    captured_cmd = {}

    def fake_popen(cmd, **kwargs):
        captured_cmd['cmd'] = cmd
        proc = mock.MagicMock()
        proc.stdin = mock.MagicMock()
        proc.stdout.readline.return_value = ""
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        run_hakrawler_crawler(
            target_urls=["https://example.com"],
            docker_image="jauderho/hakrawler:latest",
            depth=2, threads=5, timeout=30, max_urls=500,
            include_subs=False, insecure=False,
            allowed_hosts={"example.com"},
            custom_headers=[], exclude_patterns=[],
            use_proxy=True,
        )

    cmd = captured_cmd['cmd']
    assert "--network" in cmd and "host" in cmd
    assert "-proxy" in cmd
    proxy_idx = cmd.index("-proxy") + 1
    assert "socks5://127.0.0.1:9050" == cmd[proxy_idx]
    print("PASS: test_hakrawler_run_with_proxy")


def test_hakrawler_run_filters_out_of_scope():
    """URLs with hosts not in allowed_hosts should be filtered."""
    from recon.helpers.resource_enum.hakrawler_helpers import run_hakrawler_crawler

    output_lines = [
        "https://example.com/page1",
        "https://evil.com/steal",
        "https://example.com/page2",
        "https://other.com/data",
        "",
    ]

    def fake_popen(cmd, **kwargs):
        proc = mock.MagicMock()
        proc.stdin = mock.MagicMock()
        proc.stdout.readline.side_effect = [line + "\n" for line in output_lines] + [""]
        proc.poll.return_value = None
        proc.wait.return_value = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        urls, meta = run_hakrawler_crawler(
            target_urls=["https://example.com"],
            docker_image="jauderho/hakrawler:latest",
            depth=2, threads=5, timeout=30, max_urls=500,
            include_subs=False, insecure=False,
            allowed_hosts={"example.com"},
            custom_headers=[], exclude_patterns=[],
        )

    assert "https://example.com/page1" in urls
    assert "https://example.com/page2" in urls
    assert "https://evil.com/steal" not in urls
    assert "https://other.com/data" not in urls
    assert len(urls) == 2

    ext_domains = [e["domain"] for e in meta["external_domains"]]
    assert "evil.com" in ext_domains
    assert "other.com" in ext_domains
    print("PASS: test_hakrawler_run_filters_out_of_scope")


def test_hakrawler_run_respects_max_urls():
    """Process should stop collecting after max_urls is reached."""
    from recon.helpers.resource_enum.hakrawler_helpers import run_hakrawler_crawler

    output_lines = [f"https://example.com/page{i}" for i in range(100)]

    def fake_popen(cmd, **kwargs):
        proc = mock.MagicMock()
        proc.stdin = mock.MagicMock()
        proc.stdout.readline.side_effect = [line + "\n" for line in output_lines] + [""]
        proc.poll.return_value = None
        proc.wait.return_value = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        urls, _ = run_hakrawler_crawler(
            target_urls=["https://example.com"],
            docker_image="jauderho/hakrawler:latest",
            depth=2, threads=5, timeout=30, max_urls=10,
            include_subs=False, insecure=False,
            allowed_hosts={"example.com"},
            custom_headers=[], exclude_patterns=[],
        )

    assert len(urls) == 10
    print("PASS: test_hakrawler_run_respects_max_urls")


def test_hakrawler_run_applies_exclude_patterns():
    """URLs matching exclude patterns should be filtered out."""
    from recon.helpers.resource_enum.hakrawler_helpers import run_hakrawler_crawler

    output_lines = [
        "https://example.com/api/data",
        "https://example.com/logout",
        "https://example.com/static/logo.png",
        "https://example.com/admin",
    ]

    def fake_popen(cmd, **kwargs):
        proc = mock.MagicMock()
        proc.stdin = mock.MagicMock()
        proc.stdout.readline.side_effect = [line + "\n" for line in output_lines] + [""]
        proc.poll.return_value = None
        proc.wait.return_value = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        urls, _ = run_hakrawler_crawler(
            target_urls=["https://example.com"],
            docker_image="jauderho/hakrawler:latest",
            depth=2, threads=5, timeout=30, max_urls=500,
            include_subs=False, insecure=False,
            allowed_hosts={"example.com"},
            custom_headers=[],
            exclude_patterns=["logout", ".png"],
        )

    assert "https://example.com/api/data" in urls
    assert "https://example.com/admin" in urls
    assert "https://example.com/logout" not in urls
    assert "https://example.com/static/logo.png" not in urls
    print("PASS: test_hakrawler_run_applies_exclude_patterns")


def test_hakrawler_stderr_is_devnull():
    """Verify stderr uses DEVNULL to prevent deadlocks."""
    from recon.helpers.resource_enum.hakrawler_helpers import run_hakrawler_crawler

    captured_kwargs = {}

    def fake_popen(cmd, **kwargs):
        captured_kwargs.update(kwargs)
        proc = mock.MagicMock()
        proc.stdin = mock.MagicMock()
        proc.stdout.readline.return_value = ""
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        run_hakrawler_crawler(
            target_urls=["https://example.com"],
            docker_image="jauderho/hakrawler:latest",
            depth=2, threads=5, timeout=30, max_urls=500,
            include_subs=False, insecure=False,
            allowed_hosts={"example.com"},
            custom_headers=[], exclude_patterns=[],
        )

    assert captured_kwargs.get('stderr') == subprocess.DEVNULL
    print("PASS: test_hakrawler_stderr_is_devnull")


# ===========================================================================
# Hakrawler merge tests
# ===========================================================================

def test_hakrawler_merge_new_base_url():
    """Merging into empty existing should create base_url entry."""
    from recon.helpers.resource_enum.hakrawler_helpers import merge_hakrawler_into_by_base_url

    hakrawler_data = {
        "https://example.com": {
            "endpoints": {
                "/api/v1": {
                    "methods": ["GET"],
                    "category": "api",
                    "parameters": {"query": [{"name": "id"}], "body": [], "path": []},
                    "parameter_count": {"query": 1, "body": 0, "path": 0, "total": 1},
                    "urls_found": 1,
                    "sample_urls": ["https://example.com/api/v1?id=1"],
                }
            }
        }
    }

    merged, stats = merge_hakrawler_into_by_base_url(hakrawler_data, {})

    assert "https://example.com" in merged
    assert merged["https://example.com"]["base_url"] == "https://example.com"
    assert "/api/v1" in merged["https://example.com"]["endpoints"]
    assert merged["https://example.com"]["endpoints"]["/api/v1"]["sources"] == ["hakrawler"]
    assert stats["hakrawler_new"] == 1
    assert stats["hakrawler_overlap"] == 0
    assert merged["https://example.com"]["summary"]["total_endpoints"] == 1
    assert merged["https://example.com"]["summary"]["total_parameters"] == 1
    assert merged["https://example.com"]["summary"]["methods"]["GET"] == 1
    print("PASS: test_hakrawler_merge_new_base_url")


def test_hakrawler_merge_overlap_adds_source():
    """Overlapping endpoint should add 'hakrawler' to sources, not duplicate."""
    from recon.helpers.resource_enum.hakrawler_helpers import merge_hakrawler_into_by_base_url

    existing = {
        "https://example.com": {
            "base_url": "https://example.com",
            "endpoints": {
                "/page": {
                    "methods": ["GET"],
                    "sources": ["katana"],
                    "category": "other",
                }
            },
            "summary": {"total_endpoints": 1, "total_parameters": 0, "methods": {"GET": 1}, "categories": {"other": 1}},
        }
    }

    hakrawler_data = {
        "https://example.com": {
            "endpoints": {
                "/page": {
                    "methods": ["GET"],
                    "category": "other",
                    "parameters": {"query": [], "body": [], "path": []},
                    "parameter_count": {"query": 0, "body": 0, "path": 0, "total": 0},
                }
            }
        }
    }

    merged, stats = merge_hakrawler_into_by_base_url(hakrawler_data, existing)

    assert merged["https://example.com"]["endpoints"]["/page"]["sources"] == ["katana", "hakrawler"]
    assert stats["hakrawler_overlap"] == 1
    assert stats["hakrawler_new"] == 0
    print("PASS: test_hakrawler_merge_overlap_adds_source")


def test_hakrawler_merge_uses_parameter_count_total():
    """Merge should use parameter_count['total'] which includes path params."""
    from recon.helpers.resource_enum.hakrawler_helpers import merge_hakrawler_into_by_base_url

    hakrawler_data = {
        "https://example.com": {
            "endpoints": {
                "/users/{id}": {
                    "methods": ["GET"],
                    "category": "api",
                    "parameters": {
                        "query": [{"name": "format"}],
                        "body": [],
                        "path": [{"name": "id"}],
                    },
                    "parameter_count": {"query": 1, "body": 0, "path": 1, "total": 2},
                    "urls_found": 1,
                    "sample_urls": ["https://example.com/users/123?format=json"],
                }
            }
        }
    }

    merged, stats = merge_hakrawler_into_by_base_url(hakrawler_data, {})

    assert merged["https://example.com"]["summary"]["total_parameters"] == 2
    print("PASS: test_hakrawler_merge_uses_parameter_count_total")


def test_hakrawler_merge_methods_list():
    """Merge should iterate all methods from endpoint['methods'] list."""
    from recon.helpers.resource_enum.hakrawler_helpers import merge_hakrawler_into_by_base_url

    hakrawler_data = {
        "https://example.com": {
            "endpoints": {
                "/form": {
                    "methods": ["GET", "POST"],
                    "category": "dynamic",
                    "parameters": {"query": [], "body": [], "path": []},
                    "parameter_count": {"query": 0, "body": 0, "path": 0, "total": 0},
                }
            }
        }
    }

    merged, _ = merge_hakrawler_into_by_base_url(hakrawler_data, {})

    methods = merged["https://example.com"]["summary"]["methods"]
    assert methods["GET"] == 1
    assert methods["POST"] == 1
    print("PASS: test_hakrawler_merge_methods_list")


# ===========================================================================
# jsluice helpers tests
# ===========================================================================

def test_jsluice_is_js_url():
    """_is_js_url should identify .js and .mjs files."""
    from recon.helpers.resource_enum.jsluice_helpers import _is_js_url

    assert _is_js_url("https://example.com/app.js") is True
    assert _is_js_url("https://example.com/module.mjs") is True
    assert _is_js_url("https://example.com/app.js?v=123") is True
    assert _is_js_url("https://example.com/style.css") is False
    assert _is_js_url("https://example.com/page.html") is False
    assert _is_js_url("https://example.com/image.png") is False
    assert _is_js_url("https://example.com/data.json") is False
    assert _is_js_url("") is False
    print("PASS: test_jsluice_is_js_url")


def test_jsluice_resolve_url():
    """_resolve_url should handle absolute, relative, and edge cases."""
    from recon.helpers.resource_enum.jsluice_helpers import _resolve_url

    base = "https://example.com"

    assert _resolve_url("https://other.com/path", base) == "https://other.com/path"
    assert _resolve_url("//cdn.example.com/lib.js", base) == "https://cdn.example.com/lib.js"
    assert _resolve_url("/api/data", base) == "https://example.com/api/data"
    assert _resolve_url("sub/page", base) == "https://example.com/sub/page"
    assert _resolve_url("EXPR", base) == ""
    assert _resolve_url("relative/EXPR/var", base) == ""
    # /-prefixed URLs are resolved before EXPR check
    assert _resolve_url("/path/with/EXPR/var", base) == "https://example.com/path/with/EXPR/var"
    print("PASS: test_jsluice_resolve_url")


def test_jsluice_run_skips_when_no_binary():
    """run_jsluice_analysis should return empty result if jsluice not in PATH."""
    from recon.helpers.resource_enum.jsluice_helpers import run_jsluice_analysis

    with mock.patch("shutil.which", return_value=None):
        result = run_jsluice_analysis(
            discovered_urls=["https://example.com/app.js"],
            max_files=10, timeout=60,
            extract_urls=True, extract_secrets=True,
            concurrency=5, allowed_hosts={"example.com"},
        )

    assert result == {"urls": [], "secrets": [], "external_domains": []}
    print("PASS: test_jsluice_run_skips_when_no_binary")


def test_jsluice_run_skips_when_no_js_files():
    """run_jsluice_analysis should return empty if no .js URLs found."""
    from recon.helpers.resource_enum.jsluice_helpers import run_jsluice_analysis

    with mock.patch("shutil.which", return_value="/usr/local/bin/jsluice"):
        result = run_jsluice_analysis(
            discovered_urls=[
                "https://example.com/page.html",
                "https://example.com/style.css",
            ],
            max_files=10, timeout=60,
            extract_urls=True, extract_secrets=True,
            concurrency=5, allowed_hosts={"example.com"},
        )

    assert result == {"urls": [], "secrets": [], "external_domains": []}
    print("PASS: test_jsluice_run_skips_when_no_js_files")


def test_jsluice_run_filters_scope_and_cleans_up():
    """run_jsluice_analysis should scope-filter extracted URLs and clean /tmp."""
    from recon.helpers.resource_enum.jsluice_helpers import run_jsluice_analysis

    jsluice_output = "\n".join([
        json.dumps({"url": "https://example.com/api/v1/users"}),
        json.dumps({"url": "https://evil.com/exfil"}),
        json.dumps({"url": "/api/v2/data"}),
        "",
    ])

    with mock.patch("shutil.which", return_value="/usr/local/bin/jsluice"), \
         mock.patch("recon.helpers.resource_enum.jsluice_helpers._download_js_files") as mock_dl, \
         mock.patch("subprocess.run") as mock_run, \
         mock.patch("shutil.rmtree") as mock_rmtree:

        mock_dl.return_value = {"https://example.com/app.js": "/tmp/test/js_0.js"}
        mock_run.return_value = mock.MagicMock(stdout=jsluice_output, returncode=0)

        result = run_jsluice_analysis(
            discovered_urls=["https://example.com/app.js"],
            max_files=10, timeout=60,
            extract_urls=True, extract_secrets=False,
            concurrency=5, allowed_hosts={"example.com"},
        )

    assert "https://example.com/api/v1/users" in result["urls"]
    assert "https://example.com/api/v2/data" in result["urls"]
    assert "https://evil.com/exfil" not in result["urls"]

    ext = [e["domain"] for e in result["external_domains"]]
    assert "evil.com" in ext

    mock_rmtree.assert_called_once()
    print("PASS: test_jsluice_run_filters_scope_and_cleans_up")


# ===========================================================================
# jsluice merge tests
# ===========================================================================

def test_jsluice_merge_endpoint_structure():
    """Verify merged jsluice endpoints match the canonical structure."""
    from recon.helpers.resource_enum.jsluice_helpers import merge_jsluice_into_by_base_url

    urls = ["https://example.com/api/search?q=test&page=1"]
    merged, stats = merge_jsluice_into_by_base_url(urls, {})

    assert stats["jsluice_new"] == 1
    assert stats["jsluice_overlap"] == 0

    base = merged["https://example.com"]
    assert base["base_url"] == "https://example.com"

    ep = base["endpoints"]["/api/search"]

    # methods is a LIST
    assert isinstance(ep["methods"], list)
    assert ep["methods"] == ["GET"]

    # parameter_count has all four keys
    assert ep["parameter_count"]["query"] == 2
    assert ep["parameter_count"]["body"] == 0
    assert ep["parameter_count"]["path"] == 0
    assert ep["parameter_count"]["total"] == 2

    # urls_found is an INTEGER
    assert isinstance(ep["urls_found"], int)
    assert ep["urls_found"] == 1

    # sample_urls is a LIST
    assert isinstance(ep["sample_urls"], list)

    # parameters has query, body, path keys
    assert "query" in ep["parameters"]
    assert "body" in ep["parameters"]
    assert "path" in ep["parameters"]

    # params use 'category' not 'classification'
    for param in ep["parameters"]["query"]:
        assert "category" in param
        assert "classification" not in param
        assert "sample_values" in param
        assert "type" in param

    # category is set on the endpoint
    assert "category" in ep
    assert ep["sources"] == ["jsluice"]

    print("PASS: test_jsluice_merge_endpoint_structure")


def test_jsluice_merge_overlap_adds_source():
    """Overlapping paths should add 'jsluice' to sources without duplicating."""
    from recon.helpers.resource_enum.jsluice_helpers import merge_jsluice_into_by_base_url

    existing = {
        "https://example.com": {
            "base_url": "https://example.com",
            "endpoints": {
                "/api/data": {
                    "methods": ["GET"],
                    "sources": ["katana"],
                    "category": "api",
                }
            },
            "summary": {"total_endpoints": 1, "total_parameters": 0, "methods": {"GET": 1}, "categories": {"api": 1}},
        }
    }

    urls = ["https://example.com/api/data"]
    merged, stats = merge_jsluice_into_by_base_url(urls, existing)

    assert merged["https://example.com"]["endpoints"]["/api/data"]["sources"] == ["katana", "jsluice"]
    assert stats["jsluice_overlap"] == 1
    assert stats["jsluice_new"] == 0
    print("PASS: test_jsluice_merge_overlap_adds_source")


def test_jsluice_merge_no_double_source():
    """If jsluice is already in sources, don't add again."""
    from recon.helpers.resource_enum.jsluice_helpers import merge_jsluice_into_by_base_url

    existing = {
        "https://example.com": {
            "base_url": "https://example.com",
            "endpoints": {
                "/page": {
                    "methods": ["GET"],
                    "sources": ["katana", "jsluice"],
                    "category": "other",
                }
            },
            "summary": {"total_endpoints": 1, "total_parameters": 0, "methods": {"GET": 1}, "categories": {"other": 1}},
        }
    }

    urls = ["https://example.com/page"]
    merged, stats = merge_jsluice_into_by_base_url(urls, existing)

    assert merged["https://example.com"]["endpoints"]["/page"]["sources"] == ["katana", "jsluice"]
    assert stats["jsluice_overlap"] == 1
    print("PASS: test_jsluice_merge_no_double_source")


def test_jsluice_merge_summary_update():
    """Summary should be updated correctly with methods, categories, params."""
    from recon.helpers.resource_enum.jsluice_helpers import merge_jsluice_into_by_base_url

    urls = [
        "https://example.com/api/users?id=1",
        "https://example.com/api/search?q=test&limit=10",
    ]
    merged, stats = merge_jsluice_into_by_base_url(urls, {})

    summary = merged["https://example.com"]["summary"]
    assert summary["total_endpoints"] == 2
    assert summary["total_parameters"] == 3  # id + q + limit
    assert summary["methods"]["GET"] == 2
    print("PASS: test_jsluice_merge_summary_update")


# ===========================================================================
# Settings tests
# ===========================================================================

def test_hakrawler_default_settings_exist():
    """All HAKRAWLER_* keys should exist in DEFAULT_SETTINGS."""
    from recon.project_settings import DEFAULT_SETTINGS

    expected_keys = [
        'HAKRAWLER_ENABLED', 'HAKRAWLER_DOCKER_IMAGE', 'HAKRAWLER_DEPTH',
        'HAKRAWLER_THREADS', 'HAKRAWLER_TIMEOUT', 'HAKRAWLER_MAX_URLS',
        'HAKRAWLER_INCLUDE_SUBS', 'HAKRAWLER_INSECURE', 'HAKRAWLER_CUSTOM_HEADERS',
    ]
    for key in expected_keys:
        assert key in DEFAULT_SETTINGS, f"Missing key: {key}"

    assert DEFAULT_SETTINGS['HAKRAWLER_ENABLED'] is True
    assert DEFAULT_SETTINGS['HAKRAWLER_DOCKER_IMAGE'] == 'jauderho/hakrawler:latest'
    assert isinstance(DEFAULT_SETTINGS['HAKRAWLER_CUSTOM_HEADERS'], list)
    print("PASS: test_hakrawler_default_settings_exist")


def test_jsluice_default_settings_exist():
    """All JSLUICE_* keys should exist in DEFAULT_SETTINGS."""
    from recon.project_settings import DEFAULT_SETTINGS

    expected_keys = [
        'JSLUICE_ENABLED', 'JSLUICE_MAX_FILES', 'JSLUICE_TIMEOUT',
        'JSLUICE_EXTRACT_URLS', 'JSLUICE_EXTRACT_SECRETS', 'JSLUICE_CONCURRENCY',
    ]
    for key in expected_keys:
        assert key in DEFAULT_SETTINGS, f"Missing key: {key}"

    assert DEFAULT_SETTINGS['JSLUICE_ENABLED'] is True
    assert DEFAULT_SETTINGS['JSLUICE_MAX_FILES'] == 100
    assert DEFAULT_SETTINGS['JSLUICE_CONCURRENCY'] == 5
    print("PASS: test_jsluice_default_settings_exist")


def test_stealth_overrides_disable_hakrawler():
    """Stealth mode should disable Hakrawler and reduce jsluice max files."""
    from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides
    import copy

    settings = copy.deepcopy(DEFAULT_SETTINGS)
    settings['HAKRAWLER_ENABLED'] = True
    settings['JSLUICE_MAX_FILES'] = 100
    settings['STEALTH_MODE'] = True

    result = apply_stealth_overrides(settings)

    assert result['HAKRAWLER_ENABLED'] == False, f"Expected False, got {result['HAKRAWLER_ENABLED']}"
    assert result['JSLUICE_MAX_FILES'] == 20, f"Expected 20, got {result['JSLUICE_MAX_FILES']}"
    print("PASS: test_stealth_overrides_disable_hakrawler")


def test_settings_camelcase_mapping():
    """fetch_project_settings should map camelCase to SCREAMING_SNAKE_CASE."""
    from recon.project_settings import fetch_project_settings

    fake_project = {
        "hakrawlerEnabled": True,
        "hakrawlerDepth": 5,
        "hakrawlerThreads": 10,
        "hakrawlerTimeout": 60,
        "hakrawlerMaxUrls": 1000,
        "hakrawlerIncludeSubs": True,
        "hakrawlerInsecure": False,
        "hakrawlerDockerImage": "custom:latest",
        "hakrawlerCustomHeaders": ["X-Custom: test"],
        "jsluiceEnabled": False,
        "jsluiceMaxFiles": 50,
        "jsluiceTimeout": 120,
        "jsluiceExtractUrls": False,
        "jsluiceExtractSecrets": True,
        "jsluiceConcurrency": 10,
    }

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_project
    mock_resp.raise_for_status = mock.MagicMock()

    with mock.patch("requests.get", return_value=mock_resp):
        settings = fetch_project_settings("test-project", "http://localhost:3000")

    assert settings['HAKRAWLER_ENABLED'] is True
    assert settings['HAKRAWLER_DEPTH'] == 5
    assert settings['HAKRAWLER_THREADS'] == 10
    assert settings['HAKRAWLER_TIMEOUT'] == 60
    assert settings['HAKRAWLER_MAX_URLS'] == 1000
    assert settings['HAKRAWLER_INCLUDE_SUBS'] is True
    assert settings['HAKRAWLER_INSECURE'] is False
    assert settings['HAKRAWLER_DOCKER_IMAGE'] == "custom:latest"
    assert settings['HAKRAWLER_CUSTOM_HEADERS'] == ["X-Custom: test"]

    assert settings['JSLUICE_ENABLED'] is False
    assert settings['JSLUICE_MAX_FILES'] == 50
    assert settings['JSLUICE_TIMEOUT'] == 120
    assert settings['JSLUICE_EXTRACT_URLS'] is False
    assert settings['JSLUICE_EXTRACT_SECRETS'] is True
    assert settings['JSLUICE_CONCURRENCY'] == 10
    print("PASS: test_settings_camelcase_mapping")


# ===========================================================================
# __init__.py import tests
# ===========================================================================

def test_imports_resolve():
    """All new exports from __init__.py should be importable."""
    from recon.helpers.resource_enum import (
        run_hakrawler_crawler,
        pull_hakrawler_docker_image,
        merge_hakrawler_into_by_base_url,
        run_jsluice_analysis,
        merge_jsluice_into_by_base_url,
    )

    assert callable(run_hakrawler_crawler)
    assert callable(pull_hakrawler_docker_image)
    assert callable(merge_hakrawler_into_by_base_url)
    assert callable(run_jsluice_analysis)
    assert callable(merge_jsluice_into_by_base_url)
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
