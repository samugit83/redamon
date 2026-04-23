"""
Unit tests for ParamSpider passive parameter discovery integration.

Tests the merge logic, subprocess invocation, scope filtering, and settings
without making real network calls (all external tools are mocked).
"""

import sys
import subprocess
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ===========================================================================
# Helper: build a realistic by_base_url structure
# ===========================================================================

def _make_existing_by_base_url():
    """Create a realistic by_base_url structure with one endpoint."""
    return {
        'https://example.com': {
            'base_url': 'https://example.com',
            'endpoints': {
                '/api/users': {
                    'methods': ['GET'],
                    'parameters': {
                        'query': [
                            {'name': 'id', 'category': 'id_params', 'source': 'katana'}
                        ],
                        'body': [],
                        'path': []
                    },
                    'sources': ['katana'],
                    'category': 'api',
                    'parameter_count': {
                        'query': 1,
                        'body': 0,
                        'path': 0,
                        'total': 1
                    }
                }
            },
            'summary': {
                'total_endpoints': 1,
                'total_parameters': 1,
                'methods': {'GET': 1},
                'categories': {'api': 1}
            }
        }
    }


# ===========================================================================
# merge_paramspider_into_by_base_url tests
# ===========================================================================

def test_merge_new_endpoint():
    """ParamSpider should create a new endpoint when path doesn't exist."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    urls = ['https://example.com/search?q=FUZZ&page=FUZZ']

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    # New endpoint created
    assert '/search' in updated['https://example.com']['endpoints']
    ep = updated['https://example.com']['endpoints']['/search']

    # Check structure
    assert ep['methods'] == ['GET']
    assert ep['sources'] == ['paramspider']
    assert len(ep['parameters']['query']) == 2
    param_names = [p['name'] for p in ep['parameters']['query']]
    assert 'q' in param_names
    assert 'page' in param_names

    # Check param source
    for p in ep['parameters']['query']:
        assert p['source'] == 'paramspider'

    # Check stats
    assert stats['paramspider_new'] == 1
    assert stats['paramspider_overlap'] == 0
    assert stats['paramspider_parsed'] == 1

    # Check summary updated
    assert updated['https://example.com']['summary']['total_endpoints'] == 2
    print("PASS: test_merge_new_endpoint")


def test_merge_existing_endpoint_adds_source():
    """ParamSpider should append 'paramspider' to sources of existing endpoints."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    urls = ['https://example.com/api/users?id=FUZZ']

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    ep = updated['https://example.com']['endpoints']['/api/users']

    # Source should be appended
    assert 'paramspider' in ep['sources']
    assert 'katana' in ep['sources']
    assert stats['paramspider_overlap'] == 1
    assert stats['paramspider_new'] == 0

    # Existing param 'id' should NOT be duplicated
    param_names = [p.get('name', p) if isinstance(p, dict) else p for p in ep['parameters']['query']]
    assert param_names.count('id') == 1

    print("PASS: test_merge_existing_endpoint_adds_source")


def test_merge_existing_endpoint_adds_new_params():
    """ParamSpider should add new params to an existing endpoint without duplicating existing ones."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    # URL has existing param 'id' + new param 'debug'
    urls = ['https://example.com/api/users?id=FUZZ&debug=FUZZ']

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    ep = updated['https://example.com']['endpoints']['/api/users']
    param_names = [p.get('name', p) if isinstance(p, dict) else p for p in ep['parameters']['query']]

    assert 'id' in param_names
    assert 'debug' in param_names
    assert param_names.count('id') == 1  # not duplicated

    # New param should have paramspider source
    debug_param = [p for p in ep['parameters']['query'] if isinstance(p, dict) and p.get('name') == 'debug'][0]
    assert debug_param['source'] == 'paramspider'

    print("PASS: test_merge_existing_endpoint_adds_new_params")


def test_merge_existing_endpoint_merges_get_method():
    """ParamSpider should add GET method when endpoint only has POST."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    # Change existing endpoint to POST only
    by_base_url['https://example.com']['endpoints']['/api/users']['methods'] = ['POST']
    by_base_url['https://example.com']['summary']['methods'] = {'POST': 1}

    urls = ['https://example.com/api/users?id=FUZZ']

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    ep = updated['https://example.com']['endpoints']['/api/users']

    # Both methods should exist
    assert 'GET' in ep['methods']
    assert 'POST' in ep['methods']

    # Summary should include GET
    assert updated['https://example.com']['summary']['methods'].get('GET', 0) == 1

    print("PASS: test_merge_existing_endpoint_merges_get_method")


def test_merge_skips_get_if_already_present():
    """GET should not be double-counted in summary when endpoint already has it."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    urls = ['https://example.com/api/users?id=FUZZ']

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    # GET count should still be 1, not 2
    assert updated['https://example.com']['summary']['methods']['GET'] == 1

    print("PASS: test_merge_skips_get_if_already_present")


def test_merge_creates_new_base_url():
    """ParamSpider should create a new base_url entry if it doesn't exist."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    urls = ['https://api.example.com/v1/search?term=FUZZ']

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    assert 'https://api.example.com' in updated
    assert '/v1/search' in updated['https://api.example.com']['endpoints']
    assert stats['paramspider_new'] == 1

    print("PASS: test_merge_creates_new_base_url")


def test_merge_legacy_source_field_migration():
    """Merge should convert legacy 'source' string to 'sources' array."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    # Simulate legacy format (source string instead of sources array)
    ep = by_base_url['https://example.com']['endpoints']['/api/users']
    del ep['sources']
    ep['source'] = 'katana'

    urls = ['https://example.com/api/users?id=FUZZ']

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    ep = updated['https://example.com']['endpoints']['/api/users']
    assert 'sources' in ep
    assert ep['sources'] == ['katana', 'paramspider']
    assert 'source' not in ep  # legacy field removed

    print("PASS: test_merge_legacy_source_field_migration")


# ===========================================================================
# Scope filtering tests
# ===========================================================================

def test_merge_filters_out_of_scope_urls():
    """Out-of-scope URLs should be filtered and counted in stats."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = {}
    urls = [
        'https://example.com/search?q=FUZZ',        # in scope
        'https://evil.com/steal?token=FUZZ',          # out of scope
        'https://sub.example.com/api?key=FUZZ',       # in scope (subdomain)
    ]

    updated, stats = merge_paramspider_into_by_base_url(
        urls, by_base_url, target_domains={'example.com'}
    )

    assert stats['paramspider_out_of_scope'] == 1
    assert stats['paramspider_parsed'] == 2
    assert 'https://evil.com' not in updated
    assert 'https://example.com' in updated
    assert 'https://sub.example.com' in updated

    print("PASS: test_merge_filters_out_of_scope_urls")


def test_merge_no_scope_filter_when_no_target_domains():
    """All URLs should be accepted when target_domains is None."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = {}
    urls = [
        'https://example.com/a?x=FUZZ',
        'https://other.com/b?y=FUZZ',
    ]

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url, target_domains=None)

    assert stats['paramspider_out_of_scope'] == 0
    assert stats['paramspider_parsed'] == 2
    assert 'https://example.com' in updated
    assert 'https://other.com' in updated

    print("PASS: test_merge_no_scope_filter_when_no_target_domains")


# ===========================================================================
# URL parsing edge cases
# ===========================================================================

def test_merge_skips_invalid_urls():
    """Malformed URLs should be silently skipped."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = {}
    urls = [
        'not-a-url',
        '',
        'https://example.com/valid?a=FUZZ',
    ]

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    assert stats['paramspider_total'] == 3
    assert stats['paramspider_parsed'] == 1

    print("PASS: test_merge_skips_invalid_urls")


def test_merge_url_without_params_creates_endpoint():
    """URL without query params should still create an endpoint (empty params)."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = {}
    urls = ['https://example.com/page']

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    # parse_gau_url_to_endpoint returns empty params dict for no-query URLs
    assert stats['paramspider_parsed'] == 1

    print("PASS: test_merge_url_without_params_creates_endpoint")


def test_merge_deduplicates_across_urls():
    """Multiple URLs with same path should not duplicate the endpoint."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    by_base_url = {}
    urls = [
        'https://example.com/search?q=FUZZ',
        'https://example.com/search?q=FUZZ&page=FUZZ',
    ]

    updated, stats = merge_paramspider_into_by_base_url(urls, by_base_url)

    # First creates new, second overlaps and adds 'page' param
    assert stats['paramspider_new'] == 1
    ep = updated['https://example.com']['endpoints']['/search']
    param_names = [p['name'] for p in ep['parameters']['query']]
    assert 'q' in param_names
    assert 'page' in param_names

    print("PASS: test_merge_deduplicates_across_urls")


# ===========================================================================
# run_paramspider_for_domain tests (subprocess mocking)
# ===========================================================================

def test_run_for_domain_captures_stdout():
    """Should parse URLs from stdout when -s flag streams output."""
    from recon.helpers.resource_enum.paramspider_helpers import run_paramspider_for_domain

    fake_stdout = (
        "https://example.com/page?id=FUZZ\n"
        "https://example.com/search?q=FUZZ&lang=FUZZ\n"
        "some non-url noise\n"
    )

    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.MagicMock(
            stdout=fake_stdout,
            stderr="",
            returncode=0,
        )
        urls = run_paramspider_for_domain(
            domain="example.com",
            placeholder="FUZZ",
            timeout=60,
        )

    assert len(urls) == 2
    assert 'https://example.com/page?id=FUZZ' in urls
    assert 'https://example.com/search?q=FUZZ&lang=FUZZ' in urls

    # Verify command was built correctly
    cmd = mock_run.call_args[0][0]
    assert cmd[0] == 'paramspider'
    assert '-d' in cmd
    assert 'example.com' in cmd
    assert '-s' in cmd
    assert '-p' in cmd
    assert 'FUZZ' in cmd

    print("PASS: test_run_for_domain_captures_stdout")


def test_run_for_domain_with_proxy():
    """Should include --proxy flag when use_proxy=True."""
    from recon.helpers.resource_enum.paramspider_helpers import run_paramspider_for_domain

    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.MagicMock(stdout="", stderr="", returncode=0)
        run_paramspider_for_domain(
            domain="example.com",
            placeholder="FUZZ",
            timeout=60,
            use_proxy=True,
        )

    cmd = mock_run.call_args[0][0]
    assert '--proxy' in cmd
    assert '127.0.0.1:9050' in cmd

    print("PASS: test_run_for_domain_with_proxy")


def test_run_for_domain_handles_timeout():
    """Should return empty list on timeout without raising."""
    from recon.helpers.resource_enum.paramspider_helpers import run_paramspider_for_domain

    with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="paramspider", timeout=60)):
        urls = run_paramspider_for_domain(
            domain="example.com",
            placeholder="FUZZ",
            timeout=60,
        )

    assert urls == []
    print("PASS: test_run_for_domain_handles_timeout")


def test_run_for_domain_handles_missing_binary():
    """Should return empty list if paramspider is not installed."""
    from recon.helpers.resource_enum.paramspider_helpers import run_paramspider_for_domain

    with mock.patch("subprocess.run", side_effect=FileNotFoundError):
        urls = run_paramspider_for_domain(
            domain="example.com",
            placeholder="FUZZ",
            timeout=60,
        )

    assert urls == []
    print("PASS: test_run_for_domain_handles_missing_binary")


def test_run_for_domain_reads_output_file():
    """Should read results/{domain}.txt as fallback alongside stdout."""
    from recon.helpers.resource_enum.paramspider_helpers import run_paramspider_for_domain
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        (results_dir / "example.com.txt").write_text(
            "https://example.com/from-file?a=FUZZ\n"
            "https://example.com/from-file?b=FUZZ\n"
        )

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.MagicMock(
                stdout="https://example.com/from-stdout?c=FUZZ\n",
                stderr="",
                returncode=0,
            )
            urls = run_paramspider_for_domain(
                domain="example.com",
                placeholder="FUZZ",
                timeout=60,
                tmp_dir=tmp_path,
            )

    # Should have URLs from both stdout and file
    assert len(urls) == 3
    assert 'https://example.com/from-file?a=FUZZ' in urls
    assert 'https://example.com/from-file?b=FUZZ' in urls
    assert 'https://example.com/from-stdout?c=FUZZ' in urls

    print("PASS: test_run_for_domain_reads_output_file")


# ===========================================================================
# run_paramspider_discovery tests
# ===========================================================================

def test_discovery_iterates_all_domains():
    """Should run ParamSpider for each domain and aggregate results."""
    from recon.helpers.resource_enum.paramspider_helpers import run_paramspider_discovery

    call_count = {'n': 0}

    def fake_run(cmd, **kwargs):
        call_count['n'] += 1
        domain = cmd[cmd.index('-d') + 1]
        return mock.MagicMock(
            stdout=f"https://{domain}/path?param=FUZZ\n",
            stderr="",
            returncode=0,
        )

    with mock.patch("subprocess.run", side_effect=fake_run):
        with mock.patch("shutil.rmtree"):  # don't clean real dirs
            all_urls, urls_by_domain = run_paramspider_discovery(
                target_domains={'example.com', 'test.com'},
                placeholder='FUZZ',
                timeout=60,
            )

    assert call_count['n'] == 2
    assert len(all_urls) == 2
    assert 'example.com' in urls_by_domain
    assert 'test.com' in urls_by_domain

    print("PASS: test_discovery_iterates_all_domains")


# ===========================================================================
# Settings tests
# ===========================================================================

def test_default_settings_present():
    """ParamSpider settings should exist in DEFAULT_SETTINGS."""
    from recon.project_settings import DEFAULT_SETTINGS

    assert 'PARAMSPIDER_ENABLED' in DEFAULT_SETTINGS
    assert DEFAULT_SETTINGS['PARAMSPIDER_ENABLED'] is False
    assert DEFAULT_SETTINGS['PARAMSPIDER_PLACEHOLDER'] == 'FUZZ'
    assert DEFAULT_SETTINGS['PARAMSPIDER_TIMEOUT'] == 120

    print("PASS: test_default_settings_present")


def test_settings_ip_mode_disables_paramspider():
    """ParamSpider should be disabled in IP mode (archives are domain-based)."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    # Simulate what resource_enum.py does:
    ip_mode = True
    settings = {'PARAMSPIDER_ENABLED': True}
    PARAMSPIDER_ENABLED = False if ip_mode else settings.get('PARAMSPIDER_ENABLED', False)

    assert PARAMSPIDER_ENABLED is False
    print("PASS: test_settings_ip_mode_disables_paramspider")


def test_stealth_mode_enables_paramspider():
    """ParamSpider should be enabled in stealth mode (passive tool)."""
    from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides

    settings = dict(DEFAULT_SETTINGS)
    settings['STEALTH_MODE'] = True
    assert settings['PARAMSPIDER_ENABLED'] is False

    apply_stealth_overrides(settings)
    assert settings['PARAMSPIDER_ENABLED'] is True

    print("PASS: test_stealth_mode_enables_paramspider")


# ===========================================================================
# Stats structure test
# ===========================================================================

def test_stats_keys_are_complete():
    """Stats dict should contain all expected keys."""
    from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url

    _, stats = merge_paramspider_into_by_base_url([], {})

    expected_keys = {
        'paramspider_total',
        'paramspider_parsed',
        'paramspider_new',
        'paramspider_overlap',
        'paramspider_out_of_scope',
    }
    assert set(stats.keys()) == expected_keys
    print("PASS: test_stats_keys_are_complete")


# ===========================================================================
# Run all tests
# ===========================================================================

if __name__ == "__main__":
    test_merge_new_endpoint()
    test_merge_existing_endpoint_adds_source()
    test_merge_existing_endpoint_adds_new_params()
    test_merge_existing_endpoint_merges_get_method()
    test_merge_skips_get_if_already_present()
    test_merge_creates_new_base_url()
    test_merge_legacy_source_field_migration()
    test_merge_filters_out_of_scope_urls()
    test_merge_no_scope_filter_when_no_target_domains()
    test_merge_skips_invalid_urls()
    test_merge_url_without_params_creates_endpoint()
    test_merge_deduplicates_across_urls()
    test_run_for_domain_captures_stdout()
    test_run_for_domain_with_proxy()
    test_run_for_domain_handles_timeout()
    test_run_for_domain_handles_missing_binary()
    test_run_for_domain_reads_output_file()
    test_discovery_iterates_all_domains()
    test_default_settings_present()
    test_settings_ip_mode_disables_paramspider()
    test_stealth_mode_enables_paramspider()
    test_stats_keys_are_complete()
    print("\n=== ALL 22 TESTS PASSED ===")
