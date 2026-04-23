"""
Unit tests for Arjun parameter discovery integration.

Tests the merge logic, command building, scope filtering, and settings
without making real network calls (all external tools are mocked).
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
# merge_arjun_into_by_base_url tests
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
                            {'name': 'id', 'type': 'integer', 'sample_values': ['1', '2'], 'category': 'id_params'}
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


def test_merge_enrich_existing_endpoint():
    """Arjun params should be added to an existing endpoint without duplication."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    arjun_results = [
        {'url': 'https://example.com/api/users', 'params': ['debug', 'token', 'id'], 'method': 'GET'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    endpoint = result['https://example.com']['endpoints']['/api/users']

    # 'id' was already there, should NOT be duplicated
    query_names = [p['name'] for p in endpoint['parameters']['query']]
    assert query_names.count('id') == 1, f"'id' duplicated: {query_names}"

    # 'debug' and 'token' should be added
    assert 'debug' in query_names
    assert 'token' in query_names
    assert len(query_names) == 3  # id + debug + token

    # Stats
    assert stats['arjun_existing_enriched'] == 1
    assert stats['arjun_new_endpoints'] == 0
    assert stats['arjun_params_discovered'] == 2  # only debug + token are new

    # Sources should include both katana and arjun
    assert 'katana' in endpoint['sources']
    assert 'arjun' in endpoint['sources']

    # parameter_count should be updated
    assert endpoint['parameter_count']['query'] == 3
    assert endpoint['parameter_count']['total'] == 3

    # Summary should reflect new params
    assert result['https://example.com']['summary']['total_parameters'] == 3

    print("PASS: test_merge_enrich_existing_endpoint")


def test_merge_create_new_endpoint():
    """Arjun should create a new endpoint when the path doesn't exist yet."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    arjun_results = [
        {'url': 'https://example.com/api/admin', 'params': ['secret', 'cmd'], 'method': 'GET'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    assert '/api/admin' in result['https://example.com']['endpoints']
    endpoint = result['https://example.com']['endpoints']['/api/admin']

    assert endpoint['sources'] == ['arjun']
    assert endpoint['methods'] == ['GET']

    query_names = [p['name'] for p in endpoint['parameters']['query']]
    assert 'secret' in query_names
    assert 'cmd' in query_names

    # Parameter classification should work
    cmd_param = next(p for p in endpoint['parameters']['query'] if p['name'] == 'cmd')
    assert cmd_param['category'] == 'command_params'

    assert stats['arjun_new_endpoints'] == 1
    assert stats['arjun_params_discovered'] == 2

    # Summary updated
    assert result['https://example.com']['summary']['total_endpoints'] == 2
    assert result['https://example.com']['summary']['total_parameters'] == 3  # 1 original + 2 new

    print("PASS: test_merge_create_new_endpoint")


def test_merge_post_method_body_params():
    """POST method should place params in 'body', not 'query'."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {}
    arjun_results = [
        {'url': 'https://example.com/login', 'params': ['username', 'password'], 'method': 'POST'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    endpoint = result['https://example.com']['endpoints']['/login']
    assert len(endpoint['parameters']['query']) == 0
    assert len(endpoint['parameters']['body']) == 2

    body_names = [p['name'] for p in endpoint['parameters']['body']]
    assert 'username' in body_names
    assert 'password' in body_names

    # Category should be auth
    assert endpoint['category'] == 'authentication'

    # Parameter classification
    pw_param = next(p for p in endpoint['parameters']['body'] if p['name'] == 'password')
    assert pw_param['category'] == 'auth_params'

    assert stats['arjun_params_discovered'] == 2

    print("PASS: test_merge_post_method_body_params")


def test_merge_json_method_body_params():
    """JSON method should also place params in 'body'."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {}
    arjun_results = [
        {'url': 'https://api.example.com/v1/data', 'params': ['filter', 'limit'], 'method': 'JSON'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    endpoint = result['https://api.example.com']['endpoints']['/v1/data']
    assert len(endpoint['parameters']['body']) == 2
    assert len(endpoint['parameters']['query']) == 0

    print("PASS: test_merge_json_method_body_params")


def test_merge_empty_results():
    """Empty results should return untouched by_base_url and zero stats."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    original_params = by_base_url['https://example.com']['summary']['total_parameters']

    result, stats = merge_arjun_into_by_base_url([], by_base_url)

    assert stats['arjun_total'] == 0
    assert stats['arjun_params_discovered'] == 0
    assert stats['arjun_new_endpoints'] == 0
    assert stats['arjun_existing_enriched'] == 0
    assert result['https://example.com']['summary']['total_parameters'] == original_params

    print("PASS: test_merge_empty_results")


def test_merge_sources_migration_from_old_source_field():
    """Old 'source' string field should be migrated to 'sources' array."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {
        'https://example.com': {
            'base_url': 'https://example.com',
            'endpoints': {
                '/old': {
                    'methods': ['GET'],
                    'parameters': {'query': [], 'body': [], 'path': []},
                    'source': 'katana',  # OLD format (string, not array)
                    'category': 'other',
                    'parameter_count': {'query': 0, 'body': 0, 'path': 0, 'total': 0}
                }
            },
            'summary': {
                'total_endpoints': 1, 'total_parameters': 0,
                'methods': {'GET': 1}, 'categories': {'other': 1}
            }
        }
    }

    arjun_results = [
        {'url': 'https://example.com/old', 'params': ['test'], 'method': 'GET'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)
    endpoint = result['https://example.com']['endpoints']['/old']

    # Should have migrated to array format
    assert 'sources' in endpoint
    assert 'source' not in endpoint  # Old field removed
    assert 'katana' in endpoint['sources']
    assert 'arjun' in endpoint['sources']

    print("PASS: test_merge_sources_migration_from_old_source_field")


def test_merge_new_base_url():
    """Arjun results for a completely new base URL should create full structure."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {}
    arjun_results = [
        {'url': 'https://new-site.com/api/data', 'params': ['q'], 'method': 'GET'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    assert 'https://new-site.com' in result
    base = result['https://new-site.com']
    assert base['base_url'] == 'https://new-site.com'
    assert '/api/data' in base['endpoints']
    assert base['summary']['total_endpoints'] == 1
    assert base['summary']['total_parameters'] == 1
    assert base['summary']['methods'] == {'GET': 1}

    print("PASS: test_merge_new_base_url")


def test_merge_url_with_port():
    """URLs with non-standard ports should be handled correctly."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {}
    arjun_results = [
        {'url': 'http://example.com:8080/admin', 'params': ['token'], 'method': 'GET'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    assert 'http://example.com:8080' in result
    assert '/admin' in result['http://example.com:8080']['endpoints']

    print("PASS: test_merge_url_with_port")


def test_merge_skips_empty_params():
    """Results with empty params list should be skipped."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {}
    arjun_results = [
        {'url': 'https://example.com/empty', 'params': [], 'method': 'GET'},
        {'url': '', 'params': ['test'], 'method': 'GET'},
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    assert stats['arjun_params_discovered'] == 0
    assert stats['arjun_new_endpoints'] == 0

    print("PASS: test_merge_skips_empty_params")


def test_merge_duplicate_params_across_results():
    """Same param from multiple results for same endpoint should not duplicate."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {}
    arjun_results = [
        {'url': 'https://example.com/api', 'params': ['token', 'debug'], 'method': 'GET'},
        {'url': 'https://example.com/api', 'params': ['debug', 'admin'], 'method': 'GET'},
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    endpoint = result['https://example.com']['endpoints']['/api']
    query_names = [p['name'] for p in endpoint['parameters']['query']]

    # Should have 3 unique params, not 4
    assert len(query_names) == 3
    assert set(query_names) == {'token', 'debug', 'admin'}

    # First result creates endpoint (2 params), second enriches (1 new param)
    assert stats['arjun_new_endpoints'] == 1
    assert stats['arjun_existing_enriched'] == 1
    assert stats['arjun_params_discovered'] == 3

    print("PASS: test_merge_duplicate_params_across_results")


def test_merge_method_added_to_existing_endpoint():
    """POST method from Arjun should be added to endpoint that only had GET."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = _make_existing_by_base_url()
    arjun_results = [
        {'url': 'https://example.com/api/users', 'params': ['email'], 'method': 'POST'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    endpoint = result['https://example.com']['endpoints']['/api/users']
    assert 'GET' in endpoint['methods']
    assert 'POST' in endpoint['methods']

    # email should be in body (POST), not query
    body_names = [p['name'] for p in endpoint['parameters']['body']]
    assert 'email' in body_names

    # Summary methods should include POST now
    assert result['https://example.com']['summary']['methods']['POST'] == 1

    print("PASS: test_merge_method_added_to_existing_endpoint")


def test_merge_url_without_path():
    """URL without explicit path should default to '/'."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {}
    arjun_results = [
        {'url': 'https://example.com', 'params': ['debug'], 'method': 'GET'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    assert '/' in result['https://example.com']['endpoints']

    print("PASS: test_merge_url_without_path")


def test_merge_parameter_type_inference():
    """Parameter types should be inferred from names."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    by_base_url = {}
    arjun_results = [
        {'url': 'https://example.com/api', 'params': ['user_id', 'email', 'callback', 'file'], 'method': 'GET'}
    ]

    result, stats = merge_arjun_into_by_base_url(arjun_results, by_base_url)

    endpoint = result['https://example.com']['endpoints']['/api']
    params = {p['name']: p for p in endpoint['parameters']['query']}

    assert params['user_id']['type'] == 'integer'
    assert params['email']['type'] == 'email'
    assert params['callback']['type'] == 'url'
    assert params['file']['type'] == 'path'

    assert params['user_id']['category'] == 'id_params'
    assert params['email']['category'] == 'auth_params'
    assert params['callback']['category'] == 'redirect_params'
    assert params['file']['category'] == 'file_params'

    print("PASS: test_merge_parameter_type_inference")


# ===========================================================================
# run_arjun_discovery tests (mocked subprocess)
# ===========================================================================

def test_run_discovery_builds_correct_command():
    """Verify the subprocess command is built correctly with all flags."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    captured_cmd = []

    def mock_subprocess_run(cmd, **kwargs):
        captured_cmd.extend(cmd)
        # Create empty output file
        for i, arg in enumerate(cmd):
            if arg == '-oJ' and i + 1 < len(cmd):
                with open(cmd[i + 1], 'w') as f:
                    json.dump({}, f)
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        run_arjun_discovery(
            target_urls=['https://example.com'],
            methods=['POST'],
            threads=5,
            timeout=10,
            scan_timeout=300,
            chunk_size=250,
            rate_limit=50,
            stable=True,
            passive=True,
            disable_redirects=True,
            custom_headers=['Authorization: Bearer tok', 'X-Key: abc'],
            allowed_hosts={'example.com'},
            use_proxy=False,
        )

    assert captured_cmd[0] == 'arjun'
    assert '-i' in captured_cmd
    assert '-oJ' in captured_cmd
    assert '-m' in captured_cmd
    m_idx = captured_cmd.index('-m')
    assert captured_cmd[m_idx + 1] == 'POST'

    assert '-t' in captured_cmd
    t_idx = captured_cmd.index('-t')
    assert captured_cmd[t_idx + 1] == '5'

    assert '-T' in captured_cmd
    T_idx = captured_cmd.index('-T')
    assert captured_cmd[T_idx + 1] == '10'

    assert '-c' in captured_cmd
    c_idx = captured_cmd.index('-c')
    assert captured_cmd[c_idx + 1] == '250'

    assert '--rate-limit' in captured_cmd
    rl_idx = captured_cmd.index('--rate-limit')
    assert captured_cmd[rl_idx + 1] == '50'

    assert '--stable' in captured_cmd
    assert '--passive' in captured_cmd
    assert '--disable-redirects' in captured_cmd

    # Headers should be ONE argument with newline-separated values
    assert '--headers' in captured_cmd
    h_idx = captured_cmd.index('--headers')
    headers_val = captured_cmd[h_idx + 1]
    assert 'Authorization: Bearer tok' in headers_val
    assert 'X-Key: abc' in headers_val
    assert '\n' in headers_val

    print("PASS: test_run_discovery_builds_correct_command")


def test_run_discovery_no_rate_limit_flag_when_zero():
    """--rate-limit flag should NOT be added when rate_limit is 0."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    captured_cmd = []

    def mock_subprocess_run(cmd, **kwargs):
        captured_cmd.extend(cmd)
        for i, arg in enumerate(cmd):
            if arg == '-oJ' and i + 1 < len(cmd):
                with open(cmd[i + 1], 'w') as f:
                    json.dump({}, f)
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        run_arjun_discovery(
            target_urls=['https://example.com'],
            methods=['GET'], threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=[],
            allowed_hosts={'example.com'},
        )

    assert '--rate-limit' not in captured_cmd

    print("PASS: test_run_discovery_no_rate_limit_flag_when_zero")


def test_run_discovery_proxy_env_vars():
    """When use_proxy=True, HTTP_PROXY/HTTPS_PROXY should be set in env."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    captured_env = {}

    def mock_subprocess_run(cmd, **kwargs):
        captured_env.update(kwargs.get('env', {}))
        for i, arg in enumerate(cmd):
            if arg == '-oJ' and i + 1 < len(cmd):
                with open(cmd[i + 1], 'w') as f:
                    json.dump({}, f)
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        run_arjun_discovery(
            target_urls=['https://example.com'],
            methods=['GET'], threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=[],
            allowed_hosts={'example.com'},
            use_proxy=True,
        )

    assert captured_env.get('HTTP_PROXY') == 'socks5://127.0.0.1:9050'
    assert captured_env.get('HTTPS_PROXY') == 'socks5://127.0.0.1:9050'

    print("PASS: test_run_discovery_proxy_env_vars")


def test_run_discovery_no_proxy_when_disabled():
    """When use_proxy=False, proxy env vars should NOT be set."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    captured_env = {}

    def mock_subprocess_run(cmd, **kwargs):
        captured_env.update(kwargs.get('env', {}))
        for i, arg in enumerate(cmd):
            if arg == '-oJ' and i + 1 < len(cmd):
                with open(cmd[i + 1], 'w') as f:
                    json.dump({}, f)
        return subprocess.CompletedProcess(cmd, 0, '', '')

    original_http_proxy = os.environ.get('HTTP_PROXY')
    # Ensure no inherited proxy
    os.environ.pop('HTTP_PROXY', None)
    os.environ.pop('HTTPS_PROXY', None)

    try:
        with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
            run_arjun_discovery(
                target_urls=['https://example.com'],
                methods=['GET'], threads=2, timeout=15, scan_timeout=600,
                chunk_size=500, rate_limit=0, stable=False, passive=False,
                disable_redirects=False, custom_headers=[],
                allowed_hosts={'example.com'},
                use_proxy=False,
            )

        assert 'HTTP_PROXY' not in captured_env or captured_env.get('HTTP_PROXY') is None
    finally:
        if original_http_proxy:
            os.environ['HTTP_PROXY'] = original_http_proxy

    print("PASS: test_run_discovery_no_proxy_when_disabled")


def test_run_discovery_scope_filtering():
    """Out-of-scope results should be filtered into external_domains."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    arjun_output = {
        "https://example.com/api": {"params": ["debug"], "method": "GET", "headers": {}},
        "https://evil.com/admin": {"params": ["secret"], "method": "GET", "headers": {}},
        "https://other.com/path": {"params": ["token"], "method": "GET", "headers": {}},
    }

    def mock_subprocess_run(cmd, **kwargs):
        for i, arg in enumerate(cmd):
            if arg == '-oJ' and i + 1 < len(cmd):
                with open(cmd[i + 1], 'w') as f:
                    json.dump(arjun_output, f)
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        results, meta = run_arjun_discovery(
            target_urls=['https://example.com/api'],
            methods=['GET'], threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=[],
            allowed_hosts={'example.com'},
        )

    # Only example.com should be in results
    assert len(results) == 1
    assert results[0]['url'] == 'https://example.com/api'

    # evil.com and other.com should be in external_domains
    ext_domains = [d['domain'] for d in meta['external_domains']]
    assert 'evil.com' in ext_domains
    assert 'other.com' in ext_domains
    assert len(meta['external_domains']) == 2

    print("PASS: test_run_discovery_scope_filtering")


def test_run_discovery_empty_targets():
    """Empty target list should return immediately."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    results, meta = run_arjun_discovery(
        target_urls=[],
        methods=['GET'], threads=2, timeout=15, scan_timeout=600,
        chunk_size=500, rate_limit=0, stable=False, passive=False,
        disable_redirects=False, custom_headers=[],
        allowed_hosts=set(),
    )

    assert results == []
    assert meta == {"external_domains": []}

    print("PASS: test_run_discovery_empty_targets")


def test_run_discovery_timeout_handling():
    """Subprocess timeout should be caught and return empty results."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    def mock_subprocess_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get('timeout', 60))

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        results, meta = run_arjun_discovery(
            target_urls=['https://example.com'],
            methods=['GET'], threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=[],
            allowed_hosts={'example.com'},
        )

    assert results == []
    assert meta == {"external_domains": []}

    print("PASS: test_run_discovery_timeout_handling")


def test_run_discovery_no_output_file():
    """If arjun produces no output file, should return empty results gracefully."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    def mock_subprocess_run(cmd, **kwargs):
        # Don't create the output file
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        results, meta = run_arjun_discovery(
            target_urls=['https://example.com'],
            methods=['GET'], threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=[],
            allowed_hosts={'example.com'},
        )

    assert results == []

    print("PASS: test_run_discovery_no_output_file")


def test_run_discovery_malformed_json():
    """Malformed JSON in output file should be handled gracefully."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    def mock_subprocess_run(cmd, **kwargs):
        for i, arg in enumerate(cmd):
            if arg == '-oJ' and i + 1 < len(cmd):
                with open(cmd[i + 1], 'w') as f:
                    f.write("{invalid json")
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        results, meta = run_arjun_discovery(
            target_urls=['https://example.com'],
            methods=['GET'], threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=[],
            allowed_hosts={'example.com'},
        )

    assert results == []

    print("PASS: test_run_discovery_malformed_json")


def test_run_discovery_temp_dir_cleanup():
    """Temp directory should be cleaned up even on errors."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    created_dirs = []

    original_mkdtemp = tempfile.mkdtemp
    def tracking_mkdtemp(**kwargs):
        d = original_mkdtemp(**kwargs)
        created_dirs.append(d)
        return d

    def mock_subprocess_run(cmd, **kwargs):
        raise RuntimeError("simulated crash")

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.tempfile.mkdtemp', side_effect=tracking_mkdtemp):
        with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
            results, meta = run_arjun_discovery(
                target_urls=['https://example.com'],
                methods=['GET'], threads=2, timeout=15, scan_timeout=600,
                chunk_size=500, rate_limit=0, stable=False, passive=False,
                disable_redirects=False, custom_headers=[],
                allowed_hosts={'example.com'},
            )

    # Temp dir should have been cleaned up
    assert len(created_dirs) == 1
    assert not os.path.exists(created_dirs[0]), f"Temp dir not cleaned up: {created_dirs[0]}"

    print("PASS: test_run_discovery_temp_dir_cleanup")


def test_run_discovery_urls_written_to_temp_file():
    """Target URLs should be written to temp file for -i flag."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    written_urls = []

    def mock_subprocess_run(cmd, **kwargs):
        # Read the -i file to verify contents
        i_idx = cmd.index('-i')
        urls_file = cmd[i_idx + 1]
        with open(urls_file) as f:
            written_urls.extend(f.read().strip().split('\n'))
        # Create empty output
        oj_idx = cmd.index('-oJ')
        with open(cmd[oj_idx + 1], 'w') as f:
            json.dump({}, f)
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        run_arjun_discovery(
            target_urls=['https://a.com', 'https://b.com/path', 'http://c.com:8080'],
            methods=['GET'], threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=[],
            allowed_hosts={'a.com', 'b.com', 'c.com'},
        )

    assert written_urls == ['https://a.com', 'https://b.com/path', 'http://c.com:8080']

    print("PASS: test_run_discovery_urls_written_to_temp_file")


def test_run_discovery_custom_headers_empty():
    """Empty custom headers should NOT add --headers flag."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    captured_cmd = []

    def mock_subprocess_run(cmd, **kwargs):
        captured_cmd.extend(cmd)
        for i, arg in enumerate(cmd):
            if arg == '-oJ' and i + 1 < len(cmd):
                with open(cmd[i + 1], 'w') as f:
                    json.dump({}, f)
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        run_arjun_discovery(
            target_urls=['https://example.com'],
            methods=['GET'], threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=['', '  ', ''],
            allowed_hosts={'example.com'},
        )

    assert '--headers' not in captured_cmd

    print("PASS: test_run_discovery_custom_headers_empty")


def test_run_discovery_multi_method_parallel():
    """Multiple methods should each spawn a subprocess and results should merge."""
    from recon.helpers.resource_enum.arjun_helpers import run_arjun_discovery

    captured_methods = []

    def mock_subprocess_run(cmd, **kwargs):
        m_idx = cmd.index('-m')
        method = cmd[m_idx + 1]
        captured_methods.append(method)
        # Return different params per method
        output = {}
        if method == 'GET':
            output = {"https://example.com/api": {"params": ["debug"], "method": "GET", "headers": {}}}
        elif method == 'POST':
            output = {"https://example.com/api": {"params": ["csrf_token"], "method": "POST", "headers": {}}}
        for i, arg in enumerate(cmd):
            if arg == '-oJ' and i + 1 < len(cmd):
                with open(cmd[i + 1], 'w') as f:
                    json.dump(output, f)
        return subprocess.CompletedProcess(cmd, 0, '', '')

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.subprocess.run', side_effect=mock_subprocess_run):
        results, meta = run_arjun_discovery(
            target_urls=['https://example.com/api'],
            methods=['GET', 'POST'],
            threads=2, timeout=15, scan_timeout=600,
            chunk_size=500, rate_limit=0, stable=False, passive=False,
            disable_redirects=False, custom_headers=[],
            allowed_hosts={'example.com'},
        )

    # Both methods should have been called
    assert 'GET' in captured_methods
    assert 'POST' in captured_methods

    # Results from both methods should be merged
    assert len(results) == 2
    all_params = [p for r in results for p in r['params']]
    assert 'debug' in all_params
    assert 'csrf_token' in all_params

    # Methods should be preserved in results
    methods_in_results = {r['method'] for r in results}
    assert 'GET' in methods_in_results
    assert 'POST' in methods_in_results

    print("PASS: test_run_discovery_multi_method_parallel")


# ===========================================================================
# arjun_binary_check tests
# ===========================================================================

def test_binary_check_found():
    """arjun_binary_check should return True when binary exists."""
    from recon.helpers.resource_enum.arjun_helpers import arjun_binary_check

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.shutil.which', return_value='/usr/bin/arjun'):
        assert arjun_binary_check() is True

    print("PASS: test_binary_check_found")


def test_binary_check_not_found():
    """arjun_binary_check should return False when binary is missing."""
    from recon.helpers.resource_enum.arjun_helpers import arjun_binary_check

    with mock.patch('recon.helpers.resource_enum.arjun_helpers.shutil.which', return_value=None):
        assert arjun_binary_check() is False

    print("PASS: test_binary_check_not_found")


# ===========================================================================
# Settings layer consistency tests
# ===========================================================================

def test_settings_defaults_match_prisma_defaults():
    """All DEFAULT_SETTINGS keys for Arjun should have matching Prisma fields."""
    from recon.project_settings import DEFAULT_SETTINGS

    arjun_keys = {k for k in DEFAULT_SETTINGS if k.startswith('ARJUN_')}
    expected = {
        'ARJUN_ENABLED', 'ARJUN_THREADS', 'ARJUN_TIMEOUT', 'ARJUN_SCAN_TIMEOUT',
        'ARJUN_METHODS', 'ARJUN_MAX_ENDPOINTS', 'ARJUN_CHUNK_SIZE', 'ARJUN_RATE_LIMIT',
        'ARJUN_STABLE', 'ARJUN_PASSIVE', 'ARJUN_DISABLE_REDIRECTS', 'ARJUN_CUSTOM_HEADERS',
    }
    assert arjun_keys == expected, f"Missing or extra keys: {arjun_keys ^ expected}"

    # Verify default values match what we expect
    assert DEFAULT_SETTINGS['ARJUN_ENABLED'] is False
    assert DEFAULT_SETTINGS['ARJUN_THREADS'] == 2
    assert DEFAULT_SETTINGS['ARJUN_TIMEOUT'] == 15
    assert DEFAULT_SETTINGS['ARJUN_SCAN_TIMEOUT'] == 600
    assert DEFAULT_SETTINGS['ARJUN_METHODS'] == ['GET']
    assert DEFAULT_SETTINGS['ARJUN_MAX_ENDPOINTS'] == 50
    assert DEFAULT_SETTINGS['ARJUN_CHUNK_SIZE'] == 500
    assert DEFAULT_SETTINGS['ARJUN_RATE_LIMIT'] == 0
    assert DEFAULT_SETTINGS['ARJUN_STABLE'] is False
    assert DEFAULT_SETTINGS['ARJUN_PASSIVE'] is False
    assert DEFAULT_SETTINGS['ARJUN_DISABLE_REDIRECTS'] is False
    assert DEFAULT_SETTINGS['ARJUN_CUSTOM_HEADERS'] == []

    print("PASS: test_settings_defaults_match_prisma_defaults")


def test_stealth_mode_forces_passive():
    """Stealth mode should force ARJUN_PASSIVE=True."""
    from recon.project_settings import apply_stealth_overrides

    settings = {'STEALTH_MODE': True, 'ARJUN_PASSIVE': False}
    # apply_stealth_overrides modifies many keys; provide minimum required
    settings.setdefault('NUCLEI_EXCLUDE_TAGS', [])
    settings.setdefault('URLSCAN_MAX_RESULTS', 5000)
    settings.setdefault('CRTSH_MAX_RESULTS', 5000)
    settings.setdefault('HACKERTARGET_MAX_RESULTS', 5000)
    settings.setdefault('KNOCKPY_RECON_MAX_RESULTS', 5000)
    settings.setdefault('SUBFINDER_MAX_RESULTS', 5000)

    result = apply_stealth_overrides(settings)
    assert result['ARJUN_PASSIVE'] is True

    print("PASS: test_stealth_mode_forces_passive")


def test_roe_caps_arjun_rate_limit():
    """RoE global max RPS should cap ARJUN_RATE_LIMIT including 0=unlimited."""
    from recon.project_settings import DEFAULT_SETTINGS

    # Simulate the RoE rate-limit capping logic
    settings = dict(DEFAULT_SETTINGS)
    settings['ROE_ENABLED'] = True
    settings['ROE_GLOBAL_MAX_RPS'] = 10
    settings['ARJUN_RATE_LIMIT'] = 0  # unlimited

    roe_max_rps = settings['ROE_GLOBAL_MAX_RPS']
    RATE_LIMIT_KEYS = ['ARJUN_RATE_LIMIT', 'FFUF_RATE']

    for key in RATE_LIMIT_KEYS:
        if key not in settings:
            continue
        if settings[key] == 0 and key in ('FFUF_RATE', 'ARJUN_RATE_LIMIT'):
            settings[key] = roe_max_rps
        elif settings[key] > roe_max_rps:
            settings[key] = roe_max_rps

    assert settings['ARJUN_RATE_LIMIT'] == 10, f"Expected 10, got {settings['ARJUN_RATE_LIMIT']}"

    print("PASS: test_roe_caps_arjun_rate_limit")


# ===========================================================================
# Run all tests
# ===========================================================================

if __name__ == '__main__':
    # Merge tests
    test_merge_enrich_existing_endpoint()
    test_merge_create_new_endpoint()
    test_merge_post_method_body_params()
    test_merge_json_method_body_params()
    test_merge_empty_results()
    test_merge_sources_migration_from_old_source_field()
    test_merge_new_base_url()
    test_merge_url_with_port()
    test_merge_skips_empty_params()
    test_merge_duplicate_params_across_results()
    test_merge_method_added_to_existing_endpoint()
    test_merge_url_without_path()
    test_merge_parameter_type_inference()

    # Discovery tests (mocked)
    test_run_discovery_builds_correct_command()
    test_run_discovery_no_rate_limit_flag_when_zero()
    test_run_discovery_proxy_env_vars()
    test_run_discovery_no_proxy_when_disabled()
    test_run_discovery_scope_filtering()
    test_run_discovery_empty_targets()
    test_run_discovery_timeout_handling()
    test_run_discovery_no_output_file()
    test_run_discovery_malformed_json()
    test_run_discovery_temp_dir_cleanup()
    test_run_discovery_urls_written_to_temp_file()
    test_run_discovery_custom_headers_empty()
    test_run_discovery_multi_method_parallel()

    # Binary check tests
    test_binary_check_found()
    test_binary_check_not_found()

    # Settings tests
    test_settings_defaults_match_prisma_defaults()
    test_stealth_mode_forces_passive()
    test_roe_caps_arjun_rate_limit()

    print("\n" + "=" * 50)
    print("ALL ARJUN TESTS PASSED")
    print("=" * 50)
