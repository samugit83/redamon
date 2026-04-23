"""Phase 2 unit tests for graphql-cop integration (misconfig.py).

Covers:
  - TITLE_TO_KEY mapping (verbatim from graphql-cop 1.14 source)
  - _build_excluded_tests (per-test toggle -> -e flag)
  - _extract_json_array (tolerates leading text before JSON output)
  - _normalize_findings (graphql-cop JSON -> RedAmon Vulnerability dict)
  - _map_severity (HIGH/MEDIUM/LOW/INFO -> lowercase)
  - derive_endpoint_flags (raw findings -> Endpoint capability booleans)
  - run_graphql_cop (full subprocess wrapper with mocks)

Run with: python -m pytest recon/tests/test_graphql_cop.py -v
"""
import json
import subprocess
import unittest
from unittest.mock import patch, MagicMock

from recon.graphql_scan.misconfig import (
    DEFAULT_IMAGE,
    GRAPHQL_COP_TEST_TO_VULN_TYPE,
    TITLE_TO_KEY,
    HEAVY_TRAFFIC_TESTS,
    TEST_TO_ENDPOINT_FLAG,
    _build_excluded_tests,
    _extract_json_array,
    _normalize_findings,
    _map_severity,
    derive_endpoint_flags,
    run_graphql_cop,
)


# ============================================================================
# Static data: TITLE_TO_KEY integrity + mapping coverage
# ============================================================================

class TestStaticMaps(unittest.TestCase):
    def test_title_to_key_has_12_entries(self):
        self.assertEqual(len(TITLE_TO_KEY), 12,
                         "graphql-cop 1.14 registers 12 tests (field_duplication commented out)")

    def test_every_title_maps_to_a_registered_test(self):
        for title, key in TITLE_TO_KEY.items():
            self.assertIn(key, GRAPHQL_COP_TEST_TO_VULN_TYPE,
                          f"TITLE_TO_KEY[{title!r}]={key!r} not in GRAPHQL_COP_TEST_TO_VULN_TYPE")

    def test_every_vuln_type_has_a_title(self):
        # Reverse check: every internal key is discoverable from a title
        reverse = {v: k for k, v in TITLE_TO_KEY.items()}
        for key in GRAPHQL_COP_TEST_TO_VULN_TYPE:
            self.assertIn(key, reverse.values() if False else TITLE_TO_KEY.values(),
                          f"key {key!r} has no entry in TITLE_TO_KEY")

    def test_heavy_traffic_tests_are_all_registered(self):
        for key in HEAVY_TRAFFIC_TESTS:
            self.assertIn(key, GRAPHQL_COP_TEST_TO_VULN_TYPE,
                          f"HEAVY_TRAFFIC_TESTS[{key!r}] not in the registry")

    def test_endpoint_flag_keys_are_all_registered(self):
        for key in TEST_TO_ENDPOINT_FLAG:
            self.assertIn(key, GRAPHQL_COP_TEST_TO_VULN_TYPE,
                          f"TEST_TO_ENDPOINT_FLAG[{key!r}] not in the registry")


# ============================================================================
# _build_excluded_tests
# ============================================================================

class TestBuildExcludedTests(unittest.TestCase):
    def test_defaults_exclude_only_introspection(self):
        """All tests except 'introspection' default to True; introspection defaults to False."""
        excluded = _build_excluded_tests({})
        self.assertEqual(excluded, ['introspection'])

    def test_explicit_false_adds_to_excluded(self):
        settings = {
            'GRAPHQL_COP_TEST_ALIAS_OVERLOADING': False,
            'GRAPHQL_COP_TEST_BATCH_QUERY': False,
        }
        excluded = _build_excluded_tests(settings)
        self.assertIn('alias_overloading', excluded)
        self.assertIn('batch_query', excluded)
        # Introspection default (False) still excluded
        self.assertIn('introspection', excluded)

    def test_enabling_introspection_removes_from_excluded(self):
        settings = {'GRAPHQL_COP_TEST_INTROSPECTION': True}
        excluded = _build_excluded_tests(settings)
        self.assertNotIn('introspection', excluded)

    def test_all_false_excludes_all_12_tests(self):
        settings = {
            f'GRAPHQL_COP_TEST_{k.upper()}': False
            for k in [
                'field_suggestions', 'graphiql', 'get_method', 'alias_overloading',
                'batch_query', 'trace_mode', 'directive_overloading',
                'circular_introspection', 'get_mutation', 'post_csrf',
                'unhandled_error',
            ]
        }
        settings['GRAPHQL_COP_TEST_INTROSPECTION'] = False
        excluded = _build_excluded_tests(settings)
        self.assertEqual(len(excluded), 12)


# ============================================================================
# _extract_json_array (parser robustness)
# ============================================================================

class TestExtractJsonArray(unittest.TestCase):
    def test_pure_json_array(self):
        self.assertEqual(_extract_json_array('[{"title":"X","result":false}]'),
                         [{'title': 'X', 'result': False}])

    def test_leading_skip_message_before_empty_array(self):
        stdout = 'https://x/graphql does not seem to be running GraphQL. (Consider using -f to force the scan if GraphQL does exist on the endpoint)\n[]\n'
        self.assertEqual(_extract_json_array(stdout), [])

    def test_leading_text_before_real_findings(self):
        stdout = ('Running a forced scan against the endpoint\n'
                  '[{"title":"Introspection","result":true,"severity":"HIGH"}]')
        result = _extract_json_array(stdout)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['result'])

    def test_empty_stdout_returns_none(self):
        self.assertIsNone(_extract_json_array(''))
        self.assertIsNone(_extract_json_array('   \n  '))

    def test_whitespace_only_returns_none(self):
        self.assertIsNone(_extract_json_array('   '))

    def test_malformed_json_returns_none(self):
        self.assertIsNone(_extract_json_array('this is not json at all'))

    def test_truncated_json_returns_none(self):
        self.assertIsNone(_extract_json_array('[{"title":"X","res'))


# ============================================================================
# _map_severity
# ============================================================================

class TestMapSeverity(unittest.TestCase):
    def test_uppercase_maps_to_lowercase(self):
        self.assertEqual(_map_severity('HIGH'), 'high')
        self.assertEqual(_map_severity('MEDIUM'), 'medium')
        self.assertEqual(_map_severity('LOW'), 'low')
        self.assertEqual(_map_severity('INFO'), 'info')

    def test_mixed_case_handled(self):
        self.assertEqual(_map_severity('High'), 'high')
        self.assertEqual(_map_severity('medium'), 'medium')

    def test_unknown_severity_defaults_to_low(self):
        self.assertEqual(_map_severity('UNKNOWN'), 'low')
        self.assertEqual(_map_severity(''), 'low')
        self.assertEqual(_map_severity(None), 'low')


# ============================================================================
# _normalize_findings
# ============================================================================

class TestNormalizeFindings(unittest.TestCase):
    def _raw(self, overrides=None):
        base = {
            'title': 'Alias Overloading',
            'description': 'Alias Overloading with 100+ aliases is allowed',
            'impact': 'Denial of Service - /graphql',
            'severity': 'HIGH',
            'color': 'red',
            'result': True,
            'curl_verify': "curl -X POST -H 'Content-Type: application/json' -d '{\"query\":\"...\"}' 'https://api.target.com/graphql'",
        }
        if overrides:
            base.update(overrides)
        return base

    def test_triggered_finding_produces_vuln(self):
        out = _normalize_findings('https://api.target.com/graphql', [self._raw()])
        self.assertEqual(len(out), 1)
        v = out[0]
        self.assertEqual(v['vulnerability_type'], 'graphql_alias_overloading')
        self.assertEqual(v['severity'], 'high')
        self.assertEqual(v['source'], 'graphql_cop')
        self.assertEqual(v['endpoint'], 'https://api.target.com/graphql')
        self.assertIn('curl_verify', v['evidence'])
        self.assertEqual(v['evidence']['graphql_cop_key'], 'alias_overloading')

    def test_untriggered_finding_skipped(self):
        out = _normalize_findings('https://x.com/graphql', [self._raw({'result': False})])
        self.assertEqual(out, [])

    def test_unknown_title_skipped_logs_warning(self):
        out = _normalize_findings('https://x.com/graphql', [
            self._raw({'title': 'Totally New Test Added In v1.16'})
        ])
        self.assertEqual(out, [])

    def test_all_twelve_titles_map_correctly(self):
        raw = [
            self._raw({'title': title, 'result': True, 'severity': 'HIGH'})
            for title in TITLE_TO_KEY
        ]
        out = _normalize_findings('https://x.com/graphql', raw)
        self.assertEqual(len(out), 12)
        produced_types = {f['vulnerability_type'] for f in out}
        self.assertEqual(produced_types, set(GRAPHQL_COP_TEST_TO_VULN_TYPE.values()))

    def test_evidence_preserved(self):
        out = _normalize_findings('https://x.com/graphql', [self._raw()])
        evidence = out[0]['evidence']
        self.assertEqual(evidence['raw_severity'], 'HIGH')
        self.assertEqual(evidence['color'], 'red')
        self.assertTrue(evidence['curl_verify'].startswith('curl -X POST'))


# ============================================================================
# derive_endpoint_flags
# ============================================================================

class TestDeriveEndpointFlags(unittest.TestCase):
    def test_graphiql_exposed_true(self):
        raw = [{'title': 'GraphQL IDE', 'result': True}]
        self.assertEqual(derive_endpoint_flags(raw), {'graphql_graphiql_exposed': True})

    def test_graphiql_exposed_false_still_recorded(self):
        raw = [{'title': 'GraphQL IDE', 'result': False}]
        self.assertEqual(derive_endpoint_flags(raw), {'graphql_graphiql_exposed': False})

    def test_all_five_flags_derived(self):
        raw = [
            {'title': 'GraphQL IDE', 'result': True},
            {'title': 'Trace Mode', 'result': True},
            {'title': 'GET Method Query Support', 'result': False},
            {'title': 'Field Suggestions', 'result': True},
            {'title': 'Array-based Query Batching', 'result': False},
        ]
        flags = derive_endpoint_flags(raw)
        self.assertEqual(flags, {
            'graphql_graphiql_exposed': True,
            'graphql_tracing_enabled': True,
            'graphql_get_allowed': False,
            'graphql_field_suggestions_enabled': True,
            'graphql_batching_enabled': False,
        })

    def test_non_flag_tests_ignored(self):
        raw = [{'title': 'Alias Overloading', 'result': True}]
        self.assertEqual(derive_endpoint_flags(raw), {})

    def test_empty_input(self):
        self.assertEqual(derive_endpoint_flags([]), {})
        self.assertEqual(derive_endpoint_flags(None), {})


# ============================================================================
# run_graphql_cop (subprocess wrapper)
# ============================================================================

class TestRunGraphqlCop(unittest.TestCase):
    def test_disabled_returns_none(self):
        out = run_graphql_cop('https://x.com/graphql', {}, {'GRAPHQL_COP_ENABLED': False})
        self.assertIsNone(out)

    def test_all_tests_excluded_skips_invocation(self):
        settings = {
            'GRAPHQL_COP_ENABLED': True,
            **{f'GRAPHQL_COP_TEST_{k.upper()}': False for k in [
                'field_suggestions', 'introspection', 'graphiql', 'get_method',
                'alias_overloading', 'batch_query', 'trace_mode',
                'directive_overloading', 'circular_introspection', 'get_mutation',
                'post_csrf', 'unhandled_error',
            ]},
        }
        with patch('subprocess.run') as mock_run:
            out = run_graphql_cop('https://x.com/graphql', {}, settings)
        mock_run.assert_not_called()
        self.assertEqual(out, {'findings': [], 'raw': []})

    def test_successful_run_returns_findings_and_raw(self):
        cop_output = [
            {'title': 'Introspection', 'result': False, 'severity': 'HIGH'},
            {'title': 'Alias Overloading', 'result': True, 'severity': 'HIGH',
             'description': '100+ aliases', 'impact': 'DoS', 'color': 'red',
             'curl_verify': 'curl ...'},
            {'title': 'GraphQL IDE', 'result': False, 'severity': 'LOW'},
        ]
        mock_result = MagicMock(returncode=0, stdout=json.dumps(cop_output), stderr='')
        with patch('subprocess.run', return_value=mock_result):
            out = run_graphql_cop(
                'https://api.target.com/graphql',
                {'Authorization': 'Bearer xyz'},
                {'GRAPHQL_COP_ENABLED': True, 'GRAPHQL_COP_TEST_INTROSPECTION': True},
            )
        self.assertIsInstance(out, dict)
        self.assertEqual(len(out['findings']), 1)
        self.assertEqual(out['findings'][0]['vulnerability_type'], 'graphql_alias_overloading')
        self.assertEqual(len(out['raw']), 3)  # all 3 raw results preserved

    def test_timeout_returns_none(self):
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('docker', 120)):
            out = run_graphql_cop('https://x.com/graphql', {}, {'GRAPHQL_COP_ENABLED': True})
        self.assertIsNone(out)

    def test_docker_missing_returns_none(self):
        with patch('subprocess.run', side_effect=FileNotFoundError('docker')):
            out = run_graphql_cop('https://x.com/graphql', {}, {'GRAPHQL_COP_ENABLED': True})
        self.assertIsNone(out)

    def test_invalid_json_output_returns_none(self):
        mock_result = MagicMock(returncode=0, stdout='not json here at all', stderr='')
        with patch('subprocess.run', return_value=mock_result):
            out = run_graphql_cop('https://x.com/graphql', {}, {'GRAPHQL_COP_ENABLED': True})
        self.assertIsNone(out)

    def test_not_graphql_returns_empty_shape(self):
        """Endpoint isn't GraphQL -> empty findings+raw, not None."""
        stdout = 'https://x/graphql does not seem to be running GraphQL. (Consider using -f...)\n[]\n'
        mock_result = MagicMock(returncode=0, stdout=stdout, stderr='')
        with patch('subprocess.run', return_value=mock_result):
            out = run_graphql_cop('https://x.com/graphql', {}, {'GRAPHQL_COP_ENABLED': True})
        self.assertEqual(out, {'findings': [], 'raw': []})

    def test_auth_headers_one_h_flag_per_header(self):
        mock_result = MagicMock(returncode=0, stdout='[]', stderr='')
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            run_graphql_cop(
                'https://x.com/graphql',
                {'Authorization': 'Bearer A', 'X-Api-Key': 'B'},
                {'GRAPHQL_COP_ENABLED': True},
            )
        cmd = mock_run.call_args[0][0]
        h_flags = [i for i, x in enumerate(cmd) if x == '-H']
        self.assertEqual(len(h_flags), 2, "one -H per header")
        # Each -H is followed by a single-key JSON dict
        for i in h_flags:
            parsed = json.loads(cmd[i + 1])
            self.assertEqual(len(parsed), 1)

    def test_force_scan_adds_f_flag(self):
        mock_result = MagicMock(returncode=0, stdout='[]', stderr='')
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            run_graphql_cop(
                'https://x.com/graphql', {},
                {'GRAPHQL_COP_ENABLED': True, 'GRAPHQL_COP_FORCE_SCAN': True},
            )
        cmd = mock_run.call_args[0][0]
        self.assertIn('-f', cmd)

    def test_debug_adds_d_flag(self):
        mock_result = MagicMock(returncode=0, stdout='[]', stderr='')
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            run_graphql_cop(
                'https://x.com/graphql', {},
                {'GRAPHQL_COP_ENABLED': True, 'GRAPHQL_COP_DEBUG': True},
            )
        cmd = mock_run.call_args[0][0]
        self.assertIn('-d', cmd)

    def test_tor_adds_network_host_and_capital_T(self):
        mock_result = MagicMock(returncode=0, stdout='[]', stderr='')
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            run_graphql_cop(
                'https://x.com/graphql', {},
                {'GRAPHQL_COP_ENABLED': True, 'USE_TOR_FOR_RECON': True},
            )
        cmd = mock_run.call_args[0][0]
        self.assertIn('--network', cmd)
        self.assertIn('host', cmd)
        self.assertIn('-T', cmd)

    def test_no_e_flag_in_cmd_v1_14_does_not_support_it(self):
        """graphql-cop 1.14 Docker image doesn't support -e. Our wrapper
        must not pass it and must post-filter Python-side instead."""
        mock_result = MagicMock(returncode=0, stdout='[]', stderr='')
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            run_graphql_cop(
                'https://x.com/graphql', {},
                {
                    'GRAPHQL_COP_ENABLED': True,
                    'GRAPHQL_COP_TEST_ALIAS_OVERLOADING': False,
                    'GRAPHQL_COP_TEST_BATCH_QUERY': False,
                },
            )
        cmd = mock_run.call_args[0][0]
        self.assertNotIn('-e', cmd, "graphql-cop 1.14 doesn't accept -e; filter Python-side")

    def test_python_side_filter_strips_excluded_findings(self):
        """Excluded tests must be removed from both `findings` and `raw` by post-filter."""
        cop_output = [
            {'title': 'Alias Overloading', 'result': True, 'severity': 'HIGH',
             'description': '', 'impact': '', 'color': 'red', 'curl_verify': 'curl ...'},
            {'title': 'Introspection', 'result': True, 'severity': 'HIGH',
             'description': '', 'impact': '', 'color': 'red', 'curl_verify': 'curl ...'},
            {'title': 'GraphQL IDE', 'result': True, 'severity': 'LOW',
             'description': '', 'impact': '', 'color': 'blue', 'curl_verify': 'curl ...'},
        ]
        mock_result = MagicMock(returncode=0, stdout=json.dumps(cop_output), stderr='')
        with patch('subprocess.run', return_value=mock_result):
            out = run_graphql_cop(
                'https://x.com/graphql', {},
                {
                    'GRAPHQL_COP_ENABLED': True,
                    'GRAPHQL_COP_TEST_INTROSPECTION': True,    # include
                    'GRAPHQL_COP_TEST_ALIAS_OVERLOADING': False,  # EXCLUDE
                    # GRAPHQL_COP_TEST_GRAPHIQL defaults to True (included)
                },
            )
        # Alias was excluded; other two remain in both raw and findings.
        raw_titles = {f['title'] for f in out['raw']}
        self.assertEqual(raw_titles, {'Introspection', 'GraphQL IDE'})
        vuln_types = {f['vulnerability_type'] for f in out['findings']}
        self.assertEqual(vuln_types, {'graphql_introspection_enabled', 'graphql_ide_exposed'})
        self.assertNotIn('graphql_alias_overloading', vuln_types)

    def test_default_docker_image_used(self):
        mock_result = MagicMock(returncode=0, stdout='[]', stderr='')
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            run_graphql_cop(
                'https://x.com/graphql', {},
                {'GRAPHQL_COP_ENABLED': True},
            )
        cmd = mock_run.call_args[0][0]
        self.assertIn(DEFAULT_IMAGE, cmd)

    def test_custom_docker_image_honored(self):
        mock_result = MagicMock(returncode=0, stdout='[]', stderr='')
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            run_graphql_cop(
                'https://x.com/graphql', {},
                {'GRAPHQL_COP_ENABLED': True,
                 'GRAPHQL_COP_DOCKER_IMAGE': 'my.registry/fork:custom'},
            )
        cmd = mock_run.call_args[0][0]
        self.assertIn('my.registry/fork:custom', cmd)


if __name__ == '__main__':
    unittest.main()
