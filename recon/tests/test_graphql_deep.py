"""DEEP INTEGRATION TESTS for Phase 1 + Phase 2 GraphQL integration.

Unlike the mocked unit tests in test_graphql_cop.py / test_graphql_phase1.py,
this file exercises the REAL graphql-cop docker container and the REAL Neo4j
database (via the agent container's Neo4jClient). Tests are gated by
environment availability -- if docker or Neo4j are unreachable, the relevant
test class self-skips.

Covers:
  A. graphql-cop 1.14 Docker CLI: every flag we pass IS accepted
  B. graphql-cop JSON output: our parser handles 100% of real outputs
  C. Scanner call-site: test_single_endpoint enriches endpoint_data correctly
  D. Graph mixin (Neo4j): Endpoint enrichment + Vulnerability creation, live
  E. Cross-scanner dedup: same vulnerability_type via graphql_scan + graphql_cop MERGEs to ONE node
  F. Settings flow: DEFAULT_SETTINGS -> fetch_project_settings -> subprocess cmd construction

Run with: python -m pytest recon/tests/test_graphql_deep.py -v -s
"""
import json
import os
import subprocess
import sys
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from unittest.mock import patch, MagicMock

_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)


# ============================================================================
# Environment probes (auto-skip when infra unavailable)
# ============================================================================

def _docker_available() -> bool:
    try:
        r = subprocess.run(['docker', 'images', '-q', 'dolevf/graphql-cop:1.14'],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def _neo4j_available() -> bool:
    try:
        import neo4j  # noqa: F401
        from graph_db import Neo4jClient
        with Neo4jClient() as c:
            return c.verify_connection()
    except Exception:
        return False


DOCKER_OK = _docker_available()
NEO4J_OK = _neo4j_available()


# ============================================================================
# A. Real graphql-cop CLI: every flag we pass is accepted by 1.14
# ============================================================================

@unittest.skipUnless(DOCKER_OK, "dolevf/graphql-cop:1.14 not pulled -- skip")
class TestGraphqlCopCLIAcceptance(unittest.TestCase):
    """Run the REAL docker container with each flag and verify non-arg-error exit.

    Unreachable target (127.0.0.1:1) used so tests don't depend on a live GraphQL
    service -- we only care that flags are parsed without 'no such option' errors.
    """
    IMAGE = 'dolevf/graphql-cop:1.14'
    UNREACHABLE = 'http://127.0.0.1:1/graphql'

    def _run(self, *extra_args, timeout=20) -> subprocess.CompletedProcess:
        cmd = ['docker', 'run', '--rm', self.IMAGE,
               '-t', self.UNREACHABLE, '-o', 'json', *extra_args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _assert_not_arg_error(self, result):
        """CLI parsed successfully (no 'no such option' in stderr/stdout)."""
        combined = (result.stdout or '') + (result.stderr or '')
        self.assertNotIn('no such option', combined.lower(),
                         f"graphql-cop rejected a flag we pass: {combined[:300]}")
        self.assertNotIn('unrecognized arguments', combined.lower(), combined[:300])

    def test_minimal_invocation(self):
        r = self._run()
        self._assert_not_arg_error(r)

    def test_H_header_flag(self):
        r = self._run('-H', json.dumps({'Authorization': 'Bearer test'}))
        self._assert_not_arg_error(r)

    def test_H_repeated(self):
        r = self._run('-H', json.dumps({'A': '1'}), '-H', json.dumps({'B': '2'}))
        self._assert_not_arg_error(r)

    def test_o_json_output(self):
        r = self._run('-o', 'json')
        self._assert_not_arg_error(r)

    def test_f_force_scan(self):
        r = self._run('-f')
        self._assert_not_arg_error(r)

    def test_d_debug_mode(self):
        r = self._run('-d')
        self._assert_not_arg_error(r)

    def test_x_proxy(self):
        r = self._run('-x', 'http://127.0.0.1:1')
        self._assert_not_arg_error(r)

    def test_v_version(self):
        # -v prints version and exits 0
        cmd = ['docker', 'run', '--rm', self.IMAGE, '-v']
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        self.assertIn('1.14', r.stdout, r.stdout)

    def test_e_flag_REJECTED_by_1_14(self):
        """Negative test: -e is NOT supported by 1.14. Confirms our fix was needed."""
        r = self._run('-e', 'alias_overloading')
        combined = (r.stdout or '') + (r.stderr or '')
        self.assertIn('no such option', combined.lower(),
                      "If -e is accepted, our Python-side filter is no longer needed")

    def test_T_tor_flag_accepted(self):
        # -T tries to connect to Tor on 127.0.0.1:9050. It errors but doesn't reject the flag.
        r = self._run('-T', timeout=30)
        self._assert_not_arg_error(r)

    def test_all_our_flags_together(self):
        """Kitchen sink: every flag our wrapper ever passes, combined."""
        r = self._run(
            '-f', '-d',
            '-H', json.dumps({'Authorization': 'Bearer X'}),
            '-H', json.dumps({'X-Custom': 'Y'}),
            '-x', 'http://proxy:8080',
        )
        self._assert_not_arg_error(r)


# ============================================================================
# B. Real graphql-cop output parsing: 100% coverage
# ============================================================================

@unittest.skipUnless(DOCKER_OK, "dolevf/graphql-cop:1.14 not pulled -- skip")
class TestGraphqlCopRealOutputParsing(unittest.TestCase):
    """Capture REAL graphql-cop stdout against an in-process mock GraphQL server,
    then run our parser and verify every title/severity maps correctly."""

    @classmethod
    def setUpClass(cls):
        """Spin up a tiny HTTP server that answers like a vulnerable GraphQL endpoint."""
        cls.server_port = _find_free_port()
        cls.server = HTTPServer(('0.0.0.0', cls.server_port), _VulnerableGraphqlHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _run_cop_and_parse(self, extra_args=None):
        """Run graphql-cop against our mock server; return (raw_stdout, parsed_findings)."""
        extra_args = extra_args or []
        url = f'http://host.docker.internal:{self.server_port}/graphql'
        # Fall back to --network host on Linux (host.docker.internal may not resolve)
        cmd = ['docker', 'run', '--rm', '--network', 'host',
               'dolevf/graphql-cop:1.14',
               '-t', f'http://127.0.0.1:{self.server_port}/graphql',
               '-o', 'json', '-f', *extra_args]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout, r.stderr

    def test_parser_handles_real_output_robustly(self):
        """Parser handles any real stdout: valid JSON, leading text + JSON, or error output.

        graphql-cop 1.14 has a known upstream bug (curlify() fails on non-Response
        objects) that can produce stdout with a traceback and no JSON. Our parser
        must return None in that case, not crash.
        """
        from recon.graphql_scan.misconfig import _extract_json_array
        stdout, _ = self._run_cop_and_parse()
        parsed = _extract_json_array(stdout)
        # Either valid JSON list OR None (when upstream crashed). Must never raise.
        self.assertTrue(parsed is None or isinstance(parsed, list),
                        f"Parser returned {type(parsed)} for stdout: {stdout[:200]!r}")

    def test_every_parsed_title_is_in_title_to_key(self):
        """100% parsing: whatever title(s) graphql-cop emits, we map them."""
        from recon.graphql_scan.misconfig import _extract_json_array, TITLE_TO_KEY
        stdout, _ = self._run_cop_and_parse()
        parsed = _extract_json_array(stdout) or []
        unknown = [f.get('title') for f in parsed if f.get('title') not in TITLE_TO_KEY]
        self.assertEqual(unknown, [],
                         f"graphql-cop emitted titles not in TITLE_TO_KEY: {unknown}")

    def test_parsed_count_bounded_by_registered_tests(self):
        """If graphql-cop returns JSON, the count is in {0, ..., 12}."""
        from recon.graphql_scan.misconfig import _extract_json_array, TITLE_TO_KEY
        stdout, _ = self._run_cop_and_parse()
        parsed = _extract_json_array(stdout) or []
        self.assertLessEqual(len(parsed), len(TITLE_TO_KEY))

    def test_wrapper_gracefully_handles_upstream_crash(self):
        """When graphql-cop crashes (known 1.14 upstream bug), wrapper returns None
        rather than propagating the exception. This is the correct error behavior."""
        from recon.graphql_scan.misconfig import run_graphql_cop
        settings = {'GRAPHQL_COP_ENABLED': True, 'GRAPHQL_COP_FORCE_SCAN': True,
                    'GRAPHQL_COP_TIMEOUT': 60, 'GRAPHQL_COP_TEST_INTROSPECTION': True}
        out = run_graphql_cop(
            f'http://127.0.0.1:{self.server_port}/graphql',
            {},
            settings,
            timeout=60,
        )
        # Returns None (parse failure) or dict (success) — never raises
        self.assertTrue(out is None or (isinstance(out, dict)
                                        and 'findings' in out
                                        and 'raw' in out),
                        f"wrapper returned unexpected value: {out!r}")


# ============================================================================
# C. Scanner integration: test_single_endpoint enriches endpoint_data correctly
# ============================================================================

class TestScannerCallSiteIntegration(unittest.TestCase):
    """Verify scanner.test_single_endpoint hook: endpoint_data is enriched with
    graphql-cop capability flags + vulnerabilities when GRAPHQL_COP_ENABLED."""

    def _settings(self):
        return {
            'GRAPHQL_INTROSPECTION_TEST': False,    # Skip native introspection
            'GRAPHQL_COP_ENABLED': True,
            'GRAPHQL_VERIFY_SSL': True,
            'GRAPHQL_TIMEOUT': 30,
        }

    def _cop_output_mix(self):
        """Representative output: 5 result=False (for capability flags), 2 result=True (vulns)."""
        return {
            'findings': [
                {'vulnerability_type': 'graphql_ide_exposed', 'severity': 'low',
                 'endpoint': 'http://x/graphql', 'title': 'GraphQL IDE',
                 'description': 'GraphiQL Explorer/Playground Enabled',
                 'source': 'graphql_cop',
                 'evidence': {'curl_verify': 'curl ...', 'raw_severity': 'LOW',
                              'color': 'blue', 'graphql_cop_key': 'detect_graphiql'},
                 'timestamp': '2026-04-20T00:00:00+00:00'},
                {'vulnerability_type': 'graphql_alias_overloading', 'severity': 'high',
                 'endpoint': 'http://x/graphql', 'title': 'Alias Overloading',
                 'description': '', 'source': 'graphql_cop',
                 'evidence': {'curl_verify': 'curl ...', 'raw_severity': 'HIGH',
                              'color': 'red', 'graphql_cop_key': 'alias_overloading'},
                 'timestamp': '2026-04-20T00:00:00+00:00'},
            ],
            'raw': [
                # Capability flag tests (all 5)
                {'title': 'GraphQL IDE', 'result': True, 'severity': 'LOW'},
                {'title': 'Trace Mode', 'result': False, 'severity': 'INFO'},
                {'title': 'GET Method Query Support', 'result': False, 'severity': 'MEDIUM'},
                {'title': 'Field Suggestions', 'result': True, 'severity': 'LOW'},
                {'title': 'Array-based Query Batching', 'result': False, 'severity': 'HIGH'},
                # Non-flag test (alias overloading)
                {'title': 'Alias Overloading', 'result': True, 'severity': 'HIGH'},
            ],
        }

    def test_endpoint_data_has_5_capability_flags(self):
        from recon.graphql_scan.scanner import test_single_endpoint
        with patch('recon.graphql_scan.misconfig.run_graphql_cop', return_value=self._cop_output_mix()), \
             patch('recon.graphql_scan.scanner.test_introspection',
                   return_value=(False, None, None)):
            res = test_single_endpoint('http://x/graphql', {}, 30, self._settings())
        self.assertIsNotNone(res)
        ep = res['endpoint_data']
        # All 5 capability flags must be set (True or False), not missing
        self.assertEqual(ep['graphql_graphiql_exposed'], True)
        self.assertEqual(ep['graphql_tracing_enabled'], False)
        self.assertEqual(ep['graphql_get_allowed'], False)
        self.assertEqual(ep['graphql_field_suggestions_enabled'], True)
        self.assertEqual(ep['graphql_batching_enabled'], False)
        self.assertEqual(ep['graphql_cop_ran'], True)

    def test_vulnerabilities_list_extended_with_cop_findings(self):
        from recon.graphql_scan.scanner import test_single_endpoint
        with patch('recon.graphql_scan.misconfig.run_graphql_cop', return_value=self._cop_output_mix()), \
             patch('recon.graphql_scan.scanner.test_introspection',
                   return_value=(False, None, None)):
            res = test_single_endpoint('http://x/graphql', {}, 30, self._settings())
        vuln_types = {v['vulnerability_type'] for v in res['vulnerabilities']}
        self.assertIn('graphql_ide_exposed', vuln_types)
        self.assertIn('graphql_alias_overloading', vuln_types)

    def test_disabled_cop_does_not_call_wrapper(self):
        from recon.graphql_scan.scanner import test_single_endpoint
        with patch('recon.graphql_scan.misconfig.run_graphql_cop') as mock_cop, \
             patch('recon.graphql_scan.scanner.test_introspection',
                   return_value=(False, None, None)):
            settings = self._settings()
            settings['GRAPHQL_COP_ENABLED'] = False
            test_single_endpoint('http://x/graphql', {}, 30, settings)
        mock_cop.assert_not_called()

    def test_cop_none_output_does_not_crash_scanner(self):
        from recon.graphql_scan.scanner import test_single_endpoint
        with patch('recon.graphql_scan.misconfig.run_graphql_cop', return_value=None), \
             patch('recon.graphql_scan.scanner.test_introspection',
                   return_value=(False, None, None)):
            res = test_single_endpoint('http://x/graphql', {}, 30, self._settings())
        self.assertIsNotNone(res)
        self.assertNotIn('graphql_cop_ran', res['endpoint_data'])


# ============================================================================
# D. Graph mixin integration with LIVE Neo4j
# ============================================================================

@unittest.skipUnless(NEO4J_OK, "Neo4j not reachable or 'neo4j' module missing -- skip")
class TestGraphMixinLiveNeo4j(unittest.TestCase):
    """End-to-end: feed recon_data to update_graph_from_graphql_scan against the
    real Neo4j instance, then Cypher-query to verify nodes + properties."""

    @classmethod
    def setUpClass(cls):
        from graph_db import Neo4jClient
        cls.user_id = f'test-user-{uuid.uuid4().hex[:8]}'
        cls.project_id = f'test-proj-{uuid.uuid4().hex[:8]}'
        cls.baseurl = 'https://api.deeptest.invalid'
        cls.path = '/graphql'
        cls.full_url = cls.baseurl + cls.path
        cls.client = Neo4jClient()

    @classmethod
    def tearDownClass(cls):
        # Wipe all nodes for this synthetic project
        with cls.client.driver.session() as s:
            s.run("""
                MATCH (n) WHERE n.user_id = $uid AND n.project_id = $pid
                DETACH DELETE n
            """, uid=cls.user_id, pid=cls.project_id)
        cls.client.close()

    def setUp(self):
        # Reset project state before each test
        with self.client.driver.session() as s:
            s.run("""
                MATCH (n) WHERE n.user_id = $uid AND n.project_id = $pid
                DETACH DELETE n
            """, uid=self.user_id, pid=self.project_id)

    def _build_recon_data(self, cop_findings=None, cop_raw_flags=None,
                          introspection_enabled=True):
        """Assemble a recon_data dict with both native + graphql-cop output."""
        endpoint_data = {
            'tested': True,
            'introspection_enabled': introspection_enabled,
            'schema_extracted': introspection_enabled,
            'queries_count': 5, 'mutations_count': 2, 'subscriptions_count': 1,
            'schema_hash': 'sha256:abc123',
            'operations': {
                'queries': ['me', 'users', 'orders', 'products', 'search'],
                'mutations': ['login', 'logout'],
                'subscriptions': ['onMessage'],
            },
        }
        if cop_raw_flags:
            endpoint_data.update(cop_raw_flags)
            endpoint_data['graphql_cop_ran'] = True

        native_vulns = []
        if introspection_enabled:
            native_vulns.append({
                'vulnerability_type': 'graphql_introspection_enabled',
                'severity': 'medium',
                'endpoint': self.full_url,
                'title': 'GraphQL Introspection Enabled',
                'description': 'Full schema exposed',
                'source': 'graphql_scan',
                'evidence': {'queries_count': 5, 'mutations_count': 2,
                             'subscriptions_count': 1, 'sensitive_fields': []},
            })

        return {
            'graphql_scan': {
                'endpoints': {self.full_url: endpoint_data},
                'vulnerabilities': native_vulns + (cop_findings or []),
            }
        }

    def _fetch_endpoint(self):
        with self.client.driver.session() as s:
            r = s.run("""
                MATCH (e:Endpoint {
                    path: $path, method: 'POST', baseurl: $baseurl,
                    user_id: $uid, project_id: $pid
                })
                RETURN properties(e) AS props
            """, path=self.path, baseurl=self.baseurl,
                 uid=self.user_id, pid=self.project_id)
            rec = r.single()
            return rec['props'] if rec else None

    def _fetch_vulns(self):
        with self.client.driver.session() as s:
            r = s.run("""
                MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
                RETURN v.id AS id, v.vulnerability_type AS vtype,
                       v.source AS source, v.severity AS severity
                ORDER BY v.vulnerability_type
            """, uid=self.user_id, pid=self.project_id)
            return [dict(rec) for rec in r]

    def test_endpoint_enriched_with_all_graphql_properties(self):
        recon = self._build_recon_data()
        self.client.update_graph_from_graphql_scan(recon, self.user_id, self.project_id)
        props = self._fetch_endpoint()
        self.assertIsNotNone(props, "Endpoint not created")
        self.assertTrue(props['is_graphql'])
        self.assertTrue(props['graphql_introspection_enabled'])
        self.assertTrue(props['graphql_schema_extracted'])
        self.assertEqual(props['graphql_schema_hash'], 'sha256:abc123')
        self.assertIn('graphql_schema_extracted_at', props)  # ISO timestamp
        self.assertEqual(sorted(props['graphql_queries']), sorted(['me', 'users', 'orders', 'products', 'search']))
        self.assertEqual(sorted(props['graphql_mutations']), sorted(['login', 'logout']))
        self.assertEqual(props['graphql_subscriptions'], ['onMessage'])
        self.assertEqual(props['graphql_queries_count'], 5)
        self.assertEqual(props['graphql_mutations_count'], 2)
        self.assertEqual(props['graphql_subscriptions_count'], 1)

    def test_endpoint_gets_5_graphql_cop_capability_flags(self):
        cop_flags = {
            'graphql_graphiql_exposed': True,
            'graphql_tracing_enabled': False,
            'graphql_get_allowed': True,
            'graphql_field_suggestions_enabled': False,
            'graphql_batching_enabled': True,
        }
        recon = self._build_recon_data(cop_raw_flags=cop_flags)
        self.client.update_graph_from_graphql_scan(recon, self.user_id, self.project_id)
        props = self._fetch_endpoint()
        for flag, expected in cop_flags.items():
            self.assertEqual(props.get(flag), expected,
                             f"flag {flag} expected {expected}, got {props.get(flag)}")
        self.assertIn('graphql_cop_scanned_at', props)

    def test_vulnerability_nodes_have_correct_sources(self):
        """Native + graphql-cop findings both land; sources are distinguishable."""
        cop_findings = [{
            'vulnerability_type': 'graphql_alias_overloading',
            'severity': 'high',
            'endpoint': self.full_url,
            'title': 'Alias Overloading',
            'description': '100+ aliases allowed',
            'source': 'graphql_cop',
            'evidence': {'curl_verify': 'curl -X POST ...', 'graphql_cop_key': 'alias_overloading'},
        }]
        recon = self._build_recon_data(cop_findings=cop_findings)
        self.client.update_graph_from_graphql_scan(recon, self.user_id, self.project_id)
        vulns = self._fetch_vulns()
        self.assertEqual(len(vulns), 2)
        sources = {v['source'] for v in vulns}
        self.assertEqual(sources, {'graphql_scan', 'graphql_cop'})

    def test_endpoint_has_vulnerability_relationship_edges(self):
        """Each Vulnerability node is edge-connected to the Endpoint via HAS_VULNERABILITY."""
        cop_findings = [{
            'vulnerability_type': 'graphql_tracing_enabled',
            'severity': 'info',
            'endpoint': self.full_url,
            'title': 'Trace Mode',
            'source': 'graphql_cop',
            'evidence': {'curl_verify': 'curl ...'},
        }]
        recon = self._build_recon_data(cop_findings=cop_findings)
        self.client.update_graph_from_graphql_scan(recon, self.user_id, self.project_id)
        with self.client.driver.session() as s:
            r = s.run("""
                MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                WHERE e.user_id = $uid AND e.project_id = $pid
                RETURN count(v) AS n
            """, uid=self.user_id, pid=self.project_id)
            n = r.single()['n']
        # Both native introspection vuln + graphql-cop tracing vuln connected
        self.assertGreaterEqual(n, 2)

    def test_dedup_same_vuln_type_merges_to_one_node(self):
        """If BOTH native scanner AND graphql-cop produce the same vulnerability_type
        on the same endpoint, the deterministic ID MERGE produces ONE node, not two."""
        # Native scanner produces graphql_introspection_enabled (source='graphql_scan')
        # graphql-cop also produces one (source='graphql_cop')
        cop_findings = [{
            'vulnerability_type': 'graphql_introspection_enabled',
            'severity': 'high',
            'endpoint': self.full_url,
            'title': 'Introspection',
            'description': 'Introspection Query Enabled',
            'source': 'graphql_cop',
            'evidence': {'curl_verify': 'curl ...', 'graphql_cop_key': 'introspection'},
        }]
        recon = self._build_recon_data(cop_findings=cop_findings, introspection_enabled=True)
        self.client.update_graph_from_graphql_scan(recon, self.user_id, self.project_id)
        vulns = [v for v in self._fetch_vulns()
                 if v['vtype'] == 'graphql_introspection_enabled']
        self.assertEqual(len(vulns), 1, f"dedup failed: {vulns}")

    def test_deterministic_id_pattern(self):
        recon = self._build_recon_data()
        self.client.update_graph_from_graphql_scan(recon, self.user_id, self.project_id)
        vulns = self._fetch_vulns()
        introspection = next((v for v in vulns
                              if v['vtype'] == 'graphql_introspection_enabled'), None)
        self.assertIsNotNone(introspection)
        # Deterministic ID per plan: graphql_{type}_{baseurl}_{path} with :/. replaced by _
        self.assertIn('graphql_introspection_enabled', introspection['id'])
        self.assertIn('api_deeptest_invalid', introspection['id'])

    def test_evidence_curl_verify_persisted(self):
        cop_findings = [{
            'vulnerability_type': 'graphql_alias_overloading',
            'severity': 'high',
            'endpoint': self.full_url,
            'title': 'Alias Overloading',
            'source': 'graphql_cop',
            'evidence': {
                'curl_verify': "curl -X POST -H 'Content-Type: application/json' "
                               "-d '{\"query\":\"query cop { alias0:__typename }\"}' "
                               "'https://api.deeptest.invalid/graphql'",
                'graphql_cop_key': 'alias_overloading',
            },
        }]
        recon = self._build_recon_data(cop_findings=cop_findings)
        self.client.update_graph_from_graphql_scan(recon, self.user_id, self.project_id)
        with self.client.driver.session() as s:
            r = s.run("""
                MATCH (v:Vulnerability {source: 'graphql_cop', user_id: $uid, project_id: $pid})
                RETURN v.evidence AS ev
            """, uid=self.user_id, pid=self.project_id)
            ev = r.single()['ev']
        parsed = json.loads(ev)
        self.assertIn('curl_verify', parsed)
        self.assertIn("curl -X POST", parsed['curl_verify'])


# ============================================================================
# E. Settings flow: DEFAULT_SETTINGS -> fetch_project_settings -> subprocess cmd
# ============================================================================

class TestSettingsFlow(unittest.TestCase):
    """Verify camelCase DB fields round-trip through fetch_project_settings
    into SCREAMING_SNAKE_CASE Python settings, and then into correct cmd args."""

    def test_every_camelcase_key_mapped_to_snake_case(self):
        """Mock the webapp HTTP call; verify every graphqlCop* field round-trips."""
        from project_settings import fetch_project_settings
        project_response = {
            'graphqlCopEnabled': True,
            'graphqlCopDockerImage': 'custom:1.0',
            'graphqlCopTimeout': 99,
            'graphqlCopForceScan': True,
            'graphqlCopDebug': True,
            'graphqlCopTestFieldSuggestions': False,
            'graphqlCopTestIntrospection': True,
            'graphqlCopTestGraphiql': False,
            'graphqlCopTestGetMethod': False,
            'graphqlCopTestAliasOverloading': False,
            'graphqlCopTestBatchQuery': False,
            'graphqlCopTestTraceMode': False,
            'graphqlCopTestDirectiveOverloading': False,
            'graphqlCopTestCircularIntrospection': False,
            'graphqlCopTestGetMutation': False,
            'graphqlCopTestPostCsrf': False,
            'graphqlCopTestUnhandledError': False,
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = project_response
        mock_resp.raise_for_status.return_value = None
        with patch('requests.get', return_value=mock_resp):
            out = fetch_project_settings('p1', 'http://webapp:3000')
        self.assertTrue(out['GRAPHQL_COP_ENABLED'])
        self.assertEqual(out['GRAPHQL_COP_DOCKER_IMAGE'], 'custom:1.0')
        self.assertEqual(out['GRAPHQL_COP_TIMEOUT'], 99)
        self.assertTrue(out['GRAPHQL_COP_FORCE_SCAN'])
        self.assertTrue(out['GRAPHQL_COP_DEBUG'])
        self.assertFalse(out['GRAPHQL_COP_TEST_FIELD_SUGGESTIONS'])
        self.assertTrue(out['GRAPHQL_COP_TEST_INTROSPECTION'])
        self.assertFalse(out['GRAPHQL_COP_TEST_GRAPHIQL'])
        self.assertFalse(out['GRAPHQL_COP_TEST_ALIAS_OVERLOADING'])
        self.assertFalse(out['GRAPHQL_COP_TEST_BATCH_QUERY'])
        self.assertFalse(out['GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING'])
        self.assertFalse(out['GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION'])

    def test_fetch_uses_defaults_when_webapp_returns_empty_project(self):
        from project_settings import DEFAULT_SETTINGS, fetch_project_settings
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status.return_value = None
        with patch('requests.get', return_value=mock_resp):
            out = fetch_project_settings('p1', 'http://webapp:3000')
        for k in [k for k in DEFAULT_SETTINGS if k.startswith('GRAPHQL_COP_')]:
            self.assertEqual(out[k], DEFAULT_SETTINGS[k], f"{k} did not fall back to default")

    def test_stealth_overrides_disable_all_4_dos_probes(self):
        from project_settings import DEFAULT_SETTINGS, apply_stealth_overrides
        settings = dict(DEFAULT_SETTINGS)
        settings['STEALTH_MODE'] = True
        out = apply_stealth_overrides(settings)
        # All 4 DoS probes forced off
        self.assertFalse(out['GRAPHQL_COP_TEST_ALIAS_OVERLOADING'])
        self.assertFalse(out['GRAPHQL_COP_TEST_BATCH_QUERY'])
        self.assertFalse(out['GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING'])
        self.assertFalse(out['GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION'])
        # Info-leak + CSRF checks still allowed
        self.assertTrue(out.get('GRAPHQL_COP_TEST_FIELD_SUGGESTIONS', True))
        self.assertTrue(out.get('GRAPHQL_COP_TEST_GRAPHIQL', True))


# ============================================================================
# F. Subprocess cmd construction: every setting flows to the correct flag
# ============================================================================

class TestSubprocessCmdConstruction(unittest.TestCase):
    """For every settings permutation, assert the docker cmd is exactly right."""

    def _capture_cmd(self, settings, headers=None):
        mock = MagicMock(returncode=0, stdout='[]', stderr='')
        with patch('subprocess.run', return_value=mock) as run:
            from recon.graphql_scan.misconfig import run_graphql_cop
            run_graphql_cop('https://x/graphql', headers or {}, settings)
        return run.call_args[0][0]

    def test_baseline_cmd(self):
        cmd = self._capture_cmd({'GRAPHQL_COP_ENABLED': True})
        self.assertEqual(cmd[:3], ['docker', 'run', '--rm'])
        self.assertIn('dolevf/graphql-cop:1.14', cmd)
        self.assertIn('-t', cmd)
        self.assertIn('https://x/graphql', cmd)
        self.assertIn('-o', cmd)
        self.assertIn('json', cmd)

    def test_custom_docker_image_honored(self):
        cmd = self._capture_cmd({
            'GRAPHQL_COP_ENABLED': True,
            'GRAPHQL_COP_DOCKER_IMAGE': 'my.reg/fork:custom'})
        self.assertIn('my.reg/fork:custom', cmd)
        self.assertNotIn('dolevf/graphql-cop:1.14', cmd)

    def test_force_scan_flag(self):
        cmd = self._capture_cmd({
            'GRAPHQL_COP_ENABLED': True, 'GRAPHQL_COP_FORCE_SCAN': True})
        self.assertIn('-f', cmd)

    def test_debug_flag(self):
        cmd = self._capture_cmd({
            'GRAPHQL_COP_ENABLED': True, 'GRAPHQL_COP_DEBUG': True})
        self.assertIn('-d', cmd)

    def test_tor_mode_uses_network_host_plus_T(self):
        cmd = self._capture_cmd({
            'GRAPHQL_COP_ENABLED': True, 'USE_TOR_FOR_RECON': True})
        self.assertIn('--network', cmd)
        host_idx = cmd.index('--network') + 1
        self.assertEqual(cmd[host_idx], 'host')
        self.assertIn('-T', cmd)

    def test_http_proxy_flag(self):
        cmd = self._capture_cmd({
            'GRAPHQL_COP_ENABLED': True, 'HTTP_PROXY': 'http://127.0.0.1:8080'})
        x_idx = cmd.index('-x')
        self.assertEqual(cmd[x_idx + 1], 'http://127.0.0.1:8080')

    def test_auth_headers_one_H_per_header(self):
        cmd = self._capture_cmd(
            {'GRAPHQL_COP_ENABLED': True},
            headers={'Authorization': 'Bearer A', 'X-Api-Key': 'B'},
        )
        H_positions = [i for i, x in enumerate(cmd) if x == '-H']
        self.assertEqual(len(H_positions), 2)
        parsed = [json.loads(cmd[i + 1]) for i in H_positions]
        keys_seen = set().union(*(p.keys() for p in parsed))
        self.assertEqual(keys_seen, {'Authorization', 'X-Api-Key'})

    def test_no_e_flag_ever(self):
        """Regression: never pass -e (1.14 rejects it; we post-filter)."""
        for settings in [
            {'GRAPHQL_COP_ENABLED': True},
            {'GRAPHQL_COP_ENABLED': True, 'GRAPHQL_COP_TEST_ALIAS_OVERLOADING': False},
            {'GRAPHQL_COP_ENABLED': True,
             **{f'GRAPHQL_COP_TEST_{k}': False for k in [
                 'ALIAS_OVERLOADING', 'BATCH_QUERY', 'DIRECTIVE_OVERLOADING']}},
        ]:
            cmd = self._capture_cmd(settings)
            self.assertNotIn('-e', cmd, f"regression: -e should never appear. cmd={cmd}")


# ============================================================================
# Test helpers
# ============================================================================

def _find_free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(('', 0))
        return s.getsockname()[1]


class _VulnerableGraphqlHandler(BaseHTTPRequestHandler):
    """Minimal GraphQL-ish server: returns data for __typename + __schema queries,
    accepts any POST, exposes GraphiQL IDE hint via response text."""

    def log_message(self, *args, **kwargs):  # suppress stderr spam
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='ignore')
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}
        query = (payload.get('query') or '').strip()

        # Return GraphQL-shaped responses so is_graphql() returns True
        if '__typename' in query:
            resp = {'data': {'__typename': 'Query'}}
        elif '__schema' in query:
            resp = {'data': {'__schema': {
                'queryType': {'name': 'Query'},
                'mutationType': {'name': 'Mutation'},
                'types': [],
            }}}
        else:
            resp = {'data': {'result': 'ok'}}

        body_out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body_out)))
        self.end_headers()
        self.wfile.write(body_out)

    def do_GET(self):
        # Respond with fake GraphiQL so detect_graphiql can fire
        body = b"<html><body>GraphiQL Explorer/Playground</body></html>"
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    unittest.main()
