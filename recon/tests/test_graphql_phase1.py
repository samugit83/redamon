"""Phase 1 unit tests for GraphQL integration (post-PR-#93 conformance work).

Covers:
  - graph_db/mixins/graphql_mixin.py : subscriptions + explicit counts + schema_extracted_at (§6.4)
  - recon/main_recon_modules/vuln_scan.py              : run_vuln_scan_isolated (§2.5)
  - recon/partial_recon_modules/graphql_scanning.py : run_graphqlscan (§9.1)
  - recon/partial_recon_modules/graph_builders.py   : _build_graphql_data_from_graph (§9.1.c)

Run with: python -m pytest recon/tests/test_graphql_phase1.py -v
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY

# Path setup (same pattern as test_partial_recon.py)
_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)

# Pre-mock heavy deps
sys.modules['neo4j'] = MagicMock()


# ============================================================================
# §6.4 Graph mixin subscriptions + explicit counts
# ============================================================================

class TestGraphQLMixinSubscriptions(unittest.TestCase):
    """Verifies graphql_mixin.update_graph_from_graphql_scan stores subscriptions
    + explicit counts + schema_extracted_at (no silent data loss)."""

    def setUp(self):
        from graph_db.mixins.graphql_mixin import GraphQLMixin

        # Build a minimal stub class with just enough attrs for update_graph_from_graphql_scan
        class StubClient(GraphQLMixin):
            def __init__(self):
                self.driver = MagicMock()
                # session.run() returns an iterable of records
                self._session = MagicMock()
                self._session.run = MagicMock(return_value=iter([
                    MagicMock(data=lambda: {"path": "/graphql", "was_graphql": False})
                ]))
                self.driver.session.return_value.__enter__ = MagicMock(return_value=self._session)
                self.driver.session.return_value.__exit__ = MagicMock(return_value=False)

        self.client = StubClient()
        self.recon_data = {
            "graphql_scan": {
                "endpoints": {
                    "https://api.target.com/graphql": {
                        "tested": True,
                        "introspection_enabled": True,
                        "schema_extracted": True,
                        "queries_count": 23,
                        "mutations_count": 8,
                        "subscriptions_count": 2,
                        "schema_hash": "sha256:abc123",
                        "operations": {
                            "queries": ["me", "users", "orders"],
                            "mutations": ["login", "createOrder"],
                            "subscriptions": ["onMessage", "onNotification"],
                        },
                    },
                },
                "vulnerabilities": [],
            },
        }

    def _captured_endpoint_props(self):
        """Return the dict of props SET on the Endpoint MERGE call."""
        call_args_list = self.client._session.run.call_args_list
        # First run() call updates the Endpoint; kwargs contain 'props'
        for call in call_args_list:
            args, kwargs = call
            if 'props' in kwargs:
                return kwargs['props']
        self.fail("No SET-props call captured on session.run()")

    def test_stores_subscriptions_array(self):
        self.client.update_graph_from_graphql_scan(self.recon_data, "u1", "p1")
        props = self._captured_endpoint_props()
        self.assertIn('graphql_subscriptions', props)
        self.assertEqual(props['graphql_subscriptions'], ["onMessage", "onNotification"])

    def test_stores_explicit_counts(self):
        self.client.update_graph_from_graphql_scan(self.recon_data, "u1", "p1")
        props = self._captured_endpoint_props()
        self.assertEqual(props['graphql_queries_count'], 23)
        self.assertEqual(props['graphql_mutations_count'], 8)
        self.assertEqual(props['graphql_subscriptions_count'], 2)

    def test_stores_schema_extracted_at_when_schema_extracted(self):
        self.client.update_graph_from_graphql_scan(self.recon_data, "u1", "p1")
        props = self._captured_endpoint_props()
        self.assertIn('graphql_schema_extracted_at', props)
        # Validate ISO format with timezone (+00:00 suffix)
        self.assertRegex(props['graphql_schema_extracted_at'], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*\+00:00$')

    def test_omits_schema_extracted_at_when_not_extracted(self):
        self.recon_data['graphql_scan']['endpoints']['https://api.target.com/graphql']['schema_extracted'] = False
        self.client.update_graph_from_graphql_scan(self.recon_data, "u1", "p1")
        props = self._captured_endpoint_props()
        self.assertNotIn('graphql_schema_extracted_at', props)

    def test_subscriptions_capped_at_50(self):
        # Schema with 120 subscriptions → capped at 50
        self.recon_data['graphql_scan']['endpoints']['https://api.target.com/graphql']['operations']['subscriptions'] = \
            [f'sub{i}' for i in range(120)]
        self.client.update_graph_from_graphql_scan(self.recon_data, "u1", "p1")
        props = self._captured_endpoint_props()
        self.assertEqual(len(props['graphql_subscriptions']), 50)

    def test_empty_subscriptions_omits_array_but_sets_count_zero(self):
        self.recon_data['graphql_scan']['endpoints']['https://api.target.com/graphql']['operations']['subscriptions'] = []
        self.recon_data['graphql_scan']['endpoints']['https://api.target.com/graphql']['subscriptions_count'] = 0
        self.client.update_graph_from_graphql_scan(self.recon_data, "u1", "p1")
        props = self._captured_endpoint_props()
        self.assertNotIn('graphql_subscriptions', props)
        self.assertEqual(props['graphql_subscriptions_count'], 0)


# ============================================================================
# §2.5 run_vuln_scan_isolated (thread-safe wrapper for Group 6 fan-out)
# ============================================================================

class TestRunVulnScanIsolated(unittest.TestCase):
    """Verifies the isolated wrapper deep-copies, skips incremental saves,
    and returns only the vuln_scan dict."""

    def _make_stub(self):
        """Return a patched run_vuln_scan that writes a marker to recon_data."""
        def fake_run_vuln_scan(recon_data, output_file=None, settings=None):
            recon_data['vuln_scan'] = {'findings': ['marker'], '_received_output_file': output_file}
            return recon_data
        return fake_run_vuln_scan

    def test_isolated_deep_copies_input(self):
        """Mutations inside run_vuln_scan must not touch the original dict."""
        with patch('recon.main_recon_modules.vuln_scan.run_vuln_scan', side_effect=self._make_stub()):
            from recon.main_recon_modules.vuln_scan import run_vuln_scan_isolated
            combined = {'domain': 'example.com', 'http_probe': {}}
            _ = run_vuln_scan_isolated(combined, {})
            self.assertNotIn('vuln_scan', combined, "original combined_result must not be mutated")

    def test_isolated_passes_output_file_none(self):
        """run_vuln_scan_isolated must skip incremental saves (output_file=None)."""
        with patch('recon.main_recon_modules.vuln_scan.run_vuln_scan', side_effect=self._make_stub()):
            from recon.main_recon_modules.vuln_scan import run_vuln_scan_isolated
            result = run_vuln_scan_isolated({'domain': 'example.com'}, {})
            self.assertIsNone(result['_received_output_file'])

    def test_isolated_returns_only_vuln_scan_key(self):
        with patch('recon.main_recon_modules.vuln_scan.run_vuln_scan', side_effect=self._make_stub()):
            from recon.main_recon_modules.vuln_scan import run_vuln_scan_isolated
            result = run_vuln_scan_isolated({'domain': 'example.com', 'http_probe': {}}, {})
            self.assertEqual(result, {'findings': ['marker'], '_received_output_file': None})

    def test_isolated_returns_empty_when_key_missing(self):
        """If run_vuln_scan doesn't add vuln_scan (e.g. Nuclei disabled early return),
        wrapper returns {} instead of raising."""
        def no_op(recon_data, output_file=None, settings=None):
            return recon_data
        with patch('recon.main_recon_modules.vuln_scan.run_vuln_scan', side_effect=no_op):
            from recon.main_recon_modules.vuln_scan import run_vuln_scan_isolated
            result = run_vuln_scan_isolated({'domain': 'example.com'}, {})
            self.assertEqual(result, {})


# ============================================================================
# §9.1.c _build_graphql_data_from_graph
# ============================================================================

class TestBuildGraphqlDataFromGraph(unittest.TestCase):
    """Verifies the graph builder assembles the exact shape graphql_scan reads:
    http_probe.by_url + resource_enum.endpoints + resource_enum.parameters + js_recon.findings."""

    def _mock_neo4j(self, baseurl_rows=None, endpoint_rows=None, parameter_rows=None, js_rows=None):
        """Build a Neo4jClient mock whose session.run returns the given rows per query."""
        client = MagicMock()
        client.verify_connection.return_value = True
        session = MagicMock()
        responses = [
            iter([MagicMock(__getitem__=lambda self, k, r=r: r[k]) for r in (baseurl_rows or [])]),
            iter([MagicMock(__getitem__=lambda self, k, r=r: r[k]) for r in (endpoint_rows or [])]),
            iter([MagicMock(__getitem__=lambda self, k, r=r: r[k]) for r in (parameter_rows or [])]),
            iter([MagicMock(__getitem__=lambda self, k, r=r: r[k]) for r in (js_rows or [])]),
        ]
        session.run.side_effect = responses
        client.driver.session.return_value.__enter__.return_value = session
        client.driver.session.return_value.__exit__.return_value = False
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        return client

    def _call_with(self, **rows):
        with patch('recon.partial_recon_modules.graph_builders.__import__', side_effect=ImportError), \
             patch.dict('sys.modules', {'graph_db': MagicMock()}):
            pass  # Just ensure import path; real test below uses patch directly

    def test_builder_returns_required_shape(self):
        """Empty graph → returns the canonical empty shape with all keys present."""
        with patch('recon.project_settings.get_settings', return_value={'ROE_ENABLED': False, 'ROE_EXCLUDED_HOSTS': []}), \
             patch('graph_db.Neo4jClient') as MockClient:
            mock_instance = self._mock_neo4j()
            MockClient.return_value = mock_instance

            from recon.partial_recon_modules.graph_builders import _build_graphql_data_from_graph
            result = _build_graphql_data_from_graph('example.com', 'u1', 'p1')

            self.assertEqual(result['domain'], 'example.com')
            self.assertIn('http_probe', result)
            self.assertIn('by_url', result['http_probe'])
            self.assertIn('resource_enum', result)
            self.assertIn('endpoints', result['resource_enum'])
            self.assertIn('parameters', result['resource_enum'])
            self.assertIn('js_recon', result)
            self.assertIn('findings', result['js_recon'])
            self.assertIn('metadata', result)
            self.assertIn('roe', result['metadata'])

    def test_builder_populates_roe_from_settings(self):
        """RoE settings flow through to metadata.roe for filter_by_roe()."""
        settings = {'ROE_ENABLED': True, 'ROE_EXCLUDED_HOSTS': ['*.excluded.com', 'specific.host']}
        with patch('recon.project_settings.get_settings', return_value=settings), \
             patch('graph_db.Neo4jClient') as MockClient:
            MockClient.return_value = self._mock_neo4j()

            from recon.partial_recon_modules.graph_builders import _build_graphql_data_from_graph
            result = _build_graphql_data_from_graph('example.com', 'u1', 'p1')

            self.assertTrue(result['metadata']['roe']['ROE_ENABLED'])
            self.assertEqual(result['metadata']['roe']['ROE_EXCLUDED_HOSTS'], ['*.excluded.com', 'specific.host'])

    def test_builder_handles_unreachable_neo4j(self):
        """If Neo4j unreachable, returns the empty skeleton without raising."""
        with patch('recon.project_settings.get_settings', return_value={'ROE_ENABLED': False, 'ROE_EXCLUDED_HOSTS': []}), \
             patch('graph_db.Neo4jClient') as MockClient:
            mock_instance = MagicMock()
            mock_instance.verify_connection.return_value = False
            mock_instance.__enter__.return_value = mock_instance
            mock_instance.__exit__.return_value = False
            MockClient.return_value = mock_instance

            from recon.partial_recon_modules.graph_builders import _build_graphql_data_from_graph
            result = _build_graphql_data_from_graph('example.com', 'u1', 'p1')
            # Should not raise; should return empty structure
            self.assertEqual(result['http_probe']['by_url'], {})
            self.assertEqual(result['resource_enum']['endpoints'], {})


# ============================================================================
# §9.1 run_graphqlscan (partial recon entry point)
# ============================================================================

class TestRunGraphqlscan(unittest.TestCase):
    """Verifies the partial-recon dispatch: graph targets, settings overrides,
    empty-target guard, graph update call."""

    def _base_config(self, **extra):
        cfg = {"tool_id": "GraphqlScan", "domain": "example.com", "include_graph_targets": True}
        cfg.update(extra)
        return cfg

    def _patch_env(self):
        os.environ['USER_ID'] = 'u1'
        os.environ['PROJECT_ID'] = 'p1'

    def _unpatch_env(self):
        for k in ('USER_ID', 'PROJECT_ID'):
            os.environ.pop(k, None)

    def test_force_enables_graphql_security_even_if_db_disabled(self):
        """Partial recon must force-enable the tool so the DB toggle can't block an explicit run."""
        self._patch_env()
        try:
            with patch('recon.project_settings.get_settings', return_value={'GRAPHQL_SECURITY_ENABLED': False}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph',
                       return_value={'domain': 'example.com', 'http_probe': {'by_url': {'https://x': {}}},
                                     'resource_enum': {'endpoints': {}, 'parameters': {}, 'discovered_urls': []},
                                     'js_recon': {'findings': []},
                                     'metadata': {'roe': {}}}), \
                 patch('recon.graphql_scan.run_graphql_scan') as mock_scan, \
                 patch('graph_db.Neo4jClient'):

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                run_graphqlscan(self._base_config())

                # scanner.run_graphql_scan got a settings dict with GRAPHQL_SECURITY_ENABLED=True
                mock_scan.assert_called_once()
                _, called_settings = mock_scan.call_args[0]
                self.assertTrue(called_settings.get('GRAPHQL_SECURITY_ENABLED'))
        finally:
            self._unpatch_env()

    def test_settings_overrides_applied(self):
        """Modal-checkbox overrides (config.settings_overrides) must bypass DB settings."""
        self._patch_env()
        try:
            with patch('recon.project_settings.get_settings', return_value={'GRAPHQL_CONCURRENCY': 5, 'GRAPHQL_RATE_LIMIT': 10}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph',
                       return_value={'domain': 'example.com', 'http_probe': {'by_url': {'https://x': {}}},
                                     'resource_enum': {'endpoints': {}, 'parameters': {}, 'discovered_urls': []},
                                     'js_recon': {'findings': []},
                                     'metadata': {'roe': {}}}), \
                 patch('recon.graphql_scan.run_graphql_scan') as mock_scan, \
                 patch('graph_db.Neo4jClient'):

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                cfg = self._base_config(settings_overrides={'GRAPHQL_RATE_LIMIT': 99, 'GRAPHQL_CONCURRENCY': 1})
                run_graphqlscan(cfg)

                _, called_settings = mock_scan.call_args[0]
                self.assertEqual(called_settings['GRAPHQL_RATE_LIMIT'], 99)
                self.assertEqual(called_settings['GRAPHQL_CONCURRENCY'], 1)
        finally:
            self._unpatch_env()

    def test_include_graph_false_starts_empty(self):
        """include_graph_targets=false must skip _build_graphql_data_from_graph
        and start with an empty recon_data."""
        self._patch_env()
        try:
            with patch('recon.project_settings.get_settings',
                       return_value={'GRAPHQL_ENDPOINTS': 'https://custom.target.com/graphql',
                                     'ROE_ENABLED': False, 'ROE_EXCLUDED_HOSTS': []}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph') as mock_builder, \
                 patch('recon.graphql_scan.run_graphql_scan') as mock_scan, \
                 patch('graph_db.Neo4jClient'):

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                cfg = self._base_config(include_graph_targets=False)
                run_graphqlscan(cfg)

                mock_builder.assert_not_called()
                # scanner got called with an empty-targets recon_data
                recon_data, _ = mock_scan.call_args[0]
                self.assertEqual(recon_data['http_probe']['by_url'], {})
                self.assertEqual(recon_data['resource_enum']['endpoints'], {})
        finally:
            self._unpatch_env()

    def test_no_targets_triggers_early_return(self):
        """Empty graph + empty GRAPHQL_ENDPOINTS setting → scanner not invoked."""
        self._patch_env()
        try:
            with patch('recon.project_settings.get_settings',
                       return_value={'GRAPHQL_ENDPOINTS': '', 'ROE_ENABLED': False, 'ROE_EXCLUDED_HOSTS': []}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph',
                       return_value={'domain': 'example.com',
                                     'http_probe': {'by_url': {}},
                                     'resource_enum': {'endpoints': {}, 'parameters': {}, 'discovered_urls': []},
                                     'js_recon': {'findings': []},
                                     'metadata': {'roe': {}}}), \
                 patch('recon.graphql_scan.run_graphql_scan') as mock_scan, \
                 patch('graph_db.Neo4jClient') as MockClient:

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                run_graphqlscan(self._base_config())

                mock_scan.assert_not_called()
                MockClient.assert_not_called()
        finally:
            self._unpatch_env()

    def test_successful_run_calls_graph_update(self):
        """When targets exist and scanner succeeds, the graph mixin is called."""
        self._patch_env()
        try:
            with patch('recon.project_settings.get_settings', return_value={'GRAPHQL_ENDPOINTS': ''}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph',
                       return_value={'domain': 'example.com',
                                     'http_probe': {'by_url': {'https://api.x.com': {}}},
                                     'resource_enum': {'endpoints': {}, 'parameters': {}, 'discovered_urls': []},
                                     'js_recon': {'findings': []},
                                     'metadata': {'roe': {}}}), \
                 patch('recon.graphql_scan.run_graphql_scan', return_value=None) as mock_scan, \
                 patch('graph_db.Neo4jClient') as MockClient:

                mock_client = MagicMock()
                mock_client.__enter__.return_value = mock_client
                mock_client.__exit__.return_value = False
                MockClient.return_value = mock_client

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                run_graphqlscan(self._base_config())

                mock_scan.assert_called_once()
                mock_client.update_graph_from_graphql_scan.assert_called_once()
                args, _ = mock_client.update_graph_from_graphql_scan.call_args
                self.assertEqual(args[1], 'u1')
                self.assertEqual(args[2], 'p1')
        finally:
            self._unpatch_env()

    def test_user_urls_merged_into_graphql_endpoints_setting(self):
        """user_targets.urls from modal -> settings.GRAPHQL_ENDPOINTS (comma-merged)."""
        self._patch_env()
        try:
            captured_settings = {}
            def capture(recon_data, settings):
                captured_settings.update(settings)
            with patch('recon.project_settings.get_settings',
                       return_value={'GRAPHQL_ENDPOINTS': ''}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph',
                       return_value={'domain': 'example.com',
                                     'http_probe': {'by_url': {}},
                                     'resource_enum': {'endpoints': {}, 'parameters': {}, 'discovered_urls': []},
                                     'js_recon': {'findings': []},
                                     'metadata': {'roe': {}}}), \
                 patch('recon.graphql_scan.run_graphql_scan', side_effect=capture), \
                 patch('graph_db.Neo4jClient') as MockClient:

                mock_client = MagicMock()
                mock_client.__enter__.return_value = mock_client
                mock_client.__exit__.return_value = False
                MockClient.return_value = mock_client

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                cfg = self._base_config(user_targets={
                    'urls': ['https://api.target.com/graphql', 'https://v1.target.com/graphql'],
                    'url_attach_to': None,
                })
                run_graphqlscan(cfg)

                merged = captured_settings.get('GRAPHQL_ENDPOINTS', '')
                self.assertIn('https://api.target.com/graphql', merged)
                self.assertIn('https://v1.target.com/graphql', merged)
        finally:
            self._unpatch_env()

    def test_user_urls_preserve_pre_existing_endpoints(self):
        """Existing GRAPHQL_ENDPOINTS setting is preserved when merging user URLs."""
        self._patch_env()
        try:
            captured_settings = {}
            def capture(recon_data, settings):
                captured_settings.update(settings)
            with patch('recon.project_settings.get_settings',
                       return_value={'GRAPHQL_ENDPOINTS': 'https://preset.target.com/graphql'}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph',
                       return_value={'domain': 'example.com',
                                     'http_probe': {'by_url': {}},
                                     'resource_enum': {'endpoints': {}, 'parameters': {}, 'discovered_urls': []},
                                     'js_recon': {'findings': []},
                                     'metadata': {'roe': {}}}), \
                 patch('recon.graphql_scan.run_graphql_scan', side_effect=capture), \
                 patch('graph_db.Neo4jClient') as MockClient:

                mock_client = MagicMock()
                mock_client.__enter__.return_value = mock_client
                mock_client.__exit__.return_value = False
                MockClient.return_value = mock_client

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                cfg = self._base_config(user_targets={
                    'urls': ['https://new.target.com/graphql'],
                    'url_attach_to': None,
                })
                run_graphqlscan(cfg)

                merged = captured_settings.get('GRAPHQL_ENDPOINTS', '')
                self.assertIn('https://preset.target.com/graphql', merged)
                self.assertIn('https://new.target.com/graphql', merged)
        finally:
            self._unpatch_env()

    def test_user_urls_generic_creates_user_input_node(self):
        """url_attach_to=None → creates a UserInput node for the URLs."""
        self._patch_env()
        try:
            with patch('recon.project_settings.get_settings',
                       return_value={'GRAPHQL_ENDPOINTS': ''}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph',
                       return_value={'domain': 'example.com',
                                     'http_probe': {'by_url': {}},
                                     'resource_enum': {'endpoints': {}, 'parameters': {}, 'discovered_urls': []},
                                     'js_recon': {'findings': []},
                                     'metadata': {'roe': {}}}), \
                 patch('recon.graphql_scan.run_graphql_scan', return_value=None), \
                 patch('graph_db.Neo4jClient') as MockClient:

                mock_client = MagicMock()
                mock_client.__enter__.return_value = mock_client
                mock_client.__exit__.return_value = False
                MockClient.return_value = mock_client

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                cfg = self._base_config(user_targets={
                    'urls': ['https://target.com/graphql'], 'url_attach_to': None,
                })
                run_graphqlscan(cfg)

                mock_client.create_user_input_node.assert_called_once()
                args, kwargs = mock_client.create_user_input_node.call_args
                payload = kwargs.get('user_input_data') or (args[1] if len(args) > 1 else {})
                self.assertEqual(payload['input_type'], 'url')
                self.assertEqual(payload['values'], ['https://target.com/graphql'])
                self.assertEqual(payload['tool_id'], 'GraphqlScan')
        finally:
            self._unpatch_env()

    def test_user_urls_with_attach_to_skips_user_input(self):
        """url_attach_to=BaseURL → no UserInput node (Endpoint nodes will attach to BaseURL)."""
        self._patch_env()
        try:
            with patch('recon.project_settings.get_settings',
                       return_value={'GRAPHQL_ENDPOINTS': ''}), \
                 patch('recon.partial_recon_modules.graphql_scanning._build_graphql_data_from_graph',
                       return_value={'domain': 'example.com',
                                     'http_probe': {'by_url': {}},
                                     'resource_enum': {'endpoints': {}, 'parameters': {}, 'discovered_urls': []},
                                     'js_recon': {'findings': []},
                                     'metadata': {'roe': {}}}), \
                 patch('recon.graphql_scan.run_graphql_scan', return_value=None), \
                 patch('graph_db.Neo4jClient') as MockClient:

                mock_client = MagicMock()
                mock_client.__enter__.return_value = mock_client
                mock_client.__exit__.return_value = False
                MockClient.return_value = mock_client

                from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
                cfg = self._base_config(user_targets={
                    'urls': ['https://target.com/graphql'],
                    'url_attach_to': 'https://api.target.com',
                })
                run_graphqlscan(cfg)

                mock_client.create_user_input_node.assert_not_called()
        finally:
            self._unpatch_env()



# ============================================================================
# Pipeline wiring (partial_recon.py dispatch)
# ============================================================================

class TestDispatcherWiring(unittest.TestCase):
    """Verifies partial_recon.main() dispatches GraphqlScan to run_graphqlscan."""

    def test_dispatcher_has_graphqlscan_branch(self):
        """Sanity check: inspecting main() source shows the new dispatch."""
        import inspect
        from partial_recon import main
        src = inspect.getsource(main)
        self.assertIn('GraphqlScan', src)
        self.assertIn('run_graphqlscan', src)

    def test_supported_tools_includes_graphqlscan_via_modules(self):
        """Imports must resolve — catches module-load regressions."""
        # These imports fail if graphql_scanning.py has a syntax error
        import recon.partial_recon_modules.graphql_scanning as _mod
        self.assertTrue(hasattr(_mod, 'run_graphqlscan'))
        self.assertTrue(callable(_mod.run_graphqlscan))


if __name__ == '__main__':
    unittest.main()
