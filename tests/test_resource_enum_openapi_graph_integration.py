"""OpenAPI declarations in a real Neo4j, written through update_graph_from_resource_enum.

Integration tier: needs NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD and skips
without them. It creates and deletes two fixture tenants, so run it only
against a disposable database, never a stack's own Neo4j:

    docker network create --internal oa-it
    docker run -d --rm --name oa-neo4j --network oa-it \\
      -e NEO4J_AUTH=neo4j/fixture-password neo4j:5.26-community
    docker run --rm --network oa-it -v "$PWD:/repo" -w /repo -e PYTHONPATH=/repo \\
      -e NEO4J_URI=bolt://oa-neo4j:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD=fixture-password \\
      --entrypoint python redamon-agent -m pytest -q -m integration \\
      tests/test_resource_enum_openapi_graph_integration.py

The by_base_url fixtures have the shape merge_openapi_into_by_base_url
produces (pinned by recon/tests/test_openapi_merge.py). The client applies the
production constraints before any write.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

pytestmark = pytest.mark.integration

A = ('fixture-user-a', 'fixture-project-a')
B = ('fixture-user-b', 'fixture-project-b')
BASE = 'https://api.example.com'
DOC = 'https://api.example.com/openapi.json'
DOC2 = 'https://api.example.com/v2/openapi.json'


def _neo4j_configured() -> bool:
    return bool(os.getenv('NEO4J_URI') and os.getenv('NEO4J_PASSWORD'))


def _entry(methods, sources, declared_only=None, openapi=None, params=None, **extra):
    entry = {'methods': list(methods), 'sources': list(sources), 'category': 'api',
             'parameters': params or {'query': [], 'body': [], 'path': []},
             'parameter_count': {'total': sum(len(v) for v in (params or {}).values())}}
    if declared_only is not None:
        entry['declared_only'] = declared_only
    if openapi is not None:
        entry['openapi'] = openapi
    entry.update(extra)
    return entry


def _declaration(doc=DOC):
    return {
        # Observed by a crawler; the specification also declares POST.
        '/orders': _entry(['GET', 'POST'], ['katana', 'openapi'], declared_only=False,
                          openapi={'POST': {'operation_id': 'createOrder', 'deprecated': False,
                                            'security': ['oauth2'], 'tags': ['orders'], 'spec_urls': [doc]}}),
        # Known only from the specification.
        '/users/7': _entry(['GET'], ['openapi'], declared_only=True,
                           openapi={'GET': {'operation_id': 'getUser', 'deprecated': True, 'security': [],
                                            'tags': ['users'], 'spec_urls': [doc]}},
                           params={'query': [], 'body': [], 'path': [
                               {'name': 'id', 'type': 'integer', 'category': 'other', 'required': True,
                                'sample_values': ['7']}]},
                           openapi_path_templates=['/users/{id}']),
        # The document itself, fetched by recon.
        '/openapi.json': _entry(['GET'], ['openapi'], declared_only=False,
                                openapi_spec={'version': '3.0.3', 'operation_count': 2}),
    }


@unittest.skipUnless(_neo4j_configured(), 'NEO4J_URI / NEO4J_PASSWORD not set (integration tier)')
class TestResourceEnumOpenApiGraph(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from graph_db import Neo4jClient
        cls.client = Neo4jClient()
        cls.driver = cls.client.driver
        with cls.driver.session() as session:
            constraints = session.run('SHOW CONSTRAINTS YIELD name RETURN count(name) AS n').single()['n']
        assert constraints > 0, 'production constraints were not applied'

    @classmethod
    def tearDownClass(cls):
        cls._wipe()
        cls.client.close()

    @classmethod
    def _wipe(cls):
        with cls.driver.session() as session:
            session.run('MATCH (n) WHERE n.user_id IN $users DETACH DELETE n',
                        users=[A[0], B[0]]).consume()
            session.run("MATCH (c:CVE {id: 'CVE-2099-0001'}) DETACH DELETE c").consume()

    def setUp(self):
        self._wipe()
        for uid, pid in (A, B):
            self._seed(uid, pid)

    def _run(self, query, **params):
        with self.driver.session() as session:
            return session.run(query, **params).data()

    def _seed(self, uid, pid):
        self._run('''
            MERGE (d:Domain {name: 'example.com', user_id: $u, project_id: $p})
            MERGE (s:Subdomain {name: 'api.example.com', user_id: $u, project_id: $p})
            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            MERGE (b:BaseURL {url: $base, user_id: $u, project_id: $p}) SET b.status_code = 200
            MERGE (s)-[:HAS_BASE_URL]->(b)
            MERGE (e:Endpoint {path: '/orders', method: 'GET', baseurl: $base, user_id: $u, project_id: $p})
              SET e.status_code = 200, e.sources = ['katana'], e.source = 'resource_enum', e.category = 'api'
            MERGE (b)-[:HAS_ENDPOINT]->(e)
            MERGE (t:Technology {name: 'nginx', version: '1.25', user_id: $u, project_id: $p})
            MERGE (b)-[:USES_TECHNOLOGY]->(t)
            MERGE (e)-[:USES_TECHNOLOGY]->(t)
            MERGE (c:CVE {id: 'CVE-2099-0001'})
            MERGE (t)-[:HAS_KNOWN_CVE]->(c)
            MERGE (v:Vulnerability {id: 'fixture-vuln-' + $p, user_id: $u, project_id: $p})
              SET v:Muted, v.stale_since = '2026-01-01T00:00:00Z', v.severity = 'high'
            MERGE (e)-[:HAS_VULNERABILITY]->(v)
            MERGE (v)-[:FOUND_AT]->(e)
            ''', u=uid, p=pid, base=BASE)

    def _import(self, by_base_url, tenant=A, status=None):
        recon_data = {'domain': 'example.com', 'subdomains': ['api.example.com'],
                      'resource_enum': {'by_base_url': by_base_url, 'forms': []}}
        if status is not None:
            recon_data['resource_enum']['openapi'] = {'source_status': status}
        stats = self.client.update_graph_from_resource_enum(recon_data, *tenant)
        self.assertEqual(stats['errors'], [])
        return stats

    def _snapshot(self, tenant):
        uid, pid = tenant
        nodes = self._run('MATCH (n {user_id: $u, project_id: $p}) '
                          'RETURN elementId(n) AS id, labels(n) AS labels, properties(n) AS props ORDER BY id',
                          u=uid, p=pid)
        rels = self._run('MATCH (a {user_id: $u, project_id: $p})-[r]->(b) '
                         'RETURN elementId(a) AS a, type(r) AS t, properties(r) AS props, elementId(b) AS b '
                         'ORDER BY a, t, b', u=uid, p=pid)
        return nodes, rels

    def _counts(self, tenant):
        uid, pid = tenant
        return self._run('MATCH (n {user_id: $u, project_id: $p}) WITH count(n) AS nodes '
                         'MATCH (a {user_id: $u, project_id: $p})-[r]-() '
                         'RETURN nodes, count(DISTINCT r) AS rels', u=uid, p=pid)[0]

    def _endpoint(self, path, method, tenant=A):
        rows = self._run('MATCH (e:Endpoint {path: $path, method: $m, baseurl: $base, user_id: $u, project_id: $p}) '
                         'RETURN properties(e) AS props', path=path, m=method, base=BASE, u=tenant[0], p=tenant[1])
        self.assertEqual(len(rows), 1, f'{method} {path} should exist exactly once')
        return rows[0]['props']

    # -- an endpoint a crawler observed keeps everything it had ------------

    def test_observed_endpoint_keeps_its_fields_relationships_and_mute(self):
        self._import({BASE: {'endpoints': _declaration()}})
        get_orders = self._endpoint('/orders', 'GET')
        self.assertEqual(get_orders['status_code'], 200)
        self.assertEqual(get_orders['category'], 'api')
        self.assertEqual(get_orders['sources'], ['katana', 'openapi'])
        self.assertIsNone(get_orders.get('openapi_declared_only'))
        rels = self._run('MATCH (e:Endpoint {path: "/orders", method: "GET", user_id: $u, project_id: $p})'
                         '-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:FOUND_AT]->(e) '
                         'RETURN labels(v) AS labels, v.stale_since AS stale', u=A[0], p=A[1])
        self.assertEqual(len(rels), 1)
        self.assertIn('Muted', rels[0]['labels'])
        self.assertEqual(rels[0]['stale'], '2026-01-01T00:00:00Z')
        tech = self._run('MATCH (:BaseURL {url: $base, user_id: $u, project_id: $p})-[:USES_TECHNOLOGY]->'
                         '(:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c.id AS id', base=BASE, u=A[0], p=A[1])
        self.assertEqual([r['id'] for r in tech], ['CVE-2099-0001'])
        used = self._run('MATCH (:Endpoint {path: "/orders", method: "GET", user_id: $u, project_id: $p})'
                         '-[:USES_TECHNOLOGY]->(t:Technology) RETURN t.name AS name', u=A[0], p=A[1])
        self.assertEqual([r['name'] for r in used], ['nginx'])

    def _reads_declared_only(self, path, method):
        """What every consumer sees: the D15 predicate, not the stored flag alone."""
        rows = self._run('MATCH (e:Endpoint {path: $path, method: $m, baseurl: $base, user_id: $u, project_id: $p}) '
                         'RETURN coalesce(e.openapi_declared_only, e.openapi_declared, false) AS d',
                         path=path, m=method, base=BASE, u=A[0], p=A[1])
        return rows[0]['d']

    def test_a_method_declared_on_an_observed_path_is_not_declared_only(self):
        # Found in the 6.3 lab: created in the same write as its declaration,
        # the node kept the flag unset and the predicate fell back to
        # openapi_declared, so an observed path read as declared-only.
        self._import({BASE: {'endpoints': _declaration()}})
        post_orders = self._endpoint('/orders', 'POST')
        self.assertTrue(post_orders['openapi_declared'])
        self.assertIs(post_orders['openapi_declared_only'], False)
        self.assertFalse(self._reads_declared_only('/orders', 'POST'))
        self.assertEqual(post_orders['openapi_operation_id'], 'createOrder')
        self.assertTrue(self._reads_declared_only('/users/7', 'GET'))
        self.assertFalse(self._reads_declared_only('/openapi.json', 'GET'))

    # -- an endpoint known only from the specification ---------------------

    def test_declared_only_endpoint_carries_sanitized_identifiers_only(self):
        self._import({BASE: {'endpoints': _declaration()}})
        user = self._endpoint('/users/7', 'GET')
        self.assertTrue(user['openapi_declared_only'])
        self.assertEqual(user['openapi_path_templates'], ['/users/{id}'])
        self.assertEqual(user['openapi_operation_id'], 'getUser')
        self.assertTrue(user['openapi_deprecated'])
        self.assertEqual(user['openapi_security'], [])
        self.assertEqual(user['openapi_tags'], ['users'])
        self.assertEqual(user['openapi_spec_urls'], [DOC])
        for retired in ('openapi_declarations', '_openapi_write_lock', 'summary', 'description'):
            self.assertNotIn(retired, user)
        params = self._run('MATCH (e:Endpoint {path: "/users/7", method: "GET", user_id: $u, project_id: $p})'
                           '-[:HAS_PARAMETER]->(q:Parameter) RETURN q.name AS name, q.position AS position, '
                           'q.sample_values AS values', u=A[0], p=A[1])
        self.assertEqual(params, [{'name': 'id', 'position': 'path', 'values': ['7']}])
        spec = self._endpoint('/openapi.json', 'GET')
        self.assertEqual((spec['openapi_spec'], spec['openapi_spec_version'], spec['openapi_operation_count']),
                         (True, '3.0.3', 2))
        self.assertIsNone(spec.get('openapi_declared_only'))

    def test_a_declaration_reaching_an_observed_endpoint_never_marks_it_declared_only(self):
        # A partial run merges into an empty by_base_url, so every entry it
        # writes says declared_only = True; the node already existed.
        self._import({BASE: {'endpoints': {'/orders': _entry(
            ['GET'], ['openapi'], declared_only=True,
            openapi={'GET': {'operation_id': 'listOrders', 'spec_urls': [DOC]}})}}})
        get_orders = self._endpoint('/orders', 'GET')
        self.assertFalse(get_orders['openapi_declared_only'])
        self.assertTrue(get_orders['openapi_declared'])

    def test_an_endpoint_an_earlier_release_declared_counts_as_declared_only_until_observed(self):
        self._run('MERGE (e:Endpoint {path: "/legacy", method: "POST", baseurl: $base, user_id: $u, project_id: $p}) '
                  'SET e.openapi_declared = true, e.openapi_declarations = "[]"', base=BASE, u=A[0], p=A[1])
        self._import({BASE: {'endpoints': {'/legacy': _entry(
            ['POST'], ['openapi'], declared_only=True, openapi={'POST': {'spec_urls': [DOC]}})}}})
        self.assertTrue(self._endpoint('/legacy', 'POST')['openapi_declared_only'])
        self._import({BASE: {'endpoints': {'/legacy': _entry(['POST'], ['katana'])}}})
        self.assertFalse(self._endpoint('/legacy', 'POST')['openapi_declared_only'])

    def test_a_crawler_observing_a_declared_only_endpoint_clears_the_flag(self):
        self._import({BASE: {'endpoints': _declaration()}})
        self._import({BASE: {'endpoints': {'/users/7': _entry(['GET'], ['katana'])}}})
        user = self._endpoint('/users/7', 'GET')
        self.assertFalse(user['openapi_declared_only'])
        self.assertTrue(user['openapi_declared'])
        self.assertEqual(user['openapi_operation_id'], 'getUser')

    def test_spec_urls_are_unioned_across_documents(self):
        self._import({BASE: {'endpoints': _declaration()}})
        self._import({BASE: {'endpoints': _declaration(DOC2)}})
        self.assertEqual(self._endpoint('/users/7', 'GET')['openapi_spec_urls'], [DOC, DOC2])

    # -- idempotency and tenancy -----------------------------------------

    def test_a_reimport_adds_no_node_and_no_relationship(self):
        self._import({BASE: {'endpoints': _declaration()}})
        first = self._counts(A)
        self._import({BASE: {'endpoints': _declaration()}})
        self.assertEqual(self._counts(A), first)

    def test_the_other_tenant_is_byte_identical_and_no_edge_crosses_tenants(self):
        before = self._snapshot(B)
        self._import({BASE: {'endpoints': _declaration()}}, status=['s|h|ok|t'])
        self.assertEqual(self._snapshot(B), before)
        crossing = self._run('MATCH (a)-[r]-(b) WHERE a.user_id IS NOT NULL AND b.user_id IS NOT NULL '
                             'AND (a.user_id <> b.user_id OR a.project_id <> b.project_id) '
                             'AND a.user_id IN $users RETURN count(r) AS n', users=[A[0], B[0]])
        self.assertEqual(crossing[0]['n'], 0)
        endpoints = self._run('MATCH (e:Endpoint {path: "/users/7"}) WHERE e.user_id IN $users '
                              'RETURN e.user_id AS u', users=[A[0], B[0]])
        self.assertEqual([r['u'] for r in endpoints], [A[0]])

    def test_source_status_is_written_and_replaced_on_the_runs_domain(self):
        # Filed under the run's scan root (here the org itself), since several
        # scan roots share one org Domain (21a4c69f; schema_sections.md).
        self._import({}, status=['src-1|0123456789ab|ok|2026-10-19T00:00:00Z'])
        rows = self._run('MATCH (d:Domain {name: "example.com", user_id: $u, project_id: $p}) '
                         'RETURN d.openapi_source_status AS s', u=A[0], p=A[1])
        self.assertEqual(rows[0]['s'], ['example.com|src-1|0123456789ab|ok|2026-10-19T00:00:00Z'])
        self._import({}, status=[])
        rows = self._run('MATCH (d:Domain {name: "example.com", user_id: $u, project_id: $p}) '
                         'RETURN d.openapi_source_status AS s', u=A[0], p=A[1])
        self.assertEqual(rows[0]['s'], [])
        other = self._run('MATCH (d:Domain {name: "example.com", user_id: $u, project_id: $p}) '
                          'RETURN d.openapi_source_status AS s', u=B[0], p=B[1])
        self.assertIsNone(other[0]['s'])


    # -- D17: a re-read specification that no longer declares an endpoint ---

    def _withdraw(self, reread, redeclared, started_before_import=False, started_at=None):
        from graph_db.mixins.base_mixin import run_timestamp
        return self.client.prune_withdrawn_openapi_declarations(
            *A, reread, started_at or run_timestamp(), redeclared)

    def _only_user(self, doc=DOC):
        return {'/users/7': _declaration(doc)['/users/7']}

    def test_a_dropped_declaration_is_deleted_with_its_orphan_parameter(self):
        self._import({BASE: {'endpoints': _declaration()}})
        stats = self._withdraw([DOC], {f'POST {BASE}/orders': [DOC]})
        self.assertEqual(stats, {'deleted': 1, 'withdrawn': 0})
        self.assertEqual(self._run('MATCH (e:Endpoint {path: "/users/7", user_id: $u, project_id: $p}) '
                                   'RETURN count(e) AS n', u=A[0], p=A[1])[0]['n'], 0)
        self.assertEqual(self._run('MATCH (q:Parameter {name: "id", position: "path", user_id: $u, project_id: $p}) '
                                   'RETURN count(q) AS n', u=A[0], p=A[1])[0]['n'], 0)
        # The observed endpoint the same document also declared is untouched.
        self.assertEqual(self._endpoint('/orders', 'POST')['openapi_spec_urls'], [DOC])

    def test_a_dropped_declaration_with_a_finding_is_kept_and_stops_being_declared(self):
        self._import({BASE: {'endpoints': self._only_user()}})
        self._run('MATCH (e:Endpoint {path: "/users/7", method: "GET", user_id: $u, project_id: $p}) '
                  'MERGE (v:Vulnerability {id: "fixture-d17", user_id: $u, project_id: $p}) '
                  'MERGE (e)-[:HAS_VULNERABILITY]->(v)', u=A[0], p=A[1])
        stats = self._withdraw([DOC], {})
        self.assertEqual(stats, {'deleted': 0, 'withdrawn': 1})
        user = self._endpoint('/users/7', 'GET')
        self.assertFalse(user['openapi_declared'])
        for gone in ('openapi_spec_urls', 'openapi_declared_only', 'openapi_operation_id', 'openapi_tags',
                     'openapi_path_templates', 'openapi_security', 'openapi_deprecated'):
            self.assertNotIn(gone, user)

    def test_a_failed_fetch_or_another_document_removes_nothing(self):
        self._import({BASE: {'endpoints': _declaration()}})
        before = self._counts(A)
        self.assertEqual(self._withdraw([], {}), {'deleted': 0, 'withdrawn': 0})
        self.assertEqual(self._withdraw([DOC2], {}), {'deleted': 0, 'withdrawn': 0})
        self.assertEqual(self._counts(A), before)
        self.assertTrue(self._endpoint('/users/7', 'GET')['openapi_declared_only'])

    def test_of_two_documents_the_one_that_dropped_it_loses_only_its_url(self):
        self._import({BASE: {'endpoints': self._only_user()}})
        self._import({BASE: {'endpoints': self._only_user(DOC2)}})
        stats = self._withdraw([DOC, DOC2], {f'GET {BASE}/users/7': [DOC2]})
        self.assertEqual(stats, {'deleted': 0, 'withdrawn': 1})
        user = self._endpoint('/users/7', 'GET')
        self.assertEqual(user['openapi_spec_urls'], [DOC2])
        self.assertTrue(user['openapi_declared_only'])

    def test_an_endpoint_this_run_wrote_is_never_deleted(self):
        from datetime import datetime, timedelta, timezone
        # A run starts well before it writes. Neo4j stamps updated_at to the
        # millisecond, so a start taken in the same millisecond as the write
        # would compare later than it and flake.
        started = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        self._import({BASE: {'endpoints': self._only_user()}})
        stats = self._withdraw([DOC], {}, started_at=started)
        self.assertEqual(stats, {'deleted': 0, 'withdrawn': 1})
        self.assertFalse(self._endpoint('/users/7', 'GET')['openapi_declared'])

if __name__ == '__main__':
    unittest.main()
