"""Real-Neo4j integration coverage for OpenAPI graph ingestion.

Set OPENAPI_TEST_NEO4J_URI to an explicitly disposable Neo4j instance. The test
uses generated tenant IDs and deletes only nodes carrying those IDs.
"""

import json
import os
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

_NEO4J_URI = os.environ.get("OPENAPI_TEST_NEO4J_URI")


def _operation(method, source_id, summary, host="api.example.com"):
    return {
        "baseurl": f"https://{host}",
        "path": "/v1/widgets/{id}",
        "method": method,
        "source_url": "https://docs.example.com/openapi.json",
        "source_id": source_id,
        "document_hash": source_id,
        "operation_ref": f"#/paths/~1v1~1widgets~1{{id}}/{method.lower()}",
        "operation": {
            "operationId": f"{method.lower()}Widget",
            "summary": summary,
            "parameters": [{"name": "id", "in": "path", "required": True}],
            "responses": {"200": {"description": "OK"}},
        },
    }


def _recon(operations):
    return {
        "domain": "example.com",
        "openapi": {
            "operations": operations,
            "documents": [{
                "url": "https://docs.example.com/openapi.json",
                "source_id": "a" * 64,
                "sha256": "a" * 64,
                "version": "3.1.0",
                "operation_count": len(operations),
            }],
            "diagnostics": [],
            "scope": {
                "root": "example.com",
                "hosts": [],
                "include_subdomains": True,
                "include_root": True,
                "ip_networks": [],
                "excluded_hosts": ["blocked.example.com"],
            },
        },
    }


@unittest.skipUnless(
    _NEO4J_URI,
    "OPENAPI_TEST_NEO4J_URI is required and must point to disposable Neo4j",
)
class TestOpenApiGraphIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from neo4j import GraphDatabase

        from graph_db.mixins.recon.openapi_mixin import OpenApiMixin

        cls.driver = GraphDatabase.driver(_NEO4J_URI, auth=None)
        cls.driver.verify_connectivity()
        cls.client = OpenApiMixin()
        cls.client.driver = cls.driver
        suffix = uuid4().hex
        cls.user_id = f"openapi-it-user-{suffix}"
        cls.other_user_id = f"openapi-it-other-{suffix}"
        cls.project_id = f"openapi-it-project-{suffix}"
        cls.other_project_id = f"openapi-it-other-project-{suffix}"

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.driver.session() as session:
                session.run(
                    """
                    MATCH (n)
                    WHERE n.project_id IN $project_ids
                      AND n.user_id IN $user_ids
                    DETACH DELETE n
                    """,
                    project_ids=[cls.project_id, cls.other_project_id],
                    user_ids=[cls.user_id, cls.other_user_id],
                ).consume()
        finally:
            cls.driver.close()

    def test_relationship_counters_match_graph_changes_and_repeat_is_zero(self):
        payload = _recon([_operation("GET", "counters", "Count", "counters.example.com"),
                          _operation("POST", "counters", "Count", "counters.example.com")])

        def count_relationships():
            with self.driver.session() as session:
                return session.run(
                    "MATCH (n {user_id: $user_id, project_id: $project_id})-[r]->() "
                    "RETURN count(r) AS count", user_id=self.user_id,
                    project_id=self.project_id,
                ).single()["count"]

        before = count_relationships()
        first = self.client.update_graph_from_openapi(payload, self.user_id, self.project_id)
        self.assertEqual(first["errors"], [])
        self.assertEqual(first["relationships_created"], count_relationships() - before)
        self.assertEqual(first["relationships_created"], 5)
        second = self.client.update_graph_from_openapi(payload, self.user_id, self.project_id)
        self.assertEqual(second["errors"], [])
        self.assertEqual(second["relationships_created"], 0)

    def test_ip_import_reuses_pipeline_mock_subdomain(self):
        domain = f"ip-targets.{self.project_id}"
        with self.driver.session() as session:
            session.run(
                "CREATE (:Subdomain {name: '192-0-2-10', user_id: $user_id, "
                "project_id: $project_id, source: 'dns'})",
                user_id=self.user_id, project_id=self.project_id,
            ).consume()
        payload = _recon([_operation("GET", "ip-spec", "IP", "192.0.2.10")])
        payload["domain"] = domain
        payload["openapi"]["scope"] = {
            "root": "", "hosts": [], "include_subdomains": False,
            "include_root": False, "ip_networks": ["192.0.2.0/24"], "excluded_hosts": [],
        }
        stats = self.client.update_graph_from_openapi(payload, self.user_id, self.project_id)
        self.assertEqual(stats["errors"], [])
        with self.driver.session() as session:
            rows = list(session.run(
                "MATCH (s:Subdomain {user_id: $user_id, project_id: $project_id}) "
                "WHERE s.name IN ['192-0-2-10', '192.0.2.10'] "
                "OPTIONAL MATCH (s)-[:HAS_BASE_URL]->(b:BaseURL) "
                "RETURN s.name AS name, s.source AS source, b.url AS url",
                user_id=self.user_id, project_id=self.project_id,
            ))
        self.assertEqual([dict(row) for row in rows], [{
            "name": "192-0-2-10", "source": "dns", "url": "https://192.0.2.10",
        }])

    def test_concurrent_partial_summaries_preserve_sources_and_refresh_diagnostics(self):
        domain = "summary.example.com"

        def payload_for(index, version="3.0.0"):
            payload = _recon([])
            payload["domain"] = domain
            payload["openapi"]["scope"]["root"] = domain
            payload["openapi"]["documents"] = [{
                "url": "https://docs.example.com/same.json", "source_id": f"source-{index}",
                "version": version,
            }]
            return payload

        seed = payload_for(0)
        seed["openapi"]["diagnostics"] = [{
            "url": "https://unrelated.example.com/spec.json", "code": "fetch_failed",
            "message": "HTTP 404",
        }, {"url": "https://docs.example.com/same.json", "code": "old_error"}]
        self.assertEqual(self.client.update_graph_from_openapi(
            seed, self.user_id, self.project_id)["errors"], [])

        def import_source(index):
            return self.client.update_graph_from_openapi(
                payload_for(index), self.user_id, self.project_id)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(import_source, range(1, 9)))
        self.assertTrue(all(not result["errors"] for result in results), results)
        for _ in range(2):
            self.assertEqual(self.client.update_graph_from_openapi(
                payload_for(3, "3.1.1"), self.user_id, self.project_id)["errors"], [])
        with self.driver.session() as session:
            record = session.run(
                "MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id}) "
                "RETURN d.openapi_summary AS summary", domain=domain,
                user_id=self.user_id, project_id=self.project_id,
            ).single()
        summary = json.loads(record["summary"])
        self.assertEqual(len(summary["documents"]), 9)
        self.assertEqual({item["source_id"]: item["version"] for item in summary["documents"]},
                         {f"source-{i}": "3.1.1" if i == 3 else "3.0.0" for i in range(9)})
        self.assertEqual(summary["diagnostics"], [seed["openapi"]["diagnostics"][0]])

    def test_existing_service_path_does_not_gain_a_subdomain_fallback(self):
        self._assert_service_linking("service.example.com", self.user_id, False)

    def test_another_users_service_does_not_suppress_the_fallback(self):
        self._assert_service_linking("other-user.example.com", self.other_user_id, True)

    def test_another_projects_service_does_not_suppress_the_fallback(self):
        self._assert_service_linking("other-project.example.com", self.user_id, True,
                                     self.other_project_id)

    def _assert_service_linking(self, host, service_user, expect_fallback, service_project=None):
        service_project = service_project or self.project_id
        baseurl = f"https://{host}"
        with self.driver.session() as session:
            session.run(
                """
                CREATE (svc:Service {name: 'https', port_number: 443,
                                    ip_address: '192.0.2.10',
                                    user_id: $service_user, project_id: $service_project})
                CREATE (b:BaseURL {url: $baseurl, user_id: $user_id,
                                  project_id: $project_id})
                CREATE (svc)-[:SERVES_URL]->(b)
                """,
                service_user=service_user, service_project=service_project, user_id=self.user_id,
                project_id=self.project_id, baseurl=baseurl,
            ).consume()
        payload = _recon([_operation("GET", "service-spec", "Declared operation", host)])
        for iteration in range(2):
            stats = self.client.update_graph_from_openapi(payload, self.user_id, self.project_id)
            self.assertEqual(stats["errors"], [])
            self.assertEqual(stats["operations_imported"], 1)
            self.assertEqual(stats["relationships_created"],
                             3 + int(expect_fallback) if iteration == 0 else 0)
        with self.driver.session() as session:
            row = session.run(
                """
                MATCH (b:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                OPTIONAL MATCH (svc:Service {user_id: $service_user, project_id: $service_project})
                               -[serves:SERVES_URL]->(b)
                OPTIONAL MATCH (s:Subdomain {name: $host, user_id: $user_id,
                                            project_id: $project_id})-[fallback:HAS_BASE_URL]->(b)
                OPTIONAL MATCH (b)-[:HAS_ENDPOINT]->(e:Endpoint {user_id: $user_id,
                                                               project_id: $project_id})
                RETURN count(DISTINCT serves) AS services, count(DISTINCT fallback) AS fallbacks,
                       count(DISTINCT e) AS endpoints
                """,
                baseurl=baseurl, host=host, user_id=self.user_id,
                service_user=service_user, service_project=service_project, project_id=self.project_id,
            ).single()
        self.assertEqual(row["services"], 1)
        self.assertEqual(row["fallbacks"], int(expect_fallback))
        self.assertEqual(row["endpoints"], 1)

    def test_idempotent_tenant_scoped_declarations_form_a_coherent_host_chain(self):
        endpoint_key = {
            "path": "/v1/widgets/{id}",
            "method": "GET",
            "baseurl": "https://api.example.com",
            "user_id": self.user_id,
            "project_id": self.project_id,
        }
        with self.driver.session() as session:
            session.run(
                """
                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl,
                                   user_id: $user_id, project_id: $project_id})
                SET e.source = 'resource_enum', e.category = 'api', e.updated_at = datetime()
                """,
                **endpoint_key,
            ).consume()
            session.run(
                """
                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl,
                                   user_id: $user_id, project_id: $project_id})
                SET e.source = 'http_probe', e.marker = 'other-tenant', e.updated_at = datetime()
                """,
                **{**endpoint_key, "user_id": self.other_user_id},
            ).consume()

        first = _recon([
            _operation("GET", "a" * 64, "Initial GET"),
            _operation("POST", "a" * 64, "Create widget"),
            _operation("GET", "a" * 64, "Must be excluded", "blocked.example.com"),
        ])
        first_stats = self.client.update_graph_from_openapi(
            first, self.user_id, self.project_id,
        )
        self.assertEqual(first_stats["operations_imported"], 2)
        self.assertEqual(first_stats["skipped_out_of_scope"], 1)

        repeated = _recon([
            _operation("GET", "a" * 64, "Updated GET"),
            _operation("GET", "b" * 64, "Second document"),
        ])
        self.client.update_graph_from_openapi(repeated, self.user_id, self.project_id)
        self.client.update_graph_from_openapi(repeated, self.user_id, self.project_id)

        with self.driver.session() as session:
            rows = list(session.run(
                """
                MATCH (d:Domain {name: 'example.com', user_id: $user_id, project_id: $project_id})
                      -[:HAS_SUBDOMAIN]->
                      (s:Subdomain {name: 'api.example.com', user_id: $user_id, project_id: $project_id})
                      -[:HAS_BASE_URL]->
                      (b:BaseURL {url: 'https://api.example.com', user_id: $user_id, project_id: $project_id})
                      -[:HAS_ENDPOINT]->
                      (e:Endpoint {user_id: $user_id, project_id: $project_id})
                RETURN e.method AS method, e.source AS source, e.category AS category,
                       e.openapi_declarations AS declarations,
                       e._openapi_write_lock AS transient_lock
                ORDER BY method
                """,
                user_id=self.user_id,
                project_id=self.project_id,
            ))
            excluded_count = session.run(
                """
                MATCH (n {user_id: $user_id, project_id: $project_id})
                WHERE n.host = 'blocked.example.com' OR n.name = 'blocked.example.com'
                   OR n.url STARTS WITH 'https://blocked.example.com'
                RETURN count(n) AS count
                """,
                user_id=self.user_id,
                project_id=self.project_id,
            ).single()["count"]
            other = session.run(
                """
                MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl,
                                   user_id: $user_id, project_id: $project_id})
                RETURN e.source AS source, e.marker AS marker,
                       e.openapi_declarations AS declarations
                """,
                **{**endpoint_key, "user_id": self.other_user_id},
            ).single()

        self.assertEqual([row["method"] for row in rows], ["GET", "POST"])
        get_row = rows[0]
        self.assertEqual(get_row["source"], "resource_enum")
        self.assertEqual(get_row["category"], "api")
        self.assertIsNone(get_row["transient_lock"])
        declarations = json.loads(get_row["declarations"])
        self.assertEqual(len(declarations), 2)
        self.assertEqual(
            {item["operation"]["summary"] for item in declarations},
            {"Updated GET", "Second document"},
        )
        self.assertEqual(rows[1]["source"], "openapi")
        self.assertEqual(excluded_count, 0)
        self.assertEqual(other["source"], "http_probe")
        self.assertEqual(other["marker"], "other-tenant")
        self.assertIsNone(other["declarations"])


if __name__ == "__main__":
    unittest.main()
