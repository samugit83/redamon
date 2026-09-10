"""Real-Neo4j integration coverage for OpenAPI graph ingestion.

Set OPENAPI_TEST_NEO4J_URI to an explicitly disposable Neo4j instance. The test
uses generated tenant IDs and deletes only nodes carrying those IDs.
"""

import json
import os
import sys
import unittest
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

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.driver.session() as session:
                session.run(
                    """
                    MATCH (n)
                    WHERE n.project_id = $project_id
                      AND n.user_id IN $user_ids
                    DETACH DELETE n
                    """,
                    project_id=cls.project_id,
                    user_ids=[cls.user_id, cls.other_user_id],
                ).consume()
        finally:
            cls.driver.close()

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
                      -[:HAS_BASEURL]->
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
