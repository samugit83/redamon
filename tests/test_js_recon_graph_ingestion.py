import hashlib
import os
import sys
import unittest
from unittest.mock import MagicMock


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin


class FakeSession:
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.calls = []
        self.endpoint_created = endpoint_created
        self.endpoint_linked = endpoint_linked

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        if "RETURN created AS created" in query:
            return FakeResult({"created": self.endpoint_created})
        if "RETURN count(r) AS linked" in query:
            return FakeResult({"linked": 1 if self.endpoint_linked else 0})
        return FakeResult({"enriched": 0})


class FakeResult:
    def __init__(self, record):
        self.record = record

    def single(self):
        return self.record


class FakeDriver:
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.session_obj = FakeSession(
            endpoint_created=endpoint_created,
            endpoint_linked=endpoint_linked,
        )

    def session(self):
        return self.session_obj


class GraphClient(JsReconMixin):
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.driver = FakeDriver(
            endpoint_created=endpoint_created,
            endpoint_linked=endpoint_linked,
        )


class TestJsReconGraphIngestion(unittest.TestCase):
    def test_only_confirmed_dead_endpoints_are_dropped_with_validation_metadata_and_id(self):
        client = GraphClient()
        recon_data = {
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-05-28T00:00:00Z"},
                "endpoints": [
                    {
                        "path": "/api/live",
                        "method": "POST",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "full_url": "https://example.com/api/live",
                        "validation_status": "hittable",
                        "status_code": 200,
                        "resolved_url": "https://example.com/api/live",
                    },
                    {
                        "path": "/api/dead",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "validation_status": "not_hittable",
                    },
                    {
                        "path": "/api/unknown",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                    },
                ],
            },
        }

        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")

        endpoint_calls = [
            kwargs for query, kwargs in client.driver.session_obj.calls
            if "MERGE (e:Endpoint" in query
        ]
        ingested_paths = {kwargs["path"] for kwargs in endpoint_calls}
        # 'hittable' and the un-probed 'unknown' endpoint are ingested; only the
        # probe-confirmed 'not_hittable' endpoint is dropped.
        self.assertEqual(stats["endpoints_created"], 2)
        self.assertEqual(ingested_paths, {"/api/live", "/api/unknown"})
        self.assertNotIn("/api/dead", ingested_paths)

        live_call = next(k for k in endpoint_calls if k["path"] == "/api/live")
        expected_hash = hashlib.sha256(
            "https://example.com:POST:/api/live".encode()
        ).hexdigest()[:16]
        self.assertEqual(live_call["id"], f"endpoint-u1-p1-js-{expected_hash}")
        self.assertEqual(live_call["validation_status"], "hittable")
        self.assertEqual(live_call["status_code"], 200)
        self.assertEqual(live_call["resolved_url"], "https://example.com/api/live")
        link_calls = [
            (query, kwargs) for query, kwargs in client.driver.session_obj.calls
            if "MERGE (file)-[r:HAS_ENDPOINT]->(n)" in query
        ]
        self.assertEqual(len(link_calls), 2)
        self.assertIn("MATCH (n:Endpoint {path: $path, method: $method, baseurl: $baseurl", link_calls[0][0])
        self.assertNotIn("MATCH (n:Endpoint {id: $nid})", link_calls[0][0])
        self.assertEqual(stats["errors"], [])

    def test_existing_endpoint_and_unmatched_file_link_do_not_increment_counts(self):
        client = GraphClient(endpoint_created=False, endpoint_linked=False)
        recon_data = {
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-05-28T00:00:00Z"},
                "endpoints": [
                    {
                        "path": "/api/live",
                        "method": "POST",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "full_url": "https://example.com/api/live",
                        "validation_status": "hittable",
                        "status_code": 200,
                        "resolved_url": "https://example.com/api/live",
                    },
                ],
            },
        }

        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")

        self.assertEqual(stats["endpoints_created"], 0)
        # The endpoint is now linked to its BaseURL at write time, in addition
        # to the JS-file relationship.
        self.assertEqual(stats["relationships_created"], 2)
        link_calls = [
            (query, kwargs) for query, kwargs in client.driver.session_obj.calls
            if "MERGE (file)-[r:HAS_ENDPOINT]->(n)" in query
        ]
        self.assertEqual(len(link_calls), 1)
        self.assertEqual(stats["errors"], [])

    def test_unvalidated_endpoints_are_ingested_when_probing_is_off(self):
        # With endpoint probing disabled (the default), every endpoint is tagged
        # 'unvalidated'. These must still reach the graph — disabling probing keeps
        # the prior "ingest every extracted endpoint" behavior.
        client = GraphClient()
        recon_data = {
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-05-28T00:00:00Z"},
                "endpoints": [
                    {
                        "path": "/api/a",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "validation_status": "unvalidated",
                        "validation_error": "validation_disabled",
                    },
                    {
                        "path": "/api/b",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "validation_status": "unvalidated",
                        "validation_error": "validation_disabled",
                    },
                ],
            },
        }

        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")

        endpoint_calls = [
            kwargs for query, kwargs in client.driver.session_obj.calls
            if "MERGE (e:Endpoint" in query
        ]
        self.assertEqual(stats["endpoints_created"], 2)
        self.assertEqual({k["path"] for k in endpoint_calls}, {"/api/a", "/api/b"})
        self.assertEqual(stats["errors"], [])


class TestJsReconFindingPackageFields(unittest.TestCase):
    """package_name / package_version on JsReconFinding nodes.

    The JS Dep Signals table has had Package and Version columns since it was
    written, reading `name` and `version` - properties nothing ever set, so both
    columns rendered empty on every row. They are written under a `package_`
    prefix because `name` is what the graph viewer displays as the node label
    (format.ts falls back to `title` only when `name` is absent), so using it
    would relabel every framework node from "React 18.2.0" to "React".
    """

    @staticmethod
    def _finding_props(client, finding_type):
        for query, kwargs in client.driver.session_obj.calls:
            if "MERGE (jf:JsReconFinding" not in query:
                continue
            props = kwargs.get("props") or {}
            if props.get("finding_type") == finding_type:
                return props
        return None

    def test_dependency_confusion_carries_the_package_name(self):
        client = GraphClient()
        client.update_graph_from_js_recon({
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-08-07T00:00:00Z"},
                "dependencies": [{
                    "id": "dep1",
                    "finding_type": "dependency_confusion",
                    "package_name": "@acme/internal-utils",
                    "severity": "critical",
                    "title": "Dependency confusion: @acme/internal-utils not on public npm",
                    "source_url": "https://example.com/app.js",
                }],
            },
        }, "u1", "p1")
        props = self._finding_props(client, "dependency_confusion")
        self.assertIsNotNone(props)
        self.assertEqual(props["package_name"], "@acme/internal-utils")
        # `name` stays unset so the graph node label keeps using `title`.
        self.assertNotIn("name", props)

    def test_framework_carries_name_and_version_separately_from_the_label(self):
        client = GraphClient()
        client.update_graph_from_js_recon({
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-08-07T00:00:00Z"},
                "frameworks": [{
                    "id": "fw1", "name": "React", "version": "18.2.0",
                    "source_url": "https://example.com/app.js",
                }],
            },
        }, "u1", "p1")
        props = self._finding_props(client, "framework")
        self.assertIsNotNone(props)
        self.assertEqual(props["package_name"], "React")
        self.assertEqual(props["package_version"], "18.2.0")
        self.assertEqual(props["title"], "React 18.2.0")
        self.assertNotIn("name", props)


class TestJsReconEndpointOwnership(unittest.TestCase):
    def _recon_data(self, endpoints, metadata=None):
        return {
            "domain": "example.com",
            "subdomains": ["app.example.com"],
            "metadata": metadata or {},
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-09-18T00:00:00Z"},
                "endpoints": endpoints,
            },
        }

    def test_absolute_endpoint_uses_its_origin_and_links_the_owner(self):
        client = GraphClient()
        stats = client.update_graph_from_js_recon(self._recon_data([
            {
                "path": "/api/me",
                "full_url": "https://app.example.com:443/api/me",
                "base_url": "https://app.example.com:443",
                "method": "GET",
                "source_js": "https://app.example.com/app.js",
            },
            {
                "path": "/lib",
                "full_url": "https://cdn.thirdparty.test/lib",
                "method": "GET",
                "source_js": "https://app.example.com/app.js",
            },
        ]), "u1", "p1")

        endpoint_calls = [
            kwargs for query, kwargs in client.driver.session_obj.calls
            if "MERGE (e:Endpoint" in query
        ]
        self.assertEqual([call["baseurl"] for call in endpoint_calls], ["https://app.example.com"])
        self.assertEqual(stats["endpoints_created"], 1)
        self.assertEqual(stats["skipped_out_of_scope"], 1)

        owner_calls = [
            (query, kwargs) for query, kwargs in client.driver.session_obj.calls
            if "MERGE (bu:BaseURL" in query
        ]
        self.assertEqual(len(owner_calls), 1)
        self.assertIn("MERGE (bu)-[:HAS_ENDPOINT]->(e)", owner_calls[0][0])
        self.assertEqual(owner_calls[0][1]["base_url"], "https://app.example.com")

    def test_partial_target_metadata_keeps_a_new_subdomain_in_scope(self):
        client = GraphClient()
        stats = client.update_graph_from_js_recon(
            self._recon_data([
                {
                    "path": "/api/me",
                    "full_url": "https://new.example.com/api/me",
                    "method": "GET",
                    "source_js": "https://new.example.com/app.js",
                },
            ], metadata={"js_recon_target_hosts": ["https://new.example.com/start"]}),
            "u1",
            "p1",
        )

        self.assertEqual(stats["endpoints_created"], 1)
        self.assertEqual(stats["skipped_out_of_scope"], 0)


if __name__ == "__main__":
    unittest.main()
