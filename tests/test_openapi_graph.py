"""OpenAPI declaration ingestion into the tenant-scoped recon graph."""

import json
import os
import re
import sys
import unittest
from unittest.mock import MagicMock


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.openapi_mixin import OpenApiMixin  # noqa: E402
from graph_db.mixins.recon.openapi_scope import Scope  # noqa: E402


class _Result:
    def __init__(self, record=None):
        self._record = record

    def single(self):
        return self._record


class _Session:
    def __init__(self):
        self.queries = []
        self.declarations = {}
        self.fail_endpoint_write = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    @staticmethod
    def _key(kwargs):
        return (
            kwargs["baseurl"],
            kwargs["path"],
            kwargs["method"],
            kwargs["user_id"],
            kwargs["project_id"],
        )

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if "RETURN e.openapi_declarations AS declarations" in query:
            value = self.declarations.get(self._key(kwargs))
            return _Result({"declarations": value} if value is not None else None)
        if "SET e.openapi_declarations = $openapi_declarations" in query:
            if self.fail_endpoint_write:
                raise RuntimeError("simulated write failure")
            self.declarations[self._key(kwargs)] = kwargs["openapi_declarations"]
        return _Result({"count": 1})

    def execute_write(self, callback, *args):
        return callback(self, *args)


class _Driver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class _Client(OpenApiMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = _Driver(self.session)


def _operation(*, method="GET", source_url="https://docs.example.test/openapi.json",
               source_id="source-a", summary="List widgets",
               baseurl="https://api.example.test", operation_ref=None,
               path="/v2/widgets/{id}"):
    return {
        "baseurl": baseurl,
        "path": path,
        "method": method,
        "source_url": source_url,
        "source_id": source_id,
        "document_hash": "a" * 64,
        "operation_ref": operation_ref or f"#/paths/~1v2~1widgets~1{{id}}/{method.lower()}",
        "operation": {
            "operationId": f"{method.lower()}Widget",
            "summary": summary,
            "parameters": [{"name": "id", "in": "path", "required": True}],
            "responses": {"200": {"description": "OK"}},
        },
    }


def _payload(operations, scope=None):
    return {
        "openapi": {
            "operations": operations,
            "documents": [{
                "url": "https://docs.example.test/openapi.json",
                "source_id": "source-a",
                "sha256": "a" * 64,
                "version": "3.1.0",
                "operation_count": len(operations),
            }],
            "diagnostics": [{
                "url": "https://docs.example.test/missing.json",
                "code": "fetch_failed",
                "message": "HTTP 404",
            }],
            "scope": scope or {
                "root": "example.test",
                "hosts": [],
                "include_subdomains": True,
                "include_root": True,
                "ip_networks": [],
                "excluded_hosts": [],
            },
        }
    }


class TestOpenApiScope(unittest.TestCase):
    def test_domain_scope_uses_suffix_boundaries_and_exclusions(self):
        scope = Scope.from_payload({
            "root": "example.test",
            "hosts": [],
            "include_subdomains": True,
            "include_root": False,
            "ip_networks": [],
            "excluded_hosts": ["private.example.test"],
        })

        self.assertTrue(scope.allows("https://api.example.test/v1"))
        self.assertFalse(scope.allows("https://example.test/v1"))
        self.assertFalse(scope.allows("https://evil-example.test/v1"))
        self.assertFalse(scope.allows("https://private.example.test/v1"))
        self.assertFalse(scope.allows("https://child.private.example.test/v1"))

    def test_exact_hosts_and_ip_networks_are_round_trip_stable(self):
        domain_payload = {
            "root": "example.test",
            "hosts": ["API.EXAMPLE.TEST."],
            "include_subdomains": False,
            "include_root": False,
            "ip_networks": [],
            "excluded_hosts": ["private.example.test"],
        }
        scope = Scope.from_payload(domain_payload)

        self.assertEqual(scope.root, "example.test")
        self.assertTrue(scope.allows("https://api.example.test/resource"))
        self.assertEqual(Scope.from_payload(scope.to_payload()).to_payload(), scope.to_payload())

        ip_scope = Scope.from_payload({
            "root": "", "hosts": [], "include_subdomains": False,
            "include_root": False, "ip_networks": ["192.0.2.0/28"],
            "excluded_hosts": ["192.0.2.8/30"],
        })
        self.assertTrue(ip_scope.allows("http://192.0.2.4:8080/resource"))
        self.assertFalse(ip_scope.allows("http://192.0.2.9/resource"))
        self.assertEqual(
            Scope.from_payload(ip_scope.to_payload()).to_payload(), ip_scope.to_payload(),
        )

    def test_missing_or_invalid_scope_fails_closed(self):
        valid_shape = {
            "root": "example.test", "hosts": [], "include_subdomains": True,
            "include_root": True, "ip_networks": [], "excluded_hosts": [],
        }
        malformed = []
        for field, value in (
            ("root", "https://example.test/path"),
            ("root", "example.test:443"),
            ("hosts", ["api.example.test/path"]),
            ("hosts", ["api.example.test?role=admin"]),
            ("excluded_hosts", ["https://private.example.test"]),
        ):
            malformed.append({**valid_shape, field: value})
        for payload in (None, {}, {"root": [], "ip_networks": []}, {
            "root": "", "hosts": [], "include_subdomains": False,
            "include_root": False, "ip_networks": [], "excluded_hosts": [],
        }, *malformed):
            with self.subTest(payload=payload):
                self.assertFalse(Scope.from_payload(payload).allows(
                    "https://api.example.test/resource"))

    def test_raw_ipv6_is_a_valid_exact_host_token_in_ip_scope(self):
        scope = Scope.from_payload({
            "root": "", "hosts": ["2001:db8::10"],
            "include_subdomains": False, "include_root": False,
            "ip_networks": ["2001:db8::/32"], "excluded_hosts": [],
        })

        self.assertTrue(scope.is_valid)
        self.assertTrue(scope.allows("https://[2001:db8::10]/v1"))

    def test_exact_hosts_cannot_expand_domain_or_mix_domain_and_ip_scope(self):
        base = {
            "root": "example.test", "hosts": [], "include_subdomains": False,
            "include_root": False, "ip_networks": [], "excluded_hosts": [],
        }
        invalid_payloads = (
            {**base, "hosts": ["unrelated.test"]},
            {**base, "hosts": ["example.test"]},
            {**base, "ip_networks": ["192.0.2.0/24"]},
            {**base, "root": "", "hosts": ["unrelated.test"],
             "ip_networks": ["192.0.2.0/24"]},
            {**base, "root": "", "hosts": ["192.0.3.1"],
             "ip_networks": ["192.0.2.0/24"]},
        )

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                scope = Scope.from_payload(payload)
                self.assertFalse(scope.is_valid)
                self.assertFalse(scope.allows("https://unrelated.test/v1"))


class TestOpenApiGraph(unittest.TestCase):
    def test_only_in_scope_operations_are_written(self):
        client = _Client()
        stats = client.update_graph_from_openapi(_payload([
            _operation(),
            _operation(baseurl="https://unrelated.test"),
        ]), "user-1", "project-1")

        self.assertEqual(stats["operations_imported"], 1)
        self.assertEqual(stats["skipped_out_of_scope"], 1)
        written_baseurls = {
            kwargs.get("baseurl") for _, kwargs in client.session.queries
            if "baseurl" in kwargs
        }
        self.assertEqual(written_baseurls, {"https://api.example.test"})

    def test_every_entity_merge_contains_the_tenant_identity(self):
        client = _Client()
        client.update_graph_from_openapi(_payload([_operation()]), "user-1", "project-1")

        writes = "\n".join(query for query, _ in client.session.queries)
        for label in ("Domain", "Subdomain", "BaseURL", "Endpoint"):
            with self.subTest(label=label):
                pattern = rf"MERGE \(\w+:{label} \{{[^}}]*user_id: \$user_id[^}}]*project_id: \$project_id"
                self.assertRegex(writes, re.compile(pattern))

    def test_get_and_post_keep_separate_method_specific_declarations(self):
        client = _Client()
        stats = client.update_graph_from_openapi(_payload([
            _operation(method="GET", summary="Read widget"),
            _operation(method="POST", summary="Create widget"),
        ]), "user-1", "project-1")

        self.assertEqual(stats["operations_imported"], 2)
        self.assertEqual(stats["endpoints_updated"], 2)
        self.assertEqual(
            {key[2] for key in client.session.declarations},
            {"GET", "POST"},
        )
        summaries = {
            key[2]: json.loads(value)[0]["operation"]["summary"]
            for key, value in client.session.declarations.items()
        }
        self.assertEqual(summaries, {"GET": "Read widget", "POST": "Create widget"})

    def test_repeat_import_replaces_its_source_and_preserves_other_sources(self):
        client = _Client()
        key = (
            "https://api.example.test", "/v2/widgets/{id}", "GET",
            "user-1", "project-1",
        )
        client.session.declarations[key] = json.dumps([{
            "source_url": "https://catalog.example.test/service.json",
            "document_hash": "b" * 64,
            "operation_ref": "#/paths/~1v2~1widgets~1{id}/get",
            "operation": {"summary": "Catalog copy"},
        }])

        client.update_graph_from_openapi(
            _payload([_operation(summary="First import")]), "user-1", "project-1")
        client.update_graph_from_openapi(
            _payload([_operation(summary="Updated import")]), "user-1", "project-1")

        declarations = json.loads(client.session.declarations[key])
        self.assertEqual(len(declarations), 2)
        self.assertEqual(
            {item["source_url"] for item in declarations},
            {
                "https://catalog.example.test/service.json",
                "https://docs.example.test/openapi.json",
            },
        )
        current = next(item for item in declarations if item["source_url"].startswith("https://docs"))
        self.assertEqual(current["operation"]["summary"], "Updated import")

        endpoint_write = next(
            query for query, _ in client.session.queries
            if "SET e.openapi_declarations = $openapi_declarations" in query
        )
        self.assertIn("ON CREATE SET e.source = 'openapi'", endpoint_write)
        self.assertNotIn("\nSET e.source =", endpoint_write)

    def test_source_id_distinguishes_documents_with_the_same_sanitized_url(self):
        client = _Client()
        client.update_graph_from_openapi(_payload([
            _operation(source_id="source-a", summary="First selector"),
            _operation(source_id="source-b", summary="Second selector"),
        ]), "user-1", "project-1")

        declarations = json.loads(next(iter(client.session.declarations.values())))
        self.assertEqual({item["source_id"] for item in declarations}, {"source-a", "source-b"})

    def test_source_and_operation_ref_form_declaration_identity(self):
        client = _Client()
        client.update_graph_from_openapi(_payload([
            _operation(operation_ref="#/paths/~1widgets/get", summary="First path"),
            _operation(operation_ref="#/paths/~1aliases/get", summary="Aliased path"),
        ]), "user-1", "project-1")

        declarations = json.loads(next(iter(client.session.declarations.values())))
        self.assertEqual(
            {item["operation_ref"] for item in declarations},
            {"#/paths/~1widgets/get", "#/paths/~1aliases/get"},
        )

    def test_import_count_only_includes_successfully_persisted_operations(self):
        client = _Client()
        client.session.fail_endpoint_write = True

        stats = client.update_graph_from_openapi(
            _payload([_operation()]), "user-1", "project-1")

        self.assertEqual(stats["operations_imported"], 0)
        self.assertEqual(stats["endpoints_updated"], 0)
        self.assertEqual(len(stats["errors"]), 1)

    def test_documents_and_diagnostics_are_stored_as_domain_summary_json(self):
        client = _Client()
        client.update_graph_from_openapi(_payload([_operation()]), "user-1", "project-1")

        summary_call = next(
            kwargs for query, kwargs in client.session.queries
            if "d.openapi_summary = $openapi_summary" in query
        )
        summary = json.loads(summary_call["openapi_summary"])
        self.assertEqual(summary["documents"][0]["version"], "3.1.0")
        self.assertEqual(summary["diagnostics"][0]["code"], "fetch_failed")
        self.assertNotIn("operations", summary)

    def test_graph_storage_sanitizes_and_whitelists_provenance(self):
        client = _Client()
        data = _payload([_operation(
            source_url=(
                "https://reader:fixture-secret@docs.example.test/"
                "openapi.json?token=fixture-secret#section"
            ),
        )])
        data["openapi"]["documents"][0].update({
            "url": "https://docs.example.test/openapi.json?token=fixture-secret",
            "headers": {"Authorization": "fixture-secret"},
            "raw_spec": {"secret": "fixture-secret"},
        })

        client.update_graph_from_openapi(data, "user-1", "project-1")

        stored = " ".join(client.session.declarations.values())
        summary_call = next(
            kwargs for query, kwargs in client.session.queries
            if "d.openapi_summary = $openapi_summary" in query
        )
        stored += summary_call["openapi_summary"]
        self.assertNotIn("fixture-secret", stored)
        self.assertNotIn("headers", stored)
        self.assertNotIn("raw_spec", stored)
        declaration = json.loads(next(iter(client.session.declarations.values())))[0]
        self.assertEqual(
            declaration["source_url"],
            "https://docs.example.test/openapi.json",
        )

    def test_invalid_scope_writes_nothing(self):
        client = _Client()
        data = _payload([_operation()], scope={
            "root": "", "hosts": [], "include_subdomains": False,
            "include_root": False, "ip_networks": [], "excluded_hosts": [],
        })

        stats = client.update_graph_from_openapi(data, "user-1", "project-1")

        self.assertEqual(stats["operations_imported"], 0)
        self.assertEqual(stats["skipped_out_of_scope"], 1)
        self.assertEqual(client.session.queries, [])

    def test_malformed_operation_paths_never_create_endpoints(self):
        client = _Client()
        data = _payload([
            _operation(path="/v2/bad path"),
            _operation(path="/v2/bad\\path"),
            _operation(path="/v2/bad\x00path"),
        ])

        stats = client.update_graph_from_openapi(data, "user-1", "project-1")

        self.assertEqual(stats["operations_imported"], 0)
        self.assertEqual(stats["skipped_invalid"], 3)
        endpoint_writes = [
            query for query, _ in client.session.queries if "MERGE (e:Endpoint" in query
        ]
        self.assertEqual(endpoint_writes, [])


class TestReconMixinComposition(unittest.TestCase):
    def test_recon_mixin_exposes_openapi_writer(self):
        from graph_db.mixins.recon_mixin import ReconMixin

        self.assertTrue(callable(getattr(ReconMixin, "update_graph_from_openapi")))


if __name__ == "__main__":
    unittest.main()
