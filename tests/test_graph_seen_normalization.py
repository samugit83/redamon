import io
import importlib.util
import json
import sys
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock


REPO_ROOT = Path(__file__).resolve().parent.parent


def _install_dependency_stubs():
    neo4j_stub = types.ModuleType("neo4j")
    neo4j_stub.GraphDatabase = MagicMock()
    sys.modules.setdefault("neo4j", neo4j_stub)

    dotenv_stub = types.ModuleType("dotenv")
    dotenv_stub.load_dotenv = lambda *args, **kwargs: None
    sys.modules.setdefault("dotenv", dotenv_stub)

    graph_db_stub = types.ModuleType("graph_db")
    graph_db_stub.__path__ = [str(REPO_ROOT / "graph_db")]
    graph_db_stub.Neo4jClient = MagicMock()
    graph_db_module = sys.modules.setdefault("graph_db", graph_db_stub)
    if not hasattr(graph_db_module, "Neo4jClient"):
        graph_db_module.Neo4jClient = MagicMock()

    mixins_stub = types.ModuleType("graph_db.mixins")
    mixins_stub.__path__ = [str(REPO_ROOT / "graph_db" / "mixins")]
    sys.modules.setdefault("graph_db.mixins", mixins_stub)

    schema_stub = types.ModuleType("graph_db.schema")
    schema_stub.init_schema = MagicMock()
    sys.modules.setdefault("graph_db.schema", schema_stub)


def _load_module(module_name, relative_path):
    _install_dependency_stubs()
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class _NativeDateTime:
    def __init__(self, value):
        self.value = value


class _FakeResult:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)

    def single(self):
        return self._records[0] if self._records else None


class _FakeSession:
    def __init__(self, nodes):
        self.nodes = nodes
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def run(self, query, **params):
        compact_query = " ".join(query.split())
        self.calls.append((compact_query, params))
        property_name = (
            "first_seen" if "n.first_seen IS :: STRING" in compact_query
            else "last_seen"
        )

        if "RETURN elementId(n) AS element_id" in compact_query:
            after_element_id = params["after_element_id"]
            records = [
                {"element_id": node["element_id"], "value": node[property_name]}
                for node in self.nodes
                if node.get("project_id") is not None
                and isinstance(node.get(property_name), str)
                and (
                    after_element_id is None
                    or node["element_id"] > after_element_id
                )
            ]
            records.sort(key=lambda record: record["element_id"])
            return _FakeResult(records[: params["batch_size"]])

        if "UNWIND $rows AS row" in compact_query:
            converted = 0
            for row in params["rows"]:
                for node in self.nodes:
                    if (
                        node["element_id"] == row["element_id"]
                        and node.get("project_id") is not None
                        and isinstance(node.get(property_name), str)
                    ):
                        node[property_name] = _NativeDateTime(row["value"])
                        converted += 1
            return _FakeResult([{"converted": converted}])

        raise AssertionError(f"Unexpected query: {compact_query}")


class _FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class GraphSeenNormalizationTests(unittest.TestCase):
    def test_normalizes_aware_strings_and_preserves_ineligible_values(self):
        base_module = _load_module(
            "graph_db.mixins.base_mixin",
            Path("graph_db") / "mixins" / "base_mixin.py",
        )
        nodes = [
            {
                "element_id": "1",
                "project_id": "project-a",
                "first_seen": "2026-05-29T14:15:30Z",
                "last_seen": "2026-05-29T16:15:30.123456+02:00",
            },
            {
                "element_id": "2",
                "project_id": "project-a",
                "first_seen": "2026-05-29T14:15:30",
                "last_seen": "not-a-timestamp",
            },
            {
                "element_id": "3",
                "project_id": "project-a",
                "first_seen": _NativeDateTime("native-first"),
                "last_seen": _NativeDateTime("native-last"),
            },
            {"element_id": "4", "project_id": "project-a"},
            {
                "element_id": "5",
                "project_id": None,
                "first_seen": "2026-05-29T14:15:30Z",
                "last_seen": "2026-05-29T14:15:30Z",
            },
            {
                "element_id": "6",
                "project_id": "project-b",
                "first_seen": "broken",
                "last_seen": "2026-05-29T15:15:30+01:00",
            },
        ]
        session = _FakeSession(nodes)
        base = base_module.BaseMixin.__new__(base_module.BaseMixin)
        base.driver = _FakeDriver(session)
        base._SEEN_TIMESTAMP_BATCH_SIZE = 2
        self.assertTrue(
            hasattr(base, "normalize_recon_seen_timestamps"),
            "BaseMixin must expose normalize_recon_seen_timestamps",
        )

        result = base.normalize_recon_seen_timestamps()

        self.assertEqual(
            result,
            {
                "first_seen_converted": 1,
                "last_seen_converted": 2,
                "malformed_first_seen": 2,
                "malformed_last_seen": 1,
            },
        )
        self.assertEqual(
            nodes[0]["first_seen"].value, "2026-05-29T14:15:30+00:00"
        )
        self.assertEqual(
            nodes[0]["last_seen"].value, "2026-05-29T14:15:30.123456+00:00"
        )
        self.assertEqual(
            nodes[5]["last_seen"].value, "2026-05-29T14:15:30+00:00"
        )
        self.assertEqual(nodes[1]["first_seen"], "2026-05-29T14:15:30")
        self.assertEqual(nodes[1]["last_seen"], "not-a-timestamp")
        self.assertEqual(nodes[5]["first_seen"], "broken")
        self.assertIsInstance(nodes[2]["first_seen"], _NativeDateTime)
        self.assertNotIn("first_seen", nodes[3])
        self.assertIsInstance(nodes[4]["first_seen"], str)

        fetch_queries = [
            query
            for query, _params in session.calls
            if "RETURN elementId(n) AS element_id" in query
        ]
        update_queries = [
            query for query, _params in session.calls if "UNWIND $rows AS row" in query
        ]
        self.assertTrue(fetch_queries)
        self.assertTrue(update_queries)
        for query in fetch_queries:
            self.assertIn("n.project_id IS NOT NULL", query)
            self.assertIn("IS :: STRING NOT NULL", query)
            self.assertIn("elementId(n)", query)
            self.assertIn("ORDER BY element_id", query)
        for query in update_queries:
            self.assertIn("UNWIND $rows AS row", query)
            self.assertIn("elementId(n) = row.element_id", query)
            self.assertIn("n.project_id IS NOT NULL", query)
            self.assertIn("IS :: STRING NOT NULL", query)
            self.assertIn("datetime(row.value)", query)

        second_result = base.normalize_recon_seen_timestamps()

        self.assertEqual(second_result["first_seen_converted"], 0)
        self.assertEqual(second_result["last_seen_converted"], 0)
        self.assertEqual(second_result["malformed_first_seen"], 2)
        self.assertEqual(second_result["malformed_last_seen"], 1)

    def test_cli_prints_json_and_closes_client(self):
        migration_path = (
            REPO_ROOT
            / "graph_db"
            / "migrations"
            / "normalize_recon_seen_timestamps.py"
        )
        self.assertTrue(
            migration_path.exists(),
            "timestamp normalization CLI module must exist",
        )
        migration_module = _load_module(
            "graph_db.migrations.normalize_recon_seen_timestamps",
            migration_path.relative_to(REPO_ROOT),
        )

        class FakeClient:
            def __init__(self):
                self.closed = False

            def normalize_recon_seen_timestamps(self):
                return {
                    "first_seen_converted": 3,
                    "last_seen_converted": 4,
                    "malformed_first_seen": 1,
                    "malformed_last_seen": 2,
                }

            def close(self):
                self.closed = True

        client = FakeClient()
        migration_module.Neo4jClient = lambda: client
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = migration_module.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "first_seen_converted": 3,
                "last_seen_converted": 4,
                "malformed_first_seen": 1,
                "malformed_last_seen": 2,
            },
        )
        self.assertTrue(client.closed)

    def test_cli_closes_client_when_normalization_fails(self):
        migration_path = (
            REPO_ROOT
            / "graph_db"
            / "migrations"
            / "normalize_recon_seen_timestamps.py"
        )
        self.assertTrue(
            migration_path.exists(),
            "timestamp normalization CLI module must exist",
        )
        migration_module = _load_module(
            "graph_db.migrations.normalize_recon_seen_timestamps",
            migration_path.relative_to(REPO_ROOT),
        )

        class FailingClient:
            def __init__(self):
                self.closed = False

            def normalize_recon_seen_timestamps(self):
                raise RuntimeError("query failed")

            def close(self):
                self.closed = True

        client = FailingClient()
        migration_module.Neo4jClient = lambda: client

        with self.assertRaisesRegex(RuntimeError, "query failed"):
            migration_module.main()

        self.assertTrue(client.closed)


if __name__ == "__main__":
    unittest.main()
