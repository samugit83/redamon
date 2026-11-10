"""A secret or a full link with its secret in it is for the operator's UI.

Recon keeps them in display-only properties (graph_db/display_only.py). The
agent's graph reads, /graph/exec (MCP query_graph, the sandbox's redagraph)
and the agent's own query_graph, must never hand them back: a query that names
one is refused, and a whole node returned loses them.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import api  # noqa: E402
from graph_db.display_only import DISPLAY_ONLY_PROPS, display_only_named  # noqa: E402


class _FakeNode:
    def __init__(self, element_id, labels, props):
        self._props = dict(props)
        self.element_id = element_id
        self.labels = frozenset(labels)

    def items(self):
        return self._props.items()


SECRET = {"id": "secret-urlscan-1", "secret_type": "api_key", "masked_url": "https://a.test/?k=***",
          "secret_value": "ak9Q2w8E3r7T4y6U1i0O5pLz", "unmasked_url": "https://a.test/?k=ak9Q2w8E3r7T4y6U1i0O5pLz",
          "paired_secret": "s3cr3t-pair", "raw_context": "k='ak9Q2w8E3r7T4y6U1i0O5pLz'"}


class TestCoercion(unittest.TestCase):
    def test_a_node_loses_every_display_only_property(self):
        out = api._graph_exec_coerce(_FakeNode("4:db:9", ["Secret"], SECRET))
        self.assertEqual(set(out["properties"]), {"id", "secret_type", "masked_url"})

    def test_a_map_loses_them_too(self):
        out = api._graph_exec_coerce({"s": dict(SECRET), "n": 1})
        self.assertEqual(set(out["s"]), {"id", "secret_type", "masked_url"})
        self.assertEqual(out["n"], 1)


class TestRefusal(unittest.TestCase):
    def test_a_query_naming_one_is_refused_before_it_runs(self):
        ran = []
        original = api._graph_exec_run
        api._graph_exec_run = lambda *a, **k: ran.append(a) or ([], False)
        try:
            resp = api._graph_exec_respond(
                "MATCH (s:Secret {project_id: $tenant_project_id}) RETURN s.secret_value AS v", {})
        finally:
            api._graph_exec_run = original
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"secret_value", bytes(resp.body))
        self.assertEqual(ran, [])

    def test_names_are_found_in_any_position_and_only_as_whole_words(self):
        self.assertEqual(display_only_named("MATCH (e) WHERE e.unmasked_urls IS NOT NULL RETURN e"),
                         ["unmasked_urls"])
        self.assertEqual(display_only_named("RETURN s.masked_url, s.value_hmac"), [])
        self.assertEqual(display_only_named("RETURN s.my_secret_value_x"), [])

    def test_every_display_only_property_is_recognised(self):
        for prop in DISPLAY_ONLY_PROPS:
            self.assertEqual(display_only_named(f"RETURN n.{prop}"), [prop])


class TestAgentQueryGraph(unittest.TestCase):
    """The agent's own query_graph refuses and strips the same way."""

    def test_the_tool_source_guards_both_ways(self):
        src = (Path(__file__).resolve().parent.parent / "tools.py").read_text(encoding="utf-8")
        start = src.index("async def query_graph(")
        body = src[start:start + 9000]
        self.assertIn("display_only_named(filtered_cypher)", body)
        self.assertIn("_wrap_graph_result(strip_display_only(result), filtered_cypher)", body)


if __name__ == "__main__":
    unittest.main()
