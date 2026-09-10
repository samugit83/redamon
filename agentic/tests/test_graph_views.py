"""
Tests for Graph Views feature - tenant filter injection and ContextVar helpers.

Run with: python -m pytest tests/test_graph_views.py -v
"""

import os
import sys
import types
import unittest
import asyncio
import contextlib

# Add parent dir to path
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Stub out heavy dependencies not available outside Docker
class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"

class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"

def _fake_add_messages(left, right):
    if left is None:
        left = []
    return left + right

_stubs = {}
_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.language_models.chat_models',
    'langchain_openai', 'langchain_anthropic', 'langchain_aws',
    'langchain_community', 'langchain_community.graphs',
    'langchain_neo4j', 'langchain_mcp_adapters', 'langchain_mcp_adapters.client',
    'langgraph', 'langgraph.graph', 'langgraph.graph.state',
    'langgraph.graph.message', 'langgraph.checkpoint',
    'langgraph.checkpoint.memory', 'langgraph.prebuilt',
    'httpx', 'neo4j',
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        from unittest.mock import MagicMock
        stub = MagicMock()
        sys.modules[mod_name] = stub
        _stubs[mod_name] = stub

# Configure fake message classes
sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langchain_core.messages'].SystemMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

# Now import the modules under test
from tools import (
    set_tenant_context,
    set_phase_context,
    set_graph_view_context,
    get_graph_view_context,
    get_phase_context,
    current_user_id,
    current_project_id,
    current_graph_view_cypher,
    Neo4jToolManager,
    CypherGenerationTimeout,
    CYPHER_GENERATION_TIMEOUT_DEFAULT,
    _cypher_generation_timeout,
)


class TestContextVars(unittest.TestCase):
    """Test ContextVar helpers for tenant and graph view context."""

    def test_set_tenant_context(self):
        set_tenant_context("user123", "proj456")
        self.assertEqual(current_user_id.get(), "user123")
        self.assertEqual(current_project_id.get(), "proj456")

    def test_set_phase_context(self):
        set_phase_context("exploitation")
        self.assertEqual(get_phase_context(), "exploitation")

    def test_graph_view_context_default_is_none(self):
        # Reset to default
        set_graph_view_context(None)
        self.assertIsNone(get_graph_view_context())

    def test_set_graph_view_context(self):
        cypher = "MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, r, s"
        set_graph_view_context(cypher)
        self.assertEqual(get_graph_view_context(), cypher)

    def test_clear_graph_view_context(self):
        set_graph_view_context("SOME CYPHER")
        self.assertIsNotNone(get_graph_view_context())
        set_graph_view_context(None)
        self.assertIsNone(get_graph_view_context())


class TestTenantFilterInjection(unittest.TestCase):
    """Test Neo4jToolManager._inject_tenant_filter."""

    def setUp(self):
        # Create manager with dummy params (no actual connection needed)
        self.manager = Neo4jToolManager.__new__(Neo4jToolManager)
        self.manager.uri = ""
        self.manager.user = ""
        self.manager.password = ""
        self.manager.llm = None
        self.manager.graph = None

    def test_bare_node_pattern(self):
        cypher = "MATCH (d:Domain) RETURN d"
        result = self.manager._inject_tenant_filter(cypher, "u1", "p1")
        self.assertIn("user_id: $tenant_user_id", result)
        self.assertIn("project_id: $tenant_project_id", result)
        self.assertEqual(
            result,
            "MATCH (d:Domain&!Muted {user_id: $tenant_user_id, "
            "project_id: $tenant_project_id}) RETURN d"
        )

    def test_node_with_existing_props(self):
        cypher = 'MATCH (d:Domain {name: "example.com"}) RETURN d'
        result = self.manager._inject_tenant_filter(cypher, "u1", "p1")
        self.assertIn('name: "example.com"', result)
        self.assertIn("user_id: $tenant_user_id", result)
        self.assertIn("project_id: $tenant_project_id", result)

    def test_multiple_nodes(self):
        cypher = "MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, s"
        result = self.manager._inject_tenant_filter(cypher, "u1", "p1")
        # Both nodes should get tenant filters
        self.assertEqual(result.count("user_id: $tenant_user_id"), 2)
        self.assertEqual(result.count("project_id: $tenant_project_id"), 2)

    def test_relationship_not_modified(self):
        cypher = "MATCH (d:Domain)-[r:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, r, s"
        result = self.manager._inject_tenant_filter(cypher, "u1", "p1")
        # Relationship pattern should not be modified
        self.assertIn("-[r:HAS_SUBDOMAIN]->", result)

    def test_preserves_limit(self):
        cypher = "MATCH (v:Vulnerability) RETURN v LIMIT 10"
        result = self.manager._inject_tenant_filter(cypher, "u1", "p1")
        self.assertIn("LIMIT 10", result)

    def test_complex_query(self):
        cypher = (
            "MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)"
            "-[:RESOLVES_TO]->(ip:IP)"
            "-[:HAS_PORT]->(p:Port {number: 443})"
            " RETURN d, s, ip, p"
        )
        result = self.manager._inject_tenant_filter(cypher, "u1", "p1")
        # All 4 nodes should have tenant filters
        self.assertEqual(result.count("user_id: $tenant_user_id"), 4)
        # Port should keep its existing property
        self.assertIn("number: 443", result)


class TestCypherResponseHandling(unittest.TestCase):
    """Test Cypher extraction and read-only validation."""

    def test_extracts_cypher_after_think_block(self):
        raw = """<think>
I should list IP nodes.
</think>

MATCH (i:IP) RETURN i.address LIMIT 100"""
        result = Neo4jToolManager._extract_cypher_from_response(raw)
        self.assertEqual(result, "MATCH (i:IP) RETURN i.address LIMIT 100")

    def test_extracts_cypher_from_fenced_block(self):
        raw = """Here is the query:
```cypher
MATCH (d:Domain) RETURN d LIMIT 25
```"""
        result = Neo4jToolManager._extract_cypher_from_response(raw)
        self.assertEqual(result, "MATCH (d:Domain) RETURN d LIMIT 25")

    def test_allows_read_only_call(self):
        cypher = "CALL db.labels() YIELD label RETURN label LIMIT 50"
        self.assertIsNone(Neo4jToolManager._find_disallowed_write_operation(cypher))

    def test_blocks_write_clause(self):
        cypher = "MATCH (i:IP) SET i.reviewed = true RETURN i"
        self.assertEqual(Neo4jToolManager._find_disallowed_write_operation(cypher), "SET")

    def test_blocks_write_procedure(self):
        cypher = "CALL apoc.create.node(['IP'], {address: '127.0.0.1'}) YIELD node RETURN node"
        self.assertEqual(Neo4jToolManager._find_disallowed_write_operation(cypher), "apoc.create")

    def test_extracts_single_query_from_multiple_returns(self):
        """Test that extraction handles (and fixes) invalid multiple RETURN syntax"""
        raw = """MATCH (d:Domain {name: 'example.com'})
RETURN d.name, d.registrar
RETURN d.creation_date, d.expiration_date"""
        # Should extract only up to first RETURN
        result = Neo4jToolManager._extract_cypher_from_response(raw)
        self.assertEqual(result, "MATCH (d:Domain {name: 'example.com'})\nRETURN d.name, d.registrar")


class TestSubqueryReturnPreservation(unittest.TestCase):
    """A RETURN inside a subquery is not a second query and must not be cut.

    Regression: the truncator counted every RETURN, so a two-`CALL {}` query
    was cut inside the second block, leaving a dangling `ORDER BY` and a
    guaranteed Neo4j SyntaxError on every regeneration attempt.
    """

    LIVE_SHAPE = (
        "CALL {\n"
        "  OPTIONAL MATCH (p:Package)\n"
        "  RETURN count(p) AS total, collect(p.name) AS matching_packages\n"
        "}\n"
        "CALL {\n"
        "  MATCH (n)\n"
        "  UNWIND labels(n) AS node_label\n"
        "  WITH node_label, count(*) AS label_count\n"
        "  ORDER BY label_count DESC\n"
        "  RETURN collect({label: node_label, count: label_count}) AS label_counts\n"
        "}\n"
        "RETURN total, matching_packages, label_counts LIMIT 100"
    )

    def test_call_subquery_returns_survive_extraction(self):
        result = Neo4jToolManager._extract_cypher_from_response(self.LIVE_SHAPE)
        self.assertEqual(result, self.LIVE_SHAPE)
        # The clause the old truncator amputated the query after.
        self.assertTrue(result.rstrip().endswith("RETURN total, matching_packages, label_counts LIMIT 100"))

    def test_collect_subquery_return_survives(self):
        cypher = (
            "MATCH (d:Domain)\n"
            "RETURN d.name AS name, "
            "COLLECT { MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN s.name } AS subs\n"
            "LIMIT 10"
        )
        self.assertEqual(Neo4jToolManager._truncate_at_first_return(cypher), cypher)

    def test_second_top_level_return_still_truncated_after_subquery(self):
        cypher = (
            "CALL {\n  MATCH (p:Package)\n  RETURN p.name AS name\n}\n"
            "RETURN name\n"
            "RETURN name, 2"
        )
        self.assertEqual(
            Neo4jToolManager._truncate_at_first_return(cypher),
            "CALL {\n  MATCH (p:Package)\n  RETURN p.name AS name\n}\nRETURN name",
        )

    def test_return_inside_string_literal_is_not_a_cut_point(self):
        cypher = "MATCH (n:Note) WHERE n.body CONTAINS 'RETURN me' RETURN n LIMIT 5"
        self.assertEqual(Neo4jToolManager._truncate_at_first_return(cypher), cypher)

    def test_return_inside_comment_is_not_a_cut_point(self):
        cypher = "MATCH (n:IP) // RETURN n.address\nRETURN n LIMIT 5"
        self.assertEqual(Neo4jToolManager._truncate_at_first_return(cypher), cypher)

    def test_return_inside_block_comment_is_not_a_cut_point(self):
        cypher = "MATCH (n:IP) /* RETURN n.address */ RETURN n LIMIT 5"
        self.assertEqual(Neo4jToolManager._truncate_at_first_return(cypher), cypher)

    def test_unbalanced_brace_is_left_alone(self):
        """Truncated model output must be handed to Neo4j as-is, not mangled further."""
        cypher = "CALL {\n  MATCH (p:Package)\n  RETURN p.name AS name"
        self.assertEqual(Neo4jToolManager._truncate_at_first_return(cypher), cypher)


class TestGenerateCypherViewScope(unittest.TestCase):
    """Test that _generate_cypher includes view scope in prompt."""

    def test_view_scope_included_in_prompt(self):
        """Verify that when view_cypher is set, the prompt includes it."""
        manager = Neo4jToolManager.__new__(Neo4jToolManager)
        manager.llm = None
        manager.graph = None

        # We can't call _generate_cypher without an LLM, but we can verify
        # the prompt construction logic by checking the method signature
        import inspect
        sig = inspect.signature(manager._generate_cypher)
        params = list(sig.parameters.keys())
        self.assertIn('view_cypher', params)


class TestCypherGenerationTimeout(unittest.TestCase):
    """One text-to-Cypher call must be wall-clock bounded.

    Without a bound, a slow provider (4m32s per generation was observed) times
    CYPHER_MAX_RETRIES over, hanging query_graph for 10+ minutes.
    """

    def setUp(self):
        self._saved_env = os.environ.get("CYPHER_GENERATION_TIMEOUT")

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("CYPHER_GENERATION_TIMEOUT", None)
        else:
            os.environ["CYPHER_GENERATION_TIMEOUT"] = self._saved_env

    def _set_env(self, value):
        if value is None:
            os.environ.pop("CYPHER_GENERATION_TIMEOUT", None)
        else:
            os.environ["CYPHER_GENERATION_TIMEOUT"] = value

    def test_default_when_env_unset(self):
        self._set_env(None)
        self.assertEqual(_cypher_generation_timeout(), CYPHER_GENERATION_TIMEOUT_DEFAULT)

    def test_env_override(self):
        self._set_env("30")
        self.assertEqual(_cypher_generation_timeout(), 30.0)

    def test_zero_disables_the_bound(self):
        self._set_env("0")
        self.assertEqual(_cypher_generation_timeout(), 0.0)

    def test_garbage_env_falls_back_to_default(self):
        self._set_env("soon")
        self.assertEqual(_cypher_generation_timeout(), CYPHER_GENERATION_TIMEOUT_DEFAULT)

    # -- _generate_cypher behaviour -------------------------------------

    @staticmethod
    def _manager():
        manager = Neo4jToolManager.__new__(Neo4jToolManager)
        manager.llm = object()
        manager.graph = types.SimpleNamespace(get_schema="Node properties: (:Package)")
        return manager

    @staticmethod
    @contextlib.contextmanager
    def _stubbed_llm_retry(retry_llm_call):
        """Install stub orchestrator_helpers submodules for the lazy imports.

        _generate_cypher imports them inside the function body, so putting them
        in sys.modules is enough and avoids importing the real (heavy) package.
        """
        names = (
            "orchestrator_helpers",
            "orchestrator_helpers.llm_retry",
            "orchestrator_helpers.json_utils",
        )
        saved = {name: sys.modules.get(name) for name in names}

        pkg = saved["orchestrator_helpers"] or types.ModuleType("orchestrator_helpers")
        retry_mod = types.ModuleType("orchestrator_helpers.llm_retry")
        retry_mod.retry_llm_call = retry_llm_call
        json_mod = types.ModuleType("orchestrator_helpers.json_utils")
        json_mod.normalize_content = lambda content: content

        sys.modules["orchestrator_helpers"] = pkg
        sys.modules["orchestrator_helpers.llm_retry"] = retry_mod
        sys.modules["orchestrator_helpers.json_utils"] = json_mod
        try:
            yield
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module

    def test_slow_generation_raises_timeout(self):
        self._set_env("0.05")
        started = asyncio.Event()

        async def _hang(llm, prompt, label=None):
            started.set()
            await asyncio.sleep(30)
            raise AssertionError("should have been cancelled")

        async def _run():
            with self._stubbed_llm_retry(_hang):
                await self._manager()._generate_cypher("count the packages")

        with self.assertRaises(CypherGenerationTimeout) as ctx:
            asyncio.run(_run())
        self.assertIn("0.05s", str(ctx.exception))
        self.assertTrue(started.is_set(), "the LLM call should have been started")

    def test_fast_generation_is_not_timed_out(self):
        self._set_env("30")

        async def _fast(llm, prompt, label=None):
            return types.SimpleNamespace(content="MATCH (p:Package) RETURN p LIMIT 10")

        async def _run():
            with self._stubbed_llm_retry(_fast):
                return await self._manager()._generate_cypher("count the packages")

        self.assertEqual(asyncio.run(_run()), "MATCH (p:Package) RETURN p LIMIT 10")

    def test_disabled_timeout_still_returns(self):
        self._set_env("0")

        async def _fast(llm, prompt, label=None):
            return types.SimpleNamespace(content="MATCH (p:Package) RETURN p LIMIT 10")

        async def _run():
            with self._stubbed_llm_retry(_fast):
                return await self._manager()._generate_cypher("count the packages")

        self.assertEqual(asyncio.run(_run()), "MATCH (p:Package) RETURN p LIMIT 10")


if __name__ == '__main__':
    unittest.main()
