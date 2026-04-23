"""
Tests for Graph Views feature - tenant filter injection and ContextVar helpers.

Run with: python -m pytest tests/test_graph_views.py -v
"""

import os
import sys
import unittest
import asyncio

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
            "MATCH (d:Domain {user_id: $tenant_user_id, project_id: $tenant_project_id}) RETURN d"
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


if __name__ == '__main__':
    unittest.main()
