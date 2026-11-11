"""
Integration tests for the new /mcp/manifest, /mcp/reload, /mcp/test FastAPI
endpoints. Uses fastapi.testclient with a stub orchestrator so the tests
don't depend on a live Neo4j / kali-sandbox / webapp.

Run with: python tests/test_mcp_api_endpoints.py
"""

import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

# The /mcp/* routes take the configured master key only (NF-01, step 1.9): every
# request here carries it; test_scanner_key_scope.py covers the refusals.
MASTER = "mcp-endpoints-master-key"
MASTER_HEADERS = {"x-internal-key": MASTER}
_master_env = patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})


def setUpModule():
    _master_env.start()


def tearDownModule():
    _master_env.stop()


class FakeOrchestrator:
    """Minimal stand-in for AgentOrchestrator — only the methods api.py reaches."""

    def __init__(self):
        self.reload_calls = []

    async def reload_mcp_manifests(self, user_servers_raw=None, owner_id=None):
        # The route also names whose set it is (RBAC OQ-41): absent here.
        self.reload_calls.append(user_servers_raw)
        return {
            "servers": [{"id": "system_a"}, {"id": "user_a"}],
            "errors": [],
            "warnings": [],
            "declared_user_tool_names": ["user_tool"],
        }


class McpManifestEndpointTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Patch lifespan so import doesn't try to spin a real orchestrator
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        # Late imports so we can patch first
        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module
            from fastapi.testclient import TestClient
            cls.TestClient = TestClient

    def setUp(self):
        # Reset registry to a known state for /mcp/manifest tests.
        import mcp_registry as reg
        srv = reg.MCPServer.model_validate({
            "id": "stub",
            "name": "Stub",
            "transport": "streamable_http",
            "url": "http://stub.local/mcp",
            "tools": [],
        })
        reg.set_current([srv], errors=[], warnings=[])

    def test_manifest_endpoint_returns_servers(self):
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)
        r = client.get("/mcp/manifest")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("servers", data)
        self.assertIn("errors", data)
        self.assertIn("warnings", data)
        self.assertIn("system_server_ids", data)
        self.assertEqual(len(data["servers"]), 1)
        self.assertEqual(data["servers"][0]["id"], "stub")

    def test_manifest_redacts_auth_token(self):
        # Direct literal token must be masked before the API returns it.
        import mcp_registry as reg
        srv = reg.MCPServer.model_validate({
            "id": "with_auth",
            "name": "With auth",
            "transport": "streamable_http",
            "url": "http://x/mcp",
            "auth": {"type": "bearer", "token": "ghp_realtokenshouldbemasked9876"},
            "tools": [],
        })
        reg.set_current([srv])
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)
        r = client.get("/mcp/manifest")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        srv_data = next(s for s in data["servers"] if s["id"] == "with_auth")
        self.assertNotEqual(srv_data["auth"]["token"], "ghp_realtokenshouldbemasked9876")
        self.assertTrue(srv_data["auth"]["token"].startswith("•"))
        self.assertTrue(srv_data["auth"]["token"].endswith("9876"))

    def test_manifest_keeps_env_var_name_intact(self):
        # Env-var references are not secrets — they survive the redaction.
        import mcp_registry as reg
        srv = reg.MCPServer.model_validate({
            "id": "with_env_auth",
            "name": "With env auth",
            "transport": "streamable_http",
            "url": "http://x/mcp",
            "auth": {"type": "bearer", "token_env_var": "FAKE_TOKEN_ENV"},
            "tools": [],
        })
        reg.set_current([srv])
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)
        r = client.get("/mcp/manifest")
        data = r.json()
        srv_data = next(s for s in data["servers"] if s["id"] == "with_env_auth")
        self.assertEqual(srv_data["auth"]["token_env_var"], "FAKE_TOKEN_ENV")
        self.assertIsNone(srv_data["auth"].get("token"))


class McpReloadEndpointTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module
            from fastapi.testclient import TestClient
            cls.TestClient = TestClient

    def test_reload_503_when_orchestrator_not_ready(self):
        # api.orchestrator is None at import-time; no lifespan ran in tests.
        self.api_module.orchestrator = None
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)
        r = client.post("/mcp/reload", json={})
        self.assertEqual(r.status_code, 503)
        self.assertIn("orchestrator not ready", r.text)

    def test_reload_calls_orchestrator_with_payload(self):
        fake = FakeOrchestrator()
        self.api_module.orchestrator = fake
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)

        payload = {"userMcpServers": [{"id": "x"}]}
        r = client.post("/mcp/reload", json=payload)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(fake.reload_calls), 1)
        self.assertEqual(fake.reload_calls[0], [{"id": "x"}])

    def test_reload_with_empty_body_uses_cached_settings(self):
        fake = FakeOrchestrator()
        self.api_module.orchestrator = fake
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)

        r = client.post("/mcp/reload")
        self.assertEqual(r.status_code, 200)
        # Empty body → orchestrator gets None and falls back to cached settings
        self.assertEqual(fake.reload_calls[0], None)


class McpTestEndpointTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module
            from fastapi.testclient import TestClient
            cls.TestClient = TestClient

    def test_invalid_schema_returns_ok_false(self):
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)
        r = client.post("/mcp/test", json={"id": "missing-fields"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertFalse(data["ok"])
        self.assertIn("schema validation failed", data["error"])
        self.assertEqual(data["discovered_tools"], [])

    def test_disabled_server_short_circuits(self):
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)
        r = client.post("/mcp/test", json={
            "id": "off",
            "name": "Off",
            "transport": "streamable_http",
            "url": "http://x/mcp",
            "enabled": False,
            "tools": [],
        })
        data = r.json()
        self.assertFalse(data["ok"])
        self.assertIn("disabled", data["error"])

    def test_stdio_missing_cwd_returns_actionable_error(self):
        # Regression for issue #165: a stdio preset (e.g. CVE Intel) whose
        # `cwd` was never git-cloned must fail with a clear "install first"
        # message, NOT a bare FileNotFoundError.
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)
        r = client.post("/mcp/test", json={
            "id": "cve_intel_extra",
            "name": "CVE Intel (extended)",
            "transport": "stdio",
            "command": "python",
            "args": ["-m", "cve_mcp_server"],
            "cwd": "/tmp/does-not-exist-redamon-165",
            "tools": [],
        })
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertFalse(data["ok"])
        self.assertIn("does not exist", data["error"])
        self.assertIn("/tmp/does-not-exist-redamon-165", data["error"])
        self.assertNotIn("FileNotFoundError", data["error"])
        self.assertEqual(data["discovered_tools"], [])

    def _patch_session_with_tools(self, mcp_tools):
        """Patch MultiServerMCPClient.session() to yield a fake MCP session
        whose list_tools() returns the given protocol-level Tool objects.
        Mirrors the new endpoint that uses session.list_tools() instead of
        client.get_tools()."""
        from contextlib import asynccontextmanager

        fake_session = MagicMock()
        list_resp = MagicMock()
        list_resp.tools = mcp_tools
        fake_session.list_tools = AsyncMock(return_value=list_resp)

        @asynccontextmanager
        async def fake_session_ctx(_self, _server_name, **_kwargs):
            yield fake_session

        return patch(
            "langchain_mcp_adapters.client.MultiServerMCPClient.session",
            fake_session_ctx,
        )

    def test_test_endpoint_does_not_mutate_registry(self):
        # Stash current state, hit /mcp/test, confirm state unchanged.
        import mcp_registry as reg
        before = list(reg.current())
        before_errors = list(reg.current_errors())
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)

        # Build a fake MCP protocol Tool with raw inputSchema dict.
        fake_tool = MagicMock()
        fake_tool.name = "discovered_tool"
        fake_tool.description = "fake description"
        fake_tool.inputSchema = {"type": "object", "properties": {"q": {"type": "string"}}}

        with self._patch_session_with_tools([fake_tool]):
            r = client.post("/mcp/test", json={
                "id": "newone",
                "name": "New one",
                "transport": "streamable_http",
                "url": "http://x/mcp",
                "tools": [],
            })

        data = r.json()
        self.assertTrue(data["ok"], msg=str(data))
        self.assertEqual(len(data["discovered_tools"]), 1)
        self.assertEqual(data["discovered_tools"][0]["name"], "discovered_tool")
        self.assertEqual(
            data["discovered_tools"][0]["input_schema"],
            {"type": "object", "properties": {"q": {"type": "string"}}},
        )
        # Registry unchanged
        after = list(reg.current())
        self.assertEqual([s.id for s in before], [s.id for s in after])
        self.assertEqual(before_errors, list(reg.current_errors()))

    def test_test_endpoint_surfaces_declared_not_live_warning(self):
        client = self.TestClient(self.api_module.app, headers=MASTER_HEADERS)

        payload = {
            "id": "needs",
            "name": "Needs tool",
            "transport": "streamable_http",
            "url": "http://x/mcp",
            "tools": [{
                "name": "promised_tool",
                "purpose": "x", "when_to_use": "y",
                "args_format": '"a":"b"', "description": "z",
            }],
        }
        with self._patch_session_with_tools([]):  # server reports zero tools
            r = client.post("/mcp/test", json=payload)
        data = r.json()
        self.assertTrue(data["ok"])
        codes = [w["code"] for w in data["warnings"]]
        self.assertIn("declared_not_live", codes)


if __name__ == "__main__":
    unittest.main()
