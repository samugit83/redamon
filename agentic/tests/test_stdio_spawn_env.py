"""
A stdio MCP server never sees the agent's secrets (NF-14, step 1.9).

A stdio server runs its `command` inside the agent container, which holds every
tenant's data and the master secrets. Both paths that start one hand it only its
own `env` plus PATH, HOME and LANG:

  - the client config (`mcp_registry.to_mcp_servers_dict`, what MultiServerMCPClient
    spawns at reload and at /mcp/test). langchain-mcp-adapters 0.3.0 expands
    `${VAR}` in stdio env values from the agent's environment, so an env value
    `${INTERNAL_API_KEY}` must still reach the child as that literal text;
  - the diagnostic re-spawn /mcp/test runs when the client fails.

The children here are real processes that dump their environment to a file.
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mcp_registry as reg  # noqa: E402

MASTER = "master-secret-value-0001"
AGENT_SECRETS = {
    "INTERNAL_API_KEY": MASTER,
    "SCANNER_API_KEY": "scanner-secret-value-0002",
    "DATABASE_URL": "postgresql://redamon:db-secret-0003@postgres:5432/redamon",
    "NEO4J_PASSWORD": "neo4j-secret-0004",
    "AGENT_WS_TICKET_SECRET": "ticket-secret-0005",
    "MCP_AUTH_TOKEN": "mcp-secret-0006",
}
BASE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}

# Writes the child's whole environment to <dir>/<pid>.json and exits at once.
DUMP_ENV = (
    "import json, os, sys; "
    "json.dump(dict(os.environ), open(os.path.join(sys.argv[1], f'{os.getpid()}.json'), 'w'))"
)


def _server(out_dir: str, **overrides):
    spec = {
        "id": "envdump",
        "name": "env dump",
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-c", DUMP_ENV, out_dir],
        "env": {"OWN_KEY": "own-value", "REF": "${INTERNAL_API_KEY}"},
        "tools": [],
    }
    spec.update(overrides)
    return reg.MCPServer.model_validate(spec)


def _dumps(out_dir: str) -> list:
    return [json.loads(p.read_text()) for p in sorted(Path(out_dir).glob("*.json"))]


class _SecretsInEnv(unittest.TestCase):
    def setUp(self):
        self._env = patch.dict(os.environ, {**AGENT_SECRETS, **BASE_ENV})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.out_dir = tempfile.mkdtemp(prefix="stdio-env-")
        # The child runs as mcp_registry.STDIO_UID under a root agent; mkdtemp's 0700
        # would hide its dump, not its spawn.
        os.chmod(self.out_dir, 0o777)

    def assertChildEnvClean(self, env: dict):
        for name in AGENT_SECRETS:
            self.assertNotIn(name, env)
        joined = "\n".join(f"{k}={v}" for k, v in env.items())
        for value in AGENT_SECRETS.values():
            self.assertNotIn(value, joined)
        self.assertEqual(env.get("OWN_KEY"), "own-value")
        self.assertEqual(env.get("REF"), "${INTERNAL_API_KEY}", "the reference was expanded")
        self.assertEqual(set(env), {"PATH", "HOME", "LANG", "OWN_KEY", "REF"})


class StdioSpawnEnvTests(_SecretsInEnv):
    def test_the_spawn_environment_is_the_servers_own_env_plus_path_home_lang(self):
        self.assertEqual(reg.stdio_spawn_env(_server(self.out_dir)), {
            **BASE_ENV, "OWN_KEY": "own-value", "REF": "${INTERNAL_API_KEY}",
        })

    def test_the_client_config_carries_no_env_for_the_adapter_to_expand(self):
        cfg, _ = reg.to_mcp_servers_dict([_server(self.out_dir)])
        entry = cfg["envdump"]
        self.assertNotIn("env", entry)
        self.assertEqual(entry["command"], reg.STDIO_ENV_LAUNCHER)
        self.assertEqual(entry["args"][:2], ["-i", "--"])
        self.assertEqual(entry["args"][-3:], ["-c", DUMP_ENV, self.out_dir])
        self.assertIn(sys.executable, entry["args"])

    def test_the_stdio_spawn_environment_holds_no_agent_secret(self):
        """The real adapter path: MultiServerMCPClient spawns the configured server."""
        from langchain_mcp_adapters.client import MultiServerMCPClient

        cfg, _ = reg.to_mcp_servers_dict([_server(self.out_dir)])

        async def _open():
            async with MultiServerMCPClient(cfg).session("envdump"):
                pass

        async def _run():
            try:
                await asyncio.wait_for(_open(), timeout=20)
            except BaseException:  # the child is no MCP server: the session fails
                pass

        asyncio.run(_run())
        dumps = _dumps(self.out_dir)
        self.assertEqual(len(dumps), 1, "the configured server was not spawned")
        self.assertChildEnvClean(dumps[0])

    def test_a_command_or_env_name_holding_equals_is_refused(self):
        with self.assertRaises(Exception):
            _server(self.out_dir, command="A=B")
        with self.assertRaises(Exception):
            _server(self.out_dir, env={"A=B": "x"})


class McpTestRouteSpawnTests(_SecretsInEnv):
    """/mcp/test spawns the draft twice when it is no MCP server: the client, then the diagnostic."""

    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
        from fastapi.testclient import TestClient
        cls.client = TestClient(api_module.app)

    def test_both_test_spawns_hold_no_agent_secret(self):
        r = self.client.post(
            "/mcp/test", json=_server(self.out_dir).model_dump(),
            headers={"x-internal-key": MASTER},
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["ok"])
        dumps = _dumps(self.out_dir)
        self.assertEqual(len(dumps), 2, f"expected the client and the diagnostic spawn: {r.json()}")
        for env in dumps:
            self.assertChildEnvClean(env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
