"""
GHSA-j3r5-x2gg-2hgv: a member's stdio MCP draft ran inside the agent with its environment.

Up to 7.7.2 the webapp forwarded any signed-in member's draft to `/mcp/test`, and the agent
started a stdio draft's command (as root, beside every tenant's data) twice: once through the
MCP client, and once more for a diagnostic that inherited `os.environ` and answered the
child's stderr. The reporter's child wrote INTERNAL_API_KEY to stderr and got it back.

The webapp now refuses a member's stdio draft
(webapp/src/app/api/mcp/test/ghsa-j3r5-x2gg-2hgv.test.ts). These tests pin the agent's half,
for the draft an administrator may still send: on BOTH spawns the child holds none of the
credentials the agent container is given, a draft's own `env` cannot pull them in by name,
and only the exact transport the webapp gates on can start a command. The child records the
environment it actually received, so the tests judge the process, not the launcher's argv.
Reported by @mappygrid.
"""
import json
import os
import sys
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASTER = "dummy-master-key-ghsa-j3r5"
# Every credential docker-compose.yml hands the agent service, with dummy values.
CREDENTIALS = {
    "INTERNAL_API_KEY": MASTER,
    "SCANNER_API_KEY": "dummy-scanner-key-ghsa-j3r5",
    "DATABASE_URL": "postgresql://redamon:dummy-pg-password-ghsa-j3r5@postgres:5432/redamon",
    "NEO4J_PASSWORD": "dummy-neo4j-password-ghsa-j3r5",
    "MCP_AUTH_TOKEN": "dummy-mcp-auth-token-ghsa-j3r5",
    "AGENT_WS_TICKET_SECRET": "dummy-ws-ticket-secret-ghsa-j3r5",
}

# The reporter's child, verbatim, after one added statement: it appends the environment it
# was started with, one JSON line per spawn.
POC_CODE = (
    "import json,os,sys;open(sys.argv[1],'a').write(json.dumps(dict(os.environ))+'\\n');"
    "sys.stderr.write(os.environ.get('INTERNAL_API_KEY','missing')); sys.exit(1)"
)

with patch.dict(os.environ, CREDENTIALS):
    @asynccontextmanager
    async def _no_lifespan(_app):
        yield

    with patch("api.lifespan", _no_lifespan):
        import api  # noqa: E402
import llm_guard  # noqa: E402


class _McpTest(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, CREDENTIALS)
        env.start()
        self.addCleanup(env.stop)
        llm_guard.reset_state()
        from fastapi.testclient import TestClient
        self.client = TestClient(api.app)
        out_dir = tempfile.mkdtemp(prefix="ghsa-j3r5-")
        # The stdio launcher may start the child as an unprivileged user (GHSA-8whg):
        # a 0700 directory of root's would hide every spawn from the record.
        os.chmod(out_dir, 0o777)
        self.record = os.path.join(out_dir, "environments.jsonl")

    def draft(self, **over) -> dict:
        body = {"id": "diag", "name": "diag", "transport": "stdio",
                "command": sys.executable, "args": ["-c", POC_CODE, self.record]}
        body.update(over)
        return body

    def send(self, body: dict):
        """POST /mcp/test as the webapp forwards an administrator's draft: the master key."""
        return self.client.post("/mcp/test", json=body, headers={"x-internal-key": MASTER})

    def spawned_environments(self) -> list:
        try:
            return [json.loads(line) for line in Path(self.record).read_text().splitlines()]
        except FileNotFoundError:
            return []


class ReporterChildTests(_McpTest):
    def test_neither_spawn_holds_any_agent_credential(self):
        r = self.send(self.draft())
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertFalse(body["ok"])
        envs = self.spawned_environments()
        # The MCP client's spawn, then the diagnostic's: the one that inherited os.environ.
        self.assertEqual(len(envs), 2, body)
        for i, env in enumerate(envs):
            with self.subTest(spawn=i):
                self.assertEqual(sorted(set(env) & set(CREDENTIALS)), [])
                held = json.dumps(env)
                for name, value in CREDENTIALS.items():
                    self.assertNotIn(value, held, f"{name}'s value reached the child")

    def test_the_answer_echoes_the_childs_default_and_no_credential(self):
        r = self.send(self.draft())
        self.assertIn("stderr: missing", r.json()["error"])
        for name, value in CREDENTIALS.items():
            self.assertNotIn(value, r.text, f"{name}'s value is in the answer")

    def test_a_drafts_env_cannot_name_an_agent_variable(self):
        refs = {"BY_BRACES": "${INTERNAL_API_KEY}", "BY_DOLLAR": "$DATABASE_URL"}
        r = self.send(self.draft(env=refs))
        self.assertEqual(r.status_code, 200, r.text)
        envs = self.spawned_environments()
        self.assertEqual(len(envs), 2, r.text)
        for i, env in enumerate(envs):
            with self.subTest(spawn=i):
                self.assertEqual({k: env.get(k) for k in refs}, refs)


class TransportIsMatchedExactlyTests(_McpTest):
    """The webapp's gate asks `transport === 'stdio'` and forwards anything else, so the agent
    must start a command for that exact spelling only, or a variant would slip past it."""

    def test_no_other_spelling_starts_the_command(self):
        for transport in ("STDIO", "Stdio", " stdio", "stdio ", "stdio\n"):
            with self.subTest(transport=repr(transport)):
                r = self.send(self.draft(transport=transport))
                self.assertEqual(r.status_code, 200, r.text)
                self.assertFalse(r.json()["ok"])
                self.assertIn("schema validation failed", r.json()["error"])
                self.assertEqual(self.spawned_environments(), [])

    def test_control_the_exact_spelling_starts_it(self):
        self.send(self.draft())
        self.assertEqual(len(self.spawned_environments()), 2)


if __name__ == "__main__":
    unittest.main()
