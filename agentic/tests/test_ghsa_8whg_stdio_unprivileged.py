"""
GHSA-8whg-rvcr-r88r: a stdio MCP server ran as root inside the agent.

The agent container holds every tenant's data and the master secrets, and its
image has no USER. A stdio server's command ran as root there, so clearing its
environment (`env -i`, NF-14) hid nothing: the child read the agent's secrets back
from /proc/<agent pid>/environ. Since only an admin's stdio server is loaded, that
was the whole instance in the hands of whatever npm/pip package the admin added.
Reported by @recuon.

Both spawn paths now start the command as mcp_registry.STDIO_UID with no groups,
no capabilities and no-new-privs. The children here are real processes that
report who they are and try to read the agent process's environment.
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

MASTER = "dummy-master-key-ghsa-8whg-stdio"

# Reports the child's identity to <dir>/<pid>.json and tries the agent's environ.
PROBE = "\n".join((
    "import json, os, sys",
    "out, agent_pid = sys.argv[1], sys.argv[2]",
    "try:",
    "    open(f'/proc/{agent_pid}/environ', 'rb').read()",
    "    environ = 'readable'",
    "except PermissionError:",
    "    environ = 'denied'",
    "status = dict(l.split(':', 1) for l in open('/proc/self/status').read().splitlines() if ':' in l)",
    "json.dump({'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(),",
    "           'groups': os.getgroups(), 'cap_eff': status['CapEff'].strip(),",
    "           'cap_prm': status['CapPrm'].strip(),",
    "           'no_new_privs': status.get('NoNewPrivs', '').strip(),",
    "           'home': os.environ.get('HOME'), 'environ': environ},",
    "          open(os.path.join(out, f'{os.getpid()}.json'), 'w'))",
))


def _server(out_dir: str, **overrides) -> reg.MCPServer:
    spec = {
        "id": "probe", "name": "probe", "transport": "stdio",
        "command": sys.executable, "args": ["-c", PROBE, out_dir, str(os.getpid())],
        "tools": [],
    }
    spec.update(overrides)
    return reg.MCPServer.model_validate(spec)


def _reports(out_dir: str) -> list:
    return [json.loads(p.read_text()) for p in sorted(Path(out_dir).glob("*.json"))]


class LaunchCommand(unittest.TestCase):
    """What `stdio_launch` builds; the order is what makes the drop hold."""

    def _root_launch(self, srv):
        with patch.object(reg.os, "geteuid", return_value=0), \
                patch.object(reg, "_ensure_stdio_home", return_value=reg.STDIO_HOME), \
                patch.dict(os.environ, {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}):
            return reg.stdio_launch(srv)

    def test_a_root_agent_starts_the_command_through_setpriv_inside_env_i(self):
        srv = _server("/tmp/x", env={"OWN": "1"})
        launcher, args = self._root_launch(srv)
        self.assertEqual(launcher, reg.STDIO_ENV_LAUNCHER)
        self.assertEqual(args[:2], ["-i", "--"])
        at = args.index(reg.STDIO_PRIVDROP)
        # Hop 1, root: only the agent's PATH and LANG and the unprivileged HOME.
        self.assertEqual(args[2:at], ["PATH=/usr/bin:/bin", f"HOME={reg.STDIO_HOME}", "LANG=C.UTF-8"])
        # Hop 2: setpriv with every flag, then its own `--`.
        end = at + 1 + len(reg.STDIO_PRIVDROP_ARGS)
        self.assertEqual(args[at + 1:end], list(reg.STDIO_PRIVDROP_ARGS))
        self.assertEqual(args[end], "--")
        # Hop 3, unprivileged: env adds the server's own variables, then the command.
        self.assertEqual(args[end + 1:], [reg.STDIO_ENV_LAUNCHER, "--", "OWN=1", srv.command, *srv.args])
        for flag in (f"--reuid={reg.STDIO_UID}", f"--regid={reg.STDIO_GID}", "--clear-groups",
                     "--no-new-privs"):
            self.assertIn(flag, reg.STDIO_PRIVDROP_ARGS)
        self.assertNotEqual(reg.STDIO_UID, 0)

    def test_no_server_variable_reaches_the_root_hop(self):
        srv = _server("/tmp/x", env={"LD_PRELOAD": "/var/lib/redamon-mcp/x.so", "PATH": "/evil"})
        _, args = self._root_launch(srv)
        at = args.index(reg.STDIO_PRIVDROP)
        self.assertNotIn("LD_PRELOAD=/var/lib/redamon-mcp/x.so", args[:at])
        self.assertNotIn("PATH=/evil", args[:at])
        self.assertIn("LD_PRELOAD=/var/lib/redamon-mcp/x.so", args[at:])

    def test_the_servers_own_home_wins(self):
        srv = _server("/tmp/x", env={"HOME": "/opt/tool-home"})
        _, args = self._root_launch(srv)
        at = args.index(reg.STDIO_PRIVDROP)
        self.assertIn("HOME=/opt/tool-home", args[at:])

    def test_a_non_root_agent_cannot_switch_uid_and_does_not_try(self):
        srv = _server("/tmp/x")
        with patch.object(reg.os, "geteuid", return_value=1000):
            _, args = reg.stdio_launch(srv)
        self.assertNotIn(reg.STDIO_PRIVDROP, args)
        self.assertEqual(args[-len(srv.args) - 1:], [srv.command, *srv.args])

    def test_the_client_config_uses_the_same_launch(self):
        srv = _server("/tmp/x")
        with patch.object(reg.os, "geteuid", return_value=0), \
                patch.object(reg, "_ensure_stdio_home", return_value=reg.STDIO_HOME):
            cfg, _ = reg.to_mcp_servers_dict([srv])
            launcher, args = reg.stdio_launch(srv)
        self.assertEqual((cfg["probe"]["command"], cfg["probe"]["args"]), (launcher, args))


class _RealChild(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("the uid drop needs a root agent, as in the agent image")
        self._env = patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.out_dir = tempfile.mkdtemp(prefix="stdio-uid-")
        os.chmod(self.out_dir, 0o777)

    def assertUnprivileged(self, report: dict):
        self.assertEqual((report["uid"], report["euid"]), (reg.STDIO_UID, reg.STDIO_UID), report)
        self.assertEqual(report["gid"], reg.STDIO_GID, report)
        self.assertEqual([g for g in report["groups"] if g != reg.STDIO_GID], [], report)
        self.assertEqual(int(report["cap_eff"], 16), 0, report)
        self.assertEqual(int(report["cap_prm"], 16), 0, report)
        self.assertEqual(report["no_new_privs"], "1", report)
        self.assertEqual(report["home"], reg.STDIO_HOME, report)
        self.assertEqual(report["environ"], "denied", "the child read the agent's environment")


class ClientSpawnRunsUnprivileged(_RealChild):
    def test_the_configured_server_cannot_read_the_agents_environment(self):
        from langchain_mcp_adapters.client import MultiServerMCPClient

        cfg, _ = reg.to_mcp_servers_dict([_server(self.out_dir)])

        async def _open():
            async with MultiServerMCPClient(cfg).session("probe"):
                pass

        async def _run():
            try:
                await asyncio.wait_for(_open(), timeout=20)
            except BaseException:  # the probe is no MCP server: the session fails
                pass

        asyncio.run(_run())
        reports = _reports(self.out_dir)
        self.assertEqual(len(reports), 1, "the configured server was not spawned")
        self.assertUnprivileged(reports[0])
        home = os.lstat(reg.STDIO_HOME)
        self.assertEqual((home.st_uid, home.st_mode & 0o777), (reg.STDIO_UID, 0o700))


class McpTestSpawnsRunUnprivileged(_RealChild):
    """/mcp/test starts a failing draft twice: the client, then the diagnostic."""

    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
        from fastapi.testclient import TestClient
        cls.client = TestClient(api_module.app)

    def test_both_test_spawns_run_as_the_unprivileged_account(self):
        r = self.client.post("/mcp/test", json=_server(self.out_dir).model_dump(),
                             headers={"x-internal-key": MASTER})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["ok"])
        reports = _reports(self.out_dir)
        self.assertEqual(len(reports), 2, f"expected the client and the diagnostic spawn: {r.json()}")
        for report in reports:
            self.assertUnprivileged(report)

    def test_a_missing_command_is_still_named(self):
        r = self.client.post("/mcp/test", json=_server(self.out_dir, command="no-such-mcp-binary").model_dump(),
                             headers={"x-internal-key": MASTER})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("command not found: 'no-such-mcp-binary'", r.json()["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
