"""
GHSA-3cjg-8cp8-j269: the Kali terminal handed a root shell to any WebSocket client.

Up to 7.7.2 mcp/servers/terminal_server.py was a bare websockets.serve() on
0.0.0.0:8016 that forked `/bin/bash --login` for whoever connected. The bearer
check added for the MCP tool servers (BearerAuthASGI) wraps only their SSE apps,
so this separate listener stayed open to every container on redamon-network and
pentest-net, to host-network scan containers and to local processes (compose
also published it on 127.0.0.1). The agent's /ws/kali-terminal proxy checked a
ticket, but nothing forced a client to go through it.

Pinned three ways:
  - the reporter's proof of concept, replayed against the real server and the
    real PTY path, starts no shell and runs no command. A control with the
    agent's bearer runs the same command through the same harness, so the
    refusal cannot be an artefact of the harness;
  - every listener the sandbox starts passes an auth gate. The root cause was
    one listener outside the authenticated set, and the guard flags the 7.7.2
    shape of the terminal server;
  - compose publishes 8016 on no host interface, and the agent still reaches it
    over the bridge.

Runs in the agent image (root-agent section): a real websockets server on
loopback, and a real fork + /bin/bash for the control.
Run: python -m pytest tests/test_ghsa_3cjg_terminal_unauth_pty.py
"""
import ast
import asyncio
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
SERVERS = REPO / "mcp" / "servers"
ENTRYPOINT = REPO / "mcp" / "kali-sandbox" / "entrypoint.sh"

sys.path.insert(0, str(SERVERS))

import terminal_server as ts  # noqa: E402

try:
    import websockets
    from websockets.exceptions import ConnectionClosed, InvalidStatus
    _HAVE_WS = True
except Exception:  # pragma: no cover - the agent image has websockets
    _HAVE_WS = False

try:
    import yaml
except Exception:  # pragma: no cover - the agent image has PyYAML
    yaml = None

TOKEN = "ghsa-3cjg-test-token"
PROXY_QUERY = "/?user_id=proxy-user&project_id=proxy-project&session_id=s1"
# The advisory's payload, with its marker file moved into a per-test directory.
POC_COMMAND = "id > {marker}; echo PTY_OWNED=$(whoami)@$(hostname)\n"
SHELL_WAIT_S = 20.0


@unittest.skipUnless(_HAVE_WS, "websockets unavailable")
@unittest.skipUnless(os.path.exists("/bin/bash"), "no /bin/bash for the PTY control")
class ReportersProofOfConceptRunsNothing(unittest.IsolatedAsyncioTestCase):
    """The advisory's client against the real terminal server, PTY path included."""

    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ghsa-3cjg-")
        self.marker = os.path.join(self.tmp, "redamon_pwned")
        real_fork = os.fork
        self._fork = mock.patch.object(ts.os, "fork", side_effect=real_fork)
        self.fork = self._fork.start()
        self.server = await ts.serve("127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self._fork.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def _poc(self, path="", headers=None, wait_for_marker=False):
        """Connect with no init frame, type the payload, read what comes back.

        Returns the handshake status: 101 when a socket opened, else the HTTP
        status the server refused it with.
        """
        try:
            async with websockets.connect(f"ws://127.0.0.1:{self.port}{path}",
                                          additional_headers=headers or {},
                                          open_timeout=5) as ws:
                await ws.send(POC_COMMAND.format(marker=self.marker))
                deadline = asyncio.get_running_loop().time() + (SHELL_WAIT_S if wait_for_marker else 2.5)
                while asyncio.get_running_loop().time() < deadline:
                    if wait_for_marker and os.path.exists(self.marker) and os.path.getsize(self.marker):
                        break
                    try:
                        await asyncio.wait_for(ws.recv(), timeout=0.25)
                    except asyncio.TimeoutError:
                        continue
                    except ConnectionClosed:
                        break
                return 101
        except InvalidStatus as exc:
            return exc.response.status_code

    def _assert_no_shell(self):
        self.assertFalse(os.path.exists(self.marker), "the payload ran: a shell was started")
        self.fork.assert_not_called()
        self.assertEqual(ts._active_sessions, 0)

    async def test_the_advisorys_client_is_refused_before_any_shell(self):
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": TOKEN}):
            self.assertEqual(await self._poc(), 401)
        self._assert_no_shell()

    async def test_the_proxys_identity_query_does_not_stand_in_for_the_bearer(self):
        """An attacker who copies the proxy's query string still needs the agent's token."""
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": TOKEN}):
            for headers in ({}, {"Authorization": "Bearer not-the-agents-token"},
                            {"Authorization": TOKEN}, {"X-Redamon-Run": "a.b"}):
                with self.subTest(headers=list(headers)):
                    self.assertEqual(await self._poc(PROXY_QUERY, headers), 401)
        self._assert_no_shell()

    async def test_a_sandbox_without_a_token_refuses_everyone(self):
        env = {k: v for k, v in os.environ.items() if k != "MCP_AUTH_TOKEN"}
        with mock.patch.dict(os.environ, env, clear=True):
            for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": f"Bearer {TOKEN}"}):
                with self.subTest(headers=headers):
                    self.assertEqual(await self._poc(PROXY_QUERY, headers), 401)
        self._assert_no_shell()

    async def test_control_the_agents_bearer_runs_the_same_payload(self):
        """Without this, a harness that never reached a shell would pass the refusals."""
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": TOKEN}):
            status = await self._poc(PROXY_QUERY, {"Authorization": f"Bearer {TOKEN}"},
                                     wait_for_marker=True)
        self.assertEqual(status, 101)
        self.fork.assert_called_once()
        with open(self.marker, encoding="utf-8", errors="replace") as fh:
            self.assertIn("uid=", fh.read())


# --- every listener the sandbox starts passes an auth gate ------------------------

# The processes mcp/kali-sandbox/entrypoint.sh starts, and the gate on each one's
# listeners. A new server process must be added here, with its gate, on purpose.
STARTED_SERVERS = {
    "run_servers.py": "MCP SSE servers via serve_sse_with_auth (BearerAuthASGI)",
    "tunnel_manager.py": "TunnelHandler checks TUNNEL_AUTH_TOKEN",
    "terminal_server.py": "process_request checks MCP_AUTH_TOKEN",
}

# Every listener in mcp/servers today: (file, kind). The guard must keep seeing
# them, so a guard that silently stops parsing cannot pass.
KNOWN_LISTENERS = {
    ("_auth_middleware.py", "uvicorn.run"),
    ("metasploit_server.py", "HTTPServer"),
    ("network_recon_server.py", "HTTPServer"),
    ("tunnel_manager.py", "HTTPServer"),
    ("terminal_server.py", "websockets.serve"),
}

_HTTP_SERVERS = {"HTTPServer", "ThreadingHTTPServer", "TCPServer", "ThreadingTCPServer"}
_NETWORK_TRANSPORTS = {"sse", "http", "streamable-http"}
_RAW_LISTENERS = {"start_server", "create_server", "start_unix_server"}


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _is_main_guard(node) -> bool:
    return (isinstance(node, ast.If) and "__name__" in ast.unparse(node.test)
            and "__main__" in ast.unparse(node.test))


def listener_report(source: str, filename: str, started: bool):
    """(listeners found, problems) for one module's source.

    A listener is a call that opens a network socket for clients. Each must sit
    behind its gate: websockets.serve needs process_request, an http.server
    handler must take BearerAuthHTTPHandlerMixin or compare a token itself,
    uvicorn must serve an app wrapped in BearerAuthASGI, and FastMCP's own
    network transport (unauthenticated) may only run from the __main__ block of a
    module the sandbox never starts.
    """
    tree = ast.parse(source, filename=filename)
    found, problems = set(), []

    ws_serve_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "websockets":
            ws_serve_names |= {a.asname or a.name for a in node.names if a.name == "serve"}

    classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    in_main = set()
    for node in tree.body:
        if _is_main_guard(node):
            in_main |= {id(n) for n in ast.walk(node)}

    def gated_handler(name: str) -> bool:
        cls = classes.get(name)
        if cls is None:
            return False
        if any(_dotted(b).endswith("BearerAuthHTTPHandlerMixin") for b in cls.bases):
            return True
        return any(isinstance(n, ast.Call) and _dotted(n.func) == "hmac.compare_digest"
                   for n in ast.walk(cls))

    def wrapped_app(arg, scope) -> bool:
        if isinstance(arg, ast.Call):
            return _dotted(arg.func).endswith("BearerAuthASGI")
        if isinstance(arg, ast.Name):
            for n in ast.walk(scope):
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == arg.id for t in n.targets):
                    return isinstance(n.value, ast.Call) and _dotted(n.value.func).endswith("BearerAuthASGI")
        return False

    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    seen = set()
    for scope in reversed(scopes):  # innermost function first, so assignments resolve locally
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call) or id(node) in seen:
                continue
            seen.add(id(node))
            name = _dotted(node.func)
            where = f"{filename}:{node.lineno}"
            kwargs = {k.arg: k.value for k in node.keywords if k.arg}

            if name == "websockets.serve" or name.endswith(".server.serve") or name in ws_serve_names:
                found.add((filename, "websockets.serve"))
                gate = kwargs.get("process_request")
                if gate is None or (isinstance(gate, ast.Constant) and gate.value is None):
                    problems.append(f"{where}: websockets.serve without process_request")
            elif name.split(".")[-1] in _HTTP_SERVERS:
                found.add((filename, "HTTPServer"))
                handler = node.args[1] if len(node.args) > 1 else kwargs.get("RequestHandlerClass")
                if not (isinstance(handler, ast.Name) and gated_handler(handler.id)):
                    problems.append(f"{where}: {name} handler has no auth gate")
            elif name == "uvicorn.run":
                found.add((filename, "uvicorn.run"))
                if not (node.args and wrapped_app(node.args[0], scope)):
                    problems.append(f"{where}: uvicorn.run serves an app not wrapped in BearerAuthASGI")
            elif name.split(".")[-1] == "run" and isinstance(kwargs.get("transport"), ast.Constant) \
                    and kwargs["transport"].value in _NETWORK_TRANSPORTS:
                if started or id(node) not in in_main:
                    problems.append(f"{where}: {name}(transport={kwargs['transport'].value!r}) serves "
                                    "without the bearer gate (use serve_sse_with_auth)")
            elif name.split(".")[-1] in _RAW_LISTENERS:
                found.add((filename, name))
                problems.append(f"{where}: {name} opens a listener with no auth gate this guard knows")
    return found, problems


def _server_sources():
    for path in sorted(SERVERS.glob("*.py")):
        yield path.name, path.read_text(encoding="utf-8")


class EveryKaliListenerAuthenticates(unittest.TestCase):
    def test_the_entrypoint_starts_only_the_known_servers(self):
        script = ENTRYPOINT.read_text(encoding="utf-8")
        live = [ln for ln in script.splitlines() if not ln.lstrip().startswith("#")]
        started = set(re.findall(r"python3?\s+/opt/mcp_servers/([\w.-]+\.py)", "\n".join(live)))
        self.assertEqual(started, set(STARTED_SERVERS),
                         "a server process was added or removed: list it in STARTED_SERVERS with its gate")

    def test_run_servers_serves_sse_only_through_the_bearer_wrapper(self):
        tree = ast.parse((SERVERS / "run_servers.py").read_text(encoding="utf-8"))
        calls = {_dotted(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        self.assertIn("serve_sse_with_auth", calls)

    def test_no_listener_skips_its_gate(self):
        found, problems = set(), []
        for name, source in _server_sources():
            f, p = listener_report(source, name, started=name in STARTED_SERVERS)
            found |= f
            problems += p
        self.assertEqual(problems, [])
        self.assertEqual(found, KNOWN_LISTENERS,
                         "the listeners changed: add the new one to KNOWN_LISTENERS once it is gated")


class TheGuardCatchesTheVulnerableShapes(unittest.TestCase):
    def _problems(self, source, started=True):
        return listener_report(source, "probe.py", started)[1]

    def test_the_7_7_2_terminal_server_is_flagged(self):
        vulnerable = (
            "import websockets\n"
            "async def _run():\n"
            "    async with websockets.serve(_pty_session, '0.0.0.0', PORT,\n"
            "                                ping_interval=30, ping_timeout=60, max_size=2**20):\n"
            "        pass\n"
        )
        self.assertEqual(len(self._problems(vulnerable)), 1)

    def test_an_explicit_none_gate_or_an_aliased_serve_is_flagged(self):
        self.assertTrue(self._problems("import websockets\nwebsockets.serve(h, '', 1, process_request=None)\n"))
        self.assertTrue(self._problems("from websockets.asyncio.server import serve as s\ns(h, '', 1)\n"))

    def test_an_ungated_http_handler_is_flagged(self):
        source = (
            "from http.server import HTTPServer, BaseHTTPRequestHandler\n"
            "class Plain(BaseHTTPRequestHandler):\n"
            "    def do_GET(self): pass\n"
            "HTTPServer(('0.0.0.0', 1), Plain)\n"
        )
        self.assertTrue(self._problems(source))

    def test_an_unwrapped_uvicorn_app_is_flagged(self):
        self.assertTrue(self._problems("import uvicorn\nuvicorn.run(app, host='0.0.0.0', port=1)\n"))

    def test_fastmcp_network_transport_is_flagged_where_the_sandbox_runs_it(self):
        source = "mcp.run(transport='sse', host='0.0.0.0', port=1)\n"
        self.assertTrue(self._problems(source, started=True))
        self.assertTrue(self._problems(source, started=False))  # module level runs on import
        main_only = "if __name__ == '__main__':\n    mcp.run(transport='sse', host='0.0.0.0', port=1)\n"
        self.assertTrue(self._problems(main_only, started=True))
        self.assertEqual(self._problems(main_only, started=False), [])

    def test_a_raw_asyncio_listener_is_flagged(self):
        self.assertTrue(self._problems("import asyncio\nasyncio.start_server(cb, '0.0.0.0', 1)\n"))

    def test_the_gated_shapes_pass(self):
        gated = (
            "import websockets, uvicorn\n"
            "from http.server import HTTPServer, BaseHTTPRequestHandler\n"
            "from _auth_middleware import BearerAuthHTTPHandlerMixin, BearerAuthASGI\n"
            "class H(BearerAuthHTTPHandlerMixin, BaseHTTPRequestHandler):\n"
            "    pass\n"
            "def serve(host, port):\n"
            "    return websockets.serve(h, host, port, process_request=_process_request)\n"
            "def http():\n"
            "    HTTPServer(('0.0.0.0', 1), H)\n"
            "def sse(app):\n"
            "    wrapped = BearerAuthASGI(app)\n"
            "    uvicorn.run(wrapped, host='0.0.0.0', port=1)\n"
        )
        self.assertEqual(self._problems(gated), [])


# --- compose: 8016 is published on no host interface -------------------------------

def _compose_loader():
    class Loader(yaml.SafeLoader):
        pass

    def tagged(loader, node):  # compose's !override / !reset merge tags
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        return loader.construct_scalar(node)

    for tag in ("!override", "!reset"):
        Loader.add_constructor(tag, tagged)
    return Loader


def _container_port(entry) -> str:
    if isinstance(entry, dict):
        return str(entry.get("target", ""))
    return str(entry).rsplit(":", 1)[-1].split("/", 1)[0].strip()


@unittest.skipUnless(yaml is not None, "PyYAML unavailable")
class TerminalIsNotPublishedOnTheHost(unittest.TestCase):
    COMPOSE_FILES = (
        REPO / "docker-compose.yml",
        REPO / "tooling" / "deploy" / "single-host" / "compose" / "docker-compose.prod.yml",
    )

    def _load(self, path):
        return yaml.load(path.read_text(encoding="utf-8"), Loader=_compose_loader())

    def test_no_compose_file_publishes_8016(self):
        for path in self.COMPOSE_FILES:
            with self.subTest(file=path.name):
                kali = self._load(path)["services"]["kali-sandbox"]
                ports = [_container_port(p) for p in kali.get("ports", [])]
                self.assertTrue(ports, "the kali-sandbox ports list was not read")
                self.assertNotIn("8016", ports)

    def test_the_agent_still_reaches_it_over_the_bridge(self):
        services = self._load(self.COMPOSE_FILES[0])["services"]
        self.assertEqual(services["agent"]["environment"]["KALI_TERMINAL_WS_URL"], "ws://kali-sandbox:8016")
        self.assertIn("redamon", services["agent"]["networks"])
        self.assertIn("redamon", services["kali-sandbox"]["networks"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
