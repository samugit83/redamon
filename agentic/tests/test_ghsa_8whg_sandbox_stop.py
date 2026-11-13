"""
GHSA-8whg-rvcr-r88r: stopping a run left its sandbox commands running.

PAUSE ALL, the instance-wide emergency stop and the chat's own stop cancel the
run's asyncio tasks. The MCP client does not tell the server a call was
cancelled, so a `kali_shell`, hydra or nuclei process kept hitting the target
until its own timeout (300 s, 1800 s for hydra). Reported by @recuon.

The agent now names the run on each call to a run-tagged sandbox server and asks
the sandbox to kill the run's processes when it stops. These tests pin the agent
half; tests/test_ghsa_8whg_sandbox_run_kill.py pins the sandbox half.
"""
import asyncio
import importlib.util
import json
import sys
import unittest
from dataclasses import dataclass, field, replace
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_AGENTIC_DIR))

import sandbox_runs  # noqa: E402
from agent_context import current_log_session_id, current_session_id  # noqa: E402

SESSION = "3f2b9c1e-run-under-test"


@dataclass
class _Request:
    """The fields of langchain_mcp_adapters.interceptors.MCPToolCallRequest we use."""
    name: str
    server_name: str
    args: dict = field(default_factory=dict)

    def override(self, **changes):
        return replace(self, **changes)


class _Tool:
    def __init__(self, name, properties):
        self.name = name
        self.args_schema = {"type": "object", "properties": properties}


def _tagger(*tools):
    tagger = sandbox_runs.RunTagInterceptor()
    tagger.learn(tools)
    return tagger


def _call(tagger, request, session=SESSION):
    seen = []

    async def handler(req):
        seen.append(req)
        return "ok"

    async def run():
        token = current_log_session_id.set(session)
        try:
            return await tagger(request, handler)
        finally:
            current_log_session_id.reset(token)

    asyncio.run(run())
    return seen[0]


ADVERTISED = {"command": {"type": "string"}, sandbox_runs.RUN_ARG: {"type": "string"}}


class RunTagInterceptorTests(unittest.TestCase):

    def test_a_sandbox_call_inside_a_run_carries_the_run(self):
        tagger = _tagger(_Tool("kali_shell", ADVERTISED))
        sent = _call(tagger, _Request("kali_shell", "network_recon", {"command": "id"}))
        self.assertEqual(sent.args, {"command": "id", sandbox_runs.RUN_ARG: SESSION})

    def test_the_session_id_survives_a_node_blanking_current_session_id(self):
        tagger = _tagger(_Tool("kali_shell", ADVERTISED))

        async def run():
            log_token = current_log_session_id.set(SESSION)
            blank = current_session_id.set("")
            try:
                return await tagger(_Request("kali_shell", "network_recon", {}), _echo)
            finally:
                current_session_id.reset(blank)
                current_log_session_id.reset(log_token)

        self.assertEqual(asyncio.run(run()).args[sandbox_runs.RUN_ARG], SESSION)

    def test_a_tool_that_does_not_advertise_the_argument_gets_none(self):
        # A sandbox started before this change would reject the unknown argument.
        tagger = _tagger(_Tool("kali_shell", {"command": {"type": "string"}}))
        sent = _call(tagger, _Request("kali_shell", "network_recon", {"command": "id"}))
        self.assertEqual(sent.args, {"command": "id"})

    def test_a_user_mcp_server_never_learns_a_session_id(self):
        tagger = _tagger(_Tool("harvest", ADVERTISED))
        sent = _call(tagger, _Request("harvest", "someones_server", {"command": "x"}))
        self.assertNotIn(sandbox_runs.RUN_ARG, sent.args)

    def test_metasploit_is_never_tagged(self):
        # Its msfconsole is shared by every chat; it must not die with one run.
        self.assertNotIn("metasploit", sandbox_runs.RUN_TAGGED_SERVERS)
        tagger = _tagger(_Tool("metasploit_console", ADVERTISED))
        sent = _call(tagger, _Request("metasploit_console", "metasploit", {}))
        self.assertNotIn(sandbox_runs.RUN_ARG, sent.args)

    def test_the_model_cannot_name_another_run(self):
        tagger = _tagger(_Tool("kali_shell", ADVERTISED))
        forged = {"command": "id", sandbox_runs.RUN_ARG: "someone-elses-session"}
        self.assertEqual(_call(tagger, _Request("kali_shell", "network_recon", dict(forged))).args,
                         {"command": "id", sandbox_runs.RUN_ARG: SESSION})
        # Outside a run the forged value is dropped too, and nothing replaces it.
        self.assertEqual(_call(tagger, _Request("kali_shell", "network_recon", dict(forged)), session="").args,
                         {"command": "id"})

    def test_the_run_names_match_the_sandbox(self):
        spec = importlib.util.spec_from_file_location(
            "_run_registry_for_test", _AGENTIC_DIR.parent / "mcp" / "servers" / "_run_registry.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.assertEqual(sandbox_runs.RUN_ARG, sandbox.RUN_ARG)
        self.assertEqual(sandbox_runs.STOP_PATH, sandbox.STOP_PATH)
        self.assertEqual(sandbox_runs.RUN_TAGGED_SERVERS, sandbox.RUN_TAGGED_SERVERS)
        self.assertIn(sandbox.STOP_SERVER, sandbox.RUN_TAGGED_SERVERS)


async def _echo(req):
    return req


class ToolManagerInstallsTheTagger(unittest.TestCase):

    def test_get_tools_installs_the_interceptor_and_learns_the_schemas(self):
        from tools import MCPToolsManager

        built = []

        class _Client:
            def __init__(self, servers):
                self.tool_interceptors = []
                built.append(self)

            async def get_tools(self):
                return [_Tool("kali_shell", ADVERTISED), _Tool("plain", {})]

        mgr = MCPToolsManager({"network_recon": {"url": "http://kali/sse", "transport": "sse"}})
        with mock.patch("tools.MultiServerMCPClient", _Client):
            asyncio.run(mgr.get_tools(max_retries=1, retry_delay=0))
        self.assertEqual(built[0].tool_interceptors, [mgr._run_tagger])
        self.assertEqual(mgr._run_tagger._advertised, frozenset({"kali_shell"}))


class StopReachesTheSandbox(unittest.TestCase):

    def _manager(self):
        from websocket_api import WebSocketManager
        return WebSocketManager()

    def test_stopping_a_running_session_asks_the_sandbox_to_kill_its_processes(self):
        async def scenario():
            mgr = self._manager()
            task = asyncio.ensure_future(asyncio.sleep(30))
            mgr.register_task(f"u1:p1:{SESSION}", task)
            with mock.patch("websocket_api.schedule_sandbox_stop") as stop:
                await mgr.stop_session(f"u1:p1:{SESSION}")
            stop.assert_called_once_with(SESSION)

        asyncio.run(scenario())

    def test_a_running_tool_alone_is_enough(self):
        async def scenario():
            mgr = self._manager()
            tool = asyncio.ensure_future(asyncio.sleep(30))
            mgr.register_tool_task(f"u1:p1:{SESSION}", "kali_shell", None, None, tool)
            with mock.patch("websocket_api.schedule_sandbox_stop") as stop:
                await mgr.stop_session(f"u1:p1:{SESSION}")
            stop.assert_called_once_with(SESSION)

        asyncio.run(scenario())

    def test_the_emergency_stop_reaches_the_sandbox_for_each_run(self):
        async def scenario():
            mgr = self._manager()
            for sid in ("s-one", "s-two"):
                mgr.register_task(f"u{sid}:p:{sid}", asyncio.ensure_future(asyncio.sleep(30)))
            with mock.patch("websocket_api.schedule_sandbox_stop") as stop, \
                    mock.patch("websocket_api.update_conversation", mock.AsyncMock()):
                await mgr._emergency_stop(list(mgr._active_tasks), "stopped")
            self.assertEqual(sorted(c.args[0] for c in stop.call_args_list), ["s-one", "s-two"])

        asyncio.run(scenario())

    def test_a_session_with_nothing_running_sends_nothing(self):
        async def scenario():
            mgr = self._manager()
            with mock.patch("websocket_api.schedule_sandbox_stop") as stop:
                await mgr.stop_session(f"u1:p1:{SESSION}")
            stop.assert_not_called()

        asyncio.run(scenario())

    def test_the_chats_own_stop_button_reaches_the_sandbox(self):
        from websocket_api import WebSocketConnection, WebSocketHandler

        class _FakeWS:
            client = "test"

            async def send_json(self, msg):
                pass

            async def close(self, code=1000, reason=""):
                pass

        class _Graph:
            async def aget_state(self, config):
                raise RuntimeError("no checkpoint in this test")

        class _Orchestrator:
            graph = _Graph()

        async def scenario():
            mgr = self._manager()
            conn = WebSocketConnection(_FakeWS())
            await mgr.authenticate(conn, "u1", "p1", SESSION, verified=True)
            mgr.register_task(f"u1:p1:{SESSION}", asyncio.ensure_future(asyncio.sleep(30)))
            handler = WebSocketHandler(_Orchestrator(), mgr)
            with mock.patch("websocket_api.schedule_sandbox_stop") as stop:
                await handler.handle_stop(conn, {})
            stop.assert_called_once_with(SESSION)

        asyncio.run(scenario())


class StopRequest(unittest.TestCase):

    def _run(self, transport, env=None):
        import httpx

        real = httpx.AsyncClient

        def client(*args, **kwargs):
            return real(*args, transport=transport, **kwargs)

        with mock.patch.dict("os.environ", env or {}, clear=False), \
                mock.patch.object(httpx, "AsyncClient", client):
            return asyncio.run(sandbox_runs.stop_sandbox_run(SESSION))

    def test_it_posts_the_run_with_the_sandbox_bearer(self):
        import httpx

        seen = []

        def answer(request):
            seen.append(request)
            return httpx.Response(200, json={"run": SESSION, "signalled": 3})

        signalled = self._run(httpx.MockTransport(answer), {
            "MCP_NETWORK_RECON_URL": "http://kali-sandbox:8000/sse", "MCP_AUTH_TOKEN": "dummy-bearer"})
        self.assertEqual(signalled, 3)
        self.assertEqual(str(seen[0].url), "http://kali-sandbox:8000/redamon/runs/stop")
        self.assertEqual(seen[0].headers["authorization"], "Bearer dummy-bearer")
        self.assertEqual(json.loads(seen[0].read()), {"run": SESSION})

    def test_an_unreachable_or_refusing_sandbox_never_raises(self):
        import httpx

        def down(request):
            raise httpx.ConnectError("refused")

        self.assertIsNone(self._run(httpx.MockTransport(down)))
        self.assertIsNone(self._run(httpx.MockTransport(lambda r: httpx.Response(401))))

    def test_a_malformed_run_key_is_never_sent(self):
        self.assertIsNone(asyncio.run(sandbox_runs.stop_sandbox_run("../../etc")))
        self.assertIsNone(asyncio.run(sandbox_runs.stop_sandbox_run("")))


if __name__ == "__main__":
    unittest.main()
