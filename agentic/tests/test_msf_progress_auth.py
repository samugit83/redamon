"""
Every agent caller of a Kali sandbox's :8013 (Metasploit session manager) and :8014
(Hydra progress) servers sends `Authorization: Bearer <that instance's token>` (NF-03),
never the old shared MCP_AUTH_TOKEN, which is set here to show it is never sent.

Those servers refuse any request without it, so a caller that forgets the header
breaks silently: a new session is never linked to its chat (so its project never sees
it), and long-running Metasploit or Hydra commands stop streaming progress. The
callers here are the two best-effort posts of both executor nodes (single tool and
parallel plan) and the progress poller `execute_with_progress`; the six session proxy
routes of api.py are tested per sandbox in test_sandbox_sessions_proxy.py.

The HTTP client is replaced by a recorder; nothing leaves the process.

Run in-container: ./agentic/run_tests.sh tests/test_msf_progress_auth.py
"""
import ast
import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import sandbox_contract as contract  # noqa: E402
import tools  # noqa: E402
from one_sandbox import TOKEN, handle  # noqa: E402
from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node  # noqa: E402
from orchestrator_helpers.nodes.execute_tool_node import execute_tool_node  # noqa: E402

MASTER = "master-key-for-test"
OLD_TOKEN = "old-shared-mcp-auth-token"
BEARER = f"Bearer {TOKEN}"
SANDBOX = handle()
SESSIONS = f"http://{SANDBOX.host}:{contract.PORTS['sessions']}"
HYDRA = f"http://{SANDBOX.host}:{contract.PORTS['hydra']}"


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = {"ok": True} if body is None else body

    def json(self):
        return self._body


class _RecordingClient:
    """Stands in for httpx.AsyncClient; every request lands in `calls`."""

    calls = []
    status = 200
    body = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def _record(self, method, url, kwargs):
        type(self).calls.append({"method": method, "url": str(url),
                                 "headers": dict(kwargs.get("headers") or {}),
                                 "json": kwargs.get("json")})
        return _Resp(type(self).status, type(self).body)

    async def get(self, url, **kwargs):
        return self._record("GET", url, kwargs)

    async def post(self, url, **kwargs):
        return self._record("POST", url, kwargs)


class _Case(unittest.TestCase):
    """The run holds its person's sandbox (SANDBOX); the old shared token is in the
    environment and must never be sent."""

    def setUp(self):
        _RecordingClient.calls = []
        _RecordingClient.status = 200
        _RecordingClient.body = None
        patchers = [
            mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER, "MCP_AUTH_TOKEN": OLD_TOKEN,
                                         "MCP_METASPLOIT_PROGRESS_URL": "http://kali-sandbox:8013/progress",
                                         "MCP_HYDRA_PROGRESS_URL": "http://kali-sandbox:8014/progress"}),
            mock.patch("httpx.AsyncClient", _RecordingClient),
            # The nodes and the poller read the run's handle through tools.
            mock.patch.object(tools, "current_sandbox_handle", lambda project_id=None: SANDBOX),
            mock.patch("orchestrator_helpers.nodes.execute_tool_node.current_sandbox_handle",
                       lambda project_id=None: SANDBOX),
            mock.patch("orchestrator_helpers.nodes.execute_plan_node.current_sandbox_handle",
                       lambda project_id=None: SANDBOX),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.assertNoOldAddressOrToken)

    def assertNoOldAddressOrToken(self):
        for call in _RecordingClient.calls:
            self.assertNotIn("kali-sandbox:", call["url"])
            self.assertNotIn(OLD_TOKEN, str(call["headers"]))

    def calls_to(self, suffix):
        return [c for c in _RecordingClient.calls if c["url"].endswith(suffix)]


# ------------------------------------------------------------------ executor nodes

MSF_OUTPUT = "[*] Meterpreter session 3 opened (172.28.0.2:4444 -> 172.28.0.9:51000)"
LISTENER = "nc -lvnp 4444"


def _config():
    return {"configurable": {"user_id": "u1", "project_id": "p1", "session_id": "chat-1"}}


def _state(**overrides):
    state = {"messages": [], "current_iteration": 0, "current_phase": "exploitation",
             "execution_trace": [], "_current_step": None, "_current_plan": None}
    state.update(overrides)
    return state


class _Executor:
    async def execute(self, tool_name, tool_args, phase):
        out = MSF_OUTPUT if tool_name == "metasploit_console" else "listening"
        return {"success": True, "output": out}


class ExecutorNodePosts(_Case):
    def _single(self, tool_name, tool_args):
        return asyncio.run(execute_tool_node(
            _state(_current_step={"tool_name": tool_name, "tool_args": tool_args}), _config(),
            tool_executor=_Executor(), streaming_callbacks={}))

    def _plan(self, steps):
        return asyncio.run(execute_plan_node(
            _state(_current_plan={"steps": steps}), _config(),
            tool_executor=_Executor(), streaming_callbacks={}))

    def assertLinkedWithBearer(self):
        hits = self.calls_to(f"{SESSIONS}/session-chat-map")
        self.assertEqual(len(hits), 1, _RecordingClient.calls)
        self.assertEqual(hits[0]["json"], {"msf_session_id": 3, "chat_session_id": "chat-1"})
        self.assertEqual(hits[0]["headers"].get("Authorization"), BEARER)

    def assertListenerWithBearer(self):
        hits = self.calls_to(f"{SESSIONS}/non-msf-sessions")
        self.assertEqual(len(hits), 1, _RecordingClient.calls)
        self.assertEqual(hits[0]["json"]["chat_session_id"], "chat-1")
        self.assertEqual(hits[0]["headers"].get("Authorization"), BEARER)

    def test_single_tool_session_chat_map_sends_the_bearer(self):
        self._single("metasploit_console", {"command": "sessions -l"})
        self.assertLinkedWithBearer()

    def test_single_tool_listener_post_sends_the_bearer(self):
        self._single("kali_shell", {"command": LISTENER})
        self.assertListenerWithBearer()

    def test_plan_session_chat_map_sends_the_bearer(self):
        self._plan([{"tool_name": "metasploit_console", "tool_args": {"command": "sessions -l"}}])
        self.assertLinkedWithBearer()

    def test_plan_listener_post_sends_the_bearer(self):
        self._plan([{"tool_name": "kali_shell", "tool_args": {"command": LISTENER}}])
        self.assertListenerWithBearer()

    def test_a_refused_link_is_logged_and_the_run_goes_on(self):
        _RecordingClient.status = 401
        for run in (lambda: self._single("metasploit_console", {"command": "sessions -l"}),
                    lambda: self._plan([{"tool_name": "metasploit_console",
                                         "tool_args": {"command": "sessions -l"}}])):
            with self.assertLogs(level="WARNING") as logs:
                run()
            self.assertTrue(any("[rbac]" in line and "session-chat-map" in line for line in logs.output),
                            logs.output)


# ------------------------------------------------------------------ progress poller

class _SlowSelf:
    """`self` for PhaseAwareToolExecutor.execute_with_progress: a tool that runs a moment."""

    async def execute(self, tool_name, tool_args, phase):
        await asyncio.sleep(0.08)
        return {"success": True, "output": "done"}


def _poll(tool_name="metasploit_console", progress_port=None):
    async def _cb(*args, **kwargs):
        return None

    return asyncio.run(tools.PhaseAwareToolExecutor.execute_with_progress(
        _SlowSelf(), tool_name, {"command": "run"}, "exploitation",
        progress_callback=_cb, poll_interval=0.01, progress_port=progress_port))


class ProgressPolls(_Case):
    def setUp(self):
        super().setUp()
        _RecordingClient.body = {"active": True, "output": "line", "line_count": 1,
                                 "elapsed_seconds": 1}

    def test_metasploit_progress_polls_send_the_bearer(self):
        self.assertTrue(_poll()["success"])
        polls = self.calls_to(f"{SESSIONS}/progress")
        self.assertGreater(len(polls), 0)
        self.assertTrue(all(p["headers"].get("Authorization") == BEARER for p in polls))

    def test_hydra_progress_polls_send_the_bearer(self):
        _poll("execute_hydra")
        polls = self.calls_to(f"{HYDRA}/progress")
        self.assertGreater(len(polls), 0)
        self.assertTrue(all(p["headers"].get("Authorization") == BEARER for p in polls))

    def test_a_refused_poll_is_logged_once_per_command(self):
        _RecordingClient.status = 401
        with self.assertLogs(level="WARNING") as logs:
            self.assertTrue(_poll(progress_port="hydra")["success"])
        self.assertGreater(len(self.calls_to(f"{HYDRA}/progress")), 1)
        self.assertEqual(sum("[rbac]" in line for line in logs.output), 1, logs.output)

    def test_a_run_without_a_sandbox_polls_nothing(self):
        with mock.patch.object(tools, "current_sandbox_handle", lambda project_id=None: None):
            self.assertTrue(_poll()["success"])
        self.assertEqual(_RecordingClient.calls, [])


# ------------------------------------------------------------- no caller left out

class NoCallerLeftOut(unittest.TestCase):
    """A request to the session manager added later must carry the bearer too."""

    FILES = {
        "orchestrator_helpers/nodes/execute_tool_node.py": "session_manager_base",
        "orchestrator_helpers/nodes/execute_plan_node.py": "session_manager_base",
    }

    def test_every_request_to_the_session_manager_passes_the_bearer_headers(self):
        for rel, base in self.FILES.items():
            tree = ast.parse((_AGENTIC_DIR / rel).read_text())
            requests = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"get", "post", "put", "delete", "patch", "request"}
                and node.args and any(isinstance(n, ast.Name) and n.id == base
                                      for n in ast.walk(node.args[0]))
            ]
            with self.subTest(file=rel):
                self.assertGreater(len(requests), 0, f"no request to {base} found in {rel}")
                for call in requests:
                    headers = [k for k in call.keywords if k.arg == "headers"]
                    self.assertTrue(
                        headers and "kali_auth_headers_for_run" in ast.unparse(headers[0].value),
                        f"{rel}:{call.lineno} calls the session manager without kali_auth_headers_for_run()")

    def test_the_session_manager_has_no_fixed_address_left(self):
        # The base comes from the run's handle (kali_base_for_run), never the environment.
        for rel in ("api.py", "orchestrator.py", *self.FILES):
            text = (_AGENTIC_DIR / rel).read_text()
            with self.subTest(file=rel):
                self.assertNotIn("MCP_METASPLOIT_PROGRESS_URL", text)
                self.assertNotIn("MCP_HYDRA_PROGRESS_URL", text)
                self.assertNotIn("_SESSION_BASE", text)


if __name__ == "__main__":
    unittest.main()
