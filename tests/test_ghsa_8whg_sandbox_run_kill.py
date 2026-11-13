"""
GHSA-8whg-rvcr-r88r: a stopped run's commands kept running in the Kali sandbox.

The agent's stop cancelled only its own asyncio tasks. The MCP client does not tell
the server about a cancelled call and the tools run their commands in a thread, so
`kali_shell`, hydra or nuclei went on hitting the target until their own timeout.
Reported by @recuon.

The sandbox half of the fix (mcp/servers/_run_registry.py): each call to a
run-tagged server names its run, safe_env() writes it into every child, and the
stop route kills the run's processes and their descendants. The processes below
are real; the FastMCP pieces run against a stub of its Middleware base, since the
agent image (where this section runs) does not ship fastmcp.
"""
import asyncio
import contextlib
import os
import signal
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp" / "servers"))

import _run_registry as rr  # noqa: E402
from _safe_env import safe_env  # noqa: E402

RUN_A = "run-a-3f2b9c1e"
RUN_B = "run-b-77d0aa42"


@contextlib.contextmanager
def _in_run(key):
    token = rr.current_run.set(key)
    try:
        yield
    finally:
        rr.current_run.reset(token)


def _state(pid: int) -> str:
    """The process state letter; "gone" once it no longer exists."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            stat = f.read()
        return stat[stat.rindex(b")") + 2:].split()[0].decode()
    except (OSError, ValueError):
        return "gone"


def _dead(pid: int) -> bool:
    return _state(pid) in ("Z", "X", "gone")


def _wait_dead(pids, timeout=5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(_dead(p) for p in pids):
            return True
        time.sleep(0.05)
    return all(_dead(p) for p in pids)


def _children(pid: int) -> list:
    return [p for p, (ppid, _, _) in rr._proc_table().items() if ppid == pid]


def _wait_children(pid: int, n: int, timeout=5.0) -> list:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        kids = _children(pid)
        if len(kids) >= n:
            return kids
        time.sleep(0.05)
    return _children(pid)


class _Procs(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("reading other processes' environ needs root, as in the sandbox")
        self._procs = []

    def tearDown(self):
        for proc in self._procs:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            proc.wait(timeout=5)
        # Grandchildren reparented away from us are reaped by nobody here.
        for pid, (_, tag, _) in rr._proc_table().items():
            if tag in (RUN_A, RUN_B):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)

    def spawn(self, script: str, run: str = "") -> subprocess.Popen:
        with _in_run(run):
            proc = subprocess.Popen(["sh", "-c", script], env=safe_env())
        self._procs.append(proc)
        return proc


class KillingARun(_Procs):

    def test_a_run_dies_whole_and_nothing_else_does(self):
        # A tagged shell with two children, one of which cleared its environment.
        run_a = self.spawn("sleep 300 & env -i /bin/sleep 300 & wait", RUN_A)
        a_kids = _wait_children(run_a.pid, 2)
        self.assertEqual(len(a_kids), 2, "the run's children did not start")
        # Until it execs, the env -i child still holds the shell's environment.
        deadline = time.monotonic() + 5
        cleared = []
        while not cleared and time.monotonic() < deadline:
            table = rr._proc_table()
            cleared = [p for p in a_kids if p in table and table[p][1] is None]
            time.sleep(0.05)
        self.assertEqual(len(cleared), 1, "the env -i child should carry no tag")
        other_run = self.spawn("sleep 300", RUN_B)
        untagged = self.spawn("sleep 300")
        time.sleep(0.2)

        signalled = rr.kill_run(RUN_A, grace=1.0)

        self.assertEqual(signalled, 3)
        self.assertTrue(_wait_dead([run_a.pid, *a_kids]), "a process of the stopped run survived")
        for proc in (other_run, untagged):
            self.assertIsNone(proc.poll(), "a process outside the stopped run was killed")

    def test_a_process_ignoring_sigterm_is_killed_after_the_grace(self):
        stubborn = self.spawn("trap '' TERM; sleep 300", RUN_A)
        time.sleep(0.2)
        started = time.monotonic()
        rr.kill_run(RUN_A, grace=0.5)
        self.assertGreaterEqual(time.monotonic() - started, 0.5)
        self.assertTrue(_wait_dead([stubborn.pid]))
        self.assertEqual(stubborn.wait(timeout=5), -signal.SIGKILL)

    def test_a_run_with_no_process_signals_nothing(self):
        self.assertEqual(rr.kill_run("run-that-never-ran", grace=0.2), 0)

    def test_a_malformed_run_key_matches_nothing(self):
        self.spawn("sleep 300", RUN_A)
        time.sleep(0.2)
        for key in ("", "../etc", "a" * 200, None):
            self.assertEqual(rr.run_processes(key, rr._proc_table()), set(), key)


class TheTag(unittest.TestCase):

    def test_safe_env_tags_only_inside_a_tagged_call(self):
        self.assertNotIn(rr.RUN_ENV, safe_env())
        with _in_run(RUN_A):
            self.assertEqual(safe_env()[rr.RUN_ENV], RUN_A)
        self.assertNotIn(rr.RUN_ENV, safe_env())

    def test_the_tag_never_brings_a_secret_back(self):
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": "dummy-bearer"}), _in_run(RUN_A):
            env = safe_env({"EXTRA": "1"})
        self.assertNotIn("MCP_AUTH_TOKEN", env)
        self.assertEqual((env[rr.RUN_ENV], env["EXTRA"]), (RUN_A, "1"))

    def test_take_run_arg_strips_the_argument_and_keeps_only_a_run_key(self):
        args = {"command": "id", rr.RUN_ARG: RUN_A}
        self.assertEqual(rr.take_run_arg(args), RUN_A)
        self.assertEqual(args, {"command": "id"})
        for bad in ("../x", "a b", "", 7, None):
            args = {"command": "id", rr.RUN_ARG: bad}
            self.assertEqual(rr.take_run_arg(args), "")
            self.assertEqual(args, {"command": "id"}, "an invalid value must still be removed")
        self.assertEqual(rr.take_run_arg(None), "")

    def test_the_servers_own_processes_are_never_in_a_run(self):
        me, parent = os.getpid(), os.getppid()
        table = {
            1: (0, RUN_A, "S"), me: (parent, RUN_A, "S"), parent: (1, RUN_A, "S"),
            900: (me, RUN_A, "S"), 901: (900, None, "S"), 902: (900, None, "Z"),
            903: (1, RUN_B, "S"),
        }
        self.assertEqual(rr.run_processes(RUN_A, table), {900, 901})


def _stub_fastmcp():
    """sys.modules entries for fastmcp.server.middleware with a bare Middleware base."""
    middleware = types.ModuleType("fastmcp.server.middleware")
    middleware.Middleware = type("Middleware", (), {})
    server = types.ModuleType("fastmcp.server")
    server.middleware = middleware
    root = types.ModuleType("fastmcp")
    root.server = server
    return {"fastmcp": root, "fastmcp.server": server, "fastmcp.server.middleware": middleware}


class _Tool:
    def __init__(self, parameters):
        self.parameters = parameters

    def model_copy(self, update):
        return _Tool(update["parameters"])


class FastMcpWiring(unittest.TestCase):

    def setUp(self):
        patcher = mock.patch.dict(sys.modules, _stub_fastmcp())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_call_runs_inside_its_run_and_the_tool_never_sees_the_argument(self):
        mw = rr._middleware()
        seen = {}

        async def call_next(context):
            seen["run"] = rr.current_run.get()
            seen["args"] = dict(context.message.arguments)
            seen["env"] = safe_env().get(rr.RUN_ENV)
            return "result"

        context = types.SimpleNamespace(message=types.SimpleNamespace(
            arguments={"command": "id", rr.RUN_ARG: RUN_A}))
        self.assertEqual(asyncio.run(mw.on_call_tool(context, call_next)), "result")
        self.assertEqual(seen, {"run": RUN_A, "args": {"command": "id"}, "env": RUN_A})
        self.assertEqual(rr.current_run.get(), "", "the run leaked past its call")

    def test_tools_advertise_the_argument_without_losing_their_own(self):
        mw = rr._middleware()
        original = _Tool({"type": "object", "properties": {"command": {"type": "string"}},
                          "required": ["command"], "additionalProperties": False})

        async def call_next(context):
            return [original]

        (listed,) = asyncio.run(mw.on_list_tools(None, call_next))
        self.assertEqual(set(listed.parameters["properties"]), {"command", rr.RUN_ARG})
        self.assertEqual(listed.parameters["required"], ["command"])
        self.assertNotIn(rr.RUN_ARG, original.parameters["properties"])

    def test_install_tags_the_per_call_servers_and_never_metasploit(self):
        class _Mcp:
            def __init__(self):
                self.middleware, self.routes = [], []

            def add_middleware(self, mw):
                self.middleware.append(mw)

            def custom_route(self, path, methods):
                def register(fn):
                    self.routes.append((path, tuple(methods), fn))
                    return fn
                return register

        servers = {}
        for name in ("network_recon", "nmap", "nuclei", "playwright", "metasploit"):
            servers[name] = _Mcp()
            rr.install(servers[name], name)
        for name in ("network_recon", "nmap", "nuclei", "playwright"):
            self.assertEqual(len(servers[name].middleware), 1, name)
        self.assertEqual((servers["metasploit"].middleware, servers["metasploit"].routes), ([], []))
        self.assertEqual([(p, m) for p, m, _ in servers["network_recon"].routes],
                         [(rr.STOP_PATH, ("POST",))])
        for name in ("nmap", "nuclei", "playwright"):
            self.assertEqual(servers[name].routes, [], name)


class StopRoute(unittest.TestCase):

    def _app(self):
        from starlette.applications import Starlette
        from starlette.routing import Route
        return Starlette(routes=[Route(rr.STOP_PATH, rr._stop_route, methods=["POST"])])

    def test_it_kills_the_named_run(self):
        from starlette.testclient import TestClient

        with mock.patch.object(rr, "kill_run", return_value=2) as kill:
            resp = TestClient(self._app()).post(rr.STOP_PATH, json={"run": RUN_A})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), {"run": RUN_A, "signalled": 2})
        kill.assert_called_once_with(RUN_A)

    def test_it_refuses_anything_but_a_run_key(self):
        from starlette.testclient import TestClient

        client = TestClient(self._app())
        with mock.patch.object(rr, "kill_run") as kill:
            for body in ({"run": "../etc"}, {"run": ""}, {}, ["x"]):
                self.assertEqual(client.post(rr.STOP_PATH, json=body).status_code, 400, body)
            self.assertEqual(client.post(rr.STOP_PATH, content=b"not json").status_code, 400)
        kill.assert_not_called()

    def test_behind_the_servers_bearer_wrapper_it_needs_the_token(self):
        from _auth_middleware import BearerAuthASGI
        from starlette.testclient import TestClient

        app = BearerAuthASGI(self._app(), token_getter=lambda: "dummy-bearer")
        with mock.patch.object(rr, "kill_run", return_value=0) as kill:
            client = TestClient(app)
            self.assertEqual(client.post(rr.STOP_PATH, json={"run": RUN_A}).status_code, 401)
            self.assertEqual(client.post(rr.STOP_PATH, json={"run": RUN_A},
                                         headers={"Authorization": "Bearer wrong"}).status_code, 401)
            kill.assert_not_called()
            ok = client.post(rr.STOP_PATH, json={"run": RUN_A},
                             headers={"Authorization": "Bearer dummy-bearer"})
        self.assertEqual(ok.status_code, 200)


if __name__ == "__main__":
    unittest.main()
