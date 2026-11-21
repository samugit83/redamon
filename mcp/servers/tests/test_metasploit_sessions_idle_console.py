"""In a per-user Kali sandbox, `GET /sessions` never starts msfconsole (group 1, S12, WI-S12-6).

The agent's hold watcher (agentic/sandbox_hold.py) reads every per-user sandbox's session
manager once a minute to see whether it holds a session or a job. `get_msf_console()` starts
msfconsole on first use: 15-18 s and a few hundred MB, inside a 1 GiB sandbox envelope. So in
a per-user sandbox (`REDAMON_SANDBOX_MODE=per_user`, set by the orchestrator) a console that was
never started answers the empty lists at once and stays unstarted: it holds no session, job or
non-MSF session (registering one starts the console). Once a console exists, the answer is
its data, as before. The shared container is unchanged: it still starts the console.

metasploit_server is loaded by path with fastmcp stubbed (see test_metasploit_progress.py).

Run: python3 -m pytest mcp/servers/tests/test_metasploit_sessions_idle_console.py -q
"""
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.modules.setdefault("fastmcp", mock.MagicMock())

_PATH = Path(__file__).resolve().parents[1] / "metasploit_server.py"
_spec = importlib.util.spec_from_file_location("metasploit_server_idle_console", _PATH)
msf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(msf)

LIVE_DATA = {"sessions": [{"id": 1}], "jobs": [], "non_msf_sessions": [],
             "cache_age_seconds": 2.0, "agent_busy": False}


def _get(path):
    """Run do_GET on a handler with no socket; returns (status, decoded body)."""
    h = msf.SessionProgressHandler.__new__(msf.SessionProgressHandler)
    h.path = path
    h.wfile = mock.Mock()
    h.send_response = mock.Mock()
    h.send_header = mock.Mock()
    h.end_headers = mock.Mock()
    h.do_GET()
    status = h.send_response.call_args[0][0]
    body = json.loads(h.wfile.write.call_args[0][0]) if h.wfile.write.called else None
    return status, body


class _FakeConsole:
    def get_sessions_data(self):
        return dict(LIVE_DATA)


class SessionsWithoutConsole(unittest.TestCase):
    def setUp(self):
        self._saved = msf._msf_console
        self.starts = []

        def start():
            self.starts.append(1)
            return _FakeConsole()

        self._patch = mock.patch.object(msf, "get_msf_console", start)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        msf._msf_console = self._saved

    def test_per_user_sandbox_answers_empty_without_starting_the_console(self):
        msf._msf_console = None
        with mock.patch.dict(os.environ, {"REDAMON_SANDBOX_MODE": "per_user"}):
            status, body = _get("/sessions")
        self.assertEqual(self.starts, [], "a read must not start msfconsole")
        self.assertEqual(status, 200)
        self.assertEqual(body["sessions"], [])
        self.assertEqual(body["jobs"], [])
        self.assertEqual(body["non_msf_sessions"], [])
        self.assertEqual(set(body), set(LIVE_DATA), "the same shape as a started console's answer")

    def test_per_user_sandbox_with_a_console_answers_its_data(self):
        msf._msf_console = object()
        with mock.patch.dict(os.environ, {"REDAMON_SANDBOX_MODE": "per_user"}):
            status, body = _get("/sessions")
        self.assertEqual((status, body), (200, LIVE_DATA))
        self.assertEqual(self.starts, [1])

    def test_shared_container_still_starts_the_console(self):
        msf._msf_console = None
        for env in ({"REDAMON_SANDBOX_MODE": "shared"}, {}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env, clear=False):
                if not env:
                    os.environ.pop("REDAMON_SANDBOX_MODE", None)
                self.starts.clear()
                status, body = _get("/sessions")
                self.assertEqual(self.starts, [1])
                self.assertEqual((status, body), (200, LIVE_DATA))

    def test_progress_is_unchanged(self):
        """Only the session list skips the start; nothing else changes here."""
        msf._msf_console = None

        class _Progress(_FakeConsole):
            def get_progress(self):
                return {"active": False}

        with mock.patch.object(msf, "get_msf_console", lambda: (self.starts.append(1), _Progress())[1]), \
                mock.patch.dict(os.environ, {"REDAMON_SANDBOX_MODE": "per_user"}):
            status, body = _get("/progress")
        self.assertEqual((status, body), (200, {"active": False}))
        self.assertEqual(self.starts, [1])


if __name__ == "__main__":
    unittest.main()
