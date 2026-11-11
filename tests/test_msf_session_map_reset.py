"""
The Metasploit manager's link from a session id to the chat that opened it never
outlives the session (NF-05).

msfconsole numbers sessions from 1 again after `msf_restart` (or after the process
dies and a new one starts), so a link left behind pointed the next session 1 at the
previous one's chat: the sessions panel showed it under the wrong project. The map
is now cleared whenever a new msfconsole process starts or the old one stops, and an
entry leaves when its session closes or is killed.

Run (root-agent section, agent image): python -m pytest tests/test_msf_session_map_reset.py
"""
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SERVERS = REPO / "mcp" / "servers"
if str(SERVERS) not in sys.path:
    sys.path.insert(0, str(SERVERS))

if "fastmcp" not in sys.modules:
    _fm = types.ModuleType("fastmcp")

    class _StubMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            return lambda fn: fn

        def run(self, *a, **k):
            pass

    _fm.FastMCP = _StubMCP
    sys.modules["fastmcp"] = _fm

import metasploit_server  # noqa: E402

PersistentMsfConsole = metasploit_server.PersistentMsfConsole


class _DeadProcess:
    """A Popen double whose process has already exited, so the reader thread ends at once."""
    pid = 4242
    stdout = None
    stdin = None

    def poll(self):
        return 0


def _linked_console():
    console = PersistentMsfConsole()
    console.link_chat_session(1, "chat-of-project-a")
    console.link_chat_session(2, "chat-of-project-b")
    return console


class RestartClearsTheMap(unittest.TestCase):
    def test_restart_clears_the_map(self):
        console = _linked_console()
        console.restart()
        self.assertEqual(console._chat_session_map, {})

    def test_the_msf_restart_tool_clears_the_map(self):
        console = _linked_console()
        with mock.patch.object(metasploit_server, "get_msf_console", return_value=console), \
                mock.patch.object(console, "start", return_value=True):
            msg = metasploit_server.msf_restart()
        self.assertIn("restarted successfully", msg)
        self.assertEqual(console._chat_session_map, {})

    def test_a_new_msfconsole_process_forgets_the_old_links(self):
        # The process died on its own: start() spawns a fresh msfconsole, whose
        # session ids begin at 1 again.
        console = _linked_console()
        console._detail_thread_started = True
        with mock.patch.object(metasploit_server.subprocess, "Popen", return_value=_DeadProcess()), \
                mock.patch.object(console, "_wait_for_output", return_value=""):
            self.assertTrue(console.start())
        self.assertEqual(console._chat_session_map, {})

    def test_stop_clears_the_map(self):
        console = _linked_console()
        console.stop()
        self.assertEqual(console._chat_session_map, {})

    def test_listeners_outside_msfconsole_survive_a_restart(self):
        # netcat/socat listeners run in kali_shell, not in msfconsole: a console
        # restart does not end them, so their rows stay.
        console = _linked_console()
        console._non_msf_sessions["raw-1"] = {"id": "raw-1", "chat_session_id": "chat-of-project-a"}
        console.restart()
        self.assertIn("raw-1", console._non_msf_sessions)


class ClosingRemovesTheEntry(unittest.TestCase):
    def test_closing_removes_the_entry(self):
        console = _linked_console()
        console._detect_session_events("[*] 10.0.0.5 - Meterpreter session 1 closed.  Reason: Died\n")
        self.assertEqual(console._chat_session_map, {2: "chat-of-project-b"})

    def test_a_closed_shell_session_is_removed_too(self):
        console = _linked_console()
        console._detect_session_events("[*] Command shell session 2 closed.  Reason: User exit\n")
        self.assertEqual(console._chat_session_map, {1: "chat-of-project-a"})

    def test_killing_a_session_removes_its_entry(self):
        console = _linked_console()
        with mock.patch.object(console, "_quick_execute", return_value="[*] Killing session 1"):
            console.kill_session(1)
        self.assertEqual(console._chat_session_map, {2: "chat-of-project-b"})

    def test_a_reused_id_never_inherits_the_old_chat(self):
        # A close line that was never seen leaves a link behind; the next session
        # that opens with that id starts unlinked until its own chat claims it.
        console = _linked_console()
        console._detect_session_events(
            "[*] Meterpreter session 1 opened (172.28.0.2:4444 -> 172.28.0.9:51000)\n")
        self.assertNotIn(1, console._chat_session_map)
        self.assertEqual(console._chat_session_map[2], "chat-of-project-b")

    def test_an_unrelated_line_keeps_the_links(self):
        console = _linked_console()
        console._detect_session_events("[*] Started reverse TCP handler on 0.0.0.0:4444\n")
        self.assertEqual(len(console._chat_session_map), 2)

    def test_the_listing_carries_the_live_link(self):
        console = _linked_console()
        raw = "\n".join([
            "Active sessions",
            "===============",
            "  Id  Name  Type                     Information  Connection",
            "  --  ----  ----                     -----------  ----------",
            "  1         meterpreter x86/linux    uid=0        172.28.0.2:4444 -> 172.28.0.9:51000",
        ])
        before = console._parse_sessions_output(raw)
        self.assertEqual(before[0]["chat_session_id"], "chat-of-project-a")
        console._detect_session_events("[*] Meterpreter session 1 closed.  Reason: Died\n")
        after = console._parse_sessions_output(raw)
        self.assertIsNone(after[0]["chat_session_id"])


if __name__ == "__main__":
    unittest.main()
