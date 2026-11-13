"""
GHSA-w454-6hwp-fm58: one project cannot reach another project's Metasploit sessions
through the sandbox's shared msfconsole.

The advisory showed the four session routes proxying any session id for any signed-in
user (fixed in the webapp, see sessions/ghsaW454.regression.test.ts). The same user
could reach the same sessions through their own agent: the Kali sandbox runs ONE
msfconsole for every project, and `metasploit_console` passed `sessions -l`,
`sessions -c "id" -i 1`, `sessions -K`, `irb`, `set SESSION 1` or `msf_restart`
straight to it. The agent's link from a session to its chat also came from a regex
over tool output, so a printed "session 1 opened" moved another project's session
into the printer's project, where the webapp's new check then let them drive it.

Now the console is held by one project at a time: another project's call is refused
before anything is written to msfconsole while the holder runs a command, has a live
session or job, or used the console recently; the next project gets a restarted
console. Sessions are linked to the holder's chat by the console itself, and the
agent's link can neither move a linked session nor name a chat outside the holder.

Real PersistentMsfConsole, no msfconsole process: execute/restart/start are doubles,
so "refused" is proven by the console never being written to.

Run (root-agent section, agent image): python -m pytest tests/test_ghsa_w454_msf_project_lease.py
"""
import http.client
import json
import os
import sys
import threading
import time
import types
import unittest
from http.server import HTTPServer
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SERVERS = REPO / "mcp" / "servers"
if str(SERVERS) not in sys.path:
    sys.path.insert(0, str(SERVERS))

# fastmcp only ships in the kali image: an identity @mcp.tool() is enough here.
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
IDLE = metasploit_server.MSF_PROJECT_LEASE_IDLE_S


def owner(project, chat, user):
    return json.dumps({"project_id": project, "user_id": user, "chat_session_id": chat})


ALICE = owner("project-alice", "chat-alice", "alice")
BOB = owner("project-bob", "chat-bob", "bob")

# The advisory's actions, typed at the console instead of the routes, plus the
# console's own ways to reach a session by id.
CROSS_PROJECT_COMMANDS = [
    "sessions -l",
    'sessions -c "id; hostname" -i 1',
    "sessions -i 1",
    "sessions -k 1",
    "sessions -K",
    "jobs -K",
    "jobs -k 7",
    "set SESSION 1",
    "route add 10.10.10.0/24 1",
    "irb -e \"framework.sessions[1].shell_command('id')\"",
    "resource /tmp/x.rc",
]

LIVE_SESSION = {"id": 1, "type": "meterpreter", "info": "", "connection": "",
                "target_ip": "", "chat_session_id": "chat-alice"}
LIVE_JOB = {"id": 7, "name": "Exploit: multi/handler", "payload": "p", "port": 4444}


class _ConsoleCase(unittest.TestCase):
    """A console Alice holds, idle for `idle` seconds, with what the cache shows."""

    def console(self, *, idle=0.0, sessions=(), jobs=(), cache_age=1.0):
        console = PersistentMsfConsole()
        self.execute = mock.Mock(return_value="msf6 > ")
        self.restart = mock.Mock()
        self.start = mock.Mock(return_value=True)
        console.execute = self.execute
        console.restart = self.restart
        console.start = self.start
        patcher = mock.patch.object(metasploit_server, "get_msf_console", return_value=console)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.assertIn("msf6", metasploit_server.metasploit_console("use exploit/multi/handler",
                                                                    _redamon_owner=ALICE))
        self.execute.reset_mock()
        console._holder["last_used"] = time.time() - idle
        console._session_details = [dict(s) for s in sessions]
        console._job_details = [dict(j) for j in jobs]
        console._detail_cache_time = time.time() - cache_age
        return console

    def assertRefusedForBob(self, console, command="sessions -l"):
        out = metasploit_server.metasploit_console(command, _redamon_owner=BOB)
        self.assertTrue(out.startswith("[REFUSED]"), out)
        self.execute.assert_not_called()
        self.restart.assert_not_called()
        self.assertEqual(console._holder["project_id"], "project-alice")
        return out


class AnotherProjectIsRefused(_ConsoleCase):
    def test_every_advisory_command_is_refused_while_alice_has_a_session(self):
        console = self.console(idle=IDLE + 60, sessions=[LIVE_SESSION])
        for command in CROSS_PROJECT_COMMANDS:
            with self.subTest(command=command):
                out = self.assertRefusedForBob(console, command)
                self.assertIn("live sessions or jobs", out)
                # The refusal names no project, target or session of Alice's.
                self.assertNotIn("alice", out.lower())
                self.assertNotIn("10.10.10", out)

    def test_bob_cannot_restart_the_console_under_alice(self):
        console = self.console(idle=IDLE + 60, sessions=[LIVE_SESSION])
        out = metasploit_server.msf_restart(_redamon_owner=BOB)
        self.assertTrue(out.startswith("[REFUSED]"), out)
        self.restart.assert_not_called()
        self.start.assert_not_called()
        self.assertEqual(console._session_details, [LIVE_SESSION])

    def test_refused_while_alice_runs_a_command(self):
        console = self.console(idle=IDLE + 60)
        console._holder["active"] = 1
        self.assertIn("running a command", self.assertRefusedForBob(console))

    def test_refused_while_alice_has_only_a_job(self):
        console = self.console(idle=IDLE + 60, jobs=[LIVE_JOB])
        self.assertIn("live sessions or jobs", self.assertRefusedForBob(console))

    def test_refused_while_alice_used_the_console_recently(self):
        console = self.console(idle=5)
        self.assertIn("used the console recently", self.assertRefusedForBob(console))

    def test_a_session_the_cache_has_not_caught_up_with_still_counts(self):
        console = self.console(idle=IDLE + 60, cache_age=2.0)
        console._detect_session_events(
            "[*] Meterpreter session 3 opened (172.28.0.2:4444 -> 172.28.0.9:51000)\n")
        self.assertIn("live sessions or jobs", self.assertRefusedForBob(console))

    def test_a_stale_cache_cannot_prove_the_console_empty(self):
        console = self.console(idle=IDLE + 60, cache_age=metasploit_server._LEASE_CACHE_MAX_AGE_S + 5)
        self.assertIn("cannot be checked", self.assertRefusedForBob(console))

    def test_the_holder_itself_is_always_admitted(self):
        self.console(idle=0, sessions=[LIVE_SESSION], jobs=[LIVE_JOB])
        out = metasploit_server.metasploit_console('sessions -c "id" -i 1', _redamon_owner=ALICE)
        self.assertEqual(out, "msf6 >")
        self.execute.assert_called_once()
        self.assertEqual(self.execute.call_args.args[0], 'sessions -c "id" -i 1')


class TheConsolePassesToTheNextProjectClean(_ConsoleCase):
    def test_bob_takes_an_idle_empty_console_and_gets_a_restarted_one(self):
        console = self.console(idle=IDLE + 1)
        out = metasploit_server.metasploit_console("sessions -l", _redamon_owner=BOB)
        self.assertFalse(out.startswith("[REFUSED]"), out)
        self.restart.assert_called_once()
        self.start.assert_called_once()
        self.execute.assert_called_once()
        self.assertEqual(console._holder["project_id"], "project-bob")
        self.assertEqual(console._lease_chats, {"chat-bob"})
        # Now Alice is the one kept out.
        self.execute.reset_mock()
        refused = metasploit_server.metasploit_console("sessions -l", _redamon_owner=ALICE)
        self.assertTrue(refused.startswith("[REFUSED]"), refused)
        self.execute.assert_not_called()

    def test_the_restart_runs_under_the_console_lock(self):
        console = self.console(idle=IDLE + 1)
        held = []
        self.restart.side_effect = lambda: held.append(console.lock.locked())
        metasploit_server.metasploit_console("sessions -l", _redamon_owner=BOB)
        self.assertEqual(held, [True])

    def test_a_failed_restart_does_not_keep_the_console_held(self):
        console = self.console(idle=IDLE + 1)
        self.restart.side_effect = RuntimeError("msfconsole would not die")
        metasploit_server.metasploit_console("sessions -l", _redamon_owner=BOB)
        self.assertEqual(console._holder["active"], 0)

    def test_a_failing_command_still_releases_the_console(self):
        console = self.console(idle=0)
        self.execute.side_effect = RuntimeError("pipe closed")
        with self.assertRaises(RuntimeError):
            metasploit_server.metasploit_console("sessions -l", _redamon_owner=ALICE)
        self.assertEqual(console._holder["active"], 0)


class ACallNamesItsProject(_ConsoleCase):
    def test_a_call_without_a_project_never_reaches_the_console(self):
        self.console(idle=IDLE + 60)
        for raw in ("", "not json", "[]", json.dumps({"chat_session_id": "chat-bob"}),
                    json.dumps({"project_id": ""}), json.dumps({"project_id": 7})):
            with self.subTest(owner=raw):
                self.assertEqual(metasploit_server.metasploit_console("sessions -l", _redamon_owner=raw),
                                 metasploit_server.NO_OWNER_REFUSAL)
                self.assertEqual(metasploit_server.msf_restart(_redamon_owner=raw),
                                 metasploit_server.NO_OWNER_REFUSAL)
        self.execute.assert_not_called()
        self.restart.assert_not_called()

    def test_the_owner_parser_keeps_only_strings(self):
        parsed = metasploit_server.parse_console_owner(
            json.dumps({"project_id": "p", "user_id": 3, "chat_session_id": None}))
        self.assertEqual(parsed, {"project_id": "p", "user_id": "", "chat_session_id": ""})


class SessionLinksStayWithTheirProject(_ConsoleCase):
    OPENED = "[*] Meterpreter session {} opened (172.28.0.2:4444 -> 172.28.0.9:51000)\n"

    def test_a_session_that_opens_is_linked_to_the_holders_chat(self):
        console = self.console(idle=0)
        console._detect_session_events(self.OPENED.format(4))
        self.assertEqual(console._chat_session_map[4], "chat-alice")

    def test_the_agent_cannot_move_a_linked_session_to_another_chat(self):
        console = self.console(idle=0)
        console._detect_session_events(self.OPENED.format(1))
        console._lease_chats.add("chat-alice-2")
        self.assertEqual(console.claim_chat_link(1, "chat-alice-2"), "already_linked")
        self.assertEqual(console._chat_session_map[1], "chat-alice")

    def test_the_agent_cannot_link_to_a_chat_outside_the_holder(self):
        console = self.console(idle=0)
        self.assertEqual(console.claim_chat_link(1, "chat-bob"), "chat_not_holder")
        self.assertNotIn(1, console._chat_session_map)

    def test_the_holders_chat_links_an_unlinked_session(self):
        console = self.console(idle=0)
        self.assertIsNone(console.claim_chat_link(5, "chat-alice"))
        self.assertEqual(console._chat_session_map[5], "chat-alice")

    def test_the_forged_link_is_refused_over_http(self):
        console = self.console(idle=0)
        console._detect_session_events(self.OPENED.format(1))
        token = "test-mcp-auth-token-0123456789"
        server = HTTPServer(("127.0.0.1", 0), metasploit_server.SessionProgressHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": token}):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            conn.request("POST", "/session-chat-map",
                         body=json.dumps({"msf_session_id": 1, "chat_session_id": "chat-bob"}),
                         headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            resp = conn.getresponse()
            body = json.loads(resp.read())
            conn.close()
        self.assertEqual(resp.status, 409)
        self.assertEqual(body["code"], "chat_not_holder")
        self.assertEqual(console._chat_session_map, {1: "chat-alice"})


if __name__ == "__main__":
    unittest.main()
