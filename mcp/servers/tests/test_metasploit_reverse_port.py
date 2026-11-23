"""The Metasploit server and the sandbox's one reverse-shell port (FU-2, FU-3, D-C).

The orchestrator gives each sandbox one reverse-shell port, MSF_REVERSE_PORT: its pool
port, the only port a target reaches directly, or 4444 without one. Every chat and
project of the person shares it, and so does their one msfconsole.

- Every new msfconsole (a start, the reset for the next project, msf_restart) runs
  `setg LPORT <port>` when the port is not 4444: Metasploit's own default reaches
  nothing but a tunnel.
- A handler that cannot bind its port gets a note saying which job already listens
  there (reuse it, or `jobs -k` it) and that all of the person's chats share the port.
- A session is listed under the chat whose command started the handler that caught it,
  never under whichever chat called last.
- The busy refusal speaks of the person's own sandbox and projects.

metasploit_server is loaded by path with fastmcp stubbed (see test_metasploit_progress.py);
no msfconsole runs.

Run (root-agent section, agent image):
  python -m pytest mcp/servers/tests/test_metasploit_reverse_port.py -q
"""
import importlib.util
import json
import os
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

# fastmcp only ships in the Kali image. An identity @mcp.tool() keeps the tools
# callable here (a MagicMock would replace each with a mock).
_fastmcp = types.ModuleType("fastmcp")


class _StubMCP:
    def __init__(self, *a, **k):
        pass

    def tool(self, *a, **k):
        return lambda fn: fn

    def run(self, *a, **k):
        pass


_fastmcp.FastMCP = _StubMCP
_PATH = Path(__file__).resolve().parents[1] / "metasploit_server.py"
_spec = importlib.util.spec_from_file_location("metasploit_server_reverse_port", _PATH)
msf = importlib.util.module_from_spec(_spec)
with mock.patch.dict(sys.modules, {"fastmcp": _fastmcp}):
    _spec.loader.exec_module(msf)

POOL_PORT = 45001
A = json.dumps({"project_id": "project-a", "user_id": "alice", "chat_session_id": "chat-a"})
A2 = json.dumps({"project_id": "project-a", "user_id": "alice", "chat_session_id": "chat-a2"})
B = json.dumps({"project_id": "project-b", "user_id": "alice", "chat_session_id": "chat-b"})



class _DeadProcess:
    """A Popen double whose process has already exited, so the reader thread ends at once."""
    pid = 4242
    stdout = None
    stdin = None

    def poll(self):
        return 0


def _env(port):
    return mock.patch.dict(os.environ, {} if port is None else {"MSF_REVERSE_PORT": str(port)})


class EveryNewConsoleDefaultsLportToThePoolPort(unittest.TestCase):
    def started(self, port):
        console = msf.PersistentMsfConsole()
        console._detail_thread_started = True
        sent = []
        with _env(port), \
                mock.patch.object(msf.subprocess, "Popen", return_value=_DeadProcess()), \
                mock.patch.object(console, "_wait_for_output", return_value=""), \
                mock.patch.object(console, "_quick_execute", side_effect=lambda c, **k: sent.append(c) or ""):
            if port is None:
                os.environ.pop("MSF_REVERSE_PORT", None)
            self.assertTrue(console.start())
        return sent

    def test_a_start_sets_the_pool_port(self):
        self.assertEqual(self.started(POOL_PORT), [f"setg LPORT {POOL_PORT}"])

    def test_without_a_pool_port_nothing_is_set(self):
        for port in (4444, None, "x", 0, 70000):
            with self.subTest(port=port):
                self.assertEqual(self.started(port), [])

    def test_the_reset_for_the_next_project_sets_it_again(self):
        console = msf.PersistentMsfConsole()
        console._detail_thread_started = True
        sent = []
        execute = mock.Mock(return_value="msf6 > ")
        with _env(POOL_PORT), \
                mock.patch.object(msf, "get_msf_console", return_value=console), \
                mock.patch.object(msf.subprocess, "Popen", return_value=_DeadProcess()), \
                mock.patch.object(console, "_wait_for_output", return_value=""), \
                mock.patch.object(console, "execute", execute), \
                mock.patch.object(console, "_quick_execute", side_effect=lambda c, **k: sent.append(c) or ""):
            msf.metasploit_console("use exploit/multi/handler", _redamon_owner=A)
            console._holder["last_used"] = time.time() - msf.MSF_PROJECT_LEASE_IDLE_S - 1
            console._detail_cache_time = time.time()
            out = msf.metasploit_console("jobs", _redamon_owner=B)
        self.assertNotIn("[REFUSED]", out)
        self.assertEqual(console._holder["project_id"], "project-b")
        self.assertEqual(sent, [f"setg LPORT {POOL_PORT}"])

    def test_msf_restart_sets_it_again(self):
        console = msf.PersistentMsfConsole()
        console._detail_thread_started = True
        sent = []
        with _env(POOL_PORT), \
                mock.patch.object(msf, "get_msf_console", return_value=console), \
                mock.patch.object(msf.subprocess, "Popen", return_value=_DeadProcess()), \
                mock.patch.object(console, "_wait_for_output", return_value=""), \
                mock.patch.object(console, "_quick_execute", side_effect=lambda c, **k: sent.append(c) or ""):
            self.assertIn("restarted successfully", msf.msf_restart(_redamon_owner=A))
        self.assertEqual(sent, [f"setg LPORT {POOL_PORT}"])


# Real msfconsole 6.5.7 output (captured in a throwaway sandbox-image container): in pool
# mode LHOST is the host's address, which the sandbox does not have, so Metasploit falls
# back to 0.0.0.0 and the handler runs; a second handler on the same port then fails.
LHOST_FALLBACK = (
    "[*] Exploit running as background job 0.\n"
    "[*] Exploit completed, but no session was created.\n"
    f"[-] Handler failed to bind to 203.0.113.5:{POOL_PORT}:-  -\n"
    f"[*] Started reverse TCP handler on 0.0.0.0:{POOL_PORT} \n")
SECOND_ON_THE_POOL_PORT = (
    "[*] Exploit running as background job 1.\n"
    "[*] Exploit completed, but no session was created.\n"
    f"[-] Handler failed to bind to 203.0.113.5:{POOL_PORT}:-  -\n"
    f"[-] Handler failed to bind to 0.0.0.0:{POOL_PORT}:-  -\n"
    "[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: "
    f"(0.0.0.0:{POOL_PORT}).\n")
POOL_JOBS = (
    "Jobs\n====\n\n"
    "  Id  Name                    Payload                      Payload opts\n"
    "  --  ----                    -------                      ------------\n"
    f"  0   Exploit: multi/handler  linux/x64/shell_reverse_tcp  tcp://203.0.113.5:{POOL_PORT}\n")
# A tunnel's handler: LPORT is the public port, the bind port 4444 (ReverseListenerBindPort).
TUNNEL_JOBS = (
    "Jobs\n====\n\n"
    "  Id  Name                    Payload                      Payload opts\n"
    "  --  ----                    -------                      ------------\n"
    "  0   Exploit: multi/handler  linux/x64/shell_reverse_tcp  tcp://203.0.113.5:12345\n")
SECOND_ON_THE_TUNNEL_PORT = (
    "[*] Exploit running as background job 1.\n"
    "[-] Handler failed to bind to 127.0.0.1:4444:-  -\n"
    "[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: "
    "(127.0.0.1:4444).\n")


class AHandlerOnTheSharedPortSaysSo(unittest.TestCase):
    def run_console(self, output, jobs=POOL_JOBS, port=POOL_PORT, holder="metasploit"):
        console = msf.PersistentMsfConsole()
        console.execute = mock.Mock(return_value=output)
        console._quick_execute = mock.Mock(return_value=jobs)
        console.port_holder = mock.Mock(return_value=holder)
        with _env(port), mock.patch.object(msf, "get_msf_console", return_value=console):
            out = msf.metasploit_console("exploit -j", _redamon_owner=A)
        return console, out

    def test_metasploits_lhost_fallback_is_a_normal_start(self):
        console, out = self.run_console(LHOST_FALLBACK)
        self.assertNotIn("[REDAMON]", out)
        self.assertNotIn("jobs -k", out)
        console.port_holder.assert_not_called()
        self.assertIsNone(msf.bind_failure(LHOST_FALLBACK))

    def test_a_second_handler_on_the_pool_port_names_the_job_and_the_shared_port(self):
        console, out = self.run_console(SECOND_ON_THE_POOL_PORT)
        self.assertIn(f"[REDAMON] Port {POOL_PORT} is already in use in your Kali sandbox", out)
        self.assertIn("Metasploit job 0 (Exploit: multi/handler, payload linux/x64/shell_reverse_tcp, "
                      f"tcp://203.0.113.5:{POOL_PORT}) already listens on it", out)
        self.assertIn("run `jobs` to see it", out)
        self.assertIn("`jobs -k 0`", out)
        self.assertIn(f"All of your chats and projects share this sandbox and its one reverse-shell port "
                      f"(LPORT {POOL_PORT})", out)
        # The holder was looked up in the sandbox, the jobs read fresh, the command ran for its chat.
        console.port_holder.assert_called_once_with(POOL_PORT)
        console._quick_execute.assert_called_once_with("jobs -l", timeout=10, quiet_period=1.0, keep_events=True)
        self.assertEqual(console.execute.call_args.kwargs["chat"], "chat-a")

    def test_the_tunnels_bind_port_names_the_job_holding_it(self):
        # The job's payload options name the public port (12345), not the bind port.
        _, out = self.run_console(SECOND_ON_THE_TUNNEL_PORT, jobs=TUNNEL_JOBS)
        self.assertIn("[REDAMON] Port 4444 is already in use in your Kali sandbox", out)
        self.assertIn("Metasploit job 0 (Exploit: multi/handler, payload linux/x64/shell_reverse_tcp, "
                      "tcp://203.0.113.5:12345) already listens on it", out)
        self.assertIn("Port 4444 is where your tunnel (ngrok or chisel) delivers shells", out)
        self.assertNotIn("No Metasploit job", out)
        self.assertNotIn("kali_shell", out)

    def test_several_jobs_are_all_named_when_none_names_the_port(self):
        jobs = TUNNEL_JOBS + "  1   Exploit: multi/handler  linux/x64/shell_reverse_tcp  tcp://203.0.113.5:23456\n"
        _, out = self.run_console(SECOND_ON_THE_TUNNEL_PORT, jobs=jobs)
        self.assertIn("One of your Metasploit jobs listens on it (job 0 (", out)
        self.assertIn("job 1 (", out)
        self.assertIn("`jobs -v`", out)

    def test_another_process_is_named(self):
        console, out = self.run_console(SECOND_ON_THE_POOL_PORT, holder=(4321, "nc"))
        self.assertIn(f"[REDAMON] Port {POOL_PORT} is already in use", out)
        self.assertIn("Process nc (pid 4321) listens on it, outside Metasploit", out)
        self.assertIn("`kill 4321`", out)
        self.assertNotIn("Metasploit job", out)
        console._quick_execute.assert_not_called()

    def test_a_holder_proc_cannot_name_is_not_blamed_on_a_listener(self):
        _, out = self.run_console(SECOND_ON_THE_POOL_PORT, holder="unknown")
        self.assertIn("Another process in your sandbox listens on it", out)
        self.assertIn(f"ss -ltnp 'sport = :{POOL_PORT}'", out)

    def test_an_address_the_sandbox_does_not_have_gets_its_own_text(self):
        output = ("[-] Handler failed to bind to 10.9.9.9:45001:-  -\n"
                  "[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or "
                  "unavailable: (10.9.9.9:45001).\n")
        _, out = self.run_console(output, holder=None)
        self.assertIn("[REDAMON] Address 10.9.9.9 is not an address of your Kali sandbox", out)
        self.assertIn("Leave ReverseListenerBindAddress unset", out)
        self.assertNotIn("already in use", out.split("[REDAMON]")[1])
        self.assertNotIn("jobs -k", out)

    def test_a_loopback_bind_with_nothing_listening_is_no_wrong_address(self):
        # A tunnel's handler binds 127.0.0.1:4444 (ReverseListenerBindAddress): the
        # note must not tell the agent to leave that unset.
        for address in ("127.0.0.1", "::1"):
            with self.subTest(address=address):
                shown = f"[{address}]" if ":" in address else address
                output = (f"[-] Handler failed to bind to {shown}:4444:-  -\n"
                          "[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or "
                          f"unavailable: ({shown}:4444).\n")
                _, out = self.run_console(output, holder=None)
                self.assertIn(f"[REDAMON] Metasploit could not bind {address}:4444, although nothing", out)
                self.assertNotIn("is not an address of your Kali sandbox", out)
                self.assertNotIn("ReverseListenerBindAddress", out)

    def test_a_metasploit_holder_with_no_job_listed_gets_a_sentence(self):
        _, out = self.run_console(SECOND_ON_THE_POOL_PORT, jobs="No active jobs.\n")
        self.assertIn("A Metasploit handler of your console listens on it (`jobs -v` shows each job's bind "
                      "port)", out)
        self.assertNotIn("(;", out)

    def test_another_port_gets_no_shared_port_sentence(self):
        _, out = self.run_console("[-] Exploit failed [bad-config]: Rex::BindFailed The address is "
                                  "already in use or unavailable: (0.0.0.0:8080).\n", holder=(77, "python3"))
        self.assertIn("[REDAMON] Port 8080 is already in use", out)
        self.assertNotIn("share this sandbox", out)

    def test_a_handler_that_bound_gets_no_note(self):
        _, out = self.run_console(f"[*] Started reverse TCP handler on 0.0.0.0:{POOL_PORT}\n")
        self.assertNotIn("[REDAMON]", out)

    def test_the_failure_is_read_from_the_final_line_or_an_unanswered_attempt(self):
        self.assertEqual(msf.bind_failure(SECOND_ON_THE_POOL_PORT), ("0.0.0.0", POOL_PORT))
        self.assertEqual(msf.bind_failure(SECOND_ON_THE_TUNNEL_PORT), ("127.0.0.1", 4444))
        self.assertEqual(msf.bind_failure("[-] Handler failed to bind to [::1]:4555:-  -\n"), ("::1", 4555))
        # A start on another port does not answer this one.
        self.assertEqual(msf.bind_failure("[-] Handler failed to bind to 0.0.0.0:4555:-  -\n"
                                          "[*] Started reverse TCP handler on 0.0.0.0:4556\n"), ("0.0.0.0", 4555))
        self.assertIsNone(msf.bind_failure("[*] Started reverse TCP handler on 0.0.0.0:4444"))


class TheHolderIsReadFromTheSandboxsProcesses(unittest.TestCase):
    """/proc of the sandbox, which the server runs in: a listening socket's inode,
    the process holding it, and whether that process is the console or its child."""

    def setUp(self):
        import tempfile
        self.root = Path(tempfile.mkdtemp())
        (self.root / "net").mkdir()
        head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        row = "   {n}: {addr}:{port:04X} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0\n"
        (self.root / "net" / "tcp").write_text(head + row.format(n=0, addr="00000000", port=POOL_PORT, st="0A", inode=111)
                                               + row.format(n=1, addr="0100007F", port=4555, st="0A", inode=222)
                                               + row.format(n=2, addr="00000000", port=4666, st="01", inode=333))
        (self.root / "net" / "tcp6").write_text(head)
        self.proc(10, "msfconsole", 1)
        self.proc(11, "ruby", 10, sockets=[111])
        self.proc(20, "nc", 1, sockets=[222])
        patcher = mock.patch.object(msf, "PROC_ROOT", str(self.root))
        patcher.start()
        self.addCleanup(patcher.stop)

    def proc(self, pid, comm, ppid, sockets=()):
        d = self.root / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "stat").write_text(f"{pid} ({comm} x) S {ppid} {pid} {pid} 0 -1\n")
        for n, inode in enumerate(sockets, 3):
            os.symlink(f"socket:[{inode}]", d / "fd" / str(n))

    def test_the_consoles_child_is_metasploit(self):
        self.assertEqual(msf.listening_pids(POOL_PORT), {11})
        console = msf.PersistentMsfConsole()
        console.process = mock.Mock(pid=10)
        self.assertEqual(console.port_holder(POOL_PORT), "metasploit")

    def test_another_process_is_named_by_pid(self):
        console = msf.PersistentMsfConsole()
        console.process = mock.Mock(pid=10)
        self.assertEqual(console.port_holder(4555), (20, "nc"))

    def test_nothing_listening_is_none(self):
        console = msf.PersistentMsfConsole()
        console.process = mock.Mock(pid=10)
        self.assertEqual(msf.listening_pids(4666), set())
        self.assertIsNone(console.port_holder(4666))
        self.assertIsNone(console.port_holder(9))

    def test_an_unreadable_proc_is_unknown(self):
        with mock.patch.object(msf, "PROC_ROOT", str(self.root / "absent")):
            self.assertIsNone(msf.listening_pids(POOL_PORT))
            self.assertEqual(msf.PersistentMsfConsole().port_holder(POOL_PORT), "unknown")


class TheReversePortIsAsciiDigitsOnly(unittest.TestCase):
    def test_other_digits_read_as_no_port(self):
        for raw in ("٤٥٠٠١", "４５００１", "45001x", "+45001", ""):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"MSF_REVERSE_PORT": raw}):
                self.assertEqual(msf.reverse_port(), 4444)
        with mock.patch.dict(os.environ, {"MSF_REVERSE_PORT": " 45001 "}):
            self.assertEqual(msf.reverse_port(), 45001)


class ASessionFollowsTheHandlerThatCaughtIt(unittest.TestCase):
    def console(self):
        console = msf.PersistentMsfConsole()
        console.execute = mock.Mock(return_value="msf6 > ")
        patcher = mock.patch.object(msf, "get_msf_console", return_value=console)
        patcher.start()
        self.addCleanup(patcher.stop)
        return console

    def run_for(self, console, owner, *lines):
        """Lines the reader thread sees while `owner`'s command runs."""
        chat = json.loads(owner)["chat_session_id"]

        def execute(command, **kw):
            console._command_chat = kw.get("chat")
            for line in lines:
                console._detect_session_events(line)
            console._command_chat = None
            return "msf6 > "

        console.execute = mock.Mock(side_effect=execute)
        msf.metasploit_console("exploit -j", _redamon_owner=owner)
        self.assertEqual(console.execute.call_args.kwargs["chat"], chat)

    def test_a_late_catch_goes_to_the_handlers_chat_not_the_last_caller(self):
        console = self.console()
        self.run_for(console, A, f"[*] Started reverse TCP handler on 0.0.0.0:{POOL_PORT} \n")
        # Another chat of the same project calls last.
        self.run_for(console, A2, "Active sessions\n")
        self.assertEqual(console._holder["chat_session_id"], "chat-a2")
        console._detect_session_events(
            f"[*] Meterpreter session 1 opened (10.214.0.2:{POOL_PORT} -> 203.0.113.9:51234) at 2026-11-23\n")
        self.assertEqual(console._chat_session_map[1], "chat-a")

    def test_the_handler_wins_over_a_command_running_in_another_chat(self):
        console = self.console()
        self.run_for(console, A, f"[*] Started reverse TCP handler on 0.0.0.0:{POOL_PORT}\n")
        self.run_for(console, A2, f"[*] Command shell session 2 opened (10.214.0.2:{POOL_PORT} -> "
                                  f"203.0.113.9:40000) at 2026-11-23\n")
        self.assertEqual(console._chat_session_map[2], "chat-a")

    def test_a_bind_handler_is_matched_by_its_target(self):
        console = self.console()
        self.run_for(console, A, "[*] Started bind TCP handler against 10.0.0.5:4444\n")
        self.run_for(console, A2, "Active sessions\n")
        console._detect_session_events("[*] Command shell session 3 opened (10.214.0.2:39001 -> 10.0.0.5:4444)\n")
        self.assertEqual(console._chat_session_map[3], "chat-a")

    def test_an_https_handler_is_matched_by_its_port(self):
        console = self.console()
        self.run_for(console, A2, "[*] Started HTTPS reverse handler on https://0.0.0.0:8443\n")
        self.run_for(console, A, "Active sessions\n")
        console._detect_session_events("[*] Meterpreter session 4 opened (10.214.0.2:8443 -> 203.0.113.9:50000)\n")
        self.assertEqual(console._chat_session_map[4], "chat-a2")

    def test_a_foreground_exploit_links_its_own_chat(self):
        console = self.console()
        self.run_for(console, A, "Active sessions\n")
        self.run_for(console, A2, "[*] Command shell session 5 opened (10.214.0.2:41000 -> 10.0.0.9:22)\n")
        self.assertEqual(console._chat_session_map[5], "chat-a2")

    def test_a_restart_forgets_the_handlers(self):
        console = self.console()
        self.run_for(console, A, f"[*] Started reverse TCP handler on 0.0.0.0:{POOL_PORT}\n")
        console.restart()
        self.assertEqual(console._handler_chats, {})

    def test_the_real_execute_marks_its_chat_only_while_it_runs(self):
        console = msf.PersistentMsfConsole()
        console.process = mock.Mock()
        console.process.poll.return_value = None
        seen = []
        with mock.patch.object(console, "_execute_locked",
                               side_effect=lambda *a: seen.append(console._command_chat) or "ok"):
            self.assertEqual(console.execute("jobs", chat="chat-a"), "ok")
        self.assertEqual(seen, ["chat-a"])
        self.assertIsNone(console._command_chat)


class TheBusyRefusalSpeaksOfThePersonsSandbox(unittest.TestCase):
    def test_wording(self):
        text = msf._busy_refusal("it has live sessions or jobs")
        self.assertTrue(text.startswith("[REFUSED] Metasploit in your Kali sandbox is held by another of "
                                        "your projects (it has live sessions or jobs)"))
        self.assertIn("one msfconsole for all of your projects and chats", text)
        self.assertNotIn("RedAmon instance", text)
        self.assertNotIn("administrator", text)


if __name__ == "__main__":
    unittest.main()
