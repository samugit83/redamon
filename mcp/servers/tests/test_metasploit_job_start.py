"""A background job's start reaches the command that started it; late output is never lost.

On a cold msfconsole (the first handler of a fresh sandbox, minutes of module loading in
the Kali image), `handler -p ... -P <port>` printed only its echo within the command's
3 s quiet period. "Payload handler running as background job 0." and "Started reverse
TCP handler on 0.0.0.0:<port>" came 5-7 s later, and the next command's "clear pending
output" threw them away. The model never learnt the handler had started, and an exploit
fired at once called back before anything listened (follow-up FU, P7's end-to-end run,
reproduced in throwaway Kali containers through the real PersistentMsfConsole).

Now:
- a command that starts a handler or a background exploit job waits, up to
  LISTENER_WAIT_S, until its handler says it listens (or fails), and returns those
  lines; past the wait it says plainly that the handler did not start listening;
- output that arrives after a command returned is kept and handed, under a marker, to
  the next command, wherever the console's queue is drained in between.

The console here is the real PersistentMsfConsole and its reader thread, reading a
real pipe; only the msfconsole behind it is scripted: it echoes each command at once
and prints the scripted lines after the delays a cold console shows (shortened).

Run (root-agent section, agent image):
  python -m pytest mcp/servers/tests/test_metasploit_job_start.py -q
"""
import importlib.util
import json
import os
import sys
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

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
_spec = importlib.util.spec_from_file_location("metasploit_server_job_start", _PATH)
msf = importlib.util.module_from_spec(_spec)
with mock.patch.dict(sys.modules, {"fastmcp": _fastmcp}):
    _spec.loader.exec_module(msf)

OWNER = json.dumps({"project_id": "project-a", "user_id": "alice", "chat_session_id": "chat-a"})
# The command's own quiet period, shortened like the cold console's delays below.
QUIET_S = 0.5
COLD_S = 1.5


class ScriptedMsfconsole:
    """msfconsole on a pipe: a command line is echoed at once; the lines scripted for a
    command (matched by its first word) follow after their delays."""

    def __init__(self, script):
        read_fd, write_fd = os.pipe()
        self.stdout = os.fdopen(read_fd, "r")
        self._out = os.fdopen(write_fd, "w", buffering=1)
        self._lock = threading.Lock()
        self.script = script
        self.stdin = self
        self.pid = 4242
        self.sent = []

    def poll(self):
        return None

    def emit(self, line, delay=0.0):
        def put():
            with self._lock:
                self._out.write(line + "\n")
                self._out.flush()
        threading.Timer(delay, put).start() if delay else put()

    def write(self, data):
        for command in filter(None, data.split("\n")):
            self.sent.append(command)
            self.emit(f"msf > {command}")
            for delay, line in self.script.get(command.split()[0], []):
                self.emit(line, delay)

    def flush(self):
        pass


def console_on(script):
    console = msf.PersistentMsfConsole()
    console.process = ScriptedMsfconsole(script)
    console._initialized = True
    console.reader_thread = threading.Thread(target=console._read_output, daemon=True)
    console.reader_thread.start()
    return console


def run(console, command):
    with mock.patch.object(msf, "get_msf_console", return_value=console), \
            mock.patch.object(msf, "MSF_DEFAULT_QUIET_PERIOD", QUIET_S), \
            mock.patch.object(msf, "MSF_EXPLOIT_QUIET_PERIOD", QUIET_S), \
            mock.patch.object(msf, "MSF_RUN_QUIET_PERIOD", QUIET_S):
        return msf.metasploit_console(command, _redamon_owner=OWNER)


HANDLER = "handler -p generic/shell_reverse_tcp -H 172.28.0.1 -P 40190"
COLD_HANDLER = {"handler": [(COLD_S, "[*] Payload handler running as background job 0."),
                            (COLD_S + 0.1, "[-] Handler failed to bind to 172.28.0.1:40190:-  -"),
                            (COLD_S + 0.2, "[*] Started reverse TCP handler on 0.0.0.0:40190 ")]}


class AColdHandlerStartsInItsOwnCommand(unittest.TestCase):
    def test_the_handler_command_returns_its_job_and_listening_lines(self):
        console = console_on(COLD_HANDLER)
        out = run(console, HANDLER)
        self.assertIn("Payload handler running as background job 0.", out)
        self.assertIn("Started reverse TCP handler on 0.0.0.0:40190", out)
        self.assertNotIn("did not start listening", out)
        # The LHOST fallback is a normal start: no busy note.
        self.assertNotIn("[REDAMON]", out)
        # The handler is linked to the chat whose command started it.
        self.assertEqual(console._handler_chats.get(("lport", 40190)), "chat-a")

    def test_a_background_exploit_job_waits_for_its_handler(self):
        console = console_on({"exploit": [
            (0.1, "[*] Exploit running as background job 3."),
            (0.2, "[*] Exploit completed, but no session was created."),
            (COLD_S, "[*] Started reverse TCP handler on 0.0.0.0:40190 ")]})
        out = run(console, "exploit -j")
        self.assertIn("Exploit running as background job 3.", out)
        self.assertIn("Started reverse TCP handler on 0.0.0.0:40190", out)

    def test_a_bind_failure_arrives_in_the_command_and_gets_its_note(self):
        console = console_on({"handler": [
            (COLD_S, "[*] Payload handler running as background job 1."),
            (COLD_S + 0.1, "[-] Handler failed to bind to 0.0.0.0:40190:-  -"),
            (COLD_S + 0.2, "[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use "
                           "or unavailable: (0.0.0.0:40190).")]})
        console.port_holder = mock.Mock(return_value=(77, "nc"))
        out = run(console, HANDLER)
        self.assertIn("Rex::BindFailed", out)
        self.assertIn("[REDAMON] Port 40190 is already in use in your Kali sandbox", out)
        self.assertNotIn("did not start listening", out)

    def test_a_handler_that_never_listens_is_said_so(self):
        console = console_on({"handler": [(0.1, "[*] Payload handler running as background job 0.")]})
        with mock.patch.object(msf, "LISTENER_WAIT_S", 1.5):
            started = time.monotonic()
            out = run(console, HANDLER)
        self.assertLess(time.monotonic() - started, 6)
        self.assertIn("[REDAMON] The handler did not start listening within 1.5 s; check `jobs` before "
                      "firing the exploit.", out)

    def test_an_auxiliary_job_is_no_handler_to_wait_for(self):
        console = console_on({"run": [(0.1, "[*] Auxiliary module running as background job 2."),
                                      (0.2, "[*] Starting the SOCKS proxy server")]})
        started = time.monotonic()
        out = run(console, "run -j")
        self.assertLess(time.monotonic() - started, msf.LISTENER_WAIT_S)
        self.assertIn("Auxiliary module running as background job 2.", out)
        self.assertNotIn("did not start listening", out)

    def test_a_plain_command_does_not_wait(self):
        console = console_on({"jobs": [(0.05, "No active jobs.")]})
        started = time.monotonic()
        out = run(console, "jobs -l")
        self.assertLess(time.monotonic() - started, 3)
        self.assertNotIn("did not start listening", out)

    def test_the_command_start_is_read_from_the_command_and_its_output(self):
        for command in ("handler -p x -P 1", "exploit -j", "run -j -z", "use exploit/x; exploit -j", "to_handler"):
            with self.subTest(command=command):
                self.assertTrue(msf.starts_a_listener(command, ""))
        for command in ("jobs", "sessions -l", "set LHOST 1.2.3.4", "run", "search handler", "exploit"):
            with self.subTest(command=command):
                self.assertFalse(msf.starts_a_listener(command, ""))
        self.assertTrue(msf.starts_a_listener("exploit", "[*] Exploit running as background job 0."))
        self.assertFalse(msf.starts_a_listener("run", "[*] Auxiliary module running as background job 0."))


class LateOutputIsHandedToTheNextCommand(unittest.TestCase):
    MARK = "[output that arrived after the previous command returned]"

    def test_a_line_after_a_command_returned_opens_the_next_ones_output(self):
        console = console_on({"set": [(QUIET_S + 1.0, "[*] Command shell session 1 opened "
                                                       "(10.214.0.4:40190 -> 10.214.0.1:60356) at 2026-11-23")]})
        first = run(console, "set LHOST 10.214.0.4")
        self.assertNotIn("session 1 opened", first)
        time.sleep(1.5)
        second = run(console, "jobs -l")
        self.assertTrue(second.startswith(self.MARK), second)
        late, _, rest = second.partition("[end of that output]")
        self.assertIn("Command shell session 1 opened", late)
        self.assertIn("jobs -l", rest)
        # Handed once only.
        self.assertNotIn(self.MARK, run(console, "jobs -l"))

    def test_late_status_lines_survive_the_session_list_refresh(self):
        # The refresh loop's `sessions -l` drains the queue every few seconds.
        console = console_on({"set": [(QUIET_S + 0.8, "[*] Meterpreter session 2 opened "
                                                       "(10.214.0.4:40190 -> 10.214.0.1:60357)")],
                              "sessions": [(0.05, "Active sessions"), (0.06, "==============="),
                                           (0.07, "No active sessions.")]})
        run(console, "set LHOST 10.214.0.4")
        time.sleep(0.4)
        with console.lock:
            listing = console._quick_execute("sessions -l", timeout=3, quiet_period=1.0, keep_events=True)
        self.assertIn("No active sessions.", listing)
        second = run(console, "jobs -l")
        self.assertIn("Meterpreter session 2 opened", second.partition("[end of that output]")[0])
        # The refresh's own listing is not handed on.
        self.assertNotIn("No active sessions.", second)

    def test_prompt_noise_alone_is_not_handed_on(self):
        console = console_on({})
        run(console, "set LHOST 10.214.0.4")
        console.process.emit("msf6 exploit(multi/handler) > ")
        console.process.emit("")
        time.sleep(0.3)
        self.assertNotIn(self.MARK, run(console, "jobs -l"))

    def test_a_restart_forgets_late_output(self):
        console = console_on({})
        console._late_lines.append("[*] something")
        console.restart()
        self.assertEqual(list(console._late_lines), [])

    def test_late_output_is_bounded(self):
        console = console_on({})
        for n in range(msf.LATE_OUTPUT_MAX_LINES + 50):
            console._keep_late(f"[*] line {n}")
        self.assertEqual(len(console._late_lines), msf.LATE_OUTPUT_MAX_LINES)
        self.assertEqual(console._late_lines[-1], f"[*] line {msf.LATE_OUTPUT_MAX_LINES + 49}")


if __name__ == "__main__":
    unittest.main()
