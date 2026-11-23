"""The Metasploit session manager (:8013) answers concurrently (group 1, E3; S16b, after M-b).

It used to be a single-threaded ``http.server.HTTPServer``: a ``POST /sessions/<n>/interact``
holds the request thread for up to 8 s waiting for the console lock, a cache-miss
``sessions -l`` and a read until the msf prompt (up to 30 s), so the agent's ``GET /sessions``
fan-out (FANOUT_TIMEOUT_S, 5 s) gave up on that sandbox and the person's own row vanished from
the Sessions panel mid-command. Now:

- every request runs on its own daemon thread, at most SESSION_SERVER_MAX_THREADS at once; a
  connection beyond the cap is closed before it is read, so it reaches no handler;
- a peer that connects and sends nothing is dropped after SessionProgressHandler.timeout, freeing
  its thread (one such peer used to block the server for good);
- the bearer is still checked on every request before any handler runs;
- ``GET /sessions`` is answered from the cache while an interact waits for the console lock;
- the non-MSF session store is read and written under the console's ``_detail_lock``, and two
  registrations in the same millisecond get two ids (they used to overwrite each other);
- a drive waits for the console within the agent's budgets (read from agentic/api.py), a kill's
  read is capped at what its budget left, a drive whose caller hung up while it waited sends
  nothing, and interacts never take the console slots kept for kills (review round 3).

metasploit_server is loaded by path with fastmcp stubbed (see test_metasploit_progress.py).

Run (root-agent section, agent image):
  python -m pytest mcp/servers/tests/test_metasploit_session_server_concurrency.py -q
"""
import ast
import http.client
import importlib.util
import json
import os
import re
import socket
import sys
import threading
import time
import types
import unittest
from pathlib import Path
from socketserver import ThreadingMixIn
from unittest import mock

sys.modules.setdefault("fastmcp", mock.MagicMock())

_PATH = Path(__file__).resolve().parents[1] / "metasploit_server.py"
_spec = importlib.util.spec_from_file_location("metasploit_server_concurrency", _PATH)
msf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(msf)

TOKEN = "test-mcp-auth-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
REFUSED = (http.client.HTTPException, OSError)


def _request(port, method, path, body=None, headers=None, timeout=3.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        data = json.dumps(body).encode() if body is not None else None
        hdrs = dict(AUTH if headers is None else headers)
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class _HeldConsole:
    """Stands in for PersistentMsfConsole: each interact holds its request until released."""

    def __init__(self):
        self.release = threading.Event()
        self.entered = threading.Semaphore(0)
        self.calls = []

    def interact_session(self, sid, command):
        self.calls.append(("interact", sid))
        self.entered.release()
        self.release.wait(10)
        return {"busy": False, "output": "ALICE-42"}

    def kill_session(self, sid):
        self.calls.append(("kill", sid))
        return {"busy": False, "output": "killed"}

    def get_sessions_data(self):
        self.calls.append("sessions")
        return {"sessions": [{"id": 1}], "jobs": [], "non_msf_sessions": [],
                "cache_age_seconds": 1.0, "agent_busy": False}


class _ServedCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": TOKEN})
        patcher.start()
        self.addCleanup(patcher.stop)

    def serve(self, console, server=None):
        """The session manager on an ephemeral port, its console replaced by `console`, a
        console already started (a list never starts one)."""
        for name, value in (("get_msf_console", mock.Mock(return_value=console)), ("_msf_console", console)):
            patcher = mock.patch.object(msf, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        if server is None:
            server = msf.start_progress_server(0)
        else:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def in_background(self, port, method, path, body=None):
        out = []
        t = threading.Thread(target=lambda: out.append(_request(port, method, path, body, timeout=20)), daemon=True)
        t.start()
        return t, out


class TheServerIsThreaded(_ServedCase):
    def test_the_session_manager_serves_each_request_on_a_daemon_thread_with_a_cap(self):
        server = msf.start_progress_server(0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.assertIsInstance(server, ThreadingMixIn)
        self.assertTrue(server.daemon_threads)
        self.assertFalse(server.block_on_close, "closing must not wait for a hung command")
        self.assertEqual(server.max_threads, msf.SESSION_SERVER_MAX_THREADS)
        self.assertGreaterEqual(msf.SESSION_SERVER_MAX_THREADS, 4)
        self.assertLessEqual(msf.SESSION_SERVER_MAX_THREADS, 64)

    def test_a_session_list_is_answered_while_an_interact_waits_for_the_console(self):
        console = msf.PersistentMsfConsole()
        console._session_details = [{"id": 1, "type": "shell", "info": "", "connection": "",
                                     "target_ip": "", "chat_session_id": "session_x"}]
        console._detail_cache_time = time.time()
        entered = threading.Event()
        interact = console.interact_session

        def traced(sid, command):
            entered.set()
            return interact(sid, command)

        console.interact_session = traced
        port = self.serve(console)
        # An exploit (or the refresh loop) holds the console: the interact waits up to 8 s for it.
        console.lock.acquire()
        try:
            worker, answered = self.in_background(port, "POST", "/sessions/1/interact", {"command": "id"})
            self.assertTrue(entered.wait(5))
            started = time.monotonic()
            status, body = _request(port, "GET", "/sessions", timeout=3)
            took = time.monotonic() - started
        finally:
            console.lock.release()
        worker.join(15)
        self.assertEqual(status, 200)
        self.assertEqual([s["id"] for s in json.loads(body)["sessions"]], [1])
        self.assertLess(took, 2.0, "the list waited for the interact")
        self.assertEqual(answered[0][0], 200)

    def test_the_bearer_is_checked_on_every_request_while_another_one_runs(self):
        console = _HeldConsole()
        port = self.serve(console)
        self.addCleanup(console.release.set)
        worker, _ = self.in_background(port, "POST", "/sessions/1/interact", {"command": "id"})
        self.assertTrue(console.entered.acquire(timeout=5))
        for headers in ({}, {"Authorization": "Bearer wrong-token"}):
            with self.subTest(headers=headers):
                status, body = _request(port, "GET", "/sessions", headers=headers, timeout=3)
                self.assertEqual(status, 401)
                self.assertEqual(json.loads(body)["error"], "unauthorized")
        self.assertEqual(console.calls, [("interact", 1)], "a refused request reached the console")
        status, _ = _request(port, "GET", "/sessions", timeout=3)
        self.assertEqual(status, 200)
        console.release.set()
        worker.join(15)


class TheThreadsAreBounded(_ServedCase):
    def test_a_connection_beyond_the_cap_is_closed_unread_and_the_server_recovers(self):
        console = _HeldConsole()
        server = msf.SessionHTTPServer(("127.0.0.1", 0), msf.SessionProgressHandler, max_threads=2)
        port = self.serve(console, server)
        self.addCleanup(console.release.set)
        workers = [self.in_background(port, "POST", f"/sessions/{n}/interact", {"command": "id"})
                   for n in (1, 2)]
        for _ in workers:
            self.assertTrue(console.entered.acquire(timeout=5))
        with self.assertRaises(REFUSED):
            _request(port, "GET", "/sessions", timeout=3)
        self.assertNotIn("sessions", console.calls, "a refused connection reached a handler")
        console.release.set()
        for worker, answered in workers:
            worker.join(15)
            self.assertEqual(answered[0][0], 200)
        deadline = time.monotonic() + 3
        while True:
            try:
                status, _ = _request(port, "GET", "/sessions", timeout=3)
                break
            except REFUSED:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        self.assertEqual(status, 200)

    def test_a_silent_peer_is_dropped_and_frees_its_thread(self):
        # The stdlib default is None: a peer that never sends its request line holds its thread for good.
        timeout = msf.SessionProgressHandler.timeout
        self.assertIsInstance(timeout, (int, float))
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 30)
        console = _HeldConsole()
        # Shortened so the test does not wait the real timeout out.
        with mock.patch.object(msf.SessionProgressHandler, "timeout", 0.5):
            port = self.serve(console)
            silent = socket.create_connection(("127.0.0.1", port), timeout=5)
            self.addCleanup(silent.close)
            started = time.monotonic()
            self.assertEqual(silent.recv(1), b"", "the server kept a connection that sent nothing")
            self.assertLess(time.monotonic() - started, 4.0)
        status, _ = _request(port, "GET", "/sessions", timeout=3)
        self.assertEqual(status, 200)


class _NeverFreeLock:
    """A console lock some command holds for good: records how long each drive waits for it."""

    def __init__(self):
        self.waits = []

    def acquire(self, blocking=True, timeout=-1):
        self.waits.append(timeout)
        return False

    def release(self):
        raise AssertionError("released a lock that was never taken")


def _agent_drive_budgets() -> dict:
    """The agent's budget per drive (agentic/api.py `_SESSION_DRIVE_S`): past it the agent answers 504."""
    api = Path(__file__).resolve().parents[3] / "agentic" / "api.py"
    for node in ast.walk(ast.parse(api.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_SESSION_DRIVE_S" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("agentic/api.py no longer defines _SESSION_DRIVE_S")


AGENT_BUDGETS = _agent_drive_budgets()
AGENT_INTERACT_BUDGET_S = AGENT_BUDGETS["interact"]
AGENT_KILL_BUDGET_S = AGENT_BUDGETS["kill"]


class _WaitedLock:
    """A console lock taken after `waited` seconds of a patched monotonic clock."""

    def __init__(self, clock, waited):
        self.clock, self.waited = clock, waited

    def acquire(self, blocking=True, timeout=-1):
        self.clock[0] += self.waited
        return True

    def release(self):
        pass


class DrivesWaitForTheConsole(unittest.TestCase):
    """Threaded, a drive no longer queues in the listen backlog behind a running command: it waits
    for the console lock itself, so its wait must cover what the backlog used to (review S16b 1, 2)."""

    def test_a_kill_waits_longer_than_before_and_still_answers_within_the_agents_budget(self):
        wait = msf.KILL_CONSOLE_WAIT_S
        self.assertGreater(wait, 5, "a kill during a running command answered busy at 5 s")
        self.assertLess(wait, msf.KILL_ANSWER_BUDGET_S)
        self.assertLess(msf.KILL_ANSWER_BUDGET_S, AGENT_KILL_BUDGET_S, "the kill must answer before the agent gives up")
        console = msf.PersistentMsfConsole()
        console.lock = _NeverFreeLock()
        self.assertTrue(console.kill_session(2)["busy"])
        self.assertTrue(console.kill_job(0)["busy"])
        self.assertEqual(console.lock.waits, [wait, wait])

    def test_the_kill_read_is_capped_at_the_budget_left_after_the_wait(self):
        # Review S16b round 3: the read after `sessions -k` restarted its quiet clock on any output
        # (up to 15 s), so a 10 s wait plus a chatty teardown outlasted the agent's budget.
        for waited in (0.0, 4.0, msf.KILL_CONSOLE_WAIT_S):
            for kill in ("kill_session", "kill_job"):
                with self.subTest(waited=waited, kill=kill):
                    clock = [1000.0]
                    console = msf.PersistentMsfConsole()
                    console.lock = _WaitedLock(clock, waited)
                    reads = []
                    console._quick_execute = lambda command, timeout=15, quiet_period=3.0: reads.append((command, timeout)) or ""
                    fake_time = types.SimpleNamespace(monotonic=lambda: clock[0], time=time.time, sleep=time.sleep)
                    with mock.patch.object(msf, "time", fake_time):
                        self.assertFalse(getattr(console, kill)(2)["busy"])
                    command, read_s = reads[0]
                    self.assertEqual(command, "sessions -k 2" if kill == "kill_session" else "jobs -k 2")
                    self.assertAlmostEqual(read_s, max(1.0, msf.KILL_ANSWER_BUDGET_S - waited))
                    self.assertLess(waited + read_s, AGENT_KILL_BUDGET_S)

    def test_an_interact_waits_for_a_running_command_as_the_backlog_let_it(self):
        wait = msf.INTERACT_CONSOLE_WAIT_S
        self.assertGreaterEqual(wait, 25, "a second interact answered busy at 8 s")
        self.assertLess(wait, AGENT_INTERACT_BUDGET_S)
        console = msf.PersistentMsfConsole()
        console.lock = _NeverFreeLock()
        self.assertTrue(console.interact_session(1, "id")["busy"])
        self.assertEqual(console.lock.waits, [wait])


class SlotsForAuthenticatedRequests(_ServedCase):
    """Slow or silent heads and queued drives never take the threads a session list needs (S16b 4, 2)."""

    def bounded(self, console, **caps):
        server = msf.SessionHTTPServer(("127.0.0.1", 0), msf.SessionProgressHandler, **caps)
        return self.serve(console, server)

    def test_the_production_caps_leave_room_for_the_session_list(self):
        self.assertLessEqual(msf.SESSION_HEAD_DEADLINE_S, 10)
        self.assertLess(msf.SESSION_SERVER_MAX_UNAUTHENTICATED + msf.SESSION_SERVER_MAX_CONSOLE_DRIVES,
                        msf.SESSION_SERVER_MAX_THREADS)

    def test_a_head_dripped_a_byte_at_a_time_is_cut_at_the_head_deadline(self):
        port = self.bounded(_HeldConsole(), head_deadline_s=0.6)
        drip = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(drip.close)
        started = time.monotonic()
        cut = False
        for byte in b"GET /sessions HTTP/1.1\r\nX-Slow: " + b"a" * 40:
            try:
                drip.sendall(bytes([byte]))
            except OSError:
                cut = True
                break
            drip.settimeout(0.2)
            try:
                if drip.recv(1) == b"":
                    cut = True
                    break
            except socket.timeout:
                pass
            if time.monotonic() - started > 4:
                break
        self.assertTrue(cut, "a head that never completes kept its thread")
        self.assertLess(time.monotonic() - started, 3.0)

    def test_a_cut_head_or_a_peer_that_hung_up_prints_no_traceback(self):
        # Each cut head writes its 400 into a closed socket: one traceback each would let any peer
        # flood the sandbox's log. Other errors are still reported.
        server = msf.SessionHTTPServer(("127.0.0.1", 0), msf.SessionProgressHandler)
        self.addCleanup(server.server_close)
        for gone in (BrokenPipeError(32, "Broken pipe"), ConnectionResetError(104, "reset"), TimeoutError("timed out")):
            with self.subTest(error=type(gone).__name__), mock.patch("sys.stderr") as err:
                try:
                    raise gone
                except OSError:
                    server.handle_error(None, ("127.0.0.1", 1))
                self.assertFalse(err.write.called)
        with mock.patch("sys.stderr") as err:
            try:
                raise ValueError("a real handler bug")
            except ValueError:
                server.handle_error(None, ("127.0.0.1", 1))
            self.assertTrue(err.write.called)

    def test_silent_heads_beyond_the_cap_make_room_and_never_refuse_an_authenticated_request(self):
        console = _HeldConsole()
        port = self.bounded(console, max_threads=6, max_unauthenticated=2, head_deadline_s=30)
        silent = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(4)]
        for s in silent:
            self.addCleanup(s.close)
        status, _ = _request(port, "GET", "/sessions", timeout=3)
        self.assertEqual(status, 200)
        # The oldest silent heads were cut to make room: they read EOF, not a hang.
        silent[0].settimeout(3)
        self.assertEqual(silent[0].recv(1), b"")

    def test_queued_drives_are_capped_and_the_session_list_still_finds_a_thread(self):
        console = _HeldConsole()
        port = self.bounded(console, max_threads=4, max_unauthenticated=1, max_console_drives=2, kill_reserved_drives=0)
        self.addCleanup(console.release.set)
        workers = []
        for n in (1, 2):
            # One at a time: with a single unauthenticated slot a second head would cut the first.
            workers.append(self.in_background(port, "POST", f"/sessions/{n}/interact", {"command": "id"}))
            self.assertTrue(console.entered.acquire(timeout=5))
        status, body = _request(port, "POST", "/sessions/3/interact", {"command": "id"}, timeout=3)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["busy"], "a third drive queued past the cap")
        self.assertNotIn(("interact", 3), console.calls)
        status, _ = _request(port, "GET", "/sessions", timeout=3)
        self.assertEqual(status, 200)
        console.release.set()
        for worker, answered in workers:
            worker.join(15)
            self.assertEqual(answered[0][0], 200)


class _ScriptedProcess:
    """msfconsole as far as a drive sees it: records what is written, answers a `sessions -c` at once."""

    def __init__(self, console):
        self.console, self.written = console, []
        self.stdin = self

    def poll(self):
        return None

    def write(self, text):
        self.written.append(text)
        if text.startswith("sessions -c"):
            self.console.output_queue.put(text)
            self.console.output_queue.put("OUT: uid=0(root)\n")
            self.console.output_queue.put("msf6 > \n")

    def flush(self):
        pass


class AGoneCallerGetsNothing(_ServedCase):
    """Review S16b round 3: a drive that waited for the console must not run once its caller has
    gone (the agent closes its connection when it stops waiting): it would run unseen, and a retry
    would run it twice. A caller still there is served as before."""

    def held_console(self):
        console = msf.PersistentMsfConsole()
        console._session_details = [{"id": 1, "type": "shell", "info": "", "connection": "",
                                     "target_ip": "", "chat_session_id": "session_x"}]
        console._detail_cache_time = time.time()
        console.process = _ScriptedProcess(console)
        entered, done = threading.Event(), threading.Event()
        for name in ("interact_session", "kill_session"):
            real = getattr(console, name)

            def traced(*args, _real=real):
                entered.set()
                try:
                    return _real(*args)
                finally:
                    done.set()

            setattr(console, name, traced)
        return console, entered, done

    def abandon(self, port, path, body):
        """Send a whole drive request, then hang up as the agent does when its budget runs out."""
        data = json.dumps(body).encode() if body is not None else b""
        head = (f"POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode()
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.sendall(head + data)
        return sock

    def test_an_interact_whose_caller_gave_up_while_it_waited_is_never_sent(self):
        console, entered, done = self.held_console()
        port = self.serve(console)
        console.lock.acquire()
        try:
            sock = self.abandon(port, "/sessions/1/interact", {"command": "id"})
            self.assertTrue(entered.wait(5))
            sock.close()
            # Longer than the wait after which a drive checks its caller (_CALLER_CHECK_AFTER_WAIT_S).
            time.sleep(0.8)
        finally:
            console.lock.release()
        self.assertTrue(done.wait(10))
        self.assertEqual(console.process.written, [], "a command reached the session after its caller left")

    def test_a_kill_whose_caller_gave_up_while_it_waited_is_never_sent(self):
        console, entered, done = self.held_console()
        port = self.serve(console)
        console.lock.acquire()
        try:
            sock = self.abandon(port, "/sessions/1/kill", None)
            self.assertTrue(entered.wait(5))
            sock.close()
            # Longer than the wait after which a drive checks its caller (_CALLER_CHECK_AFTER_WAIT_S).
            time.sleep(0.8)
        finally:
            console.lock.release()
        self.assertTrue(done.wait(10))
        self.assertEqual(console.process.written, [])

    def test_a_caller_still_waiting_is_served_once_the_console_is_free(self):
        console, entered, done = self.held_console()
        port = self.serve(console)
        console.lock.acquire()
        try:
            worker, answered = self.in_background(port, "POST", "/sessions/1/interact", {"command": "id"})
            self.assertTrue(entered.wait(5))
            time.sleep(0.3)
        finally:
            console.lock.release()
        worker.join(15)
        self.assertEqual(answered[0][0], 200)
        self.assertIn("uid=0(root)", json.loads(answered[0][1])["output"])
        self.assertEqual(console.process.written, ['sessions -c "id" -i 1\n'])

    def test_an_mcp_call_has_no_http_caller_and_is_never_refused_as_gone(self):
        self.assertFalse(msf._caller_gave_up())

    def test_a_half_closed_caller_is_served_when_the_console_was_free(self):
        # Review S16b round 4: a client that shuts its sending side (still reading) looks like a
        # closed one; the check runs only for a drive that actually waited for the console.
        self.assertLessEqual(msf._CALLER_CHECK_AFTER_WAIT_S, 1.0)
        console, entered, done = self.held_console()
        port = self.serve(console)
        sock = self.abandon(port, "/sessions/1/interact", {"command": "id"})
        self.addCleanup(sock.close)
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(10)
        answer = b""
        while chunk := sock.recv(4096):
            answer += chunk
        self.assertIn(b" 200 ", answer.split(b"\r\n", 1)[0])
        self.assertIn(b"uid=0(root)", answer)
        self.assertEqual(console.process.written, ['sessions -c "id" -i 1\n'])


class _StillRunningProcess(_ScriptedProcess):
    """A `sessions -c` whose command keeps running: its echo and a first line, never the prompt."""

    def write(self, text):
        self.written.append(text)
        if text.startswith("sessions -c"):
            self.console.output_queue.put(text)
            self.console.output_queue.put("GHOSTB-0\n")


class AContendedInteractAnswersInTime(_ServedCase):
    """Review S16b round 4: an interact that waited for the console read up to 30 s more, so the
    agent (40 s) gave up while the command ran on unseen. Its read now gets what a budget measured
    from its arrival leaves (INTERACT_ANSWER_BUDGET_S, under the agent's), and an answer cut short
    says the command is still running. An uncontended interact keeps its full read."""

    def test_the_read_gets_what_the_budget_left_and_the_full_read_without_a_wait(self):
        self.assertLess(msf.INTERACT_ANSWER_BUDGET_S, AGENT_INTERACT_BUDGET_S)
        self.assertGreaterEqual(msf.INTERACT_ANSWER_BUDGET_S - msf.INTERACT_CONSOLE_WAIT_S, msf.INTERACT_MIN_READ_S)
        clock = [1000.0]
        fake_time = types.SimpleNamespace(monotonic=lambda: clock[0], time=time.time, sleep=time.sleep)
        with mock.patch.object(msf, "time", fake_time):
            read = msf.PersistentMsfConsole._interact_read_s
            self.assertEqual(read(1000.0), msf.INTERACT_READ_S, "an uncontended interact lost its full read")
            clock[0] = 1028.3
            self.assertAlmostEqual(read(1000.0), msf.INTERACT_ANSWER_BUDGET_S - 28.3)
            clock[0] = 1001.0
            self.assertEqual(read(1000.0, reserve=6.0), msf.INTERACT_READ_S)
            clock[0] = 1020.0
            self.assertAlmostEqual(read(1000.0, reserve=6.0), msf.INTERACT_ANSWER_BUDGET_S - 6.0 - 20.0)

    def contended(self, budget, min_read, held_s):
        console = msf.PersistentMsfConsole()
        console._session_details = [{"id": 1, "type": "shell", "info": "", "connection": "",
                                     "target_ip": "", "chat_session_id": "session_x"}]
        console._detail_cache_time = time.time()
        console.process = _StillRunningProcess(console)
        port = self.serve(console)
        for name, value in (("INTERACT_ANSWER_BUDGET_S", budget), ("INTERACT_MIN_READ_S", min_read)):
            patcher = mock.patch.object(msf, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        console.lock.acquire()
        started = time.monotonic()
        worker, answered = self.in_background(port, "POST", "/sessions/1/interact", {"command": "sleep 15"})
        time.sleep(held_s)
        console.lock.release()
        worker.join(15)
        return console, answered[0], time.monotonic() - started

    def test_a_contended_interact_answers_within_its_budget_and_says_the_command_still_runs(self):
        console, (status, body), took = self.contended(budget=3.0, min_read=0.5, held_s=1.2)
        self.assertEqual(status, 200)
        answer = json.loads(body)
        self.assertEqual(answer["busy"], False)
        self.assertIs(answer["still_running"], True)
        self.assertIn("GHOSTB-0", answer["output"])
        self.assertLess(took, 3.0 + 0.8, "the answer outlived the interact's budget")
        self.assertEqual(console.process.written, ['sessions -c "sleep 15" -i 1\n'])

    def test_too_little_time_left_sends_nothing_and_answers_busy(self):
        console, (status, body), _ = self.contended(budget=1.5, min_read=3.0, held_s=0.6)
        self.assertEqual(status, 200)
        self.assertIs(json.loads(body)["busy"], True)
        self.assertEqual(console.process.written, [], "a command was sent with no time left to read it")


class KillsKeepAConsoleSlot(_ServedCase):
    """Interacts queued for the console never take the slots a kill needs (review S16b round 3, optional)."""

    def test_with_every_interact_slot_taken_a_kill_is_still_admitted(self):
        self.assertGreaterEqual(msf.SESSION_SERVER_KILL_RESERVED_DRIVES, 1)
        self.assertLess(msf.SESSION_SERVER_KILL_RESERVED_DRIVES, msf.SESSION_SERVER_MAX_CONSOLE_DRIVES)
        console = _HeldConsole()
        server = msf.SessionHTTPServer(("127.0.0.1", 0), msf.SessionProgressHandler,
                                       max_console_drives=2, kill_reserved_drives=1)
        port = self.serve(console, server)
        self.addCleanup(console.release.set)
        worker, _ = self.in_background(port, "POST", "/sessions/1/interact", {"command": "id"})
        self.assertTrue(console.entered.acquire(timeout=5))
        status, body = _request(port, "POST", "/sessions/2/interact", {"command": "id"})
        self.assertTrue(json.loads(body)["busy"], "a second interact took the slot kept for kills")
        status, body = _request(port, "POST", "/sessions/1/kill")
        self.assertEqual((status, json.loads(body)), (200, {"busy": False, "output": "killed"}))
        self.assertIn(("kill", 1), console.calls)
        console.release.set()
        worker.join(15)


class NonMsfSessionStore(_ServedCase):
    FROZEN = 1_700_000_000.0

    def frozen_clock(self):
        """The module's `time` with a wall clock stuck on one millisecond (the server's own timing,
        on the monotonic clock, keeps running)."""
        return types.SimpleNamespace(time=lambda: self.FROZEN, monotonic=time.monotonic, sleep=time.sleep)

    def test_two_registrations_in_one_millisecond_get_two_ids(self):
        console = msf.PersistentMsfConsole()
        with mock.patch.object(msf, "time", self.frozen_clock()):
            first = console.register_non_msf_session({"type": "listener", "command": "nc -lvnp 4444"})
            second = console.register_non_msf_session({"type": "listener", "command": "nc -lvnp 5555"})
        self.assertNotEqual(first, second)
        for sid in (first, second):
            self.assertRegex(sid, r"^raw-[0-9]{1,20}$")
        listed = console.get_sessions_data()["non_msf_sessions"]
        self.assertEqual(sorted(s["id"] for s in listed), sorted([first, second]))
        self.assertEqual(sorted(s["command"] for s in listed), ["nc -lvnp 4444", "nc -lvnp 5555"])

    def test_registrations_and_deletes_over_http(self):
        console = msf.PersistentMsfConsole()
        port = self.serve(console)
        with mock.patch.object(msf, "time", self.frozen_clock()):
            ids = []
            for port_no in (4444, 5555):
                status, body = _request(port, "POST", "/non-msf-sessions",
                                        {"type": "listener", "command": f"nc -lvnp {port_no}"})
                self.assertEqual(status, 200)
                ids.append(json.loads(body)["id"])
            status, body = _request(port, "GET", "/sessions")
        self.assertEqual(len(set(ids)), 2, "the second registration overwrote the first")
        self.assertEqual(sorted(s["id"] for s in json.loads(body)["non_msf_sessions"]), sorted(ids))
        number = re.fullmatch(r"raw-([0-9]+)", ids[0]).group(1)
        status, _ = _request(port, "DELETE", f"/non-msf-sessions/{number}")
        self.assertEqual(status, 200)
        status, body = _request(port, "GET", "/sessions")
        self.assertEqual([s["id"] for s in json.loads(body)["non_msf_sessions"]], [ids[1]])

    def test_the_store_is_read_and_written_under_the_detail_lock(self):
        console = msf.PersistentMsfConsole()
        sid = console.register_non_msf_session({"type": "listener"})
        console._detail_lock.acquire()
        try:
            done = []
            for work in (lambda: console.register_non_msf_session({"type": "listener"}),
                         lambda: console.forget_non_msf_session(sid),
                         console.get_sessions_data):
                t = threading.Thread(target=lambda w=work: done.append(w()), daemon=True)
                t.start()
                t.join(0.3)
                self.assertTrue(t.is_alive(), "the store was touched without _detail_lock")
        finally:
            console._detail_lock.release()
        deadline = time.monotonic() + 5
        while len(done) < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(done), 3)


if __name__ == "__main__":
    unittest.main()
