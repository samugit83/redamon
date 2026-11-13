"""
A second writer is refused per run, not only at socket open (step 5.11 follow-up; SH-40, OQ-35).

The webapp refuses the chat ticket while another person writes the project, but the ticket is
checked once, when the socket opens, and runs start over the socket for as long as it stays open.
So before each run starts (a message, an approval, an answer to the agent's question, a tool
confirmation, a resume) the socket asks the webapp again (`POST /api/internal/agent/writer-check`,
agentic/writer_check.py) for its ticket's person (`sub`), project and session. A 409
`project_writer_busy` refuses the run with the webapp's own sentence naming who holds the project
(the ticket refusal's payload); any other answer, or none, lets the project's owner's run start and
refuses anyone else's (fail closed, as the webapp does with a source it cannot read). A refused run
starts nothing, saves nothing, and the card of a refused answer comes back in the drawer (`answer`).

Run: ./agentic/run_tests.sh tests/test_run_writer_check.py
"""
import ast
import asyncio
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import httpx  # noqa: E402

#: The real client class, kept before a test patches httpx.AsyncClient (the module is shared).
_RealAsyncClient = httpx.AsyncClient

import writer_check  # noqa: E402
from writer_check import WriterCheck, second_writer_check  # noqa: E402

try:
    import websocket_api  # noqa: F401
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

if _HAVE:
    from decision_check import DecisionCheck  # noqa: E402
    from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager  # noqa: E402

OWNER = "owner-A"
COLLAB = "collab-B"
BOUND_S = 5
ALLOWED = WriterCheck(allowed=True)
BUSY = "Olivia Owner (olivia@example.test) is running a partial recon"
BUSY_ERROR = (f"{BUSY} on this project. One person writes a project at a time: wait for it to finish, "
              "or ask them to stop it.")
UNVERIFIED_BUSY = "whether someone else is writing this project could not be verified (webapp)"
UNVERIFIED_MESSAGE = f"Nothing was started: {UNVERIFIED_BUSY}. Try again shortly."
REFUSED = WriterCheck(allowed=False, message=BUSY_ERROR, busy=BUSY)
UNVERIFIED = WriterCheck(allowed=False, message=UNVERIFIED_MESSAGE, busy=UNVERIFIED_BUSY)


class _Webapp:
    """The webapp behind httpx.MockTransport: records each request and answers `answer(body)`."""

    def __init__(self, status=200, body=None, raises=None, by_person=None):
        self.status, self.body, self.raises = status, body if body is not None else {"allowed": True}, raises
        #: {person: (status, body)}: the answer for a request naming that person.
        self.by_person = by_person or {}
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raises is not None:
            raise self.raises
        status, body = self.by_person.get(json.loads(request.content).get("userId"), (self.status, self.body))
        if isinstance(body, (bytes, str)):
            return httpx.Response(status, content=body)
        return httpx.Response(status, json=body)

    def client(self, *args, **kwargs):
        return _RealAsyncClient(transport=httpx.MockTransport(self.handler))

    def bodies(self):
        return [json.loads(r.content) for r in self.requests]


BUSY_409 = (409, {"error": BUSY_ERROR, "code": "project_writer_busy", "busy": BUSY})


def _real_client(webapp):
    return (mock.patch.object(writer_check.httpx, "AsyncClient", webapp.client),
            mock.patch.dict(writer_check.INTERNAL_HEADERS, {"X-Internal-Key": "k" * 16}))


def _ask(webapp, **kw):
    args = {"user_id": COLLAB, "tenant_id": OWNER, "project_id": "pB", "session_id": "sB", "start": "query", **kw}
    client, key = _real_client(webapp)
    with client, key:
        return asyncio.run(second_writer_check(**args))


class SecondWriterCheck(unittest.TestCase):
    """The agent's client: what it sends, and how it reads every answer."""

    def test_allowed_on_200_allowed_true_and_the_request_names_the_ticket_s_person_never_the_tenant(self):
        webapp = _Webapp()
        self.assertEqual(_ask(webapp, actor_id="admin-1"), ALLOWED)
        (req,) = webapp.requests
        self.assertEqual((req.method, req.url.path), ("POST", "/api/internal/agent/writer-check"))
        self.assertEqual(req.headers["x-internal-key"], "k" * 16)
        self.assertEqual(webapp.bodies(), [{"userId": COLLAB, "projectId": "pB", "sessionId": "sB", "actorId": "admin-1"}])
        self.assertNotIn(OWNER, req.content.decode())

    def test_no_act_sends_no_actor(self):
        webapp = _Webapp()
        _ask(webapp)
        self.assertEqual(webapp.bodies(), [{"userId": COLLAB, "projectId": "pB", "sessionId": "sB"}])

    def test_a_409_project_writer_busy_refuses_with_the_webapp_s_sentence_naming_the_holder(self):
        with self.assertLogs("writer_check", "WARNING") as logs:
            got = _ask(_Webapp(*BUSY_409))
        self.assertEqual(got, REFUSED)
        self.assertIn("[rbac] agent run refused project_writer_busy start=query session=sB", logs.output[0])

    def test_the_owner_is_refused_too_by_another_person_s_writer(self):
        self.assertEqual(_ask(_Webapp(*BUSY_409), user_id=OWNER), REFUSED)

    def test_every_other_answer_is_unverified_the_collaborator_refused(self):
        answers = [
            (200, {"allowed": False}), (200, {"allowed": "true"}), (200, {}), (200, b"not json"), (200, "[]"),
            (409, {"code": "project_writer_busy"}), (409, {"code": "other", "busy": BUSY, "error": BUSY_ERROR}),
            (409, {"code": "project_writer_busy", "busy": BUSY, "error": 7}),
            (409, {"code": "project_writer_busy", "busy": "x" * 2001, "error": BUSY_ERROR}),
            (401, {"error": "Unauthorized"}), (400, {"code": "invalid_writer_check"}), (404, {}),
            (500, {"error": "x", "code": "P1001"}), (502, b"<html>"), (204, b""),
        ]
        for status, body in answers:
            with self.subTest(status=status, body=body), self.assertLogs("writer_check", "WARNING") as logs:
                self.assertEqual(_ask(_Webapp(status, body)), UNVERIFIED)
            self.assertIn("[rbac] agent run refused project_writer_busy start=query session=sB unverified", logs.output[-1])

    def test_every_other_answer_lets_the_owner_s_run_start_with_a_log_line(self):
        for status, body in ((500, {"code": "P1001"}), (404, {}), (200, b"not json")):
            with self.subTest(status=status), self.assertLogs("writer_check", "WARNING") as logs:
                self.assertEqual(_ask(_Webapp(status, body), user_id=OWNER), ALLOWED)
            self.assertIn("[rbac] project_writer_unverified start=query session=sB", logs.output[-1])
            self.assertIn("the owner's run goes ahead", logs.output[-1])

    def test_webapp_unreachable_owner_proceeds_collaborator_refused(self):
        for exc in (httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), OSError("down")):
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(_ask(_Webapp(raises=exc)), UNVERIFIED)
                self.assertEqual(_ask(_Webapp(raises=exc), user_id=OWNER), ALLOWED)

    def test_without_the_internal_key_nothing_is_sent_owner_proceeds_collaborator_refused(self):
        webapp = _Webapp()
        with mock.patch.object(writer_check.httpx, "AsyncClient", webapp.client), \
                mock.patch.dict(writer_check.INTERNAL_HEADERS, {"X-Internal-Key": ""}):
            collab = asyncio.run(second_writer_check(user_id=COLLAB, tenant_id=OWNER, project_id="p",
                                                     session_id="s", start="approval"))
            owner = asyncio.run(second_writer_check(user_id=OWNER, tenant_id=OWNER, project_id="p",
                                                    session_id="s", start="approval"))
        self.assertEqual((collab, owner), (UNVERIFIED, ALLOWED))
        self.assertEqual(webapp.requests, [])

    def test_under_act_as_the_person_decides_the_rule_an_admin_acting_as_the_owner_is_the_owner(self):
        down = _Webapp(raises=httpx.ConnectError("refused"))
        self.assertEqual(_ask(down, user_id=OWNER, actor_id="admin-1"), ALLOWED)
        self.assertEqual(_ask(down, user_id=COLLAB, actor_id="admin-1"), UNVERIFIED)

    def test_an_unknown_start_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            asyncio.run(second_writer_check(user_id="u", tenant_id="u", project_id="p", session_id="s", start="anything"))

    def test_the_route_and_its_payload_are_the_webapp_s(self):
        webapp = _AGENTIC_DIR.parent / "webapp/src"
        route = webapp / "app/api/internal/agent/writer-check/route.ts"
        if not route.exists():
            self.skipTest("webapp source not mounted in this image")
        writers = (webapp / "lib/authz/projectWriters.ts").read_text()
        self.assertIn("secondWriterResponse", route.read_text())
        self.assertIn(f"code: '{writer_check.WRITER_BUSY}'", writers)
        # The unverified sentence is the webapp's own for a source it cannot read.
        self.assertIn("could not be verified (${unverified.join(', ')})", writers)
        self.assertIn("`Nothing was started: ${busy}. Try again shortly.`", writers)

    def test_the_wait_outlasts_the_webapp_s_own_waits(self):
        """The webapp asks the orchestrator and this agent (5 s each) before it answers: a shorter
        wait here would refuse every collaborator's run whenever one of them is slow."""
        webapp = _AGENTIC_DIR.parent / "webapp/src/lib"
        if not webapp.exists():
            self.skipTest("webapp source not mounted in this image")
        waits = []
        for rel, name in (("authz/projectWriters.ts", "ACTIVE_SCANS_TIMEOUT_MS"), ("agentSessions.ts", "LIVE_CHECK_TIMEOUT_MS")):
            m = re.search(rf"{name} = ([0-9_]+)", (webapp / rel).read_text())
            self.assertIsNotNone(m, name)
            waits.append(int(m.group(1).replace("_", "")))
        self.assertGreater(writer_check.WRITER_CHECK_TIMEOUT_S * 1000, max(waits) + 2000)


class _WS:
    def __init__(self):
        self.sent = []
        self.client = "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        pass


class _Orchestrator:
    def __init__(self):
        self.calls = []

    async def _run(self, **kw):
        self.calls.append(kw)
        if kw.get("on_admitted") is not None:
            kw["on_admitted"]()

    invoke_with_streaming = _run
    resume_after_approval_with_streaming = _run
    resume_after_tool_confirmation_with_streaming = _run
    resume_after_answer_with_streaming = _run
    resume_execution_with_streaming = _run

    async def pending_tool_confirmation_mode(self, **_kw):
        return None


async def _settle():
    for _ in range(10):
        await asyncio.sleep(0)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class EveryRunStartAsks(unittest.TestCase):
    """The five handlers that start a run, through a real manager and connection."""

    #: (handler, frame payload, start, the refused answer the drawer restores)
    STARTS = (
        ("handle_query", {"question": "list the hosts"}, "query", None),
        ("handle_approval", {"decision": "approve"}, "approval", "approval"),
        ("handle_answer", {"answer": "443"}, "question", "question"),
        ("handle_tool_confirmation", {"decision": "approve"}, "tool_confirmation", "tool_confirmation"),
        ("handle_resume", {}, "resume", None),
    )

    def setUp(self):
        self.check = mock.AsyncMock(return_value=ALLOWED)
        self.decision = mock.AsyncMock(return_value=DecisionCheck(allowed=True))
        self.saved = mock.AsyncMock(return_value=None)
        self.posted = mock.AsyncMock(return_value=True)
        self.running = mock.AsyncMock()
        for p in (
            mock.patch.object(websocket_api, "second_writer_check", self.check),
            mock.patch.object(websocket_api, "authorize_decision", self.decision),
            mock.patch.object(websocket_api, "save_chat_message", self.saved),
            mock.patch.object(websocket_api, "post_agent_decision", self.posted),
            mock.patch.object(websocket_api, "update_conversation", self.running),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _start(self, method, payload, *, user=COLLAB, tenant=OWNER, act=None, cap=None, orch=None):
        orch = orch or _Orchestrator()

        async def main():
            mgr = WebSocketManager()
            handler = WebSocketHandler(orchestrator=orch, ws_manager=mgr)
            conn = WebSocketConnection(_WS())
            conn.cap = cap
            conn.actor_id = act
            await mgr.authenticate(conn, user, "pB", "sB", verified=True)
            conn.tenant_id = tenant
            conn._is_stopped = True  # handle_resume restarts only a stopped run
            await getattr(handler, method)(conn, dict(payload))
            started = mgr.get_task(f"{user}:pB:sB")
            if conn._active_task is not None:
                await asyncio.wait_for(conn._active_task, BOUND_S)
            await _settle()
            return conn, started

        conn, started = asyncio.run(main())
        return conn, started, orch

    @staticmethod
    def _errors(conn):
        return [m["payload"] for m in conn.websocket.sent if m["type"] == "error"]

    def _nothing_started(self, conn, started, orch):
        self.assertIsNone(started)
        self.assertIsNone(conn._active_task)
        self.assertEqual(orch.calls, [])
        self.saved.assert_not_awaited()
        self.posted.assert_not_awaited()
        self.running.assert_not_awaited()

    def test_each_run_start_asks_for_the_ticket_s_person_tenant_project_session_and_admin(self):
        for method, payload, start, _ in self.STARTS:
            with self.subTest(method=method):
                self.check.reset_mock()
                self._start(method, payload, act="admin-1")
                self.check.assert_awaited_once_with(user_id=COLLAB, tenant_id=OWNER, project_id="pB",
                                                    session_id="sB", actor_id="admin-1", start=start)

    def test_a_connection_without_a_tenant_asks_as_its_own_tenant(self):
        self._start("handle_query", {"question": "q"}, user=OWNER, tenant=None)
        self.assertEqual(self.check.await_args.kwargs["tenant_id"], OWNER)

    def test_second_writer_refused_per_run_nothing_starts_and_the_frame_names_the_holder(self):
        self.check.return_value = REFUSED
        for method, payload, _, answer in self.STARTS:
            with self.subTest(method=method):
                for m in (self.saved, self.posted, self.running):
                    m.reset_mock()
                conn, started, orch = self._start(method, payload)
                self._nothing_started(conn, started, orch)
                self.assertEqual(self._errors(conn), [{
                    "message": BUSY_ERROR, "code": "project_writer_busy", "busy": BUSY,
                    **({"answer": answer} if answer else {}), "recoverable": True,
                }])
                if method == "handle_resume":
                    self.assertTrue(conn._is_stopped, "a refused resume can be asked again")

    def test_allowed_the_run_starts_as_before(self):
        for method, payload, _, _ in self.STARTS:
            with self.subTest(method=method):
                conn, started, orch = self._start(method, payload)
                self.assertIsNotNone(started)
                self.assertEqual(len(orch.calls), 1)
                self.assertEqual(self._errors(conn), [])

    def test_a_refused_decision_comes_first_and_asks_no_writer_check(self):
        conn, started, orch = self._start("handle_approval", {"decision": "approve"}, cap=frozenset())
        self.check.assert_not_awaited()
        self.assertEqual(self._errors(conn)[0]["code"], "permission_required")
        self.decision.return_value = DecisionCheck(False, "decision_check_unavailable")
        self._start("handle_tool_confirmation", {"decision": "approve"})
        self.check.assert_not_awaited()

    def test_a_fireteam_member_confirmation_starts_no_run_and_asks_nothing(self):
        with mock.patch("orchestrator_helpers.fireteam_confirmation_registry.resolve", mock.Mock(return_value=False)):
            self._start("handle_fireteam_member_confirmation", {"wave_id": "w", "member_id": "m", "decision": "approve"})
        self.check.assert_not_awaited()

    def test_collaborator_socket_opened_before_the_owner_s_partial_recon_next_run_refused_owner_unaffected(self):
        """The real client: a socket opened while nobody wrote; the owner then starts a partial recon."""
        webapp = _Webapp()
        client, key = _real_client(webapp)
        with mock.patch.object(websocket_api, "second_writer_check", second_writer_check), client, key:
            _, first, _ = self._start("handle_query", {"question": "q"})
            self.assertIsNotNone(first)
            webapp.by_person = {COLLAB: BUSY_409}
            conn, again, orch = self._start("handle_query", {"question": "q again"})
            _, owner_run, owner_orch = self._start("handle_query", {"question": "q"}, user=OWNER)
            conn2, answer, _ = self._start("handle_approval", {"decision": "approve"})
        self.assertIsNone(again)
        self.assertEqual(orch.calls, [])
        self.assertEqual(self._errors(conn)[0]["busy"], BUSY)
        self.assertIsNotNone(owner_run)
        self.assertEqual(len(owner_orch.calls), 1)
        self.assertIsNone(answer)
        self.assertEqual(self._errors(conn2)[0]["answer"], "approval")
        self.assertEqual([b["userId"] for b in webapp.bodies()], [COLLAB, COLLAB, OWNER, COLLAB])

    def test_webapp_unreachable_end_to_end_owner_runs_collaborator_refused(self):
        webapp = _Webapp(raises=httpx.ConnectError("no route"))
        client, key = _real_client(webapp)
        with mock.patch.object(websocket_api, "second_writer_check", second_writer_check), client, key:
            conn, started, orch = self._start("handle_query", {"question": "q"})
            self._nothing_started(conn, started, orch)
            self.assertEqual(self._errors(conn), [{"message": UNVERIFIED_MESSAGE, "code": "project_writer_busy",
                                                   "busy": UNVERIFIED_BUSY, "recoverable": True}])
            _, owner_run, _ = self._start("handle_resume", {}, user=OWNER)
        self.assertIsNotNone(owner_run)


def _handler_methods():
    tree = ast.parse((_AGENTIC_DIR / "websocket_api.py").read_text())
    handler = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "WebSocketHandler")
    return {n.name: n for n in handler.body if isinstance(n, ast.AsyncFunctionDef)}


def _calls(node):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            yield sub, (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))


def _run_starters(methods):
    """Every handler the socket's router dispatches that starts a run: it registers a run task."""
    entries = {name for _, name in _calls(methods["handle_message"]) if name in methods}
    return {name for name in entries if any(call == "register_task" for _, call in _calls(methods[name]))}


def _checks_before_starting(method):
    """Whether `_refused_second_writer` is awaited, and returned on, before the run task is created."""
    check_line = min((c.lineno for c, name in _calls(method) if name == "_refused_second_writer"), default=None)
    start_line = min((c.lineno for c, name in _calls(method) if name == "create_task"
                      and any(isinstance(a, ast.Call) and getattr(a.func, "attr", "").startswith("_run_orchestrator")
                              for a in c.args)), default=None)
    return check_line is not None and start_line is not None and check_line < start_line


class NoRunStartsUnasked(unittest.TestCase):
    """Static: a handler that starts a run asks the writer check first, found without a list."""

    def test_the_five_run_starters_each_ask_before_creating_the_run(self):
        methods = _handler_methods()
        starters = _run_starters(methods)
        self.assertEqual(starters, {"handle_query", "handle_approval", "handle_answer",
                                    "handle_tool_confirmation", "handle_resume"})
        for name in sorted(starters):
            with self.subTest(handler=name):
                self.assertTrue(_checks_before_starting(methods[name]), name)

    def test_a_new_run_starter_without_the_check_is_found(self):
        methods = _handler_methods()
        extra = ast.parse(
            "class X:\n"
            "    async def handle_message(self, connection, raw):\n"
            "        await self.handle_new_start(connection, {})\n"
            "    async def handle_new_start(self, connection, payload):\n"
            "        task = asyncio.create_task(self._run_orchestrator_query(connection, '', None))\n"
            "        self.ws_manager.register_task(connection.get_key(), task)\n"
        ).body[0].body
        router = extra[0]
        router.body = methods["handle_message"].body + router.body
        found = _run_starters({**methods, "handle_message": router, "handle_new_start": extra[1]})
        self.assertIn("handle_new_start", found)
        self.assertFalse(_checks_before_starting(extra[1]))


if __name__ == "__main__":
    unittest.main()
