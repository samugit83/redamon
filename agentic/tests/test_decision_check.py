"""
Approvals are re-checked when made (step 5.4; SH-34, SH-41 mid-session part, IM-09).

The ticket's `cap` is a snapshot from when the socket opened. Before the agent accepts a phase
approval, a dangerous-tool confirmation, a Fireteam member confirmation or an answer to its
question, and before CodeFix pushes with the owner's token, it asks the webapp
(`POST /api/internal/agent/authorize-decision`, agentic/decision_check.py) whether
the ticket's person (`sub`, and the admin `act` under act-as) may still take that decision on
the project. Only a 200 `{"allowed": true}` admits it; a 403 is a refusal naming the permission
(the webapp audits it); anything else, an unreachable webapp included, is refused with
`decision_check_unavailable`. A refused answer starts nothing, saves nothing and posts no
decision, so the request stays open. Only a person answers: no path outside the socket's
handlers resolves a decision (the Agent in the Loop driver has none).

Run: ./agentic/run_tests.sh tests/test_decision_check.py
"""
import ast
import asyncio
import json
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

import decision_check  # noqa: E402
from decision_check import DecisionCheck, authorize_decision  # noqa: E402

try:
    import websocket_api  # noqa: F401
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

if _HAVE:
    from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager  # noqa: E402
    from ws_ticket import AGENT_CAPS  # noqa: E402

KEY = "uB:pB:sB"
BOUND_S = 5
ALL = frozenset(("agent:approve_phase", "agent:approve_dangerous", "agent:fireteam", "agent:kali_exec"))
ALLOWED = DecisionCheck(allowed=True)


class _Webapp:
    """The webapp behind httpx.MockTransport: records each request and answers `answer`."""

    def __init__(self, status=200, body=None, raises=None):
        self.status, self.body, self.raises = status, body if body is not None else {"allowed": True}, raises
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raises is not None:
            raise self.raises
        if isinstance(self.body, (bytes, str)):
            return httpx.Response(self.status, content=self.body)
        return httpx.Response(self.status, json=self.body)

    def client(self, *args, **kwargs):
        return _RealAsyncClient(transport=httpx.MockTransport(self.handler))

    def bodies(self):
        return [json.loads(r.content) for r in self.requests]


def _ask(webapp, **kw):
    args = {"kind": "approval", "user_id": "uB", "project_id": "pB", "session_id": "sB",
            "permissions": ("agent:approve_phase",), **kw}
    with mock.patch.object(decision_check.httpx, "AsyncClient", webapp.client), \
            mock.patch.dict(decision_check.INTERNAL_HEADERS, {"X-Internal-Key": "k" * 16}):
        return asyncio.run(authorize_decision(**args))


class AuthorizeDecision(unittest.TestCase):
    """The agent's client: what it sends, and how it reads every answer (fail closed)."""

    def test_allowed_only_on_200_allowed_true_and_the_request_names_the_ticket_s_people(self):
        webapp = _Webapp()
        self.assertEqual(_ask(webapp, actor_id="admin-1"), ALLOWED)
        (req,) = webapp.requests
        self.assertEqual((req.method, req.url.path), ("POST", "/api/internal/agent/authorize-decision"))
        self.assertEqual(req.headers["x-internal-key"], "k" * 16)
        self.assertEqual(webapp.bodies(), [{"kind": "approval", "userId": "uB", "projectId": "pB",
                                            "sessionId": "sB", "actorId": "admin-1"}])

    def test_no_act_sends_no_actor_and_no_permission_or_level_is_sent(self):
        webapp = _Webapp()
        _ask(webapp, kind="codefix_push", permissions=("codefix:run",))
        self.assertEqual(webapp.bodies(), [{"kind": "codefix_push", "userId": "uB", "projectId": "pB", "sessionId": "sB"}])

    def test_a_403_is_a_refusal_naming_the_permission_and_why(self):
        webapp = _Webapp(403, {"code": "forbidden", "permission": "agent:approve_phase", "reason": "project_level"})
        with self.assertLogs("decision_check", "WARNING") as logs:
            got = _ask(webapp)
        self.assertEqual(got, DecisionCheck(False, "permission_required", "agent:approve_phase", "project_level"))
        self.assertIn("[rbac] decision refused at decision time", logs.output[0])

    def test_a_403_with_unreadable_fields_still_refuses_naming_the_asked_permission(self):
        webapp = _Webapp(403, {"permission": "<b>x</b>", "reason": "Some Text; drop"})
        got = _ask(webapp, permissions=("agent:approve_dangerous",))
        self.assertEqual(got, DecisionCheck(False, "permission_required", "agent:approve_dangerous", None))

    def test_webapp_unreachable_is_refused_decision_check_unavailable(self):
        for exc in (httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), OSError("down")):
            with self.subTest(exc=type(exc).__name__), \
                    self.assertLogs("decision_check", "WARNING") as logs:
                got = _ask(_Webapp(raises=exc))
            self.assertEqual(got, DecisionCheck(False, "decision_check_unavailable"))
            self.assertIn(f"[rbac] decision check unavailable error={type(exc).__name__}", logs.output[0])
            self.assertNotIn("refused", logs.output[0].split("error=")[1].split()[0].lower())

    def test_every_other_answer_is_unavailable_never_allowed(self):
        answers = [
            (200, {"allowed": False}), (200, {"allowed": "true"}), (200, {}), (200, b"not json"), (200, "[]"),
            (401, {"error": "Unauthorized"}), (400, {"code": "invalid_decision_check"}), (404, {}),
            (500, {"error": "x", "code": "P1001"}), (502, b"<html>"), (204, b""),
        ]
        for status, body in answers:
            with self.subTest(status=status, body=body):
                self.assertEqual(_ask(_Webapp(status, body)), DecisionCheck(False, "decision_check_unavailable"))

    def test_without_the_internal_key_nothing_is_sent_and_it_is_refused(self):
        webapp = _Webapp()
        with mock.patch.object(decision_check.httpx, "AsyncClient", webapp.client), \
                mock.patch.dict(decision_check.INTERNAL_HEADERS, {"X-Internal-Key": ""}), \
                self.assertLogs("decision_check", "WARNING") as logs:
            got = asyncio.run(authorize_decision(kind="approval", user_id="u", project_id="p", session_id="s"))
        self.assertEqual(got, DecisionCheck(False, "decision_check_unavailable"))
        self.assertEqual(webapp.requests, [])
        self.assertIn("reason=no_internal_key", logs.output[0])

    def test_an_unknown_kind_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            asyncio.run(authorize_decision(kind="anything", user_id="u", project_id="p", session_id="s"))

    def test_the_kinds_are_the_webapp_s(self):
        route = (_AGENTIC_DIR.parent / "webapp/src/app/api/internal/agent/authorize-decision/route.ts")
        if not route.exists():
            self.skipTest("webapp source not mounted in this image")
        source = route.read_text()
        kinds = source.split("const KINDS")[1].split("})")[0]
        for kind in decision_check.DECISION_KINDS:
            self.assertIn(f"\n  {kind}: {{", kinds, kind)


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

    async def _resume(self, **kw):
        self.calls.append(kw)
        kw["on_admitted"]()

    resume_after_approval_with_streaming = _resume
    resume_after_tool_confirmation_with_streaming = _resume
    resume_after_answer_with_streaming = _resume


async def _settle():
    for _ in range(10):
        await asyncio.sleep(0)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class AtDecisionTime(unittest.TestCase):
    """The four answer handlers, through a real manager and connection, with the check stubbed."""

    FT = {"wave_id": "w1", "member_id": "m1", "decision": "approve"}
    HANDLERS = (
        ("handle_approval", {"decision": "approve"}, "approval", ("agent:approve_phase",), {}),
        ("handle_tool_confirmation", {"decision": "approve"}, "tool_confirmation", ("agent:approve_dangerous",), {}),
        ("handle_fireteam_member_confirmation", FT, "fireteam_member_confirmation",
         ("agent:fireteam", "agent:approve_dangerous"), {"wave_id": "w1", "member_id": "m1"}),
        ("handle_answer", {"answer": "443"}, "question", ("agent:chat",), {}),
    )

    def setUp(self):
        self.check = mock.AsyncMock(return_value=ALLOWED)
        self.saved = mock.AsyncMock(return_value=None)
        self.posted = mock.AsyncMock(return_value=True)
        self.running = mock.AsyncMock()
        self.resolve = mock.Mock(return_value=True)
        for p in (
            mock.patch.object(websocket_api, "authorize_decision", self.check),
            mock.patch.object(websocket_api, "save_chat_message", self.saved),
            mock.patch.object(websocket_api, "post_agent_decision", self.posted),
            mock.patch.object(websocket_api, "update_conversation", self.running),
            mock.patch("orchestrator_helpers.fireteam_confirmation_registry.resolve", self.resolve),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _answer(self, method, payload, *, cap=None, act=None):
        orch = _Orchestrator()

        async def main():
            mgr = WebSocketManager()
            handler = WebSocketHandler(orchestrator=orch, ws_manager=mgr)
            conn = WebSocketConnection(_WS())
            conn.cap = cap
            conn.actor_id = act
            await mgr.authenticate(conn, "uB", "pB", "sB", verified=True)
            conn.tenant_id = "owner-A"
            await getattr(handler, method)(conn, dict(payload))
            started = mgr.get_task(KEY)
            if conn._active_task is not None:
                await asyncio.wait_for(conn._active_task, BOUND_S)
            await _settle()
            return conn, started

        conn, started = asyncio.run(main())
        return conn, started, orch

    def _errors(self, conn):
        return [m["payload"] for m in conn.websocket.sent if m["type"] == "error"]

    def _nothing_happened(self, conn, started, orch):
        self.assertIsNone(started)
        self.assertIsNone(conn._active_task)
        self.assertEqual(orch.calls, [])
        self.resolve.assert_not_called()
        self.saved.assert_not_awaited()
        self.posted.assert_not_awaited()
        self.running.assert_not_awaited()

    def test_each_answer_asks_the_check_for_the_ticket_s_person_with_its_kind(self):
        for method, payload, kind, perms, _ in self.HANDLERS:
            with self.subTest(method=method):
                self.check.reset_mock()
                self._answer(method, payload, act="admin-1")
                self.check.assert_awaited_once_with(kind=kind, user_id="uB", project_id="pB", session_id="sB",
                                                    actor_id="admin-1", permissions=perms)

    def test_audit_names_the_collaborator_the_check_carries_sub_never_the_tenant(self):
        self._answer("handle_approval", {"decision": "approve"})
        kw = self.check.await_args.kwargs
        self.assertEqual((kw["user_id"], kw["actor_id"]), ("uB", None))
        self.assertNotIn("owner-A", json.dumps(kw, default=str))

    def test_approval_refused_at_decision_time_starts_nothing_and_names_the_card(self):
        for method, payload, kind, perms, request in self.HANDLERS:
            with self.subTest(method=method):
                for m in (self.saved, self.posted, self.running, self.resolve):
                    m.reset_mock()
                self.check.return_value = DecisionCheck(False, "permission_required", perms[-1], "project_level")
                with self.assertLogs("websocket_api", "WARNING") as logs:
                    conn, started, orch = self._answer(method, payload)
                self._nothing_happened(conn, started, orch)
                self.assertEqual(self._errors(conn), [{
                    "message": f"You no longer hold the permission this answer needs ({perms[-1]}) on this project. "
                               "The agent keeps waiting for someone who does.",
                    "code": "permission_required", "permission": perms[-1], "reason": "project_level",
                    "answer": kind, **request, "recoverable": True,
                }])
                self.assertIn("[rbac] decision refused at decision time", "\n".join(logs.output))

    def test_webapp_unreachable_refused_with_decision_check_unavailable(self):
        self.check.return_value = DecisionCheck(False, "decision_check_unavailable")
        for method, payload, kind, _, request in self.HANDLERS:
            with self.subTest(method=method):
                for m in (self.saved, self.posted, self.running, self.resolve):
                    m.reset_mock()
                conn, started, orch = self._answer(method, payload)
                self._nothing_happened(conn, started, orch)
                (err,) = self._errors(conn)
                self.assertEqual({k: err[k] for k in ("code", "answer", "recoverable")},
                                 {"code": "decision_check_unavailable", "answer": kind, "recoverable": True})
                self.assertTrue(all(err[k] == v for k, v in request.items()))

    def test_allowed_with_it_the_answer_runs_as_before(self):
        conn, started, orch = self._answer("handle_approval", {"decision": "approve"})
        self.assertIsNotNone(started)
        self.assertEqual(len(orch.calls), 1)
        self.assertEqual(self._errors(conn), [])
        self.posted.assert_awaited_once()
        conn, _, _ = self._answer("handle_fireteam_member_confirmation", self.FT)
        self.resolve.assert_called_once()

    def test_a_cap_refusal_comes_first_and_asks_nothing(self):
        conn, started, orch = self._answer("handle_approval", {"decision": "approve"}, cap=frozenset())
        self.check.assert_not_awaited()
        self.assertEqual(self._errors(conn)[0]["code"], "permission_required")
        self._nothing_happened(conn, started, orch)

    def test_refused_after_a_revoke_on_an_open_socket(self):
        """The same socket, cap unchanged: allowed, then the share goes, then refused (real client)."""
        webapp = _Webapp()
        self.check.side_effect = None
        with mock.patch.object(websocket_api, "authorize_decision", authorize_decision), \
                mock.patch.object(decision_check.httpx, "AsyncClient", webapp.client), \
                mock.patch.dict(decision_check.INTERNAL_HEADERS, {"X-Internal-Key": "k" * 16}):
            _, first, orch = self._answer("handle_tool_confirmation", {"decision": "approve"}, cap=ALL)
            self.assertIsNotNone(first)
            webapp.status, webapp.body = 403, {"permission": "agent:approve_dangerous", "reason": "project_not_visible"}
            conn, again, orch2 = self._answer("handle_tool_confirmation", {"decision": "approve"}, cap=ALL)
        self.assertIsNone(again)
        self.assertEqual(orch2.calls, [])
        self.assertEqual(self._errors(conn)[0]["reason"], "project_not_visible")
        self.assertEqual(len(webapp.requests), 2)

    def test_webapp_unreachable_end_to_end_through_the_real_client(self):
        webapp = _Webapp(raises=httpx.ConnectError("no route"))
        with mock.patch.object(websocket_api, "authorize_decision", authorize_decision), \
                mock.patch.object(decision_check.httpx, "AsyncClient", webapp.client), \
                mock.patch.dict(decision_check.INTERNAL_HEADERS, {"X-Internal-Key": "k" * 16}):
            conn, started, orch = self._answer("handle_approval", {"decision": "approve"}, cap=ALL)
        self._nothing_happened(conn, started, orch)
        self.assertEqual(self._errors(conn)[0]["code"], "decision_check_unavailable")

    def test_admin_under_act_as_the_check_carries_the_admin(self):
        self._answer("handle_tool_confirmation", {"decision": "approve"}, act="admin-1")
        self.assertEqual(self.check.await_args.kwargs["actor_id"], "admin-1")
        # ...and the admitted decision's audit post still names the admin (3.9b).
        self.assertEqual(self.posted.await_args.kwargs["actor_id"], "admin-1")


def _module(rel):
    return ast.parse((_AGENTIC_DIR / rel).read_text())


class OnlyAPersonDecides(unittest.TestCase):
    """No decision is resolved outside the socket's answer handlers, and each asks the check."""

    RESOLVERS = {"resume_after_approval_with_streaming", "resume_after_tool_confirmation_with_streaming",
                 "resume_after_answer_with_streaming"}

    def _calls(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                yield node, (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))

    def test_resumes_and_the_fireteam_resolve_are_called_only_from_websocket_api(self):
        callers = set()
        for path in _AGENTIC_DIR.rglob("*.py"):
            rel = path.relative_to(_AGENTIC_DIR).as_posix()
            if rel.startswith("tests/") or "/tests/" in rel or rel.startswith(("labs/", "agent-workspace/")):
                continue
            try:
                tree = ast.parse(path.read_text())
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node, name in self._calls(tree):
                if name in self.RESOLVERS:
                    callers.add((rel, name))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and node.module.endswith("fireteam_confirmation_registry"):
                    if any(a.name == "resolve" for a in node.names):
                        callers.add((rel, "fireteam resolve"))
        self.assertEqual(callers, {
            ("websocket_api.py", "resume_after_approval_with_streaming"),
            ("websocket_api.py", "resume_after_tool_confirmation_with_streaming"),
            ("websocket_api.py", "resume_after_answer_with_streaming"),
            ("websocket_api.py", "fireteam resolve"),
        })

    def test_each_answer_handler_asks_the_check_before_it_starts_or_saves_anything(self):
        tree = _module("websocket_api.py")
        handler = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "WebSocketHandler")
        methods = {n.name: n for n in handler.body if isinstance(n, ast.AsyncFunctionDef)}
        effects = {"create_task", "_resolve", "_persist", "register_task", "update_conversation"}
        for name in ("handle_approval", "handle_tool_confirmation", "handle_fireteam_member_confirmation", "handle_answer"):
            with self.subTest(handler=name):
                lines = {}
                for node, call in self._calls(methods[name]):
                    lines.setdefault(call, []).append(node.lineno)
                self.assertIn("_refused_now", lines, name)
                check = min(lines["_refused_now"])
                first_effect = min(l for c in effects for l in lines.get(c, []))
                self.assertLess(check, first_effect)
                if "_refused_without" in lines:
                    self.assertLess(min(lines["_refused_without"]), check)


class _CodeFixCallback:
    def __init__(self):
        self.errors, self.completed, self.prs = [], [], []

    async def on_error(self, message, recoverable=True, code="", **details):
        self.errors.append({"message": message, "code": code, "recoverable": recoverable, **details})

    async def on_complete(self, *a, **k):
        self.completed.append(a)

    async def on_pr_created(self, data):
        self.prs.append(data)


class CodeFixPush(unittest.TestCase):
    """A CodeFix push with the owner's token needs Manage on top of codefix:run, asked when it happens."""

    def _finalize(self, check):
        from cypherfix_codefix import orchestrator as module
        from cypherfix_codefix.state import DiffBlock

        orch = module.CodeFixOrchestrator(module.CodeFixState(), _CodeFixCallback())
        orch.state.user_id, orch.state.project_id, orch.state.session_id = "owner-A", "pB", "cf-1"
        orch.state.actor_user_id, orch.state.real_actor_user_id = "uB", "admin-1"
        orch.state.branch_name = "cypherfix/fix-1"
        orch.state.files_modified = {"app.py"}
        orch.state.diff_blocks = [DiffBlock(block_id="b1", file_path="app.py", language="python",
                                            old_code="a", new_code="b", context_before="", context_after="",
                                            start_line=1, end_line=1, description="d", status="accepted")]
        orch.repo_manager = mock.Mock()
        orch.repo_manager.create_pr.return_value = {"pr_url": "https://example.invalid/pr/1", "pr_number": 1}
        updates = []

        async def update(rid, data):
            updates.append(data)

        orch._update_remediation = update
        with mock.patch.object(module, "authorize_decision", check):
            asyncio.run(orch._finalize("rem-1"))
        return orch, updates

    def test_the_push_asks_for_the_person_who_runs_codefix_not_the_tenant(self):
        check = mock.AsyncMock(return_value=ALLOWED)
        orch, updates = self._finalize(check)
        check.assert_awaited_once_with(kind="codefix_push", user_id="uB", project_id="pB", session_id="cf-1",
                                       actor_id="admin-1", permissions=("codefix:run",))
        orch.repo_manager.push.assert_called_once_with("cypherfix/fix-1")
        orch.repo_manager.create_pr.assert_called_once()
        self.assertEqual(updates[-1]["status"], "pr_created")

    def test_refused_no_commit_no_push_no_pr_and_the_diff_stays_for_the_owner(self):
        for got, code in ((DecisionCheck(False, "permission_required", "codefix:run", "project_level"), "permission_required"),
                          (DecisionCheck(False, "decision_check_unavailable"), "decision_check_unavailable")):
            with self.subTest(code=code):
                orch, updates = self._finalize(mock.AsyncMock(return_value=got))
                orch.repo_manager.commit.assert_not_called()
                orch.repo_manager.push.assert_not_called()
                orch.repo_manager.create_pr.assert_not_called()
                (update,) = updates
                self.assertEqual(update["status"], "pending")
                self.assertEqual([b["block_id"] for b in update["fileChanges"]], ["b1"])
                (err,) = orch.callback.errors
                self.assertEqual((err["code"], err["recoverable"]), (code, False))
                self.assertEqual(orch.state.status, "error")
                self.assertEqual(orch.callback.prs, [])

    def test_a_session_without_an_actor_is_the_tenant_s_own(self):
        """A pre-5.4 state (no actor recorded) asks for the tenant, never skips the check."""
        from cypherfix_codefix import orchestrator as module
        check = mock.AsyncMock(return_value=ALLOWED)
        orch = module.CodeFixOrchestrator(module.CodeFixState(), _CodeFixCallback())
        orch.state.user_id, orch.state.project_id, orch.state.session_id = "owner-A", "pB", "cf-1"
        orch.state.files_modified = {"x"}
        orch.repo_manager = mock.Mock()
        orch.repo_manager.create_pr.return_value = {"pr_url": "u"}

        async def update(*_a):
            return None

        orch._update_remediation = update
        with mock.patch.object(module, "authorize_decision", check):
            asyncio.run(orch._finalize("rem-1"))
        self.assertEqual(check.await_args.kwargs["user_id"], "owner-A")
        self.assertIsNone(check.await_args.kwargs["actor_id"])


if __name__ == "__main__":
    unittest.main()
