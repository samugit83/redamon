"""
Approvals need the approving person's permission, and record who approved (step 3.9b; SH-34,
IM-09, AU-02).

The webapp writes into the `agent` ticket a `cap` claim: which of `agent:approve_phase`,
`agent:approve_dangerous`, `agent:fireteam`, `agent:kali_exec` the person holds on the project
(under act-as, what both the admin and the account acted as hold). The agent keeps it on the
connection and the three handlers that answer the agent's prompts check it before anything
else happens:

- a phase approval needs `agent:approve_phase`;
- a dangerous-tool confirmation needs `agent:approve_dangerous`;
- a Fireteam member confirmation, a per-member dangerous-tool escalation, needs
  `agent:fireteam` and `agent:approve_dangerous`.

A refused frame answers an ERROR with code `permission_required` and the permission; no run
is started and nothing is saved, so the prompt stays answerable by someone who holds it. A
ticket without `cap` (a webapp from before this step: tickets live 60 s during an update) is
today's behaviour. An accepted decision is saved with the person (`sub`, and `act` when an
admin acts as `sub`) and posted to the webapp's /api/internal/agent/decisions, which writes
the audit row naming the real person.

Run: ./agentic/run_tests.sh tests/test_approval_cap.py
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from ws_ticket import AGENT_CAPS, ticket_cap  # noqa: E402

try:
    import websocket_api  # noqa: F401
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

# Outside the guard: a name missing from websocket_api is a failure, never a skip.
if _HAVE:
    from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager  # noqa: E402
    from orchestrator_helpers import chat_persistence  # noqa: E402

SECRET = "d" * 64
BOUND_S = 5
KEY = "uB:pB:sB"
ALL = frozenset(AGENT_CAPS)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ticket(**claims) -> str:
    payload = {"sub": "uB", "pid": "pB", "sid": "sB", "aud": "agent",
               "iat": int(time.time()), "exp": int(time.time()) + 60, **claims}
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    sig = hmac.new(SECRET.encode(), f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


class _WS:
    def __init__(self):
        self.sent = []
        self.client = "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        pass


class _Orchestrator:
    """Admits every resume, as the real one does once the run may stream (on_admitted)."""

    def __init__(self):
        self.calls = []

    async def _resume(self, **kw):
        self.calls.append(kw)
        kw["on_admitted"]()

    resume_after_approval_with_streaming = _resume
    resume_after_tool_confirmation_with_streaming = _resume

    async def pending_tool_confirmation_mode(self, **_kw):
        """A plain confirmation (the escalation: test_fireteam_escalation_confirmation.py)."""
        return None


def _errors(conn):
    return [m["payload"] for m in conn.websocket.sent if m["type"] == "error"]


async def _settle():
    """Let the tasks a handler leaves behind (the ordered save, the decision post) run."""
    for _ in range(10):
        await asyncio.sleep(0)


class TicketCap(unittest.TestCase):
    """What the agent reads from the ticket's `cap` claim."""

    def test_no_cap_claim_is_none_today_s_behaviour(self):
        self.assertIsNone(ticket_cap({"sub": "u", "pid": "p", "sid": "s", "aud": "agent"}))

    def test_the_listed_permissions_are_held(self):
        self.assertEqual(ticket_cap({"cap": ["agent:approve_phase", "agent:fireteam"]}),
                         frozenset({"agent:approve_phase", "agent:fireteam"}))
        self.assertEqual(ticket_cap({"cap": []}), frozenset())
        self.assertEqual(ticket_cap({"cap": list(AGENT_CAPS)}), ALL)

    def test_names_outside_the_four_are_dropped(self):
        self.assertEqual(ticket_cap({"cap": ["agent:approve_phase", "agent:chat", "admin", 7, None, ["x"]]}),
                         frozenset({"agent:approve_phase"}))

    def test_a_cap_that_is_not_a_list_holds_nothing(self):
        for bad in (None, "agent:approve_phase", {"agent:approve_phase": True}, 1, True):
            with self.subTest(cap=bad), self.assertLogs("ws_ticket", "WARNING") as logs:
                self.assertEqual(ticket_cap({"cap": bad}), frozenset())
            self.assertIn("[rbac] ticket cap malformed", logs.output[0])

    def test_the_four_are_the_webapp_s(self):
        # webapp/src/lib/authz/agentCap.ts AGENT_TICKET_CAPS lists the same four, in this order.
        self.assertEqual(AGENT_CAPS, ("agent:approve_phase", "agent:approve_dangerous",
                                      "agent:fireteam", "agent:kali_exec"))


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class InitKeepsTheCap(unittest.TestCase):
    def _init(self, ticket):
        with mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET}):
            conn = WebSocketConnection(_WS())
            handler = WebSocketHandler(orchestrator=None, ws_manager=WebSocketManager())
            asyncio.run(handler.handle_init(conn, {"user_id": "x", "project_id": "x", "session_id": "x",
                                                   "ticket": ticket}))
        self.assertTrue(conn.authenticated)
        return conn

    def test_the_ticket_s_cap_sub_and_act_are_on_the_connection(self):
        conn = self._init(_ticket(cap=["agent:fireteam"], act="admin-1"))
        self.assertEqual((conn.cap, conn.user_id, conn.actor_id), (frozenset({"agent:fireteam"}), "uB", "admin-1"))

    def test_a_ticket_without_cap_leaves_it_unset(self):
        self.assertIsNone(self._init(_ticket()).cap)

    def test_a_malformed_cap_holds_nothing(self):
        self.assertEqual(self._init(_ticket(cap="agent:approve_phase")).cap, frozenset())


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class Decisions(unittest.TestCase):
    """The three handlers that answer the agent's prompts, through a real manager and connection."""

    def setUp(self):
        self.saved = mock.AsyncMock(return_value=None)
        self.posted = mock.AsyncMock(return_value=True)
        self.running = mock.AsyncMock()
        self.resolve = mock.Mock(return_value=True)
        from decision_check import DecisionCheck
        patches = (
            # The decision-time check (step 5.4) is test_decision_check.py's; here it allows.
            mock.patch.object(websocket_api, "authorize_decision", mock.AsyncMock(return_value=DecisionCheck(allowed=True))),
            mock.patch.object(websocket_api, "save_chat_message", self.saved),
            mock.patch.object(websocket_api, "post_agent_decision", self.posted),
            mock.patch.object(websocket_api, "update_conversation", self.running),
            mock.patch("orchestrator_helpers.fireteam_confirmation_registry.resolve", self.resolve),
        )
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _answer(self, method, payload, *, cap, act=None, orch=None):
        """Send one frame on an authenticated connection holding `cap`; wait for the run it starts."""
        orch = orch or _Orchestrator()

        async def main():
            mgr = WebSocketManager()
            handler = WebSocketHandler(orchestrator=orch, ws_manager=mgr)
            conn = WebSocketConnection(_WS())
            conn.cap = cap
            conn.actor_id = act
            await mgr.authenticate(conn, "uB", "pB", "sB", verified=True)
            await getattr(handler, method)(conn, dict(payload))
            started = mgr.get_task(KEY)
            if conn._active_task is not None:
                await asyncio.wait_for(conn._active_task, BOUND_S)
            await _settle()
            return conn, started

        conn, started = asyncio.run(main())
        return conn, started, orch

    def _rows(self):
        return [(c.kwargs["msg_type"], c.kwargs["data"]) for c in self.saved.await_args_list]

    def _assert_refused(self, conn, started, orch, permission):
        [err] = _errors(conn)
        self.assertEqual((err["code"], err["permission"], err["recoverable"]),
                         ("permission_required", permission, True))
        self.assertIn(permission, err["message"])
        self.assertIsNone(started, "a refused decision starts no run")
        self.assertEqual(orch.calls, [], "the paused run is not resumed")
        self.assertEqual(self._rows(), [], "nothing is saved, so the prompt is shown again on reload")
        self.running.assert_not_awaited()
        self.posted.assert_not_awaited()

    # --- phase approval -----------------------------------------------------------------

    def test_approval_refused_without_the_permission_run_still_waiting(self):
        others = ALL - {"agent:approve_phase"}
        with self.assertLogs("websocket_api", "WARNING") as logs:
            conn, started, orch = self._answer("handle_approval", {"decision": "approve"}, cap=others)
        self._assert_refused(conn, started, orch, "agent:approve_phase")
        self.assertTrue(any("[rbac] decision refused permission=agent:approve_phase" in line for line in logs.output))
        # The run still waits for an answer: a person who holds the permission gives it.
        conn, started, orch = self._answer("handle_approval", {"decision": "approve"},
                                           cap=frozenset({"agent:approve_phase"}))
        self.assertEqual(_errors(conn), [])
        self.assertEqual(len(orch.calls), 1)

    def test_approval_allowed_with_it(self):
        conn, started, orch = self._answer("handle_approval", {"decision": "modify", "modification": "only port 80"},
                                           cap=frozenset({"agent:approve_phase"}))
        self.assertEqual(_errors(conn), [])
        self.assertIsNotNone(started)
        [call] = orch.calls
        self.assertEqual((call["decision"], call["modification"]), ("modify", "only port 80"))
        self.assertEqual(self._rows(), [("approval_response", {
            "decision": "modify", "modification": "only port 80", "actor": {"sub": "uB"}})])
        self.posted.assert_awaited_once_with(kind="approval", session_id="sB", project_id="pB",
                                             user_id="uB", actor_id=None, decision="modify")

    def test_refused_with_nothing_held(self):
        conn, started, orch = self._answer("handle_approval", {"decision": "abort"}, cap=frozenset())
        self._assert_refused(conn, started, orch, "agent:approve_phase")

    # --- dangerous-tool confirmation ----------------------------------------------------

    def test_tool_confirmation_refused_without_the_permission(self):
        conn, started, orch = self._answer("handle_tool_confirmation", {"decision": "approve"},
                                           cap=ALL - {"agent:approve_dangerous"})
        self._assert_refused(conn, started, orch, "agent:approve_dangerous")

    def test_tool_confirmation_allowed_with_it(self):
        conn, started, orch = self._answer("handle_tool_confirmation", {"decision": "reject"},
                                           cap=frozenset({"agent:approve_dangerous"}))
        self.assertEqual(_errors(conn), [])
        self.assertEqual(len(orch.calls), 1)
        self.assertEqual(self._rows(), [("tool_confirmation_response", {
            "decision": "reject", "modifications": None, "actor": {"sub": "uB"}})])
        self.posted.assert_awaited_once_with(kind="tool_confirmation", session_id="sB", project_id="pB",
                                             user_id="uB", actor_id=None, decision="reject")

    # --- Fireteam member confirmation ---------------------------------------------------

    FT = {"wave_id": "w1", "member_id": "m1", "decision": "approve"}

    def test_fireteam_confirmation_refused_with_fireteam_but_without_approve_dangerous(self):
        conn, started, orch = self._answer("handle_fireteam_member_confirmation", self.FT,
                                           cap=frozenset({"agent:fireteam", "agent:approve_phase", "agent:kali_exec"}))
        self._assert_refused(conn, started, orch, "agent:approve_dangerous")
        self.resolve.assert_not_called()

    def test_fireteam_confirmation_refused_without_fireteam(self):
        conn, started, orch = self._answer("handle_fireteam_member_confirmation", self.FT,
                                           cap=frozenset({"agent:approve_dangerous"}))
        self._assert_refused(conn, started, orch, "agent:fireteam")
        self.resolve.assert_not_called()

    def test_fireteam_confirmation_allowed_with_both(self):
        conn, _, _ = self._answer("handle_fireteam_member_confirmation", self.FT,
                                  cap=frozenset({"agent:fireteam", "agent:approve_dangerous"}), act="admin-1")
        self.assertEqual(_errors(conn), [])
        self.resolve.assert_called_once_with(session_id="sB", wave_id="w1", member_id="m1",
                                             decision="approve", modifications=None)
        self.assertEqual(self.saved.await_args_list[0].kwargs["data"], {
            "wave_id": "w1", "member_id": "m1", "decision": "approve", "resolved": True,
            "actor": {"sub": "uB", "act": "admin-1"}})
        self.posted.assert_awaited_once_with(kind="fireteam_member_confirmation", session_id="sB", project_id="pB",
                                             user_id="uB", actor_id="admin-1", decision="approve",
                                             wave_id="w1", member_id="m1")

    def test_a_refusal_names_the_answer_it_refused(self):
        """The drawer puts back the card it hid for exactly that answer (review finding 3)."""
        for method, payload, cap, expected in (
                ("handle_approval", {"decision": "approve"}, frozenset(), {"answer": "approval"}),
                ("handle_tool_confirmation", {"decision": "reject"}, frozenset(), {"answer": "tool_confirmation"}),
                ("handle_fireteam_member_confirmation", self.FT, frozenset({"agent:fireteam"}),
                 {"answer": "fireteam_member_confirmation", "wave_id": "w1", "member_id": "m1"})):
            with self.subTest(method=method):
                conn, _, _ = self._answer(method, payload, cap=cap)
                [err] = _errors(conn)
                self.assertEqual({k: err.get(k) for k in expected}, expected)
                if method != "handle_fireteam_member_confirmation":
                    self.assertNotIn("wave_id", err)

    def test_the_fireteam_audit_posts_the_decision_the_registry_applied(self):
        """The registry applies any word but `approve` as a reject (review finding 4)."""
        for word, applied in (("approve", "approve"), ("reject", "reject"), ("abort", "reject"),
                              ("Approve", "reject"), ("yes please", "reject")):
            with self.subTest(word=word):
                self.posted.reset_mock()
                self._answer("handle_fireteam_member_confirmation", {**self.FT, "decision": word}, cap=ALL)
                self.assertEqual(self.posted.await_args.kwargs["decision"], applied)

    def test_a_fireteam_answer_that_resolved_nothing_is_saved_but_not_audited(self):
        self.resolve.return_value = False
        self._answer("handle_fireteam_member_confirmation", self.FT, cap=ALL)
        self.posted.assert_not_awaited()

    # --- a ticket from before this step ---------------------------------------------------

    def test_no_cap_claim_is_today_s_behaviour(self):
        for method, payload in (("handle_approval", {"decision": "approve"}),
                                ("handle_tool_confirmation", {"decision": "approve"}),
                                ("handle_fireteam_member_confirmation", self.FT)):
            with self.subTest(method=method):
                self.saved.reset_mock()
                conn, _, _ = self._answer(method, payload, cap=None)
                self.assertEqual(_errors(conn), [])
                self.assertEqual(len(self.saved.await_args_list), 1)
        self.assertEqual(self.resolve.call_count, 1)

    # --- who decided ----------------------------------------------------------------------

    def test_the_persisted_decision_names_the_actor_and_act(self):
        self._answer("handle_approval", {"decision": "approve"}, cap=ALL, act="admin-1")
        [(row, data)] = self._rows()
        self.assertEqual((row, data["actor"]), ("approval_response", {"sub": "uB", "act": "admin-1"}))
        self.posted.assert_awaited_once_with(kind="approval", session_id="sB", project_id="pB",
                                             user_id="uB", actor_id="admin-1", decision="approve")

    def test_the_actor_is_the_one_who_answered_not_a_later_socket(self):
        """The run's callback follows a reconnect; the decision stays with the frame's sender."""
        orch = _Orchestrator()

        async def main():
            mgr = WebSocketManager()
            handler = WebSocketHandler(orchestrator=orch, ws_manager=mgr)
            first = WebSocketConnection(_WS())
            first.cap, first.actor_id = ALL, "admin-1"
            await mgr.authenticate(first, "uB", "pB", "sB", verified=True)
            later = WebSocketConnection(_WS())
            gate = asyncio.Event()

            async def resume(**kw):
                await mgr.authenticate(later, "uB", "pB", "sB", verified=True)  # the tab reconnects
                await gate.wait()
                kw["on_admitted"]()

            orch.resume_after_approval_with_streaming = resume
            await handler.handle_approval(first, {"decision": "approve"})
            await asyncio.sleep(0)
            gate.set()
            await asyncio.wait_for(first._active_task, BOUND_S)
            await _settle()

        asyncio.run(main())
        self.posted.assert_awaited_once()
        self.assertEqual(self.posted.await_args.kwargs["actor_id"], "admin-1")


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class FireteamAppliedDecision(unittest.TestCase):
    """What the handler posts is what the real registry gives the waiting member."""

    def test_applied_decision_is_what_resolve_applies(self):
        from orchestrator_helpers import fireteam_confirmation_registry as reg
        for word in ("approve", "reject", "abort", "Approve", "", "yes please"):
            with self.subTest(word=word):
                entry = reg.register("s-applied", "w1", "m1")
                try:
                    self.assertTrue(reg.resolve("s-applied", "w1", "m1", word))
                    self.assertEqual(entry.decision, reg.applied_decision(word))
                finally:
                    reg.drop("s-applied", "w1", "m1")
        self.assertEqual({reg.applied_decision(w) for w in ("approve", "x")}, {"approve", "reject"})


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class PostAgentDecision(unittest.TestCase):
    """The agent's half of the audit: one POST per accepted decision, never raising."""

    def _client(self, status=200, error=None):
        seen = []

        class _Resp:
            status_code = status
            text = "refused"

        class _Client:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, json=None, headers=None):
                seen.append((url, json, dict(headers or {})))  # a copy: patch.dict restores the original
                if error:
                    raise error
                return _Resp()

        return _Client, seen

    def _post(self, client, key="internal-key-for-test", **over):
        args = {"kind": "approval", "session_id": "sB", "project_id": "pB", "user_id": "uB",
                "actor_id": "admin-1", "decision": "approve", **over}
        with mock.patch.object(chat_persistence.httpx, "AsyncClient", client), \
                mock.patch.dict(chat_persistence.INTERNAL_HEADERS, {"X-Internal-Key": key}):
            return asyncio.run(chat_persistence.post_agent_decision(**args))

    def test_posts_the_decision_with_the_internal_key(self):
        client, seen = self._client()
        self.assertTrue(self._post(client))
        [(url, body, headers)] = seen
        self.assertEqual(url, f"{chat_persistence.WEBAPP_API_URL}/api/internal/agent/decisions")
        self.assertEqual(body, {"kind": "approval", "sessionId": "sB", "projectId": "pB", "userId": "uB",
                                "actorId": "admin-1", "decision": "approve"})
        self.assertEqual(headers, {"X-Internal-Key": "internal-key-for-test"})

    def test_a_fireteam_decision_carries_its_wave_and_member_and_no_act_is_left_out(self):
        client, seen = self._client()
        self._post(client, kind="fireteam_member_confirmation", actor_id=None, wave_id="w1", member_id="m1")
        self.assertEqual(seen[0][1], {"kind": "fireteam_member_confirmation", "sessionId": "sB", "projectId": "pB",
                                      "userId": "uB", "decision": "approve", "waveId": "w1", "memberId": "m1"})

    def test_a_refusal_is_logged_with_its_status_and_returns_false(self):
        client, _ = self._client(status=401)
        with self.assertLogs("orchestrator_helpers.chat_persistence", "WARNING") as logs:
            self.assertFalse(self._post(client))
        self.assertIn("[rbac] decision audit failed status=401", logs.output[0])

    def test_an_unreachable_webapp_is_logged_with_the_class_never_raised(self):
        client, _ = self._client(error=ConnectionRefusedError("webapp:3000 secret detail"))
        with self.assertLogs("orchestrator_helpers.chat_persistence", "WARNING") as logs:
            self.assertFalse(self._post(client))
        self.assertIn("error=ConnectionRefusedError", logs.output[0])
        self.assertNotIn("secret detail", logs.output[0])

    def test_no_internal_key_sends_nothing(self):
        client, seen = self._client()
        with self.assertLogs("orchestrator_helpers.chat_persistence", "WARNING") as logs:
            self.assertFalse(self._post(client, key=""))
        self.assertEqual(seen, [])
        self.assertIn("[rbac] decision audit not sent", logs.output[0])


if __name__ == "__main__":
    unittest.main()
