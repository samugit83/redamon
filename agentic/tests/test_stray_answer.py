"""
An answer to a request the run is no longer waiting for decides nothing (step 3.9b review,
finding 1).

The scenario. Two tabs show the same phase-approval card. Tab 2 sends a message, which drops
the request (initialize clears it); tab 1 then clicks Approve. The stray answer used to be
stored in the run's state, saved and audited although it decided nothing. When the agent later
asked for the next exploitation phase, the stored answer hid the new request (the stream skips
a request that already has an answer) and the person's next ordinary message approved it
(initialize resumes on "answer + request"), with no permission check and no audit row, even
after the person lost the permission.

Both ends are closed, and a new message never carries an answer:
- a resume whose request is not pending is refused (`no_pending_request`, recoverable) before
  anything runs: no state write, no saved row, no audit post, and a live run of the same
  session keeps its callback;
- think, and Fireteam collect, raising a new request clear any answer stored before it, so the
  new request is shown and only an answer given to it decides it;
- the graph input of a new message sets every answer to None.

Run: ./agentic/run_tests.sh tests/test_stray_answer.py
"""
import asyncio
import importlib
import json
import os
import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("WEBAPP_API_URL", "http://fake-webapp")

import agent_context as ac  # noqa: E402
import project_settings as ps  # noqa: E402
import websocket_api  # noqa: E402
from orchestrator import AgentOrchestrator  # noqa: E402
from orchestrator_helpers.streaming import emit_streaming_events  # noqa: E402
from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager  # noqa: E402
from ws_ticket import AGENT_CAPS  # noqa: E402

BOUND_S = 10
SESSION = "sB"
TRANSITION = {"from_phase": "informational", "to_phase": "exploitation", "reason": "r",
              "planned_actions": [], "risks": []}
CONFIRMATION = {"confirmation_id": "c1", "mode": "single", "phase": "informational", "iteration": 3,
                "reasoning": "r", "tools": [{"tool_name": "execute_naabu", "tool_args": {}}]}

# kind, orchestrator method, the answer's arguments, the state paused on the request, the request
# field: what each resume is and how its run waits.
RESUMES = (
    ("approval", "resume_after_approval_with_streaming", ("approve", None),
     {"awaiting_user_approval": True, "phase_transition_pending": TRANSITION}, "phase_transition_pending"),
    ("tool_confirmation", "resume_after_tool_confirmation_with_streaming", ("approve", None),
     {"awaiting_tool_confirmation": True, "tool_confirmation_pending": CONFIRMATION}, "tool_confirmation_pending"),
)
ANSWER_FIELDS = ("user_approval_response", "user_modification",
                 "tool_confirmation_response", "tool_confirmation_modification")


class _Graph:
    """The checkpoint of one session: what aget_state reads and what each run was given."""

    def __init__(self, state):
        self.state = {"messages": [], **state}
        self.inputs = []

    async def aget_state(self, _config):
        return SimpleNamespace(values=self.state)

    async def astream(self, graph_input, _config, stream_mode="values"):
        self.inputs.append(graph_input)
        yield {**self.state, **graph_input, "awaiting_user_approval": False,
               "awaiting_tool_confirmation": False, "task_complete": True}


class _Callback:
    def __init__(self):
        self.errors = []

    async def on_error(self, message, recoverable=True, **details):
        self.errors.append({"message": message, "recoverable": recoverable, **details})

    async def on_response(self, *a, **k):
        pass


def _orchestrator(graph):
    orch = AgentOrchestrator.__new__(AgentOrchestrator)
    orch._initialized = True
    orch._streaming_callbacks, orch._guidance_queues, orch._graph_view_cyphers = {}, {}, {}
    orch.graph = graph

    def apply(_project_id):
        ps._settings_ctx.set(dict(ps.DEFAULT_AGENT_SETTINGS))
        ac.current_llm.set(object())

    @asynccontextmanager
    async def no_lease(_user_id):
        yield

    orch._apply_project_settings = apply
    orch._mcp_toolset_lease = no_lease
    return orch


def _broker():
    @asynccontextmanager
    async def run_scope(*_a, **_k):
        yield SimpleNamespace(final_state=None)
    return SimpleNamespace(run_scope=run_scope)


class _Patched(unittest.TestCase):
    def setUp(self):
        for target, value in (("orchestrator.get_broker", _broker),
                              ("orchestrator.emit_streaming_events", mock.AsyncMock())):
            patcher = mock.patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(ps._settings_ctx.set, None)


class NothingPendingIsRefused(_Patched):
    """The orchestrator end: a resume reads the request before it writes or saves anything."""

    def _resume(self, method, args, graph, *, live_run_callback=None):
        orch = _orchestrator(graph)
        if live_run_callback is not None:
            orch._streaming_callbacks[SESSION] = live_run_callback
        admitted, cb = [], _Callback()

        async def main():
            return await asyncio.wait_for(getattr(orch, method)(
                SESSION, "uB", "pB", *args, cb, on_admitted=lambda: admitted.append(True)), BOUND_S)

        resp = asyncio.run(main())
        return orch, resp, cb, admitted

    def test_an_answer_to_a_request_no_longer_pending_is_refused_before_anything_runs(self):
        for kind, method, args, _paused, field in RESUMES:
            with self.subTest(kind=kind):
                # After tab 2's message (initialize) or tab 2's own answer (process_*): the
                # request field is cleared, the conversation goes on.
                graph = _Graph({field: None})
                with self.assertLogs("orchestrator", "WARNING") as logs:
                    _, resp, cb, admitted = self._resume(method, args, graph)
                [err] = cb.errors
                self.assertEqual((err["code"], err["recoverable"], err["answer"]),
                                 ("no_pending_request", True, kind))
                self.assertIn("not applied", err["message"])
                self.assertEqual(resp.error, err["message"])
                self.assertEqual(graph.inputs, [], "no state write: the answer never reaches the run")
                self.assertEqual(admitted, [], "nothing saved, nothing audited (on_admitted)")
                self.assertTrue(any(f"{kind} answer refused: no pending request" in line
                                    for line in logs.output))

    def test_a_refusal_leaves_a_live_run_of_the_session_untouched(self):
        for kind, method, args, _paused, field in RESUMES:
            with self.subTest(kind=kind):
                live = _Callback()
                orch, _, _, _ = self._resume(method, args, _Graph({field: None}), live_run_callback=live)
                self.assertIs(orch._streaming_callbacks.get(SESSION), live,
                              "tab 2's running turn keeps streaming to its own callback")

    def test_an_answer_to_the_pending_request_is_admitted_as_before(self):
        for kind, method, args, paused, field in RESUMES:
            with self.subTest(kind=kind):
                graph = _Graph(paused)
                _, resp, cb, admitted = self._resume(method, args, graph)
                self.assertEqual(cb.errors, [])
                self.assertEqual(admitted, [True])
                [graph_input] = graph.inputs
                self.assertEqual(graph_input[{"approval": "user_approval_response",
                                              "tool_confirmation": "tool_confirmation_response"}[kind]],
                                 "approve")

    def test_an_empty_session_still_reports_no_pending_session(self):
        for kind, method, args, _paused, _field in RESUMES:
            with self.subTest(kind=kind):
                graph = _Graph({})
                graph.state = {}
                _, resp, cb, admitted = self._resume(method, args, graph)
                self.assertEqual([(e["message"], e["recoverable"]) for e in cb.errors],
                                 [("No pending session found", False)])
                self.assertEqual((graph.inputs, admitted), ([], []))


class _WS:
    def __init__(self):
        self.sent = []
        self.client = "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        pass


class StrayAnswerThroughTheSocket(_Patched):
    """Tab 1's click, through the real handler and the real orchestrator method."""

    def setUp(self):
        super().setUp()
        self.saved = mock.AsyncMock(return_value=None)
        self.posted = mock.AsyncMock(return_value=True)
        for name, value in (("save_chat_message", self.saved),
                            ("post_agent_decision", self.posted),
                            ("update_conversation", mock.AsyncMock())):
            patcher = mock.patch.object(websocket_api, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _click(self, method, payload, graph):
        orch = _orchestrator(graph)

        async def main():
            mgr = WebSocketManager()
            handler = WebSocketHandler(orchestrator=orch, ws_manager=mgr)
            conn = WebSocketConnection(_WS())
            conn.cap = frozenset(AGENT_CAPS)
            await mgr.authenticate(conn, "uB", "pB", SESSION, verified=True)
            await getattr(handler, method)(conn, dict(payload))
            await asyncio.wait_for(conn._active_task, BOUND_S)
            for _ in range(10):
                await asyncio.sleep(0)
            return conn

        return asyncio.run(main())

    def test_a_stray_click_is_refused_unsaved_and_unaudited(self):
        for (kind, _method, _args, _paused, field), handler in zip(
                RESUMES, ("handle_approval", "handle_tool_confirmation")):
            with self.subTest(kind=kind):
                self.saved.reset_mock()
                self.posted.reset_mock()
                graph = _Graph({field: None})
                with self.assertLogs("orchestrator", "WARNING"):
                    conn = self._click(handler, {"decision": "approve"}, graph)
                errors = [m["payload"] for m in conn.websocket.sent if m["type"] == "error"]
                self.assertEqual([(e["code"], e["answer"]) for e in errors], [("no_pending_request", kind)])
                self.assertEqual(graph.inputs, [])
                rows = [c.kwargs["msg_type"] for c in self.saved.await_args_list]
                self.assertNotIn(f"{kind}_response", rows, "the stray answer is never saved")
                self.posted.assert_not_awaited()


def _think(state, decision: dict):
    """The real think node, its model answering `decision`."""
    tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
    resp = SimpleNamespace(content=json.dumps(decision),
                           usage_metadata={"input_tokens": 10, "output_tokens": 5})
    with mock.patch.object(tn, "retry_llm_call", new=mock.AsyncMock(return_value=resp)):
        return asyncio.run(tn.think_node(
            state, {"configurable": {"user_id": "u", "project_id": "p", "session_id": "s"}},
            llm=mock.AsyncMock(), guidance_queues={}, neo4j_creds=("bolt://x", "u", "p")))


def _stale_state(**answers):
    """A session whose state still holds an answer given to an earlier request."""
    from state import create_initial_state
    st = create_initial_state("u", "p", "s", "recover the flag", 100)
    st["current_phase"] = "informational"
    st["_just_transitioned_to"] = None
    st.update(answers)
    return st


class _Recorder:
    """A streaming callback that records what reached the drawer."""

    def __init__(self):
        self.calls = []
        self._emitted_approval_key = None
        self._emitted_question_key = None
        self._emitted_tool_confirmation_key = None
        self._emitted_thinking_ids = set()
        self._emitted_tool_complete_ids = set()
        self._emitted_tool_output_ids = set()
        self._emitted_tool_start_ids = set()

    def __getattr__(self, name):
        if not name.startswith("on_"):
            raise AttributeError(name)

        async def record(*a, **k):
            self.calls.append(name)
        return record


def _shown(state) -> list:
    rec = _Recorder()
    asyncio.run(emit_streaming_events(state, rec))
    return rec.calls


class ANewRequestClearsAStaleAnswer(unittest.TestCase):
    """The think end: a request the agent raises starts with no answer."""

    def setUp(self):
        self.addCleanup(ps._settings_ctx.set, None)
        ps._settings_ctx.set(dict(ps.DEFAULT_AGENT_SETTINGS))
        self.orch = AgentOrchestrator.__new__(AgentOrchestrator)

    def _next_message_route(self, state):
        """Where the person's next ordinary message goes (initialize's router)."""
        return self.orch._route_after_initialize(state)

    def test_a_new_phase_request_is_shown_and_a_message_does_not_approve_it(self):
        st = _stale_state(user_approval_response="approve", user_modification="old text")
        updates = _think(st, {
            "thought": "recon done", "reasoning": "exploit now", "action": "transition_phase",
            "phase_transition": {"to_phase": "exploitation", "reason": "map done", "planned_actions": ["x"]},
        })
        self.assertTrue(updates.get("awaiting_user_approval"))
        self.assertIsNotNone(updates.get("phase_transition_pending"))
        self.assertIn("user_approval_response", updates)
        self.assertIsNone(updates["user_approval_response"])
        self.assertIsNone(updates["user_modification"])
        paused = {**st, **updates}
        self.assertIn("on_approval_request", _shown(paused), "the request reaches the drawer")
        self.assertEqual(self._next_message_route(paused), "think",
                         "a message is not an answer: process_approval is not reached")

    def test_a_new_tool_confirmation_is_shown_and_a_message_does_not_confirm_it(self):
        st = _stale_state(tool_confirmation_response="approve", tool_confirmation_modification={"a": 1})
        updates = _think(st, {
            "thought": "scan", "reasoning": "map ports", "action": "use_tool",
            "tool_name": "execute_naabu", "tool_args": {"args": "-host 10.0.0.1"},
        })
        self.assertTrue(updates.get("awaiting_tool_confirmation"))
        self.assertIsNotNone(updates.get("tool_confirmation_pending"))
        self.assertIn("tool_confirmation_response", updates)
        self.assertIsNone(updates["tool_confirmation_response"])
        self.assertIsNone(updates["tool_confirmation_modification"])
        paused = {**st, **updates}
        self.assertIn("on_tool_confirmation_request", _shown(paused))
        self.assertEqual(self._next_message_route(paused), "think")

    def test_a_fireteam_escalation_is_shown_and_a_message_does_not_confirm_it(self):
        from orchestrator_helpers.nodes.fireteam_collect_node import fireteam_collect_node
        st = {
            "_current_fireteam_results": [{
                "member_id": "m1", "name": "Web", "status": "needs_confirmation",
                "pending_confirmation": dict(CONFIRMATION), "findings": [], "target_info_delta": {},
                "iterations_used": 1}],
            "_fireteam_id": "fteam-1", "target_info": {}, "chain_findings_memory": [],
            "user_id": "u", "project_id": "p", "session_id": "s", "current_phase": "informational",
            "_current_fireteam_plan": {"members": [{"member_id": "m1", "name": "Web", "task": "t"}]},
            "tool_confirmation_response": "approve", "tool_confirmation_modification": {"a": 1},
        }
        update = asyncio.run(fireteam_collect_node(st, None, llm=None, neo4j_creds=None))
        self.assertTrue(update.get("awaiting_tool_confirmation"))
        self.assertIsNone(update.get("tool_confirmation_response", "kept"))
        self.assertIsNone(update.get("tool_confirmation_modification", "kept"))
        paused = {**st, **update}
        self.assertIn("on_tool_confirmation_request", _shown(paused))
        self.assertEqual(self._next_message_route(paused), "think")

    def test_without_a_stale_answer_the_requests_are_unchanged(self):
        updates = _think(_stale_state(), {
            "thought": "recon done", "reasoning": "exploit now", "action": "transition_phase",
            "phase_transition": {"to_phase": "exploitation", "reason": "map done", "planned_actions": ["x"]},
        })
        self.assertEqual(updates["phase_transition_pending"]["to_phase"], "exploitation")
        self.assertIn("on_approval_request", _shown({**_stale_state(), **updates}))


class ANewMessageCarriesNoAnswer(_Patched):
    """A checkpoint written before this fix may hold an answer next to a hidden request: the
    next message still does not approve it."""

    def test_the_message_input_clears_every_answer(self):
        graph = _Graph({"awaiting_user_approval": True, "phase_transition_pending": TRANSITION,
                        "user_approval_response": "approve"})
        orch = _orchestrator(graph)
        asyncio.run(asyncio.wait_for(orch.invoke_with_streaming("go on", "uB", "pB", SESSION, _Callback()),
                                     BOUND_S))
        [graph_input] = graph.inputs
        for field in ANSWER_FIELDS:
            self.assertIn(field, graph_input)
            self.assertIsNone(graph_input[field], field)
        merged = {**graph.state, **graph_input}
        self.assertEqual(orch._route_after_initialize(merged), "think")


if __name__ == "__main__":
    unittest.main()
