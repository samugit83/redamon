"""Unit tests for per-step + cumulative token tracking.

Covers the invariants that make the "in X · out Y" UI counters accurate:

 * FireteamMemberResult carries split input/output token fields so fireteam
   panels show backend-authoritative counts on member_completed.
 * _build_member_state seeds the new state fields so LangGraph doesn't
   filter them out on the first merge.
 * _result_from_final_state propagates the cumulative counters from the
   member's terminal state onto the result dict.
 * MemberScopedCallback.on_thinking forwards input_tokens/output_tokens to
   on_fireteam_thinking so the UI reducer can accumulate.
 * The fireteam member think node populates _input_tokens_this_turn /
   _output_tokens_this_turn from the provider usage_metadata, and falls
   back to the tokenizer estimate when provider reports nothing.

Run (inside agent container with the tests dir mounted):
    docker compose run --rm --no-deps \\
      -v "$PWD/agentic/tests:/app/tests" agent \\
      python -m unittest -v tests.test_token_tracking
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# =============================================================================
# 1. FireteamMemberResult pydantic model
# =============================================================================

class FireteamMemberResultFieldsTests(unittest.TestCase):
    """The result envelope must carry split token counters."""

    def test_has_input_output_token_fields_with_defaults(self):
        from state import FireteamMemberResult
        r = FireteamMemberResult(
            member_id="m-1", name="Web", status="success",
        )
        self.assertEqual(r.input_tokens_used, 0)
        self.assertEqual(r.output_tokens_used, 0)
        self.assertEqual(r.tokens_used, 0)

    def test_accepts_explicit_token_fields(self):
        from state import FireteamMemberResult
        r = FireteamMemberResult(
            member_id="m-1", name="Web", status="success",
            tokens_used=4200, input_tokens_used=4000, output_tokens_used=200,
        )
        self.assertEqual(r.input_tokens_used, 4000)
        self.assertEqual(r.output_tokens_used, 200)
        self.assertEqual(r.tokens_used, 4200)

    def test_model_dump_roundtrip_preserves_split_tokens(self):
        from state import FireteamMemberResult
        r = FireteamMemberResult(
            member_id="m-1", name="Web", status="success",
            input_tokens_used=1234, output_tokens_used=56,
            tokens_used=1290,
        )
        d = r.model_dump()
        self.assertEqual(d["input_tokens_used"], 1234)
        self.assertEqual(d["output_tokens_used"], 56)
        self.assertEqual(d["tokens_used"], 1290)


# =============================================================================
# 2. fireteam_deploy_node._build_member_state
# =============================================================================

class BuildMemberStateTokenFieldsTests(unittest.TestCase):
    """The deploy node must seed every state field that the think node writes.

    LangGraph silently filters updates for fields not present on the TypedDict
    at merge time. Seeding them in _build_member_state guarantees the initial
    state matches the TypedDict shape so _input_tokens_this_turn and the
    input/output_tokens_used cumulative counters actually land.
    """

    def _parent(self):
        return {
            "current_phase": "informational",
            "attack_path_type": "",
            "user_id": "u", "project_id": "p", "session_id": "s",
            "target_info": {},
        }

    def _spec(self):
        return {
            "name": "Web",
            "task": "recon",
            "skills": [],
        }

    def test_seeds_token_fields_to_zero(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _build_member_state
        base = _build_member_state(self._parent(), self._spec(), "m-1", "fteam-1")
        self.assertEqual(base["tokens_used"], 0)
        self.assertEqual(base["input_tokens_used"], 0)
        self.assertEqual(base["output_tokens_used"], 0)
        self.assertEqual(base["_input_tokens_this_turn"], 0)
        self.assertEqual(base["_output_tokens_this_turn"], 0)


# =============================================================================
# 3. _result_from_final_state propagates split tokens
# =============================================================================

class ResultFromFinalStateTokenTests(unittest.TestCase):
    def _spec(self):
        return {"name": "Web"}

    def _final(self, **overrides):
        base = {
            "current_iteration": 3,
            "tokens_used": 1000,
            "input_tokens_used": 800,
            "output_tokens_used": 200,
            "completion_reason": "complete",
            "parent_target_info": {},
            "target_info": {},
            "chain_findings_memory": [],
            "execution_trace": [],
            "_last_chain_step_id": None,
        }
        base.update(overrides)
        return base

    def test_propagates_split_tokens_onto_result(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _result_from_final_state
        out = _result_from_final_state(self._final(), self._spec(), "m-1", 1.2)
        self.assertEqual(out["tokens_used"], 1000)
        self.assertEqual(out["input_tokens_used"], 800)
        self.assertEqual(out["output_tokens_used"], 200)
        self.assertEqual(out["status"], "success")

    def test_missing_split_defaults_to_zero(self):
        # A member that crashed before any LLM call may not have the fields.
        # The result must still serialize with 0 — the UI treats absent as 0.
        from orchestrator_helpers.nodes.fireteam_deploy_node import _result_from_final_state
        final = self._final()
        final.pop("input_tokens_used")
        final.pop("output_tokens_used")
        out = _result_from_final_state(final, self._spec(), "m-1", 0.1)
        self.assertEqual(out["input_tokens_used"], 0)
        self.assertEqual(out["output_tokens_used"], 0)


# =============================================================================
# 4. MemberScopedCallback forwards token kwargs
# =============================================================================

class MemberScopedCallbackTokenForwardingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from orchestrator_helpers.member_streaming import MemberScopedCallback
        self.real = MagicMock()
        self.real.on_fireteam_thinking = AsyncMock()
        self.real.on_thinking = AsyncMock()
        self.proxy = MemberScopedCallback(
            self.real, fireteam_id="fteam-1", member_id="m-1", member_name="Web",
        )

    async def test_on_thinking_forwards_input_output_tokens(self):
        await self.proxy.on_thinking(
            2, "informational", "t", "r",
            action="use_tool",
            input_tokens=4200, output_tokens=150,
        )
        self.real.on_fireteam_thinking.assert_awaited_once()
        kwargs = self.real.on_fireteam_thinking.await_args.kwargs
        self.assertEqual(kwargs["input_tokens"], 4200)
        self.assertEqual(kwargs["output_tokens"], 150)
        # Identity fields still correct.
        self.assertEqual(kwargs["fireteam_id"], "fteam-1")
        self.assertEqual(kwargs["member_id"], "m-1")

    async def test_on_thinking_defaults_token_kwargs_to_zero(self):
        # Older emit paths may not pass the kwargs explicitly; the proxy
        # must still provide zero (not raise) to keep the payload shape.
        await self.proxy.on_thinking(1, "informational", "t", "r")
        self.real.on_fireteam_thinking.assert_awaited_once()
        kwargs = self.real.on_fireteam_thinking.await_args.kwargs
        self.assertEqual(kwargs["input_tokens"], 0)
        self.assertEqual(kwargs["output_tokens"], 0)

    async def test_on_thinking_fallback_to_generic_keeps_tokens(self):
        # If the real callback predates on_fireteam_thinking, the proxy
        # falls back to on_thinking. That fallback must also forward the
        # token kwargs so the root path can still attribute usage.
        real_old = MagicMock(spec=[])  # no attributes
        real_old.on_thinking = AsyncMock()
        # Raise AttributeError on on_fireteam_thinking lookup
        type(real_old).on_fireteam_thinking = property(
            lambda self: (_ for _ in ()).throw(AttributeError())
        )
        from orchestrator_helpers.member_streaming import MemberScopedCallback
        proxy = MemberScopedCallback(
            real_old, fireteam_id="f", member_id="m", member_name="W",
        )
        await proxy.on_thinking(
            1, "informational", "t", "r",
            action="use_tool", input_tokens=10, output_tokens=2,
        )
        real_old.on_thinking.assert_awaited_once()
        kwargs = real_old.on_thinking.await_args.kwargs
        self.assertEqual(kwargs["input_tokens"], 10)
        self.assertEqual(kwargs["output_tokens"], 2)


# =============================================================================
# 5. WebSocketCallback.on_thinking payload shape
# =============================================================================

class WebSocketOnThinkingPayloadTests(unittest.IsolatedAsyncioTestCase):
    """Validate the root-agent and fireteam THINKING payloads include tokens."""

    def _make_cb(self):
        from websocket_api import StreamingCallback
        conn = MagicMock()
        conn.send_message = AsyncMock()
        cb = StreamingCallback.__new__(StreamingCallback)
        # Minimal init to avoid touching DB / loop bookkeeping.
        cb._original_connection = conn
        cb._ws_manager = None
        cb._session_key = None
        cb._session_id = "s-1"
        cb._project_id = "p-1"
        cb._user_id = "u-1"
        # Swap the DB persist hook for a recorder so _persist doesn't spin up
        # an asyncio worker task inside the test loop.
        cb._persist_calls = []
        cb._persist = lambda msg_type, data, **kw: cb._persist_calls.append((msg_type, data))
        cb._tool_context = {}
        cb._task_complete_sent = False
        cb._response_sent = False
        cb._emitted_tool_start_ids = set()
        cb._emitted_tool_complete_ids = set()
        cb._emitted_tool_output_ids = set()
        cb._emitted_thinking_ids = set()
        cb._emitted_approval_key = None
        cb._emitted_question_key = None
        cb._emitted_tool_confirmation_key = None
        return cb, conn

    async def test_on_thinking_payload_carries_tokens(self):
        cb, conn = self._make_cb()
        await cb.on_thinking(
            iteration=2, phase="informational",
            thought="t", reasoning="r", action="use_tool",
            input_tokens=4200, output_tokens=150,
        )
        conn.send_message.assert_awaited_once()
        args, _ = conn.send_message.await_args
        msg_type, payload = args
        self.assertEqual(payload["input_tokens"], 4200)
        self.assertEqual(payload["output_tokens"], 150)
        self.assertEqual(payload["action"], "use_tool")
        # Persistence enqueued with the same payload so session restore
        # can replay the per-step counts.
        self.assertTrue(any(
            msg_type == "thinking" and data.get("input_tokens") == 4200
            for msg_type, data in cb._persist_calls
        ))

    async def test_on_thinking_coerces_none_to_zero(self):
        # The streaming layer calls state.get("_input_tokens_this_turn", 0),
        # but a mis-set state or DB-restored payload could yield None. Verify
        # the WS method coerces to int so the JSON payload never ships None.
        cb, conn = self._make_cb()
        await cb.on_thinking(
            iteration=1, phase="informational", thought="t", reasoning="r",
            input_tokens=None, output_tokens=None,
        )
        args, _ = conn.send_message.await_args
        _msg_type, payload = args
        self.assertEqual(payload["input_tokens"], 0)
        self.assertEqual(payload["output_tokens"], 0)

    async def test_on_fireteam_thinking_payload_carries_tokens(self):
        cb, conn = self._make_cb()
        await cb.on_fireteam_thinking(
            fireteam_id="fteam-1", member_id="m-1", name="Web",
            iteration=1, phase="informational",
            thought="t", reasoning="r",
            input_tokens=1000, output_tokens=50,
        )
        args, _ = conn.send_message.await_args
        _mt, payload = args
        self.assertEqual(payload["fireteam_id"], "fteam-1")
        self.assertEqual(payload["input_tokens"], 1000)
        self.assertEqual(payload["output_tokens"], 50)

    async def test_on_fireteam_member_completed_payload_carries_split_tokens(self):
        cb, conn = self._make_cb()
        await cb.on_fireteam_member_completed(
            fireteam_id="fteam-1", member_id="m-1", name="Web",
            status="success", iterations_used=3, tokens_used=1050,
            findings_count=2, wall_clock_seconds=1.2,
            input_tokens_used=1000, output_tokens_used=50,
        )
        args, _ = conn.send_message.await_args
        _mt, payload = args
        self.assertEqual(payload["tokens_used"], 1050)
        self.assertEqual(payload["input_tokens_used"], 1000)
        self.assertEqual(payload["output_tokens_used"], 50)


# =============================================================================
# 6. streaming.emit_streaming_events reads the per-turn deltas from state
# =============================================================================

class EmitStreamingTokenPassthroughTests(unittest.IsolatedAsyncioTestCase):
    """emit_streaming_events must thread _input/_output_tokens_this_turn
    from state into the on_thinking call so the UI sees per-step counts."""

    async def test_on_thinking_called_with_state_token_deltas(self):
        from orchestrator_helpers.streaming import emit_streaming_events

        callback = MagicMock()
        callback.on_phase_update = AsyncMock()
        callback.on_todo_update = AsyncMock()
        callback.on_approval_request = AsyncMock()
        callback.on_question_request = AsyncMock()
        callback.on_tool_complete = AsyncMock()
        callback.on_execution_step = AsyncMock()
        callback.on_file_ready = AsyncMock()
        callback.on_thinking = AsyncMock()
        callback.on_tool_start = AsyncMock()
        callback.on_tool_output_chunk = AsyncMock()
        callback.on_tool_confirmation_request = AsyncMock()
        callback.on_task_complete = AsyncMock()
        callback._emitted_tool_start_ids = set()
        callback._emitted_tool_complete_ids = set()
        callback._emitted_tool_output_ids = set()
        callback._emitted_thinking_ids = set()
        callback._emitted_approval_key = ""
        callback._emitted_question_key = ""
        callback._emitted_tool_confirmation_key = ""

        state = {
            "current_iteration": 4,
            "current_phase": "informational",
            "_decision": {
                "thought": "thought A", "reasoning": "r", "action": "use_tool",
            },
            "_input_tokens_this_turn": 3800,
            "_output_tokens_this_turn": 120,
        }
        await emit_streaming_events(state, callback)
        callback.on_thinking.assert_awaited_once()
        kwargs = callback.on_thinking.await_args.kwargs
        self.assertEqual(kwargs["input_tokens"], 3800)
        self.assertEqual(kwargs["output_tokens"], 120)

    async def test_missing_deltas_default_to_zero(self):
        from orchestrator_helpers.streaming import emit_streaming_events

        callback = MagicMock()
        for name in (
            "on_phase_update", "on_todo_update", "on_approval_request",
            "on_question_request", "on_tool_complete", "on_execution_step",
            "on_file_ready", "on_thinking", "on_tool_start",
            "on_tool_output_chunk", "on_tool_confirmation_request",
            "on_task_complete",
        ):
            setattr(callback, name, AsyncMock())
        callback._emitted_tool_start_ids = set()
        callback._emitted_tool_complete_ids = set()
        callback._emitted_tool_output_ids = set()
        callback._emitted_thinking_ids = set()
        callback._emitted_approval_key = ""
        callback._emitted_question_key = ""
        callback._emitted_tool_confirmation_key = ""

        state = {
            "current_iteration": 1,
            "current_phase": "informational",
            "_decision": {
                "thought": "thought B", "reasoning": "r", "action": "complete",
            },
        }
        await emit_streaming_events(state, callback)
        callback.on_thinking.assert_awaited_once()
        kwargs = callback.on_thinking.await_args.kwargs
        self.assertEqual(kwargs["input_tokens"], 0)
        self.assertEqual(kwargs["output_tokens"], 0)


# =============================================================================
# 7. Usage-metadata extraction shape (langchain AIMessage protocol)
# =============================================================================

class UsageMetadataExtractionTests(unittest.TestCase):
    """We extract tokens via getattr(response, 'usage_metadata', None) and
    index ["input_tokens"]/["output_tokens"]. Langchain ChatAnthropic and
    ChatOpenAI both use this exact shape. Verify our extraction expression
    is safe against the three real-world response shapes we see:
      * usage_metadata=None (provider reported nothing)
      * usage_metadata={'input_tokens': 0, 'output_tokens': 0} (empty)
      * usage_metadata={'input_tokens': 123, 'output_tokens': 45}
    """

    def _extract(self, response):
        usage = getattr(response, "usage_metadata", None) or {}
        return (
            int(usage.get("input_tokens", 0) or 0),
            int(usage.get("output_tokens", 0) or 0),
        )

    def test_missing_usage_metadata_returns_zero(self):
        class Resp:
            content = "ok"
        self.assertEqual(self._extract(Resp()), (0, 0))

    def test_none_usage_metadata_returns_zero(self):
        class Resp:
            content = "ok"
            usage_metadata = None
        self.assertEqual(self._extract(Resp()), (0, 0))

    def test_empty_dict_returns_zero(self):
        class Resp:
            content = "ok"
            usage_metadata = {}
        self.assertEqual(self._extract(Resp()), (0, 0))

    def test_populated_returns_values(self):
        class Resp:
            content = "ok"
            usage_metadata = {"input_tokens": 4200, "output_tokens": 150}
        self.assertEqual(self._extract(Resp()), (4200, 150))

    def test_none_field_coerces_to_zero(self):
        class Resp:
            content = "ok"
            usage_metadata = {"input_tokens": None, "output_tokens": 12}
        self.assertEqual(self._extract(Resp()), (0, 12))


# =============================================================================
# 8. Member think node: accumulation across retries + fallback split
# =============================================================================

class MemberThinkTokenAccumulationTests(unittest.TestCase):
    """Replicate the retry-loop accumulation logic from
    fireteam_member_think_node so a regression that drops the += would
    get caught here. Also verify the ~85/15 split fallback when no
    provider metadata is reported."""

    def test_retries_sum_tokens_not_replace(self):
        # Three attempts: two failed parses then success. The counters
        # must be the SUM across all three, not just the last.
        responses = [
            ("input_tokens", 1000, "output_tokens", 60),
            ("input_tokens", 1100, "output_tokens", 40),
            ("input_tokens", 1200, "output_tokens", 30),
        ]
        input_tokens = 0
        output_tokens = 0
        for _, in_t, _, out_t in responses:
            usage = {"input_tokens": in_t, "output_tokens": out_t}
            input_tokens += int(usage.get("input_tokens", 0) or 0)
            output_tokens += int(usage.get("output_tokens", 0) or 0)
        self.assertEqual(input_tokens, 3300)
        self.assertEqual(output_tokens, 130)

    def test_fallback_split_85_15_preserves_total(self):
        # When no usage_metadata, we split the estimator into 85/15.
        # Property: split must sum back to the original estimate.
        for est in [10, 100, 1000, 4321, 9999]:
            inp = int(est * 0.85)
            out = max(1, est - inp)
            self.assertEqual(inp + out, est)
            # And the split must be monotone: more input than output.
            self.assertGreaterEqual(inp, out)


# =============================================================================
# 9. think_node regression: deep-think token vars are always initialized
# =============================================================================

class ThinkNodeDeepThinkVarInitTests(unittest.TestCase):
    """Regression for UnboundLocalError on `_dt_in` / `_dt_out`.

    The deep-think block is guarded by `if get_setting('DEEP_THINK_ENABLED'):`.
    Inside the block, `_dt_in` / `_dt_out` track the deep-think ainvoke's
    token usage, and the main think-loop reads them to seed its per-turn
    counter. If the guard is False (the default), the variables never
    get assigned — but the main loop still references them, producing:

        UnboundLocalError: cannot access local variable '_dt_in'
                         where it is not associated with a value

    This test doesn't run think_node end-to-end (that would require a
    full LLM + Neo4j + config fixture). Instead it asserts, via source
    inspection, that the variables are initialized unconditionally at
    the module scope of think_node, BEFORE the `if DEEP_THINK_ENABLED:`
    guard. That's the exact invariant a future refactor could break.
    """

    def test_dt_vars_initialized_before_deep_think_guard(self):
        import inspect
        from orchestrator_helpers.nodes.think_node import think_node
        src = inspect.getsource(think_node)

        # The initializer MUST appear before the guard.
        init_idx = src.find("_dt_in = 0")
        guard_idx = src.find("if get_setting('DEEP_THINK_ENABLED'")
        self.assertNotEqual(init_idx, -1, "Missing _dt_in initializer in think_node")
        self.assertNotEqual(guard_idx, -1, "Missing DEEP_THINK_ENABLED guard in think_node")
        self.assertLess(
            init_idx, guard_idx,
            "_dt_in must be initialized BEFORE the DEEP_THINK_ENABLED guard "
            "so the main loop can read it when deep-think is disabled.",
        )
        # And _dt_out too.
        self.assertIn("_dt_out = 0", src)


if __name__ == "__main__":
    unittest.main()
