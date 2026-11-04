"""Root think_node + guardrail transient-error retry regression.

Locks the propagation of the fireteam retry fix (PR #111 + classifier
optimization + shared helper) into the two other places that share the
same root cause:

  * Root think_node (think_node.py:469) — previously had no try/except
    around llm.ainvoke. A transient error there terminated the entire
    session, not just a fireteam member.
  * guardrail._invoke_guardrail — previously had broad `except Exception`
    that retried EVERY error (including auth/schema), wasting 3 round
    trips on permanent failures and surfacing a misleading
    "Guardrail LLM check failed after 3 attempts" RuntimeError instead
    of the real cause.

think_node is tested via source inspection because building a full
think_node fixture (LangGraph config + Neo4j + project settings + all
node deps) is heavyweight and the deep-think token-tracking regression
already established that pattern (see test_token_tracking.py:489-524).
The retry helper itself is exercised end-to-end in test_llm_retry.py.

guardrail is tested end-to-end because _invoke_guardrail is a small
isolated function — easy to mock the LLM and verify both retry paths.

Run (inside agent container):
    docker run --rm \\
        -v "/path/agentic:/app" \\
        -v "/path/graph_db:/app/graph_db:ro" \\
        -v "/path/knowledge_base:/app/knowledge_base:ro" \\
        -w /app redamon-agent python -m unittest \\
        tests.test_root_think_and_guardrail_retry -v
"""

from __future__ import annotations

import inspect
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# Synthetic exception classes — names must match the SDK class names for
# the type-MRO classifier to recognize them.
class APIConnectionError(Exception):
    pass


class _PermanentAuthError(Exception):
    pass


# =============================================================================
# 1. ROOT think_node — source inspection regression
# =============================================================================

class RootThinkNodeRetryWiringTests(unittest.TestCase):
    """Source-inspection regression. Verifies the retry helper is wired
    into think_node and that the bare `await llm.ainvoke(messages)` has
    been replaced.

    A full think_node fixture would require: state, config, llm,
    guidance_queues, neo4j_creds, streaming_callbacks, graph_view_cyphers,
    project settings, etc. — far more than the retry change warrants.
    The retry behavior itself is unit-tested in test_llm_retry.py; this
    test only locks the WIRING.
    """

    def setUp(self):
        # `from .think_node import think_node` in nodes/__init__.py rebinds
        # the `think_node` attribute on the package to the FUNCTION, masking
        # the submodule. Reach the module via sys.modules instead.
        import orchestrator_helpers.nodes.think_node  # ensure imported  # noqa: F401
        think_mod = sys.modules["orchestrator_helpers.nodes.think_node"]
        self.src = inspect.getsource(think_mod.think_node)
        self.module_src = inspect.getsource(think_mod)

    def test_retry_llm_call_is_imported(self):
        self.assertIn(
            "from orchestrator_helpers.llm_retry import retry_llm_call",
            self.module_src,
            "think_node module must import retry_llm_call from the shared helper",
        )

    def test_bare_ainvoke_no_longer_called_directly_in_main_loop(self):
        """The main reasoning loop must NOT have `await llm.ainvoke` —
        only `await retry_llm_call(llm, ...)`. Deep Think goes through
        retry_llm_call too, so a rate limit does not silently skip it
        (test_loop_purpose_labels pins that call).

        We slice the source to the parse-retry-loop region and assert
        ``await llm.ainvoke`` is absent there.
        """
        # The parse-retry loop begins at the `for attempt in range(max_retries):`
        # line and runs until the fallback `if not decision:` block.
        loop_start = self.src.find("for attempt in range(max_retries):")
        loop_end = self.src.find("# If all retries failed, use the fallback")
        self.assertNotEqual(loop_start, -1, "parse-retry loop signature changed")
        self.assertNotEqual(loop_end, -1, "fallback comment landmark changed")
        loop_src = self.src[loop_start:loop_end]
        self.assertNotIn(
            "await llm.ainvoke", loop_src,
            "main parse-retry loop must call retry_llm_call, not llm.ainvoke "
            "directly — a single transient error must not crash the session",
        )
        self.assertIn(
            "await retry_llm_call", loop_src,
            "retry_llm_call must be invoked inside the parse-retry loop",
        )

    def test_llm_error_fallback_decision_path_present(self):
        """On retry exhaustion, the function must produce a fallback
        LLMDecision with action=complete and completion_reason starting
        with 'llm_error:' so the graph exits the iteration cleanly
        rather than propagating an uncaught exception. The reason carries
        the exception's class and provider status, never its text
        (llm_error_reason, tested in test_ws_error_frames.py)."""
        self.assertIn('completion_reason=llm_error_reason(exc)', self.src,
                      "fallback decision on retry exhaustion is missing")


# =============================================================================
# 2. GUARDRAIL — end-to-end selective retry
# =============================================================================

class GuardrailSelectiveRetryTests(unittest.IsolatedAsyncioTestCase):
    """End-to-end tests for guardrail._invoke_guardrail's two retry paths:

      * Transient API errors (network blip, 529, etc.) → retry up to 3x
        with exponential backoff. Pre-fix: same behavior, but ALSO
        retried permanent errors (waste).
      * Non-transient errors (auth, schema) → re-raise IMMEDIATELY with
        the original exception. Pre-fix: silently swallowed for 3
        rounds, then raised a misleading RuntimeError.
      * Empty/malformed LLM response (no JSON) → retry up to 3x
        (parse-retry; unchanged behavior).
    """

    _VALID_JSON = '{"allowed": true, "reason": "test allow"}'

    async def _run(self, mock_llm):
        from orchestrator_helpers.guardrail import _invoke_guardrail
        with patch(
            "orchestrator_helpers.guardrail.asyncio.sleep",
            new_callable=AsyncMock,
        ) as mock_sleep:
            try:
                result = await _invoke_guardrail(mock_llm, "test prompt")
                return result, mock_sleep, None
            except Exception as exc:
                return None, mock_sleep, exc

    # ----- Happy path -----

    async def test_first_call_success_no_retry(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content=self._VALID_JSON)
        )
        result, sleep, exc = await self._run(mock_llm)
        self.assertIsNone(exc)
        self.assertEqual(result, {"allowed": True, "reason": "test allow"})
        self.assertEqual(mock_llm.ainvoke.await_count, 1)
        self.assertEqual(sleep.await_count, 0)

    # ----- Transient retry then success -----

    async def test_transient_then_success(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("blip"),
            MagicMock(content=self._VALID_JSON),
        ])
        result, sleep, exc = await self._run(mock_llm)
        self.assertIsNone(exc)
        self.assertEqual(result, {"allowed": True, "reason": "test allow"})
        self.assertEqual(mock_llm.ainvoke.await_count, 2)
        self.assertEqual(sleep.await_count, 1)

    # ----- Temperature self-heal: the reported Kimi-k3 bug -----

    async def test_temperature_rejection_self_heals(self):
        """REGRESSION (reported): selecting Moonshot kimi-k3 made the guardrail
        400 with "invalid temperature: only 1 is allowed for this model". The
        fail-closed policy turned that fixable param error into a bogus
        "Scope Guardrail: Check Failed". The guardrail must now drop temperature
        and retry, returning a real verdict."""
        healed = MagicMock()
        healed.ainvoke = AsyncMock(return_value=MagicMock(content=self._VALID_JSON))
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=Exception(
            "Error code: 400 - {'error': {'message': 'invalid temperature: "
            "only 1 is allowed for this model', 'type': 'invalid_request_error'}}"
        ))
        mock_llm.model_copy = MagicMock(return_value=healed)
        result, sleep, exc = await self._run(mock_llm)
        self.assertIsNone(exc, "temperature error must self-heal, not propagate")
        self.assertEqual(result, {"allowed": True, "reason": "test allow"})
        self.assertEqual(mock_llm.ainvoke.await_count, 1)
        self.assertEqual(healed.ainvoke.await_count, 1,
                         "temperature-stripped clone must produce the verdict")
        mock_llm.model_copy.assert_called_once_with(update={"temperature": None})

    async def test_openai_o_series_temperature_self_heals(self):
        """The same heal covers OpenAI o-series/gpt-5, which reject any
        temperature but the default. Different provider, same recovery."""
        healed = MagicMock()
        healed.ainvoke = AsyncMock(return_value=MagicMock(content=self._VALID_JSON))
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=Exception(
            "Unsupported value: 'temperature' does not support 0 with this "
            "model. Only the default (1) value is supported."
        ))
        mock_llm.model_copy = MagicMock(return_value=healed)
        result, sleep, exc = await self._run(mock_llm)
        self.assertIsNone(exc)
        self.assertEqual(result, {"allowed": True, "reason": "test allow"})
        mock_llm.model_copy.assert_called_once_with(update={"temperature": None})

    # ----- Core regression: non-transient must NOT retry -----

    async def test_non_transient_reraises_immediately(self):
        """REGRESSION: pre-fix this used broad `except Exception` and
        wasted 3 round trips before raising a generic RuntimeError. Now
        the original auth error propagates on the first attempt."""
        permanent = _PermanentAuthError("Invalid API key")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=permanent)
        result, sleep, exc = await self._run(mock_llm)
        self.assertIs(exc, permanent,
                      "auth error must propagate UNWRAPPED on first attempt")
        self.assertEqual(mock_llm.ainvoke.await_count, 1,
                         "non-transient must NOT retry — pre-fix burned 3 attempts")
        self.assertEqual(sleep.await_count, 0)

    # ----- Three transient failures → RuntimeError -----

    async def test_three_transient_failures_raise_runtime_error(self):
        """All 3 transient → 'failed after 3 attempts' RuntimeError path is
        preserved AND the last transient exception is chained via __cause__
        and surfaced in the message so operators can tell upstream-LLM
        capacity from scope/auth problems without grepping logs.

        REGRESSION (closed PR #107 intent): pre-fix the message was bare
        "Guardrail LLM check failed after 3 attempts" and __cause__ was
        None, so a 529 overload looked identical to a generic guardrail
        failure in the UI.
        """
        last = APIConnectionError("third blip")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("first blip"),
            APIConnectionError("second blip"),
            last,
        ])
        result, sleep, exc = await self._run(mock_llm)
        self.assertIsInstance(exc, RuntimeError)
        self.assertIn("3 attempts", str(exc))
        self.assertIn("Last error", str(exc))
        self.assertIn("third blip", str(exc),
                      "the final transient exception must surface in the message")
        self.assertIs(exc.__cause__, last,
                      "__cause__ must chain to the last transient — explicit "
                      "raise ... from last_transient")
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        self.assertEqual(sleep.await_count, 2,
                         "no sleep after the final attempt")

    # ----- Three no-JSON responses → RuntimeError WITHOUT chained cause -----

    async def test_three_no_json_responses_raise_runtime_error_no_cause(self):
        """REGRESSION: parse-only exhaustion (3x successful LLM calls, none
        with parseable JSON) must NOT fabricate a fake __cause__ — there was
        no exception. The message must clearly distinguish this path from
        the transient-API-error path so operators see "no parseable JSON"
        instead of misleading "Last error: None"."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            MagicMock(content="prose only attempt 1"),
            MagicMock(content="prose only attempt 2"),
            MagicMock(content="prose only attempt 3"),
        ])
        result, sleep, exc = await self._run(mock_llm)
        self.assertIsInstance(exc, RuntimeError)
        self.assertIn("3 attempts", str(exc))
        self.assertIn("no parseable JSON", str(exc))
        self.assertNotIn("Last error", str(exc),
                         "no transient was raised — must not invent one")
        self.assertIsNone(exc.__cause__,
                          "no upstream exception — chain must stay None")
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        self.assertEqual(sleep.await_count, 0,
                         "parse-retry path does not sleep")

    # ----- Mixed: 2 transient + 1 no-JSON → RuntimeError chained to transient -----

    async def test_two_transient_then_no_json_chains_last_transient(self):
        """REGRESSION: if a transient happened during the run but the final
        attempt succeeded HTTP-wise yet returned no JSON, exhaustion still
        raises and __cause__ should chain to the prior transient — that's
        the most actionable upstream signal we have."""
        first = APIConnectionError("attempt 1 blip")
        second = APIConnectionError("attempt 2 blip")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            first,
            second,
            MagicMock(content="attempt 3 returned prose, no json"),
        ])
        result, sleep, exc = await self._run(mock_llm)
        self.assertIsInstance(exc, RuntimeError)
        self.assertIn("Last error", str(exc))
        self.assertIn("attempt 2 blip", str(exc),
                      "the last transient seen must surface")
        self.assertIs(exc.__cause__, second)
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        # Two transient attempts → two sleeps (after attempts 1 and 2).
        self.assertEqual(sleep.await_count, 2)

    # ----- Parse-retry still works for empty/malformed JSON responses -----

    async def test_no_json_response_retries_then_succeeds(self):
        """LLM returns text without JSON twice, then valid JSON. Parse-
        retry is part of the original loop semantics and must remain."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            MagicMock(content="some prose without json"),
            MagicMock(content="still no json here"),
            MagicMock(content=self._VALID_JSON),
        ])
        result, sleep, exc = await self._run(mock_llm)
        self.assertIsNone(exc)
        self.assertEqual(result, {"allowed": True, "reason": "test allow"})
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        # Parse-retry does NOT sleep (only API-error retry does).
        self.assertEqual(sleep.await_count, 0)

    # ----- Mixed: transient then permanent -----

    async def test_transient_then_permanent_reraises_permanent(self):
        permanent = _PermanentAuthError("schema bug")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("transient first"),
            permanent,
        ])
        result, sleep, exc = await self._run(mock_llm)
        self.assertIs(exc, permanent)
        self.assertEqual(mock_llm.ainvoke.await_count, 2)
        self.assertEqual(sleep.await_count, 1)


if __name__ == "__main__":
    unittest.main()
