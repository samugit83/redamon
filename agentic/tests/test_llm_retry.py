"""Unit tests for the shared ``orchestrator_helpers.llm_retry`` module.

Direct tests of ``is_transient_llm_error`` and ``retry_llm_call`` — the
shared helper used by fireteam_member_think_node, root think_node, and
guardrail. These tests do NOT exercise any node integration; for that
see ``tests/test_fireteam_member_llm_retry.py`` (fireteam side) and
``tests/test_think_node_llm_retry.py`` (root side).

Run (inside agent container):
    docker run --rm \\
        -v "/path/agentic:/app" \\
        -v "/path/graph_db:/app/graph_db:ro" \\
        -v "/path/knowledge_base:/app/knowledge_base:ro" \\
        -w /app redamon-agent python -m unittest \\
        tests.test_llm_retry -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# Synthetic SDK exception classes — names match the real SDK class names
# because is_transient_llm_error matches on ``type(exc).__name__``.

class APIConnectionError(Exception):
    pass


class APITimeoutError(APIConnectionError):
    pass


class RateLimitError(Exception):
    pass


class InternalServerError(Exception):
    pass


class _PermanentAuthError(Exception):
    """Non-transient; must NOT trigger retry."""


class _ThinkingUnsupportedError(Exception):
    """Synthetic Ollama 400 for a model without the thinking capability."""


_VALID_RESPONSE = MagicMock(content='{"thought":"t","reasoning":"r","action":"complete"}')


class RetryLLMCallTests(unittest.IsolatedAsyncioTestCase):
    """Direct tests of ``retry_llm_call``.

    Patches ``asyncio.sleep`` in the llm_retry module so backoff is
    instantaneous and we can assert exact ``await_count`` for both the
    LLM and the sleep — that double-count is the only way to lock the
    "no wasted sleep after the final attempt" bug fix in place.
    """

    async def _invoke(self, mock_llm, *, max_attempts: int = 3):
        from orchestrator_helpers.llm_retry import retry_llm_call
        with patch(
            "orchestrator_helpers.llm_retry.asyncio.sleep",
            new_callable=AsyncMock,
        ) as mock_sleep:
            try:
                result = await retry_llm_call(
                    mock_llm, ["msg"],
                    label="test", max_attempts=max_attempts,
                )
                return result, mock_sleep, None
            except Exception as exc:
                return None, mock_sleep, exc

    # ----- Happy path -----

    async def test_first_attempt_success_no_retry(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=_VALID_RESPONSE)
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertIsNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 1)
        self.assertEqual(sleep.await_count, 0)

    # ----- Transient retry then success -----

    async def test_one_transient_then_success(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("blip"),
            _VALID_RESPONSE,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertIsNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 2)
        self.assertEqual(sleep.await_count, 1)

    async def test_two_transient_then_success(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("first"),
            RateLimitError("second"),
            _VALID_RESPONSE,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertIsNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        self.assertEqual(sleep.await_count, 2)

    # ----- Exhaustion: re-raise last exception -----

    async def test_three_transient_failures_raise_last(self):
        last = APIConnectionError("third")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("first"),
            APIConnectionError("second"),
            last,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIsNone(result)
        self.assertIs(exc, last,
                      "exhaustion must re-raise the LAST exception unchanged")
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        # BUG GUARD: no sleep after the FINAL attempt.
        self.assertEqual(sleep.await_count, 2,
                         "must not sleep after the final attempt")

    # ----- Non-transient: immediate re-raise -----

    async def test_non_transient_reraises_immediately(self):
        permanent = _PermanentAuthError("Invalid API key")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=permanent)
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIsNone(result)
        self.assertIs(exc, permanent,
                      "non-transient must propagate unchanged")
        self.assertEqual(mock_llm.ainvoke.await_count, 1,
                         "non-transient must NOT retry")
        self.assertEqual(sleep.await_count, 0)

    # ----- Max attempts is honored -----

    async def test_max_attempts_1_means_no_retry(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=APIConnectionError("once"))
        result, sleep, exc = await self._invoke(mock_llm, max_attempts=1)
        self.assertIsNotNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 1)
        self.assertEqual(sleep.await_count, 0,
                         "max_attempts=1 — no inter-attempt sleeps possible")

    async def test_max_attempts_5_allows_5_attempts(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=APIConnectionError("repeated"))
        result, sleep, exc = await self._invoke(mock_llm, max_attempts=5)
        self.assertIsNotNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 5)
        self.assertEqual(sleep.await_count, 4)

    # ----- Mixed transient + non-transient (transient first, then permanent) -----

    async def test_transient_then_permanent_reraises_permanent(self):
        permanent = _PermanentAuthError("auth bug after the blip")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("transient"),
            permanent,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(exc, permanent)
        self.assertEqual(mock_llm.ainvoke.await_count, 2,
                         "second attempt fires after transient, then permanent breaks")
        self.assertEqual(sleep.await_count, 1)

    # ----- Type classification used for retry decision (regression for
    # PR-#111 classifier optimization) -----

    async def test_internal_server_error_classified_transient_and_retried(self):
        """Bare InternalServerError with no transient keyword in the message
        must still be retried — proves type-MRO classification is wired
        through retry_llm_call (and not just keyword matching)."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            InternalServerError("Server returned an error"),
            _VALID_RESPONSE,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertEqual(mock_llm.ainvoke.await_count, 2)

    async def test_max_tokens_50000_is_not_retried(self):
        """Numeric-substring bug guard: '500' inside '50000' must NOT
        classify as transient."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=Exception(
            "max_tokens: 50000 exceeded model context window"
        ))
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIsNotNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 1,
                         "token-limit error must fail fast — no retry")
        self.assertEqual(sleep.await_count, 0)


class ReasoningSelfHealTests(unittest.IsolatedAsyncioTestCase):
    """A non-thinking model that rejects ``reasoning_effort`` must self-heal:
    drop the param and retry once, so a provider that enabled reasoning on a
    model without the thinking capability keeps working instead of failing
    every call. Mirrors the existing ``temperature`` self-heal."""

    async def _invoke(self, mock_llm, *, max_attempts: int = 3):
        from orchestrator_helpers.llm_retry import retry_llm_call
        with patch(
            "orchestrator_helpers.llm_retry.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            try:
                return await retry_llm_call(
                    mock_llm, ["msg"], label="test", max_attempts=max_attempts,
                ), None
            except Exception as exc:
                return None, exc

    def _healable_llm(self, *, healed_ainvoke):
        """A mock LLM whose ``model_copy`` yields a healed clone."""
        healed = MagicMock()
        healed.ainvoke = healed_ainvoke
        llm = MagicMock()
        llm.model_copy = MagicMock(return_value=healed)
        return llm, healed

    async def test_thinking_unsupported_heals_and_retries(self):
        llm, healed = self._healable_llm(
            healed_ainvoke=AsyncMock(return_value=_VALID_RESPONSE),
        )
        llm.ainvoke = AsyncMock(
            side_effect=_ThinkingUnsupportedError(
                '"gemma3:latest" does not support thinking'
            )
        )
        result, exc = await self._invoke(llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertIsNone(exc)
        # Original tried once, then the reasoning-stripped clone succeeded.
        self.assertEqual(llm.ainvoke.await_count, 1)
        self.assertEqual(healed.ainvoke.await_count, 1)
        llm.model_copy.assert_called_once_with(update={"reasoning_effort": None})

    async def test_thinking_heal_only_attempted_once(self):
        # The stripped clone STILL raises the thinking error (pathological):
        # we must not loop re-healing; after one heal the error is classified
        # non-transient and re-raised.
        persistent = _ThinkingUnsupportedError('"x" does not support thinking')
        llm, healed = self._healable_llm(
            healed_ainvoke=AsyncMock(side_effect=persistent),
        )
        llm.ainvoke = AsyncMock(side_effect=persistent)
        result, exc = await self._invoke(llm)
        self.assertIs(exc, persistent)
        self.assertEqual(llm.ainvoke.await_count, 1)
        self.assertEqual(healed.ainvoke.await_count, 1,
                         "reasoning heal must be attempted exactly once")

    async def test_helpers_classify_and_strip(self):
        from orchestrator_helpers.llm_retry import (
            _is_thinking_unsupported_error,
            _without_reasoning_effort,
        )
        self.assertTrue(_is_thinking_unsupported_error(
            _ThinkingUnsupportedError('"m" does not support thinking')))
        # A plain thinking mention without an "unsupported" hint is NOT a match.
        self.assertFalse(_is_thinking_unsupported_error(
            Exception("thinking budget exceeded")))
        # Temperature errors are handled by the other heal, not this one.
        self.assertFalse(_is_thinking_unsupported_error(
            Exception("temperature is not supported")))

        llm = MagicMock()
        clone = MagicMock()
        llm.model_copy = MagicMock(return_value=clone)
        self.assertIs(_without_reasoning_effort(llm), clone)
        llm.model_copy.assert_called_once_with(update={"reasoning_effort": None})


# Real 400 error strings observed per provider for a temperature our default of
# 0 violates. Each MUST classify as an auto-recoverable temperature error so the
# self-heal (drop temperature, retry) fires. Sources verified against provider
# docs / issue trackers (2026-07).
_PROVIDER_TEMPERATURE_ERRORS = {
    "openai_o_series": (
        "Error code: 400 - {'error': {'message': \"Unsupported value: "
        "'temperature' does not support 0 with this model. Only the default (1) "
        "value is supported.\", 'type': 'invalid_request_error'}}"
    ),
    "openai_gpt5": (
        "Unsupported value: 'temperature' does not support 0.0 with this model. "
        "Only the default (1) value is supported."
    ),
    "kimi_k3": (
        "Error code: 400 - {'error': {'message': 'invalid temperature: only 1 "
        "is allowed for this model', 'type': 'invalid_request_error'}}"
    ),
    "deepseek_reasoner": (
        "deepseek-reasoner does not support the parameter `temperature`"
    ),
    "bedrock_claude_deprecated": (
        "ValidationException: temperature is deprecated for this model"
    ),
    "bedrock_thinking": (
        "ValidationException: temperature may only be set to 1 when thinking "
        "is enabled"
    ),
    "glm_thinking": (
        "Error code: 400 - temperature must be greater than 0 and less than or "
        "equal to 1"
    ),
    "qwen_thinking": (
        "InvalidParameter: temperature must be greater than 0 for thinking mode"
    ),
    "anthropic_direct": (
        "temperature is deprecated for this model"
    ),
    # API version 2026-10-21 (anthropic SDK 2.x), every model, observed 2026-11.
    "anthropic_api_2026_10_21": (
        "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
        "'message': 'temperature: Extra inputs are not permitted'}, 'request_id': 'req_x'}"
    ),
}

# Provider errors that are NOT about temperature and MUST NOT be falsely healed.
_NON_TEMPERATURE_ERRORS = {
    "auth": "Error code: 401 - invalid api key",
    "model_not_found": "Error code: 404 - model `foo` does not exist",
    "context_window": "max_tokens: 50000 exceeded model context window",
    "content_filter": "content was blocked by the safety filter",
    "another_extra_input": "top_k: Extra inputs are not permitted",
}


class ProviderTemperatureSelfHealTests(unittest.IsolatedAsyncioTestCase):
    """Proof that the temperature self-heal covers every provider RedAmon
    supports. The classifier must fire on each real 400 string, the heal helper
    must return a temperature-stripped clone, and retry_llm_call must recover."""

    def test_every_provider_temperature_error_classifies(self):
        from orchestrator_helpers.llm_retry import _is_temperature_unsupported_error
        for name, msg in _PROVIDER_TEMPERATURE_ERRORS.items():
            with self.subTest(provider=name):
                self.assertTrue(
                    _is_temperature_unsupported_error(Exception(msg)),
                    f"{name}: {msg!r} must classify as a temperature error",
                )

    def test_non_temperature_errors_not_falsely_healed(self):
        from orchestrator_helpers.llm_retry import _is_temperature_unsupported_error
        for name, msg in _NON_TEMPERATURE_ERRORS.items():
            with self.subTest(kind=name):
                self.assertFalse(
                    _is_temperature_unsupported_error(Exception(msg)),
                    f"{name}: {msg!r} must NOT be treated as a temperature error",
                )

    def test_heal_helper_strips_temperature_for_each_provider(self):
        from orchestrator_helpers.llm_retry import heal_llm_param_error
        for name, msg in _PROVIDER_TEMPERATURE_ERRORS.items():
            with self.subTest(provider=name):
                clone = MagicMock()
                llm = MagicMock()
                llm.model_copy = MagicMock(return_value=clone)
                healed = heal_llm_param_error(llm, Exception(msg))
                self.assertIsNotNone(healed, f"{name}: expected a heal")
                healed_llm, key = healed
                self.assertIs(healed_llm, clone)
                self.assertEqual(key, "temperature")
                llm.model_copy.assert_called_once_with(update={"temperature": None})

    def test_heal_helper_respects_already_healed(self):
        from orchestrator_helpers.llm_retry import heal_llm_param_error
        llm = MagicMock()
        llm.model_copy = MagicMock(return_value=MagicMock())
        healed = heal_llm_param_error(
            llm,
            Exception("invalid temperature: only 1 is allowed"),
            already_healed=frozenset({"temperature"}),
        )
        self.assertIsNone(healed, "must not re-heal an already-stripped param")

    async def test_retry_llm_call_recovers_for_representative_providers(self):
        from orchestrator_helpers.llm_retry import retry_llm_call
        # Two representative failure shapes: a reject (OpenAI o-series) and a
        # range constraint (GLM thinking). Both must heal and succeed.
        for msg in (
            _PROVIDER_TEMPERATURE_ERRORS["openai_o_series"],
            _PROVIDER_TEMPERATURE_ERRORS["glm_thinking"],
        ):
            with self.subTest(msg=msg[:40]):
                clone = MagicMock()
                clone.ainvoke = AsyncMock(return_value=_VALID_RESPONSE)
                llm = MagicMock()
                llm.ainvoke = AsyncMock(side_effect=Exception(msg))
                llm.model_copy = MagicMock(return_value=clone)
                with patch(
                    "orchestrator_helpers.llm_retry.asyncio.sleep",
                    new_callable=AsyncMock,
                ):
                    result = await retry_llm_call(llm, ["m"], label="t")
                self.assertIs(result, _VALID_RESPONSE)
                self.assertEqual(llm.ainvoke.await_count, 1)
                self.assertEqual(clone.ainvoke.await_count, 1)


class SelfHealPrecisionAndSequenceTests(unittest.IsolatedAsyncioTestCase):
    """Guards for two subtle failure modes in the shared self-heal."""

    def test_temperature_range_error_mentioning_thinking_is_not_a_thinking_error(self):
        """REGRESSION (precision): Qwen's "temperature must be greater than 0 for
        thinking mode" contains the word 'thinking' but is a TEMPERATURE error.
        The thinking classifier must NOT match it (else, once temperature is
        healed, we'd wrongly drop reasoning_effort and never fix the real
        problem). This is why the two classifiers use separate hint sets."""
        from orchestrator_helpers.llm_retry import (
            _is_temperature_unsupported_error,
            _is_thinking_unsupported_error,
        )
        qwen = Exception("temperature must be greater than 0 for thinking mode")
        self.assertTrue(_is_temperature_unsupported_error(qwen))
        self.assertFalse(
            _is_thinking_unsupported_error(qwen),
            "a temperature-range error must not be classified as a thinking error",
        )

    def test_heal_does_not_fall_through_to_reasoning_for_temperature_error(self):
        """With temperature already healed, a temperature-worded error that
        also says 'thinking' must yield NO further heal — not a bogus
        reasoning_effort strip."""
        from orchestrator_helpers.llm_retry import heal_llm_param_error
        llm = MagicMock()
        llm.model_copy = MagicMock(return_value=MagicMock())
        healed = heal_llm_param_error(
            llm,
            Exception("temperature may only be set to 1 when thinking is enabled"),
            already_healed=frozenset({"temperature"}),
        )
        self.assertIsNone(healed)
        llm.model_copy.assert_not_called()

    async def test_retry_heals_temperature_then_reasoning_in_one_attempt(self):
        """Two distinct params rejected in sequence (temperature, then
        reasoning_effort) must both heal within the retry, ending in success."""
        from orchestrator_helpers.llm_retry import retry_llm_call

        clone2 = MagicMock()   # after reasoning stripped
        clone2.ainvoke = AsyncMock(return_value=_VALID_RESPONSE)

        clone1 = MagicMock()   # after temperature stripped
        clone1.ainvoke = AsyncMock(side_effect=Exception(
            '"m" does not support thinking'
        ))
        clone1.model_copy = MagicMock(return_value=clone2)

        llm = MagicMock()
        llm.ainvoke = AsyncMock(side_effect=Exception(
            "invalid temperature: only 1 is allowed for this model"
        ))
        llm.model_copy = MagicMock(return_value=clone1)

        with patch(
            "orchestrator_helpers.llm_retry.asyncio.sleep", new_callable=AsyncMock,
        ):
            result = await retry_llm_call(llm, ["m"], label="t")

        self.assertIs(result, _VALID_RESPONSE)
        llm.model_copy.assert_called_once_with(update={"temperature": None})
        clone1.model_copy.assert_called_once_with(update={"reasoning_effort": None})
        self.assertEqual(clone2.ainvoke.await_count, 1)

    async def test_heal_not_retried_when_clone_cannot_be_made(self):
        """If both model_copy AND copy.copy fail, heal returns None and the
        error is classified normally instead of raising inside the healer."""
        from orchestrator_helpers.llm_retry import retry_llm_call

        class _Uncopyable:
            temperature = 0
            def model_copy(self, *a, **k):
                raise RuntimeError("no model_copy")
            def __copy__(self):
                raise RuntimeError("no copy either")
            async def ainvoke(self, *a, **k):
                raise Exception("invalid temperature: only 1 is allowed")

        llm = _Uncopyable()
        with patch(
            "orchestrator_helpers.llm_retry.asyncio.sleep", new_callable=AsyncMock,
        ):
            with self.assertRaises(Exception) as ctx:
                await retry_llm_call(llm, ["m"], label="t", max_attempts=1)
        self.assertIn("temperature", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
