"""A provider's rate limit is waited out, for every provider and every chat call site.

A 429 means the account's per-minute window is full; the SDKs' own retries are
over in about a second, so a chat run used to fail at the first busy minute
(the final summary had no retry at all). These tests pin:

- which 429 is which, from each provider's real error shape: a rate limit
  (waited out), no credit / a daily quota and one request over the limit
  (never waited for), and Bedrock's ThrottlingException, which no rule matched;
- how long to wait: the provider's own hint, else growing waits, within a
  budget that rate limits use instead of ``max_attempts``;
- that the summary, Deep Think, the scope guardrail, the classifier and
  text-to-Cypher use it, and that a summary which still fails ends the run
  with a fallback report instead of an error;
- that each wait reaches the drawer as a ``rate_limit_wait`` frame, never saved.
"""
from __future__ import annotations

import asyncio
import os
import unittest
from unittest import mock

import httpx
from langchain_core.messages import AIMessage

import orchestrator as orchestrator_mod
import websocket_api
from agent_context import current_llm_wait_listener
from agent_in_the_loop.errors import LoopNoDriver
from agent_in_the_loop.purpose import llm_purpose
from llm_builder import provider_error_details, provider_error_kind, provider_status
from orchestrator_helpers import llm_retry
from orchestrator_helpers.llm_retry import (
    RateLimitWaiter,
    ainvoke_through_rate_limits,
    describe_llm_failure,
    is_transient_llm_error,
    provider_retry_hint_s,
    rate_limit_budget_s,
    retry_llm_call,
)
from websocket_api import MessageType, StreamingCallback, WebSocketConnection

SECRET = "sk-live-LEAKED-FRAGMENT"
_REQUEST = httpx.Request("POST", "https://provider.invalid/v1/chat/completions")


def _response(status=429, headers=None):
    return httpx.Response(status, request=_REQUEST, headers=headers or {})


# ---------------------------------------------------------------------------
# Provider error shapes, built with the provider SDKs the agent image ships
# ---------------------------------------------------------------------------

def openai_429(message="Rate limit reached for gpt-4o on tokens per min (TPM): "
                       "Limit 30000, Used 29000, Requested 3500. Please try again in 6.5s.",
               code="rate_limit_exceeded", headers=None):
    import openai
    return openai.RateLimitError(
        f"Error code: 429 - {{'error': {{'message': '{message}', 'code': '{code}'}}}}",
        response=_response(429, headers), body={"message": message, "code": code})


def langchain_openai_429(**kw):
    """What the agent really catches: langchain-openai re-raises the SDK error."""
    inner = openai_429(**kw)
    try:
        from langchain_openai.chat_models.base import OpenAIRateLimitError
    except ImportError:                                           # older langchain-openai
        return inner
    try:
        raise OpenAIRateLimitError(message=inner.message, response=inner.response,
                                   body=inner.body) from inner
    except OpenAIRateLimitError as exc:
        return exc


def anthropic_429(retry_after="7"):
    import anthropic
    return anthropic.RateLimitError(
        "rate_limit_error", response=_response(429, {"retry-after": retry_after}),
        body={"type": "error", "error": {"type": "rate_limit_error", "message":
              "Number of request tokens has exceeded your per-minute rate limit"}})


def bedrock_error(code, status, message):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": message},
                        "ResponseMetadata": {"HTTPStatusCode": status}}, "Converse")


def gemini_429(quota_id="GenerateRequestsPerMinutePerProjectPerModel-FreeTier"):
    from google.genai import errors
    return errors.ClientError(429, {"error": {
        "code": 429, "status": "RESOURCE_EXHAUSTED",
        "message": "You exceeded your current quota. Please retry in 17.282s.",
        "details": [
            {"@type": "type.googleapis.com/google.rpc.QuotaFailure",
             "violations": [{"quotaId": quota_id}]},
            {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "17s"},
        ]}})


class StatusError(Exception):
    """An OpenAI-compatible provider's error as the SDK surfaces it: a status, a body."""

    def __init__(self, status, text):
        super().__init__(text)
        self.status_code = status


RATE_LIMITED = {
    "openai": lambda: openai_429(),
    "openai via langchain": lambda: langchain_openai_429(),
    "anthropic": lambda: anthropic_429(),
    "bedrock throttling": lambda: bedrock_error(
        "ThrottlingException", 429, "Too many requests, please wait before trying again."),
    "gemini per minute": lambda: gemini_429(),
    "kimi": lambda: StatusError(429, "Error code: 429 - {'error': {'type': 'rate_limit_reached_error'}}"),
    "deepseek": lambda: StatusError(429, "Rate Limit Reached"),
    "mistral": lambda: StatusError(429, "Requests rate limit exceeded"),
    "qwen, no status": lambda: Exception("Throttling.RateQuota: Requests rate limit exceeded"),
}

NEVER_CLEARS = {
    "openai no credit": (lambda: openai_429(
        message="You exceeded your current quota, please check your plan and billing details.",
        code="insufficient_quota"), "quota_exhausted"),
    "openai requests per day": (lambda: openai_429(
        message="Rate limit reached for gpt-4o on requests per day (RPD): Limit 10000, Used 10000."),
        "quota_exhausted"),
    "openai request too large": (lambda: openai_429(
        message="Request too large for gpt-4o on tokens per min (TPM): Limit 30000, "
                "Requested 35000. The input or output tokens must be reduced."), "request_too_large"),
    "gemini daily quota": (lambda: gemini_429("GenerateRequestsPerDayPerProjectPerModel-FreeTier"),
                           "quota_exhausted"),
    "kimi account quota": (lambda: StatusError(
        429, "Error code: 429 - {'error': {'type': 'exceeded_current_quota_error'}}"), "quota_exhausted"),
    "glm insufficient balance": (lambda: StatusError(
        429, "Error code: 429 - {'error': {'code': '1113', 'message': "
             "'Insufficient balance or no resource package. Please recharge.'}}"), "quota_exhausted"),
    "openrouter free daily": (lambda: StatusError(
        429, "Rate limit exceeded: free-models-per-day"), "quota_exhausted"),
}


def _sdk(factory):
    try:
        return factory()
    except ImportError as exc:                                    # pragma: no cover
        raise unittest.SkipTest(f"provider SDK missing from the image: {exc}")


class ProviderErrorKindTests(unittest.TestCase):
    def test_each_providers_rate_limit_is_waited_for(self):
        for name, factory in RATE_LIMITED.items():
            with self.subTest(provider=name):
                exc = _sdk(factory)
                self.assertEqual(provider_error_kind(exc), "rate_limited")
                self.assertTrue(is_transient_llm_error(exc))

    def test_a_429_that_no_wait_clears_is_not_retried(self):
        for name, (factory, kind) in NEVER_CLEARS.items():
            with self.subTest(provider=name):
                exc = _sdk(factory)
                self.assertEqual(provider_error_kind(exc), kind)
                self.assertFalse(is_transient_llm_error(exc))

    def test_bedrock_throttling_was_not_transient_before(self):
        # Regression: its text names no status and no rate-limit phrase the old
        # classifier knew, so not even the think step retried it.
        exc = _sdk(RATE_LIMITED["bedrock throttling"])
        self.assertNotIn("429", str(exc))
        self.assertEqual(provider_status(exc), 429)
        self.assertTrue(is_transient_llm_error(exc))

    def test_a_bedrock_503_is_transient_by_its_status(self):
        exc = _sdk(lambda: bedrock_error("ServiceUnavailableException", 503, "Service is unavailable."))
        self.assertIsNone(provider_error_kind(exc))
        self.assertTrue(is_transient_llm_error(exc))

    def test_other_failures_are_no_kind_of_429(self):
        for exc in (StatusError(401, "invalid api key"), StatusError(400, "context_length_exceeded"),
                    Exception("max_tokens: 50000 exceeded model context window")):
            with self.subTest(exc=str(exc)):
                self.assertIsNone(provider_error_kind(exc))

    def test_an_aws_throttling_code_is_a_rate_limit_whatever_its_status(self):
        exc = _sdk(lambda: bedrock_error("ThrottlingException", 400, "Rate exceeded"))
        self.assertEqual(provider_error_kind(exc), "rate_limited")

    def test_an_agent_in_the_loop_error_is_never_a_rate_limit(self):
        exc = LoopNoDriver()
        exc.status_code = 429
        self.assertIsNone(provider_error_kind(exc))
        self.assertFalse(is_transient_llm_error(exc))


class ProviderErrorDetailsTests(unittest.TestCase):
    def test_the_kind_and_the_wait_join_the_class_and_status(self):
        exc = _sdk(lambda: openai_429(message=f"limit for key {SECRET}"))
        exc.rate_limit_waited_s = 118
        details = provider_error_details(exc)
        self.assertEqual(details, {"provider_status": 429, "error_class": "RateLimitError",
                                   "provider_error_kind": "rate_limited", "rate_limit_waited_s": 118})
        self.assertNotIn(SECRET, repr(details))

    def test_no_kind_without_a_429(self):
        self.assertEqual(provider_error_details(StatusError(503, "busy")),
                         {"provider_status": 503, "error_class": "StatusError"})

    def test_describe_uses_fixed_words_only(self):
        exc = _sdk(lambda: openai_429(message=f"key {SECRET}", code="insufficient_quota"))
        text = describe_llm_failure(exc)
        self.assertEqual(text, "no credit or quota left on the model provider account, provider HTTP 429")
        exc = _sdk(lambda: openai_429(message=f"key {SECRET}"))
        exc.rate_limit_waited_s = 120
        self.assertEqual(describe_llm_failure(exc), "the model provider's rate limit, provider HTTP 429, "
                                                    "still refused after waiting 120 s")
        self.assertEqual(describe_llm_failure(RuntimeError(SECRET)), "RuntimeError")


class RetryHintTests(unittest.TestCase):
    def test_headers(self):
        cases = [
            ({"retry-after": "7"}, 7.0),
            ({"retry-after-ms": "1500"}, 1.5),
            ({"x-ratelimit-reset-requests": "120ms", "x-ratelimit-reset-tokens": "6m0s"}, 360.0),
            ({"x-ratelimit-reset-tokens": "1m30.5s"}, 90.5),
        ]
        for headers, expected in cases:
            with self.subTest(headers=headers):
                exc = StatusError(429, "slow down")
                exc.response = _response(429, headers)
                self.assertAlmostEqual(provider_retry_hint_s(exc), expected)

    def test_an_http_date(self):
        from email.utils import format_datetime
        from datetime import datetime, timedelta, timezone
        exc = StatusError(429, "slow down")
        exc.response = _response(429, {"retry-after": format_datetime(
            datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)})
        self.assertTrue(25 <= provider_retry_hint_s(exc) <= 31)

    def test_messages(self):
        self.assertAlmostEqual(provider_retry_hint_s(_sdk(openai_429)), 6.5)
        self.assertAlmostEqual(provider_retry_hint_s(_sdk(gemini_429)), 17.282)
        self.assertAlmostEqual(provider_retry_hint_s(Exception("Please try again in 120ms.")), 0.12)
        self.assertAlmostEqual(provider_retry_hint_s(Exception("{'retryDelay': '21s'}")), 21.0)
        self.assertEqual(provider_retry_hint_s(_sdk(anthropic_429)), 7.0)

    def test_retry_after_then_the_message_then_the_reset_headers(self):
        # The reset headers say when a bucket is full again; the message says
        # when this request fits, which is sooner.
        resets = {"x-ratelimit-reset-tokens": "6m0s"}
        self.assertAlmostEqual(provider_retry_hint_s(_sdk(lambda: openai_429(headers=resets))), 6.5)
        both = dict(resets, **{"retry-after": "3"})
        self.assertEqual(provider_retry_hint_s(_sdk(lambda: openai_429(headers=both))), 3.0)

    def test_a_value_that_is_not_a_finite_number_is_no_hint(self):
        for value in ("nan", "inf"):
            with self.subTest(value=value):
                exc = StatusError(429, "Rate Limit Reached")
                exc.response = _response(429, {"retry-after": value})
                self.assertIsNone(provider_retry_hint_s(exc))
        exc = _sdk(lambda: openai_429(headers={"retry-after": "nan"}))
        self.assertAlmostEqual(provider_retry_hint_s(exc), 6.5)

    def test_none_when_the_provider_does_not_say(self):
        self.assertIsNone(provider_retry_hint_s(StatusError(429, "Rate Limit Reached")))
        exc = StatusError(429, "x")
        exc.response = mock.MagicMock()          # never read as a header value
        self.assertIsNone(provider_retry_hint_s(exc))


def _no_jitter(low, high):
    return high


class _PatchedSleep(unittest.IsolatedAsyncioTestCase):
    """Records each sleep instead of sleeping, and takes the upper jitter."""

    async def asyncSetUp(self):
        self.sleeps = []

        async def sleep(seconds):
            self.sleeps.append(seconds)
        for target, new in (("orchestrator_helpers.llm_retry.asyncio.sleep", sleep),
                            ("orchestrator_helpers.llm_retry.random.uniform", _no_jitter)):
            patcher = mock.patch(target, new=new)
            patcher.start()
            self.addCleanup(patcher.stop)


class WaiterTests(_PatchedSleep):
    async def test_waits_grow_and_stop_at_the_budget(self):
        waiter = RateLimitWaiter("t", budget_s=120)
        exc = StatusError(429, "Rate Limit Reached")
        while await waiter.wait(exc):
            pass
        self.assertEqual(self.sleeps, [4, 8, 16, 32, 32])
        self.assertEqual(exc.rate_limit_waited_s, 92)

    async def test_the_providers_hint_is_the_wait(self):
        waiter = RateLimitWaiter("t", budget_s=120)
        self.assertTrue(await waiter.wait(_sdk(anthropic_429)))
        self.assertAlmostEqual(self.sleeps[0], 7 * 1.15)

    async def test_a_hint_beyond_the_budget_gives_up_at_once(self):
        waiter = RateLimitWaiter("t", budget_s=120)
        self.assertFalse(await waiter.wait(_sdk(lambda: anthropic_429(retry_after="3600"))))
        self.assertEqual(self.sleeps, [])

    async def test_the_budget_counts_time_the_sdk_spent_retrying(self):
        # Anthropic's SDK waits each Retry-After itself, five times, before a
        # 429 reaches us: a 20 s budget that counted only our sleeps ran 116 s.
        clock = [1000.0]
        with mock.patch("orchestrator_helpers.llm_retry.time.monotonic", lambda: clock[0]):
            waiter = RateLimitWaiter("t", budget_s=20)
            exc = StatusError(429, "Rate Limit Reached")
            clock[0] += 25                       # the first attempt: the SDK's own retries
            self.assertFalse(await waiter.wait(exc))
        self.assertEqual(self.sleeps, [])
        self.assertEqual(exc.rate_limit_waited_s, 25)

    async def test_a_budget_that_is_not_a_number_falls_back_to_the_default(self):
        for raw in ("nan", "inf", "-inf"):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"LLM_RATE_LIMIT_MAX_WAIT_S": raw}):
                self.assertEqual(rate_limit_budget_s(), 120.0)
                self.assertTrue(await RateLimitWaiter("t").wait(StatusError(429, "x")))

    async def test_retries_are_capped(self):
        waiter = RateLimitWaiter("t", budget_s=10_000)
        exc = _sdk(lambda: anthropic_429(retry_after="1"))
        while await waiter.wait(exc):
            pass
        self.assertEqual(len(self.sleeps), 10)

    async def test_the_budget_comes_from_the_environment(self):
        with mock.patch.dict(os.environ, {"LLM_RATE_LIMIT_MAX_WAIT_S": "30"}):
            self.assertEqual(rate_limit_budget_s(), 30.0)
            self.assertEqual(RateLimitWaiter("t").budget_s, 30.0)
        with mock.patch.dict(os.environ, {"LLM_RATE_LIMIT_MAX_WAIT_S": "0"}):
            self.assertFalse(await RateLimitWaiter("t").wait(StatusError(429, "x")))
        with mock.patch.dict(os.environ, {"LLM_RATE_LIMIT_MAX_WAIT_S": "soon"}):
            self.assertEqual(rate_limit_budget_s(), 120.0)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LLM_RATE_LIMIT_MAX_WAIT_S", None)
            self.assertEqual(rate_limit_budget_s(), 120.0)


class _Scripted:
    """A chat model answering each call with the next scripted exception or text."""

    def __init__(self, *script, delay=0.0):
        self.script, self.calls, self.delay = list(script), 0, delay

    async def ainvoke(self, _messages):
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, BaseException):
            raise item
        return AIMessage(content=item)


class RetryLlmCallTests(_PatchedSleep):
    async def test_rate_limits_do_not_use_up_max_attempts(self):
        llm = _Scripted(*[_sdk(openai_429) for _ in range(5)], "ok")
        result = await retry_llm_call(llm, ["m"], label="t", max_attempts=3)
        self.assertEqual(result.content, "ok")
        self.assertEqual(llm.calls, 6)
        self.assertEqual(len(self.sleeps), 5)

    async def test_it_gives_up_at_the_budget_and_says_how_long_it_waited(self):
        llm = _Scripted(StatusError(429, "Rate Limit Reached"))
        with self.assertRaises(StatusError) as raised:
            await retry_llm_call(llm, ["m"], label="t", rate_limit_budget_s=120)
        self.assertEqual(llm.calls, 6)
        self.assertEqual(raised.exception.rate_limit_waited_s, 92)
        self.assertEqual(provider_error_details(raised.exception)["rate_limit_waited_s"], 92)

    async def test_no_credit_and_too_large_are_not_retried(self):
        for name in ("openai no credit", "openai request too large", "gemini daily quota"):
            with self.subTest(case=name):
                self.sleeps.clear()
                llm = _Scripted(_sdk(NEVER_CLEARS[name][0]), "ok")
                with self.assertRaises(Exception):
                    await retry_llm_call(llm, ["m"], label="t")
                self.assertEqual((llm.calls, self.sleeps), (1, []))

    async def test_a_non_429_status_that_mentions_a_rate_limit_is_not_waited_for(self):
        refused = StatusError(403, "Too many requests from this network, request blocked")
        self.assertIsNone(provider_error_kind(refused))
        self.assertIsNone(provider_error_kind(StatusError(400, "rate_limit: unknown parameter")))
        llm = _Scripted(refused, "ok")
        with self.assertRaises(StatusError):
            await retry_llm_call(llm, ["m"], label="t")
        self.assertEqual((llm.calls, self.sleeps), (1, []))

    async def test_bedrock_throttling_is_retried(self):
        llm = _Scripted(_sdk(RATE_LIMITED["bedrock throttling"]), "ok")
        self.assertEqual((await retry_llm_call(llm, ["m"], label="t")).content, "ok")
        self.assertEqual(llm.calls, 2)

    async def test_a_zero_budget_reports_the_rate_limit_at_once(self):
        llm = _Scripted(_sdk(openai_429), "ok")
        with self.assertRaises(Exception):
            await retry_llm_call(llm, ["m"], label="t", max_attempts=1, rate_limit_budget_s=0)
        self.assertEqual((llm.calls, self.sleeps), (1, []))

    async def test_other_transient_errors_keep_their_attempt_count(self):
        class APIConnectionError(Exception):
            pass
        llm = _Scripted(APIConnectionError("a"), _sdk(openai_429), APIConnectionError("b"),
                        _sdk(openai_429), APIConnectionError("c"))
        with self.assertRaises(APIConnectionError):
            await retry_llm_call(llm, ["m"], label="t", max_attempts=3)
        self.assertEqual(llm.calls, 5)

    async def test_each_wait_reaches_the_listener_with_its_purpose(self):
        heard = mock.AsyncMock()
        token = current_llm_wait_listener.set(heard)
        try:
            with llm_purpose("report"):
                await retry_llm_call(_Scripted(_sdk(anthropic_429), "ok"), ["m"], label="t")
        finally:
            current_llm_wait_listener.reset(token)
        heard.assert_awaited_once_with(seconds=8, retry=1, purpose="report")

    async def test_a_failing_listener_does_not_fail_the_call(self):
        token = current_llm_wait_listener.set(mock.AsyncMock(side_effect=RuntimeError("socket gone")))
        try:
            result = await retry_llm_call(_Scripted(_sdk(openai_429), "ok"), ["m"], label="t")
        finally:
            current_llm_wait_listener.reset(token)
        self.assertEqual(result.content, "ok")

    async def test_an_agent_in_the_loop_step_is_never_waited_for(self):
        llm = _Scripted(LoopNoDriver(), "ok")
        with self.assertRaises(LoopNoDriver):
            await retry_llm_call(llm, ["m"], label="t")
        self.assertEqual((llm.calls, self.sleeps), (1, []))

    async def test_through_rate_limits_waits_only_for_a_rate_limit(self):
        waiter = RateLimitWaiter("t", budget_s=120)
        llm = _Scripted(_sdk(openai_429), "ok")
        self.assertEqual((await ainvoke_through_rate_limits(llm, ["m"], waiter=waiter)).content, "ok")
        llm = _Scripted(RuntimeError("bad answer"), "ok")
        with self.assertRaises(RuntimeError):
            await ainvoke_through_rate_limits(llm, ["m"], waiter=waiter)
        self.assertEqual(llm.calls, 1)

    async def test_one_waiter_bounds_a_whole_loop(self):
        waiter = RateLimitWaiter("t", budget_s=120)
        always = _Scripted(StatusError(429, "Rate Limit Reached"))
        for _ in range(3):
            with self.assertRaises(StatusError):
                await ainvoke_through_rate_limits(always, ["m"], waiter=waiter)
        self.assertEqual(sum(self.sleeps), 92)


# ---------------------------------------------------------------------------
# Call sites
# ---------------------------------------------------------------------------

import importlib  # noqa: E402

report_mod = importlib.import_module("orchestrator_helpers.nodes.generate_response_node")


class ReportTests(_PatchedSleep):
    STATE = {
        "execution_trace": [{"success": True, "phase": "informational"},
                            {"success": False, "phase": "informational"}],
        "original_objective": "list the assets",
        "completion_reason": "Task completed successfully",
    }
    CONFIG = {"configurable": {"user_id": "u1", "project_id": "p1", "thread_id": "s1"}}

    async def run_report(self, llm):
        with mock.patch.object(report_mod.chain_graph, "fire_update_chain_status") as chain:
            out = await report_mod.generate_response_node(
                dict(self.STATE), self.CONFIG, llm=llm, streaming_callbacks={},
                neo4j_creds=("bolt://x", "u", "p"))
        return out, chain

    async def test_the_summary_waits_out_a_rate_limit(self):
        llm = _Scripted(_sdk(langchain_openai_429), _sdk(langchain_openai_429), "# Summary")
        out, _ = await self.run_report(llm)
        self.assertEqual(out["messages"][0].content, "# Summary")
        self.assertEqual(llm.calls, 3)

    async def test_a_summary_that_still_fails_ends_the_run_with_a_fallback(self):
        llm = _Scripted(_sdk(lambda: openai_429(message=f"limit for key {SECRET}")))
        out, chain = await self.run_report(llm)
        text = out["messages"][0].content
        self.assertIn("The final summary could not be written", text)
        self.assertIn("the model provider's rate limit, provider HTTP 429, still refused after waiting", text)
        self.assertIn("2 step(s) ran, 1 succeeded and 1 failed", text)
        self.assertNotIn(SECRET, text)
        self.assertTrue(out["task_complete"])
        self.assertTrue(out["_report_generated"])
        chain.assert_called_once()

    async def test_no_credit_ends_at_once_with_its_own_words(self):
        llm = _Scripted(_sdk(NEVER_CLEARS["openai no credit"][0]))
        out, _ = await self.run_report(llm)
        self.assertIn("no credit or quota left", out["messages"][0].content)
        self.assertEqual((llm.calls, self.sleeps), (1, []))


class NarrativesTests(_PatchedSleep):
    async def test_report_narratives_wait_out_a_rate_limit(self):
        from orchestrator_helpers.report_summarizer import generate_report_narratives
        answer = ('{"executiveSummary": "e", "scopeNarrative": "s", "riskNarrative": "r", '
                  '"findingsNarrative": "f", "attackSurfaceNarrative": "a", '
                  '"recommendationsNarrative": "n"}')
        llm = _Scripted(_sdk(openai_429), answer)
        result = await generate_report_narratives(llm, {})
        self.assertNotIn("narratives_failed", result)
        self.assertEqual(result["executiveSummary"], "e")
        self.assertEqual(llm.calls, 2)


class GuardrailAndClassifierTests(_PatchedSleep):
    async def test_the_guardrail_waits_without_using_up_its_attempts(self):
        from orchestrator_helpers.guardrail import _invoke_guardrail
        llm = _Scripted(*[_sdk(openai_429) for _ in range(4)], '{"allowed": true, "reason": "ok"}')
        self.assertEqual(await _invoke_guardrail(llm, "prompt"), {"allowed": True, "reason": "ok"})
        self.assertEqual(llm.calls, 5)

    async def test_a_guardrail_whose_rate_limit_never_clears_still_fails_closed(self):
        from orchestrator_helpers.guardrail import _invoke_guardrail
        llm = _Scripted(StatusError(429, "Rate Limit Reached"))
        with self.assertRaises(RuntimeError) as raised:
            await _invoke_guardrail(llm, "prompt")
        self.assertIn("after 3 attempts", str(raised.exception))
        rate_limit_waits = [s for s in self.sleeps if s >= 4]
        self.assertEqual(sum(rate_limit_waits), 92)

    async def test_the_classifier_waits_instead_of_taking_the_default(self):
        from orchestrator_helpers.phase import classify_attack_path
        answer = ('{"attack_path_type": "brute_force_credential_guess", "required_phase": '
                  '"exploitation", "confidence": 0.9, "reasoning": "r"}')
        llm = _Scripted(*[_sdk(openai_429) for _ in range(3)], answer)
        result = await classify_attack_path(llm, "brute force ssh", max_retries=3)
        self.assertEqual(result[:2], ("brute_force_credential_guess", "exploitation"))


class AttemptTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_attempt_timeout_bounds_one_attempt_and_is_not_retried(self):
        llm = _Scripted("late", delay=0.2)
        with self.assertRaises(asyncio.TimeoutError):
            await retry_llm_call(llm, ["m"], label="t", attempt_timeout_s=0.01)
        self.assertEqual(llm.calls, 1)


class TextToCypherTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_generation_timeout_bounds_each_attempt_not_the_wait(self):
        from tools import Neo4jToolManager
        llm = _Scripted(_sdk(openai_429), "MATCH (n:Domain) RETURN n LIMIT 5")
        manager = Neo4jToolManager("bolt://x", "u", "p", llm=llm)
        # A 0.15 s wait inside a 0.1 s timeout: the old overall timeout fired here.
        with mock.patch.object(RateLimitWaiter, "next_wait_s", return_value=0.15), \
                mock.patch.dict(os.environ, {"CYPHER_GENERATION_TIMEOUT": "0.1"}):
            cypher = await manager._generate_cypher("list domains")
        self.assertIn("MATCH (n:Domain)", cypher)
        self.assertEqual(llm.calls, 2)


class _FakeWS:
    def __init__(self):
        self.sent, self.client = [], "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        pass


def _callback():
    conn = WebSocketConnection(_FakeWS())
    conn.user_id, conn.project_id, conn.session_id = "u", "p", "s"
    conn.authenticated = True
    return StreamingCallback(conn), conn.websocket


class DrawerFrameTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_wait_is_sent_and_never_saved(self):
        callback, ws = _callback()
        queued = []
        callback._persist = lambda msg_type, data, **kw: queued.append(msg_type)
        await callback.on_rate_limit_wait(seconds=16, retry=3, purpose="report")
        frame = ws.sent[-1]
        self.assertEqual(frame["type"], MessageType.RATE_LIMIT_WAIT.value)
        self.assertEqual(frame["payload"], {"seconds": 16, "retry": 3, "purpose": "report"})
        self.assertEqual(queued, [])

    async def test_a_wait_inside_a_real_graph_node_reaches_the_drawer(self):
        from typing import TypedDict
        from langgraph.graph import END, StateGraph
        from agent_in_the_loop import LoopSettings, broker as broker_mod
        from agent_in_the_loop.broker import StepBroker

        class State(TypedDict, total=False):
            out: str

        async def think(_state):
            with llm_purpose("think"):
                reply = await retry_llm_call(_Scripted(_sdk(openai_429), "ok"), ["m"], label="node")
            return {"out": reply.content}

        builder = StateGraph(State)
        builder.add_node("think", think)
        builder.set_entry_point("think")
        builder.add_edge("think", END)
        fake = mock.MagicMock()
        fake.graph, fake.llm = builder.compile(), mock.MagicMock()
        broker = StepBroker(config=LoopSettings(
            step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=40000,
            answer_max_chars=262144, max_open_steps_per_user=16, no_driver_grace_s=300,
            driver_seen_s=60, state_ttl_s=3600), poll_s=0.01)
        callback, ws = _callback()
        with mock.patch.object(broker_mod, "_broker", broker), \
                mock.patch.object(orchestrator_mod, "emit_streaming_events", new=mock.AsyncMock()), \
                mock.patch.object(websocket_api, "save_chat_message", new=mock.AsyncMock()), \
                mock.patch.object(RateLimitWaiter, "next_wait_s", return_value=0.01):
            final = await orchestrator_mod.AgentOrchestrator._stream_graph(fake, {}, {}, callback, "u", "p", "s")
        self.assertEqual(final.get("out"), "ok")
        frames = [m["payload"] for m in ws.sent if m["type"] == MessageType.RATE_LIMIT_WAIT.value]
        self.assertEqual(frames, [{"seconds": 1, "retry": 1, "purpose": "think"}])
        self.assertIsNone(current_llm_wait_listener.get())

    async def test_the_run_installs_the_listener_and_removes_it(self):
        seen = []

        class Graph:
            async def astream(self, _input, _config, stream_mode="values"):
                seen.append(current_llm_wait_listener.get())
                yield {"task_complete": True}

        from agent_in_the_loop import LoopSettings, broker as broker_mod
        from agent_in_the_loop.broker import StepBroker
        broker = StepBroker(config=LoopSettings(
            step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=40000,
            answer_max_chars=262144, max_open_steps_per_user=16, no_driver_grace_s=300,
            driver_seen_s=60, state_ttl_s=3600), poll_s=0.01)
        fake = mock.MagicMock()
        fake.graph, fake.llm = Graph(), mock.MagicMock()
        callback, _ = _callback()
        with mock.patch.object(broker_mod, "_broker", broker), \
                mock.patch.object(orchestrator_mod, "emit_streaming_events", new=mock.AsyncMock()), \
                mock.patch.object(websocket_api, "save_chat_message", new=mock.AsyncMock()):
            await orchestrator_mod.AgentOrchestrator._stream_graph(fake, {}, {}, callback, "u", "p", "s")
        self.assertEqual(seen, [callback.on_rate_limit_wait])
        self.assertIsNone(current_llm_wait_listener.get())


if __name__ == "__main__":
    unittest.main()
