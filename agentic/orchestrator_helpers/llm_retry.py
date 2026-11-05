"""Shared LLM transient-error classifier + retry helper.

Background. PR #111 added a 3-attempt retry around the fireteam member's
``await llm.ainvoke(...)`` because a single transient error (network blip,
HTTP 529 overload, rate-limit) was terminating an entire fireteam member.
A subsequent review found the same root-cause pattern in two other
places:

  * Root ``think_node`` — calls ``ainvoke`` with NO try/except, so a
    transient there crashes the whole session, not just one specialist.
  * ``guardrail`` — has a 3-attempt loop but with a broad ``except
    Exception`` that retries permanent errors (invalid API key, schema
    bugs) 3x, wasting budget and producing a worse error message.

This module centralizes the classification and retry policy so all three
call sites use identical logic and a new transient exception type added
in the wild (e.g. a future SDK ``RetryableError``) only needs to be added
in one place.

Public API:
  * ``is_transient_llm_error(exc)`` — classify a raised exception
  * ``retry_llm_call(llm, messages, *, label, max_attempts)`` — async
    wrapper around ``llm.ainvoke`` that retries on transient errors
    only, exponential backoff, and re-raises the last exception on
    exhaustion or first non-transient error.
  * ``ainvoke_through_rate_limits(llm, messages, *, waiter)`` — one call
    that waits out a rate limit, for call sites with their own loop.
  * ``describe_llm_failure(exc)`` — a fixed sentence a person may read.

Rate limits. A 429 means the account's per-minute window is full, so the
next try only passes once the window resets. The SDKs' own retries are over
in about a second, so a rate limit gets its own budget here: up to
``LLM_RATE_LIMIT_MAX_WAIT_S`` (default 120 s) of waiting per call, as long as
the provider says when it can be retried, else growing waits with jitter.
It does not count against ``max_attempts``. A 429 that no wait clears (no
credit, a daily quota, one request over the limit) is not retried at all.
"""

from __future__ import annotations

import asyncio
import email.utils
import logging
import math
import os
import random
import re
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# Class names from anthropic, openai, and httpx SDKs that indicate transient
# failures. Matched against ``type(exc).__mro__`` so SDK subclasses (e.g.
# ``APITimeoutError`` extends ``APIConnectionError``) are caught even when
# only the parent name is enumerated.
_TRANSIENT_EXC_NAMES = frozenset({
    "APIConnectionError", "APITimeoutError", "RateLimitError",
    "InternalServerError", "ServiceUnavailableError", "OverloadedError",
    "ConnectError", "ConnectTimeout", "ReadTimeout", "WriteTimeout",
    "PoolTimeout", "TimeoutException", "RemoteProtocolError",
})

# Phrase fallback for wrapped exceptions or providers whose class names we
# don't enumerate (Bedrock, Gemini, custom). Lowercased substring match on
# ``str(exc)``.
_TRANSIENT_KEYWORDS = (
    "connection", "timeout", "timed out", "overloaded",
    "rate_limit", "rate limit", "apiconnectionerror",
    "service unavailable", "bad gateway", "gateway timeout",
    "internal server error", "server_error",
)

# Bare HTTP status codes matched with WORD BOUNDARIES so "500" does NOT
# fire on "50000" — e.g. a permanent ``max_tokens: 50000 exceeded`` error
# must not be classified transient. 429 is added even though it's < 500
# because it's rate-limit, retry-worthy.
_TRANSIENT_STATUS_RE = re.compile(r"\b(429|500|502|503|504|529)\b")
# The same statuses read from the error itself, for providers whose message
# names none of them (Bedrock's ServiceUnavailableException is a ClientError
# with the 503 in its response metadata).
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504, 529})

# Some models reject the `temperature` sampling param with a permanent 400,
# either because they forbid it outright or because a reasoning/thinking mode
# constrains it to a value our default of 0 violates. Observed across providers:
#   * Anthropic 4.7+/5:      "`temperature` is deprecated for this model."
#   * Anthropic API 2026-10-21 (every model): "temperature: Extra inputs are not permitted"
#   * OpenAI o-series/gpt-5:  "'temperature' does not support 0 ... Only the default (1)"
#   * Moonshot kimi-k3:       "invalid temperature: only 1 is allowed for this model."
#   * DeepSeek reasoner:      "deepseek-reasoner does not support the parameter `temperature`"
#   * Bedrock + thinking:     "temperature may only be set to 1 when thinking is enabled"
#   * Zhipu GLM / Qwen think: temperature "must be greater than 0" (open interval)
# None are transient, but ALL are auto-recoverable the same way: drop temperature
# and retry, so the model falls back to its own (compatible) default. Matching on
# these phrases means any current or future model that rejects the param, forces a
# fixed value, or requires a non-zero value works without a per-model allowlist.
# Anchored on the word "temperature" being present, so these stay specific.
# Each phrase is tied to a real provider error string above — no speculative
# widening, which would only grow the false-positive surface.
_TEMPERATURE_UNSUPPORTED_HINTS = (
    "deprecated", "unsupported", "not supported", "does not support",
    "only 1 is allowed", "invalid temperature", "only the default",
    "may only be set", "must be greater than", "greater than 0",
    "must be set to", "extra inputs are not permitted",
)

# Hints for a DIFFERENT class: the model lacks the thinking capability entirely
# and rejects `reasoning_effort` (e.g. Ollama's `"<model>" does not support
# thinking`). Deliberately NOT the temperature-range phrases above — a
# temperature-range error that happens to mention "thinking" (Qwen's
# "temperature must be greater than 0 for thinking mode") is a TEMPERATURE
# error, and must not be mis-healed by dropping reasoning_effort.
_THINKING_UNSUPPORTED_HINTS = (
    "deprecated", "unsupported", "not supported", "does not support",
)


def _is_temperature_unsupported_error(exc: BaseException) -> bool:
    s = str(exc).lower()
    return "temperature" in s and any(h in s for h in _TEMPERATURE_UNSUPPORTED_HINTS)


def _is_thinking_unsupported_error(exc: BaseException) -> bool:
    """A model without the thinking capability rejects `reasoning_effort` with a
    permanent 400, e.g. Ollama's `"<model>" does not support thinking`. Like the
    temperature case this is not transient but IS auto-recoverable: drop
    reasoning_effort and retry. Lets a user who enabled reasoning on a
    non-thinking model keep running instead of bricking every LLM call.
    """
    s = str(exc).lower()
    return "thinking" in s and any(h in s for h in _THINKING_UNSUPPORTED_HINTS)


def _without_reasoning_effort(llm: Any) -> Any:
    """Return a copy of the chat model with `reasoning_effort` removed (set to
    None, which LangChain omits from the request), or None if a copy can't be
    made. Mirrors ``_without_temperature``; never mutates the original ``llm``.
    """
    try:
        return llm.model_copy(update={"reasoning_effort": None})
    except Exception:
        pass
    try:
        import copy
        clone = copy.copy(llm)
        clone.reasoning_effort = None
        return clone
    except Exception:
        return None


def _without_temperature(llm: Any) -> Any:
    """Return a copy of the chat model with `temperature` removed (set to None,
    which LangChain omits from the request), or None if a copy can't be made.

    LangChain chat models are pydantic; ``model_copy`` (v2) is preferred, with a
    shallow-copy fallback for older cores. Never mutates the original ``llm``.
    """
    try:
        return llm.model_copy(update={"temperature": None})
    except Exception:
        pass
    try:
        import copy
        clone = copy.copy(llm)
        clone.temperature = None
        return clone
    except Exception:
        return None


def heal_llm_param_error(
    llm: Any,
    exc: BaseException,
    *,
    already_healed: frozenset = frozenset(),
) -> tuple[Any, str] | None:
    """Try to auto-recover from a permanent parameter-rejection 400.

    Some models reject our default sampling params: ``temperature`` (forbidden,
    or constrained by a reasoning mode) or ``reasoning_effort`` (model lacks the
    thinking capability). Both are fixable by dropping the offending param and
    retrying once — the model then uses its own compatible default.

    Returns ``(healed_llm, heal_key)`` where ``heal_key`` is ``"temperature"`` or
    ``"reasoning_effort"``, or ``None`` when the error isn't of that class, the
    relevant heal was already applied (``already_healed``), or no copy of ``llm``
    could be made. Never mutates the original ``llm``.

    Temperature is checked first: an error like Bedrock's "temperature may only
    be set to 1 when thinking is enabled" names both params, and dropping
    temperature is the correct fix there.

    This is the shared self-heal used by ``retry_llm_call`` and by direct
    ``ainvoke`` call sites (the scope guardrail and the attack-path classifier)
    that run their own retry loops.
    """
    if "temperature" not in already_healed and _is_temperature_unsupported_error(exc):
        neutered = _without_temperature(llm)
        if neutered is not None:
            return neutered, "temperature"
    if "reasoning_effort" not in already_healed and _is_thinking_unsupported_error(exc):
        neutered = _without_reasoning_effort(llm)
        if neutered is not None:
            return neutered, "reasoning_effort"
    return None


def is_transient_llm_error(exc: BaseException) -> bool:
    """Classify an LLM-call exception as transient (worth retrying) or not.

    Order: an explicit ``no_retry`` marker first (an Agent in the Loop step
    already waited minutes for a person's agent), then the kind of 429 (a rate
    limit is worth retrying, an empty quota is not), then type-MRO match, then
    message substring, then the HTTP status the error carries or names.
    """
    from llm_builder import provider_error_kind, provider_status
    if getattr(exc, "no_retry", False):
        return False
    kind = provider_error_kind(exc)
    if kind is not None:
        return kind == "rate_limited"
    for base in type(exc).__mro__:
        if base.__name__ in _TRANSIENT_EXC_NAMES:
            return True
    err_str = str(exc).lower()
    if any(k in err_str for k in _TRANSIENT_KEYWORDS):
        return True
    if provider_status(exc) in _TRANSIENT_STATUSES:
        return True
    return bool(_TRANSIENT_STATUS_RE.search(err_str))


def llm_error_reason(exc: BaseException) -> str:
    """The ``llm_error: ...`` completion reason of a failed LLM call, which the
    chat shows: the exception's class and the provider's HTTP status, never its
    text, which can quote part of a key or the prompt. The log keeps the text."""
    from llm_builder import provider_error_details
    details = provider_error_details(exc)
    label = details.get("error_class") or "LLM call failed"
    if "provider_status" in details:
        label += f" (provider HTTP {details['provider_status']})"
    return f"llm_error: {label}"


def describe_llm_failure(exc: BaseException) -> str:
    """A failed model call in words a person may read: the kind of refusal, the
    provider's HTTP status and how long the rate limit was waited for. Fixed
    words only; the provider's text can quote part of a key or the prompt."""
    from llm_builder import provider_error_details
    details = provider_error_details(exc)
    kind = details.get("provider_error_kind")
    parts = [_KIND_WORDS.get(kind) or details.get("error_class") or "the model call failed"]
    if "provider_status" in details:
        parts.append(f"provider HTTP {details['provider_status']}")
    if details.get("rate_limit_waited_s"):
        parts.append(f"still refused after waiting {details['rate_limit_waited_s']} s")
    return ", ".join(parts)


_KIND_WORDS = {
    "rate_limited": "the model provider's rate limit",
    "quota_exhausted": "no credit or quota left on the model provider account",
    "request_too_large": "the request is larger than the provider's per-minute limit",
}


# =============================================================================
# Rate limits
# =============================================================================

#: Most one call waits, in total, for a provider's rate limit to clear.
#: Windows are counted per minute, so this outlasts two of them. Only the
#: waits between tries count, not the tries themselves.
RATE_LIMIT_MAX_WAIT_DEFAULT_S = 120.0
#: First wait when the provider names none; it doubles up to the step cap.
_RATE_LIMIT_FIRST_WAIT_S = 4.0
_RATE_LIMIT_MAX_STEP_S = 32.0
_RATE_LIMIT_MAX_RETRIES = 10

_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")
_DURATION_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
# "Please try again in 6.5s" / "in 1m30s" / "in 120ms" (OpenAI and the
# OpenAI-compatible providers), "Please retry in 17.2s" (Gemini).
_RETRY_IN = re.compile(r"(?:try again|retry) in ((?:\d+(?:\.\d+)?(?:ms|h|m|s))+)")
# Gemini's RetryInfo detail: 'retryDelay': '17s'.
_RETRY_DELAY_FIELD = re.compile(r"retrydelay['\"]?\s*:\s*['\"]?(\d+(?:\.\d+)?)s")


def rate_limit_budget_s() -> float:
    """Seconds one call may wait for a rate limit (``LLM_RATE_LIMIT_MAX_WAIT_S``);
    0 turns the waiting off."""
    raw = os.environ.get("LLM_RATE_LIMIT_MAX_WAIT_S")
    if raw is None or raw.strip() == "":
        return RATE_LIMIT_MAX_WAIT_DEFAULT_S
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value):
        # nan would compare false everywhere and silently turn the waiting off.
        logger.warning(
            f"Invalid LLM_RATE_LIMIT_MAX_WAIT_S={raw!r}, using {RATE_LIMIT_MAX_WAIT_DEFAULT_S:g}s")
        return RATE_LIMIT_MAX_WAIT_DEFAULT_S
    return max(0.0, value)


def _duration_s(text: str) -> float | None:
    parts = _DURATION_PART.findall(text or "")
    if not parts:
        return None
    return sum(float(number) * _DURATION_UNITS[unit] for number, unit in parts)


def _header_reader(exc: BaseException):
    """A `get(name)` over the error's response headers giving non-empty strings
    only, or None when the error carries no headers."""
    get = getattr(getattr(getattr(exc, "response", None), "headers", None), "get", None)
    if get is None:
        return None

    def header(name: str) -> str | None:
        value = get(name)
        return value.strip() if isinstance(value, str) and value.strip() else None
    return header


def _retry_after_s(exc: BaseException) -> float | None:
    """retry-after-ms, then Retry-After (seconds or an HTTP date)."""
    header = _header_reader(exc)
    if header is None:
        return None
    ms = header("retry-after-ms")
    if ms:
        try:
            return float(ms) / 1000.0
        except ValueError:
            pass
    retry_after = header("retry-after")
    if retry_after:
        try:
            return float(retry_after)
        except ValueError:
            try:
                when = email.utils.parsedate_to_datetime(retry_after)
                return (when - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, IndexError):
                pass
    return None


def _message_hint_s(exc: BaseException) -> float | None:
    text = str(exc).lower()
    match = _RETRY_IN.search(text)
    if match:
        return _duration_s(match.group(1))
    match = _RETRY_DELAY_FIELD.search(text)
    return float(match.group(1)) if match else None


def _reset_headers_s(exc: BaseException) -> float | None:
    """OpenAI's x-ratelimit-reset-* ("6m0s", "120ms"): when a bucket is full
    again, which can be later than this request needs, so asked last."""
    header = _header_reader(exc)
    if header is None:
        return None
    resets = [_duration_s(header(name) or "")
              for name in ("x-ratelimit-reset-requests", "x-ratelimit-reset-tokens")]
    resets = [value for value in resets if value is not None]
    return max(resets) if resets else None


def provider_retry_hint_s(exc: BaseException) -> float | None:
    """How long the provider said to wait, or None when it did not say: its
    Retry-After, then its message ("try again in 6.5s", Gemini's retryDelay),
    then OpenAI's reset headers. A value that is not a finite number is no hint."""
    from llm_builder import _cause_chain
    for read in (_retry_after_s, _message_hint_s, _reset_headers_s):
        for current in _cause_chain(exc):
            hint = read(current)
            if hint is not None and math.isfinite(hint):
                return hint
    return None


async def _announce_wait(seconds: float, retry: int) -> None:
    """Tell the chat the run is waiting for the provider; never fails the call."""
    from agent_context import current_llm_purpose, current_llm_wait_listener
    listener = current_llm_wait_listener.get()
    if listener is None:
        return
    try:
        await listener(seconds=max(1, round(seconds)), retry=retry,
                       purpose=str(current_llm_purpose.get().get("purpose") or "other"))
    except Exception as exc:                                      # noqa: BLE001
        logger.debug(f"rate-limit wait notice not sent: {type(exc).__name__}")


class RateLimitWaiter:
    """The rate-limit budget of one model call, across all of its tries.

    A call site that runs its own retry loop keeps one waiter for the whole
    loop, so the total wait stays bounded however its attempts are counted.
    The budget is wall-clock time from the call's start: the provider SDKs
    retry a 429 on their own first (Anthropic's five retries each wait the
    Retry-After), and counting only our own sleeps lets their waits run far past it.
    """

    def __init__(self, label: str = "llm", budget_s: float | None = None):
        self.label = label
        self.budget_s = rate_limit_budget_s() if budget_s is None else max(0.0, budget_s)
        self.started = time.monotonic()
        self.waited_s = 0.0
        self.retries = 0

    def spent_s(self) -> float:
        """Seconds the call has spent; our own sleeps when they are longer,
        which only happens when a test replaces the sleep."""
        return max(self.waited_s, time.monotonic() - self.started)

    def next_wait_s(self, exc: BaseException) -> float | None:
        """Seconds to wait before trying again, or None to give up now."""
        if self.retries >= _RATE_LIMIT_MAX_RETRIES:
            return None
        hint = provider_retry_hint_s(exc)
        if hint is not None:
            # A little past the reset, and spread, so parallel calls (Fireteam
            # members) do not all come back in the same instant. A hint beyond
            # the budget (an hourly window) ends the waiting below at once.
            wait = max(hint, 1.0) * random.uniform(1.0, 1.15)
        else:
            step = min(_RATE_LIMIT_FIRST_WAIT_S * 2 ** self.retries, _RATE_LIMIT_MAX_STEP_S)
            wait = step * random.uniform(0.5, 1.0)
        if self.spent_s() + wait > self.budget_s:
            return None
        return wait

    async def wait(self, exc: BaseException) -> bool:
        """Wait before the next try and return True, or record the time
        already waited on ``exc`` and return False when the budget is spent."""
        wait = self.next_wait_s(exc)
        if wait is None:
            self.mark(exc)
            logger.warning(
                "[%s] rate limit did not clear; giving up after %.0fs over %d retries",
                self.label, self.spent_s(), self.retries)
            return False
        self.retries += 1
        logger.warning(
            "[%s] provider rate limit; retry %d in %.1fs (spent %.0fs of %.0fs)",
            self.label, self.retries, wait, self.spent_s(), self.budget_s)
        await _announce_wait(wait, self.retries)
        await asyncio.sleep(wait)
        self.waited_s += wait
        return True

    def mark(self, exc: BaseException) -> None:
        """Note on the exception how long it was waited for, so the error a
        person sees can say so (llm_builder.provider_error_details)."""
        spent = self.spent_s()
        if spent >= 1:
            try:
                exc.rate_limit_waited_s = int(round(spent))
            except Exception:                                     # noqa: BLE001
                pass


async def _ainvoke(llm: Any, messages: Any, attempt_timeout_s: float | None) -> Any:
    if attempt_timeout_s:
        return await asyncio.wait_for(llm.ainvoke(messages), attempt_timeout_s)
    return await llm.ainvoke(messages)


async def ainvoke_through_rate_limits(
    llm: Any,
    messages: Any,
    *,
    waiter: RateLimitWaiter,
) -> Any:
    """One ``llm.ainvoke`` that waits out the provider's rate limit, and only
    that: every other error is raised for the caller's own loop to judge. Pass
    the same waiter for every attempt of that loop."""
    from llm_builder import provider_error_kind
    while True:
        try:
            return await llm.ainvoke(messages)
        except Exception as exc:
            if provider_error_kind(exc) == "rate_limited" and await waiter.wait(exc):
                continue
            raise


async def retry_llm_call(
    llm: Any,
    messages: Any,
    *,
    label: str = "llm",
    max_attempts: int = 3,
    rate_limit_budget_s: float | None = None,
    attempt_timeout_s: float | None = None,
) -> Any:
    """Call ``await llm.ainvoke(messages)`` with transient-error retry.

    Behavior:
      * A rate limit (``provider_error_kind`` = ``rate_limited``) is waited
        out within the call's rate-limit budget (``RateLimitWaiter``), and
        does not count against ``max_attempts``. ``rate_limit_budget_s=0``
        turns that waiting off (the provider test button).
      * Other transient errors (as classified by ``is_transient_llm_error``)
        are retried up to ``max_attempts`` total attempts with exponential
        backoff: ``min(2 ** n, 8)`` seconds between attempts. No sleep after
        the final attempt — wasted latency before the raise.
      * On non-transient errors (auth, schema, model-not-found, token
        limit, an empty quota, etc.), re-raises immediately — no point retrying.
      * On exhaustion, re-raises the last exception unchanged so callers
        can match on the original type/message.
      * ``attempt_timeout_s`` bounds each attempt, not the waits between
        them; its ``asyncio.TimeoutError`` is raised, never retried.

    The label is included in every log line so concurrent fireteam waves
    can be disambiguated in the log stream.
    """
    from llm_builder import provider_error_kind
    waiter = RateLimitWaiter(label, rate_limit_budget_s)
    failures = 0
    healed: set[str] = set()
    while True:
        try:
            return await _ainvoke(llm, messages, attempt_timeout_s)
        except Exception as first_exc:
            exc = first_exc
            # Self-heal (once per param): a model that rejects `temperature` or
            # `reasoning_effort` raises a permanent 400. Strip the offending
            # param and immediately retry so any such model/provider works
            # without a per-model allowlist. A second param might still be
            # rejected (e.g. temperature then reasoning_effort), so heal again
            # before classifying whatever the healed call raised.
            heal = heal_llm_param_error(llm, exc, already_healed=frozenset(healed))
            while heal is not None:
                llm, heal_key = heal
                healed.add(heal_key)
                logger.warning(
                    "[%s] model rejected `%s`; retrying without it.",
                    label, heal_key,
                )
                try:
                    return await _ainvoke(llm, messages, attempt_timeout_s)
                except Exception as healed_exc:
                    exc = healed_exc
                heal = heal_llm_param_error(llm, exc, already_healed=frozenset(healed))
            transient = is_transient_llm_error(exc)
            kind = provider_error_kind(exc)
            logger.warning(
                "[%s] LLM call error (transient=%s, kind=%s, type=%s): %s",
                label, transient, kind, type(exc).__name__, exc,
            )
            if not transient:
                raise exc
            if kind == "rate_limited":
                if await waiter.wait(exc):
                    continue
                raise exc
            failures += 1
            if failures >= max_attempts:
                waiter.mark(exc)
                raise exc
            await asyncio.sleep(min(2 ** (failures - 1), 8))
