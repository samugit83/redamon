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
"""

from __future__ import annotations

import asyncio
import logging
import re
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

# Some models reject the `temperature` sampling param with a permanent 400,
# either because they forbid it outright or because a reasoning/thinking mode
# constrains it to a value our default of 0 violates. Observed across providers:
#   * Anthropic 4.7+/5:      "`temperature` is deprecated for this model."
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
    "must be set to",
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
    already waited minutes for a person's agent), then type-MRO match, then
    message substring, then bare HTTP status code regex.
    """
    if getattr(exc, "no_retry", False):
        return False
    for base in type(exc).__mro__:
        if base.__name__ in _TRANSIENT_EXC_NAMES:
            return True
    err_str = str(exc).lower()
    if any(k in err_str for k in _TRANSIENT_KEYWORDS):
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


async def retry_llm_call(
    llm: Any,
    messages: list,
    *,
    label: str = "llm",
    max_attempts: int = 3,
) -> Any:
    """Call ``await llm.ainvoke(messages)`` with transient-error retry.

    Behavior:
      * On transient errors (as classified by ``is_transient_llm_error``),
        retries up to ``max_attempts`` total attempts with exponential
        backoff: ``min(2 ** attempt, 8)`` seconds between attempts. No
        sleep after the final attempt — wasted latency before the raise.
      * On non-transient errors (auth, schema, model-not-found, token
        limit, etc.), re-raises immediately — no point retrying.
      * On exhaustion, re-raises the last exception unchanged so callers
        can match on the original type/message.

    The label is included in every log line so concurrent fireteam waves
    can be disambiguated in the log stream.
    """
    last_exc: BaseException | None = None
    healed: set[str] = set()
    for attempt in range(max_attempts):
        try:
            return await llm.ainvoke(messages)
        except Exception as exc:
            last_exc = exc
            # Self-heal (once per param): a model that rejects `temperature` or
            # `reasoning_effort` raises a permanent 400. Strip the offending
            # param and immediately retry so any such model/provider works
            # without a per-model allowlist. If the retry still fails, fall
            # through to normal classification of that error.
            heal = heal_llm_param_error(llm, exc, already_healed=frozenset(healed))
            if heal is not None:
                llm, heal_key = heal
                healed.add(heal_key)
                logger.warning(
                    "[%s] model rejected `%s`; retrying without it.",
                    label, heal_key,
                )
                try:
                    return await llm.ainvoke(messages)
                except Exception as exc2:
                    last_exc = exc2
                    exc = exc2
                    # A second param might still be rejected (e.g. temperature
                    # then reasoning_effort). Heal it too before classifying.
                    heal2 = heal_llm_param_error(
                        llm, exc, already_healed=frozenset(healed)
                    )
                    if heal2 is not None:
                        llm, heal_key = heal2
                        healed.add(heal_key)
                        logger.warning(
                            "[%s] model rejected `%s`; retrying without it.",
                            label, heal_key,
                        )
                        try:
                            return await llm.ainvoke(messages)
                        except Exception as exc3:
                            last_exc = exc3
                            exc = exc3
            transient = is_transient_llm_error(exc)
            logger.warning(
                "[%s] LLM attempt %d/%d error (transient=%s, type=%s): %s",
                label, attempt + 1, max_attempts, transient,
                type(exc).__name__, exc,
            )
            if not transient:
                raise
            if attempt < max_attempts - 1:
                await asyncio.sleep(min(2 ** attempt, 8))
    assert last_exc is not None  # pragma: no cover — loop body always assigns
    raise last_exc
