"""Build an LLM for one user and one exact model.

Used by every "Models by feature" caller: the RoE parse, report narratives and
command whisperer endpoints, Multi mute, and the tradecraft section picker. Two
things differ from the older `_build_llm_with_model_for_user` in `api.py`, which
keeps serving the recon planners unchanged:

- A provider list that cannot be fetched RAISES `ProvidersUnreachable`. The old
  helper swallowed the failure and built with no keys, so a webapp hiccup read
  as "your model is broken" and sent the person to re-pick a model that works.
- A `custom/<id>` model resolves to that exact provider or to none. The old
  `_pick_custom_provider` falls back to the first custom provider, so deleting
  a provider silently moved the feature onto a different endpoint and key.
"""

from __future__ import annotations

import logging
import os
import re
import urllib.parse

logger = logging.getLogger(__name__)

PROVIDER_FETCH_TIMEOUT_S = 10

#: Fixed text for a model that could not be built or called. The provider's own
#: message never reaches the browser: a 401 body can quote part of the key.
MODEL_UNAVAILABLE_MESSAGE = "Your model {model} could not be used"

_BUILTIN_PROVIDERS = ("openai", "anthropic", "openrouter", "bedrock", "deepseek",
                      "gemini", "glm", "kimi", "qwen", "xai", "mistral")

#: Provider rows whose key is for something other than a chat model (TypeSafe
#: Jev). Every path that builds a chat LLM from "a provider row" must skip
#: them: `setup_llm`'s custom branch would build ChatOpenAI with no base URL
#: and send the token to api.openai.com. Twin of the webapp's
#: NON_CHAT_PROVIDER_TYPES in webapp/src/lib/llmProviderKinds.ts.
NON_CHAT_PROVIDER_TYPES = frozenset({"jev", "jev_openrouter"})

#: The provider types that can serve a `custom/<id>` model.
CUSTOM_PROVIDER_TYPES = ("openai_compatible", "bedrock_custom", "ollama_local")

#: Provider answers that mean "this model, with these keys, cannot be used" -
#: a bad or revoked key, no access, or a model id the provider does not have.
#: Anything else (rate limit, a 5xx, a dropped connection) is transient and
#: must not send the person to pick another model.
_UNAVAILABLE_STATUS = frozenset({401, 403, 404})
_UNAVAILABLE_CLASS_NAMES = frozenset({
    "AuthenticationError", "PermissionDeniedError", "NotFoundError",
    # langchain_core's provider-neutral family, raised by newer integrations.
    "ModelAuthenticationError", "ModelPermissionDeniedError", "ModelNotFoundError",
})
_UNAVAILABLE_AWS_CODES = frozenset({
    "AccessDeniedException", "UnrecognizedClientException",
    "ResourceNotFoundException", "ExpiredTokenException",
    "InvalidSignatureException",
})
#: Gemini answers a bad key with a plain 400 INVALID_ARGUMENT; only the reason
#: tells it from any other bad request.
_BAD_KEY_MARKERS = ("API_KEY_INVALID", "API key not valid")
#: Bedrock answers an unknown model id with the generic ValidationException,
#: which also covers transient-looking request errors, so the message decides.
_BAD_MODEL_ID_MARKER = "model identifier is invalid"

#: A provider telling us to slow down. The status decides when the error
#: carries one; the class names and phrases catch the ones whose status sits
#: where we do not look (Gemini's RESOURCE_EXHAUSTED, Qwen's Throttling.*).
_RATE_LIMIT_CLASS_NAMES = frozenset({
    "RateLimitError", "ModelRateLimitError", "ThrottlingException",
    "TooManyRequests", "ResourceExhausted",
})
_RATE_LIMIT_PHRASES = (
    "rate limit", "rate_limit", "too many requests", "throttl",
    "resource_exhausted", "resource has been exhausted",
)
#: AWS names its throttling in the error code, whatever status it sends.
_AWS_THROTTLING_CODES = frozenset({"ThrottlingException", "TooManyRequestsException"})
#: A 429 that no wait clears, each tied to a provider's real answer: OpenAI's
#: `insufficient_quota` (no credit left), Moonshot's `exceeded_current_quota_error`,
#: Zhipu's 1113 "Insufficient balance", and a daily quota (Gemini's
#: `...PerDay...` quota ids, OpenAI's "requests per day", OpenRouter's
#: `free-models-per-day`), which resets tomorrow, not within a minute.
_QUOTA_EXHAUSTED_PHRASES = ("insufficient_quota", "exceeded_current_quota", "insufficient balance")
_DAILY_QUOTA = re.compile(r"per[-_ ]?day")
#: OpenAI's 429 for one request bigger than the account's whole per-minute
#: token limit: it can never fit, however long we wait.
_REQUEST_TOO_LARGE_PHRASE = "request too large"


class ProvidersUnreachable(RuntimeError):
    """The user's provider list could not be loaded from the webapp."""


def fetch_user_providers(user_id: str) -> list:
    """This user's LLM providers, with keys. Raises `ProvidersUnreachable`.

    Blocking (requests); async callers run it through `asyncio.to_thread`.
    """
    import requests

    if not user_id:
        raise ValueError("user_id is required")
    webapp_url = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")
    key = os.environ.get("INTERNAL_API_KEY", "")
    url = (f"{webapp_url}/api/users/{urllib.parse.quote(str(user_id), safe='')}"
           f"/llm-providers?internal=true")
    try:
        resp = requests.get(url, headers={"X-Internal-Key": key},
                            timeout=PROVIDER_FETCH_TIMEOUT_S)
        resp.raise_for_status()
        providers = resp.json()
    except Exception as exc:                                      # noqa: BLE001
        raise ProvidersUnreachable(exc.__class__.__name__) from exc
    if providers is None:
        return []
    if not isinstance(providers, list):
        raise ProvidersUnreachable("the provider list is not a list")
    return providers


def chat_providers(rows: list) -> list:
    """The provider rows that hold a chat-model key (non-chat types dropped)."""
    return [row for row in rows or []
            if isinstance(row, dict)
            and row.get("providerType") not in NON_CHAT_PROVIDER_TYPES]


def exact_custom_provider(providers: list, model: str):
    """The provider a `custom/<id>` model names, or None. Never another one."""
    if not model or not model.startswith("custom/"):
        return None
    wanted = model[len("custom/"):]
    for provider in chat_providers(providers):
        if provider.get("id") == wanted:
            return provider
    return None


def custom_provider_or_fallback(providers: list, model: str):
    """The provider for a `custom/<id>` model, else the first custom-capable one.

    For the agent session and text-to-cypher, which keep working when a
    provider was deleted and recreated under a new id. The fallback only ever
    lands on a custom-capable type: any other row (a built-in key, a Jev token)
    would be sent to whatever endpoint `setup_llm`'s custom branch builds.
    """
    exact = exact_custom_provider(providers, model)
    if exact is not None:
        return exact
    for provider in chat_providers(providers):
        if provider.get("providerType") in CUSTOM_PROVIDER_TYPES:
            return provider
    return None


def build_llm_from_providers(model: str, providers: list):
    """An LLM for exactly `model`, keyed from `providers`. Raises on any failure.

    A `custom/<id>` whose provider is gone raises in `setup_llm` rather than
    falling back to another custom provider.
    """
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from agent_in_the_loop.errors import refuse_loop_model

    if not model:
        raise ValueError("a model is required")
    refuse_loop_model(model)
    keys = {name: (_resolve_provider_key(providers or [], name) or {})
            for name in _BUILTIN_PROVIDERS}
    bedrock = keys["bedrock"]
    return setup_llm(
        model,
        openai_api_key=keys["openai"].get("apiKey"),
        anthropic_api_key=keys["anthropic"].get("apiKey"),
        openrouter_api_key=keys["openrouter"].get("apiKey"),
        deepseek_api_key=keys["deepseek"].get("apiKey"),
        gemini_api_key=keys["gemini"].get("apiKey"),
        glm_api_key=keys["glm"].get("apiKey"),
        kimi_api_key=keys["kimi"].get("apiKey"),
        qwen_api_key=keys["qwen"].get("apiKey"),
        xai_api_key=keys["xai"].get("apiKey"),
        mistral_api_key=keys["mistral"].get("apiKey"),
        aws_access_key_id=bedrock.get("awsAccessKeyId"),
        aws_secret_access_key=bedrock.get("awsSecretKey"),
        aws_bearer_token=bedrock.get("awsBearerToken"),
        aws_region=bedrock.get("awsRegion") or "us-east-1",
        custom_llm_config=exact_custom_provider(providers, model),
    )


def is_model_unavailable_error(exc: BaseException) -> bool:
    """True when a call failed because the model or its key cannot be used.

    Walks the cause chain: LangChain wraps SDK errors, and the SDKs wrap the
    HTTP response, so the status can sit two levels down.
    """
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if type(current).__name__ in _UNAVAILABLE_CLASS_NAMES:
            return True
        status = getattr(current, "status_code", None)
        if status is None:
            status = getattr(getattr(current, "response", None), "status_code", None)
        if status is None:
            # google-genai errors carry the HTTP status as `.code`.
            code = getattr(current, "code", None)
            status = code if isinstance(code, int) and not isinstance(code, bool) else None
        if status in _UNAVAILABLE_STATUS:
            return True
        if status == 400 and any(marker in str(current) for marker in _BAD_KEY_MARKERS):
            return True
        response = getattr(current, "response", None)
        if isinstance(response, dict):
            error = response.get("Error") or {}
            code = error.get("Code")
            if code in _UNAVAILABLE_AWS_CODES:
                return True
            if (code == "ValidationException"
                    and _BAD_MODEL_ID_MARKER in str(error.get("Message") or "").lower()):
                return True
        current = current.__cause__ or current.__context__
    return False


_SAFE_CLASS_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _http_status_of(exc: BaseException):
    """The HTTP status a provider error carries, or None. Same fields as above."""
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    if status is None:
        code = getattr(exc, "code", None)
        status = code if isinstance(code, int) and not isinstance(code, bool) else None
    if status is None:
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
    if isinstance(status, bool) or not isinstance(status, int):
        return None
    return status if 100 <= status <= 599 else None


def _cause_chain(exc: BaseException):
    """The exception, then what it wraps: LangChain wraps the SDK error, which
    wraps the HTTP response, so a status can sit two levels down."""
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def provider_status(exc: BaseException):
    """The first HTTP status found along the cause chain, or None."""
    for current in _cause_chain(exc):
        status = _http_status_of(current)
        if status is not None:
            return status
    return None


def provider_error_kind(exc: BaseException):
    """Which kind of 429 a failed model call was, or None when it was not one.

    `rate_limited` clears by waiting. `quota_exhausted` (no credit, a daily
    quota) and `request_too_large` (one request over the per-minute limit)
    never do. A 402 is `quota_exhausted` too: DeepSeek and OpenRouter answer
    "no credit" with Payment Required instead of a 429. A fixed word, so it may reach the browser where the text may not.
    An Agent in the Loop error is never one: it is not a provider's answer.
    """
    if getattr(exc, "no_retry", False):
        return None
    limited = False
    status = None
    texts = []
    for current in _cause_chain(exc):
        current_status = _http_status_of(current)
        status = status if status is not None else current_status
        response = getattr(current, "response", None)
        aws_code = ((response.get("Error") or {}).get("Code")
                    if isinstance(response, dict) else None)
        if current_status == 429 or aws_code in _AWS_THROTTLING_CODES or any(
                base.__name__ in _RATE_LIMIT_CLASS_NAMES for base in type(current).__mro__):
            limited = True
        texts.append(str(current).lower())
    text = " ".join(texts)
    if status == 402:
        return "quota_exhausted"
    # The words decide only when no status does: a 400 or 403 that mentions a
    # rate limit is that status's error, and waiting two minutes would not fix it.
    if not limited and (status is not None
                        or not any(phrase in text for phrase in _RATE_LIMIT_PHRASES)):
        return None
    if any(phrase in text for phrase in _QUOTA_EXHAUSTED_PHRASES) or _DAILY_QUOTA.search(text):
        return "quota_exhausted"
    if _REQUEST_TOO_LARGE_PHRASE in text:
        return "request_too_large"
    return "rate_limited"


def provider_error_details(exc: BaseException) -> dict:
    """What a person may see of a provider failure: its class and HTTP status.

    `{"error_class": "RateLimitError", "provider_status": 429}`; a key is left out
    when it is unknown. The SDK's message is never included: a 401 body can quote
    part of the key and a 400 the prompt. The class is the one that carried the
    status (LangChain and the SDKs wrap it), else the outermost one.

    A 429 adds `provider_error_kind` (see provider_error_kind), and a call that
    waited for a rate limit to clear adds `rate_limit_waited_s`, set on the
    exception by orchestrator_helpers.llm_retry when it gave up.
    """
    out = {}
    for current in _cause_chain(exc):
        status = _http_status_of(current)
        if status is not None:
            out["provider_status"] = status
            name = type(current).__name__
            break
    else:
        name = type(exc).__name__
    if _SAFE_CLASS_NAME.match(name):
        out["error_class"] = name
    kind = provider_error_kind(exc)
    if kind:
        out["provider_error_kind"] = kind
    waited = getattr(exc, "rate_limit_waited_s", None)
    if isinstance(waited, int) and not isinstance(waited, bool) and waited > 0:
        out["rate_limit_waited_s"] = waited
    return out


def log_provider_error(feature: str, model: str, exc: BaseException) -> None:
    """Log a provider failure with secrets redacted; the browser gets a fixed text."""
    try:
        from logging_config import redact_text
        detail = redact_text(str(exc))
    except Exception:                                             # noqa: BLE001
        detail = exc.__class__.__name__
    logger.warning(f"{feature}: model {model} failed: "
                   f"{exc.__class__.__name__}: {detail[:500]}")
