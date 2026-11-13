"""LLM initialization and project settings helpers."""

import hashlib
import json
import logging
from collections import OrderedDict

from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel

from project_settings import load_project_settings
from agent_context import set_llm_context
from orchestrator_helpers.llm_url_guard import validate_llm_base_url
from llm_builder import (
    INSTANCE_MODEL_PREFIX,
    NON_CHAT_PROVIDER_TYPES,
    InstanceProviderUnavailable,
    instance_build_args,
)

logger = logging.getLogger(__name__)

OLLAMA_REASONING_EFFORTS = frozenset({"low", "medium", "high", "max"})

# Anthropic models that reject the `temperature` parameter (HTTP 400
# "temperature is deprecated for this model"). Anthropic deprecated the param
# from the 4.7 / 4.6 generation onward and rejects it on every newer model.
ANTHROPIC_NO_TEMPERATURE_MODELS = {
    "claude-opus-4-7",
    "claude-sonnet-4-7",
    "claude-haiku-4-6",
    "claude-opus-4-8",
}

# Prefix families that reject `temperature` regardless of any date- or
# context-window suffix (e.g. "claude-opus-4-8-20260115", "claude-opus-4-8[1m]",
# "claude-sonnet-5-...")). Anthropic's deprecation is one-directional — newer
# generations keep dropping the param — so match whole families by prefix. This
# is the fast path; retry_llm_call self-heals anything not covered here.
ANTHROPIC_NO_TEMPERATURE_PREFIXES = (
    "claude-opus-4-8",
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-haiku-5",
    "claude-fable-5",
)


def _anthropic_supports_temperature(model_id: str) -> bool:
    if model_id in ANTHROPIC_NO_TEMPERATURE_MODELS:
        return False
    return not any(model_id.startswith(p) for p in ANTHROPIC_NO_TEMPERATURE_PREFIXES)


def _anthropic_sdk_refuses_sampling() -> bool:
    """True when the installed `anthropic` SDK sends API version 2026-10-21.

    The SDK picks the version: 2.0.0 and later send `anthropic-version:
    2026-10-21`, on which every model answers `temperature`, `top_p` or `top_k`
    with a 400 ("temperature: Extra inputs are not permitted"); 1.x sends
    2023-06-01, where the lists above decide. The webapp's preset generator
    sends 2023-06-01 itself, so those lists stay its rule too.
    """
    import anthropic
    try:
        return int(str(anthropic.__version__).split(".")[0]) >= 2
    except ValueError:
        return True


def _anthropic_sends_temperature(model_id: str) -> bool:
    return not _anthropic_sdk_refuses_sampling() and _anthropic_supports_temperature(model_id)


# OpenAI reasoning families accept only the default temperature (1) and reject
# 0 with HTTP 400 "Only the default (1) value is supported". Matched by prefix
# so dated/variant ids (gpt-6-luna, o3-mini-2025-01-31) are covered. Like the
# Anthropic list this is the fast path: it saves the rejected first request,
# and the call sites that run ainvoke() without retry_llm_call's self-heal
# (CypherFix, the report summarizer, the /llm/* endpoints) depend on it.
OPENAI_NO_TEMPERATURE_PREFIXES = (
    "o1", "o3", "o4",
    "gpt-5", "gpt-6",
)
# gpt-5-chat-* is the non-reasoning ChatGPT snapshot and still takes temperature.
OPENAI_TEMPERATURE_EXCEPTIONS = ("gpt-5-chat",)


def _openai_supports_temperature(model_id: str) -> bool:
    # Custom/OpenRouter-style ids may carry a vendor prefix ("openai/gpt-6-luna").
    name = model_id.rsplit("/", 1)[-1].lower()
    if name.startswith(OPENAI_TEMPERATURE_EXCEPTIONS):
        return True
    return not name.startswith(OPENAI_NO_TEMPERATURE_PREFIXES)


def _resolve_reasoning_effort(custom_llm_config: dict) -> str | None:
    """Return the OpenAI-compatible ``reasoning_effort`` value to send, if any.

    Enabling the control is an explicit opt-in and works through reverse
    proxies. When disabled we send nothing at all, so the model's own default
    thinking behavior is preserved and unrelated OpenAI-compatible providers
    are untouched. Enabling reasoning on a model that lacks the thinking
    capability makes the endpoint reject the request; ``retry_llm_call``
    self-heals that by dropping ``reasoning_effort`` and retrying once.
    """
    if custom_llm_config.get("reasoningEnabled") is not True:
        return None

    effort = str(custom_llm_config.get("reasoningEffort", "high")).lower()
    if effort not in OLLAMA_REASONING_EFFORTS:
        allowed = ", ".join(sorted(OLLAMA_REASONING_EFFORTS))
        raise ValueError(f"Invalid reasoning effort '{effort}'. Expected one of: {allowed}")
    return effort


def parse_model_provider(model_name: str) -> tuple[str, str]:
    """
    Parse provider and API model name from the stored model identifier.

    Prefix convention:
      - "custom/<configId>"   → ("custom", "<configId>")
      - "openrouter/<model>"  → ("openrouter", "<model>")
      - "bedrock/<model>"     → ("bedrock", "<model>")
      - "deepseek/<model>"    → ("deepseek", "<model>")
      - "gemini/<model>"      → ("gemini", "<model>")
      - "glm/<model>"         → ("glm", "<model>")
      - "kimi/<model>"        → ("kimi", "<model>")
      - "qwen/<model>"        → ("qwen", "<model>")
      - "xai/<model>"         → ("xai", "<model>")
      - "mistral/<model>"     → ("mistral", "<model>")
      - "loop/<name>"         → ("loop", "<name>")  Agent in the Loop, not a provider:
                                an external MCP client answers, no key is involved
      - "instance/<id>/<model>" → ("instance", "<id>/<model>")  an administrator's
                                provider (GV-15); built only from its own row
                                (llm_builder.instance_build_args), never sent on
      - "claude-*"            → ("anthropic", "claude-*")
      - anything else         → ("openai", "<model>")

    Legacy (still supported for backward compat):
      - "openai_compat/<model>" → ("openai_compat", "<model>")
    """
    if model_name.startswith("custom/"):
        return ("custom", model_name[len("custom/"):])
    elif model_name.startswith("openai_compat/"):
        return ("openai_compat", model_name[len("openai_compat/"):])
    elif model_name.startswith("openrouter/"):
        return ("openrouter", model_name[len("openrouter/"):])
    elif model_name.startswith("bedrock/"):
        return ("bedrock", model_name[len("bedrock/"):])
    elif model_name.startswith("deepseek/"):
        return ("deepseek", model_name[len("deepseek/"):])
    elif model_name.startswith("gemini/"):
        return ("gemini", model_name[len("gemini/"):])
    elif model_name.startswith("glm/"):
        return ("glm", model_name[len("glm/"):])
    elif model_name.startswith("kimi/"):
        return ("kimi", model_name[len("kimi/"):])
    elif model_name.startswith("qwen/"):
        return ("qwen", model_name[len("qwen/"):])
    elif model_name.startswith("xai/"):
        return ("xai", model_name[len("xai/"):])
    elif model_name.startswith("mistral/"):
        return ("mistral", model_name[len("mistral/"):])
    elif model_name.startswith("loop/"):
        return ("loop", model_name[len("loop/"):])
    elif model_name.startswith(INSTANCE_MODEL_PREFIX):
        return ("instance", model_name[len(INSTANCE_MODEL_PREFIX):])
    elif model_name.startswith("claude-"):
        return ("anthropic", model_name)
    else:
        return ("openai", model_name)


def setup_llm(
    model_name: str,
    *,
    openai_api_key: str | None = None,
    anthropic_api_key: str | None = None,
    openrouter_api_key: str | None = None,
    deepseek_api_key: str | None = None,
    gemini_api_key: str | None = None,
    glm_api_key: str | None = None,
    kimi_api_key: str | None = None,
    qwen_api_key: str | None = None,
    xai_api_key: str | None = None,
    mistral_api_key: str | None = None,
    openai_compat_api_key: str | None = None,
    openai_compat_base_url: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
    aws_bearer_token: str | None = None,
    aws_region: str = "us-east-1",
    custom_llm_config: dict | None = None,
) -> BaseChatModel:
    """Initialize and return the LLM based on model name (detect provider from prefix).

    For custom/ models, custom_llm_config must contain the UserLlmProvider fields.
    For instance/ models, custom_llm_config must be the exact instance row the id
    names (llm_builder.exact_model_provider); anything else is refused with
    InstanceProviderUnavailable, and the keys passed here are never used for it.
    For built-in providers, the relevant API key must be supplied.
    """
    logger.info(f"Setting up LLM: {model_name}")

    provider, api_model = parse_model_provider(model_name)

    if provider == "instance":
        native_model, build_kwargs = instance_build_args(model_name, custom_llm_config)
        from llm_budget import attach_instance_budget
        # The daily budget (GV-12) is asked before every call; the row names its list's owner.
        return attach_instance_budget(setup_llm(native_model, **build_kwargs),
                                      owner_id=str(custom_llm_config.get("userId") or ""),
                                      provider_id=str(custom_llm_config.get("id") or ""))

    if provider == "loop":
        from agent_in_the_loop import loop_enabled
        if not loop_enabled():
            raise ValueError(
                "Agent in the Loop is turned off on this deployment (AGENT_IN_THE_LOOP_ENABLED)."
            )
        from agent_in_the_loop.model import LoopChatModel
        return LoopChatModel()

    if provider == "custom":
        if not custom_llm_config:
            raise ValueError(
                f"Custom LLM config is required for model '{model_name}'. "
                "Configure the provider in Global Settings."
            )
        ptype = custom_llm_config.get("providerType", "openai_compatible")
        if ptype in NON_CHAT_PROVIDER_TYPES:
            # The default branch below would send this key to api.openai.com.
            raise ValueError(
                f"Provider type '{ptype}' is not a chat model provider and "
                f"cannot serve model '{model_name}'."
            )

        if ptype == "anthropic":
            anth_model = custom_llm_config.get("modelIdentifier", api_model)
            # SSRF guard (I15): reject metadata/link-local baseUrl targets. The
            # anthropic SDK has no TLS-off knob, so ssl_verify stays True here.
            validate_llm_base_url(custom_llm_config.get("baseUrl"))
            anth_kwargs = dict(
                model=anth_model,
                api_key=custom_llm_config.get("apiKey", ""),
                base_url=custom_llm_config.get("baseUrl") or None,
                default_headers=custom_llm_config.get("defaultHeaders") or {},
                timeout=float(custom_llm_config.get("timeout", 120)),
                max_tokens=custom_llm_config.get("maxTokens", 16384),
                # Survive transient network blips. SDK default max_retries=2
                # with ~3s total budget fails through spikes lasting 5-10s; 5
                # retries spread over ~30s ride out any reasonable blip. The
                # per-request timeout is user-configurable via the `timeout`
                # kwarg above (alias of default_request_timeout in
                # langchain_anthropic — passing both would silently let the
                # user value win, so we keep only the configurable one).
                max_retries=5,
            )
            if _anthropic_sends_temperature(anth_model):
                anth_kwargs["temperature"] = custom_llm_config.get("temperature", 0)
            llm = ChatAnthropic(**anth_kwargs)
        elif ptype == "bedrock":
            from langchain_aws import ChatBedrockConverse
            bedrock_kwargs = dict(
                model=custom_llm_config.get("modelIdentifier", api_model),
                region_name=custom_llm_config.get("awsRegion", "us-east-1"),
                temperature=custom_llm_config.get("temperature", 0),
                max_tokens=custom_llm_config.get("maxTokens", 16384),
            )
            bearer = custom_llm_config.get("awsBearerToken") or None
            if bearer:
                # Bedrock long-term API key (bearer auth, boto3 >= 1.39).
                bedrock_kwargs["bedrock_api_key"] = bearer
            else:
                bedrock_kwargs["aws_access_key_id"] = custom_llm_config.get("awsAccessKeyId") or None
                bedrock_kwargs["aws_secret_access_key"] = custom_llm_config.get("awsSecretKey") or None
            llm = ChatBedrockConverse(**bedrock_kwargs)
        else:
            # openai_compatible (default) — also handles openai/openrouter custom entries
            oai_model = custom_llm_config.get("modelIdentifier", api_model)
            kwargs = dict(
                model=oai_model,
                api_key=custom_llm_config.get("apiKey") or "ollama",
                max_tokens=custom_llm_config.get("maxTokens", 16384),
            )
            if _openai_supports_temperature(oai_model):
                kwargs["temperature"] = custom_llm_config.get("temperature", 0)
            if ptype == "openai_compatible":
                # Consume OpenAI-compatible responses as SSE while preserving
                # the existing ainvoke() contract. Long-running cloud-backed
                # runtimes such as Ollama can otherwise leave a non-streaming
                # request silent until the full completion is ready, causing
                # an intermediary/read timeout even though generation is
                # healthy. stream_usage keeps token accounting intact when
                # ChatOpenAI aggregates the chunks into one AIMessage.
                kwargs["streaming"] = True
                kwargs["stream_usage"] = True
                reasoning_effort = _resolve_reasoning_effort(custom_llm_config)
                if reasoning_effort is not None:
                    kwargs["reasoning_effort"] = reasoning_effort
            base_url = custom_llm_config.get("baseUrl")
            ssl_verify = custom_llm_config.get("sslVerify", True)
            # SSRF guard (I15) + TLS-off-on-public guard (I16). Localhost/LAN
            # self-hosted models stay allowed; cloud metadata is rejected.
            validate_llm_base_url(base_url, ssl_verify=ssl_verify)
            if base_url:
                kwargs["base_url"] = base_url
            headers = custom_llm_config.get("defaultHeaders")
            if headers:
                kwargs["default_headers"] = headers
            timeout = custom_llm_config.get("timeout")
            if timeout:
                kwargs["timeout"] = float(timeout)
            if not ssl_verify:
                import httpx
                kwargs["http_client"] = httpx.Client(verify=False)
                kwargs["http_async_client"] = httpx.AsyncClient(verify=False)
            llm = ChatOpenAI(**kwargs)

    elif provider == "openai_compat":
        # Legacy: openai_compat/ prefix (env-var based)
        if not openai_compat_base_url:
            raise ValueError(
                f"OPENAI_COMPAT_BASE_URL is required for model '{model_name}'. "
                "Consider migrating to Global Settings."
            )
        # Operator-set env baseUrl; guard it too for defense in depth (I15).
        validate_llm_base_url(openai_compat_base_url)
        llm = ChatOpenAI(
            model=api_model,
            api_key=openai_compat_api_key or "ollama",
            base_url=openai_compat_base_url,
            temperature=0,
            streaming=True,
            stream_usage=True,
        )

    elif provider == "openrouter":
        if not openrouter_api_key:
            raise ValueError(
                f"OpenRouter API key is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=openrouter_api_key,
            base_url="https://openrouter.ai/api/v1",
            temperature=0,
            default_headers={
                "HTTP-Referer": "https://www.redamon.org",
                "X-Title": "RedAmon Agent",
            },
        )

    elif provider == "deepseek":
        if not deepseek_api_key:
            raise ValueError(
                f"DeepSeek API key is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=deepseek_api_key,
            base_url="https://api.deepseek.com/v1",
            temperature=0,
        )

    elif provider == "gemini":
        if not gemini_api_key:
            raise ValueError(
                f"Google Gemini API key is required for model '{model_name}'"
            )
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(
            model=api_model,
            google_api_key=gemini_api_key,
            temperature=0,
        )

    elif provider == "glm":
        if not glm_api_key:
            raise ValueError(
                f"GLM (Zhipu AI) API key is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=glm_api_key,
            base_url="https://open.bigmodel.cn/api/paas/v4",
            temperature=0,
        )

    elif provider == "kimi":
        if not kimi_api_key:
            raise ValueError(
                f"Kimi (Moonshot) API key is required for model '{model_name}'"
            )
        # Moonshot's reasoning models (kimi-k3, kimi-k2.6, ...) reject any
        # temperature except 1 with a permanent HTTP 400 ("invalid temperature:
        # only 1 is allowed for this model"). Classic moonshot-v1 models accept
        # 0, but there is no reliable per-model signal, so we omit temperature
        # entirely and let each model use its own default rather than crash the
        # newer ones. The llm_retry self-heal is the backstop if a future model
        # ever forces a different fixed value.
        llm = ChatOpenAI(
            model=api_model,
            api_key=kimi_api_key,
            base_url="https://api.moonshot.ai/v1",
        )

    elif provider == "qwen":
        if not qwen_api_key:
            raise ValueError(
                f"Qwen (Alibaba) API key is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=qwen_api_key,
            base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            temperature=0,
        )

    elif provider == "xai":
        if not xai_api_key:
            raise ValueError(
                f"xAI (Grok) API key is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=xai_api_key,
            base_url="https://api.x.ai/v1",
            temperature=0,
        )

    elif provider == "mistral":
        if not mistral_api_key:
            raise ValueError(
                f"Mistral AI API key is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=mistral_api_key,
            base_url="https://api.mistral.ai/v1",
            temperature=0,
        )

    elif provider == "bedrock":
        from langchain_aws import ChatBedrockConverse
        if aws_bearer_token:
            # Long-term Bedrock API key (bearer auth). Takes precedence over
            # IAM keys if both are supplied — the UI surfaces one or the other.
            llm = ChatBedrockConverse(
                model=api_model,
                region_name=aws_region,
                bedrock_api_key=aws_bearer_token,
                temperature=0,
            )
        else:
            if not aws_access_key_id or not aws_secret_access_key:
                raise ValueError(
                    f"AWS credentials are required for model '{model_name}' "
                    "(set IAM access key + secret, or a Bedrock long-term API key)"
                )
            llm = ChatBedrockConverse(
                model=api_model,
                region_name=aws_region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                temperature=0,
            )

    elif provider == "anthropic":
        if not anthropic_api_key:
            raise ValueError(
                f"Anthropic API key is required for model '{model_name}'"
            )
        anth_kwargs = dict(
            model=api_model,
            api_key=anthropic_api_key,
            max_tokens=16384,
            # Survive transient network blips: see custom-provider path for
            # max_retries rationale. 300s is below Anthropic's 10-min
            # server-side cap but generous for Opus heavy prompts.
            max_retries=5,
            default_request_timeout=300.0,
        )
        if _anthropic_sends_temperature(api_model):
            anth_kwargs["temperature"] = 0
        llm = ChatAnthropic(**anth_kwargs)

    else:  # openai
        if not openai_api_key:
            raise ValueError(
                f"OpenAI API key is required for model '{model_name}'"
            )
        oai_kwargs = dict(model=api_model, api_key=openai_api_key)
        if _openai_supports_temperature(api_model):
            oai_kwargs["temperature"] = 0
        llm = ChatOpenAI(**oai_kwargs)

    logger.info(f"LLM provider: {provider}, model: {api_model}")
    return llm


def _resolve_provider_key(
    providers: list[dict],
    provider_type: str,
) -> dict | None:
    """Find the first provider entry matching the given type."""
    for p in providers:
        if p.get("providerType") == provider_type:
            return p
    return None


# Every setup_llm refusal for a missing key or provider row says this, and only those do.
_MISSING_CREDENTIALS_MARKER = " is required for model "


def llm_setup_failure(model: str, exc: BaseException) -> dict:
    """Why `model` could not be built, in the words an error frame may carry.

    A missing key or provider row is `llm_not_configured`: the person has to add
    one. Anything else (an SDK refusing its arguments, a non-chat provider row,
    a bad option) is `llm_setup_failed` with the exception's class, never its
    text: a client constructor's validation error can echo the key it was given.
    An `instance/` model the owner's list does not hold is
    `instance_provider_unavailable`: only an administrator can change that.
    """
    if isinstance(exc, InstanceProviderUnavailable):
        return {"code": InstanceProviderUnavailable.code, "model": model}
    if isinstance(exc, ValueError) and _MISSING_CREDENTIALS_MARKER in str(exc):
        return {"code": "llm_not_configured", "model": model}
    return {"code": "llm_setup_failed", "model": model, "error_class": type(exc).__name__}


class LlmClientCache:
    """The agent's model clients, one per (model id, provider fingerprint, owner).

    Each run is bound to the client built from its own owner's providers (RBAC T17,
    F-16). The single slot this replaces was rebuilt only when the model id changed,
    so a second owner on the same model id ran on the first owner's key. Least
    recently used out; a key holds a SHA-256, never a credential.
    """

    MAX_ENTRIES = 32

    def __init__(self):
        self._entries: "OrderedDict[tuple[str, str, str], BaseChatModel]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def keys(self) -> list:
        return list(self._entries)

    def get_or_build(self, key: tuple[str, str, str], build) -> BaseChatModel:
        llm = self._entries.get(key)
        if llm is not None:
            self._entries.move_to_end(key)
            return llm
        llm = build()
        self._entries[key] = llm
        while len(self._entries) > self.MAX_ENTRIES:
            self._entries.popitem(last=False)
        return llm


def provider_fingerprint(providers: list, custom_config: dict | None) -> str:
    """SHA-256 of everything a client is built from: a changed key, base URL or
    header is a different client."""
    blob = json.dumps({"providers": providers or [], "custom": custom_config or None},
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def credential_owner(providers: list) -> str:
    """The account whose provider rows these are (the webapp sends each row's userId)."""
    for p in providers or []:
        if isinstance(p, dict) and p.get("userId"):
            return str(p["userId"])
    return ""


def _build_llm_from_settings(model: str, settings: dict) -> BaseChatModel:
    """Build `model` from the providers in this run's settings (DB-driven, no env-var fallback)."""
    user_providers = settings.get('USER_LLM_PROVIDERS', []) or []
    openai_p = _resolve_provider_key(user_providers, "openai")
    anthropic_p = _resolve_provider_key(user_providers, "anthropic")
    openrouter_p = _resolve_provider_key(user_providers, "openrouter")
    bedrock_p = _resolve_provider_key(user_providers, "bedrock")
    deepseek_p = _resolve_provider_key(user_providers, "deepseek")
    gemini_p = _resolve_provider_key(user_providers, "gemini")
    glm_p = _resolve_provider_key(user_providers, "glm")
    kimi_p = _resolve_provider_key(user_providers, "kimi")
    qwen_p = _resolve_provider_key(user_providers, "qwen")
    xai_p = _resolve_provider_key(user_providers, "xai")
    mistral_p = _resolve_provider_key(user_providers, "mistral")
    return setup_llm(
        model,
        openai_api_key=(openai_p or {}).get("apiKey"),
        anthropic_api_key=(anthropic_p or {}).get("apiKey"),
        openrouter_api_key=(openrouter_p or {}).get("apiKey"),
        deepseek_api_key=(deepseek_p or {}).get("apiKey"),
        gemini_api_key=(gemini_p or {}).get("apiKey"),
        glm_api_key=(glm_p or {}).get("apiKey"),
        kimi_api_key=(kimi_p or {}).get("apiKey"),
        qwen_api_key=(qwen_p or {}).get("apiKey"),
        xai_api_key=(xai_p or {}).get("apiKey"),
        mistral_api_key=(mistral_p or {}).get("apiKey"),
        aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
        aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
        aws_bearer_token=(bedrock_p or {}).get("awsBearerToken"),
        aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
        custom_llm_config=settings.get('CUSTOM_LLM_CONFIG'),
    )


def _client_cache(orchestrator) -> LlmClientCache:
    cache = getattr(orchestrator, "_llm_cache", None)
    if not isinstance(cache, LlmClientCache):
        cache = LlmClientCache()
        orchestrator._llm_cache = cache
    return cache


def apply_project_settings(orchestrator, project_id: str) -> None:
    """Load the project's settings and bind THIS run's model client to the task.

    The client is the cache entry of the run's own model id, provider fingerprint
    and owner. A run whose model cannot be built gets no client, never another
    run's, and `llm_setup_failure` says why. apply_project_settings is fully
    synchronous, so the binding is atomic for this task; nodes, Fireteam members
    and text-to-Cypher read it through `current_llm`.
    """
    settings = load_project_settings(project_id)

    # HTTP traffic capture (Phase 1): the per-project routing gate is now read
    # from the (task-isolated) CAPTURE_PROXY_ENABLED setting at tool-execution
    # time (tools.py), so concurrent sessions can't clobber a shared flag. No
    # per-turn mutation of the shared tool_executor is needed here anymore.

    model = settings.get('OPENAI_MODEL', 'claude-opus-4-6')
    providers = settings.get('USER_LLM_PROVIDERS', []) or []
    key = (model, provider_fingerprint(providers, settings.get('CUSTOM_LLM_CONFIG')),
           credential_owner(providers))
    try:
        llm = _client_cache(orchestrator).get_or_build(
            key, lambda: _build_llm_from_settings(model, settings))
    except Exception as e:
        logger.error(f"LLM setup failed for {model}: {type(e).__name__}: {e}")
        llm = None
        orchestrator.llm_setup_failure = llm_setup_failure(model, e)
    else:
        orchestrator.llm_setup_failure = None

    # On AgentOrchestrator `llm` is this task's view of current_llm, not a shared slot.
    orchestrator.llm = llm
    set_llm_context(llm)
