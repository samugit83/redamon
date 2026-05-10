"""LLM initialization and project settings helpers."""

import logging

from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel

from project_settings import load_project_settings

logger = logging.getLogger(__name__)

# Anthropic models that reject the `temperature` parameter (HTTP 400
# "temperature is deprecated for this model"). Add new model IDs here as
# Anthropic deprecates the param on subsequent generations.
ANTHROPIC_NO_TEMPERATURE_MODELS = {
    "claude-opus-4-7",
    "claude-sonnet-4-7",
    "claude-haiku-4-6",
}


def _anthropic_supports_temperature(model_id: str) -> bool:
    return model_id not in ANTHROPIC_NO_TEMPERATURE_MODELS


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
    aws_region: str = "us-east-1",
    custom_llm_config: dict | None = None,
) -> BaseChatModel:
    """Initialize and return the LLM based on model name (detect provider from prefix).

    For custom/ models, custom_llm_config must contain the UserLlmProvider fields.
    For built-in providers, the relevant API key must be supplied.
    """
    logger.info(f"Setting up LLM: {model_name}")

    provider, api_model = parse_model_provider(model_name)

    if provider == "custom":
        if not custom_llm_config:
            raise ValueError(
                f"Custom LLM config is required for model '{model_name}'. "
                "Configure the provider in Global Settings."
            )
        ptype = custom_llm_config.get("providerType", "openai_compatible")

        if ptype == "anthropic":
            anth_model = custom_llm_config.get("modelIdentifier", api_model)
            anth_kwargs = dict(
                model=anth_model,
                api_key=custom_llm_config.get("apiKey", ""),
                base_url=custom_llm_config.get("baseUrl") or None,
                default_headers=custom_llm_config.get("defaultHeaders") or {},
                timeout=float(custom_llm_config.get("timeout", 120)),
                max_tokens=custom_llm_config.get("maxTokens", 16384),
                # FIX: Survive transient VPS network blips. SDK default is
                # max_retries=2 with ~3s total budget. Network spikes on this
                # path can last 5-10s, so 2 retries fail before the spike
                # clears. 5 retries spread over ~30s ride out any reasonable
                # blip. default_request_timeout=60s overrides httpx's default
                # 5s connect timeout that fails mid-handshake during spikes.
                max_retries=5,
                default_request_timeout=300.0,  # 5 min - generous for Opus heavy prompts but trips before Anthropic 10-min server timeout
            )
            if _anthropic_supports_temperature(anth_model):
                anth_kwargs["temperature"] = custom_llm_config.get("temperature", 0)
            llm = ChatAnthropic(**anth_kwargs)
        elif ptype == "bedrock":
            from langchain_aws import ChatBedrockConverse
            llm = ChatBedrockConverse(
                model=custom_llm_config.get("modelIdentifier", api_model),
                region_name=custom_llm_config.get("awsRegion", "us-east-1"),
                aws_access_key_id=custom_llm_config.get("awsAccessKeyId") or None,
                aws_secret_access_key=custom_llm_config.get("awsSecretKey") or None,
                temperature=custom_llm_config.get("temperature", 0),
                max_tokens=custom_llm_config.get("maxTokens", 16384),
            )
        else:
            # openai_compatible (default) — also handles openai/openrouter custom entries
            kwargs = dict(
                model=custom_llm_config.get("modelIdentifier", api_model),
                api_key=custom_llm_config.get("apiKey") or "ollama",
                temperature=custom_llm_config.get("temperature", 0),
                max_tokens=custom_llm_config.get("maxTokens", 16384),
            )
            base_url = custom_llm_config.get("baseUrl")
            if base_url:
                kwargs["base_url"] = base_url
            headers = custom_llm_config.get("defaultHeaders")
            if headers:
                kwargs["default_headers"] = headers
            timeout = custom_llm_config.get("timeout")
            if timeout:
                kwargs["timeout"] = float(timeout)
            ssl_verify = custom_llm_config.get("sslVerify", True)
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
        llm = ChatOpenAI(
            model=api_model,
            api_key=openai_compat_api_key or "ollama",
            base_url=openai_compat_base_url,
            temperature=0,
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
                "HTTP-Referer": "https://redamon.dev",
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
        llm = ChatOpenAI(
            model=api_model,
            api_key=kimi_api_key,
            base_url="https://api.moonshot.ai/v1",
            temperature=0,
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
        if not aws_access_key_id or not aws_secret_access_key:
            raise ValueError(
                f"AWS credentials are required for model '{model_name}'"
            )
        from langchain_aws import ChatBedrockConverse
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
            # FIX: Survive transient VPS network blips. See comment on the
            # custom-provider path above for full rationale.
            max_retries=5,
            default_request_timeout=300.0,  # 5 min - generous for Opus heavy prompts but trips before Anthropic 10-min server timeout
        )
        if _anthropic_supports_temperature(api_model):
            anth_kwargs["temperature"] = 0
        llm = ChatAnthropic(**anth_kwargs)

    else:  # openai
        if not openai_api_key:
            raise ValueError(
                f"OpenAI API key is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=openai_api_key,
            temperature=0,
        )

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


def apply_project_settings(orchestrator, project_id: str) -> None:
    """Load project settings from webapp API and reconfigure LLM if model changed."""
    settings = load_project_settings(project_id)
    new_model = settings.get('OPENAI_MODEL', 'claude-opus-4-6')

    # Re-run LLM setup if model changed OR if LLM is None (previous setup failed)
    model_changed = new_model != orchestrator.model_name
    need_setup = model_changed or orchestrator.llm is None
    if need_setup:
        if model_changed:
            logger.info(f"Model changed: {orchestrator.model_name} -> {new_model}")
        else:
            logger.info(f"Retrying LLM setup for {new_model} (previous attempt failed)")
        orchestrator.model_name = new_model

        # Resolve keys from user's LLM providers (DB-driven)
        user_providers = settings.get('USER_LLM_PROVIDERS', [])
        custom_config = settings.get('CUSTOM_LLM_CONFIG')

        # Build kwargs from DB providers (no env-var fallback)
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

        try:
            orchestrator.llm = setup_llm(
                new_model,
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
                aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
                custom_llm_config=custom_config,
            )
        except (ValueError, Exception) as e:
            logger.error(f"LLM setup failed for {new_model}: {e}")
            orchestrator.llm = None
            return

        # Update Neo4j tool's LLM for text-to-Cypher queries
        if orchestrator.neo4j_manager:
            orchestrator.neo4j_manager.llm = orchestrator.llm
            logger.info("Updated Neo4j tool LLM")

    # Store user settings on orchestrator for other components (Tavily key)
    user_settings = settings.get('USER_SETTINGS', {})
    if user_settings:
        orchestrator._user_settings = user_settings
