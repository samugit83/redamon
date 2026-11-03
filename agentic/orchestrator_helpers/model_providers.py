"""
Model provider discovery for RedAmon Agent.

Fetches available models from configured AI providers (OpenAI, Anthropic,
OpenRouter, AWS Bedrock) and returns them in a unified format for the frontend.
Provider keys come from user settings in the database (passed as params).
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Unified model schema
# ---------------------------------------------------------------------------
def _model(id: str, name: str, context_length: int | None = None,
           description: str = "") -> dict:
    return {
        "id": id,
        "name": name,
        "context_length": context_length,
        "description": description,
    }


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------
async def fetch_openai_models(api_key: str = "") -> list[dict]:
    """Fetch chat models from the OpenAI API."""
    if not api_key:
        return []

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        resp.raise_for_status()

    data = resp.json().get("data", [])

    # Keep only chat-capable models (gpt-*, o1-*, o3-*)
    chat_prefixes = ("gpt-", "o1-", "o3-", "o4-")
    # Exclude known non-chat suffixes
    exclude_suffixes = ("-instruct", "-realtime", "-transcribe", "-tts", "-search",
                        "-audio", "-mini-tts")
    exclude_substrings = ("dall-e", "whisper", "embedding", "moderation", "davinci",
                          "babbage", "curie")

    models = []
    for m in data:
        mid = m.get("id", "")
        if not any(mid.startswith(p) for p in chat_prefixes):
            continue
        if any(mid.endswith(s) for s in exclude_suffixes):
            continue
        if any(sub in mid for sub in exclude_substrings):
            continue
        models.append(_model(
            id=mid,
            name=mid,
            description="OpenAI",
        ))

    # Sort: newest/largest first (reverse alphabetical is a rough proxy)
    models.sort(key=lambda m: m["id"], reverse=True)
    return models


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------
async def fetch_anthropic_models(api_key: str = "") -> list[dict]:
    """Fetch models from the Anthropic API."""
    if not api_key:
        return []

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            params={"limit": 100},
        )
        resp.raise_for_status()

    data = resp.json().get("data", [])
    models = []
    for m in data:
        mid = m.get("id", "")
        display_name = m.get("display_name", mid)
        models.append(_model(
            id=mid,
            name=display_name,
            description="Anthropic",
        ))

    return models


# ---------------------------------------------------------------------------
# OpenRouter
# ---------------------------------------------------------------------------
async def fetch_openrouter_models(api_key: str = "") -> list[dict]:
    """Fetch models from the OpenRouter API."""
    # OpenRouter model listing is public, but we only show it if a key is configured
    if not api_key:
        return []

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get("https://openrouter.ai/api/v1/models")
        resp.raise_for_status()

    data = resp.json().get("data", [])

    models = []
    for m in data:
        mid = m.get("id", "")
        name = m.get("name", mid)
        ctx = m.get("context_length")

        # Only include models that accept text input and produce text output
        arch = m.get("architecture", {})
        input_mods = arch.get("input_modalities", [])
        output_mods = arch.get("output_modalities", [])
        if "text" not in input_mods or "text" not in output_mods:
            continue

        # Build pricing description
        pricing = m.get("pricing", {})
        prompt_cost = pricing.get("prompt", "0")
        completion_cost = pricing.get("completion", "0")
        try:
            p_cost = float(prompt_cost) * 1_000_000
            c_cost = float(completion_cost) * 1_000_000
            price_desc = f"${p_cost:.2f}/${c_cost:.2f} per 1M tokens"
        except (ValueError, TypeError):
            price_desc = ""

        models.append(_model(
            id=f"openrouter/{mid}",
            name=name,
            context_length=ctx,
            description=price_desc,
        ))

    return models


# ---------------------------------------------------------------------------
# xAI (Grok)
# ---------------------------------------------------------------------------
_XAI_FALLBACK_MODELS: list[tuple[str, str]] = [
    ("grok-3", "Grok 3"),
    ("grok-3-fast", "Grok 3 Fast"),
    ("grok-3-mini", "Grok 3 Mini"),
    ("grok-3-mini-fast", "Grok 3 Mini Fast"),
    ("grok-2", "Grok 2"),
    ("grok-2-image", "Grok 2 Image"),
]


async def fetch_xai_models(api_key: str = "") -> list[dict]:
    """Fetch chat models from xAI's OpenAI-compatible /v1/models endpoint."""
    if not api_key:
        return []

    discovered: list[dict] = await _fetch_openai_compat_models(
        base_url="https://api.x.ai/v1",
        api_key=api_key,
        id_prefix="xai",
        description="xAI Grok",
    )

    if not discovered:
        for mid, mname in _XAI_FALLBACK_MODELS:
            discovered.append(_model(
                id=f"xai/{mid}",
                name=mname,
                description="xAI Grok",
            ))

    discovered.sort(key=lambda m: m["id"], reverse=True)
    return discovered


# ---------------------------------------------------------------------------
# Mistral AI
# ---------------------------------------------------------------------------
_MISTRAL_FALLBACK_MODELS: list[tuple[str, str]] = [
    ("mistral-large-2411", "Mistral Large (2411)"),
    ("mistral-small-2501", "Mistral Small (2501)"),
    ("mistral-moderation-2411", "Mistral Moderation (2411)"),
    ("open-mistral-nemo", "Mistral Nemo"),
    ("open-codestral-mamba", "Codestral Mamba"),
]


async def fetch_mistral_models(api_key: str = "") -> list[dict]:
    """Fetch chat models from Mistral AI's OpenAI-compatible /v1/models endpoint."""
    if not api_key:
        return []

    discovered: list[dict] = await _fetch_openai_compat_models(
        base_url="https://api.mistral.ai/v1",
        api_key=api_key,
        id_prefix="mistral",
        description="Mistral AI",
    )

    if not discovered:
        for mid, mname in _MISTRAL_FALLBACK_MODELS:
            discovered.append(_model(
                id=f"mistral/{mid}",
                name=mname,
                description="Mistral AI",
            ))

    discovered.sort(key=lambda m: m["id"], reverse=True)
    return discovered


# ---------------------------------------------------------------------------
# DeepSeek
# ---------------------------------------------------------------------------
# Curated fallback used if /v1/models is unreachable. Keep ids in sync with the
# DeepSeek docs (https://api-docs.deepseek.com/quick_start/pricing).
_DEEPSEEK_FALLBACK_MODELS: list[tuple[str, str]] = [
    ("deepseek-v4-pro", "DeepSeek V4 Pro"),
    ("deepseek-v4-flash", "DeepSeek V4 Flash"),
]


async def fetch_deepseek_models(api_key: str = "") -> list[dict]:
    """Fetch chat models from DeepSeek's OpenAI-compatible /v1/models endpoint.

    Falls back to a hardcoded curated list if the endpoint is unreachable or
    returns no entries — DeepSeek occasionally rate-limits /v1/models even
    when chat completions still work.
    """
    if not api_key:
        return []

    discovered: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.deepseek.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            resp.raise_for_status()

        data = resp.json().get("data", [])
        for m in data:
            mid = m.get("id", "")
            if not mid.startswith("deepseek-"):
                continue
            discovered.append(_model(
                id=f"deepseek/{mid}",
                name=mid,
                description="DeepSeek",
            ))
    except Exception as e:
        logger.warning(f"DeepSeek /v1/models unreachable, using fallback list: {type(e).__name__}: {e}")

    if not discovered:
        for mid, mname in _DEEPSEEK_FALLBACK_MODELS:
            discovered.append(_model(
                id=f"deepseek/{mid}",
                name=mname,
                description="DeepSeek",
            ))

    discovered.sort(key=lambda m: m["id"], reverse=True)
    return discovered


# ---------------------------------------------------------------------------
# OpenAI-compatible discovery for additional providers (GLM, Kimi, Qwen)
# ---------------------------------------------------------------------------
async def _fetch_openai_compat_models(
    *,
    base_url: str,
    api_key: str,
    id_prefix: str,
    description: str,
) -> list[dict]:
    """Generic helper for providers exposing an OpenAI-compatible /models endpoint."""
    if not api_key:
        return []

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{base_url.rstrip('/')}/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            resp.raise_for_status()
        data = resp.json().get("data", [])
    except Exception as e:
        logger.warning(f"{id_prefix} /models unreachable: {type(e).__name__}: {e}")
        return []

    models = []
    for m in data:
        mid = m.get("id", "")
        if not mid:
            continue
        models.append(_model(
            id=f"{id_prefix}/{mid}",
            name=mid,
            description=description,
        ))
    models.sort(key=lambda m: m["id"], reverse=True)
    return models


async def fetch_glm_models(api_key: str = "") -> list[dict]:
    return await _fetch_openai_compat_models(
        base_url="https://open.bigmodel.cn/api/paas/v4",
        api_key=api_key,
        id_prefix="glm",
        description="Zhipu GLM",
    )


async def fetch_kimi_models(api_key: str = "") -> list[dict]:
    return await _fetch_openai_compat_models(
        base_url="https://api.moonshot.ai/v1",
        api_key=api_key,
        id_prefix="kimi",
        description="Moonshot Kimi",
    )


async def fetch_qwen_models(api_key: str = "") -> list[dict]:
    return await _fetch_openai_compat_models(
        base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        api_key=api_key,
        id_prefix="qwen",
        description="Alibaba Qwen",
    )


# ---------------------------------------------------------------------------
# Google Gemini (AI Studio)
# ---------------------------------------------------------------------------
async def fetch_gemini_models(api_key: str = "") -> list[dict]:
    """Fetch chat models from Google AI Studio's generativelanguage API."""
    if not api_key:
        return []

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            params={"key": api_key},
        )
        resp.raise_for_status()

    data = resp.json().get("models", [])
    models = []
    for m in data:
        full_name = m.get("name", "")
        if not full_name.startswith("models/gemini-"):
            continue
        if "generateContent" not in m.get("supportedGenerationMethods", []):
            continue

        mid = full_name[len("models/"):]
        display = m.get("displayName", mid)
        ctx = m.get("inputTokenLimit")
        models.append(_model(
            id=f"gemini/{mid}",
            name=display,
            context_length=ctx,
            description="Google Gemini",
        ))

    models.sort(key=lambda m: m["id"], reverse=True)
    return models


# ---------------------------------------------------------------------------
# AWS Bedrock
# ---------------------------------------------------------------------------
_BEDROCK_BEARER_ENV_LOCK = None


def _get_bedrock_bearer_lock():
    """Lazy singleton — avoids importing threading at module load."""
    global _BEDROCK_BEARER_ENV_LOCK
    if _BEDROCK_BEARER_ENV_LOCK is None:
        import threading
        _BEDROCK_BEARER_ENV_LOCK = threading.Lock()
    return _BEDROCK_BEARER_ENV_LOCK


async def fetch_bedrock_models(
    region: str = "",
    access_key_id: str = "",
    secret_access_key: str = "",
    bearer_token: str = "",
) -> list[dict]:
    """Fetch foundation models from AWS Bedrock.

    Auth mode is picked from the supplied credentials:
      - bearer_token non-empty -> Bedrock long-term API key (boto3 >= 1.39
        reads ``AWS_BEARER_TOKEN_BEDROCK`` from env to bake bearer auth into
        the client at construction time).
      - else IAM access key + secret (SigV4).
    """
    import asyncio
    import os

    if not region:
        region = "us-east-1"

    if not bearer_token and (not access_key_id or not secret_access_key):
        return []

    def _list_models() -> list[dict]:
        import boto3
        if bearer_token:
            # boto3 has no direct kwarg for the Bedrock bearer token. Botocore
            # consults AWS_BEARER_TOKEN_BEDROCK lazily on the first request
            # (not at client construction), so the env var must stay set across
            # the actual list_foundation_models call. A lock keeps the env var
            # from leaking to concurrent requests.
            lock = _get_bedrock_bearer_lock()
            with lock:
                prev = os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
                os.environ["AWS_BEARER_TOKEN_BEDROCK"] = bearer_token
                try:
                    client = boto3.client("bedrock", region_name=region)
                    response = client.list_foundation_models(
                        byOutputModality="TEXT",
                        byInferenceType="ON_DEMAND",
                    )
                finally:
                    if prev is None:
                        os.environ.pop("AWS_BEARER_TOKEN_BEDROCK", None)
                    else:
                        os.environ["AWS_BEARER_TOKEN_BEDROCK"] = prev
        else:
            client = boto3.client(
                "bedrock",
                region_name=region,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
            )
            response = client.list_foundation_models(
                byOutputModality="TEXT",
                byInferenceType="ON_DEMAND",
            )
        summaries = response.get("modelSummaries", [])

        results = []
        for m in summaries:
            mid = m.get("modelId", "")
            name = m.get("modelName", mid)
            provider = m.get("providerName", "")
            input_mods = m.get("inputModalities", [])
            output_mods = m.get("outputModalities", [])
            inference_types = m.get("inferenceTypesSupported", [])
            lifecycle = m.get("modelLifecycle", {}).get("status", "")
            streaming = m.get("responseStreamingSupported", False)

            # Only include active, on-demand, text-in/text-out, streaming models
            if "ON_DEMAND" not in inference_types:
                continue
            if "TEXT" not in input_mods or "TEXT" not in output_mods:
                continue
            if lifecycle != "ACTIVE":
                continue
            if not streaming:
                continue

            results.append(_model(
                id=f"bedrock/{mid}",
                name=f"{name} ({provider})",
                description=f"AWS Bedrock — {provider}",
            ))

        return results

    # Run boto3 call in a thread to avoid blocking the event loop
    return await asyncio.to_thread(_list_models)


# ---------------------------------------------------------------------------
# Agent in the Loop (not a provider: needs no key, so it is listed even when
# the person has no provider at all)
# ---------------------------------------------------------------------------
LOOP_GROUP = "Agent in the Loop"


def _loop_group() -> dict[str, list[dict]]:
    from agent_in_the_loop import LOOP_MODEL_ID, LOOP_MODEL_LABEL, loop_enabled
    if not loop_enabled():
        return {}
    return {LOOP_GROUP: [_model(
        id=LOOP_MODEL_ID, name=LOOP_MODEL_LABEL,
        description="Claude Code, Codex or another MCP agent answers each step",
    )]}


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------
async def fetch_all_models(
    providers: list[dict] | None = None,
) -> dict[str, list[dict]]:
    """
    Fetch models from configured providers in parallel.

    Args:
        providers: List of provider config dicts from DB (UserLlmProvider rows).
                   If None, falls back to environment variables.

    Returns a dict keyed by provider display name, each containing a list
    of model dicts with {id, name, context_length, description}.
    Uses an in-memory cache (1 hour TTL) only for env-var fallback mode.
    """
    global _cache, _cache_ts

    # If no providers from DB, use env var fallback with caching
    if providers is None:
        # No env-var fallback — keys come exclusively from DB providers
        return _loop_group()

    # --- DB-driven mode: build tasks from provider configs ---
    import asyncio
    tasks_db: dict[str, Any] = {}

    for p in providers:
        ptype = p.get("providerType", "")
        pid = p.get("id", "")
        pname = p.get("name", ptype)

        if ptype == "openai":
            tasks_db[f"OpenAI ({pname})"] = fetch_openai_models(api_key=p.get("apiKey", ""))
        elif ptype == "anthropic":
            tasks_db[f"Anthropic ({pname})"] = fetch_anthropic_models(api_key=p.get("apiKey", ""))
        elif ptype == "openrouter":
            tasks_db[f"OpenRouter ({pname})"] = fetch_openrouter_models(api_key=p.get("apiKey", ""))
        elif ptype == "deepseek":
            tasks_db[f"DeepSeek ({pname})"] = fetch_deepseek_models(api_key=p.get("apiKey", ""))
        elif ptype == "gemini":
            tasks_db[f"Google Gemini ({pname})"] = fetch_gemini_models(api_key=p.get("apiKey", ""))
        elif ptype == "glm":
            tasks_db[f"GLM ({pname})"] = fetch_glm_models(api_key=p.get("apiKey", ""))
        elif ptype == "kimi":
            tasks_db[f"Kimi ({pname})"] = fetch_kimi_models(api_key=p.get("apiKey", ""))
        elif ptype == "qwen":
            tasks_db[f"Qwen ({pname})"] = fetch_qwen_models(api_key=p.get("apiKey", ""))
        elif ptype == "xai":
            tasks_db[f"xAI Grok ({pname})"] = fetch_xai_models(api_key=p.get("apiKey", ""))
        elif ptype == "mistral":
            tasks_db[f"Mistral AI ({pname})"] = fetch_mistral_models(api_key=p.get("apiKey", ""))
        elif ptype == "bedrock":
            tasks_db[f"AWS Bedrock ({pname})"] = fetch_bedrock_models(
                region=p.get("awsRegion", "us-east-1"),
                access_key_id=p.get("awsAccessKeyId", ""),
                secret_access_key=p.get("awsSecretKey", ""),
                bearer_token=p.get("awsBearerToken", ""),
            )
        elif ptype == "openai_compatible":
            # Single model entry — no discovery needed
            model_id = p.get("modelIdentifier", "")
            if model_id:
                tasks_db.setdefault("Custom", [])
                # Not a coroutine — just append directly
                if isinstance(tasks_db.get("Custom"), list):
                    tasks_db["Custom"].append(_model(
                        id=f"custom/{pid}",
                        name=f"{pname}",
                        description="Custom",
                    ))

    # Separate coroutines from pre-built lists
    coro_tasks: dict[str, Any] = {}
    results_db: dict[str, list[dict]] = {}

    for key, val in tasks_db.items():
        if isinstance(val, list):
            results_db[key] = val
        else:
            coro_tasks[key] = val

    if coro_tasks:
        gathered_db = await asyncio.gather(*coro_tasks.values(), return_exceptions=True)
        for prov_name, result in zip(coro_tasks.keys(), gathered_db):
            if isinstance(result, Exception):
                logger.warning(f"Failed to fetch models from {prov_name}: {type(result).__name__}: {result}")
                results_db[prov_name] = []
            else:
                results_db[prov_name] = result

    total = sum(len(v) for v in results_db.values())
    logger.info(f"Fetched {total} models from {len(results_db)} providers (DB-driven)")
    results_db.update(_loop_group())
    return results_db
