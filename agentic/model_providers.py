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
# AWS Bedrock
# ---------------------------------------------------------------------------
async def fetch_bedrock_models(
    region: str = "",
    access_key_id: str = "",
    secret_access_key: str = "",
) -> list[dict]:
    """Fetch foundation models from AWS Bedrock."""
    import asyncio

    if not region:
        region = "us-east-1"

    if not access_key_id or not secret_access_key:
        return []

    def _list_models() -> list[dict]:
        import boto3
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
        return {}

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
        elif ptype == "bedrock":
            tasks_db[f"AWS Bedrock ({pname})"] = fetch_bedrock_models(
                region=p.get("awsRegion", "us-east-1"),
                access_key_id=p.get("awsAccessKeyId", ""),
                secret_access_key=p.get("awsSecretKey", ""),
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
                logger.warning(f"Failed to fetch models from {prov_name}: {result}")
                results_db[prov_name] = []
            else:
                results_db[prov_name] = result

    total = sum(len(v) for v in results_db.values())
    logger.info(f"Fetched {total} models from {len(results_db)} providers (DB-driven)")
    return results_db
