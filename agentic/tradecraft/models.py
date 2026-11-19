"""The model an ingestion job calls (crawl decisions, the summary): the owner's own.

Built from the owner's provider list (the webapp's internal route) with
``build_llm_from_providers``, which refuses a ``loop/`` model: an ingestion job runs outside
any chat run, so no driver could ever answer it (``LoopModelNotSupportedHere``). Every call
carries the ``tradecraft_ingest`` purpose and the owner as ``metadata.user_id``, which the
daily budget counts; nothing here retries a call (TD-20).
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from agent_context import current_llm_purpose
from agent_in_the_loop.errors import LoopModelNotSupportedHere, refuse_loop_model
from agent_in_the_loop.purpose import llm_purpose
from llm_builder import build_llm_from_providers
from logging_config import get_logger

logger = get_logger(__name__)

PROVIDERS_TIMEOUT_SEC = 10.0


class ModelUnavailable(RuntimeError):
    """The owner's providers could not be read, or the model could not be built from them."""

    code = "model_unavailable"
    no_retry = True


def _webapp_url() -> str:
    return os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")


def _internal_headers() -> dict[str, str]:
    key = os.environ.get("INTERNAL_API_KEY", "")
    return {"X-Internal-Key": key} if key else {}


async def fetch_providers(owner_id: str) -> list:
    """The owner's providers, keys included (master key only; never logged)."""
    url = f"{_webapp_url()}/api/users/{owner_id}/llm-providers?internal=true"
    async with httpx.AsyncClient(timeout=PROVIDERS_TIMEOUT_SEC) as client:
        resp = await client.get(url, headers=_internal_headers())
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else []


class IngestModel:
    """A chat model whose every call carries the purpose label and the budget's user."""

    def __init__(self, llm: Any, owner_id: str, model: str) -> None:
        self.model = model
        self.owner_id = owner_id
        self._llm = llm.with_config(metadata={"user_id": owner_id}) if hasattr(llm, "with_config") else llm

    async def ainvoke(self, messages: Any, config: Any = None, **kwargs: Any) -> Any:
        if current_llm_purpose.get().get("purpose") == "tradecraft_ingest":
            return await self._llm.ainvoke(messages, config, **kwargs)
        with llm_purpose("tradecraft_ingest"):
            return await self._llm.ainvoke(messages, config, **kwargs)


async def build_ingest_llm(owner_id: str, model: str, *, providers: Optional[list] = None) -> IngestModel:
    """The owner's ``model`` for an ingestion job. Raises ``LoopModelNotSupportedHere`` for a
    loop model (before any request) and ``ModelUnavailable`` when it cannot be built."""
    refuse_loop_model(model)
    if providers is None:
        try:
            providers = await fetch_providers(owner_id)
        except Exception as exc:
            logger.warning(f"[tradecraft] model providers unavailable: {type(exc).__name__}")
            raise ModelUnavailable("the owner's model providers could not be read") from None
    try:
        llm = build_llm_from_providers(model, providers)
    except LoopModelNotSupportedHere:
        raise
    except Exception as exc:
        logger.warning(f"[tradecraft] model {model!r} could not be built: {type(exc).__name__}")
        raise ModelUnavailable("the model could not be built from the owner's providers") from None
    return IngestModel(llm, owner_id, model)
