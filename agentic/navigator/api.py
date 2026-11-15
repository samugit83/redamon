"""AI Navigator's agent routes (plan §8.2). Master key only: the scan containers hold
SCANNER_API_KEY, so nothing here admits it.

    POST /navigator/chat      NDJSON stream of one run (the webapp is the only caller)
    POST /navigator/stop      cancel one run
    POST /navigator/stop-all  cancel every run (Root switch off, emergency stop)
    GET  /navigator/health    the wiki index's state

Every id in the chat body comes from the webapp's server-side decision. A run's task is cancelled
when the client disconnects (the webapp aborting its fetch is how most stops arrive), and before
every model and tool call the run checks the connection again.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from llm_guard import require_configured_master_auth, require_internal_auth, require_master_internal_auth
from navigator import events, runs
from navigator.graph import ChatRequest, run_navigator
from navigator.limits import ROUTES, RUN_TIMEOUT_S
from navigator.wiki_index import wiki_index

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI Navigator"])

_SENTINEL = object()
_Id = Annotated[str, Field(min_length=1, max_length=200)]


class HistoryTurn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    role: Literal["user", "assistant"]
    content: str = Field(..., max_length=20000)


class PageContext(BaseModel):
    model_config = ConfigDict(extra="ignore")
    path: Optional[str] = Field(None, max_length=200)
    wiki_hint: Optional[str] = Field(None, max_length=120)


class ChatBody(BaseModel):
    model_config = ConfigDict(extra="ignore")
    run_id: _Id
    credential: str = Field(..., min_length=20, max_length=200)
    user_id: _Id
    actor_id: Optional[str] = Field(None, max_length=200)
    project_id: _Id
    tenant_id: _Id
    model: str = Field(..., min_length=1, max_length=300)
    history: list[HistoryTurn] = Field(default_factory=list, max_length=40)
    message: str = Field(..., min_length=1, max_length=4000)
    page: Optional[PageContext] = None
    allowed_routes: list[Literal[ROUTES]] = Field(default_factory=list, max_length=5)
    route_reasons: dict[str, str] = Field(default_factory=dict, max_length=5)
    language_hint: Optional[str] = Field(None, max_length=10)


class StopBody(BaseModel):
    run_id: _Id


async def _build_llm(model: str, user_id: str):
    """(llm, None) or (None, error code). The person's own providers (D2); loop models refused."""
    import api as agent_api
    llm, failure = await agent_api._build_feature_llm("AI Navigator", model, user_id)
    if failure is None:
        return llm, None
    try:
        code = json.loads(failure.body).get("code") or "model_unavailable"
    except (ValueError, AttributeError):
        code = "model_unavailable"
    return None, code if re.match(r"^[a-z_]{1,40}$", code) else "model_unavailable"


_BUILD_MESSAGES = {
    "loop_model_not_supported_here": "Agent in the Loop can't answer AI Navigator. Choose a provider model.",
    "providers_unreachable": "Couldn't load your LLM providers, try again.",
    "model_unavailable": "Your model could not be used. Choose another model for AI Navigator.",
}


def _clean_reasons(raw: dict) -> dict[str, str]:
    return {k: v for k, v in raw.items() if k in ROUTES and isinstance(v, str) and re.match(r"^[a-z_]{1,40}$", v)}


@router.post("/navigator/chat",
             dependencies=[Depends(require_master_internal_auth), Depends(require_internal_auth)])
async def navigator_chat(body: ChatBody, request: Request):
    req = ChatRequest(
        run_id=body.run_id, credential=body.credential, user_id=body.user_id, actor_id=body.actor_id,
        project_id=body.project_id, tenant_id=body.tenant_id, model=body.model,
        history=[t.model_dump() for t in body.history], message=body.message,
        page_path=body.page.path if body.page else None, wiki_hint=body.page.wiki_hint if body.page else None,
        allowed_routes=list(dict.fromkeys(body.allowed_routes)), route_reasons=_clean_reasons(body.route_reasons),
    )
    queue: asyncio.Queue = asyncio.Queue()

    async def emit(ev: dict) -> None:
        await queue.put(ev)

    async def checkpoint() -> None:
        if await request.is_disconnected():
            raise asyncio.CancelledError()

    async def run() -> None:
        try:
            if runs.at_capacity():
                await emit(events.meta(req.run_id, req.model))
                await emit(events.error("agent_busy", "AI Navigator is busy right now. Try again in a moment."))
                return
            llm, code = await _build_llm(req.model, req.user_id)
            if llm is None:
                await emit(events.meta(req.run_id, req.model))
                await emit(events.error(code, _BUILD_MESSAGES.get(code, _BUILD_MESSAGES["model_unavailable"])))
                return
            try:
                await asyncio.wait_for(run_navigator(req, llm, emit, checkpoint), timeout=RUN_TIMEOUT_S)
            except asyncio.TimeoutError:
                await emit(events.error("timeout", "The answer took too long."))
        finally:
            await queue.put(_SENTINEL)

    async def stream():
        task = asyncio.create_task(run())
        if runs.register(req.run_id, task, req.user_id, req.project_id) is None:
            task.cancel()
            yield events.ndjson(events.error("navigator_error", "This run is already in progress."))
            return
        try:
            while True:
                ev = await queue.get()
                if ev is _SENTINEL:
                    break
                yield events.ndjson(ev)
        finally:
            if not task.done():
                task.cancel()
            runs.unregister(req.run_id)

    return StreamingResponse(stream(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.post("/navigator/stop", dependencies=[Depends(require_configured_master_auth)])
async def navigator_stop(body: StopBody):
    return {"stopped": runs.stop(body.run_id)}


@router.post("/navigator/stop-all", dependencies=[Depends(require_configured_master_auth)])
async def navigator_stop_all():
    stopped = runs.stop_all()
    if stopped:
        logger.warning("[navigator] stop-all stopped=%d", stopped)
    return {"stopped": stopped}


@router.get("/navigator/health", dependencies=[Depends(require_configured_master_auth)])
async def navigator_health():
    idx = await asyncio.to_thread(wiki_index)
    return {"wiki": {"present": idx.present, "pages": len(idx.pages), "sections": idx.section_count,
                     "built_at": idx.built_at, "updated_at": idx.mtime or None},
            "runs": runs.count()}
