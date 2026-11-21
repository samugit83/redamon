"""The agent's Tradecraft 2.0 routes (``contract.ROUTES``), all under the master internal key.

The agent port is published on every interface, so every route takes
``require_configured_master_auth`` (no key configured: 503 to everyone;
``tests/test_ghsa_8whg_master_key_fail_closed.py`` walks this router too). The routes that
fetch a site or call a model also spend the per-user token bucket and daily cap of
``llm_guard``: Check URL, the focus preview and Read now through ``require_internal_auth``
(their body names the user), the job start once per owner named in its batch, so a whole
Save & refresh all costs one token (D-49) and one owner's bulk never spends another's.

The synchronous routes end at the contract's deadlines with ``error_code: "timeout"``; the
webapp waits ``WEBAPP_DEADLINE_MARGIN_SEC`` longer. A route whose card has not landed yet
answers 501 ``not_implemented``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request
from fastapi.responses import JSONResponse

from llm_guard import _enforce_llm_limits, require_configured_master_auth, require_internal_auth
from logging_config import get_logger
from tradecraft import check_url as check_url_mod
from tradecraft import convert as convert_mod
from tradecraft import jobs, net
from tradecraft import preview as preview_mod
from tradecraft import read_now as read_now_mod
from tradecraft import settings as tc_settings
from tradecraft.contract import (
    DEADLINES_SEC,
    CancelAnswer,
    CheckUrlRequest,
    CheckUrlResult,
    ConvertAnswer,
    JobStartBatch,
    PreviewRequest,
    PreviewResult,
    ReadNowRequest,
    ReadNowResult,
    UserCancelAnswer,
)

logger = get_logger(__name__)

def _id_path() -> Any:
    # One Path() per parameter: FastAPI binds a shared instance to the first name it serves.
    return Path(min_length=1, max_length=200)


async def require_job_owner_limits(request: Request) -> None:
    """The token bucket and daily cap of ``require_internal_auth``, spent once for each owner
    a job batch names: its body has no top-level user id, so ``require_internal_auth`` would
    charge every owner's starts to one shared "anonymous" bucket and daily cap."""
    try:
        body = await request.json()
    except Exception:
        return  # the body model refuses it with 422
    owners: list[str] = []
    for job in (body.get("jobs") if isinstance(body, dict) else None) or []:
        owner = job.get("user_id") if isinstance(job, dict) else None
        if isinstance(owner, str) and owner and owner not in owners:
            owners.append(owner)
    for owner in owners[: tc_settings.constant("jobStartBatchMax")]:
        _enforce_llm_limits(request, owner)


router = APIRouter(prefix="/tradecraft/v2", tags=["Tradecraft 2.0"],
                   dependencies=[Depends(require_configured_master_auth)])


def _unavailable(exc: BaseException) -> JSONResponse:
    logger.warning(f"[tradecraft] route failed code=internal_error error={type(exc).__name__}")
    return JSONResponse({"error_code": "internal_error"}, status_code=503)


@router.post("/jobs", status_code=202, dependencies=[Depends(require_job_owner_limits)])
async def start_jobs(batch: JobStartBatch) -> Any:
    try:
        answer = await jobs.get_runner().submit(batch)
    except Exception as exc:
        return _unavailable(exc)
    return answer.model_dump()


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str = _id_path(), _body: dict = Body(default_factory=dict)) -> Any:
    try:
        await jobs.get_runner().cancel_job(job_id)
    except Exception as exc:
        return _unavailable(exc)
    return CancelAnswer(ok=True).model_dump()


@router.post("/users/{user_id}/cancel")
async def cancel_user(user_id: str = _id_path(), _body: dict = Body(default_factory=dict)) -> Any:
    try:
        n = await jobs.get_runner().cancel_user(user_id)
    except Exception as exc:
        return _unavailable(exc)
    return UserCancelAnswer(cancelled=n).model_dump()


async def _within_deadline(name: str, call: Callable[[], Awaitable[Any]], on_timeout: Callable[[], Any]) -> Any:
    try:
        result = await asyncio.wait_for(call(), timeout=DEADLINES_SEC[name])
    except NotImplementedError:
        return JSONResponse({"error_code": "not_implemented"}, status_code=501)
    except asyncio.TimeoutError:
        logger.info(f"[tradecraft] {name} code=timeout")
        return on_timeout().model_dump()
    return result.model_dump()


@router.post("/check-url", dependencies=[Depends(require_internal_auth)])
async def check_url(body: CheckUrlRequest) -> Any:
    async def call() -> CheckUrlResult:
        # The jobs' fetcher, so the browser tier works here too (a JavaScript site, "always
        # use the browser", "wait for element", a GitBook's rendered menu), in the Kali
        # sandbox of the account the request names.
        with jobs.sandbox_person(body.user_id), net.use_fetcher(jobs.default_fetcher()):
            return await check_url_mod.check_url(body)

    return await _within_deadline("check_url", call, lambda: CheckUrlResult(ok=False, error_code="timeout"))


@router.post("/preview-focus", dependencies=[Depends(require_internal_auth)])
async def preview_focus(body: PreviewRequest) -> Any:
    return await _within_deadline("preview_focus", lambda: preview_mod.preview_focus(body),
                                  lambda: PreviewResult(error_code="timeout"))


@router.post("/read-now", dependencies=[Depends(require_internal_auth)])
async def read_now(body: ReadNowRequest) -> Any:
    async def call() -> ReadNowResult:
        # The jobs' fetcher, as Check URL: a page reads as the agent's tool reads it, the browser
        # tier included (a JavaScript site, "always use the browser"; never with a login), in
        # the Kali sandbox of the account the request names.
        with jobs.sandbox_person(body.user_id), net.use_fetcher(jobs.default_fetcher()):
            return await read_now_mod.read_now(body)

    return await _within_deadline("read_now", call, lambda: ReadNowResult(error_code="timeout"))


@router.post("/users/{user_id}/convert")
async def convert_user(user_id: str = _id_path(), _body: dict = Body(default_factory=dict)) -> Any:
    try:
        queued = await convert_mod.convert_user(user_id)
    except NotImplementedError:
        return JSONResponse({"error_code": "not_implemented"}, status_code=501)
    except HTTPException:
        raise
    except Exception as exc:
        return _unavailable(exc)
    return ConvertAnswer(queued=queued).model_dump()
