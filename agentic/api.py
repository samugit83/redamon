"""
RedAmon Agent WebSocket API

FastAPI application providing WebSocket endpoint for real-time agent communication.
Supports session-based conversation continuity and phase-based approval flow.

Endpoints:
    WS /ws/agent - WebSocket endpoint for real-time bidirectional streaming
    GET /health - Health check
    GET /defaults - Agent default settings (camelCase, for frontend)
    GET /models - Available AI models from all configured providers
"""

import asyncio
import base64
import json
import logging
import os
import re
import shlex
import time
from contextlib import asynccontextmanager
from typing import Any, List, Literal, Optional

import httpx
import websockets
from fastapi import Depends, FastAPI, File, Form, Query, UploadFile, WebSocket
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llm_guard import (master_key_is_weak, require_configured_master_auth,
                       require_internal_auth, require_internal_auth_only,
                       require_master_internal_auth)
from logging_config import setup_logging
from agent_in_the_loop import is_loop_llm, is_loop_model, loop_enabled
from agent_in_the_loop.broker import get_broker
from agent_in_the_loop.errors import LoopModelNotSupportedHere
from agent_in_the_loop.routes import router as loop_router
from orchestrator import AgentOrchestrator
from orchestrator_helpers import normalize_content
from plugin_api import router as plugin_router
from prompt_safety import wrap_untrusted, UNTRUSTED_OUTPUT_GUIDANCE
from startup_guard import check_single_worker
from utils import get_session_count
from websocket_api import WebSocketManager, websocket_endpoint, MessageType
import workspace_fs
import job_runner
import ws_job_emitter
from workspace_import import downloads as _ws_downloads
from workspace_import import staging as _ws_staging
from workspace_import import upload_sessions as _ws_upload_sessions
from workspace_import.errors import ImportFailure, error_body
from workspace_import.http_routes import reset_project_imports, router as workspace_import_router

# Initialize logging with file rotation
setup_logging(log_level=logging.INFO, log_to_console=True, log_to_file=True)
logger = logging.getLogger(__name__)

orchestrator: Optional[AgentOrchestrator] = None
ws_manager: Optional[WebSocketManager] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Initializes the orchestrator and WebSocket manager on startup and cleans up on shutdown.
    """
    global orchestrator, ws_manager

    # Refuse to start under multi-worker uvicorn/gunicorn. The fireteam
    # confirmation registry uses an in-process dict; multiple workers would
    # silently break confirmation routing. See startup_guard for the env
    # vars consulted and the documented remediation paths.
    check_single_worker()

    # Agent container runs as root; bind-mounted /workspace files would
    # otherwise end up root:root on the host (UID 1000), breaking the
    # plan's promise that the workspace is browsable/editable directly
    # from the host. umask 0 makes new dirs world-writable (0777) and
    # new files world-readable+writable (0666), so the host user can
    # rm/edit them. Ownership still root, but mode 666/777 makes that OK.
    os.umask(0)

    logger.info("Starting RedAmon Agent API...")

    # Initialize orchestrator
    orchestrator = AgentOrchestrator()
    await orchestrator.initialize()

    # Initialize WebSocket manager
    ws_manager = WebSocketManager()

    # Background job recovery: flip any meta files marked 'running' on disk
    # (from a previous agent process that died mid-job) to 'interrupted' so
    # the drawer can show their final state correctly. In-flight asyncio
    # tasks are gone by definition - this is a state-only fixup.
    reg = job_runner.get_registry()
    reg.recover_on_boot()

    # No upload or import survives a restart. First put back any folder a
    # Re-sync was swapping when the process died, then empty the staging area.
    _ws_staging.recover_swaps()
    _ws_staging.sweep_all()
    idle_upload_sweeper = asyncio.create_task(_ws_upload_sessions.sweep_idle_forever())

    # Wire the JobRegistry to push job_update events through the WS manager
    # so the frontend drawer sees status changes in real time. The emitter
    # lives in ws_job_emitter.py so it stays unit-testable without the
    # full FastAPI/langgraph stack.
    ws_job_emitter.set_ws_manager(ws_manager)
    reg.set_ws_emitter(ws_job_emitter.emit_job_update)

    # Registry skew, reported at BOOT as well as refused per request.
    #
    # The refusal in /roe/parse is the control and it is deliberately
    # per-request rather than cached: the registry is a live mount for recon and
    # the orchestrator, so a digest checked once at startup can go stale under a
    # running agent - which is the failure this whole mechanism guards against.
    # This line exists so an operator finds out from the log rather than from a
    # user's failed upload.
    from recon_settings.roe_parse_prompt import ROE_PARSE_REGISTRY_DIGEST as _boot_digest
    from recon_settings.roe_prompt import prompt_skew as _boot_skew

    _skew = _boot_skew(_boot_digest)
    if _skew:
        logger.error(
            "RoE parse prompt was generated from a DIFFERENT settings registry than the one "
            f"loaded here (prompt {_skew[0][:12]}, registry {_skew[1][:12]}). /roe/parse will "
            "refuse with 503 until the agent image is rebuilt: docker compose build agent."
        )
    else:
        logger.info(f"RoE parse prompt matches the loaded registry ({_boot_digest[:12]})")

    logger.info("RedAmon Agent API ready (WebSocket)")

    yield

    logger.info("Shutting down RedAmon Agent API...")
    idle_upload_sweeper.cancel()
    if orchestrator:
        await orchestrator.close()


app = FastAPI(
    title="RedAmon Agent API",
    description="WebSocket API for real-time agent communication with phase tracking, MCP tools, and Neo4j integration",
    version="3.0.0",
    lifespan=lifespan
)

# CORS scoped to the webapp origin (I17). A wildcard `*` let any website the
# operator visits script their browser into reading the agent's unauthenticated
# endpoints cross-origin. Scope to the webapp origin(s); override with
# AGENT_CORS_ORIGINS (comma-separated) for non-localhost deployments.
_default_cors_origins = "http://localhost:3000,http://127.0.0.1:3000"
_cors_origins = [
    o.strip()
    for o in os.getenv("AGENT_CORS_ORIGINS", _default_cors_origins).split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class _AsciiJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii")


@app.exception_handler(RequestValidationError)
async def _request_validation_error(request, exc: RequestValidationError):
    # FastAPI's default handler, rendered ASCII-escaped. It echoes the rejected
    # input, and a lone surrogate in it (a target string recon passed through)
    # fails the UTF-8 render, which turned a 422 into a 500.
    return _AsciiJSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})


# Plugin platform: the overridable built-in skill parts and their validator.
app.include_router(plugin_router)
# Workspace folder/archive upload sessions and URL imports.
app.include_router(workspace_import_router)
# Agent in the Loop: drivers claim and answer model-call steps (via the webapp).
app.include_router(loop_router)


# =============================================================================
# RESPONSE MODELS (for /health endpoint only)
# =============================================================================

class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    tools_loaded: int
    active_sessions: int
    # Fireteam (multi-agent) observability
    fireteam_enabled: bool = False
    persistent_checkpointer: bool = False
    active_waves: int = 0
    # Only the switch: /health is unauthenticated and the agent port is
    # published, so loop activity counts live on the master-key /loop/stats.
    loop_enabled: bool = False


# =============================================================================
# ENDPOINTS
# =============================================================================


# =============================================================================
# TARGET GUARDRAIL — LLM-based check before project creation
# =============================================================================

class GuardrailRequest(BaseModel):
    """Request model for target guardrail check."""
    target_domain: str = ""
    target_ips: list[str] = []
    # Domain batch sends every in-scope root here. A joined string in
    # target_domain would reach a SINGULAR prompt and invite one aggregate
    # verdict, so a blocked domain among many could be allowed.
    target_domains: list[str] = []
    project_id: str = ""
    user_id: str = ""


@app.post("/guardrail/check-target", tags=["Guardrail"], dependencies=[Depends(require_internal_auth)])
async def check_target_guardrail(body: GuardrailRequest):
    """
    Check if a target domain or IP list is safe to scan.

    Two layers:
    1. Hard guardrail (deterministic): always blocks government/public domains.
       Cannot be disabled. Runs first.
    2. Soft guardrail (LLM-based): blocks well-known private companies.
       Fails open if LLM is unavailable.
    """
    from orchestrator_helpers.hard_guardrail import is_hard_blocked
    from orchestrator_helpers.guardrail import check_target_allowed
    from project_settings import DEFAULT_AGENT_SETTINGS

    # Hard guardrail: deterministic, non-disableable. Checks EVERY domain the
    # caller named: a Domain-batch create sends its roots in target_domains and
    # leaves target_domain empty, so a check on the single field alone would let
    # a blocked root through the one control that cannot be switched off.
    for _domain in ([body.target_domain] if body.target_domain else []) + list(body.target_domains or []):
        blocked, reason = is_hard_blocked(_domain)
        if blocked:
            return {"allowed": False, "reason": f"{_domain}: {reason}", "hard_blocked": True}

    if not orchestrator or not orchestrator._initialized:
        return {"allowed": True, "reason": "Agent not initialized, guardrail skipped"}

    # Ensure LLM is set up. An Agent in the Loop adapter counts as no LLM: it
    # answers only inside a chat run, and this check has no driver.
    if not orchestrator.llm or is_loop_llm(orchestrator.llm):
        if body.project_id:
            try:
                orchestrator._apply_project_settings(body.project_id)
            except Exception as e:
                logger.warning(f"Guardrail: failed to load project settings: {e}")
        # Still no LLM? Bootstrap with default model + user's API keys from DB
        if not orchestrator.llm or is_loop_llm(orchestrator.llm):
            try:
                from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
                import requests as _requests

                model_name = DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
                user_providers = []

                # Fetch user's LLM providers from DB (needed for API keys)
                if body.user_id:
                    webapp_url = os.environ.get('WEBAPP_API_URL', 'http://webapp:3000')
                    try:
                        resp = _requests.get(
                            f"{webapp_url.rstrip('/')}/api/users/{body.user_id}/llm-providers?internal=true",
                            headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
                            timeout=10,
                        )
                        resp.raise_for_status()
                        user_providers = resp.json()
                    except Exception as e:
                        logger.warning(f"Guardrail: failed to fetch user LLM providers: {e}")

                openai_p = _resolve_provider_key(user_providers, "openai")
                anthropic_p = _resolve_provider_key(user_providers, "anthropic")
                openrouter_p = _resolve_provider_key(user_providers, "openrouter")
                deepseek_p = _resolve_provider_key(user_providers, "deepseek")
                gemini_p = _resolve_provider_key(user_providers, "gemini")
                glm_p = _resolve_provider_key(user_providers, "glm")
                kimi_p = _resolve_provider_key(user_providers, "kimi")
                qwen_p = _resolve_provider_key(user_providers, "qwen")
                xai_p = _resolve_provider_key(user_providers, "xai")
                mistral_p = _resolve_provider_key(user_providers, "mistral")

                orchestrator.llm = setup_llm(
                    model_name,
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
                )
                orchestrator.model_name = model_name
                logger.info(f"Guardrail: bootstrapped LLM with default model {model_name}")
            except Exception as e:
                logger.warning(f"Guardrail: failed to bootstrap default LLM: {e}")
                return {"allowed": True, "reason": "LLM not configured, guardrail skipped"}
    if is_loop_llm(orchestrator.llm):
        return {"allowed": True, "reason": "LLM not configured, guardrail skipped"}

    try:
        result = await check_target_allowed(
            orchestrator.llm,
            target_domain=body.target_domain,
            target_ips=body.target_ips,
            target_domains=body.target_domains,
        )
        return result
    except Exception as e:
        # A malformed or missing verdict lands here too. This check is the
        # soft, user-disableable one and stays fail-open; the session-start
        # check refuses on the same error.
        logger.error(f"Guardrail error: {e}")
        return {"allowed": True, "verdict": "unknown", "reason": f"Guardrail verdict unknown: {str(e)}"}


# =============================================================================
# ROE PARSING — LLM-based extraction of Rules of Engagement from document text
# =============================================================================

class RoeParseRequest(BaseModel):
    """Request model for RoE document parsing."""
    text: str
    # The caller's saved "RoE parsing" model, read by the webapp from the
    # user's settings. Required: there is no default to fall back to.
    model: str | None = None
    # Whose LLM providers to use. The parse is project-INDEPENDENT, so there is
    # no project whose settings could supply a key: the document is uploaded
    # while a project is being created, and on a freshly started agent no
    # project is loaded at all.
    user_id: str | None = None


# The parse prompt is a BUILD ARTIFACT generated from the registry, never a
# string literal here. Three services read the registry on three different
# schedules - the agent has it COPY-baked, recon mounts it, the orchestrator
# mounts it read-only - so a hand-written field list in this file goes stale in
# three silent ways: a renamed column the model still returns, a new field the
# parser can never set, and a changed bound that makes a correct model answer
# look like a model error.
#
# Rebuild with: python3 recon_settings/build.py
from recon_settings.roe_parse_prompt import (
    ROE_PARSE_FIELDS,
    ROE_PARSE_PROMPT,
    ROE_PARSE_REGISTRY_DIGEST,
)
# The skew check lives beside the generator it guards, so the rule is testable
# without importing the whole agent.
from recon_settings.roe_prompt import prompt_skew as _prompt_skew

# The model reads the first ROE_PARSE_MAX_CHARS of a document; the webapp mirrors
# it as MAX_MODEL_CHARS to tell the reviewer when a tail went unread.
ROE_PARSE_MAX_CHARS = 50_000
# Under the webapp's 285 s wait, which is under undici's 300 s default, so the
# person gets this coded answer rather than a dropped connection. The provider
# SDKs' own timeouts are per attempt and retried, so they cannot bound the call.
ROE_PARSE_TIMEOUT_S = 270


@app.post("/roe/parse", tags=["RoE"],
          dependencies=[Depends(require_master_internal_auth), Depends(require_internal_auth)])
async def parse_roe_document(body: RoeParseRequest):
    """Parse a Rules of Engagement document using the LLM and extract structured settings."""
    import json as json_mod

    requested_model = (body.model or "").strip()

    # FAIL CLOSED on registry skew. This image can hold a prompt generated from
    # last week's registry while the mounted one is today's, and the failure that
    # produces is not an error - it is a confidently wrong configuration, parsed
    # against one field list and validated against another. Refusing names both
    # digests so the fix is obvious: rebuild the agent image.
    skew = _prompt_skew(ROE_PARSE_REGISTRY_DIGEST)
    if skew:
        built_from, live = skew
        logger.error(f"RoE parse: registry skew, prompt={built_from} live={live}")
        return JSONResponse(
            content={
                "error": (
                    "The RoE parse prompt was generated from a different settings registry "
                    f"than the one loaded here (prompt {built_from[:12]}, registry {live[:12]}). "
                    "Parsing now would judge the result against bounds the model was never "
                    "told. Rebuild the agent image: docker compose build agent."
                ),
                "promptRegistryDigest": built_from,
                "loadedRegistryDigest": live,
                "model_used": requested_model,
            },
            status_code=503,
        )

    missing = _feature_request_error(requested_model, body.user_id)
    if missing:
        return missing
    llm, failure = await _build_feature_llm("RoE parse", requested_model, body.user_id)
    if failure:
        return failure

    # System message has instructions only; user document goes in HumanMessage
    # to reduce prompt injection risk from adversarial document content
    system_prompt = ROE_PARSE_PROMPT.strip()
    doc_text = body.text[:ROE_PARSE_MAX_CHARS]
    logger.info(f"RoE parse: using model {requested_model}")
    import time as time_mod
    started = time_mod.monotonic()
    try:
        response, failure = await asyncio.wait_for(
            _invoke_feature_llm("RoE parse", requested_model, llm, [
                SystemMessage(content=system_prompt),
                HumanMessage(content=f"RoE Document:\n---\n{doc_text}\n---\n\nParse the RoE document above and return the JSON."),
            ]),
            timeout=ROE_PARSE_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        logger.warning(f"RoE parse: model call stopped after {ROE_PARSE_TIMEOUT_S}s ({len(doc_text)} chars)")
        return _feature_error(
            "agent_timeout", requested_model, 504,
            "The model did not finish reading the document in time. Try again, or pick a faster model.",
        )
    outcome = "failed" if failure else "answered"
    logger.info(f"RoE parse: model {outcome} in {time_mod.monotonic() - started:.1f}s ({len(doc_text)} chars)")
    if failure:
        return failure

    try:
        content = normalize_content(response.content).strip()

        # Strip markdown code fences if present (handle ```json, ```JSON, ``` json, etc.)
        import re
        fence_match = re.search(r'```(?:json)?\s*\n(.*?)```', content, re.DOTALL | re.IGNORECASE)
        if fence_match:
            content = fence_match.group(1).strip()
        else:
            # Fallback: try to extract first JSON object
            brace_start = content.find('{')
            if brace_start > 0:
                content = content[brace_start:]
            # Strip trailing non-JSON
            brace_end = content.rfind('}')
            if brace_end >= 0 and brace_end < len(content) - 1:
                content = content[:brace_end + 1]

        parsed = json_mod.loads(content)
        if not isinstance(parsed, dict):
            return JSONResponse(
                content={"error": "LLM returned JSON that is not an object",
                         "model_used": requested_model},
                status_code=422,
            )
        # A key the prompt never named is a key the model invented, and the
        # webapp validates what comes back anyway. Reporting the extras rather
        # than dropping them silently is what lets a person see a model drifting.
        known = set(ROE_PARSE_FIELDS)
        return {
            "fields": {k: v for k, v in parsed.items() if k in known and v is not None},
            "unknownKeys": sorted(k for k in parsed if k not in known),
            "registryDigest": ROE_PARSE_REGISTRY_DIGEST,
            "model_used": requested_model,
        }

    except json_mod.JSONDecodeError as e:
        logger.error(f"RoE parse: invalid JSON from LLM: {e}")
        return JSONResponse(
            content={"error": f"LLM returned invalid JSON: {str(e)}",
                     "model_used": requested_model},
            status_code=422,
        )
    except Exception as e:
        logger.error(f"RoE parse error: {e}")
        return JSONResponse(
            content={"error": "Failed to parse the RoE document. The details are in the agent log.",
                     "model_used": requested_model},
            status_code=500,
        )


# =============================================================================
# MODELS BY FEATURE — shared plumbing for the endpoints that run one user's
# chosen model on that user's own keys (RoE parse, report narratives, command
# whisperer, Multi mute). Every answer the handler itself writes carries
# `model_used`: the webapp reads its absence as "this agent predates the
# feature" (502 agent_outdated) rather than as a model failure.
# =============================================================================

from llm_builder import (  # noqa: E402
    MODEL_UNAVAILABLE_MESSAGE,
    ProvidersUnreachable,
    build_llm_from_providers,
    fetch_user_providers,
    is_model_unavailable_error,
    log_provider_error,
    provider_error_details,
)


def _feature_error(code: str, model: str, status: int, error: str,
                   exc: Optional[BaseException] = None) -> JSONResponse:
    # The provider's class and HTTP status tell a bad key from a rate limit or
    # an overflowing context; its message stays in the log (it can quote the key).
    details = provider_error_details(exc) if exc is not None else {}
    return JSONResponse(
        content={"error": error, "code": code, "model_used": model, **details},
        status_code=status,
    )


def _feature_request_error(model: str, user_id: Optional[str]) -> Optional[JSONResponse]:
    """400 for a request with no model or no user: there is nothing to fall back to."""
    if not model:
        return JSONResponse(content={"error": "model is required", "model_used": ""},
                            status_code=400)
    if not user_id:
        return JSONResponse(content={"error": "user_id is required", "model_used": model},
                            status_code=400)
    return None


def _loop_model_refusal(model: str) -> JSONResponse:
    """400 for a loop model on a path with no chat run (no driver can answer)."""
    from agent_in_the_loop.errors import LoopModelNotSupportedHere
    return _feature_error(LoopModelNotSupportedHere.code, model, 400,
                          LoopModelNotSupportedHere.message)


async def _build_feature_llm(feature: str, model: str, user_id: str):
    """(llm, None), or (None, the coded JSONResponse to return)."""
    if is_loop_model(model):
        return None, _loop_model_refusal(model)
    try:
        providers = await asyncio.to_thread(fetch_user_providers, user_id)
    except ProvidersUnreachable as exc:
        logger.warning(f"{feature}: could not load the user's LLM providers ({exc})")
        return None, _feature_error("providers_unreachable", model, 503,
                                    "Couldn't load your LLM providers, try again")
    try:
        llm = await asyncio.to_thread(build_llm_from_providers, model, providers)
    except Exception as exc:                                      # noqa: BLE001
        log_provider_error(feature, model, exc)
        return None, _feature_error("model_unavailable", model, 503,
                                    MODEL_UNAVAILABLE_MESSAGE.format(model=model), exc)
    return llm, None


async def _invoke_feature_llm(feature: str, model: str, llm, messages):
    """(response, None), or (None, the JSONResponse to return).

    A key or model the provider refuses is `model_unavailable`, which opens the
    model picker. Anything else is transient and keeps the model.
    """
    try:
        return await llm.ainvoke(messages), None
    except Exception as exc:                                      # noqa: BLE001
        log_provider_error(feature, model, exc)
        if is_model_unavailable_error(exc):
            return None, _feature_error("model_unavailable", model, 503,
                                        MODEL_UNAVAILABLE_MESSAGE.format(model=model), exc)
        return None, JSONResponse(
            content={"error": "The model call failed. Try again in a moment.",
                     "model_used": model, **provider_error_details(exc)},
            status_code=502,
        )


# =============================================================================
# REPORT SUMMARIZER — LLM-generated narratives for pentest report sections
# =============================================================================

class ReportSummarizeRequest(BaseModel):
    """Request model for report narrative generation."""
    data: dict
    model: str | None = None
    user_id: str | None = None


@app.post("/api/report/summarize", tags=["Report"],
          dependencies=[Depends(require_master_internal_auth), Depends(require_internal_auth)])
async def summarize_report(body: ReportSummarizeRequest):
    """Generate LLM narrative summaries for pentest report sections."""
    from orchestrator_helpers.report_summarizer import generate_report_narratives

    requested_model = (body.model or "").strip()
    missing = _feature_request_error(requested_model, body.user_id)
    if missing:
        return missing
    llm, failure = await _build_feature_llm("Report summarizer", requested_model, body.user_id)
    if failure:
        return failure

    try:
        narratives = await generate_report_narratives(llm, body.data)
    except Exception as exc:                                      # noqa: BLE001
        log_provider_error("Report summarizer", requested_model, exc)
        if is_model_unavailable_error(exc):
            return _feature_error("model_unavailable", requested_model, 503,
                                  MODEL_UNAVAILABLE_MESSAGE.format(model=requested_model), exc)
        return JSONResponse(
            content={"error": "Failed to generate report narratives. The details are in the agent log.",
                     "model_used": requested_model, **provider_error_details(exc)},
            status_code=500,
        )
    if isinstance(narratives, dict):
        return {**narratives, "model_used": requested_model}
    return {"narratives": narratives, "model_used": requested_model}


class FfufExtensionsRequest(BaseModel):
    url: str
    headers: dict
    model: str
    max_extensions: int = 6
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_FFUF_EXT_SYSTEM_PROMPT = """You are a security testing assistant helping with directory fuzzing.

Given a target URL and its HTTP response headers, suggest the file extensions
most likely to discover real files on this server. Use header signals
(Server, X-Powered-By, Set-Cookie like JSESSIONID, framework hints) and the
URL path context to choose suffixes.

Rules:
- Path-aware: if the path is /js/ or /static/, prefer no extensions or only
  source-map/config-style extensions (.map). For /api/ prefer .json, .xml.
- Tech-aware: Apache+PHP -> .php, .phtml, .bak. IIS/ASP.NET -> .aspx, .asmx,
  .config. Tomcat/Java -> .jsp, .do, .action.
- Always include a small tail of generic backup/config suffixes when the
  path looks admin-like: .bak, .old, .config, .zip.
- Each extension must start with '.' and be a-z/0-9 only, max 8 chars.
- If the path is clearly a CDN/static asset path with no useful suffixes,
  return an empty list -- do not invent.
- Never include leading wildcards or directory separators.

Respond with ONLY a JSON object of this exact shape, no prose:
{"extensions": [".ext1", ".ext2", ...]}"""


def _build_llm_with_model_for_user(model_name: str, user_id: Optional[str]):
    """Build an LLM using the user's saved providers but force a specific model.
    Mirrors `_build_llm_for_user` but takes the model as an explicit argument
    instead of reading it from project settings."""
    import os
    import requests as requests_mod
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from agent_in_the_loop.errors import refuse_loop_model

    refuse_loop_model(model_name)
    user_providers: list = []
    if user_id:
        webapp_url = os.environ.get('WEBAPP_URL', 'http://webapp:3000')
        internal_key = os.environ.get('INTERNAL_API_KEY', '')
        try:
            resp = requests_mod.get(
                f"{webapp_url.rstrip('/')}/api/users/{user_id}/llm-providers?internal=true",
                headers={'x-internal-key': internal_key} if internal_key else {},
                timeout=10,
            )
            resp.raise_for_status()
            user_providers = resp.json() or []
        except Exception as e:
            logger.warning(f"ffuf-extensions: failed to fetch user LLM providers: {e}")

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

    custom_llm_config = _pick_custom_provider(user_providers, model_name)

    return setup_llm(
        model_name,
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
        custom_llm_config=custom_llm_config,
    )


@app.post("/llm/ffuf-extensions", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def llm_ffuf_extensions(body: FfufExtensionsRequest):
    """Suggest FFuf file extensions for a target based on its response headers.

    Called by the recon container's AI planner when FFUF_AI_EXTENSIONS is on.
    Reuses the same per-user LLM provider resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "ffuf-extensions: url=%s model=%s user=%s headers=%d-keys",
        body.url, body.model, body.user_id, len(body.headers or {}),
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except LoopModelNotSupportedHere:
        return _loop_model_refusal(body.model)
    except Exception as e:
        logger.error(f"ffuf-extensions: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    # STRIDE T20: response headers are target-controlled; frame them.
    user_msg = (
        f"URL: {body.url}\n"
        f"Headers: {wrap_untrusted(json_mod.dumps(body.headers), label='TARGET_HEADERS')}\n"
        f"Suggest up to {body.max_extensions} extensions."
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_FFUF_EXT_SYSTEM_PROMPT + "\n\n" + UNTRUSTED_OUTPUT_GUIDANCE),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"ffuf-extensions: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    # Strip ``` fences if the model wrapped the JSON
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"ffuf-extensions: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    extensions = data.get('extensions', [])
    if not isinstance(extensions, list):
        return JSONResponse(content={"error": "Model returned non-list extensions", "raw": str(extensions)[:500]}, status_code=502)

    return {"extensions": extensions[:body.max_extensions]}


class NucleiTagsRequest(BaseModel):
    technologies: list[str]
    servers: list[str]
    current_tags: list[str]
    candidates: list[str]
    model: str
    max_tags: int = 15
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_NUCLEI_TAGS_SYSTEM_PROMPT = """You are a security testing assistant selecting Nuclei
template tags for a vulnerability scan. Given a tech stack fingerprint, pick the
tags most likely to find real vulnerabilities and drop irrelevant ones.

Rules:
- You MUST pick ONLY from the `candidates` list provided. Any tag not in
  candidates will be rejected.
- ALWAYS keep universal high-impact tags when present in candidates: cve,
  exposure, misconfig, default-login, kev, oast, takeover.
- INCLUDE tech-specific tags ONLY when the technology is detected:
    WordPress signal -> wordpress, wp-plugin, wp (when in candidates)
    Apache signal    -> apache
    Nginx signal     -> nginx
    IIS / ASP.NET    -> iis, dotnet
    Tomcat / JVM     -> tomcat, java
    PHP signal       -> php
    Node/React/Express signal -> nodejs
    Joomla / Drupal / Magento / Jenkins / GitLab / Jira / Confluence -> their tag
    AWS / Azure / GCP / cloud signal -> their cloud tag
- DROP tech tags whose stack is NOT detected. Do not invent technologies that
  are not in the input.
- DROP narrow vuln-class tags that don't fit the stack (e.g. drop xxe on pure-JS
  apps with no XML, drop ssti if no template engine signal, drop sqli if the
  app appears static).
- Cap output at `max_tags` (default 15). Prefer breadth over redundancy.
- Be conservative: if unsure whether a tag matches, drop it.

Respond with ONLY a JSON object of this exact shape, no prose:
{"tags": ["tag1", "tag2", ...]}"""


@app.post("/llm/nuclei-tags", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def llm_nuclei_tags(body: NucleiTagsRequest):
    """Suggest Nuclei tags for a vuln scan based on tech fingerprint.

    Called by the recon container's AI planner when NUCLEI_AI_TAGS is on.
    Reuses the same per-user LLM provider resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "nuclei-tags: model=%s user=%s techs=%d servers=%d candidates=%d",
        body.model, body.user_id, len(body.technologies or []),
        len(body.servers or []), len(body.candidates or []),
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except LoopModelNotSupportedHere:
        return _loop_model_refusal(body.model)
    except Exception as e:
        logger.error(f"nuclei-tags: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    # STRIDE T20: detected technologies/servers are derived from target
    # fingerprints (attacker-influenced); frame them. current_tags/candidates
    # are tool-supplied control values and stay plain.
    user_msg = (
        f"Detected technologies: {wrap_untrusted(json_mod.dumps(body.technologies), label='TARGET_FINGERPRINT')}\n"
        f"Detected servers: {wrap_untrusted(json_mod.dumps(body.servers), label='TARGET_FINGERPRINT')}\n"
        f"User's current tags: {json_mod.dumps(body.current_tags)}\n"
        f"Candidates (pick only from these): {json_mod.dumps(body.candidates)}\n"
        f"Pick up to {body.max_tags} tags."
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_NUCLEI_TAGS_SYSTEM_PROMPT + "\n\n" + UNTRUSTED_OUTPUT_GUIDANCE),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"nuclei-tags: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"nuclei-tags: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    tags = data.get('tags', [])
    if not isinstance(tags, list):
        return JSONResponse(content={"error": "Model returned non-list tags", "raw": str(tags)[:500]}, status_code=502)

    return {"tags": tags[:body.max_tags]}


class WafClassifyRequest(BaseModel):
    url: str
    status_code: int
    headers: dict
    body_sample: str = ""
    response_time_ms: int = 0
    model: str
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_WAF_CLASSIFY_SYSTEM_PROMPT = """You are a security testing assistant classifying whether
an HTTP response came through a WAF (Web Application Firewall) or CDN edge layer.
Your output drives downstream throttling and false-positive filtering, so calibrated
confidence matters more than guessing a vendor.

You will receive: target URL, HTTP status code, full response headers, the first
4KB of the response body, and an optional response_time_ms hint.

Detection signals to weigh:
- Header tokens (vendor-branded): cf-ray, cf-cache-status, x-amz-cf-id, x-served-by,
  x-akamai-*, x-fastly-request-id, x-azure-ref, x-azure-fdid, x-sucuri-id, x-iinfo
  (Imperva), Server: cloudflare/cloudfront/akamai/fastly/varnish/imperva/sucuri.
- Cookie tokens: __cf_bm, cf_clearance, __cfduid (cloudflare), incap_ses_, visid_incap_
  (imperva), AKA_A2/AKAALB_ (akamai), awsalb (AWS), TS01* (BIG-IP/F5).
- Body fingerprints: "Attention Required! | Cloudflare", "error 1003", "Request blocked",
  "Access denied", "Reference #", challenge-page HTML structures, captcha widgets,
  Akamai "Pragma" pages, AWS WAF "Request blocked" JSON.
- Status+body mismatch: 200 OK with a tiny "blocked" body, 403 with branded reason
  phrase, 406/418/429 returned for benign requests.
- Latency outliers: response_time_ms >> 200ms for a static-looking 403 hints at
  inspection delay.
- Status codes commonly used by WAFs to short-circuit: 403, 406, 418, 429, 503.

WAF type values you may emit (lowercase, snake/kebab):
cloudflare, akamai, aws_waf, imperva, sucuri, fastly, azure_frontdoor, cloudfront,
modsecurity, f5, fortinet, barracuda, stackpath, custom. Use null for waf_type when
waf_detected is false. Use "custom" if signals indicate a WAF but vendor is unclear.

Confidence calibration (be honest, not optimistic):
- 90-100: clear vendor branding in multiple places (header + cookie + body)
- 70-89: strong fingerprint (one branded header OR challenge-page body)
- 40-69: suggestive signals (status+body mismatch, latency, no vendor token)
- 10-39: weak hints, mostly speculative
- 0-9:   no signal at all (return waf_detected=false)

Reasoning field: ONE sentence (<=200 chars) citing the strongest signals.

Respond with ONLY a JSON object of this exact shape, no prose:
{"waf_detected": true|false, "waf_type": "cloudflare"|null, "confidence": 0..100, "reasoning": "..."}"""


@app.post("/llm/waf-classify", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def llm_waf_classify(body: WafClassifyRequest):
    """Classify whether a response came through a WAF/CDN.

    Called by the recon container's WAF AI classifier when WAF_AI_CLASSIFIER is on.
    Reuses the same per-user LLM provider resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "waf-classify: url=%s status=%d model=%s user=%s headers=%d body=%dB rt=%dms",
        body.url, body.status_code, body.model, body.user_id,
        len(body.headers or {}), len(body.body_sample or ''), body.response_time_ms,
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except LoopModelNotSupportedHere:
        return _loop_model_refusal(body.model)
    except Exception as e:
        logger.error(f"waf-classify: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    # STRIDE T20: headers + body are attacker-controlled target response data;
    # frame them in a nonce boundary so the helper LLM treats them as data, not
    # instructions.
    user_msg = (
        f"URL: {body.url}\n"
        f"Status: {body.status_code}\n"
        f"Response time (ms): {body.response_time_ms}\n"
        f"Headers: {wrap_untrusted(json_mod.dumps(body.headers), label='TARGET_HEADERS')}\n"
        f"Body sample (first 4KB):\n{wrap_untrusted(body.body_sample, label='TARGET_BODY')}"
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_WAF_CLASSIFY_SYSTEM_PROMPT + "\n\n" + UNTRUSTED_OUTPUT_GUIDANCE),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"waf-classify: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"waf-classify: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    if not isinstance(data, dict):
        return JSONResponse(content={"error": "Model returned non-object", "raw": str(data)[:500]}, status_code=502)

    detected = data.get('waf_detected')
    confidence = data.get('confidence')
    if not isinstance(detected, bool) or not isinstance(confidence, (int, float)):
        return JSONResponse(content={"error": "Model returned malformed schema", "raw": str(data)[:500]}, status_code=502)

    return {
        "waf_detected": detected,
        "waf_type": data.get('waf_type'),
        "confidence": int(confidence),
        "reasoning": (data.get('reasoning') or '')[:500],
    }


class NucleiFpFilterRequest(BaseModel):
    template_id: str
    tags: list[str] = []
    status_line: str = ""
    response_sample: str = ""
    model: str
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_NUCLEI_FP_FILTER_SYSTEM_PROMPT = """You are a security testing assistant deciding
whether a Nuclei response is a real vulnerability hit or a WAF/rate-limit block
page disguised as one. Your verdict gates the finding -- a wrong "blocked" call
HIDES a real vuln, a wrong "real" call SHIPS a false positive. Calibrate.

You will receive: Nuclei template id, template tags (sqli/xss/rce/...), HTTP
status line, and the first 4KB of the response body.

Block-page signals (lean toward is_blocked=true):
- Status 403/406/418/429/503 paired with a tiny generic body.
- Body contains vendor-branded WAF text: "Cloudflare Ray ID", "Reference #",
  "Request ID:", "AWS WAF", "Imperva Incapsula", "Sucuri", "ModSecurity",
  "Forbidden by F5", "Fortinet". Note: a body MENTIONING WAF terms in a
  legitimate context (admin panel, docs) is NOT a block; look at structure.
- Body is a generic 1-2 line error: "Access Denied", "Request blocked",
  "Sorry, your request couldn't be processed".
- AWS WAF JSON shape: {"message": "Forbidden"} or similar minimal JSON error.
- Cookies set in response: __cf_bm, cf_clearance, incap_ses_, visid_incap_,
  AKA_A2, awsalb, TS01* (BIG-IP/F5).
- Body is a captcha/challenge page: "Please verify you are human", JS challenge
  redirect, "Just a moment...".

Real-finding signals (lean toward is_blocked=false):
- Status 200/302 with substantive content (DB error message, reflected payload,
  exposed file content, version banner, debug page).
- Body contains actual evidence the template was looking for: SQL error string,
  reflected XSS payload echo, OS command output, leaked stack trace, file system
  paths, debug variable dumps.
- Body discusses WAF terms in CONTEXT (e.g. an admin panel that lets you toggle
  WAF settings) -- that's the page being exposed, not the page blocking you.
- Status code matches what the template hunts for (e.g. 200 for an exposure
  template, 500 for a backend error template).

Confidence calibration (be honest):
- 90-100: clear vendor branding (WAF cookie + status + branded body).
- 70-89: strong block-page shape (small body + suspicious status + generic
  error tone) OR strong real-hit shape (clear template-target evidence).
- 40-69: ambiguous (small 403 with no vendor signature, could be either).
- 10-39: weak hint, mostly speculative.
- 0-9: no signal -- return is_blocked=false.

Reason field: ONE sentence (<=200 chars) citing the strongest signal.

Respond with ONLY a JSON object of this exact shape, no prose:
{"is_blocked": true|false, "confidence": 0..100, "reason": "..."}"""


@app.post("/llm/nuclei-fp-filter", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def llm_nuclei_fp_filter(body: NucleiFpFilterRequest):
    """Classify whether a Nuclei response is a WAF/rate-limit block page
    rather than a real vulnerability hit.

    Called by the recon container's Nuclei FP filter when
    NUCLEI_AI_RESPONSE_FILTER is on. Reuses the same per-user LLM provider
    resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "nuclei-fp-filter: template=%s tags=%s status=%s body=%dB model=%s user=%s",
        body.template_id, body.tags, body.status_line[:60],
        len(body.response_sample or ''), body.model, body.user_id,
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except LoopModelNotSupportedHere:
        return _loop_model_refusal(body.model)
    except Exception as e:
        logger.error(f"nuclei-fp-filter: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    # STRIDE T20: status line + response body are attacker-controlled target data.
    user_msg = (
        f"Template: {body.template_id}\n"
        f"Tags: {json_mod.dumps(body.tags)}\n"
        f"Status: {wrap_untrusted(body.status_line, label='TARGET_STATUS')}\n"
        f"Response sample (first 4KB):\n{wrap_untrusted(body.response_sample, label='TARGET_BODY')}"
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_NUCLEI_FP_FILTER_SYSTEM_PROMPT + "\n\n" + UNTRUSTED_OUTPUT_GUIDANCE),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"nuclei-fp-filter: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"nuclei-fp-filter: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    if not isinstance(data, dict):
        return JSONResponse(content={"error": "Model returned non-object", "raw": str(data)[:500]}, status_code=502)

    is_blocked = data.get('is_blocked')
    confidence = data.get('confidence')
    if not isinstance(is_blocked, bool) or not isinstance(confidence, (int, float)):
        return JSONResponse(content={"error": "Model returned malformed schema", "raw": str(data)[:500]}, status_code=502)

    return {
        "is_blocked": is_blocked,
        "confidence": int(confidence),
        "reason": (data.get('reason') or '')[:500],
    }


class TakeoverClassifyRequest(BaseModel):
    hostname: str
    expected_provider: str = ""
    status_code: int = 0
    headers: dict = {}
    response_sample: str = ""
    model: str
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_TAKEOVER_CLASSIFY_SYSTEM_PROMPT = """You are a security testing assistant deciding
whether an HTTP response is a genuine third-party SaaS "service unclaimed" page
(a real subdomain takeover candidate) or a WAF block page that LOOKS like one.

Subdomain takeover detectors (Subjack, Nuclei takeover templates) match against
fingerprint strings like "There's nothing here yet" (Heroku), "NoSuchBucket"
(S3), "The page you have requested does not exist" (Bitbucket). WAFs and CDN
edges with no origin configured for a hostname return very similar text. The
collision produces critical-severity false positives that page on-call.

You will receive: hostname, the takeover provider the static signature claimed
to match, HTTP status code, response headers, and the first 4KB of the
response body.

WAF-block signals (lean is_waf_block=true):
- Status 403/406/429/503 (most SaaS unclaimed pages return 404).
- Body is a generic 1-2 line error with no provider branding.
- Body contains vendor WAF signatures: "Cloudflare Ray ID", "Reference #",
  "AWS WAF", "Imperva", "Akamai", "Sucuri", "ModSecurity", "Forbidden by F5".
- Cookies set: __cf_bm, cf_clearance, incap_ses_, awsalb, TS01*, akamai-*.
- Response body claims "blocked" / "denied" / "unauthorized" without naming
  the SaaS provider the static fingerprint claimed.
- Body shape mismatches the claimed provider (e.g. claimed "heroku" but the
  body has no Heroku branding, dyno mention, or characteristic styling).

Genuine-unclaimed signals (lean is_waf_block=false):
- Status 404 with body that EXPLICITLY names the claimed provider:
  - heroku: "There's nothing here yet", references herokuapp.com
  - s3: "NoSuchBucket", "The specified bucket does not exist"
  - github pages: "There isn't a GitHub Pages site here"
  - bitbucket: "Repository not found"
  - netlify/vercel/surge: provider-branded "site not found" pages
- Body has provider-specific HTML structure (Heroku error theme, S3 XML
  error, GitHub octocat).
- Headers include the SaaS edge's Server token (Server: AmazonS3,
  GitHub.com, Netlify, Vercel) -- this is unambiguous proof.

Special case -- AMBIGUOUS but lean WAF when:
- Generic "page not found" 404 with NO provider branding at all (could be
  either; absence of provider signal is itself suspicious for a real
  takeover).

Confidence calibration:
- 90-100: clear vendor branding (WAF cookie/branded body OR clear SaaS-
  branded unclaimed page).
- 70-89: strong shape signal (clean WAF block tone OR clean SaaS error).
- 40-69: ambiguous, no clear vendor token either way.
- 10-39: weak hint.
- 0-9: no signal.

Reason field: ONE sentence (<=200 chars) citing the strongest signal.

Respond with ONLY a JSON object of this exact shape, no prose:
{"is_waf_block": true|false, "confidence": 0..100, "reason": "..."}"""


@app.post("/llm/takeover-classify", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def llm_takeover_classify(body: TakeoverClassifyRequest):
    """Disambiguate a takeover finding from a WAF block masquerading as one.

    Called by the recon container's takeover scanner when
    TAKEOVER_AI_CLASSIFIER is on. Reuses the same per-user LLM provider
    resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "takeover-classify: host=%s provider=%s status=%d body=%dB model=%s user=%s",
        body.hostname, body.expected_provider, body.status_code,
        len(body.response_sample or ''), body.model, body.user_id,
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except LoopModelNotSupportedHere:
        return _loop_model_refusal(body.model)
    except Exception as e:
        logger.error(f"takeover-classify: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    # STRIDE T20: headers + response body are attacker-controlled target data.
    user_msg = (
        f"Hostname: {body.hostname}\n"
        f"Claimed provider: {body.expected_provider}\n"
        f"Status: {body.status_code}\n"
        f"Headers: {wrap_untrusted(json_mod.dumps(body.headers), label='TARGET_HEADERS')}\n"
        f"Response sample (first 4KB):\n{wrap_untrusted(body.response_sample, label='TARGET_BODY')}"
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_TAKEOVER_CLASSIFY_SYSTEM_PROMPT + "\n\n" + UNTRUSTED_OUTPUT_GUIDANCE),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"takeover-classify: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"takeover-classify: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    if not isinstance(data, dict):
        return JSONResponse(content={"error": "Model returned non-object", "raw": str(data)[:500]}, status_code=502)

    is_waf_block = data.get('is_waf_block')
    confidence = data.get('confidence')
    if not isinstance(is_waf_block, bool) or not isinstance(confidence, (int, float)):
        return JSONResponse(content={"error": "Model returned malformed schema", "raw": str(data)[:500]}, status_code=502)

    return {
        "is_waf_block": is_waf_block,
        "confidence": int(confidence),
        "reason": (data.get('reason') or '')[:500],
    }


# =============================================================================
# /jev/* — the same request bodies and response shapes as the matching /llm/*
# endpoints, answered by TypeSafe Jev instead of a chat LLM. Recon reuses its
# existing validators and fallbacks unchanged. The token is loaded here from the
# project owner's account and never leaves the agent.
# =============================================================================

def _jev_failure(err) -> JSONResponse:
    """A Jev-side failure as a 503 with a fixed body. Never exception text."""
    body = {"error_type": err.error_type, "error": err.message}
    if err.retry_after is not None:
        body["retry_after"] = err.retry_after
    return JSONResponse(content=body, status_code=503)


class _JevPreambleError(Exception):
    """A request the /jev/* preamble refused, carrying the exact response to send.

    Not an HTTPException: recon reads `error_type` from the TOP LEVEL of the body, and
    HTTPException would nest it under "detail".
    """

    def __init__(self, response: JSONResponse):
        self.response = response


async def _jev_preamble(user_id: str, project_id: str):
    """Return the selected immutable Jev provider, or raise `_JevPreambleError`.

    Order matters: the caller's ids are validated, the project is bound to its owner
    (fail closed), and only then is the token loaded, so a mismatched project never
    causes the owner's token to be read.
    """
    import jev_client
    from llm_builder import fetch_user_providers, ProvidersUnreachable

    if not (user_id or "").strip() or not (project_id or "").strip():
        raise _JevPreambleError(JSONResponse(
            content={"error_type": "jev_bad_request", "error": "user_id and project_id are required"},
            status_code=422))

    # Owner binding, fail closed: the project must belong to this user.
    try:
        selected_id = await jev_client.selected_provider_id(project_id, user_id)
    except jev_client.JevError as e:
        status = 403 if e.error_type == "jev_forbidden" else 503
        raise _JevPreambleError(JSONResponse(
            content={"error_type": e.error_type, "error": e.message}, status_code=status))

    try:
        providers = await asyncio.to_thread(fetch_user_providers, user_id)
    except ProvidersUnreachable:
        raise _JevPreambleError(_jev_failure(jev_client.JevError("jev_unavailable")))
    try:
        return jev_client.resolve_provider(providers, selected_id, user_id)
    except jev_client.JevError as e:
        raise _JevPreambleError(_jev_failure(e))


def _log_jev(endpoint: str, user_id: str, project_id: str, n_questions: int,
             model: str, latency_ms: int, outcome: str) -> None:
    logger.info(
        "jev %s: user=%s project=%s questions=%d model=%s latency=%dms %s",
        endpoint, user_id, project_id, n_questions, model, latency_ms, outcome,
    )


async def _run_jev(endpoint: str, user_id: str, project_id: str, n_questions: int, coro):
    """Shared wrapper: owner/token preamble, timing, fixed-error mapping, log."""
    import time as _time
    import jev_hooks

    try:
        key = await _jev_preamble(user_id, project_id)
    except _JevPreambleError as e:
        _log_jev(endpoint, user_id, project_id, n_questions, jev_hooks.JEV_MODEL, 0,
                 f"rejected status={e.response.status_code}")
        return e.response

    started = _time.monotonic()
    try:
        result = await coro(key)
    except jev_hooks.JevError as e:
        _log_jev(endpoint, user_id, project_id, n_questions, jev_hooks.JEV_MODEL,
                 int((_time.monotonic() - started) * 1000),
                 f"backend={key.provider_type} error_type={e.error_type}")
        return _jev_failure(e)
    except Exception as e:                                        # noqa: BLE001
        # Anything unclassified still has to be a fixed 503 that recon's breaker can
        # name. The class is logged, never the message: it can carry request state.
        _log_jev(endpoint, user_id, project_id, n_questions, jev_hooks.JEV_MODEL,
                 int((_time.monotonic() - started) * 1000),
                 f"backend={key.provider_type} error={type(e).__name__}")
        return _jev_failure(jev_hooks.JevError("jev_bad_response"))
    _log_jev(endpoint, user_id, project_id, n_questions, jev_hooks.JEV_MODEL,
             int((_time.monotonic() - started) * 1000), f"backend={key.provider_type} ok")
    return result


@app.post("/jev/ffuf-extensions", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_ffuf_extensions(body: FfufExtensionsRequest):
    import jev_hooks
    return await _run_jev(
        "ffuf-extensions", body.user_id or "", body.project_id or "",
        len(jev_hooks.FFUF_JEV_CATALOG),
        lambda key: jev_hooks.ffuf_extensions(key, body.url, body.headers or {}, body.max_extensions),
    )


@app.post("/jev/nuclei-tags", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_nuclei_tags(body: NucleiTagsRequest):
    import jev_hooks
    return await _run_jev(
        "nuclei-tags", body.user_id or "", body.project_id or "",
        len(body.candidates or []),
        lambda key: jev_hooks.nuclei_tags(key, body.technologies, body.servers,
                                          body.candidates, body.max_tags),
    )


@app.post("/jev/waf-classify", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_waf_classify(body: WafClassifyRequest):
    import jev_hooks
    return await _run_jev(
        "waf-classify", body.user_id or "", body.project_id or "", 2,
        lambda key: jev_hooks.waf_classify(key, body.url, body.status_code, body.headers or {},
                                           body.body_sample, body.response_time_ms),
    )


@app.post("/jev/takeover-classify", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_takeover_classify(body: TakeoverClassifyRequest):
    import jev_hooks
    return await _run_jev(
        "takeover-classify", body.user_id or "", body.project_id or "", 1,
        lambda key: jev_hooks.takeover_classify(key, body.hostname, body.expected_provider,
                                                body.status_code, body.headers or {},
                                                body.response_sample),
    )


# /jev/* hooks with no /llm/* twin: a deterministic step recon used to take alone.
# Their request models are their own and tightly bounded, because nothing upstream
# shaped them; recon validates each response shape before using it.

class FfufBasePathsRequest(BaseModel):
    candidates: List[str] = Field(min_length=1, max_length=400)
    cap: int = Field(ge=1, le=50)
    user_id: Optional[str] = None
    project_id: Optional[str] = None

    @field_validator("candidates")
    @classmethod
    def _distinct_bounded_paths(cls, value):
        if any(not p or len(p) > 200 for p in value):
            raise ValueError("each candidate is 1-200 characters")
        if len(set(value)) != len(value):
            raise ValueError("candidates must be distinct")
        return value


class PageTypeItem(BaseModel):
    url: str = ""
    host: str = ""
    status_code: int = Field(default=0, ge=0, le=999)
    content_length: int = Field(default=0, ge=0)
    word_count: int = Field(default=0, ge=0)
    line_count: int = Field(default=0, ge=0)
    response_time_ms: int = Field(default=0, ge=0)
    is_cdn: bool = False
    title: str = ""
    server: str = ""
    cname: str = ""
    headers: dict = Field(default_factory=dict)
    body: str = ""


class PageTypeRequest(BaseModel):
    pages: List[PageTypeItem] = Field(min_length=1, max_length=50)
    user_id: Optional[str] = None
    project_id: Optional[str] = None


class ToolHealthRequest(BaseModel):
    tool: Literal["katana", "hakrawler", "gau", "paramspider", "kiterunner", "ffuf", "arjun", "jsluice"]
    return_code: int
    elapsed_s: float = Field(ge=0)
    seed_count: int = Field(ge=0)
    stderr: str = Field(min_length=1)
    user_id: Optional[str] = None
    project_id: Optional[str] = None


class CrawlSeedHost(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    title: str = ""
    server: str = ""
    status_code: int = Field(default=0, ge=0, le=999)
    content_length: int = Field(default=0, ge=0)
    word_count: int = Field(default=0, ge=0)
    line_count: int = Field(default=0, ge=0)
    url_count: int = Field(default=0, ge=0)


class CrawlSeedOrderRequest(BaseModel):
    hosts: List[CrawlSeedHost] = Field(min_length=1, max_length=400)
    user_id: Optional[str] = None
    project_id: Optional[str] = None


class SerializedBlobItem(BaseModel):
    # Evidence only: no field carries the format the signatures matched or their
    # label for it, so Jev's format answer stays its own reading of the blob. A
    # blank snippet is refused: Jev is never asked about nothing.
    snippet: str = Field(min_length=1, max_length=200)
    transport: Literal["cookie", "header", "param", "body", ""] = ""
    location: str = Field(default="", max_length=300)
    encoding_layers: List[Literal["url", "base64", "gzip", "zlib", "hex", "truncated"]] = Field(
        default_factory=list, max_length=8)


class SerializedClassifyRequest(BaseModel):
    blobs: List[SerializedBlobItem] = Field(min_length=1, max_length=50)
    user_id: Optional[str] = None
    project_id: Optional[str] = None


class RoutePrivacyItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=200)
    method: Literal["GET", "HEAD"] = "GET"
    category: Literal["admin", "admin_debug", "api", "api_documentation", "authentication", "dynamic",
                      "endpoint", "file_access", "file_upload", "search", "upload", "other"] = "other"
    openapi_secured: bool = False
    declared_only: bool = False
    js_only: bool = False
    host_internal: bool = False


class RoutePrivacyRankRequest(BaseModel):
    routes: List[RoutePrivacyItem] = Field(min_length=1, max_length=400)
    user_id: Optional[str] = None
    project_id: Optional[str] = None


class RouteCandidateItem(BaseModel):
    # Evidence only: no route_class and no signature, so Jev's kind is a second
    # opinion rather than the classifier read back. Key names, never values.
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=200)
    method: Literal["GET", "HEAD"] = "GET"
    anon_status: int = Field(default=0, ge=0, le=999)
    authed_status: Optional[int] = Field(default=None, ge=0, le=999)
    content_class: Literal["json", "html", "text", "xml", "binary", "other"] = "other"
    size_bucket: Literal["<1k", "1-10k", "10-100k", ">100k"] = "<1k"
    bodies_match: Optional[bool] = None
    key_paths: List[str] = Field(default_factory=list, max_length=60)
    max_array_len: int = Field(default=0, ge=0)
    det_signals: List[Literal["pii", "pii_others", "sensitive_fields", "secret"]] = Field(
        default_factory=list, max_length=4)
    auth_expected_by: List[Literal["openapi", "openapi_tag", "declared_only", "seen_denied", "path_word",
                                   "host_word", "siblings_locked", "version_locked", "vary_auth"]] = Field(
        default_factory=list, max_length=9)
    generated_by: Literal["found", "seed", "vcs", "backup", "version", "sibling", "framework", "catalog",
                          "cross_host"] = "found"

    @field_validator("key_paths")
    @classmethod
    def _short_keys(cls, value):
        if any(len(k) > 80 for k in value):
            raise ValueError("key paths are at most 80 characters")
        return value


class RouteExposureAssessRequest(BaseModel):
    candidates: List[RouteCandidateItem] = Field(min_length=1, max_length=50)
    user_id: Optional[str] = None
    project_id: Optional[str] = None


@app.post("/jev/ffuf-base-paths", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_ffuf_base_paths(body: FfufBasePathsRequest):
    import jev_hooks
    return await _run_jev(
        "ffuf-base-paths", body.user_id or "", body.project_id or "", len(body.candidates),
        lambda key: jev_hooks.ffuf_base_paths(key, body.candidates, body.cap),
    )


@app.post("/jev/page-type", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_page_type(body: PageTypeRequest):
    import jev_hooks
    return await _run_jev(
        "page-type", body.user_id or "", body.project_id or "",
        len(body.pages) * len(jev_hooks.PAGE_CLASSES),
        lambda key: jev_hooks.page_type(key, [p.model_dump() for p in body.pages]),
    )


@app.post("/jev/tool-health", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_tool_health(body: ToolHealthRequest):
    import jev_hooks
    return await _run_jev(
        "tool-health", body.user_id or "", body.project_id or "", 1,
        lambda key: jev_hooks.tool_health(key, body.tool, body.return_code, body.elapsed_s,
                                          body.seed_count, body.stderr),
    )


@app.post("/jev/crawl-seed-order", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_crawl_seed_order(body: CrawlSeedOrderRequest):
    import jev_hooks
    return await _run_jev(
        "crawl-seed-order", body.user_id or "", body.project_id or "", len(body.hosts),
        lambda key: jev_hooks.crawl_seed_order(key, [h.model_dump() for h in body.hosts]),
    )


@app.post("/jev/serialized-classify", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_serialized_classify(body: SerializedClassifyRequest):
    import jev_hooks
    return await _run_jev(
        "serialized-classify", body.user_id or "", body.project_id or "",
        len(body.blobs) * 2,
        lambda key: jev_hooks.serialized_classify(key, [b.model_dump() for b in body.blobs]),
    )


@app.post("/jev/route-privacy-rank", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_route_privacy_rank(body: RoutePrivacyRankRequest):
    import jev_hooks
    return await _run_jev(
        "route-privacy-rank", body.user_id or "", body.project_id or "", len(body.routes),
        lambda key: jev_hooks.route_privacy_rank(key, [r.model_dump() for r in body.routes]),
    )


@app.post("/jev/route-exposure-assess", tags=["LLM"], dependencies=[Depends(require_internal_auth)])
async def jev_route_exposure_assess(body: RouteExposureAssessRequest):
    import jev_hooks
    return await _run_jev(
        "route-exposure-assess", body.user_id or "", body.project_id or "",
        len(body.candidates) * 2,
        lambda key: jev_hooks.route_exposure_assess(key, [c.model_dump() for c in body.candidates]),
    )


@app.post("/emergency-stop-all", tags=["System"], dependencies=[Depends(require_internal_auth_only)])
async def emergency_stop_all():
    """Emergency stop: cancel every running agent task immediately."""
    if not ws_manager:
        return JSONResponse(content={"stopped": 0}, status_code=503)
    stopped = await ws_manager.stop_all()
    logger.warning(f"Emergency stop: cancelled {stopped} agent task(s)")
    return {"stopped": stopped}


class SessionStopRequest(BaseModel):
    user_id: str
    project_id: str
    session_id: str


@app.post("/agent-session/stop", tags=["Sessions"],
          dependencies=[Depends(require_configured_master_auth)])
async def stop_agent_session(body: SessionStopRequest):
    """Cancel the running agent task for ONE session (by user/project/session).

    Called when a conversation is deleted so its agent loop stops instead of
    continuing to run headlessly and re-seeding the Neo4j attack-chain graph.
    """
    if not ws_manager:
        return JSONResponse(content={"stopped": False}, status_code=503)
    session_key = f"{body.user_id}:{body.project_id}:{body.session_id}"
    stopped = await ws_manager.stop_session(session_key)
    logger.info(f"Agent session stop requested for {session_key}: cancelled={stopped}")
    return {"stopped": stopped}


@app.get("/agent-sessions/live", tags=["Sessions"], dependencies=[Depends(require_master_internal_auth)])
async def live_agent_sessions(project_id: str):
    """Session ids of a project whose agent run is still in progress.

    The webapp asks this before it treats a Conversation.agentRunning flag as a
    running session, so a flag left behind by a restarted agent does not lock
    the project. 503 when the manager is not up: the caller then stays busy.

    Master key only: the scanner token lives in the target-facing sandbox, and a
    live session id is what /agent-session/stop needs.
    """
    if not ws_manager:
        return JSONResponse(content={"error": "agent not ready"}, status_code=503)
    answer = {"project_id": project_id, "session_ids": ws_manager.live_session_ids(project_id)}
    # Agent in the Loop runs only: what the run waits for, so a refused preset
    # or scan can say "waiting for the external agent" (states, never ids of steps).
    loop_states = get_broker().loop_states_for_project(project_id)
    if loop_states:
        answer["loop_states"] = loop_states
    return answer


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """
    Health check endpoint.

    Returns the API status, version, number of loaded tools, and active sessions.
    """
    tools_count = 0
    if orchestrator and orchestrator.tool_executor:
        tools_count = len(orchestrator.tool_executor.get_all_tools())

    sessions_count = get_session_count()

    # Count in-flight fireteam waves by scanning active asyncio tasks for
    # names starting with "fireteam-" (set by fireteam_deploy_node). Cheap
    # probe — no DB roundtrip.
    active_waves = 0
    try:
        for task in asyncio.all_tasks():
            name = task.get_name() or ""
            if name.startswith("fireteam-"):
                active_waves += 1
    except Exception:
        pass

    from project_settings import get_setting
    return HealthResponse(
        status="ok" if orchestrator and orchestrator._initialized else "initializing",
        version="3.0.0",
        tools_loaded=tools_count,
        active_sessions=sessions_count,
        fireteam_enabled=bool(get_setting("FIRETEAM_ENABLED", False)),
        persistent_checkpointer=bool(get_setting("PERSISTENT_CHECKPOINTER", False)),
        active_waves=active_waves,
        loop_enabled=loop_enabled(),
    )


@app.get("/host-ip", tags=["System"])
async def get_host_ip():
    """The Docker host's LAN IP, for the UI to suggest as the reverse-shell LHOST.

    Detected on the host by redamon.sh (export_host_lan_ip) and passed in via the
    HOST_LAN_IP env var, because a container cannot discover the host's routable
    address from inside the 172.x sandbox (issue #180). Empty string when
    detection failed or a HOST_LAN_IP override is unset; the caller then simply
    shows no suggestion. Read-only, no parameters, no secrets.
    """
    return {"detectedHostIp": os.getenv("HOST_LAN_IP", "").strip()}


# =============================================================================
# TRADECRAFT — Verify endpoint for the per-user knowledge resource catalog
# =============================================================================

class TradecraftVerifyRequest(BaseModel):
    url: str
    user_id: Optional[str] = None      # used to load the user's LLM provider keys
    github_token: Optional[str] = None
    force: bool = False
    # Per-resource model override. When set, the verify endpoint builds a
    # provider-agnostic LLM for THIS model (resolving the user's provider
    # keys) instead of reusing orchestrator.llm. Decouples tradecraft
    # ingestion from the agent's current chat model and from project-load
    # order (fixes the "agent reverted to default Anthropic after restart"
    # 401 path).
    model: Optional[str] = None


def _pick_custom_provider(user_providers: list, model_name: str) -> Optional[dict]:
    """Return the custom-provider record that should serve this request, if any.

    Resolution order:
      1. If `model_name` is `custom/<id>`, look up that exact provider id.
      2. Otherwise, the first provider whose providerType is custom.
    Returns None when no custom provider is configured. Non-chat rows (Jev)
    are never returned.
    """
    from llm_builder import custom_provider_or_fallback
    return custom_provider_or_fallback(user_providers, model_name)


def _build_llm_for_user(user_id: Optional[str]):
    """Build an LLM for a non-project endpoint by loading the user's providers
    via the internal webapp API. Falls back to env-based providers when user_id
    is missing or the lookup fails.

    When the user has only a custom (OpenAI-compatible / bedrock_custom /
    ollama_local) provider configured, this honors it instead of falling back
    to the global default model — otherwise the call would crash trying to
    instantiate an Anthropic client with no key.
    """
    import os
    import requests
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from project_settings import DEFAULT_AGENT_SETTINGS, get_settings

    model_name = (get_settings() or {}).get(
        'OPENAI_MODEL', DEFAULT_AGENT_SETTINGS.get('OPENAI_MODEL', 'claude-opus-4-6')
    )
    if is_loop_model(model_name):
        raise LoopModelNotSupportedHere()
    user_providers: list = []
    if user_id:
        webapp_url = os.environ.get('WEBAPP_URL', 'http://webapp:3000')
        internal_key = os.environ.get('INTERNAL_API_KEY', '')
        try:
            resp = requests.get(
                f"{webapp_url.rstrip('/')}/api/users/{user_id}/llm-providers?internal=true",
                headers={'x-internal-key': internal_key} if internal_key else {},
                timeout=10,
            )
            resp.raise_for_status()
            user_providers = resp.json() or []
        except Exception as e:
            logger.warning(f"tradecraft verify: failed to fetch user LLM providers: {e}")

    custom_provider = _pick_custom_provider(user_providers, model_name)
    if custom_provider:
        custom_model = f"custom/{custom_provider.get('id', '')}"
        logger.info(
            f"tradecraft verify: using custom provider id={custom_provider.get('id')} "
            f"type={custom_provider.get('providerType')}"
        )
        return setup_llm(custom_model, custom_llm_config=custom_provider)

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
        model_name,
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
    )


# Authenticated because it fetches a caller-chosen URL from inside the agent's
# network and spends the named user's LLM keys (CVE-2026-111323).
@app.post("/tradecraft/verify", tags=["Tradecraft"], dependencies=[Depends(require_internal_auth)])
async def tradecraft_verify(body: TradecraftVerifyRequest):
    """
    Fetch a tradecraft resource URL, detect its type, build a sitemap, and
    LLM-summarize its scope. Called by the webapp `/api/users/{id}/tradecraft-resources/{rid}/verify` route.
    """
    from orchestrator_helpers.tradecraft_lookup import verify_resource
    from project_settings import DEFAULT_AGENT_SETTINGS

    if not orchestrator or not orchestrator._initialized:
        return JSONResponse(
            {"error": "Agent not initialized"}, status_code=503
        )
    # SSRF / scheme validation runs BEFORE LLM setup so a private-IP probe
    # never wakes the LLM client. verify_resource also re-validates internally,
    # but failing fast here keeps the path symmetric with the webapp guard.
    from orchestrator_helpers.tradecraft_lookup import validate_url
    ok, err = validate_url(body.url)
    if not ok:
        return {
            "summary": "",
            "resource_type": "agentic-crawl",
            "sitemap": {},
            "crawl_stopped_because": "",
            "crawl_stats": {},
            "last_error": err,
        }
    # Resolve the LLM used for crawl decisions + summary:
    #   1. If the request specifies a per-resource model, build a provider-
    #      agnostic LLM for THAT model from the user's saved providers.
    #      (Same path the 5 recon AI classifiers use.) This is the normal
    #      path — the webapp always sends a model now that the field is
    #      required at create/edit time.
    #   2. Otherwise (back-compat for direct API callers and old rows
    #      written before this column existed), prefer the orchestrator's
    #      loaded LLM, then fall back to _build_llm_for_user.
    try:
        if body.model:
            llm = _build_llm_with_model_for_user(body.model, body.user_id)
        elif orchestrator.llm is not None and not is_loop_llm(orchestrator.llm):
            llm = orchestrator.llm
        else:
            llm = _build_llm_for_user(body.user_id)
    except LoopModelNotSupportedHere:
        return _loop_model_refusal(body.model or "")
    except Exception as e:
        logger.error(f"tradecraft verify: cannot set up LLM: {e}")
        return JSONResponse(
            {"error": f"LLM not configured: {e}"}, status_code=503
        )
    bounds = {
        "max_pages": DEFAULT_AGENT_SETTINGS.get("TRADECRAFT_CRAWL_MAX_PAGES", 30),
        "max_llm_calls": DEFAULT_AGENT_SETTINGS.get("TRADECRAFT_CRAWL_MAX_LLM_CALLS", 20),
        "time_budget_sec": DEFAULT_AGENT_SETTINGS.get("TRADECRAFT_CRAWL_TIME_BUDGET_SEC", 180),
        "max_depth": DEFAULT_AGENT_SETTINGS.get("TRADECRAFT_CRAWL_MAX_DEPTH", 3),
    }
    mcp_manager = getattr(orchestrator, "_mcp_manager", None)
    try:
        result = await verify_resource(
            body.url,
            github_token=body.github_token or "",
            force=body.force,
            llm=llm,
            mcp_manager=mcp_manager,
            bounds=bounds,
        )
        return result
    except Exception as exc:
        logger.error(f"tradecraft verify failed: {exc}")
        return JSONResponse(
            {"error": str(exc)}, status_code=500
        )


@app.get("/mcp/manifest", tags=["MCP"], dependencies=[Depends(require_internal_auth_only)])
async def get_mcp_manifest():
    """
    Return the current MCP server manifest as seen by the agent.

    Combines the 5 system MCP servers (shipped with the product) and any
    user-managed servers loaded from the most recent project session. Auth
    tokens are NOT exposed — only env-var references.
    """
    import mcp_registry
    return {
        "servers": mcp_registry.redact_for_api(mcp_registry.current()),
        "errors": [e.model_dump() for e in mcp_registry.current_errors()],
        "warnings": [w.model_dump() for w in mcp_registry.current_warnings()],
        "system_server_ids": sorted(mcp_registry.SYSTEM_SERVER_IDS),
    }


@app.post("/mcp/reload", tags=["MCP"], dependencies=[Depends(require_internal_auth_only)])
async def reload_mcp_manifest(payload: dict = None):
    """
    Re-merge system + user MCP servers and reconnect the MCP client.

    Called by the webapp after a user adds/edits/deletes an MCP server.
    Body (optional): {"userMcpServers": [...]} — when omitted, uses the
    most recent cached project settings.
    """
    if orchestrator is None:
        return JSONResponse({"error": "orchestrator not ready"}, status_code=503)

    user_servers_raw = None
    if isinstance(payload, dict):
        user_servers_raw = payload.get("userMcpServers")

    try:
        result = await orchestrator.reload_mcp_manifests(user_servers_raw)
        return result
    except Exception as exc:
        logger.exception(f"/mcp/reload failed: {exc}")
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.post("/mcp/test", tags=["MCP"], dependencies=[Depends(require_internal_auth_only)])
async def test_mcp_server(server: dict):
    """
    Test connectivity to a single MCP server draft (NOT yet persisted).

    Builds a throwaway MultiServerMCPClient, calls list_tools(), tears it down.
    Does not mutate any agent state — safe to call while scans are in flight.
    """
    import mcp_registry
    import time
    from langchain_mcp_adapters.client import MultiServerMCPClient

    started = time.monotonic()
    parse_errors: list = []
    try:
        srv_obj = mcp_registry.MCPServer.model_validate(server)
    except Exception as exc:
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": f"schema validation failed: {exc}",
            "warnings": [],
        }

    config_dict, env_warnings = mcp_registry.to_mcp_servers_dict([srv_obj])
    if not config_dict:
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": "server is disabled — enable it before testing",
            "warnings": [w.model_dump() for w in env_warnings],
        }

    # Fast-fail check for stdio transport: missing/invalid `command`. The
    # full diagnostic spawn happens only on real-MCP-client failure below.
    if srv_obj.transport == "stdio" and not srv_obj.command:
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": "stdio transport requires a `command`",
            "warnings": [w.model_dump() for w in env_warnings],
        }

    # Fast-fail for stdio when the declared working directory is missing.
    # This is the common "preset not installed yet" case: presets like CVE
    # Intel point `cwd` at /tmp/cve-mcp-server, which the user must git-clone
    # + pip install first. Without this check the spawn raises a bare
    # FileNotFoundError with the path stripped ("No such file or directory"),
    # which a non-expert cannot act on. Catch it here with actionable text.
    if srv_obj.transport == "stdio" and srv_obj.cwd and not os.path.isdir(srv_obj.cwd):
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": (
                f"working directory '{srv_obj.cwd}' does not exist. This MCP "
                f"server needs a one-time setup before it can run — follow the "
                f"preset's setup hint (typically a git clone + pip install into "
                f"that directory), then Test again."
            ),
            "warnings": [w.model_dump() for w in env_warnings],
        }

    def _stdio_diagnostic_stderr() -> Optional[str]:
        """
        Spawn the stdio MCP ourselves and capture stderr if it crashes.
        Used only when the real MCP client failed, to translate the
        SDK's opaque "Connection closed" into the actual reason
        (missing API key, npm package not found, etc.).

        Returns the formatted error string, or None if the process is
        still running after the timeout (in which case it's not an
        immediate-crash failure mode and we should fall back to the
        upstream message).
        """
        if srv_obj.transport != "stdio" or not srv_obj.command:
            return None
        import subprocess
        spawn_env = {**os.environ, **(srv_obj.env or {})}
        try:
            proc = subprocess.Popen(
                [srv_obj.command, *list(srv_obj.args or [])],
                env=spawn_env,
                cwd=srv_obj.cwd or None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            # FileNotFoundError at spawn means EITHER the cwd is missing OR the
            # command binary is missing. Check the cwd first so we don't blame
            # a perfectly-valid command (e.g. `python`) for a missing folder.
            if srv_obj.cwd and not os.path.isdir(srv_obj.cwd):
                return (
                    f"working directory '{srv_obj.cwd}' does not exist — run "
                    f"the preset's setup step (git clone + pip install into "
                    f"that directory) first, then Test again."
                )
            return (
                f"command not found: '{srv_obj.command}'. Is it installed in "
                f"the agent container? (e.g. for npx-based MCPs ensure node, "
                f"for uvx ensure uv)"
            )
        except OSError as exc:
            return f"failed to spawn '{srv_obj.command}': {exc}"
        # Generous timeout: npx/uvx may need to fetch the package on first
        # run before the actual MCP server starts up and immediately
        # crashes on bad config. 25s covers cold cache for typical MCPs.
        try:
            stderr_text = proc.communicate(timeout=25.0)[1] or ""
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
            return None
        # Pick the most informative slice of stderr. Node.js / Python
        # tracebacks print the actual `Error: <message>` line ABOVE the
        # stack trace, so a plain tail loses the message we care about.
        # Strategy: surface any line that looks like an error message,
        # then add the last few lines for context. Cap total length.
        all_lines = [ln for ln in stderr_text.splitlines() if ln.strip()]
        error_pattern = re.compile(
            r"^\s*(?:[A-Z][a-zA-Z]*Error|Exception|Traceback|throw\b|"
            r"FATAL|Cannot find|Missing|Required|environment variable)",
        )
        error_lines = [ln for ln in all_lines if error_pattern.search(ln)]
        # Combine: deduplicated error lines (preserve order) + last 8 lines.
        chosen: list[str] = []
        seen: set[str] = set()
        for ln in error_lines + all_lines[-8:]:
            stripped = ln.strip()
            if stripped and stripped not in seen:
                seen.add(stripped)
                chosen.append(stripped)
        if not chosen:
            chosen_str = "(no stderr output)"
        else:
            joined = " | ".join(chosen)
            chosen_str = joined if len(joined) <= 1500 else joined[:1500] + "…"
        return (
            f"stdio MCP exited (code {proc.returncode}) before/during MCP "
            f"handshake. stderr: {chosen_str}"
        )

    client = None
    try:
        client = MultiServerMCPClient(config_dict)

        # Open an MCP session and call list_tools at the protocol level.
        # This returns mcp.types.Tool objects with their raw inputSchema
        # JSON dict, exactly as the server published it — works with any
        # MCP-spec-compliant server regardless of how langchain happens
        # to wrap things.
        async def _fetch_raw_tools():
            async with client.session(srv_obj.id) as session:
                resp = await session.list_tools()
                return resp.tools

        raw_tools = await asyncio.wait_for(_fetch_raw_tools(), timeout=30.0)

        discovered = []
        declared_names = {t.name for t in srv_obj.tools}
        seen_names = set()
        for mcp_tool in raw_tools:
            name = getattr(mcp_tool, "name", None)
            if not name:
                continue
            seen_names.add(name)
            # inputSchema is a pydantic-modeled dict per the MCP spec.
            # model_dump() flattens it back to the canonical JSON Schema dict.
            schema = getattr(mcp_tool, "inputSchema", None)
            if hasattr(schema, "model_dump"):
                schema = schema.model_dump(exclude_none=True)
            elif not isinstance(schema, dict):
                schema = None
            discovered.append({
                "name": name,
                "description": getattr(mcp_tool, "description", "") or "",
                "input_schema": schema,
            })

        warnings = [w.model_dump() for w in env_warnings]
        for declared_name in declared_names - seen_names:
            warnings.append({
                "server_id": srv_obj.id, "code": "declared_not_live",
                "message": f"Tool '{declared_name}' declared in form but not returned by server.",
            })

        return {
            "ok": True,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": discovered,
            "error": None,
            "warnings": warnings,
        }
    except asyncio.TimeoutError:
        diag = _stdio_diagnostic_stderr()
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": diag or "connection timed out after 30s",
            "warnings": [w.model_dump() for w in env_warnings],
        }
    except BaseExceptionGroup as group:  # noqa: F821 — Python 3.11+
        # langchain_mcp_adapters wraps anyio TaskGroup failures in an
        # ExceptionGroup whose default str() is "unhandled errors in a
        # TaskGroup (1 sub-exception)" — useless. Recursively flatten
        # the leaves so the user sees the real cause (401, DNS error, etc).
        leaves: list[BaseException] = []
        def _flatten(g):
            for sub in g.exceptions:
                if isinstance(sub, BaseExceptionGroup):
                    _flatten(sub)
                else:
                    leaves.append(sub)
        _flatten(group)
        msg = "; ".join(f"{type(e).__name__}: {e}" for e in leaves) or str(group)
        logger.warning(f"/mcp/test ExceptionGroup unwrapped: {msg}")
        # For stdio "Connection closed"-style failures, the SDK swallows
        # the subprocess stderr. Re-spawn ourselves to capture the real
        # reason (missing API key, npm pkg not found, etc.).
        if srv_obj.transport == "stdio" and (
            "Connection closed" in msg or "ClosedResourceError" in msg
            or "BrokenPipe" in msg or "FileNotFoundError" in msg
            or "No such file or directory" in msg
        ):
            diag = _stdio_diagnostic_stderr()
            if diag:
                msg = diag
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": msg,
            "warnings": [w.model_dump() for w in env_warnings],
        }
    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        if srv_obj.transport == "stdio" and (
            "Connection closed" in msg or "ClosedResource" in msg
            or "BrokenPipe" in msg or "FileNotFoundError" in msg
            or "No such file or directory" in msg
        ):
            diag = _stdio_diagnostic_stderr()
            if diag:
                msg = diag
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": msg,
            "warnings": [w.model_dump() for w in env_warnings],
        }
    finally:
        # Drop the throwaway client; rely on GC + peer SSE half-close.
        client = None


@app.get("/defaults", tags=["System"])
async def get_defaults():
    """
    Get default agent settings for frontend project creation.

    Returns DEFAULT_AGENT_SETTINGS keyed by Project column name, from
    AGENT_SETTING_COLUMNS (e.g. OPENAI_MODEL -> agentOpenaiModel, SSRF_GOPHER_ENABLED
    -> ssrfGopherEnabled). Settings with no column are not served.
    """
    from project_settings import AGENT_SETTING_COLUMNS, DEFAULT_AGENT_SETTINGS

    # STEALTH_MODE is a project-level setting (not agent-specific), served by
    # recon defaults as "stealthMode".
    camel_case_defaults = {
        column: DEFAULT_AGENT_SETTINGS[key]
        for key, column in AGENT_SETTING_COLUMNS.items()
        if key != 'STEALTH_MODE'
    }

    # An engagement LIMIT has no global default: it belongs to one engagement,
    # not to the installation. It matters more than tidiness, because the
    # ProjectForm's preset-apply path resets every form field that appears in
    # this payload BEFORE applying the preset, so a limit here would zero a
    # configured rate ceiling and empty an exclusion list on every preset apply.
    #
    # Filtered by COLUMN, after the naming, because the six limits the agent
    # enforces alone are keyed on their column name rather than on a recon
    # runtime key the registry would know. One helper, shared with the
    # orchestrator's /defaults.
    from recon_settings.engagement import strip_engagement_limits

    strip_engagement_limits(camel_case_defaults)

    return camel_case_defaults


class ModelsRequest(BaseModel):
    providers: list[dict] | None = None


@app.post("/models", tags=["System"], dependencies=[Depends(require_internal_auth)])
async def get_models(body: ModelsRequest | None = None):
    """
    Fetch available AI models from all configured providers.

    Providers (a list of UserLlmProvider rows) are passed in the POST body
    rather than the URL to keep apiKey values out of uvicorn access logs.
    Falls back to env vars when the body is empty.
    """
    from orchestrator_helpers.model_providers import fetch_all_models

    provider_list = body.providers if body else None
    return await fetch_all_models(providers=provider_list)


# =============================================================================
# SKILLS — Infosec-skills-compatible skill catalog endpoint
# =============================================================================

@app.get("/skills", tags=["System"])
async def list_skills():
    """
    Return the catalog of all available Infosec-skills-compatible skills.

    Each entry contains: id, name, description, category.
    The frontend uses this to populate the skill selector in Project Settings.
    """
    from orchestrator_helpers.skill_loader import list_skills as _list_skills
    skills = _list_skills()
    return {"skills": skills, "total": len(skills)}


@app.get("/skills/{skill_id:path}", tags=["System"])
async def get_skill_content(skill_id: str):
    """Return full content of a specific skill."""
    from orchestrator_helpers.skill_loader import load_skill_content, list_skills as _list_skills
    content = load_skill_content(skill_id)
    if content is None:
        return JSONResponse({"error": f"Skill not found: {skill_id}"}, status_code=404)
    # Find metadata
    skills = _list_skills()
    meta = next((s for s in skills if s['id'] == skill_id), {})
    return {"id": skill_id, "name": meta.get("name", skill_id), "description": meta.get("description", ""), "category": meta.get("category", "general"), "content": content}


@app.get("/community-skills", tags=["System"])
async def list_community_skills():
    """Return catalog of community Agent Skills from agentic/community-skills/."""
    from pathlib import Path
    skills_dir = Path(__file__).parent / "community-skills"
    skills = []
    if skills_dir.exists():
        for md_file in sorted(skills_dir.glob("*.md")):
            if md_file.name == "README.md":
                continue
            content = md_file.read_text(encoding="utf-8")
            name = md_file.stem.replace("_", " ").title()
            desc = ""
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    desc = stripped[:200]
                    break
            skills.append({
                "id": md_file.stem,
                "name": name,
                "description": desc,
                "file": str(md_file),
            })
    return {"skills": skills, "total": len(skills)}


@app.get("/community-skills/{skill_id}", tags=["System"])
async def get_community_skill_content(skill_id: str):
    """Return full content of a specific community Agent Skill."""
    from pathlib import Path
    skills_dir = Path(__file__).parent / "community-skills"
    skill_path = skills_dir / f"{skill_id}.md"
    if not skill_path.exists():
        return JSONResponse({"error": f"Community skill not found: {skill_id}"}, status_code=404)
    content = skill_path.read_text(encoding="utf-8")
    name = skill_id.replace("_", " ").title()
    return {"id": skill_id, "name": name, "content": content}


# =============================================================================
# LLM PROVIDER TEST — test a provider config with a simple message
# =============================================================================

class LlmProviderTestRequest(BaseModel):
    """Request model for testing an LLM provider config."""
    providerType: str = "openai_compatible"
    apiKey: str = ""
    baseUrl: str = ""
    modelIdentifier: str = ""
    defaultHeaders: dict = {}
    timeout: int = 120
    temperature: float = 0
    maxTokens: int = 16384
    sslVerify: bool = True
    reasoningEnabled: bool = False
    reasoningEffort: Literal["low", "medium", "high", "max"] = "high"
    awsRegion: str = "us-east-1"
    awsAccessKeyId: str = ""
    awsSecretKey: str = ""
    awsBearerToken: str = ""
    testMode: Literal["key", "capability"] = "key"


_JEV_TEST_ERRORS = {
    "jev_auth": "TypeSafe rejected the key",
    "jev_no_credit": "No TypeSafe credit",
}


@app.post("/llm-provider/test", tags=["System"], dependencies=[Depends(require_internal_auth)])
async def test_llm_provider(body: LlmProviderTestRequest):
    """Test an LLM provider config by sending a simple message."""
    from orchestrator_helpers.llm_setup import setup_llm

    try:
        ptype = body.providerType

        if ptype == "openai":
            llm = setup_llm("gpt-4o-mini", openai_api_key=body.apiKey)
        elif ptype == "anthropic":
            # Connection check uses a current, valid alias (no date suffix).
            # Dated snapshots like claude-sonnet-4-20250514 are deprecated and 404
            # once retired. claude-opus-4-6 still accepts the temperature param.
            llm = setup_llm("claude-opus-4-6", anthropic_api_key=body.apiKey)
        elif ptype == "openrouter":
            llm = setup_llm("openrouter/openai/gpt-4o-mini", openrouter_api_key=body.apiKey)
        elif ptype == "deepseek":
            # Discover models instead of hardcoding an alias — DeepSeek retired
            # deepseek-chat/deepseek-reasoner in favour of deepseek-v4-*.
            from orchestrator_helpers.model_providers import fetch_deepseek_models
            available = await fetch_deepseek_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No DeepSeek models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "flash" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], deepseek_api_key=body.apiKey)
        elif ptype == "gemini":
            from orchestrator_helpers.model_providers import fetch_gemini_models
            available = await fetch_gemini_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Gemini models available for this API key"},
                    status_code=400,
                )
            flash = next((m for m in available if "flash" in m["id"].lower()), available[0])
            llm = setup_llm(flash["id"], gemini_api_key=body.apiKey)
        elif ptype == "glm":
            from orchestrator_helpers.model_providers import fetch_glm_models
            available = await fetch_glm_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No GLM models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "flash" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], glm_api_key=body.apiKey)
        elif ptype == "kimi":
            from orchestrator_helpers.model_providers import fetch_kimi_models
            available = await fetch_kimi_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Kimi models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "8k" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], kimi_api_key=body.apiKey)
        elif ptype == "qwen":
            from orchestrator_helpers.model_providers import fetch_qwen_models
            available = await fetch_qwen_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Qwen models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "turbo" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], qwen_api_key=body.apiKey)
        elif ptype == "xai":
            from orchestrator_helpers.model_providers import fetch_xai_models
            available = await fetch_xai_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No xAI models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "mini" in m["id"].lower() or "fast" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], xai_api_key=body.apiKey)
        elif ptype == "mistral":
            from orchestrator_helpers.model_providers import fetch_mistral_models
            available = await fetch_mistral_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Mistral models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "small" in m["id"].lower() or "nemo" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], mistral_api_key=body.apiKey)
        elif ptype == "bedrock":
            from orchestrator_helpers.model_providers import fetch_bedrock_models
            available = await fetch_bedrock_models(
                region=body.awsRegion,
                access_key_id=body.awsAccessKeyId,
                secret_access_key=body.awsSecretKey,
                bearer_token=body.awsBearerToken,
            )
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Bedrock models available — check region, credentials, and Model Access in the Bedrock console."},
                    status_code=400,
                )
            # Prefer a small Haiku/Nova model for the smoke test if present;
            # otherwise fall back to the first listed model.
            pick = next(
                (m for m in available if "haiku" in m["id"].lower() or "nova-micro" in m["id"].lower()),
                available[0],
            )
            llm = setup_llm(
                pick["id"],
                aws_access_key_id=body.awsAccessKeyId,
                aws_secret_access_key=body.awsSecretKey,
                aws_bearer_token=body.awsBearerToken,
                aws_region=body.awsRegion,
            )
        elif ptype == "openai_compatible":
            from orchestrator_helpers.llm_url_guard import (
                BaseUrlValidationError,
                validate_llm_base_url,
            )
            # SSRF guard (I15) + TLS-off-on-public guard (I16). Rejected before
            # any live request is issued, so the test endpoint can't be abused
            # to probe internal services or cloud metadata.
            try:
                validate_llm_base_url(body.baseUrl, ssl_verify=body.sslVerify)
            except BaseUrlValidationError as e:
                return JSONResponse(
                    content={"success": False, "error": str(e)},
                    status_code=400,
                )
            # Exercise the same construction path used by real agent sessions,
            # including SSE and Ollama reasoning controls.
            llm = setup_llm(
                "custom/provider-test",
                custom_llm_config=body.model_dump(),
            )
        elif ptype in {"jev", "jev_openrouter"}:
            import jev_client
            try:
                provider = jev_client.JevProvider(ptype, body.apiKey)
                return await jev_client.test_provider(
                    provider, capability=body.testMode == "capability")
            except jev_client.JevError as e:
                error = _JEV_TEST_ERRORS.get(e.error_type, e.message) if ptype == "jev" else e.message
                return JSONResponse(
                    content={"success": False, "error": error}, status_code=400,
                )
        else:
            return JSONResponse(
                content={"success": False, "error": f"Unknown provider type: {ptype}"},
                status_code=400,
            )

        from orchestrator_helpers.llm_retry import retry_llm_call
        # Same self-heal as the agent loop: a model that rejects `temperature` or
        # `reasoning_effort` is retried once without it instead of failing the test.
        response = await retry_llm_call(
            llm, [HumanMessage(content="Say hello in one sentence.")],
            label="provider-test", max_attempts=1,
        )
        from orchestrator_helpers import normalize_content
        text = normalize_content(response.content).strip()

        return {"success": True, "response_text": text}

    except Exception as e:
        # I5: log the detail server-side ONLY. The raw SDK/httpx error string can
        # embed the Authorization header / API key; returning it to the settings
        # UI would leak key material. Respond with a generic message instead.
        logger.error(f"LLM provider test failed: {e}")
        return JSONResponse(
            content={"success": False, "error": "Provider test failed. Check the key, model, and base URL; see server logs for detail."},
            status_code=400,
        )


@app.get("/files", tags=["Files"], dependencies=[Depends(require_internal_auth_only)])
async def download_file(
    path: str = Query(..., description="File path inside kali-sandbox (must be under /tmp/)"),
):
    """
    Download a file from kali-sandbox via the kali_shell MCP tool.

    Reads the file using base64 encoding through the existing MCP tool,
    decodes it, and returns the binary content.
    Security: Only paths under /tmp/ are allowed.
    """
    # Security: restrict to /tmp/ paths and prevent directory traversal
    if not path.startswith("/tmp/"):
        return Response(content="Forbidden: only /tmp/ paths allowed", status_code=403)
    normalized = os.path.normpath(path)
    if not normalized.startswith("/tmp/"):
        return Response(content="Forbidden: path traversal detected", status_code=403)

    # The file is read INSIDE kali-sandbox via kali_shell, which runs the command
    # through `bash -c`, so `normalized` is interpolated into a shell string.
    # `os.path.normpath` collapses `.`/`..`/`//` but does NOT strip shell
    # metacharacters (`;`, `|`, `` ` ``, `$(...)`), so a path like `/tmp/x; id`
    # would inject a second command. Quote it so it is always a single literal
    # argument. This is the actual injection fix; the `/tmp/` prefix check above
    # is not sufficient on its own.
    safe_path = shlex.quote(normalized)

    if not orchestrator or not orchestrator.tool_executor:
        return Response(content="Agent not initialized", status_code=503)

    try:
        # Check file exists first
        check_result = await orchestrator.tool_executor.execute(
            "kali_shell",
            {"command": f"test -f {safe_path} && stat -c '%s' {safe_path}"},
            "informational",
            skip_phase_check=True,
        )
        if not check_result.get("success") or not check_result.get("output", "").strip():
            return Response(content="File not found", status_code=404)

        # Read file as base64
        b64_result = await orchestrator.tool_executor.execute(
            "kali_shell",
            {"command": f"base64 -w0 {safe_path}"},
            "informational",
            skip_phase_check=True,
        )
        if not b64_result.get("success"):
            return Response(
                content=f"Error reading file: {b64_result.get('error', 'unknown')}",
                status_code=500,
            )

        b64_str = (b64_result.get("output") or "").strip()
        file_bytes = base64.b64decode(b64_str)
        filename = os.path.basename(normalized)

        # Content type mapping for common payload/document types
        ext = os.path.splitext(filename)[1].lower()
        content_types = {
            ".exe": "application/x-msdownload",
            ".elf": "application/x-elf",
            ".pdf": "application/pdf",
            ".docm": "application/vnd.ms-word.document.macroEnabled.12",
            ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
            ".apk": "application/vnd.android.package-archive",
            ".war": "application/x-webarchive",
            ".ps1": "text/plain",
            ".py": "text/plain",
            ".sh": "text/plain",
            ".hta": "text/html",
            ".lnk": "application/x-ms-shortcut",
            ".rtf": "application/rtf",
            ".vba": "text/plain",
            ".macho": "application/x-mach-binary",
        }
        content_type = content_types.get(ext, "application/octet-stream")

        return Response(
            content=file_bytes,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(file_bytes)),
            },
        )
    except Exception as e:
        logger.error(f"File download error: {e}")
        return Response(content=f"Error reading file: {str(e)}", status_code=500)


# =============================================================================
# WORKSPACE - per-project filesystem + background-job HTTP endpoints
# =============================================================================
# All routes are project-scoped (projectId is required) and use the same
# _resolve_safe validator as the fs_* tools, so path traversal and symlink
# escape attempts are rejected at the boundary. The webapp drawer + AI panel
# both consume these. The projectId is NOT an authorization: the webapp proxy
# checks the caller owns the project, then calls with the master key, which is
# all that stands between the 0.0.0.0-published agent port and every tenant's files.


@app.get("/workspace/list", tags=["Workspace"],
         dependencies=[Depends(require_configured_master_auth)])
async def workspace_list(
    projectId: str = Query(..., description="Project UUID"),
    path: str = Query(".", description="Subdir relative to /workspace/<projectId>/"),
    limit: int = Query(2000, ge=1, le=10000, description="Entries returned at most"),
):
    """Directory listing as structured JSON for the drawer Files tab.

    Capped: the drawer polls this every 5 s and an imported folder can hold
    tens of thousands of entries. `total` and `truncated` say what was left out.
    """
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        entries, total = workspace_fs.list_dir_page(projectId, path, limit)
        return {"projectId": projectId, "path": path, "entries": entries,
                "total": total, "truncated": total > len(entries)}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/list failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/workspace/tree", tags=["Workspace"],
         dependencies=[Depends(require_configured_master_auth)])
async def workspace_tree(
    projectId: str = Query(...),
    path: str = Query("."),
    maxDepth: int = Query(3, ge=1, le=10),
    maxEntries: int = Query(500, ge=10, le=5000),
):
    """ASCII tree view of a workspace subtree."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        return {"projectId": projectId, "path": path,
                "tree": workspace_fs.tree_for_project(projectId, path, maxDepth, maxEntries)}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/tree failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/workspace/download", tags=["Workspace"],
         dependencies=[Depends(require_configured_master_auth)])
async def workspace_download(
    projectId: str = Query(...),
    path: str = Query(...),
):
    """Stream file bytes directly from the bind-mount (no kali_shell round-trip).

    Streams the descriptor that was checked (open_download_for_project), never
    a path reopened later, and always as an attachment with nosniff.
    """
    if not projectId:
        return Response(content="projectId required", status_code=400)
    try:
        fd, size, mime, filename = workspace_fs.open_download_for_project(projectId, path)
    except ValueError as e:
        return Response(content=str(e), status_code=400)
    except Exception as e:
        logger.error(f"/workspace/download failed: {e}")
        return Response(content=str(e), status_code=500)
    return _ws_downloads.stream_fd(fd, size, mime, filename)


class WorkspaceRenameRequest(BaseModel):
    projectId: str
    path: str
    newName: str


@app.post("/workspace/rename", tags=["Workspace"],
          dependencies=[Depends(require_configured_master_auth)])
async def workspace_rename(req: WorkspaceRenameRequest):
    """Rename a single entry within its parent (no cross-dir moves)."""
    if not req.projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        new_path = workspace_fs.rename_for_project(req.projectId, req.path, req.newName)
        return {"projectId": req.projectId, "path": new_path}
    except ImportFailure as e:
        return JSONResponse(content=error_body(e.code, jobId=e.detail), status_code=e.status)
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/rename failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.delete("/workspace", tags=["Workspace"],
            dependencies=[Depends(require_configured_master_auth)])
async def workspace_delete(
    projectId: str = Query(...),
    path: str = Query(...),
    recursive: bool = Query(False),
):
    """Delete a file or directory (recursive required for dirs)."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        workspace_fs.delete_for_project(projectId, path, recursive)
        return {"projectId": projectId, "path": path, "deleted": True}
    except ImportFailure as e:
        return JSONResponse(content=error_body(e.code, jobId=e.detail), status_code=e.status)
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/delete failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


class WorkspaceResetRequest(BaseModel):
    projectId: str


@app.post("/workspace/reset", tags=["Workspace"],
          dependencies=[Depends(require_configured_master_auth)])
async def workspace_reset(req: WorkspaceResetRequest):
    """Wipe the workspace back to its initial state (4 empty default folders)."""
    if not req.projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        workspace_fs._validate_project_id(req.projectId)
        await reset_project_imports(req.projectId)
        summary = workspace_fs.reset_for_project(req.projectId)
        return {"projectId": req.projectId, **summary}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/reset failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/workspace/jobs", tags=["Workspace"],
         dependencies=[Depends(require_configured_master_auth)])
async def workspace_jobs_list(
    projectId: str = Query(...),
    active: Optional[bool] = Query(None, description="True=running only, False=terminal only, omit for all"),
):
    """List background jobs for the drawer Jobs tab."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    reg = job_runner.get_registry()
    return {"projectId": projectId, "jobs": reg.list(projectId, active=active)}


@app.post("/workspace/jobs/{job_id}/cancel", tags=["Workspace"],
          dependencies=[Depends(require_configured_master_auth)])
async def workspace_job_cancel(
    job_id: str,
    projectId: str = Query(...),
):
    """Cancel a running background job."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    reg = job_runner.get_registry()
    result = await reg.cancel(projectId, job_id)
    return result


@app.post("/workspace/upload", tags=["Workspace"],
          dependencies=[Depends(require_configured_master_auth)])
async def workspace_upload(
    projectId: str = Form(...),
    path: str = Form("."),
    overwrite: bool = Form(False),
    file: UploadFile = File(...),
):
    """Multipart file upload into a workspace directory.

    409 (`code: exists`) on name collision when `overwrite=False` so the
    frontend can prompt for confirmation, then retry with `overwrite=true`.
    """
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        file_bytes = await file.read()
        new_path = workspace_fs.upload_for_project(
            projectId, path, file_bytes, file.filename or "uploaded", overwrite=overwrite,
        )
        return {"projectId": projectId, "path": new_path, "size": len(file_bytes)}
    except ImportFailure as e:
        return JSONResponse(content=error_body(e.code, jobId=e.detail), status_code=e.status)
    except FileExistsError as e:
        return JSONResponse(
            content={"error": str(e), "code": "exists"}, status_code=409,
        )
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/upload failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


class WorkspaceMkdirRequest(BaseModel):
    projectId: str
    path: str


@app.post("/workspace/mkdir", tags=["Workspace"],
          dependencies=[Depends(require_configured_master_auth)])
async def workspace_mkdir(req: WorkspaceMkdirRequest):
    """Create a new directory (parents created automatically)."""
    if not req.projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        new_path = workspace_fs.mkdir_for_project(req.projectId, req.path)
        return {"projectId": req.projectId, "path": new_path}
    except ImportFailure as e:
        return JSONResponse(content=error_body(e.code, jobId=e.detail), status_code=e.status)
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/mkdir failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


class WorkspaceBulkArchiveRequest(BaseModel):
    projectId: str
    paths: list[str]
    format: str = "tar.gz"
    archiveName: str = "bundle"


@app.post("/workspace/bulk-archive", tags=["Workspace"],
          dependencies=[Depends(require_configured_master_auth)])
async def workspace_bulk_archive(req: WorkspaceBulkArchiveRequest):
    """Bundle N workspace entries into one tar.gz/zip; stream back to client.

    POST (not GET) because the list of paths can be long and we want a JSON
    body for clarity over a megalong query string.
    """
    if not req.projectId:
        return Response(content="projectId required", status_code=400)
    try:
        resolved, filename = workspace_fs.prepare_bulk_archive(
            req.projectId, req.paths, req.format, req.archiveName,
        )
    except ValueError as e:
        return Response(content=str(e), status_code=400)
    except Exception as e:
        logger.error(f"/workspace/bulk-archive failed: {e}")
        return Response(content=str(e), status_code=500)
    return await _ws_downloads.archive_response(
        req.projectId, resolved,
        lambda f: workspace_fs.write_bulk_archive(f, resolved, req.format),
        filename, req.format,
    )


@app.get("/workspace/archive-download", tags=["Workspace"],
         dependencies=[Depends(require_configured_master_auth)])
async def workspace_archive_download(
    projectId: str = Query(...),
    path: str = Query(...),
    format: str = Query("tar.gz"),
):
    """Stream a directory as a tar.gz or zip archive."""
    if not projectId:
        return Response(content="projectId required", status_code=400)
    try:
        src, name, filename = workspace_fs.prepare_dir_archive(projectId, path, format)
    except ValueError as e:
        return Response(content=str(e), status_code=400)
    except Exception as e:
        logger.error(f"/workspace/archive-download failed: {e}")
        return Response(content=str(e), status_code=500)
    return await _ws_downloads.archive_response(
        projectId, [src],
        lambda f: workspace_fs.write_dir_archive(f, src, name, format),
        filename, format,
    )


@app.get("/workspace/preview", tags=["Workspace"],
         dependencies=[Depends(require_configured_master_auth)])
async def workspace_preview(
    projectId: str = Query(...),
    path: str = Query(...),
    maxBytes: int = Query(1024 * 1024, ge=1, le=10 * 1024 * 1024),
):
    """File preview for the inline viewer pane (text or base64 binary)."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        return workspace_fs.preview_for_project(projectId, path, max_bytes=maxBytes)
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/preview failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/workspace/properties", tags=["Workspace"],
         dependencies=[Depends(require_configured_master_auth)])
async def workspace_properties(
    projectId: str = Query(...),
    path: str = Query(...),
):
    """Rich metadata for the properties popover (size, mtime, mode, sha256)."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        return workspace_fs.properties_for_project(projectId, path)
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/properties failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


# =============================================================================
# COMMAND WHISPERER - NLP-to-command translation using the project's LLM
# =============================================================================

_COMMAND_WHISPERER_SYSTEM_PROMPT = """You are a command-line expert for penetration testing.
The user has an active {session_type} session and needs a command.

Session type details:
- "meterpreter": Meterpreter commands (hashdump, getsystem, upload, download, sysinfo, getuid, ps, migrate, search, cat, ls, portfwd, route, load, etc.)
- "shell": Standard Linux/Unix shell commands (find, grep, cat, ls, whoami, id, uname, ifconfig, netstat, awk, sed, curl, wget, chmod, python, perl, etc.)

Rules:
1. Output ONLY the command — no explanations, no markdown, no commentary
2. Single command (use && or ; to chain if needed)
3. No sudo unless explicitly requested
4. Prefer concise, commonly-used flags
5. If ambiguous, pick the most likely interpretation"""


class CommandWhispererRequest(BaseModel):
    prompt: str
    session_type: str
    project_id: str
    # Set by the webapp from the caller's saved "Command whisperer" model and
    # effective user. The agent's own LLM belongs to whichever project loaded
    # last, so it is never used here.
    user_id: str | None = None
    model: str | None = None


@app.post("/command-whisperer", tags=["Sessions"],
          dependencies=[Depends(require_master_internal_auth), Depends(require_internal_auth)])
async def command_whisperer(body: CommandWhispererRequest):
    """Translate a natural language request into a shell command with the caller's model."""
    requested_model = (body.model or "").strip()
    missing = _feature_request_error(requested_model, body.user_id)
    if missing:
        return missing
    llm, failure = await _build_feature_llm("Command whisperer", requested_model, body.user_id)
    if failure:
        return failure

    system_prompt = _COMMAND_WHISPERER_SYSTEM_PROMPT.format(session_type=body.session_type)
    response, failure = await _invoke_feature_llm("Command whisperer", requested_model, llm, [
        SystemMessage(content=system_prompt),
        HumanMessage(content=body.prompt),
    ])
    if failure:
        return failure

    command = normalize_content(response.content).strip()

    # Strip markdown code fences if the LLM wraps the answer
    if command.startswith("```") and command.endswith("```"):
        command = command[3:-3].strip()
    if command.startswith(("bash\n", "sh\n", "shell\n")):
        command = command.split("\n", 1)[1].strip()

    return {"command": command, "model_used": requested_model}


# =============================================================================
# SKILL METADATA - the upload dialog's "Generate with AI" for user attack skills
# =============================================================================

import skill_metadata  # noqa: E402


class SkillMetadataItem(BaseModel):
    key: str
    content: str
    file_name: str = ""
    # The current name, as context when only the description is asked.
    name: str = ""
    want_name: bool = False
    want_description: bool = False


class SkillMetadataRequest(BaseModel):
    items: list[SkillMetadataItem]
    other_names: list[str] = []
    # Set by the webapp from the caller's saved "Skill names & descriptions"
    # model and effective user, like every feature endpoint.
    model: Optional[str] = None
    user_id: Optional[str] = None


def _skill_metadata_size_error(body: SkillMetadataRequest, model: str) -> Optional[JSONResponse]:
    def refuse(error: str) -> JSONResponse:
        return JSONResponse(content={"error": error, "model_used": model}, status_code=400)

    if not 1 <= len(body.items) <= skill_metadata.MAX_ITEMS:
        return refuse(f"Send 1 to {skill_metadata.MAX_ITEMS} skills")
    for item in body.items:
        if not item.content.strip() or len(item.content) > skill_metadata.CONTENT_MAX_CHARS:
            return refuse(f"Each skill needs a text of at most {skill_metadata.CONTENT_MAX_CHARS // 1024} KB")
        if not (item.want_name or item.want_description):
            return refuse("Each skill must ask for a name or a description")
        if len(item.key) > 64:
            return refuse("A skill key is at most 64 characters")
    if len(body.other_names) > skill_metadata.OTHER_NAMES_MAX:
        return refuse(f"At most {skill_metadata.OTHER_NAMES_MAX} other names")
    return None


@app.post("/skill-metadata/generate", tags=["Skills"],
          dependencies=[Depends(require_master_internal_auth), Depends(require_internal_auth)])
async def generate_skill_metadata(body: SkillMetadataRequest):
    """Propose the missing name and/or description of up to 5 uploaded skills, on the caller's model.

    Nothing is saved: the webapp re-validates the answer and the person reviews it.
    """
    started = time.monotonic()
    model = (body.model or "").strip()
    missing = _feature_request_error(model, body.user_id)
    if missing:
        return missing
    too_big = _skill_metadata_size_error(body, model)
    if too_big:
        return too_big
    llm, failure = await _build_feature_llm("Skill metadata", model, body.user_id)
    if failure:
        return failure

    other_names = [n[:skill_metadata.NAME_MAX] for n in body.other_names]
    gate = asyncio.Semaphore(skill_metadata.CONCURRENCY)
    unavailable: list[JSONResponse] = []
    call_failures: list[JSONResponse] = []

    async def one(item: SkillMetadataItem) -> dict:
        async with gate:
            messages = skill_metadata.build_messages(item, other_names)
            try:
                response, failed = await asyncio.wait_for(
                    _invoke_feature_llm("Skill metadata", model, llm, messages),
                    skill_metadata.ITEM_TIMEOUT_S)
            except asyncio.TimeoutError:
                return {"key": item.key, "error": "timeout"}
        if failed:
            if failed.status_code == 503:
                unavailable.append(failed)
            else:
                call_failures.append(failed)
            return {"key": item.key, "error": "model_call_failed"}
        answer = skill_metadata.parse_answer(
            normalize_content(response.content), item.want_name, item.want_description)
        return {"key": item.key, **answer} if answer else {"key": item.key, "error": "unreadable_answer"}

    try:
        items = await asyncio.wait_for(asyncio.gather(*(one(i) for i in body.items)),
                                       skill_metadata.REQUEST_TIMEOUT_S)
    except asyncio.TimeoutError:
        # Still one line per request: it is the operator's only record of a Generate call.
        logger.info("skill_metadata user=%s model=%s items=%d ok=0 failed=%d ms=%d timeout",
                    body.user_id, model, len(body.items), len(body.items),
                    int((time.monotonic() - started) * 1000))
        return _feature_error("agent_timeout", model, 504, "The model took too long, try again")

    failed = sum(1 for i in items if "error" in i)
    # Counts only: a skill file, its name or the generated text can hold anything.
    logger.info("skill_metadata user=%s model=%s items=%d ok=%d failed=%d ms=%d",
                body.user_id, model, len(items), len(items) - failed, failed,
                int((time.monotonic() - started) * 1000))
    if unavailable:
        return unavailable[0]
    if call_failures and len(call_failures) == len(items):
        return call_failures[0]
    return {"items": items, "model_used": model}


# =============================================================================
# SESSION MANAGEMENT PROXY — proxies to kali-sandbox:8013 session endpoints
# =============================================================================

# Derive base URL from existing progress URL (already in docker-compose)
_SESSION_BASE = os.environ.get(
    "MCP_METASPLOIT_PROGRESS_URL", "http://kali-sandbox:8013/progress"
).rsplit("/progress", 1)[0]


@app.get("/tunnel-status", tags=["System"])
async def get_tunnel_status():
    """Return live status of ngrok and chisel tunnels."""
    from utils import _query_ngrok_tunnel, _query_chisel_tunnel

    # Always try to query both — they return None gracefully if not running
    ngrok_info = _query_ngrok_tunnel()
    chisel_info = _query_chisel_tunnel()

    return {
        "ngrok": {"active": True, "host": ngrok_info["host"], "port": ngrok_info["port"]} if ngrok_info else {"active": False},
        "chisel": {"active": True, "host": chisel_info["host"], "port": chisel_info["port"], "srvPort": chisel_info["srv_port"]} if chisel_info else {"active": False},
    }


@app.get("/sessions", tags=["Sessions"],
         dependencies=[Depends(require_configured_master_auth)])
async def get_sessions():
    """List all active Metasploit sessions, background jobs, and non-MSF sessions."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{_SESSION_BASE}/sessions")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except httpx.TimeoutException:
        return JSONResponse(content={"error": "Session manager timeout"}, status_code=504)
    except Exception as e:
        logger.error(f"Session proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/sessions/{session_id}/interact", tags=["Sessions"],
          dependencies=[Depends(require_configured_master_auth)])
async def interact_session(session_id: int, body: dict):
    """Send a command to a specific Metasploit session."""
    try:
        async with httpx.AsyncClient(timeout=40.0) as client:
            resp = await client.post(
                f"{_SESSION_BASE}/sessions/{session_id}/interact", json=body
            )
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except httpx.TimeoutException:
        return JSONResponse(content={"error": "Session interaction timeout"}, status_code=504)
    except Exception as e:
        logger.error(f"Session interact proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/sessions/{session_id}/kill", tags=["Sessions"],
          dependencies=[Depends(require_configured_master_auth)])
async def kill_session(session_id: int):
    """Kill a specific Metasploit session."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/sessions/{session_id}/kill")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Session kill proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/jobs/{job_id}/kill", tags=["Sessions"],
          dependencies=[Depends(require_configured_master_auth)])
async def kill_job(job_id: int):
    """Kill a background Metasploit job."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/jobs/{job_id}/kill")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Job kill proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/session-chat-map", tags=["Sessions"],
          dependencies=[Depends(require_configured_master_auth)])
async def session_chat_map(body: dict):
    """Register a mapping between a Metasploit session ID and agent chat session ID."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/session-chat-map", json=body)
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Session chat map proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/non-msf-sessions", tags=["Sessions"],
          dependencies=[Depends(require_configured_master_auth)])
async def register_non_msf_session(body: dict):
    """Register a non-Metasploit session (netcat, socat, etc.)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/non-msf-sessions", json=body)
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Non-MSF session register proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


# =============================================================================
# TEXT-TO-CYPHER — Generate Cypher from natural language using existing prompt
# =============================================================================

class TextToCypherRequest(BaseModel):
    """Request model for text-to-cypher conversion."""
    question: str
    user_id: str
    project_id: str
    # Default True for backward compatibility with the webapp graph view, which
    # needs whole nodes/relationships to render. CLI callers (e.g. redagraph)
    # should send False so the LLM is free to return scalar properties.
    for_graph_view: bool = True


# --- shared NL -> Cypher plumbing --------------------------------------------
#
# Two endpoints need the same three steps (resolve the caller's LLM, build a
# Neo4jToolManager, generate and validate Cypher): the graph-view generator
# (/text-to-cypher, which returns the query for the webapp to save) and the MCP
# entry point (/graph/nl-query, which also runs it and returns rows). They are
# factored here so the tenant scoping and the retry policy cannot drift apart.


LOOP_OUT_OF_SESSION_CYPHER = (
    "This project's agent model is Agent in the Loop, which answers only inside a "
    "chat. Natural-language graph queries need a provider model; raw Cypher still works."
)


class _CypherSetupError(Exception):
    """Carries the (status, safe message) to answer with, plus safe extra fields
    (a code, the provider's class and HTTP status) for the body."""

    def __init__(self, status: int, message: str, fields: Optional[dict] = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.fields = dict(fields or {})


def _cypher_model_error(exc: BaseException) -> _CypherSetupError:
    """A failed model call while generating Cypher.

    Not a bad query: retrying it with the "previous error" fed back would bill
    the same refused key or exhausted quota three more times and then tell the
    person to rephrase their question.
    """
    log_provider_error("text-to-cypher", "", exc)
    details = provider_error_details(exc)
    if is_model_unavailable_error(exc):
        return _CypherSetupError(
            503,
            "The AI model could not be used. Check the project's AI model and its API key.",
            {"code": "model_unavailable", **details},
        )
    return _CypherSetupError(
        502, "The AI model call failed. Try again in a moment.",
        {"code": "model_call_failed", **details},
    )


async def _build_cypher_manager(user_id: str, project_id: str):
    """Resolve the project's model + the user's provider key into a manager.

    The identity is the CALLER's responsibility: both entry points are guarded
    by require_internal_auth, and the webapp resolves the real user before
    calling. Raises _CypherSetupError with a safe message.
    """
    from tools import Neo4jToolManager
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from project_settings import DEFAULT_AGENT_SETTINGS, fetch_agent_settings
    import requests as _requests

    model_name = DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
    try:
        webapp_url = os.environ.get('WEBAPP_API_URL', 'http://webapp:3000')
        settings = fetch_agent_settings(project_id, webapp_url, include_skill_overrides=False)
        if settings and settings.get('OPENAI_MODEL'):
            model_name = settings['OPENAI_MODEL']
    except Exception as e:
        logger.warning(f"text-to-cypher: failed to fetch project settings: {e}")
    if is_loop_model(model_name):
        # No chat run, so no driver can answer the generation step.
        raise _CypherSetupError(409, LOOP_OUT_OF_SESSION_CYPHER,
                                {"code": "loop_model_out_of_session"})

    user_providers = []
    try:
        webapp_url = os.environ.get('WEBAPP_API_URL', 'http://webapp:3000')
        resp = _requests.get(
            f"{webapp_url.rstrip('/')}/api/users/{user_id}/llm-providers?internal=true",
            headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
            timeout=10,
        )
        resp.raise_for_status()
        user_providers = resp.json()
    except Exception as e:
        logger.warning(f"text-to-cypher: failed to fetch user LLM providers: {e}")

    llm = None
    try:
        if model_name.startswith("custom/"):
            from llm_builder import custom_provider_or_fallback
            matched = custom_provider_or_fallback(user_providers, model_name)
            if not matched:
                raise _CypherSetupError(
                    400, "Custom LLM provider not found. Configure an AI model in settings."
                )
            llm = setup_llm(model_name, custom_llm_config=matched)
        else:
            def key(kind):
                return (_resolve_provider_key(user_providers, kind) or {})

            bedrock = key("bedrock")
            llm = setup_llm(
                model_name,
                openai_api_key=key("openai").get("apiKey"),
                anthropic_api_key=key("anthropic").get("apiKey"),
                openrouter_api_key=key("openrouter").get("apiKey"),
                deepseek_api_key=key("deepseek").get("apiKey"),
                gemini_api_key=key("gemini").get("apiKey"),
                glm_api_key=key("glm").get("apiKey"),
                kimi_api_key=key("kimi").get("apiKey"),
                qwen_api_key=key("qwen").get("apiKey"),
                xai_api_key=key("xai").get("apiKey"),
                mistral_api_key=key("mistral").get("apiKey"),
                aws_access_key_id=bedrock.get("awsAccessKeyId"),
                aws_secret_access_key=bedrock.get("awsSecretKey"),
                aws_bearer_token=bedrock.get("awsBearerToken"),
                aws_region=bedrock.get("awsRegion") or "us-east-1",
            )
    except _CypherSetupError:
        raise
    except Exception as e:
        logger.error(f"text-to-cypher: failed to create LLM: {e}")
        raise _CypherSetupError(
            400, "Failed to initialize the LLM. Make sure an AI model is configured."
        )

    if not llm:
        raise _CypherSetupError(
            400,
            "No LLM configured. Configure an AI model in project settings to use graph views.",
        )

    neo4j_uri = os.environ.get('NEO4J_URI', 'bolt://neo4j:7687')
    manager = Neo4jToolManager(
        neo4j_uri,
        os.environ.get('NEO4J_USER', 'neo4j'),
        os.environ.get('NEO4J_PASSWORD', 'password'),
        llm,
    )
    try:
        from langchain_community.graphs import Neo4jGraph
        manager.graph = Neo4jGraph(
            url=neo4j_uri,
            username=os.environ.get('NEO4J_USER', 'neo4j'),
            password=os.environ.get('NEO4J_PASSWORD', 'password'),
        )
    except Exception as e:
        logger.error(f"text-to-cypher: failed to connect to Neo4j: {e}")
        raise _CypherSetupError(500, "Failed to connect to the graph database.")

    return manager


async def _generate_validated_cypher(
    manager, question: str, user_id: str, project_id: str, for_graph_view: bool
) -> str:
    """Generate Cypher and prove it parses, scopes and runs. Returns the RAW
    (un-scoped) Cypher, which is what a caller saves or re-scopes itself.

    Raises _CypherSetupError. Retries feed the previous error back to the model;
    an unscopable pattern raises TenantScopeError, which the loop treats the same
    way rather than executing anything unfiltered.
    """
    from tools import CypherGenerationTimeout

    last_error = None
    last_cypher = None
    cypher = None
    max_retries = 3

    for attempt in range(max_retries):
        try:
            try:
                if attempt == 0:
                    cypher = await manager._generate_cypher(question, for_graph_view=for_graph_view)
                else:
                    cypher = await manager._generate_cypher(
                        question,
                        previous_error=last_error,
                        previous_cypher=last_cypher,
                        for_graph_view=for_graph_view,
                    )
            except CypherGenerationTimeout:
                raise
            except Exception as gen_exc:                          # noqa: BLE001
                raise _cypher_model_error(gen_exc) from gen_exc

            if manager._find_disallowed_write_operation(cypher):
                raise _CypherSetupError(400, "Write operations are not allowed in data filters")

            # Validate by executing (with the tenant filter) to catch syntax
            # errors. Bounded (P0-4): the rows are discarded, so ask for one
            # under a transaction timeout rather than materialising a result.
            filtered = manager._scope_query(cypher, user_id, project_id)
            await asyncio.to_thread(
                _graph_exec_run,
                filtered,
                {"tenant_user_id": user_id, "tenant_project_id": project_id},
                1,
            )
            return cypher

        except _CypherSetupError:
            raise
        except CypherGenerationTimeout as e:
            # Terminal: retrying would burn the same budget on the same model.
            logger.error(f"text-to-cypher: {e}")
            raise _CypherSetupError(504, "Timed out generating a query for that question.")
        except Exception as e:
            last_error = str(e)
            last_cypher = cypher
            logger.warning(f"text-to-cypher attempt {attempt + 1} failed: {last_error}")

    logger.error(f"text-to-cypher: gave up after {max_retries} attempts: {last_error}")
    raise _CypherSetupError(
        422,
        f"Could not generate a valid query after {max_retries} attempts. "
        "Try rephrasing the question.",
    )


@app.post(
    "/text-to-cypher",
    tags=["Graph"],
    dependencies=[Depends(require_internal_auth)],
)
async def text_to_cypher(body: TextToCypherRequest):
    """
    Generate a Cypher query from a natural language description.

    Reuses the rendered schema catalog and Neo4jToolManager._generate_cypher()
    so the graph schema is always in sync with the agent's query_graph tool.

    Returns the raw Cypher (without tenant filters) for the webapp to save and execute.

    BILLED: one request can cost up to 9 provider calls (3 attempts, each wrapped
    in retry_llm_call), spending the key of the user named in the body. It was
    previously unauthenticated, so anyone who could reach the agent port could
    spend any user's LLM budget. `require_internal_auth` applies the token bucket
    and the daily spend cap, and the caller is trusted to have resolved the
    identity it sends (mcp_plan.md P0-3).
    """
    try:
        manager = await _build_cypher_manager(body.user_id, body.project_id)
        cypher = await _generate_validated_cypher(
            manager, body.question, body.user_id, body.project_id, body.for_graph_view
        )
    except _CypherSetupError as e:
        return JSONResponse(content={"error": e.message, **e.fields}, status_code=e.status)
    return JSONResponse(content={"cypher": cypher})


class GraphNlQueryRequest(BaseModel):
    """Webapp (MCP server) -> agent: ask a question and get the ROWS.

    The tenant comes from the caller, which resolved it from a personal access
    token before calling and presents the master internal key. The MCP route
    deliberately does not go through /api/agent/text-to-cypher: that is a
    session-authenticated proxy for the browser, and it returns the query rather
    than running it.
    """
    question: str
    user_id: str
    project_id: str


@app.post(
    "/graph/nl-query",
    tags=["Graph"],
    dependencies=[Depends(require_internal_auth)],
)
async def graph_nl_query(body: GraphNlQueryRequest):
    """Natural language -> tenant-scoped rows, in one call.

    Generation and execution report SEPARATELY (`stage`), so a caller that
    failed can retry the right half: rephrasing helps a generation failure and
    does nothing for an execution one. Never answers an empty result for a
    dependency failure - conflating the two is the false negative this whole
    surface is built to avoid.
    """
    if not body.user_id or not body.project_id:
        return JSONResponse(status_code=400, content={"error": "missing tenant identity"})

    try:
        manager = await _build_cypher_manager(body.user_id, body.project_id)
        # for_graph_view=False: an external agent wants the values it asked
        # about, not whole nodes to render.
        cypher = await _generate_validated_cypher(
            manager, body.question, body.user_id, body.project_id, False
        )
    except _CypherSetupError as e:
        return JSONResponse(
            status_code=e.status, content={"error": e.message, "stage": "generate", **e.fields}
        )

    from graph_db.tenant_filter import scope_query, TenantScopeError

    try:
        final = scope_query(cypher, body.user_id, body.project_id)
    except TenantScopeError:
        # The generator already proved this scopes, so reaching here means the
        # query changed under us. Refuse rather than run anything unscoped.
        logger.error("graph/nl-query: generated Cypher failed to scope on re-check")
        return JSONResponse(
            status_code=400,
            content={"error": "Could not scope that query to your project.", "stage": "generate"},
        )

    params = {"tenant_user_id": body.user_id, "tenant_project_id": body.project_id}
    async with _graph_exec_mcp_semaphore():
        resp = await asyncio.to_thread(_graph_exec_respond, final, params)

    if resp.status_code != 200:
        import json as _json
        detail = _json.loads(bytes(resp.body).decode() or "{}")
        return JSONResponse(
            status_code=resp.status_code,
            content={**detail, "stage": "execute", "cypher": cypher},
        )

    import json as _json
    payload = _json.loads(bytes(resp.body).decode())
    # The generated Cypher travels back for transparency: the caller should be
    # able to see what its question became.
    payload["cypher"] = cypher
    return JSONResponse(content=payload)


@app.get(
    "/graph/schema-doc",
    tags=["Graph"],
    dependencies=[Depends(require_internal_auth_only)],
)
async def graph_schema_doc():
    """The graph schema INCLUDING its semantics: what each node type means, what
    its properties mean, which relationships connect what, and the distinctions
    that are easy to get wrong.

    Served from graph_db/schema_catalog.py, the same content the Cypher generator is
    prompted with on every call. One source, no second copy, nothing to drift.

    Deliberately NOT `CALL db.schema.visualization()`: that carries no semantics
    and is database-global, so it would reflect labels created by other tenants.
    Nor `op: "types"`, which is a bare list of label names.

    Reads from code only: no database, no project id, no tenant data. It is
    therefore the one graph tool that still answers when Neo4j is down.
    """
    # Rendered from graph_db/schema_catalog.py rather than read from the prompt
    # constant. render_schema() with no arguments is byte-identical to that
    # constant (asserted in recon/tests/test_schema_catalog.py), so this swap
    # changes no output today; what it buys is that the catalog is completeness-
    # checked against schema.py, and can later serve a per-label subset.
    from graph_schema_prompt import build_schema_document

    return JSONResponse(content={"schema": build_schema_document()})

# =============================================================================
# GRAPH EXEC — run a read-only, tenant-scoped graph query on behalf of the
# worker's `redagraph` CLI, so the worker does NOT hold the Neo4j credentials
# (DP5). ALL enforcement (read-only guard, tenant scoping, fixed schema/types
# queries) happens here, server-side; the worker cannot bypass it. The worker
# never controls a "raw/unscoped" path — `op` selects a fixed operation, and
# `op=cypher` always requires a labelled node pattern + the tenant filter.
# =============================================================================

# (the old `\(\w+:\w+` "has a labelled pattern" guard was replaced by
#  graph_db.tenant_filter.scope_query, which checks EVERY node pattern)
_graph_exec_driver = None

# Fixed op, so it never reaches scope_query - the mute exclusion that every
# agent-emitted pattern gets for free has to be written out by hand here, or a
# suppressed finding still shows up in the node-type counts. Excluding the node
# also keeps `Muted` itself out of the returned label list, since the only nodes
# carrying it are the ones this filter drops.
_GRAPH_TYPES_CYPHER = (
    "MATCH (n) "
    "WHERE n.user_id = $tenant_user_id AND n.project_id = $tenant_project_id "
    "AND NOT n:Muted "
    "UNWIND labels(n) AS label "
    "RETURN DISTINCT label AS type ORDER BY type"
)

# Fixed ops for `graph_summary`: what this project ACTUALLY contains.
#
# A label census cannot go through op="cypher": that path requires a labelled
# node pattern (least privilege - no blind whole-graph dump from the sandbox),
# and a census is by definition unlabelled. As a fixed op it is
# server-controlled, so the caller cannot alter it, and the tenant filter is
# written out by hand exactly as it is for op="types".
#
# `stale_since IS NULL` matters as much as the mute exclusion: since
# ingest-then-prune, a finding a scanner has stopped reporting is KEPT and
# stamped rather than deleted, so counting it would report resolved findings as
# live - the opposite of what a census is read for.
_GRAPH_SUMMARY_NODES_CYPHER = (
    "MATCH (n) "
    "WHERE n.user_id = $tenant_user_id AND n.project_id = $tenant_project_id "
    "AND NOT n:Muted AND n.stale_since IS NULL "
    "UNWIND labels(n) AS label "
    "RETURN label, count(*) AS count ORDER BY label"
)

_GRAPH_SUMMARY_RELS_CYPHER = (
    "MATCH (a)-[r]->(b) "
    "WHERE a.user_id = $tenant_user_id AND a.project_id = $tenant_project_id "
    "AND NOT a:Muted AND NOT b:Muted "
    "AND a.stale_since IS NULL AND b.stale_since IS NULL "
    "RETURN type(r) AS type, count(*) AS count ORDER BY type"
)


def _graph_exec_get_driver():
    global _graph_exec_driver
    if _graph_exec_driver is None:
        from neo4j import GraphDatabase
        _graph_exec_driver = GraphDatabase.driver(
            os.environ.get("NEO4J_URI", "bolt://neo4j:7687"),
            auth=(
                os.environ.get("NEO4J_USER", "neo4j"),
                os.environ.get("NEO4J_PASSWORD", "password"),
            ),
        )
    return _graph_exec_driver


# --- P0-4: bounds on the graph read path -------------------------------------
#
# Every guard on /graph/exec was about WHAT may be read (read-only, labelled
# pattern, tenant scope); none bounded HOW MUCH. One read-only Cartesian product
# passes all of them and pins Neo4j, which the graph screen, the agent and every
# running scan share. The webapp's own driver has injected a transaction timeout
# for exactly this reason since the graph-bounding work; this brings the agent
# in line and adds the transfer/memory bounds the webapp gets from its LIMIT.
#
# The bounds are deliberately NOT implemented by appending `LIMIT` to the
# caller's Cypher: string-appending a limit breaks UNION, aggregations and
# subqueries, and would create a second Cypher parser that has to be trusted.
# The timeout bounds server work; the record cap bounds transfer; the byte cap
# bounds memory (the webapp runs under mem_limit: 1g).

_GRAPH_EXEC_DEFAULT_MAX_RECORDS = 1000
_GRAPH_EXEC_DEFAULT_MAX_BYTES = 2 * 1024 * 1024
_GRAPH_EXEC_DEFAULT_TIMEOUT_MS = 120_000
_GRAPH_EXEC_DEFAULT_MCP_CONCURRENCY = 5


def _env_positive_int(name: str, default: int) -> int:
    """Unset / garbage / non-positive all fall back to the documented default,
    never to "no limit"."""
    try:
        n = int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default
    return n if n > 0 else default


def _graph_exec_max_records() -> int:
    return _env_positive_int("GRAPH_EXEC_MAX_RECORDS", _GRAPH_EXEC_DEFAULT_MAX_RECORDS)


def _graph_exec_max_bytes() -> int:
    return _env_positive_int("GRAPH_EXEC_MAX_BYTES", _GRAPH_EXEC_DEFAULT_MAX_BYTES)


def _graph_query_timeout_seconds() -> float:
    """Same env var and same 120s default as webapp/src/app/api/graph/neo4j.ts,
    so both readers of this database are bounded the same way."""
    ms = _env_positive_int("NEO4J_QUERY_TIMEOUT_MS", _GRAPH_EXEC_DEFAULT_TIMEOUT_MS)
    return ms / 1000.0


_graph_exec_mcp_sem = None


def _graph_exec_mcp_semaphore():
    """Concurrency ceiling for MCP-originated reads only.

    The kali sandbox is semi-trusted and loopback-only; an external agent behind
    a PAT is neither, and a looping one must not monopolise the Neo4j pool that
    the UI and running scans also draw from.
    """
    global _graph_exec_mcp_sem
    if _graph_exec_mcp_sem is None:
        _graph_exec_mcp_sem = asyncio.Semaphore(
            _env_positive_int("GRAPH_EXEC_MCP_CONCURRENCY", _GRAPH_EXEC_DEFAULT_MCP_CONCURRENCY)
        )
    return _graph_exec_mcp_sem


class GraphResultTooLarge(Exception):
    """The coerced result exceeded the serialised-byte cap."""

    def __init__(self, size: int, limit: int):
        super().__init__(f"result too large ({size} bytes > {limit})")
        self.size = size
        self.limit = limit


def _graph_exec_run(final: str, params: dict, max_records: int | None = None):
    """Run one bounded read. Returns ``(records, truncated)``.

    Streams the cursor and stops at the cap instead of materialising every
    record into a list, so a runaway query costs the cap rather than the result.
    """
    from neo4j import READ_ACCESS, Query

    cap = _graph_exec_max_records() if max_records is None else max_records
    driver = _graph_exec_get_driver()
    query = Query(final, timeout=_graph_query_timeout_seconds())

    records: list = []
    truncated = False
    # READ_ACCESS, not the driver default of WRITE. The read-only guard is a
    # regex over the query text, and a regex cannot be the only thing standing
    # between an LLM-generated query and a write: `\u0043REATE` inside a string
    # literal reads as CREATE to Neo4j and as nothing to the regex. Asking the
    # database for a read-only session moves that guarantee out of our parser
    # and into the engine, which cannot be fooled by how the text is spelled.
    with driver.session(default_access_mode=READ_ACCESS) as session:
        result = session.run(query, params)
        for rec in result:
            if len(records) >= cap:
                # Leaving the loop lets the session close and DISCARD the rest;
                # consuming it here would make the server produce every
                # remaining row, which is the cost this cap exists to avoid.
                truncated = True
                break
            records.append({k: _graph_exec_coerce(rec[k]) for k in rec.keys()})
    return records, truncated


def _graph_exec_payload(records: list, truncated: bool) -> dict:
    """Build the response body, refusing one that is too large to return.

    Fails loudly rather than truncating silently: a caller that received half a
    result and was not told would report a false negative, which is the failure
    mode this whole surface is built to avoid.
    """
    import json as _json

    payload: dict = {"records": records}
    if truncated:
        payload["truncated"] = True
    size = len(_json.dumps(payload, default=str).encode("utf-8"))
    limit = _graph_exec_max_bytes()
    if size > limit:
        raise GraphResultTooLarge(size, limit)
    return payload


def _graph_exec_node_id(node) -> int | None:
    """The node's `id(n)`: the Node ID the webapp tables and node drawer show.

    Read from the tail of `element_id` ("4:<db-uuid>:<id>" on Neo4j 5) rather
    than the driver's `Node.id`, which driver 6 deprecates and warns on for
    every node returned. None when the id is not in that form, never a guess:
    a wrong id would point the caller at a different node.
    """
    element_id = getattr(node, "element_id", None)
    if isinstance(element_id, str):
        tail = element_id.rsplit(":", 1)[-1]
        if tail.isdigit():
            return int(tail)
    return None


def _graph_exec_coerce(v):
    """Neo4j driver value -> JSON-serialisable primitive (mirrors redagraph)."""
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (list, tuple)):
        return [_graph_exec_coerce(x) for x in v]
    if isinstance(v, dict):
        return {k: _graph_exec_coerce(x) for k, x in v.items()}
    labels = getattr(v, "labels", None)
    if labels is not None and hasattr(v, "items"):
        # `nodeId` sits beside `properties`, not in it: many labels carry their
        # own `id` property (CVE ids, finding ids) that means something else.
        return {"_kind": "node",
                "nodeId": _graph_exec_node_id(v),
                "labels": sorted(labels) if hasattr(labels, "__iter__") else [str(labels)],
                "properties": {k: _graph_exec_coerce(x) for k, x in v.items()}}
    rel_type = getattr(v, "type", None)
    if rel_type is not None and hasattr(v, "items") and hasattr(v, "nodes"):
        return {"_kind": "relationship", "type": str(rel_type),
                "properties": {k: _graph_exec_coerce(x) for k, x in v.items()}}
    if hasattr(v, "items"):
        return {k: _graph_exec_coerce(x) for k, x in v.items()}
    return str(v)


_triage_client = None


def _triage_graph_client():
    """One long-lived Neo4jClient for the triage endpoint.

    Constructing a client per request also re-runs the FULL schema DDL, because
    `BaseMixin.__init__` calls `init_schema`. Measured on a live stack that put
    /graph/triage at 0.26-0.41s against /graph/exec's 0.002-0.012s, and it built
    and abandoned a Bolt connection pool every time - the same create-and-drop
    pattern documented in webapp/src/app/api/graph/neo4j.ts as having produced
    Neo4j's "Increase in network aborts detected" on a busy instance.

    A neo4j Driver is designed to be long-lived and shared, and reconnects on
    its own, so caching it is the intended usage rather than an optimisation.
    """
    global _triage_client
    if _triage_client is None:
        from graph_db.neo4j_client import Neo4jClient
        _triage_client = Neo4jClient()
    return _triage_client


#: Every op this endpoint answers. Validated up front so the dispatch below can
#: be a plain function with no early-return path back through the handler.
_TRIAGE_OPS = frozenset({
    "mute", "unmute", "unmute_many", "list_muted", "muted_facets",
    "list_findings", "human_verdict", "preflight", "stop_run",
    "mute_many", "resolve_muted", "mute_batch",
    "finding_detail", "finding_evidence", "submit_review", "triage_facets",
})

#: Ops that address ONE finding by its stored id (`node_id`).
_FINDING_OPS = ("human_verdict", "finding_detail", "finding_evidence", "submit_review")

#: A finding id as the board and MCP send it: the stored `id` / `finding_id`.
_FINDING_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,200}")

#: A review's evidence hash: `evidence.bundle_hash`, 40 hex characters.
_EVIDENCE_HASH_RE = re.compile(r"[0-9a-f]{40}")

#: The finding labels a single-finding op may be narrowed to.
_FINDING_LABELS = ("Vulnerability", "JsReconFinding", "Secret", "MultiscannerFinding",
                   "GithubSecret", "GithubSensitiveFile", "MalPackageFinding", "ExploitGvm")

#: The board's pushed-down filters, enum-checked before any graph work.
_TRIAGE_FILTERS = {
    "decided_by": ("person", "review", "rules"),
    "reviewed_via": ("builtin", "mcp", "none"),
    "review_current": ("current", "stale", "none"),
}

#: What an MCP mute is stamped with: the display prefix of the access token,
#: never the token. The webapp's `MCP_TOKEN_PREFIX` plus 8 hex characters.
_MCP_TOKEN_PREFIX_RE = re.compile(r"rdmn_mcp_[0-9a-f]{8}")

#: Graph Node IDs as the tables show them: Neo4j internal ids, digits only.
_GRAPH_ID_RE = re.compile(r"[0-9]{1,18}")

#: Per-call ceilings, re-checked here because any master-key holder can call
#: this endpoint without going through the webapp's own checks.
_MCP_MUTE_MAX = 5000
_MCP_UNMUTE_MAX = 5000
_UI_UNMUTE_MAX = 500
_MUTE_REASON_MAX = 500

#: A Multi mute batch id, as `multi_mute.batches` issues it.
_MULTI_BATCH_RE = re.compile(r"mm-[0-9a-f]{8}")
_MULTI_MUTE_MAX = 500
#: What a Multi mute write says it muted, in the reason line. The five
#: grouping concepts of the modal, plus the footer's whole selection and the
#: seed on its own.
_MULTI_MUTE_CONCEPT_LABELS = {
    "same_problem": "Same issue elsewhere",
    "same_detector": "Same detector",
    "same_host": "Same host",
    "same_fp_pattern": "Same false-positive pattern",
    "same_low_risk": "Same low-risk weakness",
    "selected": "Selected findings",
    "seed": "This finding",
}


def _triage_request_error(body) -> Optional[str]:
    """Why this request may not run, or None. Checked BEFORE any graph work.

    These checks hold for EVERY caller holding the master key, not just the
    webapp's MCP tools:

    - a `muted_by` starting `rule:` is refused on every mute. Only the Mute
      Rules sweep writes rule attribution, and it does not come through here;
      a forged one would make the prune delete a finding a person muted and
      let a sweep release or re-attribute it.
    - `mute_many` is the MCP mute and nothing else: it needs the MCP source,
      the exemptions (the only thing that keeps a person's unmute standing),
      a real token prefix and a reason.
    """
    muted_by = body.muted_by or ""
    if body.op in ("mute", "mute_many", "mute_batch") and muted_by.startswith("rule:"):
        return "muted_by may not name a rule: only the Mute Rules sweep writes rule mutes"
    if body.op == "mute_batch":
        # A person's mute, confirmed in the modal: never an agent's.
        if body.source == "mcp":
            return "mute_batch is a person's Multi mute and is never taken over MCP"
        if not _MULTI_BATCH_RE.fullmatch(body.batch_id or ""):
            return "batch_id must be a Multi mute batch id"
        if not body.keys:
            return "mute_batch needs keys"
        if len(body.keys) > _MULTI_MUTE_MAX:
            return f"at most {_MULTI_MUTE_MAX} findings per Multi mute call"
        if body.concept not in _MULTI_MUTE_CONCEPT_LABELS:
            return "concept is not a Multi mute grouping"
        pairs = body.exempt_pairs
        if pairs is None or any(not isinstance(p, list) or len(p) != 2
                                or not all(isinstance(x, str) for x in p) for p in pairs):
            return "exempt_pairs is required: a list of [label, key] pairs"
    if body.only_batch is not None:
        if body.op != "unmute_many" or body.source == "mcp":
            return "only_batch is the Multi mute Undo and belongs to unmute_many"
        if not _MULTI_BATCH_RE.fullmatch(body.only_batch):
            return "only_batch must be a Multi mute batch id"
    if body.op == "mute" and len(body.reason or "") > _MUTE_REASON_MAX:
        return f"reason is longer than {_MUTE_REASON_MAX} characters"
    graph_ids = body.graph_ids or []
    if any(not _GRAPH_ID_RE.fullmatch(str(g)) for g in graph_ids):
        return "graph_ids must be graph node ids (digits only)"
    keys = body.keys or []
    if body.op == "mute_many":
        if body.source != "mcp":
            return "mute_many is the MCP mute and needs source=mcp"
        pairs = body.exempt_pairs
        if pairs is None or not isinstance(pairs, list) or any(
                not isinstance(p, list) or len(p) != 2
                or not all(isinstance(x, str) for x in p) for p in pairs):
            return "exempt_pairs is required: a list of [label, key] pairs"
        if not _MCP_TOKEN_PREFIX_RE.fullmatch(body.token_prefix or ""):
            return "token_prefix must be an MCP token prefix"
        reason = (body.reason or "").strip()
        if not 3 <= len(reason) <= _MUTE_REASON_MAX:
            return f"reason must be 3-{_MUTE_REASON_MAX} characters"
        if not keys and not graph_ids:
            return "mute_many needs keys or graph_ids"
        # Counted together: the mixin caps the combined set, so a full list of
        # each would drop refs that are then reported neither done nor not found.
        if len(keys) + len(graph_ids) > _MCP_MUTE_MAX:
            return f"at most {_MCP_MUTE_MAX} findings per mute"
    if body.op in ("resolve_muted", "unmute_many"):
        ceiling = _MCP_UNMUTE_MAX if body.source == "mcp" else _UI_UNMUTE_MAX
        if len(keys) + len(graph_ids) > ceiling:
            return f"at most {ceiling} findings per unmute"
    if body.token is not None and not (_MCP_TOKEN_PREFIX_RE.fullmatch(body.token)
                                       or _MULTI_BATCH_RE.fullmatch(body.token)):
        return "token must be an MCP token prefix or a Multi mute batch id"
    if body.op in _FINDING_OPS:
        if not _FINDING_ID_RE.fullmatch(body.node_id or ""):
            return "node_id must be a finding id"
        if body.label is not None and body.label not in _FINDING_LABELS:
            return "label must be a finding label"
    if body.op == "human_verdict" and body.source == "mcp" and body.token_prefix \
            and not _MCP_TOKEN_PREFIX_RE.fullmatch(body.token_prefix):
        return "token_prefix must be an MCP token prefix"
    if body.op == "submit_review":
        # An external agent's review, and nothing else: the built-in AI writes
        # its reviews through a run's publish, never through here.
        if body.source != "mcp":
            return "submit_review is the MCP review and needs source=mcp"
        if not _MCP_TOKEN_PREFIX_RE.fullmatch(body.token_prefix or ""):
            return "token_prefix must be an MCP token prefix"
        if not isinstance(body.review, dict):
            return "review is required"
        if not _EVIDENCE_HASH_RE.fullmatch(body.evidence_hash or ""):
            return "evidence_hash must be 40 hex characters"
    if body.op in ("list_findings",):
        for name, allowed in _TRIAGE_FILTERS.items():
            value = getattr(body, name, None)
            if value is not None and value not in allowed:
                return f"{name} must be one of {', '.join(allowed)}"
    return None

#: The mixin's own ceiling on `list_triage_findings`. A caller-supplied limit is
#: clamped to it, never above it.
_TRIAGE_LIST_MAX = 2000


class GraphTriageRequest(BaseModel):
    """Webapp -> agent triage write.

    The tenant is supplied by the CALLER, which resolved it through
    `guardProject` before calling. `node_id` is scoped by that tenant inside the
    mixin, so a guessed id from another project matches nothing rather than
    mutating anything.
    """
    op: str  # mute | unmute | unmute_many | list_muted | muted_facets
             # | list_findings | human_verdict | preflight | stop_run
             # | mute_many | resolve_muted | mute_batch
    user_id: str
    project_id: str
    node_id: Optional[str] = None
    reason: Optional[str] = None
    muted_by: Optional[str] = None
    status: Optional[str] = None
    #: "mcp" opts the call into the MCP concurrency ceiling, exactly as the same
    #: field does on /graph/exec. It is set by the CALLER, so it can only ever
    #: narrow what that caller gets; the browser paths leave it unset and keep
    #: their current behaviour. A write's channel is derived from it, for the
    #: verdict (`triage_verdict_channel`), the review (`triage_ai_channel`) and
    #: the MCP mute (`muted_channel`) alike.
    source: Optional[str] = None
    #: Who the verdict is attributed to, mirroring `muted_by`.
    verdict_by: Optional[str] = None
    #: Cap on rows for `list_findings`. The mixin's own default is 2000 and the
    #: webapp pages far below that, so without this every page transferred the
    #: whole table internally. `total` still comes from the uncapped count, so a
    #: capped read can never pass for a complete one.
    limit: Optional[int] = None
    #: Muted Nodes paging and filters (`list_muted`). All optional: with none of
    #: them the op returns what it always did, plus a `total`.
    offset: Optional[int] = None
    label: Optional[str] = None
    muted_via: Optional[str] = None   # person | mcp | rule | deleted_rule
    rule: Optional[str] = None        # an exact muted_by, e.g. rule:vuln.nuclei/k3f9a2
    search: Optional[str] = None
    order: Optional[str] = None       # recent (default) | person_first
    #: The rule ids that still exist, for `muted_via = deleted_rule`.
    live_rules: Optional[List[str]] = None
    #: `unmute_many`: the findings' natural keys (id, or finding_id).
    keys: Optional[List[str]] = None
    #: `mute_many` / `resolve_muted`: Graph Node IDs, resolved inside the tenant.
    graph_ids: Optional[List[str]] = None
    #: `resolve_muted` / `unmute_many` over MCP: also release rule mutes.
    include_rule_mutes: Optional[bool] = None
    #: `mute_many`: the access-token prefix the mute is stamped with.
    token_prefix: Optional[str] = None
    #: `mute_many`: the project's Mute Rules exemptions, as [label, key] pairs.
    #: Required: an absent list would silently re-hide what a person unmuted.
    exempt_pairs: Optional[List[List[str]]] = None
    #: `list_muted`: only the mutes one access token (or one Multi mute batch) made.
    token: Optional[str] = None
    #: `mute_batch`: the suggestion batch the keys must come from, which
    #: grouping the person muted, and whether the batch's seed is included.
    batch_id: Optional[str] = None
    concept: Optional[str] = None
    include_seed: Optional[bool] = None
    #: `unmute_many`: a Multi mute Undo, limited to what that batch muted.
    only_batch: Optional[str] = None
    #: `submit_review`: the external agent's review, as MCP received it
    #: (verdict, evidence_quote, disputed_facts, impact_multiplier,
    #: impact_quote, why, fix_lever), and the evidence hash it read.
    review: Optional[dict] = None
    evidence_hash: Optional[str] = None
    #: `list_findings`: the board's pushed-down filters.
    decided_by: Optional[str] = None      # person | review | rules
    reviewed_via: Optional[str] = None    # builtin | mcp | none
    review_current: Optional[str] = None  # current | stale | none


def _multi_mute_batch_write(body):
    """The `mute_findings_batch` arguments for a Multi mute, or the 409 to send.

    Only keys from the suggestion the agent stored may be muted, so a tampered
    client cannot turn a suggestion into an arbitrary bulk mute: the batch must
    exist for this user and project, and every key must be one of its members,
    or its seed when the seed is included. The label, the seed's ceiling and
    the reason come from the batch too, never from the request.
    """
    from multi_mute.batches import STORE

    batch = STORE.get(body.user_id, body.project_id, body.batch_id)
    if batch is None:
        return JSONResponse(status_code=409, content={
            "error": "This suggestion expired; run Multi mute again.",
            "code": "batch_expired", "multi_mute": 1})
    keys = {str(k) for k in body.keys or []}
    allowed = set(batch.members) | ({batch.seed_key} if body.include_seed else set())
    if not keys <= allowed:
        return JSONResponse(status_code=409, content={
            "error": "Some findings are not part of this suggestion.",
            "code": "batch_mismatch", "multi_mute": 1})
    seed_name = " ".join(str(batch.seed_name or "").split())[:120]
    reason = (f"Multi mute {batch.batch_id} · {_MULTI_MUTE_CONCEPT_LABELS[body.concept]}"
              f' · like "{seed_name}"')[:_MUTE_REASON_MAX]
    return {
        "label": batch.label,
        "keys": sorted(keys),
        "seed_key": batch.seed_key if body.include_seed else "",
        "ceiling": batch.ceiling,
        "exempt_pairs": body.exempt_pairs,
        "muted_by": body.muted_by or body.user_id,
        "reason": reason,
        "batch_id": batch.batch_id,
        # Echoed to the webapp for its audit row; popped before the write.
        "_meta": {"model": batch.model, "prompt_version": batch.prompt_version},
    }


@app.post("/graph/triage", tags=["Graph"], dependencies=[Depends(require_master_internal_auth)])
async def graph_triage(body: GraphTriageRequest):
    """Mute / unmute a finding, and read the triage tables.

    Graph writes live in Python behind this endpoint rather than in the webapp's
    own Neo4j driver, so the tenant scoping and the muteable-label guard have
    exactly one implementation (`graph_db/mixins/recon/triage_mixin.py`).

    Auth is the MASTER key only, deliberately stricter than `/graph/exec`.
    `/graph/exec` accepts the scoped SCANNER_API_KEY because the kali-sandbox
    holds it and needs read-only graph access; this endpoint WRITES suppression
    state, and the sandbox is the least-trusted, target-facing component. It
    stays outside the LLM rate-limit bucket either way: these are cheap graph
    operations, not billed LLM calls.
    """
    # `require_master_internal_auth` fails open with no key so a bare dev
    # install still boots. This route writes suppression and verdict state, so
    # it refuses for itself instead of accepting unauthenticated callers.
    if master_key_is_weak():
        # `code`: refused before any graph work, so the webapp can report a
        # write as not done rather than as an unknown outcome.
        return JSONResponse(status_code=503, content={
            "error": "INTERNAL_API_KEY is not configured; triage operations are "
                     "disabled. Generate the secret via redamon.sh.",
            "code": "not_configured",
        })

    if not body.user_id or not body.project_id:
        return JSONResponse(status_code=400, content={"error": "missing tenant identity"})

    needs_node = ("mute", "unmute", *_FINDING_OPS)
    if body.op in needs_node and not body.node_id:
        return JSONResponse(status_code=400, content={"error": f"op {body.op} needs node_id"})

    if body.op not in _TRIAGE_OPS:
        return JSONResponse(status_code=400,
                            content={"error": f"unknown op {body.op!r}"})

    refused = _triage_request_error(body)
    if refused:
        return JSONResponse(status_code=400, content={"error": refused})

    batch_write = None
    batch_meta = None
    if body.op == "mute_batch":
        batch_write = _multi_mute_batch_write(body)
        if isinstance(batch_write, JSONResponse):
            return batch_write
        batch_meta = batch_write.pop("_meta")

    def run_op():
        """The blocking body, in one place.

        Extracted so the MCP and browser paths cannot drift in WHAT they do -
        only in how they are scheduled.
        """
        client = _triage_graph_client()
        if body.op == "mute_batch":
            return client.mute_findings_batch(body.user_id, body.project_id, **batch_write)
        if body.op == "mute":
            return client.mute_finding(
                body.user_id, body.project_id, body.node_id,
                muted_by=body.muted_by or body.user_id, reason=body.reason or "")
        if body.op == "mute_many":
            return client.mute_findings_delegated(
                body.user_id, body.project_id,
                keys=body.keys or [], graph_ids=body.graph_ids or [],
                exempt_pairs=body.exempt_pairs,
                muted_by=body.muted_by or body.user_id,
                reason=(body.reason or "").strip(),
                token_prefix=body.token_prefix or "")
        if body.op == "resolve_muted":
            return client.resolve_muted(
                body.user_id, body.project_id,
                keys=body.keys or [], graph_ids=body.graph_ids or [],
                include_rule_mutes=bool(body.include_rule_mutes))
        if body.op == "unmute":
            return client.unmute_finding(body.user_id, body.project_id, body.node_id)
        if body.op == "list_muted":
            # Unbounded unless the caller asks for a bound. Muted Nodes pages
            # with offset/limit and reads the size from `total`; the MCP
            # surface passes a limit and orders person-first.
            muted_limit = (max(1, min(int(body.limit), _TRIAGE_LIST_MAX))
                           if body.limit is not None else None)
            filters = dict(label=body.label, muted_via=body.muted_via,
                           rule=body.rule, search=body.search,
                           live_rules=body.live_rules, token=body.token)
            return {
                "findings": client.list_muted(
                    body.user_id, body.project_id, limit=muted_limit,
                    offset=max(0, int(body.offset or 0)) or None,
                    order=body.order, **filters),
                "total": client.count_muted(body.user_id, body.project_id, **filters),
            }
        if body.op == "muted_facets":
            return client.muted_facets(body.user_id, body.project_id)
        if body.op == "unmute_many":
            # An MCP caller releases a rule mute only when it asked to: the
            # unmute becomes a standing exception to that rule. The UI keeps
            # unmuting whatever it is given.
            return client.unmute_findings(
                body.user_id, body.project_id, body.keys or [],
                skip_rule_mutes=body.source == "mcp" and not body.include_rule_mutes,
                **({"only_batch": body.only_batch} if body.only_batch else {}))
        if body.op == "list_findings":
            # `total` is what stops the table lying: the query is capped, so
            # without it the operator reads a truncated list as complete. It
            # comes from the count with the SAME filters and no cap, so it
            # stays exact whatever `limit` the caller asked for.
            kwargs = {}
            if body.limit is not None:
                kwargs["limit"] = max(1, min(int(body.limit), _TRIAGE_LIST_MAX))
            filters = {name: getattr(body, name) for name in _TRIAGE_FILTERS
                       if getattr(body, name) is not None}
            return {
                "findings": client.list_triage_findings(
                    body.user_id, body.project_id, **kwargs, **filters),
                "total": client.count_triage_findings(
                    body.user_id, body.project_id, **filters),
            }
        if body.op == "triage_facets":
            return client.triage_facets(body.user_id, body.project_id)
        if body.op == "human_verdict":
            # Keyed on the channel, not a flag, so no MCP caller can forget it:
            # on a rule-muted finding a verdict releases the mute, and a token
            # releases one only through unmute_many, with its own permission
            # and an explicit include_rule_mutes. The same transaction rescores
            # the finding from its layers.
            from cypherfix_triage.layers import combine_props
            return client.set_human_verdict(
                body.user_id, body.project_id, body.node_id,
                body.status or "", body.reason or "",
                channel=body.source or "app",
                verdict_by=body.verdict_by or body.user_id,
                refuse_muted=body.source == "mcp",
                combine=combine_props,
                token=(body.token_prefix or "") if body.source == "mcp" else "",
                label=body.label)
        if body.op == "finding_detail":
            from cypherfix_triage.evidence import review_survives_rescan
            detail = client.get_triage_detail(
                body.user_id, body.project_id, body.node_id, body.label)
            if detail.get("found"):
                detail["review_survives_rescan"] = review_survives_rescan(
                    detail["row"].get("label"), detail["row"].get("source"))
            return detail
        if body.op == "finding_evidence":
            from cypherfix_triage.finding_ops import finding_evidence
            return finding_evidence(client, body.user_id, body.project_id,
                                    body.node_id, body.label)
        if body.op == "submit_review":
            from cypherfix_triage.finding_ops import submit_review
            return submit_review(client, body.user_id, body.project_id, body.node_id,
                                 body.label, body.review or {}, body.evidence_hash or "",
                                 body.token_prefix or "")
        if body.op == "preflight":
            return client.triage_preflight(body.user_id, body.project_id)
        # stop_run. Project delete calls this before deleting (X12). A run that
        # keeps working against a project being deleted would only notice at its
        # next heartbeat, minutes later, and could still be mid-publish.
        from cypherfix_triage.websocket_handler import stop_project_run
        return stop_project_run(body.project_id)

    from graph_db.mixins.recon.triage_mixin import TriageWriteBusy

    try:
        if body.op == "stop_run":
            # Touches the in-process run registry, which lives on the loop.
            result = run_op()
        elif body.source == "mcp":
            # An external agent behind a personal access token is the least
            # trusted caller this endpoint has, and unlike /graph/exec it took
            # NO concurrency ceiling at all. The published guarantee is a fixed
            # number at a time across all tokens, and the contention lands on the
            # operator's own Priority Board, which reads this same data through
            # this same endpoint.
            async with _graph_exec_mcp_semaphore():
                result = await asyncio.to_thread(run_op)
        else:
            # Every op off the event loop (B18). These are synchronous Neo4j
            # calls, and a write can wait on a run's publish lock: inline, that
            # wait stalled every coroutine in the agent, runs included.
            result = await asyncio.to_thread(run_op)
    except TriageWriteBusy:
        return JSONResponse(status_code=503, content={
            "error": "The finding is locked by another write (usually a triage run "
                     "publishing); nothing was changed. Try again in a moment.",
            "code": "busy", "layered_publish": True})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        logger.error(f"graph/triage {body.op} failed: {e}")
        if type(e).__name__ == "TransientError" or getattr(e, "is_retryable", lambda: False)():
            # execute_write already retried; a deadlock that outlasted it is
            # still not the caller's fault, and trying again later will work.
            return JSONResponse(status_code=503, content={
                "error": "The graph was busy; nothing was changed. Try again.",
                "code": "retry"})
        # A Neo4j message quotes the Cypher and its values; its status code
        # (Neo.ClientError.Schema...) or the class says enough to tell causes apart.
        neo4j_code = getattr(e, "code", None)
        error_class = (neo4j_code if isinstance(neo4j_code, str)
                       and re.fullmatch(r"Neo\.[A-Za-z]+\.[A-Za-z]+\.[A-Za-z]+", neo4j_code)
                       else type(e).__name__)
        return JSONResponse(status_code=500, content={
            "error": "The triage operation failed. The details are in the agent log.",
            "code": "internal_error", "error_class": error_class})

    # An acknowledgement the CALLER can check. The agent's Python is baked into
    # its image while the webapp is a separate one, so a deploy that rebuilds
    # only the webapp leaves an older agent here. Pydantic ignores fields it
    # does not know, so such an agent accepts `source`, `limit` and
    # `verdict_by`, discards all three, and answers 200: the MCP concurrency
    # ceiling silently does not apply, and every verdict is written with no
    # channel and no actor. Without this marker that mismatch has no signal at
    # all. Only added for MCP callers, so the browser paths are untouched.
    if body.source == "mcp" and isinstance(result, dict):
        result = {**result, "mcp_gated": True}
    # The capability the webapp checks before it lets an MCP verdict through
    # while a run is live: this agent's publish re-reads decisions and reviews
    # under the node lock, so a write made during a run is honoured. An older
    # agent does not say so, and the webapp then keeps refusing.
    if isinstance(result, dict):
        result = {**result, "layered_publish": True}
    # The same kind of marker for Multi mute: an agent that predates it answers
    # "unknown op" for mute_batch, and ignores `only_batch` on an unmute, which
    # would turn an Undo into an unmute of whatever the keys name.
    if (body.op == "mute_batch" or body.only_batch) and isinstance(result, dict):
        result = {**result, "multi_mute": 1, **(batch_meta or {})}

    # Who suppressed what, and when. The node itself carries muted_by/muted_at;
    # this is the time-ordered half. log_event never raises, so auditability
    # cannot turn a successful mute into a 500.
    if body.op == "unmute_many" and isinstance(result, dict):
        from session_log import log_event
        for item in result.get("items") or []:
            log_event("finding_unmuted", user_id=body.user_id,
                      project_id=body.project_id, node_id=item.get("key"),
                      label=item.get("label"), muted_by=item.get("muted_by"),
                      channel=body.source or "app")
    if body.op == "mute_batch" and isinstance(result, dict):
        from session_log import log_event
        for item in result.get("items") or []:
            if item.get("outcome") != "muted":
                continue
            log_event("finding_muted", user_id=body.user_id,
                      project_id=body.project_id, node_id=item.get("key"),
                      label=item.get("label"), channel="multi",
                      batch_id=body.batch_id, concept=body.concept)
    if body.op == "mute_many" and isinstance(result, dict):
        from session_log import log_event
        for item in result.get("items") or []:
            if item.get("outcome") != "muted":
                continue
            log_event("finding_muted", user_id=body.user_id,
                      project_id=body.project_id, node_id=item.get("key"),
                      label=item.get("label"), reason=(body.reason or "").strip(),
                      channel=body.source or "app", token_prefix=body.token_prefix)
    if body.op == "submit_review" and isinstance(result, dict):
        from session_log import log_event
        if result.get("written"):
            # Never the review's text: the why, quotes and fix lever are
            # target-derived and agent-written. The webapp's audit row carries
            # a hash of them for forensic matching.
            log_event("finding_review_submitted", user_id=body.user_id,
                      project_id=body.project_id, node_id=body.node_id,
                      label=result.get("label"), channel="mcp",
                      token_prefix=body.token_prefix,
                      verdict=(result.get("accepted") or {}).get("verdict"),
                      score_before=(result.get("before") or {}).get("score"),
                      score_after=(result.get("after") or {}).get("score"))
        else:
            logger.info("graph/triage submit_review refused (%s): node_id=%s project=%s",
                        result.get("reason"), body.node_id, body.project_id)
    # An already-muted finding was left exactly as it was, so there is no
    # mute to log, and it did match.
    if body.op in ("mute", "unmute", "human_verdict") and not result.get("already"):
        from session_log import log_event
        # The three ops write durable operator decisions. mute/unmute report
        # `muted`/`unmuted`; a verdict reports `updated`.
        applied = result.get("updated") if body.op == "human_verdict" \
            else result.get(f"{body.op}d")
        if applied and body.op == "human_verdict":
            # No reason text: over MCP it is agent-written.
            log_event(
                "finding_verdict_set",
                user_id=body.user_id,
                project_id=body.project_id,
                node_id=body.node_id,
                label=result.get("label"),
                channel=body.source or "app",
                status=body.status or "",
                score_before=(result.get("before") or {}).get("score"),
                score_after=(result.get("after") or {}).get("score"),
            )
        elif applied:
            log_event(
                f"finding_{body.op}d",
                user_id=body.user_id,
                project_id=body.project_id,
                node_id=body.node_id,
                label=result.get("label"),
                reason=body.reason or "",
                channel=body.source or "app",
            )
        elif result.get("reason") in ("muted", "decided_in_app", "ambiguous"):
            logger.info("graph/triage human_verdict refused (%s): node_id=%s project=%s",
                        result.get("reason"), body.node_id, body.project_id)
        else:
            # Matched nothing: a stale node id (version-activate recreates
            # nodes), an asset id, or another tenant's. The caller gets a
            # generic failure on purpose, so this is the only place the id is
            # recorded and the only way to diagnose it afterwards.
            logger.warning(
                "graph/triage %s matched no finding: node_id=%s user=%s project=%s",
                body.op, body.node_id, body.user_id, body.project_id)

    return JSONResponse(content=result)


class TriageRunStartRequest(BaseModel):
    """Webapp -> agent: start a triage run with no browser attached.

    The webapp resolved the tenant and checked ownership, the graph writers and
    (for an MCP start) the cooldown BEFORE calling: `stop_project_run` and this
    start are keyed on the project alone.
    """
    user_id: str
    project_id: str
    real_actor_user_id: Optional[str] = None
    trigger: str = "app"             # app | mcp
    token_id: Optional[str] = None   # the MCP token's id, never the token
    max_review_budget: Optional[int] = None


class TriageRunStopRequest(BaseModel):
    project_id: str


_RUN_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


@app.post("/triage/runs", tags=["Triage"], dependencies=[Depends(require_master_internal_auth)])
async def triage_run_start(body: TriageRunStartRequest):
    """Start (or attach to) a project's triage run, and answer 202 with its id.

    The same `start_detached_run` the websocket uses, so a run started here is
    the same run a tab later attaches to, with the same one-run-per-project
    slot. Runs on the event loop: it only creates a task and waits for the
    webapp to authorise it, which is where the run id comes from.
    """
    if master_key_is_weak():
        return JSONResponse(status_code=503, content={
            "error": "INTERNAL_API_KEY is not configured; triage runs are disabled."})
    for value in (body.user_id, body.project_id):
        if not _RUN_ID_RE.fullmatch(value or ""):
            return JSONResponse(status_code=400, content={"error": "invalid tenant identity"})
    if body.trigger not in ("app", "mcp"):
        return JSONResponse(status_code=400, content={"error": "trigger must be app or mcp"})
    if body.token_id is not None and not _RUN_ID_RE.fullmatch(body.token_id):
        return JSONResponse(status_code=400, content={"error": "invalid token id"})
    if body.real_actor_user_id is not None and not _RUN_ID_RE.fullmatch(body.real_actor_user_id):
        return JSONResponse(status_code=400, content={"error": "invalid actor id"})

    from cypherfix_triage.websocket_handler import start_detached_run
    run, attached, refusal = start_detached_run(
        body.user_id, body.project_id,
        real_actor_user_id=body.real_actor_user_id,
        trigger=body.trigger, token_id=body.token_id,
        max_review_budget=body.max_review_budget)
    if refusal:
        return JSONResponse(status_code=409, content={"error": refusal, "code": "busy"})

    if not attached:
        try:
            await asyncio.wait_for(run.authorized.wait(), timeout=20)
        except asyncio.TimeoutError:
            pass
        if run.start_error or (not run.run_id and run.task is not None and run.task.done()):
            return JSONResponse(status_code=409, content={
                "error": run.start_error or "the run could not be authorised",
                "code": "busy"})
    return JSONResponse(status_code=202, content={
        "runId": run.run_id or None, "attached": bool(attached),
        "trigger": run.trigger, "layered_publish": True})


@app.post("/triage/runs/stop", tags=["Triage"], dependencies=[Depends(require_master_internal_auth)])
async def triage_run_stop(body: TriageRunStopRequest):
    """Stop a project's run. Refused while it publishes (`reason: publishing`).

    Keyed on the project alone, so the webapp checks the caller owns it first.
    """
    if master_key_is_weak():
        return JSONResponse(status_code=503, content={
            "error": "INTERNAL_API_KEY is not configured; triage runs are disabled."})
    if not _RUN_ID_RE.fullmatch(body.project_id or ""):
        return JSONResponse(status_code=400, content={"error": "invalid project id"})
    from cypherfix_triage.websocket_handler import stop_project_run
    return JSONResponse(content={**stop_project_run(body.project_id), "layered_publish": True})


class NodeFilterPreviewRequest(BaseModel):
    """Webapp -> agent: count what draft node-filter rules would do.

    The tenant is resolved by the webapp route (strict owner check) before the
    call. The rules are re-validated here by the engine; nothing is written.
    """
    user_id: str
    project_id: str
    mode: str
    rules: Optional[Any] = None
    #: [label, key] pairs from Postgres: nodes an operator unmuted.
    exemptions: Optional[List[List[str]]] = None
    kinds: Optional[List[str]] = None


# =============================================================================
# MULTI MUTE — suggest the other findings a person would mute for the same
# reason as one they are muting. Read-only: the suggestion is stored as a batch
# and the later /graph/triage `mute_batch` write accepts only its keys.
# =============================================================================

class MultiMuteSuggestRequest(BaseModel):
    user_id: str
    project_id: str
    seed_key: str
    #: The caller's saved "Multi mute" model, read by the webapp from the
    #: owner's settings. Required: there is no default to fall back to.
    model: Optional[str] = None
    #: The project's Mute Rules exemptions as [label, key] pairs: findings a
    #: person brought back are never proposed.
    exempt_pairs: List[List[str]] = []


@app.post("/graph/multi-mute/suggest", tags=["Graph"],
          dependencies=[Depends(require_master_internal_auth), Depends(require_internal_auth)])
async def multi_mute_suggest(body: MultiMuteSuggestRequest):
    """Suggest findings like the seed, grouped, for a person to confirm."""
    from multi_mute import service as multi_mute_service

    model = (body.model or "").strip()
    # Stricter than the master-key dependency, which fails open on a dev install
    # with no key: this spends a user's LLM keys and reads their whole findings
    # pool, so it refuses for itself.
    if master_key_is_weak():
        return JSONResponse(status_code=503, content={
            "error": "INTERNAL_API_KEY is not configured; Multi mute is disabled. "
                     "Generate the secret via redamon.sh.",
            "multi_mute": 1, "model_used": model})
    if not model:
        return JSONResponse(status_code=400, content={
            "error": "model is required", "multi_mute": 1, "model_used": ""})
    if not body.user_id or not body.project_id or not body.seed_key:
        return JSONResponse(status_code=400, content={
            "error": "missing tenant identity or seed", "multi_mute": 1, "model_used": model})
    pairs = [p for p in body.exempt_pairs or [] if isinstance(p, list) and len(p) == 2]

    def build_llm(model_name):
        return build_llm_from_providers(model_name, fetch_user_providers(body.user_id))

    try:
        payload = await multi_mute_service.suggest(
            user_id=body.user_id, project_id=body.project_id, seed_key=body.seed_key,
            model=model, exempt_pairs=pairs, driver=_triage_graph_client().driver,
            build_llm=build_llm)
    except multi_mute_service.Superseded:
        return JSONResponse(status_code=409, content={
            "error": "A newer Multi mute search replaced this one.",
            "code": "superseded", "multi_mute": 1, "model_used": model})
    except multi_mute_service.SuggestError as exc:
        return JSONResponse(status_code=exc.status, content={
            "error": exc.message, "code": exc.code, "multi_mute": 1, "model_used": model})
    except Exception as exc:                                      # noqa: BLE001
        logger.error(f"multi-mute suggest failed: {exc.__class__.__name__}: {exc}")
        return JSONResponse(status_code=500, content={
            "error": "Multi mute failed. The details are in the agent log.",
            "multi_mute": 1, "model_used": model})
    # An unreadable answer still carries the exact groups, all unchecked.
    status_code = 502 if payload.get("status") == "model_unreadable" else 200
    return JSONResponse(status_code=status_code, content=payload)


@app.post("/graph/node-filters/preview", tags=["Graph"],
          dependencies=[Depends(require_master_internal_auth)])
def node_filters_preview(body: NodeFilterPreviewRequest):
    """A dry run of the one sweep that applies node filters.

    A plain `def`, so FastAPI runs it in its worker pool and the paged graph
    reads never block the event loop. One preview per project and two in total
    (429 otherwise), and a 20 s deadline after which the counts come back
    marked `partial`.
    """
    if master_key_is_weak():
        return JSONResponse(status_code=503, content={
            "error": "INTERNAL_API_KEY is not configured; mute rules are disabled."})
    if not body.user_id or not body.project_id:
        return JSONResponse(status_code=400, content={"error": "missing tenant identity"})
    from node_filter_runs import PreviewBusy, preview
    try:
        stats = preview(_triage_graph_client(), body.user_id, body.project_id, body.mode,
                        body.rules, exemptions=body.exemptions or [], kinds=body.kinds or None)
    except PreviewBusy as e:
        return JSONResponse(status_code=429, content={"error": str(e)})
    except Exception as e:
        logger.error(f"node-filter preview failed: {e}")
        return JSONResponse(status_code=500, content={"error": "the preview failed"})
    return JSONResponse(content=stats)


class NodeFilterApplyRequest(BaseModel):
    """Webapp -> agent: apply one NodeFilterRun. The id is ALL it carries.

    The rules, mode, tenant and exemptions are read back from the run row over
    the master-key internal route, so a forged body cannot choose what is muted.
    """
    run_id: str


@app.post("/graph/node-filters/apply", tags=["Graph"],
          dependencies=[Depends(require_master_internal_auth)])
async def node_filters_apply(body: NodeFilterApplyRequest):
    """Start an apply in a background thread and answer 202 at once.

    An apply can take minutes on a large graph; the webapp's call must not wait
    for it, and the event loop must not run it. Progress and the outcome reach
    the webapp through the run's heartbeat and finish routes.
    """
    if master_key_is_weak():
        return JSONResponse(status_code=503, content={
            "error": "INTERNAL_API_KEY is not configured; mute rules are disabled."})
    run_id = (body.run_id or "").strip()
    if not run_id or len(run_id) > 64 or not re.fullmatch(r"[A-Za-z0-9_-]+", run_id):
        return JSONResponse(status_code=400, content={"error": "invalid run id"})
    from node_filter_runs import start_apply
    from session_log import log_event
    if not start_apply(run_id, _triage_graph_client, log_event=log_event):
        return JSONResponse(status_code=409, content={"error": "this run is already being applied"})
    return JSONResponse(status_code=202, content={"accepted": True, "run_id": run_id})


class GraphExecRequest(BaseModel):
    """Worker (redagraph) -> agent graph query. `op` selects a fixed operation
    so arbitrary unscoped queries are impossible."""
    op: str  # "cypher" | "types" | "schema" | "summary"
    user_id: str
    project_id: str
    cypher: Optional[str] = None  # only for op="cypher"
    # "mcp" opts the read into the concurrency ceiling (P0-4). It is a throttling
    # hint only: it grants nothing, so a caller that lies about it can only
    # throttle itself.
    source: str = ""


@app.post("/graph/exec", tags=["Graph"], dependencies=[Depends(require_internal_auth_only)])
async def graph_exec(body: GraphExecRequest):
    from graph_db.tenant_filter import (
        find_disallowed_write_operation,
        has_labelled_node_pattern,
        scope_query,
        TenantScopeError,
    )

    if not body.user_id or not body.project_id:
        return JSONResponse(status_code=400, content={"error": "missing tenant identity"})

    # R12 (phased): the caller is now authenticated (require_internal_auth), but
    # the tenant is still derived from the request BODY. Log the legacy body-
    # identity use so the migration surface is observable; the enforce-flip
    # (claim-derived tenant threaded from terminal->redagraph) is a tracked
    # follow-on. A foothold inside the authenticated worker can still assert a
    # tenant here — a strictly smaller surface than the prior anonymous LAN read.
    logger.info(
        "graph/exec: authenticated caller, body-identity tenant (R12 legacy path) "
        "user=%s project=%s op=%s", body.user_id, body.project_id, body.op)

    op = body.op
    if op == "schema":
        # Fixed, read-only structural query — server-controlled, worker can't alter it.
        # It is database-global (never tenant-scoped), so it does surface the
        # existence of the `Muted` label. Accepted: it exposes no node and no
        # count, and scope_query refuses any follow-up query that names the
        # label, so knowing it exists buys nothing.
        final, params = "CALL db.schema.visualization()", {}
    elif op == "types":
        final = _GRAPH_TYPES_CYPHER
        params = {"tenant_user_id": body.user_id, "tenant_project_id": body.project_id}
    elif op == "summary":
        # Two fixed queries, so this op answers alone rather than making the
        # caller issue two and stitch them. It returns early, so it takes the
        # MCP concurrency ceiling here rather than at the shared exit below.
        params = {"tenant_user_id": body.user_id, "tenant_project_id": body.project_id}
        if body.source == "mcp":
            async with _graph_exec_mcp_semaphore():
                return await asyncio.to_thread(_graph_exec_summary, params)
        return await asyncio.to_thread(_graph_exec_summary, params)
    elif op == "cypher":
        cypher = (body.cypher or "").strip()
        if not cypher:
            return JSONResponse(status_code=400, content={"error": "missing cypher"})
        bad = find_disallowed_write_operation(cypher)
        if bad:
            return JSONResponse(status_code=403, content={"error": f"write operation rejected ({bad}); read-only"})
        # Worker-supplied Cypher must name the labels it wants (least privilege:
        # no blind whole-graph dump from the sandbox) AND be provably scoped to
        # ONE project. The label check alone used to be the only guard, and it
        # passed queries like `MATCH (p:Package) OPTIONAL MATCH (n)` with `(n)`
        # left unscoped; scope_query now covers every pattern in the query.
        if not has_labelled_node_pattern(cypher):
            return JSONResponse(status_code=400, content={"error": "query has no labelled node pattern; cannot scope to tenant"})
        try:
            final = scope_query(cypher, body.user_id, body.project_id)
        except TenantScopeError as e:
            return JSONResponse(status_code=400, content={"error": str(e)})
        params = {"tenant_user_id": body.user_id, "tenant_project_id": body.project_id}
    else:
        return JSONResponse(status_code=400, content={"error": f"unknown op {op!r}"})

    # An MCP-originated read is throttled; the kali sandbox's is not (P0-4).
    if body.source == "mcp":
        async with _graph_exec_mcp_semaphore():
            return await asyncio.to_thread(_graph_exec_respond, final, params)
    return await asyncio.to_thread(_graph_exec_respond, final, params)


def _graph_exec_summary(params: dict) -> JSONResponse:
    """The fixed label + relationship census behind `op: "summary"`.

    COUNTS ONLY, never sample values: sample values are live target data
    (hostnames, secrets, endpoints) and would leak recon output into an external
    agent's context ahead of any deliberate query.
    """
    from graph_db.coverage_stamps import COVERAGE_SUMMARY_CYPHER, coverage_summary

    try:
        nodes, _ = _graph_exec_run(_GRAPH_SUMMARY_NODES_CYPHER, params)
        rels, _ = _graph_exec_run(_GRAPH_SUMMARY_RELS_CYPHER, params)
    except Exception as e:
        logger.error(f"graph/exec summary failed: {e}")
        return JSONResponse(status_code=500, content={"error": "graph query failed"})
    body = {"nodes": nodes, "relationships": rels}
    # The per-host coverage counts explain the census, they are not part of it:
    # an unreadable count drops the block, never the answer, and never reads as 0.
    try:
        coverage, _ = _graph_exec_run(COVERAGE_SUMMARY_CYPHER, params)
        body["coverage"] = coverage_summary(coverage[0] if coverage else None)
    except Exception as e:
        logger.warning(f"graph/exec summary: coverage counts unreadable: {e}")
    return JSONResponse(content=body)


def _graph_exec_respond(final: str, params: dict) -> JSONResponse:
    try:
        records, truncated = _graph_exec_run(final, params)
        return JSONResponse(content=_graph_exec_payload(records, truncated))
    except GraphResultTooLarge as e:
        logger.warning(f"graph/exec refused an oversized result: {e}")
        return JSONResponse(
            status_code=413,
            content={"error": "result too large, narrow your query"},
        )
    except Exception as e:
        logger.error(f"graph/exec failed: {e}")
        return JSONResponse(status_code=500, content={"error": "graph query failed"})


# =============================================================================
# TRAFFIC — proxy_brain broker endpoints (kali `redamon` SDK -> agent)
# =============================================================================
#
# The kali sandbox runs agent-authored code (`proxy_brain`) but holds NO
# DATABASE_URL. Its `redamon` SDK reaches the captured-traffic corpus and the
# active replay path ONLY through these two endpoints — the mirror of the
# redagraph -> /graph/exec pattern. Tenant identity is NOT taken from the body:
# it is derived from a signed `ctx` tag (source=agent) that only the agent could
# have minted (it holds INTERNAL_API_KEY; kali does not), so a foothold inside
# the least-trusted worker cannot forge a cross-tenant read or send.

# Per-session live-send budget for /traffic/replay. One proxy_brain confirmation
# fans out to many sends (a loop / batch); without a cap a single confirmed run
# could flood a target. Counted per session (from the verified tag) across the
# agent process (single-worker; startup_guard enforces one worker, and async
# increments here happen with no intervening await, so no lock is needed).
_TRAFFIC_REPLAY_SENDS: dict[str, int] = {}


# Cache for the project row behind replay auth. One proxy_brain run fans out to
# many replays, and each was doing a full project GET with a 10s timeout on the
# send path. An entry is reused for at most the TTL, and never once a settings
# load has seen the project's updatedAt move: a rescope must not keep sending a
# session to a host it no longer covers.
_AUTH_PROFILE_CACHE: dict[str, tuple[float, dict]] = {}
_AUTH_PROFILE_TTL_SEC = 60.0


async def _cached_project(project_id: str) -> dict:
    """The project row behind replay auth, cached (see _AUTH_PROFILE_CACHE). Raises."""
    webapp_url = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
    def _fetch():
        import requests as _rq
        r = _rq.get(f"{webapp_url.rstrip('/')}/api/projects/{project_id}",
                    headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}, timeout=10)
        r.raise_for_status()
        return r.json()
    import time as _time  # `time` is not imported at module scope in this file
    from project_settings import seen_project_updated_at
    _now = _time.time()
    _hit = _AUTH_PROFILE_CACHE.get(project_id)
    _seen = seen_project_updated_at(project_id)
    if (_hit and (_now - _hit[0]) < _AUTH_PROFILE_TTL_SEC
            and (_seen is None or _hit[1].get("updatedAt") == _seen)):
        return _hit[1]
    project = await asyncio.to_thread(_fetch)
    _AUTH_PROFILE_CACHE[project_id] = (_now, project)
    return project


#: Always credentials, whatever the profile says.
_CREDENTIAL_HEADERS = frozenset({"cookie", "authorization", "proxy-authorization"})


async def _anonymous_strip_names(project_id: str) -> frozenset:
    """Header names an anonymous send must not carry: the standard credential
    headers plus every name the project's profile sets (its header, apikey and
    extraHeaders names), whatever host it is scoped to."""
    names = set(_CREDENTIAL_HEADERS)
    try:
        from auth_profile import build_auth_headers
        profile = (await _cached_project(project_id)).get("authProfile")
        names |= {str(k).lower() for k in build_auth_headers(profile or {})}
    except Exception:  # noqa: BLE001 - the standard names are still stripped
        pass
    return frozenset(names)


async def _profile_auth_base(project_id: str, txn: dict) -> dict:
    """AuthProfile headers to seed under an in-scope replay/browser send.

    Best-effort and fail-open: any error (no profile, webapp down, out of scope)
    returns {} so replay is never blocked. The profile rides UNDER the origin
    header and the agent's explicit mutate, so an IDOR/BOLA swap still wins.
    """
    try:
        host = txn.get("host")
        if not host:
            return {}
        project = await _cached_project(project_id)
        profile = project.get("authProfile")
        if not profile:
            return {}
        # The same scope as the agent's curl session (§4.6), from the webapp's
        # scope groups; the profile's explicit hosts only narrow it, and the
        # request's host is RoE-checked.
        from auth_profile import auth_headers_for_host
        from recon_settings.engagement import derive_roe_enabled
        from scope_groups import auth_scope_patterns, scope_groups_from_project
        groups = scope_groups_from_project(project)[0]
        patterns = auth_scope_patterns(groups, ip_mode=bool(project.get("ipMode")),
                                       target_ips=project.get("targetIps") or [])
        roe = (project.get("roeExcludedHosts") or []) if derive_roe_enabled(project) else []
        return auth_headers_for_host(profile, host, patterns, roe)
    except Exception:  # noqa: BLE001
        return {}


def _replay_budget() -> int:
    try:
        return max(1, int(os.environ.get("TRAFFIC_REPLAY_BUDGET", "1000") or "1000"))
    except (TypeError, ValueError):
        return 1000


class TrafficExecRequest(BaseModel):
    """kali redamon SDK -> agent, read-only corpus access. `ctx` is the signed
    agent tag; tenant is derived from it (never from the body). `op` selects a
    fixed read operation; `args` are the op's parameters."""
    ctx: str
    op: str  # search|get|sitemap|params|grep|diff|to_curl|query
    args: dict = {}


class TrafficReplayRequest(BaseModel):
    """kali redamon SDK -> agent, ACTIVE replay PREPARE. The agent validates
    tenant + phase, reads the origin (tenant-scoped), builds the HOST-PINNED curl
    and signs the replay lineage tag, then returns them for the worker to send
    through the capture proxy. The agent never reaches the target itself."""
    ctx: str
    op: str = "replay"  # replay | fuzz
    id: str
    mutate: dict = {}
    insertion_point: Optional[str] = None  # fuzz only
    payloads: Optional[list] = None        # fuzz only
    # The same request with no credentials at all: no profile seeded, and the
    # origin's Cookie/Authorization/profile headers stripped (an authz check).
    anonymous: bool = False


def _verify_traffic_ctx(ctx: str) -> Optional[dict]:
    """Verify the signed agent tag and return its claims, or None (fail closed).

    The tag is HMAC-signed with INTERNAL_API_KEY, which the kali worker does not
    hold, so it can present the scoped SCANNER_API_KEY for transport auth yet
    cannot mint a tag for a tenant it was not issued for."""
    try:
        from redamon_ctx import verify_tag
    except Exception:  # noqa: BLE001
        return None
    key = os.environ.get("INTERNAL_API_KEY", "")
    if not key or key == "changeme":
        # Fail closed: without the signing key we cannot authenticate the tenant
        # claim, and this path authorizes cross-tenant reads + live sends.
        return None
    payload = verify_tag(ctx, {"agent": key})
    if not payload or not payload.get("user_id") or not payload.get("project_id"):
        return None
    return payload


def _apply_traffic_tenant(claims: dict) -> None:
    """Bind the verified tenant into request-local ContextVars so the reused
    traffic_tools logic scopes to it. FastAPI runs each request in its own task
    context, so these sets never leak across concurrent requests."""
    from agent_context import (
        current_user_id, current_project_id, current_session_id, current_phase,
    )
    current_user_id.set(claims["user_id"])
    current_project_id.set(claims["project_id"])
    if claims.get("session_id"):
        current_session_id.set(claims["session_id"])
    if claims.get("phase"):
        current_phase.set(claims["phase"])


@app.post("/traffic/exec", tags=["Traffic"], dependencies=[Depends(require_internal_auth_only)])
async def traffic_exec(body: TrafficExecRequest):
    """Read-only corpus access for the kali `redamon` SDK. Constrained ops only;
    tenant from the verified tag; every underlying query hard-injects the tenant
    filter (traffic_tools). Returns the tool's formatted text under `result`."""
    claims = _verify_traffic_ctx(body.ctx)
    if not claims:
        return JSONResponse(status_code=401, content={"error": "invalid or missing traffic ctx"})
    _apply_traffic_tenant(claims)

    import json as _json
    from traffic_tools import (
        proxy_search, proxy_get, proxy_sitemap, proxy_params, proxy_grep,
        proxy_diff, proxy_to_curl, proxy_query,
    )
    a = body.args or {}
    op = body.op
    try:
        if op == "search":
            filt = a if isinstance(a, dict) else {}
            out = await proxy_search.ainvoke({"filters": _json.dumps(filt)})
        elif op == "get":
            out = await proxy_get.ainvoke({"id": str(a.get("id", "")), "part": a.get("part", "response")})
        elif op == "sitemap":
            out = await proxy_sitemap.ainvoke({})
        elif op == "params":
            out = await proxy_params.ainvoke({})
        elif op == "grep":
            out = await proxy_grep.ainvoke({"pattern": str(a.get("pattern", "")), "limit": int(a.get("limit", 50) or 50)})
        elif op == "diff":
            out = await proxy_diff.ainvoke({"id_a": str(a.get("id_a", "")), "id_b": str(a.get("id_b", ""))})
        elif op == "to_curl":
            out = await proxy_to_curl.ainvoke({"id": str(a.get("id", ""))})
        elif op == "query":
            out = await proxy_query.ainvoke({"spec": _json.dumps(a.get("spec", a))})
        else:
            return JSONResponse(status_code=400, content={"error": f"unknown op {op!r}"})
    except Exception as e:  # noqa: BLE001 — surface to the SDK, never a trace
        return JSONResponse(status_code=500, content={"error": str(e)[:300]})
    return JSONResponse(content={"result": out})


@app.post("/traffic/replay", tags=["Traffic"], dependencies=[Depends(require_internal_auth_only)])
async def traffic_replay(body: TrafficReplayRequest):
    """ACTIVE replay PREPARE. Validates tenant + phase, reads the origin
    (tenant-scoped), builds the host-pinned curl and signs the replay lineage
    tag. The worker performs the send through the capture proxy. Per-send gating
    lives here because one proxy_brain run fans out to many sends."""
    claims = _verify_traffic_ctx(body.ctx)
    if not claims:
        return JSONResponse(status_code=401, content={"error": "invalid or missing traffic ctx"})

    # Per-send phase gate (the tag carries the session phase). Active sends are
    # confined to the exploitation phases, mirroring TOOL_PHASE_MAP for the old
    # proxy_replay/proxy_fuzz. Fail closed on anything else.
    phase = claims.get("phase") or "informational"
    if phase not in ("exploitation", "post_exploitation"):
        return JSONResponse(status_code=403, content={"error": f"active replay not allowed in phase '{phase}'"})

    _apply_traffic_tenant(claims)

    import json as _json
    from traffic_tools import fetch_transaction, build_replay_curl, build_fuzz_curls
    txn = await fetch_transaction(str(body.id))
    if not txn:
        return JSONResponse(status_code=404, content={"error": "origin transaction not found (or not in your project)"})

    # Sign the replay lineage tag (source=agent, is_replay, origin_id) so the
    # ingest attributes the re-captured row from the VERIFIED tag, not the body.
    try:
        from redamon_ctx import sign_tag
        replay_tag = sign_tag({
            "source": "agent",
            "project_id": claims["project_id"],
            "user_id": claims["user_id"],
            "session_id": claims.get("session_id") or None,
            "tool": "proxy_brain",
            "phase": phase,
            "is_replay": True,
            "origin_id": str(body.id),
        }, os.environ.get("INTERNAL_API_KEY", ""))
    except Exception:  # noqa: BLE001
        replay_tag = ""

    # Authenticated identity for in-scope hosts (best-effort; {} otherwise), or
    # none at all for an anonymous send.
    if body.anonymous:
        auth_base, strip = {}, await _anonymous_strip_names(claims["project_id"])
    else:
        auth_base, strip = await _profile_auth_base(claims["project_id"], txn), None

    try:
        if body.op == "fuzz":
            ip = str(body.insertion_point or "")
            # Bound the INPUT before materializing (build_fuzz_curls also caps the
            # output, but a huge input list would still be stringified in full).
            payloads = [str(x) for x in (body.payloads or [])[:200]]
            if not ip or not payloads:
                return JSONResponse(status_code=400, content={"error": "fuzz requires insertion_point + payloads"})
            sends = [{"payload": pl, "curl_args": args}
                     for pl, args in build_fuzz_curls(txn, ip, payloads, auth_base=auth_base, strip_headers=strip)]
        else:
            mutate = body.mutate if isinstance(body.mutate, dict) else {}
            sends = [{"payload": None,
                      "curl_args": build_replay_curl(txn, mutate, auth_base=auth_base, strip_headers=strip)}]
    except ValueError as e:
        # Host-pin / scope violation (F1) or a malformed mutate — refuse, fail closed.
        return JSONResponse(status_code=400, content={"error": f"replay refused: {str(e)[:200]}"})
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=400, content={"error": f"could not build replay: {str(e)[:200]}"})

    # Per-session send budget (F2): one confirmed proxy_brain run must not emit
    # unbounded live traffic. Count PREPARED sends per session; refuse over budget.
    budget = _replay_budget()
    bkey = claims.get("session_id") or f"{claims['user_id']}:{claims['project_id']}"
    used = _TRAFFIC_REPLAY_SENDS.get(bkey, 0)
    if used + len(sends) > budget:
        return JSONResponse(status_code=429, content={
            "error": f"replay send budget exhausted for this session ({used}/{budget}); refusing {len(sends)} more"})
    _TRAFFIC_REPLAY_SENDS[bkey] = used + len(sends)

    return JSONResponse(content={"sends": sends, "ctx": replay_tag,
                                 "identity": "anonymous" if body.anonymous else "session"})


# Per-session browser-action budget for /traffic/browser. proxy_brain's
# `redamon.browser` drives a real chromium in the kali sandbox; its page loads
# fan out to sub-requests the /traffic/replay send-budget never sees (they go
# kali -> capture proxy directly), so a separate counter caps browser ACTIONS
# (goto/click/eval). Same in-process single-worker model as _TRAFFIC_REPLAY_SENDS.
_TRAFFIC_BROWSER_ACTIONS: dict[str, int] = {}


def _browser_budget() -> int:
    try:
        return max(1, int(os.environ.get("TRAFFIC_BROWSER_ACTION_BUDGET", "100") or "100"))
    except (TypeError, ValueError):
        return 100


class TrafficBrowserRequest(BaseModel):
    """kali `redamon.browser` -> agent, browser PREPARE. `open` mints one signed
    capture tag pinned to the origin transaction's host; `navigate`/`interact`/
    `eval` enforce the per-session action budget, and `navigate` additionally
    refuses any URL whose host is not the pinned origin host. The kali worker
    holds no signing key, so it can neither forge a tenant nor retarget the pin."""
    ctx: str
    action: str  # open | navigate | interact | eval
    origin_id: str
    url: Optional[str] = None  # navigate only (for the host-pin check)
    anonymous: bool = False    # open only: no session in the browser context


@app.post("/traffic/browser", tags=["Traffic"], dependencies=[Depends(require_internal_auth_only)])
async def traffic_browser(body: TrafficBrowserRequest):
    """Browser PREPARE for the kali `redamon.browser` SDK. Mirrors /traffic/replay:
    validates tenant + phase, re-reads the origin transaction tenant-scoped to pin
    the host, and (for `open`) signs the capture-lineage tag the browser stamps on
    every request. Active navigation is exploitation-phase only and per-session
    action-budgeted, because one proxy_brain run drives many browser actions."""
    claims = _verify_traffic_ctx(body.ctx)
    if not claims:
        return JSONResponse(status_code=401, content={"error": "invalid or missing traffic ctx"})

    # Browsing emits live traffic; confine it to the exploitation phases exactly
    # like /traffic/replay. Fail closed on anything else.
    phase = claims.get("phase") or "informational"
    if phase not in ("exploitation", "post_exploitation"):
        return JSONResponse(status_code=403, content={"error": f"browser not allowed in phase '{phase}'"})

    _apply_traffic_tenant(claims)

    from traffic_tools import fetch_transaction
    txn = await fetch_transaction(str(body.origin_id))
    if not txn:
        return JSONResponse(status_code=404, content={"error": "origin transaction not found (or not in your project)"})
    origin_host = txn.get("host")
    origin_scheme = txn.get("scheme", "http")
    origin_port = txn.get("port")
    _DEFAULT_PORT = {"http": 80, "https": 443}

    # Host-pin: a navigation may only ever land on the ORIGIN transaction's host
    # AND port AND scheme. Hostname alone would let `:8443` or an http->https
    # upgrade reach a DIFFERENT service on the same host, so pin all three exactly
    # like the curl replay path (_origin_url). Sub-resource / redirect egress is
    # contained by the capture proxy's egress guard, not here. Checked BEFORE the
    # budget so a refused nav costs nothing.
    if body.action == "navigate":
        from urllib.parse import urlsplit
        u = urlsplit(str(body.url or ""))
        nav_host = u.hostname
        nav_port = u.port if u.port is not None else _DEFAULT_PORT.get(u.scheme)
        pin_port = origin_port if origin_port is not None else _DEFAULT_PORT.get(origin_scheme)
        if (not nav_host or nav_host != origin_host
                or u.scheme != origin_scheme or nav_port != pin_port):
            return JSONResponse(status_code=400, content={
                "error": (f"browser host pin violated (navigation "
                          f"{u.scheme}://{nav_host}:{nav_port} != pinned "
                          f"{origin_scheme}://{origin_host}:{pin_port})")})
    elif body.action not in ("open", "interact", "eval"):
        return JSONResponse(status_code=400, content={"error": f"unknown browser action {body.action!r}"})

    # Per-session action budget. EVERY action costs one unit, INCLUDING `open`:
    # each open launches a real chromium, so an unbudgeted open would let a loop
    # spawn unbounded browsers and OOM the shared kali container. The get and set
    # have no await between them (single worker), so no lock is needed.
    budget = _browser_budget()
    bkey = claims.get("session_id") or f"{claims['user_id']}:{claims['project_id']}"
    used = _TRAFFIC_BROWSER_ACTIONS.get(bkey, 0)
    if used + 1 > budget:
        return JSONResponse(status_code=429, content={
            "error": f"browser action budget exhausted for this session ({used}/{budget})"})
    _TRAFFIC_BROWSER_ACTIONS[bkey] = used + 1

    if body.action == "open":
        # Sign ONE capture tag for the browser's lifetime. The browser stamps it
        # as X-Redamon-Ctx so every re-captured row is attributed from the VERIFIED
        # tag (tool=proxy_brain_browser), not from anything the target controls.
        try:
            from redamon_ctx import sign_tag
            cap_tag = sign_tag({
                "source": "agent",
                "project_id": claims["project_id"],
                "user_id": claims["user_id"],
                "session_id": claims.get("session_id") or None,
                "tool": "proxy_brain_browser",
                "phase": phase,
                "origin_id": str(body.origin_id),
            }, os.environ.get("INTERNAL_API_KEY", ""))
        except Exception:  # noqa: BLE001
            cap_tag = ""
        # Authenticated identity for the chromium context: the browser is pinned
        # to the origin transaction's host, which _profile_auth_base scope-checks,
        # so the session rides every request the page makes (best-effort, {} when
        # no profile / out of scope). Same write-only channel as the ctx tag.
        auth_headers = {} if body.anonymous else await _profile_auth_base(claims["project_id"], txn)
        return JSONResponse(content={
            "origin_host": origin_host,
            "scheme": origin_scheme,
            "port": origin_port,
            "ctx": cap_tag,
            "auth_headers": auth_headers,
            "identity": "anonymous" if body.anonymous else "session",
        })

    return JSONResponse(content={"ok": True})


# =============================================================================
# KALI TOOLBOX — what this Kali image actually carries, for the inbound MCP
# server (webapp /api/mcp-server -> this endpoint -> kali_toolbox).
# =============================================================================


@app.get(
    "/kali/toolbox",
    tags=["Kali"],
    dependencies=[Depends(require_internal_auth_only)],
)
async def kali_toolbox():
    """The Kali sandbox's installed-tooling catalogue, by category.

    Served from the `kali_shell` TOOL_REGISTRY description, the same bytes this
    agent's own model is prompted with. One source, no second copy: a
    transcription would drift from the image the moment a tool is added, and a
    catalogue that lies about what is installed is worse than none.

    It describes the whole image because the whole image is runnable. kali_exec
    is `bash -c` with no allowlist, at parity with the in-app agent, so unlike
    the previous version there is no second set of "runnable here" to separate
    out - what this lists is what you can run.

    Reads from code only: no container call, no project id, no tenant data. It
    therefore still answers when the kali-sandbox is down, which is the point -
    an agent planning work needs to know what exists before anything can run.
    """
    from prompts.tool_registry import TOOL_REGISTRY

    catalogue = str((TOOL_REGISTRY.get("kali_shell") or {}).get("description") or "").strip()
    if not catalogue:
        # Never an empty string: the caller cannot tell that apart from "this
        # image ships no tools", which is the false negative the MCP surface
        # forbids everywhere else.
        logger.error("Kali toolbox catalogue is empty - TOOL_REGISTRY['kali_shell'] lost its description")
        return JSONResponse(status_code=500, content={"error": "toolbox catalogue unavailable"})
    # The catalogue is written FOR THE IN-APP AGENT, which has dedicated tools
    # (execute_nmap, execute_nuclei, execute_curl ...) alongside kali_shell. It
    # therefore ends by telling the reader NOT to use the shell for those. An
    # MCP caller has no dedicated tools - kali_exec is the only way it runs
    # anything - so that line reads as "do not use the one tool you have".
    # Corrected here rather than by forking the text, which would put a second
    # copy of the catalogue in the codebase.
    note = (
        "\n\n---\n\n"
        "NOTE FOR MCP CALLERS: the line above about preferring dedicated tools "
        "(execute_nmap, execute_nuclei, execute_curl and so on) applies to RedAmon's "
        "IN-APP agent, which has them. You do not. On this surface `kali_exec` is the "
        "only way to run anything, so use it for every tool listed here, including "
        "curl, nmap, nuclei, httpx, ffuf, subfinder, katana and the rest.\n\n"
        "`kali_exec` is `bash -c` with this whole toolset: pipelines, redirection and "
        "shell syntax all work, and there is no allowlist. One command is capped at "
        "300 seconds by the sandbox."
    )
    return JSONResponse(content={"toolbox": catalogue + note})


# =============================================================================
# KALI EXEC — admitted, scope-checked single commands for the inbound MCP
# server. At parity with the in-app agent: no allowlist and no per-command
# target check, so this is transport, job lifecycle and output paging only.
# =============================================================================

# An inline wait long enough for the quick checks (curl, dig, whatweb) to answer
# in one call, short enough that no MCP client's own request timeout is the
# thing that decides. Anything slower becomes a job the caller polls.
KALI_EXEC_DEFAULT_WAIT = 15.0
KALI_EXEC_MAX_WAIT = 60.0
# Per CALL, not per job: the rest is fetched with the returned cursor, so a big
# output is paged rather than truncated. Same rule as the graph tools - nothing
# is ever cut silently.
KALI_EXEC_MAX_OUTPUT_BYTES = 100_000


class KaliExecRequest(BaseModel):
    """webapp MCP -> agent. The tenant is the caller's, already resolved from
    the access token and ownership-checked before this is sent."""
    project_id: str
    command: str
    wait_seconds: float = KALI_EXEC_DEFAULT_WAIT


# A job id reaches a filesystem path, so traversal in it must not. uuid4().hex
# is what JobRegistry.spawn generates, and nothing else is accepted. This is NOT
# part of the removed command guard - it protects the AGENT container from a
# poisoned id, and stays whatever kali_exec is allowed to run.
_KALI_JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _kali_log_path(project_id: str, job_id: str) -> str:
    """Derive the log path from the tenant and job id, SERVER-SIDE.

    Never from the job's own metadata. `JobRegistry.status()` falls back to
    reading `<workspace>/<project>/jobs/<job_id>.meta.json` off disk and returns
    its parsed contents, and kali_exec can write into that same workspace - so
    trusting the `output_path` it carries turned two allowed calls into an
    arbitrary file read on THIS container (INTERNAL_API_KEY, NEO4J_PASSWORD via
    /proc/self/environ). Composing the path here means a poisoned meta file
    cannot redirect the read.
    """
    root = os.environ.get("WORKSPACE_ROOT", "/workspace")
    return os.path.join(root, project_id, "jobs", f"{job_id}.log")


def _kali_read_log(path: str, cursor: int) -> dict:
    """Read forward from a byte offset, reporting where to resume.

    Byte offsets, not lines: the caller resumes exactly where it stopped, and a
    partial read can never be mistaken for the whole output.
    """
    if not path:
        return {"output": "", "next_cursor": cursor, "truncated": False}
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, int(cursor)))
            chunk = fh.read(KALI_EXEC_MAX_OUTPUT_BYTES + 1)
    except FileNotFoundError:
        return {"output": "", "next_cursor": cursor, "truncated": False}
    except OSError as exc:
        logger.error("kali_exec log read failed: %s", exc)
        return {"output": "", "next_cursor": cursor, "truncated": False}

    truncated = len(chunk) > KALI_EXEC_MAX_OUTPUT_BYTES
    chunk = chunk[:KALI_EXEC_MAX_OUTPUT_BYTES]
    return {
        # errors="replace": tool output is bytes from a third-party target and
        # is not guaranteed to be UTF-8. A decode error must not lose the run.
        "output": chunk.decode("utf-8", "replace"),
        "next_cursor": max(0, int(cursor)) + len(chunk),
        "truncated": truncated,
    }


def _kali_lookup_failed(state: dict) -> bool:
    """Did the REGISTRY fail to find this job, as opposed to the job failing?

    JobHandle carries its own `error` field, so a job that ran and failed - a
    tool that exited non-zero, or the 300s kali_shell timeout - comes back as a
    dict with `error` set. Treating any `error` as "not found" reported a real,
    finished run as a job that never existed: the output was unreachable and the
    caller was told the wrong thing. A genuine lookup miss has no job_id,
    because JobRegistry.status() returns a bare {"error": ...} for it.
    """
    return not state.get("job_id")


def _kali_job_view(state: dict, cursor: int, project_id: str, job_id: str) -> dict:
    """The wire shape shared by exec, poll and cancel, so a caller parses one.

    The log path is composed from (project_id, job_id), NOT read from `state`:
    see _kali_log_path.
    """
    view = {
        "job_id": state.get("job_id") or job_id,
        "status": state.get("status"),
        "exit_code": state.get("exit_code"),
        "started_at": state.get("started_at"),
        "ended_at": state.get("ended_at"),
    }
    view.update(_kali_read_log(_kali_log_path(project_id, job_id), cursor))
    # WHY it failed, not just that it did. Without this a timed-out scan is
    # indistinguishable from a scan that ran clean and found nothing.
    if state.get("error"):
        view["error"] = str(state["error"])
    if view["status"] == "cancelled":
        # Honest wording. reg.cancel() cancels the asyncio task awaiting the MCP
        # call; kali_shell is a blocking subprocess.run in the SANDBOX process,
        # and nothing propagates the cancellation to it, so the command itself
        # can keep running against the target for up to its own 300s timeout.
        view["note"] = (
            "Cancelled on RedAmon's side. The sandbox command may still be running at "
            "the target until its own timeout; output after this point is not collected."
        )
    return view


# Master key only. require_internal_auth_only also accepts SCANNER_API_KEY, which
# the kali-sandbox and every spawned scan container hold - the least-trusted
# tier. A leaked scanner token must not be able to run commands, the same
# reasoning that gave /graph/triage the stricter dependency.
@app.post("/kali/exec", tags=["Kali"], dependencies=[Depends(require_master_internal_auth)])
async def kali_exec(body: KaliExecRequest):
    """Run a command in the Kali sandbox and answer with what it produced.

    PARITY WITH THE IN-APP AGENT, BY DECISION. This is `kali_shell`, which is
    `bash -c` with the sandbox's whole toolset: pipelines, redirection, every
    installed binary, no allowlist and no per-command target check. The drawer
    agent has exactly this and no per-command admission either - its own gates
    are a HUMAN clicking the DANGEROUS_TOOLS confirmation, an RoE check that
    matches tool NAMES, and a scope guardrail that runs once per session.

    The confirmation gate cannot apply here because there is no human, so what
    carries the weight instead is who is allowed to reach this endpoint at all:

        1. MCP_KALI_EXEC_ENABLED     operator, per deployment, default on
        2. the `kali:exec` scope     user, password-confirmed at mint time
        3. project.mcpKaliExecEnabled a human in the project form, per
           engagement, and DENIED to update_recon_settings so a token can never
           grant itself this

    A token that holds all three has a shell in a container with NET_ADMIN,
    NET_RAW, seccomp:unconfined and open egress. That is the intended contract.
    """
    if not body.project_id:
        return JSONResponse(status_code=400, content={"error": "project_id is required"})
    if not body.command or not body.command.strip():
        return JSONResponse(status_code=400, content={"error": "a command is required"})
    if not orchestrator or not getattr(orchestrator, "tool_executor", None):
        return JSONResponse(status_code=503, content={"error": "the sandbox is not available"})

    # Verbatim. `kali_shell` hands it to `bash -c`, so quoting it would break
    # every pipeline the caller is now entitled to write.
    safe_command = body.command

    async def runner(name, args, append_log):
        result = await orchestrator.tool_executor.execute(
            name, dict(args, output_mode="inline"), "informational", skip_phase_check=True
        )
        output = result.get("output")
        if output:
            await append_log(str(output))
        # The executor reports success for ANY MCP call that came back with a
        # string, so a tool that exited non-zero - or timed out - arrived here as
        # success and was published with exitCode 0. kali_shell encodes that in
        # its output instead (`_format_subprocess_result`), so it is read back
        # out: a caller told "exit 0" for a failed scan has a false negative.
        text = str(output or "")
        failed = text.startswith("[ERROR]")
        # Output already tee'd: returning it again would have the registry
        # append a second copy under its own "--- final ---" header.
        return {
            "success": bool(result.get("success")) and not failed,
            "output": None,
            "error": result.get("error") or (text[:300] if failed else None),
        }

    reg = job_runner.get_registry()
    spawned = await reg.spawn(
        body.project_id, "kali_shell", {"command": safe_command}, runner,
        label=safe_command.split()[0][:40] if safe_command.split() else "kali_shell",
    )
    if isinstance(spawned, dict) and spawned.get("error"):
        return JSONResponse(status_code=429, content={"error": spawned["error"]})

    job_id = spawned["job_id"]
    wait = max(0.0, min(float(body.wait_seconds or 0), KALI_EXEC_MAX_WAIT))
    state = await reg.wait(body.project_id, job_id, timeout_sec=wait)

    view = _kali_job_view(state, 0, body.project_id, job_id)
    view["command"] = safe_command
    return JSONResponse(content=view)


@app.get("/kali/exec/{job_id}", tags=["Kali"], dependencies=[Depends(require_master_internal_auth)])
async def kali_exec_status(
    job_id: str,
    project_id: str = Query(...),
    cursor: int = Query(0, ge=0),
):
    """Poll a running command and read its output forward from `cursor`."""
    if not _KALI_JOB_ID_RE.match(job_id or ""):
        return JSONResponse(status_code=404, content={"error": "no such command"})
    reg = job_runner.get_registry()
    # status() keys on (project_id, job_id) and reads a per-project directory,
    # so another project's job id resolves to nothing rather than to its output.
    state = reg.status(project_id, job_id)
    if _kali_lookup_failed(state):
        return JSONResponse(status_code=404, content={"error": "no such command"})
    return JSONResponse(content=_kali_job_view(state, cursor, project_id, job_id))


@app.post("/kali/exec/{job_id}/cancel", tags=["Kali"], dependencies=[Depends(require_master_internal_auth)])
async def kali_exec_cancel(job_id: str, project_id: str = Query(...)):
    """Stop a running command. An agent that can start one must be able to."""
    if not _KALI_JOB_ID_RE.match(job_id or ""):
        return JSONResponse(status_code=404, content={"error": "no such command"})
    reg = job_runner.get_registry()
    state = reg.status(project_id, job_id)
    if _kali_lookup_failed(state):
        return JSONResponse(status_code=404, content={"error": "no such command"})
    result = await reg.cancel(project_id, job_id)
    if isinstance(result, dict) and result.get("error"):
        return JSONResponse(status_code=409, content={"error": str(result["error"])})
    return JSONResponse(content=_kali_job_view(reg.status(project_id, job_id), 0, project_id, job_id))


# =============================================================================
# KALI TERMINAL — WebSocket PTY proxy to kali-sandbox terminal server
# =============================================================================

_KALI_TERMINAL_WS_URL = os.environ.get("KALI_TERMINAL_WS_URL", "ws://kali-sandbox:8016")


@app.websocket("/ws/kali-terminal")
async def kali_terminal_proxy(websocket: WebSocket):
    """
    Proxy WebSocket connection to the kali-sandbox PTY terminal server.

    Bridges the browser ↔ agent ↔ kali-sandbox terminal for interactive shell access.

    STRIDE S3: this proxy is the authentication chokepoint. Before accepting the
    handshake or dialing the upstream PTY it requires a valid ws-ticket (query
    param ``ticket``) and a same-origin request. An unset AGENT_WS_TICKET_SECRET
    fails CLOSED (mirrors S2). Identity is taken from the verified claims, never
    from the browser's self-asserted frame, and forwarded to the upstream.
    """
    from ws_ticket import authorize_ws

    # Same-origin + fail-closed ticket gate BEFORE accept()/upstream dial.
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    ticket = websocket.query_params.get("ticket")
    ok, claims, reason = authorize_ws(origin, host, ticket, _cors_origins)
    if not ok:
        logger.warning("Rejected /ws/kali-terminal: %s (origin=%r host=%r)", reason, origin, host)
        await websocket.close(code=1008)
        return

    # Identity from the VERIFIED ticket, forwarded to the upstream PTY as query
    # params (never from the browser's self-asserted frame).
    from urllib.parse import urlencode, urlparse
    _tenant = urlencode({
        "user_id": str(claims["sub"]),
        "project_id": str(claims["pid"]),
        "session_id": str(claims["sid"]),
    })
    _sep = "&" if urlparse(_KALI_TERMINAL_WS_URL).query else "?"
    upstream_url = f"{_KALI_TERMINAL_WS_URL}{_sep}{_tenant}"

    await websocket.accept()

    close_code, close_reason = 1000, ""
    try:
        async with websockets.connect(
            upstream_url,
            ping_interval=30,
            ping_timeout=60,
            max_size=2**20,
        ) as kali_ws:

            async def browser_to_kali():
                try:
                    while True:
                        data = await websocket.receive()
                        if "text" in data:
                            await kali_ws.send(data["text"])
                        elif "bytes" in data:
                            await kali_ws.send(data["bytes"])
                except Exception as e:
                    logger.debug("Browser→Kali stream ended: %s", e)

            async def kali_to_browser():
                try:
                    async for message in kali_ws:
                        if isinstance(message, bytes):
                            await websocket.send_bytes(message)
                        else:
                            await websocket.send_text(message)
                except Exception as e:
                    logger.debug("Kali→Browser stream ended: %s", e)

            upstream = asyncio.create_task(browser_to_kali())
            downstream = asyncio.create_task(kali_to_browser())
            try:
                await asyncio.wait(
                    [upstream, downstream], return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                upstream.cancel()
                downstream.cancel()
                await asyncio.gather(upstream, downstream, return_exceptions=True)

    except Exception as e:
        logger.error("Kali terminal proxy error: %s", e)
        # The class only: the terminal shows the reason, and the text can carry
        # the upstream URL with the tenant ids in its query.
        close_code = 1011
        close_reason = f"Kali sandbox terminal unavailable ({type(e).__name__})"
    finally:
        try:
            await websocket.close(code=close_code, reason=close_reason)
        except Exception:
            pass


@app.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time agent communication.

    Provides bidirectional streaming of:
    - LLM thinking process
    - Tool executions and outputs
    - Phase transitions
    - Approval requests
    - Agent questions
    - Todo list updates

    The client must send an 'init' message first to authenticate the session.
    """
    # Closing before accept() refuses the handshake, which the browser sees as a
    # bare 1006; accepting first lets the code and reason reach the drawer.
    if not orchestrator:
        await websocket.accept()
        await websocket.close(code=1011, reason="Orchestrator not initialized")
        return

    if not ws_manager:
        await websocket.accept()
        await websocket.close(code=1011, reason="WebSocket manager not initialized")
        return

    await websocket_endpoint(websocket, orchestrator, ws_manager)


# =============================================================================
# CYPHERFIX WEBSOCKET ENDPOINTS
# =============================================================================


@app.websocket("/ws/cypherfix-triage")
async def cypherfix_triage_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for CypherFix triage agent.

    Runs vulnerability triage: collects findings from Neo4j graph,
    correlates and prioritizes them, generates remediation items.
    """
    from cypherfix_triage.websocket_handler import handle_triage_websocket
    await handle_triage_websocket(websocket)


@app.websocket("/ws/cypherfix-codefix")
async def cypherfix_codefix_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for CypherFix CodeFix agent.

    Runs automated code remediation: clones repo, explores codebase,
    implements fix, streams diff blocks for review, creates PR.
    """
    from cypherfix_codefix.websocket_handler import handle_codefix_websocket
    await handle_codefix_websocket(websocket)
