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
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

import httpx
import websockets
from fastapi import FastAPI, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel

from logging_config import setup_logging
from orchestrator import AgentOrchestrator
from orchestrator_helpers import normalize_content
from utils import get_session_count
from websocket_api import WebSocketManager, websocket_endpoint

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

    logger.info("Starting RedAmon Agent API...")

    # Initialize orchestrator
    orchestrator = AgentOrchestrator()
    await orchestrator.initialize()

    # Initialize WebSocket manager
    ws_manager = WebSocketManager()

    logger.info("RedAmon Agent API ready (WebSocket)")

    yield

    logger.info("Shutting down RedAmon Agent API...")
    if orchestrator:
        await orchestrator.close()


app = FastAPI(
    title="RedAmon Agent API",
    description="WebSocket API for real-time agent communication with phase tracking, MCP tools, and Neo4j integration",
    version="3.0.0",
    lifespan=lifespan
)

# Add CORS middleware for webapp (allow all origins for development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Must be False when allow_origins is ["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    project_id: str = ""
    user_id: str = ""


@app.post("/guardrail/check-target", tags=["Guardrail"])
async def check_target_guardrail(body: GuardrailRequest):
    """
    Check if a target domain or IP list is safe to scan.

    Two layers:
    1. Hard guardrail (deterministic): always blocks government/public domains.
       Cannot be disabled. Runs first.
    2. Soft guardrail (LLM-based): blocks well-known private companies.
       Fails open if LLM is unavailable.
    """
    from hard_guardrail import is_hard_blocked
    from guardrail import check_target_allowed
    from project_settings import DEFAULT_AGENT_SETTINGS

    # Hard guardrail: deterministic, non-disableable
    if body.target_domain:
        blocked, reason = is_hard_blocked(body.target_domain)
        if blocked:
            return {"allowed": False, "reason": reason, "hard_blocked": True}

    if not orchestrator or not orchestrator._initialized:
        return {"allowed": True, "reason": "Agent not initialized, guardrail skipped"}

    # Ensure LLM is set up
    if not orchestrator.llm:
        if body.project_id:
            try:
                orchestrator._apply_project_settings(body.project_id)
            except Exception as e:
                logger.warning(f"Guardrail: failed to load project settings: {e}")
        # Still no LLM? Bootstrap with default model + user's API keys from DB
        if not orchestrator.llm:
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

                orchestrator.llm = setup_llm(
                    model_name,
                    openai_api_key=(openai_p or {}).get("apiKey"),
                    anthropic_api_key=(anthropic_p or {}).get("apiKey"),
                    openrouter_api_key=(openrouter_p or {}).get("apiKey"),
                )
                orchestrator.model_name = model_name
                logger.info(f"Guardrail: bootstrapped LLM with default model {model_name}")
            except Exception as e:
                logger.warning(f"Guardrail: failed to bootstrap default LLM: {e}")
                return {"allowed": True, "reason": "LLM not configured, guardrail skipped"}

    try:
        result = await check_target_allowed(
            orchestrator.llm,
            target_domain=body.target_domain,
            target_ips=body.target_ips,
        )
        return result
    except Exception as e:
        logger.error(f"Guardrail error: {e}")
        return {"allowed": True, "reason": f"Guardrail error: {str(e)}"}


# =============================================================================
# ROE PARSING — LLM-based extraction of Rules of Engagement from document text
# =============================================================================

class RoeParseRequest(BaseModel):
    """Request model for RoE document parsing."""
    text: str
    model: str | None = None  # Optional: override the LLM model for parsing


_ROE_PARSE_PROMPT = """You are parsing a Rules of Engagement (RoE) document for a penetration testing engagement.
Extract ALL relevant information into the JSON structure below.
Use null for any field not mentioned in the document. Only set values you are confident about.

Return ONLY valid JSON — no markdown, no explanations, no code fences.

{
  "name": "suggested project name based on client/target",
  "description": "brief engagement description",
  "targetDomain": "primary target domain (e.g. devergolabs.com) — just the root domain, no www prefix",
  "targetIps": ["in-scope IPs/CIDRs"],
  "ipMode": false,
  "subdomainList": ["subdomain PREFIXES only, NOT full domains — e.g. 'www', 'api', 'portal', NOT 'www.example.com'"],
  "stealthMode": "ONLY set true if the document EXPLICITLY requires passive-only/no active scanning. Mentions of 'stealth' or 'low-noise' do NOT qualify — those are handled by notes. Default: false",

  "roeClientName": "client organization name",
  "roeClientContactName": "primary client point of contact name",
  "roeClientContactEmail": "client POC email",
  "roeClientContactPhone": "client POC phone",
  "roeEmergencyContact": "who to contact if incident occurs",
  "roeEngagementStartDate": "YYYY-MM-DD",
  "roeEngagementEndDate": "YYYY-MM-DD",
  "roeEngagementType": "external|internal|web_app|api|mobile|physical|social_engineering|red_team",

  "roeExcludedHosts": ["IPs/domains explicitly excluded from testing"],
  "roeExcludedHostReasons": ["reason for each exclusion, parallel array"],

  "roeTimeWindowEnabled": true,
  "roeTimeWindowTimezone": "timezone (e.g. America/New_York, Europe/Rome)",
  "roeTimeWindowDays": ["monday","tuesday"],
  "roeTimeWindowStartTime": "HH:MM",
  "roeTimeWindowEndTime": "HH:MM",

  "roeForbiddenCategories": ["brute_force, dos, social_engineering, physical"],
  "roeMaxSeverityPhase": "informational|exploitation|post_exploitation",
  "agentToolPhaseMap": "ONLY set this if the RoE says something like 'do not use Hydra' or 'tool X is forbidden'. Set the forbidden tool to []. Example: if the RoE says 'Hydra must not be used', return {\"execute_hydra\": []}. 'discouraged' or 'use with caution' does NOT count — only an explicit unconditional ban. Return null if no tool is explicitly banned by name.",
  "roeAllowDos": false,
  "roeAllowSocialEngineering": false,
  "roeAllowPhysicalAccess": false,
  "roeAllowDataExfiltration": false,
  "roeAllowAccountLockout": false,
  "roeAllowProductionTesting": true,

  "roeGlobalMaxRps": 0,

  "roeSensitiveDataHandling": "no_access|prove_access_only|limited_collection|full_access",
  "roeDataRetentionDays": 90,
  "roeRequireDataEncryption": true,

  "roeStatusUpdateFrequency": "daily|weekly|on_finding|none",
  "roeCriticalFindingNotify": true,
  "roeIncidentProcedure": "description of incident response procedure",

  "roeThirdPartyProviders": ["cloud/hosting providers needing separate authorization"],
  "roeComplianceFrameworks": ["PCI-DSS", "HIPAA", "SOC2", "GDPR", "ISO27001"],

  "roeNotes": "any other rules, restrictions, or guidance not captured above",

  "naabuRateLimit": null,
  "nucleiRateLimit": null,
  "katanaRateLimit": null,
  "httpxRateLimit": null,
  "nucleiSeverity": null,
  "scanModules": null
}

IMPORTANT RULES:
- If DoS is prohibited, set roeAllowDos=false AND add "dos" to roeForbiddenCategories
- If social engineering is prohibited, set roeAllowSocialEngineering=false AND add "social_engineering" to roeForbiddenCategories
- If brute force is EXPLICITLY forbidden (not just "discouraged"), add "brute_force" to roeForbiddenCategories AND set execute_hydra to [] in agentToolPhaseMap
- For phase restrictions (e.g. "no post-exploitation", "reconnaissance only"), ONLY set roeMaxSeverityPhase. Do NOT touch agentToolPhaseMap for phase-level restrictions.
- If a global rate limit is specified, also set individual tool rate limits to that value
- Map compliance requirements (PCI, HIPAA, etc.) to roeComplianceFrameworks
- "discouraged", "use with caution", or "avoid unattended use" does NOT mean forbidden. Only disable a tool if the RoE explicitly says "do not use [tool]" or "[tool] is prohibited/forbidden".
- agentToolPhaseMap: Return null unless the RoE explicitly bans a specific tool by name with words like "forbidden", "prohibited", "must not be used", or "not permitted".

RoE Document:
---
{document_text}
---"""


@app.post("/roe/parse", tags=["RoE"])
async def parse_roe_document(body: RoeParseRequest):
    """Parse a Rules of Engagement document using the LLM and extract structured settings."""
    import json as json_mod
    from project_settings import DEFAULT_AGENT_SETTINGS

    if not orchestrator or not orchestrator._initialized:
        return JSONResponse(content={"error": "Agent not initialized"}, status_code=503)

    # Use the requested model, or fall back to orchestrator's current LLM
    from orchestrator_helpers.llm_setup import setup_llm

    requested_model = body.model or DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
    try:
        llm = _setup_llm_for_endpoint(requested_model)
    except Exception as e:
        logger.error(f"RoE parse: failed to set up LLM ({requested_model}): {e}")
        return JSONResponse(content={"error": f"LLM not available for model {requested_model}"}, status_code=503)

    try:
        # System message has instructions only; user document goes in HumanMessage
        # to reduce prompt injection risk from adversarial document content
        system_prompt = _ROE_PARSE_PROMPT.split("RoE Document:\n---")[0].strip()
        doc_text = body.text[:50000]
        logger.info(f"RoE parse: using model {requested_model}")
        response = await llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"RoE Document:\n---\n{doc_text}\n---\n\nParse the RoE document above and return the JSON."),
        ])
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
        return parsed

    except json_mod.JSONDecodeError as e:
        logger.error(f"RoE parse: invalid JSON from LLM: {e}")
        return JSONResponse(
            content={"error": f"LLM returned invalid JSON: {str(e)}"},
            status_code=422,
        )
    except Exception as e:
        logger.error(f"RoE parse error: {e}")
        return JSONResponse(
            content={"error": f"Failed to parse RoE document: {str(e)}"},
            status_code=500,
        )


# =============================================================================
# REPORT SUMMARIZER — LLM-generated narratives for pentest report sections
# =============================================================================

class ReportSummarizeRequest(BaseModel):
    """Request model for report narrative generation."""
    data: dict
    model: str | None = None


@app.post("/api/report/summarize", tags=["Report"])
async def summarize_report(body: ReportSummarizeRequest):
    """Generate LLM narrative summaries for pentest report sections."""
    from report_summarizer import generate_report_narratives
    from project_settings import DEFAULT_AGENT_SETTINGS
    from orchestrator_helpers.llm_setup import setup_llm

    if not orchestrator or not orchestrator._initialized:
        return JSONResponse(content={"error": "Agent not initialized"}, status_code=503)

    requested_model = body.model or DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
    try:
        llm = _setup_llm_for_endpoint(requested_model)
    except Exception as e:
        logger.error(f"Report summarizer: failed to set up LLM ({requested_model}): {e}")
        return JSONResponse(content={"error": f"LLM not available for model {requested_model}"}, status_code=503)

    try:
        narratives = await generate_report_narratives(llm, body.data)
        return narratives
    except Exception as e:
        logger.error(f"Report summarizer error: {e}")
        return JSONResponse(
            content={"error": f"Failed to generate report narratives: {str(e)}"},
            status_code=500,
        )


@app.post("/emergency-stop-all", tags=["System"])
async def emergency_stop_all():
    """Emergency stop: cancel every running agent task immediately."""
    if not ws_manager:
        return JSONResponse(content={"stopped": 0}, status_code=503)
    stopped = await ws_manager.stop_all()
    logger.warning(f"Emergency stop: cancelled {stopped} agent task(s)")
    return {"stopped": stopped}


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
    )


def _setup_llm_for_endpoint(model_name: str) -> "BaseChatModel":
    """Set up an LLM for non-agent endpoints (RoE parse, report summarizer).

    Uses the orchestrator's loaded project settings (user LLM providers from DB).
    """
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from project_settings import get_settings

    settings = get_settings()
    user_providers = settings.get('USER_LLM_PROVIDERS', [])
    custom_config = settings.get('CUSTOM_LLM_CONFIG')

    openai_p = _resolve_provider_key(user_providers, "openai")
    anthropic_p = _resolve_provider_key(user_providers, "anthropic")
    openrouter_p = _resolve_provider_key(user_providers, "openrouter")
    bedrock_p = _resolve_provider_key(user_providers, "bedrock")

    return setup_llm(
        model_name,
        openai_api_key=(openai_p or {}).get("apiKey"),
        anthropic_api_key=(anthropic_p or {}).get("apiKey"),
        openrouter_api_key=(openrouter_p or {}).get("apiKey"),
        aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
        aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
        aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
        custom_llm_config=custom_config,
    )


@app.get("/defaults", tags=["System"])
async def get_defaults():
    """
    Get default agent settings for frontend project creation.

    Returns DEFAULT_AGENT_SETTINGS with camelCase keys prefixed with 'agent'
    for frontend compatibility (e.g., OPENAI_MODEL -> agentOpenaiModel).
    """
    from project_settings import DEFAULT_AGENT_SETTINGS

    def to_camel_case(snake_str: str, prefix: str = "agent") -> str:
        """Convert SCREAMING_SNAKE_CASE to prefixCamelCase."""
        prefixed = f"{prefix}_{snake_str}" if prefix else snake_str
        components = prefixed.lower().split('_')
        return components[0] + ''.join(x.title() for x in components[1:])

    # STEALTH_MODE is a project-level setting (not agent-specific), served by
    # recon defaults as "stealthMode".  Exclude it here to avoid creating a
    # duplicate "agentStealthMode" key that Prisma doesn't recognise.
    SKIP_KEYS = {'STEALTH_MODE', 'USER_ATTACK_SKILLS'}

    # HYDRA_* keys map to Prisma fields without the 'agent' prefix
    # (e.g. HYDRA_ENABLED -> hydraEnabled, not agentHydraEnabled)
    NO_PREFIX_KEYS = {k for k in DEFAULT_AGENT_SETTINGS if k.startswith(('HYDRA_', 'PHISHING_', 'ROE_', 'ATTACK_SKILL_', 'SHODAN_', 'DOS_', 'FIRETEAM_'))}
    # Exclude internal-only fireteam keys that the frontend should not see.
    SKIP_KEYS = SKIP_KEYS | {'PERSISTENT_CHECKPOINTER'}

    camel_case_defaults = {}
    for k, v in DEFAULT_AGENT_SETTINGS.items():
        if k in SKIP_KEYS:
            continue
        if k in NO_PREFIX_KEYS:
            camel_case_defaults[to_camel_case(k, prefix="")] = v
        else:
            camel_case_defaults[to_camel_case(k)] = v

    return camel_case_defaults


@app.get("/models", tags=["System"])
async def get_models(providers: str = Query(default="", description="JSON-encoded list of provider configs from DB")):
    """
    Fetch available AI models from all configured providers.

    When `providers` query param is supplied (JSON list of UserLlmProvider rows),
    uses those configs for discovery. Otherwise falls back to env vars.
    """
    from model_providers import fetch_all_models

    provider_list = None
    if providers:
        import json as json_mod
        try:
            provider_list = json_mod.loads(providers)
        except (json_mod.JSONDecodeError, TypeError):
            logger.warning("Invalid providers JSON in /models request, falling back to env")

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
    from skill_loader import list_skills as _list_skills
    skills = _list_skills()
    return {"skills": skills, "total": len(skills)}


@app.get("/skills/{skill_id:path}", tags=["System"])
async def get_skill_content(skill_id: str):
    """Return full content of a specific skill."""
    from skill_loader import load_skill_content, list_skills as _list_skills
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
    awsRegion: str = "us-east-1"
    awsAccessKeyId: str = ""
    awsSecretKey: str = ""


@app.post("/llm-provider/test", tags=["System"])
async def test_llm_provider(body: LlmProviderTestRequest):
    """Test an LLM provider config by sending a simple message."""
    from orchestrator_helpers.llm_setup import setup_llm

    try:
        ptype = body.providerType

        if ptype == "openai":
            llm = setup_llm("gpt-4o-mini", openai_api_key=body.apiKey)
        elif ptype == "anthropic":
            llm = setup_llm("claude-sonnet-4-20250514", anthropic_api_key=body.apiKey)
        elif ptype == "openrouter":
            llm = setup_llm("openrouter/openai/gpt-4o-mini", openrouter_api_key=body.apiKey)
        elif ptype == "bedrock":
            llm = setup_llm(
                "bedrock/anthropic.claude-3-haiku-20240307-v1:0",
                aws_access_key_id=body.awsAccessKeyId,
                aws_secret_access_key=body.awsSecretKey,
                aws_region=body.awsRegion,
            )
        elif ptype == "openai_compatible":
            from langchain_openai import ChatOpenAI
            kwargs = dict(
                model=body.modelIdentifier or "default",
                api_key=body.apiKey or "ollama",
                temperature=body.temperature,
                max_tokens=body.maxTokens,
            )
            if body.baseUrl:
                kwargs["base_url"] = body.baseUrl
            if body.defaultHeaders:
                kwargs["default_headers"] = body.defaultHeaders
            if body.timeout:
                kwargs["timeout"] = float(body.timeout)
            if not body.sslVerify:
                import httpx
                kwargs["http_client"] = httpx.Client(verify=False)
                kwargs["http_async_client"] = httpx.AsyncClient(verify=False)
            llm = ChatOpenAI(**kwargs)
        else:
            return JSONResponse(
                content={"success": False, "error": f"Unknown provider type: {ptype}"},
                status_code=400,
            )

        response = await llm.ainvoke([HumanMessage(content="Say hello in one sentence.")])
        from orchestrator_helpers import normalize_content
        text = normalize_content(response.content).strip()

        return {"success": True, "response_text": text}

    except Exception as e:
        logger.error(f"LLM provider test failed: {e}")
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=400,
        )


@app.get("/files", tags=["Files"])
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

    if not orchestrator or not orchestrator.tool_executor:
        return Response(content="Agent not initialized", status_code=503)

    try:
        # Check file exists first
        check_result = await orchestrator.tool_executor.execute(
            "kali_shell",
            {"command": f"test -f {normalized} && stat -c '%s' {normalized}"},
            "informational",
            skip_phase_check=True,
        )
        if not check_result.get("success") or not check_result.get("output", "").strip():
            return Response(content="File not found", status_code=404)

        # Read file as base64
        b64_result = await orchestrator.tool_executor.execute(
            "kali_shell",
            {"command": f"base64 -w0 {normalized}"},
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
# COMMAND WHISPERER — NLP-to-command translation using the project's LLM
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


@app.post("/command-whisperer", tags=["Sessions"])
async def command_whisperer(body: CommandWhispererRequest):
    """Translate a natural language request into a shell command using the project's LLM."""
    if not orchestrator or not orchestrator._initialized:
        return JSONResponse(content={"error": "Agent not initialized"}, status_code=503)

    # Ensure LLM is set up for this project
    if not orchestrator.llm:
        try:
            orchestrator._apply_project_settings(body.project_id)
        except Exception as e:
            logger.error(f"Command whisperer LLM setup error: {e}")
            return JSONResponse(
                content={"error": "LLM not configured. Open the AI assistant first or check API keys."},
                status_code=503,
            )

    if not orchestrator.llm:
        return JSONResponse(content={"error": "LLM not available"}, status_code=503)

    try:
        system_prompt = _COMMAND_WHISPERER_SYSTEM_PROMPT.format(
            session_type=body.session_type,
        )
        response = await orchestrator.llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=body.prompt),
        ])

        command = normalize_content(response.content).strip()

        # Strip markdown code fences if the LLM wraps the answer
        if command.startswith("```") and command.endswith("```"):
            command = command[3:-3].strip()
        if command.startswith(("bash\n", "sh\n", "shell\n")):
            command = command.split("\n", 1)[1].strip()

        return {"command": command}

    except Exception as e:
        logger.error(f"Command whisperer error: {e}")
        return JSONResponse(
            content={"error": f"Failed to generate command: {str(e)}"},
            status_code=500,
        )


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


@app.get("/sessions", tags=["Sessions"])
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


@app.post("/sessions/{session_id}/interact", tags=["Sessions"])
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


@app.post("/sessions/{session_id}/kill", tags=["Sessions"])
async def kill_session(session_id: int):
    """Kill a specific Metasploit session."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/sessions/{session_id}/kill")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Session kill proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/jobs/{job_id}/kill", tags=["Sessions"])
async def kill_job(job_id: int):
    """Kill a background Metasploit job."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/jobs/{job_id}/kill")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Job kill proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/session-chat-map", tags=["Sessions"])
async def session_chat_map(body: dict):
    """Register a mapping between a Metasploit session ID and agent chat session ID."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/session-chat-map", json=body)
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Session chat map proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/non-msf-sessions", tags=["Sessions"])
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


@app.post("/text-to-cypher", tags=["Graph"])
async def text_to_cypher(body: TextToCypherRequest):
    """
    Generate a Cypher query from a natural language description.

    Reuses the TEXT_TO_CYPHER_SYSTEM prompt and Neo4jToolManager._generate_cypher()
    so the graph schema is always in sync with the agent's query_graph tool.

    Returns the raw Cypher (without tenant filters) for the webapp to save and execute.
    """
    from tools import Neo4jToolManager
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from project_settings import DEFAULT_AGENT_SETTINGS, fetch_agent_settings
    import requests as _requests

    # 1. Resolve LLM for the user
    llm = None

    # Try to get project-specific model first
    model_name = DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
    try:
        webapp_url = os.environ.get('WEBAPP_API_URL', 'http://webapp:3000')
        settings = fetch_agent_settings(body.project_id, webapp_url)
        if settings and settings.get('OPENAI_MODEL'):
            model_name = settings['OPENAI_MODEL']
    except Exception as e:
        logger.warning(f"text-to-cypher: failed to fetch project settings: {e}")

    # Fetch user's LLM providers for API keys
    user_providers = []
    try:
        webapp_url = os.environ.get('WEBAPP_API_URL', 'http://webapp:3000')
        resp = _requests.get(
            f"{webapp_url.rstrip('/')}/api/users/{body.user_id}/llm-providers?internal=true",
            headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
            timeout=10,
        )
        resp.raise_for_status()
        user_providers = resp.json()
    except Exception as e:
        logger.warning(f"text-to-cypher: failed to fetch user LLM providers: {e}")

    openai_p = _resolve_provider_key(user_providers, "openai")
    anthropic_p = _resolve_provider_key(user_providers, "anthropic")
    openrouter_p = _resolve_provider_key(user_providers, "openrouter")

    try:
        # Check if model uses custom provider config
        if model_name.startswith("custom/"):
            config_id = model_name[len("custom/"):]
            matched = None
            for p in user_providers:
                if p.get("id") == config_id:
                    matched = p
                    break
            if not matched and user_providers:
                matched = user_providers[0]
            if matched:
                llm = setup_llm(model_name, custom_llm_config=matched)
            else:
                return JSONResponse(
                    content={"error": "Custom LLM provider not found. Configure an AI model in settings."},
                    status_code=400,
                )
        else:
            llm = setup_llm(
                model_name,
                openai_api_key=(openai_p or {}).get("apiKey"),
                anthropic_api_key=(anthropic_p or {}).get("apiKey"),
                openrouter_api_key=(openrouter_p or {}).get("apiKey"),
            )
    except Exception as e:
        logger.error(f"text-to-cypher: failed to create LLM: {e}")
        return JSONResponse(
            content={"error": f"Failed to initialize LLM: {str(e)}. Make sure an AI model is configured."},
            status_code=400,
        )

    if not llm:
        return JSONResponse(
            content={"error": "No LLM configured. Configure an AI model in project settings to use graph views."},
            status_code=400,
        )

    # 2. Create Neo4jToolManager and generate Cypher
    neo4j_uri = os.environ.get('NEO4J_URI', 'bolt://neo4j:7687')
    neo4j_user = os.environ.get('NEO4J_USER', 'neo4j')
    neo4j_password = os.environ.get('NEO4J_PASSWORD', 'password')

    manager = Neo4jToolManager(neo4j_uri, neo4j_user, neo4j_password, llm)

    try:
        from langchain_community.graphs import Neo4jGraph
        manager.graph = Neo4jGraph(
            url=neo4j_uri,
            username=neo4j_user,
            password=neo4j_password,
        )
    except Exception as e:
        logger.error(f"text-to-cypher: failed to connect to Neo4j: {e}")
        return JSONResponse(
            content={"error": f"Failed to connect to graph database: {str(e)}"},
            status_code=500,
        )

    # 3. Generate Cypher with retry logic
    last_error = None
    last_cypher = None
    cypher = None
    max_retries = 3

    for attempt in range(max_retries):
        try:
            if attempt == 0:
                cypher = await manager._generate_cypher(body.question, for_graph_view=True)
            else:
                cypher = await manager._generate_cypher(
                    body.question,
                    previous_error=last_error,
                    previous_cypher=last_cypher,
                    for_graph_view=True,
                )

            # Reject write operations -- data filters are read-only
            _upper = cypher.upper()
            _WRITE_KW = ['CREATE', 'MERGE', 'DELETE', 'DETACH', 'SET ', 'REMOVE', 'DROP', 'CALL']
            if any(kw in _upper for kw in _WRITE_KW):
                return JSONResponse(
                    content={"error": "Write operations are not allowed in data filters"},
                    status_code=400,
                )

            # Validate by executing (with tenant filter) to catch syntax errors
            filtered = manager._inject_tenant_filter(cypher, body.user_id, body.project_id)
            manager.graph.query(
                filtered,
                params={
                    "tenant_user_id": body.user_id,
                    "tenant_project_id": body.project_id,
                },
            )

            # Return the raw (un-filtered) Cypher for saving
            return JSONResponse(content={"cypher": cypher})

        except Exception as e:
            last_error = str(e)
            last_cypher = cypher
            logger.warning(f"text-to-cypher attempt {attempt + 1} failed: {last_error}")

            if attempt == max_retries - 1:
                return JSONResponse(
                    content={"error": f"Failed to generate valid Cypher after {max_retries} attempts: {last_error}"},
                    status_code=422,
                )

    return JSONResponse(content={"error": "Unexpected end of retry loop"}, status_code=500)


# =============================================================================
# KALI TERMINAL — WebSocket PTY proxy to kali-sandbox terminal server
# =============================================================================

_KALI_TERMINAL_WS_URL = os.environ.get("KALI_TERMINAL_WS_URL", "ws://kali-sandbox:8016")


@app.websocket("/ws/kali-terminal")
async def kali_terminal_proxy(websocket: WebSocket):
    """
    Proxy WebSocket connection to the kali-sandbox PTY terminal server.

    Bridges the browser ↔ agent ↔ kali-sandbox terminal for interactive shell access.
    """
    await websocket.accept()

    try:
        async with websockets.connect(
            _KALI_TERMINAL_WS_URL,
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
    finally:
        try:
            await websocket.close()
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
    if not orchestrator:
        await websocket.close(code=1011, reason="Orchestrator not initialized")
        return

    if not ws_manager:
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
