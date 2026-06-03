"""
Pydantic models for Recon Orchestrator API
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Union
from pydantic import BaseModel


class ReconStatus(str, Enum):
    """Status of a recon process"""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPING = "stopping"


class ReconStartRequest(BaseModel):
    """Request to start a recon process"""
    project_id: str
    user_id: str
    webapp_api_url: str
    delete_graph: bool = False


class CaptureProxyConfig(BaseModel):
    """Optional runtime knobs for the capture proxy, from the Global Settings
    toggle. The image is deliberately NOT here — it stays the trusted orchestrator
    env so the operator toggle can never spawn an arbitrary container image."""
    port: Optional[int] = None
    maxBodyKb: Optional[int] = None
    storeBodies: Optional[bool] = None
    redactSecrets: Optional[bool] = None
    scope: Optional[str] = None
    blockedIps: Optional[str] = None
    # Granular body-storage policy (Global Settings > TrafficMind > Body storage).
    # storeReqBodies/storeRespBodies gate direction; maxStoreMb is a hard drop
    # ceiling; bodyRules is a JSON family->policy map (auto|inline|disk|meta).
    storeReqBodies: Optional[bool] = None
    storeRespBodies: Optional[bool] = None
    maxStoreMb: Optional[int] = None
    bodyRules: Optional[str] = None
    # Egress-guard toggles (Global Settings > TrafficMind). Each defaults to block
    # (True) both here and in the proxy, so omitting any keeps the always-on guard.
    egressBlockEmptyHost: Optional[bool] = None
    egressBlockHardGuardrail: Optional[bool] = None
    egressFailClosed: Optional[bool] = None
    egressBlockUnresolvable: Optional[bool] = None
    egressBlockPrivate: Optional[bool] = None
    egressBlockLoopback: Optional[bool] = None
    egressBlockLinkLocal: Optional[bool] = None
    egressBlockCgnat: Optional[bool] = None
    egressBlockReserved: Optional[bool] = None
    egressBlockMulticast: Optional[bool] = None
    egressBlockUnspecified: Optional[bool] = None


class ReconState(BaseModel):
    """Current state of a recon process"""
    project_id: str
    status: ReconStatus
    current_phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    total_phases: int = 6
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    container_id: Optional[str] = None


class ReconLogEvent(BaseModel):
    """A single log event from recon container"""
    log: str
    timestamp: datetime
    phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    is_phase_start: bool = False
    is_phase_end: bool = False
    level: str = "info"  # info, warning, error, success, action


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    running_recons: int
    running_gvm_scans: int = 0
    running_github_hunts: int = 0
    running_trufflehog_scans: int = 0
    running_ai_attack_scans: int = 0
    gvm_available: bool = False


# =============================================================================
# GVM Vulnerability Scan Models
# =============================================================================


class GvmStatus(str, Enum):
    """Status of a GVM scan process"""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPING = "stopping"


class GvmStartRequest(BaseModel):
    """Request to start a GVM scan"""
    project_id: str
    user_id: str
    webapp_api_url: str


class GvmState(BaseModel):
    """Current state of a GVM scan process"""
    project_id: str
    status: GvmStatus
    current_phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    total_phases: int = 4
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    container_id: Optional[str] = None


class GvmLogEvent(BaseModel):
    """A single log event from GVM scanner container"""
    log: str
    timestamp: datetime
    phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    is_phase_start: bool = False
    is_phase_end: bool = False
    level: str = "info"


# =============================================================================
# GitHub Secret Hunt Models
# =============================================================================


class GithubHuntStatus(str, Enum):
    """Status of a GitHub secret hunt process"""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPING = "stopping"


class GithubHuntStartRequest(BaseModel):
    """Request to start a GitHub secret hunt"""
    project_id: str
    user_id: str
    webapp_api_url: str


class GithubHuntState(BaseModel):
    """Current state of a GitHub secret hunt process"""
    project_id: str
    status: GithubHuntStatus
    current_phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    total_phases: int = 3
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    container_id: Optional[str] = None


class GithubHuntLogEvent(BaseModel):
    """A single log event from GitHub secret hunt container"""
    log: str
    timestamp: datetime
    phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    is_phase_start: bool = False
    is_phase_end: bool = False
    level: str = "info"


# =============================================================================
# TruffleHog Secret Scanner Models
# =============================================================================


class TrufflehogStatus(str, Enum):
    """Status of a TruffleHog scan process"""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPING = "stopping"


class TrufflehogStartRequest(BaseModel):
    """Request to start a TruffleHog scan"""
    project_id: str
    user_id: str
    webapp_api_url: str


class TrufflehogState(BaseModel):
    """Current state of a TruffleHog scan process"""
    project_id: str
    status: TrufflehogStatus
    current_phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    total_phases: int = 3
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    container_id: Optional[str] = None


class TrufflehogLogEvent(BaseModel):
    """A single log event from TruffleHog scanner container"""
    log: str
    timestamp: datetime
    phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    is_phase_start: bool = False
    is_phase_end: bool = False
    level: str = "info"


# =============================================================================
# Partial Recon Models
# =============================================================================


class PartialReconStatus(str, Enum):
    """Status of a partial recon process"""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPING = "stopping"


class PartialReconStartRequest(BaseModel):
    """Request to start a partial recon run for a single tool"""
    project_id: str
    user_id: str
    webapp_api_url: str
    tool_id: str                              # e.g. "SubdomainDiscovery"
    graph_inputs: dict                        # e.g. {"domain": "example.com"}
    user_inputs: list[str] = []               # user-added values (SubdomainDiscovery)
    user_targets: dict | None = None          # structured inputs (Naabu: {subdomains, ips, ip_attach_to})
    include_graph_targets: bool = True        # whether to include existing graph data in scan
    settings_overrides: dict = {}             # optional per-tool settings


class PartialReconState(BaseModel):
    """Current state of a partial recon process"""
    project_id: str
    run_id: str = ""
    tool_id: str = ""
    status: PartialReconStatus = PartialReconStatus.IDLE
    container_id: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    stats: Optional[dict] = None
    # Last Docker-timestamp emitted to any SSE consumer; used as `since=` on
    # reconnect so re-subscribing to the log stream doesn't replay history.
    last_log_timestamp: Optional[datetime] = None


class PartialReconListResponse(BaseModel):
    """Response listing all partial recon runs for a project"""
    project_id: str
    runs: list[PartialReconState]


# =============================================================================
# AI Attack Surface Models
# =============================================================================


class AiAttackSurfaceStatus(str, Enum):
    """Status of an AI Attack Surface scan job"""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPING = "stopping"


class AiAttackSurfaceStartRequest(BaseModel):
    """Request to start an AI Attack Surface job for a single tool"""
    project_id: str
    user_id: str
    webapp_api_url: str = ""
    tool: str = "skeleton"                     # skeleton / garak / pyrit / giskard / promptfoo
    targets: list[dict] = []                   # picker selection: [{baseurl, path, method}]
    bounds: dict = {}                          # {trials, asr_threshold, judge_model, max_turns}
    roe_confirmed: bool = False                # a launch is a confirmed action (§10)
    dry_run: bool = False
    probes: list[str] = []                     # per-tool probe/plugin selection (garak families, etc.)
    strategies: list[str] = []                 # promptfoo: payload-mutation strategies (base64/rot13/...)
    objective: str = ""                        # pyrit: optional custom attack objective (the harmful goal)
    target_model: str = ""                     # model id the target serves (else derived from recon)
    # Free-text description of what the target app does. Shared across tools that
    # generate/grade attacks from app context (giskard description, promptfoo
    # redteam.purpose, pyrit objective framing). Empty -> a generic default.
    target_purpose: str = ""
    # Target authentication (shared across tools): the secret + the header that
    # carries it + an optional scheme prefix (e.g. "Bearer").
    api_key: str = ""
    auth_header: str = ""
    auth_scheme: str = ""


class AiAttackSurfaceState(BaseModel):
    """Current state of an AI Attack Surface scan job"""
    project_id: str
    run_id: str = ""
    tool: str = ""
    status: AiAttackSurfaceStatus = AiAttackSurfaceStatus.IDLE
    current_phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    total_phases: int = 4
    container_id: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    # Whether this job currently holds an Ollama judge lease (ref-counted).
    # Internal bookkeeping so we release exactly once when the job ends.
    llm_leased: bool = False
    # SSE reconnect high-water mark (same role as PartialReconState).
    last_log_timestamp: Optional[datetime] = None


class AiAttackSurfaceLogEvent(BaseModel):
    """A single log event from an AI Attack Surface container"""
    log: str
    timestamp: datetime
    phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    is_phase_start: bool = False
    is_phase_end: bool = False
    level: str = "info"


class AiAttackSurfaceListResponse(BaseModel):
    """Response listing all AI Attack Surface runs for a project"""
    project_id: str
    runs: list[AiAttackSurfaceState]
