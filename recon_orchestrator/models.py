"""
Pydantic models for Recon Orchestrator API
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Union
from pydantic import BaseModel, Field


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
    # Scan Timeline: "new" (the webapp already froze the outgoing graph as a saved
    # version) or "overwrite" (it was discarded). Telemetry/history ONLY — the
    # pipeline behaves identically either way, because a full recon always wipes
    # and rebuilds the live graph. Forwarded to the container as SCAN_MODE.
    mode: Optional[str] = None


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
    # Domain batch: the phases above cycle 1..6 once PER GROUP, so a UI showing
    # only "Phase 3 of 6" looks like it is going backwards. These carry the outer
    # progress so it can read "Group 2/3, Phase 3/6". None outside batch mode.
    current_group: Optional[str] = None
    group_number: Optional[int] = None
    total_groups: Optional[int] = None
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
    # Set only on the line that starts a new Domain-batch group.
    group_number: Optional[int] = None
    total_groups: Optional[int] = None
    current_group: Optional[str] = None
    is_group_start: bool = False


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
    #: Needed by the orchestrator-side ingest backstop, which writes the graph
    #: when the container died before it could (SIGKILL, OOM, crash).
    user_id: Optional[str] = None
    ingested: bool = False
    ingest_attempts: int = 0


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
    """Request to start ONE TruffleHog source.

    `source` is the run key (C3): two runs of the same source are refused, any
    number of distinct sources run in parallel, gated only by the memory
    governor. `config` is the source-specific field set from the scan profile and
    `common` the shared per-project options; neither ever carries a credential —
    those are resolved from UserSettings by the start route and injected as env.
    """
    project_id: str
    user_id: str
    webapp_api_url: str
    source: str
    config: dict = Field(default_factory=dict)
    common: dict = Field(default_factory=dict)
    #: Resolved credential values keyed by UserSettings column name. Server-side
    #: only: the webapp start route reads them, the orchestrator injects the ones
    #: this source needs, and they are never persisted or logged.
    secrets: dict = Field(default_factory=dict)


class TrufflehogState(BaseModel):
    """Current state of ONE TruffleHog source run"""
    project_id: str
    status: TrufflehogStatus
    #: Carried so the clean ingest step knows which tenant to write the findings
    #: under; the dirty container never learns it.
    user_id: str = ""
    #: The source id, which is also the run key. Empty only on a synthetic IDLE.
    source: str = ""
    run_id: str = ""
    target: str = ""
    current_phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    total_phases: int = 3
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    container_id: Optional[str] = None
    #: Set once the clean ingest step has written this run's findings to Neo4j.
    ingested: bool = False
    #: Bounded so a permanently-failing ingest is not retried on every 30 s sweep.
    ingest_attempts: int = 0
    #: True once the finished container has been removed — after which there is
    #: nothing left to ask Docker about this run.
    container_removed: bool = False
    findings_count: int = 0


class TrufflehogListResponse(BaseModel):
    """Every TruffleHog run for a project. The webapp reconcile and the
    activation guard both read this instead of a project-level status, which
    would only ever show one of N parallel runs."""
    project_id: str
    runs: list[TrufflehogState] = Field(default_factory=list)


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
# Supply-Chain Scan Models (L1 "Other Scans")
# =============================================================================
class SupplyChainStatus(str, Enum):
    """Status of a Supply-Chain scan process"""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPING = "stopping"


class SupplyChainStartRequest(BaseModel):
    """Request to start a Supply-Chain scan"""
    project_id: str
    user_id: str
    webapp_api_url: str
    # Scan Queue Phase 6: a supply_chain_repo (org-batch) item targets ONE repo,
    # overriding the project's supply-chain config. Optional; absent for a normal
    # single supply-chain scan.
    repo_override_url: Optional[str] = None
    # Empty/absent = github.com. A GitHub Enterprise host, already allowlisted by
    # the webapp against the operator's configured host.
    repo_override_host: Optional[str] = None
    repo_override_ref: Optional[str] = None
    repo_override_scope: Optional[str] = None
    repo_override_deep: Optional[bool] = None


class GuarddogRequest(BaseModel):
    """Request for a one-shot GuardDog behavioural analysis of one package (L3)."""
    ecosystem: str
    name: str
    version: str = ""


class GuarddogResult(BaseModel):
    """Outcome of a one-shot GuardDog run. `error` set only on dispatch failure."""
    issues: int = 0
    rules_fired: list[str] = []
    errors: list[str] = []
    error: Optional[str] = None


class SupplyChainState(BaseModel):
    """Current state of a Supply-Chain scan process"""
    project_id: str
    status: SupplyChainStatus
    current_phase: Optional[str] = None
    phase_number: Optional[Union[int, float]] = None
    total_phases: int = 1
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    container_id: Optional[str] = None


class SupplyChainLogEvent(BaseModel):
    """A single log line from the Supply-Chain scanner container"""
    log: str
    timestamp: datetime
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
