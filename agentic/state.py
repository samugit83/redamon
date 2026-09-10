"""
RedAmon Agent State Management

LangGraph state and Pydantic models for the ReAct agent orchestrator.
Supports iterative Thought-Tool-Output pattern with phase tracking.
"""

from typing import Annotated, TypedDict, Optional, List, Literal, Dict
from datetime import datetime, timezone
import uuid

from project_settings import get_setting
from prompt_safety import wrap_untrusted, wrap_untrusted_inline


def utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)

import re
from pydantic import BaseModel, Field, field_validator
from langgraph.graph.message import add_messages


# =============================================================================
# TYPE DEFINITIONS
# =============================================================================

Phase = Literal["informational", "exploitation", "post_exploitation"]
TodoStatus = Literal["pending", "in_progress", "completed", "blocked"]
Priority = Literal["high", "medium", "low"]

# LLM occasionally emits severity-style words ("info", "critical") in the
# todo-item priority slot — observed in a 2026-05-16 think step where
# `priority: "info"` triggered a pydantic retry that cost one LLM round-trip.
# Coerce the common confusables to the canonical 3 values before the Literal
# validator runs, so the parse succeeds on attempt 1.
_PRIORITY_SYNONYMS = {"info": "low", "critical": "high", "urgent": "high"}


def _coerce_priority(value):
    if isinstance(value, str):
        return _PRIORITY_SYNONYMS.get(value.lower().strip(), value)
    return value
ApprovalDecision = Literal["approve", "modify", "abort"]
QuestionFormat = Literal["text", "single_choice", "multi_choice"]

# Attack path types for dynamic routing
# Known types: "cve_exploit", "brute_force_credential_guess", "phishing_social_engineering", "denial_of_service", "sql_injection", "xss", "ssrf", "rce", "path_traversal"
# Unclassified types: "<descriptive_term>-unclassified" (e.g., "file_upload-unclassified", "xxe-unclassified")
AttackPathType = str  # Validated by AttackPathClassification.attack_path_type validator

KNOWN_ATTACK_PATHS = {"cve_exploit", "brute_force_credential_guess", "phishing_social_engineering", "denial_of_service", "sql_injection", "xss", "ssrf", "rce", "path_traversal", "access_control", "xxe", "crypto_attack"}
_UNCLASSIFIED_RE = re.compile(r'^[a-z][a-z0-9_]*-unclassified$')


def is_unclassified_path(attack_path_type: str) -> bool:
    """Check if an attack path type is an unclassified fallback."""
    return attack_path_type.endswith("-unclassified")


def is_valid_attack_path_value(v: str) -> bool:
    """True if v is a legal attack_path_type: a known builtin skill id,
    a 'user_skill:<id>' reference, or a '<term>-unclassified' fallback.

    Shared contract used by both the classifier (AttackPathClassification) and
    the mid-run skill switch (SkillSwitchDecision) so both accept exactly the
    same set of values.
    """
    return (
        v in KNOWN_ATTACK_PATHS
        or v.startswith("user_skill:")
        or bool(_UNCLASSIFIED_RE.match(v))
    )


def evaluate_skill_switch(new_skill, current_skill, enabled_builtins, enabled_user_ids):
    """Pure decision for a switch_skill action (action=switch_skill).

    Kept side-effect-free so it can be unit-tested directly; the think_node
    dispatch branch calls this and then applies the state/message/persistence
    effects. Enforces the SAME enable contract the classifier uses: only an
    ENABLED builtin skill, an ENABLED 'user_skill:<id>', or a '<term>-unclassified'
    fallback may be switched to.

    Args:
        new_skill: requested target attack_path_type (may be None/empty).
        current_skill: the currently-active attack_path_type.
        enabled_builtins: set of enabled builtin skill ids.
        enabled_user_ids: set of enabled user_skill ids (bare ids, no prefix).

    Returns:
        (outcome, resolved_skill) where outcome is one of:
          "switched" — valid new skill different from current; resolved_skill set.
          "noop"     — valid but equal to current; resolved_skill == current.
          "rejected" — missing/disabled/invalid target; resolved_skill is None.
    """
    if not new_skill:
        return ("rejected", None)
    if new_skill.startswith("user_skill:"):
        valid = new_skill.split(":", 1)[1] in (enabled_user_ids or set())
    elif is_unclassified_path(new_skill):
        valid = True
    else:
        valid = new_skill in (enabled_builtins or set())
    if not valid:
        return ("rejected", None)
    if new_skill == current_skill:
        return ("noop", new_skill)
    return ("switched", new_skill)


def should_auto_transition_on_skill(resolved_skill, current_phase):
    """Pure decision for Proposal 1 (behavior-triggered phase switch).

    When the agent switches to an OFFENSIVE attack skill while still in the
    informational phase, the phase should follow what the agent is actually doing
    and move to exploitation — instead of waiting for a separate manual
    `transition_phase` action the agent frequently neglects (observed: a run that
    switched to the SSTI/rce skill repeatedly yet stayed labeled 'informational'
    for 35 iterations, starving the exploitation-gated tree search).

    Returns True iff:
      - resolved_skill is a concrete attack class — truthy and NOT a
        '<term>-unclassified' fallback (switching to "unclassified" is a recon
        decision, not a commitment to exploit), AND
      - current_phase is 'informational' (no-op if already exploiting).

    Side-effect-free for unit testing; the caller still applies the config gate
    (AUTO_TRANSITION_ON_ATTACK_SKILL) and the approval gate
    (REQUIRE_APPROVAL_FOR_EXPLOITATION).
    """
    if not resolved_skill or is_unclassified_path(resolved_skill):
        return False
    return current_phase == "informational"


# =============================================================================
# PYDANTIC MODELS FOR STRUCTURED DATA
# =============================================================================

class TodoItem(BaseModel):
    """LLM-managed task item for tracking progress."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str
    status: TodoStatus = "pending"
    priority: Priority = "medium"
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None

    @field_validator("priority", mode="before")
    @classmethod
    def _coerce_priority_synonyms(cls, v):
        return _coerce_priority(v)

    def mark_complete(self) -> "TodoItem":
        """Mark this todo as completed."""
        return self.model_copy(update={
            "status": "completed",
            "completed_at": utc_now()
        })

    def mark_in_progress(self) -> "TodoItem":
        """Mark this todo as in progress."""
        return self.model_copy(update={"status": "in_progress"})


class ExecutionStep(BaseModel):
    """Single step in the Thought-Tool-Output execution trace."""
    step_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    iteration: int
    timestamp: datetime = Field(default_factory=utc_now)
    phase: Phase

    # Thought (reasoning before action)
    thought: str
    reasoning: str  # Why agent decided to take this action

    # Tool call (if any)
    tool_name: Optional[str] = None
    tool_args: Optional[dict] = None

    # Output (after tool execution)
    tool_output: Optional[str] = None
    output_analysis: Optional[str] = None  # Agent's interpretation of output

    # Status
    success: bool = True
    error_message: Optional[str] = None


class TargetInfo(BaseModel):
    """Accumulated intelligence about the target from graph queries and tools."""
    primary_target: Optional[str] = None  # IP or hostname
    target_type: Optional[Literal["ip", "hostname", "domain", "url"]] = None
    ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)  # CVE IDs or vuln descriptions
    credentials: List[dict] = Field(default_factory=list)  # Discovered credentials
    sessions: List[int] = Field(default_factory=list)  # Metasploit session IDs
    # Session details for richer tracking: {session_id: {'type': str, 'connection': str, 'info': str}}
    session_details: Dict[int, dict] = Field(default_factory=dict)

    def merge_from(self, other: "TargetInfo") -> "TargetInfo":
        """Merge new target info into existing, avoiding duplicates."""
        # Merge session_details, with other taking precedence for existing keys
        merged_session_details = {**self.session_details, **other.session_details}
        return TargetInfo(
            primary_target=other.primary_target or self.primary_target,
            target_type=other.target_type or self.target_type,
            ports=list(set(self.ports + other.ports)),
            services=list(set(self.services + other.services)),
            technologies=list(set(self.technologies + other.technologies)),
            vulnerabilities=list(set(self.vulnerabilities + other.vulnerabilities)),
            credentials=self.credentials + [c for c in other.credentials if c not in self.credentials],
            sessions=list(set(self.sessions + other.sessions)),
            session_details=merged_session_details,
        )


class PhaseTransitionRequest(BaseModel):
    """Request for user approval to transition between phases."""
    from_phase: Phase
    to_phase: Phase
    reason: str
    planned_actions: List[str] = Field(default_factory=list)
    risks: List[str] = Field(default_factory=list)
    requires_approval: bool = True


class PhaseHistoryEntry(BaseModel):
    """Record of a phase transition."""
    phase: Phase
    entered_at: datetime = Field(default_factory=utc_now)
    exited_at: Optional[datetime] = None


class ToolConfirmationRequest(BaseModel):
    """Request for user confirmation before executing dangerous tool(s)."""
    confirmation_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    mode: Literal["single", "plan"]  # single tool or plan wave
    tools: List[dict]  # [{tool_name, tool_args, rationale}]
    reasoning: str
    phase: str
    iteration: int


# =============================================================================
# USER Q&A MODELS
# =============================================================================

class UserQuestionRequest(BaseModel):
    """Request for user clarification from the agent."""
    question_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    question: str  # The question text to display to user
    context: str  # Why the agent needs this information
    format: QuestionFormat = "text"  # How user should respond
    options: List[str] = Field(default_factory=list)  # For choice formats
    default_value: Optional[str] = None  # Suggested default
    phase: Phase = "informational"  # Phase where question was asked


class UserQuestionAnswer(BaseModel):
    """User's answer to an agent question."""
    question_id: str
    answer: str  # The actual answer text
    timestamp: datetime = Field(default_factory=utc_now)


class QAHistoryEntry(BaseModel):
    """Combined Q&A entry for history tracking."""
    question: UserQuestionRequest
    answer: Optional[UserQuestionAnswer] = None
    answered_at: Optional[datetime] = None


# =============================================================================
# CONVERSATION OBJECTIVES (Multi-Objective Support)
# =============================================================================

class ConversationObjective(BaseModel):
    """Single objective within a continuous conversation."""
    objective_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    content: str  # The user's question/request
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    completion_reason: Optional[str] = None
    required_phase: Optional[Phase] = None  # Hint for which phase this needs


class ObjectiveOutcome(BaseModel):
    """Outcome of a completed objective."""
    objective: ConversationObjective
    execution_steps: List[str] = Field(default_factory=list)  # Step IDs from execution_trace
    findings: dict = Field(default_factory=dict)  # Key findings from target_info
    success: bool = True


# =============================================================================
# LLM RESPONSE MODELS (for structured parsing)
# =============================================================================

ActionType = Literal[
    "use_tool", "plan_tools", "transition_phase", "complete", "ask_user",
    "deploy_fireteam", "switch_skill",
]


class PhaseTransitionDecision(BaseModel):
    """Phase transition details from LLM decision."""
    to_phase: Phase
    reason: str = ""
    planned_actions: List[str] = Field(default_factory=list)
    risks: List[str] = Field(default_factory=list)


class UserQuestionDecision(BaseModel):
    """Question details from LLM decision when action=ask_user."""
    question: str
    context: str
    format: QuestionFormat = "text"
    options: List[str] = Field(default_factory=list)
    default_value: Optional[str] = None


class SkillSwitchDecision(BaseModel):
    """Attack-skill switch details from an LLM decision (action=switch_skill).

    Lets the agent rebind attack_path_type mid-run — e.g. once recon reveals the
    real vulnerability class — WITHOUT a phase change or a new objective. The
    system prompt re-selects the skill workflow from attack_path_type on the next
    think iteration, so switching to a skill whose gate tool is available in the
    current phase (xss/ssrf/path_traversal via execute_curl; sql_injection/rce via
    kali_shell) takes effect immediately, even in the informational phase.
    """
    to_skill: str = Field(
        description="New attack_path_type: a known skill id (e.g. 'xss'), "
                    "'user_skill:<id>', or '<term>-unclassified'"
    )
    reason: str = Field(
        default="",
        description="Why the skill is being switched — what live evidence revealed the class"
    )

    @field_validator("to_skill")
    @classmethod
    def _validate_to_skill(cls, v: str) -> str:
        if is_valid_attack_path_value(v):
            return v
        raise ValueError(
            f"to_skill must be a known attack path, 'user_skill:<id>', or "
            f"'<term>-unclassified'. Got: '{v}'"
        )


class TodoItemUpdate(BaseModel):
    """Todo item from LLM response (simplified for updates)."""
    id: Optional[str] = None
    description: str
    status: TodoStatus = "pending"
    priority: Priority = "medium"

    @field_validator("priority", mode="before")
    @classmethod
    def _coerce_priority_synonyms(cls, v):
        return _coerce_priority(v)


class ExtractedTargetInfo(BaseModel):
    """Target information extracted from tool output analysis."""
    primary_target: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    credentials: List[dict] = Field(default_factory=list)
    sessions: List[int] = Field(default_factory=list)


class ChainFindingExtract(BaseModel):
    """Single finding extracted by LLM from tool output for attack chain graph."""
    # Informational: service_identified, vulnerability_confirmed, configuration_found,
    #                exploit_module_found, defense_detected, information_disclosure
    # Goal/outcome:  exploit_success, access_gained, privilege_escalation, credential_found,
    #                data_exfiltration, lateral_movement, persistence_established,
    #                denial_of_service_success, social_engineering_success, remote_code_execution,
    #                session_hijacked
    # Fallback:      custom
    finding_type: str = "custom"
    severity: str = "info"        # critical, high, medium, low, info
    title: str = ""
    evidence: str = ""
    related_cves: List[str] = Field(default_factory=list)
    related_ips: List[str] = Field(default_factory=list)
    confidence: int = 80
    # Member think node stamps this with the producing ReAct iteration so the
    # parent's format_chain_context renders "(step N)" after fireteam roll-up.
    # Without this field declared, Pydantic drops the key when the deploy node
    # rebuilds findings into ChainFindingExtract in _result_from_final_state,
    # and the parent context shows "(step ?)".
    step_iteration: int = 0


class ProductivityVerdict(BaseModel):
    """LLM-emitted verdict on whether the last tool call advanced the engagement.

    Consumed by the orchestrator's loop detector in place of keyword-based
    failure heuristics. The closed `verdict` enum prevents free-form dodging
    and the rationale + what_was_new fields force the model to cite evidence.

    The orchestrator cross-checks `new_information_gained` against actual
    state delta (findings_grew, extracted_info populated) and downgrades
    dishonest claims to `no_progress` before the loop counter consumes it.
    """
    verdict: Literal["new_info", "confirmation", "no_progress", "blocked", "duplicate", "diagnostic_progress"] = "new_info"
    new_information_gained: bool = True
    what_was_new: str = Field(default="", description="One sentence; empty if nothing new.")
    should_repeat_similar_call: bool = False
    rationale: str = Field(default="", description="One sentence citing specific evidence from the output.")


class PerStepAnalysis(BaseModel):
    """Per-step read of a plan_tools wave, used by LATS to score each child
    probe independently (see LATS_integration.md §5.3, §6). Optional: when the
    LLM does not populate it, LATS falls back to the deterministic per-step
    `error_class` stamped by execute_plan_node."""
    step_index: int = 0
    verdict: str = ""            # ProductivityVerdict.verdict for this step
    finding: str = ""            # short description of any finding at this step
    confidence: int = 0          # confidence (0-100) of that finding
    exploit_succeeded: bool = False   # this step reached a foothold (localizes a wave win)
    # W4: app-semantic response class (24-class taxonomy) the LLM assigns to THIS
    # probe's response. LATS maps it to a per-node value + actionable reflection.
    # "inconclusive" (or omitted) => LATS falls back to legacy verdict/error_class
    # scoring. Free-form validation is done in lats._response_class_for (a label
    # outside the 24 is treated as inconclusive), so this stays a str for forward-
    # compatibility rather than a hard Literal that would reject new labels.
    response_class: str = ""


class OutputAnalysisInline(BaseModel):
    """Inline output analysis embedded in LLMDecision when tool output is pending."""
    interpretation: str = ""
    extracted_info: ExtractedTargetInfo = Field(default_factory=ExtractedTargetInfo)
    actionable_findings: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    exploit_succeeded: bool = False
    exploit_details: Optional[dict] = None
    chain_findings: List[ChainFindingExtract] = Field(default_factory=list)
    productivity: ProductivityVerdict = Field(default_factory=ProductivityVerdict)
    # Optional per-step verdicts for a plan_tools wave (LATS wave scoring, §5.3).
    per_step: List[PerStepAnalysis] = Field(default_factory=list)


# =============================================================================
# DEEP THINK MODEL
# =============================================================================

class CompetingHypothesis(BaseModel):
    """One candidate explanation for the current evidence.

    Deep Think MUST emit >=2 of these whenever a chain finding with non-trivial
    confidence is in scope. The point is to force the strategist to articulate
    what ELSE the evidence could mean — and crucially, the single cheapest
    probe that would tell the alternatives apart.

    Without this structure, the model writes a high-confidence finding
    ("NoSQL injection confirmed") on iter 7 from a single 500 differential,
    and every subsequent deep-think starts from that as established fact.
    With it, deep-think becomes a hypothesis-engineering exercise instead
    of a brainstorm.
    """
    hypothesis: str = Field(
        description=(
            "One sentence stating what could explain the current evidence — "
            "e.g., 'NoSQL injection in job_type' or 'SQL parse error from "
            "non-string input crashing sqlite3.execute'."
        )
    )
    supporting_evidence: str = Field(
        description=(
            "Cite the specific observation(s) that support THIS hypothesis. "
            "Reference iteration numbers / step ids where possible."
        )
    )
    disambiguating_probe: str = Field(
        description=(
            "ONE cheap, concrete test that would distinguish this hypothesis "
            "from the OTHER hypotheses in this list. Describe the exact "
            "tool call and what an expected confirming/refuting response looks like."
        )
    )


class DeepThinkResult(BaseModel):
    """Deep Think reasoning output — structured analysis before complex decisions.

    The `competing_hypotheses` field is the structural fix for confirmation
    bias: forcing the strategist to enumerate >=2 explanations for current
    evidence prevents locking onto the first plausible-sounding inference.
    """
    situation_assessment: str = Field(description="Current state summary")
    competing_hypotheses: List[CompetingHypothesis] = Field(
        default_factory=list,
        description=(
            "REQUIRED when any chain finding has confidence >= 60 OR when "
            "trigger_reason is 'Unproductive streak detected'. Provide >=2 "
            "competing explanations and the probe that would tell them apart."
        ),
    )
    attack_vectors_identified: List[str] = Field(default_factory=list, description="All possible attack vectors")
    recommended_approach: str = Field(description="Chosen approach and rationale")
    priority_order: List[str] = Field(default_factory=list, description="Ordered action steps")
    risks_and_mitigations: str = Field(description="Potential risks and how to handle them")


# =============================================================================
# TOOL PLAN MODELS (for parallel tool execution)
# =============================================================================

class ToolPlanStep(BaseModel):
    """Single step in a tool execution plan."""
    tool_name: str
    tool_args: dict = Field(default_factory=dict)
    rationale: str = ""
    # Filled after execution by execute_plan_node:
    tool_output: Optional[str] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None


class ToolPlan(BaseModel):
    """Wave of independent tools to execute in parallel."""
    steps: List[ToolPlanStep]
    plan_rationale: str = ""


# =============================================================================
# FIRETEAM MODELS (multi-agent deployment)
# =============================================================================

FireteamMemberStatus = Literal[
    "running", "success", "partial", "timeout",
    "needs_confirmation", "cancelled", "error",
]


class FireteamMemberSpec(BaseModel):
    """One member in a fireteam deployment plan (emitted by the LLM).

    Note: `max_iterations` is intentionally NOT a field here. ReAct loops
    run until the agent decides `complete` — the operator-facing safety cap
    is set globally via project setting FIRETEAM_MEMBER_MAX_ITERATIONS and
    applied in _build_member_state. Letting the root LLM pre-specify a
    per-member iteration budget in advance is both wasteful (extra tokens
    in the fireteam_plan JSON) and meaningless (the model has no way to
    predict iteration count before the member encounters the target).
    """
    name: str = Field(description="Short human-readable name, shown in UI")
    task: str = Field(description="Task description the member receives as its objective")
    # The member's "primary tools" — names MUST match keys in TOOL_REGISTRY
    # exactly (e.g. "execute_httpx", "execute_curl", "kali_shell",
    # "query_graph"). Tools outside this list are treated as "fallback" and
    # require a tool_expansion_reason on the member's decision.
    tools: List[str] = Field(
        default_factory=list,
        description=(
            "Canonical tool names from TOOL_REGISTRY (e.g. 'execute_httpx', "
            "'execute_curl', 'kali_shell'). These become the member's primary "
            "toolbox; everything else is a 'fallback' that requires "
            "justification when the member calls it."
        ),
    )


class FireteamPlan(BaseModel):
    """A deployment of independent fireteam members to run concurrently."""
    members: List[FireteamMemberSpec] = Field(min_length=1, max_length=8)
    plan_rationale: str
    fireteam_id: Optional[str] = None  # Filled by fireteam_deploy_node


class FireteamMemberResult(BaseModel):
    """Shape returned by each member when its ReAct loop completes."""
    member_id: str
    name: str
    status: FireteamMemberStatus
    completion_reason: str = ""
    iterations_used: int = 0
    tokens_used: int = 0
    input_tokens_used: int = 0
    output_tokens_used: int = 0
    wall_clock_seconds: float = 0.0
    findings: List[ChainFindingExtract] = Field(default_factory=list)
    target_info_delta: dict = Field(default_factory=dict)
    execution_trace_summary: List[dict] = Field(default_factory=list)
    # ID of the member's last-written ChainStep. Findings extracted from this
    # member's run are anchored to this step when persisted to Neo4j — without
    # it they would orphan (no PRODUCED edge). Propagated from the member's
    # FireteamMemberState._last_chain_step_id by _result_from_final_state.
    last_chain_step_id: Optional[str] = None
    # When status == "needs_confirmation"
    pending_confirmation: Optional[dict] = None
    # When status == "error"
    error_message: Optional[str] = None


class FireteamMemberState(TypedDict):
    """Stripped state for the fireteam member graph. NOT a superset of AgentState."""
    messages: Annotated[list, add_messages]
    current_iteration: int
    max_iterations: int
    task_complete: bool
    completion_reason: Optional[str]

    # Read-only inherited from parent
    current_phase: Phase
    attack_path_type: str
    user_id: str
    project_id: str
    session_id: str
    parent_target_info: dict     # snapshot of parent target_info at deploy time
    member_name: str             # for streaming attribution
    member_id: str               # UUID for chain graph and logging
    fireteam_id: str             # fireteam this member belongs to
    tools: List[str]             # primary tool allowlist (canonical TOOL_REGISTRY names)
    task: str                    # member's local objective

    # Member-local
    execution_trace: List[dict]
    target_info: dict
    chain_findings_memory: List[dict]
    chain_failures_memory: List[dict]

    # Parent engagement-state snapshot at deploy time. Populated once by
    # fireteam_deploy_node._build_member_state, then read every iteration by
    # fireteam_member_think_node._build_member_prompt and rendered via
    # format_chain_context (the same renderer the root agent uses). MUST be
    # declared here — LangGraph strips undeclared keys from a TypedDict
    # state on merge, so without these fields the member would never see
    # the root agent's findings/failures/decisions/trace and would appear
    # to start from a cold context (the bug that produced empty
    # "Engagement state" sections in member prompts).
    _parent_chain_findings: List[dict]
    _parent_chain_failures: List[dict]
    _parent_chain_decisions: List[dict]
    _parent_execution_trace: List[dict]

    # Sibling member specs for the same wave, minus this member. Populated once
    # by fireteam_deploy_node._build_member_state from the fireteam plan, then
    # rendered into the system prompt as an "out of scope" block so the LLM
    # knows which surfaces are owned by other members and must not be probed.
    # MUST be declared here (see comment above) — LangGraph strips undeclared
    # keys on merge, so without this field the peer block would always be empty.
    _peer_tasks: List[dict]

    # Soft skill-allowlist accounting (per-run). Incremented inside
    # fireteam_member_think_node whenever the member's decision references a
    # tool outside its declared `tools` (the "fallback toolbox"). Surfaces a
    # graduated nudge in the prompt prefix when it climbs without producing new
    # findings — see _build_member_prompt's `budget_prefix`. Reset implicitly
    # because each member starts with a fresh state.
    fallback_uses_this_run: int

    # Stall detector for the soft allowlist (paired with fallback_uses_this_run).
    # Tracks how many consecutive iterations have produced zero new
    # chain_findings entries. Combined with the fallback counter it powers the
    # "Recommendation: complete" nudge when a member is burning fallback calls
    # without yield.
    iterations_since_new_finding: int

    # Last-seen findings count, snapshotted at end of each iteration. Read at
    # start of next iteration to compute the "did we get new findings?" delta
    # that feeds iterations_since_new_finding.
    last_findings_count: int

    # Tool confirmation escalation (member does not block; parent handles)
    _pending_confirmation: Optional[dict]

    # Parallel tool wave support (reuses execute_plan pattern)
    _current_plan: Optional[dict]

    # Current ExecutionStep (set by member think, read + updated by
    # execute_tool_node, then analyzed on the next think iteration).
    _current_step: Optional[dict]

    # PREVIOUS step snapshot (populated by member think AFTER it analyzes
    # the prev tool's output). emit_streaming_events watches this key to
    # fire fireteam_tool_complete. Without this field being declared on
    # the TypedDict, LangGraph filters the update out on merge and the
    # UI never sees the tool transition from `running` → `success`.
    _completed_step: Optional[dict]

    # Parsed LLMDecision for the current turn.
    _decision: Optional[dict]

    # Raw tool result from execute_tool_node (success, output, error).
    _tool_result: Optional[dict]

    # Last-written ChainStep id so follow-on steps can link via prev_step_id.
    _last_chain_step_id: Optional[str]

    # Always False in members (parent does guardrail check); kept for shape parity.
    _guardrail_blocked: bool

    # Passive observability — tokens_used accumulates per turn for metrics
    # and report display. No enforcement: iteration budget (max_iterations)
    # is the sole cap on member runtime. input/output are broken out from
    # the provider's usage_metadata; tokens_used = input + output.
    tokens_used: int
    input_tokens_used: int
    output_tokens_used: int
    _input_tokens_this_turn: int
    _output_tokens_this_turn: int


class LLMDecision(BaseModel):
    """
    Structured response from the ReAct think node.

    The LLM outputs JSON matching this schema to decide its next action.
    When tool output is pending, also includes output_analysis.
    """
    thought: str = Field(description="Analysis of current situation")
    reasoning: str = Field(description="Why this action was chosen")
    action: ActionType = Field(default="use_tool", description="Type of action to take")

    # Tool execution fields (when action="use_tool")
    tool_name: Optional[str] = Field(default=None, description="Name of tool to execute")
    tool_args: Optional[dict] = Field(default=None, description="Arguments for the tool")

    # Phase transition fields (when action="transition_phase")
    phase_transition: Optional[PhaseTransitionDecision] = Field(default=None)

    # Skill switch fields (when action="switch_skill") — rebind attack_path_type
    # mid-run without changing phase or issuing a new objective.
    skill_switch: Optional[SkillSwitchDecision] = Field(default=None)

    # Completion fields (when action="complete")
    completion_reason: Optional[str] = Field(default=None, description="Why task is complete")

    # User question fields (when action="ask_user")
    user_question: Optional[UserQuestionDecision] = Field(default=None, description="Question to ask user")

    # Todo list updates (always present)
    updated_todo_list: List[TodoItemUpdate] = Field(default_factory=list)

    # Output analysis (only present when analyzing previous tool output)
    output_analysis: Optional[OutputAnalysisInline] = Field(default=None)

    # Tool plan fields (when action="plan_tools")
    tool_plan: Optional[ToolPlan] = Field(default=None, description="Wave of independent tools to execute")

    # Fireteam plan fields (when action="deploy_fireteam")
    fireteam_plan: Optional[FireteamPlan] = Field(
        default=None,
        description="Deployment of independent fireteam members to execute concurrently",
    )

    # Deep Think self-request (only used when Deep Think is enabled)
    need_deep_think: bool = Field(default=False, description="Set to true if you feel stuck or not progressing, to trigger strategic re-evaluation on next iteration")

    # Tool expansion (fireteam members only). When a member's tool call uses a
    # tool outside its declared `tools` list (the "fallback toolbox"), this
    # field MUST carry a one-sentence justification. The validator in
    # fireteam_member_think_node re-prompts the LLM if it reaches for a fallback
    # tool without filling this field. Logged in chain context so the root
    # planner sees which expansions were genuinely useful and can adjust the
    # tools assignment on the next wave. Always None for the root agent.
    tool_expansion_reason: Optional[str] = Field(
        default=None,
        description=(
            "Required ONLY when tool_name (or any plan_tools step's tool_name) "
            "is outside your declared `tools` (primary) list. One sentence "
            "explaining why your primary tools cannot accomplish this step. "
            "If your primary tools CAN do the job, switch to one instead of "
            "filling this field."
        ),
    )


class OutputAnalysis(BaseModel):
    """
    Structured response from analyzing tool output.

    The LLM outputs JSON matching this schema after a tool executes.
    """
    interpretation: str = Field(description="What the output tells us about the target")
    extracted_info: ExtractedTargetInfo = Field(default_factory=ExtractedTargetInfo)
    actionable_findings: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    # LLM-based exploit success detection
    exploit_succeeded: bool = Field(default=False, description="True if this output indicates successful exploitation")
    exploit_details: Optional[dict] = Field(default=None, description="Details about the successful exploit")


class AttackPathClassification(BaseModel):
    """
    LLM classification of attack path type and required phase from user objective.

    Uses structured output for reliable parsing and Pydantic validation.
    Determines BOTH the phase (informational/exploitation) AND the attack path type,
    plus an optional secondary attack path for fallback.
    """
    required_phase: Phase = Field(
        default="informational",
        description="Required phase for this request: 'informational' for recon, 'exploitation' for attacks"
    )
    attack_path_type: str = Field(
        description="The classified attack path type: 'cve_exploit', 'brute_force_credential_guess', 'phishing_social_engineering', 'denial_of_service', 'sql_injection', 'xss', 'ssrf', 'rce', 'path_traversal', 'user_skill:<id>', or '<term>-unclassified'"
    )
    secondary_attack_path: Optional[str] = Field(
        default=None,
        description="Fallback attack path if primary fails (e.g., brute_force after CVE exploit fails). null if no alternative."
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence score for the classification (0.0-1.0)"
    )
    reasoning: str = Field(
        description="Brief explanation of the classification"
    )
    detected_service: Optional[str] = Field(
        default=None,
        description="Specific service detected (ssh, mysql, etc.) for brute_force_credential_guess paths"
    )
    target_host: Optional[str] = Field(
        default=None,
        description="IP or hostname extracted from objective (for graph linking)"
    )
    target_port: Optional[int] = Field(
        default=None,
        description="Port number extracted from objective (for graph linking)"
    )
    target_cves: List[str] = Field(
        default_factory=list,
        description="CVE IDs extracted from objective (for graph linking)"
    )

    @field_validator('attack_path_type')
    @classmethod
    def validate_attack_path_type(cls, v: str) -> str:
        if v in KNOWN_ATTACK_PATHS:
            return v
        if v.startswith("user_skill:"):
            return v
        if _UNCLASSIFIED_RE.match(v):
            return v
        raise ValueError(
            f"attack_path_type must be one of {sorted(KNOWN_ATTACK_PATHS)}, "
            f"'user_skill:<id>', or match '<term>-unclassified' pattern. Got: '{v}'"
        )


# =============================================================================
# LANGGRAPH STATE
# =============================================================================

# =============================================================================
# LATS (Language Agent Tree Search) MODELS
# Bounded, value-guided tree search over executed exploit probes. See
# internal/LATS_integration.md. The whole tree rides inside AgentState as a
# plain dict (_exploit_tree), so the Postgres checkpointer persists it for free.
# =============================================================================

LatsNodeStatus = Literal[
    "proposed",    # candidate edge, not yet executed
    "executing",   # emitted as this iteration's decision, awaiting output
    "evaluated",   # observation scored, value known
    "pruned",      # value below floor or dead-end (WAF/403/rate-limited)
    "terminal",    # exploit_succeeded on this node
]


class ExploitTreeNode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    parent_id: Optional[str] = None
    depth: int = 0

    # The edge that produced this node (None only for the synthetic root).
    tool_name: Optional[str] = None
    tool_args: Optional[dict] = None
    probe_rationale: str = ""           # from the hypothesis / expand step

    # Filled after execution + evaluation.
    observation_summary: str = ""       # compressed tool_output (~200 chars; NOT raw)
    verdict: str = ""                   # ProductivityVerdict.verdict
    error_class: str = ""               # from error_class.py annotation
    response_class: str = ""            # W4: response-semantics discriminator (lead|input_filter|waf_wall|auth_wall|dead_endpoint|benign_app)
    duration_ms: int = 0                # from the executed step
    finding_confidence_delta: int = 0   # confidence of any new ChainFinding at this node
    exploit_succeeded: bool = False
    step_id: Optional[str] = None       # ExecutionStep.step_id; links to execution_trace for raw output

    # Search bookkeeping.
    status: LatsNodeStatus = "proposed"
    value: float = 0.0                  # backprop-aggregated value (higher = closer to foothold)
    local_value: float = 0.0            # this node's own evaluation, pre-aggregation
    visits: int = 0
    reflection: str = ""                # lesson_learned when pruned/failed
    children: List[str] = Field(default_factory=list)


class ExploitTree(BaseModel):
    root_id: str
    nodes: Dict[str, ExploitTreeNode] = Field(default_factory=dict)
    active_node_id: Optional[str] = None   # parent node whose children are the current wave
    rollouts: int = 0                      # completed Select->...->Backprop cycles
    best_terminal_id: Optional[str] = None
    objective: str = ""                    # the exploitation objective this tree serves
    attack_path_type: str = ""             # skill/path at seed time; a switch invalidates the tree (§20.6)
    primary_target: str = ""               # target at seed time; a target change invalidates the tree

    def to_view(self, *, search_id: str, phase: str, shadow_mode: bool,
                max_rollouts: int, max_depth: int,
                best_trajectory: Optional[List[str]] = None) -> dict:
        """UI-facing projection (LatsTreeSnapshot, LATS_integration.md §17.4).
        Raw tool_output is intentionally excluded (size); the inspector fetches
        it from execution_trace via step_id. Runtime context not stored on the
        model (search_id, phase, shadow_mode, budgets, trajectory) is passed in.
        """
        try:
            from project_settings import DANGEROUS_TOOLS
        except Exception:
            DANGEROUS_TOOLS = frozenset()

        def _node_view(n: "ExploitTreeNode") -> dict:
            return {
                "id": n.id,
                "parent_id": n.parent_id,
                "depth": n.depth,
                # Full rationale: the frontend clamps display (outline rows
                # ellipsis, best line 3-line clamp + expand), so don't truncate
                # here or the "best line" gets cut mid-word with no way to see it.
                "label": (n.probe_rationale or n.tool_name or n.id),
                "tool_name": n.tool_name,
                "tool_args": n.tool_args,
                "status": n.status,
                "value": n.value,
                "local_value": n.local_value,
                "visits": n.visits,
                "verdict": n.verdict,
                "error_class": n.error_class,
                "response_class": n.response_class,
                "finding_confidence": n.finding_confidence_delta,
                "exploit_succeeded": n.exploit_succeeded,
                "duration_ms": n.duration_ms,
                "observation": n.observation_summary,
                "reflection": n.reflection,
                "is_dangerous": n.tool_name in DANGEROUS_TOOLS if n.tool_name else False,
                "step_id": n.step_id,
            }

        return {
            "search_id": search_id,
            "objective": self.objective,
            "phase": phase,
            "shadow_mode": shadow_mode,
            "rollouts": self.rollouts,
            "budget": {"max_rollouts": max_rollouts, "max_depth": max_depth},
            "active_id": self.active_node_id,
            "best_trajectory": best_trajectory or [],
            "nodes": [_node_view(n) for n in self.nodes.values()],
        }


class AgentState(TypedDict):
    """
    LangGraph state for the ReAct agent orchestrator.

    This state is maintained in memory via MemorySaver checkpointer.
    All execution history, todos, and phase tracking lives here.
    """
    # Core conversation history (managed by add_messages reducer)
    messages: Annotated[list, add_messages]

    # ReAct loop control
    current_iteration: int
    max_iterations: int
    task_complete: bool
    completion_reason: Optional[str]

    # Phase tracking
    current_phase: Phase
    phase_history: List[dict]  # List of PhaseHistoryEntry.model_dump()
    phase_transition_pending: Optional[dict]  # PhaseTransitionRequest.model_dump() or None

    # Attack path routing
    attack_path_type: str  # AttackPathType: "cve_exploit" or "brute_force_credential_guess"

    # Execution trace (Thought-Tool-Output history)
    execution_trace: List[dict]  # List of ExecutionStep.model_dump()

    # LLM-managed todo list
    todo_list: List[dict]  # List of TodoItem.model_dump()

    # Objectives (multi-objective support)
    conversation_objectives: List[dict]  # List of ConversationObjective.model_dump()
    current_objective_index: int
    objective_history: List[dict]  # List of ObjectiveOutcome.model_dump()
    original_objective: str  # DEPRECATED: kept for backward compatibility

    # Target intelligence accumulated from queries
    target_info: dict  # TargetInfo.model_dump()

    # Session context
    user_id: str
    project_id: str
    session_id: str

    # Approval control
    awaiting_user_approval: bool
    user_approval_response: Optional[ApprovalDecision]
    user_modification: Optional[str]  # User's modification if they chose "modify"

    # User Q&A control
    awaiting_user_question: bool
    pending_question: Optional[dict]  # UserQuestionRequest.model_dump() or None
    user_question_answer: Optional[str]  # User's answer text
    qa_history: List[dict]  # List of QAHistoryEntry.model_dump() for context

    # Tool confirmation control
    awaiting_tool_confirmation: bool
    tool_confirmation_pending: Optional[dict]  # ToolConfirmationRequest.model_dump() or None
    tool_confirmation_response: Optional[str]  # "approve" | "modify" | "reject"
    tool_confirmation_modification: Optional[dict]  # Modified tool args from user
    _reject_tool: bool  # True when user rejected tool (routes to think)
    _tool_confirmation_mode: Optional[str]  # "single" | "plan" — preserved for router after clearing pending

    # Internal fields for inter-node communication (not persisted long-term)
    _current_step: Optional[dict]  # Current ExecutionStep being processed
    _completed_step: Optional[dict]  # Previous step with analysis, for streaming emission
    _decision: Optional[dict]  # LLM decision from think node
    _tool_result: Optional[dict]  # Result from tool execution
    _just_transitioned_to: Optional[str]  # Phase we just transitioned to (prevents re-requesting)
    _redundant_transition_count: int  # Consecutive no-op transition_phase requests to the current phase
    _abort_transition: bool  # True when user aborted a phase transition (routes to generate_response)
    _guardrail_blocked: bool  # True when project target was blocked by the scope guardrail

    # Tool plan execution (parallel wave)
    _current_plan: Optional[dict]  # ToolPlan.model_dump() with results after execution

    # Attack Chain memory (structured LLM context, populated alongside graph writes)
    chain_findings_memory: List[dict]    # Accumulated findings for this session
    chain_failures_memory: List[dict]    # Accumulated failures for this session
    chain_decisions_memory: List[dict]   # Accumulated decisions for this session
    # Wave-completion history (one entry per completed fireteam wave). Written
    # unconditionally by fireteam_collect_node — including for zero-finding
    # waves — so the planner can see "wave X already covered scope Y" even
    # when the wave produced no findings to attribute via source_agent tags.
    chain_waves_memory: List[dict]

    # Internal: previous step ID for NEXT_STEP linking in chain graph
    _last_chain_step_id: Optional[str]

    # Internal: prior chain context string (loaded once at session init)
    _prior_chain_context: Optional[str]

    # Response tier for adaptive formatting ("conversational", "summary", "full_report")
    _response_tier: Optional[str]

    # Deep Think result (persists for chain, replaced on re-trigger)
    deep_think_result: Optional[str]
    _need_deep_think: bool  # LLM self-requested Deep Think for next iteration

    # Productivity scoring v2 — dynamic, multi-signal loop detection.
    # `_deep_think_cooldown_until` suppresses redundant Deep Thinks for N
    # iterations after one fires (override on self-request or critical score).
    # `_iterations_since_state_grew` is an observed counter (incremented every
    # turn, reset whenever target_info / chain_findings_memory grows). It's the
    # most reliable "is the agent stuck" signal because it does not depend on
    # the LLM's self-reported productivity verdict.
    # `_previous_priority_order` lets the orchestrator compare the latest Deep
    # Think's plan against the prior one and reject paraphrased repeats.
    # `tested_axes` is a session-long ledger keyed by semantic axis (per
    # tool-family axis extractor) — addresses the slow-loop case where the same
    # logical attack is retried with bigger N across iterations spaced too far
    # apart for the 6-step verdict window to catch.
    _deep_think_cooldown_until: int  # iteration number; current_iteration < this → suppress
    _iterations_since_state_grew: int
    # `_iterations_since_chain_advance` is the DEPTH counter (Proposal 3): think
    # iterations since the chain last advanced (a confirmed finding / foothold —
    # NOT mere map-growth). Feeds the churn-aware novelty saturation so pure
    # enumeration stops pinning the productivity score to green.
    _iterations_since_chain_advance: int
    # `_diagnostic_progress_streak` counts consecutive stall-counter resets that
    # came from *diagnostic* progress (debugging a failing-but-correct approach)
    # rather than real target-state growth. Capped so diagnostic progress cannot
    # suppress the unproductive streak forever on a dead approach.
    _diagnostic_progress_streak: int
    _previous_priority_order: Optional[List[str]]
    tested_axes: dict  # axis_key (str) -> list of {iteration, verdict, tool} dicts
    _last_productivity_score: Optional[dict]  # diagnostic: last computed score + components

    # Metasploit state tracking
    msf_session_reset_done: bool  # True if metasploit was reset at start of this session

    # LLM token accounting (cumulative across the session, populated from each
    # ainvoke's usage_metadata). Used by the UI to render per-step and
    # cumulative counters. tokens_used = input + output; kept alongside for
    # backwards-compatible reporting.
    input_tokens_used: int
    output_tokens_used: int
    tokens_used: int

    # Per-turn deltas (reset every think iteration). emit_streaming_events
    # picks these up when emitting on_thinking so the UI can render per-step
    # in/out counts. MUST be declared here or LangGraph filters them out of
    # state updates. See FIRETEAM.md §13.3.
    _input_tokens_this_turn: int
    _output_tokens_this_turn: int

    # Fireteam (multi-agent) deployment state
    _current_fireteam_plan: Optional[dict]       # FireteamPlan.model_dump()
    _current_fireteam_results: Optional[list]    # List[FireteamMemberResult.model_dump()]
    _fireteam_id: Optional[str]                  # active fireteam identifier
    _fireteam_start_time: Optional[float]
    _escalated_fireteam_confirmation: Optional[dict]  # pending_confirmation from a member
    _escalated_member_id: Optional[str]
    # Queue of additional pending_confirmation dicts from other members in the
    # same wave. Drained one-at-a-time by fireteam_collect_node /
    # process_fireteam_confirmation_node so each escalation gets its own
    # operator decision. See FIRETEAM.md §20 Q3 ("v1: 3 times").
    _pending_escalations: Optional[list]

    # LATS (Language Agent Tree Search) — bounded exploit-path search.
    # `_exploit_tree` is ExploitTree.model_dump() (or None when LATS inactive);
    # it carries all per-node search state, so no other LATS bookkeeping key is
    # needed. The remaining flags are per-turn signals the LATS hook reads:
    #   `deep_think_ran_this_turn` — think_node's local deep_think_triggered,
    #     the LATS activation pre-gate (NOT Deep Think's output, §20.16).
    #   `guidance_drained_this_turn` — operator guidance was drained this turn,
    #     so LATS should graft it as a high-prior probe (§21.1).
    #   `_lats_operator_stop` / `_lats_refocus_target` — typed operator controls
    #     to stop or refocus a running search (§21.2).
    # ALL must be declared here or LangGraph strips them on merge (§20.1).
    _exploit_tree: Optional[dict]
    deep_think_ran_this_turn: bool
    guidance_drained_this_turn: bool
    _lats_operator_stop: bool
    _lats_refocus_target: Optional[str]
    # Iteration at which the last LATS search archived — persisted so the Fix B2
    # re-activation cooldown survives across turns (else lats_active reads it as
    # None every turn and the cooldown never applies).
    _lats_last_archive_iter: Optional[int]
    # Append-only, capped digest of every finished LATS tree (outcome + best line).
    # Persisted so prior-tree knowledge ACCUMULATES for each subsequent tree,
    # surviving execution_trace's eviction window.
    _lats_tree_digest: Optional[list]

    # Run-level, deduped SEMANTIC cross-tree memory (W7): the confirmed LEADS to
    # build on and the confirmed-DEAD `class @ target` pairs never to re-attempt,
    # MERGED across every finished tree (not N repetitive per-tree blobs). Rendered
    # into each new tree's expansion so the search compounds instead of restarting.
    _lats_leads: Optional[list]
    _lats_dead: Optional[list]

    # Run-level ledger of the EXECUTED probe dedup-keys of every finished LATS
    # tree. The digest above is the human-readable soft hint; this is the HARD
    # cross-tree guarantee — a later tree's expand drops any byte-identical
    # re-run of a probe a prior tree already tried (§3 cross-tree amnesia fix).
    _lats_probe_ledger: Optional[list]

    # Debounce counter for the tree-reset guard: how many CONSECUTIVE turns a
    # reset condition has held. A tree is only torn down once this reaches
    # LATS_RESET_DEBOUNCE, so transient jitter (a one-turn blank/oscillation in
    # phase/skill/target) never falsely resets a healthy tree.
    _lats_reset_streak: Optional[int]


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class InvokeResponse(BaseModel):
    """Response from agent invocation - returned by API."""
    # Core response
    answer: str = Field(default="", description="The agent's final answer or current status")
    tool_used: Optional[str] = Field(default=None, description="Name of the tool executed")
    tool_output: Optional[str] = Field(default=None, description="Raw output from the tool")
    error: Optional[str] = Field(default=None, description="Error message if failed")

    # ReAct state
    current_phase: Phase = Field(default="informational", description="Current agent phase")
    iteration_count: int = Field(default=0, description="Current iteration number")
    task_complete: bool = Field(default=False, description="Whether the task is complete")

    # Todo list for frontend display
    todo_list: List[dict] = Field(default_factory=list, description="Current task breakdown")

    # Execution trace summary (last N steps for context)
    execution_trace_summary: List[dict] = Field(
        default_factory=list,
        description="Summary of recent execution steps"
    )

    # Approval flow
    awaiting_approval: bool = Field(default=False, description="True if waiting for user approval")
    approval_request: Optional[dict] = Field(
        default=None,
        description="Phase transition request details if awaiting approval"
    )

    # Q&A flow
    awaiting_question: bool = Field(default=False, description="True if waiting for user answer")
    question_request: Optional[dict] = Field(
        default=None,
        description="Question request details if awaiting_question is True"
    )

    # Tool confirmation flow
    awaiting_tool_confirmation: bool = Field(default=False, description="True if waiting for tool confirmation")
    tool_confirmation_request: Optional[dict] = Field(
        default=None,
        description="Tool confirmation request details if awaiting_tool_confirmation is True"
    )


class ApprovalRequest(BaseModel):
    """Request model for user approval endpoint."""
    session_id: str
    user_id: str
    project_id: str
    decision: ApprovalDecision
    modification: Optional[str] = None  # User's modification if decision="modify"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_initial_state(
    user_id: str,
    project_id: str,
    session_id: str,
    objective: str,
    max_iterations: int = None
) -> dict:
    """Create initial state for a new agent session."""
    if max_iterations is None:
        max_iterations = get_setting('MAX_ITERATIONS', 100)
    # Create first objective
    first_objective = ConversationObjective(content=objective).model_dump()

    return {
        "messages": [],
        "current_iteration": 0,
        "max_iterations": max_iterations,
        "task_complete": False,
        "completion_reason": None,
        "current_phase": "informational",
        "phase_history": [PhaseHistoryEntry(phase="informational").model_dump()],
        "phase_transition_pending": None,
        "attack_path_type": "",  # Empty until classified by classify_attack_path
        "execution_trace": [],
        "todo_list": [],
        # Multi-objective support
        "conversation_objectives": [first_objective],
        "current_objective_index": 0,
        "objective_history": [],
        "original_objective": objective,  # Kept for backward compatibility
        "target_info": TargetInfo().model_dump(),
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
        "awaiting_user_approval": False,
        "user_approval_response": None,
        "user_modification": None,
        # Q&A fields
        "awaiting_user_question": False,
        "pending_question": None,
        "user_question_answer": None,
        "qa_history": [],
        # Tool confirmation fields
        "awaiting_tool_confirmation": False,
        "tool_confirmation_pending": None,
        "tool_confirmation_response": None,
        "tool_confirmation_modification": None,
        "_reject_tool": False,
        "_tool_confirmation_mode": None,
        # Internal fields
        "_current_step": None,
        "_completed_step": None,
        "_decision": None,
        "_tool_result": None,
        "_just_transitioned_to": None,
        "_redundant_transition_count": 0,
        "_abort_transition": False,
        "_guardrail_blocked": False,
        "_current_plan": None,
        # Attack Chain memory
        "chain_findings_memory": [],
        "chain_failures_memory": [],
        "chain_decisions_memory": [],
        "chain_waves_memory": [],
        "_last_chain_step_id": None,
        "_prior_chain_context": None,
        "_response_tier": None,
        # Deep Think
        "deep_think_result": None,
        "_need_deep_think": False,
        # Productivity scoring v2
        "_deep_think_cooldown_until": 0,
        "_iterations_since_state_grew": 0,
        "_iterations_since_chain_advance": 0,
        "_diagnostic_progress_streak": 0,
        "_previous_priority_order": None,
        "tested_axes": {},
        "_last_productivity_score": None,
        # Metasploit state
        "msf_session_reset_done": False,
        # Fireteam (multi-agent) deployment
        "_current_fireteam_plan": None,
        "_current_fireteam_results": None,
        "_fireteam_id": None,
        "_fireteam_start_time": None,
        "_escalated_fireteam_confirmation": None,
        "_escalated_member_id": None,
        "_pending_escalations": None,
    }


def format_todo_list(todo_list: List[dict]) -> str:
    """Format todo list for display in prompts."""
    if not todo_list:
        return "No tasks defined yet."

    lines = []
    for i, todo in enumerate(todo_list, 1):
        status_icon = {
            "pending": "[ ]",
            "in_progress": "[~]",
            "completed": "[x]",
            "blocked": "[!]"
        }.get(todo.get("status", "pending"), "[ ]")

        priority = todo.get("priority", "medium")
        priority_marker = {"high": "!!!", "medium": "!!", "low": "!"}.get(priority, "!!")

        lines.append(f"{i}. {status_icon} {priority_marker} {todo.get('description', 'No description')}")
        if todo.get("notes"):
            lines.append(f"   Notes: {todo['notes']}")

    return "\n".join(lines)


def format_execution_trace(
    trace: List[dict],
    objectives: List[dict] = None,
    objective_history: List[dict] = None,
    current_objective_index: int = 0,
    last_n: int = None
) -> str:
    """
    Format execution trace with objective grouping.

    Groups steps by objective for better context across multi-objective sessions.
    Uses EXECUTION_TRACE_MEMORY_STEPS from params to control how many steps to show.

    IMPORTANT: This function provides context to the LLM for subsequent decisions.
    Tool outputs must be included so the agent can reference previous results
    (e.g., module paths from 'search CVE-XXX', options from 'info exploit/...').

    Args:
        trace: List of execution step dicts
        objectives: List of conversation objectives
        objective_history: List of completed objective outcomes
        current_objective_index: Index of current objective
        last_n: Override for number of steps (None = use EXECUTION_TRACE_MEMORY_STEPS)
    """
    if not trace:
        return "No steps executed yet."

    # Use configured limit or override
    limit = last_n if last_n is not None else get_setting('EXECUTION_TRACE_MEMORY_STEPS', 100)

    # Apply limit to trace (most recent steps)
    limited_trace = trace[-limit:] if len(trace) > limit else trace

    lines = []

    # If we truncated, show a note
    if len(trace) > limit:
        lines.append(f"[Showing last {limit} of {len(trace)} total steps]")
        lines.append("")

    # Determine which steps are "recent" (last 5) — these get full output
    # Older steps get compact formatting (no raw tool_output, shorter analysis)
    recent_count = 5
    recent_step_ids = set()
    if len(limited_trace) > recent_count:
        for step in limited_trace[-recent_count:]:
            sid = step.get("step_id")
            if sid:
                recent_step_ids.add(sid)
    # If trace is short enough, all steps are recent
    all_recent = len(limited_trace) <= recent_count

    def _is_recent(step):
        if all_recent:
            return True
        return step.get("step_id") in recent_step_ids

    # Build objective boundaries from objective_history
    # Each completed objective in history has 'execution_steps' (step IDs)
    completed_step_ids = set()
    if objective_history:
        for i, outcome in enumerate(objective_history):
            obj = outcome.get("objective", {})
            step_ids = set(outcome.get("execution_steps", []))

            # Find steps belonging to this objective (that are in our limited trace)
            obj_steps = [s for s in limited_trace if s.get("step_id") in step_ids]

            if obj_steps:
                completed_step_ids.update(step_ids)
                lines.append(f"\n{'='*60}")
                lines.append(f"=== OBJECTIVE {i+1}: {obj.get('content', 'Unknown')[:80]}...")
                lines.append(f"=== Status: COMPLETED")
                lines.append(f"{'='*60}\n")

                for step in obj_steps:
                    lines.extend(_format_single_step(step, compact=not _is_recent(step)))

    # Current objective steps (not in completed history)
    current_steps = [s for s in limited_trace if s.get("step_id") not in completed_step_ids]

    if current_steps:
        current_obj_content = "Current objective"
        if objectives and current_objective_index < len(objectives):
            current_obj_content = objectives[current_objective_index].get("content", "Current objective")[:80]

        lines.append(f"\n{'='*60}")
        lines.append(f"=== OBJECTIVE {len(objective_history or []) + 1}: {current_obj_content}...")
        lines.append(f"=== Status: IN PROGRESS")
        lines.append(f"{'='*60}\n")

        for step in current_steps:
            lines.extend(_format_single_step(step, compact=not _is_recent(step)))

    return "\n".join(lines)


def _format_single_step(step: dict, compact: bool = False) -> List[str]:
    """Format a single execution step.

    Args:
        step: Execution step dict.
        compact: If True, omit raw tool_output and truncate analysis to save tokens.
                 Used for older steps where the agent only needs a summary.
    """
    lines = []
    iteration = step.get("iteration", "?")
    phase = step.get("phase", "unknown")
    thought = step.get("thought", "No thought recorded")
    tool = step.get("tool_name", "none")
    tool_args = step.get("tool_args", {})
    success = "OK" if step.get("success", True) else "FAILED"
    error_msg = step.get("error_message")

    lines.append(f"--- Step {iteration} [{phase}] - {success} ---")
    lines.append(f"Thought: {thought[:10000]}..." if len(thought) > 10000 else f"Thought: {thought}")

    if tool and tool != "none":
        lines.append(f"Tool: {tool}")
        if tool_args:
            args_str = str(tool_args)
            max_args = 200 if compact else 10000
            lines.append(f"Args: {args_str[:max_args]}..." if len(args_str) > max_args else f"Args: {args_str}")

        if not compact:
            # Full tool output for recent steps — essential for exploitation workflows
            # where search/info results must be used in subsequent commands
            tool_output = step.get("tool_output", "")
            if tool_output:
                max_output_len = 10000
                if len(tool_output) > max_output_len:
                    # Wrap the untrusted bytes; keep the truncation note as framework text.
                    lines.append("Output (truncated):\n" + wrap_untrusted(tool_output[:max_output_len])
                                 + f"\n[{len(tool_output) - max_output_len} more chars]")
                else:
                    lines.append("Output:\n" + wrap_untrusted(tool_output))

        if step.get("output_analysis"):
            analysis = step["output_analysis"]
            max_analysis = 1000 if compact else 10000
            lines.append(f"Analysis: {analysis[:max_analysis]}..." if len(analysis) > max_analysis else f"Analysis: {analysis}")

    if error_msg:
        lines.append(f"Error: {error_msg}")

    lines.append("")
    return lines


def summarize_trace_for_response(trace: List[dict], last_n: int = None) -> List[dict]:
    """Create a summary of the execution trace for API response."""
    limit = last_n if last_n is not None else get_setting('EXECUTION_TRACE_MEMORY_STEPS', 100)
    recent = trace[-limit:] if len(trace) > limit else trace

    return [
        {
            "iteration": step.get("iteration"),
            "phase": step.get("phase"),
            "thought": step.get("thought", "")[:10000],
            "tool_name": step.get("tool_name"),
            "success": step.get("success", True),
            "output_summary": (step.get("output_analysis") or "")[:10000]
        }
        for step in recent
    ]


def format_qa_history(qa_history: List[dict]) -> str:
    """Format Q&A history for display in prompts."""
    if not qa_history:
        return "No previous questions asked."

    lines = []
    for i, entry in enumerate(qa_history, 1):
        q = entry.get("question", {})
        a = entry.get("answer")

        lines.append(f"Q{i}: {q.get('question', 'Unknown question')}")
        lines.append(f"   Context: {q.get('context', 'No context')}")
        lines.append(f"   Phase: {q.get('phase', 'unknown')}")

        if a:
            lines.append(f"   Answer: {a.get('answer', 'No answer')}")
        else:
            lines.append(f"   Answer: (unanswered)")
        lines.append("")

    return "\n".join(lines)


def format_objective_history(objective_history: List[dict]) -> str:
    """Format completed objectives for display in prompts."""
    if not objective_history:
        return "No previous objectives completed."

    lines = []
    for i, outcome in enumerate(objective_history, 1):
        obj = outcome.get("objective", {})
        lines.append(f"{i}. {obj.get('content', 'Unknown')}")
        lines.append(f"   Status: {'✓ Success' if outcome.get('success') else '✗ Failed'}")

        # Format findings summary
        findings = outcome.get("findings", {})
        vuln_count = len(findings.get("vulnerabilities", []))
        port_count = len(findings.get("ports", []))
        session_count = len(findings.get("sessions", []))

        lines.append(f"   Findings: {vuln_count} vulns, {port_count} ports, {session_count} sessions")
        lines.append("")

    return "\n".join(lines)


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(s: str) -> int:
    return _SEVERITY_ORDER.get((s or "info").lower(), 4)


def _dedup_findings(chain_findings: List[dict]) -> List[dict]:
    """Deduplicate findings by normalized title, keeping earliest occurrence.

    If a later duplicate has higher severity or confidence, upgrade the kept entry.
    """
    seen: dict[str, dict] = {}
    for f in chain_findings:
        raw_title = f.get("title") or f.get("finding_type") or "custom"
        key = raw_title.strip().lower()
        if not key:
            continue
        if key in seen:
            existing = seen[key]
            if _severity_rank(f.get("severity", "info")) < _severity_rank(existing.get("severity", "info")):
                existing["severity"] = f["severity"]
            if (f.get("confidence") or 0) > (existing.get("confidence") or 0):
                existing["confidence"] = f["confidence"]
        else:
            seen[key] = dict(f)
    return list(seen.values())


def _group_trace_by_iteration(execution_trace: List[dict]) -> List[dict]:
    """Group execution_trace entries by iteration number.

    Returns a list of iteration groups, each containing:
      - iteration, phase: from the first entry
      - tools: list of individual tool entries
      - output_analysis: the shared analysis (taken once)
      - is_wave: True if multiple tools ran in this iteration
    """
    from collections import OrderedDict
    groups: OrderedDict[int, dict] = OrderedDict()
    for entry in execution_trace:
        it = entry.get("iteration", 0)
        if it not in groups:
            groups[it] = {
                "iteration": it,
                "phase": entry.get("phase", "?"),
                "tools": [],
                "output_analysis": entry.get("output_analysis", ""),
            }
        groups[it]["tools"].append(entry)
    result = list(groups.values())
    for g in result:
        g["is_wave"] = len(g["tools"]) > 1
    return result


def _format_step_diagnostics(tool_entry: dict) -> str:
    """Build the inline `[12ms, application_5xx_fast: parse-time crash...]`
    diagnostic suffix that follows a tool's args in the chain context.
    Returns empty string when the entry has no diagnostic data (older entries
    without duration_ms / error_class written before this feature shipped —
    backward compatible).

    Surfacing duration alongside the error-class HINT is the cheap fix for
    the "all 12 SQL payloads returned 500" trap: 500-in-3ms and 500-in-150ms
    have the same status code but completely different meanings (parse-time
    crash vs. DB-level error), and the LLM cannot tell them apart from the
    status code alone.

    Format: `[duration, class_label: terse hint]`

    The class LABEL is preserved (engineers grep agent.log for it, and
    programmatic consumers in tests assertIn on it). The HINT is appended
    after a colon so the LLM gets plain English next to the cryptic label.
    Together they cost ~30-80 chars per step, which is acceptable for the
    information density gained.

    Falls back to label-only rendering when no hint is registered for the
    class — defensive, keeps the chain context informative even if a new
    class is added without a matching ERROR_CLASS_HINTS entry.
    """
    from orchestrator_helpers.error_class import ERROR_CLASS_HINTS

    dur = tool_entry.get("duration_ms")
    ec = tool_entry.get("error_class")
    parts: list[str] = []
    if isinstance(dur, (int, float)) and dur >= 0:
        parts.append(f"{int(dur)}ms")
    if ec and ec != "success":
        hint = ERROR_CLASS_HINTS.get(ec)
        if hint:
            parts.append(f"{ec}: {hint}")
        else:
            # Unknown class — show just the label so the chain context still
            # carries the diagnostic, even if the hint registry is stale.
            parts.append(str(ec))
    if not parts:
        return ""
    return f" [{', '.join(parts)}]"


def format_chain_context(
    chain_findings: List[dict],
    chain_failures: List[dict],
    chain_decisions: List[dict],
    execution_trace: List[dict],
    recent_iterations: int = 20,
    chain_waves: Optional[List[dict]] = None,
) -> str:
    """Format attack chain memory for the LLM system prompt.

    Groups tool calls by iteration -- a wave of parallel tools = 1 step.
    Shows the last *recent_iterations* steps with wave tools collapsed
    into a compact summary.  Findings/failures/decisions are listed up
    front for instant signal.

    ``chain_waves`` lists completed fireteam waves (one entry per wave,
    including zero-finding waves). Rendered in its own section so the planner
    can detect "this wave already covered scope X" even when no findings were
    attributed via source_agent.
    """
    chain_waves = chain_waves or []
    if (
        not execution_trace
        and not chain_findings
        and not chain_failures
        and not chain_waves
    ):
        return "No steps executed yet."

    lines: list[str] = []

    # ── Findings ────────────────────────────────────────
    if chain_findings:
        deduped = _dedup_findings(chain_findings)
        deduped.sort(key=lambda f: _severity_rank(f.get("severity", "info")))

        lines.append("── Findings ──────────────────────────────────────")
        for f in deduped:
            sev = (f.get("severity") or "info").upper()
            title = f.get("title") or f.get("finding_type") or "custom"
            step = f.get("step_iteration", "?")
            confidence = f.get("confidence")
            conf_str = f", {confidence}%" if confidence is not None else ""
            # Surface source_agent when present so the LLM can see that a
            # fireteam already covered this ground. Root-agent findings leave
            # source_agent unset — no attribution suffix in that case.
            source_agent = f.get("source_agent")
            source_str = f", from {source_agent}" if source_agent else ""
            lines.append(f"  [{sev}] {title} (step {step}{source_str}{conf_str})")

            evidence = (f.get("evidence") or "").strip()
            if evidence:
                lines.append("    Evidence:\n" + wrap_untrusted(evidence[:10000], "EVIDENCE"))

            cves = f.get("related_cves") or []
            ips = f.get("related_ips") or []
            meta_parts = []
            if cves:
                meta_parts.append(f"CVEs: {', '.join(cves[:5])}")
            if ips:
                meta_parts.append(f"IPs: {', '.join(ips[:5])}")
            if meta_parts:
                lines.append(f"    {' | '.join(meta_parts)}")
        lines.append("")

    # ── Failed Attempts ─────────────────────────────────
    if chain_failures:
        lines.append("── Failed Attempts ───────────────────────────────")
        for fl in chain_failures:
            step = fl.get("step_iteration", "?")
            ftype = fl.get("failure_type") or "error"
            err = fl.get("error_message") or ""
            lesson = fl.get("lesson_learned") or ""
            lines.append(f"  [step {step}] {ftype}: " + wrap_untrusted(err[:300], "TOOL_ERROR"))
            if lesson:
                lines.append(f"           Lesson: {lesson[:300]}")
        lines.append("")

    # ── Decisions ───────────────────────────────────────
    if chain_decisions:
        lines.append("── Decisions ─────────────────────────────────────")
        for d in chain_decisions:
            step = d.get("step_iteration", "?")
            dtype = d.get("decision_type") or "decision"
            from_s = d.get("from_state") or "?"
            to_s = d.get("to_state") or "?"
            approved = "approved" if d.get("approved") else "rejected"
            by = d.get("made_by") or "user"
            lines.append(f"  [step {step}] {dtype}: {from_s} → {to_s} ({by} {approved})")
        lines.append("")

    # ── Fireteam Waves ──────────────────────────────────
    # One entry per completed fireteam wave, including zero-finding waves.
    # The planner consults this to recognize "wave X already covered scope Y"
    # even when no findings were attributed via source_agent tags. Without
    # this section, a zero-finding wave leaves the planner with the same
    # context a brand-new session sees, and the "DO NOT redeploy the same
    # plan" directive in the system prompt has no checkable referent.
    if chain_waves:
        lines.append("── Fireteam Waves ────────────────────────────────")
        for w in chain_waves:
            wave_id = w.get("wave_id") or "?"
            it = w.get("completed_at_iteration", "?")
            n_members = w.get("n_members", 0)
            n_success = w.get("n_success", 0)
            n_timeout = w.get("n_timeout", 0)
            n_error = w.get("n_error", 0)
            total_findings = w.get("total_findings", 0)
            status_parts = [f"{n_success}/{n_members} succeeded"]
            if n_timeout:
                status_parts.append(f"{n_timeout} timed out")
            if n_error:
                status_parts.append(f"{n_error} errored")
            status_parts.append(f"{total_findings} findings")
            lines.append(
                f"  Wave {wave_id} [iter {it}] {', '.join(status_parts)}"
            )
            for m in (w.get("members") or []):
                name = m.get("name") or "(unnamed)"
                task = (m.get("task_summary") or "").strip()
                status = m.get("status") or "unknown"
                iters = m.get("iterations_used", 0)
                f_count = m.get("findings_count", 0)
                reason = (m.get("completion_reason") or "").strip()
                task_str = f" — {task}" if task else ""
                reason_str = f" — {reason}" if reason else ""
                lines.append(
                    f"    - {name}{task_str}: {status}, {iters} iter, "
                    f"{f_count} findings{reason_str}"
                )
        lines.append("")

    # ── Recent Steps (grouped by iteration) ─────────────
    if execution_trace:
        iter_groups = _group_trace_by_iteration(execution_trace)
        total_iterations = len(iter_groups)
        total_tools = len(execution_trace)

        recent = iter_groups[-recent_iterations:]
        older = iter_groups[:-recent_iterations] if total_iterations > recent_iterations else []

        # ── Summary tier for old steps ──
        if older:
            summary_max = 50
            if len(older) > summary_max:
                omitted = len(older) - summary_max
                summary_groups = older[-summary_max:]
                first_shown = summary_groups[0]["iteration"]
                lines.append(
                    f"── Earlier Steps (iterations {first_shown}-{older[-1]['iteration']} summary, "
                    f"{omitted} older omitted -- findings preserved above) ──"
                )
            else:
                summary_groups = older
                lines.append(f"── Earlier Steps (iterations 1-{older[-1]['iteration']} summary) ──")

            for group in summary_groups:
                it = group["iteration"]
                phase_raw = group["phase"] or "?"
                phase = {"informational": "info", "exploitation": "exploit", "post_exploitation": "post-ex"}.get(phase_raw, phase_raw[:6])
                analysis = group["output_analysis"] or ""
                tools = group["tools"]
                any_failed = any(not t.get("success", True) for t in tools)
                fail_marker = " FAILED |" if any_failed else ""
                if group["is_wave"]:
                    tool_counts: dict = {}
                    for t in tools:
                        tname = t.get("tool_name") or "unknown"
                        tool_counts[tname] = tool_counts.get(tname, 0) + 1
                    tool_str = ", ".join(f"{c} {n}" for n, c in tool_counts.items())
                    lines.append(f"  {it} [{phase}]: Wave[{tool_str}] ->{fail_marker} {analysis[:10000]}")
                else:
                    tool_name = tools[0].get("tool_name") or "none"
                    lines.append(f"  {it} [{phase}]: {tool_name} ->{fail_marker} {analysis[:10000]}")
                # A+B: tool digest with args + tiny output fingerprint. Without
                # this, older iterations lose all per-tool detail and the
                # Self-Check duplicate-target rule has nothing to match on.
                digest_parts: list = []
                for t in tools:
                    tname = t.get("tool_name") or "unknown"
                    targs = t.get("tool_args") or {}
                    args_str = str(targs)[:80] if targs else ""
                    entry = f"{tname}({args_str})" if args_str else tname
                    diag = _format_step_diagnostics(t)
                    if diag:
                        entry = f"{entry}{diag}"
                    if t.get("success", True):
                        raw = t.get("tool_output") or t.get("output_summary") or ""
                        if raw:
                            fp = str(raw).replace("\n", " ").strip()[:60]
                            if fp:
                                entry = f"{entry} -> {wrap_untrusted_inline(fp)}"
                    digest_parts.append(entry)
                if digest_parts:
                    lines.append(f"      tools: {'; '.join(digest_parts)}")
            lines.append("")

        if total_iterations > recent_iterations:
            lines.append(
                f"── Recent Steps (last {len(recent)} of {total_iterations} "
                f"iterations, {total_tools} tool calls) ──"
            )
        else:
            lines.append(
                f"── Steps ({total_iterations} iterations, "
                f"{total_tools} tool calls) ──"
            )

        for idx, group in enumerate(recent):
            it = group["iteration"]
            phase = group["phase"]
            tools = group["tools"]
            is_wave = group["is_wave"]
            analysis = group["output_analysis"]
            is_last = idx == len(recent) - 1

            if is_wave:
                # ── Wave: collapse tools into compact summary ──
                tool_counts: dict = {}
                ok_count = 0
                fail_count = 0
                failed_tools: list = []
                # C: per-tool entries carry (args_line, output_preview). The
                # output preview lets the Self-Check duplicate-target rule
                # match prior probes by result, not just by args.
                tool_entries: list = []
                for t in tools:
                    tname = t.get("tool_name") or "unknown"
                    tool_counts[tname] = tool_counts.get(tname, 0) + 1
                    diag = _format_step_diagnostics(t)
                    if t.get("success", True):
                        ok_count += 1
                    else:
                        fail_count += 1
                        # Annotate failed tools with their diagnostic class so
                        # 12 "FAILED" lines aren't all the same to the LLM.
                        ec = t.get("error_class") or ""
                        ec_str = f"[{ec}] " if ec and ec != "success" else ""
                        # error_message can echo target-controlled bytes (a server
                        # banner, an HTTP error body), so wrap it like any tool output.
                        emsg = (t.get('error_message') or '')[:300]
                        emsg_part = wrap_untrusted_inline(emsg, "TOOL_ERROR") if emsg else ""
                        failed_tools.append(f"{tname}{diag}: {ec_str}{emsg_part}")
                    targs = t.get("tool_args") or {}
                    if targs:
                        args_line = f"    - {tname}{diag}: {str(targs)[:300]}"
                        preview = ""
                        if t.get("success", True):
                            raw = t.get("tool_output") or t.get("output_summary") or ""
                            if raw:
                                preview = str(raw).replace("\n", " ").strip()[:200]
                        tool_entries.append((args_line, preview))

                tool_summary = ", ".join(
                    f"{cnt} {name}" for name, cnt in tool_counts.items()
                )
                status = f"{ok_count} OK" + (
                    f", {fail_count} FAILED" if fail_count else ""
                )
                lines.append(
                    f"  Step {it} [{phase}] Wave [{tool_summary}] ({status})"
                )

                # Rationale (from plan_rationale or first tool thought)
                first_thought = tools[0].get("thought") or ""
                if first_thought.startswith("[Wave] "):
                    first_thought = first_thought[7:]
                plan_reasoning = tools[0].get("reasoning") or ""
                rationale = plan_reasoning or first_thought
                if rationale:
                    lines.append(f"    Rationale: {rationale[:400]}")

                # Individual tool args + short output preview. The preview
                # makes prior probes visible to the duplicate-target rule
                # without the LLM having to consult Analysis prose.
                if tool_entries:
                    lines.append("    Tools:")
                    for args_line, preview in tool_entries:
                        lines.append(args_line)
                        if preview:
                            lines.append(f"      -> {wrap_untrusted_inline(preview)}")

                # Failures
                for ft in failed_tools:
                    lines.append(f"    FAILED | {ft}")

                # Analysis (once, not repeated per tool)
                if analysis:
                    lines.append(f"    Analysis: {analysis[:10000]}")

            else:
                # ── Single tool ──
                tool_entry = tools[0]
                tool = tool_entry.get("tool_name") or "none"
                args = tool_entry.get("tool_args") or {}
                success = tool_entry.get("success", True)
                err = tool_entry.get("error_message") or ""
                thought = tool_entry.get("thought", "")
                output = tool_entry.get("tool_output", "")
                diag = _format_step_diagnostics(tool_entry)

                lines.append(f"  Step {it} [{phase}]: {tool}{diag}")
                if thought:
                    lines.append(f"    Thought: {thought[:500]}")
                if args and tool != "none":
                    lines.append(f"    Args: {str(args)[:300]}")
                if success:
                    if analysis:
                        lines.append(f"    OK | {analysis[:10000]}")
                    elif output:
                        lines.append("    OK |\n" + wrap_untrusted(str(output)[:10000]))
                    else:
                        lines.append(f"    OK")
                    # D: when analysis exists AND raw output is non-empty, the
                    # OK line carries the analysis (LLM's interpretation) but
                    # shadows the raw response. Surface a short raw-output
                    # preview separately so the duplicate-target rule sees the
                    # actual probe result, not just the interpretation.
                    if analysis and output:
                        raw_preview = str(output).replace("\n", " ").strip()[:300]
                        if raw_preview:
                            lines.append(f"    Raw: {wrap_untrusted_inline(raw_preview)}")
                else:
                    # Tag the FAILED line with error_class so the LLM
                    # distinguishes a shell-quoting glitch from a real 4xx.
                    ec = tool_entry.get("error_class") or ""
                    ec_str = f"[{ec}] " if ec and ec != "success" else ""
                    # error_message can echo target-controlled bytes — wrap it.
                    err_part = wrap_untrusted_inline(err[:300], "TOOL_ERROR") if err else ""
                    lines.append(f"    FAILED | {ec_str}{err_part}")

            # Full output for the very last iteration's last tool
            if is_last:
                last_output = tools[-1].get("tool_output", "")
                if last_output:
                    max_out = 5000
                    if len(last_output) > max_out:
                        lines.append(
                            "    Output (last tool):\n" + wrap_untrusted(str(last_output)[:max_out]) + "..."
                        )
                    else:
                        lines.append("    Output (last tool):\n" + wrap_untrusted(str(last_output)))

        lines.append("")

    return "\n".join(lines)


def format_prior_chains(prior_chains: List[dict]) -> str:
    """Format prior attack chain summaries for system prompt injection.

    Called once at session init to give the agent cross-session memory.
    """
    if not prior_chains:
        return "No prior sessions."

    lines = ["### Prior Attack Chain History", ""]
    for chain in prior_chains:
        title = chain.get("title") or "Untitled"
        status = chain.get("status") or "unknown"
        total = chain.get("total_steps") or 0
        ok = chain.get("successful_steps") or 0
        fail = chain.get("failed_steps") or 0
        outcome = chain.get("final_outcome") or ""
        phases = chain.get("phases_reached") or []
        atype = chain.get("attack_path_type") or ""

        lines.append(f"**{title}** [{status}] ({atype})")
        lines.append(f"  Steps: {total} total, {ok} OK, {fail} failed | Phases: {', '.join(phases) if phases else 'none'}")
        if outcome:
            lines.append(f"  Outcome: {outcome[:300]}")

        # Key findings
        findings = chain.get("findings") or []
        if findings:
            for f in findings[:5]:
                if f and f.get("title"):
                    lines.append(f"  • [{f.get('severity', 'info').upper()}] {f['title']}")

        # Key lessons from failures
        failures = chain.get("failures") or []
        if failures:
            for fl in failures[:3]:
                if fl and fl.get("lesson"):
                    lines.append(f"  ⚠ Lesson: {fl['lesson'][:200]}")

        lines.append("")

    return "\n".join(lines)


def migrate_legacy_objective(state: dict) -> dict:
    """
    Migrate old original_objective to new conversation_objectives format.

    This ensures backward compatibility with sessions created before multi-objective support.
    """
    if "original_objective" in state and "conversation_objectives" not in state:
        original = state.get("original_objective", "")
        if original:
            state["conversation_objectives"] = [
                ConversationObjective(content=original).model_dump()
            ]
            state["current_objective_index"] = 0
            state["objective_history"] = []
    return state
