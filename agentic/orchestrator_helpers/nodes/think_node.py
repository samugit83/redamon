"""Think node — core ReAct reasoning with LLM decision, output analysis, and chain memory."""

import asyncio
import hashlib
import logging
import time
from uuid import uuid4

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from state import (
    AgentState,
    DeepThinkResult,
    ExecutionStep,
    LLMDecision,
    PhaseHistoryEntry,
    PhaseTransitionRequest,
    TargetInfo,
    ToolConfirmationRequest,
    UserQuestionRequest,
    format_chain_context,
    format_todo_list,
    format_qa_history,
    format_objective_history,
    evaluate_skill_switch,
    should_auto_transition_on_skill,
    utc_now,
)
import orchestrator_helpers.chain_graph_writer as chain_graph
from orchestrator_helpers.agent_context import get_agent_context
from orchestrator_helpers.json_utils import json_dumps_safe, normalize_content
from orchestrator_helpers.parsing import try_parse_llm_decision
from orchestrator_helpers.config import get_identifiers, is_session_config_complete
from orchestrator_helpers.llm_retry import retry_llm_call
from orchestrator_helpers.productivity import (
    audit_productivity_claim,
    axis_key,
    axis_unproductive_count,
    build_productivity_audit_section,
    compute_productivity_score,
    detect_state_growth,
    detect_chain_advance,
    detect_diagnostic_progress,
    update_stall_counters,
    extract_axis,
    priority_order_jaccard,
    record_axis_attempt,
    tier_for_score,
    detect_uniform_response_anomaly,
    downgrade_verdict_to_no_progress,
    is_unproductive,
)
from project_settings import get_setting, get_allowed_tools_for_phase, DANGEROUS_TOOLS, get_enabled_builtin_skills, get_enabled_user_skills

from prompts import (
    REACT_SYSTEM_PROMPT,
    PENDING_OUTPUT_ANALYSIS_SECTION,
    PENDING_PLAN_OUTPUTS_SECTION,
    RESPONSE_CLASS_TAXONOMY_BLOCK,
    DEEP_THINK_PROMPT,
    DEEP_THINK_SECTION,
    DEEP_THINK_SELF_REQUEST_INSTRUCTION,
    get_phase_tools,
    build_phase_definitions,
    build_informational_guidance,
    build_attack_path_behavior,
    build_tool_name_enum,
    build_tool_args_section,
)
from prompts.base import build_fireteam_prompt_fragments, CACHE_PREFIX_END_MARKER
from prompts.classification import build_skill_menu
from prompt_safety import wrap_untrusted
from utils import get_session_config_prompt
from tools import set_tenant_context, set_phase_context, set_graph_view_context

logger = logging.getLogger(__name__)


def _complete_transition_todos(todo_list, to_phase):
    """Mark any open "request transition to <phase>" todo as completed.

    A leftover in-progress transition todo is one of the anchors that keeps the
    model re-requesting a phase change it already completed (the think prompt is
    rebuilt stateless each turn and renders the todo list, so an open transition
    task reads as unfinished work). Scoped narrowly: only todos that clearly
    describe a phase transition are touched.
    """
    out = []
    for item in (todo_list or []):
        d = dict(item) if isinstance(item, dict) else item
        try:
            if isinstance(d, dict):
                desc = (d.get("description", "") or "").lower()
                if (d.get("status") != "completed"
                        and "transition" in desc
                        and ("phase" in desc or str(to_phase) in desc)):
                    d = {**d, "status": "completed"}
        except Exception:
            pass
        out.append(d)
    return out


def _phase_breadcrumb_trace(state, updates, iteration, phase, *, redundant, count=0):
    """Append a phase-change note into execution_trace and return the new list.

    execution_trace is the ONLY channel that reaches the think LLM next turn: the
    node rebuilds a stateless prompt and never replays state["messages"], so the
    AIMessage/HumanMessage nudges elsewhere are invisible to the reasoning model.
    The correction has to live in the trace (rendered as chain_context) to work.
    `count` escalates the wording on repeated no-op requests.
    """
    if redundant:
        if count >= 2:
            analysis = (
                f"STOP RE-REQUESTING THE PHASE. You have asked to transition to "
                f"{phase} {count} times in a row while already in {phase} — this is a "
                f"no-op loop that makes no progress. Your NEXT output MUST be a "
                f"concrete tool call executing the first action from your plan. Do "
                f"NOT emit transition_phase again."
            )
        else:
            analysis = (
                f"You are already in {phase} phase; that transition request was a "
                f"no-op. Do NOT request transition_phase to {phase} again — proceed "
                f"directly to your next concrete step (probe/build/submit your payload)."
            )
        step = ExecutionStep(
            iteration=iteration,
            phase=phase,
            thought=f"Redundant transition_phase to {phase} ignored (already in {phase}).",
            reasoning="Agent re-requested a phase it is already in; no state change.",
            tool_name="phase_transition",
            tool_args={"to_phase": phase, "redundant": True},
            tool_output=f"NO-OP: already in {phase} phase (redundant request #{count}).",
            success=True,
            output_analysis=analysis,
        )
    else:
        step = ExecutionStep(
            iteration=iteration,
            phase=phase,
            thought=f"Phase auto-approved; now operating in {phase} phase.",
            reasoning=f"Transition to {phase} required no approval and was applied.",
            tool_name="phase_transition",
            tool_args={"to_phase": phase},
            tool_output=f"PHASE TRANSITION AUTO-APPROVED. Now operating in {phase} phase.",
            success=True,
            output_analysis=(
                f"You are now in {phase} phase and may use {phase}-specific tools. DO "
                f"NOT request another transition to {phase} - you are already there. "
                f"Proceed directly to the next concrete step (probe/build/submit your "
                f"payload)."
            ),
        )
    base = updates["execution_trace"] if "execution_trace" in updates else state.get("execution_trace", [])
    return base + [step.model_dump()]


async def think_node(state: AgentState, config, *, llm, guidance_queues, neo4j_creds, streaming_callbacks=None, graph_view_cyphers=None) -> dict:
    """
    Core ReAct reasoning node.

    Analyzes previous steps, updates todo list, and decides next action.

    Args:
        state: Current agent state.
        config: LangGraph config with user/project/session identifiers.
        llm: The LLM instance for reasoning.
        guidance_queues: Dict of session_id -> asyncio.Queue for user guidance messages.
        neo4j_creds: Tuple of (neo4j_uri, neo4j_user, neo4j_password).
    """
    user_id, project_id, session_id = get_identifiers(state, config)
    neo4j_uri, neo4j_user, neo4j_password = neo4j_creds

    iteration = state.get("current_iteration", 0) + 1
    phase = state.get("current_phase", "informational")

    # Check if we just transitioned - log and clear the marker
    just_transitioned = state.get("_just_transitioned_to")
    if just_transitioned:
        logger.info(f"[{user_id}/{project_id}/{session_id}] Just transitioned to {just_transitioned}, now in phase: {phase}")

    logger.info(f"[{user_id}/{project_id}/{session_id}] Think node - iteration {iteration}, phase: {phase}")

    # Set context for tools
    set_tenant_context(user_id, project_id)
    set_phase_context(phase)
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    # Get current objective from conversation objectives
    objectives = state.get("conversation_objectives", [])
    current_idx = state.get("current_objective_index", 0)

    if current_idx < len(objectives):
        current_objective = objectives[current_idx].get("content", "No objective specified")
    else:
        # Fallback to original_objective for backward compatibility
        current_objective = state.get("original_objective", "No objective specified")

    # Build the prompt with current state
    chain_context_formatted = format_chain_context(
        chain_findings=state.get("chain_findings_memory", []),
        chain_failures=state.get("chain_failures_memory", []),
        chain_decisions=state.get("chain_decisions_memory", []),
        execution_trace=state.get("execution_trace", []),
        chain_waves=state.get("chain_waves_memory", []),
    )
    todo_list_formatted = format_todo_list(state.get("todo_list", []))
    target_info_formatted = json_dumps_safe(state.get("target_info", {}), indent=2)
    qa_history_formatted = format_qa_history(state.get("qa_history", []))
    objective_history_formatted = format_objective_history(state.get("objective_history", []))

    # ─── Deep Think pre-step (conditional) ────────────────────────────────
    deep_think_result = state.get("deep_think_result")  # existing from prior iterations
    deep_think_triggered = False
    # Deep-think token deltas — initialized unconditionally so the main
    # think-loop can seed its tally from them whether deep-think ran or not.
    _dt_in = 0
    _dt_out = 0
    # Productivity v2 outputs — initialized unconditionally so the final
    # `updates` block can reference them regardless of whether the Deep
    # Think branch ran or which sub-path it took.
    _score_obj = None
    dt_parsed = None
    # Deep Think's hypotheses + attack vectors, exposed to the LATS seed as
    # branching material (NOT its recommended plan). None unless Deep Think fires.
    _lats_dt_hints = None

    trigger_reason = None

    # Compute the productivity score every think turn — used both to
    # decide tier-based Deep Think firing AND to surface diagnostic
    # signals downstream (logged onto state for streaming/debugging).
    _exec_trace = state.get("execution_trace", [])
    _window = int(get_setting('PRODUCTIVITY_AUDIT_WINDOW', 6))
    _threshold = int(get_setting('UNPRODUCTIVE_STREAK_THRESHOLD', 3))
    _score_enabled = bool(get_setting('PRODUCTIVITY_SCORE_ENABLED', True))
    _score_obj = None
    _tier = "green"
    if _score_enabled and _exec_trace:
        try:
            # Churn-aware score (Proposal 3): pass the chain-advance depth counter so
            # pure map-growth enumeration cannot pin the score to green. When the
            # toggle is off, pass 0 (=> novelty_scale 1.0 => legacy behavior).
            _churn_aware = bool(get_setting('PRODUCTIVITY_CHURN_AWARE', True))
            _isca = int(state.get("_iterations_since_chain_advance", 0) or 0) if _churn_aware else 0
            _score_obj = compute_productivity_score(
                execution_trace=_exec_trace,
                tested_axes=state.get("tested_axes", {}),
                iterations_since_state_grew=state.get("_iterations_since_state_grew", 0),
                iteration=iteration,
                max_iterations=state.get("max_iterations", get_setting('MAX_ITERATIONS', 100)),
                phase=phase,
                window=_window,
                iterations_since_chain_advance=_isca,
                novelty_saturation_grace=int(get_setting('PRODUCTIVITY_NOVELTY_SATURATION_GRACE', 3)),
            )
            _tier = tier_for_score(
                _score_obj["score"],
                hint_threshold=float(get_setting('PRODUCTIVITY_SCORE_HINT_THRESHOLD', 3.0)),
                deepthink_threshold=float(get_setting('PRODUCTIVITY_SCORE_DEEPTHINK_THRESHOLD', 5.0)),
                require_pivot_threshold=float(get_setting('PRODUCTIVITY_SCORE_REQUIRE_PIVOT_THRESHOLD', 7.0)),
                block_threshold=float(get_setting('PRODUCTIVITY_SCORE_BLOCK_THRESHOLD', 9.0)),
            )
            _score_obj["tier"] = _tier
            logger.info(
                f"[{user_id}/{project_id}/{session_id}] Productivity score "
                f"{_score_obj['score']} ({_tier}) iter={iteration} "
                f"components={_score_obj['components']}"
            )
        except Exception as _e_score:
            logger.warning(f"productivity score compute failed: {_e_score}")
            _score_obj = None

    # Condition 1: phase transition just happened
    if just_transitioned:
        trigger_reason = f"Phase transition to {just_transitioned} — re-evaluating strategy"

    # Condition 2: continuous score crosses Deep Think threshold (subject
    # to cooldown to avoid Deep-Think-every-turn loops).
    # When the score path is disabled, fall back to the legacy 3/6 verdict
    # counter so behaviour is backward-compatible.
    _cooldown_until = int(state.get("_deep_think_cooldown_until", 0) or 0)
    _cooldown_active = iteration < _cooldown_until
    _critical_override = _score_obj and _score_obj["score"] >= float(
        get_setting('PRODUCTIVITY_SCORE_BLOCK_THRESHOLD', 9.0)
    )
    _stall_override = (
        state.get("_iterations_since_state_grew", 0)
        >= int(get_setting('STATE_GROWTH_HARD_THRESHOLD', 10))
    )

    if not trigger_reason and _score_enabled and _score_obj is not None:
        if _tier in ("orange", "red", "critical") and (
            not _cooldown_active or _critical_override or _stall_override
        ):
            trigger_reason = (
                f"Productivity tier '{_tier}' (score {_score_obj['score']}) — "
                f"components: {_score_obj['components']}"
            )
    elif not trigger_reason and len(_exec_trace) >= _threshold:
        # Legacy fallback: 3/6 verdict counter
        _unproductive_count = 0
        for _step in _exec_trace[-_window:]:
            _out = ((_step.get("tool_output") or "")[:500]).lower()
            _is_keyword_fail = (
                not _step.get("success", True)
                or "failed" in _out
                or "error" in _out
                or "exploit completed, but no session" in _out
            )
            if _is_keyword_fail or is_unproductive(_step):
                _unproductive_count += 1
        if _unproductive_count >= _threshold and not _cooldown_active:
            trigger_reason = (
                f"Unproductive streak detected ({_unproductive_count}/{_window} "
                f"recent steps yielded no_progress / duplicate / blocked / failure) "
                f"— pivoting strategy"
            )

    # Condition 3: LLM self-requested deep think on previous iteration
    # — ALWAYS bypasses cooldown (agent should be able to ask for help)
    if not trigger_reason and state.get("_need_deep_think", False):
        trigger_reason = "Agent self-assessed stagnation — strategic re-evaluation requested"

    # Fix C: while a LATS tree is live AND driving (non-shadow), LATS owns
    # strategy for these turns — its own tree search IS the re-planning Deep
    # Think would do. Suppress Deep Think so the failing probes it issues cannot
    # pin productivity 'critical' and bypass the cooldown into a Deep-Think-
    # every-turn loop (double meta-reasoning whose output LATS overrides anyway).
    # Deep Think resumes once LATS archives — now informed by the tree summary
    # LATS carries into execution_trace. Shadow mode never drives, so it is
    # unaffected here.
    from orchestrator_helpers.lats import lats_is_driving
    _lats_driving = lats_is_driving(state)
    if _lats_driving and trigger_reason:
        logger.info(
            f"[{user_id}/{project_id}/{session_id}] Deep Think suppressed "
            f"(LATS driving a live tree): '{trigger_reason}'"
        )
        trigger_reason = None

    if trigger_reason:
        try:
            # Build session config (tunnel/LHOST/LPORT) for deep think context
            _attack_path = state.get("attack_path_type", "")
            _is_statefull = get_setting('POST_EXPL_PHASE_TYPE', 'statefull') == 'statefull'
            _needs_session = (
                (phase == "exploitation" and _is_statefull)
                or _attack_path == "phishing_social_engineering"
            )
            _session_config = ""
            if _needs_session:
                _sc = get_session_config_prompt()
                if _sc:
                    _session_config = f"\n{_sc}\n"

            # Build RoE section if enabled
            _roe_section = ""
            if get_setting('ROE_ENABLED', False):
                from prompts.base import build_roe_prompt_section
                _roe = build_roe_prompt_section()
                if _roe:
                    _roe_section = f"\n{_roe}\n"

            deep_think_prompt = DEEP_THINK_PROMPT.format(
                current_phase=phase,
                objective=current_objective,
                attack_path_type=_attack_path,
                attack_path_behavior=build_attack_path_behavior(_attack_path),
                phase_definitions=build_phase_definitions(),
                iteration=iteration,
                max_iterations=state.get("max_iterations", get_setting('MAX_ITERATIONS', 100)),
                target_info=target_info_formatted,
                chain_context=chain_context_formatted,
                trigger_reason=trigger_reason,
                todo_list=todo_list_formatted,
                objective_history=objective_history_formatted,
                session_config=_session_config,
                roe_section=_roe_section,
            )

            dt_response = await llm.ainvoke([
                SystemMessage(content=deep_think_prompt),
                HumanMessage(content="Produce the deep think analysis JSON now."),
            ])
            dt_raw = normalize_content(dt_response.content).strip()
            _dt_usage = getattr(dt_response, "usage_metadata", None) or {}
            _dt_in += int(_dt_usage.get("input_tokens", 0) or 0)
            _dt_out += int(_dt_usage.get("output_tokens", 0) or 0)
            # Strip markdown code fences if present (LLMs often wrap JSON in ```json ... ```)
            if dt_raw.startswith("```"):
                dt_raw = dt_raw.split("\n", 1)[1] if "\n" in dt_raw else dt_raw[3:]
                if dt_raw.endswith("```"):
                    dt_raw = dt_raw[:-3].strip()
            dt_parsed = DeepThinkResult.model_validate_json(dt_raw)

            # Novelty check: compare new priority_order against the prior
            # Deep Think's priority_order. If too similar (Jaccard >=
            # threshold), the new plan is a paraphrase of one that already
            # failed — prepend a strong warning instead of silently
            # accepting the rephrased same plan.
            _prior_priority = state.get("_previous_priority_order")
            _jaccard = priority_order_jaccard(
                dt_parsed.priority_order, _prior_priority
            )
            _novelty_max = float(get_setting('DEEP_THINK_NOVELTY_JACCARD_MAX', 0.6))
            _novelty_warning = ""
            if _prior_priority and _jaccard >= _novelty_max:
                _novelty_warning = (
                    f"\n\n> ⚠ **Plan novelty low** (Jaccard {_jaccard:.2f} vs "
                    f"previous Deep Think). The previous plan did not produce "
                    f"new information. If you intend to retry an axis, you "
                    f"MUST state explicitly in your next `output_analysis.rationale` "
                    f"what specific parameter has changed; otherwise pick a "
                    f"strategy class not present in the previous priority_order.\n"
                )
                logger.info(
                    f"[{user_id}/{project_id}/{session_id}] Deep Think novelty "
                    f"warning fired (Jaccard {_jaccard:.2f} >= {_novelty_max})"
                )

            # Render competing hypotheses prominently. They're the load-
            # bearing section of deep-think now: each carries a hypothesis,
            # the evidence behind it, and the single probe that distinguishes
            # it from the alternatives. The next iteration's system prompt
            # surfaces this verbatim so the LLM acts on disambiguating tests
            # rather than confirming its existing belief.
            if dt_parsed.competing_hypotheses:
                hyp_lines = []
                for i, h in enumerate(dt_parsed.competing_hypotheses, 1):
                    hyp_lines.append(
                        f"  {i}. **{h.hypothesis}**\n"
                        f"     - Supporting: {h.supporting_evidence}\n"
                        f"     - Disambiguating probe: {h.disambiguating_probe}"
                    )
                hypotheses_block = (
                    "**Competing Hypotheses — your NEXT action MUST be a disambiguating "
                    "probe, not a commitment to your favorite:**\n"
                    + "\n".join(hyp_lines)
                    + "\n\nRequirement: the next tool call must be one of the "
                    "`disambiguating probe`s above (or a direct equivalent). Do NOT pick a "
                    "hypothesis and act on it until a probe has actually ruled the others out. "
                    "If you genuinely cannot run any probe, say so explicitly in your `thought` "
                    "and justify why before proceeding. A list of guesses with no executed test "
                    "is a brainstorm; running the probe is what makes this a real experiment.\n\n"
                )
            else:
                hypotheses_block = ""

            deep_think_result = (
                f"**Situation:** {dt_parsed.situation_assessment}\n\n"
                f"{hypotheses_block}"
                f"**Attack Vectors:** {', '.join(dt_parsed.attack_vectors_identified)}\n\n"
                f"**Approach:** {dt_parsed.recommended_approach}\n\n"
                f"**Priority:** {' → '.join(dt_parsed.priority_order)}\n\n"
                f"**Risks:** {dt_parsed.risks_and_mitigations}"
                f"{_novelty_warning}"
            )
            deep_think_triggered = True
            # Expose the hypotheses + attack vectors (NOT the recommended plan) so
            # the LATS seed can turn them into concrete probe branches this turn.
            try:
                _lats_dt_hints = {
                    "hypotheses": [
                        {"hypothesis": getattr(h, "hypothesis", ""),
                         "probe": getattr(h, "disambiguating_probe", "")}
                        for h in (dt_parsed.competing_hypotheses or [])
                    ],
                    "attack_vectors": list(dt_parsed.attack_vectors_identified or []),
                }
            except Exception:
                _lats_dt_hints = None
            logger.info(f"[{user_id}/{project_id}/{session_id}] Deep Think triggered: {trigger_reason}")

            # Stream to frontend
            if streaming_callbacks:
                streaming_cb = streaming_callbacks.get(session_id)
                if streaming_cb:
                    await streaming_cb.on_deep_think(
                        trigger_reason=trigger_reason,
                        analysis=deep_think_result,
                        iteration=iteration,
                        phase=phase,
                    )
        except Exception as e:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Deep Think failed (non-blocking): {e}")
    # ─── End Deep Think ──────────────────────────────────────────────────

    # Get phase tools with attack path type for dynamic routing
    attack_path_type = state.get("attack_path_type", "")
    available_tools = get_phase_tools(
        phase,
        get_setting('ACTIVATE_POST_EXPL_PHASE', True),
        get_setting('POST_EXPL_PHASE_TYPE', 'statefull'),
        attack_path_type,
        execution_trace=state.get("execution_trace", []),
    )

    allowed_tools = get_allowed_tools_for_phase(phase)

    # Conditionally render the deploy_fireteam action based on project gates.
    # When FIRETEAM_ENABLED=false OR current phase not in allowed phases, the
    # three fragments are empty strings so the LLM never sees the action —
    # saves ~500 tokens per call and avoids the LLM emitting a gated action.
    ft_action_enum, ft_plan_field, ft_example = build_fireteam_prompt_fragments(
        enabled=get_setting("FIRETEAM_ENABLED", False)
                and get_setting("PERSISTENT_CHECKPOINTER", False),
        phase=phase,
        allowed_phases=get_setting("FIRETEAM_ALLOWED_PHASES", ["informational"]),
        max_members=int(get_setting("FIRETEAM_MAX_MEMBERS", 5)),
        propensity=int(get_setting("FIRETEAM_PROPENSITY", 3)),
    )

    system_prompt = REACT_SYSTEM_PROMPT.format(
        current_phase=phase,
        phase_definitions=build_phase_definitions(),
        informational_guidance=build_informational_guidance(phase),
        attack_path_type=attack_path_type,
        attack_path_behavior=build_attack_path_behavior(attack_path_type),
        skill_selection_guide=build_skill_menu(get_enabled_builtin_skills(), get_enabled_user_skills()),
        available_tools=available_tools,
        tool_name_enum=build_tool_name_enum(allowed_tools),
        tool_args_section=build_tool_args_section(allowed_tools),
        iteration=iteration,
        max_iterations=state.get("max_iterations", get_setting('MAX_ITERATIONS', 100)),
        objective=current_objective,
        objective_history_summary=objective_history_formatted,
        prior_chain_history=state.get("_prior_chain_context") or "No prior sessions.",
        chain_context=chain_context_formatted,
        todo_list=todo_list_formatted,
        target_info=target_info_formatted,
        qa_history=qa_history_formatted,
        fireteam_action_enum=ft_action_enum,
        fireteam_plan_field=ft_plan_field,
        fireteam_example_section=ft_example,
    )

    # Inject Deep Think section if available (from state or just computed)
    if deep_think_result:
        system_prompt += DEEP_THINK_SECTION.format(deep_think_result=deep_think_result)

    # Inject Deep Think self-request instruction so the LLM can ask for a
    # strategic re-evaluation on the next iteration when it senses stagnation.
    system_prompt += DEEP_THINK_SELF_REQUEST_INSTRUCTION

    # Inject the workspace-layout doc on every think step. The block teaches
    # the agent which folder is for what (notes/ = scratch, tool-outputs/ +
    # jobs/ = auto-managed, uploads/ = user inbox). The uploads/ section
    # only appears when files are actually present - keeps the prompt lean
    # when the user hasn't staged anything.
    from prompts.base import build_workspace_layout_block
    workspace_block = build_workspace_layout_block(project_id)
    system_prompt = workspace_block + "\n\n" + system_prompt

    # Inject stealth mode rules if enabled (prepended for maximum priority)
    if get_setting('STEALTH_MODE', False):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        system_prompt = STEALTH_MODE_RULES + "\n\n" + system_prompt
        logger.info(f"[{user_id}/{project_id}/{session_id}] STEALTH MODE active — injected stealth rules into prompt")

    # Scope guardrail: remind agent to stay within authorized targets
    # Always inject for hard-blocked domains (government/public); also inject when soft guardrail is enabled
    _inject_scope_guardrail = get_setting('AGENT_GUARDRAIL_ENABLED', True)
    if not _inject_scope_guardrail:
        from orchestrator_helpers.hard_guardrail import is_hard_blocked
        _target_domain = get_setting('TARGET_DOMAIN', '')
        _ip_mode = get_setting('IP_MODE', False)
        if not _ip_mode and _target_domain:
            _inject_scope_guardrail, _ = is_hard_blocked(_target_domain)

    if _inject_scope_guardrail:
        system_prompt += (
            "\n\n## SCOPE GUARDRAIL\n\n"
            "You must ONLY operate against the project's configured target domain/IPs. "
            "Never scan, exploit, probe, or interact with domains or IPs outside the authorized scope. "
            "If the user asks you to target something outside the project scope, refuse and explain why."
        )

    # Rules of Engagement injection
    if get_setting('ROE_ENABLED', False):
        from prompts.base import build_roe_prompt_section
        roe_section = build_roe_prompt_section()
        if roe_section:
            system_prompt += "\n\n" + roe_section
            logger.info(f"[{user_id}/{project_id}/{session_id}] RoE rules injected into prompt")

        # Inject engagement date/time warnings from initialize_node
        roe_warnings = state.get("_roe_warnings", [])
        if roe_warnings:
            warning_block = "\n".join(f"- WARNING: {w}" for w in roe_warnings)
            system_prompt += (
                "\n\n## RoE TIMING WARNINGS\n"
                f"{warning_block}\n"
                "IMPORTANT: Inform the user about these warnings before proceeding. "
                "If the engagement has ended, do NOT perform any active testing."
            )

    # Unproductive-streak detection: inject a prompt warning if N of last K steps
    # were failures OR the LLM classified them as no_progress / duplicate / blocked.
    # Catches both hard errors and "successful but useless" calls.
    exec_trace = state.get("execution_trace", [])
    _audit_window = int(get_setting('PRODUCTIVITY_AUDIT_WINDOW', 6))
    _audit_threshold = int(get_setting('UNPRODUCTIVE_STREAK_THRESHOLD', 3))
    if len(exec_trace) >= _audit_threshold:
        unproductive_count = 0
        for step in exec_trace[-_audit_window:]:
            output_lower = ((step.get("tool_output") or "")[:500]).lower()
            is_keyword_failure = (
                not step.get("success", True)
                or "failed" in output_lower
                or "error" in output_lower
                or "exploit completed, but no session" in output_lower
            )
            if is_keyword_failure or is_unproductive(step):
                unproductive_count += 1

        if unproductive_count >= _audit_threshold:
            system_prompt += (
                "\n\n## UNPRODUCTIVE STREAK DETECTED\n\n"
                f"{unproductive_count} of your last {_audit_window} steps yielded no_progress, "
                "duplicate, blocked, or hard-failure outcomes. A streak does NOT prove your "
                "current technique is wrong — it often means a correct technique is failing for a "
                "small, fixable reason (wrong flag, wrong encoding, wrong assumption about the "
                "target). Before you abandon the current approach, you MUST take ONE validation "
                "step this turn:\n"
                "  (a) reproduce the last failure in a place you fully control (run your own "
                "payload locally in your own browser/interpreter) and confirm the tool produced "
                "what you intended — distinguish 'my technique is wrong' from 'my execution is "
                "wrong' from 'the environment is noisy';\n"
                "  (b) run the cheap probe that would tell your competing hypotheses apart "
                "(e.g. fingerprint the real server/engine before assuming a modern stack); or\n"
                "  (c) state plainly, in your `thought`, an assumption you have ACTUALLY TESTED "
                "this run that rules the current approach out.\n"
                "If you are stuck on a reflected/injected input (a filter keeps rejecting "
                "payloads, or a grader keeps returning the same message), the validation step "
                "MUST be: (i) re-read WHERE your marker lands in the RAW response body -- never "
                "infer a sink or an execution context from an error/status string, which is an "
                "outcome, not a location; and (ii) re-probe the filter's accepted alphabet at the "
                "injection character (single-character accept/reject diff) rather than trying more "
                "variants of the same rejected form.\n"
                "Only AFTER one of (a)/(b)/(c) may you pivot (switch tool family / vulnerability "
                "hypothesis, `web_search` for alternatives, or action='ask_user'). Do NOT pivot on "
                "an untested guess, and do NOT blindly re-send the identical call.\n"
            )

    # Productivity v2: surface tiered hints derived from the continuous score.
    # The score was computed up top (in the Deep Think trigger block). Inject
    # the appropriate intensity of warning into the prompt — soft hint at
    # yellow, hard pivot demand at red, explicit block-warning at critical.
    if _score_obj is not None:
        _score_val = _score_obj["score"]
        _tier_val = _score_obj.get("tier", "green")
        _components = _score_obj.get("components", {})
        if _tier_val == "yellow":
            system_prompt += (
                "\n\n## PRODUCTIVITY HINT (yellow)\n\n"
                f"Score {_score_val} — engagement state has not grown in "
                f"{_components.get('iterations_since_state_grew', 0)} iterations. "
                "Consider whether your current hypothesis is still viable. If "
                "your last 2-3 probes returned no new information, the next "
                "probe should change a different parameter than 'how big' or "
                "'how many' — change the *hypothesis class* or the *target* "
                "instead.\n"
            )
        elif _tier_val == "red":
            system_prompt += (
                "\n\n## PRODUCTIVITY HINT (red — pivot required)\n\n"
                f"Score {_score_val}. State-growth stall = "
                f"{_components.get('iterations_since_state_grew', 0)}, "
                f"max axis-repeat = {_components.get('max_axis_repeats', 0)}. "
                "Your next action MUST be on a different hypothesis class. "
                "In your `output_analysis.rationale` (or your `thought` before "
                "the next tool call), name the new hypothesis explicitly and "
                "state WHY the previous hypothesis class has been ruled out.\n"
            )
        elif _tier_val == "critical":
            system_prompt += (
                "\n\n## PRODUCTIVITY HINT (critical — blocked axis)\n\n"
                f"Score {_score_val}. The engagement appears genuinely stuck "
                f"(stall {_components.get('iterations_since_state_grew', 0)}, "
                f"axis-repeats {_components.get('max_axis_repeats', 0)}). "
                "Spawning another expensive call on the same axis will be "
                "rejected. Either: (a) pick a fundamentally different "
                "vulnerability class, (b) target a different endpoint / "
                "credential / user, or (c) emit action='ask_user' to request "
                "a hint. Do NOT repeat the dominant axis.\n"
            )

    # Productivity audit section: show the model its own recent same-pattern
    # fingerprints. Empty string if fewer than 3 same-pattern recent calls.
    _audit_section = build_productivity_audit_section(
        exec_trace, window=_audit_window,
    )
    if _audit_section:
        system_prompt += "\n" + _audit_section

    # Response-uniformity anomaly: complementary to the productivity audit.
    # The audit catches "same TOOL/ARGS pattern → no new info" (loops).
    # The uniformity detector catches "DIFFERENT payloads → identical short-
    # duration failure" — the signature of probes being short-circuited at
    # parse time. Without this, the LLM marks vector classes 'tested' on
    # the basis of failures that never reached the target layer.
    _anomaly_warning = detect_uniform_response_anomaly(
        exec_trace,
        window=int(get_setting('UNIFORM_RESPONSE_WINDOW', 25)),
        min_count=int(get_setting('UNIFORM_RESPONSE_MIN_COUNT', 3)),
        duration_threshold_ms=int(
            get_setting('UNIFORM_RESPONSE_DURATION_MS', 200)
        ),
    )
    if _anomaly_warning:
        system_prompt += "\n\n" + _anomaly_warning
        logger.info(
            f"[{user_id}/{project_id}/{session_id}] "
            f"Uniform-response anomaly injected into prompt"
        )

    # Surface any prior-iteration discrepancy note so the model sees it before
    # filling productivity again.
    _last_discrepancy = state.get("_last_productivity_discrepancy")
    if _last_discrepancy:
        system_prompt += (
            "\n\n## Prior Productivity Claim Was Downgraded\n\n"
            f"Reason: {_last_discrepancy}\n"
            "Be more critical about your verdict this turn — empty/duplicate outputs are "
            "not 'confirmation'.\n"
        )

    # CHECK: Is there a pending tool output to analyze?
    pending_step = state.get("_current_step")
    has_pending_output = (
        pending_step and
        pending_step.get("tool_output") is not None and
        not pending_step.get("output_analysis")
    )

    if has_pending_output:
        tool_output_raw = pending_step.get("tool_output") or pending_step.get("error_message") or "No output"
        output_section = PENDING_OUTPUT_ANALYSIS_SECTION.format(
            tool_name=pending_step.get("tool_name", "unknown"),
            tool_args=json_dumps_safe(pending_step.get("tool_args") or {}),
            success=pending_step.get("success", False),
            tool_output=wrap_untrusted(tool_output_raw[:get_setting('TOOL_OUTPUT_MAX_CHARS', 20000)]),
        )
        system_prompt = system_prompt + "\n" + output_section
        logger.info(f"[{user_id}/{project_id}/{session_id}] Injected output analysis section for tool: {pending_step.get('tool_name')}")

    # CHECK: Is there a pending plan wave to analyze?
    pending_plan = state.get("_current_plan")
    has_pending_plan_outputs = (
        pending_plan
        and pending_plan.get("steps")
        and any(s.get("tool_output") is not None for s in pending_plan.get("steps", []))
        and not pending_plan.get("_analyzed")
    )

    if has_pending_plan_outputs:
        plan_steps = pending_plan.get("steps", [])
        max_chars = get_setting('TOOL_OUTPUT_MAX_CHARS', 20000)
        chars_per_tool = max(2000, max_chars // len(plan_steps))

        # Build per-tool output sections
        tool_outputs_parts = []
        for i, s in enumerate(plan_steps):
            output = (s.get("tool_output") or s.get("error_message") or "No output")[:chars_per_tool]
            status = "OK" if s.get("success") else "FAILED"
            tool_outputs_parts.append(
                f"### Tool {i+1}: {s.get('tool_name', 'unknown')} ({status})\n"
                f"Args: {json_dumps_safe(s.get('tool_args', {}))}\n"
                f"Output:\n{wrap_untrusted(output)}"
            )

        plan_section = PENDING_PLAN_OUTPUTS_SECTION.format(
            n_tools=len(plan_steps),
            tool_outputs_section="\n\n".join(tool_outputs_parts),
        )
        # W4: always ask for per_step response_class (LATS classifies every probe).
        plan_section = plan_section + RESPONSE_CLASS_TAXONOMY_BLOCK
        system_prompt = system_prompt + "\n" + plan_section
        logger.info(f"[{user_id}/{project_id}/{session_id}] Injected plan output analysis section for {len(plan_steps)} tools")

    # Drain pending guidance messages from user (per-session queue)
    guidance_messages = []
    guidance_queue = guidance_queues.get(session_id)
    if guidance_queue:
        while not guidance_queue.empty():
            try:
                guidance_messages.append(guidance_queue.get_nowait())
            except asyncio.QueueEmpty:
                break

    if guidance_messages:
        guidance_section = (
            "\n\n## USER GUIDANCE (IMPORTANT)\n\n"
            "The user sent these guidance messages while you were working. "
            "They refine your CURRENT objective — do NOT treat them as new tasks. "
            "Adjust your plan and next action accordingly:\n\n"
        )
        for i, msg in enumerate(guidance_messages, 1):
            guidance_section += f"{i}. {msg}\n"
        guidance_section += "\nAcknowledge this guidance in your thought.\n"
        system_prompt += guidance_section
        logger.info(f"[{user_id}/{project_id}/{session_id}] Injected {len(guidance_messages)} guidance messages into prompt")

    # SKILL FIT CHECK — appended LAST (highest recency, uncached suffix) so the
    # model re-evaluates its active attack skill on EVERY turn, in either
    # direction (generic -> concrete, or a wrong concrete class -> the right
    # one). Not gated to unclassified: the initial classification can be wrong,
    # so the agent must be able to correct it mid-run without a phase change.
    # The "do NOT switch to the skill you already have" line plus the code-level
    # noop guard in evaluate_skill_switch prevent turn-wasting re-affirmations,
    # and "no new contradicting evidence" discourages A<->B flip-flop.
    _skill_label = attack_path_type or "unclassified"
    # The switchable classes MUST reflect the actually-enabled built-in skills so
    # the agent can name any of them as a `to_skill` (a class the agent never sees
    # listed here is one it cannot switch to). Built dynamically from the enabled
    # set so new built-in skills become selectable without editing this string.
    try:
        _switchable = sorted(get_enabled_builtin_skills()) + [
            f'user_skill:{s["id"]}' for s in get_enabled_user_skills()
        ]
    except Exception:
        _switchable = []
    _switchable_str = ", ".join(_switchable) if _switchable else "xss, sql_injection, ssrf, rce, path_traversal"
    system_prompt += (
        f"\n\n## SKILL FIT CHECK — re-evaluate EVERY turn\n"
        f"Active attack skill: `{_skill_label}`.\n"
        f"Before choosing your action, match the STRONGEST current evidence from the live target "
        f"against the **ATTACK SKILL SELECTION** catalog above (each class lists its description + "
        f"selection criteria — the same used to classify at session start):\n"
        f"- If the evidence fits the criteria of a DIFFERENT enabled class better than "
        f"`{_skill_label}` (switchable: {_switchable_str}) — or you are still on a generic "
        f"`*-unclassified` skill and the class has become clear — your action THIS TURN MUST be "
        f"`switch_skill` to that class, before any further probing or exploitation.\n"
        f"- If the active skill still best fits the evidence, or the class is not yet determined, "
        f"continue — do NOT switch to the skill you already have (that wastes a turn), and do NOT "
        f"switch without new, contradicting evidence.\n"
        f"Naming the right class in your thought but not switching is the mistake to avoid. "
        f"Switching is a first-class action and needs no phase change."
    )

    # Prompt logging. The system prompt is ~100 KB and largely static across
    # iterations, so dumping it every turn is ~90% of the log's volume. Emit it
    # in full only on the first iteration (or when LOG_LLM_VERBOSE is set); on
    # later turns log a one-line fingerprint (length + hash) so a change is still
    # visible. The small, dynamic context (chain / todo / target / Q&A) is always
    # logged since it is what actually changes turn to turn.
    _prompt_hash = hashlib.sha1(system_prompt.encode("utf-8", "replace")).hexdigest()[:12]
    _verbose_prompt = bool(get_setting('LOG_LLM_VERBOSE', False))
    logger.info(f"# THINK NODE PROMPT - Iteration {iteration} - Phase: {phase}")
    logger.info(f"--- CHAIN CONTEXT ---\n{chain_context_formatted}")
    logger.info(f"--- TODO LIST ---\n{todo_list_formatted}")
    logger.info(f"--- TARGET INFO ---\n{target_info_formatted}")
    logger.info(f"--- Q&A HISTORY ---\n{qa_history_formatted}")
    if _verbose_prompt or iteration <= 1:
        logger.info(f"--- FULL SYSTEM PROMPT ({len(system_prompt)} chars, sha1={_prompt_hash}) ---")
        chunk_size = 4000
        for i in range(0, len(system_prompt), chunk_size):
            chunk = system_prompt[i:i+chunk_size]
            logger.info(f"PROMPT[{i}:{i+len(chunk)}]:\n{chunk}")
    else:
        logger.info(
            f"--- SYSTEM PROMPT: {len(system_prompt)} chars, sha1={_prompt_hash} "
            f"(full dump suppressed; set LOG_LLM_VERBOSE=true to emit) ---"
        )

    # Anthropic prompt caching: when the LLM is ChatAnthropic, split the
    # assembled system prompt at CACHE_PREFIX_END_MARKER and emit two content
    # blocks. The prefix block (persona + phase definitions + tool registry +
    # attack skill) is marked cache_control={"type": "ephemeral"} so Anthropic
    # caches it once and bills subsequent reads at ~10% of base input cost.
    # The dynamic suffix (current state, chain context, etc.) is uncached.
    # langchain-anthropic>=0.3 auto-attaches the prompt-caching beta header
    # when it sees cache_control content blocks; no extra_headers needed.
    # Gated on ANTHROPIC_PROMPT_CACHING_ENABLED so operators can disable.
    _caching_enabled = (
        get_setting('ANTHROPIC_PROMPT_CACHING_ENABLED', True)
        and type(llm).__name__ == 'ChatAnthropic'
        and CACHE_PREFIX_END_MARKER in system_prompt
    )
    if _caching_enabled:
        _prefix, _, _suffix = system_prompt.partition(CACHE_PREFIX_END_MARKER)
        system_message_content = [
            {"type": "text", "text": _prefix.rstrip(), "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": _suffix.lstrip()},
        ]
    else:
        # Caching disabled, non-Anthropic LLM, or marker absent — strip the
        # marker so the LLM never sees the sentinel string.
        system_message_content = system_prompt.replace(CACHE_PREFIX_END_MARKER, "")

    # Get LLM decision with retry on parse failures
    messages = [
        SystemMessage(content=system_message_content),
        HumanMessage(content="Based on the current state, what is your next action? Output EXACTLY ONE valid JSON object and nothing else. Do NOT simulate tool execution - you will receive actual tool output after submitting your decision. Do NOT output multiple JSON objects or continue the conversation - just ONE decision JSON.")
    ]

    max_retries = get_setting('LLM_PARSE_MAX_RETRIES', 3)
    decision = None
    last_error = None
    response_text = ""
    input_tokens_this_turn = _dt_in
    output_tokens_this_turn = _dt_out
    _think_t0 = time.monotonic()

    for attempt in range(max_retries):
        if attempt > 0:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Parse attempt {attempt}/{max_retries} failed: {last_error}")
            messages.append(AIMessage(content=response_text))
            messages.append(HumanMessage(
                content=f"Your previous JSON response failed validation:\n{last_error}\n\n"
                        f"Fix the error and output EXACTLY ONE valid JSON object. No extra text."
            ))

        try:
            response = await retry_llm_call(
                llm, messages,
                label=f"{user_id}/{project_id}/{session_id} think iter={iteration}",
            )
        except Exception as exc:
            logger.error(
                f"[{user_id}/{project_id}/{session_id}] LLM call failed after retries: {exc}"
            )
            decision = LLMDecision(
                thought="",
                reasoning="LLM call failed after transient-error retries",
                action="complete",
                completion_reason=f"llm_error: {exc}",
                updated_todo_list=[],
            )
            break

        response_text = normalize_content(response.content).strip()

        usage = getattr(response, "usage_metadata", None) or {}
        input_tokens_this_turn += int(usage.get("input_tokens", 0) or 0)
        output_tokens_this_turn += int(usage.get("output_tokens", 0) or 0)

        # Prompt-cache observability: log all four token-detail fields so the
        # operator can confirm caching is firing. Anthropic populates the
        # ephemeral_5m_input_tokens / ephemeral_1h_input_tokens fields on
        # cache WRITE (cache_creation stays 0 in newer SDK versions) and
        # the cache_read field on cache HIT. OpenAI / DeepSeek populate
        # cache_read only. Zero on every field means no cache activity.
        _ctok = (usage.get("input_token_details") or {})
        logger.info(
            f"LLM CACHE: read={_ctok.get('cache_read', 0)} "
            f"creation={_ctok.get('cache_creation', 0)} "
            f"eph_5m={_ctok.get('ephemeral_5m_input_tokens', 0)} "
            f"eph_1h={_ctok.get('ephemeral_1h_input_tokens', 0)} "
            f"provider={type(llm).__name__} (iter {iteration})"
        )

        # Raw response is redundant with the structured THOUGHT/REASONING/ACTION
        # block below; emit it only under LOG_LLM_VERBOSE.
        if _verbose_prompt:
            logger.info(f"LLM RAW RESPONSE - Iteration {iteration} (attempt {attempt+1}/{max_retries})")
            logger.info(f"{response_text}")

        decision, last_error = try_parse_llm_decision(response_text)
        if decision:
            break

    # If all retries failed, use the fallback
    if not decision:
        logger.error(f"[{user_id}/{project_id}/{session_id}] All {max_retries} parse attempts failed: {last_error}")
        decision = LLMDecision(
            thought=response_text,
            reasoning="Failed to parse structured response after retries",
            action="complete",
            completion_reason=f"Unable to continue: JSON parsing failed after {max_retries} attempts",
            updated_todo_list=[],
        )

    _think_ms = int((time.monotonic() - _think_t0) * 1000)
    logger.info(
        f"[{user_id}/{project_id}/{session_id}] Decision: action={decision.action}, "
        f"tool={decision.tool_name} think_ms={_think_ms} provider={type(llm).__name__} "
        f"tokens_turn(in={input_tokens_this_turn},out={output_tokens_this_turn})"
    )
    # Structured decision event for the machine-readable stream.
    try:
        from session_log import log_event
        log_event(
            "decision",
            session=session_id, iteration=iteration, phase=phase,
            action=str(decision.action), tool=decision.tool_name,
            think_ms=_think_ms, provider=type(llm).__name__,
            tokens_in=input_tokens_this_turn, tokens_out=output_tokens_this_turn,
            prompt_sha1=_prompt_hash,
        )
    except Exception:
        pass

    # Detailed logging for debugging
    logger.info(f"\n{'='*60}")
    logger.info(f"THINK NODE - Iteration {iteration} - Phase: {phase}")
    logger.info(f"{'='*60}")
    logger.info(f"THOUGHT: {decision.thought}")
    logger.info(f"REASONING: {decision.reasoning}")
    logger.info(f"ACTION: {decision.action}")
    if decision.tool_name:
        logger.info(f"TOOL: {decision.tool_name}")
        logger.info(f"TOOL_ARGS: {json_dumps_safe(decision.tool_args, indent=2) if decision.tool_args else 'None'}")
    if decision.phase_transition:
        logger.info(f"PHASE_TRANSITION: {decision.phase_transition.to_phase}")

    # Log todo list updates
    if decision.updated_todo_list:
        logger.info(f"TODO LIST ({len(decision.updated_todo_list)} items):")
        for todo in decision.updated_todo_list:
            status_icon = {
                "pending": "[ ]",
                "in_progress": "[~]",
                "completed": "[x]",
                "blocked": "[!]"
            }.get(todo.status, "[ ]")
            priority_marker = {"high": "!!!", "medium": "!!", "low": "!"}.get(todo.priority, "!!")
            logger.info(f"  {status_icon} {priority_marker} {todo.description}")
    else:
        logger.info(f"TODO LIST: (no updates)")

    # Log Q&A history if present
    qa_history = state.get("qa_history", [])
    if qa_history:
        logger.info(f"Q&A HISTORY ({len(qa_history)} entries):")
        for i, entry in enumerate(qa_history, 1):
            q = entry.get("question", {})
            a = entry.get("answer", {})
            logger.info(f"  Q{i}: {q.get('question', 'N/A')[:10000]}")
            logger.info(f"      Answer: {a.get('answer', 'N/A')[:10000] if a else '(unanswered)'}")
    else:
        logger.info(f"Q&A HISTORY: (none)")

    # Fireteam gate: enforce feature-flag + persistent-checkpointer + allowed-phases.
    # If the LLM emitted deploy_fireteam but any gate fails, rewrite the action
    # to use_tool without a tool (so _route_after_think routes safely). The
    # system note is injected after `updates` is constructed below.
    _fireteam_gate_note: str | None = None
    if decision.action == "deploy_fireteam":
        ft_enabled = get_setting("FIRETEAM_ENABLED", False)
        persistent = get_setting("PERSISTENT_CHECKPOINTER", False)
        allowed_phases = get_setting("FIRETEAM_ALLOWED_PHASES", ["informational"])
        if not ft_enabled:
            _fireteam_gate_note = "fireteam feature disabled for this project"
        elif not persistent:
            _fireteam_gate_note = "persistent checkpointer required (PERSISTENT_CHECKPOINTER=false); fireteam cannot run safely without it"
        elif phase not in allowed_phases:
            _fireteam_gate_note = f"phase '{phase}' not in allowed phases {allowed_phases}"
        if _fireteam_gate_note:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] deploy_fireteam rejected: {_fireteam_gate_note}")
            decision = decision.model_copy(update={
                "action": "use_tool",
                "tool_name": None,
                "tool_args": None,
                "fireteam_plan": None,
            })

    # Log user_question if action is ask_user
    if decision.action == "ask_user" and decision.user_question:
        logger.info(f"USER_QUESTION:")
        logger.info(f"  Question: {decision.user_question.question}")
        logger.info(f"  Context: {decision.user_question.context}")
        logger.info(f"  Format: {decision.user_question.format}")
        if decision.user_question.options:
            logger.info(f"  Options: {decision.user_question.options}")

    logger.info(f"{'='*60}\n")

    # LATS (exploit-path tree search) hook. Strict no-op unless LATS_ENABLED.
    # Runs AFTER the fireteam gate and BEFORE the ExecutionStep build so the
    # router, the confirmation gate, and the RoE gates all inherit any LATS
    # override automatically. In shadow mode it builds/streams the tree but
    # returns the decision unchanged. See internal/LATS_integration.md §5.3/§19.
    if get_setting("LATS_ENABLED", False):
        from orchestrator_helpers.lats import lats_hook
        # Expose Deep Think's FIRING (not its output, §20.16), guidance-drain,
        # and this turn's productivity score as intra-turn signals the hook reads
        # via state. The score lets lats_active re-engage as the cheaper first
        # responder just BELOW the Deep Think threshold (Fix B2 score trigger).
        state["deep_think_ran_this_turn"] = deep_think_triggered
        state["guidance_drained_this_turn"] = bool(guidance_messages)
        state["_last_productivity_score"] = _score_obj
        # Deep Think's hypotheses/vectors for the LATS seed (turn-local; the seed
        # runs the same turn Deep Think fires, so no cross-turn persistence needed).
        state["_lats_deep_think_hints"] = _lats_dt_hints
        decision = await lats_hook(
            state, decision, llm=llm,
            streaming_callbacks=streaming_callbacks, session_id=session_id,
        )
        # Fold LATS's own expand-call tokens into this turn's counters (and thus
        # the cumulative total + the streamed KPI), so a LATS-active turn is not
        # undercounted. Turn-local: cleared after reading, never persisted.
        _lats_tok = state.pop("_lats_expand_tokens", None) or {}
        input_tokens_this_turn += int(_lats_tok.get("in", 0) or 0)
        output_tokens_this_turn += int(_lats_tok.get("out", 0) or 0)

    # Create execution step
    step = ExecutionStep(
        iteration=iteration,
        phase=phase,
        thought=decision.thought,
        reasoning=decision.reasoning,
        tool_name=decision.tool_name if decision.action == "use_tool" else None,
        tool_args=decision.tool_args if decision.action == "use_tool" else None,
    )

    # Convert todo list updates to dicts for state storage
    todo_list = [item.model_dump() for item in decision.updated_todo_list] if decision.updated_todo_list else state.get("todo_list", [])

    # Build state updates
    _prev_input_tokens = int(state.get("input_tokens_used", 0) or 0)
    _prev_output_tokens = int(state.get("output_tokens_used", 0) or 0)
    _new_input_tokens = _prev_input_tokens + input_tokens_this_turn
    _new_output_tokens = _prev_output_tokens + output_tokens_this_turn

    updates = {
        "current_iteration": iteration,
        "todo_list": todo_list,
        "_decision": decision.model_dump(),
        "_just_transitioned_to": None,  # Clear the marker
        "_redundant_transition_count": 0,  # Reset no-op transition loop counter (redundant branches override)
        "_reject_tool": False,  # Clear tool rejection marker from previous iteration
        "_tool_confirmation_mode": None,  # Clear mode from previous confirmation
        "_completed_step": None,  # Will be set if we process pending output
        "input_tokens_used": _new_input_tokens,
        "output_tokens_used": _new_output_tokens,
        "tokens_used": _new_input_tokens + _new_output_tokens,
        "_input_tokens_this_turn": input_tokens_this_turn,
        "_output_tokens_this_turn": output_tokens_this_turn,
    }

    # LATS state pass-through (declared keys, or LangGraph strips them, §20.1).
    # Only written when LATS_ENABLED so the disabled path is a strict no-op.
    if get_setting("LATS_ENABLED", False):
        updates["deep_think_ran_this_turn"] = deep_think_triggered
        updates["guidance_drained_this_turn"] = bool(guidance_messages)
        updates["_exploit_tree"] = state.get("_exploit_tree")
        # Persist the archive stamp so the re-activation cooldown (Fix B2)
        # survives across turns (else it resets to None and never applies).
        updates["_lats_last_archive_iter"] = state.get("_lats_last_archive_iter")
        # Persist the accumulated tree digest + the merged cross-tree leads/dead
        # knowledge so prior-tree knowledge survives across turns and feeds every
        # subsequent LATS tree.
        updates["_lats_tree_digest"] = state.get("_lats_tree_digest")
        updates["_lats_leads"] = state.get("_lats_leads")
        updates["_lats_dead"] = state.get("_lats_dead")

    logger.info(
        f"[{user_id}/{project_id}/{session_id}] Tokens this turn: "
        f"in={input_tokens_this_turn} out={output_tokens_this_turn} "
        f"(cumulative in={_new_input_tokens} out={_new_output_tokens})"
    )

    # Inject fireteam-gate rejection note so the LLM doesn't just re-emit
    # deploy_fireteam on the next iteration. Use HumanMessage to represent
    # operator/system feedback mid-conversation (AIMessage would model the
    # LLM's own past output, which is semantically wrong).
    if _fireteam_gate_note:
        updates["messages"] = [HumanMessage(
            content=f"[system] deploy_fireteam rejected: {_fireteam_gate_note}. Choose use_tool, plan_tools, transition_phase, or complete instead."
        )]

    # Persist deep think result in state (only when newly triggered)
    if deep_think_triggered:
        updates["deep_think_result"] = deep_think_result
        # Productivity v2: arm the cooldown so we don't fire another Deep
        # Think on the very next turn just because the unproductive window
        # hasn't moved on yet. Critical-score and self-request paths bypass
        # the cooldown in the trigger logic above.
        _cooldown_n = int(get_setting('DEEP_THINK_COOLDOWN_ITERATIONS', 5))
        updates["_deep_think_cooldown_until"] = iteration + max(1, _cooldown_n)
        # Productivity v2: remember the priority_order for next-turn novelty
        # comparison.
        if dt_parsed is not None:
            try:
                updates["_previous_priority_order"] = list(dt_parsed.priority_order or [])
            except Exception:
                pass

    # Productivity v2: persist the score breakdown for diagnostics / streaming.
    if _score_obj is not None:
        updates["_last_productivity_score"] = _score_obj

    # Persist LLM self-request for deep think (triggers on next iteration)
    updates["_need_deep_think"] = decision.need_deep_think

    # When action is plan_tools, set _current_plan instead of _current_step.
    # When action is deploy_fireteam, set _current_fireteam_plan.
    if decision.action == "plan_tools" and decision.tool_plan:
        updates["_current_step"] = None  # No single step — plan node handles streaming
        updates["_current_plan"] = decision.tool_plan.model_dump()
        updates["_current_fireteam_plan"] = None
    elif decision.action == "deploy_fireteam" and decision.fireteam_plan:
        updates["_current_step"] = None
        updates["_current_plan"] = None
        updates["_current_fireteam_plan"] = decision.fireteam_plan.model_dump()
    else:
        updates["_current_step"] = step.model_dump()
        updates["_current_plan"] = None  # Clear any stale plan
        updates["_current_fireteam_plan"] = None

    # Process output analysis if we had pending tool output
    if has_pending_output:
        step_iteration = pending_step.get("iteration", iteration)

        if decision.output_analysis:
            analysis = decision.output_analysis

            # Update step with analysis data
            pending_step["output_analysis"] = analysis.interpretation
            pending_step["actionable_findings"] = analysis.actionable_findings or []
            pending_step["recommended_next_steps"] = analysis.recommended_next_steps or []

            # Persist the LLM's productivity verdict on the step so the loop
            # detector and subsequent prompts can read it back.
            _productivity_dict = (
                analysis.productivity.model_dump()
                if getattr(analysis, "productivity", None)
                else {}
            )

            # Honesty audit: cross-check the verdict against actual state delta.
            # If the LLM claims new info but nothing actually changed, downgrade.
            _prior_findings_count = len(state.get("chain_findings_memory", []) or [])
            _findings_will_grow = bool(
                (analysis.chain_findings or [])
                or (analysis.exploit_succeeded and analysis.exploit_details)
                or (analysis.actionable_findings and not analysis.chain_findings)
            )
            _discrepancy = audit_productivity_claim(
                productivity=_productivity_dict,
                extracted_info=(
                    analysis.extracted_info.model_dump()
                    if analysis.extracted_info else {}
                ),
                actionable_findings=analysis.actionable_findings or [],
                findings_grew=_findings_will_grow,
            )
            if _discrepancy:
                _productivity_dict = downgrade_verdict_to_no_progress(
                    _productivity_dict, _discrepancy,
                )
                logger.info(
                    f"[{user_id}/{project_id}/{session_id}] Productivity verdict "
                    f"downgraded to no_progress: {_discrepancy}"
                )
                updates["_last_productivity_discrepancy"] = _discrepancy
            else:
                updates["_last_productivity_discrepancy"] = None

            pending_step["productivity"] = _productivity_dict

            # Log analysis results
            logger.info(f"\n{'='*60}")
            logger.info(f"OUTPUT ANALYSIS (inline) - Iteration {iteration} - Phase: {phase}")
            logger.info(f"{'='*60}")
            logger.info(f"TOOL: {pending_step.get('tool_name')}")
            logger.info(f"INTERPRETATION: {analysis.interpretation[:2000]}")
            if analysis.actionable_findings:
                logger.info(f"ACTIONABLE FINDINGS: {analysis.actionable_findings}")
            if analysis.recommended_next_steps:
                logger.info(f"RECOMMENDED NEXT STEPS: {analysis.recommended_next_steps}")
            if analysis.exploit_succeeded:
                logger.info(f"EXPLOIT SUCCEEDED: {analysis.exploit_details}")
            logger.info(f"{'='*60}\n")

            # Merge target info
            current_target = TargetInfo(**state.get("target_info", {}))
            extracted = analysis.extracted_info
            new_target = TargetInfo(
                primary_target=extracted.primary_target,
                ports=extracted.ports,
                services=extracted.services,
                technologies=extracted.technologies,
                vulnerabilities=extracted.vulnerabilities,
                credentials=extracted.credentials,
                sessions=extracted.sessions,
            )
            merged_target = current_target.merge_from(new_target)

            # --- Chain Memory Population ---
            step_id = pending_step.get("step_id")

            # 1. Populate chain_findings_memory
            chain_findings_mem = list(state.get("chain_findings_memory", []))
            if analysis.chain_findings:
                for cf in analysis.chain_findings:
                    finding_dict = cf.model_dump() if hasattr(cf, 'model_dump') else (cf if isinstance(cf, dict) else {})
                    finding_dict["step_iteration"] = step_iteration
                    chain_findings_mem.append(finding_dict)
            elif analysis.actionable_findings:
                for af_text in analysis.actionable_findings:
                    chain_findings_mem.append({
                        "finding_type": "custom",
                        "severity": "info",
                        "title": af_text[:200],
                        "evidence": "",
                        "step_iteration": step_iteration,
                        "confidence": 60,
                    })
            # Exploit success also goes into findings memory
            if analysis.exploit_succeeded and analysis.exploit_details:
                details = analysis.exploit_details
                chain_findings_mem.append({
                    "finding_type": "exploit_success",
                    "severity": "critical",
                    "title": f"Exploit success: {details.get('evidence', '')[:100]}",
                    "evidence": details.get("evidence", ""),
                    "step_iteration": step_iteration,
                    "confidence": 95,
                    "related_cves": details.get("cve_ids", []),
                    "related_ips": [details.get("target_ip", "")] if details.get("target_ip") else [],
                })
            updates["chain_findings_memory"] = chain_findings_mem

            # 2. Populate chain_failures_memory if step failed
            if not pending_step.get("success"):
                chain_failures_mem = list(state.get("chain_failures_memory", []))
                chain_failures_mem.append({
                    "step_iteration": step_iteration,
                    "failure_type": "tool_error",
                    "tool_name": pending_step.get("tool_name", ""),
                    "error_message": pending_step.get("error_message", ""),
                    "lesson_learned": analysis.interpretation[:300] if analysis else "",
                })
                updates["chain_failures_memory"] = chain_failures_mem

            # 3. Write ChainStep to Neo4j (via executor to avoid blocking the event loop)
            prev_step_id = state.get("_last_chain_step_id")
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: chain_graph.sync_record_step(
                    neo4j_uri, neo4j_user, neo4j_password,
                    step_id=step_id,
                    chain_id=session_id,
                    prev_step_id=prev_step_id,
                    user_id=user_id, project_id=project_id,
                    iteration=step_iteration, phase=phase,
                    tool_name=pending_step.get("tool_name"),
                    tool_args_summary=str(pending_step.get("tool_args", {}))[:500],
                    thought=pending_step.get("thought", "")[:20000],
                    reasoning=pending_step.get("reasoning", "")[:20000],
                    output_summary=(pending_step.get("tool_output") or "")[:20000],
                    output_analysis=analysis.interpretation[:20000] if analysis else "",
                    success=pending_step.get("success", True),
                    error_message=pending_step.get("error_message"),
                    extracted_info=analysis.extracted_info.model_dump() if analysis and analysis.extracted_info else {},
                    **get_agent_context(state),
                ),
            )
            updates["_last_chain_step_id"] = step_id

            # 4. Fire-and-forget: write exploit success (AFTER step so PRODUCED link works)
            if analysis.exploit_succeeded and analysis.exploit_details and phase == "exploitation":
                details = analysis.exploit_details
                try:
                    chain_graph.fire_record_exploit_success(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=step_id,
                        user_id=user_id,
                        project_id=project_id,
                        attack_type=details.get("attack_type", state.get("attack_path_type", "cve_exploit")),
                        target_ip=details.get("target_ip", merged_target.primary_target),
                        target_port=details.get("target_port"),
                        cve_ids=details.get("cve_ids", merged_target.vulnerabilities),
                        session_id=details.get("session_id"),
                        username=details.get("username"),
                        password_found=details.get("password"),
                        evidence=details.get("evidence", ""),
                        execution_trace=state.get("execution_trace", []),
                        iteration=step_iteration,
                    )
                    logger.info(f"[{user_id}/{project_id}/{session_id}] Exploit success detected - ChainFinding created")
                except Exception as e:
                    logger.error(f"[{user_id}/{project_id}/{session_id}] Failed to record exploit success: {e}")

            # 5. Fire-and-forget: write other ChainFindings (skip exploit-related if already recorded)
            _EXPLOIT_OVERLAP_TYPES = {"exploit_success", "access_gained", "credential_found"}
            for cf in (analysis.chain_findings or []):
                if analysis.exploit_succeeded and cf.finding_type in _EXPLOIT_OVERLAP_TYPES:
                    continue
                _ctx = get_agent_context(state)
                chain_graph.fire_record_finding(
                    neo4j_uri, neo4j_user, neo4j_password,
                    chain_id=session_id, step_id=step_id,
                    user_id=user_id, project_id=project_id,
                    finding_type=cf.finding_type, severity=cf.severity,
                    title=cf.title, evidence=cf.evidence,
                    confidence=cf.confidence, phase=phase,
                    iteration=step_iteration,
                    related_cves=cf.related_cves, related_ips=cf.related_ips,
                    related_finding_ids=getattr(cf, 'related_finding_ids', None),
                    agent_id=_ctx["agent_id"],
                    source_agent=_ctx["agent_name"],
                    fireteam_id=_ctx["fireteam_id"],
                )

            # 6. Fire-and-forget: write ChainFailure if failed
            if not pending_step.get("success"):
                chain_graph.fire_record_failure(
                    neo4j_uri, neo4j_user, neo4j_password,
                    chain_id=session_id, step_id=step_id,
                    user_id=user_id, project_id=project_id,
                    failure_type="tool_error",
                    tool_name=pending_step.get("tool_name", ""),
                    error_message=pending_step.get("error_message", ""),
                    lesson_learned=analysis.interpretation[:20000] if analysis else "",
                    phase=phase,
                    iteration=step_iteration,
                )

            # Append completed step to execution trace
            execution_trace = state.get("execution_trace", []) + [pending_step]
            updates["execution_trace"] = execution_trace
            updates["target_info"] = merged_target.model_dump()
            updates["_completed_step"] = pending_step
            updates["messages"] = [AIMessage(content=f"**Step {step_iteration}** [{phase}]\n\n{analysis.interpretation}")]

            # Productivity v2: tick the state-growth counter. Reset to 0 when
            # any engagement-state collection grew; otherwise increment. This
            # is the orchestrator-owned "are we still making progress?" signal
            # that does not depend on LLM self-report.
            _before_growth_snapshot = {
                "target_info": state.get("target_info", {}),
                "chain_findings_memory": state.get("chain_findings_memory", []),
            }
            _after_growth_snapshot = {
                "target_info": merged_target.model_dump(),
                "chain_findings_memory": chain_findings_mem,
            }
            _grew = detect_state_growth(_before_growth_snapshot, _after_growth_snapshot)
            # Fix 1: debugging a correct-but-failing approach adds no new target
            # fact, so detect_state_growth alone would mark every fix attempt as
            # "no progress" and fuel a false unproductive streak. Also reset the
            # stall counter when this step made *diagnostic* progress (a changed
            # result / error on a same-approach re-attempt, or a ruled-out cause).
            # update_stall_counters caps how long diagnostic progress can keep
            # suppressing the streak, so a dead approach still surfaces.
            _prev_step = execution_trace[-2] if len(execution_trace) >= 2 else None
            _diag = detect_diagnostic_progress(_prev_step, pending_step)
            _new_its, _new_ds = update_stall_counters(
                state.get("_iterations_since_state_grew", 0),
                state.get("_diagnostic_progress_streak", 0),
                grew=_grew, diag=_diag,
                cap=int(get_setting('DIAGNOSTIC_PROGRESS_MAX_STREAK', 6)),
            )
            updates["_iterations_since_state_grew"] = _new_its
            updates["_diagnostic_progress_streak"] = _new_ds
            # Proposal 3: DEPTH counter — iterations since the chain last advanced
            # (a confirmed finding / foothold, NOT mere map-growth). Feeds the
            # churn-aware novelty saturation next think turn.
            _chain_grew = detect_chain_advance(_before_growth_snapshot, _after_growth_snapshot)
            updates["_iterations_since_chain_advance"] = (
                0 if _chain_grew else int(state.get("_iterations_since_chain_advance", 0) or 0) + 1
            )

            # Productivity v2: record the completed step on the axis ledger.
            # `extract_axis` returns None for tool calls that aren't expensive
            # / repeat-prone enough to track (recon probes, single-shot
            # curls, etc.) — those are skipped silently.
            try:
                _axis = extract_axis(
                    pending_step.get("tool_name"),
                    pending_step.get("tool_args") or {},
                )
                if _axis:
                    _verdict_val = (_productivity_dict or {}).get("verdict") or (
                        "hard_failure" if not pending_step.get("success", True) else "confirmation"
                    )
                    _new_axes = record_axis_attempt(
                        state.get("tested_axes", {}),
                        axis_key(_axis),
                        iteration=step_iteration,
                        verdict=_verdict_val,
                        tool=pending_step.get("tool_name", ""),
                    )
                    updates["tested_axes"] = _new_axes
                    logger.info(
                        f"[{user_id}/{project_id}/{session_id}] axis recorded "
                        f"{axis_key(_axis)} verdict={_verdict_val} "
                        f"prior_unproductive={axis_unproductive_count(_new_axes, axis_key(_axis))}"
                    )
            except Exception as _e_axis:
                logger.warning(f"axis recording failed: {_e_axis}")

        else:
            # LLM didn't return analysis — use raw output as fallback
            logger.warning(f"[{user_id}/{project_id}/{session_id}] No output_analysis in LLM response, using fallback")
            pending_step["output_analysis"] = (pending_step.get("tool_output") or "")[:20000]
            pending_step["actionable_findings"] = []
            pending_step["recommended_next_steps"] = []
            execution_trace = state.get("execution_trace", []) + [pending_step]
            updates["execution_trace"] = execution_trace
            updates["_completed_step"] = pending_step

    # Process plan wave outputs — uses same output_analysis as single-tool path
    if has_pending_plan_outputs:
        plan_steps = pending_plan.get("steps", [])
        analysis = decision.output_analysis  # Same field as single-tool
        plan_iteration = iteration - 1

        merged_target = TargetInfo(**state.get("target_info", {}))
        chain_findings_mem = list(state.get("chain_findings_memory", []))
        chain_failures_mem = list(state.get("chain_failures_memory", []))
        new_trace_entries = []

        # Productivity verdict for the whole wave (one verdict shared across
        # all steps in the wave). Audited against actual state delta.
        _wave_productivity: dict = {}
        if analysis:
            _wave_productivity = (
                analysis.productivity.model_dump()
                if getattr(analysis, "productivity", None) else {}
            )
            _wave_findings_will_grow = bool(
                (analysis.chain_findings or [])
                or (analysis.exploit_succeeded and analysis.exploit_details)
                or (analysis.actionable_findings and not analysis.chain_findings)
            )
            _wave_discrepancy = audit_productivity_claim(
                productivity=_wave_productivity,
                extracted_info=(
                    analysis.extracted_info.model_dump()
                    if analysis.extracted_info else {}
                ),
                actionable_findings=analysis.actionable_findings or [],
                findings_grew=_wave_findings_will_grow,
            )
            if _wave_discrepancy:
                _wave_productivity = downgrade_verdict_to_no_progress(
                    _wave_productivity, _wave_discrepancy,
                )
                logger.info(
                    f"[{user_id}/{project_id}/{session_id}] Wave productivity "
                    f"verdict downgraded to no_progress: {_wave_discrepancy}"
                )
                updates["_last_productivity_discrepancy"] = _wave_discrepancy
            else:
                updates["_last_productivity_discrepancy"] = None

        if analysis:
            logger.info(f"\n{'='*60}")
            logger.info(f"PLAN OUTPUT ANALYSIS (combined) - {len(plan_steps)} tools")
            logger.info(f"{'='*60}")
            logger.info(f"  INTERPRETATION: {analysis.interpretation[:200]}")

            # Single target info merge from combined extracted_info
            extracted = analysis.extracted_info
            new_target = TargetInfo(
                primary_target=extracted.primary_target,
                ports=extracted.ports, services=extracted.services,
                technologies=extracted.technologies,
                vulnerabilities=extracted.vulnerabilities,
                credentials=extracted.credentials, sessions=extracted.sessions,
            )
            merged_target = merged_target.merge_from(new_target)

            # Chain findings (once, from combined analysis)
            if analysis.chain_findings:
                for cf in analysis.chain_findings:
                    finding_dict = cf.model_dump() if hasattr(cf, 'model_dump') else (cf if isinstance(cf, dict) else {})
                    finding_dict["step_iteration"] = plan_iteration
                    chain_findings_mem.append(finding_dict)
            elif analysis.actionable_findings:
                # Fallback: promote actionable_findings to chain_findings_memory
                for af_text in analysis.actionable_findings:
                    chain_findings_mem.append({
                        "finding_type": "custom",
                        "severity": "info",
                        "title": af_text[:200],
                        "evidence": "",
                        "step_iteration": plan_iteration,
                        "confidence": 60,
                    })

            # Exploit success
            if analysis.exploit_succeeded and analysis.exploit_details:
                details = analysis.exploit_details
                chain_findings_mem.append({
                    "finding_type": "exploit_success", "severity": "critical",
                    "title": f"Exploit success: {details.get('evidence', '')[:100]}",
                    "evidence": details.get("evidence", ""),
                    "step_iteration": plan_iteration, "confidence": 95,
                    "related_cves": details.get("cve_ids", []),
                    "related_ips": [details.get("target_ip", "")] if details.get("target_ip") else [],
                })

            logger.info(f"{'='*60}\n")

            # Emit plan_analysis to frontend so PlanWaveCard shows Analysis/Findings/NextSteps
            wave_id = pending_plan.get("wave_id")
            if wave_id and streaming_callbacks:
                streaming_cb = streaming_callbacks.get(session_id)
                if streaming_cb:
                    try:
                        await streaming_cb.on_plan_analysis(
                            wave_id=wave_id,
                            interpretation=analysis.interpretation,
                            actionable_findings=analysis.actionable_findings or [],
                            recommended_next_steps=analysis.recommended_next_steps or [],
                        )
                    except Exception as e:
                        logger.warning(f"Error emitting plan_analysis: {e}")
        else:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] No output_analysis for wave, using fallback for {len(plan_steps)} tools")

        # Create one ExecutionStep per plan tool (for trace granularity)
        # Use sync writes so each step exists before the next links to it
        prev_chain_step_id = state.get("_last_chain_step_id")
        loop = asyncio.get_running_loop()

        # Combined extracted_info for all wave tools (same for each — wave has one analysis)
        combined_extracted = {}
        if analysis and analysis.extracted_info:
            combined_extracted = analysis.extracted_info.model_dump() if hasattr(analysis.extracted_info, 'model_dump') else {}

        for i, plan_step in enumerate(plan_steps):
            step_id = uuid4().hex[:8]
            step_thought = f"[Wave] {plan_step.get('rationale', '')}"
            step_reasoning = pending_plan.get("plan_rationale", "")
            step_output_analysis = analysis.interpretation if analysis else (plan_step.get("tool_output") or "")[:20000]

            exec_step = {
                "step_id": step_id,
                "iteration": plan_iteration,
                "timestamp": utc_now().isoformat(),
                "phase": phase,
                "thought": step_thought,
                "reasoning": step_reasoning,
                "tool_name": plan_step.get("tool_name"),
                "tool_args": plan_step.get("tool_args"),
                "tool_output": plan_step.get("tool_output"),
                "success": plan_step.get("success", False),
                "error_message": plan_step.get("error_message"),
                # Diagnostic fields populated by execute_plan_node. Without
                # propagating them here, the P1+P2 chain-context annotations
                # (`[12ms, application_5xx_fast]`) and the P3 anomaly detector
                # see nothing because plan-wave steps land in the trace
                # without diagnostic data.
                "duration_ms": plan_step.get("duration_ms"),
                "error_class": plan_step.get("error_class"),
                "output_analysis": step_output_analysis,
                "actionable_findings": (analysis.actionable_findings or []) if analysis else [],
                "recommended_next_steps": (analysis.recommended_next_steps or []) if analysis else [],
                # Wave-level productivity verdict copied onto every wave step so
                # the loop detector can read it from any single step in isolation.
                "productivity": dict(_wave_productivity) if _wave_productivity else {},
            }
            new_trace_entries.append(exec_step)

            # Chain failure per failed tool (memory + Neo4j)
            if not plan_step.get("success"):
                chain_failures_mem.append({
                    "step_iteration": plan_iteration,
                    "failure_type": "tool_error",
                    "tool_name": plan_step.get("tool_name", ""),
                    "error_message": plan_step.get("error_message", ""),
                    "lesson_learned": analysis.interpretation[:300] if analysis else "",
                })

            # Neo4j chain step (sync so prev_step_id linkage is sequential)
            # Capture all loop variables via default args to avoid closure issues
            _ctx = get_agent_context(state)
            await loop.run_in_executor(
                None,
                lambda _sid=step_id, _prev=prev_chain_step_id, _ps=plan_step,
                       _ei=combined_extracted, _thought=step_thought,
                       _reasoning=step_reasoning, _oa=step_output_analysis,
                       _c=_ctx: chain_graph.sync_record_step(
                    neo4j_uri, neo4j_user, neo4j_password,
                    step_id=_sid,
                    chain_id=session_id,
                    prev_step_id=_prev,
                    user_id=user_id, project_id=project_id,
                    iteration=plan_iteration, phase=phase,
                    tool_name=_ps.get("tool_name", ""),
                    tool_args_summary=str(_ps.get("tool_args", {}))[:500],
                    thought=_thought[:20000],
                    reasoning=_reasoning[:20000],
                    output_summary=(_ps.get("tool_output") or "")[:20000],
                    output_analysis=_oa[:20000],
                    success=_ps.get("success", False),
                    error_message=_ps.get("error_message"),
                    extracted_info=_ei,
                    agent_id=_c["agent_id"],
                    agent_name=_c["agent_name"],
                    fireteam_id=_c["fireteam_id"],
                ),
            )
            # Update prev for next tool in wave (sequential chain linkage)
            prev_chain_step_id = step_id

            # Neo4j ChainFailure node for failed tools (mirrors single-tool path)
            if not plan_step.get("success"):
                chain_graph.fire_record_failure(
                    neo4j_uri, neo4j_user, neo4j_password,
                    chain_id=session_id, step_id=step_id,
                    user_id=user_id, project_id=project_id,
                    failure_type="tool_error",
                    tool_name=plan_step.get("tool_name", ""),
                    error_message=plan_step.get("error_message", ""),
                    lesson_learned=analysis.interpretation[:20000] if analysis else "",
                    phase=phase,
                    iteration=plan_iteration,
                )

        # Neo4j exploit success (mirrors single-tool path)
        if analysis and analysis.exploit_succeeded and analysis.exploit_details and phase == "exploitation":
            last_step_id = new_trace_entries[-1]["step_id"] if new_trace_entries else None
            if last_step_id:
                details = analysis.exploit_details
                try:
                    chain_graph.fire_record_exploit_success(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=last_step_id,
                        user_id=user_id,
                        project_id=project_id,
                        attack_type=details.get("attack_type", state.get("attack_path_type", "cve_exploit")),
                        target_ip=details.get("target_ip", merged_target.primary_target),
                        target_port=details.get("target_port"),
                        cve_ids=details.get("cve_ids", merged_target.vulnerabilities),
                        session_id=details.get("session_id"),
                        username=details.get("username"),
                        password_found=details.get("password"),
                        evidence=details.get("evidence", ""),
                        execution_trace=state.get("execution_trace", []) + new_trace_entries,
                        iteration=plan_iteration,
                    )
                    logger.info(f"[{user_id}/{project_id}/{session_id}] Wave exploit success detected - ChainFinding created")
                except Exception as e:
                    logger.error(f"[{user_id}/{project_id}/{session_id}] Failed to record wave exploit success: {e}")

        # Neo4j chain findings (linked to last step — step already exists from sync write)
        if analysis and new_trace_entries:
            last_step_id = new_trace_entries[-1]["step_id"]
            # Skip exploit-related findings if exploit success already recorded (mirrors single-tool)
            _EXPLOIT_OVERLAP_TYPES = {"exploit_success", "access_gained", "credential_found"}
            _ctx = get_agent_context(state)
            for cf in (analysis.chain_findings or []):
                if analysis.exploit_succeeded and cf.finding_type in _EXPLOIT_OVERLAP_TYPES:
                    continue
                chain_graph.fire_record_finding(
                    neo4j_uri, neo4j_user, neo4j_password,
                    chain_id=session_id, step_id=last_step_id,
                    user_id=user_id, project_id=project_id,
                    finding_type=cf.finding_type, severity=cf.severity,
                    title=cf.title, evidence=cf.evidence,
                    confidence=cf.confidence, phase=phase,
                    iteration=plan_iteration,
                    related_cves=cf.related_cves, related_ips=cf.related_ips,
                    related_finding_ids=getattr(cf, 'related_finding_ids', None),
                    agent_id=_ctx["agent_id"],
                    source_agent=_ctx["agent_name"],
                    fireteam_id=_ctx["fireteam_id"],
                )

        # Update state
        updates["execution_trace"] = state.get("execution_trace", []) + new_trace_entries
        updates["target_info"] = merged_target.model_dump()
        updates["chain_findings_memory"] = chain_findings_mem
        updates["chain_failures_memory"] = chain_failures_mem
        if not (decision.action == "plan_tools" and decision.tool_plan):
            updates["_current_plan"] = None
        if new_trace_entries:
            updates["_last_chain_step_id"] = new_trace_entries[-1]["step_id"]
        tool_summary = ", ".join(f"{s.get('tool_name')}({'OK' if s.get('success') else 'FAIL'})" for s in plan_steps)
        overall = analysis.interpretation if analysis else "Plan wave completed"
        updates["messages"] = [AIMessage(content=f"**Wave** [{phase}] {tool_summary}\n\n{overall}")]

        # Productivity v2: tick state-growth and record axes for wave steps.
        # The wave path was missing these and would have left axis lock-in
        # invisible in fireteam / plan_tools mode. Mirrors the single-tool
        # path's logic, applied once per wave.
        _before_growth_snapshot = {
            "target_info": state.get("target_info", {}),
            "chain_findings_memory": state.get("chain_findings_memory", []),
        }
        _after_growth_snapshot = {
            "target_info": merged_target.model_dump(),
            "chain_findings_memory": chain_findings_mem,
        }
        # Fix 1 (wave path): mirror the single-tool path — reset the stall
        # counter on target-state growth OR diagnostic progress, with the same
        # cap on how long diagnostic progress may suppress the streak.
        _wave_trace = updates.get("execution_trace") or state.get("execution_trace") or []
        _wave_prev = _wave_trace[-2] if len(_wave_trace) >= 2 else None
        _wave_cur = _wave_trace[-1] if _wave_trace else None
        _wave_grew = detect_state_growth(_before_growth_snapshot, _after_growth_snapshot)
        _wave_diag = detect_diagnostic_progress(_wave_prev, _wave_cur)
        _w_its, _w_ds = update_stall_counters(
            state.get("_iterations_since_state_grew", 0),
            state.get("_diagnostic_progress_streak", 0),
            grew=_wave_grew, diag=_wave_diag,
            cap=int(get_setting('DIAGNOSTIC_PROGRESS_MAX_STREAK', 6)),
        )
        updates["_iterations_since_state_grew"] = _w_its
        updates["_diagnostic_progress_streak"] = _w_ds
        # Proposal 3: DEPTH counter for the wave path (mirror of the single-tool path).
        _wave_chain_grew = detect_chain_advance(_before_growth_snapshot, _after_growth_snapshot)
        updates["_iterations_since_chain_advance"] = (
            0 if _wave_chain_grew else int(state.get("_iterations_since_chain_advance", 0) or 0) + 1
        )

        # Record an axis attempt per wave step that has an extractable axis.
        # Use the wave-level productivity verdict (all wave steps share it).
        _current_axes = state.get("tested_axes", {}) or {}
        _wave_verdict = (
            (_wave_productivity or {}).get("verdict") if _wave_productivity else None
        )
        for _ps in plan_steps:
            try:
                _ax = extract_axis(_ps.get("tool_name"), _ps.get("tool_args") or {})
                if not _ax:
                    continue
                _verdict_for_ax = _wave_verdict or (
                    "hard_failure" if not _ps.get("success", True) else "confirmation"
                )
                _current_axes = record_axis_attempt(
                    _current_axes, axis_key(_ax),
                    iteration=plan_iteration,
                    verdict=_verdict_for_ax,
                    tool=_ps.get("tool_name", ""),
                )
            except Exception as _e_ax_wave:
                logger.warning(f"wave-path axis recording failed: {_e_ax_wave}")
        updates["tested_axes"] = _current_axes

    # Handle different actions
    if decision.action == "complete":
        updates["task_complete"] = True
        updates["completion_reason"] = decision.completion_reason or "Task completed"

    elif decision.action == "transition_phase":
        phase_transition = decision.phase_transition
        to_phase = phase_transition.to_phase if phase_transition else "exploitation"

        # Block post-exploitation if ACTIVATE_POST_EXPL_PHASE=False
        if to_phase == "post_exploitation" and not get_setting('ACTIVATE_POST_EXPL_PHASE', True):
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Blocking post_exploitation transition: ACTIVATE_POST_EXPL_PHASE=False")
            updates["task_complete"] = True
            updates["completion_reason"] = "Exploitation completed. Post-exploitation phase is disabled."
            updates["messages"] = [
                AIMessage(content="Exploitation completed successfully. "
                                 "Post-exploitation phase is not available because ACTIVATE_POST_EXPL_PHASE=False. "
                                 "If you need post-exploitation capabilities, enable it in the project settings.")
            ]
            return updates

        # Ignore transition to same phase - just continue
        if to_phase == phase:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Ignoring transition to same phase: {phase}")
            if decision.tool_name:
                updates["_decision"]["action"] = "use_tool"
                updates["_redundant_transition_count"] = 0
            else:
                _rc = int(state.get("_redundant_transition_count", 0) or 0) + 1
                updates["_redundant_transition_count"] = _rc
                logger.info(f"[{user_id}/{project_id}/{session_id}] No tool specified, looping back to think (redundant same-phase transition #{_rc})")
                # Deliver the correction on the channel the model actually re-reads
                # (execution_trace -> chain_context), clear the leftover transition
                # todo, and escalate wording after repeats. The messages nudge below
                # never reaches the think LLM (state["messages"] is not replayed).
                updates["todo_list"] = _complete_transition_todos(
                    updates.get("todo_list") or state.get("todo_list", []), phase
                )
                updates["execution_trace"] = _phase_breadcrumb_trace(
                    state, updates, iteration, phase, redundant=True, count=_rc
                )
                updates["messages"] = [HumanMessage(
                    content=f"[system] You are ALREADY in the {phase} phase — that transition was a "
                            f"no-op and did NOT end anything. Do NOT request transition_phase to "
                            f"{phase} again. Proceed with the next concrete step of your workflow "
                            f"(probe/build/submit your payload)."
                )]
            return updates

        # Also ignore if we JUST transitioned to this phase
        if just_transitioned and to_phase == just_transitioned:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Ignoring re-request for recent transition to: {to_phase}")
            if decision.tool_name:
                updates["_decision"]["action"] = "use_tool"
                updates["_redundant_transition_count"] = 0
            else:
                _rc = int(state.get("_redundant_transition_count", 0) or 0) + 1
                updates["_redundant_transition_count"] = _rc
                logger.info(f"[{user_id}/{project_id}/{session_id}] No tool specified, looping back to think (redundant re-request #{_rc})")
                updates["todo_list"] = _complete_transition_todos(
                    updates.get("todo_list") or state.get("todo_list", []), to_phase
                )
                updates["execution_trace"] = _phase_breadcrumb_trace(
                    state, updates, iteration, to_phase, redundant=True, count=_rc
                )
                updates["messages"] = [HumanMessage(
                    content=f"[system] You just transitioned to {to_phase} and are already there. "
                            f"Do NOT request that transition again. Proceed with your workflow's next step."
                )]
            return updates

        # AUTO-APPROVE: Downgrade to informational (safe, no approval needed)
        if to_phase == "informational" and phase in ["exploitation", "post_exploitation"]:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Auto-approving safe downgrade: {phase} → informational")
            updates["current_phase"] = to_phase
            updates["phase_history"] = state.get("phase_history", []) + [
                PhaseHistoryEntry(phase=to_phase).model_dump()
            ]
            updates["_just_transitioned_to"] = to_phase
            updates["messages"] = [
                AIMessage(content=f"Automatically transitioned from {phase} to informational phase for new objective.")
            ]
            return updates

        # Check if approval is required
        needs_approval = (
            (to_phase == "exploitation" and get_setting('REQUIRE_APPROVAL_FOR_EXPLOITATION', True)) or
            (to_phase == "post_exploitation" and get_setting('REQUIRE_APPROVAL_FOR_POST_EXPLOITATION', True))
        )

        if needs_approval:
            updates["phase_transition_pending"] = PhaseTransitionRequest(
                from_phase=phase,
                to_phase=to_phase,
                reason=phase_transition.reason if phase_transition else "",
                planned_actions=phase_transition.planned_actions if phase_transition else [],
                risks=phase_transition.risks if phase_transition else [],
            ).model_dump()
            updates["awaiting_user_approval"] = True
        else:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Auto-approving phase transition (approval not required): {phase} → {to_phase}")
            updates["current_phase"] = to_phase
            updates["phase_history"] = state.get("phase_history", []) + [
                PhaseHistoryEntry(phase=to_phase).model_dump()
            ]
            updates["_just_transitioned_to"] = to_phase
            updates["_redundant_transition_count"] = 0
            # Record the transition in execution_trace so the think LLM actually
            # sees it next turn (it never replays state["messages"]), and check off
            # any leftover "request transition" todo so it stops reading as open
            # work. Mirrors the approval-node path, which the manual-approval flow
            # already does; the auto-approve path previously skipped both, which is
            # what let the model loop re-requesting a transition it already had.
            updates["execution_trace"] = _phase_breadcrumb_trace(
                state, updates, iteration, to_phase, redundant=False
            )
            updates["todo_list"] = _complete_transition_todos(
                updates.get("todo_list") or state.get("todo_list", []), to_phase
            )
            updates["messages"] = [
                AIMessage(content=f"Phase transition from {phase} to {to_phase} auto-approved (approval not required in settings). Now operating in {to_phase} phase. Proceed with the objective.")
            ]

    elif decision.action == "switch_skill":
        # Rebind attack_path_type mid-run WITHOUT a phase change. The next think
        # iteration re-reads attack_path_type and injects the matching skill
        # workflow (gated only on the skill being enabled + its tool being in the
        # current phase's allowed_tools — phase itself is never tested). Routing:
        # _route_after_think sends action=switch_skill straight back to `think`
        # in every case below, so the agent always keeps working.
        skill_switch = decision.skill_switch
        new_skill = skill_switch.to_skill if skill_switch else None
        current_skill = state.get("attack_path_type", "")

        # Validate against the SAME contract the classifier uses (enabled builtin,
        # enabled user_skill:<id>, or *-unclassified). Pure decision lives in
        # state.evaluate_skill_switch so it is unit-testable in isolation.
        enabled_builtins = get_enabled_builtin_skills()
        enabled_user_ids = {s.get("id") for s in get_enabled_user_skills()}
        outcome, resolved = evaluate_skill_switch(
            new_skill, current_skill, enabled_builtins, enabled_user_ids
        )

        if outcome == "rejected":
            logger.warning(
                f"[{user_id}/{project_id}/{session_id}] switch_skill rejected: "
                f"'{new_skill}' is not an enabled/valid skill"
            )
            # Same root cause as the redundant phase-transition churn: state["messages"]
            # is never replayed into the stateless think prompt, so a messages-only
            # rejection is invisible to the model and it can re-request the same invalid
            # skill in a loop. Put the correction into execution_trace (chain_context),
            # the channel the think LLM actually re-reads.
            _rej_step = ExecutionStep(
                iteration=iteration,
                phase=phase,
                thought=f"switch_skill to '{new_skill}' rejected (not an enabled skill).",
                reasoning="Requested attack skill is not enabled/valid.",
                tool_name="switch_skill",
                tool_args={"to_skill": new_skill, "rejected": True},
                tool_output=f"REJECTED: '{new_skill}' is not an enabled attack skill.",
                success=False,
                output_analysis=(
                    f"Do NOT request switch_skill to '{new_skill}' again — it is not "
                    f"enabled. Enabled skills: {sorted(enabled_builtins)}. Keep working "
                    f"with your current skill, or switch to one of the enabled skills."
                ),
            )
            _rej_base = updates["execution_trace"] if "execution_trace" in updates else state.get("execution_trace", [])
            updates["execution_trace"] = _rej_base + [_rej_step.model_dump()]
            updates["messages"] = [HumanMessage(
                content=f"[system] switch_skill rejected: '{new_skill}' is not an enabled attack "
                        f"skill. Enabled skills: {sorted(enabled_builtins)}. Keep working with your "
                        f"current skill, or emit switch_skill again with an enabled to_skill."
            )]
        elif outcome == "noop":
            logger.info(
                f"[{user_id}/{project_id}/{session_id}] switch_skill to current skill "
                f"'{resolved}' — no-op, continuing"
            )
        else:  # "switched"
            logger.info(
                f"[{user_id}/{project_id}/{session_id}] Attack skill switched: "
                f"'{current_skill or 'unclassified'}' -> '{resolved}'"
            )
            updates["attack_path_type"] = resolved
            reason = (skill_switch.reason if skill_switch else "") or ""
            _switch_msg = (
                f"Attack skill switched from '{current_skill or 'unclassified'}' to "
                f"'{resolved}'" + (f": {reason}" if reason else "") +
                ". The specialized workflow for this skill is now active."
            )
            # Proposal 1: behavior-triggered phase switch. Switching to an offensive
            # attack skill while still in recon signals intent to exploit, so move to
            # the exploitation phase automatically instead of waiting for a manual
            # transition_phase action the agent tends to neglect. Only auto-FLIP when
            # approval is not required (the unattended/CTF path); when approval IS
            # required we leave the phase as-is so the agent's own transition_phase
            # drives the proper approval routing (switch_skill routes straight back to
            # think and would otherwise bypass the approval gate).
            if (get_setting('AUTO_TRANSITION_ON_ATTACK_SKILL', True)
                    and should_auto_transition_on_skill(resolved, phase)
                    and not get_setting('REQUIRE_APPROVAL_FOR_EXPLOITATION', True)):
                logger.info(
                    f"[{user_id}/{project_id}/{session_id}] Auto-transition to "
                    f"exploitation on attack skill '{resolved}' (was informational)"
                )
                updates["current_phase"] = "exploitation"
                updates["phase_history"] = state.get("phase_history", []) + [
                    PhaseHistoryEntry(phase="exploitation").model_dump()
                ]
                updates["_just_transitioned_to"] = "exploitation"
                updates["_redundant_transition_count"] = 0
                updates["execution_trace"] = _phase_breadcrumb_trace(
                    state, updates, iteration, "exploitation", redundant=False
                )
                updates["todo_list"] = _complete_transition_todos(
                    updates.get("todo_list") or state.get("todo_list", []), "exploitation"
                )
                _switch_msg += (
                    " Auto-transitioned to the exploitation phase (an offensive skill "
                    "is now active) — proceed with exploitation."
                )
            updates["messages"] = [AIMessage(content=_switch_msg)]
            # Persist the switch to the attack-chain graph (fire-and-forget) so the
            # UI/graph reflect the new class; core behavior does not depend on this.
            chain_graph.fire_update_chain_attack_path(
                neo4j_uri, neo4j_user, neo4j_password,
                chain_id=session_id, attack_path_type=resolved,
            )

    elif decision.action == "ask_user":
        user_q = decision.user_question
        if user_q:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Asking user: {user_q.question[:10000]}")
            updates["pending_question"] = UserQuestionRequest(
                question=user_q.question,
                context=user_q.context,
                format=user_q.format,
                options=user_q.options,
                default_value=user_q.default_value,
                phase=phase,
            ).model_dump()
            updates["awaiting_user_question"] = True
        else:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] ask_user action but no user_question provided")

    # Pre-exploitation validation: Force ask_user when session params are missing
    if (get_setting('POST_EXPL_PHASE_TYPE', 'statefull') == "statefull" and
        state.get("attack_path_type") == "cve_exploit" and
        decision.action == "use_tool" and
        decision.tool_name == "metasploit_console" and
        not updates.get("awaiting_user_question")):

        config_complete, missing_params = is_session_config_complete()

        if not config_complete:
            qa_history = state.get("qa_history", [])
            answered_params = set()
            for qa in qa_history:
                answer = qa.get("answer", {})
                answer_text = answer.get("answer", "") if answer else ""
                question_obj = qa.get("question", {})
                question_text = question_obj.get("question", "") if question_obj else ""

                if answer_text:
                    if "LHOST" in question_text.upper():
                        answered_params.add("LHOST")
                    if "LPORT" in question_text.upper():
                        answered_params.add("LPORT")
                    if "BIND" in question_text.upper():
                        answered_params.add("LPORT or BIND_PORT_ON_TARGET")

            still_missing = [p for p in missing_params if p not in answered_params]

            if still_missing:
                logger.info(f"[{user_id}/{project_id}/{session_id}] Forcing ask_user: missing session params {still_missing}")
                updates["_decision"]["action"] = "ask_user"
                updates["pending_question"] = UserQuestionRequest(
                    question=f"Please provide the following required parameters for session-based exploitation: {', '.join(still_missing)}",
                    context="Session-based exploitation requires these parameters to be configured. "
                            "LHOST is your attacker IP address where the target will connect back. "
                            "LPORT is the port you will listen on. "
                            "For bind payloads, BIND_PORT is the port the target will open.",
                    format="text",
                    phase=phase,
                ).model_dump()
                updates["awaiting_user_question"] = True

    # Tool confirmation gate — only when setting enabled and no other gate active
    if (get_setting('REQUIRE_TOOL_CONFIRMATION', True)
            and not updates.get("awaiting_user_approval")
            and not updates.get("awaiting_user_question")):

        action = decision.action
        if action == "use_tool" and decision.tool_name in DANGEROUS_TOOLS:
            updates["awaiting_tool_confirmation"] = True
            updates["tool_confirmation_pending"] = ToolConfirmationRequest(
                mode="single",
                tools=[{
                    "tool_name": decision.tool_name,
                    "tool_args": decision.tool_args or {},
                    "rationale": decision.reasoning or "",
                }],
                reasoning=decision.reasoning or "",
                phase=phase,
                iteration=iteration,
            ).model_dump()

        elif action == "plan_tools" and decision.tool_plan:
            dangerous = [
                {
                    "tool_name": s.tool_name,
                    "tool_args": s.tool_args,
                    "rationale": s.rationale,
                }
                for s in decision.tool_plan.steps
                if s.tool_name in DANGEROUS_TOOLS
            ]
            if dangerous:
                updates["awaiting_tool_confirmation"] = True
                updates["tool_confirmation_pending"] = ToolConfirmationRequest(
                    mode="plan",
                    tools=dangerous,
                    reasoning=decision.tool_plan.plan_rationale,
                    phase=phase,
                    iteration=iteration,
                ).model_dump()

    # If tool confirmation is pending, suppress the step analysis message
    # (it would show as a premature "Step X" report in chat; analysis is already
    # communicated via tool_complete streaming event)
    if updates.get("awaiting_tool_confirmation"):
        updates.pop("messages", None)

    return updates
