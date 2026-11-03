"""Initialize node — handles new vs continuing objectives and attack chain creation."""

import asyncio
import logging
import zoneinfo
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, HumanMessage

from state import (
    AgentState,
    ConversationObjective,
    ObjectiveOutcome,
    PhaseHistoryEntry,
    TargetInfo,
    format_prior_chains,
    utc_now,
)
import orchestrator_helpers.chain_graph_writer as chain_graph
from orchestrator_helpers.config import get_config_values
from orchestrator_helpers.phase import classify_attack_path, determine_phase_for_new_objective
from neo4j_read_pool import run_neo4j_read
from project_settings import get_setting

logger = logging.getLogger(__name__)

# Seconds a session's first turn waits for the optional prior-chain context.
PRIOR_CHAINS_WAIT_S = 15.0


def _build_guardrail_block(user_id, project_id, session_id, target_desc, reason) -> dict:
    """Build state update that blocks the agent with a guardrail message."""
    return {
        "messages": [AIMessage(content=(
            f"**Scope Guardrail: Target Blocked**\n\n"
            f"The target `{target_desc}` has been blocked by the security guardrail.\n\n"
            f"**Reason:** {reason}\n\n"
            f"This guardrail prevents scanning well-known public services, government websites, "
            f"and major companies that you are unlikely authorized to test. "
            f"Please create a new project with a target you are authorized to scan."
        ))],
        "task_complete": True,
        "completion_reason": f"Guardrail blocked: {reason}",
        "_guardrail_blocked": True,
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
    }


def _build_guardrail_error(user_id, project_id, session_id, target_desc, error) -> dict:
    """Build state update when the guardrail check itself fails (LLM error)."""
    return {
        "messages": [AIMessage(content=(
            f"**Scope Guardrail: Check Failed**\n\n"
            f"The guardrail could not verify whether `{target_desc}` is authorized for scanning "
            f"because the LLM check encountered an error.\n\n"
            f"**Error:** {error}\n\n"
            f"**What to do:**\n"
            f"- Verify your LLM model is correctly configured (must be a chat model)\n"
            f"- Check that your API key is valid and the provider is reachable\n"
            f"- Check the agent logs for more details\n\n"
            f"The agent uses a fail-closed policy — it will not proceed until the guardrail "
            f"can successfully verify the target."
        ))],
        "task_complete": True,
        "completion_reason": f"Guardrail check failed: {error}",
        "_guardrail_blocked": True,
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
    }


LOOP_GUARDRAIL_NO_ANSWER = "Scope Guardrail: your external agent did not answer"


def _build_guardrail_loop_failure(user_id, project_id, session_id, target_desc, exc) -> dict:
    """The guardrail step of an Agent in the Loop run got no answer: still blocked."""
    return {
        "messages": [AIMessage(content=(
            f"**{LOOP_GUARDRAIL_NO_ANSWER}**\n\n"
            f"The scope check for `{target_desc}` is answered by your external agent "
            f"(Agent in the Loop), and it did not answer ({exc.code}). Start Claude Code "
            f"or Codex with the Agent in the Loop skill, say \"Drive my RedAmon session\", "
            f"and send your message again.\n\n"
            f"The agent uses a fail-closed policy: it will not proceed until the guardrail "
            f"can verify the target."
        ))],
        "task_complete": True,
        "completion_reason": LOOP_GUARDRAIL_NO_ANSWER,
        "_guardrail_blocked": True,
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
    }


async def _run_scope_guardrail(llm, user_id, project_id, session_id) -> dict | None:
    """Run LLM-based guardrail check on the project's target scope.

    FAIL CLOSED: if the LLM is unavailable or errors occur, the agent refuses
    to proceed. This is intentional — the agent must never blindly trust
    project settings, even if the creation-time guardrail was bypassed.

    Returns a state update dict if blocked, or None if allowed.
    """
    from orchestrator_helpers.guardrail import check_target_allowed
    from project_settings import soft_guardrail_names

    ip_mode = get_setting('IP_MODE', False)
    target_ips = get_setting('TARGET_IPS', [])
    # The orgs and scan roots, whatever the target mode. A Domain-batch project
    # has no TARGET_DOMAIN, so reading that field alone used to skip this check
    # on the projects with the MOST targets.
    scope_domains = soft_guardrail_names()

    # A batch project with no derivable scope is misconfigured, not unconstrained:
    # fail closed rather than fall through to "nothing to check".
    if get_setting('DOMAIN_BATCH_MODE', False) and not ip_mode and not scope_domains:
        return _build_guardrail_block(
            user_id, project_id, session_id, '',
            "This project is in Domain batch mode but has no valid domain groups, "
            "so its scope cannot be verified. Re-save its hostname list.",
        )

    # Nothing to check (no target configured yet)
    if not scope_domains and not target_ips:
        return None

    target_desc = ", ".join(scope_domains[:5]) if not ip_mode else ", ".join(target_ips[:5])

    try:
        result = await check_target_allowed(
            llm,
            # A LIST, never a joined string: the singular prompt would ask for one
            # verdict on "a.com, b.com, c.com" and could allow the set despite one
            # blocked member. check_target_allowed routes a list to the
            # block-if-any prompt.
            target_domains=[] if ip_mode else scope_domains,
            target_ips=target_ips if ip_mode else [],
        )

        # Only an explicit True passes; check_target_allowed raises on a
        # malformed verdict, which the except below refuses.
        if result.get("allowed") is not True:
            reason = result.get("reason", "Target not authorized")
            logger.warning(
                f"[{user_id}/{project_id}/{session_id}] GUARDRAIL BLOCKED: {reason}"
            )
            return _build_guardrail_block(user_id, project_id, session_id, target_desc, reason)

    except Exception as e:
        if getattr(e, "no_retry", False):
            logger.error(
                f"[{user_id}/{project_id}/{session_id}] Scope guardrail step not answered "
                f"(fail closed): {type(e).__name__}"
            )
            return _build_guardrail_loop_failure(user_id, project_id, session_id, target_desc, e)
        # FAIL CLOSED — agent must not proceed if it cannot verify the target
        logger.error(
            f"[{user_id}/{project_id}/{session_id}] Scope guardrail error (fail closed): {e}"
        )
        return _build_guardrail_error(
            user_id, project_id, session_id, target_desc, str(e)
        )

    return None


# `_scope_signature` of a session refused because its settings could not be
# loaded: the refusal was about that turn's fetch, not the target, so the next
# turn judges the scope afresh instead of staying blocked.
_SETTINGS_UNAVAILABLE = "settings-unavailable"


def _build_session_refusal(user_id, project_id, session_id, title, body, reason) -> dict:
    return {
        "messages": [AIMessage(content=f"**{title}**\n\n{body}")],
        "task_complete": True,
        "completion_reason": reason,
        "_guardrail_blocked": True,
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
    }


async def _run_scope_checks(llm, user_id, project_id, session_id) -> dict | None:
    """The session-start scope checks: a refusal update, or None to proceed."""
    from orchestrator_helpers.hard_guardrail import first_hard_blocked
    from project_settings import guardrail_names, target_scope_groups

    ip_mode = get_setting('IP_MODE', False)
    if not ip_mode:
        dropped = get_setting('SCOPE_GROUPS_DROPPED', 0) or 0
        configured = get_setting('DOMAIN_BATCH_MODE', False) or (get_setting('TARGET_DOMAIN', '') or '').strip()
        if dropped or (configured and not target_scope_groups()):
            # A group that failed validation, or a target with no valid group,
            # is a scope the agent cannot verify: never "nothing to check".
            return _build_session_refusal(
                user_id, project_id, session_id, "Scope Guardrail: Scope Unverifiable",
                "This project's target scope could not be read as valid scope groups, so the "
                "agent cannot verify what it is authorized to test. Open the project, re-save "
                "its target, and start a new message.",
                "Guardrail blocked: scope unverifiable",
            )
        # Hard guardrail: deterministic, non-disableable. EVERY in-scope name,
        # not just TARGET_DOMAIN: is_hard_blocked('') returns "not blocked", so
        # checking the empty field of a batch project disarmed it entirely. One
        # blocked name blocks the session.
        hit = first_hard_blocked(guardrail_names())
        if hit:
            target_domain, reason = hit
            logger.warning(f"[{user_id}/{project_id}/{session_id}] HARD GUARDRAIL BLOCKED: {reason}")
            return _build_guardrail_block(user_id, project_id, session_id, target_domain, reason)

    if get_setting('AGENT_GUARDRAIL_ENABLED', True):
        return await _run_scope_guardrail(llm, user_id, project_id, session_id)
    return None


async def _scope_gate(state, llm, user_id, project_id, session_id) -> tuple[dict | None, dict]:
    """(refusal, updates). The scope checks run at session start and again on any
    later turn whose scope differs from the one last checked: a mid-session
    rescope must not inherit the old scope's approval."""
    from project_settings import SETTINGS_SOURCE_KEY, scope_signature

    previous = state.get("_scope_signature")
    retry = bool(state.get("_guardrail_blocked")) and previous == _SETTINGS_UNAVAILABLE
    if state.get("_guardrail_blocked") and not retry:
        return None, {}

    if get_setting(SETTINGS_SOURCE_KEY) == "default":
        # The defaults have no target: running on them would skip every scope
        # check. Refuse rather than test an unverified scope.
        logger.error(f"[{user_id}/{project_id}/{session_id}] Project settings unavailable; refusing the turn")
        refusal = _build_session_refusal(
            user_id, project_id, session_id, "Project Settings Unavailable",
            "The agent could not load this project's settings, so it cannot verify the target "
            "scope and will not run on defaults. Check that the webapp is reachable, then send "
            "the message again.",
            "Project settings unavailable",
        )
        refusal["_scope_signature"] = _SETTINGS_UNAVAILABLE
        return refusal, {}

    signature = scope_signature()
    if state.get("execution_trace") and not retry and previous == signature:
        return None, {"_scope_signature": signature}
    if state.get("execution_trace") and not retry:
        logger.warning(f"[{user_id}/{project_id}/{session_id}] Scope changed mid-session; re-running the guardrails")

    refusal = await _run_scope_checks(llm, user_id, project_id, session_id)
    if refusal is not None:
        refusal["_scope_signature"] = signature
        return refusal, {}
    updates = {"_scope_signature": signature}
    if retry:
        updates["_guardrail_blocked"] = False
    return None, updates


def _roe_timing_warnings(now_utc: datetime, get=None) -> list[str]:
    """Why ``now_utc`` falls outside the engagement dates or the testing window.

    ``get(key, default)`` reads the settings: this session's by default. The
    workspace mirror passes its own project's dict, because outside a session
    ``get_setting`` reads whichever project loaded last.
    """
    read = get or get_setting
    warnings = []

    start_date = read('ROE_ENGAGEMENT_START_DATE', '')
    end_date = read('ROE_ENGAGEMENT_END_DATE', '')
    if start_date:
        try:
            if now_utc.date() < datetime.strptime(start_date, '%Y-%m-%d').date():
                warnings.append(f"Engagement has not started yet (starts {start_date}).")
        except ValueError:
            pass
    if end_date:
        try:
            if now_utc.date() > datetime.strptime(end_date, '%Y-%m-%d').date():
                warnings.append(f"Engagement has ended ({end_date}). Testing may no longer be authorized.")
        except ValueError:
            pass

    if read('ROE_TIME_WINDOW_ENABLED', False):
        tz_name = read('ROE_TIME_WINDOW_TIMEZONE', 'UTC')
        try:
            now_local = now_utc.astimezone(zoneinfo.ZoneInfo(tz_name))
            day_name = now_local.strftime('%A').lower()
            allowed_days = read('ROE_TIME_WINDOW_DAYS', [])
            start_time = read('ROE_TIME_WINDOW_START_TIME', '09:00')
            end_time = read('ROE_TIME_WINDOW_END_TIME', '18:00')

            if day_name not in allowed_days:
                warnings.append(f"Current day ({day_name.capitalize()}) is outside the allowed testing window.")
            else:
                current_time = now_local.strftime('%H:%M')
                # Handle overnight windows (e.g. 22:00 - 06:00)
                if start_time <= end_time:
                    outside = current_time < start_time or current_time > end_time
                else:
                    outside = current_time < start_time and current_time > end_time
                if outside:
                    warnings.append(f"Current time ({current_time} {tz_name}) is outside the allowed window ({start_time}-{end_time}).")
        except Exception:
            pass

    return warnings


def _roe_warning_update(user_id, project_id, session_id) -> dict:
    """This turn's RoE warnings for think_node's prompt, as a state update.

    Returned, never written into ``state``: LangGraph hands a node a copy of the
    state, so an in-place write never reaches the next node. Recomputed on every
    turn because the value persists in the checkpoint and a session can outlive
    its testing window or its engagement.
    """
    if not get_setting('ROE_ENABLED', False):
        return {"_roe_warnings": []}
    warnings = _roe_timing_warnings(datetime.now(timezone.utc))
    if warnings:
        logger.warning(f"[{user_id}/{project_id}/{session_id}] RoE WARNING: {' | '.join(warnings)}")
    return {"_roe_warnings": warnings}


async def initialize_node(state: AgentState, config, *, llm, neo4j_creds) -> dict:
    """Initialize state, after the scope gate (_scope_gate) lets the turn run."""
    user_id, project_id, session_id = get_config_values(config)
    refusal, updates = await _scope_gate(state, llm, user_id, project_id, session_id)
    if refusal is not None:
        return refusal
    if updates.get("_guardrail_blocked") is False:
        state = {**state, "_guardrail_blocked": False}
    result = await _initialize(state, config, llm=llm, neo4j_creds=neo4j_creds)
    return {**result, **updates, **_roe_warning_update(user_id, project_id, session_id)}


async def _initialize(state: AgentState, config, *, llm, neo4j_creds) -> dict:
    """
    Initialize state for new conversation or update for continuation.

    Handles multi-objective support: detects when a new objective should be added
    based on task completion and new user messages.

    Args:
        state: Current agent state.
        config: LangGraph config with user/project/session identifiers.
        llm: The LLM instance for attack path classification.
        neo4j_creds: Tuple of (neo4j_uri, neo4j_user, neo4j_password).
    """
    user_id, project_id, session_id = get_config_values(config)
    neo4j_uri, neo4j_user, neo4j_password = neo4j_creds

    logger.info(f"[{user_id}/{project_id}/{session_id}] Initializing state...")

    # Migrate legacy state if needed (backward compatibility)
    from state import migrate_legacy_objective
    state = migrate_legacy_objective(state)

    # If resuming after approval/answer, preserve state for routing
    if state.get("user_approval_response") and state.get("phase_transition_pending"):
        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with approval response: {state.get('user_approval_response')}")
        return {
            "user_id": user_id,
            "project_id": project_id,
            "session_id": session_id,
        }

    if state.get("user_question_answer") and state.get("pending_question"):
        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with question answer")
        return {
            "user_id": user_id,
            "project_id": project_id,
            "session_id": session_id,
        }

    # Extract latest user message
    messages = state.get("messages", [])
    latest_message = ""
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            latest_message = msg.content
            break

    # Get current objective list
    objectives = state.get("conversation_objectives", [])
    current_idx = state.get("current_objective_index", 0)

    # Check if this is a NEW message (not approval/answer)
    is_new_message = not (
        state.get("user_approval_response") or
        state.get("user_question_answer")
    )

    # If new message AND previous objective was completed, add as new objective
    if is_new_message and latest_message:
        task_was_complete = state.get("task_complete", False)

        # Also detect new objective by comparing message content with current objective
        current_objective_content = ""
        if current_idx < len(objectives):
            current_objective_content = objectives[current_idx].get("content", "")

        # New objective if: task was completed, OR index out of bounds, OR message differs from current objective
        is_different_message = latest_message.strip() != current_objective_content.strip()

        logger.debug(f"[{user_id}/{project_id}/{session_id}] New objective check: task_complete={task_was_complete}, "
                    f"idx={current_idx}, len={len(objectives)}, is_different={is_different_message}")

        if task_was_complete or current_idx >= len(objectives) or is_different_message:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Detected new objective after task completion")

            # Archive completed objective
            if task_was_complete and current_idx < len(objectives):
                completed_obj = ConversationObjective(**objectives[current_idx])
                outcome = ObjectiveOutcome(
                    objective=completed_obj.model_copy(
                        update={
                            "completed_at": utc_now(),
                            "completion_reason": state.get("completion_reason")
                        }
                    ),
                    execution_steps=[s["step_id"] for s in state.get("execution_trace", [])],
                    findings=state.get("target_info", {}),
                    success=True
                )
                objective_history = state.get("objective_history", []) + [outcome.model_dump()]
                logger.info(f"[{user_id}/{project_id}/{session_id}] Archived objective: {completed_obj.content[:10000]}")
            else:
                objective_history = state.get("objective_history", [])

            # Classify attack path, required phase, and target hints using LLM
            attack_path, required_phase, target_host, target_port, target_cves = await classify_attack_path(llm, latest_message)
            logger.info(f"[{user_id}/{project_id}/{session_id}] Attack path classified: {attack_path}, required_phase: {required_phase}, target: {target_host}:{target_port}, cves: {target_cves}")

            # Create new objective from latest message
            new_objective = ConversationObjective(
                content=latest_message,
                required_phase=required_phase
            ).model_dump()

            objectives = objectives + [new_objective]
            current_idx = len(objectives) - 1

            logger.info(f"[{user_id}/{project_id}/{session_id}] New objective #{current_idx + 1}: {latest_message[:10000]}")

            # CRITICAL: Reset task_complete for new objective
            task_complete = False

            # Determine if phase should auto-transition
            new_phase = determine_phase_for_new_objective(
                required_phase,
                state.get("current_phase"),
            )

            # Fire-and-forget: create/update AttackChain node (MERGE = idempotent)
            chain_graph.fire_create_attack_chain(
                neo4j_uri, neo4j_user, neo4j_password,
                chain_id=session_id,
                user_id=user_id,
                project_id=project_id,
                title=latest_message[:200] if latest_message else "Untitled",
                objective=latest_message[:500],
                attack_path_type=attack_path,
                target_host=target_host,
                target_port=target_port,
                target_cves=target_cves,
            )

            # CRITICAL: Preserve ALL context (user preference)
            return {
                "conversation_objectives": objectives,
                "current_objective_index": current_idx,
                "objective_history": objective_history,
                "task_complete": task_complete,
                "current_phase": new_phase,
                "attack_path_type": attack_path,
                "completion_reason": None,
                # Preserve context except TODO list (new objective = fresh TODO list)
                "execution_trace": state.get("execution_trace", []),
                "target_info": state.get("target_info", {}),
                "todo_list": [],  # Clear TODO list for new objective
                "phase_history": state.get("phase_history", []),
                "user_id": user_id,
                "project_id": project_id,
                "session_id": session_id,
                "awaiting_user_approval": False,
                "phase_transition_pending": None,
                "_abort_transition": False,
                "original_objective": state.get("original_objective", latest_message),  # Backward compat
                # Chain memory (preserve across objectives)
                "chain_findings_memory": state.get("chain_findings_memory", []),
                "chain_failures_memory": state.get("chain_failures_memory", []),
                "chain_decisions_memory": state.get("chain_decisions_memory", []),
                "chain_waves_memory": state.get("chain_waves_memory", []),
                "_last_chain_step_id": state.get("_last_chain_step_id"),
                "_prior_chain_context": state.get("_prior_chain_context"),
            }

    # Otherwise, continue with current objective
    logger.info(f"[{user_id}/{project_id}/{session_id}] Continuing with current objective")

    # Fire-and-forget: create/update AttackChain node (MERGE = idempotent)
    current_objective_content = ""
    if current_idx < len(objectives):
        current_objective_content = objectives[current_idx].get("content", "")
    chain_graph.fire_create_attack_chain(
        neo4j_uri, neo4j_user, neo4j_password,
        chain_id=session_id,
        user_id=user_id,
        project_id=project_id,
        title=latest_message[:200] if latest_message else "Untitled",
        objective=current_objective_content[:500],
        attack_path_type=state.get("attack_path_type", "cve_exploit"),
    )

    updates = {
        "current_iteration": state.get("current_iteration", 0),
        "max_iterations": state.get("max_iterations", get_setting('MAX_ITERATIONS', 100)),
        "task_complete": False,
        "current_phase": state.get("current_phase", "informational"),
        "attack_path_type": state.get("attack_path_type", "cve_exploit"),
        "phase_history": state.get("phase_history", [
            PhaseHistoryEntry(phase="informational").model_dump()
        ]),
        "execution_trace": state.get("execution_trace", []),
        "todo_list": state.get("todo_list", []),
        "conversation_objectives": objectives,
        "current_objective_index": current_idx,
        "objective_history": state.get("objective_history", []),
        "original_objective": state.get("original_objective", latest_message),  # Backward compat
        "target_info": state.get("target_info", TargetInfo().model_dump()),
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
        "awaiting_user_approval": False,
        "phase_transition_pending": None,
        "_abort_transition": False,
        # Chain memory (preserve)
        "chain_findings_memory": state.get("chain_findings_memory", []),
        "chain_failures_memory": state.get("chain_failures_memory", []),
        "chain_decisions_memory": state.get("chain_decisions_memory", []),
        "chain_waves_memory": state.get("chain_waves_memory", []),
        "_last_chain_step_id": state.get("_last_chain_step_id"),
        "_prior_chain_context": state.get("_prior_chain_context"),
    }

    # Load prior chain context on first invocation (empty trace)
    if not state.get("execution_trace"):
        try:
            # Off the event loop and bounded: this read runs before the first
            # think turn, and a slow Neo4j here froze every session on the agent.
            # The context is optional, so a slow read is skipped, not awaited.
            prior_chains = await asyncio.wait_for(
                run_neo4j_read(
                    chain_graph.query_prior_chains,
                    neo4j_uri, neo4j_user, neo4j_password,
                    user_id, project_id, session_id,
                ),
                timeout=PRIOR_CHAINS_WAIT_S,
            )
            if prior_chains:
                updates["_prior_chain_context"] = format_prior_chains(prior_chains)
        except Exception as exc:
            logger.warning("Failed to load prior chain context: %s", exc)

    return updates
