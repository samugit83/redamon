"""Approval and Q&A nodes — handle phase transitions and user questions."""

import logging

from langchain_core.messages import AIMessage, HumanMessage

from state import (
    AgentState,
    ExecutionStep,
    PhaseHistoryEntry,
    UserQuestionRequest,
    UserQuestionAnswer,
    QAHistoryEntry,
    utc_now,
)
import orchestrator_helpers.chain_graph_writer as chain_graph
from orchestrator_helpers.config import get_identifiers
from prompts import PHASE_TRANSITION_MESSAGE, USER_QUESTION_MESSAGE

logger = logging.getLogger(__name__)


async def await_approval_node(state: AgentState, config) -> dict:
    """Pause and request user approval for phase transition."""
    user_id, project_id, session_id = get_identifiers(state, config)

    transition = state.get("phase_transition_pending", {})

    logger.info(f"[{user_id}/{project_id}/{session_id}] Awaiting approval for {transition.get('from_phase')} -> {transition.get('to_phase')}")

    # Format the approval message
    planned_actions = "\n".join(f"- {a}" for a in transition.get("planned_actions", []))
    risks = "\n".join(f"- {r}" for r in transition.get("risks", []))

    message = PHASE_TRANSITION_MESSAGE.format(
        from_phase=transition.get("from_phase", "informational"),
        to_phase=transition.get("to_phase", "exploitation"),
        reason=transition.get("reason", "No reason provided"),
        planned_actions=planned_actions or "- No specific actions planned",
        risks=risks or "- Standard penetration testing risks apply",
    )

    return {
        "awaiting_user_approval": True,
        "messages": [AIMessage(content=message)],
    }


async def process_approval_node(state: AgentState, config, *, neo4j_creds) -> dict:
    """Process user's approval response."""
    user_id, project_id, session_id = get_identifiers(state, config)
    neo4j_uri, neo4j_user, neo4j_password = neo4j_creds

    approval = state.get("user_approval_response")
    modification = state.get("user_modification")
    transition = state.get("phase_transition_pending", {})

    logger.info(f"[{user_id}/{project_id}/{session_id}] Processing approval: {approval}")

    # Common fields to clear approval state
    clear_approval_state = {
        "awaiting_user_approval": False,
        "phase_transition_pending": None,
        "user_approval_response": None,
        "user_modification": None,
        "_emitted_approval_key": None,
    }

    if approval == "approve":
        new_phase = transition.get("to_phase", "exploitation")
        from_phase = transition.get("from_phase", state.get("current_phase", "informational"))
        logger.info(f"[{user_id}/{project_id}/{session_id}] Transitioning to phase: {new_phase}")

        # Update objective's required_phase hint
        objectives = state.get("conversation_objectives", [])
        current_idx = state.get("current_objective_index", 0)
        if current_idx < len(objectives):
            objectives[current_idx]["required_phase"] = new_phase

        # Add execution trace entry so LLM sees the transition happened
        transition_step = ExecutionStep(
            iteration=state.get("current_iteration", 0),
            phase=new_phase,
            thought=f"Phase transition from {from_phase} to {new_phase} approved by user.",
            reasoning=f"User approved the transition request. Moving from {from_phase} phase to {new_phase} phase to continue with the objective.",
            tool_name="phase_transition",
            tool_args={"from_phase": from_phase, "to_phase": new_phase},
            tool_output=f"PHASE TRANSITION APPROVED: {from_phase} → {new_phase}. Now operating in {new_phase} phase.",
            success=True,
            output_analysis=f"Phase transition approved. Agent is now in {new_phase} phase and can use {new_phase}-specific tools. DO NOT request another transition to {new_phase} - you are already there.",
        )
        updated_trace = state.get("execution_trace", []) + [transition_step.model_dump()]

        # Fire-and-forget: record ChainDecision for phase transition
        chain_graph.fire_record_decision(
            neo4j_uri, neo4j_user, neo4j_password,
            chain_id=session_id,
            step_id=state.get("_last_chain_step_id"),
            user_id=user_id, project_id=project_id,
            decision_type="phase_transition",
            from_state=from_phase,
            to_state=new_phase,
            reason=transition.get("reason", ""),
            made_by="user",
            approved=True,
            iteration=state.get("current_iteration"),
        )

        # Update chain_decisions_memory
        chain_decisions_mem = list(state.get("chain_decisions_memory", []))
        chain_decisions_mem.append({
            "step_iteration": state.get("current_iteration", 0),
            "decision_type": "phase_transition",
            "from_state": from_phase,
            "to_state": new_phase,
            "made_by": "user",
            "approved": True,
        })

        return {
            **clear_approval_state,
            "current_phase": new_phase,
            "phase_history": state.get("phase_history", []) + [
                PhaseHistoryEntry(phase=new_phase).model_dump()
            ],
            "conversation_objectives": objectives,
            "execution_trace": updated_trace,
            "messages": [AIMessage(content=f"Phase transition approved. Now in **{new_phase}** phase.")],
            "_just_transitioned_to": new_phase,
            "chain_decisions_memory": chain_decisions_mem,
        }

    elif approval == "modify":
        return {
            **clear_approval_state,
            "messages": [
                HumanMessage(content=f"User modification: {modification}"),
                AIMessage(content="Understood. Adjusting approach based on your feedback."),
            ],
        }

    else:  # abort
        chain_graph.fire_record_decision(
            neo4j_uri, neo4j_user, neo4j_password,
            chain_id=session_id,
            step_id=state.get("_last_chain_step_id"),
            user_id=user_id, project_id=project_id,
            decision_type="phase_transition",
            from_state=transition.get("from_phase", state.get("current_phase", "informational")),
            to_state=transition.get("to_phase", "exploitation"),
            reason="User aborted transition",
            made_by="user",
            approved=False,
            iteration=state.get("current_iteration"),
        )
        return {
            **clear_approval_state,
            "_abort_transition": True,
            "messages": [AIMessage(content="Phase transition cancelled by user. Continuing in current phase. What would you like to do next?")],
        }


async def await_question_node(state: AgentState, config) -> dict:
    """Pause and request user answer to a question."""
    user_id, project_id, session_id = get_identifiers(state, config)

    question = state.get("pending_question", {})

    logger.info(f"[{user_id}/{project_id}/{session_id}] Awaiting answer: {question.get('question', '')[:10000]}")

    # Format options for display
    options_text = ""
    if question.get("options"):
        options_text = "\n".join(f"- {opt}" for opt in question.get("options", []))
    else:
        options_text = "Free text response"

    message = USER_QUESTION_MESSAGE.format(
        question=question.get("question", ""),
        context=question.get("context", ""),
        format=question.get("format", "text"),
        options=options_text,
        default=question.get("default_value") or "None",
    )

    return {
        "awaiting_user_question": True,
        "messages": [AIMessage(content=message)],
    }


async def process_answer_node(state: AgentState, config) -> dict:
    """Process user's answer to a question."""
    user_id, project_id, session_id = get_identifiers(state, config)

    answer = state.get("user_question_answer")
    question = state.get("pending_question", {})

    logger.info(f"[{user_id}/{project_id}/{session_id}] Processing answer: {answer[:10000] if answer else 'None'}")

    # Create Q&A history entry
    qa_entry = QAHistoryEntry(
        question=UserQuestionRequest(**question),
        answer=UserQuestionAnswer(
            question_id=question.get("question_id", ""),
            answer=answer or "",
        ),
        answered_at=utc_now(),
    )

    qa_history = state.get("qa_history", []) + [qa_entry.model_dump()]

    return {
        "awaiting_user_question": False,
        "pending_question": None,
        "user_question_answer": None,
        "qa_history": qa_history,
        "messages": [
            HumanMessage(content=f"User answer: {answer}"),
            AIMessage(content="Thank you for the clarification. Continuing with the task..."),
        ],
    }
