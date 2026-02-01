"""
RedAmon Agent Orchestrator

ReAct-style agent orchestrator with iterative Thought-Tool-Output pattern.
Supports phase tracking, LLM-managed todo lists, and checkpoint-based approval.
"""

import os
import logging
from typing import Optional

from dotenv import load_dotenv

from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from state import (
    AgentState,
    InvokeResponse,
    ExecutionStep,
    TargetInfo,
    PhaseTransitionRequest,
    PhaseHistoryEntry,
    UserQuestionRequest,
    UserQuestionAnswer,
    QAHistoryEntry,
    ConversationObjective,
    ObjectiveOutcome,
    format_todo_list,
    format_execution_trace,
    format_qa_history,
    format_objective_history,
    migrate_legacy_objective,
    summarize_trace_for_response,
    utc_now,
)
from params import (
    OPENAI_MODEL,
    CREATE_GRAPH_IMAGRE_ON_INIT,
    MAX_ITERATIONS,
    REQUIRE_APPROVAL_FOR_EXPLOITATION,
    REQUIRE_APPROVAL_FOR_POST_EXPLOITATION,
    TOOL_OUTPUT_MAX_CHARS,
    ACTIVATE_POST_EXPL_PHASE,
    POST_EXPL_PHASE_TYPE,
)
from tools import (
    MCPToolsManager,
    Neo4jToolManager,
    PhaseAwareToolExecutor,
    set_tenant_context,
    set_phase_context,
)
from prompts import (
    REACT_SYSTEM_PROMPT,
    OUTPUT_ANALYSIS_PROMPT,
    PHASE_TRANSITION_MESSAGE,
    USER_QUESTION_MESSAGE,
    FINAL_REPORT_PROMPT,
    get_phase_tools,
)
from orchestrator_helpers import (
    json_dumps_safe,
    extract_json,
    parse_llm_decision,
    parse_analysis_response,
    classify_attack_path,
    determine_phase_for_new_objective,
    update_target_with_detections,
    save_graph_image,
    set_checkpointer,
    create_config,
    get_config_values,
    get_identifiers,
    is_session_config_complete,
)

checkpointer = MemorySaver()
set_checkpointer(checkpointer)

load_dotenv()

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    ReAct-style agent orchestrator for penetration testing.

    Implements the Thought-Tool-Output pattern with:
    - Phase tracking (Informational → Exploitation → Post-Exploitation)
    - LLM-managed todo lists
    - Checkpoint-based approval for phase transitions
    - Full execution trace in memory
    """

    def __init__(self):
        """Initialize the orchestrator with configuration."""
        self.model_name = OPENAI_MODEL
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        self.neo4j_password = os.getenv("NEO4J_PASSWORD")

        self.llm: Optional[ChatOpenAI] = None
        self.tool_executor: Optional[PhaseAwareToolExecutor] = None
        self.graph = None

        self._initialized = False
        self._streaming_callback = None  # Set during invoke_with_streaming

    async def initialize(self) -> None:
        """Initialize all components asynchronously."""
        if self._initialized:
            logger.warning("Orchestrator already initialized")
            return

        logger.info("Initializing AgentOrchestrator...")

        self._setup_llm()
        await self._setup_tools()
        self._build_graph()
        self._initialized = True

        if CREATE_GRAPH_IMAGRE_ON_INIT:
            save_graph_image(self.graph)

        logger.info("AgentOrchestrator initialized with ReAct pattern")

    def _setup_llm(self) -> None:
        """Initialize the OpenAI LLM."""
        logger.info(f"Setting up LLM: {self.model_name}")
        self.llm = ChatOpenAI(
            model=self.model_name,
            api_key=self.openai_api_key,
            temperature=0
        )

    async def _setup_tools(self) -> None:
        """Set up all tools (MCP and Neo4j)."""
        # Setup MCP tools
        mcp_manager = MCPToolsManager()
        mcp_tools = await mcp_manager.get_tools()

        # Setup Neo4j graph query tool
        neo4j_manager = Neo4jToolManager(
            uri=self.neo4j_uri,
            user=self.neo4j_user,
            password=self.neo4j_password,
            llm=self.llm
        )
        graph_tool = neo4j_manager.get_tool()

        # Create phase-aware tool executor
        self.tool_executor = PhaseAwareToolExecutor(mcp_manager, graph_tool)
        self.tool_executor.register_mcp_tools(mcp_tools)

        logger.info(f"Tools initialized: {len(self.tool_executor.get_all_tools())} available")

    def _build_graph(self) -> None:
        """Build the ReAct LangGraph with phase tracking."""
        logger.info("Building ReAct LangGraph...")

        builder = StateGraph(AgentState)

        # Add nodes
        builder.add_node("initialize", self._initialize_node)
        builder.add_node("think", self._think_node)
        builder.add_node("execute_tool", self._execute_tool_node)
        builder.add_node("analyze_output", self._analyze_output_node)
        builder.add_node("await_approval", self._await_approval_node)
        builder.add_node("process_approval", self._process_approval_node)
        builder.add_node("await_question", self._await_question_node)
        builder.add_node("process_answer", self._process_answer_node)
        builder.add_node("generate_response", self._generate_response_node)

        # Entry point
        builder.add_edge(START, "initialize")

        # Route after initialize - process approval, process answer, or continue to think
        builder.add_conditional_edges(
            "initialize",
            self._route_after_initialize,
            {
                "process_approval": "process_approval",
                "process_answer": "process_answer",
                "think": "think",
            }
        )

        # Main routing from think node
        builder.add_conditional_edges(
            "think",
            self._route_after_think,
            {
                "execute_tool": "execute_tool",
                "await_approval": "await_approval",
                "await_question": "await_question",
                "generate_response": "generate_response",
            }
        )

        # Tool execution flow
        builder.add_edge("execute_tool", "analyze_output")

        # After analysis, continue loop or end
        builder.add_conditional_edges(
            "analyze_output",
            self._route_after_analyze,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )

        # Approval flow - pause for user input
        builder.add_edge("await_approval", END)

        # Process approval routes back to think or ends
        builder.add_conditional_edges(
            "process_approval",
            self._route_after_approval,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )

        # Q&A flow - pause for user input
        builder.add_edge("await_question", END)

        # Process answer routes back to think or ends
        builder.add_conditional_edges(
            "process_answer",
            self._route_after_answer,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )

        # Final response always ends
        builder.add_edge("generate_response", END)

        self.graph = builder.compile(checkpointer=checkpointer)
        logger.info("ReAct LangGraph compiled with checkpointer")

    # =========================================================================
    # LANGGRAPH NODES
    # =========================================================================

    async def _initialize_node(self, state: AgentState, config = None) -> dict:
        """
        Initialize state for new conversation or update for continuation.

        Handles multi-objective support: detects when a new objective should be added
        based on task completion and new user messages.
        """
        user_id, project_id, session_id = get_config_values(config)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Initializing state...")

        # Migrate legacy state if needed (backward compatibility)
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
            # This handles race conditions where task_complete might not be set yet
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

                # Classify attack path and required phase using LLM
                attack_path, required_phase = await classify_attack_path(self.llm, latest_message)
                logger.info(f"[{user_id}/{project_id}/{session_id}] Attack path classified: {attack_path}, required_phase: {required_phase}")

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
                    "original_objective": state.get("original_objective", latest_message),  # Backward compat
                }

        # Otherwise, continue with current objective
        logger.info(f"[{user_id}/{project_id}/{session_id}] Continuing with current objective")
        return {
            "current_iteration": state.get("current_iteration", 0),
            "max_iterations": state.get("max_iterations", MAX_ITERATIONS),
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
        }

    async def _think_node(self, state: AgentState, config = None) -> dict:
        """
        Core ReAct reasoning node.

        Analyzes previous steps, updates todo list, and decides next action.
        """
        user_id, project_id, session_id = get_identifiers(state, config)

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

        # Get current objective from conversation objectives
        objectives = state.get("conversation_objectives", [])
        current_idx = state.get("current_objective_index", 0)

        if current_idx < len(objectives):
            current_objective = objectives[current_idx].get("content", "No objective specified")
        else:
            # Fallback to original_objective for backward compatibility
            current_objective = state.get("original_objective", "No objective specified")

        # Build the prompt with current state
        execution_trace_formatted = format_execution_trace(
            state.get("execution_trace", []),
            objectives=state.get("conversation_objectives", []),
            objective_history=state.get("objective_history", []),
            current_objective_index=state.get("current_objective_index", 0)
        )
        todo_list_formatted = format_todo_list(state.get("todo_list", []))
        target_info_formatted = json_dumps_safe(state.get("target_info", {}), indent=2)
        qa_history_formatted = format_qa_history(state.get("qa_history", []))
        objective_history_formatted = format_objective_history(state.get("objective_history", []))

        # Get phase tools with attack path type for dynamic routing
        attack_path_type = state.get("attack_path_type", "cve_exploit")
        available_tools = get_phase_tools(phase, ACTIVATE_POST_EXPL_PHASE, POST_EXPL_PHASE_TYPE, attack_path_type)

        system_prompt = REACT_SYSTEM_PROMPT.format(
            current_phase=phase,
            attack_path_type=attack_path_type,
            available_tools=available_tools,
            iteration=iteration,
            max_iterations=state.get("max_iterations", MAX_ITERATIONS),
            objective=current_objective,  # Now uses current objective, not original
            objective_history_summary=objective_history_formatted,  # Added
            execution_trace=execution_trace_formatted,
            todo_list=todo_list_formatted,
            target_info=target_info_formatted,
            qa_history=qa_history_formatted,
        )

        # Log the full prompt for debugging
        logger.info(f"\n{'#'*80}")
        logger.info(f"# THINK NODE PROMPT - Iteration {iteration} - Phase: {phase}")
        logger.info(f"{'#'*80}")
        logger.info(f"\n--- EXECUTION TRACE ---\n{execution_trace_formatted}")
        logger.info(f"\n--- TODO LIST ---\n{todo_list_formatted}")
        logger.info(f"\n--- TARGET INFO ---\n{target_info_formatted}")
        logger.info(f"\n--- Q&A HISTORY ---\n{qa_history_formatted}")
        logger.info(f"\n--- FULL SYSTEM PROMPT ({len(system_prompt)} chars) ---")
        # Log full prompt in chunks to avoid log line limits
        chunk_size = 4000
        for i in range(0, len(system_prompt), chunk_size):
            chunk = system_prompt[i:i+chunk_size]
            logger.info(f"PROMPT[{i}:{i+len(chunk)}]:\n{chunk}")
        logger.info(f"{'#'*80}\n")

        # Get LLM decision
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content="Based on the current state, what is your next action? Output EXACTLY ONE valid JSON object and nothing else. Do NOT simulate tool execution - you will receive actual tool output after submitting your decision. Do NOT output multiple JSON objects or continue the conversation - just ONE decision JSON.")
        ]

        response = await self.llm.ainvoke(messages)
        response_text = response.content.strip()

        # Log the raw LLM response
        logger.info(f"\n{'='*60}")
        logger.info(f"LLM RAW RESPONSE - Iteration {iteration}")
        logger.info(f"{'='*60}")
        logger.info(f"{response_text}")
        logger.info(f"{'='*60}\n")

        # Parse the JSON response into Pydantic model
        decision = parse_llm_decision(response_text)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Decision: action={decision.action}, tool={decision.tool_name}")

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

        # Log user_question if action is ask_user
        if decision.action == "ask_user" and decision.user_question:
            logger.info(f"USER_QUESTION:")
            logger.info(f"  Question: {decision.user_question.question}")
            logger.info(f"  Context: {decision.user_question.context}")
            logger.info(f"  Format: {decision.user_question.format}")
            if decision.user_question.options:
                logger.info(f"  Options: {decision.user_question.options}")

        logger.info(f"{'='*60}\n")

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
        updates = {
            "current_iteration": iteration,
            "todo_list": todo_list,
            "_current_step": step.model_dump(),
            "_decision": decision.model_dump(),
            "_just_transitioned_to": None,  # Clear the marker
        }

        # Handle different actions
        if decision.action == "complete":
            updates["task_complete"] = True
            updates["completion_reason"] = decision.completion_reason or "Task completed"

        elif decision.action == "transition_phase":
            phase_transition = decision.phase_transition
            to_phase = phase_transition.to_phase if phase_transition else "exploitation"

            # Block post-exploitation if ACTIVATE_POST_EXPL_PHASE=False
            if to_phase == "post_exploitation" and not ACTIVATE_POST_EXPL_PHASE:
                logger.warning(f"[{user_id}/{project_id}/{session_id}] Blocking post_exploitation transition: ACTIVATE_POST_EXPL_PHASE=False")
                updates["task_complete"] = True
                updates["completion_reason"] = "Exploitation completed. Post-exploitation phase is disabled."
                updates["messages"] = [
                    AIMessage(content="Exploitation completed successfully. "
                                     "Post-exploitation phase is not available because ACTIVATE_POST_EXPL_PHASE=False. "
                                     "If you need post-exploitation capabilities, set ACTIVATE_POST_EXPL_PHASE=True in params.py.")
                ]
                return updates

            # Ignore transition to same phase - just continue
            if to_phase == phase:
                logger.warning(f"[{user_id}/{project_id}/{session_id}] Ignoring transition to same phase: {phase}")
                # If agent specified a tool, use it; otherwise loop back to think
                if decision.tool_name:
                    updates["_decision"]["action"] = "use_tool"
                else:
                    # Let the LLM figure out what to do next
                    logger.info(f"[{user_id}/{project_id}/{session_id}] No tool specified, looping back to think")
                return updates

            # Also ignore if we JUST transitioned to this phase (prevents immediate re-request)
            if just_transitioned and to_phase == just_transitioned:
                logger.warning(f"[{user_id}/{project_id}/{session_id}] Ignoring re-request for recent transition to: {to_phase}")
                # If agent specified a tool, use it; otherwise loop back to think
                if decision.tool_name:
                    updates["_decision"]["action"] = "use_tool"
                else:
                    # Let the LLM figure out what to do next
                    logger.info(f"[{user_id}/{project_id}/{session_id}] No tool specified, looping back to think")
                return updates

            # AUTO-APPROVE: Downgrade to informational (safe, no approval needed)
            # Per user preference: auto-downgrade when transitioning to informational from later phases
            if to_phase == "informational" and phase in ["exploitation", "post_exploitation"]:
                logger.info(f"[{user_id}/{project_id}/{session_id}] Auto-approving safe downgrade: {phase} → informational")
                updates["current_phase"] = to_phase
                updates["phase_history"] = state.get("phase_history", []) + [
                    PhaseHistoryEntry(phase=to_phase).model_dump()
                ]
                updates["_just_transitioned_to"] = to_phase

                # Add system message to context
                updates["messages"] = [
                    AIMessage(content=f"Automatically transitioned from {phase} to informational phase for new objective.")
                ]

                # Continue to next iteration (will call think node again with new phase)
                # Don't set action explicitly - let routing continue
                return updates

            # Check if approval is required (for exploitation/post-exploitation upgrades)
            needs_approval = (
                (to_phase == "exploitation" and REQUIRE_APPROVAL_FOR_EXPLOITATION) or
                (to_phase == "post_exploitation" and REQUIRE_APPROVAL_FOR_POST_EXPLOITATION)
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
                # Auto-approve if not required
                updates["current_phase"] = to_phase
                updates["phase_history"] = state.get("phase_history", []) + [
                    PhaseHistoryEntry(phase=to_phase).model_dump()
                ]

        elif decision.action == "ask_user":
            # Handle ask_user action - agent wants to ask user a question
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
        # This only applies to CVE exploits in statefull mode that need reverse/bind payloads
        # Brute force attacks don't need LHOST/LPORT - SSH creates direct shell via CreateSession=true
        if (POST_EXPL_PHASE_TYPE == "statefull" and
            state.get("attack_path_type") == "cve_exploit" and
            decision.action == "use_tool" and
            decision.tool_name == "metasploit_console" and
            not updates.get("awaiting_user_question")):

            config_complete, missing_params = is_session_config_complete()

            if not config_complete:
                # Check if user already answered these questions in qa_history
                qa_history = state.get("qa_history", [])
                answered_params = set()
                for qa in qa_history:
                    answer = qa.get("answer", {})
                    answer_text = answer.get("answer", "") if answer else ""
                    question_obj = qa.get("question", {})
                    question_text = question_obj.get("question", "") if question_obj else ""

                    # Simple heuristic: if question mentions LHOST/LPORT and has an answer
                    if answer_text:
                        if "LHOST" in question_text.upper():
                            answered_params.add("LHOST")
                        if "LPORT" in question_text.upper():
                            answered_params.add("LPORT")
                        if "BIND" in question_text.upper():
                            answered_params.add("LPORT or BIND_PORT_ON_TARGET")

                # Remove already-answered params from missing list
                still_missing = [p for p in missing_params if p not in answered_params]

                if still_missing:
                    # Force ask_user action instead of use_tool
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

        return updates

    async def _execute_tool_node(self, state: AgentState, config = None) -> dict:
        """Execute the selected tool."""
        user_id, project_id, session_id = get_identifiers(state, config)

        step_data = state.get("_current_step") or {}
        tool_name = step_data.get("tool_name")
        tool_args = step_data.get("tool_args") or {}
        phase = state.get("current_phase", "informational")
        iteration = state.get("current_iteration", 0)

        # Detailed logging - tool execution start
        logger.info(f"\n{'='*60}")
        logger.info(f"EXECUTE TOOL - Iteration {iteration} - Phase: {phase}")
        logger.info(f"{'='*60}")
        logger.info(f"TOOL_NAME: {tool_name}")
        logger.info(f"TOOL_ARGS:")
        if tool_args:
            for key, value in tool_args.items():
                # Truncate long values for readability
                val_str = str(value)
                if len(val_str) > 200:
                    val_str = val_str[:10000]
                logger.info(f"  {key}: {val_str}")
        else:
            logger.info("  (no arguments)")

        # Handle missing tool name
        if not tool_name:
            logger.error(f"[{user_id}/{project_id}/{session_id}] No tool name in step_data")
            step_data["tool_output"] = "Error: No tool specified"
            step_data["success"] = False
            step_data["error_message"] = "No tool name provided"
            logger.info(f"TOOL_OUTPUT: Error - No tool specified")
            logger.info(f"{'='*60}\n")
            return {
                "_current_step": step_data,
                "_tool_result": {"success": False, "error": "No tool name provided"},
            }

        # Set context
        set_tenant_context(user_id, project_id)
        set_phase_context(phase)

        # Auto-reset Metasploit on first use in this session
        msf_reset_done = state.get("msf_session_reset_done", False)
        extra_updates = {}
        if tool_name == "metasploit_console" and not msf_reset_done:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Auto-resetting Metasploit state (first use in session)")
            # Restart msfconsole completely for a clean state
            # This kills any stuck sessions and starts fresh
            await self.tool_executor.execute("msf_restart", {}, phase)
            extra_updates["msf_session_reset_done"] = True
            logger.info(f"[{user_id}/{project_id}/{session_id}] Metasploit reset complete")

        # Check if this is a long-running metasploit command
        is_long_running_msf = (
            tool_name == "metasploit_console" and
            any(cmd in (tool_args.get("command", "") or "").lower() for cmd in ["run", "exploit"])
        )

        # Execute the tool (with progress streaming for long-running commands)
        if is_long_running_msf and self._streaming_callback:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Using execute_with_progress for long-running MSF command")
            result = await self.tool_executor.execute_with_progress(
                tool_name,
                tool_args,
                phase,
                progress_callback=self._streaming_callback.on_tool_output_chunk
            )
        else:
            result = await self.tool_executor.execute(tool_name, tool_args, phase)

        # Update step with output (handle None result)
        if result:
            step_data["tool_output"] = result.get("output") or ""
            step_data["success"] = result.get("success", False)
            step_data["error_message"] = result.get("error")
        else:
            step_data["tool_output"] = ""
            step_data["success"] = False
            step_data["error_message"] = "Tool execution returned no result"

        # Detailed logging - tool output
        tool_output = step_data.get("tool_output", "")
        success = step_data.get("success", False)
        error_msg = step_data.get("error_message")

        logger.info(f"SUCCESS: {success}")
        if error_msg:
            logger.info(f"ERROR: {error_msg}")

        logger.info(f"TOOL_OUTPUT ({len(tool_output)} chars):")
        if tool_output:
            output_preview = tool_output[:100000]
            for line in output_preview.split('\n'):
                logger.info(f"  | {line}")
            if len(tool_output) > 100000:
                logger.info(f"  | ... ({len(tool_output) - 100000} more chars)")
        else:
            logger.info("  (empty output)")
        logger.info(f"{'='*60}\n")

        updates = {
            "_current_step": step_data,
            "_tool_result": result or {"success": False, "error": "No result"},
        }
        # Include any extra updates (e.g., msf_session_reset_done)
        updates.update(extra_updates)
        return updates

    async def _analyze_output_node(self, state: AgentState, config = None) -> dict:
        """Analyze tool output and extract intelligence."""
        user_id, project_id, session_id = get_identifiers(state, config)

        step_data = state.get("_current_step") or {}
        tool_output = step_data.get("tool_output") or ""
        tool_name = step_data.get("tool_name") or "unknown"
        iteration = state.get("current_iteration", 0)
        phase = state.get("current_phase", "informational")

        # Handle None or empty tool output
        if not tool_output:
            tool_output = step_data.get("error_message") or "No output received from tool"

        # Use LLM to analyze the output (truncate to avoid token limits)
        analysis_prompt = OUTPUT_ANALYSIS_PROMPT.format(
            tool_name=tool_name,
            tool_args=json_dumps_safe(step_data.get("tool_args") or {}),
            tool_output=tool_output[:TOOL_OUTPUT_MAX_CHARS] if tool_output else "No output",
            current_target_info=json_dumps_safe(state.get("target_info") or {}, indent=2),
        )

        response = await self.llm.ainvoke([HumanMessage(content=analysis_prompt)])
        analysis = parse_analysis_response(response.content)

        # Update step with analysis and rich data for streaming
        step_data["output_analysis"] = analysis.interpretation
        step_data["actionable_findings"] = analysis.actionable_findings or []
        step_data["recommended_next_steps"] = analysis.recommended_next_steps or []

        # Detailed logging - output analysis
        logger.info(f"\n{'='*60}")
        logger.info(f"ANALYZE OUTPUT - Iteration {iteration} - Phase: {phase}")
        logger.info(f"{'='*60}")
        logger.info(f"TOOL: {tool_name}")
        logger.info(f"OUTPUT_ANALYSIS:")
        interpretation = analysis.interpretation or "(no interpretation)"
        # Show interpretation with nice formatting
        for line in interpretation.split('\n'):
            logger.info(f"  | {line}")

        # Log extracted info
        extracted = analysis.extracted_info
        if extracted:
            logger.info(f"EXTRACTED INFO:")
            if extracted.primary_target:
                logger.info(f"  primary_target: {extracted.primary_target}")
            if extracted.ports:
                logger.info(f"  ports: {extracted.ports}")
            if extracted.services:
                logger.info(f"  services: {extracted.services}")
            if extracted.technologies:
                logger.info(f"  technologies: {extracted.technologies}")
            if extracted.vulnerabilities:
                logger.info(f"  vulnerabilities: {extracted.vulnerabilities}")
            if extracted.credentials:
                logger.info(f"  credentials: {len(extracted.credentials)} found")
            if extracted.sessions:
                logger.info(f"  sessions: {extracted.sessions}")

        # Log actionable findings
        if analysis.actionable_findings:
            logger.info(f"ACTIONABLE FINDINGS:")
            for finding in analysis.actionable_findings:
                logger.info(f"  - {finding}")

        # Log recommended next steps
        if analysis.recommended_next_steps:
            logger.info(f"RECOMMENDED NEXT STEPS:")
            for step_rec in analysis.recommended_next_steps:
                logger.info(f"  - {step_rec}")

        logger.info(f"{'='*60}\n")

        # Update target info with extracted data
        current_target = TargetInfo(**state.get("target_info", {}))
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

        # Detect sessions and credentials from tool output
        merged_target = update_target_with_detections(
            merged_target,
            tool_output,
            phase,
            state.get("attack_path_type", "cve_exploit"),
            POST_EXPL_PHASE_TYPE,
            user_id, project_id, session_id
        )

        # Add step to execution trace
        execution_trace = state.get("execution_trace", []) + [step_data]

        # Add AI message to conversation
        analysis_summary = analysis.interpretation or tool_output[:10000]

        return {
            "_current_step": step_data,
            "execution_trace": execution_trace,
            "target_info": merged_target.model_dump(),
            "messages": [AIMessage(content=f"**Step {step_data.get('iteration')}** [{state.get('current_phase')}]\n\n{analysis_summary}")],
        }

    async def _await_approval_node(self, state: AgentState, config = None) -> dict:
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

    async def _process_approval_node(self, state: AgentState, config = None) -> dict:
        """Process user's approval response."""
        user_id, project_id, session_id = get_identifiers(state, config)

        approval = state.get("user_approval_response")
        modification = state.get("user_modification")
        transition = state.get("phase_transition_pending", {})

        logger.info(f"[{user_id}/{project_id}/{session_id}] Processing approval: {approval}")

        # Common fields to clear approval state - CRITICAL for frontend to close dialog
        # Also clear _emitted_approval_key so the same transition can be requested again later
        clear_approval_state = {
            "awaiting_user_approval": False,
            "phase_transition_pending": None,
            "user_approval_response": None,
            "user_modification": None,
            "_emitted_approval_key": None,
        }

        if approval == "approve":
            # Transition to new phase
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
                phase=new_phase,  # Use new_phase (must be valid Phase literal)
                thought=f"Phase transition from {from_phase} to {new_phase} approved by user.",
                reasoning=f"User approved the transition request. Moving from {from_phase} phase to {new_phase} phase to continue with the objective.",
                tool_name="phase_transition",
                tool_args={"from_phase": from_phase, "to_phase": new_phase},
                tool_output=f"PHASE TRANSITION APPROVED: {from_phase} → {new_phase}. Now operating in {new_phase} phase.",
                success=True,
                output_analysis=f"Phase transition approved. Agent is now in {new_phase} phase and can use {new_phase}-specific tools. DO NOT request another transition to {new_phase} - you are already there.",
            )
            updated_trace = state.get("execution_trace", []) + [transition_step.model_dump()]

            return {
                **clear_approval_state,
                "current_phase": new_phase,
                "phase_history": state.get("phase_history", []) + [
                    PhaseHistoryEntry(phase=new_phase).model_dump()
                ],
                "conversation_objectives": objectives,  # Updated
                "execution_trace": updated_trace,  # Add transition to trace so LLM sees it
                "messages": [AIMessage(content=f"Phase transition approved. Now in **{new_phase}** phase.")],
                # Mark that we just transitioned to prevent re-requesting
                "_just_transitioned_to": new_phase,
            }

        elif approval == "modify":
            # User provided modifications - add to context
            return {
                **clear_approval_state,
                "messages": [
                    HumanMessage(content=f"User modification: {modification}"),
                    AIMessage(content="Understood. Adjusting approach based on your feedback."),
                ],
            }

        else:  # abort
            return {
                **clear_approval_state,
                "task_complete": True,
                "completion_reason": "Phase transition cancelled by user",
                "messages": [AIMessage(content="Phase transition cancelled. Ending session.")],
            }

    async def _await_question_node(self, state: AgentState, config = None) -> dict:
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

        # Format the question message
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

    async def _process_answer_node(self, state: AgentState, config = None) -> dict:
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

        # Update Q&A history
        qa_history = state.get("qa_history", []) + [qa_entry.model_dump()]

        # Clear Q&A state and add to messages
        # Also clear _emitted_question_key so the same question can be asked again later if needed
        return {
            "awaiting_user_question": False,
            "pending_question": None,
            "user_question_answer": None,
            "_emitted_question_key": None,
            "qa_history": qa_history,
            "messages": [
                HumanMessage(content=f"User answer: {answer}"),
                AIMessage(content="Thank you for the clarification. Continuing with the task..."),
            ],
        }

    async def _generate_response_node(self, state: AgentState, config = None) -> dict:
        """Generate final response summarizing the session."""
        user_id, project_id, session_id = get_identifiers(state, config)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Generating final response...")

        # Build final report prompt
        report_prompt = FINAL_REPORT_PROMPT.format(
            objective=state.get("original_objective", ""),
            iteration_count=state.get("current_iteration", 0),
            final_phase=state.get("current_phase", "informational"),
            completion_reason=state.get("completion_reason", "Session ended"),
            execution_trace=format_execution_trace(
                state.get("execution_trace", []),
                objectives=state.get("conversation_objectives", []),
                objective_history=state.get("objective_history", []),
                current_objective_index=state.get("current_objective_index", 0)
            ),
            target_info=json_dumps_safe(state.get("target_info", {}), indent=2),
            todo_list=format_todo_list(state.get("todo_list", [])),
        )

        response = await self.llm.ainvoke([HumanMessage(content=report_prompt)])

        return {
            "messages": [AIMessage(content=response.content)],
            "task_complete": True,
            "completion_reason": state.get("completion_reason") or "Task completed successfully",
        }

    # =========================================================================
    # ROUTING FUNCTIONS
    # =========================================================================

    def _route_after_initialize(self, state: AgentState) -> str:
        """Route after initialization - process approval, process answer, or think."""
        # If we have an approval response pending, go to process_approval
        if state.get("user_approval_response") and state.get("phase_transition_pending"):
            logger.info("Routing to process_approval - approval response pending")
            return "process_approval"

        # If we have a question answer pending, go to process_answer
        if state.get("user_question_answer") and state.get("pending_question"):
            logger.info("Routing to process_answer - question answer pending")
            return "process_answer"

        return "think"

    def _route_after_think(self, state: AgentState) -> str:
        """Route based on think node decision."""
        # Check for max iterations
        if state.get("current_iteration", 0) >= state.get("max_iterations", MAX_ITERATIONS):
            logger.info("Max iterations reached, generating response")
            return "generate_response"

        # Check if task is complete
        if state.get("task_complete"):
            return "generate_response"

        # Check if awaiting approval
        if state.get("awaiting_user_approval"):
            return "await_approval"

        # Check if awaiting question answer
        if state.get("awaiting_user_question"):
            return "await_question"

        # Check decision action (may have been modified by _think_node when ignoring transitions)
        decision = state.get("_decision", {})
        action = decision.get("action", "use_tool")
        tool_name = decision.get("tool_name")

        if action == "complete":
            return "generate_response"
        elif action == "ask_user":
            # If question is pending, await user answer
            if state.get("pending_question"):
                return "await_question"
            else:
                logger.warning("ask_user action but no pending_question, continuing to think")
                return "generate_response"
        elif action == "transition_phase":
            # If transition is pending, await approval
            if state.get("phase_transition_pending"):
                return "await_approval"
            # Transition was ignored - route based on tool availability
            if tool_name:
                logger.info(f"Transition ignored, executing tool: {tool_name}")
                return "execute_tool"
            else:
                logger.info("Transition ignored and no tool, generating response")
                return "generate_response"
        elif action == "use_tool" and tool_name:
            return "execute_tool"
        else:
            # No valid action and no tool - end session
            logger.warning(f"No valid action in decision: {action}, tool: {tool_name}")
            return "generate_response"

    def _route_after_analyze(self, state: AgentState) -> str:
        """Route after output analysis."""
        if state.get("task_complete"):
            return "generate_response"

        if state.get("current_iteration", 0) >= state.get("max_iterations", MAX_ITERATIONS):
            return "generate_response"

        return "think"

    def _route_after_approval(self, state: AgentState) -> str:
        """Route after processing approval."""
        # If task is complete (abort case), generate response
        if state.get("task_complete"):
            return "generate_response"

        # Otherwise continue to think node
        return "think"

    def _route_after_answer(self, state: AgentState) -> str:
        """Route after processing user's answer to a question."""
        # If task is complete, generate response
        if state.get("task_complete"):
            return "generate_response"

        # Otherwise continue to think node with the answer in context
        return "think"

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    async def invoke(
        self,
        question: str,
        user_id: str,
        project_id: str,
        session_id: str
    ) -> InvokeResponse:
        """Main entry point for agent invocation."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        logger.info(f"[{user_id}/{project_id}/{session_id}] Invoking with: {question[:10000]}")

        try:
            config = create_config(user_id, project_id, session_id)
            input_data = {
                "messages": [HumanMessage(content=question)]
            }

            final_state = await self.graph.ainvoke(input_data, config)

            return self._build_response(final_state)

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Error: {e}")
            return InvokeResponse(error=str(e))

    async def resume_after_approval(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        decision: str,
        modification: Optional[str] = None
    ) -> InvokeResponse:
        """Resume execution after user provides approval response."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with approval: {decision}")

        try:
            config = create_config(user_id, project_id, session_id)

            # Get current state from checkpointer
            current_state = await self.graph.aget_state(config)

            if not current_state or not current_state.values:
                return InvokeResponse(error="No pending session found")

            # Update state with approval response
            update_data = {
                "user_approval_response": decision,
                "user_modification": modification,
            }

            # Resume from process_approval node
            # We need to invoke with the updated state
            final_state = await self.graph.ainvoke(
                update_data,
                config,
            )

            return self._build_response(final_state)

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))

    async def resume_after_answer(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        answer: str
    ) -> InvokeResponse:
        """Resume execution after user provides answer to a question."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with answer: {answer[:10000]}")

        try:
            config = create_config(user_id, project_id, session_id)

            # Get current state from checkpointer
            current_state = await self.graph.aget_state(config)

            if not current_state or not current_state.values:
                return InvokeResponse(error="No pending session found")

            # Update state with user's answer
            update_data = {
                "user_question_answer": answer,
            }

            # Resume execution with the answer
            final_state = await self.graph.ainvoke(
                update_data,
                config,
            )

            return self._build_response(final_state)

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))

    def _build_response(self, state: dict) -> InvokeResponse:
        """Build InvokeResponse from final state."""
        # Extract final answer from messages
        final_answer = ""
        tool_used = None
        tool_output = None

        messages = state.get("messages", [])
        for msg in reversed(messages):
            if isinstance(msg, AIMessage):
                final_answer = msg.content
                break

        # Get tool info from current step if available
        step = state.get("_current_step", {})
        if step:
            tool_used = step.get("tool_name")
            tool_output = step.get("tool_output")

        return InvokeResponse(
            answer=final_answer,
            tool_used=tool_used,
            tool_output=tool_output,
            current_phase=state.get("current_phase", "informational"),
            iteration_count=state.get("current_iteration", 0),
            task_complete=state.get("task_complete", False),
            todo_list=state.get("todo_list", []),
            execution_trace_summary=summarize_trace_for_response(
                state.get("execution_trace", [])
            ),
            awaiting_approval=state.get("awaiting_user_approval", False),
            approval_request=state.get("phase_transition_pending"),
            awaiting_question=state.get("awaiting_user_question", False),
            question_request=state.get("pending_question"),
        )

    async def invoke_with_streaming(
        self,
        question: str,
        user_id: str,
        project_id: str,
        session_id: str,
        streaming_callback
    ) -> InvokeResponse:
        """
        Invoke agent with streaming callbacks for real-time updates.

        The streaming_callback should have methods:
        - on_thinking(iteration, phase, thought, reasoning)
        - on_tool_start(tool_name, tool_args)
        - on_tool_output_chunk(tool_name, chunk, is_final)
        - on_tool_complete(tool_name, success, output_summary)
        - on_phase_update(current_phase, iteration_count)
        - on_todo_update(todo_list)
        - on_approval_request(approval_request)
        - on_question_request(question_request)
        - on_response(answer, iteration_count, phase, task_complete)
        - on_execution_step(step)
        - on_error(error_message, recoverable)
        - on_task_complete(message, final_phase, total_iterations)
        """
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        logger.info(f"[{user_id}/{project_id}/{session_id}] Invoking with streaming: {question[:10000]}")

        # Store streaming callback for use in _execute_tool_node
        self._streaming_callback = streaming_callback

        try:
            config = create_config(user_id, project_id, session_id)
            input_data = {
                "messages": [HumanMessage(content=question)]
            }

            # Stream graph execution
            final_state = None
            async for event in self.graph.astream(input_data, config, stream_mode="values"):
                final_state = event
                await self._emit_streaming_events(event, streaming_callback)

            if final_state:
                # Send final response
                response = self._build_response(final_state)
                await streaming_callback.on_response(
                    response.answer,
                    response.iteration_count,
                    response.current_phase,
                    response.task_complete
                )
                return response
            else:
                raise RuntimeError("No final state returned from graph execution")

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Streaming error: {e}")
            await streaming_callback.on_error(str(e), recoverable=False)
            return InvokeResponse(error=str(e))
        finally:
            self._streaming_callback = None  # Clear callback after execution

    async def resume_after_approval_with_streaming(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        decision: str,
        modification: Optional[str],
        streaming_callback
    ) -> InvokeResponse:
        """Resume after approval with streaming callbacks."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with streaming approval: {decision}")

        # Store streaming callback for use in _execute_tool_node
        self._streaming_callback = streaming_callback

        try:
            config = create_config(user_id, project_id, session_id)

            # Get current state
            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No pending session found", recoverable=False)
                return InvokeResponse(error="No pending session found")

            # Update with approval
            update_data = {
                "user_approval_response": decision,
                "user_modification": modification,
            }

            # Stream execution
            final_state = None
            async for event in self.graph.astream(update_data, config, stream_mode="values"):
                final_state = event
                await self._emit_streaming_events(event, streaming_callback)

            if final_state:
                response = self._build_response(final_state)
                await streaming_callback.on_response(
                    response.answer,
                    response.iteration_count,
                    response.current_phase,
                    response.task_complete
                )
                return response
            else:
                raise RuntimeError("No final state returned")

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume streaming error: {e}")
            await streaming_callback.on_error(str(e), recoverable=False)
            return InvokeResponse(error=str(e))
        finally:
            self._streaming_callback = None  # Clear callback after execution

    async def resume_after_answer_with_streaming(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        answer: str,
        streaming_callback
    ) -> InvokeResponse:
        """Resume after answer with streaming callbacks."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with streaming answer: {answer[:10000]}")

        # Store streaming callback for use in _execute_tool_node
        self._streaming_callback = streaming_callback

        try:
            config = create_config(user_id, project_id, session_id)

            # Get current state
            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No pending session found", recoverable=False)
                return InvokeResponse(error="No pending session found")

            # Update with answer
            update_data = {
                "user_question_answer": answer,
            }

            # Stream execution
            final_state = None
            async for event in self.graph.astream(update_data, config, stream_mode="values"):
                final_state = event
                await self._emit_streaming_events(event, streaming_callback)

            if final_state:
                response = self._build_response(final_state)
                await streaming_callback.on_response(
                    response.answer,
                    response.iteration_count,
                    response.current_phase,
                    response.task_complete
                )
                return response
            else:
                raise RuntimeError("No final state returned")

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume streaming error: {e}")
            await streaming_callback.on_error(str(e), recoverable=False)
            return InvokeResponse(error=str(e))
        finally:
            self._streaming_callback = None  # Clear callback after execution

    async def _emit_streaming_events(self, state: dict, callback):
        """Emit appropriate streaming events based on state changes."""
        try:
            # Phase update (includes attack_path_type for dynamic routing display)
            if "current_phase" in state:
                await callback.on_phase_update(
                    state.get("current_phase", "informational"),
                    state.get("current_iteration", 0),
                    state.get("attack_path_type", "cve_exploit")
                )

            # Todo list update
            if "todo_list" in state and state.get("todo_list"):
                await callback.on_todo_update(state["todo_list"])

            # Approval request - use state marker to prevent duplicate emissions
            if state.get("awaiting_user_approval") and state.get("phase_transition_pending"):
                pending = state["phase_transition_pending"]
                # Create unique key for this specific transition
                approval_key = f"{pending.get('from_phase', '')}_{pending.get('to_phase', '')}"
                if state.get("_emitted_approval_key") != approval_key:
                    await callback.on_approval_request(pending)
                    state["_emitted_approval_key"] = approval_key

            # Question request - use state marker to prevent duplicate emissions
            if state.get("awaiting_user_question") and state.get("pending_question"):
                pending = state["pending_question"]
                # Create unique key for this specific question
                question_key = f"{pending.get('phase', '')}_{hash(pending.get('question', '')[:100])}"
                if state.get("_emitted_question_key") != question_key:
                    await callback.on_question_request(pending)
                    state["_emitted_question_key"] = question_key

            # Emit thinking FIRST (from _decision stored by _think_node)
            # This ensures thinking appears BEFORE the tool execution it leads to
            if "_decision" in state and state["_decision"]:
                decision = state["_decision"]
                # Only emit if we haven't emitted this decision yet
                if decision.get("thought") and not decision.get("_emitted_thinking"):
                    try:
                        await callback.on_thinking(
                            state.get("current_iteration", 0),
                            state.get("current_phase", "informational"),
                            decision.get("thought", ""),
                            decision.get("reasoning", "")
                        )
                        # Mark as emitted to avoid duplicates
                        decision["_emitted_thinking"] = True
                    except Exception as e:
                        logger.error(f"Error emitting thinking event: {e}")

            # Execution step (from _current_step) - AFTER thinking
            if "_current_step" in state and state["_current_step"]:
                step = state["_current_step"]
                # Emit tool start
                if step.get("tool_name") and not step.get("_emitted_start"):
                    await callback.on_tool_start(
                        step["tool_name"],
                        step.get("tool_args", {})
                    )
                    step["_emitted_start"] = True

                # Emit tool output chunk (raw tool output)
                if step.get("tool_output") and not step.get("_emitted_output"):
                    await callback.on_tool_output_chunk(
                        step.get("tool_name", "unknown"),
                        step["tool_output"],
                        is_final=True
                    )
                    step["_emitted_output"] = True

                # Emit tool complete ONLY after analysis is done (output_analysis exists)
                # This ensures we have all the rich data to send
                if step.get("success") is not None and step.get("output_analysis") and not step.get("_emitted_complete"):
                    await callback.on_tool_complete(
                        step.get("tool_name", "unknown"),
                        step["success"],
                        step.get("output_analysis", "")[:10000],
                        # Include rich analysis data
                        actionable_findings=step.get("actionable_findings", []),
                        recommended_next_steps=step.get("recommended_next_steps", []),
                    )
                    step["_emitted_complete"] = True

                # Emit execution step summary (only after analysis)
                if step.get("output_analysis"):
                    await callback.on_execution_step({
                        "iteration": step.get("iteration", 0),
                        "phase": state.get("current_phase", "informational"),
                        "thought": step.get("thought", ""),
                        "tool_name": step.get("tool_name"),
                        "success": step.get("success", False),
                        "output_summary": step.get("output_analysis", "")[:10000],
                        "actionable_findings": step.get("actionable_findings", []),
                        "recommended_next_steps": step.get("recommended_next_steps", []),
                    })

            # Task complete - only emit if this is a genuine completion, not stale state
            # We check for completion_reason to ensure this is from _generate_response_node
            # and not just residual state from a previous completed task
            if state.get("task_complete") and state.get("completion_reason"):
                await callback.on_task_complete(
                    state.get("completion_reason", "Task completed successfully"),
                    state.get("current_phase", "informational"),
                    state.get("current_iteration", 0)
                )

        except Exception as e:
            logger.error(f"Error emitting streaming events: {e}")
            # Don't fail the whole operation if streaming fails
            pass

    async def close(self) -> None:
        """Clean up resources."""
        self._initialized = False
        logger.info("AgentOrchestrator closed")
