"""Configuration and session management helpers for the orchestrator."""

from typing import TYPE_CHECKING, Tuple, List, Optional

from state import AgentState
from project_settings import get_setting

if TYPE_CHECKING:
    from langgraph.checkpoint.memory import MemorySaver


_checkpointer: "MemorySaver | None" = None


def _bind_log_session(session_id: str) -> None:
    """Bind session_id for per-session log routing (best-effort, never raises).

    Called from get_config_values so each node re-asserts the routing key in its
    own execution context, covering any node LangGraph runs outside the task that
    ran create_config.
    """
    if not session_id or session_id == "unknown":
        return
    try:
        from agent_context import current_log_session_id
        if current_log_session_id.get() != session_id:
            current_log_session_id.set(session_id)
    except Exception:
        pass


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


def create_config(
    user_id: str,
    project_id: str,
    session_id: str,
    tenant_user_id: Optional[str] = None,
) -> dict:
    """
    Create config for graph invocation with checkpointer thread_id.

    Config contains:
    - thread_id: For MemorySaver checkpointer (session persistence)
    - user_id, project_id, session_id: For logging in nodes
    - tenant_user_id: the graph tenant (get_tenant_id)

    Args:
        user_id: The person running the session (the ticket's `sub`): the thread id,
            the chat, the run registry and the Agent in the Loop scope are theirs
        project_id: Project identifier
        session_id: Session identifier for conversation continuity
        tenant_user_id: The project's owner (the ticket's `ten`), whose id the
            project's graph nodes, traffic and run credentials carry. None or empty
            is `user_id`: a ticket without `ten` came from an owner (RBAC T9).

    Returns:
        Config dict for graph.invoke()
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    # Bind this turn's session id for per-session log routing. Set here (not in
    # set_tenant_context, which nodes call with session_id="") so it survives the
    # whole graph run; asyncio child tasks snapshot it at creation, so every node
    # spawned by the astream below inherits it.
    try:
        from agent_context import current_log_session_id
        current_log_session_id.set(session_id or "")
    except Exception:
        pass

    return {
        # LangGraph recursion limit - must be higher than MAX_ITERATIONS
        # Each iteration may have multiple graph transitions (think -> execute -> analyze)
        "recursion_limit": get_setting('MAX_ITERATIONS', 100) * 5,
        "configurable": {
            "thread_id": thread_id,
            "user_id": user_id,
            "tenant_user_id": tenant_user_id or user_id,
            "project_id": project_id,
            "session_id": session_id
        }
    }


def get_config_values(config) -> Tuple[str, str, str]:
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
        sid = configurable.get("session_id", "unknown")
        _bind_log_session(sid)
        return (
            configurable.get("user_id", "unknown"),
            configurable.get("project_id", "unknown"),
            sid
        )
    elif hasattr(configurable, 'get'):
        sid = configurable.get("session_id", "unknown")
        _bind_log_session(sid)
        return (
            configurable.get("user_id", "unknown"),
            configurable.get("project_id", "unknown"),
            sid
        )
    else:
        sid = getattr(configurable, "session_id", "unknown")
        _bind_log_session(sid)
        return (
            getattr(configurable, "user_id", "unknown"),
            getattr(configurable, "project_id", "unknown"),
            sid
        )


def get_identifiers(state: AgentState, config=None) -> Tuple[str, str, str]:
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


def get_tenant_id(state: AgentState, config=None) -> str:
    """The graph tenant of this run: the project's owner, whose id every graph read and
    write, the REDAMON_CTX tag and the run credentials carry (set_tenant_context, the
    chain writers). `get_identifiers` keeps answering the person, who keys the thread,
    the chat and the loop scope.

    From the config (create_config always writes it), else the state (initialize_node
    copies it there for the Fireteam members), else the person: a config built
    without a tenant is an owner's, as every config was before step 5.3.
    """
    configurable = None
    if isinstance(config, dict):
        configurable = config.get("configurable")
    elif config is not None:
        configurable = getattr(config, "configurable", None)
    tenant = configurable.get("tenant_user_id") if isinstance(configurable, dict) else None
    if not tenant and isinstance(state, dict):
        tenant = state.get("tenant_user_id")
    if tenant:
        return tenant
    user_id, _project_id, _session_id = get_identifiers(state, config)
    return user_id


def is_session_config_complete() -> Tuple[bool, List[str]]:
    """
    Check if session configuration is complete for exploitation.

    Decision Logic:
        IF ngrok tunnel is enabled and reachable:
            → LHOST/LPORT auto-detected from ngrok, config is complete
        ELSE IF LPORT is set (not None, > 0):
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
    # Check ngrok tunnel first — if active, LHOST/LPORT are auto-detected
    NGROK_TUNNEL_ENABLED = get_setting('NGROK_TUNNEL_ENABLED', False)
    if NGROK_TUNNEL_ENABLED:
        from utils import _query_ngrok_tunnel
        tunnel_info = _query_ngrok_tunnel()
        if tunnel_info:
            return (True, [])

    # Check chisel tunnel — if active, LHOST/LPORT are derived from VPS URL
    CHISEL_TUNNEL_ENABLED = get_setting('CHISEL_TUNNEL_ENABLED', False)
    if CHISEL_TUNNEL_ENABLED:
        from utils import _query_chisel_tunnel
        tunnel_info = _query_chisel_tunnel()
        if tunnel_info:
            return (True, [])

    LPORT = get_setting('LPORT')
    LHOST = get_setting('LHOST', '') or None
    BIND_PORT_ON_TARGET = get_setting('BIND_PORT_ON_TARGET', 4444)

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
