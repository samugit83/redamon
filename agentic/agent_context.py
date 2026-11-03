"""
Per-request agent context.

These ContextVars are set by the agent runtime (orchestrator / websocket
endpoint / fireteam) at the start of each turn so that tools can read user
and project identity from any depth of call stack without threading args.

Lives in its own module (instead of in tools.py) so that lightweight callers
- workspace_fs, job_runner, output_offload, and unit tests for those modules -
can import the contextvars without pulling in langchain / MCP / neo4j as a
side effect of importing tools.
"""
from contextvars import ContextVar
from typing import Optional

current_user_id: ContextVar[str] = ContextVar("current_user_id", default="")
current_project_id: ContextVar[str] = ContextVar("current_project_id", default="")
current_session_id: ContextVar[str] = ContextVar("current_session_id", default="")
# Session id used ONLY to route log records to per-session files. Kept separate
# from current_session_id because node-level set_tenant_context(user, project)
# calls reset current_session_id to "" mid-run; this one is set once per turn at
# the graph entrypoint (create_config) and must survive the whole execution so
# every node's records land in the same agent.<session_id>.log.
current_log_session_id: ContextVar[str] = ContextVar("current_log_session_id", default="")
current_phase: ContextVar[str] = ContextVar("current_phase", default="informational")
current_graph_view_cypher: ContextVar[Optional[str]] = ContextVar(
    "current_graph_view_cypher", default=None,
)
# Per-session LLM. Set during apply_project_settings (synchronous, so the
# capture is atomic per asyncio task). Concurrent sessions for different projects
# each read their OWN model's client instead of a shared, race-prone self.llm.
# Typed as object to keep this module import-light (no langchain dependency).
current_llm: ContextVar[Optional[object]] = ContextVar("current_llm", default=None)
# What the next model call is for (agent_in_the_loop.purpose.llm_purpose).
# Read only by the Agent in the Loop adapter; the default dict is never mutated.
current_llm_purpose: ContextVar[dict] = ContextVar(
    "current_llm_purpose", default={"purpose": "other"},
)


def set_tenant_context(user_id: str, project_id: str, session_id: str = "") -> None:
    """Set the current user, project (and session) context for tools."""
    current_user_id.set(user_id)
    current_project_id.set(project_id)
    # Always set (even to "") so a later call can't inherit a previous call's
    # session_id and mis-attribute a captured request.
    current_session_id.set(session_id or "")


def set_phase_context(phase: str) -> None:
    """Set the current phase context for tool restrictions."""
    current_phase.set(phase)


def set_graph_view_context(cypher: Optional[str]) -> None:
    """Set the active graph view Cypher for scoped queries."""
    current_graph_view_cypher.set(cypher)


def get_graph_view_context() -> Optional[str]:
    """Get the active graph view Cypher template."""
    return current_graph_view_cypher.get()


def get_phase_context() -> str:
    """Get the current phase context."""
    return current_phase.get()


def set_llm_context(llm: Optional[object]) -> None:
    """Bind the current session's LLM for this asyncio task (and its children)."""
    current_llm.set(llm)


def get_llm_context() -> Optional[object]:
    """Get the current session's LLM, or None if not set in this task."""
    return current_llm.get()
