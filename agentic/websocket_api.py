"""
WebSocket API for RedAmon Agent

Provides WebSocket endpoint for real-time bidirectional communication with the agent.
Supports streaming of LLM thoughts, tool executions, and interactive approval/question flows.
"""

import asyncio
import json
import logging
import time
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Any, Callable
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ValidationError
from orchestrator_helpers import create_config
from orchestrator_helpers.chat_persistence import post_agent_decision, save_chat_message, update_conversation
from decision_check import UNAVAILABLE as DECISION_CHECK_UNAVAILABLE, RunActor, authorize_decision, bind_run_actor
from agent_in_the_loop.broker import get_broker
from sandbox_runs import schedule_sandbox_stop


def serialize_for_json(obj):
    """Convert objects to JSON-serializable format, handling datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_for_json(item) for item in obj]
    return obj

logger = logging.getLogger(__name__)


def _error_details(exc: BaseException) -> dict:
    """What an ERROR frame may say about an exception: its class and, for a
    provider error, the HTTP status the provider answered. Never its text: a
    provider message can quote part of a key or the prompt, a Neo4j one the
    Cypher with target data. The text goes to the log."""
    from llm_builder import provider_error_details
    return provider_error_details(exc)


def _invalid_fields(exc: ValidationError) -> list:
    """The paths of the fields a client frame got wrong, never their values."""
    paths = {".".join(str(part) for part in err.get("loc", ())) for err in exc.errors()}
    return sorted(p for p in paths if p)[:10]


def _invalid_frame(message: str, exc: ValidationError, recoverable: bool) -> dict:
    fields = _invalid_fields(exc)
    return {
        "message": f"{message}: {', '.join(fields)}" if fields else message,
        "code": "invalid_frame",
        "fields": fields,
        "recoverable": recoverable,
    }


def _governed_max_sessions():
    """Concurrent agent-session ceiling byte-budgeted to available RAM, or None to
    not cap. Each session holds a full agent state (~measured envelope), so this
    uses the byte-budget model (not ratio) — safe on small hosts. Generous base
    (MAX_AGENT_SESSIONS, default 20). The agent mem_limit is the hard backstop.
    Fail-open."""
    import os
    try:
        from graph_db import resource_governor as rg
    except Exception:
        try:
            import resource_governor as rg
        except Exception:
            return None
    try:
        if not rg.governor_enabled():
            return None
        base = int(os.environ.get("MAX_AGENT_SESSIONS", "20") or "20")
        env = rg.envelope("agent_session_envelope_bytes")
        frac = rg._env_float("AGENT_MEM_BUDGET_FRACTION", 0.5)
        return rg.scaled_cap(base, env, frac, 1)
    except Exception:
        return None


# =============================================================================
# MESSAGE TYPE DEFINITIONS
# =============================================================================

class MessageType(str, Enum):
    """WebSocket message types"""
    # Client → Server
    INIT = "init"
    QUERY = "query"
    APPROVAL = "approval"
    ANSWER = "answer"
    TOOL_CONFIRMATION = "tool_confirmation"
    FIRETEAM_MEMBER_CONFIRMATION = "fireteam_member_confirmation"
    PING = "ping"
    GUIDANCE = "guidance"
    SKILL_INJECT = "skill_inject"
    STOP = "stop"
    RESUME = "resume"
    TOOL_STOP = "tool_stop"

    # Server → Client
    CONNECTED = "connected"
    THINKING = "thinking"
    THINKING_CHUNK = "thinking_chunk"
    TOOL_START = "tool_start"
    TOOL_OUTPUT_CHUNK = "tool_output_chunk"
    # The tool itself returned; its tool_complete (with the LLM's analysis)
    # follows only after the next think turn.
    TOOL_FINISHED = "tool_finished"
    TOOL_COMPLETE = "tool_complete"
    PHASE_UPDATE = "phase_update"
    TODO_UPDATE = "todo_update"
    APPROVAL_REQUEST = "approval_request"
    QUESTION_REQUEST = "question_request"
    RESPONSE = "response"
    EXECUTION_STEP = "execution_step"
    ERROR = "error"
    PONG = "pong"
    TASK_COMPLETE = "task_complete"
    GUIDANCE_ACK = "guidance_ack"
    SKILL_INJECT_ACK = "skill_inject_ack"
    STOPPED = "stopped"
    FILE_READY = "file_ready"
    PLAN_START = "plan_start"
    PLAN_COMPLETE = "plan_complete"
    PLAN_ANALYSIS = "plan_analysis"
    DEEP_THINK = "deep_think"
    TOOL_CONFIRMATION_REQUEST = "tool_confirmation_request"
    # Fireteam (multi-agent) events
    FIRETEAM_DEPLOYED = "fireteam_deployed"
    FIRETEAM_MEMBER_STARTED = "fireteam_member_started"
    FIRETEAM_THINKING = "fireteam_thinking"
    FIRETEAM_TOOL_START = "fireteam_tool_start"
    FIRETEAM_TOOL_OUTPUT_CHUNK = "fireteam_tool_output_chunk"
    FIRETEAM_TOOL_COMPLETE = "fireteam_tool_complete"
    FIRETEAM_PLAN_START = "fireteam_plan_start"
    FIRETEAM_PLAN_COMPLETE = "fireteam_plan_complete"
    FIRETEAM_MEMBER_COMPLETED = "fireteam_member_completed"
    FIRETEAM_COMPLETED = "fireteam_completed"
    FIRETEAM_MEMBER_AWAITING_CONFIRMATION = "fireteam_member_awaiting_confirmation"
    # LATS (exploit-path tree search) lifecycle events. String values MUST stay
    # byte-identical to the TS MessageType enum in webapp/src/lib/websocket-types.ts.
    LATS_START = "lats_start"
    LATS_TREE_UPDATE = "lats_tree_update"
    LATS_COMPLETE = "lats_complete"
    # Background-job lifecycle events emitted by JobRegistry
    JOB_UPDATE = "job_update"
    # Agent in the Loop: who answers the run's model calls right now. Sent, never
    # persisted, and only for a run whose model is the loop model.
    LOOP_STATUS = "loop_status"
    # A model call is waiting for the provider's rate limit to clear before its
    # next try. Sent, never persisted: a pause, not part of the conversation.
    RATE_LIMIT_WAIT = "rate_limit_wait"


# =============================================================================
# CLIENT MESSAGE MODELS
# =============================================================================

class InitMessage(BaseModel):
    """Initialize WebSocket session"""
    user_id: str
    project_id: str
    session_id: str
    graph_view_cypher: Optional[str] = None
    # STRIDE S6/S2: short-lived HS256 ticket minted by the webapp, binding the
    # operator's authenticated identity to (user_id, project_id, session_id).
    # Verified by the agent before the session is registered. The field stays
    # Optional on the wire, but handle_init now FAILS CLOSED: a missing/invalid
    # ticket (or an unset AGENT_WS_TICKET_SECRET) is rejected, not trusted.
    ticket: Optional[str] = None


class QueryMessage(BaseModel):
    """Send query to agent"""
    question: str


class ApprovalMessage(BaseModel):
    """Respond to phase transition approval request"""
    decision: str  # 'approve' | 'modify' | 'abort'
    modification: Optional[str] = None


class AnswerMessage(BaseModel):
    """Answer agent's question"""
    answer: str


class ToolConfirmationMessage(BaseModel):
    """Respond to tool confirmation request"""
    decision: str  # 'approve' | 'modify' | 'reject'
    modifications: Optional[dict] = None  # {tool_name: {arg: value}} for modify


class FireteamMemberConfirmationMessage(BaseModel):
    """Operator decision for a single fireteam member's dangerous-tool request.

    Routed to fireteam_confirmation_registry.resolve() which wakes the
    awaiting member task. Unlike ToolConfirmationMessage, this does NOT
    pause the parent graph — multiple members may be awaiting in parallel.
    """
    wave_id: str
    member_id: str
    decision: str  # 'approve' | 'reject'
    modifications: Optional[dict] = None


class GuidanceMessage(BaseModel):
    """Send guidance to steer agent while it's working"""
    message: str


class ToolStopMessage(BaseModel):
    """Cancel a single running tool execution.

    Identifies the specific tool to stop via tool_name plus optional
    wave_id / step_index (for tools running inside a plan wave). The
    running task is cancelled and the tool completes with success=False,
    letting the agent flow proceed to the next tool / iteration.
    """
    tool_name: str
    wave_id: Optional[str] = None
    step_index: Optional[int] = None


# =============================================================================
# WEBSOCKET CONNECTION MANAGER
# =============================================================================

class WebSocketConnection:
    """Manages individual WebSocket connection state"""

    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.user_id: Optional[str] = None
        #: The project's owner (the ticket's `ten`, ws_ticket.ticket_tenant): the graph
        #: tenant the session's runs read and write. `user_id` stays the person, who keys
        #: the session, the chat and the loop scope. None until a verified init.
        self.tenant_id: Optional[str] = None
        self.project_id: Optional[str] = None
        self.session_id: Optional[str] = None
        #: The person signed in when an admin acts as `user_id` (the ticket's `act`),
        #: so closing that person's sockets reaches this one too.
        self.actor_id: Optional[str] = None
        #: The agent permissions the ticket's person holds on the project (its `cap`,
        #: ws_ticket.ticket_cap); None for a ticket without one, which allows everything.
        self.cap: Optional[frozenset] = None
        self.graph_view_cypher: Optional[str] = None
        self.authenticated = False
        self.connected_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self.last_ping = datetime.now(timezone.utc).replace(tzinfo=None)
        self.guidance_queue: asyncio.Queue = asyncio.Queue()
        self._active_task: Optional[Any] = None
        self._is_stopped: bool = False

    async def send_message(self, message_type: MessageType, payload: Any):
        """Send JSON message to client. Gracefully handles closed connections."""
        try:
            # Serialize payload to handle datetime objects
            serialized_payload = serialize_for_json(payload)
            message = {
                "type": message_type.value,
                "payload": serialized_payload,
                "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
            }
            await self.websocket.send_json(message)
            logger.debug(f"Sent {message_type.value} message to {self.session_id}")
        except Exception as e:
            # Gracefully handle closed WebSocket (e.g. user switched conversation)
            # Messages are still persisted via chat_persistence
            logger.debug(f"WebSocket send failed for {self.session_id} (client may have switched): {e}")

    def drain_guidance(self) -> list:
        """Drain all pending guidance messages from the queue (non-blocking)."""
        messages = []
        while not self.guidance_queue.empty():
            try:
                messages.append(self.guidance_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return messages

    def get_key(self) -> Optional[str]:
        """Get unique key for this connection"""
        if self.authenticated:
            return f"{self.user_id}:{self.project_id}:{self.session_id}"
        return None

    def holds(self, permission: str) -> bool:
        """Whether this connection's person may take a decision that needs `permission`."""
        return self.cap is None or permission in self.cap

    def decision_actor(self) -> dict:
        """Who answered on this connection, as a saved decision records it."""
        return {"sub": self.user_id, **({"act": self.actor_id} if self.actor_id else {})}

    def run_actor(self) -> RunActor:
        """Who a run this connection starts or resumes acts for: the decisions the project's
        settings take without asking need this person's permissions (decision_check)."""
        return RunActor(user_id=self.user_id, tenant_id=self.tenant_id or self.user_id,
                        project_id=self.project_id, session_id=self.session_id,
                        actor_id=self.actor_id, cap=self.cap)


#: What an emergency stop tells the open socket of each run it stops.
EMERGENCY_STOP_ALL_MESSAGE = "Emergency stop — all agents halted"
EMERGENCY_STOP_OWN_MESSAGE = "Emergency stop — your agent runs were halted"


class WebSocketManager:
    """Manages active WebSocket connections"""

    def __init__(self):
        # Map of session_key → WebSocketConnection
        self.active_connections: Dict[str, WebSocketConnection] = {}
        # Separate task registry keyed by session_key — survives connection replacement
        self._active_tasks: Dict[str, asyncio.Task] = {}
        # Callback registry keyed by session_key. Mirrors _active_tasks so a
        # NEW connection joining a still-running session (reconnect / switch back
        # from history) can reach the live StreamingCallback and flush its
        # persist queue — the DB otherwise lags the live stream, so the restore
        # read returns a stale/empty timeline. See handle_init flush-on-connect.
        self._active_callbacks: Dict[str, 'StreamingCallback'] = {}
        # Keyed by the run's task itself, so an entry leaves with the run however
        # its registration ends (released, stopped, found done, emergency stop).
        self._run_actors: 'weakref.WeakKeyDictionary[asyncio.Task, str]' = weakref.WeakKeyDictionary()
        # Per-tool task registry for individual tool cancellation.
        # Keyed by f"{session_key}|{wave_id or '__standalone__'}|{step_index if step_index is not None else -1}|{tool_name}".
        # Populated by execute_tool_node / execute_plan_node before awaiting the
        # tool executor; cleared in a finally block after the tool returns or
        # is cancelled.
        self._tool_tasks: Dict[str, asyncio.Task] = {}
        self.lock = asyncio.Lock()

    @staticmethod
    def _tool_task_key(session_key: str, tool_name: str,
                       wave_id: Optional[str], step_index: Optional[int]) -> str:
        wid = wave_id or "__standalone__"
        sidx = step_index if step_index is not None else -1
        return f"{session_key}|{wid}|{sidx}|{tool_name}"

    def register_tool_task(self, session_key: str, tool_name: str,
                           wave_id: Optional[str], step_index: Optional[int],
                           task: asyncio.Task):
        key = self._tool_task_key(session_key, tool_name, wave_id, step_index)
        self._tool_tasks[key] = task

    def unregister_tool_task(self, session_key: str, tool_name: str,
                             wave_id: Optional[str], step_index: Optional[int]):
        key = self._tool_task_key(session_key, tool_name, wave_id, step_index)
        self._tool_tasks.pop(key, None)

    def cancel_tool_task(self, session_key: str, tool_name: str,
                         wave_id: Optional[str], step_index: Optional[int]) -> bool:
        """Cancel a specific running tool task. Returns True if a task was cancelled."""
        key = self._tool_task_key(session_key, tool_name, wave_id, step_index)
        task = self._tool_tasks.get(key)
        if task and not task.done():
            task.cancel()
            return True
        # Fallback: if step_index wasn't provided, try the standalone key or
        # any matching tool_name within this session. This handles cases
        # where the frontend couldn't disambiguate.
        if step_index is None and wave_id is None:
            prefix = f"{session_key}|__standalone__|"
            for k, t in list(self._tool_tasks.items()):
                if k.startswith(prefix) and k.endswith(f"|{tool_name}") and not t.done():
                    t.cancel()
                    return True
        return False

    async def connect(self, websocket: WebSocket) -> WebSocketConnection:
        """Accept new WebSocket connection"""
        await websocket.accept()
        connection = WebSocketConnection(websocket)
        logger.info(f"WebSocket connection accepted from {websocket.client}")
        return connection

    async def authenticate(
        self,
        connection: WebSocketConnection,
        user_id: str,
        project_id: str,
        session_id: str,
        verified: bool = False
    ):
        """Authenticate and register connection.

        `verified` is True only when the caller presented a cryptographically
        valid WS ticket (S6). An UNVERIFIED peer may open a brand-new session
        (subject to the memory cap) but must NEVER seize or evict an existing
        one — that is exactly the S6 task-hijack + operator-eviction vector.
        """
        async with self.lock:
            # The drawer's "new session" re-inits the SAME socket. disconnect()
            # removes only the key the connection holds when it closes, so the
            # previous key would hold a session-cap slot until the agent restarts:
            # give it up first, and stay unauthenticated if this init is refused.
            previous = connection.get_key()
            if previous and self.active_connections.get(previous) is connection:
                del self.active_connections[previous]
            connection.authenticated = False

            connection.user_id = user_id
            connection.project_id = project_id
            connection.session_id = session_id

            # Compute the key DIRECTLY (not via get_key(), which returns None until
            # authenticated=True is set below) so the cap check + registration use
            # the real key, not None.
            session_key = f"{user_id}:{project_id}:{session_id}"
            collision = session_key in self.active_connections

            # Memory governor (Part 3): cap concurrent NEW sessions to available
            # RAM (none existed before). Reconnects to an existing key are always
            # allowed. On rejection we close the socket and leave authenticated
            # False, so the caller's existing `if not authenticated` guard applies.
            # A run whose tab closed keeps all its memory, so live runs count
            # as well as connections; a verified peer returning to such a run is
            # a reconnect. Agent in the Loop runs are long and often headless.
            live = set(self.active_connections) | {
                k for k in list(self._active_tasks) if self.get_task(k) is not None}
            reconnect = collision or (verified and session_key in live)
            if not reconnect:
                cap = _governed_max_sessions()
                if cap is not None and len(live) >= cap:
                    logger.warning(f"session cap reached ({len(live)}/{cap}); "
                                   f"rejecting new session {session_key}")
                    try:
                        await connection.websocket.close(
                            code=1013, reason="Server busy (low memory) - retry shortly")
                    except Exception:
                        pass
                    return

            # STRIDE S6: refuse to take over a live session from an unverified
            # peer. The existing operator keeps the socket and the running task;
            # the impersonating connection is closed. This holds even in the
            # dev fail-open mode (no ticket secret), so the worst S6 outcome
            # (hijack + eviction) is prevented regardless of secret config.
            if collision and not verified:
                logger.warning(
                    f"rejecting unverified takeover of active session {session_key}")
                try:
                    await connection.websocket.close(
                        code=1008, reason="Session in use; authentication required")
                except Exception:
                    pass
                return

            connection.authenticated = True

            # Verified reconnect: transfer running task from the old connection.
            if collision:
                old_conn = self.active_connections[session_key]
                # Transfer active task and state to the new connection
                if old_conn._active_task and not old_conn._active_task.done():
                    connection._active_task = old_conn._active_task
                    connection._is_stopped = old_conn._is_stopped
                    connection.guidance_queue = old_conn.guidance_queue
                    logger.info(f"Transferred running task to new connection for {session_key}")
                try:
                    await old_conn.websocket.close(code=1000, reason="New connection established")
                except Exception as e:
                    logger.warning(f"Error closing old connection: {e}")

            self.active_connections[session_key] = connection
            logger.info(f"Authenticated session: {session_key} (verified={verified})")

    async def disconnect(self, connection: WebSocketConnection):
        """Remove connection from active connections (only if it's the SAME object)"""
        async with self.lock:
            session_key = connection.get_key()
            if session_key and session_key in self.active_connections:
                # Identity check: don't remove a newer connection that replaced us
                if self.active_connections[session_key] is connection:
                    del self.active_connections[session_key]
                    logger.info(f"Disconnected session: {session_key}")
                else:
                    logger.debug(f"Skipped disconnect for {session_key} — connection already replaced")

    def register_task(self, session_key: str, task: asyncio.Task,
                      actor_id: Optional[str] = None):
        """Register an active task for a session (survives connection replacement).

        `actor_id` is the admin who started it while acting as the session's user
        (the starting socket's `actor_id`). It stays with the run, so closing that
        admin's sockets finds the run after its tab is gone (close_sockets).
        """
        self._active_tasks[session_key] = task
        if actor_id:
            self._run_actors[task] = actor_id

    def run_actor(self, session_key: str) -> Optional[str]:
        """The admin who started the session's registered run while acting, if any."""
        task = self._active_tasks.get(session_key)
        return self._run_actors.get(task) if task is not None else None

    def get_task(self, session_key: str) -> Optional[asyncio.Task]:
        """Get active (non-done) task for a session"""
        task = self._active_tasks.get(session_key)
        if task and task.done():
            del self._active_tasks[session_key]
            return None
        return task

    def clear_task(self, session_key: str):
        """Remove task from registry"""
        self._active_tasks.pop(session_key, None)

    def release_task(self, session_key: str, task: Optional[asyncio.Task]):
        """Remove the registration only if it is still `task`'s.

        A run that is finishing must not clear a NEWER run of the same session
        that registered while it was draining its persist queue.
        """
        if task is not None and self._active_tasks.get(session_key) is task:
            del self._active_tasks[session_key]

    def live_session_ids(self, project_id: str) -> List[str]:
        """Session ids of PROJECT whose agent task is still running.

        The webapp's Conversation.agentRunning flag is cleared by a fire-and-forget
        PATCH that a restarted or killed agent never sends; this registry is what
        the webapp checks a set flag against before treating the project as busy.
        """
        live = []
        for key in list(self._active_tasks):
            _user, _, rest = key.partition(":")
            key_project, _, session_id = rest.partition(":")
            if key_project == project_id and self.get_task(key) is not None:
                live.append(session_id)
        return live

    def all_sessions(self) -> List[dict]:
        """Every session of the instance with an open socket or a registered run, for the
        admin operations view (step 6.5): its person, project and session, whether a run is
        in progress, whether a socket is open, and the admin behind an act-as run (the run's,
        else the open socket's). Keys are parsed as live_session_ids does. Ids and flags only:
        never a message, a title, a ticket or the tenant.
        """
        sessions = []
        for key in sorted(set(self.active_connections) | set(self._active_tasks)):
            user_id, _, rest = key.partition(":")
            project_id, _, session_id = rest.partition(":")
            if not (user_id and project_id and session_id):
                continue
            running = self.get_task(key) is not None
            connection = self.active_connections.get(key)
            if not running and connection is None:
                # A run that ended with no socket left: get_task has just forgotten it.
                continue
            actor_id = (self.run_actor(key) if running else None) or (connection.actor_id if connection else None)
            sessions.append({
                "user_id": user_id, "project_id": project_id, "session_id": session_id,
                "running": running, "connected": connection is not None, "actor_id": actor_id or None,
            })
        return sessions

    def live_run_count(self, user_id: str) -> int:
        """How many of `user_id`'s runs are in progress, for the agent-run quota (step 6.8).

        The person is the session key's user, parsed as live_session_ids does, so an admin's
        act-as run is the member's. An open socket without a run does not count.
        """
        if not user_id:
            return 0
        count = 0
        for key in list(self._active_tasks):
            key_user, _, _rest = key.partition(":")
            if key_user == user_id and self.get_task(key) is not None:
                count += 1
        return count

    def register_callback(self, session_key: str, callback: 'StreamingCallback'):
        """Register the live StreamingCallback for a session (survives reconnect)."""
        self._active_callbacks[session_key] = callback

    def get_callback(self, session_key: str) -> Optional['StreamingCallback']:
        """Return the live callback for a session, or None if no run is active."""
        return self._active_callbacks.get(session_key)

    def clear_callback(self, session_key: str):
        """Remove callback from registry."""
        self._active_callbacks.pop(session_key, None)

    def release_callback(self, session_key: str, callback: 'StreamingCallback'):
        """Remove the callback only if it is still this run's (see release_task)."""
        if self._active_callbacks.get(session_key) is callback:
            del self._active_callbacks[session_key]

    def get_connection(self, user_id: str, project_id: str, session_id: str) -> Optional[WebSocketConnection]:
        """Get active connection by session identifiers"""
        session_key = f"{user_id}:{project_id}:{session_id}"
        return self.active_connections.get(session_key)

    def get_connection_count(self) -> int:
        """Get number of active connections"""
        return len(self.active_connections)

    async def stop_all(self) -> int:
        """Emergency stop: stop every running agent run, of every user.

        Returns the number of runs that were cancelled.
        """
        return await self._emergency_stop(list(self._active_tasks), EMERGENCY_STOP_ALL_MESSAGE)

    async def stop_for_user(self, user_id: str, project_ids: Optional[Iterable[str]] = None) -> int:
        """Emergency stop for one user: stop the runs registered under `user_id`.

        A run's key names the ticket's subject, the effective user, so a run an
        admin started acting as the member is the member's and stops here too.
        `project_ids`, when given, limits it to those projects. Returns the number
        of runs that were cancelled; an unknown user stops nothing.
        """
        if not user_id:
            return 0
        projects = None if project_ids is None else set(project_ids)
        keys = []
        # Parsed as live_session_ids does: the user is everything before the first ':'.
        for key in list(self._active_tasks):
            key_user, _, rest = key.partition(":")
            key_project, _, _session = rest.partition(":")
            if key_user == user_id and (projects is None or key_project in projects):
                keys.append(key)
        return await self._emergency_stop(keys, EMERGENCY_STOP_OWN_MESSAGE)

    async def stop_project_session(self, project_id: str, session_id: str,
                                   message: str = "Session stopped (conversation deleted)") -> bool:
        """stop_session for every key of `session_id` in `project_id`, whoever's.

        For a caller that knows the session but not its person: an orphan attack
        chain names its project's owner (the tenant), never the person whose run
        keys it. Parsed as live_session_ids does. True if a live run was cancelled.
        """
        if not project_id or not session_id:
            return False
        cancelled = False
        for key in sorted(set(self._active_tasks) | set(self.active_connections)):
            _user, _, rest = key.partition(":")
            key_project, _, key_session = rest.partition(":")
            if key_project == project_id and key_session == session_id:
                cancelled = await self.stop_session(key, message=message) or cancelled
        return cancelled

    async def _emergency_stop(self, keys, message: str) -> int:
        """stop_session for each key with a live run (its tool tasks too)."""
        stopped = 0
        for key in keys:
            if self.get_task(key) is None:
                continue
            if not await self.stop_session(key, message=message):
                continue
            stopped += 1
            # The run's own `finally` clears the flag as well, but a run cancelled
            # before its first step never executes it.
            session_id = key.split(":", 2)[2] if key.count(":") >= 2 else ""
            if session_id:
                asyncio.create_task(update_conversation(session_id, {"agentRunning": False}))
        return stopped

    async def stop_session(self, session_key: str,
                           message: str = "Session stopped (conversation deleted)") -> bool:
        """Cancel the running agent task for a SINGLE session key.

        Used when its conversation is deleted so the backing agent loop halts
        instead of continuing headlessly (and re-seeding the attack-chain graph
        after the UI clears it), and when the person's access is revoked
        (close_sockets). Also cancels any in-flight tool tasks for the session and
        marks a connected socket stopped, telling it `message`. Returns True if a
        live task was cancelled.
        """
        cancelled = False
        task = self._active_tasks.get(session_key)
        if task and not task.done():
            task.cancel()
            cancelled = True
        self._active_tasks.pop(session_key, None)

        # Cancel any in-flight tool/wave tasks for this session (keys are
        # "<session_key>|...", see _tool_task_key).
        tools_cancelled = False
        for k, t in list(self._tool_tasks.items()):
            if k.startswith(f"{session_key}|") and t and not t.done():
                t.cancel()
                tools_cancelled = True
                self._tool_tasks.pop(k, None)

        # Cancelling only stops the agent waiting; the sandbox ends the run's
        # processes itself (GHSA-8whg-rvcr-r88r).
        if cancelled or tools_cancelled:
            schedule_sandbox_stop(session_key.split(":", 2)[-1])

        conn = self.active_connections.get(session_key)
        if conn:
            conn._is_stopped = True
            try:
                await conn.send_message(MessageType.STOPPED, {
                    "message": message,
                    "iteration": 0,
                    "phase": "informational",
                })
            except Exception:
                pass
        return cancelled


# =============================================================================
# PROXIED SOCKETS AND CLOSING BY USER (T16, DV-21)
# =============================================================================

#: Every socket kind a ticket can open (ws_ticket.WS_AUDIENCES); `agent` lives in
#: WebSocketManager, the other three in PROXIED_SOCKETS.
SOCKET_KINDS = ("agent", "kali-terminal", "cypherfix-triage", "cypherfix-codefix")
PROXIED_KINDS = SOCKET_KINDS[1:]

#: 4403: an application close code (4000-4999) the browser shows with its reason.
ACCESS_REVOKED_CODE = 4403
ACCESS_REVOKED_REASON = "Access revoked"


@dataclass
class ProxiedSocket:
    ws: Any
    kind: str
    sub: str
    act: Optional[str]
    pid: str
    sid: str
    opened_at: float = field(default_factory=time.time)
    # The run of the graph credential a terminal's shell was handed: it is honoured
    # only while this entry exists (holds_run).
    run: Optional[str] = None
    # The ticket's graph tenant (ws_ticket.ticket_tenant), whom that credential names.
    # Revocation matches `sub`, the person, never this: a collaborator's revoke must not
    # close the owner's sockets.
    ten: str = ""


class ProxiedSocketRegistry:
    """The open /ws/kali-terminal, /ws/cypherfix-triage and /ws/cypherfix-codefix
    sockets, with the verified ticket's identity. Each handler adds its socket
    after the ticket check and accept(), and removes it in its `finally`, so a
    revoke can find a socket whose ticket was valid when it opened.
    """

    def __init__(self):
        # By identity: two sockets of the same user, project and kind are two entries.
        self._entries: Dict[int, ProxiedSocket] = {}

    def add(self, ws, kind: str, claims: dict, run: Optional[str] = None) -> ProxiedSocket:
        if kind not in PROXIED_KINDS:
            raise ValueError(f"not a proxied socket kind: {kind!r}")
        from ws_ticket import ticket_tenant
        entry = ProxiedSocket(
            ws=ws, kind=kind, sub=str(claims["sub"]),
            act=str(claims["act"]) if claims.get("act") else None,
            pid=str(claims["pid"]), sid=str(claims["sid"]), run=run or None,
            ten=ticket_tenant(claims))
        self._entries[id(ws)] = entry
        return entry

    def holds_run(self, run: str, tenant: str, project_id: str) -> bool:
        """Whether an open terminal socket was handed the graph credential of `run`,
        for that tenant (the credential's `ten`) and project: a copy of the credential
        dies with the socket."""
        return bool(run) and any(
            e.kind == "kali-terminal" and e.run == run and e.ten == tenant and e.pid == project_id
            for e in list(self._entries.values()))

    def remove(self, ws) -> None:
        entry = self._entries.get(id(ws))
        if entry is not None and entry.ws is ws:
            del self._entries[id(ws)]

    def matching(self, *, kinds, user_id: Optional[str] = None,
                 project_id: Optional[str] = None, scope: str = "access",
                 actor_id: Optional[str] = None) -> List[ProxiedSocket]:
        _check_scope(scope, user_id=user_id, actor_id=actor_id)
        return [e for e in list(self._entries.values())
                if e.kind in kinds
                and _names(user_id, e.sub, e.act, scope=scope, project_id=project_id, actor_id=actor_id)
                and (project_id is None or e.pid == project_id)]

    def __len__(self) -> int:
        return len(self._entries)


PROXIED_SOCKETS = ProxiedSocketRegistry()


#: What ended for the user a close names (`scope` of close_sockets and POST /ws/close).
CLOSE_SCOPES = ("access", "account", "act_as")


def _check_scope(scope: str, *, user_id: Optional[str] = None, actor_id: Optional[str] = None) -> None:
    if scope not in CLOSE_SCOPES:
        raise ValueError(f"unknown close scope: {scope!r}")
    # One impersonation names both people; any other scope names no admin.
    if scope == "act_as" and not (user_id and actor_id):
        raise ValueError("the act_as scope needs user_id and actor_id")
    if scope != "act_as" and actor_id is not None:
        raise ValueError("actor_id belongs to the act_as scope")


def _names(user_id: Optional[str], sub: str, act: Optional[str], *,
           scope: str, project_id: Optional[str], actor_id: Optional[str] = None) -> bool:
    """Whether a socket or run opened as `sub` (by admin `act`, when acting) is `user_id`'s.

    See close_sockets for the rule.
    """
    if scope == "act_as":
        return sub == user_id and act == actor_id
    if user_id is None or user_id == (act or sub):
        return True
    return user_id == sub and (scope == "account" or project_id is not None)


async def close_sockets(manager: Optional[WebSocketManager], registry: ProxiedSocketRegistry, *,
                        kinds, user_id: Optional[str] = None,
                        project_id: Optional[str] = None, scope: str = "access",
                        actor_id: Optional[str] = None) -> dict:
    """Close the open sockets of `kinds` that match the user and/or the project.

    A ticket is checked once, at the handshake, so a revoke, a disabled account or
    a removed grant must end what is already open. Closing means, per kind:
    `agent` stops the session's run too (a run outlives its socket by design, so a
    headless run of the user is stopped as well); `cypherfix-codefix` cancels its
    run (its handler's `finally`); `cypherfix-triage` only detaches from the
    project's run, which keeps going; `kali-terminal` ends the proxy, which closes
    the sandbox's PTY. A socket that fails to close is still forgotten.

    Matching a `user_id`. An admin acting as a member opens sockets as the member
    (`sub`) with the admin as `act`; the ticket route checks the project for the
    member and the terminal grant on the admin. `scope` says what ended:
    - `access` (default), something the user's own access gave, such as a legacy
      grant: a socket matches the person whose access opened it, `act` when set,
      else `sub`. The member losing a grant leaves the admin's act-as socket open.
    - `account`, the account itself (disabled, deleted, sessions revoked): every
      socket naming the user, as `sub` or as `act`.
    - `act_as`, one impersonation ended (Stop, its time limit, sign-out, the admin
      losing the right): only what admin `actor_id` opened or started acting as
      `user_id`. The member's own sockets and runs, the admin's own, and other
      admins' impersonations of the member stay.
    With a `project_id`, the user's access to that project ended, which an act-as
    socket relied on, so it matches as `account` inside that project. An agent
    run matches by who started it (recorded at its start, so a run whose tab is
    closed is still found) and its socket by who holds it: stopping one never
    ends another person's.
    """
    _check_scope(scope, user_id=user_id, actor_id=actor_id)
    by_kind: Dict[str, int] = {}
    stopped_runs = 0

    def ours(sub: str, act: Optional[str]) -> bool:
        return _names(user_id, sub, act, scope=scope, project_id=project_id, actor_id=actor_id)

    if "agent" in kinds and manager is not None:
        keys = set(manager.active_connections) | set(manager._active_tasks)
        for key in sorted(keys):
            sub, _, rest = key.partition(":")
            pid, _, _sid = rest.partition(":")
            if project_id is not None and pid != project_id:
                continue
            if key in manager._active_tasks and ours(sub, manager.run_actor(key)):
                if await manager.stop_session(key, message="Session stopped (access revoked)"):
                    stopped_runs += 1
            conn = manager.active_connections.get(key)
            if conn is None or not ours(sub, conn.actor_id):
                continue
            try:
                await conn.websocket.close(code=ACCESS_REVOKED_CODE, reason=ACCESS_REVOKED_REASON)
            except Exception as e:
                logger.warning("[rbac] socket-close failed kind=agent: %s", type(e).__name__)
            await manager.disconnect(conn)
            # Any frame that still arrives before the disconnect is refused.
            conn.authenticated = False
            by_kind["agent"] = by_kind.get("agent", 0) + 1

    for entry in registry.matching(kinds=[k for k in kinds if k in PROXIED_KINDS],
                                   user_id=user_id, project_id=project_id, scope=scope,
                                   actor_id=actor_id):
        try:
            await entry.ws.close(code=ACCESS_REVOKED_CODE, reason=ACCESS_REVOKED_REASON)
        except Exception as e:
            logger.warning("[rbac] socket-close failed kind=%s: %s", entry.kind, type(e).__name__)
        registry.remove(entry.ws)
        by_kind[entry.kind] = by_kind.get(entry.kind, 0) + 1

    return {"closed": sum(by_kind.values()), "by_kind": by_kind, "stopped_runs": stopped_runs}


# =============================================================================
# STREAMING CALLBACK INTERFACE
# =============================================================================

_PENDING_REQUEST_FRAMES = {
    "approval": MessageType.APPROVAL_REQUEST,
    "question": MessageType.QUESTION_REQUEST,
    "tool_confirmation": MessageType.TOOL_CONFIRMATION_REQUEST,
}


class StreamingCallback:
    """Callback interface for streaming events from orchestrator.

    Also persists messages to the webapp database via chat_persistence.
    Uses dynamic connection resolution so reconnecting users see live updates.

    Persistence uses an ordered asyncio.Queue so messages are saved
    sequentially in the exact order they were emitted — preventing the
    race condition where concurrent HTTP POSTs arrive out-of-order and
    get wrong sequenceNum values.
    """

    def __init__(self, connection: WebSocketConnection, ws_manager: Optional['WebSocketManager'] = None):
        self._original_connection = connection
        self._session_key = connection.get_key()
        self._ws_manager = ws_manager
        self._session_id = connection.session_id
        self._project_id = connection.project_id
        self._user_id = connection.user_id
        # Response and task_complete are truly once-per-session events
        self._task_complete_sent = False
        self._response_sent = False
        # Accumulate tool output per tool_name so tool_complete includes raw output
        self._tool_context: dict = {}  # tool_name -> {"args": dict, "chunks": list[str]}
        # Deduplication tracking for streaming events — survives checkpoint reloads
        # unlike state-dict markers which are lost on astream resume
        self._emitted_approval_key: str | None = None
        self._emitted_question_key: str | None = None
        self._emitted_tool_confirmation_key: str | None = None
        self._emitted_thinking_ids: set = set()
        self._emitted_tool_start_ids: set = set()
        self._emitted_tool_complete_ids: set = set()
        self._emitted_tool_output_ids: set = set()
        self._emitted_tool_finished_ids: set = set()
        # Ordered persistence queue — messages are saved one-at-a-time in FIFO order
        self._persist_queue: asyncio.Queue = asyncio.Queue()
        self._persist_worker_task: Optional[asyncio.Task] = None
        self._persist_failure_reported = False

    def _ensure_persist_worker(self):
        """Lazily start the background persist worker."""
        if self._persist_worker_task is None or self._persist_worker_task.done():
            self._persist_worker_task = asyncio.create_task(self._persist_worker())

    async def _persist_worker(self):
        """Process persist messages sequentially to guarantee ordering."""
        while True:
            item = await self._persist_queue.get()
            # Support both legacy 2-tuple and extended 4-tuple entries.
            if len(item) == 2:
                msg_type, data = item
                agent_id_key = None
                fireteam_id_key = None
            else:
                msg_type, data, agent_id_key, fireteam_id_key = item
            try:
                failure = await save_chat_message(
                    session_id=self._session_id,
                    msg_type=msg_type,
                    data=data,
                    project_id=self._project_id,
                    user_id=self._user_id,
                    agent_id_key=agent_id_key,
                    fireteam_id_key=fireteam_id_key,
                )
            except Exception as e:
                logger.warning(f"Persist worker error: {e}")
                failure = {"error_class": type(e).__name__}
            try:
                if isinstance(failure, dict) and not self._persist_failure_reported:
                    self._persist_failure_reported = True
                    await self._report_persist_failure(failure)
            finally:
                self._persist_queue.task_done()

    async def _report_persist_failure(self, failure: dict):
        """Say once per run that the chat is not being saved. The live stream is
        still complete; a reload would show a timeline with holes in it."""
        try:
            await self.connection.send_message(MessageType.ERROR, {
                "message": "The chat is not being saved: messages from this run "
                           "may be missing after a reload",
                "code": "persist_failed",
                "recoverable": True,
                **failure,
            })
        except Exception:
            logger.debug("persist_failed notice not sent", exc_info=True)

    async def drain_persist_queue(self):
        """Wait for all pending persist messages to be saved, then stop the worker."""
        if self._persist_queue.qsize() > 0:
            await self._persist_queue.join()
        if self._persist_worker_task and not self._persist_worker_task.done():
            self._persist_worker_task.cancel()

    async def flush_persist_queue(self, timeout: float = 3.0) -> bool:
        """Block until the currently-queued persist messages are written to the DB,
        WITHOUT stopping the worker (unlike drain_persist_queue). Called on a new
        connection so the client's restore read sees an up-to-date timeline instead
        of a snapshot lagging behind the live stream.

        Bounded by `timeout` so a fast-emitting agent (queue never reaches zero)
        can't block CONNECTED indefinitely; returns True if fully flushed, False
        on timeout (partial flush — the client's post-connect resync still closes
        any remaining gap).
        """
        if self._persist_queue.qsize() == 0:
            return True
        self._ensure_persist_worker()
        try:
            await asyncio.wait_for(self._persist_queue.join(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            logger.warning(
                f"flush_persist_queue timed out after {timeout}s for session "
                f"{self._session_id} ({self._persist_queue.qsize()} still queued)")
            return False

    @property
    def connection(self) -> WebSocketConnection:
        """Always resolve to the current connection (may have been replaced by reconnect)."""
        if self._ws_manager and self._session_key:
            conn = self._ws_manager.active_connections.get(self._session_key)
            if conn:
                return conn
        return self._original_connection

    def _loop_note(self, state: str, **detail) -> None:
        """Tell the Agent in the Loop broker what the run is doing (no-op for
        a provider-model run, whose scope does not use the loop)."""
        try:
            get_broker().note(self._session_key, state, **detail)
        except Exception:
            logger.debug("loop status note failed", exc_info=True)

    async def on_loop_status(self, payload: dict):
        """Agent in the Loop status for the drawer. Sent only: a status is live
        state, and it carries no prompt or answer text."""
        await self.connection.send_message(MessageType.LOOP_STATUS, payload)

    async def on_rate_limit_wait(self, seconds: int, retry: int, purpose: str = "other"):
        """The run waits `seconds` for the provider's rate limit before retry
        number `retry` of a `purpose` model call (think, report, ...). Sent only."""
        await self.connection.send_message(
            MessageType.RATE_LIMIT_WAIT, {"seconds": seconds, "retry": retry, "purpose": purpose})

    def _persist(self, msg_type: str, data: dict,
                 *, member_id_key: Optional[str] = None,
                 fireteam_id_key: Optional[str] = None):
        """Enqueue message for ordered persistence to DB.

        member_id_key and fireteam_id_key attribute the row to a fireteam
        member. Root agent messages leave both None.
        """
        self._ensure_persist_worker()
        if member_id_key or fireteam_id_key:
            self._persist_queue.put_nowait((msg_type, data, member_id_key, fireteam_id_key))
        else:
            self._persist_queue.put_nowait((msg_type, data))

    async def on_thinking(self, iteration: int, phase: str, thought: str, reasoning: str,
                          action: Optional[str] = None,
                          input_tokens: int = 0,
                          output_tokens: int = 0,
                          productivity_score: Optional[float] = None,
                          productivity_tier: Optional[str] = None,
                          stall: Optional[int] = None):
        """Called when agent starts thinking.

        `action` is the decision's action (e.g. "use_tool", "deploy_fireteam").
        It's persisted so session restore can suppress redundant thinking
        cards — notably `deploy_fireteam` thinks whose rationale already
        lives on the FireteamCard.

        `input_tokens` / `output_tokens` are the per-turn LLM usage deltas
        (from provider usage_metadata). The UI renders them as "in X · out Y"
        and sums them across every thinking event for the cumulative counter.
        """
        payload = {
            "iteration": iteration,
            "phase": phase,
            "thought": thought,
            "reasoning": reasoning,
            "action": action,
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            # Live agent-status KPIs (rendered on the Todos bar). Optional so
            # older callers / restores without them still work.
            "productivity_score": productivity_score,
            "productivity_tier": productivity_tier,
            "stall": stall,
        }
        answered_by = get_broker().take_answered_by(self._session_key)
        if answered_by:
            # Which MCP token supplied this decision (display prefix and name only).
            payload["answeredBy"] = answered_by
        await self.connection.send_message(MessageType.THINKING, payload)
        self._persist("thinking", payload)

    async def on_thinking_chunk(self, chunk: str):
        """Called during LLM generation for streaming thoughts"""
        await self.connection.send_message(MessageType.THINKING_CHUNK, {
            "chunk": chunk
        })
        # Don't persist chunks — they are partial data; the full thinking is persisted via on_thinking

    async def on_tool_start(self, tool_name: str, tool_args: dict, wave_id: str = None, step_index: int = None,
                            step_id: Optional[str] = None):
        """Called when tool execution starts.

        `step_id` is the ExecutionStep's stable uuid4 (state.py). It is the SAME
        value on this tool's later tool_complete, so the frontend restore layer
        can pair start<->complete by identity instead of by content fingerprint
        (tool_name+args), which used to drop legitimately-repeated tool calls.
        """
        payload = {
            "tool_name": tool_name,
            "tool_args": tool_args
        }
        if wave_id:
            payload["wave_id"] = wave_id
        if step_index is not None:
            payload["step_index"] = step_index
        if step_id:
            payload["step_id"] = step_id
        await self.connection.send_message(MessageType.TOOL_START, payload)
        self._persist("tool_start", payload)
        if not wave_id:
            self._loop_note("running_tool", tool=tool_name)
        # Initialize accumulator for this tool's output chunks
        # Use step_index in key to disambiguate same-name tools in a wave
        ctx_key = f"{wave_id}:{step_index}:{tool_name}" if wave_id and step_index is not None else (f"{wave_id}:{tool_name}" if wave_id else tool_name)
        self._tool_context[ctx_key] = {"args": tool_args, "chunks": []}

    async def on_tool_output_chunk(self, tool_name: str, chunk: str, is_final: bool = False, wave_id: str = None, step_index: int = None,
                                   step_id: Optional[str] = None):
        """Called when tool outputs data chunk"""
        payload = {
            "tool_name": tool_name,
            "chunk": chunk,
            "is_final": is_final
        }
        if wave_id:
            payload["wave_id"] = wave_id
        if step_index is not None:
            payload["step_index"] = step_index
        if step_id:
            payload["step_id"] = step_id
        await self.connection.send_message(MessageType.TOOL_OUTPUT_CHUNK, payload)
        # Accumulate chunks — they'll be joined and included in tool_complete
        ctx_key = f"{wave_id}:{step_index}:{tool_name}" if wave_id and step_index is not None else (f"{wave_id}:{tool_name}" if wave_id else tool_name)
        if ctx_key in self._tool_context:
            self._tool_context[ctx_key]["chunks"].append(chunk)

    async def on_tool_finished(
        self,
        tool_name: str,
        success: bool,
        duration_ms: Optional[int] = None,
        step_id: Optional[str] = None,
    ):
        """Called when a standalone tool call has returned, before its analysis.

        Lets the UI stop the card's stopwatch at the tool's real duration and
        show that the agent is analysing, instead of a "Running" card that
        keeps counting through the whole next LLM turn. Persisted so a restore
        mid-analysis shows the same thing.
        """
        payload = {"tool_name": tool_name, "success": success}
        if duration_ms is not None:
            payload["duration_ms"] = duration_ms
        if step_id:
            payload["step_id"] = step_id
        await self.connection.send_message(MessageType.TOOL_FINISHED, payload)
        self._persist("tool_finished", payload)

    async def on_tool_complete(
        self,
        tool_name: str,
        success: bool,
        output_summary: str,
        actionable_findings: list = None,
        recommended_next_steps: list = None,
        wave_id: str = None,
        step_index: int = None,
        duration_ms: Optional[int] = None,
        step_id: Optional[str] = None,
    ):
        """Called when tool execution completes.

        `step_id` matches the value emitted on this tool's tool_start, letting
        session restore pair the two by identity (see on_tool_start).
        """
        payload = {
            "tool_name": tool_name,
            "success": success,
            "output_summary": output_summary,
            "actionable_findings": actionable_findings or [],
            "recommended_next_steps": recommended_next_steps or [],
        }
        if wave_id:
            payload["wave_id"] = wave_id
        if step_index is not None:
            payload["step_index"] = step_index
        if duration_ms is not None:
            payload["duration_ms"] = duration_ms
        if step_id:
            payload["step_id"] = step_id
        await self.connection.send_message(MessageType.TOOL_COMPLETE, payload)
        if not wave_id:
            self._loop_note("thinking")
        # Include accumulated raw output and tool_args in persisted payload
        ctx_key = f"{wave_id}:{step_index}:{tool_name}" if wave_id and step_index is not None else (f"{wave_id}:{tool_name}" if wave_id else tool_name)
        ctx = self._tool_context.pop(ctx_key, {})
        persist_payload = {
            **payload,
            "tool_args": ctx.get("args", {}),
            "raw_output": "".join(ctx.get("chunks", [])),
        }
        self._persist("tool_complete", persist_payload)

    async def on_plan_start(self, wave_id: str, plan_rationale: str, tools: list):
        """Called when a tool plan wave starts executing."""
        payload = {
            "wave_id": wave_id,
            "plan_rationale": plan_rationale,
            "tool_count": len(tools),
            "tools": tools,
        }
        await self.connection.send_message(MessageType.PLAN_START, payload)
        self._persist("plan_start", payload)
        self._loop_note("running_tool", tool="plan_tools")

    async def on_plan_complete(self, wave_id: str, total: int, successful: int, failed: int):
        """Called when a tool plan wave finishes executing."""
        payload = {
            "wave_id": wave_id,
            "total_steps": total,
            "successful": successful,
            "failed": failed,
        }
        await self.connection.send_message(MessageType.PLAN_COMPLETE, payload)
        self._persist("plan_complete", payload)
        self._loop_note("thinking")

    # ---------- Fireteam events ----------

    async def on_fireteam_deployed(self, fireteam_id: str, iteration: int,
                                   plan_rationale: str, members: list):
        payload = {
            "fireteam_id": fireteam_id,
            "iteration": iteration,
            "plan_rationale": plan_rationale,
            "member_count": len(members),
            "members": members,
        }
        await self.connection.send_message(MessageType.FIRETEAM_DEPLOYED, payload)
        self._persist("fireteam_deployed", payload, fireteam_id_key=fireteam_id)

    async def on_fireteam_member_started(self, fireteam_id: str, member_id: str, name: str):
        payload = {"fireteam_id": fireteam_id, "member_id": member_id, "name": name}
        await self.connection.send_message(MessageType.FIRETEAM_MEMBER_STARTED, payload)
        self._persist("fireteam_member_started", payload,
                      fireteam_id_key=fireteam_id, member_id_key=member_id)

    async def on_fireteam_thinking(self, fireteam_id: str, member_id: str, name: str,
                                   iteration: int, phase: str, thought: str, reasoning: str,
                                   input_tokens: int = 0,
                                   output_tokens: int = 0):
        payload = {
            "fireteam_id": fireteam_id,
            "member_id": member_id,
            "name": name,
            "iteration": iteration,
            "phase": phase,
            "thought": thought,
            "reasoning": reasoning,
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
        }
        await self.connection.send_message(MessageType.FIRETEAM_THINKING, payload)
        self._persist("fireteam_thinking", payload,
                      fireteam_id_key=fireteam_id, member_id_key=member_id)

    async def on_fireteam_tool_start(self, fireteam_id: str, member_id: str,
                                     tool_name: str, tool_args: dict,
                                     wave_id: Optional[str] = None, step_index: Optional[int] = None):
        payload = {
            "fireteam_id": fireteam_id,
            "member_id": member_id,
            "tool_name": tool_name,
            "tool_args": tool_args,
            "wave_id": wave_id,
            "step_index": step_index,
        }
        await self.connection.send_message(MessageType.FIRETEAM_TOOL_START, payload)
        self._persist("fireteam_tool_start", payload,
                      fireteam_id_key=fireteam_id, member_id_key=member_id)

    async def on_fireteam_tool_output_chunk(self, fireteam_id: str, member_id: str,
                                            tool_name: str, chunk: str,
                                            is_final: bool = False,
                                            wave_id: Optional[str] = None,
                                            step_index: Optional[int] = None):
        payload = {
            "fireteam_id": fireteam_id,
            "member_id": member_id,
            "tool_name": tool_name,
            "chunk": chunk,
            "is_final": is_final,
            "wave_id": wave_id,
            "step_index": step_index,
        }
        await self.connection.send_message(MessageType.FIRETEAM_TOOL_OUTPUT_CHUNK, payload)
        self._persist("fireteam_tool_output_chunk", payload,
                      fireteam_id_key=fireteam_id, member_id_key=member_id)

    async def on_fireteam_tool_complete(self, fireteam_id: str, member_id: str,
                                        tool_name: str, success: bool, duration_ms: int,
                                        output_excerpt: str = "",
                                        wave_id: Optional[str] = None,
                                        step_index: Optional[int] = None):
        # wave_id/step_index let the frontend disambiguate which container
        # (standalone member.tools[] vs nested plan wave) this complete event
        # belongs to. Without them, two tools with the same name (e.g. an
        # iter-1 standalone playwright and an iter-2 plan-wave playwright)
        # collide in the reducer's findLast(name+running) match.
        payload = {
            "fireteam_id": fireteam_id,
            "member_id": member_id,
            "tool_name": tool_name,
            "success": success,
            "duration_ms": duration_ms,
            "output_excerpt": output_excerpt[:500],
            "wave_id": wave_id,
            "step_index": step_index,
        }
        await self.connection.send_message(MessageType.FIRETEAM_TOOL_COMPLETE, payload)
        self._persist("fireteam_tool_complete", payload,
                      fireteam_id_key=fireteam_id, member_id_key=member_id)

    async def on_fireteam_plan_start(self, fireteam_id: str, member_id: str,
                                     wave_id: str, plan_rationale: str, tools: list):
        payload = {
            "fireteam_id": fireteam_id,
            "member_id": member_id,
            "wave_id": wave_id,
            "plan_rationale": plan_rationale,
            "tools": tools,
        }
        await self.connection.send_message(MessageType.FIRETEAM_PLAN_START, payload)
        self._persist("fireteam_plan_start", payload,
                      fireteam_id_key=fireteam_id, member_id_key=member_id)

    async def on_fireteam_plan_complete(self, fireteam_id: str, member_id: str,
                                        wave_id: str, total: int, successful: int, failed: int):
        payload = {
            "fireteam_id": fireteam_id,
            "member_id": member_id,
            "wave_id": wave_id,
            "total_steps": total,
            "successful": successful,
            "failed": failed,
        }
        await self.connection.send_message(MessageType.FIRETEAM_PLAN_COMPLETE, payload)
        self._persist("fireteam_plan_complete", payload,
                      fireteam_id_key=fireteam_id, member_id_key=member_id)

    async def on_fireteam_member_completed(self, fireteam_id: str, member_id: str, name: str,
                                           status: str, iterations_used: int, tokens_used: int,
                                           findings_count: int, wall_clock_seconds: float,
                                           error_message: Optional[str] = None,
                                           input_tokens_used: int = 0,
                                           output_tokens_used: int = 0):
        payload = {
            "fireteam_id": fireteam_id,
            "member_id": member_id,
            "name": name,
            "status": status,
            "iterations_used": iterations_used,
            "tokens_used": tokens_used,
            "input_tokens_used": int(input_tokens_used or 0),
            "output_tokens_used": int(output_tokens_used or 0),
            "findings_count": findings_count,
            "wall_clock_seconds": wall_clock_seconds,
            "error_message": error_message,
        }
        await self.connection.send_message(MessageType.FIRETEAM_MEMBER_COMPLETED, payload)
        self._persist("fireteam_member_completed", payload,
                      fireteam_id_key=fireteam_id, member_id_key=member_id)

    async def on_fireteam_completed(self, fireteam_id: str, total: int,
                                    status_counts: dict, wall_clock_seconds: float):
        payload = {
            "fireteam_id": fireteam_id,
            "total": total,
            "status_counts": status_counts,
            "wall_clock_seconds": wall_clock_seconds,
        }
        await self.connection.send_message(MessageType.FIRETEAM_COMPLETED, payload)
        self._persist("fireteam_completed", payload, fireteam_id_key=fireteam_id)

    async def on_fireteam_member_awaiting_confirmation(self, info: dict):
        """A single fireteam member is paused awaiting operator approval.

        ``info`` = {wave_id, member_id, member_name, confirmation_id, mode,
                    tools: [{tool_name, tool_args}], reasoning, iteration}.
        Other members in the same wave continue running; operator resolves
        each independently via MessageType.FIRETEAM_MEMBER_CONFIRMATION.
        """
        wave_id = info.get("wave_id") or ""
        member_id = info.get("member_id") or ""
        payload = {
            "fireteam_id": wave_id,
            "wave_id": wave_id,
            "member_id": member_id,
            "member_name": info.get("member_name"),
            "confirmation_id": info.get("confirmation_id"),
            "mode": info.get("mode") or "single",
            "tools": info.get("tools") or [],
            "reasoning": info.get("reasoning") or "",
            "iteration": info.get("iteration"),
        }
        await self.connection.send_message(
            MessageType.FIRETEAM_MEMBER_AWAITING_CONFIRMATION, payload,
        )
        self._persist(
            "fireteam_member_awaiting_confirmation", payload,
            fireteam_id_key=wave_id, member_id_key=member_id,
        )
        self._loop_note("awaiting_human", kind="tool_confirmation")

    async def on_plan_analysis(self, wave_id: str, interpretation: str,
                               actionable_findings: list, recommended_next_steps: list):
        """Called when think_node finishes analyzing a wave's outputs."""
        payload = {
            "wave_id": wave_id,
            "interpretation": interpretation,
            "actionable_findings": actionable_findings or [],
            "recommended_next_steps": recommended_next_steps or [],
        }
        await self.connection.send_message(MessageType.PLAN_ANALYSIS, payload)
        self._persist("plan_analysis", payload)

    async def on_deep_think(self, trigger_reason: str, analysis: str, iteration: int, phase: str):
        """Called when Deep Think produces a strategic analysis."""
        payload = {
            "trigger_reason": trigger_reason,
            "analysis": analysis,
            "iteration": iteration,
            "phase": phase,
        }
        await self.connection.send_message(MessageType.DEEP_THINK, payload)
        self._persist("deep_think", payload)
        logger.info(f"Deep Think analysis sent to session {self.connection.session_id}")

    async def on_lats_start(self, search_id: str, objective: str, phase: str,
                            budget: dict, shadow_mode: bool):
        """Called when a LATS exploit-path search activates (a new tree seeded)."""
        payload = {
            "search_id": search_id,
            "objective": objective,
            "phase": phase,
            "budget": budget,
            "shadow_mode": shadow_mode,
        }
        await self.connection.send_message(MessageType.LATS_START, payload)
        self._persist("lats_start", payload)
        logger.info(f"LATS search {search_id} started for session {self.connection.session_id}")

    async def on_lats_tree_update(self, search_id: str, snapshot: dict):
        """Called once per hook invocation (= once per wave) with the full tree
        snapshot. The tree is <= LATS_MAX_TREE_NODES nodes, so no diffing."""
        payload = {"search_id": search_id, "snapshot": snapshot}
        await self.connection.send_message(MessageType.LATS_TREE_UPDATE, payload)
        self._persist("lats_tree_update", payload)

    async def on_lats_complete(self, search_id: str, best_trajectory: list,
                               outcome: str, metrics: Optional[dict] = None):
        """Called when a LATS search ends (terminal_success | budget_exhausted |
        branch_collapsed). metrics carries the A/B telemetry (§20.13)."""
        payload = {
            "search_id": search_id,
            "best_trajectory": best_trajectory,
            "outcome": outcome,
            "metrics": metrics or {},
        }
        await self.connection.send_message(MessageType.LATS_COMPLETE, payload)
        self._persist("lats_complete", payload)
        logger.info(f"LATS search {search_id} complete ({outcome}) for session {self.connection.session_id}")

    async def on_phase_update(self, current_phase: str, iteration_count: int, attack_path_type: str = "",
                              skill_workflow: Optional[dict] = None):
        """Called when phase changes.

        skill_workflow is what the last think turn rendered, or None when it rendered
        none: {skillId, revision, changeSetId} for a built-in playbook (revision 1 and
        changeSetId None = factory text), or {skillId: "user_skill:<id>", kind: "user",
        contentSha256} for a user skill's text (first 16 hex of the SHA-256 of its UTF-8
        content; no revision key). skillId names the skill actually rendered, which for a
        user skill can be the version that supersedes the label's. A skill label alone
        does not prove its playbook was in the prompt.
        """
        payload = {
            "current_phase": current_phase,
            "iteration_count": iteration_count,
            "attack_path_type": attack_path_type,
            "skill_workflow": skill_workflow,
        }
        await self.connection.send_message(MessageType.PHASE_UPDATE, payload)
        # Persist phase update as message + update conversation metadata
        self._persist("phase_update", payload)
        asyncio.create_task(update_conversation(
            self._session_id,
            {"currentPhase": current_phase, "iterationCount": iteration_count},
        ))

    async def on_todo_update(self, todo_list: list):
        """Called when todo list is updated"""
        await self.connection.send_message(MessageType.TODO_UPDATE, {
            "todo_list": todo_list
        })
        self._persist("todo_update", {"todo_list": todo_list})

    async def on_approval_request(self, approval_request: dict):
        """Called when agent requests phase transition approval"""
        # Deduplication is handled by emit_streaming_events via callback._emitted_approval_key
        await self.connection.send_message(MessageType.APPROVAL_REQUEST, approval_request)
        self._persist("approval_request", approval_request)
        self._loop_note("awaiting_human", kind="approval")
        logger.info(f"Approval request sent to session {self.connection.session_id}")

    async def on_question_request(self, question_request: dict):
        """Called when agent asks user a question"""
        # Deduplication is handled by emit_streaming_events via callback._emitted_question_key
        await self.connection.send_message(MessageType.QUESTION_REQUEST, question_request)
        self._persist("question_request", question_request)
        self._loop_note("awaiting_human", kind="question")
        logger.info(f"Question request sent to session {self.connection.session_id}")

    async def on_tool_confirmation_request(self, confirmation_request: dict):
        """Called when agent requests tool confirmation before executing dangerous tools"""
        # Deduplication is handled by emit_streaming_events via callback._emitted_tool_confirmation_key
        await self.connection.send_message(MessageType.TOOL_CONFIRMATION_REQUEST, confirmation_request)
        self._persist("tool_confirmation_request", confirmation_request)
        self._loop_note("awaiting_human", kind="tool_confirmation")
        logger.info(f"Tool confirmation request sent to session {self.connection.session_id}")

    async def resend_pending_request(self, kind: str, request: dict):
        """Show a request again after the person's answer to it was refused. Sent
        only: the stored timeline still ends on this request, unanswered."""
        await self.connection.send_message(_PENDING_REQUEST_FRAMES[kind], request)

    async def on_response(self, answer: str, iteration_count: int, phase: str, task_complete: bool, response_tier: str = "full_report"):
        """Called when agent provides final response"""
        if not self._response_sent:
            payload = {
                "answer": answer,
                "iteration_count": iteration_count,
                "phase": phase,
                "task_complete": task_complete,
                "response_tier": response_tier,
            }
            await self.connection.send_message(MessageType.RESPONSE, payload)
            self._response_sent = True
            self._persist("assistant_message", {"content": answer, "phase": phase, "task_complete": task_complete, "response_tier": response_tier})
            logger.info(f"Response sent to session {self.connection.session_id} (tier: {response_tier})")
        else:
            logger.debug(f"Duplicate response blocked for session {self.connection.session_id}")

    async def on_execution_step(self, step: dict):
        """Called after each execution step"""
        await self.connection.send_message(MessageType.EXECUTION_STEP, step)

    async def on_error(self, error_message: str, recoverable: bool = True,
                       code: str = "", **details):
        """Called when error occurs. `code` and `details` (an exception class, a
        provider HTTP status, a model id) say why; never an exception's text."""
        payload = {"message": error_message, "recoverable": recoverable}
        if code:
            payload["code"] = code
        payload.update(details)
        await self.connection.send_message(MessageType.ERROR, payload)
        self._persist("error", payload)
        if not recoverable:
            self._loop_note("error")

    async def on_task_complete(self, message: str, final_phase: str, total_iterations: int):
        """Called when task is complete"""
        if not self._task_complete_sent:
            payload = {
                "message": message,
                "final_phase": final_phase,
                "total_iterations": total_iterations
            }
            await self.connection.send_message(MessageType.TASK_COMPLETE, payload)
            self._task_complete_sent = True
            self._persist("task_complete", payload)
            self._loop_note("finished")
            logger.info(f"Task complete sent to session {self.connection.session_id}")
        else:
            logger.debug(f"Duplicate task_complete blocked for session {self.connection.session_id}")

    async def on_file_ready(self, file_info: dict):
        """Called when agent has created a downloadable file."""
        await self.connection.send_message(MessageType.FILE_READY, file_info)
        self._persist("file_ready", file_info)
        logger.info(f"File ready notification sent: {file_info.get('filename')}")

    # ------------------------------------------------------------------
    # Per-tool task registry helpers
    # ------------------------------------------------------------------
    # The execute_tool_node / execute_plan_node wrappers call these to
    # register their inner asyncio.Task so the frontend's per-tool stop
    # button can cancel just that one tool via handle_tool_stop.
    def register_tool_task(self, tool_name: str, wave_id: Optional[str],
                           step_index: Optional[int], task: asyncio.Task):
        if self._ws_manager and self._session_key:
            self._ws_manager.register_tool_task(
                self._session_key, tool_name, wave_id, step_index, task,
            )

    def unregister_tool_task(self, tool_name: str, wave_id: Optional[str],
                             step_index: Optional[int]):
        if self._ws_manager and self._session_key:
            self._ws_manager.unregister_tool_task(
                self._session_key, tool_name, wave_id, step_index,
            )


# =============================================================================
# MESSAGE HANDLERS
# =============================================================================

class WebSocketHandler:
    """Handles WebSocket messages and routes to orchestrator"""

    def __init__(self, orchestrator, ws_manager: WebSocketManager):
        self.orchestrator = orchestrator
        self.ws_manager = ws_manager

    async def _refused_without(self, connection: WebSocketConnection, *permissions: str,
                               answer: str, **request) -> bool:
        """Refuse a decision the connection's person may not take (step 3.9b).

        Checked before anything runs or is saved, so the agent's prompt stays open for
        someone who holds the permission. The frame names the refused `answer` (and the
        Fireteam wave and member in `request`), so the drawer puts back the card it hid for
        it. True when refused (the frame is sent).
        """
        missing = next((p for p in permissions if not connection.holds(p)), None)
        if missing is None:
            return False
        logger.warning("[rbac] decision refused permission=%s session=%s", missing, connection.session_id)
        await connection.send_message(MessageType.ERROR, {
            "message": f"You do not hold the permission this answer needs ({missing}). "
                       "The agent keeps waiting for someone who does.",
            "code": "permission_required",
            "permission": missing,
            "answer": answer,
            **request,
            "recoverable": True,
        })
        return True

    async def _refused_now(self, connection: WebSocketConnection, *permissions: str,
                           answer: str, mode: Optional[str] = None, **request) -> bool:
        """Refuse a decision the person may no longer take, asked of the webapp now (step 5.4).

        The ticket's `cap` is from when the socket opened: the account, the share, a toggle or a
        permission may have gone since the prompt was shown. So after the cap, and before
        anything runs or is saved, the webapp decides the decision's kind (`answer`) again for the
        ticket's person (`sub`, with `act` under act-as), never for anyone a frame names. Fail
        closed: an unreachable webapp is a refusal (`decision_check_unavailable`). A refusal for
        a permission keeps the `permission_required` frame of `_refused_without`, so the drawer
        puts the card back. `mode` is the decision's mode the webapp maps (decision_check
        DECISION_MODES). True when refused (the frame is sent).
        """
        check = await authorize_decision(
            kind=answer, user_id=connection.user_id, project_id=connection.project_id,
            session_id=connection.session_id, actor_id=connection.actor_id, permissions=permissions,
            **({"mode": mode} if mode else {}))
        if check.allowed:
            return False
        if check.code == DECISION_CHECK_UNAVAILABLE:
            await connection.send_message(MessageType.ERROR, {
                "message": "Your answer was not applied: RedAmon could not check that you may still "
                           "take this decision. Try again in a moment.",
                "code": DECISION_CHECK_UNAVAILABLE,
                "answer": answer,
                **request,
                "recoverable": True,
            })
            return True
        permission = check.permission or permissions[0]
        logger.warning("[rbac] decision refused at decision time permission=%s reason=%s session=%s",
                       permission, check.reason, connection.session_id)
        await connection.send_message(MessageType.ERROR, {
            "message": f"You no longer hold the permission this answer needs ({permission}) on this project. "
                       "The agent keeps waiting for someone who does.",
            "code": "permission_required",
            "permission": permission,
            "reason": check.reason,
            "answer": answer,
            **request,
            "recoverable": True,
        })
        return True

    def _record_decision(self, connection: WebSocketConnection, callback: 'StreamingCallback',
                         kind: str, row: str, data: dict):
        """An admitted answer: saved with who gave it, and posted for the audit row.

        `connection` is the socket the answer came on, not the run's current one (a
        reconnect moves the run), so the record names the person who answered.
        """
        callback._persist(row, {**data, "actor": connection.decision_actor()})
        asyncio.create_task(post_agent_decision(
            kind=kind, session_id=connection.session_id, project_id=connection.project_id,
            user_id=connection.user_id, actor_id=connection.actor_id, decision=data["decision"]))

    async def handle_init(self, connection: WebSocketConnection, payload: dict):
        """Handle session initialization"""
        try:
            init_msg = InitMessage(**payload)

            # STRIDE S6/S2: verify the webapp-minted ticket and bind the session
            # to the cryptographically attested identity. A missing/invalid/
            # expired ticket is rejected outright. When the ticket secret is UNSET
            # we now FAIL CLOSED (STRIDE S2): reject the connection instead of
            # trusting the self-asserted identity. redamon.sh ensure_auth_secrets
            # always generates AGENT_WS_TICKET_SECRET, so real installs are
            # unaffected; only a token-less dev stack is refused (by design).
            from ws_ticket import ticket_cap, ticket_secret, ticket_tenancy_refusal, ticket_tenant, verify_ws_ticket

            secret = ticket_secret()
            user_id = init_msg.user_id
            project_id = init_msg.project_id
            session_id = init_msg.session_id
            verified = False

            # The reasons are fixed text, safe to show; the drawer tells a
            # missing secret from a rejected ticket by the code.
            async def _reject_ticket(reason: str, code: str):
                logger.warning("Rejected /ws/agent init: %s", reason)
                await connection.send_message(MessageType.ERROR, {
                    "message": f"WebSocket authentication failed: {reason}",
                    "code": code,
                    "recoverable": False,
                })
                try:
                    await connection.websocket.close(code=1008, reason=reason)
                except Exception:
                    pass

            if not secret:
                # Fail closed: no secret configured means we cannot attest identity.
                await _reject_ticket("ticket auth not configured", "ws_ticket_not_configured")
                return

            claims = verify_ws_ticket(init_msg.ticket, secret, expected_aud="agent")
            if claims is None:
                await _reject_ticket("Invalid or missing ticket", "ws_ticket_invalid")
                return
            # A ticket minted before an ownership transfer names the old owner: never opened after it.
            tenancy = await asyncio.to_thread(ticket_tenancy_refusal, claims)
            if tenancy:
                await _reject_ticket(tenancy, "ws_ticket_tenant")
                return
            # Identity comes from the verified ticket, not the client body.
            user_id = str(claims["sub"])
            project_id = str(claims["pid"])
            session_id = str(claims["sid"])
            verified = True
            connection.tenant_id = ticket_tenant(claims)
            connection.actor_id = str(claims["act"]) if claims.get("act") else None
            connection.cap = ticket_cap(claims)

            # Authenticate connection
            await self.ws_manager.authenticate(
                connection,
                user_id,
                project_id,
                session_id,
                verified=verified,
            )

            # authenticate() rejects (and closes the socket) when the memory
            # governor's session cap is hit, or when an unverified peer tries to
            # take over an active session (S6), leaving authenticated False.
            # Don't proceed to send CONNECTED on a closed/unauthenticated socket.
            if not connection.authenticated:
                return

            # Store graph view scope (if provided)
            connection.graph_view_cypher = init_msg.graph_view_cypher

            # Flush-on-connect: if this session has a live run, force its persist
            # queue to the DB before we confirm the connection. The client's
            # restore reads the conversation over HTTP right around now; without
            # this the read races ahead of the async persist queue and returns a
            # stale/empty timeline (the "empty chat that fills in over seconds"
            # bug when reopening a running session from history). Bounded so a
            # busy agent can't stall the handshake.
            try:
                live_cb = self.ws_manager.get_callback(connection.get_key())
                if live_cb is not None:
                    await live_cb.flush_persist_queue()
            except Exception as e:
                logger.warning(f"flush-on-connect failed for {session_id}: {e}")

            # Send connected confirmation with protocol version + feature
            # advertising. Protocol v2 adds the FIRETEAM_* event family;
            # older clients ignore unknown fields so this is backwards-compat.
            _features = ["plan_tools", "tool_confirmation"]
            try:
                from project_settings import get_setting
                if get_setting("FIRETEAM_ENABLED", False):
                    _features.append("fireteam")
            except Exception:
                pass
            # agent_running is the authoritative live answer to "is this
            # session's run still going?". The client cannot know on its own:
            # events emitted while its socket was down (tool_complete, STOPPED,
            # task_complete) are lost, and its DB flag lags. On every
            # (re)connect it uses this to clear or keep its spinner.
            connected = {
                "session_id": session_id,
                "message": "WebSocket connection established",
                "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                "protocol_version": 2,
                "features": _features,
                "agent_running": self.ws_manager.get_task(connection.get_key()) is not None,
            }
            # A reconnecting browser gets the Agent in the Loop status at once.
            loop_state = get_broker().status_payload(connection.get_key())
            if loop_state is not None:
                connected["loop_state"] = loop_state
            await connection.send_message(MessageType.CONNECTED, connected)

            logger.info(f"Session initialized: {session_id}")

        except ValidationError as e:
            logger.error(f"Invalid init message: {e}")
            await connection.send_message(
                MessageType.ERROR, _invalid_frame("Invalid initialization message", e, False))

    async def _finish_run(self, connection: WebSocketConnection, callback: 'StreamingCallback'):
        """Release a finished run: task registration first, then persistence.

        The registration is dropped BEFORE the persist queue drains, so a client
        that reconnects during the drain is told agent_running=false; its final
        events (response, task_complete, stopped) were already sent. Registry
        entries are released only while they still belong to this run, so a
        query started meanwhile keeps its own.
        """
        key = connection.get_key()
        this_task = asyncio.current_task()
        self.ws_manager.release_task(key, this_task)
        # Drain the persist queue so all messages are saved before marking agent as done
        await callback.drain_persist_queue()
        if connection._active_task is this_task:
            connection._active_task = None
        self.ws_manager.release_callback(key, callback)
        if self.ws_manager.get_task(key) is None:
            asyncio.create_task(update_conversation(connection.session_id, {"agentRunning": False}))

    async def handle_query(self, connection: WebSocketConnection, payload: dict):
        """Handle user query — launches orchestrator as background task"""
        try:
            query_msg = QueryMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated. Send init message first.",
                    "code": "not_authenticated",
                    "recoverable": False
                })
                return

            # Create streaming callback with ws_manager for dynamic connection resolution
            callback = StreamingCallback(connection, self.ws_manager)
            connection._is_stopped = False
            # Drain stale guidance from previous runs
            connection.drain_guidance()

            logger.info(f"Processing query for session {connection.session_id}: {query_msg.question[:50]}...")

            # Mark agent as running in DB
            asyncio.create_task(update_conversation(connection.session_id, {"agentRunning": True}))

            # Persist the user message via the callback's ordered queue so it
            # gets a sequenceNum *before* any thinking/tool messages
            callback._persist("user_message", {"content": query_msg.question})

            # Run orchestrator as background task so receive loop stays free
            task = asyncio.create_task(
                self._run_orchestrator_query(connection, query_msg.question, callback)
            )
            connection._active_task = task
            self.ws_manager.register_task(connection.get_key(), task, actor_id=connection.actor_id)
            self.ws_manager.register_callback(connection.get_key(), callback)

        except ValidationError as e:
            logger.error(f"Invalid query message: {e}")
            await connection.send_message(
                MessageType.ERROR, _invalid_frame("Invalid query format", e, True))

    async def _run_orchestrator_query(self, connection: WebSocketConnection, question: str, callback):
        """Background coroutine that runs the orchestrator invocation."""
        bind_run_actor(connection.run_actor())
        try:
            result = await self.orchestrator.invoke_with_streaming(
                question=question,
                user_id=connection.user_id,
                project_id=connection.project_id,
                session_id=connection.session_id,
                streaming_callback=callback,
                guidance_queue=connection.guidance_queue,
                graph_view_cypher=connection.graph_view_cypher,
                tenant_user_id=connection.tenant_id,
            )
            logger.info(f"Query completed for session {connection.session_id}")
        except asyncio.CancelledError:
            logger.info(f"Query task cancelled for session {connection.session_id}")
        except Exception as e:
            logger.error(f"Error processing query: {e}")
            try:
                await callback.connection.send_message(MessageType.ERROR, {
                    "message": "Error processing query",
                    "code": "query_failed",
                    **_error_details(e),
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            await self._finish_run(connection, callback)

    async def handle_approval(self, connection: WebSocketConnection, payload: dict):
        """Handle approval response — launches as background task"""
        try:
            approval_msg = ApprovalMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated",
                    "code": "not_authenticated",
                    "recoverable": False
                })
                return
            if await self._refused_without(connection, "agent:approve_phase", answer="approval"):
                return
            if await self._refused_now(connection, "agent:approve_phase", answer="approval"):
                return

            callback = StreamingCallback(connection, self.ws_manager)
            connection._is_stopped = False

            logger.info(f"Processing approval for session {connection.session_id}: {approval_msg.decision}")

            asyncio.create_task(update_conversation(connection.session_id, {"agentRunning": True}))

            task = asyncio.create_task(
                self._run_orchestrator_approval(connection, approval_msg, callback)
            )
            connection._active_task = task
            self.ws_manager.register_task(connection.get_key(), task, actor_id=connection.actor_id)
            self.ws_manager.register_callback(connection.get_key(), callback)

        except ValidationError as e:
            logger.error(f"Invalid approval message: {e}")
            await connection.send_message(
                MessageType.ERROR, _invalid_frame("Invalid approval format", e, True))

    async def _run_orchestrator_approval(self, connection: WebSocketConnection, approval_msg: ApprovalMessage, callback):
        """Background coroutine that runs approval resumption."""
        bind_run_actor(connection.run_actor())
        try:
            result = await self.orchestrator.resume_after_approval_with_streaming(
                session_id=connection.session_id,
                user_id=connection.user_id,
                tenant_user_id=connection.tenant_id,
                project_id=connection.project_id,
                decision=approval_msg.decision,
                modification=approval_msg.modification,
                streaming_callback=callback,
                guidance_queue=connection.guidance_queue,
                # Saved (it survives a reload) only once the run is admitted: a
                # refused resume leaves the request unanswered, and shows it again.
                on_admitted=lambda: self._record_decision(
                    connection, callback, "approval", "approval_response", {
                        "decision": approval_msg.decision,
                        "modification": approval_msg.modification,
                    }),
            )
            logger.info(f"Approval processed for session {connection.session_id}")
        except asyncio.CancelledError:
            logger.info(f"Approval task cancelled for session {connection.session_id}")
        except Exception as e:
            logger.error(f"Error processing approval: {e}")
            try:
                await callback.connection.send_message(MessageType.ERROR, {
                    "message": "Error processing approval",
                    "code": "approval_failed",
                    **_error_details(e),
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            await self._finish_run(connection, callback)

    async def handle_answer(self, connection: WebSocketConnection, payload: dict):
        """Handle answer to agent question — launches as background task"""
        try:
            answer_msg = AnswerMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated",
                    "code": "not_authenticated",
                    "recoverable": False
                })
                return
            if await self._refused_now(connection, "agent:chat", answer="question"):
                return

            callback = StreamingCallback(connection, self.ws_manager)
            connection._is_stopped = False

            logger.info(f"Processing answer for session {connection.session_id}")

            asyncio.create_task(update_conversation(connection.session_id, {"agentRunning": True}))

            task = asyncio.create_task(
                self._run_orchestrator_answer(connection, answer_msg.answer, callback)
            )
            connection._active_task = task
            self.ws_manager.register_task(connection.get_key(), task, actor_id=connection.actor_id)
            self.ws_manager.register_callback(connection.get_key(), callback)

        except ValidationError as e:
            logger.error(f"Invalid answer message: {e}")
            await connection.send_message(
                MessageType.ERROR, _invalid_frame("Invalid answer format", e, True))

    async def _run_orchestrator_answer(self, connection: WebSocketConnection, answer: str, callback):
        """Background coroutine that runs answer resumption."""
        bind_run_actor(connection.run_actor())
        try:
            result = await self.orchestrator.resume_after_answer_with_streaming(
                session_id=connection.session_id,
                user_id=connection.user_id,
                tenant_user_id=connection.tenant_id,
                project_id=connection.project_id,
                answer=answer,
                streaming_callback=callback,
                guidance_queue=connection.guidance_queue,
                on_admitted=lambda: callback._persist("answer_response", {"answer": answer}),
            )
            logger.info(f"Answer processed for session {connection.session_id}")
        except asyncio.CancelledError:
            logger.info(f"Answer task cancelled for session {connection.session_id}")
        except Exception as e:
            logger.error(f"Error processing answer: {e}")
            try:
                await callback.connection.send_message(MessageType.ERROR, {
                    "message": "Error processing answer",
                    "code": "answer_failed",
                    **_error_details(e),
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            await self._finish_run(connection, callback)

    async def handle_fireteam_member_confirmation(self, connection: WebSocketConnection, payload: dict):
        """Operator decision for a per-member dangerous-tool escalation.

        Does NOT pause/resume the graph — parent+other members keep running.
        The decision is stored in the process-local confirmation registry,
        which wakes the single awaiting member task.
        """
        try:
            msg = FireteamMemberConfirmationMessage(**payload)
        except ValidationError as e:
            logger.error(f"Invalid fireteam_member_confirmation payload: {e}")
            await connection.send_message(
                MessageType.ERROR, _invalid_frame("Invalid fireteam member confirmation payload", e, True))
            return

        if not connection.authenticated:
            await connection.send_message(MessageType.ERROR, {
                "message": "Not authenticated",
                "code": "not_authenticated",
                "recoverable": False,
            })
            return
        if await self._refused_without(connection, "agent:fireteam", "agent:approve_dangerous",
                                       answer="fireteam_member_confirmation",
                                       wave_id=msg.wave_id, member_id=msg.member_id):
            return
        if await self._refused_now(connection, "agent:fireteam", "agent:approve_dangerous",
                                   answer="fireteam_member_confirmation",
                                   wave_id=msg.wave_id, member_id=msg.member_id):
            return

        from orchestrator_helpers.fireteam_confirmation_registry import applied_decision, resolve as _resolve
        ok = _resolve(
            session_id=connection.session_id,
            wave_id=msg.wave_id,
            member_id=msg.member_id,
            decision=msg.decision,
            modifications=msg.modifications,
        )
        logger.info(
            "fireteam_member_confirmation session=%s wave=%s member=%s decision=%s resolved=%s",
            connection.session_id, msg.wave_id, msg.member_id, msg.decision, ok,
        )
        # Persist so session replay can see the operator's decision.
        try:
            StreamingCallback(connection, self.ws_manager)._persist(
                "fireteam_member_confirmation_response",
                {
                    "wave_id": msg.wave_id,
                    "member_id": msg.member_id,
                    "decision": msg.decision,
                    "resolved": ok,
                    "actor": connection.decision_actor(),
                },
                fireteam_id_key=msg.wave_id,
                member_id_key=msg.member_id,
            )
        except Exception:
            logger.exception("fireteam_member_confirmation: persist failed")
        # Only an answer that reached a waiting member decided anything, and the audit row
        # names what the member was given, never the raw word.
        if ok:
            asyncio.create_task(post_agent_decision(
                kind="fireteam_member_confirmation", session_id=connection.session_id,
                project_id=connection.project_id, user_id=connection.user_id,
                actor_id=connection.actor_id, decision=applied_decision(msg.decision),
                wave_id=msg.wave_id, member_id=msg.member_id))

    async def handle_tool_confirmation(self, connection: WebSocketConnection, payload: dict):
        """Handle tool confirmation response — launches as background task"""
        try:
            confirmation_msg = ToolConfirmationMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated",
                    "code": "not_authenticated",
                    "recoverable": False
                })
                return
            needs, mode = await self._tool_confirmation_needs(connection)
            if await self._refused_without(connection, *needs, answer="tool_confirmation"):
                return
            if await self._refused_now(connection, *needs, answer="tool_confirmation", mode=mode):
                return

            callback = StreamingCallback(connection, self.ws_manager)
            connection._is_stopped = False

            logger.info(f"Processing tool confirmation for session {connection.session_id}: {confirmation_msg.decision}")

            asyncio.create_task(update_conversation(connection.session_id, {"agentRunning": True}))

            task = asyncio.create_task(
                self._run_orchestrator_tool_confirmation(connection, confirmation_msg, callback)
            )
            connection._active_task = task
            self.ws_manager.register_task(connection.get_key(), task, actor_id=connection.actor_id)
            self.ws_manager.register_callback(connection.get_key(), callback)

        except ValidationError as e:
            logger.error(f"Invalid tool confirmation message: {e}")
            await connection.send_message(
                MessageType.ERROR, _invalid_frame("Invalid tool confirmation format", e, True))

    async def _tool_confirmation_needs(self, connection: WebSocketConnection) -> tuple:
        """The permissions a tool confirmation needs, and the mode to send with it.

        Answering a Fireteam member's escalation redeploys that member (fireteam_redeploy), so it
        needs `agent:fireteam` as well, as the member's own confirmation does. The mode is read
        from the run's state, never from the frame; a state that cannot be read asks for both.
        """
        try:
            mode = await self.orchestrator.pending_tool_confirmation_mode(
                user_id=connection.user_id, project_id=connection.project_id,
                session_id=connection.session_id)
        except Exception as e:
            logger.warning("[rbac] tool confirmation mode unreadable, asking for both permissions "
                           "error=%s session=%s", type(e).__name__, connection.session_id)
            mode = "fireteam_escalation"
        if mode == "fireteam_escalation":
            return ("agent:approve_dangerous", "agent:fireteam"), mode
        return ("agent:approve_dangerous",), None

    async def _run_orchestrator_tool_confirmation(self, connection: WebSocketConnection, confirmation_msg: ToolConfirmationMessage, callback):
        """Background coroutine that runs tool confirmation resumption."""
        bind_run_actor(connection.run_actor())
        try:
            result = await self.orchestrator.resume_after_tool_confirmation_with_streaming(
                session_id=connection.session_id,
                user_id=connection.user_id,
                tenant_user_id=connection.tenant_id,
                project_id=connection.project_id,
                decision=confirmation_msg.decision,
                modifications=confirmation_msg.modifications,
                streaming_callback=callback,
                guidance_queue=connection.guidance_queue,
                on_admitted=lambda: self._record_decision(
                    connection, callback, "tool_confirmation", "tool_confirmation_response", {
                        "decision": confirmation_msg.decision,
                        "modifications": confirmation_msg.modifications,
                    }),
            )
            logger.info(f"Tool confirmation processed for session {connection.session_id}")
        except asyncio.CancelledError:
            logger.info(f"Tool confirmation task cancelled for session {connection.session_id}")
        except Exception as e:
            logger.error(f"Error processing tool confirmation: {e}")
            try:
                await callback.connection.send_message(MessageType.ERROR, {
                    "message": "Error processing tool confirmation",
                    "code": "tool_confirmation_failed",
                    **_error_details(e),
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            await self._finish_run(connection, callback)

    async def handle_guidance(self, connection: WebSocketConnection, payload: dict):
        """Handle guidance message while agent is executing."""
        try:
            guidance_msg = GuidanceMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated",
                    "code": "not_authenticated",
                    "recoverable": False
                })
                return

            await connection.guidance_queue.put(guidance_msg.message)
            queue_size = connection.guidance_queue.qsize()

            await connection.send_message(MessageType.GUIDANCE_ACK, {
                "message": guidance_msg.message,
                "queue_position": queue_size,
            })

            logger.info(f"Guidance queued for session {connection.session_id}: {guidance_msg.message[:100]}...")

        except ValidationError as e:
            logger.error(f"Invalid guidance message: {e}")
            await connection.send_message(
                MessageType.ERROR, _invalid_frame("Invalid guidance format", e, True))

    async def handle_skill_inject(self, connection: WebSocketConnection, payload: dict):
        """Handle skill injection -- push skill content as a guidance message."""
        try:
            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated",
                    "code": "not_authenticated",
                    "recoverable": False
                })
                return

            skill_id = payload.get('skill_id', '')
            skill_name = payload.get('skill_name', 'Unknown Skill')
            content = payload.get('content', '')

            if not content:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Skill content is empty",
                    "recoverable": True
                })
                return

            # Format as guidance message with skill context
            guidance_text = f"[CHAT SKILL: {skill_name}]\n\n{content}"
            await connection.guidance_queue.put(guidance_text)
            queue_size = connection.guidance_queue.qsize()

            await connection.send_message(MessageType.SKILL_INJECT_ACK, {
                "skill_id": skill_id,
                "skill_name": skill_name,
                "queue_position": queue_size,
            })

            logger.info(f"Skill '{skill_name}' injected for session {connection.session_id}")

        except Exception as e:
            logger.error(f"Skill inject failed: {e}")
            await connection.send_message(MessageType.ERROR, {
                "message": "Failed to inject skill",
                "code": "skill_inject_failed",
                **_error_details(e),
                "recoverable": True
            })

    async def handle_stop(self, connection: WebSocketConnection, payload: dict):
        """Handle stop request — cancels active agent execution.

        Looks up the task from both the connection AND the central task registry,
        so it works even if a WebSocket reconnection replaced the connection object.
        """
        if not connection.authenticated:
            await connection.send_message(MessageType.ERROR, {
                "message": "Not authenticated",
                "code": "not_authenticated",
                "recoverable": False
            })
            return

        session_key = connection.get_key()

        # Find the task: prefer connection-local, fall back to central registry
        task = connection._active_task if (connection._active_task and not connection._active_task.done()) else None
        if not task:
            task = self.ws_manager.get_task(session_key)

        if task and not task.done():
            task.cancel()
            connection._is_stopped = True
            self.ws_manager.clear_task(session_key)
            schedule_sandbox_stop(connection.session_id)

            # Get current state for the STOPPED message
            try:
                config = create_config(connection.user_id, connection.project_id, connection.session_id,
                                       connection.tenant_id)
                current_state = await self.orchestrator.graph.aget_state(config)
                iteration = current_state.values.get("current_iteration", 0) if current_state and current_state.values else 0
                phase = current_state.values.get("current_phase", "informational") if current_state and current_state.values else "informational"
            except Exception:
                iteration = 0
                phase = "informational"

            await connection.send_message(MessageType.STOPPED, {
                "message": "Agent execution stopped",
                "iteration": iteration,
                "phase": phase,
            })
            logger.info(f"Execution stopped for session {connection.session_id}")
        else:
            # No active task anywhere — confirm stopped state (e.g. restored
            # conversation where agentRunning was stale in DB).
            connection._is_stopped = True
            await connection.send_message(MessageType.STOPPED, {
                "message": "Agent execution stopped",
                "iteration": 0,
                "phase": "informational",
            })
            asyncio.create_task(update_conversation(connection.session_id, {"agentRunning": False}))

    async def handle_tool_stop(self, connection: WebSocketConnection, payload: dict):
        """Cancel a single running tool — the agent flow continues with the next tool.

        Looks up the tool task in the per-tool registry keyed by
        (session_key, wave_id, step_index, tool_name). When cancelled, the
        wrapper in execute_tool_node / execute_plan_node catches the
        CancelledError and marks the tool as failed, so the agent's normal
        success/failure branches take over from there (no global stop).
        """
        if not connection.authenticated:
            await connection.send_message(MessageType.ERROR, {
                "message": "Not authenticated",
                "code": "not_authenticated",
                "recoverable": False,
            })
            return
        try:
            msg = ToolStopMessage(**payload)
        except ValidationError as e:
            logger.error(f"Invalid tool_stop message: {e}")
            await connection.send_message(
                MessageType.ERROR, _invalid_frame("Invalid tool_stop payload", e, True))
            return

        session_key = connection.get_key()
        cancelled = self.ws_manager.cancel_tool_task(
            session_key, msg.tool_name, msg.wave_id, msg.step_index,
        )
        logger.info(
            f"[{connection.session_id}] tool_stop requested for {msg.tool_name} "
            f"(wave={msg.wave_id}, step={msg.step_index}) — cancelled={cancelled}"
        )
        if not cancelled:
            # Best-effort: tool may have already completed between click and
            # receive. Swallow silently — the tool's own tool_complete event
            # will reach the UI and reconcile state. Don't error: treating
            # this as recoverable noise keeps the UX calm.
            logger.debug(
                f"No running tool task found for {msg.tool_name} in {session_key}"
            )

    async def handle_resume(self, connection: WebSocketConnection, payload: dict):
        """Handle resume request — restarts agent from last checkpoint."""
        if not connection.authenticated:
            await connection.send_message(MessageType.ERROR, {
                "message": "Not authenticated",
                "code": "not_authenticated",
                "recoverable": False
            })
            return

        if not connection._is_stopped:
            await connection.send_message(MessageType.ERROR, {
                "message": "No stopped execution to resume",
                "recoverable": True,
            })
            return

        connection._is_stopped = False
        callback = StreamingCallback(connection, self.ws_manager)

        asyncio.create_task(update_conversation(connection.session_id, {"agentRunning": True}))

        task = asyncio.create_task(
            self._run_orchestrator_resume(connection, callback)
        )
        connection._active_task = task
        self.ws_manager.register_task(connection.get_key(), task, actor_id=connection.actor_id)
        self.ws_manager.register_callback(connection.get_key(), callback)
        logger.info(f"Resuming execution for session {connection.session_id}")

    async def _run_orchestrator_resume(self, connection: WebSocketConnection, callback):
        """Background coroutine that resumes orchestrator from checkpoint."""
        bind_run_actor(connection.run_actor())
        try:
            result = await self.orchestrator.resume_execution_with_streaming(
                user_id=connection.user_id,
                tenant_user_id=connection.tenant_id,
                project_id=connection.project_id,
                session_id=connection.session_id,
                streaming_callback=callback,
                guidance_queue=connection.guidance_queue,
            )
            logger.info(f"Resumed execution completed for session {connection.session_id}")
        except asyncio.CancelledError:
            logger.info(f"Resumed task cancelled for session {connection.session_id}")
        except Exception as e:
            logger.error(f"Error resuming execution: {e}")
            try:
                await callback.connection.send_message(MessageType.ERROR, {
                    "message": "Error resuming execution",
                    "code": "resume_failed",
                    **_error_details(e),
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            await self._finish_run(connection, callback)

    async def handle_ping(self, connection: WebSocketConnection, payload: dict):
        """Handle ping for keep-alive"""
        connection.last_ping = datetime.now(timezone.utc).replace(tzinfo=None)
        await connection.send_message(MessageType.PONG, {})
        logger.debug(f"Pong sent to session {connection.session_id}")

    async def handle_message(self, connection: WebSocketConnection, raw_message: str):
        """Route incoming message to appropriate handler"""
        try:
            message = json.loads(raw_message)
            msg_type = message.get("type")
            payload = message.get("payload", {})

            if msg_type == MessageType.INIT:
                await self.handle_init(connection, payload)
            elif msg_type == MessageType.QUERY:
                await self.handle_query(connection, payload)
            elif msg_type == MessageType.APPROVAL:
                await self.handle_approval(connection, payload)
            elif msg_type == MessageType.ANSWER:
                await self.handle_answer(connection, payload)
            elif msg_type == MessageType.TOOL_CONFIRMATION:
                await self.handle_tool_confirmation(connection, payload)
            elif msg_type == MessageType.FIRETEAM_MEMBER_CONFIRMATION:
                await self.handle_fireteam_member_confirmation(connection, payload)
            elif msg_type == MessageType.PING:
                await self.handle_ping(connection, payload)
            elif msg_type == MessageType.GUIDANCE:
                await self.handle_guidance(connection, payload)
            elif msg_type == MessageType.SKILL_INJECT:
                await self.handle_skill_inject(connection, payload)
            elif msg_type == MessageType.STOP:
                await self.handle_stop(connection, payload)
            elif msg_type == MessageType.TOOL_STOP:
                await self.handle_tool_stop(connection, payload)
            elif msg_type == MessageType.RESUME:
                await self.handle_resume(connection, payload)
            else:
                logger.warning(f"Unknown message type: {msg_type}")
                await connection.send_message(MessageType.ERROR, {
                    "message": f"Unknown message type: {msg_type}",
                    "recoverable": True
                })

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON message: {e}")
            await connection.send_message(MessageType.ERROR, {
                "message": "Invalid JSON format",
                "recoverable": True
            })
        except Exception as e:
            logger.error(f"Error handling message: {e}")
            await connection.send_message(MessageType.ERROR, {
                "message": "Internal error",
                "code": "internal_error",
                **_error_details(e),
                "recoverable": True
            })


# =============================================================================
# WEBSOCKET ENDPOINT
# =============================================================================

async def websocket_endpoint(
    websocket: WebSocket,
    orchestrator,
    ws_manager: WebSocketManager
):
    """
    Main WebSocket endpoint for agent communication.

    Handles connection lifecycle, message routing, and error handling.
    """
    connection = await ws_manager.connect(websocket)
    handler = WebSocketHandler(orchestrator, ws_manager)

    try:
        while True:
            # Receive message from client
            message_data = await websocket.receive()

            # Check for disconnect event
            if message_data.get("type") == "websocket.disconnect":
                logger.info(f"WebSocket disconnect received: {connection.get_key() or 'unauthenticated'}")
                break

            # Handle different message types
            if "text" in message_data:
                raw_message = message_data["text"]
            elif "bytes" in message_data:
                # Convert bytes to string if sent as binary
                raw_message = message_data["bytes"].decode("utf-8")
            else:
                logger.warning(f"Received unexpected message type: {message_data}")
                continue

            # Handle message
            await handler.handle_message(connection, raw_message)

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {connection.get_key() or 'unauthenticated'}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await connection.send_message(MessageType.ERROR, {
                "message": "Fatal error",
                "code": "fatal_error",
                **_error_details(e),
                "recoverable": False
            })
        except:
            pass
    finally:
        # Don't cancel active tasks — let background agents keep running
        # and persisting messages to DB even when the user disconnects.
        # Tasks will clean up via their own finally blocks.
        if not (connection._active_task and not connection._active_task.done()):
            # Only disconnect if no task is running
            await ws_manager.disconnect(connection)
        else:
            logger.info(f"WebSocket closed but agent task still running for {connection.get_key()}")
