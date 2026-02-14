"""
WebSocket API for RedAmon Agent

Provides WebSocket endpoint for real-time bidirectional communication with the agent.
Supports streaming of LLM thoughts, tool executions, and interactive approval/question flows.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Optional, Any, Callable
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ValidationError
from orchestrator_helpers import create_config


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
    PING = "ping"
    GUIDANCE = "guidance"
    STOP = "stop"
    RESUME = "resume"

    # Server → Client
    CONNECTED = "connected"
    THINKING = "thinking"
    THINKING_CHUNK = "thinking_chunk"
    TOOL_START = "tool_start"
    TOOL_OUTPUT_CHUNK = "tool_output_chunk"
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
    STOPPED = "stopped"


# =============================================================================
# CLIENT MESSAGE MODELS
# =============================================================================

class InitMessage(BaseModel):
    """Initialize WebSocket session"""
    user_id: str
    project_id: str
    session_id: str


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


class GuidanceMessage(BaseModel):
    """Send guidance to steer agent while it's working"""
    message: str


# =============================================================================
# WEBSOCKET CONNECTION MANAGER
# =============================================================================

class WebSocketConnection:
    """Manages individual WebSocket connection state"""

    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.user_id: Optional[str] = None
        self.project_id: Optional[str] = None
        self.session_id: Optional[str] = None
        self.authenticated = False
        self.connected_at = datetime.utcnow()
        self.last_ping = datetime.utcnow()
        self.guidance_queue: asyncio.Queue = asyncio.Queue()
        self._active_task: Optional[Any] = None
        self._is_stopped: bool = False

    async def send_message(self, message_type: MessageType, payload: Any):
        """Send JSON message to client"""
        try:
            # Serialize payload to handle datetime objects
            serialized_payload = serialize_for_json(payload)
            message = {
                "type": message_type.value,
                "payload": serialized_payload,
                "timestamp": datetime.utcnow().isoformat()
            }
            await self.websocket.send_json(message)
            logger.debug(f"Sent {message_type.value} message to {self.session_id}")
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise

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


class WebSocketManager:
    """Manages active WebSocket connections"""

    def __init__(self):
        # Map of session_key → WebSocketConnection
        self.active_connections: Dict[str, WebSocketConnection] = {}
        self.lock = asyncio.Lock()

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
        session_id: str
    ):
        """Authenticate and register connection"""
        async with self.lock:
            connection.user_id = user_id
            connection.project_id = project_id
            connection.session_id = session_id
            connection.authenticated = True

            session_key = connection.get_key()

            # Close existing connection for this session if any
            if session_key in self.active_connections:
                old_conn = self.active_connections[session_key]
                try:
                    await old_conn.websocket.close(code=1000, reason="New connection established")
                except Exception as e:
                    logger.warning(f"Error closing old connection: {e}")

            self.active_connections[session_key] = connection
            logger.info(f"Authenticated session: {session_key}")

    async def disconnect(self, connection: WebSocketConnection):
        """Remove connection from active connections"""
        async with self.lock:
            session_key = connection.get_key()
            if session_key and session_key in self.active_connections:
                del self.active_connections[session_key]
                logger.info(f"Disconnected session: {session_key}")

    def get_connection(self, user_id: str, project_id: str, session_id: str) -> Optional[WebSocketConnection]:
        """Get active connection by session identifiers"""
        session_key = f"{user_id}:{project_id}:{session_id}"
        return self.active_connections.get(session_key)

    def get_connection_count(self) -> int:
        """Get number of active connections"""
        return len(self.active_connections)


# =============================================================================
# STREAMING CALLBACK INTERFACE
# =============================================================================

class StreamingCallback:
    """Callback interface for streaming events from orchestrator"""

    def __init__(self, connection: WebSocketConnection):
        self.connection = connection
        # Response and task_complete are truly once-per-session events
        self._task_complete_sent = False
        self._response_sent = False

    async def on_thinking(self, iteration: int, phase: str, thought: str, reasoning: str):
        """Called when agent starts thinking"""
        await self.connection.send_message(MessageType.THINKING, {
            "iteration": iteration,
            "phase": phase,
            "thought": thought,
            "reasoning": reasoning
        })

    async def on_thinking_chunk(self, chunk: str):
        """Called during LLM generation for streaming thoughts"""
        await self.connection.send_message(MessageType.THINKING_CHUNK, {
            "chunk": chunk
        })

    async def on_tool_start(self, tool_name: str, tool_args: dict):
        """Called when tool execution starts"""
        await self.connection.send_message(MessageType.TOOL_START, {
            "tool_name": tool_name,
            "tool_args": tool_args
        })

    async def on_tool_output_chunk(self, tool_name: str, chunk: str, is_final: bool = False):
        """Called when tool outputs data chunk"""
        await self.connection.send_message(MessageType.TOOL_OUTPUT_CHUNK, {
            "tool_name": tool_name,
            "chunk": chunk,
            "is_final": is_final
        })

    async def on_tool_complete(
        self,
        tool_name: str,
        success: bool,
        output_summary: str,
        actionable_findings: list = None,
        recommended_next_steps: list = None,
    ):
        """Called when tool execution completes"""
        await self.connection.send_message(MessageType.TOOL_COMPLETE, {
            "tool_name": tool_name,
            "success": success,
            "output_summary": output_summary,
            "actionable_findings": actionable_findings or [],
            "recommended_next_steps": recommended_next_steps or [],
        })

    async def on_phase_update(self, current_phase: str, iteration_count: int, attack_path_type: str = "cve_exploit"):
        """Called when phase changes"""
        await self.connection.send_message(MessageType.PHASE_UPDATE, {
            "current_phase": current_phase,
            "iteration_count": iteration_count,
            "attack_path_type": attack_path_type
        })

    async def on_todo_update(self, todo_list: list):
        """Called when todo list is updated"""
        await self.connection.send_message(MessageType.TODO_UPDATE, {
            "todo_list": todo_list
        })

    async def on_approval_request(self, approval_request: dict):
        """Called when agent requests phase transition approval"""
        # Deduplication is handled by orchestrator using _emitted_approval marker in state
        await self.connection.send_message(MessageType.APPROVAL_REQUEST, approval_request)
        logger.info(f"Approval request sent to session {self.connection.session_id}")

    async def on_question_request(self, question_request: dict):
        """Called when agent asks user a question"""
        # Deduplication is handled by orchestrator using _emitted_question marker in state
        await self.connection.send_message(MessageType.QUESTION_REQUEST, question_request)
        logger.info(f"Question request sent to session {self.connection.session_id}")

    async def on_response(self, answer: str, iteration_count: int, phase: str, task_complete: bool):
        """Called when agent provides final response"""
        if not self._response_sent:
            await self.connection.send_message(MessageType.RESPONSE, {
                "answer": answer,
                "iteration_count": iteration_count,
                "phase": phase,
                "task_complete": task_complete
            })
            self._response_sent = True
            logger.info(f"Response sent to session {self.connection.session_id}")
        else:
            logger.debug(f"Duplicate response blocked for session {self.connection.session_id}")

    async def on_execution_step(self, step: dict):
        """Called after each execution step"""
        await self.connection.send_message(MessageType.EXECUTION_STEP, step)

    async def on_error(self, error_message: str, recoverable: bool = True):
        """Called when error occurs"""
        await self.connection.send_message(MessageType.ERROR, {
            "message": error_message,
            "recoverable": recoverable
        })

    async def on_task_complete(self, message: str, final_phase: str, total_iterations: int):
        """Called when task is complete"""
        if not self._task_complete_sent:
            await self.connection.send_message(MessageType.TASK_COMPLETE, {
                "message": message,
                "final_phase": final_phase,
                "total_iterations": total_iterations
            })
            self._task_complete_sent = True
            logger.info(f"Task complete sent to session {self.connection.session_id}")
        else:
            logger.debug(f"Duplicate task_complete blocked for session {self.connection.session_id}")


# =============================================================================
# MESSAGE HANDLERS
# =============================================================================

class WebSocketHandler:
    """Handles WebSocket messages and routes to orchestrator"""

    def __init__(self, orchestrator, ws_manager: WebSocketManager):
        self.orchestrator = orchestrator
        self.ws_manager = ws_manager

    async def handle_init(self, connection: WebSocketConnection, payload: dict):
        """Handle session initialization"""
        try:
            init_msg = InitMessage(**payload)

            # Authenticate connection
            await self.ws_manager.authenticate(
                connection,
                init_msg.user_id,
                init_msg.project_id,
                init_msg.session_id
            )

            # Send connected confirmation
            await connection.send_message(MessageType.CONNECTED, {
                "session_id": init_msg.session_id,
                "message": "WebSocket connection established",
                "timestamp": datetime.utcnow().isoformat()
            })

            # Pre-warm Metasploit: restart msfconsole in background so it's
            # ready by the time the agent needs it (hides 60-120s startup)
            session_key = f"{init_msg.user_id}:{init_msg.project_id}:{init_msg.session_id}"
            self.orchestrator.start_msf_prewarm(session_key)

            logger.info(f"Session initialized: {init_msg.session_id}")

        except ValidationError as e:
            logger.error(f"Invalid init message: {e}")
            await connection.send_message(MessageType.ERROR, {
                "message": "Invalid initialization message",
                "recoverable": False
            })

    async def handle_query(self, connection: WebSocketConnection, payload: dict):
        """Handle user query — launches orchestrator as background task"""
        try:
            query_msg = QueryMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated. Send init message first.",
                    "recoverable": False
                })
                return

            # Create streaming callback
            callback = StreamingCallback(connection)
            connection._is_stopped = False
            # Drain stale guidance from previous runs
            connection.drain_guidance()

            logger.info(f"Processing query for session {connection.session_id}: {query_msg.question[:50]}...")

            # Run orchestrator as background task so receive loop stays free
            task = asyncio.create_task(
                self._run_orchestrator_query(connection, query_msg.question, callback)
            )
            connection._active_task = task

        except ValidationError as e:
            logger.error(f"Invalid query message: {e}")
            await connection.send_message(MessageType.ERROR, {
                "message": "Invalid query format",
                "recoverable": True
            })

    async def _run_orchestrator_query(self, connection: WebSocketConnection, question: str, callback):
        """Background coroutine that runs the orchestrator invocation."""
        try:
            result = await self.orchestrator.invoke_with_streaming(
                question=question,
                user_id=connection.user_id,
                project_id=connection.project_id,
                session_id=connection.session_id,
                streaming_callback=callback,
                guidance_queue=connection.guidance_queue,
            )
            logger.info(f"Query completed for session {connection.session_id}")
        except asyncio.CancelledError:
            logger.info(f"Query task cancelled for session {connection.session_id}")
        except Exception as e:
            logger.error(f"Error processing query: {e}")
            try:
                await connection.send_message(MessageType.ERROR, {
                    "message": f"Error processing query: {str(e)}",
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            connection._active_task = None

    async def handle_approval(self, connection: WebSocketConnection, payload: dict):
        """Handle approval response — launches as background task"""
        try:
            approval_msg = ApprovalMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated",
                    "recoverable": False
                })
                return

            callback = StreamingCallback(connection)
            connection._is_stopped = False

            logger.info(f"Processing approval for session {connection.session_id}: {approval_msg.decision}")

            task = asyncio.create_task(
                self._run_orchestrator_approval(connection, approval_msg, callback)
            )
            connection._active_task = task

        except ValidationError as e:
            logger.error(f"Invalid approval message: {e}")
            await connection.send_message(MessageType.ERROR, {
                "message": "Invalid approval format",
                "recoverable": True
            })

    async def _run_orchestrator_approval(self, connection: WebSocketConnection, approval_msg: ApprovalMessage, callback):
        """Background coroutine that runs approval resumption."""
        try:
            result = await self.orchestrator.resume_after_approval_with_streaming(
                session_id=connection.session_id,
                user_id=connection.user_id,
                project_id=connection.project_id,
                decision=approval_msg.decision,
                modification=approval_msg.modification,
                streaming_callback=callback,
                guidance_queue=connection.guidance_queue,
            )
            logger.info(f"Approval processed for session {connection.session_id}")
        except asyncio.CancelledError:
            logger.info(f"Approval task cancelled for session {connection.session_id}")
        except Exception as e:
            logger.error(f"Error processing approval: {e}")
            try:
                await connection.send_message(MessageType.ERROR, {
                    "message": f"Error processing approval: {str(e)}",
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            connection._active_task = None

    async def handle_answer(self, connection: WebSocketConnection, payload: dict):
        """Handle answer to agent question — launches as background task"""
        try:
            answer_msg = AnswerMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated",
                    "recoverable": False
                })
                return

            callback = StreamingCallback(connection)
            connection._is_stopped = False

            logger.info(f"Processing answer for session {connection.session_id}")

            task = asyncio.create_task(
                self._run_orchestrator_answer(connection, answer_msg.answer, callback)
            )
            connection._active_task = task

        except ValidationError as e:
            logger.error(f"Invalid answer message: {e}")
            await connection.send_message(MessageType.ERROR, {
                "message": "Invalid answer format",
                "recoverable": True
            })

    async def _run_orchestrator_answer(self, connection: WebSocketConnection, answer: str, callback):
        """Background coroutine that runs answer resumption."""
        try:
            result = await self.orchestrator.resume_after_answer_with_streaming(
                session_id=connection.session_id,
                user_id=connection.user_id,
                project_id=connection.project_id,
                answer=answer,
                streaming_callback=callback,
                guidance_queue=connection.guidance_queue,
            )
            logger.info(f"Answer processed for session {connection.session_id}")
        except asyncio.CancelledError:
            logger.info(f"Answer task cancelled for session {connection.session_id}")
        except Exception as e:
            logger.error(f"Error processing answer: {e}")
            try:
                await connection.send_message(MessageType.ERROR, {
                    "message": f"Error processing answer: {str(e)}",
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            connection._active_task = None

    async def handle_guidance(self, connection: WebSocketConnection, payload: dict):
        """Handle guidance message while agent is executing."""
        try:
            guidance_msg = GuidanceMessage(**payload)

            if not connection.authenticated:
                await connection.send_message(MessageType.ERROR, {
                    "message": "Not authenticated",
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
            await connection.send_message(MessageType.ERROR, {
                "message": "Invalid guidance format",
                "recoverable": True
            })

    async def handle_stop(self, connection: WebSocketConnection, payload: dict):
        """Handle stop request — cancels active agent execution."""
        if not connection.authenticated:
            await connection.send_message(MessageType.ERROR, {
                "message": "Not authenticated",
                "recoverable": False
            })
            return

        if connection._active_task and not connection._active_task.done():
            connection._active_task.cancel()
            connection._is_stopped = True

            # Get current state for the STOPPED message
            try:
                config = create_config(connection.user_id, connection.project_id, connection.session_id)
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
            await connection.send_message(MessageType.ERROR, {
                "message": "No active execution to stop",
                "recoverable": True,
            })

    async def handle_resume(self, connection: WebSocketConnection, payload: dict):
        """Handle resume request — restarts agent from last checkpoint."""
        if not connection.authenticated:
            await connection.send_message(MessageType.ERROR, {
                "message": "Not authenticated",
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
        callback = StreamingCallback(connection)

        task = asyncio.create_task(
            self._run_orchestrator_resume(connection, callback)
        )
        connection._active_task = task
        logger.info(f"Resuming execution for session {connection.session_id}")

    async def _run_orchestrator_resume(self, connection: WebSocketConnection, callback):
        """Background coroutine that resumes orchestrator from checkpoint."""
        try:
            result = await self.orchestrator.resume_execution_with_streaming(
                user_id=connection.user_id,
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
                await connection.send_message(MessageType.ERROR, {
                    "message": f"Error resuming execution: {str(e)}",
                    "recoverable": True
                })
            except Exception:
                pass
        finally:
            connection._active_task = None

    async def handle_ping(self, connection: WebSocketConnection, payload: dict):
        """Handle ping for keep-alive"""
        connection.last_ping = datetime.utcnow()
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
            elif msg_type == MessageType.PING:
                await self.handle_ping(connection, payload)
            elif msg_type == MessageType.GUIDANCE:
                await self.handle_guidance(connection, payload)
            elif msg_type == MessageType.STOP:
                await self.handle_stop(connection, payload)
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
                "message": f"Internal error: {str(e)}",
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
                "message": f"Fatal error: {str(e)}",
                "recoverable": False
            })
        except:
            pass
    finally:
        if connection._active_task and not connection._active_task.done():
            connection._active_task.cancel()
        await ws_manager.disconnect(connection)
