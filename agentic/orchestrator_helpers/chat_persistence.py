"""
Chat Persistence Module

Persists agent chat messages to the webapp's PostgreSQL database
via the REST API. Uses httpx (already in requirements.txt).

All calls are fire-and-forget with error handling — persistence
failures must NEVER crash the agent.
"""

import os
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}


async def save_chat_message(
    session_id: str,
    msg_type: str,
    data: dict,
    project_id: Optional[str] = None,
    user_id: Optional[str] = None,
    *,
    agent_id_key: Optional[str] = None,
    fireteam_id_key: Optional[str] = None,
) -> Optional[dict]:
    """Save a single chat message to the conversation via session ID.

    agent_id_key and fireteam_id_key attribute the event to a Fireteam member.
    When both are None (root agent), the row is root-attributed.

    Returns None when the row was saved, else what a person may see of the
    failure: `{"http_status": n}` for a webapp refusal, `{"error_class": name}`
    when the webapp was not reached. The texts stay in the log.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            body: dict = {"type": msg_type, "data": data}
            if project_id:
                body["projectId"] = project_id
            if user_id:
                body["userId"] = user_id
            if agent_id_key:
                body["memberIdKey"] = agent_id_key
            if fireteam_id_key:
                body["fireteamIdKey"] = fireteam_id_key
            resp = await client.post(
                f"{WEBAPP_API_URL}/api/conversations/by-session/{session_id}/messages",
                json=body,
                headers=INTERNAL_HEADERS,
            )
            if resp.status_code not in (200, 201):
                logger.warning(
                    f"Chat persistence failed ({resp.status_code}): {resp.text[:200]}"
                )
                return {"http_status": resp.status_code}
    except Exception as e:
        logger.warning(f"Chat persistence error: {type(e).__name__}: {e}")
        return {"error_class": type(e).__name__}
    return None


async def update_conversation(
    session_id: str,
    updates: dict,
):
    """Update conversation metadata (agentRunning, phase, etc.) by session ID."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.patch(
                f"{WEBAPP_API_URL}/api/conversations/by-session/{session_id}",
                json=updates,
                headers=INTERNAL_HEADERS,
            )
            if resp.status_code not in (200, 201):
                logger.warning(
                    f"Conversation update failed ({resp.status_code}): {resp.text[:200]}"
                )
    except Exception as e:
        logger.warning(f"Conversation update error: {type(e).__name__}: {e}")


async def post_agent_decision(
    *,
    kind: str,
    session_id: str,
    project_id: str,
    user_id: str,
    actor_id: Optional[str],
    decision: str,
    wave_id: Optional[str] = None,
    member_id: Optional[str] = None,
) -> bool:
    """Ask the webapp to write the audit row of a decision the agent accepted (step 3.9b).

    `kind` is `approval`, `tool_confirmation` or `fireteam_member_confirmation`;
    `user_id` is the ticket's `sub`, `actor_id` its `act` (the admin acting as `sub`), and
    the webapp names the real person as the row's actor. Never raises: the decision is
    already applied, so a lost row is told to the operator by the `[rbac]` log line only.
    """
    if not INTERNAL_HEADERS.get("X-Internal-Key"):
        # The webapp refuses a call without the key: say so instead of sending it.
        logger.warning("[rbac] decision audit not sent: INTERNAL_API_KEY is unset kind=%s session=%s",
                       kind, session_id)
        return False
    body: dict = {"kind": kind, "sessionId": session_id, "projectId": project_id,
                  "userId": user_id, "decision": decision}
    if actor_id:
        body["actorId"] = actor_id
    if wave_id:
        body["waveId"] = wave_id
    if member_id:
        body["memberId"] = member_id
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{WEBAPP_API_URL}/api/internal/agent/decisions",
                json=body,
                headers=INTERNAL_HEADERS,
            )
        if resp.status_code not in (200, 201):
            logger.warning("[rbac] decision audit failed status=%s kind=%s session=%s",
                           resp.status_code, kind, session_id)
            return False
    except Exception as e:
        logger.warning("[rbac] decision audit failed error=%s kind=%s session=%s",
                       type(e).__name__, kind, session_id)
        return False
    return True
