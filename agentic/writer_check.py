"""Ask the webapp, before an agent run starts, whether another person is writing the project
(step 5.11 follow-up; SH-40, OQ-35).

The webapp refuses the chat ticket while another person writes the project (a scan, an agent
run, a triage run, a mute-rule apply), but the ticket is checked once, when the socket opens, and
runs start over the socket for as long as it stays open. So before each run starts (a message, an
approval, an answer to the agent's question, a tool confirmation, a resume) the socket asks again:
`POST /api/internal/agent/writer-check` with its verified ticket's person (`sub`), project and
session (`act` only for the webapp's log). The webapp answers as it answers the ticket: 200
`{"allowed": true}`, or 409 `project_writer_busy` naming who holds the project. It decides only
with sharing in force; the same person may run several things at once, as before.

What each answer does:
  - 200 `{"allowed": true}`: the run starts.
  - 409 `project_writer_busy` with its sentence and `busy`: refused, in the webapp's words.
  - no answer (no internal key, the webapp unreachable or slow) or a 5xx: unverified, read as the
    webapp reads a source it cannot ask: the project's owner's run starts (the person is the
    ticket's tenant: an admin acting as the owner is the owner), anyone else's is refused.
  - anything else the webapp answered (a 400 or 422 for a check it refused as asked, a 401, a 404,
    a malformed body): refused for everyone, the owner included. The session id is the browser's,
    so an answer the request itself can provoke must never let a run through.
Each refusal and each unverified start with an `[rbac]` log line, whose session id carries no
control character and is bounded.
"""

import logging
import os
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}

WRITER_BUSY = "project_writer_busy"

#: What starts a run on the socket, for the log lines.
RUN_STARTS = ("query", "approval", "question", "tool_confirmation", "resume")

#: The webapp asks the orchestrator and this agent (5 s each, at once) before it answers, so the
#: wait outlasts theirs: a shorter one would refuse every collaborator's run while one is slow.
WRITER_CHECK_TIMEOUT_S = 10.0

#: A refusal's sentences come from the webapp and reach the person; anything longer is not one.
_MAX_TEXT = 2000

#: The longest session id a log line carries (the webapp's own bound, lib/wsTicket.ts).
_LOG_MAX = 200

#: The webapp's own words for a source it cannot read (lib/authz/projectWriters.ts).
UNVERIFIED_BUSY = "whether someone else is writing this project could not be verified (webapp)"
UNVERIFIED_MESSAGE = f"Nothing was started: {UNVERIFIED_BUSY}. Try again shortly."


@dataclass(frozen=True)
class WriterCheck:
    allowed: bool
    #: The sentence the person reads ("" when allowed).
    message: str = ""
    #: "<person> is running <kind>", or why it could not be verified.
    busy: str = ""


def _text(value) -> Optional[str]:
    return value if isinstance(value, str) and 0 < len(value) <= _MAX_TEXT else None


def _loggable(value: str) -> str:
    """A ticket's session id inside a log line: a CR/LF or any other unprintable character would forge a
    line, so it becomes `?`; cut at _LOG_MAX."""
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return text if len(text) <= _LOG_MAX else text[:_LOG_MAX] + "..."


def _unverified(why: str, *, is_owner: bool, start: str, session_id: str) -> WriterCheck:
    if is_owner:
        logger.warning("[rbac] project_writer_unverified start=%s session=%s %s: the owner's run goes ahead",
                       start, _loggable(session_id), why)
        return WriterCheck(allowed=True)
    logger.warning("[rbac] agent run refused %s start=%s session=%s unverified %s",
                   WRITER_BUSY, start, _loggable(session_id), why)
    return WriterCheck(allowed=False, message=UNVERIFIED_MESSAGE, busy=UNVERIFIED_BUSY)


def _rejected(status: int, *, start: str, session_id: str) -> WriterCheck:
    logger.warning("[rbac] agent run refused %s start=%s session=%s rejected status=%s: refused for everyone",
                   WRITER_BUSY, start, _loggable(session_id), status)
    busy = f"whether someone else is writing this project could not be checked (the webapp answered HTTP {status})"
    return WriterCheck(allowed=False, message=f"Nothing was started: {busy}. Reload the chat and try again.", busy=busy)


async def second_writer_check(*, user_id: str, tenant_id: str, project_id: str, session_id: str,
                              start: str, actor_id: Optional[str] = None) -> WriterCheck:
    """Whether the run `start` names may start now for `user_id` (the ticket's `sub`) on
    `project_id`, whose owner is `tenant_id` (the ticket's `ten`, which decides only the
    unverified rule; the webapp reads the owner itself). Raises only on an unknown start."""
    if start not in RUN_STARTS:
        raise ValueError(f"unknown run start {start!r}")
    is_owner = user_id == tenant_id
    if not INTERNAL_HEADERS.get("X-Internal-Key"):
        return _unverified("reason=no_internal_key", is_owner=is_owner, start=start, session_id=session_id)
    body: dict = {"userId": user_id, "projectId": project_id, "sessionId": session_id}
    if actor_id:
        body["actorId"] = actor_id
    try:
        async with httpx.AsyncClient(timeout=WRITER_CHECK_TIMEOUT_S) as client:
            resp = await client.post(
                f"{WEBAPP_API_URL}/api/internal/agent/writer-check",
                json=body,
                headers=INTERNAL_HEADERS,
            )
    except Exception as e:
        return _unverified(f"error={type(e).__name__}", is_owner=is_owner, start=start, session_id=session_id)
    if resp.status_code >= 500:
        return _unverified(f"status={resp.status_code}", is_owner=is_owner, start=start, session_id=session_id)
    try:
        data = resp.json()
    except Exception:
        data = None
    if isinstance(data, dict):
        if resp.status_code == 200 and data.get("allowed") is True:
            return WriterCheck(allowed=True)
        message, busy = _text(data.get("error")), _text(data.get("busy"))
        if resp.status_code == 409 and data.get("code") == WRITER_BUSY and message and busy:
            logger.warning("[rbac] agent run refused %s start=%s session=%s", WRITER_BUSY, start, _loggable(session_id))
            return WriterCheck(allowed=False, message=message, busy=busy)
    return _rejected(resp.status_code, start=start, session_id=session_id)
