"""Ask the webapp, when a person answers, whether they may still take that decision (step 5.4).

The ticket's `cap` is what the person held when the socket opened. Their account can be
disabled, their share revoked or narrowed, a toggle or a permission taken away while the
agent's prompt waits, so every approval, dangerous-tool confirmation, Fireteam member
confirmation and answer to a question, and CodeFix's push with the owner's token, is asked
again here before it decides anything: `POST /api/internal/agent/authorize-decision`.

Fail closed: only a 200 `{"allowed": true}` admits the decision. A 403 is a refusal naming
the permission and why (the webapp audits it); anything else (no key, the webapp down or
slow, an unreadable answer) is `decision_check_unavailable`, also a refusal.

A project can switch the prompts off (REQUIRE_APPROVAL_FOR_(POST_)EXPLOITATION,
REQUIRE_TOOL_CONFIRMATION), and nobody asks before a Fireteam wave starts. Those decisions are
taken in the run's person's place, so they need what the prompt would have checked
(`authorize_unasked`): the run's actor is bound by the socket task that runs the graph.
"""

import logging
import os
import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}

#: The kinds the webapp knows (its KINDS table decides their permissions and level).
DECISION_KINDS = ("approval", "tool_confirmation", "fireteam_member_confirmation",
                  "question", "codefix_push", "fireteam_deploy")

#: A person's answer waits on this call, so it is short; a slower webapp is a refusal.
DECISION_CHECK_TIMEOUT_S = 5.0

REFUSED = "permission_required"
UNAVAILABLE = "decision_check_unavailable"

_WORD = re.compile(r"^[a-z_]{1,40}$")
_PERMISSION = re.compile(r"^[a-z_]{1,40}:[a-z_]{1,40}$")


@dataclass(frozen=True)
class DecisionCheck:
    allowed: bool
    #: "" when allowed, else REFUSED or UNAVAILABLE.
    code: str = ""
    #: The permission refused (one the kind needs), for the drawer to name.
    permission: Optional[str] = None
    #: Why, as the webapp words it (`capability`, `project_level`, `project_not_visible`, ...).
    reason: Optional[str] = None


def _unavailable(why: str, kind: str, session_id: str) -> DecisionCheck:
    logger.warning("[rbac] decision check unavailable %s kind=%s session=%s", why, kind, session_id)
    return DecisionCheck(allowed=False, code=UNAVAILABLE)


async def authorize_decision(*, kind: str, user_id: str, project_id: str, session_id: str,
                             actor_id: Optional[str] = None,
                             permissions: tuple = ()) -> DecisionCheck:
    """Whether `user_id` (the ticket's `sub`; `actor_id` its `act`) may take a `kind` decision
    on `project_id` now. `permissions` are the ones the caller's own check asked, used only
    to name a refused permission the webapp's answer leaves out. Never raises."""
    if kind not in DECISION_KINDS:
        raise ValueError(f"unknown decision kind {kind!r}")
    if not INTERNAL_HEADERS.get("X-Internal-Key"):
        return _unavailable("reason=no_internal_key", kind, session_id)
    body: dict = {"kind": kind, "userId": user_id, "projectId": project_id, "sessionId": session_id}
    if actor_id:
        body["actorId"] = actor_id
    try:
        async with httpx.AsyncClient(timeout=DECISION_CHECK_TIMEOUT_S) as client:
            resp = await client.post(
                f"{WEBAPP_API_URL}/api/internal/agent/authorize-decision",
                json=body,
                headers=INTERNAL_HEADERS,
            )
    except Exception as e:
        return _unavailable(f"error={type(e).__name__}", kind, session_id)
    try:
        data = resp.json()
    except Exception:
        data = None
    if not isinstance(data, dict):
        return _unavailable(f"status={resp.status_code} unreadable", kind, session_id)
    if resp.status_code == 200 and data.get("allowed") is True:
        return DecisionCheck(allowed=True)
    if resp.status_code == 403:
        permission = data.get("permission")
        if not isinstance(permission, str) or not _PERMISSION.match(permission):
            permission = permissions[0] if permissions else None
        reason = data.get("reason") if isinstance(data.get("reason"), str) and _WORD.match(data["reason"]) else None
        logger.warning("[rbac] decision refused at decision time kind=%s permission=%s reason=%s session=%s",
                       kind, permission, reason, session_id)
        return DecisionCheck(allowed=False, code=REFUSED, permission=permission, reason=reason)
    return _unavailable(f"status={resp.status_code}", kind, session_id)


@dataclass(frozen=True)
class RunActor:
    """Who a chat run acts for: the ticket of the socket that started or resumed it.

    `user_id` is the person (`sub`), `tenant_id` the project's owner (`ten`), `actor_id` the
    admin under act-as (`act`), `cap` the agent permissions the ticket carries (None: a ticket
    without `cap`, which holds everything, as on the socket).
    """
    user_id: str
    tenant_id: str
    project_id: str
    session_id: str
    actor_id: Optional[str] = None
    cap: Optional[frozenset] = None

    def holds(self, permission: str) -> bool:
        return self.cap is None or permission in self.cap

    @property
    def is_owner(self) -> bool:
        """The project's owner signed in as themself: no one else's access to re-check."""
        return self.user_id == self.tenant_id and not self.actor_id


#: Every node and Fireteam member task created inside the socket's run task inherits it.
#: None outside a socket's run (no person to check).
current_run_actor: ContextVar[Optional[RunActor]] = ContextVar("current_run_actor", default=None)


def bind_run_actor(actor: RunActor) -> None:
    """Bind the run's actor to the current task. Call it first in the task that runs the graph:
    the binding ends with that task."""
    current_run_actor.set(actor)


def run_actor_holds(permission: str) -> bool:
    """Whether the run's person holds `permission` by their ticket alone (no webapp call), for
    leaving an action out of the prompt; the decision itself goes through authorize_unasked."""
    actor = current_run_actor.get()
    return actor is None or actor.holds(permission)


async def authorize_unasked(kind: str, *permissions: str) -> DecisionCheck:
    """A decision the project's settings take without asking anyone (a phase transition with
    approvals off, a dangerous call with confirmations off, a Fireteam wave): the run's person
    must hold what the prompt would have checked (`kind` names it, as for an answer).

    The ticket's `cap` first, so a person it leaves out is refused without a call; then, for
    anyone but the owner signed in as themself, the webapp now (fail closed, as an answer). The
    owner keeps today's behaviour: their `cap` holds everything and no call is made. Never raises.
    """
    actor = current_run_actor.get()
    if actor is None:
        return DecisionCheck(allowed=True)
    missing = next((p for p in permissions if not actor.holds(p)), None)
    if missing is not None:
        logger.warning("[rbac] unasked decision refused kind=%s permission=%s session=%s",
                       kind, missing, actor.session_id)
        return DecisionCheck(allowed=False, code=REFUSED, permission=missing, reason="capability")
    if actor.is_owner:
        return DecisionCheck(allowed=True)
    return await authorize_decision(kind=kind, user_id=actor.user_id, project_id=actor.project_id,
                                    session_id=actor.session_id, actor_id=actor.actor_id,
                                    permissions=permissions)


def unasked_refusal_text(check: DecisionCheck, doing: str) -> str:
    """The sentence the chat and the agent read for a refused unasked decision."""
    if check.code == UNAVAILABLE:
        return (f"The agent did not {doing}: RedAmon could not check that the person running it "
                "may (the permission check did not answer).")
    return (f"The agent did not {doing}: that needs {check.permission or 'a permission'} on this "
            "project from the person running the agent, who does not hold it.")
