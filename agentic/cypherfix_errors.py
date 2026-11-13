"""Fixed, code-keyed error text for the CypherFix triage and codefix sockets.

A raw exception from an LLM SDK, a git clone or an HTTP client routinely carries
the credential it was called with, the internal URL it reached, or a stack that
names the container's paths. Sending `str(e)` to the browser puts all of that in
front of whoever has the tab open, and into any bug report they paste it into.

So the socket gets a code and one of these fixed sentences; the exception itself
is logged server-side, where the redaction filter runs.
"""

from __future__ import annotations

TRIAGE_ERROR_MESSAGES = {
    "llm_error": (
        "The AI model call failed. Check your Triage review model in "
        "Global Settings > LLM Providers > Models by feature, then run triage again."
    ),
    "model_required": (
        "Choose a Triage review model first (Global Settings > LLM Providers > "
        "Models by feature), or set the review budget to 0 to rank without a model."
    ),
    "settings_unavailable": (
        "The project owner's model settings could not be loaded. Nothing was "
        "changed. Try again in a moment."
    ),
    "save_failed": (
        "The results could not be saved. Nothing was changed. Try again in a moment."
    ),
    "internal_error": (
        "The triage run stopped because of an internal error. Nothing was changed. "
        "The details are in the agent log."
    ),
    "authorize_failed": (
        "The triage run could not be authorised and did not start."
    ),
    "publish_refused": (
        "The results could not be published because the project changed while the "
        "run was working. Nothing was changed. Run triage again."
    ),
    "agent_lost": (
        "The results were not published because the run stopped checking in with "
        "the webapp for too long. Nothing was changed. Run triage again."
    ),
    "unknown_run": (
        "The results were not published because the webapp no longer knows this "
        "run. Nothing was changed. Run triage again."
    ),
    "stopped": (
        "The triage run was stopped before it published its results. Nothing was "
        "changed."
    ),
}

CODEFIX_ERROR_MESSAGES = {
    "llm_error": (
        "The AI model call failed. Check your CodeFix model in Global "
        "Settings > LLM Providers > Models by feature, then start the fix again."
    ),
    "model_required": (
        "Choose a CodeFix model first (Global Settings > LLM Providers > Models "
        "by feature), then start the fix again."
    ),
    "settings_unavailable": (
        "The project's settings could not be loaded. Nothing was changed. Try "
        "again in a moment."
    ),
    "remediation_not_found": "Remediation not found",
    "remediation_load_failed": (
        "The remediation could not be loaded from the webapp. Nothing was changed. "
        "Try again in a moment."
    ),
    "clone_failed": (
        "The repository could not be cloned. Check the repository name, the "
        "default branch and the GitHub token in the project's CypherFix settings."
    ),
    "pr_failed": (
        "The changes were committed and pushed, but the pull request could not be "
        "created. Open it from the branch in GitHub."
    ),
    "internal_error": (
        "The fix session stopped because of an internal error. The details are in "
        "the agent log."
    ),
    "permission_required": (
        "Nothing was pushed: pushing the fix with the project's GitHub token needs "
        "Manage on this project. The changes are saved on the remediation for the "
        "project owner."
    ),
    "decision_check_unavailable": (
        "Nothing was pushed: RedAmon could not check that you may push to this "
        "project's repository. The changes are saved on the remediation; start the "
        "fix again in a moment."
    ),
}

_GENERIC = "Something went wrong. The details are in the agent log."


def safe_error(code: str, *, codefix: bool = False, reason: str = "") -> str:
    """The user-facing sentence for an error code.

    `reason` is appended only when OUR code wrote it (a webapp refusal such as
    "A version activation is in progress"), never an exception's message.
    """
    table = CODEFIX_ERROR_MESSAGES if codefix else TRIAGE_ERROR_MESSAGES
    message = table.get(code, _GENERIC)
    return f"{message} {reason}" if reason else message


#: The ws-ticket gate's reason that must not earn a socket at all.
_CROSS_SITE = "disallowed origin"


async def reject_websocket(websocket, reason: str) -> None:
    """Refuse a socket the ws-ticket gate turned down, so the tab can say why.

    A close before `accept()` reaches the browser as 1006 with no reason, and an
    expired ticket then reads exactly like an agent that is down. A same-origin
    caller is accepted and closed at once with 1008 and the gate's fixed reason
    ("missing or invalid ticket", "ticket auth not configured"); nothing it
    sends is read. A cross-site page is still closed before accept: it must not
    get a socket, even a closed one.
    """
    if reason == _CROSS_SITE:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    # A close frame's reason is capped at 123 bytes.
    await websocket.close(code=1008, reason=str(reason)[:120])
