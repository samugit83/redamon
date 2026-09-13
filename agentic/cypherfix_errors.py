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
        "The AI model could not be reached. Check the model and API key in the "
        "project's CypherFix settings, then run triage again."
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
}

CODEFIX_ERROR_MESSAGES = {
    "llm_error": (
        "The AI model could not be reached. Check the model and API key in the "
        "project's CypherFix settings, then start the fix again."
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
}

_GENERIC = "Something went wrong. The details are in the agent log."


def safe_error(code: str, *, codefix: bool = False) -> str:
    """The user-facing sentence for an error code."""
    table = CODEFIX_ERROR_MESSAGES if codefix else TRIAGE_ERROR_MESSAGES
    return table.get(code, _GENERIC)
