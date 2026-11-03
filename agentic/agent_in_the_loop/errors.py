"""Errors of an Agent in the Loop step.

Every message is a fixed sentence that matches none of the transient phrases
of ``llm_retry.is_transient_llm_error`` ("timeout", "connection", a bare 5xx,
...): a step that already waited minutes for a person's agent must never be
waited for again. ``no_retry`` says the same thing explicitly.
"""
from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
REASON_MAX_CHARS = 300


def sanitize_reason(reason: object) -> str:
    """One line, no control characters, at most 300 characters."""
    text = _CONTROL.sub(" ", str(reason or "")).strip()
    return re.sub(r" {2,}", " ", text)[:REASON_MAX_CHARS]


class LoopError(RuntimeError):
    no_retry = True
    code = "loop_error"
    message = "the Agent in the Loop step failed"

    def __init__(self, message: str | None = None):
        super().__init__(message or self.message)


class LoopStepNotAnswered(LoopError):
    code = "loop_step_not_answered"
    message = "the external agent did not answer this step"


class LoopNoDriver(LoopError):
    code = "loop_no_driver"
    message = "no external agent picked up this step"


class LoopStepDeclined(LoopError):
    code = "loop_step_declined"
    message = "the external agent declined this step"

    def __init__(self, reason: object = ""):
        super().__init__()
        # Kept apart from the message: a driver's reason is free text and may
        # contain any phrase, including the transient ones.
        self.reason = sanitize_reason(reason)


class LoopModelOutsideRun(LoopError):
    code = "loop_model_outside_run"
    message = "Agent in the Loop answers only inside a chat run"


class LoopCapReached(LoopError):
    code = "loop_too_many_steps"
    message = "too many Agent in the Loop steps are waiting for this user"


class LoopDisabled(LoopError):
    code = "loop_disabled"
    message = "Agent in the Loop is turned off on this deployment"


class LoopModelNotSupportedHere(ValueError):
    """A loop model reached a builder outside a chat run (a feature, recon AI, ...).

    A ValueError, not a LoopError: it is a refusal before any step exists.
    """
    code = "loop_model_not_supported_here"
    message = ("Agent in the Loop answers only inside a chat run; "
               "pick a provider model for this feature.")

    def __init__(self):
        super().__init__(self.message)


def refuse_loop_model(model: object) -> None:
    from . import is_loop_model
    if is_loop_model(model):  # type: ignore[arg-type]
        raise LoopModelNotSupportedHere()
