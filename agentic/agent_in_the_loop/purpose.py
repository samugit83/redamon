"""What a model call is for, so a loop step can tell its driver what to output.

The label is a ContextVar set around each call site; it is read only by the
loop adapter and is a no-op for every provider model.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from agent_context import current_llm_purpose

PURPOSES = (
    "think", "deep_think", "lats_expand", "fireteam_member", "classify",
    "scope_guardrail", "cypher", "report", "other",
)

ANSWER_FORMAT = {
    "think": "json",
    "deep_think": "json",
    "lats_expand": "json",
    "fireteam_member": "json",
    "classify": "json",
    "scope_guardrail": "json",
    "cypher": "cypher",
    "report": "markdown",
    "other": "text",
}


def answer_format(purpose: str) -> str:
    return ANSWER_FORMAT.get(purpose, "text")


@contextmanager
def llm_purpose(purpose: str, **meta) -> Iterator[None]:
    token = current_llm_purpose.set({"purpose": purpose if purpose in PURPOSES else "other", **meta})
    try:
        yield
    finally:
        current_llm_purpose.reset(token)
