"""The bounded tool loop every AI Navigator specialist runs (plan §8.5).

Bind only the route's tools, call the model, run its tool calls in sequence, wrap every result as
untrusted data, stop at TOOL_CALLS_PER_SPECIALIST (and the run's TOOL_CALLS_PER_RUN) or when the
model stops calling tools. One model call per step and no retry: a provider error ends the run.

A specialist either returns NOTES for the synthesizer (several routes), or, when it is the only
route, streams its own final answer (one model call saved). While streaming, text that comes
before a tool call is the model thinking aloud and is held back; once more than FLUSH_AT
characters arrive with no tool call, the step is the answer and streams live.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from navigator import events
from navigator.limits import (ANSWER_MAX_CHARS, RUN_CYPHER_TIMEOUT_S, TOOL_CALLS_PER_RUN,
                              TOOL_CALLS_PER_SPECIALIST, TOOL_TIMEOUT_S, WORKSPACE_FILES_PER_RUN)
from navigator.remote_tools import SUMMARIES
from navigator.text import message_text
from navigator.tooling import NavTool, ToolOutcome, as_json
from prompt_safety import wrap_untrusted

logger = logging.getLogger(__name__)

FLUSH_AT = 200


class ModelCannotCallTools(Exception):
    code = "model_no_tools"


class AnswerCapReached(Exception):
    pass


@dataclass
class RunState:
    llm: object
    config: dict
    emit: Callable[[dict], Awaitable[None]]
    checkpoint: Callable[[], Awaitable[None]]
    tool_calls: int = 0
    workspace_reads: int = 0
    answer: str = ""
    answer_capped: bool = False

    async def stream_text(self, text: str) -> None:
        if not text or self.answer_capped:
            return
        room = ANSWER_MAX_CHARS - len(self.answer)
        if len(text) > room:
            text = text[:max(0, room)]
            self.answer_capped = True
        self.answer += text
        for ev in events.delta(text):
            await self.emit(ev)
        if self.answer_capped:
            raise AnswerCapReached()


@dataclass
class SpecialistResult:
    route: str
    notes: str = ""
    errors: list[str] = field(default_factory=list)
    tool_calls: int = 0


def _start_summary(name: str, args: dict) -> str:
    if name == "wiki_search":
        return f"Searching the docs for “{str(args.get('query') or '')[:80]}”"
    if name == "wiki_read":
        return f"Reading the docs: {str(args.get('page') or '')[:80]}"
    if name == "wiki_outline":
        return f"Reading the outline of {str(args.get('page') or '')[:80]}"
    if name == "wiki_toc":
        return "Reading the docs table of contents"
    if name in ("graph_labels", "graph_label_schema"):
        return "Reading the graph schema"
    return SUMMARIES.get(name, f"Calling {name}")


def bind(llm, tools: list[NavTool]):
    if not tools:
        return llm
    try:
        return llm.bind_tools([t.schema() for t in tools])
    except (NotImplementedError, AttributeError, TypeError, ValueError) as exc:
        logger.info("[navigator] model cannot bind tools class=%s", type(exc).__name__)
        raise ModelCannotCallTools() from exc


async def _run_tool(state: RunState, route: str, tool: Optional[NavTool], name: str, args: dict) -> ToolOutcome:
    refusal = None
    if tool is None:
        refusal = ToolOutcome(as_json({"ok": False, "code": "tool_unknown", "message": "No such tool here."}),
                              False, "Asked for a tool that does not exist", error_code="tool_unknown")
    elif name == "workspace_read":
        if state.workspace_reads >= WORKSPACE_FILES_PER_RUN:
            refusal = ToolOutcome(as_json({"ok": False, "code": "tool_budget", "message": "At most 3 files per answer."}),
                                  False, "Read a workspace file (refused: too many files)", error_code="tool_budget")
        else:
            state.workspace_reads += 1
    if refusal is not None:
        await state.emit(events.tool(route, name if tool is not None else "unknown_tool", "error", refusal.summary))
        return refusal
    await state.checkpoint()
    await state.emit(events.tool(route, name, "start", _start_summary(name, args)))
    timeout = (RUN_CYPHER_TIMEOUT_S if name == "run_cypher" else TOOL_TIMEOUT_S) + 10
    try:
        outcome = await asyncio.wait_for(tool.run(args), timeout=timeout)
    except asyncio.TimeoutError:
        outcome = ToolOutcome(as_json({"ok": False, "code": "tool_timeout", "message": "The tool took too long."}),
                              False, f"{_start_summary(name, args)} (timed out)", error_code="tool_timeout")
    await state.emit(events.tool(route, name, "end" if outcome.ok else "error", outcome.summary, outcome.detail))
    return outcome


async def _stream_step(bound, messages: list, state: RunState) -> tuple[AIMessage, bool]:
    """One streamed model step: (the message, whether its text was streamed as the answer)."""
    acc = None
    held = ""
    live = False
    saw_tool = False
    async for chunk in bound.astream(messages, config=state.config):
        acc = chunk if acc is None else acc + chunk
        if getattr(chunk, "tool_call_chunks", None):
            saw_tool = True
        text = message_text(chunk.content)
        if not text or (saw_tool and not live):
            continue
        if live:
            await state.stream_text(text)
        else:
            held += text
            if len(held) >= FLUSH_AT:
                live = True
                await state.stream_text(held)
                held = ""
    if acc is None:
        return AIMessage(""), False
    if not saw_tool and held and not live:
        live = True
        await state.stream_text(held)
    calls = [] if live else list(acc.tool_calls or [])
    msg = AIMessage(content=acc.content if not live else message_text(acc.content), tool_calls=calls,
                    additional_kwargs=dict(acc.additional_kwargs or {}))
    return msg, live


async def run_specialist(state: RunState, route: str, system: str, conversation: list, tools: list[NavTool],
                         *, answer: bool) -> SpecialistResult:
    """The loop. `conversation` holds the history and the user's question, after the system prompt."""
    result = SpecialistResult(route)
    by_name = {t.name: t for t in tools}
    bound = bind(state.llm, tools)
    messages: list = [SystemMessage(system), *conversation]
    own_calls = 0
    final: Optional[AIMessage] = None
    while True:
        exhausted = own_calls >= TOOL_CALLS_PER_SPECIALIST or state.tool_calls >= TOOL_CALLS_PER_RUN
        await state.checkpoint()
        if answer:
            ai, streamed = await _stream_step(bound, messages, state)
        else:
            ai, streamed = await bound.ainvoke(messages, config=state.config), False
        if streamed or not ai.tool_calls:
            final = ai
            break
        if exhausted:
            final = ai
            break
        messages.append(ai)
        for call in ai.tool_calls:
            name = call.get("name") or ""
            args = call.get("args") if isinstance(call.get("args"), dict) else {}
            if own_calls >= TOOL_CALLS_PER_SPECIALIST or state.tool_calls >= TOOL_CALLS_PER_RUN:
                outcome = ToolOutcome(as_json({"ok": False, "code": "tool_budget",
                                               "message": "Tool budget used up; answer with what you have."}),
                                      False, "tool budget", error_code="tool_budget")
            else:
                own_calls += 1
                state.tool_calls += 1
                outcome = await _run_tool(state, route, by_name.get(name), name, args)
            if not outcome.ok and outcome.error_code:
                result.errors.append(outcome.error_code)
            messages.append(ToolMessage(content=wrap_untrusted(outcome.content, label=name.upper()[:40] or "TOOL"),
                                        tool_call_id=call.get("id") or name))
        if own_calls >= TOOL_CALLS_PER_SPECIALIST or state.tool_calls >= TOOL_CALLS_PER_RUN:
            messages.append(HumanMessage("You have used every tool call allowed. Do not call tools again: "
                                         + ("write the final answer now." if answer else "write your notes now.")))
    result.tool_calls = own_calls
    text = message_text(final.content) if final is not None else ""
    if answer:
        if not state.answer and text and not (final is not None and final.tool_calls):
            await state.stream_text(text)
    else:
        result.notes = text.strip()
    return result
