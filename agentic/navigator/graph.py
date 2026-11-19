"""One AI Navigator run (plan §8.3): load → route → specialists (in parallel) → synthesize.

    load        the wiki index, the webapp's tool manifest for this person and project
    route       one model call (router.py)
    specialists one bounded tool loop per chosen route, in parallel (specialists.py)
    synthesize  one streamed call merging the notes; skipped when one route answers alone

A plain asyncio pipeline: each stage awaits the one before, the specialists run under
asyncio.gather, and cancelling the run's task (a disconnect, /navigator/stop) stops whatever
call is in flight. Every model call carries `metadata.user_id`, the person, so an instance
provider's daily budget is charged to them (llm_budget.InstanceBudgetCallback).
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from navigator import events, prompts
from navigator.citations import CitationRegistry
from navigator.limits import DATA_ROUTES
from navigator.remote_tools import fetch_manifest, make_remote_tools
from navigator.router import RouteDecision, route_message
from navigator.schema_tools import cypher_rules, label_lines, make_schema_tools
from navigator.specialists import (AnswerCapReached, ModelCannotCallTools, RunState,
                                   SpecialistResult, run_specialist)
from navigator.text import message_text
from navigator.wiki_index import WikiIndex, wiki_index
from navigator.wiki_tools import make_wiki_tools, toc_text

logger = logging.getLogger(__name__)

EMPTY_ANSWER = "I couldn't put an answer together this time. Try asking again, perhaps more specifically."


@dataclass
class ChatRequest:
    run_id: str
    credential: str
    user_id: str
    actor_id: Optional[str]
    project_id: str
    tenant_id: str
    model: str
    history: list[dict]
    message: str
    page_path: Optional[str] = None
    wiki_hint: Optional[str] = None
    allowed_routes: list[str] = field(default_factory=list)
    route_reasons: dict[str, str] = field(default_factory=dict)


def _history_messages(history: list[dict]) -> list:
    out = []
    for turn in history:
        content = turn.get("content") or ""
        out.append(HumanMessage(content) if turn.get("role") == "user" else AIMessage(content))
    return out


def _question(req: ChatRequest, decision: RouteDecision) -> str:
    where = f"(The user is on the screen {req.page_path}.)\n" if req.page_path else ""
    if decision.standalone_question and decision.standalone_question != req.message:
        return f"{where}{req.message}\n\n(Standalone form of this question: {decision.standalone_question})"
    return f"{where}{req.message}"


def _system_for(route: str, index: WikiIndex, req: ChatRequest, answer: bool, language: str,
                refused: dict[str, str], handoff: bool) -> str:
    if route == "docs":
        base = prompts.DOCS.format(wiki_hint=req.wiki_hint or "none", toc=toc_text(index))
    elif route == "graph":
        base = prompts.GRAPH.format(cypher_rules=cypher_rules(), labels=label_lines())
    elif route == "records":
        base = prompts.RECORDS
    elif route == "workspace":
        base = prompts.WORKSPACE
    else:
        base = prompts.GENERAL
    tail = prompts.ANSWER_RULES.format(language=language) if answer else prompts.NOTES_RULES
    extra = "\n\n".join(x for x in (prompts.refused_note(refused) if answer else "",
                                    prompts.HANDOFF_NOTE if (answer and handoff) else "") if x)
    return f"{base}\n\n{tail}" + (f"\n\n{extra}" if extra else "")


async def _stream_plain(state: RunState, messages: list) -> None:
    async for chunk in state.llm.astream(messages, config=state.config):
        await state.stream_text(message_text(chunk.content))


def _classify_failure(exc: BaseException) -> tuple[str, str]:
    from llm_builder import is_model_unavailable_error
    if isinstance(exc, ModelCannotCallTools):
        return "model_no_tools", "This model can't call tools. Choose another model for AI Navigator."
    if getattr(exc, "code", None) == "llm_budget_exhausted" or type(exc).__name__ == "LlmBudgetExhausted":
        return "llm_budget_exhausted", "The daily budget of model calls on instance providers is used up."
    text = str(exc).lower()
    if "tool" in text and ("not support" in text or "does not support" in text or "unsupported" in text):
        return "model_no_tools", "This model can't call tools. Choose another model for AI Navigator."
    if is_model_unavailable_error(exc):
        return "model_unavailable", "Your model could not be used. Choose another model for AI Navigator."
    return "model_error", "The model call failed. Try again in a moment."


async def run_navigator(req: ChatRequest, llm, emit: Callable[[dict], Awaitable[None]],
                        checkpoint: Callable[[], Awaitable[None]], *,
                        index_provider: Optional[Callable[[], WikiIndex]] = None,
                        manifest_fetcher=None) -> None:
    started = time.monotonic()
    index_provider = index_provider or wiki_index
    manifest_fetcher = manifest_fetcher or fetch_manifest
    state = RunState(llm=llm, config={"metadata": {"user_id": req.user_id}, "run_name": "ai_navigator"},
                     emit=emit, checkpoint=checkpoint)
    await emit(events.meta(req.run_id, req.model))
    routes_done: list[str] = []
    try:
        index = await asyncio.to_thread(index_provider)
        allowed = [r for r in req.allowed_routes if r in ("docs", "direct", *DATA_ROUTES)]
        reasons = dict(req.route_reasons)
        if not index.present and "docs" in allowed:
            reasons.setdefault("docs", "docs_missing")

        remote = []
        if any(r in allowed for r in DATA_ROUTES):
            manifest = await manifest_fetcher(req.credential)
            if manifest is None:
                for r in DATA_ROUTES:
                    if r in allowed:
                        allowed.remove(r)
                        reasons[r] = "tools_unavailable"
            else:
                remote = make_remote_tools(manifest, req.credential)
                present = {t.route for t in remote}
                for r in DATA_ROUTES:
                    if r in allowed and r not in present:
                        allowed.remove(r)
                        reasons.setdefault(r, "missing_permission")

        decision = await route_message(llm, state.config, req.history, req.message, allowed, reasons,
                                       req.page_path, checkpoint)
        routes = decision.routes
        routes_done = list(routes)
        await emit(events.route(routes))
        for r, code in decision.refused.items():
            await emit(events.refused_route(r, code))
        if decision.action_request:
            await emit(events.handoff())

        citations = CitationRegistry()
        docs_tools = make_wiki_tools(index, citations) if index.present else []
        tools_by_route = {
            "docs": docs_tools,
            "graph": make_schema_tools() + [t for t in remote if t.route == "graph"],
            "records": [t for t in remote if t.route == "records"],
            "workspace": [t for t in remote if t.route == "workspace"],
        }
        history = _history_messages(req.history)
        question = _question(req, decision)
        language = decision.language

        if decision.fallback:
            tools = [t for r in routes for t in tools_by_route.get(r, [])]
            system = _system_for("general", index, req, True, language, decision.refused, decision.action_request)
            await run_specialist(state, "docs" if "docs" in routes else (routes[0] if routes else "direct"),
                                 system, [*history, HumanMessage(question)], tools, answer=True)
        elif routes == ["direct"] or (routes == ["docs"] and not index.present):
            refused = dict(decision.refused)
            if routes == ["docs"]:
                refused["docs"] = "docs_missing"
            system = prompts.DIRECT.format(refused=prompts.refused_note(refused)
                                           + ("\n" + prompts.DOCS_MISSING if "docs" in refused else ""))
            system += "\n\n" + prompts.ANSWER_RULES.format(language=language)
            await checkpoint()
            await _stream_plain(state, [SystemMessage(system), *history, HumanMessage(req.message)])
        elif len(routes) == 1:
            route = routes[0]
            system = _system_for(route, index, req, True, language, decision.refused, decision.action_request)
            await run_specialist(state, route, system, [*history, HumanMessage(question)],
                                 tools_by_route.get(route, []), answer=True)
        else:
            work = [r for r in routes if r != "direct"]

            async def one(route: str) -> SpecialistResult:
                system = _system_for(route, index, req, False, language, {}, False)
                return await run_specialist(state, route, system, [HumanMessage(question)],
                                            tools_by_route.get(route, []), answer=False)

            results = await asyncio.gather(*(one(r) for r in work))
            notes = "\n\n".join(f"[{prompts.ROUTE_NAMES.get(r.route, r.route)}]\n{r.notes or '(no notes)'}"
                                for r in results)
            system = prompts.SYNTHESIZER.format(
                refused=prompts.refused_note(decision.refused),
                handoff=prompts.HANDOFF_NOTE if decision.action_request else "",
                notes=notes) + "\n\n" + prompts.ANSWER_RULES.format(language=language)
            await checkpoint()
            await _stream_plain(state, [SystemMessage(system), *history, HumanMessage(req.message)])

        if not state.answer.strip():
            await state.stream_text(EMPTY_ANSWER)
        _, used = citations.finalize(state.answer)
        if used:
            await emit(events.citations([c.event() for c in used]))
        await emit(events.done())
    except AnswerCapReached:
        await emit(events.error("answer_too_long", "The answer was cut because it grew too long."))
    except asyncio.CancelledError:
        raise
    except Exception as exc:                                       # noqa: BLE001
        code, message = _classify_failure(exc)
        logger.warning("[navigator] run failed run=%s code=%s class=%s", req.run_id, code, type(exc).__name__)
        await emit(events.error(code, message))
    finally:
        logger.info("[navigator] run ended run=%s user=%s project=%s routes=%s tools=%d ms=%d",
                    req.run_id, req.user_id, req.project_id, ",".join(routes_done), state.tool_calls,
                    int((time.monotonic() - started) * 1000))
