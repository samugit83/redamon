"""The librarian sub-graph (Q9, TD-12): run inside one ``tradecraft_ask`` call, then discarded.

    START -> shortlist -> inspect -> judge -+- FOUND / PARTIAL --------> answer -> END
                 ^                          |
                 +----------- plan <--------+  NONE, in the first round only

- ``shortlist`` (model): reads up to ``constants.mergedCandidates`` (40) cards from its own
  searches and picks pages to read: ``librarian.maxPages`` per question, both rounds together;
- ``inspect`` (no model): for each pick, the outline, the 1-2 sections that match the need (a
  section a stored copy's grep finds the need's code-like terms in comes first), each read up
  to ``constants.librarianSectionChars`` characters;
- ``judge`` (model): FOUND, PARTIAL or NONE, the best 1-3 sections and the sentences to quote;
- ``plan`` (model): after NONE in the first round, new queries from what it learned and the
  library's top folders, searched, then back to ``shortlist``;
- ``answer`` (no model): every page ID and excerpt checked (``validate``), the result built.

Compiled with ``checkpointer=False`` and run with a fresh config of its own: its thread id, the
person in ``metadata.user_id`` (whom the daily budget charges) and the owner in
``metadata.owner_id``, its recursion limit, and no inherited callbacks. It runs in a copy of the
caller's context whose LangChain run config is cleared, so nothing of the main run's thread,
checkpoint or streaming handlers reaches it (EX-3). Every model call carries the
``tradecraft_librarian`` purpose and is never retried (TD-20). The asks of one run (a plan wave,
Fireteam members) share one gate of two simultaneous model calls.

Degrading (AC-68): no model, an Agent in the Loop run, a model error, the time limit or the
call limit answer the free first pass's results (or the best result so far), PARTIAL, or NOT
FOUND when there were none, with a line saying why. Nothing found by the free first pass is
NOT FOUND with no model call.
"""

from __future__ import annotations

import asyncio
import contextvars
import re
import uuid
import weakref
from dataclasses import dataclass, field
from typing import Any, Optional, TypedDict

from agent_in_the_loop import is_loop_llm
from agent_in_the_loop.purpose import llm_purpose
from logging_config import get_logger
from orchestrator_helpers.json_utils import normalize_content
from tradecraft import clock, run_state
from tradecraft.ingest.crawl import error_code_of
from tradecraft.librarian import prompts, validate
from tradecraft.librarian.tools import CANDIDATES, Found, LibraryTools, exact_terms, narrowed
from tradecraft.library.search import Session
from tradecraft.library.types import Card, LibrarianAnswer, LibrarianPick
from tradecraft.settings import EffectiveSettings, constant
from tradecraft.vocab import load_vocab

logger = get_logger(__name__)

CONCURRENT_CALLS = 2
RECURSION_LIMIT = 20
SECOND_TRIES = int(constant("librarianSecondTries"))
SECTIONS_PER_PAGE = 2
# Real seconds past the time limit after which the whole graph is stopped: each model call is
# already cut at the limit, this only covers a step that hangs outside one.
HARD_STOP_GRACE_SEC = 5.0
WANTS = ("payload", "methodology", "poc", "any")
BROWSED_RESOURCES = 5

NO_MODEL = "no librarian model is set, so these are the plain search results"
LOOP_RUN = "the librarian is not used in an Agent in the Loop run: these are the plain search results"
MODEL_ERROR = "the librarian's model failed ({code}) and was not retried: these are the plain search results"
FAILED = "the librarian stopped on an error ({code}): these are the plain search results"
TIME_UP = "the time limit of {secs} s was reached: this is the best result so far"
CALLS_UP = "the limit of {calls} model calls per question was reached: this is the best result so far"
PAGES_UP = "the limit of {pages} pages inspected per question was reached: this is the best result so far"
UNREADABLE = "the pages found could not be read: these are the plain search results"
UNCHECKED = "no excerpt could be checked against the pages' text: the pages read are listed instead"
SCOPE_MISSED = "the scope named no resource of this run: the whole library was searched"

_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class Request:
    need: str
    context: str = ""
    want: str = "any"
    scope: tuple[str, ...] = ()


class Step(TypedDict, total=False):
    next: str


_GATES: "weakref.WeakKeyDictionary[Any, asyncio.Semaphore]" = weakref.WeakKeyDictionary()


def call_gate() -> asyncio.Semaphore:
    """The gate of the run's model calls: one per run (its ``run_state`` collector, which the
    main agent, a plan wave's tools and Fireteam members share); a fresh one outside a run."""
    collector = run_state.current()
    if collector is None:
        return asyncio.Semaphore(CONCURRENT_CALLS)
    gate = _GATES.get(collector)
    if gate is None:
        gate = _GATES[collector] = asyncio.Semaphore(CONCURRENT_CALLS)
    return gate


@dataclass
class _Run:
    """One question's working state, in memory only, and the limits it runs under."""

    request: Request
    tools: Any
    llm: Any
    settings: EffectiveSettings
    session: Optional[Session]
    gate: asyncio.Semaphore
    started: float
    request_block: str = ""
    calls: int = 0
    round: int = 1
    queries: list = field(default_factory=list)
    cards: dict = field(default_factory=dict)
    order: list = field(default_factory=list)
    picks: list = field(default_factory=list)
    inspected: list = field(default_factory=list)
    read: dict = field(default_factory=dict)
    this_round: list = field(default_factory=list)
    judged: Optional[validate.Judged] = None
    stop: str = ""
    error_code: str = ""

    @property
    def max_calls(self) -> int:
        return self.settings.int("librarian.maxModelCalls")

    @property
    def max_pages(self) -> int:
        return self.settings.int("librarian.maxPages")

    @property
    def deadline(self) -> float:
        return self.started + self.settings.int("librarian.timeLimitSec")

    def add(self, found: Found) -> int:
        """The search's cards joined to the candidates (its own results: the only page IDs an
        answer may name); returns how many are new and not read yet."""
        new = 0
        for card in found.cards:
            if card.page_id not in self.cards:
                self.cards[card.page_id] = card
                self.order.append(card.page_id)
                new += 1
        return new

    def pages_left(self) -> int:
        """Pages this question may still open: ``librarian.maxPages`` counts both rounds (Q9.6)."""
        return self.max_pages - len(self.inspected)

    def time_up(self) -> bool:
        if clock.monotonic() >= self.deadline:
            self.stop = self.stop or "time"
        return self.stop == "time"

    async def call(self, messages: list, step: str) -> Optional[dict]:
        """One model call, or None when the limits, the time or an error stop the question
        (``stop`` says which). An answer that is not JSON is ``{}``."""
        if self.stop:
            return None
        if self.calls >= self.max_calls:
            self.stop = "calls"
            return None
        if self.time_up():
            return None
        self.calls += 1

        async def invoke() -> Any:
            async with self.gate:
                with llm_purpose("tradecraft_librarian", step=step):
                    return await self.llm.ainvoke(messages)

        try:
            resp = await asyncio.wait_for(invoke(), timeout=max(0.001, self.deadline - clock.monotonic()))
        except asyncio.TimeoutError:
            self.stop = "time"
            return None
        except Exception as exc:
            self.stop, self.error_code = "model_error", error_code_of(exc)
            logger.info(f"[tradecraft] librarian step={step} code={self.error_code}")
            return None
        return prompts.parse_json(normalize_content(getattr(resp, "content", "") or "")) or {}

    def crumbs(self, page_id: str) -> tuple[str, ...]:
        card: Optional[Card] = self.cards.get(page_id)
        return ((card.resource_slug, *card.breadcrumb, card.title) if card else ())


# --------------------------------------------------------------------------------------
# The steps
# --------------------------------------------------------------------------------------

# Words too common to tell sections apart.
_STOP = frozenset({"the", "and", "for", "with", "from", "that", "this", "need", "needs", "into", "another", "way",
                   "what", "how", "use", "using", "can", "get", "not", "are", "you"})


def _words(text: str) -> set[str]:
    return {w for w in _WORD.findall((text or "").lower()) if len(w) >= 3 and w not in _STOP}


async def shortlist(run: _Run) -> Step:
    candidates = [run.cards[p] for p in run.order if p not in run.inspected][:CANDIDATES]
    room = run.pages_left()
    if not candidates or room <= 0 or run.time_up():
        return {"next": "answer"}
    data = await run.call(prompts.shortlist(run.request_block, candidates, room), "shortlist")
    if data is None:
        return {"next": "answer"}
    picks = validate.shortlist_ids(data, [c.page_id for c in candidates], room)
    # An answer outside the format picks nothing: the search's own order decides.
    run.picks = picks or [c.page_id for c in candidates[:room]]
    return {"next": "inspect"}


async def _sections_of(run: _Run, page_id: str) -> list[tuple[str, str]]:
    outline = await run.tools.outline(page_id)
    if not outline:
        return []
    need = f"{run.request.need} {run.request.context}"
    asked = _words(need)
    terms = [t for t in exact_terms(need) if await run.tools.grep(page_id, t)]
    scored = []
    for position, (name, _chars) in enumerate(outline):
        text = await run.tools.read(page_id, name) or ""
        lowered = text.lower()
        score = (5 * sum(1 for t in terms if t.lower() in lowered) + 2 * len(asked & _words(name))
                 + len(asked & _words(text)))
        scored.append((score, -position, name, text))
    ranked = [s for s in sorted(scored, reverse=True) if s[0] > 0 and s[3].strip()]
    # A second section is read only when it matches about as well as the first.
    best = [s for s in ranked[:SECTIONS_PER_PAGE] if 2 * s[0] >= ranked[0][0]]
    if not best:
        best = [next((s for s in scored if s[3].strip()), scored[0])]
    return [(name, text) for _s, _p, name, text in best]


async def inspect(run: _Run) -> Step:
    if run.time_up():
        return {"next": "answer"}
    picks = [p for p in run.picks if p not in run.inspected][:max(0, run.pages_left())]
    found = await asyncio.gather(*(_sections_of(run, p) for p in picks))
    run.this_round = []
    for page_id, sections in zip(picks, found):
        run.inspected.append(page_id)
        for name, text in sections:
            run.read[(page_id, name)] = text
            run.this_round.append((page_id, name))
    return {"next": "judge" if run.this_round else "answer"}


async def judge(run: _Run) -> Step:
    sections = [(p, " › ".join(run.crumbs(p)), name, run.read[(p, name)]) for p, name in run.this_round]
    data = await run.call(prompts.judge(run.request_block, sections), "judge")
    if data is None:
        return {"next": "answer"}
    run.judged = validate.judge_answer(data)
    if run.judged is not None and run.judged.verdict == "NONE" and run.round <= SECOND_TRIES:
        if run.pages_left() <= 0:
            # The second try would have nothing left to read: no plan call for it.
            run.stop = "pages"
            return {"next": "answer"}
        return {"next": "plan"}
    return {"next": "answer"}


async def plan(run: _Run) -> Step:
    if run.time_up():
        return {"next": "answer"}
    run.round += 1
    levels = []
    for resource in list(run.tools.catalog.resources)[:BROWSED_RESOURCES]:
        level = await run.tools.browse(resource.slug, "")
        if level is not None:
            levels.append(level)
    read_pages = []
    for page_id in run.inspected:
        names = ", ".join(n for p, n in run.read if p == page_id)
        read_pages.append((" › ".join(run.crumbs(page_id)), names))
    data = await run.call(prompts.plan(run.request_block, run.queries, read_pages, levels), "plan")
    if data is None:
        return {"next": "answer"}
    new = 0
    for query in validate.plan_queries(data, run.queries):
        run.queries.append(query)
        new += run.add(await run.tools.search(query))
    if not new:
        return {"next": "answer"}
    run.judged = None
    return {"next": "shortlist"}


# --------------------------------------------------------------------------------------
# The answer
# --------------------------------------------------------------------------------------

def _plain(run: _Run, first: Found, note: str, *, inspected_first: bool = False) -> LibrarianAnswer:
    """The free results (the pages read first, when asked): PARTIAL, or NOT FOUND without one."""
    order = list(run.order) if run.order else [c.page_id for c in first.cards]
    if inspected_first:
        order = [p for p in run.inspected if p in order] + [p for p in order if p not in run.inspected]
    cards = {c.page_id: c for c in first.cards} | run.cards
    picks = tuple(LibrarianPick(page_id=p, breadcrumb=run.crumbs(p) or _crumbs(cards[p]), why=_matched(cards[p]),
                                excerpt="")
                  for p in order[:validate.PAGES_RETURNED])
    also = validate.also_relevant(order[validate.PAGES_RETURNED:], set(cards), [p.page_id for p in picks])
    verdict = "PARTIAL" if picks else "NOT FOUND"
    return _finish(run, verdict, "low", picks, also, (note,) if note else ())


def _matched(card: Card) -> str:
    """The "why" of a plain search result: fixed words and the card's kinds, never its text."""
    labels = {k["id"]: k["mapLabel"] for k in load_vocab().kinds}
    kinds = ", ".join(labels.get(k, k) for k in card.kinds[:2])
    return f"found by search ({kinds})" if kinds else "found by search"


def _crumbs(card: Card) -> tuple[str, ...]:
    return (card.resource_slug, *card.breadcrumb, card.title)


def _finish(run: _Run, verdict: str, confidence: str, picks: tuple, also: tuple, notes: tuple) -> LibrarianAnswer:
    return LibrarianAnswer(verdict=verdict, confidence=confidence, model_calls=run.calls,
                           pages_inspected=len(run.inspected), seconds=round(clock.monotonic() - run.started, 1),
                           queries=tuple(run.queries), picks=tuple(picks), also_relevant=tuple(also), notes=notes)


def _stop_note(run: _Run) -> str:
    if run.stop == "time":
        return TIME_UP.format(secs=run.settings.int("librarian.timeLimitSec"))
    if run.stop == "calls":
        return CALLS_UP.format(calls=run.max_calls)
    if run.stop == "pages":
        return PAGES_UP.format(pages=run.max_pages)
    if run.stop == "model_error":
        return MODEL_ERROR.format(code=run.error_code or "model_unavailable")
    if run.stop == "error":
        return FAILED.format(code=run.error_code or "internal_error")
    return ""


def build_answer(run: _Run, first: Found, extra_notes: tuple = ()) -> LibrarianAnswer:
    judged = run.judged
    known = set(run.cards)
    if judged is not None and judged.verdict in ("FOUND", "PARTIAL"):
        picks, failed = validate.checked_picks(judged, known, run.read, {p: run.crumbs(p) for p in run.inspected})
        also = validate.also_relevant([*failed, *judged.also, *run.inspected], known, [p.page_id for p in picks])
        if picks:
            verdict = "FOUND" if judged.verdict == "FOUND" else "PARTIAL"
            # A partial answer is never of high confidence.
            confidence = judged.confidence if verdict == "FOUND" else ("low" if judged.confidence == "low" else "medium")
            return _finish(run, verdict, confidence, tuple(picks), also, extra_notes)
        return _with(_plain(run, first, UNCHECKED, inspected_first=True), extra_notes)
    if judged is not None and judged.verdict == "NONE" and not run.stop:
        # NONE after the second try (or with none possible): nothing suitable, with the
        # searches tried so the agent does not repeat them.
        return _finish(run, "NOT FOUND", "medium", (), (), extra_notes)
    if run.stop:
        return _with(_plain(run, first, _stop_note(run), inspected_first=True), extra_notes)
    if run.order and not run.read:
        return _with(_plain(run, first, UNREADABLE), extra_notes)
    return _with(_plain(run, first, UNCHECKED, inspected_first=True), extra_notes)


def _with(answer: LibrarianAnswer, notes: tuple) -> LibrarianAnswer:
    if not notes:
        return answer
    return LibrarianAnswer(**{**answer.__dict__, "notes": tuple(notes) + answer.notes})


# --------------------------------------------------------------------------------------
# The graph and the entry point
# --------------------------------------------------------------------------------------

def build_graph(run: _Run) -> Any:
    from langgraph.graph import END, START, StateGraph

    def node(step):
        async def _node(state: Step) -> Step:
            return await step(run)
        return _node

    builder = StateGraph(Step)
    for name, step in (("shortlist", shortlist), ("inspect", inspect), ("judge", judge), ("plan", plan)):
        builder.add_node(name, node(step))

    async def answer(state: Step) -> Step:
        return {"next": "end"}

    builder.add_node("answer", answer)
    builder.add_edge(START, "shortlist")
    for name, targets in (("shortlist", ("inspect", "answer")), ("inspect", ("judge", "answer")),
                          ("judge", ("plan", "answer")), ("plan", ("shortlist", "answer"))):
        builder.add_conditional_edges(name, lambda s: s["next"], {t: t for t in targets})
    builder.add_edge("answer", END)
    # Never the run's checkpointer: a sub-graph left without its own setting inherits it and
    # would save its state, excerpts included, with the chat (EX-3).
    return builder.compile(checkpointer=False)


def fresh_config(person_id: Optional[str], owner_id: str) -> dict:
    return {
        "configurable": {"thread_id": f"tradecraft-librarian-{uuid.uuid4().hex}"},
        "metadata": {"user_id": person_id or owner_id, "owner_id": owner_id},
        "recursion_limit": RECURSION_LIMIT,
        # Set on purpose: left out, the main run's streaming and logging handlers would be
        # inherited by every librarian call. The model's own callbacks (the budget's) stay.
        "callbacks": [],
    }


def _without_parent_run() -> None:
    from langchain_core.runnables.config import var_child_runnable_config
    var_child_runnable_config.set(None)


async def ask(request: Request, *, owner_id: str, person_id: Optional[str], catalog: Any,
              session: Optional[Session] = None, settings: Optional[EffectiveSettings] = None, llm: Any = None,
              tools: Any = None, first: Optional[Found] = None) -> LibrarianAnswer:
    """The librarian's answer to one need over the catalog's resources (narrowed to the
    request's scope). ``first`` is the free first pass when the caller ran it already."""
    started = clock.monotonic()
    settings = settings or EffectiveSettings(catalog.search or {}, scope="search")
    scoped, matched = narrowed(catalog, request.scope)
    notes = (SCOPE_MISSED,) if request.scope and not matched else ()
    if tools is None:
        tools = LibraryTools(owner_id, scoped, session=session, settings=settings)
    want = request.want if request.want in WANTS else "any"
    run = _Run(request=request, tools=tools, llm=llm, settings=settings, session=session, gate=call_gate(),
               started=started, request_block=prompts.need_block(request.need, request.context, want, session))
    run.queries.append(validate.one_line(request.need, validate.QUERY_CHARS))
    first = first if first is not None else await tools.search(request.need)
    if first.verdict == "NOT FOUND" or not first.cards:
        return _finish(run, "NOT FOUND", "medium", (), (), notes)
    run.add(first)
    if llm is None:
        return _with(_plain(run, first, NO_MODEL), notes)
    if is_loop_llm(llm):
        return _with(_plain(run, first, LOOP_RUN), notes)
    graph = build_graph(run)
    context = contextvars.copy_context()
    context.run(_without_parent_run)
    task = asyncio.get_running_loop().create_task(
        graph.ainvoke({"next": "shortlist"}, config=fresh_config(person_id, owner_id)), context=context)
    try:
        await asyncio.wait_for(task, timeout=settings.int("librarian.timeLimitSec") + HARD_STOP_GRACE_SEC)
    except asyncio.TimeoutError:
        run.stop = "time"
    except Exception as exc:
        # A step that failed outside a model call (the store, a read); the free results answer.
        logger.warning(f"[tradecraft] librarian code=internal_error error={type(exc).__name__}")
        if not run.stop:
            run.stop, run.error_code = "error", "internal_error"
    answer = build_answer(run, first, notes)
    logger.info(f"[tradecraft] librarian verdict={answer.verdict} calls={answer.model_calls} "
                f"pages={answer.pages_inspected} picks={len(answer.picks)} stop={run.stop or '-'}")
    return answer
