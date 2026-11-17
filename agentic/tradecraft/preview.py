"""The focus preview (§6.14 "Preview", T5.3): how a focus would sort up to 100 entries of a map.

The webapp sends the entries (a sample of the resource's live map, or of the page list Check URL
found), the focus, the model and the effective ingestion settings a refresh would carry; the
preview reads the focus with those settings as the refresh does (the account's "Always skip"
added to the resource's Skip, or replaced by it), runs the focus's keyword pre-sort and its title
triage (``ingest.focus``, one call for 100 titles) with that model, and answers the counts and
every entry with its decision, reason and tags. It writes nothing: this module imports neither the
page store nor a database driver (AC-13). The preview always judges as a Focused focus would, so
the person sees what Focused would keep whatever mode is chosen.

The model is the owner's, built like an ingestion job's (``models.build_ingest_llm``): a loop
model is refused before any call, every call carries the ``tradecraft_ingest`` purpose and none is
retried. The preview's time counts from the request, building the model included, and it stops a
little before the contract's deadline (``contract.DEADLINES_SEC["preview_focus"]``), which the
router counts from the same moment: its answer still carries the entries, those not judged by then
``maybe``, with ``timeout``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional

from logging_config import get_logger
from tradecraft import clock, contract
from tradecraft.contract import PreviewExample, PreviewRequest, PreviewResult
from tradecraft.ingest import focus as focus_mod
from tradecraft.ingest.crawl import error_code_of
from tradecraft.settings import EffectiveSettings

logger = get_logger(__name__)

# Seconds the preview keeps for building its answer before the router's deadline cuts the call.
DEADLINE_MARGIN_SEC = 2.0
REASON_MAX = 300

BuildLlm = Callable[[str, str], Awaitable[Any]]


def _example(entry: Any, decision: str, verdict: Optional[focus_mod.Verdict], reason: str = "") -> PreviewExample:
    return PreviewExample(url=entry.url, title=entry.title, decision=decision,
                          reason=(reason or (verdict.reason if verdict else ""))[:REASON_MAX],
                          topics=list(verdict.topics) if verdict else [], kinds=list(verdict.kinds) if verdict else [])


async def preview_focus(request: PreviewRequest, *, build_llm: Optional[BuildLlm] = None) -> PreviewResult:
    deadline = clock.monotonic() + contract.DEADLINES_SEC["preview_focus"] - DEADLINE_MARGIN_SEC
    entries = request.entries[:contract.PREVIEW_MAX_ENTRIES]
    raw = focus_mod.focus_of(request.focus, EffectiveSettings(request.settings))
    focus = focus_mod.Focus("focused", raw.topics, raw.kinds, raw.keep, raw.skip, raw.strictness)
    matchers = focus_mod.keyword_matchers(focus)
    decided: dict[int, PreviewExample] = {}
    judged: list[int] = []
    for i, entry in enumerate(entries):
        _score, linked = focus_mod.presort_score(matchers, entry.title, entry.url)
        if focus.strictness == "strict" and matchers.any and not linked:
            decided[i] = _example(entry, "drop", None, focus_mod.PRESORT_DROP_REASON)
        else:
            judged.append(i)
    result = focus_mod.TriageResult([None] * len(judged))
    error_code = ""
    if judged and focus.filters:
        error_code = await _triage(request, focus, [(entries[i].title, entries[i].url) for i in judged], result,
                                   build_llm, deadline)
    for i, verdict in zip(judged, result.verdicts):
        decided[i] = _example(entries[i], verdict.decision if verdict else ("maybe" if focus.filters else "keep"),
                              verdict)
    examples = [decided[i] for i in range(len(entries))]
    answer = PreviewResult(kept=sum(1 for e in examples if e.decision == "keep"),
                           maybe=sum(1 for e in examples if e.decision == "maybe"),
                           dropped=sum(1 for e in examples if e.decision == "drop"),
                           examples=examples, llm_calls=result.calls, error_code=error_code)
    logger.info(f"[tradecraft] preview entries={len(entries)} calls={answer.llm_calls} "
                f"code={error_code or 'ok'}")
    return answer


async def _triage(request: PreviewRequest, focus: focus_mod.Focus, items: list, result: focus_mod.TriageResult,
                  build_llm: Optional[BuildLlm], deadline: float) -> str:
    """Fills ``result`` and answers the error code ("" when every batch answered). Building the
    model (the owner's providers are read first) and the triage share the time to ``deadline``."""
    if build_llm is None:
        from tradecraft.models import build_ingest_llm
        build_llm = build_ingest_llm

    async def build_and_judge() -> str:
        try:
            llm = await build_llm(request.user_id, request.model)
        except Exception as exc:
            return error_code_of(exc)
        await focus_mod.triage_titles(llm, items, drop=True, focus=focus, step="preview", out=result)
        return result.error_code

    try:
        return await asyncio.wait_for(build_and_judge(), timeout=max(0.01, deadline - clock.monotonic()))
    except asyncio.TimeoutError:
        return "timeout"
