"""The librarian's limits (T7.3, Q9.6): model calls, pages, time (a fake clock), one second try,
PARTIAL with the best result so far when a limit or the time ends a question, no retry of a model
error (TD-20), and one gate of two simultaneous model calls per run.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_tradecraft_librarian_graph import (  # noqa: E402
    FOUND_ANSWER, NONE_ANSWER, REQUEST, LibrarianModel, run, tools)
from test_tradecraft_librarian_graph import ask as ask_with  # noqa: E402
from tradecraft import clock, run_state  # noqa: E402
from tradecraft.librarian import graph, validate  # noqa: E402
from tradecraft_doubles import FakeClock  # noqa: E402

ALL = ["patt:412", "htk:88", "patt:415", "htk:91"]


def test_call_limit():
    """With 2 calls per question, a NONE leaves no call for the second try: PARTIAL, the best so
    far (the pages read first), saying why."""
    model = LibrarianModel({"shortlist": {"pages": ["patt:415"]}, "judge": NONE_ANSWER, "plan": {"queries": ["x"]}})
    answer = run(ask_with(model, **{"librarian.maxModelCalls": 2}))
    assert model.steps == ["shortlist", "judge"] and answer.model_calls == 2
    assert answer.verdict == "PARTIAL" and answer.notes == (graph.CALLS_UP.format(calls=2),)
    assert answer.picks[0].page_id == "patt:415"


def test_pages_limit():
    lib = tools()
    model = LibrarianModel({"shortlist": {"pages": ALL}, "judge": FOUND_ANSWER})
    answer = run(ask_with(model, lib, **{"librarian.maxPages": 2}))
    assert {c[1] for c in lib.calls if c[0] == "outline"} == {"patt:412", "htk:88"}
    assert answer.pages_inspected == 2 and "Pick at most 2 pages" in model.messages[0][-1]["content"]


def test_time_limit_with_a_fake_clock():
    """The time limit is read from the tradecraft clock: after 40 s of model time a 30 s question
    takes no second try and answers PARTIAL with the best so far."""
    fake = FakeClock()
    model = LibrarianModel({"shortlist": {"pages": ["patt:415"]}, "judge": NONE_ANSWER, "plan": {"queries": ["x"]}},
                           on_call=lambda step: fake.advance(20))

    async def go():
        with clock.use_clock(fake):
            return await ask_with(model)

    answer = run(go())
    assert model.steps == ["shortlist", "judge"]
    assert answer.verdict == "PARTIAL" and answer.notes == (graph.TIME_UP.format(secs=30),)
    assert answer.seconds == 40.0 and "· 40.0 s" in validate.render(answer)


def test_a_call_cut_at_the_time_limit():
    """A model call that does not answer within the time left is cut there (it is not waited for)."""
    fake = FakeClock()

    async def hold(step):
        if step == "judge":
            await asyncio.Event().wait()

    def near_the_end(step):
        if step == "shortlist":
            fake.advance(30 - 0.05)

    model = LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER}, on_call=near_the_end,
                           hold=hold)

    async def go():
        with clock.use_clock(fake):
            return await ask_with(model)

    answer = run(go())
    assert model.steps == ["shortlist", "judge"] and answer.verdict == "PARTIAL"
    assert answer.notes == (graph.TIME_UP.format(secs=30),) and answer.picks[0].page_id == "patt:412"


def test_one_second_try():
    """NONE twice: one second try only, then NOT FOUND with every search tried."""
    lib = tools(results={REQUEST.need: ["patt:415"], "q1": ["htk:91"], "q2": ["htk:88"]}, default=[])
    model = LibrarianModel({"shortlist": [{"pages": ["patt:415"]}, {"pages": ["htk:91", "htk:88"]}],
                            "judge": NONE_ANSWER, "plan": {"queries": ["q1", "q2"]}})
    answer = run(ask_with(model, lib, **{"librarian.maxModelCalls": 10}))
    assert model.steps == ["shortlist", "judge", "plan", "shortlist", "judge"]
    assert answer.verdict == "NOT FOUND" and answer.picks == () and answer.queries[1:] == ("q1", "q2")
    text = validate.render(answer)
    assert 'searched: "' in text and '"q1", "q2"' in text and "Do not repeat these searches" in text
    assert graph.SECOND_TRIES == 1


def test_model_error_not_retried():
    """TD-20: the first error ends the question; the free results answer, PARTIAL."""
    from llm_budget import LlmBudgetExhausted

    for step, calls in (("shortlist", 1), ("judge", 2)):
        answers = {"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER}
        answers[step] = LlmBudgetExhausted("person-1", 5, "yours")
        model = LibrarianModel(answers)
        answer = run(ask_with(model))
        assert model.calls == calls and answer.model_calls == calls
        assert answer.verdict == "PARTIAL" and answer.notes == (graph.MODEL_ERROR.format(code="llm_budget_exhausted"),)
        assert all(p.excerpt == "" for p in answer.picks)


def test_an_answer_outside_the_format_costs_its_call_only():
    """A shortlist that is not JSON falls back to the search's order; a judge that is not JSON
    lists the pages read, PARTIAL."""
    model = LibrarianModel({"shortlist": "I would read the first two.", "judge": "They look fine."})
    answer = run(ask_with(model, **{"librarian.maxPages": 2}))
    assert model.steps == ["shortlist", "judge"] and answer.pages_inspected == 2
    assert answer.verdict == "PARTIAL" and answer.notes == (graph.UNCHECKED,)
    assert [p.page_id for p in answer.picks][:2] == ["patt:412", "htk:88"]


def test_shared_semaphore():
    """Three asks of one run at once (a plan wave, Fireteam members): at most two model calls run
    together. Asks of two different runs do not share a gate."""
    release = asyncio.Event

    async def three_asks():
        gate_open = release()
        started = []

        async def hold(step):
            started.append(step)
            if len(started) >= 2:
                gate_open.set()
            await gate_open.wait()

        model = LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER}, hold=hold)
        with run_state.bound({"session_id": "s1", "current_objective_index": 0}):
            answers = await asyncio.gather(*(ask_with(model) for _ in range(3)))
        return model, answers

    model, answers = run(three_asks())
    assert model.max_running == graph.CONCURRENT_CALLS == 2
    assert [a.verdict for a in answers] == ["FOUND"] * 3 and model.calls == 6

    async def two_runs():
        with run_state.bound({"session_id": "s1", "current_objective_index": 0}):
            first = graph.call_gate()
            assert graph.call_gate() is first
        with run_state.bound({"session_id": "s2", "current_objective_index": 0}):
            assert graph.call_gate() is not first
        assert graph.call_gate() is not graph.call_gate()  # outside a run: one gate per ask

    run(two_runs())
