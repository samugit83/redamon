"""One collector per run (T2.1, TD-13, R-366): bound by the first node, shared by the tasks
it starts (a plan wave, Fireteam members), and drained as full merged values."""

from __future__ import annotations

import asyncio
import contextvars
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import run_state  # noqa: E402


def in_fresh_context(fn, *args):
    return contextvars.Context().run(fn, *args)


def test_bind_reads_the_state_and_a_missing_field_as_empty():
    def go():
        rs = run_state.bind({"session_id": "s1"})
        return rs.drain()

    assert in_fresh_context(go) == run_state.fresh_values()


def test_drain_merges_and_deduplicates():
    state = {
        "session_id": "s1",
        "tradecraft_seen_pages": ["patt:1", "htk:2", "patt:1"],
        "tradecraft_ask_count": 2,
        "tradecraft_hint_count": 1,
        "tradecraft_hint_log": [{"checkpoint": "skill", "pages": ["patt:1"]}],
    }

    def go():
        rs = run_state.bind(state)
        assert rs.record_seen(["htk:2", "patt:3", "patt:3", ""]) == ["patt:3"]
        rs.incr("ask")
        rs.incr("hint")
        rs.log_hint({"checkpoint": "phase", "pages": ["patt:3"]})
        first = rs.drain()
        second = rs.drain()
        return first, second

    first, second = in_fresh_context(go)
    assert first == second
    assert first == {
        "tradecraft_seen_pages": ["patt:1", "htk:2", "patt:3"],
        "tradecraft_ask_count": 3,
        "tradecraft_hint_count": 2,
        "tradecraft_hint_log": [{"checkpoint": "skill", "pages": ["patt:1"]}, {"checkpoint": "phase", "pages": ["patt:3"]}],
        "tradecraft_run_key": None,
    }
    # Drained values are copies: changing them does not change the run.
    first["tradecraft_seen_pages"].append("x:1")
    assert "x:1" not in second["tradecraft_seen_pages"]


def test_bad_stored_values_read_as_empty():
    state = {"session_id": "s", "tradecraft_ask_count": -4, "tradecraft_hint_count": True,
             "tradecraft_seen_pages": ["ok:1", 7, None], "tradecraft_hint_log": ["not a dict", {"k": 1}]}
    got = in_fresh_context(lambda: run_state.bind(state).drain())
    assert got == {"tradecraft_seen_pages": ["ok:1"], "tradecraft_ask_count": 0, "tradecraft_hint_count": 0,
                   "tradecraft_hint_log": [{"k": 1}], "tradecraft_run_key": None}


RUN_VALUES = {
    "session_id": "s1",
    "tradecraft_seen_pages": ["patt:1"],
    "tradecraft_ask_count": 10,
    "tradecraft_hint_count": 6,
    "tradecraft_hint_log": [{"checkpoint": "skill"}],
    "tradecraft_run_key": "objective:0",
}


def test_a_new_message_starts_from_empty_values():
    """R-366, Q6: a run is one message. The second message of a session must not inherit the
    first one's ten librarian questions, or questionsPerRun would refuse every later message."""
    state = {**RUN_VALUES, "current_objective_index": 1}
    got = in_fresh_context(lambda: run_state.bind(state).drain())
    assert got == run_state.fresh_values("objective:1")


def test_a_resume_keeps_the_runs_values():
    state = {**RUN_VALUES, "current_objective_index": 0}
    got = in_fresh_context(lambda: run_state.bind(state).drain())
    assert got["tradecraft_ask_count"] == 10
    assert got["tradecraft_seen_pages"] == ["patt:1"]
    assert got["tradecraft_run_key"] == "objective:0"


def test_values_from_before_the_run_key_start_fresh_once():
    legacy = {k: v for k, v in RUN_VALUES.items() if k != "tradecraft_run_key"}
    first = in_fresh_context(lambda: run_state.bind({**legacy, "current_objective_index": 3}).drain())
    assert first == run_state.fresh_values("objective:3")
    resumed = in_fresh_context(lambda: run_state.bind({**legacy, **first, "current_objective_index": 3, "tradecraft_ask_count": 2}).drain())
    assert resumed["tradecraft_ask_count"] == 2


def test_a_member_state_without_an_objective_keeps_the_seeded_values():
    member = {k: v for k, v in RUN_VALUES.items()}
    got = in_fresh_context(lambda: run_state.bind(member).drain())
    assert got["tradecraft_ask_count"] == 10
    assert got["tradecraft_run_key"] == "objective:0"


def test_a_collector_of_an_earlier_run_is_not_reused():
    def go():
        first = run_state.bind({"session_id": "s1", "current_objective_index": 0})
        first.incr("ask")
        second = run_state.bind({"session_id": "s1", "current_objective_index": 1})
        member = run_state.bind({"session_id": "s1"})
        return first is second, second is member, second.counts()["ask"]

    assert in_fresh_context(go) == (False, True, 0)


def test_parallel_tasks_share_one_collector_bound_before_they_start():
    async def tool(n):
        await asyncio.sleep(0)
        run_state.record_seen([f"patt:{n}"])
        run_state.incr("ask")

    async def node(state):
        run_state.bind(state)
        await asyncio.gather(*(asyncio.create_task(tool(n)) for n in range(1, 6)))
        return run_state.drain()

    out = in_fresh_context(asyncio.run, node({"session_id": "s1", "tradecraft_ask_count": 1}))
    assert sorted(out["tradecraft_seen_pages"]) == [f"patt:{n}" for n in range(1, 6)]
    assert out["tradecraft_ask_count"] == 6


def test_rebind_in_child_task_keeps_collector():
    """A Fireteam member binds with its own state (seeded from the run's): it counts into the
    run's collector, so its asks count against the run's limit."""

    async def member(member_state):
        rs = run_state.bind(member_state)
        rs.incr("ask")
        rs.record_seen(["htk:9"])
        return id(rs)

    async def deploy(state):
        parent = run_state.bind(state)
        seeded = {**state, "member_id": "m1"}
        ids = await asyncio.gather(member(seeded), member(dict(seeded)))
        return parent, ids

    parent, ids = in_fresh_context(asyncio.run, deploy({"session_id": "s1", "tradecraft_ask_count": 4}))
    assert ids == [id(parent), id(parent)]
    assert parent.counts()["ask"] == 6
    assert parent.drain()["tradecraft_seen_pages"] == ["htk:9"]


def test_a_task_started_before_the_bind_does_not_share_it():
    async def early():
        await asyncio.sleep(0.01)
        return run_state.current()

    async def node():
        task = asyncio.create_task(early())
        run_state.bind({"session_id": "s1"})
        return await task

    assert in_fresh_context(asyncio.run, node()) is None


def test_another_session_gets_its_own_collector():
    def go():
        a = run_state.bind({"session_id": "s1"})
        b = run_state.bind({"session_id": "s2"})
        return a is b

    assert in_fresh_context(go) is False


def test_bound_restores_the_context():
    def go():
        outer = run_state.bind({"session_id": "s1"})
        with run_state.bound({"session_id": "s2"}) as inner:
            assert run_state.current() is inner
        return run_state.current() is outer

    assert in_fresh_context(go) is True


def test_unbound_calls_fail_loudly():
    def go():
        with pytest.raises(LookupError):
            run_state.record_seen(["patt:1"])
        with pytest.raises(LookupError):
            run_state.drain()
        return run_state.current()

    assert in_fresh_context(go) is None


def test_unknown_counter():
    with pytest.raises(ValueError):
        in_fresh_context(lambda: run_state.bind({"session_id": "s"}).incr("search"))


def test_threads_do_not_lose_updates():
    rs = in_fresh_context(lambda: run_state.bind({"session_id": "s"}))

    def work(i):
        for j in range(200):
            rs.incr("hint")
            rs.record_seen([f"p:{i * 1000 + j + 1}"])

    threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert rs.counts()["hint"] == 800
    assert len(rs.drain()["tradecraft_seen_pages"]) == 800
