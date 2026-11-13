"""The daily budget of model calls on instance LLM providers (step 6.11, GV-12).

- budget refused when exhausted: the stricter of the actor's and the owner's
  budget refuses, with `llm_budget_exhausted`, never retried;
- a call is counted once, for the actor, and the counts are reported to the
  webapp at most every minute (kept for the next report when one fails);
- the existing daily caps still apply (llm_guard), independently;
- a model built from an instance row carries the budget check; an own provider
  does not;
- a budget the agent cannot read lets the call through, logged.

Runs inside the agent container (`./agentic/run_tests.sh tests/test_llm_budget.py`).
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import llm_budget  # noqa: E402
from llm_budget import BudgetTracker, LlmBudgetExhausted  # noqa: E402

DAY0 = 1_800_000_000.0  # a fixed UTC instant


class _Clock:
    def __init__(self, t: float = DAY0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _tracker(budgets: dict, reports: list | None = None, fail_report: bool = False, clock=None):
    reports = reports if reports is not None else []
    calls = {"fetch": []}

    def fetch(user):
        calls["fetch"].append(user)
        if user not in budgets:
            raise ConnectionError("webapp down")
        return budgets[user]

    def report(counts):
        if fail_report:
            raise ConnectionError("webapp down")
        reports.append(counts)

    t = BudgetTracker(fetch=fetch, report=report, clock=clock or _Clock(), background=False)
    return t, calls, reports


def test_budget_refused_when_exhausted():
    t, _, _ = _tracker({"alice": (2, 1)})
    t.consume("alice", "alice")
    with pytest.raises(LlmBudgetExhausted) as err:
        t.consume("alice", "alice")
    assert err.value.code == "llm_budget_exhausted"
    assert err.value.no_retry is True
    assert err.value.limit == 2


def test_unlimited_never_refuses():
    t, _, _ = _tracker({"alice": (None, 10_000)})
    for _ in range(50):
        t.consume("alice", "alice")


def test_the_stricter_of_actor_and_owner_refuses():
    # A collaborator with budget left, on an owner with none left: refused (the owner's).
    t, _, _ = _tracker({"owner": (5, 5), "bob": (100, 0)})
    with pytest.raises(LlmBudgetExhausted) as err:
        t.consume("owner", "bob")
    assert err.value.user_id == "owner"
    assert "project owner" in str(err.value)
    # And the other way round: the owner has room, the actor has none.
    t, _, _ = _tracker({"owner": (100, 0), "bob": (1, 1)})
    with pytest.raises(LlmBudgetExhausted) as err:
        t.consume("owner", "bob")
    assert err.value.user_id == "bob"


def test_a_call_is_counted_once_for_the_actor():
    t, _, reports = _tracker({"owner": (100, 0), "bob": (100, 0)})
    t.consume("owner", "bob")
    t.consume("owner", "bob")
    t.maybe_report(force=True)
    assert reports == [[{"userId": "bob", "day": llm_budget.utc_day(DAY0), "count": 2}]]


def test_usage_reported_at_most_every_minute_and_attributed():
    clock = _Clock()
    t, _, reports = _tracker({"alice": (None, 0)}, clock=clock)
    t.consume("alice", "alice")
    assert reports == []
    clock.t += 61
    t.consume("alice", "alice")
    assert reports == [[{"userId": "alice", "day": llm_budget.utc_day(DAY0), "count": 2}]]
    assert t.pending() == {}


def test_a_failed_report_keeps_the_counts_for_the_next():
    clock = _Clock()
    t, _, _ = _tracker({"alice": (None, 0)}, fail_report=True, clock=clock)
    t.consume("alice", "alice")
    t.maybe_report(force=True)
    assert t.pending() == {("alice", llm_budget.utc_day(DAY0)): 1}


def test_counts_since_the_read_are_added_to_the_stored_count():
    clock = _Clock()
    t, calls, _ = _tracker({"alice": (3, 1)}, clock=clock)
    t.consume("alice", "alice")
    t.consume("alice", "alice")
    with pytest.raises(LlmBudgetExhausted):
        t.consume("alice", "alice")
    assert calls["fetch"] == ["alice"]  # cached for a minute


def test_the_budget_is_read_again_after_its_minute():
    clock = _Clock()
    budgets = {"alice": (5, 0)}
    t, calls, _ = _tracker(budgets, clock=clock)
    t.consume("alice", "alice")
    budgets["alice"] = (5, 5)  # another copy of the agent spent the rest
    clock.t += 61
    with pytest.raises(LlmBudgetExhausted):
        t.consume("alice", "alice")
    assert calls["fetch"] == ["alice", "alice"]


def test_a_new_utc_day_starts_again():
    clock = _Clock()
    budgets = {"alice": (1, 0)}
    t, _, _ = _tracker(budgets, clock=clock)
    t.consume("alice", "alice")
    with pytest.raises(LlmBudgetExhausted):
        t.consume("alice", "alice")
    clock.t += 86_400
    budgets["alice"] = (1, 0)
    t.consume("alice", "alice")


def test_an_unreadable_budget_lets_the_call_through_logged(caplog):
    t, _, _ = _tracker({})
    with caplog.at_level("WARNING"):
        t.consume("alice", "alice")
    assert "[rbac] llm_budget_unreadable" in caplog.text


def test_no_person_no_count():
    t, calls, _ = _tracker({})
    t.consume("", "")
    assert calls["fetch"] == []


def test_the_refusal_is_never_retried_as_transient():
    from orchestrator_helpers.llm_retry import is_transient_llm_error
    exc = LlmBudgetExhausted("alice", 5, "yours")
    assert is_transient_llm_error(exc) is False
    for phrase in ("timeout", "connection", "503", "502"):
        assert phrase not in str(exc).lower()


def test_the_existing_daily_caps_still_apply():
    """llm_guard's per-user cap refuses on its own, whatever the instance budget says."""
    import llm_guard
    cap = llm_guard._DailyCap(2)
    assert cap.allow("alice") and cap.allow("alice")
    assert cap.allow("alice") is False


# ---------------------------------------------------------------------------
# the callback on models built from an instance row
# ---------------------------------------------------------------------------

INST = {"id": "inst-1", "providerType": "instance", "instanceProviderType": "openai",
        "apiKey": "sk-inst", "userId": "owner-1"}


def test_an_instance_model_carries_the_budget_check_and_an_own_model_does_not():
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        chat_openai.side_effect = lambda **_kw: MagicMock(callbacks=None)
        inst = llm_setup.setup_llm("instance/inst-1/gpt-5", custom_llm_config=INST)
        own = llm_setup.setup_llm("gpt-5", openai_api_key="sk-own")
    handlers = [h for h in inst.callbacks if isinstance(h, llm_budget.InstanceBudgetCallback)]
    assert len(handlers) == 1 and handlers[0].owner_id == "owner-1" and handlers[0].raise_error is True
    assert not [h for h in (own.callbacks or []) if isinstance(h, llm_budget.InstanceBudgetCallback)]


def test_the_callback_takes_the_run_person_as_actor_and_raises_the_refusal():
    t, _, reports = _tracker({"owner-1": (100, 0), "bob": (0, 0)})
    llm_budget.set_tracker_for_tests(t)
    try:
        cb = llm_budget.InstanceBudgetCallback("owner-1", "inst-1")
        with pytest.raises(LlmBudgetExhausted):
            cb.on_chat_model_start({}, [[]], run_id="r1", metadata={"user_id": "bob", "tenant_user_id": "owner-1"})
        cb.on_chat_model_start({}, [[]], run_id="r2", metadata={})  # no run: the owner is the actor
        t.maybe_report(force=True)
        assert reports == [[{"userId": "owner-1", "day": llm_budget.utc_day(DAY0), "count": 1}]]
    finally:
        llm_budget.set_tracker_for_tests(None)


def test_a_real_chat_model_refuses_before_any_request():
    """Through LangChain's callback manager: raise_error makes the refusal stop the call."""
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
    t, _, _ = _tracker({"owner-1": (0, 0)})
    llm_budget.set_tracker_for_tests(t)
    try:
        model = llm_budget.attach_instance_budget(FakeListChatModel(responses=["hi"]), "owner-1", "inst-1")
        with pytest.raises(LlmBudgetExhausted):
            model.invoke("hello")
    finally:
        llm_budget.set_tracker_for_tests(None)
