"""
A daily budget on instance LLM providers (step 6.11, GV-12) that refuses the
scope guardrail's model call ends the session in the budget's own words, not
the Agent in the Loop's (the S5 red P6-09).

`LlmBudgetExhausted` carries `no_retry` like the loop's errors, so the
guardrail's "not answered" branch, written for the loop, took it and told the
person their external agent had not answered. Both still fail closed: the
session is blocked and the model is never asked again.
"""
import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from agent_in_the_loop.errors import LoopStepNotAnswered  # noqa: E402
from llm_budget import LlmBudgetExhausted  # noqa: E402

node = importlib.import_module('orchestrator_helpers.nodes.initialize_node')

DOMAINS = ['example.com']


class FakeLLM:
    """Raises `error` on every call, counting the calls."""

    def __init__(self, error):
        self.error, self.calls = error, 0

    async def ainvoke(self, messages):
        self.calls += 1
        raise self.error


def _guardrail(error):
    llm = FakeLLM(error)
    token = ps._settings_ctx.set({'IP_MODE': False, 'DOMAIN_BATCH_MODE': False})
    try:
        with patch.object(ps, 'soft_guardrail_names', return_value=DOMAINS):
            update = asyncio.run(node._run_scope_guardrail(llm, 'u1', 'p1', 's1'))
    finally:
        ps._settings_ctx.reset(token)
    return update, llm


def _text(update):
    return update['messages'][0].content


class TestABudgetRefusal:
    def test_names_the_budget_in_its_own_words(self):
        exc = LlmBudgetExhausted('u1', 2, 'yours')
        update, llm = _guardrail(exc)
        assert update['_guardrail_blocked'] is True and update['task_complete'] is True
        assert str(exc) in _text(update)
        assert 'The daily budget of 2 model calls on instance LLM providers is used up (yours)' in _text(update)
        assert update['completion_reason'] == node.LLM_BUDGET_GUARDRAIL_REFUSED
        assert llm.calls == 1  # never retried

    def test_is_not_reported_as_the_external_agent(self):
        update, _ = _guardrail(LlmBudgetExhausted('u1', 2, 'yours'))
        assert 'Agent in the Loop' not in _text(update)
        assert 'external agent' not in _text(update)
        assert 'Drive my RedAmon session' not in _text(update)
        assert update['completion_reason'] != node.LOOP_GUARDRAIL_NO_ANSWER

    def test_the_owners_budget_says_whose(self):
        update, _ = _guardrail(LlmBudgetExhausted('owner-1', 5, "the project owner's"))
        assert "used up (the project owner's)" in _text(update)

    def test_carries_no_account_id(self):
        update, _ = _guardrail(LlmBudgetExhausted('acct-7f3e', 2, 'yours'))
        assert 'acct-7f3e' not in _text(update)
        assert 'acct-7f3e' not in update['completion_reason']


class TestTheOtherRefusalsKeepTheirWords:
    def test_a_loop_step_not_answered_still_names_the_external_agent(self):
        update, llm = _guardrail(LoopStepNotAnswered())
        assert update['_guardrail_blocked'] is True
        assert update['completion_reason'] == node.LOOP_GUARDRAIL_NO_ANSWER
        assert 'Agent in the Loop' in _text(update) and '(loop_step_not_answered)' in _text(update)
        assert llm.calls == 1

    def test_a_provider_error_is_still_a_failed_check(self):
        # Not a transient phrase, so the guardrail raises it on the first try.
        update, _ = _guardrail(ValueError('model rejected the request'))
        assert update['_guardrail_blocked'] is True
        assert 'Scope Guardrail: Check Failed' in _text(update)
        assert 'model rejected the request' in _text(update)
