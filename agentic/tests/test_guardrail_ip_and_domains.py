"""
The soft guardrail judges an IP-mode project's addresses AND the hostnames it
scans under, in two separate model calls (design §10, B-24).

check_target_allowed returned on the domain branch before reaching the IP one,
so a request carrying both judged the names only. Each list now gets its own
prompt (the IP prompt names the PTR hostnames, the domain prompt the include
bases). The second call is a model call site of its own: a loop model's
failure there is never retried and blocks the session like the first.

Own file: it imports api.py, which is heavy.
"""
import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from agent_in_the_loop.errors import LoopStepNotAnswered  # noqa: E402
from orchestrator_helpers import guardrail as g  # noqa: E402

node = importlib.import_module('orchestrator_helpers.nodes.initialize_node')

ALLOW = '{"allowed": true, "reason": "obscure"}'
BLOCK = '{"allowed": false, "reason": "a major company"}'
IPS = ['203.0.113.10']


class FakeLLM:
    """Answers each call from `answers` in order; an exception is raised."""

    def __init__(self, *answers):
        self.answers, self.prompts = list(answers), []

    async def ainvoke(self, messages):
        self.prompts.append(messages[-1].content)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return MagicMock(content=answer)


def _is_private(ip):
    # The documentation ranges count as private to `ipaddress`, which the IP
    # branch auto-allows without a model call; real public addresses would be
    # real target data. So 203.0.113.0/24 plays a public range here.
    return not ip.startswith('203.0.113.') and g.ipaddress.ip_address(ip.split('/')[0]).is_private


def _ip_branch_sees_public_addresses():
    return (patch.object(g, 'resolve_ips', return_value=['host.example.net']),
            patch.object(g, 'is_private_ip', side_effect=_is_private))


def _check(llm, **kw):
    ptr, private = _ip_branch_sees_public_addresses()
    with ptr, private:
        return asyncio.run(g.check_target_allowed(llm, **kw))


class TestBothAreJudged:
    def test_ips_then_names_each_in_its_own_call(self):
        llm = FakeLLM(ALLOW, ALLOW)
        assert _check(llm, target_ips=IPS, target_domains=['example.com', 'example.de'])['allowed'] is True
        assert len(llm.prompts) == 2
        assert 'Target IPs: 203.0.113.10' in llm.prompts[0] and 'host.example.net' in llm.prompts[0]
        assert 'Target domains: example.com, example.de' in llm.prompts[1]

    def test_a_blocked_name_blocks_after_allowed_addresses(self):
        result = _check(FakeLLM(ALLOW, BLOCK), target_ips=IPS, target_domain='example.com')
        assert result == {'allowed': False, 'reason': 'a major company'}

    def test_blocked_addresses_skip_the_name_call(self):
        llm = FakeLLM(BLOCK)
        assert _check(llm, target_ips=IPS, target_domains=['example.com'])['allowed'] is False
        assert len(llm.prompts) == 1

    def test_private_addresses_are_still_auto_allowed_and_the_names_judged(self):
        llm = FakeLLM(BLOCK)
        result = _check(llm, target_ips=['10.0.0.0/24'], target_domains=['example.com'])
        assert result['allowed'] is False
        assert len(llm.prompts) == 1 and 'Target domain: example.com' in llm.prompts[0]

    def test_domain_only_and_ip_only_requests_are_unchanged(self):
        llm = FakeLLM(ALLOW)
        assert _check(llm, target_domains=['example.com', 'example.de'])['allowed'] is True
        assert len(llm.prompts) == 1 and 'Target domains:' in llm.prompts[0]
        llm = FakeLLM(ALLOW)
        assert _check(llm, target_ips=IPS)['allowed'] is True
        assert len(llm.prompts) == 1 and 'Target IPs:' in llm.prompts[0]
        assert _check(FakeLLM(), target_ips=[]) == {'allowed': True, 'reason': 'No targets specified'}


class TestTheSecondCallHonoursNoRetry:
    def test_a_loop_failure_on_the_name_call_is_raised_once(self):
        llm = FakeLLM(ALLOW, LoopStepNotAnswered(), ALLOW, ALLOW)
        with pytest.raises(LoopStepNotAnswered):
            _check(llm, target_ips=IPS, target_domains=['example.com'])
        assert len(llm.prompts) == 2  # never retried

    def test_a_transient_error_on_the_name_call_is_still_retried(self):
        llm = FakeLLM(ALLOW, RuntimeError('upstream 503'), ALLOW)
        with patch.object(g.asyncio, 'sleep', AsyncMock()):
            assert _check(llm, target_ips=IPS, target_domains=['example.com'])['allowed'] is True
        assert len(llm.prompts) == 3

    def test_the_session_blocks_with_the_loop_reason(self):
        values = {'IP_MODE': True, 'TARGET_IPS': IPS, 'IP_HOSTNAME_MODE': 'record_filter',
                  'IP_HOSTNAME_INCLUDE': ['*.example.com'], 'IP_HOSTNAME_EXCLUDE': []}
        llm = FakeLLM(ALLOW, LoopStepNotAnswered())
        token = ps._settings_ctx.set(values)
        try:
            ptr, private = _ip_branch_sees_public_addresses()
            with ptr, private:
                update = asyncio.run(node._run_scope_guardrail(llm, 'u1', 'p1', 's1'))
        finally:
            ps._settings_ctx.reset(token)
        assert len(llm.prompts) == 2
        assert update['_guardrail_blocked'] is True
        assert update['completion_reason'] == node.LOOP_GUARDRAIL_NO_ANSWER


class TestTheSessionStartCall:
    def _run(self, **values):
        soft = AsyncMock(return_value={'allowed': True, 'reason': 'ok'})
        token = ps._settings_ctx.set({'IP_MODE': True, 'TARGET_IPS': IPS, **values})
        try:
            with patch('orchestrator_helpers.guardrail.check_target_allowed', soft):
                update = asyncio.run(node._run_scope_guardrail(MagicMock(), 'u1', 'p1', 's1'))
        finally:
            ps._settings_ctx.reset(token)
        return update, soft

    def test_record_filter_sends_the_include_bases_with_the_ips(self):
        update, soft = self._run(IP_HOSTNAME_MODE='record_filter',
                                 IP_HOSTNAME_INCLUDE=['*.example.com', 'shop.example.de', '*.example.com'])
        assert update is None
        assert soft.await_args.kwargs['target_ips'] == IPS
        assert soft.await_args.kwargs['target_domains'] == ['example.com', 'shop.example.de']

    @pytest.mark.parametrize('mode', ['ip_only', 'record_only', 'scan_all'])
    def test_the_other_modes_send_the_ips_alone(self, mode):
        # Only record_filter scans under the include entries; a stale list left
        # from an earlier policy must not cost a model call or block a session.
        _, soft = self._run(IP_HOSTNAME_MODE=mode, IP_HOSTNAME_INCLUDE=['*.example.com'])
        assert soft.await_args.kwargs['target_ips'] == IPS
        assert soft.await_args.kwargs['target_domains'] == []

    def test_an_unparsable_include_entry_is_left_to_the_hard_guardrail(self):
        _, soft = self._run(IP_HOSTNAME_MODE='record_filter', IP_HOSTNAME_INCLUDE=['*.example.com', '10.0.0.1'])
        assert soft.await_args.kwargs['target_domains'] == ['example.com']


class TestTheWebappEndpoint:
    """POST /guardrail/check-target passes both lists through; both are judged."""

    def test_a_request_with_ips_and_names_judges_both(self):
        import api

        llm = FakeLLM(ALLOW, BLOCK)
        with patch.object(api, 'orchestrator', MagicMock(_initialized=True)), \
             patch.object(api, '_build_llm_for_user', return_value=llm), \
             patch.object(g, 'resolve_ips', return_value=['host.example.net']), \
             patch.object(g, 'is_private_ip', side_effect=_is_private):
            result = asyncio.run(api.check_target_guardrail(api.GuardrailRequest(
                target_ips=IPS, target_domains=['example.com'], user_id='u1')))
        assert result['allowed'] is False
        assert len(llm.prompts) == 2
