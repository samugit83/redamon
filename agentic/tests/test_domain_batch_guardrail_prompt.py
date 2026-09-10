"""
Domain batch F4: the soft guardrail must be asked about EVERY in-scope domain.

The regression: a batch project's roots were joined into one string and passed as
`target_domain`, which lands in GUARDRAIL_DOMAIN_PROMPT - "Target domain: {target}
... Should this target be allowed or blocked?". That is singular, and unlike the
IP prompt it carries no "block if ANY" instruction, so one aggregate verdict could
allow a set containing a domain that should have been refused.

These tests capture the prompt actually sent to the model and assert on it, so a
revert to the joined-string form is what goes red.

Run with: python -m pytest tests/test_domain_batch_guardrail_prompt.py
"""

import sys
from pathlib import Path

import pytest

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.guardrail import (  # noqa: E402
    GUARDRAIL_DOMAIN_PROMPT,
    GUARDRAIL_DOMAINS_PROMPT,
    check_target_allowed,
)


class RecordingLLM:
    """Captures the prompt and answers with a fixed verdict."""

    def __init__(self, verdict='{"allowed": true, "reason": "ok"}'):
        self.verdict = verdict
        self.prompts: list[str] = []

    async def ainvoke(self, messages):
        self.prompts.append(messages[-1].content)

        class R:
            content = self.verdict
        return R()

    @property
    def last(self) -> str:
        return self.prompts[-1]


@pytest.mark.asyncio
async def test_several_domains_use_the_plural_block_if_any_prompt():
    llm = RecordingLLM()
    await check_target_allowed(llm, target_domains=['a-corp.com', 'b-corp.it', 'c-corp.com'])

    assert len(llm.prompts) == 1
    # Every domain is named...
    for d in ('a-corp.com', 'b-corp.it', 'c-corp.com'):
        assert d in llm.last
    # ...and the model is told the set fails if any member fails.
    assert 'ANY' in llm.last
    assert llm.last.startswith(GUARDRAIL_DOMAINS_PROMPT.split('{')[0])


@pytest.mark.asyncio
async def test_the_singular_prompt_is_never_handed_a_list():
    # The exact defect: "Target domain: a.com, b.com" inside a prompt that asks
    # for one verdict about "this target".
    llm = RecordingLLM()
    await check_target_allowed(llm, target_domains=['a-corp.com', 'b-corp.it'])

    singular_header = GUARDRAIL_DOMAIN_PROMPT.split('{')[0]
    assert not llm.last.startswith(singular_header)
    assert 'Target domain: a-corp.com, b-corp.it' not in llm.last


@pytest.mark.asyncio
async def test_a_refusal_of_one_member_blocks_the_whole_batch():
    llm = RecordingLLM('{"allowed": false, "reason": "google.com is a major company"}')
    result = await check_target_allowed(
        llm, target_domains=['obscure-startup.io', 'google.com', 'tiny-shop.net'])

    assert result['allowed'] is False
    assert 'google.com' in result['reason']


@pytest.mark.asyncio
async def test_a_single_element_list_still_uses_the_singular_prompt():
    # No behaviour change for a one-group batch or a single-domain project.
    llm = RecordingLLM()
    await check_target_allowed(llm, target_domains=['only-one.com'])
    assert llm.last == GUARDRAIL_DOMAIN_PROMPT.format(target='only-one.com')


@pytest.mark.asyncio
async def test_single_domain_mode_is_untouched():
    llm = RecordingLLM()
    await check_target_allowed(llm, target_domain='classic.com')
    assert llm.last == GUARDRAIL_DOMAIN_PROMPT.format(target='classic.com')


@pytest.mark.asyncio
async def test_blank_and_whitespace_entries_are_dropped_not_sent():
    llm = RecordingLLM()
    await check_target_allowed(llm, target_domains=['  ', '', 'real.com', '   '])
    # One real domain survives -> singular prompt for exactly that domain.
    assert llm.last == GUARDRAIL_DOMAIN_PROMPT.format(target='real.com')


@pytest.mark.asyncio
async def test_ip_mode_is_unaffected_by_the_new_parameter():
    llm = RecordingLLM()
    result = await check_target_allowed(llm, target_ips=['10.0.0.1'], target_domains=[])
    # All-private IPs short-circuit without an LLM call, as before.
    assert result['allowed'] is True
    assert llm.prompts == []
