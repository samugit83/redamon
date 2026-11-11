"""
B-35: the soft guardrail's LLM verdict is parsed strictly.

`result.get("allowed", True)` read a missing key as "allowed", and
`bool("false")` is True, so a garbled answer allowed the target. Now only a
JSON boolean is a verdict. A malformed answer is retried, then raises: the
session start refuses on that (fail closed), and the webapp's soft check
endpoint reports the verdict as unknown and lets the save through (it is the
fail-open, user-disableable layer; the hard guardrail is the closed one).

Own file: it imports api.py, which is heavy.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator_helpers.guardrail import _invoke_guardrail, _parse_verdict  # noqa: E402


@pytest.mark.parametrize('raw', [
    None, '', 'not json', '[true]', '{"reason": "no verdict"}', '{"allowed": "false"}',
    '{"allowed": "true"}', '{"allowed": 1}', '{"allowed": null}',
])
def test_anything_but_a_json_boolean_is_no_verdict(raw):
    assert _parse_verdict(raw) is None


def test_a_boolean_verdict_is_kept():
    assert _parse_verdict('{"allowed": false, "reason": "major company"}') == {
        'allowed': False, 'reason': 'major company'}
    assert _parse_verdict('{"allowed": true}') == {'allowed': True, 'reason': 'No reason provided'}


def _llm(*contents):
    llm = MagicMock()
    llm.ainvoke = AsyncMock(side_effect=[MagicMock(content=c) for c in contents])
    return llm


def test_a_string_verdict_is_retried_then_raises():
    llm = _llm('{"allowed": "false"}', '{"allowed": "yes"}', '{"reason": "x"}')
    with pytest.raises(RuntimeError, match='no parseable JSON'):
        asyncio.run(_invoke_guardrail(llm, 'prompt'))
    assert llm.ainvoke.await_count == 3


def test_a_malformed_answer_then_a_real_verdict_uses_the_verdict():
    llm = _llm('{"allowed": "false"}', '{"allowed": false, "reason": "blocked"}')
    assert asyncio.run(_invoke_guardrail(llm, 'prompt')) == {'allowed': False, 'reason': 'blocked'}


def test_the_soft_webapp_check_reports_unknown_and_stays_open():
    import api

    orchestrator = MagicMock(_initialized=True)
    broken = AsyncMock(side_effect=RuntimeError('no parseable JSON verdict in any response'))
    # The check builds the named user's own client (RBAC HD-16), not orchestrator.llm.
    with patch.object(api, 'orchestrator', orchestrator), \
         patch.object(api, '_build_llm_for_user', return_value=MagicMock()), \
         patch('orchestrator_helpers.guardrail.check_target_allowed', broken):
        result = asyncio.run(api.check_target_guardrail(api.GuardrailRequest(target_domains=['example.com'])))
    assert result['allowed'] is True
    assert result['verdict'] == 'unknown'


def test_the_soft_webapp_check_still_runs_the_hard_guardrail_first():
    import api

    result = asyncio.run(api.check_target_guardrail(api.GuardrailRequest(target_domains=['example.com', 'gov.uk'])))
    assert result['allowed'] is False
    assert result['hard_blocked'] is True
