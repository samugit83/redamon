"""
The agent's session-start hard guardrail, driven through initialize_node itself.

project_settings.guardrail_names() is unit-tested on its own; this pins that the
node actually uses it. The node used to loop over the batch group roots only, so
a host under a multi-label government name that groups under an unblocked root
(www.isa.org.jm under org.jm) started a session.
"""
import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# The package re-exports the function under the module's name; take the module.
node = importlib.import_module('orchestrator_helpers.nodes.initialize_node')

CONFIG = {'configurable': {'user_id': 'u1', 'project_id': 'p1', 'thread_id': 's1'}}


def _settings(**values):
    def _impl(key, default=None):
        return values.get(key, default)
    return _impl


def _run(**settings):
    fake = _settings(**settings)
    with patch('project_settings.get_setting', fake), patch.object(node, 'get_setting', fake):
        return asyncio.run(node.initialize_node({}, CONFIG, llm=MagicMock(), neo4j_creds=('bolt://x', 'u', 'p')))


def test_a_batch_host_under_an_unblocked_root_ends_the_session_and_names_the_host():
    result = _run(
        DOMAIN_BATCH_MODE=True,
        DOMAIN_BATCH_GROUPS=[
            {'rootDomain': 'example.com', 'prefixes': ['www.'], 'hosts': ['www.example.com']},
            {'rootDomain': 'org.jm', 'prefixes': ['www.isa.'], 'hosts': ['www.isa.org.jm']},
        ],
        AGENT_GUARDRAIL_ENABLED=False,
    )
    assert result['_guardrail_blocked'] is True
    assert result['task_complete'] is True
    assert '`www.isa.org.jm`' in result['messages'][0].content


def test_ip_mode_is_not_hard_blocked():
    result = _run(
        IP_MODE=True, TARGET_IPS=['192.0.2.10'],
        DOMAIN_BATCH_MODE=True,
        DOMAIN_BATCH_GROUPS=[{'rootDomain': 'gov.uk', 'hosts': ['www.agency.gov.uk']}],
        AGENT_GUARDRAIL_ENABLED=False,
    )
    assert not result.get('_guardrail_blocked')


# --- Scope groups, AGT-10, AGT-11 and B-35 ------------------------------------

from unittest.mock import AsyncMock  # noqa: E402

import scope_groups as sg  # noqa: E402


def _group(root, mode='enumerate', exact=(), org=None):
    return {'scanRoot': root, 'orgDomain': org or root, 'mode': mode, 'includeRoot': False,
            'exactHosts': list(exact), 'entries': [f'*.{root}'] if mode == 'enumerate' else list(exact),
            'notes': []}


def _webapp(groups, **extra):
    parsed, source, dropped = sg.scope_groups_from_project({'scopeGroups': groups})
    return {'SCOPE_GROUPS': parsed, 'SCOPE_GROUPS_SOURCE': source, 'SCOPE_GROUPS_DROPPED': dropped,
            'DOMAIN_BATCH_MODE': True, '_SETTINGS_SOURCE': 'api', **extra}


SAFE = [_group('example.com'), _group('acme.test', mode='exact', exact=['www.acme.test'])]
TRACE = [{'step_id': 's1'}]


def _run_state(state, soft=None, **settings):
    """initialize_node on `state`; `soft` replaces the LLM guardrail check."""
    fake = _settings(**settings)
    soft = soft or AsyncMock(return_value={'allowed': True, 'reason': 'ok'})
    with patch('project_settings.get_setting', fake), patch.object(node, 'get_setting', fake), \
         patch('orchestrator_helpers.guardrail.check_target_allowed', soft):
        result = asyncio.run(node.initialize_node(state, CONFIG, llm=MagicMock(), neo4j_creds=('bolt://x', 'u', 'p')))
    return result, soft


def _signature(groups):
    return sg.scope_signature(sg.parse_scope_groups(groups))


def test_a_blocked_exact_host_from_the_scope_groups_ends_the_session():
    groups = SAFE + [_group('agency.gov.uk', mode='exact', exact=['portal.agency.gov.uk'])]
    result, _ = _run_state({}, **_webapp(groups, AGENT_GUARDRAIL_ENABLED=False))
    assert result['_guardrail_blocked'] is True
    assert '`portal.agency.gov.uk`' in result['messages'][0].content


def test_the_soft_guardrail_judges_orgs_and_scan_roots():
    groups = [_group('api.example.com', org='example.com')]
    result, soft = _run_state({}, **_webapp(groups, AGENT_GUARDRAIL_ENABLED=True))
    assert not result.get('_guardrail_blocked')
    assert soft.await_args.kwargs['target_domains'] == ['example.com', 'api.example.com']
    assert result['_scope_signature'] == _signature(groups)


def test_a_malformed_scope_group_refuses_even_with_the_soft_guardrail_off():
    result, _ = _run_state({}, **_webapp(SAFE + [_group('bad_label.test')], AGENT_GUARDRAIL_ENABLED=False))
    assert result['_guardrail_blocked'] is True
    assert 'Scope Unverifiable' in result['messages'][0].content


def test_a_batch_with_no_valid_group_refuses_even_with_the_soft_guardrail_off():
    result, _ = _run_state({}, **_webapp([], AGENT_GUARDRAIL_ENABLED=False))
    assert result['_guardrail_blocked'] is True


def test_settings_from_the_defaults_refuse_the_turn():
    # AGT-10: the defaults have no target, so every scope check would skip.
    result, soft = _run_state({}, **_webapp(SAFE, _SETTINGS_SOURCE='default'))
    assert result['_guardrail_blocked'] is True
    assert 'Project Settings Unavailable' in result['messages'][0].content
    assert result['_scope_signature'] == node._SETTINGS_UNAVAILABLE
    soft.assert_not_awaited()


def test_a_settings_refusal_is_lifted_once_the_settings_load():
    state = {'_guardrail_blocked': True, '_scope_signature': node._SETTINGS_UNAVAILABLE, 'execution_trace': TRACE}
    result, soft = _run_state(state, **_webapp(SAFE, AGENT_GUARDRAIL_ENABLED=True))
    assert result['_guardrail_blocked'] is False
    assert result['_scope_signature'] == _signature(SAFE)
    soft.assert_awaited_once()


def test_a_guardrail_block_is_not_lifted_by_a_later_turn():
    state = {'_guardrail_blocked': True, '_scope_signature': 'exact|old.test', 'execution_trace': TRACE}
    result, soft = _run_state(state, **_webapp(SAFE, AGENT_GUARDRAIL_ENABLED=True))
    assert result.get('_guardrail_blocked') is not False
    soft.assert_not_awaited()


def test_a_rescope_to_a_blocked_name_ends_a_running_session():
    # AGT-11: the new scope is judged as at session start, not inherited.
    state = {'_scope_signature': _signature(SAFE), 'execution_trace': TRACE}
    groups = SAFE + [_group('agency.gov.uk', mode='exact', exact=['portal.agency.gov.uk'])]
    result, _ = _run_state(state, **_webapp(groups, AGENT_GUARDRAIL_ENABLED=False))
    assert result['_guardrail_blocked'] is True
    assert result['task_complete'] is True
    assert result['_scope_signature'] == _signature(groups)


def test_a_rescope_reruns_the_soft_guardrail_and_an_unchanged_scope_does_not():
    state = {'_scope_signature': _signature(SAFE), 'execution_trace': TRACE}
    result, soft = _run_state(state, **_webapp(SAFE, AGENT_GUARDRAIL_ENABLED=True))
    soft.assert_not_awaited()
    assert result['_scope_signature'] == _signature(SAFE)

    wider = SAFE + [_group('other.test')]
    denied = AsyncMock(return_value={'allowed': False, 'reason': 'well-known company'})
    result, soft = _run_state(state, soft=denied, **_webapp(wider, AGENT_GUARDRAIL_ENABLED=True))
    soft.assert_awaited_once()
    assert result['_guardrail_blocked'] is True


def test_a_malformed_soft_verdict_blocks_at_session_start():
    # B-35: check_target_allowed raises on a verdict that is not a JSON boolean.
    broken = AsyncMock(side_effect=RuntimeError('no parseable JSON verdict'))
    result, _ = _run_state({}, soft=broken, **_webapp(SAFE, AGENT_GUARDRAIL_ENABLED=True))
    assert result['_guardrail_blocked'] is True
    assert 'Check Failed' in result['messages'][0].content

    truthy = AsyncMock(return_value={'allowed': 'false', 'reason': 'garbled'})
    result, _ = _run_state({}, soft=truthy, **_webapp(SAFE, AGENT_GUARDRAIL_ENABLED=True))
    assert result['_guardrail_blocked'] is True


# --- IP mode (design §10, I-2): the include entries get the hard guardrail ----

IP = {'IP_MODE': True, 'TARGET_IPS': ['192.0.2.10'], '_SETTINGS_SOURCE': 'api', 'AGENT_GUARDRAIL_ENABLED': False}


def test_ip_mode_checks_the_include_entries_and_a_blocked_one_ends_the_session():
    result, soft = _run_state({}, **IP, IP_HOSTNAME_MODE='record_filter',
                              IP_HOSTNAME_INCLUDE=['*.example.com', '*.agency.gov.uk'])
    assert result['_guardrail_blocked'] is True
    assert result['task_complete'] is True
    assert '`agency.gov.uk`' in result['messages'][0].content
    soft.assert_not_awaited()


def test_ip_mode_checks_the_include_entries_in_every_hostname_mode():
    # As the webapp and the orchestrator do: a rescope to record_filter would
    # scan under a list nobody wrote again.
    for mode in ('ip_only', 'record_only', 'scan_all'):
        result, _ = _run_state({}, **IP, IP_HOSTNAME_MODE=mode, IP_HOSTNAME_INCLUDE=['www.whitehouse.gov'])
        assert result['_guardrail_blocked'] is True, mode


def test_ip_mode_with_safe_include_entries_proceeds():
    result, _ = _run_state({}, **IP, IP_HOSTNAME_MODE='record_filter', IP_HOSTNAME_INCLUDE=['*.example.com'])
    assert not result.get('_guardrail_blocked')


def test_an_ip_mode_rescope_to_a_blocked_include_entry_ends_a_running_session():
    safe, _ = _run_state({}, **IP, IP_HOSTNAME_MODE='record_filter', IP_HOSTNAME_INCLUDE=['*.example.com'])
    state = {'_scope_signature': safe['_scope_signature'], 'execution_trace': TRACE}
    result, _ = _run_state(state, **IP, IP_HOSTNAME_MODE='record_filter',
                           IP_HOSTNAME_INCLUDE=['*.example.com', 'portal.agency.gov.uk'])
    assert result['_guardrail_blocked'] is True
    assert '`portal.agency.gov.uk`' in result['messages'][0].content
