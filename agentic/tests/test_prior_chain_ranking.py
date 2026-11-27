"""Hermetic episodic-memory ranking and tenant-scoped retrieval tests."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import orchestrator_helpers.chain_graph_writer as cg
from state import format_prior_chains

NOW = datetime(2026, 1, 31, tzinfo=timezone.utc)


def chain(identifier, days=0, **fields):
    return dict(chain_id=identifier, created_at=NOW - timedelta(days=days), **fields)


def ranked(chains, tech=None, path=None, now=NOW):
    return [c['chain_id'] for c in cg.rank_prior_chains(
        chains, current_tech=tech or set(), current_attack_path=path, now=now)]


def test_technology_and_service_relevance_beats_recency():
    chains = [chain('new', status='completed'),
              chain('old', 10, technologies=[' NGINX ', 'nginx'], services=['SSH'])]
    assert ranked(chains, {'nginx', 'ssh'}) == ['old', 'new']
    assert chains[0]['chain_id'] == 'new'


def test_attack_path_match():
    assert ranked([chain('new'), chain('old', 10, attack_path_type='xss')],
                  path='xss') == ['old', 'new']


def test_injected_clock_and_thirty_day_half_life():
    chains = [chain('old', 30, technologies=['nginx', 'ssh']),
              chain('new', technologies=['nginx'], status='completed')]
    assert ranked(chains, {'nginx', 'ssh'}, now=NOW - timedelta(days=30)) == ['old', 'new']
    assert ranked(chains, {'nginx', 'ssh'}) == ['new', 'old']


def test_success_bonus():
    assert ranked([chain('a'), chain('b', status='completed')], path='xss') == ['b', 'a']


def test_stable_date_and_id_ties():
    chains = [chain('b'), chain('old', 1), chain('a')]
    assert ranked(chains, {'nginx'}) == ['a', 'b', 'old']
    assert ranked(list(reversed(chains)), {'nginx'}) == ['a', 'b', 'old']


def test_without_signal_uses_recency_even_for_success():
    assert ranked([chain('old', 1, status='completed'), chain('new')]) == ['new', 'old']


def test_query_keeps_tenant_scope_ranks_pool_and_limits():
    lesson = 'Check the service before retrying.'
    rows = [chain('new'), chain('relevant', 1, technologies=['nginx'],
                                failures=[dict(lesson=lesson)])]
    session = mock.MagicMock()
    session.run.return_value = rows
    with mock.patch.object(cg, '_get_driver') as driver, \
            mock.patch.object(cg, '_session') as session_factory:
        session_factory.return_value.__enter__.return_value = session
        result = cg.query_prior_chains('bolt://unused', 'neo4j', 'pw',
                                      'tenant-test', 'project-test', 'current',
                                      limit=1, current_tech={'nginx'})
    session_factory.assert_called_once_with(driver.return_value)
    query, params = session.run.call_args.args
    assert '{user_id: $user_id, project_id: $project_id}' in query
    assert 'ac.chain_id <> $current_chain_id' in query
    assert "ac.status IN ['completed', 'aborted']" in query
    assert params == dict(user_id='tenant-test', project_id='project-test',
                          current_chain_id='current', limit=4)
    assert [c['chain_id'] for c in result] == ['relevant']
    assert lesson in format_prior_chains(result)


def test_query_pool_is_capped():
    session = mock.MagicMock()
    session.run.return_value = []
    with mock.patch.object(cg, '_get_driver'), mock.patch.object(cg, '_session') as factory:
        factory.return_value.__enter__.return_value = session
        assert cg.query_prior_chains('bolt://unused', 'neo4j', 'pw', 't', 'p', 'c', limit=20) == []
    assert session.run.call_args.args[1]['limit'] == 40
