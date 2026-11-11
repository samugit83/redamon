"""One request clock per scan paces every OpenAPI fetch, and a Domain batch splits its sources by group.

A batch runs its groups one after another in one process, and a partial run
walks its roots the same way: the RoE ceiling holds across all of them because
the clock is process-wide (D11). A new scan is a new process; _reset_pacer()
stands in for it here. Each configured source is fetched and reported by the
one group whose scope allows it (D18), so the canonical file adds the groups
up instead of repeating or contradicting them.
"""

import pytest

from recon.helpers.openapi.discovery import _reset_pacer, run_openapi_discovery

ROOTS = ('one.example.test', 'two.example.test')


@pytest.fixture(autouse=True)
def _fresh_pacer():
    _reset_pacer()
    yield
    _reset_pacer()


@pytest.fixture
def clock_and_requests(monkeypatch):
    now = [100.0]
    calls = []

    class Response:
        status_code = 200
        headers = {}

        def iter_content(self, chunk_size):
            yield b'{"openapi":"3.1.0","info":{"title":"fixture","version":"1"},"paths":{}}'

        def close(self):
            pass

    def get(self, url, **kwargs):
        calls.append((url, now[0]))
        return Response()

    monkeypatch.setattr('requests.Session.get', get)
    monkeypatch.setattr('recon.helpers.openapi.fetch.time.monotonic', lambda: now[0])
    monkeypatch.setattr('recon.helpers.openapi.fetch.time.sleep',
                        lambda delay: now.__setitem__(0, now[0] + delay))
    return now, calls


def settings(extra_sources=()):
    return {
        'DOMAIN_BATCH_MODE': True, 'ROE_ENABLED': True, 'ROE_GLOBAL_MAX_RPS': 1,
        'UPDATE_GRAPH_DB': False,
        'DOMAIN_BATCH_GROUPS': [{'rootDomain': root, 'prefixes': ['.']} for root in ROOTS],
        'OPENAPI_SOURCES': [{'id': root, 'url': f'https://{root}/spec'} for root in ROOTS]
                           + list(extra_sources),
    }


def test_sequential_groups_share_one_clock_and_a_new_scan_starts_a_new_one(clock_and_requests):
    _, calls = clock_and_requests
    config = settings()
    for root in ROOTS:
        payload = run_openapi_discovery({'domain': root}, config, [])
        # D18: each group fetches only the source its own scope allows.
        assert [d['url'] for d in payload['documents']] == [f'https://{root}/spec']
    assert [stamp for _, stamp in calls] == [100.0, 101.0]
    _reset_pacer()
    run_openapi_discovery({'domain': ROOTS[0]}, config, [])
    assert [stamp for _, stamp in calls] == [100.0, 101.0, 101.0]


def test_partial_batch_paces_its_roots_on_the_same_clock(monkeypatch, clock_and_requests):
    from recon.partial_recon_modules.openapi_recon import run_openapi_partial
    monkeypatch.setattr('recon.project_settings.get_settings', settings)
    # Isolate the request ceiling from the separate inter-root pause.
    monkeypatch.setattr('recon.partial_recon_modules.helpers.ROOT_PAUSE_S', 0)
    monkeypatch.setenv('USER_ID', 'fixture-user')
    monkeypatch.setenv('PROJECT_ID', 'fixture-project')
    _, calls = clock_and_requests
    run_openapi_partial({'domains': list(ROOTS), 'include_graph_targets': False})
    assert [url for url, _ in calls] == [f'https://{root}/spec' for root in ROOTS]
    assert [stamp for _, stamp in calls] == [100.0, 101.0]


def test_a_source_no_group_allows_is_reported_once_by_the_first_group(clock_and_requests):
    _, calls = clock_and_requests
    config = settings([{'id': 'stray', 'url': 'https://elsewhere.example.org/spec'}])
    first = run_openapi_discovery({'domain': ROOTS[0]}, config, [])
    second = run_openapi_discovery({'domain': ROOTS[1]}, config, [])
    assert [s.split('|')[:3:2] for s in first['source_status']] == [[ROOTS[0], 'ok'], ['stray', 'out_of_scope']]
    assert [s.split('|')[:3:2] for s in second['source_status']] == [[ROOTS[1], 'ok']]
    assert [d['code'] for d in second['diagnostics']] == []
    assert 'https://elsewhere.example.org/spec' not in [url for url, _ in calls]


def test_a_run_that_is_not_a_batch_group_fetches_nothing(clock_and_requests):
    _, calls = clock_and_requests
    payload = run_openapi_discovery({'domain': 'unlisted.example.test'}, settings(), [])
    assert calls == []
    assert [d['code'] for d in payload['diagnostics']] == ['invalid_scope']


def test_group_inventories_add_up_in_the_canonical_file(tmp_path):
    from recon.helpers.output_paths import _merge_group_into
    from recon.helpers.resource_enum import build_openapi_inventory
    merged = {}
    for root in ROOTS:
        payload = {'documents': [{'url': f'https://{root}/spec'}], 'source_status': [f'{root}|h|ok|t'],
                   'requests': [{'url': f'https://{root}/spec'}], 'diagnostics': [], 'skipped_servers': []}
        group = {'resource_enum': {'openapi': build_openapi_inventory(
            {'domain': root}, payload, {'openapi_operations': 3, 'openapi_new': 2})}}
        _merge_group_into(merged, group)
    inventory = merged['resource_enum']['openapi']
    assert [g['root'] for g in inventory['groups']] == list(ROOTS)
    assert sum(g['operations_count'] for g in inventory['groups']) == 6
    assert [s.split('|')[0] for s in inventory['source_status']] == list(ROOTS)
    assert len(inventory['requests']) == 2


def test_shared_clock_keeps_fetcher_caches_and_budgets_separate(clock_and_requests):
    from recon.helpers.openapi.fetch import Fetcher, RequestPacer
    pacer = RequestPacer(1)
    first = Fetcher(max_requests=1, pacer=pacer)
    second = Fetcher(max_requests=1, pacer=pacer)
    _, calls = clock_and_requests
    url = 'https://one.example.test/spec'
    try:
        first.fetch(url, {}, 'https://one.example.test')
        first.fetch(url, {}, 'https://one.example.test')
        second.fetch(url, {}, 'https://one.example.test')
        assert first.count == second.count == 1
        assert [stamp for _, stamp in calls] == [100.0, 101.0]
    finally:
        first.close()
        second.close()


def test_shared_clock_wait_does_not_eat_next_groups_document_deadline(clock_and_requests):
    # The next group queues for its slot on the shared clock, then fetches with
    # its whole timeout: a queue behind other requesters is not a slow server.
    from recon.helpers.openapi.fetch import Fetcher, RequestPacer
    pacer = RequestPacer(0.1)
    first = Fetcher(timeout=1, pacer=pacer)
    second = Fetcher(timeout=1, pacer=pacer)
    now, calls = clock_and_requests
    try:
        first.fetch('https://one.example.test/spec', {}, 'https://one.example.test')
        second.fetch('https://two.example.test/spec', {}, 'https://two.example.test')
        assert [stamp for _, stamp in calls] == [100.0, 110.0]
        assert second.count == 1
    finally:
        first.close()
        second.close()
