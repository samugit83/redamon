"""Domain groups share an engagement clock without sharing fetch caches or budgets."""
import ast
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

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


def settings():
    return {
        'DOMAIN_BATCH_MODE': True, 'ROE_GLOBAL_MAX_RPS': 1,
        'UPDATE_GRAPH_DB': False,
        'DOMAIN_BATCH_GROUPS': [
            {'rootDomain': root, 'prefixes': ['.']}
            for root in ('one.example.test', 'two.example.test')
        ],
        'OPENAPI_SOURCES': [
            {'url': f'https://{root}/spec'}
            for root in ('one.example.test', 'two.example.test')
        ],
    }


def test_partial_batch_paces_groups_and_resets_for_next_scan(monkeypatch, clock_and_requests):
    from recon.partial_recon_modules.openapi_recon import run_openapi_partial
    monkeypatch.setattr('recon.project_settings.get_settings', settings)
    # Isolate the request ceiling from the separate inter-root pause.
    monkeypatch.setattr('recon.partial_recon_modules.helpers.ROOT_PAUSE_S', 0)
    monkeypatch.setenv('USER_ID', 'fixture-user')
    monkeypatch.setenv('PROJECT_ID', 'fixture-project')
    _, calls = clock_and_requests
    run_openapi_partial({'include_graph_targets': False})
    assert [stamp for _, stamp in calls] == [100.0, 101.0]
    run_openapi_partial({'include_graph_targets': False})
    assert [stamp for _, stamp in calls] == [100.0, 101.0, 101.0, 102.0]


def test_full_batch_paces_groups_and_resets_for_next_scan(tmp_path, clock_and_requests):
    path = Path(__file__).parents[1] / 'main.py'
    tree = ast.parse(path.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('run_domain_batch', '_maybe_run_openapi', '_eligible_batch_roots')]
    config = settings()
    namespace = {
        'Path': Path, 'datetime': datetime, '_settings': config,
        'VERIFY_DOMAIN_OWNERSHIP': False, '_seed_batch_root_domains': Mock(),
        'OUTPUT_DIR': tmp_path, 'PROJECT_ID': 'fixture-project',
        'clear_batch_outputs': Mock(return_value=0), 'initialize_batch_canonical': Mock(),
        'merge_batch_outputs': Mock(), 'save_recon_file': Mock(),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), namespace)

    def group(root, prefixes, start_time, openapi_pacer=None):
        result = namespace['_maybe_run_openapi'](
            {'domain': root}, config, tmp_path / 'out.json', pacer=openapi_pacer)
        assert len(result['openapi']['documents']) == 1
        return 0

    namespace['run_domain_group'] = group
    _, calls = clock_and_requests
    for _ in range(2):
        assert namespace['run_domain_batch'](config['DOMAIN_BATCH_GROUPS'], datetime.now()) == 0
    assert [stamp for _, stamp in calls] == [100.0, 101.0, 101.0, 102.0]


def test_full_pipeline_forwards_pacer_through_discovery_and_saved_recon():
    tree = ast.parse((Path(__file__).parents[1] / 'main.py').read_text())
    calls = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in ('run_domain_group', 'run_domain_recon'):
            calls.extend(call for call in ast.walk(node) if isinstance(call, ast.Call)
                         and isinstance(call.func, ast.Name)
                         and call.func.id in ('run_domain_recon', '_maybe_run_openapi'))
    assert len(calls) == 3
    for call in calls:
        keyword = 'pacer' if call.func.id == '_maybe_run_openapi' else 'openapi_pacer'
        assert any(arg.arg == keyword and isinstance(arg.value, ast.Name)
                   and arg.value.id == 'openapi_pacer' for arg in call.keywords)


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


def test_shared_clock_honors_next_groups_document_deadline(clock_and_requests):
    from recon.helpers.openapi.fetch import DocumentError, Fetcher, RequestPacer
    pacer = RequestPacer(0.1)
    first = Fetcher(timeout=1, pacer=pacer)
    second = Fetcher(timeout=1, pacer=pacer)
    now, calls = clock_and_requests
    try:
        first.fetch('https://one.example.test/spec', {}, 'https://one.example.test')
        with pytest.raises(DocumentError, match='deadline'):
            second.fetch('https://two.example.test/spec', {}, 'https://two.example.test')
        assert len(calls) == 1
        assert now[0] == 100.0
        assert second.count == 0
    finally:
        first.close()
        second.close()
