"""Check all pipeline branches use the shared OpenAPI stage."""
import ast
from pathlib import Path
from unittest.mock import Mock


def test_full_pipeline_has_three_openapi_entrypoints_and_persists(tmp_path, monkeypatch):
    path = Path(__file__).parents[1] / 'main.py'
    tree = ast.parse(path.read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == '_maybe_run_openapi']
    assert len(calls) == 3
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_maybe_run_openapi')
    runner = Mock(side_effect=lambda result, settings, *, pacer=None: {**result, 'openapi': {'operations': []}})
    monkeypatch.setattr('recon.main_recon_modules.openapi_recon.run_openapi_recon', runner)
    save = Mock()
    import graph_db
    graph = Mock()
    graph.update_graph_from_openapi.return_value = {'operations_imported': 0, 'errors': []}
    context = Mock()
    context.__enter__ = Mock(return_value=graph)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(graph_db, 'Neo4jClient', lambda: context)
    namespace = {'Path': Path, 'run_openapi_recon': runner, 'save_recon_file': save,
                 'USER_ID': 'fixture-user', 'PROJECT_ID': 'fixture-project'}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
    result = namespace['_maybe_run_openapi']({}, {'OPENAPI_ENABLED': True}, tmp_path / 'out.json')
    assert result['metadata']['modules_executed'] == ['openapi']
    graph.update_graph_from_openapi.assert_called_once_with(result, 'fixture-user', 'fixture-project')
    assert result['metadata']['openapi_graph_updated'] is True
    save.assert_called_once()

    graph.update_graph_from_openapi.return_value = {'operations_imported': 0, 'errors': ['fixture-private-error']}
    failed = namespace['_maybe_run_openapi']({}, {'OPENAPI_ENABLED': True}, tmp_path / 'out.json')
    assert failed['metadata']['openapi_graph_updated'] is False
    assert failed['metadata']['openapi_graph_stats']['error_count'] == 1
    assert 'fixture-private-error' not in str(failed)


    batch_settings = {'OPENAPI_ENABLED': True, 'DOMAIN_BATCH_MODE': True,
                      'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [],
                      'DOMAIN_BATCH_GROUPS': [{'rootDomain': 'example.com', 'prefixes': ['api.']}]}
    namespace['_maybe_run_openapi']({'domain': 'example.com'}, batch_settings, tmp_path / 'batch.json')
    assert runner.call_args.args[1]['TARGET_DOMAIN'] == 'example.com'
    assert runner.call_args.args[1]['SUBDOMAIN_LIST'] == ['api.']
    assert batch_settings['TARGET_DOMAIN'] == ''

def test_partial_dispatch_calls_shared_runner():
    path = Path(__file__).parents[1] / 'partial_recon.py'
    assert 'run_openapi_partial(config)' in path.read_text()
    from recon.partial_recon_modules.openapi_recon import run_openapi_partial
    assert callable(run_openapi_partial)


def test_partial_uses_stored_scope_and_shared_graph_writer(monkeypatch):
    import graph_db
    import recon.project_settings
    import recon.main_recon_modules.openapi_recon as runner_module
    from recon.partial_recon_modules.openapi_recon import run_openapi_partial

    settings = {'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': ['api.'],
                'AUTH_PROFILE': {'authType': 'bearer', 'authValue': 'fixture-session'},
                'OPENAPI_SOURCES': [{'url': 'https://docs.example.com/spec'}]}
    monkeypatch.setattr(recon.project_settings, 'get_settings', lambda: settings)
    monkeypatch.setenv('USER_ID', 'fixture-user')
    monkeypatch.setenv('PROJECT_ID', 'fixture-project')
    captured = []

    def runner(data, config, *, pacer=None):
        captured.append((data, config))
        data['openapi'] = {'operations': []}
        return data

    monkeypatch.setattr(runner_module, 'run_openapi_recon', runner)
    client = Mock()
    client.update_graph_from_openapi.return_value = {'errors': []}
    context = Mock()
    context.__enter__ = Mock(return_value=client)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(graph_db, 'Neo4jClient', lambda: context)
    run_openapi_partial({'domain': 'unrelated.test', 'include_graph_targets': False,
                        'user_targets': {'urls': ['https://unrelated.test']}})
    data, config = captured[0]
    assert data['domain'] == config['TARGET_DOMAIN'] == 'example.com'
    assert config['OPENAPI_SOURCES'] == settings['OPENAPI_SOURCES']
    assert config['AUTH_PROFILE'] == settings['AUTH_PROFILE']
    assert 'OPENAPI_ENABLED' not in settings
    client.update_graph_from_openapi.assert_called_once_with(data, 'fixture-user', 'fixture-project')

    captured.clear()
    settings.update({'TARGET_DOMAIN': '', 'DOMAIN_BATCH_MODE': True, 'DOMAIN_BATCH_GROUPS': [
        {'rootDomain': 'example.com', 'prefixes': ['api.']},
        {'rootDomain': 'example.net', 'prefixes': ['.']},
    ]})
    run_openapi_partial({'include_graph_targets': False})
    assert [(config['TARGET_DOMAIN'], config['SUBDOMAIN_LIST']) for _, config in captured] == [
        ('example.com', ['api.']), ('example.net', ['.'])]


def test_partial_recon_cannot_override_stealth(monkeypatch):
    import recon.project_settings
    import recon.main_recon_modules.openapi_recon as runner_module
    from recon.partial_recon_modules.openapi_recon import run_openapi_partial

    monkeypatch.setattr(recon.project_settings, 'get_settings', lambda: {'STEALTH_MODE': True})
    runner = Mock()
    monkeypatch.setattr(runner_module, 'run_openapi_recon', runner)
    run_openapi_partial({'include_graph_targets': False})
    runner.assert_not_called()


def test_partial_honors_prevalidated_roots_and_settings(monkeypatch):
    import recon.project_settings
    import recon.main_recon_modules.openapi_recon as runner_module
    import recon.partial_recon_modules.graph_builders as builders
    from recon.partial_recon_modules.openapi_recon import run_openapi_partial

    settings = {'DOMAIN_BATCH_MODE': True, 'UPDATE_GRAPH_DB': False,
                'DOMAIN_BATCH_GROUPS': [
                    {'rootDomain': 'allowed.test', 'prefixes': ['api.']},
                    {'rootDomain': 'refused.test', 'prefixes': ['.']},
                ]}
    monkeypatch.setattr(recon.project_settings, 'get_settings', Mock(return_value=settings))
    monkeypatch.setenv('USER_ID', 'fixture-user')
    monkeypatch.setenv('PROJECT_ID', 'fixture-project')
    builder = Mock(side_effect=lambda domain, *args, **kwargs: {'domain': domain})
    monkeypatch.setattr(builders, '_build_http_probe_data_from_graph', builder)
    scanned = []

    def runner(data, settings, *, pacer=None):
        scanned.append(settings['TARGET_DOMAIN'])
        data['openapi'] = {'operations': []}

    monkeypatch.setattr(runner_module, 'run_openapi_recon', runner)
    groups = [{'rootDomain': 'allowed.test', 'prefixes': ['api.'], 'batch': True}]
    run_openapi_partial({'_settings': settings, 'domains': ['allowed.test'],
                        'domain_groups': groups})
    assert scanned == ['allowed.test']
    recon.project_settings.get_settings.assert_not_called()
    assert builder.call_args.kwargs['domain_groups'] == groups
