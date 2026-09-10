import copy
import json

import pytest

from recon.main_recon_modules.openapi_recon import run_openapi_recon, run_openapi_recon_isolated


class Response:
    def __init__(self, body, status=200, headers=None):
        self.content = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.status_code = status
        self.headers = headers or {}

    def iter_content(self, chunk_size):
        yield self.content

    def close(self):
        pass


def spec(**overrides):
    return {
        'openapi': '3.1.0', 'info': {'title': 'Fixture', 'version': '1'},
        'servers': [{'url': 'https://api.example.com/v2'}],
        'paths': {'/users/{id}': {'get': {'responses': {'200': {'description': 'OK'}}}}},
        **overrides,
    }


def run(monkeypatch, documents, settings=None, data=None):
    calls = []

    def get(self, url, **kwargs):
        calls.append((url, kwargs))
        return documents.get(url, Response('', 404))

    monkeypatch.setattr('requests.Session.get', get)
    config = {'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [],
              'OPENAPI_AUTO_DISCOVER': False,
              'OPENAPI_SOURCES': [{'url': 'https://docs.example.com/openapi.json'}]}
    config.update(settings or {})
    result = run_openapi_recon(data or {}, config)['openapi']
    return result, calls


def test_imports_declared_target_operation_without_probing(monkeypatch):
    result, calls = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(spec())})
    operation, = result['operations']
    assert (operation['baseurl'], operation['path'], operation['method']) == (
        'https://api.example.com', '/v2/users/{id}', 'GET')
    assert operation['source_url'] == 'https://docs.example.com/openapi.json'
    assert len(operation['document_hash']) == 64
    assert [url for url, _ in calls] == ['https://docs.example.com/openapi.json']


def test_scope_exclusions_and_filtered_subdomains(monkeypatch):
    doc = spec(servers=[{'url': f'https://{host}/v1'} for host in
               ['api.example.com', 'staging.example.com', 'example.com', 'example.com.evil.test']])
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)},
                    {'SUBDOMAIN_LIST': ['api.', 'staging.', '.'], 'ROE_ENABLED': True,
                     'ROE_EXCLUDED_HOSTS': ['staging.example.com']})
    assert {op['baseurl'] for op in result['operations']} == {'https://api.example.com', 'https://example.com'}
    assert len([d for d in result['diagnostics'] if d['code'] == 'out_of_scope']) == 2


def test_empty_target_fails_closed(monkeypatch):
    result, calls = run(monkeypatch, {}, {'TARGET_DOMAIN': ''})
    assert result['operations'] == []
    assert calls == []
    assert result['diagnostics'][0]['code'] == 'invalid_scope'


def test_server_precedence_and_parameter_security_overrides(monkeypatch):
    doc = spec(security=[{'bearer': []}], paths={'/users': {
        'servers': [{'url': '/path-base'}],
        'parameters': [{'name': 'id', 'in': 'query', 'schema': {'type': 'string'}}],
        'get': {'servers': [{'url': '/operation-base'}], 'security': [],
                'parameters': [{'name': 'id', 'in': 'query', 'schema': {'type': 'integer'}}],
                'responses': {'200': {'description': 'OK'}}},
        'post': {'requestBody': {'content': {'application/json': {'schema': {'type': 'object'}}}},
                 'responses': {'201': {'description': 'Created'}}}}})
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    get, post = sorted(result['operations'], key=lambda op: op['method'])
    assert get['path'] == '/operation-base/users'
    assert get['operation']['parameters'][0]['schema']['type'] == 'integer'
    assert get['operation']['security'] == []
    assert post['path'] == '/path-base/users'
    assert post['operation']['security'] == [{'bearer': []}]
    assert 'requestBody' in post['operation']


def test_swagger2_and_override(monkeypatch):
    doc = {'swagger': '2.0', 'info': {'title': 'Fixture', 'version': '1'},
           'schemes': ['https'], 'host': 'api.example.com', 'basePath': '/v1',
           'paths': {'/users': {'post': {'responses': {'200': {'description': 'OK'}}}}}}
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    assert result['operations'][0]['path'] == '/v1/users'
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)},
                    {'OPENAPI_SOURCES': [{'url': 'https://docs.example.com/openapi.json',
                                          'serverOverride': 'https://other.example.com/public'}]})
    assert result['operations'][0]['baseurl'] == 'https://other.example.com'
    assert result['operations'][0]['path'] == '/public/users'


def test_yaml_and_external_relative_parameter_reference(monkeypatch):
    doc = '''openapi: 3.0.3
info: {title: Fixture, version: "1"}
servers: [{url: https://api.example.com}]
paths:
  /users:
    get:
      parameters: [{$ref: './params.yaml#/id'}]
      responses: {'200': {description: OK}}
'''
    result, calls = run(monkeypatch, {
        'https://docs.example.com/openapi.json': Response(doc),
        'https://docs.example.com/params.yaml': Response('id: {name: id, in: query, schema: {type: integer}}')})
    assert result['operations'][0]['operation']['parameters'][0]['name'] == 'id'
    assert len(calls) == 2


def test_fetch_headers_do_not_cross_origins(monkeypatch):
    result, calls = run(monkeypatch, {
        'https://docs.example.com/openapi.json': Response('', 302, {'Location': 'https://other.example.com/spec.json'})},
        {'OPENAPI_SOURCES': [{'url': 'https://docs.example.com/openapi.json', 'headers': ['Authorization: Bearer fixture-token']}]})
    assert len(calls) == 1
    assert calls[0][1]['headers']['Authorization'] == 'Bearer fixture-token'
    assert result['operations'] == []
    assert 'fixture-token' not in json.dumps(result)
    assert result['diagnostics'][0]['code'] == 'fetch_failed'


@pytest.mark.parametrize('body,status,code', [('<html>login</html>', 200, 'invalid_document'),
                                           ('', 401, 'fetch_failed'),
                                           ({'openapi': '3.2.0', 'paths': {}}, 200, 'unsupported_version')])
def test_bad_documents_are_reported(monkeypatch, body, status, code):
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(body, status)})
    assert result['operations'] == []
    assert any(d['code'] == code for d in result['diagnostics'])


def test_swagger_ui_config_multiple_specs(monkeypatch):
    result, calls = run(monkeypatch, {
        'https://docs.example.com/openapi.json': Response('<script>SwaggerUIBundle({configUrl: "/config"})</script>'),
        'https://docs.example.com/config': Response({'urls': [{'url': '/one.json'}, {'url': '/two.json'}]}),
        'https://docs.example.com/one.json': Response(spec()),
        'https://docs.example.com/two.json': Response(spec(paths={'/other': {'post': {'responses': {}}}})),
    })
    assert len(result['operations']) == 2
    assert len(calls) == 4


def test_recursive_schema_is_bounded_and_preserved(monkeypatch):
    doc = spec(paths={'/tree': {'get': {'responses': {'200': {'description': 'OK', 'content': {
        'application/json': {'schema': {'$ref': '#/components/schemas/Tree'}}}}}}}},
        components={'schemas': {'Tree': {'type': 'object', 'properties': {'child': {'$ref': '#/components/schemas/Tree'}}}}})
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    assert len(result['operations']) == 1
    assert '$ref' in json.dumps(result['operations'][0]['operation'])


def test_isolated_wrapper_does_not_mutate(monkeypatch):
    original = {'domain': 'example.com'}
    before = copy.deepcopy(original)
    result = run_openapi_recon_isolated(original, {'OPENAPI_ENABLED': False})
    assert original == before
    assert result == {}


def test_automatic_discovery_includes_crawled_nonstandard_spec(monkeypatch):
    url = 'https://api.example.com/custom/swagger.yml'
    result, calls = run(monkeypatch, {url: Response(spec())},
                        {'OPENAPI_AUTO_DISCOVER': True, 'OPENAPI_SOURCES': []},
                        {'http_probe': {'by_url': {'https://api.example.com': {}}},
                         'resource_enum': {'by_base_url': {'https://api.example.com': {
                             'endpoints': {'/custom/swagger.yml': {}}}}}})
    assert len(result['operations']) == 1
    assert all(url.startswith('https://api.example.com/') for url, _ in calls)
    assert any(url.endswith('/openapi.json') for url, _ in calls)


def test_server_variables_use_defaults(monkeypatch):
    doc = spec(servers=[{'url': 'https://{service}.example.com/{version}',
                        'variables': {'service': {'default': 'api'}, 'version': {'default': 'v3'}}}])
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    assert result['operations'][0]['path'] == '/v3/users/{id}'


def test_external_reference_does_not_forward_credentials(monkeypatch):
    doc = spec(paths={'/users': {'get': {'parameters': [{'$ref': 'https://vendor.test/params#/id'}],
                                      'responses': {'200': {'description': 'OK'}}}}})
    result, calls = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)},
                        {'OPENAPI_SOURCES': [{'url': 'https://docs.example.com/openapi.json',
                                              'headers': ['Authorization: Bearer fixture-token']}]})
    assert len(calls) == 1
    assert result['operations'][0]['operation']['parameters'][0]['$ref']
    assert any(d['code'] == 'unresolved_reference' for d in result['diagnostics'])


def test_documents_with_query_selectors_keep_distinct_provenance(monkeypatch):
    urls = ['https://docs.example.com/spec?group=one', 'https://docs.example.com/spec?group=two']
    result, _ = run(monkeypatch, {url: Response(spec()) for url in urls},
                    {'OPENAPI_SOURCES': [{'url': url} for url in urls]})
    assert len(result['operations']) == 2
    assert len({op['source_id'] for op in result['operations']}) == 2
    assert all('?' not in op['source_url'] for op in result['operations'])


def test_document_budget_reports_incomplete(monkeypatch):
    urls = ['https://docs.example.com/one.json', 'https://docs.example.com/two.json']
    result, calls = run(monkeypatch, {url: Response(spec()) for url in urls},
                        {'OPENAPI_MAX_DOCUMENTS': 1, 'OPENAPI_SOURCES': [{'url': url} for url in urls]})
    assert len(calls) == 1
    assert any(d['code'] == 'limit_reached' for d in result['diagnostics'])


def test_yaml_examples_remain_json_compatible(monkeypatch):
    doc = '''openapi: 3.0.3
info: {title: Fixture, version: "1"}
servers: [{url: https://api.example.com}]
paths:
  /users:
    get:
      parameters:
        - name: mode
          in: query
          schema: {type: string, enum: [on, off], example: 2026-01-01}
      responses: {'200': {description: OK}}
'''
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    parameter = result['operations'][0]['operation']['parameters'][0]
    assert parameter['schema']['enum'] == ['on', 'off']
    assert parameter['schema']['example'] == '2026-01-01'
    json.dumps(result)


def test_recursive_reference_does_not_leak_document_query_credentials(monkeypatch):
    url = 'https://docs.example.com/spec?auth=fixture-secret'
    doc = spec(paths={'/tree': {'get': {'responses': {'200': {'description': 'OK', 'content': {
        'application/json': {'schema': {'$ref': '#/components/schemas/Tree'}}}}}}}},
        components={'schemas': {'Tree': {'type': 'object', 'properties': {'child': {'$ref': '#/components/schemas/Tree'}}}}})
    result, _ = run(monkeypatch, {url: Response(doc)}, {'OPENAPI_SOURCES': [{'url': url}]})
    assert result['operations']
    assert 'fixture-secret' not in json.dumps(result)


def test_invalid_method_does_not_drop_valid_sibling(monkeypatch):
    doc = spec(paths={'/users': {'get': 'invalid', 'post': {'responses': {'200': {'description': 'OK'}}}}})
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    assert [op['method'] for op in result['operations']] == ['POST']
    assert any(d['code'] == 'invalid_operation' for d in result['diagnostics'])


def test_schema_property_named_document_url_is_preserved(monkeypatch):
    doc = spec(paths={'/users': {'post': {'requestBody': {'content': {'application/json': {
        'schema': {'type': 'object', 'properties': {'_document_url': {'type': 'string'}}}}}},
        'responses': {'200': {'description': 'OK'}}}}})
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    schema = result['operations'][0]['operation']['requestBody']['content']['application/json']['schema']
    assert schema['properties']['_document_url'] == {'type': 'string'}


@pytest.mark.parametrize('path', ['/bad path', '/bad\\path', '/bad\npath'])
def test_invalid_uri_paths_are_not_published(monkeypatch, path):
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(spec(paths={path: {'get': {}}}))})
    assert result['operations'] == []
    assert any(d['code'] == 'invalid_path' for d in result['diagnostics'])


def test_observed_spec_failure_is_reported(monkeypatch):
    result, _ = run(monkeypatch, {}, {'OPENAPI_AUTO_DISCOVER': True, 'OPENAPI_SOURCES': []},
                    {'resource_enum': {'by_base_url': {'https://api.example.com': {
                        'endpoints': {'/custom/openapi.json': {}}}}}})
    assert any(d['url'].endswith('/custom/openapi.json') and d['code'] == 'fetch_failed'
               for d in result['diagnostics'])


def test_selector_redirects_keep_separate_sources(monkeypatch):
    calls = []
    def get(self, url, **kwargs):
        calls.append(url)
        if '?' in url:
            return Response('', 302, {'Location': '/current.json'})
        return Response(spec(paths={'/users': {'get': {'summary': str(len(calls)), 'responses': {}}}}))
    monkeypatch.setattr('requests.Session.get', get)
    data = run_openapi_recon({}, {'TARGET_DOMAIN': 'example.com', 'OPENAPI_AUTO_DISCOVER': False,
                                 'OPENAPI_SOURCES': [{'url': 'https://docs.example.com/spec?group=one'},
                                                     {'url': 'https://docs.example.com/spec?group=two'}]})['openapi']
    assert len(data['operations']) == 2
    assert len({op['source_id'] for op in data['operations']}) == 2


@pytest.mark.parametrize('value', ['.nan', '.inf', '!!binary Zml4dHVyZQ==', '!!set {a: null}'])
def test_non_json_yaml_values_are_rejected(monkeypatch, value):
    body = f'openapi: 3.0.3\ninfo: {{title: Fixture, version: "1"}}\npaths: {{}}\nx-example: {value}\n'
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(body)})
    assert not result['documents']
    assert any(d['code'] == 'invalid_document' for d in result['diagnostics'])


def test_only_effective_security_schemes_are_embedded(monkeypatch):
    doc = spec(security=[{'bearer': []}], components={'securitySchemes': {
        'bearer': {'type': 'http', 'scheme': 'bearer'},
        'unused': {'type': 'apiKey', 'in': 'header', 'name': 'X-Unused'}}})
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    assert set(result['operations'][0]['operation']['securitySchemes']) == {'bearer'}


def test_amplified_operation_has_explicit_output_limit(monkeypatch):
    doc = spec(paths={'/large': {'get': {'responses': {'200': {'description': 'x' * (1024 * 1024)}}}}})
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    assert result['operations'] == []
    assert any(d['code'] == 'limit_reached' for d in result['diagnostics'])


def test_fetch_has_total_deadline(monkeypatch):
    from recon.helpers.openapi.fetch import Fetcher, DocumentError
    class SlowResponse(Response):
        def iter_content(self, chunk_size):
            yield b'first'
            yield b'second'
    times = iter([0, 0, 1, 25])
    monkeypatch.setattr('recon.helpers.openapi.fetch.time.monotonic', lambda: next(times))
    monkeypatch.setattr('requests.Session.get', lambda *a, **kw: SlowResponse(''))
    with pytest.raises(DocumentError, match='deadline'):
        Fetcher(timeout=10).fetch('https://docs.example.com/spec', {}, 'https://docs.example.com')


def test_ip_mode_ignores_stale_domain_prefixes(monkeypatch):
    url = 'https://docs.example.com/openapi.json'
    result, _ = run(monkeypatch, {url: Response(spec(servers=[{'url': 'http://192.0.2.10/v1'}]))},
                    {'IP_MODE': True, 'TARGET_IPS': ['192.0.2.0/24'], 'SUBDOMAIN_LIST': ['api.', '.']})
    assert result['operations'][0]['baseurl'] == 'http://192.0.2.10'


def test_source_identity_survives_reordering_and_header_rotation(monkeypatch):
    urls = ['https://docs.example.com/one', 'https://docs.example.com/two']
    documents = {url: Response(spec()) for url in urls}
    sources = [{'url': url, 'id': f'fixture-{i}', 'headers': ['Authorization: Bearer old']} for i, url in enumerate(urls)]
    first, _ = run(monkeypatch, documents, {'OPENAPI_SOURCES': sources})
    second, _ = run(monkeypatch, documents, {'OPENAPI_SOURCES': [{**source, 'headers': ['Authorization: Bearer new']}
                                                               for source in reversed(sources)]})
    assert {op['source_id'] for op in first['operations']} == {op['source_id'] for op in second['operations']}


@pytest.mark.parametrize('body', ['{"openapi":"3.0.3","paths":{},"paths":{}}',
                                 'openapi: 3.0.3\npaths: {}\npaths: {}'])
def test_duplicate_document_keys_are_rejected(monkeypatch, body):
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(body)})
    assert not result['documents']
    assert any('Duplicate' in d['message'] for d in result['diagnostics'])


def test_redirected_external_refs_keep_final_base_on_cache_hits(monkeypatch):
    doc = spec(paths={'/users': {
        method: {'parameters': [{'$ref': '/schemas/shared.yaml#/id'}], 'responses': {}}
        for method in ['get', 'post']}})
    result, calls = run(monkeypatch, {
        'https://docs.example.com/openapi.json': Response(doc),
        'https://docs.example.com/schemas/shared.yaml': Response('', 302, {'Location': '/v2/shared.yaml'}),
        'https://docs.example.com/v2/shared.yaml': Response('id: {$ref: "child.yaml#/id"}'),
        'https://docs.example.com/v2/child.yaml': Response('id: {name: id, in: query, schema: {type: string}}'),
    })
    assert len(result['operations']) == 2
    assert all(op['operation']['parameters'][0].get('name') == 'id' for op in result['operations'])
    assert not any('/schemas/child.yaml' in url for url, _ in calls)


def test_example_payload_ref_is_literal_data(monkeypatch):
    doc = spec(paths={'/users': {'post': {'requestBody': {'content': {'application/json': {
        'schema': {'type': 'object', 'properties': {'example': {'$ref': '#/components/schemas/Name'}}},
        'example': {'$ref': 'literal-user-data'}}}}, 'responses': {}}}},
        components={'schemas': {'Name': {'type': 'string'}}})
    result, calls = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    media = result['operations'][0]['operation']['requestBody']['content']['application/json']
    assert media['example'] == {'$ref': 'literal-user-data'}
    assert media['schema']['properties']['example'] == {'type': 'string'}
    assert len(calls) == 1


def test_schema_reference_sibling_constraints_are_not_overwritten(monkeypatch):
    doc = spec(paths={'/users': {'get': {'parameters': [{'name': 'count', 'in': 'query',
        'schema': {'$ref': '#/components/schemas/Count', 'minimum': -1}}], 'responses': {}}}},
        components={'schemas': {'Count': {'type': 'integer', 'minimum': 0}}})
    result, _ = run(monkeypatch, {'https://docs.example.com/openapi.json': Response(doc)})
    schema = result['operations'][0]['operation']['parameters'][0]['schema']
    assert schema == {'allOf': [{'type': 'integer', 'minimum': 0}, {'minimum': -1}]}


def test_redirect_aliases_preserve_requested_representation():
    from recon.helpers.openapi.parser import Resolver

    class RedirectFetcher:
        def fetch(self, url, headers, allowed_origin):
            name = 'first' if 'one' in url else 'second'
            return 'https://docs.example.com/v2/schema', json.dumps({'id': {'name': name, 'in': 'query'}})

    base = 'https://docs.example.com/openapi.json'
    resolver = Resolver({'openapi': '3.1.0'}, base, RedirectFetcher(), {}, [])
    first = resolver.expand({'$ref': '/schema?group=one#/id'}, base)
    second = resolver.expand({'$ref': '/schema?group=two#/id'}, base)
    assert first['name'] == 'first'
    assert second['name'] == 'second'

def test_cached_document_still_requires_origin_authorization():
    from recon.helpers.openapi.fetch import Fetcher, DocumentError
    fetcher = Fetcher()
    url = 'https://a.example.com/shared.yaml'
    fetcher.cache[(url, ())] = (url, '{}')
    with pytest.raises(DocumentError, match='Cross-origin'):
        fetcher.fetch(url, {}, 'https://b.example.com')
    fetcher.close()

@pytest.mark.parametrize('key', ['swaggerDoc', 'spec'])
def test_auto_discovers_api_docs_with_embedded_spec(monkeypatch, key):
    base = 'https://api.example.com'
    doc = spec(servers=[{'url': '/v2'}])
    initializer = 'window.onload = function() { var options = {"' + key + '": ' + json.dumps(doc) + '}; SwaggerUIBundle(options); };'
    result, calls = run(monkeypatch, {
        base + '/api-docs/': Response('<script src="./swagger-ui-init.js"></script>'),
        base + '/api-docs/swagger-ui-init.js': Response(initializer),
    }, {'OPENAPI_AUTO_DISCOVER': True, 'OPENAPI_SOURCES': []},
        {'http_probe': {'by_url': {base: {}}}})
    operation, = result['operations']
    assert (operation['baseurl'], operation['path']) == (base, '/v2/users/{id}')
    assert operation['source_url'] == base + '/api-docs/swagger-ui-init.js'
    assert not any('/v2/users' in url for url, _ in calls)


def test_embedded_spec_rejects_executable_javascript(monkeypatch):
    source = 'https://docs.example.com/swagger-ui-init.js'
    result, _ = run(monkeypatch, {source: Response('SwaggerUIBundle({spec: getDocument()});')},
                    {'OPENAPI_SOURCES': [{'url': source}]})
    assert not result['operations']
    assert any(d['code'] == 'invalid_document' for d in result['diagnostics'])

def test_project_discovery_paths_replace_defaults(monkeypatch):
    base = 'https://api.example.com'
    result, calls = run(monkeypatch, {base + '/custom/spec.json': Response(spec())},
        {'OPENAPI_AUTO_DISCOVER': True, 'OPENAPI_SOURCES': [],
         'OPENAPI_DISCOVERY_PATHS': ['/custom/spec.json']},
        {'http_probe': {'by_url': {base: {}}}})
    assert len(result['operations']) == 1
    assert [url for url, _ in calls] == [base + '/custom/spec.json']


def test_empty_discovery_paths_disable_only_common_probes(monkeypatch):
    base = 'https://api.example.com'
    result, calls = run(monkeypatch, {},
        {'OPENAPI_AUTO_DISCOVER': True, 'OPENAPI_SOURCES': [], 'OPENAPI_DISCOVERY_PATHS': []},
        {'http_probe': {'by_url': {base: {}}}})
    assert calls == []


@pytest.mark.parametrize('paths', [['//evil.example.test/spec'], ['https://example.test/spec'], ['/bad?x=1'], 'invalid'])
def test_invalid_discovery_paths_are_diagnosed(monkeypatch, paths):
    result, calls = run(monkeypatch, {},
        {'OPENAPI_AUTO_DISCOVER': True, 'OPENAPI_SOURCES': [], 'OPENAPI_DISCOVERY_PATHS': paths},
        {'http_probe': {'by_url': {'https://api.example.com': {}}}})
    assert not calls
    assert any(d['code'] == 'invalid_source' for d in result['diagnostics'])