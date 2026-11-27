"""Pure test planning against the operation inventory's real parser contract."""
from collections import Counter
from copy import deepcopy
import json
from unittest.mock import Mock

import pytest

from recon.helpers.openapi.parser import parse_operations
from recon.helpers.openapi.testcases import TestCase as SecurityTestCase, build_example, generate_test_cases


@pytest.fixture
def operations():
    spec = {
        'openapi': '3.1.0', 'info': {'title': 'Synthetic', 'version': '1'},
        'servers': [{'url': 'https://example.test/v1'}],
        'security': [{'bearer': []}],
        'components': {
            'securitySchemes': {'bearer': {'type': 'http', 'scheme': 'bearer'}},
            'schemas': {'User': {
                'type': 'object', 'required': ['name', 'age'],
                'properties': {'name': {'type': 'string', 'example': 'sample', 'maxLength': 20},
                               'age': {'type': 'integer', 'minimum': 1, 'maximum': 100}},
            }},
        },
        'paths': {'/admin/users/{userId}': {
            'parameters': [{'name': 'userId', 'in': 'path', 'required': True,
                            'schema': {'type': 'integer', 'example': 7}},
                           {'name': 'owner_id', 'in': 'query', 'required': True,
                            'schema': {'type': 'string', 'example': 'own'}}],
            'post': {'operationId': 'createUser', 'requestBody': {'required': True, 'content': {
                'application/json': {'schema': {'$ref': '#/components/schemas/User'}}}},
                     'responses': {'201': {'description': 'Created'}}},
            'get': {'operationId': 'getUser', 'security': [],
                    'responses': {'200': {'description': 'OK'}}},
        }},
    }
    fetcher = Mock()
    diagnostics = []
    result, version = parse_operations(spec, 'https://example.test/spec.json', 'synthetic',
                                       fetcher, {}, Mock(allows=lambda _: True), diagnostics)
    assert version == '3.1.0'
    assert diagnostics == []
    fetcher.fetch.assert_not_called()
    return result


def cases_for(operations, category):
    return generate_test_cases(operations, categories=[category], max_per_operation=100)


def test_all_categories_and_no_inventory_host(operations):
    cases = generate_test_cases(operations, max_per_operation=100)
    assert {case.category for case in cases} == {
        'bola', 'bfla', 'auth_missing', 'mass_assignment', 'input_validation', 'method_drift'}
    for case in cases:
        assert case.request['path'].startswith('{{BASE_URL}}/v1/admin/users/')
        assert 'example.test' not in case.to_json()
        assert 'https://' not in case.to_json()
        assert case.owasp_api.startswith('API') and case.owasp_api.endswith(':2023')


def test_bola_swaps_path_and_query(operations):
    cases = cases_for(operations, 'bola')
    assert len(cases) == 4
    for case in cases:
        assert case.expectation['kind'] == 'deny_expected'
        if ':path:' in case.name:
            assert case.request['path'].endswith('/<OTHER_USER_OBJECT_ID>')
        else:
            assert case.request['query']['owner_id'] == '<OTHER_USER_OBJECT_ID>'


def test_bfla_and_mass_assignment(operations):
    case, = cases_for(operations, 'bfla')
    assert case.method == 'POST'
    assert '<AUTH_TOKEN>' in case.request['headers']['Authorization']
    assert case.expectation['kind'] == 'deny_expected'
    case, = cases_for(operations, 'mass_assignment')
    assert case.request['body'] == {'name': 'sample', 'age': 1, 'role': 'admin', 'isAdmin': True,
                                   'ownerId': '<OTHER_USER_OBJECT_ID>', 'tenantId': '<OTHER_TENANT_ID>'}
    assert case.expectation['kind'] == 'fields_ignored'


def test_auth_requires_security_and_removes_credentials(operations):
    cases = cases_for(operations, 'auth_missing')
    assert len(cases) == 2
    assert {case.operation_id for case in cases} == {'createUser'}
    missing = next(case for case in cases if case.name == 'no_auth')
    malformed = next(case for case in cases if case.name == 'malformed_token')
    assert 'Authorization' not in missing.request['headers']
    assert malformed.request['headers']['Authorization'] == 'Bearer malformed-token'
    assert missing.expectation == {'kind': 'status_in', 'detail': [401, 403]}
    for record in operations:
        record['operation']['security'] = [{'bearer': []}, {}]
    assert cases_for(operations, 'auth_missing') == []


def test_input_validation_mutations(operations):
    cases = {case.name: case for case in cases_for(operations, 'input_validation')
             if case.operation_id == 'createUser'}
    assert cases['body:age:wrong_type'].request['body']['age'] == {'invalid': True}
    assert cases['body:age:outside_minimum'].request['body']['age'] == 0
    assert cases['body:age:outside_maximum'].request['body']['age'] == 101
    assert 'age' not in cases['body:age:missing_required'].request['body']
    assert len(cases['body:name:long_string'].request['body']['name']) > 20
    assert 'owner_id' not in cases['query:owner_id:missing_required'].request['query']
    assert cases['query:owner_id:wrong_type'].request['query']['owner_id'] == {'invalid': True}
    assert cases['path:userId:missing_required'].request['path'].endswith('/users/')
    assert all(case.expectation['kind'] == 'status_4xx_not_5xx' for case in cases.values())


def test_method_drift_once_per_path_excludes_all_declared_methods(operations):
    cases = cases_for(operations, 'method_drift')
    assert len(cases) == 3
    assert {case.request['method'] for case in cases} == {'PUT', 'PATCH', 'DELETE'}
    assert all(case.method == case.request['method'] for case in cases)
    assert all(case.expectation == {'kind': 'status_in', 'detail': [404, 405]} for case in cases)


def test_determinism_serialization_order_and_no_input_mutation(operations):
    before = deepcopy(operations)
    first = generate_test_cases(operations, max_per_operation=100)
    second = generate_test_cases(list(reversed(operations)), max_per_operation=100)
    assert first == second
    assert [case.to_json() for case in first] == [case.to_json() for case in second]
    assert operations == before
    assert first == sorted(first, key=lambda c: (c.operation_id, c.method, c.path_template, c.category, c.name))
    data = first[0].to_dict()
    assert list(data) == ['operation_id', 'method', 'path_template', 'category', 'name',
                          'request', 'expectation', 'owasp_api']
    assert list(data['request']) == ['method', 'path', 'query', 'headers', 'body']
    assert list(data['expectation']) == ['kind', 'detail']
    assert SecurityTestCase(**json.loads(first[0].to_json())) == first[0]


def test_limits_filters_override_and_duplicate_servers(operations):
    for limit in (0, 1, 3, 12):
        cases = generate_test_cases(operations, max_per_operation=limit)
        assert all(count <= limit for count in Counter(c.operation_id for c in cases).values())
        assert len(cases) <= len(operations) * limit
    assert generate_test_cases(operations, categories=[]) == []
    assert generate_test_cases(operations, max_per_operation=0) == []
    assert generate_test_cases(operations + deepcopy(operations)) == generate_test_cases(operations)
    assert all(c.request['path'].startswith('https://example.test/api/v1/') for c in
               generate_test_cases(operations, base_url='https://example.test/api/'))
    with pytest.raises(ValueError):
        generate_test_cases(operations, categories=['unknown'])
    with pytest.raises(ValueError):
        generate_test_cases(operations, max_per_operation=-1)


def test_build_minimal_examples_and_reference_cycles():
    components = {'schemas': {'Node': {'type': 'object', 'required': ['child'],
                                      'properties': {'child': {'$ref': '#/components/schemas/Node'}}}}}
    example = build_example({'$ref': '#/components/schemas/Node'}, components)
    assert len(json.dumps(example)) < 100
    assert 'null' in json.dumps(example)
    assert build_example({'$ref': '#/components/schemas/Loop'},
                         {'schemas': {'Loop': {'$ref': '#/components/schemas/Loop'}}}) is None
    assert build_example({'$ref': 'https://example.test/schema.json'}, {}) is None
    assert build_example({'type': 'object', 'required': ['a'], 'properties': {
        'a': {'type': 'string', 'enum': ['chosen']}, 'b': {'type': 'boolean'}}}, {}) == {'a': 'chosen'}
    assert build_example({'type': 'integer', 'minimum': 5, 'maximum': 8}, {}) == 5
    assert build_example({'type': 'array', 'minItems': 1, 'items': {'type': 'boolean'}}, {}) == [False]
    assert build_example({'type': 'string', 'enum': ['enum'], 'example': 'example'}, {}) == 'example'


@pytest.mark.parametrize('location', ['header', 'query', 'cookie'])
def test_api_key_credentials_are_removed_or_malformed(operations, location):
    record = deepcopy(operations[0])
    record['operation']['security'] = [{'key': []}]
    record['operation']['securitySchemes'] = {'key': {'type': 'apiKey', 'in': location, 'name': 'X-Key'}}
    cases = {case.name: case for case in cases_for([record], 'auth_missing')}
    missing = cases['no_auth'].request
    malformed = cases['malformed_token'].request
    key = 'Cookie' if location == 'cookie' else 'X-Key'
    target = 'query' if location == 'query' else 'headers'
    assert key not in missing[target]
    assert 'malformed-token' in malformed[target][key]
    assert '<AUTH_TOKEN>' not in json.dumps(malformed)


def test_nested_required_fields_keep_siblings_valid(operations):
    record = deepcopy(operations[0])
    record['operation']['requestBody'] = {'content': {'application/json': {'schema': {
        'type': 'object', 'properties': {'profile': {
            'type': 'object', 'required': ['a', 'b'], 'properties': {
                'a': {'type': 'string'}, 'b': {'type': 'integer', 'minimum': 1}}}}}}}}
    cases = {case.name: case for case in cases_for([record], 'input_validation')}
    assert cases['body:profile/a:missing_required'].request['body'] == {'profile': {'b': 1}}
    assert cases['body:profile/b:outside_minimum'].request['body'] == {'profile': {'a': 'x', 'b': 0}}


def test_allof_and_missing_operation_id(operations):
    assert build_example({'allOf': [
        {'type': 'object', 'required': ['a'], 'properties': {'a': {'type': 'boolean'}}},
        {'type': 'object', 'required': ['b'], 'properties': {'b': {'type': 'integer'}}},
    ]}, {}) == {'a': False, 'b': 0}
    record = deepcopy(operations[0])
    record['operation'].pop('operationId', None)
    assert all(case.operation_id == record['operation_ref'] for case in generate_test_cases([record]))
