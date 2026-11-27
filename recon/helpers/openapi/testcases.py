"""Pure, deterministic security test plans from parser operation records."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import json
import math
import re
from urllib.parse import quote


OWASP_API = {
    'bola': 'API1:2023',
    'bfla': 'API5:2023',
    'auth_missing': 'API2:2023',
    'mass_assignment': 'API3:2023',
    'input_validation': 'API8:2023',
    'method_drift': 'API9:2023',
}
DRIFT_METHODS = ('GET', 'POST', 'PUT', 'DELETE', 'PATCH')


def _ordered(value):
    if isinstance(value, dict):
        return {key: _ordered(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_ordered(item) for item in value]
    return value


@dataclass
class TestCase:
    operation_id: str
    method: str
    path_template: str
    category: str
    name: str
    request: dict
    expectation: dict
    owasp_api: str

    def to_dict(self):
        result = asdict(self)
        result['request'] = {key: _ordered(self.request[key])
                             for key in ('method', 'path', 'query', 'headers', 'body')}
        result['expectation'] = {key: _ordered(self.expectation[key]) for key in ('kind', 'detail')}
        return result

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, allow_nan=False, separators=(',', ':'))


def _schema(schema, components, depth=0, refs=()):
    if not isinstance(schema, dict) or depth >= 6:
        return {}
    if '$ref' in schema:
        ref = schema['$ref']
        if not isinstance(ref, str) or ref in refs or not ref.startswith('#/components/'):
            return {}
        target = {'components': components}
        try:
            for token in ref[2:].split('/'):
                target = target[token.replace('~1', '/').replace('~0', '~')]
        except (KeyError, TypeError):
            return {}
        return _schema(target, components, depth + 1, refs + (ref,))
    result = dict(schema)
    for part in schema.get('allOf', []):
        resolved = _schema(part, components, depth + 1, refs)
        result['properties'] = {**result.get('properties', {}), **resolved.get('properties', {})}
        result['required'] = sorted(set(result.get('required', [])) | set(resolved.get('required', [])))
        for key, value in resolved.items():
            if key not in ('properties', 'required', 'allOf'):
                result.setdefault(key, value)
    for choice in ('oneOf', 'anyOf'):
        if schema.get(choice):
            result = {**_schema(schema[choice][0], components, depth + 1, refs), **result}
    return result


def build_example(schema, components):
    """Build a minimal example; unsupported/cyclic schemas terminate as null.

    Local component references only: resolving a schema must never fetch a URL.
    Examples/enums take precedence over inferred primitive values. This is a
    structural example builder, not a complete JSON Schema validator.
    """
    def build(value, depth):
        if depth >= 6:
            return None
        value = _schema(value, components, depth)
        for key in ('example', 'const'):
            if key in value:
                return deepcopy(value[key])
        if value.get('enum'):
            return deepcopy(value['enum'][0])
        kind = _type(value)
        if kind == 'object':
            return {name: build(child, depth + 1)
                    for name, child in sorted(value.get('properties', {}).items())
                    if name in value.get('required', []) and not child.get('readOnly')}
        if kind == 'array':
            return [build(value.get('items', {}), depth + 1)
                    for _ in range(max(0, value.get('minItems', 0)))]
        if kind == 'string':
            return 'x' * max(1, value.get('minLength', 0)) if value.get('maxLength') != 0 else ''
        if kind in ('integer', 'number'):
            number = max(0, value.get('minimum', 0))
            exclusive = value.get('exclusiveMinimum')
            if exclusive is True:
                number += 1
            elif type(exclusive) in (int, float):
                number = max(number, exclusive + 1)
            if 'maximum' in value:
                number = min(number, value['maximum'])
            exclusive = value.get('exclusiveMaximum')
            if exclusive is True:
                number -= 1
            elif type(exclusive) in (int, float):
                number = min(number, exclusive - 1)
            return math.ceil(number) if kind == 'integer' else number
        if kind == 'boolean':
            return False
        return None
    return build(schema, 0)


def _type(schema):
    kind = schema.get('type')
    if isinstance(kind, list):
        kind = next((item for item in kind if item != 'null'), 'null')
    return kind or ('object' if 'properties' in schema else None)


def _body_schema(operation):
    content = operation.get('requestBody', {}).get('content', {})
    for media in sorted(content):
        if media == 'application/json' or media.endswith('+json'):
            return content[media].get('schema', {})
    if 'application/json' in operation.get('consumes', []):
        for param in operation.get('parameters', []):
            if param.get('in') == 'body':
                return param.get('schema', {})
    return None


def _parameters(operation):
    return sorted((p for p in operation.get('parameters', [])
                   if p.get('in') in ('path', 'query', 'header', 'cookie') and 'name' in p),
                  key=lambda p: (p['in'], p['name']))


def _set_parameter(request, param, value, *, missing=False):
    location, name = param['in'], param['name']
    if location == 'path':
        replacement = '' if missing else quote(str(value), safe='<>_')
        request['path'] = request['path'].replace('{' + name + '}', replacement)
    else:
        target = request['query'] if location == 'query' else request['headers']
        if location == 'cookie':
            name = 'Cookie'
            value = param['name'] + '=' + str(value)
        if missing:
            target.pop(name, None)
        else:
            target[name] = value


def _request(record, base_url, body_schema):
    operation = record['operation']
    request = {'method': record['method'].upper(),
               'path': (base_url or '{{BASE_URL}}').rstrip('/') + record['path'],
               'query': {}, 'headers': {},
               'body': build_example(body_schema, {}) if body_schema is not None else None}
    if body_schema is not None:
        request['headers']['Content-Type'] = 'application/json'
    for param in _parameters(operation):
        if param['in'] != 'path':
            _set_parameter(request, param, param.get('example', build_example(param.get('schema', param), {})))
    return request


def _authenticated(request, operation):
    request = deepcopy(request)
    # Use one satisfiable alternative; credentials are supplied only by a future executor.
    requirements = operation.get('security', [])
    if requirements and all(requirements):
        for name in sorted(requirements[0]):
            scheme = operation.get('securitySchemes', {}).get(name, {})
            if scheme.get('type') == 'apiKey':
                _set_parameter(request, {'in': scheme.get('in', 'header'),
                                        'name': scheme.get('name', name)}, '<AUTH_TOKEN>')
            else:
                request['headers']['Authorization'] = 'Bearer <AUTH_TOKEN>'
    return request


def _case(record, category, name, request, kind, detail):
    operation_id = record['operation'].get('operationId') or record.get('operation_ref') or (
        record['method'].upper() + ' ' + record['path'])
    return TestCase(operation_id, request['method'], record['path'], category, name,
                    request, {'kind': kind, 'detail': detail}, OWASP_API[category])


def _concrete(record, request):
    result = deepcopy(request)
    for param in _parameters(record['operation']):
        if param['in'] == 'path':
            _set_parameter(result, param, param.get('example', build_example(param.get('schema', param), {})))
    result['path'] = re.sub(r'(?<!\{)\{([^{}]+)\}(?!\})', '1', result['path'])
    return result


def generate_bola(record, request, schema):
    for param in _parameters(record['operation']):
        name = param['name']
        if param['in'] in ('path', 'query') and (
                name.lower() in ('id', 'uuid') or name.endswith('Id') or name.lower().endswith('_id')
                or param.get('schema', param).get('format') == 'uuid'):
            candidate = deepcopy(request)
            _set_parameter(candidate, param, '<OTHER_USER_OBJECT_ID>')
            yield _case(record, 'bola', 'swap_identifier:' + param['in'] + ':' + name,
                        _concrete(record, candidate), 'deny_expected',
                        'Use an authenticated user and an object owned by another user.')


def generate_bfla(record, request, schema):
    if record['method'].upper() in ('POST', 'PUT', 'PATCH', 'DELETE') and set(
            record['path'].lower().split('/')) & {'admin', 'internal', 'manage', 'private'}:
        yield _case(record, 'bfla', 'unprivileged', _concrete(record, request),
                    'deny_expected', 'Use an authenticated user without administrative privileges.')


def generate_auth_missing(record, request, schema):
    requirements = record['operation'].get('security', [])
    if not requirements or not all(requirements):
        return
    candidate = _concrete(record, request)
    schemes = record['operation'].get('securitySchemes', {})
    auth_headers = {'authorization'} | {s.get('name', '').lower() for s in schemes.values()
                                       if s.get('in') == 'header'}
    candidate['headers'] = {k: v for k, v in candidate['headers'].items() if k.lower() not in auth_headers}
    for scheme in schemes.values():
        if scheme.get('in') in ('query', 'cookie'):
            _set_parameter(candidate, {'in': scheme['in'], 'name': scheme['name']}, None, missing=True)
    yield _case(record, 'auth_missing', 'no_auth', deepcopy(candidate), 'status_in', [401, 403])
    malformed = _authenticated(candidate, record['operation'])
    for target in (malformed['headers'], malformed['query']):
        for key, value in target.items():
            if isinstance(value, str) and '<AUTH_TOKEN>' in value:
                target[key] = value.replace('<AUTH_TOKEN>', 'malformed-token')
    yield _case(record, 'auth_missing', 'malformed_token', malformed, 'status_in', [401, 403])


def generate_mass_assignment(record, request, schema):
    if schema is not None and _type(_schema(schema, {})) == 'object' and isinstance(request['body'], dict):
        candidate = deepcopy(request)
        candidate['body'].update(role='admin', isAdmin=True, ownerId='<OTHER_USER_OBJECT_ID>',
                                 tenantId='<OTHER_TENANT_ID>')
        yield _case(record, 'mass_assignment', 'privileged_fields', _concrete(record, candidate),
                    'fields_ignored', ['role', 'isAdmin', 'ownerId', 'tenantId'])


def _mutations(schema, required):
    kind = _type(schema)
    if kind:
        yield 'wrong_type', [] if kind == 'object' else {'invalid': True}
    if kind == 'string':
        yield 'long_string', 'x' * max(1024, schema.get('maxLength', 0) + 1)
    if kind in ('integer', 'number'):
        for bound, offset in (('minimum', -1), ('maximum', 1)):
            if bound in schema:
                yield 'outside_' + bound, schema[bound] + offset
    if required:
        yield 'missing_required', None


def _fields(schema, prefix=(), depth=0):
    if depth >= 6:
        return
    schema = _schema(schema, {})
    for name, child in sorted(schema.get('properties', {}).items()):
        child = _schema(child, {})
        if child.get('readOnly'):
            continue
        path = prefix + (name,)
        yield path, child, name in schema.get('required', [])
        yield from _fields(child, path, depth + 1)


def generate_input_validation(record, request, schema):
    for param in _parameters(record['operation']):
        for mutation, value in _mutations(param.get('schema', param), param.get('required', False)):
            candidate = deepcopy(request)
            _set_parameter(candidate, param, value, missing=mutation == 'missing_required')
            yield _case(record, 'input_validation', param['in'] + ':' + param['name'] + ':' + mutation,
                        _concrete(record, candidate), 'status_4xx_not_5xx', 'Reject invalid input without a server error.')
    for path, child, required in _fields(schema or {}):
        for mutation, value in _mutations(child, required):
            candidate = deepcopy(request)
            if not isinstance(candidate['body'], dict):
                continue
            target = candidate['body']
            parent_schema = _schema(schema, {})
            for name in path[:-1]:
                parent_schema = _schema(parent_schema.get('properties', {}).get(name, {}), {})
                if not isinstance(target.get(name), dict):
                    target[name] = build_example(parent_schema, {}) or {}
                target = target[name]
            if mutation == 'missing_required':
                target.pop(path[-1], None)
            else:
                target[path[-1]] = value
            yield _case(record, 'input_validation', 'body:' + '/'.join(path) + ':' + mutation,
                        _concrete(record, candidate), 'status_4xx_not_5xx', 'Reject invalid input without a server error.')


def generate_method_drift(record, request, schema, declared):
    for method in DRIFT_METHODS:
        if method not in declared:
            candidate = _concrete(record, request)
            candidate['method'] = method
            yield _case(record, 'method_drift', 'undeclared:' + method, candidate, 'status_in', [404, 405])


def generate_test_cases(operations, *, base_url=None, categories=None, max_per_operation=12):
    """Generate plans, never execute them; cap each record after category/name sorting.

    ``operations`` is the list returned by ``parser.parse_operations``. Method
    drift belongs to the first sorted operation of each path. The inventory's
    server/source URLs are never used as request targets.
    """
    if not isinstance(max_per_operation, int) or max_per_operation < 0:
        raise ValueError('max_per_operation must be a nonnegative integer')
    selected = set(OWASP_API if categories is None else categories)
    if selected - OWASP_API.keys():
        raise ValueError('Unknown categories: ' + ', '.join(sorted(selected - OWASP_API.keys())))
    records = sorted(operations, key=lambda r: (r['operation'].get('operationId', ''), r['method'],
                                               r['path'], json.dumps(r['operation'], sort_keys=True)))
    declared = {}
    for record in records:
        declared.setdefault(record['path'], set()).add(record['method'].upper())
    generators = (generate_bola, generate_bfla, generate_auth_missing,
                  generate_mass_assignment, generate_input_validation)
    result, seen_paths, seen_records = [], set(), set()
    for record in records:
        signature = (record['path'], record['method'], json.dumps(record['operation'], sort_keys=True))
        if signature in seen_records:
            continue
        seen_records.add(signature)
        schema = _body_schema(record['operation'])
        request = _authenticated(_request(record, base_url, schema), record['operation'])
        cases = []
        for generator in generators:
            if generator.__name__.removeprefix('generate_') in selected:
                cases.extend(generator(record, request, schema))
        if 'method_drift' in selected and record['path'] not in seen_paths:
            cases.extend(generate_method_drift(record, request, schema, declared[record['path']]))
        seen_paths.add(record['path'])
        result.extend(sorted(cases, key=_case_key)[:max_per_operation])
    return sorted(result, key=_case_key)


def _case_key(case):
    return case.operation_id, case.method, case.path_template, case.category, case.name
