"""Merge OpenAPI declarations into resource enumeration's ``by_base_url``.

Mirrors ``merge_kiterunner_into_by_base_url``: each declared operation becomes
an endpoint under its declared server's origin, and the existing graph writer
(``update_graph_from_resource_enum``) persists it. Only short, sanitized
identifiers survive the merge; no free text from a specification (summary,
description) reaches the graph or the agent, because the text is target-supplied.
"""
import re
from typing import Dict, Tuple
from urllib.parse import quote, unquote, urlsplit

from .classification import classify_endpoint, classify_parameter

IDENTIFIER = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
SPEC_VERSION = re.compile(r'^(2\.0|3\.[01]\.\d+)$')
TAG = re.compile(r'^[\x20-\x7e]{1,64}$')
TAG_FORBIDDEN = set('\'"`<>')
TEMPLATE_VARIABLE = re.compile(r'\{([^{}/]+)\}')
CONTROL = re.compile(r'[\x00-\x1f\x7f]')
BODY_CONTENT_TYPES = ('application/json', 'application/x-www-form-urlencoded', 'multipart/form-data')
NIL_UUID = '00000000-0000-0000-0000-000000000000'
MAX_SECURITY_NAMES = 16
MAX_TAGS = 10
MAX_PARAMETER_NAME = 128


def _schema(param):
    schema = param.get('schema')
    return schema if isinstance(schema, dict) else {}


def _declared_value(param):
    """The spec's own example for a parameter, or ``None`` when it gives none."""
    schema = _schema(param)
    for holder in (param, schema):
        if 'example' in holder:
            return holder['example']
    for holder in (param, schema):
        examples = holder.get('examples')
        if isinstance(examples, dict) and examples:
            first = next(iter(examples.values()))
            if isinstance(first, dict) and 'value' in first:
                return first['value']
        elif isinstance(examples, list) and examples:
            return examples[0]
    for holder in (param, schema):
        if 'default' in holder:
            return holder['default']
    for holder in (param, schema):
        enum = holder.get('enum')
        if isinstance(enum, list) and enum:
            return enum[0]
    return None


def _value_by_type(param):
    schema = _schema(param)
    kind = schema.get('type', param.get('type'))
    fmt = schema.get('format', param.get('format'))
    if kind == 'string' and fmt == 'uuid':
        return NIL_UUID
    return 1


def encode_value(value) -> str:
    """D4: a spec-supplied value as one safe path segment or query value.

    The value comes from the target. One that could rewrite the request target
    (a slash, a backslash, ``?``, ``#``, a dot segment, a control character,
    once percent-decoded) or that is longer than 64 characters becomes ``1``.
    """
    if isinstance(value, (dict, list)) or value is None:
        return '1'
    text = str(value)
    decoded = unquote(text)
    if (not text or len(text) > 64 or CONTROL.search(text) or CONTROL.search(decoded)
            or any(c in decoded for c in '/\\?#') or decoded in ('.', '..')):
        return '1'
    return quote(text, safe='-._~')


def concrete_path(template, path_params) -> str:
    """Fill each ``{name}`` with the parameter's encoded example (D4), else ``1``."""
    def fill(match):
        param = path_params.get(match.group(1))
        if param is None:
            return '1'
        value = _declared_value(param)
        return encode_value(_value_by_type(param) if value is None else value)
    return TEMPLATE_VARIABLE.sub(fill, template)


def _valid_name(name) -> bool:
    return (isinstance(name, str) and 0 < len(name) <= MAX_PARAMETER_NAME
            and not CONTROL.search(name))


#: JSON-schema `format` -> the shared parameter type every module writes.
_FORMAT_TYPES = {"uri": "url", "url": "url", "uri-reference": "url", "iri": "url",
                 "email": "email", "idn-email": "email", "date": "datetime", "date-time": "datetime"}


def _kind(schema):
    """The shared type words (integer, boolean, url, email, datetime, string),
    from the schema's `type` and `format`: `number` is an integer, an array or
    object is a string, as for every other source."""
    kind = schema.get('type') if isinstance(schema, dict) else None
    if isinstance(kind, list):
        kind = next((k for k in kind if k != 'null'), None)
    kind = kind if isinstance(kind, str) else 'string'
    if kind in ('integer', 'number'):
        return 'integer'
    if kind == 'boolean':
        return 'boolean'
    if kind == 'string':
        fmt = schema.get('format') if isinstance(schema, dict) else None
        return _FORMAT_TYPES.get(str(fmt or '').lower(), 'string')
    return 'string'


def _parameter(name, schema_or_param, required, *, sample=True):
    entry = {'name': name, 'type': _kind(_schema(schema_or_param) or schema_or_param),
             'category': classify_parameter(name), 'required': bool(required)}
    if sample:
        value = _declared_value(schema_or_param)
        entry['sample_values'] = [] if value is None else [encode_value(value)]
    return entry


def _body_parameters(operation, stats):
    params = []
    body = operation.get('requestBody')
    if isinstance(body, dict) and isinstance(body.get('content'), dict):
        for content_type in BODY_CONTENT_TYPES:
            media = body['content'].get(content_type)
            schema = media.get('schema') if isinstance(media, dict) else None
            if not isinstance(schema, dict):
                continue
            required = schema.get('required') if isinstance(schema.get('required'), list) else []
            for name, prop in (schema.get('properties') or {}).items():
                params.append(_parameter(name, prop if isinstance(prop, dict) else {}, name in required, sample=False))
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict):
            continue
        location = param.get('in')
        if location == 'formData':
            params.append(_parameter(param.get('name'), param, param.get('required'), sample=False))
        elif location == 'body' and isinstance(param.get('schema'), dict):
            schema = param['schema']
            required = schema.get('required') if isinstance(schema.get('required'), list) else []
            for name, prop in (schema.get('properties') or {}).items():
                params.append(_parameter(name, prop if isinstance(prop, dict) else {}, name in required, sample=False))
    kept = [p for p in params if _valid_name(p['name'])]
    stats['openapi_parameters_dropped'] += len(params) - len(kept)
    return kept


def _operation_metadata(operation, spec_url) -> dict:
    meta = {'spec_urls': [spec_url] if spec_url else []}
    op_id = operation.get('operationId')
    if isinstance(op_id, str) and IDENTIFIER.fullmatch(op_id):
        meta['operation_id'] = op_id
    meta['deprecated'] = operation.get('deprecated') is True
    names = []
    for requirement in operation.get('security') or []:
        if isinstance(requirement, dict):
            names.extend(n for n in requirement if isinstance(n, str) and IDENTIFIER.fullmatch(n))
    meta['security'] = list(dict.fromkeys(names))[:MAX_SECURITY_NAMES]
    tags = [t for t in operation.get('tags') or []
            if isinstance(t, str) and TAG.fullmatch(t) and not (set(t) & TAG_FORBIDDEN)]
    meta['tags'] = list(dict.fromkeys(tags))[:MAX_TAGS]
    return meta


def _merge_meta(existing, incoming):
    """Union two per-method records: lists are unioned, scalars keep the first."""
    for key, value in incoming.items():
        if isinstance(value, list):
            existing[key] = list(dict.fromkeys((existing.get(key) or []) + value))
        else:
            existing.setdefault(key, value)
    return existing


def _new_base(base):
    return {'base_url': base, 'endpoints': {},
            'summary': {'total_endpoints': 0, 'total_parameters': 0, 'methods': {}, 'categories': {}}}


def _recount(endpoint):
    params = endpoint['parameters']
    counts = {k: len(params.get(k) or []) for k in ('query', 'body', 'path')}
    counts['total'] = sum(counts.values())
    endpoint['parameter_count'] = counts


def merge_openapi_into_by_base_url(payload: Dict, by_base_url: Dict) -> Tuple[Dict, Dict[str, int]]:
    """Merge the engine's transient operations into ``by_base_url``.

    An existing endpoint keeps every field it has; only ``methods``,
    ``sources``, ``parameters`` (by name and position) and ``openapi`` are
    unioned, and it is marked ``declared_only = False`` because a tool already
    observed it. An endpoint this merge creates is ``declared_only = True``:
    later scanners request it with GET or HEAD only.
    """
    stats = {'openapi_operations': 0, 'openapi_new': 0, 'openapi_overlap': 0,
             'openapi_header_cookie_parameters': 0, 'openapi_parameters_dropped': 0,
             'openapi_spec_documents': 0}
    created = set()
    touched = set()

    def endpoint_for(base, path):
        touched.add(base)
        bucket = by_base_url.setdefault(base, _new_base(base))
        endpoints = bucket['endpoints']
        if path in endpoints:
            entry = endpoints[path]
            if (base, path) not in created:
                if entry.get('declared_only') is not True:
                    entry['declared_only'] = False
                    stats['openapi_overlap'] += 1
            entry.setdefault('parameters', {}).setdefault('query', [])
            entry['parameters'].setdefault('body', [])
            entry['parameters'].setdefault('path', [])
            sources = entry.get('sources') or ([entry['source']] if entry.get('source') else [])
            entry.pop('source', None)
            entry['sources'] = sources
            entry.setdefault('methods', [])
            return entry, False
        entry = {'methods': [], 'parameters': {'query': [], 'body': [], 'path': []},
                 'sources': [], 'category': 'other', 'declared_only': True}
        endpoints[path] = entry
        created.add((base, path))
        bucket['summary']['total_endpoints'] += 1
        stats['openapi_new'] += 1
        return entry, True

    for operation in payload.get('operations') or []:
        try:
            base = operation['baseurl']
            template = operation['path']
            method = str(operation['method']).upper()
            spec = operation.get('operation') if isinstance(operation.get('operation'), dict) else {}
        except (KeyError, TypeError):
            continue
        stats['openapi_operations'] += 1
        declared = [p for p in spec.get('parameters') or [] if isinstance(p, dict)]
        path_params = {p.get('name'): p for p in declared if p.get('in') == 'path'}
        path = concrete_path(template, path_params)
        entry, _ = endpoint_for(base, path)
        bucket = by_base_url[base]

        if path != template:
            entry['openapi_path_templates'] = list(dict.fromkeys(
                (entry.get('openapi_path_templates') or []) + [template]))
        if method not in entry['methods']:
            entry['methods'].append(method)
            bucket['summary']['methods'][method] = bucket['summary']['methods'].get(method, 0) + 1
        if 'openapi' not in entry['sources']:
            entry['sources'].append('openapi')

        incoming = {'query': [], 'path': [], 'body': _body_parameters(spec, stats)}
        for param in declared:
            location = param.get('in')
            if location in ('header', 'cookie'):
                stats['openapi_header_cookie_parameters'] += 1
            elif location in ('query', 'path'):
                if _valid_name(param.get('name')):
                    incoming[location].append(_parameter(param['name'], param, param.get('required')))
                else:
                    stats['openapi_parameters_dropped'] += 1
        for position, params in incoming.items():
            have = {p.get('name') for p in entry['parameters'][position]}
            for param in params:
                if param['name'] not in have:
                    entry['parameters'][position].append(param)
                    have.add(param['name'])

        meta = _operation_metadata(spec, operation.get('source_url'))
        per_method = entry.setdefault('openapi', {})
        per_method[method] = _merge_meta(per_method.get(method, {}), meta)

        _recount(entry)
        entry['category'] = classify_endpoint(path, entry['methods'], entry['parameters'])

    for document in payload.get('documents') or []:
        try:
            parts = urlsplit(document['url'])
            base = f'{parts.scheme}://{parts.netloc}'
            path = parts.path or '/'
        except (KeyError, TypeError, ValueError):
            continue
        version = document.get('version')
        if not isinstance(version, str) or not SPEC_VERSION.fullmatch(version):
            version = None
        entry, is_new = endpoint_for(base, path)
        # The document was fetched, so its own path was observed.
        entry['declared_only'] = False
        if 'GET' not in entry['methods']:
            entry['methods'].append('GET')
            summary = by_base_url[base]['summary']['methods']
            summary['GET'] = summary.get('GET', 0) + 1
        if 'openapi' not in entry['sources']:
            entry['sources'].append('openapi')
        entry['openapi_spec'] = {'version': version,
                                 'operation_count': int(document.get('operation_count') or 0)}
        _recount(entry)
        if is_new:
            entry['category'] = classify_endpoint(path, entry['methods'], entry['parameters'])
        stats['openapi_spec_documents'] += 1

    for base in touched:
        bucket = by_base_url[base]
        categories = {}
        params = 0
        for entry in bucket['endpoints'].values():
            category = entry.get('category', 'other')
            categories[category] = categories.get(category, 0) + 1
            params += (entry.get('parameter_count') or {}).get('total', 0)
        bucket['summary']['categories'] = categories
        bucket['summary']['total_parameters'] = params
    return by_base_url, stats


def build_openapi_inventory(recon_data: Dict, payload: Dict, stats: Dict) -> Dict:
    """What resource enumeration keeps of an OpenAPI run: an inventory, no operations.

    Per-group lists rather than scalar totals, so a Domain batch's canonical
    merge (which concatenates lists and keeps the first scalar) adds the groups
    up instead of reporting the first one.
    """
    inventory = {
        'groups': [{
            'root': recon_data.get('domain') or '',
            'documents': list(payload.get('documents') or []),
            'operations_count': int(stats.get('openapi_operations', 0)),
            'new_endpoints': int(stats.get('openapi_new', 0)),
        }],
        'diagnostics': list(payload.get('diagnostics') or []),
        'skipped_servers': list(payload.get('skipped_servers') or []),
        'source_status': list(payload.get('source_status') or []),
        'requests': list(payload.get('requests') or []),
    }
    for key in ('degraded', 'unreachable_hosts'):
        if key in payload:
            inventory[key] = payload[key]
    return inventory
