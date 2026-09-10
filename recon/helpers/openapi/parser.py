"""Version-aware operation parsing; no operation requests are executed."""
import copy
import hashlib
import json
import re
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

from .fetch import DocumentError, decode_document, http_url, origin, public_url

METHODS = ('get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace')


def safe_reference(reference):
    document_url, fragment = urldefrag(reference)
    return public_url(document_url) + ('#' + fragment if fragment else '')


class ServerDefinition(dict):
    """Reference base travels outside document keys and is never serialized."""
    def __init__(self, value, document_url):
        super().__init__(value)
        self.document_url = document_url


class Resolver:
    def __init__(self, document, document_url, fetcher, headers, diagnostics):
        self.documents = {document_url: document}
        self.document_bases = {document_url: document_url}
        self.fetcher = fetcher
        self.headers = headers
        self.origin = origin(document_url)
        self.diagnostics = diagnostics
        self.remaining = 100000
        self.schema_siblings = str(document.get('openapi', '')).startswith('3.1.')

    def expand(self, value, base, stack=(), depth=0, context='object'):
        self.remaining -= 1
        if self.remaining < 0 or depth > 64:
            raise DocumentError('Reference expansion limit reached')
        if isinstance(value, list):
            return [self.expand(v, base, stack, depth + 1, context) for v in value]
        if not isinstance(value, dict):
            return value
        if context in ('schema_map', 'example_map', 'reference_map'):
            child_context = {'schema_map': 'schema', 'example_map': 'example', 'reference_map': 'object'}[context]
            return {str(k): self.expand(v, base, stack, depth + 1, child_context) for k, v in value.items()}
        if '$ref' in value:
            reference = value['$ref']
            if not isinstance(reference, str):
                raise DocumentError('Invalid reference')
            absolute = urljoin(base, reference)
            if absolute in stack:
                return {'$ref': safe_reference(absolute)}
            document_url, fragment = urldefrag(absolute)
            document_url = http_url(document_url)
            try:
                if document_url not in self.documents:
                    final_url, text = self.fetcher.fetch(document_url, self.headers, self.origin)
                    parsed = decode_document(text)
                    self.documents[document_url] = parsed
                    self.document_bases[document_url] = final_url
                    self.document_bases[final_url] = final_url
                    self.documents.setdefault(final_url, parsed)
                target = self.documents[document_url]
                document_url = self.document_bases.get(document_url, document_url)
                if fragment:
                    pointer = unquote(fragment)
                    if not pointer.startswith('/'):
                        raise DocumentError('Non-pointer reference anchor is unsupported')
                    for token in pointer[1:].split('/'):
                        token = token.replace('~1', '/').replace('~0', '~')
                        target = target[int(token)] if isinstance(target, list) else target[token]
                resolved = self.expand(target, document_url, stack + (absolute,), depth + 1, context)
                siblings = self.expand({k: v for k, v in value.items() if k != '$ref'},
                                       base, stack, depth + 1, context)
                if siblings and isinstance(resolved, dict):
                    if context == 'schema' and self.schema_siblings:
                        resolved = {'allOf': [resolved, siblings]}
                    elif context == 'path_item':
                        resolved = {**resolved, **siblings}
                    elif self.schema_siblings:
                        resolved = {**resolved, **{k: v for k, v in siblings.items() if k in ('summary', 'description')}}
                return resolved
            except (DocumentError, KeyError, IndexError, TypeError, ValueError):
                self.diagnostics.append({'url': public_url(base), 'code': 'unresolved_reference',
                                         'message': 'A reference could not be resolved within document limits'})
                return {'$ref': safe_reference(absolute)}
        result = {}
        for key, child in value.items():
            if (key.startswith('x-') or key == 'example'
                    or (context == 'example' and key == 'value')
                    or (context == 'schema' and key in ('default', 'enum', 'const', 'examples'))):
                result[key] = copy.deepcopy(child)
                continue
            child_context = 'object'
            if key == 'schema':
                child_context = 'schema'
            elif context == 'schema':
                child_context = 'schema_map' if key in ('properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas') else 'schema'
            elif key == 'examples':
                child_context = 'example_map'
            result[key] = self.expand(child, base, stack, depth + 1, child_context)
        if 'servers' in result and isinstance(result['servers'], list):
            result['servers'] = [ServerDefinition(server, base) if isinstance(server, dict) else server
                                 for server in result['servers']]
        return result


def server_urls(document, path_item, operation, document_url, override):
    if override:
        return [http_url(override)]
    if document.get('swagger') == '2.0':
        parts = urlsplit(document_url)
        schemes = operation.get('schemes', document.get('schemes', [parts.scheme]))
        host = document.get('host', parts.netloc)
        base_path = document.get('basePath', '/')
        if not isinstance(base_path, str) or not base_path.startswith('/'):
            raise DocumentError('Invalid Swagger basePath')
        return [http_url(f'{scheme}://{host}{base_path}') for scheme in schemes if scheme in ('http', 'https')]
    servers = operation.get('servers', path_item.get('servers', document.get('servers'))) or [{'url': '/'}]
    if not isinstance(servers, list):
        raise DocumentError('Invalid servers array')
    urls = []
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get('url'), str):
            raise DocumentError('Invalid server object')
        def substitute(match):
            variable = server.get('variables', {}).get(match.group(1), {})
            if not isinstance(variable.get('default'), str):
                raise DocumentError('Server variable has no string default')
            return variable['default']
        url = re.sub(r'\{([^{}]+)\}', substitute, server['url'])
        urls.append(http_url(urljoin(getattr(server, 'document_url', document_url), url)))
    return urls


def parse_operations(document, document_url, document_hash, fetcher, headers, scope, diagnostics, override=None, budget=None):
    budget = budget if budget is not None else {'bytes': 16 * 1024 * 1024, 'operations': 10000}
    version = document.get('openapi') or document.get('swagger')
    if not isinstance(version, str) or not (version == '2.0' or re.fullmatch(r'3\.[01]\.\d+', version)):
        raise DocumentError('unsupported_version')
    paths = document.get('paths', {})
    if not isinstance(paths, dict) or not isinstance(document.get('info'), dict):
        raise DocumentError('Invalid OpenAPI document structure')
    resolver = Resolver(document, document_url, fetcher, headers, diagnostics)
    operations = []
    for path, raw_path_item in paths.items():
        if (not isinstance(path, str) or not path.startswith('/') or '?' in path or '#' in path
                or '\\' in path or any(ord(char) <= 32 or ord(char) == 127 for char in path)):
            diagnostics.append({'url': public_url(document_url), 'code': 'invalid_path', 'message': 'Invalid operation path'})
            continue
        try:
            path_item = resolver.expand(raw_path_item, document_url, context='path_item')
            if not isinstance(path_item, dict) or '$ref' in path_item:
                raise DocumentError('Unresolved or invalid path item')
        except (DocumentError, TypeError, ValueError, AttributeError, RecursionError):
            diagnostics.append({'url': public_url(document_url), 'code': 'invalid_operation',
                                'message': 'Path item could not be fully parsed'})
            continue
        for method in METHODS:
            if method not in path_item:
                continue
            if budget['operations'] <= 0 or budget['bytes'] <= 0:
                diagnostics.append({'url': public_url(document_url), 'code': 'limit_reached',
                                    'message': 'Operation inventory budget exhausted'})
                return operations, version
            try:
                operation = path_item[method]
                if not isinstance(operation, dict) or '$ref' in operation:
                    raise DocumentError('Unresolved or invalid operation')
                operation = copy.deepcopy(operation)
                parameters = {}
                for param in list(path_item.get('parameters', [])) + list(operation.get('parameters', [])):
                    if not isinstance(param, dict):
                        raise DocumentError('Invalid parameter object')
                    if 'name' in param and 'in' in param:
                        parameters[(param['name'], param['in'])] = param
                    else:
                        parameters[('$ref', len(parameters))] = param
                operation['parameters'] = list(parameters.values())
                operation.setdefault('security', copy.deepcopy(document.get('security', [])))
                catalog = (document.get('securityDefinitions', {}) if version == '2.0'
                           else document.get('components', {}).get('securitySchemes', {}))
                names = {name for requirement in operation['security'] for name in requirement}
                operation['securitySchemes'] = resolver.expand(
                    {name: catalog[name] for name in names if name in catalog}, document_url, context='reference_map')
                for key in ('consumes', 'produces'):
                    if version == '2.0' and key not in operation and key in document:
                        operation[key] = document[key]
                for server in server_urls(document, path_item, operation, document_url, override):
                    parts = urlsplit(server)
                    if parts.query or parts.fragment:
                        raise DocumentError('API server URL must not contain query or fragment')
                    full_path = parts.path.rstrip('/') + path
                    baseurl = origin(server)
                    if not scope.allows(baseurl):
                        diagnostics.append({'url': public_url(server), 'code': 'out_of_scope',
                                            'message': 'Declared API server is outside target scope'})
                        continue
                    operation_ref = '#/paths/' + path.replace('~', '~0').replace('/', '~1') + '/' + method
                    clean_operation = copy.deepcopy(operation)
                    size = 0
                    for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False).iterencode(clean_operation):
                        size += len(chunk.encode('utf-8'))
                        if size > min(1024 * 1024, budget['bytes']):
                            raise DocumentError('Operation output limit reached')
                    budget['bytes'] -= size
                    budget['operations'] -= 1
                    operations.append({'baseurl': baseurl, 'path': full_path, 'method': method.upper(),
                                       'source_url': public_url(document_url), 'document_hash': document_hash,
                                       'source_id': hashlib.sha256(document_url.encode()).hexdigest(),
                                       'operation_ref': operation_ref, 'operation': clean_operation})
            except (DocumentError, TypeError, ValueError, AttributeError, RecursionError) as error:
                limited = isinstance(error, DocumentError) and 'limit' in str(error)
                diagnostics.append({'url': public_url(document_url), 'code': 'limit_reached' if limited else 'invalid_operation',
                                    'message': 'Operation output limit reached' if limited else 'Operation could not be fully parsed'})
    return operations, version
