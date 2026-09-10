"""Discover OpenAPI descriptions and enumerate target-scoped operations."""
import copy
import hashlib
import json
import re
from collections import deque
from html import unescape
from urllib.parse import urljoin, urlsplit

from graph_db.mixins.recon.openapi_scope import Scope
from recon.helpers.openapi.fetch import DocumentError, Fetcher, decode_document, http_url, origin, parse_headers, public_url
from recon.helpers.openapi.parser import parse_operations

DISCOVERY_PATHS = ('/openapi.json', '/openapi.yaml', '/swagger.json', '/swagger.yaml',
                   '/v3/api-docs', '/v2/api-docs', '/swagger/v1/swagger.json',
                   '/swagger-ui/index.html', '/swagger-ui.html', '/docs', '/api-docs', '/api-docs/')


class Diagnostics(list):
    def append(self, entry):
        if len(self) < 1000:
            super().append(entry)
        else:
            self[-1] = {'url': '', 'code': 'limit_reached',
                        'message': 'Additional diagnostics omitted after 1000 entries'}


def scope_payload(settings):
    root = str(settings.get('TARGET_DOMAIN') or '').strip().lower().rstrip('.')
    prefixes = settings.get('SUBDOMAIN_LIST') or []
    actual = [p.rstrip('.') for p in prefixes if isinstance(p, str) and p.rstrip('.')]
    if settings.get('IP_MODE'):
        return {'root': '', 'hosts': [], 'include_subdomains': False, 'include_root': False,
                'ip_networks': list(settings.get('TARGET_IPS') or []),
                'excluded_hosts': list(settings.get('ROE_EXCLUDED_HOSTS') or []) if settings.get('ROE_ENABLED') else []}
    return {'root': root,
            'hosts': [f'{p}.{root}' for p in actual],
            'include_subdomains': not actual,
            'include_root': any(isinstance(p, str) and not p.rstrip('.') for p in prefixes),
            'ip_networks': list(settings.get('TARGET_IPS') or []) if settings.get('IP_MODE') else [],
            'excluded_hosts': list(settings.get('ROE_EXCLUDED_HOSTS') or []) if settings.get('ROE_ENABLED') else []}


def linked_documents(text, document):
    """Extract literal documentation links; never evaluate a page's JavaScript."""
    links = []
    if isinstance(document, dict):
        for key in ('url', 'configUrl'):
            if isinstance(document.get(key), str):
                links.append(document[key])
        for entry in document.get('urls', []) if isinstance(document.get('urls'), list) else []:
            if isinstance(entry, dict) and isinstance(entry.get('url'), str):
                links.append(entry['url'])
    if re.search(r'SwaggerUI|swagger|redoc|spec-url', text, re.I):
        links.extend(re.findall(r'''(?:["']?(?:url|configUrl)["']?\s*:\s*|spec-url\s*=\s*)["']([^"']+)["']''', text))
        for link in re.findall(r'''(?:href|src)\s*=\s*["']([^"']+)["']''', text, re.I):
            if re.search(r'openapi|swagger.*(?:json|yaml|yml|init.*js)|api-docs', link, re.I):
                links.append(link)
    return list(dict.fromkeys(unescape(link) for link in links))


def embedded_document(text):
    """Read JSON literals emitted by Swagger UI generators without evaluating JS."""
    if not re.search(r'SwaggerUI|swaggerDoc', text):
        return None
    decoder = json.JSONDecoder()
    pattern = r'''(?:["'](?:swaggerDoc|spec)["']|\b(?:swaggerDoc|spec))\s*:\s*(?=\{)'''
    for index, match in enumerate(re.finditer(pattern, text)):
        if index >= 20:
            break
        try:
            value, end = decoder.raw_decode(text, match.end())
            if isinstance(value, dict) and ('openapi' in value or 'swagger' in value):
                # Apply the same duplicate-key, nesting and value restrictions as direct specs.
                return decode_document(text[match.end():end])
        except (ValueError, RecursionError, DocumentError):
            continue
    return None


def run_openapi_recon(recon_data: dict, settings: dict) -> dict:
    if not settings.get('OPENAPI_ENABLED', True):
        return recon_data
    scope_data = scope_payload(settings)
    scope = Scope.from_payload(scope_data)
    output = {'scope': scope.to_payload(), 'operations': [], 'documents': [], 'diagnostics': Diagnostics()}
    recon_data['openapi'] = output
    diagnostics = output['diagnostics']
    if not scope.is_valid:
        diagnostics.append({'url': '', 'code': 'invalid_scope', 'message': 'OpenAPI requires a configured target'})
        return recon_data
    max_documents = min(max(int(settings.get('OPENAPI_MAX_DOCUMENTS', 50)), 1), 200)
    fetcher = Fetcher(settings.get('OPENAPI_TIMEOUT', 10), max_requests=max_documents * 10)
    queue = deque()
    seen = set()
    source_count = 0

    def enqueue(url, headers, override=None, explicit=False, allowed_origin=None, context_id=None):
        try:
            url = http_url(url)
            allowed_origin = allowed_origin or origin(url)
            if origin(url) != allowed_origin:
                raise DocumentError('Cross-origin documentation link blocked')
            context_id = context_id or url
            key = (url, tuple(sorted(headers.items())), override, context_id)
            if key not in seen and len(seen) < 2000:
                seen.add(key)
                queue.append((url, headers, override, explicit, allowed_origin, context_id))
        except DocumentError as error:
            diagnostics.append({'url': public_url(url), 'code': 'fetch_failed', 'message': str(error)})

    for source in settings.get('OPENAPI_SOURCES') or []:
        if not isinstance(source, dict) or not source.get('enabled', True):
            continue
        try:
            headers = parse_headers(source.get('headers', []))
            enqueue(source.get('url'), headers, source.get('serverOverride') or None, True,
                    context_id=f"configured:{source.get('id') or source.get('url')}")
            source_count += 1
        except DocumentError as error:
            diagnostics.append({'url': public_url(source.get('url')), 'code': 'invalid_source', 'message': str(error)})

    if settings.get('OPENAPI_AUTO_DISCOVER', True):
        discovery_paths = settings.get('OPENAPI_DISCOVERY_PATHS', list(DISCOVERY_PATHS))
        if (not isinstance(discovery_paths, list) or len(discovery_paths) > 200
                or any(not isinstance(path, str) or len(path) > 2048
                       or not path.startswith('/') or path.startswith('//')
                       or re.search(r'[\s\x00-\x1f\x7f\\?#]', path) for path in discovery_paths)):
            diagnostics.append({'url': '', 'code': 'invalid_source',
                                'message': 'Discovery paths must be at most 200 origin-relative paths without queries or fragments'})
            discovery_paths = []
        auth_by_origin = {}
        for entry in settings.get('OPENAPI_DISCOVERY_HEADERS') or []:
            try:
                auth_by_origin[origin(entry['origin'])] = parse_headers(entry.get('headers'))
            except (DocumentError, TypeError, KeyError):
                diagnostics.append({'url': '', 'code': 'invalid_source', 'message': 'Invalid discovery header configuration'})
        candidates = set((recon_data.get('http_probe') or {}).get('by_url', {}))
        resources = (recon_data.get('resource_enum') or {}).get('by_base_url', {})
        candidates.update(resources)
        for base, data in resources.items():
            for path in data.get('endpoints', {}):
                if re.search(r'openapi|swagger|api-docs|/docs', path, re.I):
                    candidates.add(base.rstrip('/') + path)
        origins = set()
        for url in sorted(candidates):
            try:
                if not scope.allows(url):
                    continue
                base = origin(url)
                origins.add(base)
                if re.search(r'openapi|swagger|api-docs|/docs', urlsplit(url).path, re.I):
                    enqueue(url, auth_by_origin.get(base, {}), explicit=True)
            except DocumentError:
                continue
        for base in sorted(origins):
            for path in dict.fromkeys(discovery_paths):
                enqueue(base + path, auth_by_origin.get(base, {}))

    print(f'[*][OpenAPI] Processing {source_count} configured sources and {len(queue)} document candidates')
    budget = {'bytes': 16 * 1024 * 1024, 'operations': 10000}
    try:
        while queue and len(output['documents']) < max_documents and fetcher.count < fetcher.max_requests:
            url, headers, override, explicit, allowed_origin, context_id = queue.popleft()
            try:
                final_url, text = fetcher.fetch(url, headers, allowed_origin)
            except DocumentError as error:
                # Ordinary missing common paths are expected; configured sources
                # and authentication failures must always be visible.
                if explicit or '404' not in str(error):
                    diagnostics.append({'url': public_url(url), 'code': 'fetch_failed', 'message': str(error)})
                continue
            decode_error = None
            try:
                document = decode_document(text)
            except DocumentError as error:
                decode_error = str(error)
                document = None
            if document is None:
                document = embedded_document(text)
            if isinstance(document, dict) and ('openapi' in document or 'swagger' in document):
                try:
                    document_hash = hashlib.sha256(text.encode()).hexdigest()
                    operations, version = parse_operations(document, final_url, document_hash, fetcher,
                                                           headers, scope, diagnostics, override, budget)
                    source_id = hashlib.sha256((context_id + '\0' + url).encode()).hexdigest()
                    for operation in operations:
                        operation['source_id'] = source_id
                        operation['source_url'] = public_url(url)
                    output['operations'].extend(operations)
                    output['documents'].append({'url': public_url(url), 'sha256': document_hash,
                                                'source_id': source_id,
                                                'version': version, 'operation_count': len(operations)})
                except DocumentError as error:
                    code = 'unsupported_version' if str(error) == 'unsupported_version' else 'invalid_document'
                    diagnostics.append({'url': public_url(final_url), 'code': code, 'message': str(error)})
            else:
                links = linked_documents(text, document)
                if not links and explicit:
                    diagnostics.append({'url': public_url(final_url), 'code': 'invalid_document',
                                        'message': decode_error or 'No OpenAPI description or static documentation links found'})
                for link in links:
                    child_context = context_id if context_id.startswith('configured:') else None
                    enqueue(urljoin(final_url, link), headers, override, True, allowed_origin, child_context)
        if queue:
            diagnostics.append({'url': '', 'code': 'limit_reached', 'message': 'Document budget exhausted; inventory is incomplete'})
    finally:
        fetcher.close()
    unique = {}
    for operation in output['operations']:
        key = tuple(operation[field] for field in ('baseurl', 'path', 'method', 'source_id', 'operation_ref'))
        unique[key] = operation
    output['operations'] = list(unique.values())
    print(f"[+][OpenAPI] Parsed {len(output['operations'])} declarations from {len(output['documents'])} documents; {len(diagnostics)} diagnostics")
    return recon_data


def run_openapi_recon_isolated(recon_data: dict, settings: dict) -> dict:
    snapshot = copy.deepcopy(recon_data)
    run_openapi_recon(snapshot, settings)
    return snapshot.get('openapi', {})
