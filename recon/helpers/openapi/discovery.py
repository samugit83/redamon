"""Find and parse the OpenAPI documents of one recon run.

Resource enumeration calls this after its crawlers have merged (full run), and
partial recon calls it on its own. It fetches documents and parses their
operations; it never requests a declared operation. It never raises: OpenAPI
is one endpoint source among several, and its failure must not cost the run
the others.
"""
import hashlib
import ipaddress
import re
from collections import deque
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urljoin, urlsplit

from helpers import proxy_routing
from recon.helpers.auth_profile import auth_header_lines, profile_from_settings
from recon.helpers import request_pacer
from recon.helpers.openapi.fetch import (
    DocumentError, Fetcher, decode_document, http_url, origin, parse_headers, public_url,
)
from recon.helpers.openapi.parser import parse_operations
from recon.helpers.openapi.scope import Scope

DISCOVERY_PATHS = ('/openapi.json', '/openapi.yaml', '/swagger.json', '/swagger.yaml',
                   '/v3/api-docs', '/v2/api-docs', '/swagger/v1/swagger.json',
                   '/swagger-ui/index.html', '/swagger-ui.html', '/docs', '/api-docs', '/api-docs/')

SPEC_LIKE_PATH = re.compile(r'openapi|swagger|api-docs|/docs', re.I)

MAX_DIAGNOSTICS = 1000
MAX_SKIPPED_SERVERS = 200
MAX_LEDGER = 500


class Diagnostics(list):
    def append(self, entry):
        if len(self) < MAX_DIAGNOSTICS:
            super().append(entry)
        else:
            self[-1] = {'url': '', 'code': 'limit_reached',
                        'message': f'Additional diagnostics omitted after {MAX_DIAGNOSTICS} entries'}


def _pacer_for(settings):
    """The process-wide request clock (recon/helpers/request_pacer.py), so the RoE
    ceiling holds across the groups of a Domain batch, a partial run's roots and
    every other in-process requester. A partial run's process may not have
    configured it yet; the settings do then."""
    return request_pacer.pacer(settings)


def _reset_pacer():
    request_pacer.reset()


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _norm_host(value):
    return str(value or '').strip().strip('[]').rstrip('.').lower()


def scope_payload(settings, group=None, ip_mode_hosts=None):
    """The OpenAPI fetch scope of one target, as a Scope payload.

    With a scope group (SCOPE_GROUPS) it is the group's auth scope, the same
    hosts the webapp's authScopePatterns names: an ENUMERATE group's strict
    subdomains, an EXACT group's listed hosts, the scan root only with Include
    Root. Without one, the legacy TARGET_DOMAIN + SUBDOMAIN_LIST reading.

    IP mode: the target networks, plus ``ip_mode_hosts``, the hostnames the
    run's selection rule scanned on them (a recorded name is no target).
    """
    excluded = list(settings.get('ROE_EXCLUDED_HOSTS') or []) if settings.get('ROE_ENABLED') else []
    if group is not None and not settings.get('IP_MODE'):
        return {'root': _norm_host(group.get('scanRoot')),
                'hosts': [_norm_host(h) for h in group.get('exactHosts') or [] if _norm_host(h)],
                'include_subdomains': group.get('mode') == 'enumerate',
                'include_root': bool(group.get('includeRoot')),
                'ip_networks': [],
                'excluded_hosts': excluded}
    root = _norm_host(settings.get('TARGET_DOMAIN'))
    prefixes = [p.strip() for p in settings.get('SUBDOMAIN_LIST') or [] if isinstance(p, str)]
    if settings.get('IP_MODE'):
        names = sorted({_norm_host(h) for h in (ip_mode_hosts or {}) if _norm_host(h)})
        return {'root': '', 'hosts': names, 'include_subdomains': False, 'include_root': False,
                'ip_networks': list(settings.get('TARGET_IPS') or []), 'excluded_hosts': excluded}
    wildcard = '*' in prefixes
    actual = [p.rstrip('.') for p in prefixes if p.rstrip('.') and p != '*']
    return {'root': root,
            'hosts': [f'{p}.{root}' for p in actual],
            'include_subdomains': wildcard or (not actual and not settings.get('DOMAIN_BATCH_MODE')),
            'include_root': any(not p.rstrip('.') for p in prefixes),
            'ip_networks': [],
            'excluded_hosts': excluded}


def operator_targets(settings, extra_urls=()):
    """Hosts and networks the operator typed, exempt from the address guard.

    Mirrors the pipeline's rule for discovered names: what the operator named
    is scanned whatever it resolves to (recon/main.py, "Operator-supplied hosts
    are NOT filtered"), and IP mode applies no never-scannable filter.
    """
    from recon.helpers.batch_groups import settings_scope_groups
    hosts, networks = set(), []
    batch = bool(settings.get('DOMAIN_BATCH_MODE'))
    for group in settings_scope_groups(settings) if not settings.get('IP_MODE') else []:
        root = _norm_host(group.get('scanRoot'))
        hosts.update(_norm_host(h) for h in group.get('exactHosts') or [])
        # A batch root is named only when listed; a single-domain target is
        # the name the operator typed either way.
        if root and (group.get('includeRoot') or not batch):
            hosts.add(root)
    for value in settings.get('TARGET_IPS') or []:
        try:
            networks.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            continue
    for url in extra_urls:
        try:
            hosts.add(_norm_host(urlsplit(http_url(url)).hostname))
        except DocumentError:
            continue
    hosts.discard('')
    return hosts, networks


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
    import json
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


def valid_discovery_paths(paths, diagnostics):
    """Keep each valid origin-relative path; one bad entry no longer drops the list."""
    if paths is None:
        return list(DISCOVERY_PATHS)
    if not isinstance(paths, list):
        diagnostics.append({'url': '', 'code': 'invalid_source',
                            'message': 'Discovery paths must be a list'})
        return []
    kept = []
    for path in paths[:200]:
        if (not isinstance(path, str) or len(path) > 2048 or not path.startswith('/')
                or path.startswith('//') or re.search(r'[\s\x00-\x1f\x7f\\?#]', path)):
            diagnostics.append({'url': '', 'code': 'invalid_source',
                                'message': 'Discovery path skipped: it must be origin-relative, '
                                           'without whitespace, a query or a fragment'})
            continue
        kept.append(path)
    if len(paths) > 200:
        diagnostics.append({'url': '', 'code': 'invalid_source',
                            'message': 'Only the first 200 discovery paths are used'})
    return list(dict.fromkeys(kept))


class _Health:
    """The circuit-breaker hooks the fetcher calls; never raises (jsluice pattern)."""

    def __init__(self):
        self.scope = None
        try:
            from recon.helpers import circuit_breaker as cb
            self.scope = cb.scope((), label='OpenAPI', unit='host(s)')
            self._is_connection_failure = cb.is_connection_failure
        except Exception:  # noqa: BLE001
            self._is_connection_failure = lambda exc: False

    def skip_if_down(self, url):
        try:
            return bool(self.scope and self.scope.skip_if_down(url))
        except Exception:  # noqa: BLE001
            return False

    def host_alive(self, url):
        try:
            if self.scope:
                self.scope.host_alive(url)
        except Exception:  # noqa: BLE001
            pass

    def host_failed(self, url, exc):
        try:
            if self.scope and self._is_connection_failure(exc):
                self.scope.host_failed(url, exc)
        except Exception:  # noqa: BLE001
            pass

    def finish(self, payload):
        try:
            if self.scope:
                self.scope.finish('resource_enum', host_source='resource_enum', payload=payload)
        except Exception:  # noqa: BLE001
            pass


def _empty_result():
    return {'documents': [], 'operations': [], 'diagnostics': Diagnostics(), 'skipped_servers': [],
            'source_status': [], 'requests': []}


def run_openapi_discovery(recon_data, settings, seed_urls=(), *, documents=(), title_seeds=()):
    """Fetch and parse this run's OpenAPI documents.

    ``seed_urls``: live URLs and crawled URLs; used only with auto-discover on.
    ``documents``: URLs the operator typed in a partial run, fetched as
    specification documents whatever auto-discover says.
    ``title_seeds``: pages titled like an API description (Swagger UI, ReDoc);
    with auto-discover on they are enqueued whatever their path.

    Returns ``{documents, operations, diagnostics, skipped_servers,
    source_status, requests}``. Operations are transient: the caller merges
    them into ``by_base_url`` and keeps nothing else of them.
    """
    result = _empty_result()
    try:
        _discover(recon_data or {}, settings or {}, list(seed_urls or ()), list(documents or ()), result,
                  title_seeds=list(title_seeds or ()))
    except Exception:  # noqa: BLE001
        # Request exceptions can embed credentials; log a fixed text only.
        print('[!][OpenAPI] Ingestion failed')
        result['operations'] = []
        result['documents'] = []
        result['diagnostics'].append({'url': '', 'code': 'ingestion_failed',
                                      'message': 'OpenAPI ingestion failed'})
    return result


def _source_hash(url):
    return hashlib.sha256(public_url(url).encode()).hexdigest()[:12]


def _discover(recon_data, settings, seed_urls, explicit_urls, result, title_seeds=()):
    if not settings.get('OPENAPI_ENABLED', True):
        return
    if settings.get('STEALTH_MODE', False):
        print('[-][OpenAPI] Stealth mode: no document is fetched')
        return
    diagnostics = result['diagnostics']

    from recon.helpers.batch_groups import settings_scope_groups
    groups = settings_scope_groups(settings) if not settings.get('IP_MODE') else []
    own_group = groups[0] if groups else None
    own_index = 0
    group_scopes = []
    if settings.get('DOMAIN_BATCH_MODE'):
        own_root = _norm_host(recon_data.get('domain'))
        own_index = next((i for i, g in enumerate(groups) if _norm_host(g.get('scanRoot')) == own_root), None)
        own_group = groups[own_index] if own_index is not None else None
        if own_group is None:
            diagnostics.append({'url': '', 'code': 'invalid_scope',
                                'message': 'This run is not one of the Domain batch groups'})
            print('[!][OpenAPI] Domain batch: this run is not an approved group; nothing fetched')
            return
        group_scopes = [Scope.from_payload(scope_payload(settings, g)) for g in groups]

    scope = Scope.from_payload(scope_payload(
        settings, own_group, ip_mode_hosts=((recon_data or {}).get('metadata') or {}).get('ip_mode_hosts')))
    if not scope.is_valid:
        diagnostics.append({'url': '', 'code': 'invalid_scope', 'message': 'OpenAPI requires a configured target'})
        return

    def owner_of(url):
        """D18: the index of the first group whose scope allows the URL, else None.

        Outside a batch the run is its own single group, index 0.
        """
        if not group_scopes:
            return 0 if scope.allows(url) else None
        return next((i for i, s in enumerate(group_scopes) if s.allows(url)), None)

    sources = []
    for source in settings.get('OPENAPI_SOURCES') or []:
        if isinstance(source, dict) and source.get('enabled', True) and isinstance(source.get('url'), str):
            sources.append(source)
    configured_urls = [s['url'] for s in sources]
    operator_hosts, operator_networks = operator_targets(settings, configured_urls + explicit_urls)

    max_documents = min(max(int(settings.get('OPENAPI_MAX_DOCUMENTS', 50) or 50), 1), 200)
    try:
        proxy_routing.configure(settings)
    except Exception:  # noqa: BLE001
        pass

    from recon.main_recon_modules.ip_filter import is_address_safe_to_scan

    def address_guard(host):
        return is_address_safe_to_scan(host, operator_hosts, operator_networks)

    ledger = result['requests']

    def on_request(url, code, session, routed):
        public = public_url(url)
        if len(ledger) < MAX_LEDGER:
            ledger.append({'url': public, 'code': code, 'session_headers': bool(session),
                           'routed_via_capture': bool(routed), 'at': _now()})
        print(f"[*][OpenAPI] GET {public} session={'yes' if session else 'no'} "
              f"capture={'yes' if routed else 'no'} -> {code}")

    health = _Health()
    fetcher = Fetcher(settings.get('OPENAPI_TIMEOUT', 10), max_requests=max_documents * 10,
                      pacer=_pacer_for(settings), address_guard=address_guard,
                      health=health, on_request=on_request)

    # Status per configured source (D19): its id, a hash of its URL, a code.
    status = {}

    def set_status(source, code, *, overwrite=True):
        key = source.get('id') or _source_hash(source['url'])
        if overwrite or key not in status:
            status[key] = (source, code)

    queue = deque()
    seen = set()

    def refuse_out_of_scope(url, listed):
        diagnostics.append({'url': public_url(url), 'code': 'out_of_scope',
                            'message': 'Document source is outside engagement scope'})
        # A document the operator listed is named in the log; a link found
        # while discovering is only counted, or a hostile page could flood it.
        if listed:
            print(f'[-][OpenAPI] Outside the project scope, not fetched: {public_url(url)}')

    def enqueue(url, override=None, explicit=False, allowed_origin=None, context=None, listed=False):
        try:
            url = http_url(url)
            if not scope.allows(url):
                refuse_out_of_scope(url, listed)
                return 'out_of_scope'
            allowed_origin = allowed_origin or origin(url)
            if origin(url) != allowed_origin:
                raise DocumentError('Cross-origin documentation link blocked', code='out_of_scope')
            headers = parse_headers(auth_header_lines(profile_from_settings(settings),
                                                      urlsplit(url).hostname, settings))
            key = (url, tuple(sorted(headers.items())), override, (context or {}).get('id') or url)
            if key not in seen and len(seen) < 2000:
                seen.add(key)
                queue.append((url, headers, override, explicit, allowed_origin, context or {}))
            return None
        except DocumentError as error:
            diagnostics.append({'url': public_url(url), 'code': 'fetch_failed', 'message': str(error)})
            return error.code

    for source in sources:
        owner = owner_of(source['url'])
        if owner is None:
            # Allowed by no group: reported once, by the first group.
            if own_index == 0:
                refuse_out_of_scope(source['url'], True)
                set_status(source, 'out_of_scope')
            continue
        if owner != own_index:
            continue
        refused = enqueue(source['url'], source.get('serverOverride') or None, True,
                          context={'id': f"configured:{source.get('id') or source['url']}", 'source': source},
                          listed=True)
        if refused:
            set_status(source, refused)

    for url in explicit_urls:
        owner = owner_of(url)
        if owner is None and own_index == 0:
            enqueue(url, listed=True)  # records the out_of_scope diagnostic
        elif owner == own_index:
            enqueue(url, None, True, context={'id': f'custom:{url}', 'custom': True}, listed=True)

    if settings.get('OPENAPI_AUTO_DISCOVER', False):
        paths = valid_discovery_paths(settings.get('OPENAPI_DISCOVERY_PATHS'), diagnostics)
        origins = set()
        flagged = set(title_seeds or ())
        for url in sorted(set(seed_urls) | flagged):
            try:
                if not scope.allows(url):
                    continue
                origins.add(origin(url))
                if url in flagged or SPEC_LIKE_PATH.search(urlsplit(url).path):
                    enqueue(url, explicit=True)
            except (DocumentError, ValueError):
                continue
        for base in sorted(origins):
            for path in paths:
                enqueue(base + path)

    print(f'[*][OpenAPI] Processing {len(sources)} configured source(s) and {len(queue)} document candidate(s)')
    budget = {'bytes': 16 * 1024 * 1024, 'operations': 10000}
    child_outcome = {}
    try:
        while queue and len(result['documents']) < max_documents and fetcher.count < fetcher.max_requests:
            url, headers, override, explicit, allowed_origin, context = queue.popleft()
            source = context.get('source')
            try:
                final_url, text = fetcher.fetch(url, headers, allowed_origin)
            except DocumentError as error:
                # Missing common paths are expected; explicit documents, guard
                # refusals and authentication failures stay visible.
                if explicit or error.code != 'http_404':
                    code = error.code if error.code in ('blocked_address', 'host_down') else 'fetch_failed'
                    diagnostics.append({'url': public_url(url), 'code': code, 'message': str(error)})
                if source is not None:
                    child_outcome.setdefault(context['id'], error.code)
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
                    source_id = hashlib.sha256((context.get('id', url) + '\0' + url).encode()).hexdigest()
                    for operation in operations:
                        operation['source_id'] = source_id
                        operation['source_url'] = public_url(url)
                        operation['custom'] = bool(context.get('custom'))
                    result['operations'].extend(operations)
                    result['documents'].append({'url': public_url(url),
                                                'sha256': document_hash, 'source_id': source_id,
                                                'version': version, 'operation_count': len(operations)})
                    if source is not None:
                        child_outcome[context['id']] = 'ok'
                except DocumentError as error:
                    code = 'unsupported_version' if str(error) == 'unsupported_version' else 'invalid_document'
                    diagnostics.append({'url': public_url(final_url), 'code': code, 'message': str(error)})
                    if source is not None:
                        child_outcome.setdefault(context['id'], code)
            else:
                links = linked_documents(text, document)
                if not links and explicit:
                    diagnostics.append({'url': public_url(final_url), 'code': 'invalid_document',
                                        'message': decode_error or 'No OpenAPI description or static documentation links found'})
                    if source is not None:
                        child_outcome.setdefault(context['id'], 'invalid_document')
                for link in links:
                    child = context if context.get('id', '').startswith(('configured:', 'custom:')) else {}
                    enqueue(urljoin(final_url, link), override, True, allowed_origin, child)
        if queue:
            diagnostics.append({'url': '', 'code': 'limit_reached',
                                'message': 'Document budget exhausted; inventory is incomplete'})
            for *_, context in queue:
                if context.get('source') is not None:
                    child_outcome.setdefault(context['id'], 'limit_reached')
    finally:
        fetcher.close()

    for source in sources:
        cid = f"configured:{source.get('id') or source['url']}"
        if cid in child_outcome:
            set_status(source, child_outcome[cid], overwrite=False)

    unique = {}
    for operation in result['operations']:
        key = tuple(operation[field] for field in ('baseurl', 'path', 'method', 'source_id', 'operation_ref'))
        unique[key] = operation
    operations = list(unique.values())

    # D2: a declared server on a host this run has not discovered is neither
    # written nor fetched; list it so the operator can see what was left out.
    try:
        from graph_db.mixins.recon.scope import build_host_scope, host_in_scope
        host_scope = build_host_scope(recon_data)
    except Exception:  # noqa: BLE001
        host_scope, host_in_scope = None, None
    if host_scope is not None:
        kept, skipped = [], {}
        for operation in operations:
            if host_in_scope(operation['baseurl'], host_scope):
                kept.append(operation)
            else:
                skipped.setdefault(operation['baseurl'], None)
        operations = kept
        result['skipped_servers'] = list(skipped)[:MAX_SKIPPED_SERVERS]
        if skipped:
            print(f'[-][OpenAPI] {len(skipped)} declared server(s) on undiscovered hosts not added')
    result['operations'] = operations

    at = _now()
    for source in sources:
        key = source.get('id') or _source_hash(source['url'])
        if key in status:
            result['source_status'].append(f"{source.get('id') or ''}|{_source_hash(source['url'])}|{status[key][1]}|{at}")

    health.finish(result)
    print(f"[+][OpenAPI] Parsed {len(operations)} declarations from {len(result['documents'])} documents; "
          f"{len(diagnostics)} diagnostics")
