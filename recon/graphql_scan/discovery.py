"""
GraphQL Endpoint Discovery Module

Discovers potential GraphQL endpoints from multiple sources:
1. Explicit patterns (/graphql, /api/graphql, /v1/graphql) on live web roots
2. Resource enumeration results (resource_enum.by_base_url)
3. JS Recon endpoints (js_recon.endpoints)
4. URLScan pages with a GraphQL path (urlscan.urls_with_paths)
5. HTTP probe results (http_probe.by_url, content_type)
6. User-specified endpoints
"""

import re
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse


# Common GraphQL endpoint patterns (ordered by likelihood)
PRIMARY_GRAPHQL_PATTERNS = [
    '/graphql',
    '/api/graphql',
    '/v1/graphql',
    '/v2/graphql'
]

# Less common patterns - only try if we have evidence
SECONDARY_GRAPHQL_PATTERNS = [
    '/query',
    '/api/query',
    '/gql',
    '/api/gql',
    '/graphiql',
    '/api/graphiql',
    '/playground',
    '/api/playground',
]

# GraphQL indicators in response content
GRAPHQL_INDICATORS = [
    '__schema',
    '__type',
    'IntrospectionQuery',
    'GraphQL Playground',
    'GraphiQL',
    'application/graphql',
    '"query"',
    '"mutation"',
    '"subscription"',
]


def discover_graphql_endpoints(combined_result: dict, settings: dict) -> List[str]:
    """
    Discover potential GraphQL endpoints from multiple sources.

    Every source is read in the shape its writer produces (http_probe.by_url,
    resource_enum.by_base_url, js_recon.endpoints, urlscan.urls_with_paths);
    partial recon's graph builder produces the same shapes. Only candidates on
    a host in this run's scope are kept: a live http_probe host, or a host the
    run's scope admits. The operator's own GRAPHQL_ENDPOINTS pass the project's
    scope too (_typed_endpoints). The RoE exclusion list is applied by the
    caller (scanner.run_graphql_scan).

    Args:
        combined_result: The combined recon data
        settings: Project settings

    Returns:
        List of unique GraphQL endpoint URLs to test
    """
    admits = _scope_admits(combined_result)
    user_endpoints = _typed_endpoints(combined_result, settings, admits)

    # Only live, in-scope web roots get pattern guesses: never a URLScan page.
    base_urls = _extract_base_urls(combined_result)

    discovered = set()
    discovered.update(_extract_from_http_probe(combined_result))
    discovered.update(_extract_from_resource_enum(combined_result))
    discovered.update(_extract_from_js_recon(combined_result))
    discovered.update(_extract_from_urlscan(combined_result))

    # A base URL with GraphQL evidence gets the less common patterns too.
    evidence = {_origin(endpoint) for endpoint in discovered}
    for base_url in base_urls:
        patterns = PRIMARY_GRAPHQL_PATTERNS
        if base_url in evidence:
            patterns = PRIMARY_GRAPHQL_PATTERNS + SECONDARY_GRAPHQL_PATTERNS
        for pattern in patterns:
            discovered.add(urljoin(base_url, pattern))

    out_of_scope = sorted(e for e in discovered if not admits(urlparse(e).hostname or ''))
    if out_of_scope:
        print(f"[-][GraphQL] Scope: skipped {len(out_of_scope)} candidate(s) on hosts outside this run")
    unique_endpoints = sorted((discovered - set(out_of_scope)) | user_endpoints)

    print(f"[+][GraphQL] Discovered {len(unique_endpoints)} potential endpoints")
    return unique_endpoints


_GRAPHQL_PATH_HINTS = ('graphql', 'gql', 'query')
_GRAPHQL_PARAM_NAMES = {'query', 'mutation', 'variables', 'operationname'}


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _live_hosts(combined_result: dict) -> Set[str]:
    return {
        (urlparse(url).hostname or '').lower()
        for url in (combined_result.get('http_probe') or {}).get('by_url', {}) or {}
    } - {''}


def _scope_admits(combined_result: dict):
    """host -> bool: a live http_probe host, or one this run's scope admits
    (the group's scope from its metadata; a partial run's roots)."""
    from recon.helpers.recon_scope import recon_scope

    live = _live_hosts(combined_result)
    scope = recon_scope(combined_result)
    roots = [str(r).strip().strip('.').lower()
             for r in combined_result.get('domains') or [] if str(r).strip()]

    def admits(host: str) -> bool:
        host = (host or '').strip().strip('.').lower()
        if not host:
            return False
        if host in live or scope.admits(host):
            return True
        return any(host == root or host.endswith('.' + root) for root in roots)

    return admits


def _endpoint_host(endpoint: str) -> str:
    try:
        return (urlparse(endpoint).hostname or '').lower()
    except ValueError:  # an unbalanced IPv6 bracket
        return ''


def _project_admits(settings: dict):
    """host -> bool: where the project's authenticated session may go (its
    scope groups, or its target IPs and CIDRs), the rule the project
    AuthProfile uses. Unreadable means no host (fail closed)."""
    from recon.helpers.auth_profile import default_scope_hosts, host_in_scope
    try:
        scope = default_scope_hosts(settings)
    except Exception as exc:  # noqa: BLE001 - a scope fault refuses, never admits
        print(f"[!][GraphQL] Project scope unreadable ({type(exc).__name__}): "
              f"GRAPHQL_ENDPOINTS entries refused")
        scope = []
    return lambda host: bool(host) and host_in_scope(host, scope)


def _typed_endpoints(combined_result: dict, settings: dict, admits) -> Set[str]:
    """The operator's GRAPHQL_ENDPOINTS this run may test (R-43).

    They get the GraphQL credential like every candidate, so they need the
    same scope: an entry on a host outside the project (a typo, or a value an
    MCP client with recon:settings wrote) is refused, with no request at all,
    and said once per run. An entry on another batch group's host is left to
    that group's run. IP mode has one group, so every project address is this
    run's, even one with no BaseURL. Checked here rather than when the setting
    is saved, because the scope is only whole at scan time.
    """
    typed = list(dict.fromkeys(
        e.strip() for e in (settings.get('GRAPHQL_ENDPOINTS', '') or '').split(',') if e.strip()))
    if not typed:
        return set()

    from recon.helpers.recon_scope import recon_scope
    in_project = _project_admits(settings)
    ip_mode = bool(settings.get('IP_MODE')) or recon_scope(combined_result).ip_mode
    kept, elsewhere, refused = set(), [], []
    for endpoint in typed:
        host = _endpoint_host(endpoint)
        if not in_project(host):
            refused.append(endpoint)
        elif ip_mode or admits(host):
            kept.add(endpoint)
            print(f"[+][GraphQL] User-specified endpoint: {endpoint}")
        else:
            elsewhere.append(endpoint)

    if elsewhere:
        print(f"[*][GraphQL] {len(elsewhere)} user-specified endpoint(s) on another scope "
              f"group's hosts: left to that group's run")
    if refused:
        _refuse_once(refused)
    return kept


def _refuse_once(refused: List[str]) -> None:
    """Log and note each refused entry once per run: a domain batch runs this
    discovery once per group, in one process."""
    from recon.helpers import circuit_breaker as cb
    try:
        seen = cb.run_cache('graphql_refused_endpoints')
        fresh = [e for e in refused if not seen.get(e)[0]]
        for endpoint in fresh:
            seen.put(endpoint, True)
    except Exception:  # noqa: BLE001 - the dedupe is cosmetic; the refusal stands
        fresh = refused
    if not fresh:
        return
    hosts = sorted({_endpoint_host(e) or '<not a URL>' for e in fresh})
    print(f"[!][GraphQL] Refused {len(fresh)} user-specified endpoint(s) outside the project "
          f"scope; no request and no credential sent to: {', '.join(hosts)}")
    # No finding source is cut, so this is a report gap only: no prune effect.
    cb.note_degraded('graphql_scan', entries=[{
        "source": "roe_excluded", "reason": "GRAPHQL_ENDPOINTS outside the project scope",
        "skipped": len(fresh)}])


def _extract_base_urls(combined_result: dict) -> Set[str]:
    """Unique base URLs of the live web roots http_probe found."""
    base_urls = set()
    http_probe = combined_result.get('http_probe', {}) or {}
    for url in http_probe.get('by_url', {}) or {}:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            base_urls.add(f"{parsed.scheme}://{parsed.netloc}")
    return base_urls


def _extract_from_resource_enum(combined_result: dict) -> Set[str]:
    """GraphQL endpoints from resource_enum.by_base_url[base].endpoints[path]:
    a path that names GraphQL (any method: GET is allowed by many servers), or
    one that takes GraphQL's own parameters (query, variables, ...)."""
    graphql_endpoints = set()
    by_base = (combined_result.get('resource_enum') or {}).get('by_base_url') or {}
    for base_url, base_data in by_base.items():
        endpoints = (base_data or {}).get('endpoints') or {}
        for path, endpoint in endpoints.items():
            endpoint = endpoint or {}
            path = endpoint.get('path') or path
            if not path:
                continue
            url = urljoin(base_url, path)
            if any(hint in path.lower() for hint in _GRAPHQL_PATH_HINTS):
                graphql_endpoints.add(url)
                print(f"[+][GraphQL] Found from resource enum: {url}")
                continue
            params = endpoint.get('parameters') or {}
            names = {
                str((p or {}).get('name', '')).lower()
                for kind in ('query', 'body', 'path')
                for p in params.get(kind) or []
            }
            if names & _GRAPHQL_PARAM_NAMES:
                graphql_endpoints.add(url)
                print(f"[+][GraphQL] Found from parameters: {url}")
    return graphql_endpoints


def _extract_from_js_recon(combined_result: dict) -> Set[str]:
    """GraphQL endpoints JS Recon found in the bundles (js_recon.endpoints).

    A relative path is joined to the origin of the script that named it, never
    to every base URL; an absolute one is kept as found and judged by scope.
    """
    graphql_endpoints = set()
    for endpoint in (combined_result.get('js_recon') or {}).get('endpoints') or []:
        endpoint = endpoint or {}
        kind = endpoint.get('type', '')
        path = endpoint.get('full_url') or endpoint.get('path') or ''
        if kind not in ('graphql', 'graphql_introspection') and 'graphql' not in path.lower():
            continue
        if not path:
            continue
        if path.startswith(('http://', 'https://')):
            url = path
        else:
            source = endpoint.get('source_js') or ''
            if not source.startswith(('http://', 'https://')):
                continue  # an uploaded bundle names no host
            url = urljoin(_origin(source), path)
        graphql_endpoints.add(url)
        print(f"[+][GraphQL] Found from JS recon: {url}")
    return graphql_endpoints


def _extract_from_urlscan(combined_result: dict) -> Set[str]:
    """GraphQL paths URLScan saw on in-scope pages (urlscan.urls_with_paths).
    Its `entries` include out-of-scope pages, so they are never read."""
    graphql_endpoints = set()
    for row in (combined_result.get('urlscan') or {}).get('urls_with_paths') or []:
        row = row or {}
        path = row.get('path') or ''
        base = row.get('base_url') or ''
        if base and any(hint in path.lower() for hint in ('graphql', 'gql')):
            url = urljoin(base, path)
            graphql_endpoints.add(url)
            print(f"[+][GraphQL] Found from URLScan: {url}")
    return graphql_endpoints


def _extract_from_http_probe(combined_result: dict) -> Set[str]:
    """Endpoints whose response says GraphQL, plus the common paths on each
    live URL as candidates to test."""
    graphql_endpoints = set()

    http_probe = combined_result.get('http_probe', {}) or {}
    for url, probe_data in (http_probe.get('by_url', {}) or {}).items():
        probe_data = probe_data or {}
        content_type = str(probe_data.get('content_type') or '').lower()
        if 'graphql' in content_type:
            graphql_endpoints.add(url)
            print(f"[+][GraphQL] Found from Content-Type: {url}")
            continue

        if (probe_data.get('status_code') or 0) < 400:
            parsed = urlparse(url)
            for pattern in ['/graphql', '/api/graphql', '/query']:
                graphql_endpoints.add(f"{parsed.scheme}://{parsed.netloc}{pattern}")

    return graphql_endpoints


def roe_settings_for(combined_result: dict, settings: dict) -> dict:
    """The RoE exclusion settings: the run's own settings, falling back to the
    copy a partial-recon graph builder stamps in metadata.roe."""
    if settings.get('ROE_ENABLED', False):
        return {'ROE_ENABLED': True, 'ROE_EXCLUDED_HOSTS': list(settings.get('ROE_EXCLUDED_HOSTS') or [])}
    meta_roe = (combined_result.get('metadata') or {}).get('roe') or {}
    return {'ROE_ENABLED': bool(meta_roe.get('ROE_ENABLED')),
            'ROE_EXCLUDED_HOSTS': list(meta_roe.get('ROE_EXCLUDED_HOSTS') or [])}


def filter_by_roe(endpoints: List[str], roe_settings: dict) -> List[str]:
    """
    Filter endpoints by Rules of Engagement (RoE), with the pipeline's one
    matcher (roe_scope._is_roe_excluded): CIDRs and IPs, a domain that covers
    its subdomains, `*.domain` for subdomains only, case and port ignored.

    Args:
        endpoints: List of discovered endpoints
        roe_settings: {'ROE_ENABLED', 'ROE_EXCLUDED_HOSTS'}

    Returns:
        List of in-scope endpoints
    """
    from recon.helpers.roe_scope import _is_roe_excluded

    if not roe_settings.get('ROE_ENABLED', False):
        return endpoints

    excluded_hosts = roe_settings.get('ROE_EXCLUDED_HOSTS', [])
    if not excluded_hosts:
        return endpoints

    filtered_endpoints = [
        e for e in endpoints
        if not _is_roe_excluded(urlparse(e).hostname or urlparse(e).netloc, excluded_hosts)
    ]
    excluded_count = len(endpoints) - len(filtered_endpoints)
    if excluded_count > 0:
        print(f"[-][GraphQL] RoE: excluded {excluded_count} out-of-scope endpoint(s)")

    return filtered_endpoints
