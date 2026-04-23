"""
GraphQL Endpoint Discovery Module

Discovers potential GraphQL endpoints from multiple sources:
1. Explicit patterns (/graphql, /api/graphql, /v1/graphql)
2. Resource enumeration results
3. JS Recon findings
4. HTTP probe results
5. User-specified endpoints
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

    Args:
        combined_result: The combined recon data
        settings: Project settings

    Returns:
        List of unique GraphQL endpoint URLs to test
    """
    discovered_endpoints = set()

    # 1. User-specified endpoints
    user_endpoints = settings.get('GRAPHQL_ENDPOINTS', '')
    if user_endpoints:
        for endpoint in user_endpoints.split(','):
            endpoint = endpoint.strip()
            if endpoint:
                discovered_endpoints.add(endpoint)
                print(f"[+][GraphQL] User-specified endpoint: {endpoint}")

    # 2. Extract base URLs from HTTP probe results
    base_urls = _extract_base_urls(combined_result)

    # 3. Check for GraphQL evidence first
    graphql_evidence_urls = set()

    # Check HTTP probe for GraphQL indicators
    probe_endpoints = _extract_from_http_probe(combined_result)
    discovered_endpoints.update(probe_endpoints)

    # Check resource enumeration results
    resource_endpoints = _extract_from_resource_enum(combined_result, base_urls)
    discovered_endpoints.update(resource_endpoints)

    # Check JS Recon findings
    js_endpoints = _extract_from_js_recon(combined_result, base_urls)
    discovered_endpoints.update(js_endpoints)

    # Extract base URLs that have GraphQL evidence
    for endpoint in list(discovered_endpoints):
        parsed = urlparse(endpoint)
        base = f"{parsed.scheme}://{parsed.netloc}"
        graphql_evidence_urls.add(base)

    # 4. Generate pattern-based endpoints intelligently
    for base_url in base_urls:
        if base_url in graphql_evidence_urls:
            # We have evidence, try more patterns
            patterns_to_try = PRIMARY_GRAPHQL_PATTERNS + SECONDARY_GRAPHQL_PATTERNS
        else:
            # No evidence, only try the most common patterns
            patterns_to_try = PRIMARY_GRAPHQL_PATTERNS

        for pattern in patterns_to_try:
            endpoint_url = urljoin(base_url, pattern)
            discovered_endpoints.add(endpoint_url)

    # 5. All extraction already done above

    # Remove duplicates and sort
    unique_endpoints = sorted(list(discovered_endpoints))

    print(f"[+][GraphQL] Discovered {len(unique_endpoints)} potential endpoints")
    return unique_endpoints


def _extract_base_urls(combined_result: dict) -> Set[str]:
    """Extract unique base URLs from HTTP probe results."""
    base_urls = set()

    # From HTTP probe
    http_probe = combined_result.get('http_probe', {})
    for url in http_probe.get('by_url', {}):
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        base_urls.add(base_url)

    # From URLScan if available
    urlscan = combined_result.get('urlscan', {})
    for domain_data in urlscan.get('by_domain', {}).values():
        for url_info in domain_data.get('urls', []):
            url = url_info.get('url', '')
            if url:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                base_urls.add(base_url)

    return base_urls


def _extract_from_resource_enum(combined_result: dict, base_urls: Set[str]) -> Set[str]:
    """Extract GraphQL endpoints from resource enumeration results."""
    graphql_endpoints = set()

    resource_enum = combined_result.get('resource_enum', {})

    # Check discovered endpoints
    for base_url in base_urls:
        endpoints = resource_enum.get('endpoints', {}).get(base_url, [])
        for endpoint in endpoints:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'GET')

            # Check if path suggests GraphQL
            if any(pattern in path.lower() for pattern in ['graphql', 'gql', 'query']):
                # GraphQL typically uses POST
                if method == 'POST':
                    endpoint_url = urljoin(base_url, path)
                    graphql_endpoints.add(endpoint_url)
                    print(f"[+][GraphQL] Found from resource enum: {endpoint_url}")

    # Check parameters that might indicate GraphQL
    parameters = resource_enum.get('parameters', {})
    for base_url, params in parameters.items():
        for param in params:
            param_name = param.get('name', '').lower()
            if param_name in ['query', 'mutation', 'variables', 'operationname']:
                # This endpoint accepts GraphQL-like parameters
                graphql_endpoints.add(base_url)
                print(f"[+][GraphQL] Found from parameters: {base_url}")
                break

    return graphql_endpoints


def _extract_from_js_recon(combined_result: dict, base_urls: Set[str]) -> Set[str]:
    """Extract GraphQL endpoints from JS Recon findings."""
    graphql_endpoints = set()

    js_recon = combined_result.get('js_recon', {})
    findings = js_recon.get('findings', [])

    for finding in findings:
        finding_type = finding.get('type', '')

        # Check for GraphQL-specific findings
        if finding_type in ['graphql', 'graphql_introspection']:
            path = finding.get('path', '')
            method = finding.get('method', 'POST')

            # Try to construct full URL
            if path.startswith('http'):
                graphql_endpoints.add(path)
                print(f"[+][GraphQL] Found from JS recon: {path}")
            else:
                # Try to match with base URLs
                for base_url in base_urls:
                    endpoint_url = urljoin(base_url, path)
                    graphql_endpoints.add(endpoint_url)

        # Also check for GraphQL in endpoint findings
        elif finding_type == 'rest' and 'graphql' in finding.get('path', '').lower():
            path = finding.get('path', '')
            if path.startswith('http'):
                graphql_endpoints.add(path)
            else:
                for base_url in base_urls:
                    endpoint_url = urljoin(base_url, path)
                    graphql_endpoints.add(endpoint_url)

    return graphql_endpoints


def _extract_from_http_probe(combined_result: dict) -> Set[str]:
    """Extract endpoints that show GraphQL indicators in responses."""
    graphql_endpoints = set()

    http_probe = combined_result.get('http_probe', {})

    # Check response headers and content for GraphQL indicators
    for url, probe_data in http_probe.get('by_url', {}).items():
        headers = probe_data.get('headers', {})

        # Check Content-Type header
        content_type = headers.get('content-type', '').lower()
        if 'graphql' in content_type:
            graphql_endpoints.add(url)
            print(f"[+][GraphQL] Found from Content-Type header: {url}")
            continue

        # Check if response body contains GraphQL indicators
        # Note: In real implementation, we'd need to fetch and check response bodies
        # For now, we'll check common GraphQL paths on live URLs
        if probe_data.get('status_code', 0) < 400:
            parsed = urlparse(url)
            for pattern in ['/graphql', '/api/graphql', '/query']:
                potential_endpoint = f"{parsed.scheme}://{parsed.netloc}{pattern}"
                # We'll add these as candidates to test
                graphql_endpoints.add(potential_endpoint)

    return graphql_endpoints


def filter_by_roe(endpoints: List[str], roe_settings: dict) -> List[str]:
    """
    Filter endpoints by Rules of Engagement (RoE).

    Args:
        endpoints: List of discovered endpoints
        roe_settings: RoE settings from project

    Returns:
        List of in-scope endpoints
    """
    if not roe_settings.get('ROE_ENABLED', False):
        return endpoints

    excluded_hosts = roe_settings.get('ROE_EXCLUDED_HOSTS', [])
    if not excluded_hosts:
        return endpoints

    filtered_endpoints = []
    excluded_count = 0

    for endpoint in endpoints:
        # Parse the endpoint URL to get the hostname
        parsed = urlparse(endpoint)
        hostname = parsed.hostname or parsed.netloc

        # Check if hostname matches any excluded pattern
        is_excluded = False
        for excluded in excluded_hosts:
            # Support wildcards: *.example.com
            if excluded.startswith('*.'):
                domain = excluded[2:]
                if hostname == domain or hostname.endswith('.' + domain):
                    is_excluded = True
                    break
            # Exact match
            elif hostname == excluded:
                is_excluded = True
                break

        if not is_excluded:
            filtered_endpoints.append(endpoint)
        else:
            excluded_count += 1

    if excluded_count > 0:
        print(f"[-][GraphQL] RoE: excluded {excluded_count} out-of-scope endpoint(s)")

    return filtered_endpoints