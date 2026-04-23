"""
Main GraphQL Security Scanner Module

Orchestrates GraphQL security testing including:
- Endpoint discovery
- Introspection testing
- Vulnerability detection
"""

import time
import copy
import threading
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .discovery import discover_graphql_endpoints, filter_by_roe
from .introspection import (
    test_introspection, extract_operations, calculate_schema_hash,
    detect_sensitive_fields
)
from .normalizers import normalize_introspection_finding, aggregate_findings
from .auth import build_auth_headers


def _build_retry_session(retry_count: int, backoff: float) -> requests.Session:
    """Build a requests.Session with retry/backoff on transient HTTP failures.

    Targets 429 (rate-limit) and 5xx explicitly — Cloudflare-fronted targets
    frequently 429 burst probes and a single retry with backoff recovers
    most of them. Network-level errors (connection reset, DNS fail) also retry.
    """
    retry_count = max(0, min(10, int(retry_count)))  # clamp 0-10
    backoff = max(0.0, min(10.0, float(backoff)))    # clamp 0-10 seconds
    retry = Retry(
        total=retry_count,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def run_graphql_scan(combined_result: dict, settings: dict) -> dict:
    """
    Run GraphQL security scan on discovered endpoints.

    This is the main entry point that modifies combined_result in place.

    Args:
        combined_result: The combined recon data (modified in place)
        settings: Project settings

    Returns:
        The modified combined_result dict
    """
    # Check if GraphQL scanning is enabled
    if not settings.get('GRAPHQL_SECURITY_ENABLED', False):
        print("[-][GraphQL] GraphQL security scanning disabled")
        return combined_result

    print("\n[*][GraphQL] Starting GraphQL security scan")
    print("=" * 50)

    start_time = time.time()

    # Initialize GraphQL scan results
    graphql_results = {
        'summary': {
            'endpoints_discovered': 0,
            'endpoints_tested': 0,
            'endpoints_skipped': 0,
            'introspection_enabled': 0,
            'vulnerabilities_found': 0,
            'by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        },
        'discovered_endpoints': [],
        'endpoints': {},
        'vulnerabilities': []
    }

    # Phase 1: Discover GraphQL endpoints
    print("\n[*][GraphQL] Phase 1: Endpoint Discovery")
    print("-" * 40)

    discovered_endpoints = discover_graphql_endpoints(combined_result, settings)
    graphql_results['discovered_endpoints'] = discovered_endpoints
    graphql_results['summary']['endpoints_discovered'] = len(discovered_endpoints)

    if not discovered_endpoints:
        print("[-][GraphQL] No GraphQL endpoints discovered")
        combined_result['graphql_scan'] = graphql_results
        return combined_result

    # Filter by RoE
    roe_settings = combined_result.get('metadata', {}).get('roe', {})
    in_scope_endpoints = filter_by_roe(discovered_endpoints, roe_settings)
    skipped_count = len(discovered_endpoints) - len(in_scope_endpoints)

    if skipped_count > 0:
        print(f"[-][GraphQL] Skipped {skipped_count} out-of-scope endpoints")
        graphql_results['summary']['endpoints_skipped'] = skipped_count

    if not in_scope_endpoints:
        print("[-][GraphQL] No in-scope GraphQL endpoints to test")
        combined_result['graphql_scan'] = graphql_results
        return combined_result

    # Build authentication headers
    auth_headers = build_auth_headers(settings)

    # Initialize introspection cache to avoid duplicate queries
    introspection_cache = {}

    # Phase 2: Test endpoints
    print(f"\n[*][GraphQL] Phase 2: Testing {len(in_scope_endpoints)} endpoints")
    print("-" * 40)

    # Test configuration with input validation
    timeout = max(1, min(600, settings.get('GRAPHQL_TIMEOUT', 30)))  # 1-600 seconds
    rate_limit = max(0, min(100, settings.get('GRAPHQL_RATE_LIMIT', 10)))  # 0-100 requests per second
    concurrency = max(1, min(20, min(settings.get('GRAPHQL_CONCURRENCY', 5), len(in_scope_endpoints))))  # 1-20 threads
    retry_count = settings.get('GRAPHQL_RETRY_COUNT', 3)
    retry_backoff = settings.get('GRAPHQL_RETRY_BACKOFF', 2.0)
    depth_limit = settings.get('GRAPHQL_DEPTH_LIMIT', 3)

    # Shared retry-enabled session — thread-safe, reused across all endpoint probes.
    http_session = _build_retry_session(retry_count, retry_backoff)

    # Rate limiting delay
    delay = 1.0 / rate_limit if rate_limit > 0 else 0

    # Log configuration
    print(f"[*][GraphQL] Configuration: timeout={timeout}s, rate_limit={rate_limit}/s, "
          f"concurrency={concurrency}, retries={retry_count}@backoff={retry_backoff}s, "
          f"introspection_depth={depth_limit}")

    # Test endpoints with concurrency control
    if concurrency > 1 and len(in_scope_endpoints) > 1:
        # Parallel testing
        result_lock = threading.Lock()  # Lock for thread-safe result updates
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {}
            last_submit_time = 0

            for endpoint in in_scope_endpoints:
                # Rate limiting
                current_time = time.time()
                if current_time - last_submit_time < delay:
                    time.sleep(delay - (current_time - last_submit_time))

                future = executor.submit(
                    test_single_endpoint,
                    endpoint,
                    auth_headers,
                    timeout,
                    settings,
                    introspection_cache,
                    http_session,
                    depth_limit,
                )
                futures[future] = endpoint
                last_submit_time = time.time()

            # Collect results
            for future in as_completed(futures):
                endpoint = futures[future]
                try:
                    result = future.result()
                    if result:
                        with result_lock:
                            graphql_results['endpoints'][endpoint] = result['endpoint_data']
                            graphql_results['vulnerabilities'].extend(result['vulnerabilities'])
                            graphql_results['summary']['endpoints_tested'] += 1

                            if result['endpoint_data'].get('introspection_enabled'):
                                graphql_results['summary']['introspection_enabled'] += 1

                except Exception as e:
                    print(f"[!][GraphQL] Error testing {endpoint}: {str(e)}")
    else:
        # Sequential testing
        for endpoint in in_scope_endpoints:
            try:
                result = test_single_endpoint(endpoint, auth_headers, timeout, settings, introspection_cache, http_session, depth_limit)
                if result:
                    graphql_results['endpoints'][endpoint] = result['endpoint_data']
                    graphql_results['vulnerabilities'].extend(result['vulnerabilities'])
                    graphql_results['summary']['endpoints_tested'] += 1

                    if result['endpoint_data'].get('introspection_enabled'):
                        graphql_results['summary']['introspection_enabled'] += 1

                # Rate limiting
                if delay > 0:
                    time.sleep(delay)

            except Exception as e:
                print(f"[!][GraphQL] Error testing {endpoint}: {str(e)}")

    # Aggregate vulnerability statistics
    vuln_summary = aggregate_findings(graphql_results['vulnerabilities'])
    graphql_results['summary']['vulnerabilities_found'] = vuln_summary['total_findings']
    graphql_results['summary']['by_severity'] = vuln_summary['by_severity']

    # Store results
    combined_result['graphql_scan'] = graphql_results

    # Print summary
    duration = time.time() - start_time
    print(f"\n[+][GraphQL] Scan complete in {duration:.2f}s")
    print(f"[+][GraphQL] Endpoints tested: {graphql_results['summary']['endpoints_tested']}")
    print(f"[+][GraphQL] Introspection enabled: {graphql_results['summary']['introspection_enabled']}")
    print(f"[+][GraphQL] Vulnerabilities found: {graphql_results['summary']['vulnerabilities_found']}")

    if graphql_results['summary']['vulnerabilities_found'] > 0:
        print(f"[+][GraphQL] By severity: " +
              f"Critical: {vuln_summary['by_severity']['critical']}, " +
              f"High: {vuln_summary['by_severity']['high']}, " +
              f"Medium: {vuln_summary['by_severity']['medium']}, " +
              f"Low: {vuln_summary['by_severity']['low']}, " +
              f"Info: {vuln_summary['by_severity']['info']}")

    return combined_result


def run_graphql_scan_isolated(combined_result: dict, settings: dict) -> dict:
    """
    Thread-safe isolated wrapper for GraphQL scanning.

    Makes a copy of combined_result and returns only GraphQL scan data.

    Args:
        combined_result: The combined recon data
        settings: Project settings

    Returns:
        Dict containing only GraphQL scan results
    """
    # Deep copy to avoid thread conflicts
    snapshot = copy.deepcopy(combined_result)

    # Run scan on the copy
    run_graphql_scan(snapshot, settings)

    # Return only GraphQL results
    return snapshot.get('graphql_scan', {})


def test_single_endpoint(endpoint: str, auth_headers: dict,
                        timeout: int, settings: dict,
                        introspection_cache: dict = None,
                        http_session: 'requests.Session' = None,
                        depth_limit: int = 3) -> dict:
    """
    Test a single GraphQL endpoint.

    Args:
        endpoint: The endpoint URL to test
        auth_headers: Authentication headers
        timeout: Request timeout
        settings: Project settings
        introspection_cache: Shared cache (thread-safe) across endpoints
        http_session: Retry-enabled session (built in run_graphql_scan).
            Falls through to bare requests.post when None.
        depth_limit: TypeRef fragment recursion depth for full introspection.

    Returns:
        Dict with endpoint data and vulnerabilities
    """
    result = {
        'endpoint_data': {
            'tested': True,
            'introspection_enabled': False,
            'schema_extracted': False,
            'mutations_count': 0,
            'queries_count': 0,
            'subscriptions_count': 0,
            'schema_hash': None,
            'error': None
        },
        'vulnerabilities': []
    }

    # Test introspection
    if settings.get('GRAPHQL_INTROSPECTION_TEST', True):
        # Check cache first (thread-safe for shared cache)
        cache_key = endpoint
        if introspection_cache and cache_key in introspection_cache:
            cached_result = introspection_cache[cache_key]
            is_enabled = cached_result['is_enabled']
            schema_data = cached_result['schema_data']
            error = cached_result['error']
            print(f"[*][GraphQL] Using cached introspection result for: {endpoint}")
        else:
            is_enabled, schema_data, error = test_introspection(
                endpoint, auth_headers, timeout,
                verify_ssl=settings.get('GRAPHQL_VERIFY_SSL', True),
                session=http_session,
                depth_limit=depth_limit,
            )

            # Cache the result if cache is provided
            if introspection_cache is not None:
                introspection_cache[cache_key] = {
                    'is_enabled': is_enabled,
                    'schema_data': schema_data,
                    'error': error
                }

        if error:
            result['endpoint_data']['error'] = error
            if 'not a graphql endpoint' in error.lower():
                result['endpoint_data']['tested'] = False
                return None  # Not a GraphQL endpoint

        if is_enabled:
            result['endpoint_data']['introspection_enabled'] = True

            if schema_data:
                result['endpoint_data']['schema_extracted'] = True

                # Extract operations
                operations = extract_operations(schema_data)
                result['endpoint_data']['mutations_count'] = len(operations.get('mutations', []))
                result['endpoint_data']['queries_count'] = len(operations.get('queries', []))
                result['endpoint_data']['subscriptions_count'] = len(operations.get('subscriptions', []))

                # Calculate schema hash
                result['endpoint_data']['schema_hash'] = calculate_schema_hash(schema_data)

                # Detect sensitive fields
                sensitive_fields = detect_sensitive_fields(schema_data)

                # Create introspection finding
                finding = normalize_introspection_finding(
                    endpoint=endpoint,
                    schema_data=schema_data,
                    operations=operations,
                    sensitive_fields=sensitive_fields
                )
                result['vulnerabilities'].append(finding)

                # Store operations list for future phases
                result['endpoint_data']['operations'] = operations

    # Phase 2: graphql-cop external misconfig scanner (opt-in, Docker-in-Docker)
    if settings.get('GRAPHQL_COP_ENABLED', False):
        try:
            from recon.graphql_scan.misconfig import run_graphql_cop, derive_endpoint_flags
            cop_output = run_graphql_cop(endpoint, auth_headers, settings)
        except Exception as e:
            print(f"[!][GraphQL-Cop] Unexpected error running graphql-cop on {endpoint}: {e}")
            cop_output = None

        if cop_output is not None:
            cop_findings = cop_output.get('findings') or []
            cop_raw = cop_output.get('raw') or []
            # Use RAW output (includes result=False rows) to set Endpoint capability
            # flags -- captures negative signals like "GraphiQL not exposed" explicitly.
            endpoint_flags = derive_endpoint_flags(cop_raw)
            result['endpoint_data'].update(endpoint_flags)
            result['endpoint_data']['graphql_cop_ran'] = True
            result['vulnerabilities'].extend(cop_findings)
            if cop_findings:
                high = sum(1 for f in cop_findings if f.get('severity') in ('critical', 'high'))
                print(f"[+][GraphQL-Cop] {endpoint}: {len(cop_findings)} findings ({high} high/critical)")

    return result