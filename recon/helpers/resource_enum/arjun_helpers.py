"""
RedAmon - Arjun Parameter Discovery Helpers for Resource Enumeration
=====================================================================
Active/passive HTTP parameter discovery using Arjun.
Tests common parameter names against endpoints to find hidden query/body
parameters (debug params, admin functionality, hidden API inputs).

Installed via pip (arjun>=2.2.7), runs as a subprocess.
"""

import json
import os
import signal
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from .classification import classify_endpoint, classify_parameter, infer_parameter_type


def arjun_binary_check() -> bool:
    """Check if arjun binary is available on PATH."""
    if shutil.which('arjun'):
        print("[✓][Arjun] arjun binary found")
        return True
    print("[!][Arjun] arjun binary not found in PATH")
    return False


def _run_arjun_single_method(
    target_urls: List[str],
    method: str,
    threads: int,
    timeout: int,
    scan_timeout: int,
    chunk_size: int,
    rate_limit: int,
    stable: bool,
    passive: bool,
    disable_redirects: bool,
    custom_headers: List[str],
    allowed_hosts: Set[str],
    use_proxy: bool = False,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Run Arjun for a single HTTP method. Called in parallel by run_arjun_discovery().

    Returns:
        Tuple of (results_list, external_domains_list)
    """
    tmp_dir = tempfile.mkdtemp(prefix="redamon_arjun_")
    results = []
    external_domains = []

    try:
        urls_file = os.path.join(tmp_dir, "urls.txt")
        output_file = os.path.join(tmp_dir, "results.json")

        with open(urls_file, 'w') as f:
            for url in target_urls:
                f.write(url + '\n')

        cmd = [
            'arjun',
            '-i', urls_file,
            '-oJ', output_file,
            '-m', method,
            '-t', str(threads),
            '-T', str(timeout),
            '-c', str(chunk_size),
        ]

        if rate_limit > 0:
            cmd.extend(['--rate-limit', str(rate_limit)])
        if stable:
            cmd.append('--stable')
        if passive:
            cmd.append('--passive')
        if disable_redirects:
            cmd.append('--disable-redirects')

        headers_str = '\n'.join(h.strip() for h in custom_headers if h.strip())
        if headers_str:
            cmd.extend(['--headers', headers_str])

        print(f"[*][Arjun/{method}] Scanning {len(target_urls)} URLs...")

        env = os.environ.copy()
        if use_proxy:
            env['HTTP_PROXY'] = 'socks5://127.0.0.1:9050'
            env['HTTPS_PROXY'] = 'socks5://127.0.0.1:9050'

        timed_out = False
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        try:
            stdout, stderr = proc.communicate(timeout=scan_timeout + 60)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Graceful shutdown: SIGTERM first, give Arjun time to flush output
            try:
                proc.send_signal(signal.SIGTERM)
                proc.communicate(timeout=10)
            except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
                # Process didn't exit gracefully or already dead — force kill
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
                proc.communicate()
            print(f"[!][Arjun/{method}] Timed out after {scan_timeout}s — collecting partial results")
        else:
            if proc.returncode != 0 and stderr:
                stderr_lines = stderr.strip().split('\n')
                for line in stderr_lines[-3:]:
                    print(f"[!][Arjun/{method}] {line}")

        # Parse output file (full results or partial after graceful shutdown)
        if not os.path.exists(output_file):
            if not timed_out:
                print(f"[-][Arjun/{method}] No parameters found")
            else:
                print(f"[-][Arjun/{method}] No partial results saved before timeout")
            return [], []

        with open(output_file, 'r') as f:
            content = f.read().strip()
            if not content:
                if not timed_out:
                    print(f"[-][Arjun/{method}] No parameters found")
                else:
                    print(f"[-][Arjun/{method}] Output file empty after timeout")
                return [], []

        try:
            arjun_output = json.loads(content)
        except json.JSONDecodeError:
            if not timed_out:
                print(f"[!][Arjun/{method}] Failed to parse JSON output")
                return [], []
            # Arjun may have been killed mid-write — try to salvage truncated JSON
            try:
                # Close unclosed brackets and braces in correct order
                stack = []
                in_string = False
                escape_next = False
                for ch in content:
                    if escape_next:
                        escape_next = False
                        continue
                    if ch == '\\' and in_string:
                        escape_next = True
                        continue
                    if ch == '"':
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if ch in ('{', '['):
                        stack.append('}' if ch == '{' else ']')
                    elif ch in ('}', ']') and stack:
                        stack.pop()
                # Close unclosed string if truncated mid-value
                salvaged = content
                if in_string:
                    salvaged += '"'
                # Strip trailing comma before closing (e.g. '{"a": 1,' -> '{"a": 1}')
                salvaged = salvaged.rstrip().rstrip(',')
                salvaged += ''.join(reversed(stack))
                arjun_output = json.loads(salvaged)
                print(f"[*][Arjun/{method}] Recovered partial JSON output")
            except Exception as e:
                print(f"[!][Arjun/{method}] Failed to recover partial JSON: {e}")
                return [], []

        total_params = 0
        for url, url_data in arjun_output.items():
            params = url_data.get('params', [])
            discovered_method = url_data.get('method', method)

            if not params:
                continue

            try:
                parsed = urlparse(url)
                host = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
            except Exception:
                continue

            if allowed_hosts and host not in allowed_hosts:
                external_domains.append({
                    "domain": host,
                    "source": "arjun",
                    "url": url,
                })
                continue

            results.append({
                "url": url,
                "params": params,
                "method": discovered_method,
            })
            total_params += len(params)

        if timed_out and total_params > 0:
            print(f"[+][Arjun/{method}] Recovered {len(results)} URLs with params, {total_params} params from partial scan")
        elif timed_out:
            print(f"[-][Arjun/{method}] No parameters found before timeout")
        else:
            print(f"[+][Arjun/{method}] {len(results)} URLs with params, {total_params} params discovered")

    except Exception as e:
        print(f"[!][Arjun/{method}] Error: {e}")
    finally:
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass

    return results, external_domains


def run_arjun_discovery(
    target_urls: List[str],
    methods: List[str],
    threads: int,
    timeout: int,
    scan_timeout: int,
    chunk_size: int,
    rate_limit: int,
    stable: bool,
    passive: bool,
    disable_redirects: bool,
    custom_headers: List[str],
    allowed_hosts: Set[str],
    use_proxy: bool = False,
) -> Tuple[List[Dict], Dict]:
    """
    Run Arjun parameter discovery against target URLs with multiple methods in parallel.

    Each method (GET, POST, JSON, XML) runs as a separate Arjun subprocess
    via ThreadPoolExecutor. Results from all methods are merged.

    Args:
        target_urls: Full endpoint URLs to test (e.g., https://example.com/api/users)
        methods: List of HTTP methods to test (GET, POST, JSON, XML)
        threads: Number of concurrent threads per Arjun process
        timeout: Per-request timeout in seconds
        scan_timeout: Overall scan timeout per method in seconds
        chunk_size: Number of parameters per request batch
        rate_limit: Max requests per second (0 = unlimited)
        stable: Enable stable mode (random delays for WAF evasion)
        passive: Use passive sources only (no active requests)
        disable_redirects: Do not follow HTTP redirects
        custom_headers: Custom HTTP headers to include
        allowed_hosts: Set of in-scope hostnames
        use_proxy: Use Tor SOCKS proxy

    Returns:
        Tuple of (results_list, metadata_dict)
    """
    if not target_urls:
        print("[-][Arjun] No target URLs provided")
        return [], {"external_domains": []}

    if not methods:
        methods = ['GET']

    print(f"\n[*][Arjun] Starting parameter discovery on {len(target_urls)} endpoints")
    print(f"[*][Arjun] Methods: {', '.join(methods)} ({'parallel' if len(methods) > 1 else 'single'})")
    if passive:
        print("[*][Arjun] Mode: PASSIVE (CommonCrawl/OTX/WaybackMachine only)")
    if use_proxy:
        print("[*][Arjun] Using Tor SOCKS proxy via environment variables")

    all_results = []
    all_external_domains = []

    if len(methods) == 1:
        # Single method — run directly, no thread overhead
        results, ext = _run_arjun_single_method(
            target_urls, methods[0], threads, timeout, scan_timeout,
            chunk_size, rate_limit, stable, passive, disable_redirects,
            custom_headers, allowed_hosts, use_proxy,
        )
        all_results.extend(results)
        all_external_domains.extend(ext)
    else:
        # Multiple methods — run in parallel
        with ThreadPoolExecutor(max_workers=len(methods)) as executor:
            futures = {}
            for method in methods:
                futures[method] = executor.submit(
                    _run_arjun_single_method,
                    target_urls, method, threads, timeout, scan_timeout,
                    chunk_size, rate_limit, stable, passive, disable_redirects,
                    custom_headers, allowed_hosts, use_proxy,
                )

            for method, future in futures.items():
                try:
                    results, ext = future.result(timeout=scan_timeout + 120)
                    all_results.extend(results)
                    all_external_domains.extend(ext)
                except Exception as e:
                    print(f"[!][Arjun/{method}] Failed: {e}")

    total_params = sum(len(r['params']) for r in all_results)
    print(f"[+][Arjun] Total: {len(all_results)} URLs with params, {total_params} params across {len(methods)} method(s)")
    if all_external_domains:
        print(f"[*][Arjun] Filtered {len(all_external_domains)} out-of-scope results")

    return all_results, {"external_domains": all_external_domains}


def merge_arjun_into_by_base_url(
    arjun_results: List[Dict],
    by_base_url: Dict,
) -> Tuple[Dict, Dict[str, int]]:
    """
    Merge Arjun parameter discovery results into existing by_base_url structure.

    Unlike Kiterunner/FFuf which discover endpoints, Arjun discovers **parameters**
    on endpoints. It enriches existing endpoints with new params AND creates new
    endpoints when the URL wasn't previously known.

    Args:
        arjun_results: List of result dicts from run_arjun_discovery()
        by_base_url: Existing by_base_url structure from crawlers/fuzzers

    Returns:
        Tuple of (updated by_base_url, merge stats)
    """
    stats = {
        "arjun_total": len(arjun_results),
        "arjun_new_endpoints": 0,
        "arjun_existing_enriched": 0,
        "arjun_params_discovered": 0,
    }

    for result in arjun_results:
        url = result.get('url', '')
        params = result.get('params', [])
        discovered_method = result.get('method', 'GET').upper()

        if not url or not params:
            continue

        # Parse URL into base_url + path
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path or '/'
        except Exception:
            continue

        # Determine parameter position based on method
        if discovered_method in ('POST', 'JSON', 'XML'):
            param_position = 'body'
        else:
            param_position = 'query'

        # Initialize base URL if not exists
        if base not in by_base_url:
            by_base_url[base] = {
                'base_url': base,
                'endpoints': {},
                'summary': {
                    'total_endpoints': 0,
                    'total_parameters': 0,
                    'methods': {},
                    'categories': {}
                }
            }

        endpoints = by_base_url[base]['endpoints']
        new_params_count = 0

        if path in endpoints:
            # Endpoint exists — enrich with discovered parameters
            endpoint = endpoints[path]

            # Migrate sources field (backward compat)
            existing_sources = endpoint.get('sources', [])
            if not existing_sources:
                old_source = endpoint.get('source', '')
                if old_source:
                    existing_sources = [old_source]
            if 'arjun' not in existing_sources:
                existing_sources.append('arjun')
            endpoint['sources'] = existing_sources
            endpoint.pop('source', None)

            # Add method if not present
            if discovered_method not in endpoint.get('methods', []):
                endpoint.setdefault('methods', []).append(discovered_method)
                by_base_url[base]['summary']['methods'][discovered_method] = \
                    by_base_url[base]['summary']['methods'].get(discovered_method, 0) + 1

            # Add discovered parameters
            existing_param_names = {
                p['name'] for p in endpoint['parameters'].get(param_position, [])
            }

            for param_name in params:
                if param_name in existing_param_names:
                    continue  # Skip duplicate

                param_info = {
                    'name': param_name,
                    'type': infer_parameter_type(param_name, []),
                    'sample_values': [],
                    'category': classify_parameter(param_name),
                }
                endpoint['parameters'][param_position].append(param_info)
                new_params_count += 1
                existing_param_names.add(param_name)

            # Update parameter_count
            if 'parameter_count' in endpoint:
                endpoint['parameter_count'][param_position] = len(endpoint['parameters'][param_position])
                endpoint['parameter_count']['total'] = (
                    len(endpoint['parameters'].get('query', []))
                    + len(endpoint['parameters'].get('body', []))
                    + len(endpoint['parameters'].get('path', []))
                )

            # Update base URL summary
            by_base_url[base]['summary']['total_parameters'] += new_params_count

            if new_params_count > 0:
                stats["arjun_existing_enriched"] += 1

        else:
            # New endpoint from Arjun
            stats["arjun_new_endpoints"] += 1

            # Build parameter list
            param_list = []
            for param_name in params:
                param_info = {
                    'name': param_name,
                    'type': infer_parameter_type(param_name, []),
                    'sample_values': [],
                    'category': classify_parameter(param_name),
                }
                param_list.append(param_info)
                new_params_count += 1

            parameters = {'query': [], 'body': [], 'path': []}
            parameters[param_position] = param_list

            category = classify_endpoint(path, [discovered_method], parameters)

            endpoints[path] = {
                'methods': [discovered_method],
                'parameters': parameters,
                'sources': ['arjun'],
                'category': category,
                'parameter_count': {
                    'query': len(parameters['query']),
                    'body': len(parameters['body']),
                    'path': 0,
                    'total': len(param_list),
                },
            }

            # Update summary
            by_base_url[base]['summary']['total_endpoints'] += 1
            by_base_url[base]['summary']['total_parameters'] += new_params_count
            by_base_url[base]['summary']['methods'][discovered_method] = \
                by_base_url[base]['summary']['methods'].get(discovered_method, 0) + 1
            by_base_url[base]['summary']['categories'][category] = \
                by_base_url[base]['summary']['categories'].get(category, 0) + 1

        stats["arjun_params_discovered"] += new_params_count

    return by_base_url, stats
