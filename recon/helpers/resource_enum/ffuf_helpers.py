"""
RedAmon - FFuf Directory Fuzzer Helpers for Resource Enumeration
================================================================
Active endpoint/directory discovery using FFuf (Fuzz Faster U Fool).
Brute-forces common directory and file paths using wordlists to find
hidden content that crawlers cannot discover (admin panels, backups,
configs, undocumented API endpoints).

Compiled from source via multi-stage Docker build (pure Go, no CGO).
"""

import json
import os
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


def _fuzz_single_target(
    idx: int,
    fuzz_url: str,
    output_dir: str,
    wordlist: str,
    threads: int,
    timeout: int,
    max_time: int,
    rate: int,
    match_codes: List[int],
    filter_codes: List[int],
    filter_size: str,
    extensions: List[str],
    recursion: bool,
    recursion_depth: int,
    auto_calibrate: bool,
    custom_headers: List[str],
    follow_redirects: bool,
    allowed_hosts: set,
    use_proxy: bool,
) -> Tuple[List[Dict], List[Dict]]:
    """Run FFuf against a single fuzz target URL. Returns (results, external_entries)."""
    results = []
    external_entries = []
    output_file = os.path.join(output_dir, f"ffuf_result_{idx}.json")

    cmd = ["ffuf"]
    cmd.extend(["-u", fuzz_url])
    cmd.extend(["-w", wordlist])
    cmd.extend(["-t", str(threads)])
    cmd.extend(["-timeout", str(timeout)])
    cmd.extend(["-maxtime", str(max_time)])

    if rate > 0:
        cmd.extend(["-rate", str(rate)])

    if match_codes:
        cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])

    if filter_codes:
        cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])

    if filter_size:
        cmd.extend(["-fs", filter_size])

    if extensions:
        cmd.extend(["-e", ",".join(extensions)])

    if recursion:
        cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])

    if auto_calibrate:
        cmd.append("-ac")

    if follow_redirects:
        cmd.append("-r")

    for header in custom_headers:
        cmd.extend(["-H", header])

    if use_proxy:
        cmd.extend(["-x", "socks5://127.0.0.1:9050"])

    cmd.extend(["-of", "json", "-o", output_file])
    cmd.extend(["-s"])  # Silent mode (no banner/progress)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_time + 60,
        )

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                try:
                    ffuf_output = json.load(f)
                except json.JSONDecodeError:
                    print(f"[!][FFuf] Failed to parse JSON output for {fuzz_url}")
                    return results, external_entries

            for entry in ffuf_output.get("results", []):
                url = entry.get("url", "")
                if not url:
                    continue

                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or ''
                    if host and allowed_hosts and host not in allowed_hosts:
                        external_entries.append({
                            "domain": host, "source": "ffuf", "url": url,
                        })
                        continue
                except Exception:
                    continue

                results.append({
                    "url": url,
                    "status": entry.get("status", 0),
                    "length": entry.get("length", 0),
                    "words": entry.get("words", 0),
                    "lines": entry.get("lines", 0),
                    "content_type": entry.get("content-type", ""),
                    "redirect_location": entry.get("redirectlocation", ""),
                    "duration": entry.get("duration", 0),
                    "input_fuzz": entry.get("input", {}).get("FUZZ", ""),
                })

    except subprocess.TimeoutExpired:
        print(f"[!][FFuf] Timeout exceeded for {fuzz_url}")
    except Exception as e:
        print(f"[!][FFuf] Error fuzzing {fuzz_url}: {e}")

    return results, external_entries


def run_ffuf_discovery(
    target_urls: List[str],
    wordlist: str,
    threads: int,
    rate: int,
    timeout: int,
    max_time: int,
    match_codes: List[int],
    filter_codes: List[int],
    filter_size: str,
    extensions: List[str],
    recursion: bool,
    recursion_depth: int,
    auto_calibrate: bool,
    custom_headers: List[str],
    follow_redirects: bool,
    allowed_hosts: set,
    discovered_base_paths: Optional[List[str]] = None,
    use_proxy: bool = False,
    parallelism: int = 3,
) -> Tuple[List[Dict], Dict]:
    """
    Run FFuf directory fuzzer against target URLs.

    Fuzzes from root (target/FUZZ) and optionally under discovered base paths
    (target/api/v1/FUZZ, etc.) for targeted discovery.

    Args:
        target_urls: Base URLs to fuzz (e.g., https://example.com)
        wordlist: Path to wordlist file inside the container
        threads: Number of concurrent threads
        rate: Max requests per second (0 = unlimited)
        timeout: Per-request timeout in seconds
        max_time: Overall max execution time in seconds
        match_codes: HTTP status codes to match (include in results)
        filter_codes: HTTP status codes to filter out (exclude from results)
        filter_size: Response size filter (e.g., "0" to exclude empty responses)
        extensions: File extensions to append (e.g., [".php", ".bak"])
        recursion: Enable recursive fuzzing
        recursion_depth: Maximum recursion depth
        auto_calibrate: Enable auto-calibration to filter false positives
        custom_headers: Custom HTTP headers
        follow_redirects: Follow HTTP redirects
        allowed_hosts: Set of in-scope hostnames
        discovered_base_paths: Base paths discovered by crawlers to fuzz under
        use_proxy: Whether to use Tor proxy

    Returns:
        Tuple of (results_list, {"external_domains": [...]})
    """
    print(f"\n[*][FFuf] Running FFuf directory fuzzer...")
    print(f"[*][FFuf] Wordlist: {wordlist}")
    print(f"[*][FFuf] Threads: {threads}")
    print(f"[*][FFuf] Rate limit: {rate} req/s" if rate > 0 else "[*][FFuf] Rate limit: unlimited")
    print(f"[*][FFuf] Timeout: {timeout}s per request, {max_time}s max total")
    print(f"[*][FFuf] Auto-calibrate: {auto_calibrate}")
    if match_codes:
        print(f"[*][FFuf] Match status codes: {','.join(str(c) for c in match_codes)}")
    if filter_codes:
        print(f"[*][FFuf] Filter status codes: {','.join(str(c) for c in filter_codes)}")
    if extensions:
        print(f"[*][FFuf] Extensions: {','.join(extensions)}")
    if recursion:
        print(f"[*][FFuf] Recursion: depth {recursion_depth}")
    print(f"[*][FFuf] Target URLs: {len(target_urls)}")
    print(f"[*][FFuf] Parallelism: {parallelism} concurrent targets")

    all_results = []
    external_domain_entries = []

    fuzz_targets = _build_fuzz_targets(target_urls, discovered_base_paths)
    print(f"[*][FFuf] Fuzz targets (root + base paths): {len(fuzz_targets)}")

    output_dir = tempfile.mkdtemp(prefix="redamon_ffuf_")

    try:
        effective_threads = max(threads // parallelism, 5)
        max_workers = min(parallelism, len(fuzz_targets))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for idx, fuzz_url in enumerate(fuzz_targets):
                future = executor.submit(
                    _fuzz_single_target,
                    idx, fuzz_url, output_dir, wordlist, effective_threads,
                    timeout, max_time, rate, match_codes, filter_codes,
                    filter_size, extensions, recursion, recursion_depth,
                    auto_calibrate, custom_headers, follow_redirects,
                    allowed_hosts, use_proxy
                )
                futures[future] = fuzz_url

            for future in as_completed(futures):
                try:
                    results, externals = future.result()
                    all_results.extend(results)
                    external_domain_entries.extend(externals)
                except Exception as e:
                    print(f"[!][FFuf] Error: {e}")

    finally:
        shutil.rmtree(output_dir, ignore_errors=True)

    unique_results = _deduplicate_results(all_results)
    print(f"[+][FFuf] Discovered {len(unique_results)} unique endpoints")
    if external_domain_entries:
        print(f"[+][FFuf] Filtered {len(external_domain_entries)} out-of-scope URLs")

    return unique_results, {"external_domains": external_domain_entries}


def _build_fuzz_targets(
    target_urls: List[str],
    discovered_base_paths: Optional[List[str]] = None,
) -> List[str]:
    """
    Build the list of fuzz target URLs.

    For each target URL, creates:
    - Root fuzz: https://target.com/FUZZ
    - Base path fuzz: https://target.com/api/v1/FUZZ (from crawlers)
    """
    fuzz_targets = []

    for base_url in target_urls:
        base = base_url.rstrip('/')
        fuzz_targets.append(f"{base}/FUZZ")

    if discovered_base_paths:
        seen_targets = set(fuzz_targets)
        for base_url in target_urls:
            base = base_url.rstrip('/')
            for path in discovered_base_paths:
                path = path.strip('/').rstrip('/')
                if not path:
                    continue
                target = f"{base}/{path}/FUZZ"
                if target not in seen_targets:
                    fuzz_targets.append(target)
                    seen_targets.add(target)

    return fuzz_targets


def _deduplicate_results(results: List[Dict]) -> List[Dict]:
    """Deduplicate results by URL."""
    seen = set()
    unique = []
    for r in results:
        url = r.get("url", "")
        if url and url not in seen:
            seen.add(url)
            unique.append(r)
    return unique


def merge_ffuf_into_by_base_url(
    ffuf_results: List[Dict],
    existing_by_base_url: Dict,
) -> Tuple[Dict, Dict]:
    """
    Merge FFuf discovery results into the existing by_base_url structure.

    Deduplicates against existing endpoints and tracks overlap.

    Args:
        ffuf_results: List of FFuf result dicts with url, status, etc.
        existing_by_base_url: Existing by_base_url from crawlers/jsluice

    Returns:
        Tuple of (merged by_base_url, stats dict)
    """
    stats = {
        "ffuf_total": len(ffuf_results),
        "ffuf_new": 0,
        "ffuf_overlap": 0,
    }

    for result in ffuf_results:
        url = result.get("url", "")
        if not url:
            continue

        try:
            parsed = urlparse(url)
        except Exception:
            continue

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        if base_url in existing_by_base_url:
            existing_endpoints = existing_by_base_url[base_url].get('endpoints', {})
            if path in existing_endpoints:
                stats["ffuf_overlap"] += 1
                existing_ep = existing_endpoints[path]
                sources = existing_ep.get('sources', [])
                if 'ffuf' not in sources:
                    sources.append('ffuf')
                    existing_ep['sources'] = sources
                continue

        stats["ffuf_new"] += 1

        if base_url not in existing_by_base_url:
            existing_by_base_url[base_url] = {
                'base_url': base_url,
                'endpoints': {},
                'summary': {
                    'total_endpoints': 0,
                    'total_parameters': 0,
                    'methods': {},
                    'categories': {},
                }
            }

        status = result.get("status", 200)
        method = "GET"
        category = _classify_ffuf_endpoint(path, status, result.get("content_type", ""))

        endpoint = {
            'methods': [method],
            'sources': ['ffuf'],
            'category': category,
            'parameters': {'query': [], 'body': [], 'path': []},
            'parameter_count': {'query': 0, 'body': 0, 'path': 0, 'total': 0},
            'urls_found': 1,
            'sample_urls': [url],
            'ffuf_metadata': {
                'status': status,
                'length': result.get("length", 0),
                'words': result.get("words", 0),
                'lines': result.get("lines", 0),
                'content_type': result.get("content_type", ""),
            },
        }

        existing_by_base_url[base_url]['endpoints'][path] = endpoint
        summary = existing_by_base_url[base_url]['summary']
        summary['total_endpoints'] = len(existing_by_base_url[base_url]['endpoints'])
        summary['methods'][method] = summary['methods'].get(method, 0) + 1
        summary['categories'][category] = summary['categories'].get(category, 0) + 1

    return existing_by_base_url, stats


def _classify_ffuf_endpoint(path: str, status: int, content_type: str) -> str:
    """Classify an FFuf-discovered endpoint by path and response characteristics."""
    path_lower = path.lower()

    if status in (301, 302, 307, 308):
        return "redirect"
    if status == 403:
        return "forbidden"

    admin_indicators = ['/admin', '/dashboard', '/manager', '/cpanel', '/wp-admin',
                        '/console', '/panel', '/control', '/backend']
    if any(ind in path_lower for ind in admin_indicators):
        return "admin"

    config_indicators = ['.env', '.config', '.ini', '.yml', '.yaml', '.xml',
                         '.properties', '.conf', 'web.config', '.htaccess']
    if any(ind in path_lower for ind in config_indicators):
        return "config"

    backup_indicators = ['.bak', '.old', '.backup', '.orig', '.save', '.swp',
                         '.copy', '.tmp', '.dist']
    if any(ind in path_lower for ind in backup_indicators):
        return "backup"

    api_indicators = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/',
                      '/json/', '/xml/']
    if any(ind in path_lower for ind in api_indicators):
        return "api"

    if '/login' in path_lower or '/auth' in path_lower or '/signin' in path_lower:
        return "auth"

    if content_type and 'application/json' in content_type:
        return "api"

    return "directory"


def pull_ffuf_binary_check() -> bool:
    """Verify ffuf binary is available in PATH."""
    try:
        result = subprocess.run(
            ["ffuf", "-V"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False
