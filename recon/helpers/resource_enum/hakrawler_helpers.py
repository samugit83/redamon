"""
RedAmon - Hakrawler Crawler Helpers for Resource Enumeration
============================================================
Active URL discovery using Hakrawler web crawler (Docker-in-Docker).
"""

import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple
from urllib.parse import urlparse


def _crawl_single_url(
    base_url: str,
    docker_image: str,
    depth: int,
    threads: int,
    timeout: int,
    include_subs: bool,
    insecure: bool,
    allowed_hosts: set,
    custom_headers: List[str],
    exclude_patterns: List[str],
    use_proxy: bool,
    shared_urls: set,
    urls_lock: threading.Lock,
    max_urls: int,
) -> Tuple[set, int, list]:
    """
    Crawl a single URL with Hakrawler. Thread-safe via shared_urls + lock.

    Returns:
        Tuple of (discovered_urls_set, filtered_out_of_scope_count, external_entries)
    """
    local_urls = set()
    filtered_count = 0
    external_entries = []

    cmd = ["docker", "run", "--rm", "-i"]

    if use_proxy:
        cmd.extend(["--network", "host"])

    cmd.append(docker_image)

    cmd.extend(["-d", str(depth)])
    cmd.extend(["-t", str(threads)])
    cmd.extend(["-timeout", str(timeout)])
    cmd.append("-u")

    if insecure:
        cmd.append("-insecure")

    if include_subs:
        cmd.append("-subs")

    if custom_headers:
        header_str = ";;".join(custom_headers)
        cmd.extend(["-h", header_str])

    if use_proxy:
        cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        try:
            process.stdin.write(base_url + "\n")
            process.stdin.close()

            start_time = time.time()
            overall_timeout = timeout * 2 + 60

            while True:
                if time.time() - start_time > overall_timeout:
                    print(f"[!][Hakrawler] Overall timeout for {base_url}")
                    process.kill()
                    break

                # Check if global max_urls already reached by other workers
                with urls_lock:
                    if len(shared_urls) >= max_urls:
                        process.kill()
                        break

                line = process.stdout.readline()
                if not line:
                    break

                url = line.strip()
                if not url:
                    continue

                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or ''
                    if host and allowed_hosts and host not in allowed_hosts:
                        filtered_count += 1
                        external_entries.append({
                            "domain": host, "source": "hakrawler", "url": url,
                        })
                        continue
                except Exception:
                    continue

                url_lower = url.lower()
                if any(pattern.lower() in url_lower for pattern in exclude_patterns):
                    continue

                local_urls.add(url)

                # Check max_urls with lock
                with urls_lock:
                    shared_urls.add(url)
                    if len(shared_urls) >= max_urls:
                        print(f"[+][Hakrawler] Reached max URL limit ({max_urls}), stopping")
                        process.kill()
                        break

        finally:
            if process.poll() is None:
                process.kill()
            process.wait()

    except Exception as e:
        print(f"[!][Hakrawler] Error for {base_url}: {e}")

    return local_urls, filtered_count, external_entries


def run_hakrawler_crawler(
    target_urls: List[str],
    docker_image: str,
    depth: int,
    threads: int,
    timeout: int,
    max_urls: int,
    include_subs: bool,
    insecure: bool,
    allowed_hosts: set,
    custom_headers: List[str],
    exclude_patterns: List[str],
    use_proxy: bool = False,
    parallelism: int = 4,
) -> Tuple[List[str], Dict]:
    """
    Run Hakrawler crawler to discover endpoints via stdin-based Docker execution.

    Uses ThreadPoolExecutor to crawl multiple URLs in parallel.
    Hakrawler accepts URLs via stdin and outputs discovered URLs line by line.
    Scope is enforced post-hoc against the allowed_hosts set.

    Args:
        target_urls: Base URLs to crawl
        docker_image: Hakrawler Docker image name
        depth: Crawl depth
        threads: Number of concurrent threads per Hakrawler instance
        timeout: Per-URL timeout in seconds
        max_urls: Maximum URLs to discover (enforced by killing process)
        include_subs: Whether to include subdomains in crawl scope
        insecure: Disable TLS certificate verification
        allowed_hosts: Set of hostnames for scope filtering
        custom_headers: Custom HTTP headers
        exclude_patterns: URL patterns to exclude
        use_proxy: Whether to use Tor proxy
        parallelism: Number of URLs to crawl in parallel

    Returns:
        Tuple of (discovered_urls, {"external_domains": [...]})
    """
    print(f"\n[*][Hakrawler] Running Hakrawler crawler for endpoint discovery...")
    print(f"[*][Hakrawler] Crawl depth: {depth}")
    print(f"[*][Hakrawler] Threads per instance: {threads}")
    print(f"[*][Hakrawler] Per-URL timeout: {timeout}s")
    print(f"[*][Hakrawler] Max URLs: {max_urls}")
    print(f"[*][Hakrawler] Parallelism: {parallelism} concurrent crawlers")
    print(f"[*][Hakrawler] Include subdomains: {include_subs}")
    print(f"[*][Hakrawler] Allowed hosts: {len(allowed_hosts)} ({', '.join(sorted(allowed_hosts)[:5])}{'...' if len(allowed_hosts) > 5 else ''})")

    discovered_urls = set()
    filtered_out_of_scope = 0
    external_domain_entries = []
    urls_lock = threading.Lock()

    valid_urls = [u for u in target_urls if u.startswith(('http://', 'https://'))]
    if not valid_urls:
        return [], {"external_domains": []}

    max_workers = min(parallelism, len(valid_urls))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _crawl_single_url,
                url, docker_image, depth, threads, timeout,
                include_subs, insecure, allowed_hosts, custom_headers,
                exclude_patterns, use_proxy, discovered_urls, urls_lock, max_urls,
            ): url
            for url in valid_urls
        }

        for future in as_completed(futures):
            try:
                local_urls, filtered, externals = future.result()
                with urls_lock:
                    filtered_out_of_scope += filtered
                    external_domain_entries.extend(externals)
            except Exception as e:
                print(f"[!][Hakrawler] Worker error: {e}")

    urls_list = sorted(list(discovered_urls))
    print(f"[+][Hakrawler] Discovered {len(urls_list)} URLs")
    if filtered_out_of_scope > 0:
        print(f"[+][Hakrawler] Filtered {filtered_out_of_scope} out-of-scope URLs")

    return urls_list, {"external_domains": external_domain_entries}


def pull_hakrawler_docker_image(docker_image: str) -> bool:
    """Pull the Hakrawler Docker image if not present."""
    try:
        print(f"[*][Hakrawler] Pulling Hakrawler image: {docker_image}...")
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


def merge_hakrawler_into_by_base_url(
    hakrawler_by_base_url: Dict,
    existing_by_base_url: Dict,
) -> Tuple[Dict, Dict]:
    """
    Merge Hakrawler-organized endpoints into the existing by_base_url structure.

    Deduplicates against existing Katana endpoints and tracks overlap.

    Args:
        hakrawler_by_base_url: Endpoints organized from Hakrawler URLs
        existing_by_base_url: Existing by_base_url from Katana

    Returns:
        Tuple of (merged by_base_url, stats dict)
    """
    stats = {
        "hakrawler_total": 0,
        "hakrawler_new": 0,
        "hakrawler_overlap": 0,
    }

    for base_url, base_data in hakrawler_by_base_url.items():
        for path, endpoint in base_data.get('endpoints', {}).items():
            stats["hakrawler_total"] += 1

            if base_url in existing_by_base_url:
                existing_endpoints = existing_by_base_url[base_url].get('endpoints', {})
                if path in existing_endpoints:
                    stats["hakrawler_overlap"] += 1
                    existing_ep = existing_endpoints[path]
                    sources = existing_ep.get('sources', [])
                    if 'hakrawler' not in sources:
                        sources.append('hakrawler')
                        existing_ep['sources'] = sources
                    continue

            stats["hakrawler_new"] += 1
            endpoint['sources'] = ['hakrawler']

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

            existing_by_base_url[base_url]['endpoints'][path] = endpoint
            summary = existing_by_base_url[base_url]['summary']
            summary['total_endpoints'] = len(existing_by_base_url[base_url]['endpoints'])

            methods = endpoint.get('methods', ['GET'])
            for method in methods:
                summary['methods'][method] = summary['methods'].get(method, 0) + 1

            category = endpoint.get('category', 'other')
            summary['categories'][category] = summary['categories'].get(category, 0) + 1

            pc = endpoint.get('parameter_count', {})
            total = pc.get('total', 0)
            if total == 0:
                params = endpoint.get('parameters', {})
                total = len(params.get('query') or []) + len(params.get('body') or []) + len(params.get('path') or [])
            summary['total_parameters'] += total

    return existing_by_base_url, stats
