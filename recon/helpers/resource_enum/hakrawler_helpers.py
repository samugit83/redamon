"""
RedAmon - Hakrawler Crawler Helpers for Resource Enumeration
============================================================
Active URL discovery using Hakrawler web crawler (Docker-in-Docker).
"""

import math
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from recon.helpers.docker_helpers import kill_container, pull_image_or_use_local, tool_container_name
from recon.helpers.js_recon.urls import is_js_url
from recon.helpers.resource_enum import tool_health


def per_url_budget(timeout: int) -> int:
    """Seconds one URL may run before its container is killed.

    hakrawler's own -timeout caps the crawl of each URL; the doubling and the
    extra minute absorb container start-up and a slow final flush.
    """
    return timeout * 2 + 60


def _crawlable_urls(target_urls: List[str]) -> List[str]:
    return [u for u in target_urls if u.startswith(('http://', 'https://'))]


def hakrawler_job_budget(target_urls: List[str], timeout: int, parallelism: int) -> int:
    """Worst-case seconds for run_hakrawler_crawler over these seeds.

    A caller waiting on the crawler must size its wait from THIS, not from the
    per-URL timeout. The crawler works through every seed, `parallelism` at a
    time, so a wait sized for one URL expires minutes into a large run. The
    caller then discards every URL found, yet still blocks in the executor's
    shutdown until the crawl finishes: all of the time, none of the output.
    """
    urls = _crawlable_urls(target_urls)
    if not urls:
        return 0
    workers = max(1, min(parallelism, len(urls)))
    return math.ceil(len(urls) / workers) * per_url_budget(timeout)


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
    shared_urls: set,
    urls_lock: threading.Lock,
    max_urls: int,
    health: Optional[dict] = None,
    js_urls: Optional[set] = None,
) -> Tuple[set, int, list]:
    """
    Crawl a single URL with Hakrawler. Thread-safe via shared_urls + lock.

    ``js_urls``, when given, collects every in-scope JS URL before the exclude
    filter (under the lock), for js_recon and jsluice; see run_katana_crawler.

    A seed that printed nothing is classified (tool_health): a non-zero exit, a
    watchdog kill or error output counts in `health["failed"]` (under the lock),
    so the caller can protect jsluice. A seed stopped because the shared URL cap
    was reached is not an empty result.

    Returns:
        Tuple of (discovered_urls_set, filtered_out_of_scope_count, external_entries)
    """
    local_urls = set()
    filtered_count = 0
    external_entries = []
    lines_seen = 0
    capped = False
    overran = threading.Event()
    return_code = None
    stderr_text = ""
    raised = False
    start_time = time.time()

    # --net=host is ALWAYS passed so Hakrawler can reach loopback / local-lab
    # targets. See recon/helpers/resource_enum/katana_helpers.py for the long
    # comment on why sibling docker containers can't see 127.0.0.1 otherwise.
    #
    # Named because the watchdog and the URL cap kill only the docker CLI: the
    # container is then killed by this name, or it would go on crawling.
    container_name = tool_container_name("hakrawler")
    cmd = ["docker", "run", "--rm", "--net=host", "-i", "--name", container_name]

    cmd.append(docker_image)

    cmd.extend(["-d", str(depth)])
    cmd.extend(["-t", str(threads)])
    cmd.extend(["-timeout", str(timeout)])
    cmd.append("-u")

    if insecure:
        cmd.append("-insecure")

    if include_subs:
        cmd.append("-subs")

    # HTTP traffic capture (Phase 1): route through the capture proxy when
    # enabled + reachable. The X-Redamon-Ctx tag is added ONLY in this routing
    # branch (§20.2 no-leak). hakrawler joins headers with ';;' via -h.
    _cap_headers = list(custom_headers) if custom_headers else []
    from helpers.proxy_routing import get_capture_routing
    _cap_url, _cap_token = get_capture_routing("hakrawler")
    if _cap_url and _cap_token:
        cmd.extend(["-proxy", _cap_url])
        _cap_headers.append(f"X-Redamon-Ctx: {_cap_token}")
    if _cap_headers:
        cmd.extend(["-h", ";;".join(_cap_headers)])

    # stderr goes to a file, not a pipe: nothing drains a pipe while stdout is
    # read line by line, so a chatty hakrawler would block on a full one.
    stderr_file = tempfile.TemporaryFile(mode="w+")
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            text=True,
        )

        # Heartbeat thread: emit progress every 30s independently of the
        # readline() loop below, which can block for arbitrary periods
        # while the subprocess is silent. Defined outside the inner try
        # so the finally always sees a valid thread reference.
        overall_timeout = per_url_budget(timeout)
        heartbeat_stop = threading.Event()

        def _hb():
            while not heartbeat_stop.wait(30):
                elapsed = int(time.time() - start_time)
                with urls_lock:
                    found = len(shared_urls)
                print(
                    f"[*][Hakrawler] still running... "
                    f"({elapsed}s elapsed, {found} URLs found)",
                    flush=True,
                )

        heartbeat_thread = threading.Thread(target=_hb, daemon=True)
        heartbeat_thread.start()

        # A timer, not a check in the read loop: readline() blocks for as long
        # as hakrawler stays silent, so a loop check never fires on the host
        # that hangs. hakrawler_job_budget() relies on this bound being real.
        def _overrun():
            if process.poll() is None:
                print(f"[!][Hakrawler] Overall timeout for {base_url}", flush=True)
                overran.set()
                process.kill()

        watchdog = threading.Timer(overall_timeout, _overrun)
        watchdog.daemon = True
        watchdog.start()

        try:
            process.stdin.write(base_url + "\n")
            process.stdin.close()

            while True:
                # Check if global max_urls already reached by other workers
                with urls_lock:
                    if len(shared_urls) >= max_urls:
                        capped = True
                        process.kill()
                        break

                line = process.stdout.readline()
                if not line:
                    break

                url = line.strip()
                if not url:
                    continue
                lines_seen += 1

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

                if js_urls is not None and is_js_url(url):
                    with urls_lock:
                        js_urls.add(url)

                url_lower = url.lower()
                if any(pattern.lower() in url_lower for pattern in exclude_patterns):
                    continue

                local_urls.add(url)

                # Check max_urls with lock
                with urls_lock:
                    shared_urls.add(url)
                    if len(shared_urls) >= max_urls:
                        print(f"[+][Hakrawler] Reached max URL limit ({max_urls}), stopping")
                        capped = True
                        process.kill()
                        break

        finally:
            watchdog.cancel()
            heartbeat_stop.set()
            stopped = capped or overran.is_set()
            if process.poll() is None:
                process.kill()
                stopped = True
            process.wait()
            if stopped:
                kill_container(container_name)
            heartbeat_thread.join(timeout=1)
            return_code = process.returncode if isinstance(process.returncode, int) else None

    except Exception as e:
        raised = True
        print(f"[!][Hakrawler] Error for {base_url}: {e}")
    finally:
        try:
            stderr_file.seek(0)
            stderr_text = stderr_file.read(tool_health.STDERR_KEEP)
            stderr_file.close()
        except Exception:  # noqa: BLE001
            pass

    if lines_seen == 0 and not capped:
        verdict = tool_health.check_empty(
            "hakrawler", seeds=1, return_code=return_code, stderr=stderr_text,
            elapsed_s=time.time() - start_time, timed_out=overran.is_set(), raised=raised)
        if verdict in (tool_health.FAILURE, tool_health.UNDECIDED) and health is not None:
            with urls_lock:
                health["failed"] = health.get("failed", 0) + 1

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
        parallelism: Number of URLs to crawl in parallel

    Returns:
        Tuple of (discovered_urls, {"external_domains": [...], "failed": bool,
        "failed_seeds": int}). `failed` is true when any seed came back empty
        with a failure or unexplained error output (tool_health), so the caller
        keeps last run's jsluice secrets out of the prune.
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
    js_found = set()
    filtered_out_of_scope = 0
    external_domain_entries = []
    urls_lock = threading.Lock()
    health = {"failed": 0}

    valid_urls = _crawlable_urls(target_urls)
    if not valid_urls:
        return [], {"external_domains": [], "failed": False, "failed_seeds": 0, "js_urls": []}

    # Skip a seed whose host another module already found unreachable: each
    # crawl otherwise costs its full per-seed timeout against a dead host. The
    # skip is noted per host (gap 'resource_enum'), so the prune keeps every
    # finding on that host; Endpoints are assets, which the prune never touches.
    from recon.helpers import circuit_breaker as _cb
    _scope = _cb.scope((), label="Hakrawler", unit="seed(s)")
    live_urls = [u for u in valid_urls if not _scope.skip_if_down(u)]
    if not live_urls:
        _scope.finish("resource_enum", host_source="resource_enum")
        return [], {"external_domains": [], "failed": False, "failed_seeds": 0, "js_urls": []}

    max_workers = min(parallelism, len(live_urls))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _crawl_single_url,
                url, docker_image, depth, threads, timeout,
                include_subs, insecure, allowed_hosts, custom_headers,
                exclude_patterns, discovered_urls, urls_lock, max_urls, health, js_found,
            ): url
            for url in live_urls
        }

        for future in as_completed(futures):
            try:
                local_urls, filtered, externals = future.result()
                with urls_lock:
                    filtered_out_of_scope += filtered
                    external_domain_entries.extend(externals)
            except Exception as e:
                print(f"[!][Hakrawler] Worker error: {e}")
                with urls_lock:
                    health["failed"] += 1

    _scope.finish("resource_enum", host_source="resource_enum")

    urls_list = sorted(list(discovered_urls))
    print(f"[+][Hakrawler] Discovered {len(urls_list)} URLs")
    if filtered_out_of_scope > 0:
        print(f"[+][Hakrawler] Filtered {filtered_out_of_scope} out-of-scope URLs")
    if health["failed"]:
        print(f"[!][Hakrawler] {health['failed']} seed(s) came back empty with an error or no "
              f"clean exit")

    return urls_list, {"external_domains": external_domain_entries,
                       "failed": health["failed"] > 0, "failed_seeds": health["failed"],
                       "js_urls": sorted(js_found)}


def pull_hakrawler_docker_image(docker_image: str) -> bool:
    """Pull the Hakrawler Docker image, or use the copy already on this host if the pull fails."""
    print(f"[*][Hakrawler] Pulling Hakrawler image: {docker_image}...")
    return pull_image_or_use_local(docker_image, "Hakrawler")


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
