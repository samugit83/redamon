"""
RedAmon - Katana Crawler Helpers for Resource Enumeration
=========================================================
Active URL discovery using Katana web crawler.
"""

import select
import subprocess
import ssl
import time
import urllib.request
import uuid
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from .form_helpers import parse_forms_from_html


def run_katana_crawler(
    target_urls: List[str],
    docker_image: str,
    depth: int,
    max_urls: int,
    rate_limit: int,
    timeout: int,
    js_crawl: bool,
    params_only: bool,
    allowed_hosts: set,
    custom_headers: List[str],
    exclude_patterns: List[str],
    use_proxy: bool = False,
    parallelism: int = 5,
    concurrency: int = 10,
) -> Tuple[List[str], Dict[str, str]]:
    """
    Run Katana crawler to discover all endpoints.

    Uses a single Katana process with -list flag to crawl all target URLs,
    with -p (parallelism) and -c (concurrency) for parallel crawling.

    Scope is automatically enforced: Katana uses FQDN scope to stay on the
    target hostname during crawl, and output is post-filtered against the
    allowed_hosts set (derived from the recon pipeline's target domains).

    Max URLs is enforced during the crawl by streaming output and killing
    the Katana process once the limit is reached.

    Args:
        target_urls: Base URLs to crawl
        docker_image: Katana Docker image name
        depth: Crawl depth
        max_urls: Maximum URLs to discover (enforced during crawl)
        rate_limit: Requests per second limit
        timeout: Request timeout in seconds
        js_crawl: Whether to enable JavaScript crawling
        params_only: Only return URLs with parameters
        allowed_hosts: Set of hostnames from the recon pipeline (for scope filtering)
        custom_headers: Custom headers to send
        exclude_patterns: URL patterns to exclude
        use_proxy: Whether to use Tor proxy
        parallelism: Number of target URLs to crawl simultaneously (-p flag)
        concurrency: Number of concurrent fetchers per target (-c flag)

    Returns:
        Tuple of (discovered_urls, url_to_response_body)
    """
    # Convert timeout (seconds) to Katana crawl-duration format
    crawl_duration = f"{timeout}s"
    # Idle timeout: kill if no output for 5 minutes (crawl is stuck/done)
    idle_timeout = 300

    print(f"\n[*][Katana] Running Katana crawler for endpoint discovery...")
    print(f"[*][Katana] Crawl depth: {depth}")
    print(f"[*][Katana] Max URLs: {max_urls}")
    print(f"[*][Katana] Rate limit: {rate_limit} req/s")
    print(f"[*][Katana] Crawl duration: {crawl_duration}")
    print(f"[*][Katana] Parallelism: {parallelism} (concurrent targets)")
    print(f"[*][Katana] Concurrency: {concurrency} (fetchers per target)")
    print(f"[*][Katana] Params only: {params_only}")
    print(f"[*][Katana] Allowed hosts: {len(allowed_hosts)} ({', '.join(sorted(allowed_hosts)[:5])}{'...' if len(allowed_hosts) > 5 else ''})")

    discovered_urls = set()
    filtered_out_of_scope = 0
    external_domain_entries = []  # Collect out-of-scope domains for situational awareness

    # Filter to valid HTTP(S) URLs
    valid_urls = [u for u in target_urls if u.startswith(('http://', 'https://'))]
    if not valid_urls:
        print("[!][Katana] No valid HTTP(S) URLs to crawl")
        return [], {"external_domains": []}

    print(f"[*][Katana] Target URLs: {len(valid_urls)}")

    # Write all target URLs to a temp file for Katana's -list flag
    url_file = f"/tmp/katana_targets_{uuid.uuid4().hex[:8]}.txt"

    try:
        with open(url_file, 'w') as f:
            f.write('\n'.join(valid_urls))

        # Build single Katana command with -list
        cmd = ["docker", "run", "--rm"]

        if use_proxy:
            cmd.extend(["--network", "host"])

        cmd.extend(["-v", "/tmp:/tmp"])

        cmd.extend([
            docker_image,
            "-list", url_file,
            "-d", str(depth),
            "-silent",
            "-nc",
            "-rl", str(rate_limit),
            "-p", str(parallelism),
            "-c", str(concurrency),
            "-timeout", "30",
            "-crawl-duration", crawl_duration,
            # Use FQDN scope: restricts crawl to exact hostnames of seed URLs
            # This prevents crawling parent domains (e.g. sub.example.com won't
            # crawl example.com). Post-hoc filtering provides additional safety.
            "-fs", "fqdn",
        ])

        # JavaScript crawling
        if js_crawl:
            cmd.append("-jc")

        # Custom headers
        if custom_headers:
            for header in custom_headers:
                cmd.extend(["-H", header])

        # Proxy for Tor
        if use_proxy:
            cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

        try:
            # Stream output line-by-line so we can enforce max_urls and kill early
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            try:
                start_time = time.time()
                deadline = start_time + timeout + 60
                last_output_time = start_time

                # Use select-based polling so timeouts trigger even when
                # Katana outputs nothing (e.g. headless browser spinning)
                while True:
                    # Check overall deadline
                    if time.time() > deadline:
                        print(f"[!][Katana] Overall timeout reached")
                        process.kill()
                        break

                    # Check idle timeout (no output for too long)
                    if time.time() - last_output_time > idle_timeout:
                        print(f"[!][Katana] Idle timeout ({idle_timeout}s with no output)")
                        process.kill()
                        break

                    # Poll stdout with 10s timeout so we can re-check deadlines
                    ready, _, _ = select.select([process.stdout], [], [], 10)
                    if not ready:
                        # No data, check if process exited
                        if process.poll() is not None:
                            break
                        continue

                    line = process.stdout.readline()
                    if not line:  # EOF -- process finished
                        break

                    last_output_time = time.time()
                    url = line.strip()
                    if not url:
                        continue

                    # Post-hoc scope filter: only keep URLs whose host is in allowed_hosts
                    try:
                        parsed = urlparse(url)
                        host = parsed.hostname or ''
                        if host and allowed_hosts and host not in allowed_hosts:
                            filtered_out_of_scope += 1
                            external_domain_entries.append({
                                "domain": host, "source": "katana", "url": url,
                            })
                            continue
                    except Exception:
                        continue

                    # Skip URLs matching exclude patterns
                    url_lower = url.lower()
                    if any(pattern.lower() in url_lower for pattern in exclude_patterns):
                        continue

                    # Apply params_only filter
                    if params_only:
                        if '?' in url and '=' in url:
                            discovered_urls.add(url)
                        else:
                            continue
                    else:
                        discovered_urls.add(url)

                    # Enforce max_urls: kill process early
                    if len(discovered_urls) >= max_urls:
                        print(f"[+][Katana] Reached max URL limit ({max_urls}), stopping Katana")
                        process.kill()
                        break

            finally:
                # Ensure process is cleaned up
                if process.poll() is None:
                    process.kill()
                process.wait()

        except Exception as e:
            print(f"[!][Katana] Error: {e}")

    finally:
        # Clean up temp file
        try:
            import os
            os.unlink(url_file)
        except OSError:
            pass

    urls_list = sorted(list(discovered_urls))
    print(f"[+][Katana] Discovered {len(urls_list)} URLs")
    if filtered_out_of_scope > 0:
        print(f"[+][Katana] Filtered {filtered_out_of_scope} out-of-scope URLs")

    return urls_list, {"external_domains": external_domain_entries}


def fetch_forms_from_urls(
    urls: List[str],
    use_proxy: bool = False,
    max_urls: int = 50
) -> List[Dict]:
    """
    Fetch HTML from URLs and extract forms.

    Args:
        urls: URLs to fetch (will filter to HTML pages only)
        use_proxy: Whether to use Tor proxy
        max_urls: Maximum URLs to fetch for form extraction

    Returns:
        List of form dictionaries
    """
    all_forms = []

    # Filter to likely HTML pages (exclude static files)
    static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
                         '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip',
                         '.mp3', '.mp4', '.webp', '.xml', '.json', '.txt']

    html_urls = []
    for url in urls:
        url_lower = url.lower().split('?')[0]  # Remove query params for extension check
        if not any(url_lower.endswith(ext) for ext in static_extensions):
            html_urls.append(url)

    # Limit to avoid too many requests
    html_urls = html_urls[:max_urls]

    if not html_urls:
        return all_forms

    print(f"[*][Katana] Fetching HTML from {len(html_urls)} URLs to extract forms...")

    # Create SSL context that doesn't verify certificates (for testing)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Setup proxy if needed
    if use_proxy:
        proxy_handler = urllib.request.ProxyHandler({
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        })
        opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ssl_context))
    else:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))

    for url in html_urls:
        try:
            request = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            )
            response = opener.open(request, timeout=10)
            content_type = response.headers.get('Content-Type', '')

            # Only process HTML responses
            if 'text/html' in content_type:
                html_content = response.read().decode('utf-8', errors='ignore')
                forms = parse_forms_from_html(html_content, url)
                all_forms.extend(forms)

        except Exception:
            continue

    print(f"[+][Katana] Extracted {len(all_forms)} forms from HTML pages")
    return all_forms


def pull_katana_docker_image(docker_image: str) -> bool:
    """
    Pull the Katana Docker image if not present.
    
    Args:
        docker_image: Docker image name to pull
        
    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"[*][Katana] Pulling Katana image: {docker_image}...")
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False

