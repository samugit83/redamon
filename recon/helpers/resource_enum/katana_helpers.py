"""
RedAmon - Katana Crawler Helpers for Resource Enumeration
=========================================================
Active URL discovery using Katana web crawler.
"""

import os
import select
import subprocess
import ssl
import time
import urllib.request
import uuid
from typing import Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlparse, urlsplit

from recon.helpers.docker_helpers import kill_container, pull_image_or_use_local, tool_container_name
from recon.helpers.system_resolvers import resolver_args
from recon.helpers.js_recon.urls import is_js_url
from recon.helpers.target_admission import admission_context
from .form_helpers import parse_forms_from_html


def redirects_contained(settings: Optional[Mapping], recon_data: Optional[Mapping]) -> bool:
    """True when the run admits its targets one by one: RoE exclusions are in
    force, or IP mode keeps it to the target list. A crawler may then reach only
    the hosts it was seeded with, since a redirect or a sibling-subdomain link
    can name a host the run refused. With neither, crawling is unchanged."""
    return admission_context(settings, recon_data).active


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
    parallelism: int = 5,
    concurrency: int = 10,
    *,
    settings: Optional[Mapping] = None,
    recon_data: Optional[Mapping] = None,
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
        parallelism: Number of target URLs to crawl simultaneously (-p flag)
        concurrency: Number of concurrent fetchers per target (-c flag)
        settings, recon_data: the run's, for redirects_contained

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
    no_redirects = redirects_contained(settings, recon_data)
    if no_redirects:
        print("[*][Katana] Redirects not followed: RoE exclusions or the IP target list are in force")

    discovered_urls = set()
    js_urls = set()
    filtered_out_of_scope = 0
    external_domain_entries = []  # Collect out-of-scope domains for situational awareness
    # Katana exits 0 on a crawl that genuinely found nothing, so an empty result
    # alone cannot be read as a failure; a non-zero exit, stderr output or an
    # exception can. The caller uses this to keep the findings of the tools fed
    # by this crawl (jsluice) out of the prune.
    crawl_failed = False

    # Filter to valid HTTP(S) URLs
    valid_urls = [u for u in target_urls if u.startswith(('http://', 'https://'))]
    if not valid_urls:
        print("[!][Katana] No valid HTTP(S) URLs to crawl")
        return [], {"external_domains": [], "js_urls": []}

    print(f"[*][Katana] Target URLs: {len(valid_urls)}")

    # Write target URLs to /tmp/redamon (bind-mounted same path host<->recon
    # container, see docker-compose.yml). Plain /tmp doesn't work under
    # Docker-in-Docker: the spawned katana container's -v /tmp:/tmp resolves
    # against the host daemon's /tmp, not the recon container's /tmp.
    os.makedirs("/tmp/redamon", exist_ok=True)
    url_file = f"/tmp/redamon/katana_targets_{uuid.uuid4().hex[:8]}.txt"

    try:
        with open(url_file, 'w') as f:
            f.write('\n'.join(valid_urls))

        # Build single Katana command with -list.
        #
        # --net=host is ALWAYS passed so Katana can reach loopback / local-lab
        # targets (127.0.0.1, our guinea pigs at agentic/labs/* and
        # guinea_pigs/*, anything running on the host with `network_mode: host`).
        # Without it, the spawned Katana container gets a fresh bridge network
        # where `localhost` == the Katana container itself, causing every fetch
        # to silently fail with ECONNREFUSED and Katana to sit at 0% CPU for
        # the full crawl-duration window. For non-loopback targets host
        # networking is equivalent to bridge — both have internet egress —
        # so the flag is strictly an upgrade.
        #
        # Named because every stop below kills only the docker CLI: the
        # container is then killed by this name, or it would go on crawling.
        container_name = tool_container_name("katana")
        cmd = ["docker", "run", "--rm", "--net=host", "--name", container_name]

        cmd.extend(["-v", "/tmp/redamon:/tmp/redamon"])

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
            # FQDN scope keeps the crawl on the seed URLs' exact hostnames. It is
            # fixed, not a setting: the filter below keeps only allowed_hosts,
            # which both callers build from those same seeds, so a wider scope
            # (rdn, dn) would only send requests to hosts no scan admitted,
            # RoE-excluded names included, and then discard the results.
            "-fs", "fqdn",
        ])
        if no_redirects:
            # katana follows a redirect inside its HTTP client, before any scope
            # check: -fs, -cos and -exclude judge only the links it queues
            # (v1.8.0, run against a loopback 302 into an excluded host), so a
            # seed answering 302 to an RoE-excluded host or to an address
            # outside the IP target list had that host requested. -dr is the
            # only flag that stops the hop. It also drops same-host redirect
            # targets, which is the coverage this costs.
            cmd.append("-dr")
        # Resolve as the DNS step did (recon/helpers/system_resolvers.py).
        cmd.extend(resolver_args())

        # JavaScript crawling
        if js_crawl:
            cmd.append("-jc")

        # Custom headers
        if custom_headers:
            for header in custom_headers:
                cmd.extend(["-H", header])

        # HTTP traffic capture (Phase 1): route this crawl through the capture
        # proxy when enabled + reachable. The X-Redamon-Ctx tag is added ONLY in
        # this same branch as -proxy (§20.2), so it can never leak to the target
        # on the direct path.
        from helpers.proxy_routing import get_capture_routing
        _cap_url, _cap_token = get_capture_routing("katana")
        if _cap_url and _cap_token:
            cmd.extend(["-proxy", _cap_url, "-H", f"X-Redamon-Ctx: {_cap_token}"])

        try:
            # Stream output line-by-line so we can enforce max_urls and kill early
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            cut = False
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
                        cut = True
                        break

                    # Check idle timeout (no output for too long)
                    if time.time() - last_output_time > idle_timeout:
                        print(f"[!][Katana] Idle timeout ({idle_timeout}s with no output)")
                        process.kill()
                        cut = True
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

                    # The exclude list drops /static/, /_next/static and .min.js,
                    # which is where an app keeps its own bundle; js_recon needs
                    # those files, so they are handed over before the filter.
                    if is_js_url(url):
                        js_urls.add(url)

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
                        cut = True
                        break

            finally:
                # Ensure process is cleaned up
                if process.poll() is None:
                    process.kill()
                    cut = True
                process.wait()
                if cut:
                    kill_container(container_name)

                # Surface stderr WHENEVER the crawl found nothing.
                #
                # This used to also require `elapsed < 10` and a NON-ZERO exit
                # code, which made it unreachable in the case it was written
                # for: katana exits 0 when it crawls nothing, and a spawn that
                # fails (broker denial, unreadable -list under DinD, DNS) can
                # take longer than 10s. The result was a completely silent
                # "Discovered 0 URLs" with the real cause captured in the
                # stderr pipe and then thrown away - which is exactly how a
                # zero-URL crawl became impossible to diagnose from the logs.
                #
                # A crawl that legitimately finds nothing prints a short,
                # harmless note; a broken one finally prints its reason.
                elapsed = time.time() - start_time
                if not discovered_urls:
                    try:
                        stderr_output = process.stderr.read() if process.stderr else ""
                    except Exception:
                        stderr_output = ""
                    print(f"[!][Katana] Found 0 URLs in {elapsed:.1f}s "
                          f"(exit code {process.returncode}). Seed list: {url_file} "
                          f"({len(valid_urls)} URL(s))")
                    if process.returncode != 0 or stderr_output.strip():
                        crawl_failed = True
                    # Everything it printed was filtered by scope or excludes: that
                    # is the crawl working, not an empty result.
                    if not filtered_out_of_scope and not js_urls:
                        from recon.helpers.resource_enum import tool_health
                        tool_health.check_empty(
                            "katana", seeds=len(valid_urls), elapsed_s=elapsed,
                            return_code=process.returncode if isinstance(process.returncode, int) else None,
                            stderr=stderr_output)
                    if stderr_output.strip():
                        print("[!][Katana] stderr:")
                        for line in stderr_output.strip().splitlines()[:20]:
                            print(f"[!][Katana]   {line}")
                    else:
                        print("[!][Katana]   (no stderr output - the crawl ran "
                              "but the target returned no crawlable links)")

        except Exception as e:
            crawl_failed = True
            print(f"[!][Katana] Error: {e}")
            from recon.helpers.resource_enum import tool_health
            tool_health.report_empty("katana", tool_health.FAILURE, return_code=None,
                                     seeds=len(valid_urls), elapsed_s=0)

    finally:
        # Clean up temp file
        try:
            os.unlink(url_file)
        except OSError:
            pass

    urls_list = sorted(list(discovered_urls))
    print(f"[+][Katana] Discovered {len(urls_list)} URLs")
    if filtered_out_of_scope > 0:
        print(f"[+][Katana] Filtered {filtered_out_of_scope} out-of-scope URLs")

    return urls_list, {"external_domains": external_domain_entries, "failed": crawl_failed,
                       "js_urls": sorted(js_urls)}


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to the host the request went to. A refused hop
    ends that fetch with an HTTPError, which the caller skips like any other."""

    def __init__(self):
        super().__init__()
        self.refused = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _url_host(newurl) != _url_host(req.full_url):
            self.refused += 1
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").rstrip(".").lower()
    except ValueError:
        return ""


def fetch_forms_from_urls(
    urls: List[str],
    max_urls: int = 50,
    *,
    settings: Optional[Mapping] = None,
    recon_data: Optional[Mapping] = None,
) -> List[Dict]:
    """
    Fetch HTML from URLs and extract forms.

    Args:
        urls: URLs to fetch (will filter to HTML pages only)
        max_urls: Maximum URLs to fetch for form extraction
        settings, recon_data: the run's. Under redirects_contained a redirect
            is followed only on the same host: the crawlers report a 3xx URL
            whose Location may name a host the run refused.

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

    handlers = [urllib.request.HTTPSHandler(context=ssl_context)]
    same_host = _SameHostRedirects() if redirects_contained(settings, recon_data) else None
    if same_host is not None:
        handlers.append(same_host)
    opener = urllib.request.build_opener(*handlers)

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

    if same_host is not None and same_host.refused:
        print(f"[-][Katana] Form fetch: {same_host.refused} redirect(s) to another host not followed "
              f"(RoE exclusions or the IP target list are in force)")
    print(f"[+][Katana] Extracted {len(all_forms)} forms from HTML pages")
    return all_forms


def pull_katana_docker_image(docker_image: str) -> bool:
    """
    Pull the Katana Docker image, or use the copy already on this host if the pull fails.
    
    Args:
        docker_image: Docker image name to pull
        
    Returns:
        True if successful, False otherwise
    """
    print(f"[*][Katana] Pulling Katana image: {docker_image}...")
    return pull_image_or_use_local(docker_image, "Katana")

