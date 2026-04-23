"""
RedAmon - GAU (GetAllUrls) Helpers
==================================
Passive URL discovery from web archives using GAU.
"""

import json
import os
import platform
import shutil
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

from .classification import classify_parameter, classify_endpoint


def _is_arm64_host() -> bool:
    """Return True when running on an ARM64 host."""
    machine = platform.machine().lower()
    return machine in ("arm64", "aarch64")


def _create_temp_dir(prefix: str = "gau") -> Path:
    """Create a temp directory under /tmp/redamon for Docker-in-Docker compatibility."""
    temp_dir = Path(f"/tmp/redamon/.{prefix}_{uuid.uuid4().hex[:8]}")
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def _cleanup_temp_dir(temp_dir: Path):
    """Clean up a temp directory."""
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    except Exception:
        pass


def pull_gau_docker_image(docker_image: str) -> bool:
    """
    Pull the GAU Docker image if not present.
    
    Args:
        docker_image: Docker image name to pull
        
    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"[*][GAU] Pulling GAU image: {docker_image}...")
        pull_cmd = ["docker", "pull"]
        if _is_arm64_host():
            pull_cmd.extend(["--platform", "linux/amd64"])
        pull_cmd.append(docker_image)

        result = subprocess.run(
            pull_cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


def filter_gau_url(url: str, blacklist_extensions: List[str]) -> bool:
    """
    Check if URL should be included (not filtered out by extension blacklist).

    Args:
        url: URL to check
        blacklist_extensions: List of extensions to filter out

    Returns:
        True if URL should be included, False if filtered out
    """
    if not url:
        return False

    try:
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        # Check against blacklisted extensions
        for ext in blacklist_extensions:
            if path_lower.endswith(f".{ext.lower()}"):
                return False

        return True
    except Exception:
        return False


def _write_gau_config(urlscan_api_key: str, temp_dir: Path) -> Path:
    """Write a .gau.toml config file with API keys and return its path."""
    config_path = temp_dir / ".gau.toml"
    lines = []
    if urlscan_api_key:
        lines.append("[urlscan]")
        lines.append(f'  apikey = "{urlscan_api_key}"')
    config_path.write_text("\n".join(lines) + "\n")
    return config_path


def run_gau_for_domain(
    domain: str,
    docker_image: str,
    providers: List[str],
    threads: int,
    timeout: int,
    blacklist_extensions: List[str],
    max_urls: int,
    year_range: Optional[List[str]] = None,
    verbose: bool = False,
    use_proxy: bool = False,
    urlscan_api_key: str = ""
) -> List[str]:
    """
    Run GAU for a single domain to fetch historical URLs.

    Args:
        domain: Domain to query (e.g., "example.com")
        docker_image: GAU Docker image
        providers: List of providers (wayback, commoncrawl, etc.)
        threads: Number of threads
        timeout: Request timeout
        blacklist_extensions: Extensions to filter out
        max_urls: Maximum URLs to return
        year_range: Optional [from_year, to_year] filter
        verbose: Enable verbose output
        use_proxy: Whether to use Tor proxy
        urlscan_api_key: Optional URLScan API key for higher rate limits

    Returns:
        List of discovered URLs
    """
    # Write .gau.toml config if API key is provided
    config_temp_dir = None
    if urlscan_api_key:
        config_temp_dir = _create_temp_dir("gau_config")
        _write_gau_config(urlscan_api_key, config_temp_dir)

    try:
        return _run_gau_docker(
            domain, docker_image, providers, threads, timeout,
            blacklist_extensions, max_urls, year_range, verbose,
            use_proxy, config_temp_dir,
        )
    finally:
        if config_temp_dir:
            _cleanup_temp_dir(config_temp_dir)


def _run_gau_docker(
    domain: str,
    docker_image: str,
    providers: List[str],
    threads: int,
    timeout: int,
    blacklist_extensions: List[str],
    max_urls: int,
    year_range: Optional[List[str]],
    verbose: bool,
    use_proxy: bool,
    config_temp_dir: Optional[Path],
) -> List[str]:
    """Internal: execute GAU Docker container."""
    discovered_urls = set()

    # Build GAU command
    cmd = ["docker", "run", "--rm"]
    if _is_arm64_host():
        cmd.extend(["--platform", "linux/amd64"])

    # Mount .gau.toml config if available
    if config_temp_dir:
        config_file = config_temp_dir / ".gau.toml"
        cmd.extend(["-v", f"{config_file}:/root/.gau.toml:ro"])

    # Network mode for Tor proxy
    if use_proxy:
        cmd.extend(["--network", "host"])
        cmd.extend([
            "-e", "HTTP_PROXY=socks5://127.0.0.1:9050",
            "-e", "HTTPS_PROXY=socks5://127.0.0.1:9050"
        ])

    cmd.extend([
        docker_image,
        "--threads", str(threads),
        "--timeout", str(timeout),
        "--providers", ",".join(providers),
    ])

    # Blacklist extensions
    if blacklist_extensions:
        cmd.extend(["--blacklist", ",".join(blacklist_extensions)])

    # Year range filter (wayback only)
    if year_range and len(year_range) == 2:
        cmd.extend(["--from", year_range[0]])
        cmd.extend(["--to", year_range[1]])

    # Verbose mode
    if verbose:
        cmd.append("--verbose")

    # Add domain at the end
    cmd.append(domain)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * len(providers) + 120
        )

        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                url = line.strip()
                if url and filter_gau_url(url, blacklist_extensions):
                    discovered_urls.add(url)

                    if max_urls > 0 and len(discovered_urls) >= max_urls:
                        break

        if result.stderr and verbose:
            print(f"[*][GAU] GAU stderr: {result.stderr[:200]}")

    except subprocess.TimeoutExpired:
        print(f"[!][GAU] Timeout for {domain}")
    except Exception as e:
        print(f"[!][GAU] Error for {domain}: {e}")

    return sorted(list(discovered_urls))


def run_gau_discovery(
    target_domains: Set[str],
    docker_image: str,
    providers: List[str],
    threads: int,
    timeout: int,
    blacklist_extensions: List[str],
    max_urls: int,
    year_range: Optional[List[str]] = None,
    verbose: bool = False,
    use_proxy: bool = False,
    urlscan_api_key: str = "",
    workers: int = 10
) -> Tuple[List[str], Dict[str, List[str]]]:
    """
    Run GAU passive URL discovery for multiple domains.

    Args:
        target_domains: Set of domains to query
        ... (configuration parameters)
        use_proxy: Whether to use Tor proxy
        urlscan_api_key: Optional URLScan API key for higher rate limits

    Returns:
        Tuple of (all_discovered_urls, urls_by_domain)
    """
    print(f"\n[*][GAU] Running GAU passive URL discovery...")
    print(f"[*][GAU] Providers: {', '.join(providers)}")
    print(f"[*][GAU] Max URLs per domain: {max_urls if max_urls > 0 else 'unlimited'}")
    if urlscan_api_key:
        print(f"[*][GAU] URLScan API key: configured")

    all_discovered_urls = set()
    urls_by_domain = {}
    total_domains = len(target_domains)
    max_workers = min(workers, total_domains)

    print(f"[*][GAU] Processing {total_domains} domains with {max_workers} parallel workers (max configured: {workers})...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {}
        for domain in sorted(target_domains):
            future = executor.submit(
                run_gau_for_domain,
                domain=domain,
                docker_image=docker_image,
                providers=providers,
                threads=threads,
                timeout=timeout,
                blacklist_extensions=blacklist_extensions,
                max_urls=max_urls,
                year_range=year_range,
                verbose=verbose,
                use_proxy=use_proxy,
                urlscan_api_key=urlscan_api_key
            )
            future_to_domain[future] = domain

        completed = 0
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            completed += 1
            try:
                domain_urls = future.result()
                urls_by_domain[domain] = domain_urls
                all_discovered_urls.update(domain_urls)
                print(f"[+][GAU] [{completed}/{total_domains}] {domain}: {len(domain_urls)} URLs")
            except Exception as e:
                print(f"[!][GAU] [{completed}/{total_domains}] {domain} failed: {e}")
                urls_by_domain[domain] = []

    urls_list = sorted(list(all_discovered_urls))
    print(f"[+][GAU] Discovered {len(urls_list)} total URLs")

    return urls_list, urls_by_domain


def parse_gau_url_to_endpoint(url: str) -> Optional[Dict]:
    """
    Parse a GAU URL into the resource_enum endpoint format.

    Args:
        url: Full URL (e.g., "http://example.com/api/users?id=123&debug=1")

    Returns:
        Dictionary with base_url, path, and parameters, or None if invalid
    """
    if not url:
        return None

    try:
        parsed = urlparse(url)

        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return None

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        # Normalize path - remove trailing slash except for root
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        # Extract query parameters (just the names, not values)
        query_params = list(parse_qs(parsed.query).keys()) if parsed.query else []

        return {
            "base_url": base_url,
            "path": path,
            "parameters": {"query": query_params} if query_params else {}
        }
    except Exception:
        return None


def verify_gau_urls(
    urls: List[str],
    docker_image: str,
    threads: int,
    timeout: int,
    rate_limit: int,
    accept_status: List[int],
    use_proxy: bool = False
) -> Set[str]:
    """
    Verify GAU-discovered URLs are live using httpx.

    Args:
        urls: List of URLs to verify
        docker_image: httpx Docker image
        threads: Number of threads
        timeout: Request timeout
        rate_limit: Rate limit
        accept_status: List of acceptable status codes
        use_proxy: Whether to use Tor proxy

    Returns:
        Set of verified live URLs
    """
    if not urls:
        return set()

    print(f"\n[*][GAU] Verifying {len(urls)} GAU URLs...")

    # Create temp directory for httpx input/output (Docker-in-Docker compatible)
    temp_dir = _create_temp_dir("gau_verify")
    try:
        urls_file = temp_dir / "urls.txt"
        output_file = temp_dir / "verified.json"

        # Write URLs to file
        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")

        # Build httpx command
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{temp_dir}:/data",
            docker_image,
            "-l", "/data/urls.txt",
            "-o", "/data/verified.json",
            "-json",
            "-silent",
            "-nc",
            "-t", str(threads),
            "-timeout", str(timeout),
            "-rl", str(rate_limit),
        ]

        if use_proxy:
            cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("[!][GAU] URL verification timeout")
            return set(urls)
        except Exception as e:
            print(f"[!][GAU] URL verification error: {e}")
            return set(urls)

        # Parse results
        live_urls = set()
        accept_codes = set(accept_status)

        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        url = entry.get('url', '')
                        status = entry.get('status_code') or entry.get('status-code')
                        if status and status in accept_codes:
                            live_urls.add(url)
                    except json.JSONDecodeError:
                        continue

        print(f"[+][GAU] Verified: {len(live_urls)}/{len(urls)} URLs are live")
        return live_urls
    finally:
        _cleanup_temp_dir(temp_dir)


def detect_gau_methods(
    urls: List[str],
    docker_image: str,
    threads: int,
    timeout: int,
    rate_limit: int,
    filter_dead: bool = True,
    use_proxy: bool = False
) -> Dict[str, List[str]]:
    """
    Detect allowed HTTP methods for GAU URLs using OPTIONS probe.

    Args:
        urls: List of URLs to probe
        docker_image: httpx Docker image
        threads: Number of threads
        timeout: Request timeout
        rate_limit: Rate limit
        filter_dead: Whether to filter out dead endpoints
        use_proxy: Whether to use Tor proxy

    Returns:
        Dict mapping URL -> list of allowed methods
    """
    if not urls:
        return {}

    print(f"\n[*][GAU] Detecting HTTP methods for {len(urls)} GAU endpoints...")

    url_methods: Dict[str, List[str]] = {}

    # Create temp directory (Docker-in-Docker compatible)
    temp_dir = _create_temp_dir("gau_methods")
    try:
        urls_file = temp_dir / "urls.txt"
        output_file = temp_dir / "options_output.json"

        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{temp_dir}:/data",
            docker_image,
            "-l", "/data/urls.txt",
            "-o", "/data/options_output.json",
            "-json",
            "-silent",
            "-nc",
            "-X", "OPTIONS",
            "-include-response-header", "Allow,allow",
            "-t", str(threads),
            "-timeout", str(timeout),
            "-rl", str(rate_limit),
        ]

        if use_proxy:
            cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("[!][GAU] Method detection timeout")
            return {url: ["GET"] for url in urls}
        except Exception as e:
            print(f"[!][GAU] Method detection error: {e}")
            return {url: ["GET"] for url in urls}

        options_responded = set()

        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        url = entry.get('url', '')
                        status = entry.get('status_code') or entry.get('status-code', 0)

                        headers = entry.get('header', {}) or entry.get('headers', {})
                        allow_header = None

                        for key in ['Allow', 'allow', 'ALLOW']:
                            if key in headers:
                                allow_value = headers[key]
                                if isinstance(allow_value, list):
                                    allow_header = allow_value[0] if allow_value else None
                                else:
                                    allow_header = allow_value
                                break

                        if allow_header and status and status < 500:
                            methods = [m.strip().upper() for m in allow_header.split(',')]
                            valid_methods = [m for m in methods if m in
                                           ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']]
                            if valid_methods:
                                valid_methods = [m for m in valid_methods if m != 'OPTIONS']
                                if valid_methods:
                                    url_methods[url] = valid_methods
                                    options_responded.add(url)
                        elif status and status < 400:
                            url_methods[url] = ["GET"]
                            options_responded.add(url)

                    except json.JSONDecodeError:
                        continue

        # GET fallback for URLs that didn't respond to OPTIONS
        urls_needing_get_check = [url for url in urls if url not in options_responded]

        if urls_needing_get_check and filter_dead:
            print(f"[*][GAU] Checking {len(urls_needing_get_check)} endpoints with GET fallback...")

            get_urls_file = temp_dir / "get_urls.txt"
            get_output_file = temp_dir / "get_output.json"

            with open(get_urls_file, 'w') as f:
                for url in urls_needing_get_check:
                    f.write(f"{url}\n")

            get_cmd = [
                "docker", "run", "--rm",
                "-v", f"{temp_dir}:/data",
                docker_image,
                "-l", "/data/get_urls.txt",
                "-o", "/data/get_output.json",
                "-json",
                "-silent",
                "-nc",
                "-t", str(threads),
                "-timeout", str(timeout),
                "-rl", str(rate_limit),
            ]

            if use_proxy:
                get_cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

            try:
                subprocess.run(get_cmd, capture_output=True, text=True, timeout=300)

                if get_output_file.exists():
                    with open(get_output_file, 'r') as f:
                        for line in f:
                            try:
                                entry = json.loads(line.strip())
                                url = entry.get('url', '')
                                status = entry.get('status_code') or entry.get('status-code', 0)

                                if status and status < 500 and status != 404:
                                    url_methods[url] = ["GET"]
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                print(f"[!][GAU] GET fallback error: {e}")
                for url in urls_needing_get_check:
                    if url not in url_methods:
                        url_methods[url] = ["GET"]
        elif not filter_dead:
            for url in urls_needing_get_check:
                url_methods[url] = ["GET"]

        with_methods = sum(1 for methods in url_methods.values() if len(methods) > 1)
        filtered_out = len(urls) - len(url_methods)

        print(f"[+][GAU] Method detection complete:")
        print(f"[*][GAU]   - Endpoints with multiple methods: {with_methods}")
        print(f"[*][GAU]   - Endpoints with GET only: {len(url_methods) - with_methods}")
        if filter_dead:
            print(f"[*][GAU]   - Dead endpoints filtered out: {filtered_out}")

        return url_methods
    finally:
        _cleanup_temp_dir(temp_dir)


def merge_gau_into_by_base_url(
    gau_urls: List[str],
    by_base_url: Dict,
    verified_urls: Set[str] = None,
    url_methods: Dict[str, List[str]] = None
) -> Tuple[Dict, Dict[str, int]]:
    """
    Merge GAU endpoints into existing by_base_url structure.

    Args:
        gau_urls: List of GAU-discovered URLs
        by_base_url: Existing by_base_url structure
        verified_urls: Set of URLs verified as live
        url_methods: Dict mapping URL -> list of allowed methods

    Returns:
        Tuple of (updated by_base_url, merge stats)
    """
    stats = {
        "gau_total": len(gau_urls),
        "gau_parsed": 0,
        "gau_new": 0,
        "gau_overlap": 0,
        "gau_skipped_unverified": 0,
        "gau_skipped_dead": 0,
        "gau_with_post": 0,
        "gau_with_multiple_methods": 0
    }

    for url in gau_urls:
        if verified_urls is not None and url not in verified_urls:
            stats["gau_skipped_unverified"] += 1
            continue

        if url_methods is not None and url not in url_methods:
            stats["gau_skipped_dead"] += 1
            continue

        parsed = parse_gau_url_to_endpoint(url)
        if not parsed:
            continue

        stats["gau_parsed"] += 1
        base = parsed["base_url"]
        path = parsed["path"]

        methods = url_methods.get(url, ["GET"]) if url_methods else ["GET"]

        if "POST" in methods:
            stats["gau_with_post"] += 1
        if len(methods) > 1:
            stats["gau_with_multiple_methods"] += 1

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

        if path in endpoints:
            existing_sources = endpoints[path].get('sources', [])
            if not existing_sources:
                old_source = endpoints[path].get('source', '')
                if old_source:
                    existing_sources = [old_source]
            if 'gau' not in existing_sources:
                existing_sources.append('gau')
                stats["gau_overlap"] += 1
            endpoints[path]['sources'] = existing_sources
            endpoints[path].pop('source', None)

            existing_methods = set(endpoints[path].get('methods', []))
            new_methods = existing_methods.union(set(methods))
            endpoints[path]['methods'] = sorted(list(new_methods))

            for method in methods:
                if method not in existing_methods:
                    by_base_url[base]['summary']['methods'][method] = \
                        by_base_url[base]['summary']['methods'].get(method, 0) + 1

            existing_query = endpoints[path].get('parameters', {}).get('query', [])
            new_query = parsed["parameters"].get("query", [])

            if new_query:
                if isinstance(existing_query, list):
                    existing_names = [p.get('name', p) if isinstance(p, dict) else p for p in existing_query]
                else:
                    existing_names = []

                for param_name in new_query:
                    if param_name not in existing_names:
                        param_info = {
                            'name': param_name,
                            'category': classify_parameter(param_name),
                            'source': 'gau'
                        }
                        if 'parameters' not in endpoints[path]:
                            endpoints[path]['parameters'] = {'query': [], 'body': [], 'path': []}
                        if 'query' not in endpoints[path]['parameters']:
                            endpoints[path]['parameters']['query'] = []
                        endpoints[path]['parameters']['query'].append(param_info)
        else:
            stats["gau_new"] += 1

            query_params = []
            for param_name in parsed["parameters"].get("query", []):
                query_params.append({
                    'name': param_name,
                    'category': classify_parameter(param_name),
                    'source': 'gau'
                })

            category = classify_endpoint(path, methods, {'query': query_params, 'body': [], 'path': []})

            endpoints[path] = {
                'methods': methods,
                'parameters': {
                    'query': query_params,
                    'body': [],
                    'path': []
                },
                'sources': ['gau'],
                'category': category,
                'parameter_count': {
                    'query': len(query_params),
                    'body': 0,
                    'path': 0,
                    'total': len(query_params)
                },
                'sample_urls': [url]
            }

            by_base_url[base]['summary']['total_endpoints'] += 1
            by_base_url[base]['summary']['total_parameters'] += len(query_params)
            for method in methods:
                by_base_url[base]['summary']['methods'][method] = \
                    by_base_url[base]['summary']['methods'].get(method, 0) + 1
            by_base_url[base]['summary']['categories'][category] = \
                by_base_url[base]['summary']['categories'].get(category, 0) + 1

    return by_base_url, stats

