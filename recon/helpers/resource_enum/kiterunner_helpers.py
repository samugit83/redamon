"""
RedAmon - Kiterunner API Discovery Helpers
==========================================
API endpoint bruteforcing using Kiterunner.
"""

import json
import platform
import shutil
import subprocess
import tarfile
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .classification import classify_endpoint


def _create_temp_dir(prefix: str = "kr") -> Path:
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


def ensure_kiterunner_binary(wordlist_name: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Ensure Kiterunner binary and wordlist are available.

    Downloads from GitHub releases if not present.

    Args:
        wordlist_name: Name of the wordlist to use (e.g., "routes-large")

    Returns:
        Tuple of (binary_path, wordlist_path) or (None, None) if failed
    """
    # Determine paths
    tools_dir = Path.home() / ".redamon" / "tools"
    kr_dir = tools_dir / "kiterunner"
    kr_dir.mkdir(parents=True, exist_ok=True)

    # Determine binary name based on OS
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if machine in ["x86_64", "amd64"]:
            asset_name = "kiterunner_1.0.2_linux_amd64.tar.gz"
            binary_name = "kr"
        elif machine in ["aarch64", "arm64"]:
            asset_name = "kiterunner_1.0.2_linux_arm64.tar.gz"
            binary_name = "kr"
        else:
            print(f"[!][Kiterunner] Unsupported architecture: {machine}")
            return None, None
    elif system == "darwin":
        if machine in ["x86_64", "amd64"]:
            asset_name = "kiterunner_1.0.2_macOS_amd64.tar.gz"
            binary_name = "kr"
        elif machine in ["aarch64", "arm64"]:
            asset_name = "kiterunner_1.0.2_macOS_arm64.tar.gz"
            binary_name = "kr"
        else:
            print(f"[!][Kiterunner] Unsupported architecture: {machine}")
            return None, None
    else:
        print(f"[!][Kiterunner] Unsupported OS: {system}")
        return None, None

    binary_path = kr_dir / binary_name
    wordlist_path = kr_dir / f"{wordlist_name}.kite"

    # Download binary if not present
    if not binary_path.exists():
        print(f"[*][Kiterunner] Downloading Kiterunner binary...")
        download_url = f"https://github.com/assetnote/kiterunner/releases/download/v1.0.2/{asset_name}"

        try:
            archive_path = kr_dir / asset_name

            # Download archive with User-Agent header
            request = urllib.request.Request(
                download_url,
                headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) RedAmon/1.0'}
            )
            with urllib.request.urlopen(request) as response:
                with open(archive_path, 'wb') as f:
                    f.write(response.read())

            # Extract archive
            if asset_name.endswith(".tar.gz"):
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=kr_dir)
            elif asset_name.endswith(".zip"):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(kr_dir)

            # Make binary executable
            if binary_path.exists():
                binary_path.chmod(0o755)
                print(f"[+][Kiterunner] Binary installed: {binary_path}")

            # Cleanup archive
            archive_path.unlink()

        except Exception as e:
            print(f"[!][Kiterunner] Failed to download Kiterunner: {e}")
            return None, None

    # Download wordlist if not present
    # Note: routes-large.kite is the comprehensive wordlist (~140k routes)
    # The apiroutes-* wordlists are only available via the -A flag (auto-download by kr)
    if not wordlist_path.exists():
        print(f"[*][Kiterunner] Downloading wordlist: {wordlist_name}...")

        # Map wordlist names to download URLs
        wordlist_urls = {
            "routes-large": "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz",
            "routes-small": "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz",
        }

        # Check if it's a standard wordlist we can download
        base_wordlist = wordlist_name.replace(".kite", "")
        if base_wordlist in wordlist_urls:
            wordlist_url = wordlist_urls[base_wordlist]
            try:
                archive_path = kr_dir / f"{base_wordlist}.kite.tar.gz"

                # Download compressed wordlist with User-Agent header (required by CDN)
                request = urllib.request.Request(
                    wordlist_url,
                    headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) RedAmon/1.0'}
                )
                with urllib.request.urlopen(request) as response:
                    with open(archive_path, 'wb') as f:
                        f.write(response.read())

                # Extract wordlist
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=kr_dir)

                # Cleanup archive
                archive_path.unlink()

                # Rename to expected name if needed
                extracted_path = kr_dir / f"{base_wordlist}.kite"
                if extracted_path.exists() and not wordlist_path.exists():
                    extracted_path.rename(wordlist_path)

                print(f"[+][Kiterunner] Wordlist downloaded: {wordlist_path}")
            except Exception as e:
                print(f"[!][Kiterunner] Failed to download wordlist: {e}")
                return None, None
        else:
            # For apiroutes-* wordlists, they're downloaded automatically by kr using -A flag
            # We'll return a special marker to use -A flag instead of -w
            print(f"[*][Kiterunner] Wordlist '{wordlist_name}' will be fetched by Kiterunner using -A flag")
            return str(binary_path), f"ASSETNOTE:{wordlist_name}"

    if binary_path.exists() and wordlist_path.exists():
        return str(binary_path), str(wordlist_path)
    return None, None


def run_kiterunner_discovery(
    target_urls: List[str],
    binary_path: str,
    wordlist_path: str,
    wordlist_name: str,
    rate_limit: int,
    connections: int,
    timeout: int,
    scan_timeout: int,
    threads: int,
    ignore_status: List[int],
    match_status: List[int],
    min_content_length: int,
    headers: List[str],
    use_proxy: bool = False,
) -> List[Dict]:
    """
    Run Kiterunner API endpoint bruteforcing.

    Kiterunner uses Swagger/OpenAPI specs to discover hidden API routes.
    Unlike Katana/GAU, it finds endpoints that aren't linked or archived.

    Args:
        target_urls: Base URLs to scan (e.g., ["http://example.com"])
        binary_path: Path to Kiterunner binary (kr)
        wordlist_path: Path to wordlist file (.kite)
        wordlist_name: Name of wordlist for display
        rate_limit: Requests per second limit
        connections: Number of connections
        timeout: Request timeout in seconds
        scan_timeout: Overall scan timeout
        threads: Number of threads
        ignore_status: Status codes to ignore
        match_status: Status codes to match
        min_content_length: Minimum content length to include
        headers: Custom headers to send
        use_proxy: Whether to use Tor proxy

    Returns:
        List of discovered endpoint dictionaries with url, path, method, status
    """
    print(f"\n[*][Kiterunner] Running Kiterunner API discovery...")
    print(f"[*][Kiterunner] Wordlist: {wordlist_name}")
    print(f"[*][Kiterunner] Rate limit: {rate_limit} req/s")
    print(f"[*][Kiterunner] Targets: {len(target_urls)}")

    discovered_endpoints = []

    # Check if binary and wordlist are available
    if not binary_path or not wordlist_path:
        print("[!][Kiterunner] Binary or wordlist not available")
        return discovered_endpoints

    if not Path(binary_path).exists():
        print(f"[!][Kiterunner] Binary not found: {binary_path}")
        return discovered_endpoints

    # Check if using Assetnote wordlist (via -A flag) or local file
    use_assetnote_wordlist = wordlist_path.startswith("ASSETNOTE:")
    assetnote_wordlist_name = wordlist_path.replace("ASSETNOTE:", "") if use_assetnote_wordlist else None

    if not use_assetnote_wordlist and not Path(wordlist_path).exists():
        print(f"[!][Kiterunner] Wordlist not found: {wordlist_path}")
        return discovered_endpoints

    # Create temp directory for targets file (use /tmp/redamon for Docker-in-Docker compatibility)
    temp_path = _create_temp_dir("kr_scan")
    try:
        targets_file = temp_path / "targets.txt"

        # Write targets to file (one per line)
        with open(targets_file, 'w') as f:
            for url in target_urls:
                if url.startswith(('http://', 'https://')):
                    f.write(f"{url}\n")

        # Build Kiterunner command using local binary
        # Output in JSON format to stdout for parsing
        cmd = [
            binary_path,
            "scan",
            str(targets_file),
            "-x", str(connections),
            "-j", str(threads),
            "-t", f"{timeout}s",  # -t for timeout, not --timeout
            "-o", "json",  # -o is for output FORMAT (json/text/pretty), not file path
        ]

        # Add wordlist - either local file (-w) or Assetnote wordlist (-A)
        if use_assetnote_wordlist:
            # Use -A flag for Assetnote wordlists (auto-downloaded by kr)
            # Limit to first 20000 routes to avoid excessive scanning
            cmd.extend(["-A", f"{assetnote_wordlist_name}:20000"])
        else:
            cmd.extend(["-w", wordlist_path])

        # Rate limiting (delay in ms between requests)
        if rate_limit > 0:
            delay_ms = int(1000 / rate_limit)
            if delay_ms > 0:
                cmd.extend(["--delay", f"{delay_ms}ms"])

        # Status code filters (kiterunner expects comma-separated values)
        if ignore_status:
            # --fail-status-codes blacklists status codes (comma-separated)
            codes_str = ",".join(str(code) for code in ignore_status)
            cmd.extend(["--fail-status-codes", codes_str])

        if match_status:
            # --success-status-codes whitelists status codes (comma-separated)
            codes_str = ",".join(str(code) for code in match_status)
            cmd.extend(["--success-status-codes", codes_str])

        # Content length filter
        if min_content_length > 0:
            cmd.extend(["--ignore-length", f"0-{min_content_length}"])

        # Custom headers
        for header in headers:
            cmd.extend(["-H", header])

        # Proxy support
        if use_proxy:
            cmd.extend(["--proxy", "socks5://127.0.0.1:9050"])

        try:
            print(f"[*][Kiterunner] Command: {' '.join(cmd[:6])}...")  # Show partial command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_timeout + 60
            )

            # Parse Kiterunner JSON output from stdout
            # Kiterunner JSON format (with -o json):
            # {
            #   "method": "GET",
            #   "target": "http://example.com",
            #   "path": "/api/users",
            #   "responses": [{"uri": "", "sc": 200, "len": 1234}],
            #   "time": "2026-01-04T19:12:21+01:00"
            # }
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue

                    # Try to parse as JSON
                    try:
                        data = json.loads(line)

                        # Skip info/log messages (they have "level" or "message" fields)
                        if 'level' in data or 'message' in data:
                            continue

                        # Skip if no method (not a result line)
                        if 'method' not in data:
                            continue

                        # Extract fields from Kiterunner JSON format
                        method = data.get('method', 'GET').upper()
                        target = data.get('target', '')
                        path = data.get('path', '')

                        # Get status code and content length from responses array
                        responses = data.get('responses', [])
                        status = 0
                        content_length = 0
                        if responses and isinstance(responses, list) and len(responses) > 0:
                            first_response = responses[0]
                            status = first_response.get('sc', 0)  # 'sc' = status code
                            content_length = first_response.get('len', 0)  # 'len' = content length

                        # Build full URL from target + path
                        if target and path:
                            url = target.rstrip('/') + path
                        elif target:
                            url = target
                        else:
                            url = ''

                        if path and target:
                            endpoint = {
                                'method': method,
                                'status': status,
                                'url': url,
                                'path': path,
                                'content_length': content_length
                            }
                            discovered_endpoints.append(endpoint)
                        continue
                    except json.JSONDecodeError:
                        pass

                    # Fallback: parse plain text format (for non-JSON output)
                    # Format: METHOD STATUS_CODE URL [content_length]
                    parts = line.split()
                    if len(parts) >= 3:
                        method = parts[0].upper()
                        if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                            continue
                        try:
                            status = int(parts[1])
                        except ValueError:
                            continue
                        url = parts[2]

                        try:
                            parsed_url = urlparse(url)
                            path = parsed_url.path or "/"
                        except Exception:
                            continue

                        # Avoid duplicates
                        if not any(e['url'] == url and e['method'] == method for e in discovered_endpoints):
                            endpoint = {
                                'method': method,
                                'status': status,
                                'url': url,
                                'path': path,
                                'content_length': int(parts[3]) if len(parts) > 3 else 0
                            }
                            discovered_endpoints.append(endpoint)

            if result.stderr and "error" in result.stderr.lower():
                print(f"[!][Kiterunner] stderr: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            print(f"[!][Kiterunner] Timeout after {scan_timeout}s")
        except Exception as e:
            print(f"[!][Kiterunner] Error: {e}")
    finally:
        _cleanup_temp_dir(temp_path)

    print(f"[+][Kiterunner] Discovered {len(discovered_endpoints)} API endpoints")
    return discovered_endpoints


def merge_kiterunner_into_by_base_url(
    kr_results: List[Dict],
    by_base_url: Dict,
    url_methods: Dict[str, List[str]] = None
) -> Tuple[Dict, Dict[str, int]]:
    """
    Merge Kiterunner API endpoints into existing by_base_url structure.

    Args:
        kr_results: List of Kiterunner result dictionaries
        by_base_url: Existing by_base_url structure from Katana/GAU
        url_methods: Optional dict mapping URL -> list of detected methods

    Returns:
        Tuple of (updated by_base_url, merge stats)
    """
    stats = {
        "kr_total": len(kr_results),
        "kr_parsed": 0,
        "kr_new": 0,
        "kr_overlap": 0,
        "kr_methods": {},
        "kr_methods_detected": 0,
        "kr_with_multiple_methods": 0
    }

    for result in kr_results:
        url = result.get('url', '')
        path = result.get('path', '')
        original_method = result.get('method', 'GET').upper()
        status = result.get('status', 0)

        if not url or not path:
            continue

        stats["kr_parsed"] += 1

        # Get methods for this URL (from detection or original)
        if url_methods and url in url_methods:
            methods = url_methods[url]
            if len(methods) > 1:
                stats["kr_with_multiple_methods"] += 1
        else:
            methods = [original_method]

        # Track method statistics
        for method in methods:
            stats["kr_methods"][method] = stats["kr_methods"].get(method, 0) + 1

        # Parse base URL
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            continue

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

        if path in endpoints:
            # Endpoint exists - add kiterunner to sources and merge methods
            existing_sources = endpoints[path].get('sources', [])
            if not existing_sources:
                # Migrate old 'source' string to 'sources' array
                old_source = endpoints[path].get('source', '')
                if old_source:
                    existing_sources = [old_source]
            if 'kiterunner' not in existing_sources:
                existing_sources.append('kiterunner')
            endpoints[path]['sources'] = existing_sources
            endpoints[path].pop('source', None)  # Remove old field

            stats["kr_overlap"] += 1

            # Add all detected methods if new
            existing_methods = set(endpoints[path].get('methods', []))
            for method in methods:
                if method not in existing_methods:
                    endpoints[path]['methods'].append(method)
                    by_base_url[base]['summary']['methods'][method] = \
                        by_base_url[base]['summary']['methods'].get(method, 0) + 1
        else:
            # New endpoint from Kiterunner
            stats["kr_new"] += 1

            # Classify endpoint using all detected methods
            category = classify_endpoint(path, methods, {'query': [], 'body': [], 'path': []})

            endpoints[path] = {
                'methods': methods,  # Use all detected methods
                'parameters': {
                    'query': [],
                    'body': [],
                    'path': []
                },
                'sources': ['kiterunner'],  # Use array format
                'category': category,
                'status_code': status,
                'parameter_count': {
                    'query': 0,
                    'body': 0,
                    'path': 0,
                    'total': 0
                }
            }

            # Update summary for all methods
            by_base_url[base]['summary']['total_endpoints'] += 1
            for method in methods:
                by_base_url[base]['summary']['methods'][method] = \
                    by_base_url[base]['summary']['methods'].get(method, 0) + 1
            by_base_url[base]['summary']['categories'][category] = \
                by_base_url[base]['summary']['categories'].get(category, 0) + 1

    return by_base_url, stats


def detect_kiterunner_methods(
    kr_results: List[Dict],
    verify_docker_image: str,
    detect_methods: bool,
    method_detection_mode: str,
    bruteforce_methods: List[str],
    method_detect_timeout: int,
    method_detect_rate_limit: int,
    method_detect_threads: int,
    use_proxy: bool = False
) -> Dict[str, List[str]]:
    """
    Detect allowed HTTP methods for Kiterunner-discovered endpoints.

    Supports two modes:
    - "options": Send OPTIONS request, parse 'Allow' header (faster)
    - "bruteforce": Try each method directly (slower, more accurate)

    Args:
        kr_results: List of Kiterunner result dictionaries
        verify_docker_image: Docker image for httpx verification
        detect_methods: Whether method detection is enabled
        method_detection_mode: Detection mode ("options" or "bruteforce")
        bruteforce_methods: List of methods to try in bruteforce mode
        method_detect_timeout: Timeout for method detection
        method_detect_rate_limit: Rate limit for method detection
        method_detect_threads: Number of threads for detection
        use_proxy: Whether to use Tor proxy

    Returns:
        Dict mapping URL -> list of allowed methods (e.g., ["GET", "POST"])
    """
    if not kr_results or not detect_methods:
        # Return original methods from Kiterunner output
        return {r['url']: [r.get('method', 'GET')] for r in kr_results if r.get('url')}

    mode = method_detection_mode.lower()
    print(f"\n[*][Kiterunner] Detecting HTTP methods for {len(kr_results)} endpoints...")
    print(f"[*][Kiterunner] Mode: {mode}")

    # Extract unique URLs from Kiterunner results
    urls = list(set(r['url'] for r in kr_results if r.get('url')))
    url_methods: Dict[str, List[str]] = {}

    # Initialize with methods found by Kiterunner
    for result in kr_results:
        url = result.get('url', '')
        method = result.get('method', 'GET').upper()
        if url:
            if url not in url_methods:
                url_methods[url] = []
            if method not in url_methods[url]:
                url_methods[url].append(method)

    # Use /tmp/redamon for Docker-in-Docker compatibility (avoids paths with spaces)
    temp_path = _create_temp_dir("kr_methods")
    try:
        if mode == "options":
            # OPTIONS probe mode - same as GAU method detection
            urls_file = temp_path / "urls.txt"
            output_file = temp_path / "options_output.json"

            with open(urls_file, 'w') as f:
                for url in urls:
                    f.write(f"{url}\n")

            cmd = [
                "docker", "run", "--rm",
                "-v", f"{temp_path}:/data",
                verify_docker_image,
                "-l", "/data/urls.txt",
                "-o", "/data/options_output.json",
                "-json",
                "-silent",
                "-nc",
                "-X", "OPTIONS",
                "-include-response-header", "Allow,allow",
                "-t", str(method_detect_threads),
                "-timeout", str(method_detect_timeout),
                "-rl", str(method_detect_rate_limit),
            ]

            if use_proxy:
                cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=300)

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
                                    valid_methods = [m for m in valid_methods if m != 'OPTIONS']

                                    if valid_methods and url in url_methods:
                                        # Merge with existing methods
                                        for method in valid_methods:
                                            if method not in url_methods[url]:
                                                url_methods[url].append(method)

                            except json.JSONDecodeError:
                                continue

            except subprocess.TimeoutExpired:
                print("[!][Kiterunner] OPTIONS probe timeout")
            except Exception as e:
                print(f"[!][Kiterunner] OPTIONS probe error: {e}")

        elif mode == "bruteforce":
            # Bruteforce mode - try each method directly
            methods_to_try = bruteforce_methods
            print(f"[*][Kiterunner] Methods to try: {', '.join(methods_to_try)}")

            for method in methods_to_try:
                urls_file = temp_path / f"urls_{method.lower()}.txt"
                output_file = temp_path / f"output_{method.lower()}.json"

                with open(urls_file, 'w') as f:
                    for url in urls:
                        f.write(f"{url}\n")

                cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{temp_path}:/data",
                    verify_docker_image,
                    "-l", f"/data/urls_{method.lower()}.txt",
                    "-o", f"/data/output_{method.lower()}.json",
                    "-json",
                    "-silent",
                    "-nc",
                    "-X", method,
                    "-t", str(method_detect_threads),
                    "-timeout", str(method_detect_timeout),
                    "-rl", str(method_detect_rate_limit),
                ]

                if use_proxy:
                    cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

                try:
                    subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                    if output_file.exists():
                        with open(output_file, 'r') as f:
                            for line in f:
                                try:
                                    entry = json.loads(line.strip())
                                    url = entry.get('url', '')
                                    status = entry.get('status_code') or entry.get('status-code', 0)

                                    # Accept responses that indicate the endpoint accepts this method
                                    # 200, 201, 204 = success
                                    # 301, 302, 307 = redirect (method works)
                                    # 400 = bad request (method accepted, params wrong)
                                    # 401, 403 = auth required (method accepted)
                                    # 405 = method not allowed (skip)
                                    # 404 = not found (skip - might be method-specific)
                                    if status and status not in [404, 405, 500, 502, 503, 504]:
                                        if url in url_methods and method not in url_methods[url]:
                                            url_methods[url].append(method)

                                except json.JSONDecodeError:
                                    continue

                except subprocess.TimeoutExpired:
                    print(f"[!][Kiterunner] {method} probe timeout")
                except Exception as e:
                    print(f"[!][Kiterunner] {method} probe error: {e}")
    finally:
        _cleanup_temp_dir(temp_path)

    # Count statistics
    with_multiple = sum(1 for methods in url_methods.values() if len(methods) > 1)
    method_counts = {}
    for methods in url_methods.values():
        for m in methods:
            method_counts[m] = method_counts.get(m, 0) + 1

    print(f"[+][Kiterunner] Method detection complete:")
    print(f"[+][Kiterunner] Endpoints with multiple methods: {with_multiple}")
    print(f"[+][Kiterunner] Method distribution: {method_counts}")

    return url_methods

