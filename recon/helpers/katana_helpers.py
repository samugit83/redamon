"""
RedAmon - Katana Crawler Helpers
================================
Functions for running the Katana web crawler to discover URLs with parameters.
"""

import subprocess
from typing import List


# =============================================================================
# Katana Web Crawler
# =============================================================================

def run_katana_crawler(
    target_urls: List[str],
    docker_image: str,
    use_proxy: bool = False,
    # Katana configuration
    depth: int = 3,
    max_urls: int = 500,
    rate_limit: int = 10,
    timeout: int = 30,
    js_crawl: bool = True,
    params_only: bool = True,
    scope: str = "rdn",
    custom_headers: List[str] = None,
    exclude_patterns: List[str] = None,
) -> List[str]:
    """
    Run Katana crawler to discover URLs with parameters for DAST fuzzing.
    
    Args:
        target_urls: Base URLs to crawl (e.g., ["http://example.com"])
        docker_image: Katana Docker image to use
        use_proxy: Whether to use Tor proxy
        depth: Crawl depth
        max_urls: Maximum URLs to discover
        rate_limit: Requests per second
        timeout: Request timeout in seconds
        js_crawl: Enable JavaScript crawling
        params_only: Only collect URLs with parameters
        scope: Field scope (rdn = root domain name)
        custom_headers: Custom headers (e.g., ["Cookie: session=abc"])
        exclude_patterns: URL patterns to exclude
        
    Returns:
        List of discovered URLs with parameters
    """
    print(f"\n[*][Katana] Running Katana crawler to discover URLs with parameters...")
    print(f"[*][Katana] Crawl depth: {depth}")
    print(f"[*][Katana] Max URLs: {max_urls}")
    print(f"[*][Katana] Rate limit: {rate_limit} req/s")
    
    if exclude_patterns is None:
        exclude_patterns = []
    
    discovered_urls = set()
    
    for base_url in target_urls:
        # Only crawl http/https URLs
        if not base_url.startswith(('http://', 'https://')):
            continue
            
        # Build Katana command
        cmd = [
            "docker", "run", "--rm",
        ]

        # Add network host mode for Tor proxy access
        if use_proxy:
            cmd.extend(["--network", "host"])

        # Mount tmp directory for Chrome/headless browser (needed for JS crawling)
        cmd.extend(["-v", "/tmp:/tmp"])

        cmd.extend([
            docker_image,
            "-u", base_url,
            "-d", str(depth),
            "-silent",
            "-nc",  # No color
            "-rl", str(rate_limit),
            "-timeout", str(timeout),
            "-fs", scope,  # Field scope
        ])
        
        # JavaScript crawling
        if js_crawl:
            cmd.append("-jc")
        
        # Custom headers for authentication (cookies, tokens, etc.)
        if custom_headers:
            for header in custom_headers:
                cmd.extend(["-H", header])
        
        # Proxy for Tor
        if use_proxy:
            cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 60  # Extra buffer
            )
            
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    url = line.strip()
                    if url:
                        # Skip URLs matching exclude patterns (static assets, images, etc.)
                        url_lower = url.lower()
                        if any(pattern.lower() in url_lower for pattern in exclude_patterns):
                            continue

                        # Filter for URLs with parameters if enabled
                        if params_only:
                            if '?' in url and '=' in url:
                                discovered_urls.add(url)
                        else:
                            discovered_urls.add(url)

                        # Stop if we've reached max URLs
                        if len(discovered_urls) >= max_urls:
                            break
                            
        except subprocess.TimeoutExpired:
            print(f"[!][Katana] Timeout for {base_url}")
        except Exception as e:
            print(f"[!][Katana] Error for {base_url}: {e}")
        
        if len(discovered_urls) >= max_urls:
            break
    
    urls_list = sorted(list(discovered_urls))
    
    print(f"[✓][Katana] Found {len(urls_list)} URLs with parameters")
    if urls_list:
        print(f"[*][Katana] Sample URLs:")
        for url in urls_list[:5]:
            print(f"[*][Katana]   - {url[:80]}{'...' if len(url) > 80 else ''}")
        if len(urls_list) > 5:
            print(f"[*][Katana]   ... and {len(urls_list) - 5} more")
    
    return urls_list

