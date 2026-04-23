"""
JS Recon Source Map Discovery + Analysis

Discovers .map source map files for JS files and analyzes them
to extract original source code, file paths, and embedded secrets.
"""

import re
import json
import hashlib
import requests
from urllib.parse import urljoin, urlparse
from typing import Optional


# Default paths to probe for source maps
DEFAULT_SOURCEMAP_PROBE_PATHS = [
    '{url}.map',
    '{base}/static/js/{filename}.map',
    '{base}/assets/js/{filename}.map',
    '{base}/dist/{filename}.map',
    '{base}/build/{filename}.map',
    '{base}/dist/js/{filename}.map',
    '{base}/build/js/{filename}.map',
    '{base}/public/js/{filename}.map',
]


def check_sourcemap_comment(content: str) -> Optional[str]:
    """
    Check last lines of JS content for sourceMappingURL comment.

    Returns the source map URL/path if found, None otherwise.
    """
    lines = content.strip().split('\n')
    # Check last 5 lines (source map comment is typically the very last line)
    for line in reversed(lines[-5:]):
        line = line.strip()
        match = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', line)
        if match:
            return match.group(1)
        # Also check multi-line comment style
        match = re.search(r'/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/', line)
        if match:
            return match.group(1)
    return None


def check_sourcemap_header(headers: dict) -> Optional[str]:
    """
    Check HTTP response headers for SourceMap or X-SourceMap header.

    Returns the source map URL if found, None otherwise.
    """
    for header_name in ('SourceMap', 'X-SourceMap', 'sourcemap', 'x-sourcemap'):
        value = headers.get(header_name)
        if value:
            return value.strip()
    return None


def _resolve_map_url(js_url: str, map_ref: str) -> str:
    """Resolve a source map reference (could be relative) against the JS file URL."""
    if map_ref.startswith(('http://', 'https://', '//')):
        return map_ref
    if map_ref.startswith('data:'):
        return map_ref  # Inline source map
    return urljoin(js_url, map_ref)


def _build_probe_urls(js_url: str, custom_paths: Optional[list] = None) -> list:
    """Build list of URLs to probe for source map files."""
    parsed = urlparse(js_url)
    filename = parsed.path.split('/')[-1]
    base = f"{parsed.scheme}://{parsed.netloc}"

    paths = list(DEFAULT_SOURCEMAP_PROBE_PATHS)
    if custom_paths:
        paths.extend(custom_paths)

    urls = []
    for path_template in paths:
        try:
            url = path_template.format(
                url=js_url,
                base=base,
                filename=filename,
            )
        except (KeyError, IndexError):
            continue
        if url not in urls:
            urls.append(url)

    return urls


def _fetch_sourcemap(url: str, timeout: int = 10) -> Optional[dict]:
    """Fetch and parse a source map JSON file."""
    if url.startswith('data:'):
        # Inline base64-encoded source map
        try:
            import base64
            _, data = url.split(',', 1)
            content = base64.b64decode(data).decode('utf-8')
            return json.loads(content)
        except Exception:
            return None

    try:
        resp = requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code == 200:
            content_type = resp.headers.get('Content-Type', '')
            # Source maps should be JSON
            if 'json' in content_type or 'javascript' in content_type or 'text' in content_type:
                data = resp.json()
                if (isinstance(data, dict)
                        and 'version' in data
                        and isinstance(data.get('sources'), list)):
                    return data
    except Exception:
        pass
    return None


def analyze_sourcemap(
    map_data: dict,
    map_url: str,
    js_url: str,
    scan_content_func=None,
) -> dict:
    """
    Analyze a parsed source map.

    Args:
        map_data: Parsed source map JSON
        map_url: URL of the source map
        js_url: URL of the original JS file
        scan_content_func: Optional function(content, source_url) -> list to scan source content

    Returns:
        dict with: js_url, map_url, sources, source_count, secrets_in_source, file_paths
    """
    sources = map_data.get('sources', [])
    sources_content = map_data.get('sourcesContent', [])

    finding_id = hashlib.sha256(f"srcmap:{js_url}:{map_url}".encode()).hexdigest()[:16]
    result = {
        'id': finding_id,
        'js_url': js_url,
        'map_url': map_url,
        'accessible': True,
        'discovery_method': 'probe',
        'files_count': len(sources),
        'source_files': sources[:100],  # Cap at 100 for storage
        'secrets_in_source': 0,
        'secrets': [],
        'severity': 'high' if sources_content else 'medium',
        'finding_type': 'source_map_exposure',
    }

    # If sourcesContent is available, scan for secrets
    if sources_content and scan_content_func:
        for i, content in enumerate(sources_content):
            if not content or not isinstance(content, str):
                continue
            source_name = sources[i] if i < len(sources) else f"source_{i}"
            findings = scan_content_func(content, f"{map_url}:{source_name}")
            if findings:
                result['secrets_in_source'] += len(findings)
                result['secrets'].extend(findings[:20])  # Cap per source file

    return result


def discover_and_analyze_sourcemaps(
    js_files: list,
    settings: dict,
    scan_content_func=None,
) -> list:
    """
    Discover and analyze source maps for a list of JS files.

    Args:
        js_files: List of dicts with 'url', 'content', and optionally 'headers'
        settings: Project settings dict
        scan_content_func: Function to scan source content for secrets

    Returns:
        List of source map finding dicts
    """
    if not settings.get('JS_RECON_SOURCE_MAPS', True):
        return []

    # Load custom probe paths
    custom_paths = []
    custom_file = settings.get('JS_RECON_CUSTOM_SOURCEMAP_PATHS', '')
    if custom_file:
        try:
            with open(custom_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        custom_paths.append(line)
        except Exception as e:
            print(f"[!][JsRecon] Failed to load custom sourcemap paths: {e}")

    findings = []
    checked_map_urls = set()
    # Use fraction of overall timeout for each sourcemap fetch, minimum 10s
    timeout = max(settings.get('JS_RECON_TIMEOUT', 900) // 60, 10)

    for js_file in js_files:
        try:
            js_url = js_file.get('url', '')
            content = js_file.get('content', '')
            headers = js_file.get('headers', {})

            if not js_url:
                continue

            map_url = None
            discovery_method = None

            # Method 1: Check sourceMappingURL comment in JS content
            map_ref = check_sourcemap_comment(content)
            if map_ref:
                map_url = _resolve_map_url(js_url, map_ref)
                discovery_method = 'comment'

            # Method 2: Check HTTP response headers
            if not map_url:
                header_ref = check_sourcemap_header(headers)
                if header_ref:
                    map_url = _resolve_map_url(js_url, header_ref)
                    discovery_method = 'header'

            # Method 3: Probe common paths
            if not map_url:
                probe_urls = _build_probe_urls(js_url, custom_paths)
                for probe_url in probe_urls:
                    if probe_url in checked_map_urls:
                        continue
                    checked_map_urls.add(probe_url)
                    map_data = _fetch_sourcemap(probe_url, timeout=timeout)
                    if map_data:
                        map_url = probe_url
                        discovery_method = 'probe'
                        # Analyze directly since we already fetched it
                        result = analyze_sourcemap(map_data, map_url, js_url, scan_content_func)
                        result['discovery_method'] = discovery_method
                        findings.append(result)
                        break
                continue  # Skip the fetch below if we already probed

            # Fetch and analyze the discovered source map
            if map_url and map_url not in checked_map_urls:
                checked_map_urls.add(map_url)
                map_data = _fetch_sourcemap(map_url, timeout=timeout)
                if map_data:
                    result = analyze_sourcemap(map_data, map_url, js_url, scan_content_func)
                    result['discovery_method'] = discovery_method
                    findings.append(result)
                else:
                    # Source map referenced but not accessible
                    finding_id = hashlib.sha256(f"srcmap-ref:{js_url}:{map_url}".encode()).hexdigest()[:16]
                    findings.append({
                        'id': finding_id,
                        'js_url': js_url,
                        'map_url': map_url,
                        'accessible': False,
                        'discovery_method': discovery_method,
                        'files_count': 0,
                        'source_files': [],
                        'secrets_in_source': 0,
                        'secrets': [],
                        'severity': 'info',
                        'finding_type': 'source_map_reference',
                    })
        except Exception as e:
            print(f"[!][JsRecon] Error processing sourcemap for {js_file.get('url', '?')}: {e}")

    return findings
