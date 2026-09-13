"""
JS Recon Scanner -- Comprehensive JavaScript Reconnaissance

Orchestrates all 6 analysis modules (patterns, validators, sourcemap,
dependency, endpoints, framework) against JS files discovered by the
recon pipeline. Runs as a post-resource_enum phase.

Three modes:
  1. Post-recon: analyze JS URLs from combined_result['resource_enum']
  2. Standalone: crawl target domain then analyze
  3. Manual upload: analyze user-uploaded JS files
"""

import os
import re
import json
import time
import shutil
import hashlib
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import Optional

from recon.helpers.js_recon.patterns import (
    scan_js_content, scan_dev_comments, load_custom_patterns,
)
from recon.helpers.js_recon.validators import validate_secret
from recon.helpers.js_recon.sourcemap import discover_and_analyze_sourcemaps
from recon.helpers.js_recon.dependency import detect_dependency_confusion
from recon.helpers.js_recon.endpoints import extract_endpoints
from recon.helpers.js_recon.framework import (
    detect_frameworks, detect_dom_sinks, detect_dev_comments,
    load_custom_frameworks,
)
from recon.helpers.ai_signal_catalog import match_ai_sdk

try:
    from recon.main_recon_modules.ip_filter import is_url_safe_to_probe
except ImportError:  # spawned-container path where CWD is on sys.path
    from ip_filter import is_url_safe_to_probe


def _safe_redirect_get(url, *, timeout, headers, max_redirects=5):
    """GET that validates the SSRF guard on every hop (STRIDE I14).

    Follows redirects manually (allow_redirects=False) so a target-hosted JS URL
    that 3xx-redirects into cloud metadata / an internal host is refused, while
    legitimate CDN redirects to public hosts still resolve. Returns the final
    ``requests.Response`` or ``None`` if a hop is unsafe / exceeds the hop cap.
    """
    current = url
    for _hop in range(max_redirects + 1):
        if not is_url_safe_to_probe(current):
            print(f"[!][JsRecon] {current} -- blocked (SSRF guard)")
            return None
        resp = requests.get(current, timeout=timeout, headers=headers, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get('Location') or resp.headers.get('location')
            if not loc:
                return None
            current = urljoin(current, loc)
            continue
        return resp
    print(f"[!][JsRecon] {url} -- too many redirects")
    return None


# File extensions to include as JS files
_JS_EXTENSIONS = {'.js', '.mjs', '.jsx', '.ts', '.tsx'}

# Framework JS paths that Katana typically excludes but contain app code
_FRAMEWORK_JS_PATTERNS = [
    re.compile(r'/_next/static/chunks/'),
    re.compile(r'/_next/static/[a-zA-Z0-9_-]+/'),
    re.compile(r'/_nuxt/'),
    re.compile(r'\.chunk\.js'),
    re.compile(r'\.bundle\.js'),
]

# Paths to skip (third-party libraries, CDN-hosted)
_SKIP_PATTERNS = [
    re.compile(r'/node_modules/'),
    re.compile(r'jquery[.-]'),
    re.compile(r'bootstrap\.min\.js'),
    re.compile(r'lodash\.min\.js'),
    re.compile(r'react\.production\.min\.js'),
    re.compile(r'cdn\.cloudflare\.com'),
    re.compile(r'cdnjs\.cloudflare\.com'),
    re.compile(r'unpkg\.com'),
    re.compile(r'jsdelivr\.net'),
]

# Max file size for download (5MB)
_MAX_JS_FILE_SIZE = 5 * 1024 * 1024


def _parse_endpoint_validation_headers(header_lines: list) -> dict:
    """Parse user-provided endpoint validation headers."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; RedAmon-JsRecon/1.0)',
    }

    for line in header_lines:
        if not isinstance(line, str):
            continue

        line = line.strip()
        if not line or ':' not in line:
            continue

        name, value = line.split(':', 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            continue

        headers[name] = value

    return headers


def _resolve_endpoint_candidate_url(endpoint: dict) -> str:
    """Resolve an endpoint candidate to an absolute URL suitable for validation."""
    candidate = endpoint.get('full_url') or endpoint.get('path') or ''
    if not isinstance(candidate, str):
        return ''

    candidate = candidate.strip()
    if not candidate:
        return ''

    if candidate.startswith(('http://', 'https://')):
        return candidate

    source_js = endpoint.get('source_js') or ''
    source_scheme = ''
    if isinstance(source_js, str) and source_js:
        source_scheme = urlparse(source_js).scheme

    if candidate.startswith('//'):
        scheme = source_scheme if source_scheme in ('http', 'https') else 'https'
        return f'{scheme}:{candidate}'

    if not isinstance(source_js, str) or urlparse(source_js).scheme not in ('http', 'https'):
        return ''

    return urljoin(source_js, candidate)


def _url_origin(url: str) -> str:
    """Return a normalized URL origin, or an empty string when unavailable."""
    if not isinstance(url, str):
        return ''
    try:
        parsed = urlparse(url)
        if parsed.scheme in ('http', 'https') and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}".lower()
    except Exception:
        pass
    return ''


def _endpoint_probe_method(extracted_method: str) -> str:
    """Choose a non-mutating method for endpoint validation probes."""
    method = extracted_method.upper() if isinstance(extracted_method, str) else 'GET'
    if method in ('HEAD', 'OPTIONS'):
        return method
    if method == 'GET':
        return 'GET'
    return 'OPTIONS'


def _endpoint_probe_headers(endpoint: dict, resolved_url: str, custom_header_lines: list) -> dict:
    """Use custom validation headers only for same-origin endpoint probes."""
    default_headers = _parse_endpoint_validation_headers([])
    custom_headers = _parse_endpoint_validation_headers(custom_header_lines)
    source_origin = _url_origin(endpoint.get('source_js', ''))
    target_origin = _url_origin(resolved_url)
    if source_origin and source_origin == target_origin:
        return custom_headers
    return default_headers


def _is_js_url(url: str) -> bool:
    """Check if a URL points to a JavaScript file."""
    try:
        path = urlparse(url).path.lower()
        # Check extension
        for ext in _JS_EXTENSIONS:
            if path.endswith(ext):
                return True
        # Check common JS path patterns without extension
        if '/js/' in path or '/javascript/' in path:
            return True
    except Exception:
        pass
    return False


def _keep_work_dir(settings: dict) -> bool:
    """Whether the downloaded-JS dir must survive this module.

    Supply-chain recon (GROUP 5.5) runs after JS recon and needs the raw bytes
    for retire.js. JS_RECON_KEEP_WORK_DIR forces it independently (useful for
    debugging a harvest).
    """
    settings = settings or {}
    return bool(settings.get('JS_RECON_KEEP_WORK_DIR')
                or settings.get('SUPPLY_CHAIN_RECON_ENABLED'))


def _should_include_url(url: str, settings: dict) -> bool:
    """Check if a JS URL should be included based on settings."""
    url_lower = url.lower()

    # Always skip third-party libraries
    for pattern in _SKIP_PATTERNS:
        if pattern.search(url_lower):
            return False

    # Check framework JS inclusion settings
    is_framework_js = any(p.search(url_lower) for p in _FRAMEWORK_JS_PATTERNS)
    if is_framework_js:
        if '.chunk.js' in url_lower or '.bundle.js' in url_lower:
            return settings.get('JS_RECON_INCLUDE_CHUNKS', True)
        else:
            return settings.get('JS_RECON_INCLUDE_FRAMEWORK_JS', True)

    return True


def _collect_js_urls(combined_result: dict, settings: dict) -> list:
    """
    Collect JS file URLs from the recon pipeline output.

    Sources:
    - resource_enum discovered_urls (filtered to .js)
    - GAU/Wayback archived URLs (if JS_RECON_INCLUDE_ARCHIVED_JS)
    """
    js_urls = set()

    # Primary source: all discovered URLs from resource_enum
    resource_enum = combined_result.get('resource_enum', {})
    discovered_urls = resource_enum.get('discovered_urls', [])

    for url in discovered_urls:
        if isinstance(url, str) and _is_js_url(url) and _should_include_url(url, settings):
            js_urls.add(url)

    # Also check httpx probed URLs (the by_url dict keys are URLs)
    http_probe = combined_result.get('http_probe', {})
    if isinstance(http_probe, dict):
        for url in http_probe.get('by_url', {}).keys():
            if isinstance(url, str) and _is_js_url(url) and _should_include_url(url, settings):
                js_urls.add(url)

    print(f"[*][JsRecon] Collected {len(js_urls)} JS URLs from pipeline")
    return list(js_urls)


def _load_uploaded_files(settings: dict, project_id: str) -> list:
    """
    Load manually uploaded JS files from /data/js-recon-uploads/{projectId}/.

    Returns list of dicts with: url, filepath, content, headers, size
    (same format as _download_js_files output)
    """
    upload_dir = Path(f'/data/js-recon-uploads/{project_id}')
    if not upload_dir.exists():
        print(f"[-][JsRecon] Upload dir not found: {upload_dir}")
        return []

    uploaded_files = settings.get('JS_RECON_UPLOADED_FILES', [])
    if not uploaded_files:
        # Fall back to reading directory contents
        uploaded_files = [f.name for f in upload_dir.iterdir() if f.is_file()]

    if not uploaded_files:
        return []

    loaded = []
    for filename in uploaded_files:
        filepath = upload_dir / filename
        if not filepath.is_file():
            continue
        try:
            content = filepath.read_text(encoding='utf-8', errors='replace')
            if not content.strip():
                continue
            if len(content) > _MAX_JS_FILE_SIZE:
                print(f"[!][JsRecon] Uploaded file {filename} too large ({len(content)} bytes), skipping")
                continue
            loaded.append({
                'url': f'upload://{filename}',
                'filepath': str(filepath),
                'content': content,
                'headers': {},
                'size': len(content),
            })
        except Exception as e:
            print(f"[!][JsRecon] Failed to read uploaded file {filename}: {e}")

    if loaded:
        print(f"[+][JsRecon] Loaded {len(loaded)} uploaded JS files from {upload_dir}")

    return loaded


def _download_js_files(
    js_urls: list,
    work_dir: Path,
    max_files: int,
    concurrency: int,
    timeout: int,
) -> list:
    """
    Download JS files to local temp directory.

    Returns list of dicts with: url, filepath, content, headers, size
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []
    urls_to_fetch = js_urls[:max_files]

    print(f"[*][JsRecon] Downloading {len(urls_to_fetch)} JS files (max {max_files})...")

    def fetch_one(idx_url):
        idx, url = idx_url
        try:
            # STRIDE I14: JS URLs are target-derived; validate every redirect hop
            # (rather than disabling redirects, so legit CDN-hosted JS still loads).
            resp = _safe_redirect_get(
                url,
                timeout=min(timeout // 10, 30),
                headers={'User-Agent': 'Mozilla/5.0 (compatible; RedAmon/1.0)'},
            )
            if resp is None:
                return None
            if resp.status_code != 200:
                print(f"[!][JsRecon] {url} -- HTTP {resp.status_code}")
                return None

            # Check content length (pre-download check if header available)
            content_length = resp.headers.get('Content-Length')
            if content_length and int(content_length) > _MAX_JS_FILE_SIZE:
                print(f"[!][JsRecon] {url} -- too large ({int(content_length)} bytes)")
                return None

            content = resp.text
            if not content or len(content) > _MAX_JS_FILE_SIZE:
                return None

            filepath = work_dir / f"js_{idx}.js"
            filepath.write_text(content, encoding='utf-8')

            return {
                'url': url,
                'filepath': str(filepath),
                'content': content,
                'headers': dict(resp.headers),
                'size': len(content),
            }
        except Exception as e:
            print(f"[!][JsRecon] {url} -- {type(e).__name__}: {e}")
            return None

    with ThreadPoolExecutor(max_workers=min(concurrency, 20)) as executor:
        futures = {
            executor.submit(fetch_one, (i, url)): url
            for i, url in enumerate(urls_to_fetch)
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                downloaded.append(result)

    print(f"[+][JsRecon] Downloaded {len(downloaded)}/{len(urls_to_fetch)} JS files "
          f"({sum(f['size'] for f in downloaded) / 1024 / 1024:.1f} MB total)")
    return downloaded


def _run_analysis(js_files: list, settings: dict) -> dict:
    """
    Run all enabled analysis modules in parallel.

    Returns dict with all finding categories.
    """
    results = {
        'secrets': [],
        'endpoints': [],
        'source_maps': [],
        'dependencies': [],
        'dom_sinks': [],
        'frameworks': [],
        'dev_comments': [],
        'cloud_assets': [],
        'emails': [],
        'ip_addresses': [],
        'object_references': [],
        'ai_sdk_findings': [],
    }

    # Load custom extensions
    custom_patterns = None
    if settings.get('JS_RECON_CUSTOM_PATTERNS'):
        custom_patterns = load_custom_patterns(settings['JS_RECON_CUSTOM_PATTERNS'])

    custom_frameworks = None
    if settings.get('JS_RECON_CUSTOM_FRAMEWORKS'):
        custom_frameworks = load_custom_frameworks(settings['JS_RECON_CUSTOM_FRAMEWORKS'])

    min_confidence = settings.get('JS_RECON_MIN_CONFIDENCE', 'low')

    # --- Run analyzers in parallel ---
    # Manual executor management so that JS_RECON_TIMEOUT acts as a real
    # wall-clock budget: when it elapses, pending tasks are cancelled and the
    # function returns with whatever results completed. The default `with`
    # form calls shutdown(wait=True) which blocks until all worker threads
    # finish naturally, defeating the per-future timeout.
    analysis_budget = settings.get('JS_RECON_TIMEOUT', 900)
    deadline = time.monotonic() + analysis_budget
    executor = ThreadPoolExecutor(max_workers=4)
    try:
        futures = {}

        # 1. Pattern scanning (secrets, emails, IPs, UUIDs)
        if settings.get('JS_RECON_REGEX_PATTERNS', True):
            def run_patterns():
                all_findings = []
                total_filtered = {'low_entropy': 0, 'base64_blob': 0, 'binary_context': 0, 'repetitive': 0, 'url_whitelist': 0}
                for js_file in js_files:
                    try:
                        findings, file_filtered = scan_js_content(
                            js_file['content'], js_file['url'],
                            custom_patterns=custom_patterns,
                            min_confidence=min_confidence,
                        )
                        all_findings.extend(findings)
                        for k, v in file_filtered.items():
                            total_filtered[k] = total_filtered.get(k, 0) + v
                    except Exception as e:
                        print(f"[!][JsRecon] Pattern scan failed for {js_file.get('url', '?')}: {e}")
                return all_findings, total_filtered
            futures['patterns'] = executor.submit(run_patterns)

        # 2. Source map discovery
        if settings.get('JS_RECON_SOURCE_MAPS', True):
            scan_func = lambda content, url: scan_js_content(content, url, min_confidence=min_confidence)[0]
            futures['sourcemaps'] = executor.submit(
                discover_and_analyze_sourcemaps, js_files, settings, scan_func
            )

        # 3. Dependency confusion
        if settings.get('JS_RECON_DEPENDENCY_CHECK', True):
            futures['dependencies'] = executor.submit(
                detect_dependency_confusion, js_files, settings
            )

        # 4. Endpoint extraction
        if settings.get('JS_RECON_EXTRACT_ENDPOINTS', True):
            futures['endpoints'] = executor.submit(
                extract_endpoints, js_files, settings
            )

        # 5. Framework + DOM sinks + dev comments
        def run_framework_analysis():
            fw_results = {'frameworks': [], 'dom_sinks': [], 'dev_comments': []}
            for js_file in js_files:
                try:
                    content = js_file['content']
                    url = js_file['url']

                    if settings.get('JS_RECON_FRAMEWORK_DETECT', True):
                        fw_results['frameworks'].extend(
                            detect_frameworks(content, url, custom_signatures=custom_frameworks)
                        )

                    if settings.get('JS_RECON_DOM_SINKS', True):
                        fw_results['dom_sinks'].extend(
                            detect_dom_sinks(content, url)
                        )

                    if settings.get('JS_RECON_DEV_COMMENTS', True):
                        fw_results['dev_comments'].extend(
                            detect_dev_comments(content, url)
                        )
                except Exception as e:
                    print(f"[!][JsRecon] Framework analysis failed for {js_file.get('url', '?')}: {e}")
            return fw_results
        futures['framework'] = executor.submit(run_framework_analysis)

        # 6. AI SDK detection (LLM SDKs, hard-coded keys, browser-mode flag,
        #    AI-frontend product markers in shipped JS chunks). Reads the
        #    AI signal catalogue; sends no extra traffic.
        if settings.get('JS_RECON_AI_SDK_DETECTION_ENABLED', True):
            def run_ai_sdk_detection():
                all_findings = []
                for js_file in js_files:
                    try:
                        content = js_file.get('content', '')
                        url = js_file.get('url', '')
                        for finding in match_ai_sdk(content):
                            # Stamp the source URL so the mixin can build a
                            # parent file linkage. A deterministic ID lets
                            # the graph MERGE be idempotent across re-scans.
                            sig = f"{url}:{finding['category']}:{finding['sdk_name']}:{finding['byte_offset']}"
                            finding['id'] = f"ai-sdk-{hashlib.sha256(sig.encode()).hexdigest()[:16]}"
                            finding['source_url'] = url
                            all_findings.append(finding)
                    except Exception as e:
                        print(f"[!][JsRecon] AI SDK scan failed for {js_file.get('url', '?')}: {e}")
                return all_findings
            futures['ai_sdk'] = executor.submit(run_ai_sdk_detection)

        # Collect results
        for name, future in futures.items():
            try:
                remaining = max(1.0, deadline - time.monotonic())
                result = future.result(timeout=remaining)

                if name == 'patterns':
                    # Unpack tuple: (findings, filtered_stats)
                    result, filtered_stats = result
                    results['_filtered_stats'] = filtered_stats
                    # Separate secrets from info findings (emails, IPs, UUIDs)
                    for finding in result:
                        cat = finding.get('category', '')
                        fname = finding.get('name', '')
                        if cat == 'info' and fname == 'Email Address':
                            results['emails'].append({
                                'email': finding.get('matched_text', ''),
                                'category': 'unknown',
                                'source_url': finding.get('source_url', ''),
                                'context': finding.get('context', ''),
                            })
                        elif cat == 'info' and fname == 'Private IP (RFC1918)':
                            results['ip_addresses'].append({
                                'ip': finding.get('matched_text', '').strip(),
                                'type': 'private',
                                'source_url': finding.get('source_url', ''),
                                'context': finding.get('context', ''),
                            })
                        elif cat == 'info' and fname == 'UUID v4':
                            results['object_references'].append({
                                'type': 'uuid',
                                'value': finding.get('matched_text', ''),
                                'source_url': finding.get('source_url', ''),
                                'context': finding.get('context', ''),
                                'potential_idor': True,
                            })
                        elif cat == 'infrastructure':
                            if 'S3' in fname or 'GCP' in fname or 'Azure' in fname:
                                results['cloud_assets'].append({
                                    'provider': 'aws' if 'S3' in fname else ('gcp' if 'GCP' in fname else 'azure'),
                                    'type': fname,
                                    'url': finding.get('matched_text', ''),
                                    'source_url': finding.get('source_url', ''),
                                })
                            else:
                                results['secrets'].append(finding)
                        else:
                            results['secrets'].append(finding)

                elif name == 'sourcemaps':
                    results['source_maps'] = result

                elif name == 'dependencies':
                    results['dependencies'] = result

                elif name == 'endpoints':
                    results['endpoints'] = result

                elif name == 'framework':
                    results['frameworks'] = result.get('frameworks', [])
                    results['dom_sinks'] = result.get('dom_sinks', [])
                    results['dev_comments'] = result.get('dev_comments', [])

                elif name == 'ai_sdk':
                    results['ai_sdk_findings'] = result

            except Exception as e:
                print(f"[!][JsRecon] Analyzer '{name}' failed: {type(e).__name__}: {e}")
    finally:
        # cancel_futures drops tasks that have not started yet; tasks already
        # running cannot be killed (Python limitation) but the container exits
        # shortly after this function returns so the threads die with it.
        executor.shutdown(wait=False, cancel_futures=True)

    return results


def _validate_secrets(secrets: list, settings: dict) -> list:
    """
    Validate discovered secrets using service-specific validators.

    Only validates high/medium-confidence findings that have a validator_ref.
    Network validations run in parallel (capped by JS_RECON_CONCURRENCY); each
    task mutates its own secret dict in place, so no shared-state lock needed.
    """
    if not settings.get('JS_RECON_VALIDATE_KEYS', True):
        for s in secrets:
            s['validation'] = {'status': 'skipped'}
        return secrets

    validation_timeout = settings.get('JS_RECON_VALIDATION_TIMEOUT', 5)

    def _validate_one(secret: dict) -> None:
        try:
            validator_ref = secret.get('validator_ref')
            if not validator_ref:
                secret['validation'] = {'status': 'unvalidated'}
                return

            if secret.get('confidence') not in ('high', 'medium'):
                secret['validation'] = {'status': 'skipped'}
                return

            result = validate_secret(
                secret['name'],
                secret['matched_text'],
                validator_ref=validator_ref,
                timeout=validation_timeout,
            )

            err = result.get('error')
            if err == 'no_validator':
                secret['validation'] = {'status': 'unvalidated'}
            elif err == 'incomplete_credentials':
                secret['validation'] = {'status': 'incomplete', 'info': result.get('info', '')}
            elif err == 'format_only':
                secret['validation'] = {'status': 'format_validated', 'info': result.get('info', '')}
            elif err == 'format_invalid':
                secret['validation'] = {
                    'status': 'invalid',
                    'valid': False,
                    'info': result.get('info', ''),
                    'error': 'format_invalid',
                }
            elif result.get('valid'):
                secret['validation'] = {
                    'status': 'validated',
                    'valid': True,
                    'scope': result.get('scope', ''),
                    'info': result.get('info', ''),
                    'checked_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                }
            else:
                secret['validation'] = {
                    'status': 'invalid',
                    'valid': False,
                    'info': result.get('info', ''),
                    'error': result.get('error', ''),
                    'checked_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                }
        except Exception as e:
            secret['validation'] = {'status': 'error', 'error': f'{type(e).__name__}: {e}'}

    workers = max(1, min(settings.get('JS_RECON_CONCURRENCY', 10), 20))
    if secrets:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_validate_one, secrets))

    validated_count = sum(1 for s in secrets if s.get('validation', {}).get('status') == 'validated')
    invalid_count = sum(1 for s in secrets if s.get('validation', {}).get('status') == 'invalid')
    if validated_count or invalid_count:
        print(f"[+][JsRecon] Key validation: {validated_count} live, {invalid_count} invalid")

    return secrets


def _validate_extracted_endpoints(endpoints: list, settings: dict, request_func=None) -> list:
    """Validate extracted endpoints with lightweight non-following HTTP probes."""
    if not settings.get('JS_RECON_VALIDATE_ENDPOINTS', False):
        for endpoint in endpoints:
            endpoint['validation_status'] = 'unvalidated'
            endpoint['validation_error'] = 'validation_disabled'
        return endpoints

    def _clamp_int(value, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = default
        return max(minimum, min(value, maximum))

    def _configured_status_codes(value) -> set:
        default_codes = [200, 201, 204, 301, 302, 307, 308, 401, 403, 405]
        if value is None:
            value = default_codes
        elif isinstance(value, str):
            value = re.split(r'[\s,]+', value)

        codes = set()
        try:
            iterator = iter(value)
        except TypeError:
            iterator = iter([value])

        for code in iterator:
            try:
                codes.add(int(code))
            except (TypeError, ValueError):
                continue

        return codes or set(default_codes)

    accepted_statuses = _configured_status_codes(
        settings.get('JS_RECON_ENDPOINT_ACCEPT_STATUS')
    )
    custom_header_lines = settings.get('JS_RECON_ENDPOINT_CUSTOM_HEADERS', [])
    timeout = _clamp_int(settings.get('JS_RECON_VALIDATION_TIMEOUT', 5), 5, 1, 30)
    # Dedicated parallelism dial for endpoint probes, independent of the shared
    # JS_RECON_CONCURRENCY used for downloads/secret validation.
    workers = _clamp_int(settings.get('JS_RECON_ENDPOINT_CONCURRENCY', 10), 10, 1, 20)
    requester = request_func or requests.request

    def _validate_one(endpoint: dict) -> None:
        candidate = endpoint.get('full_url') or endpoint.get('path') or ''
        if isinstance(candidate, str) and candidate.strip().lower().startswith(('ws://', 'wss://')):
            endpoint['validation_status'] = 'unvalidated'
            endpoint['validation_error'] = 'unsupported_scheme'
            return

        method = endpoint.get('method') or 'GET'
        if not isinstance(method, str):
            method = 'GET'
        method = method.upper()
        if endpoint.get('type') == 'websocket' or method in ('WS', 'WSS'):
            endpoint['validation_status'] = 'unvalidated'
            endpoint['validation_error'] = 'unsupported_scheme'
            return

        resolved_url = _resolve_endpoint_candidate_url(endpoint)
        if not resolved_url:
            endpoint['validation_status'] = 'unvalidated'
            endpoint['validation_error'] = 'unresolved_url'
            return

        endpoint['resolved_url'] = resolved_url
        # STRIDE I14: endpoints come from the target's JavaScript and are
        # attacker-influenced. Refuse to probe URLs that resolve to cloud
        # metadata / loopback / RFC-1918 / link-local — otherwise the recon
        # container becomes an SSRF probe against internal services.
        if not is_url_safe_to_probe(resolved_url):
            endpoint['validation_status'] = 'unvalidated'
            endpoint['validation_error'] = 'ssrf_blocked'
            return

        probe_method = _endpoint_probe_method(method)
        headers = _endpoint_probe_headers(endpoint, resolved_url, custom_header_lines)

        try:
            response = requester(
                probe_method,
                resolved_url,
                timeout=timeout,
                headers=headers,
                allow_redirects=False,
            )
            status_code = int(getattr(response, 'status_code', 0))
            endpoint['status_code'] = status_code
            endpoint['validation_status'] = (
                'hittable' if status_code in accepted_statuses else 'not_hittable'
            )
            endpoint['validation_error'] = ''
        except requests.Timeout:
            endpoint['validation_status'] = 'not_hittable'
            endpoint['validation_error'] = 'timeout'
        except Exception as exc:
            endpoint['validation_status'] = 'not_hittable'
            endpoint['validation_error'] = type(exc).__name__

    if endpoints:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_validate_one, endpoints))

    return endpoints


def _extract_subdomains(
    endpoints: list,
    root_domain: str,
    known_subdomains: set,
) -> tuple:
    """
    Extract unique subdomains and external domains from JS-discovered endpoints.

    Returns (new_subdomains: list, external_domains: list)
    """
    new_subdomains = set()
    external_domains = {}

    for ep in endpoints:
        full_url = ep.get('full_url', '')
        if not full_url.startswith(('http://', 'https://')):
            continue

        try:
            hostname = urlparse(full_url).netloc.split(':')[0].lower()
        except Exception:
            continue

        if not hostname:
            continue

        if hostname.endswith(f'.{root_domain}') or hostname == root_domain:
            if hostname not in known_subdomains:
                new_subdomains.add(hostname)
        else:
            if hostname not in external_domains:
                external_domains[hostname] = {
                    'domain': hostname,
                    'source': 'js_recon',
                    'urls': [],
                    'times_seen': 0,
                }
            external_domains[hostname]['times_seen'] += 1
            if len(external_domains[hostname]['urls']) < 3:
                external_domains[hostname]['urls'].append(full_url)

    return list(new_subdomains), list(external_domains.values())


def _build_summary(results: dict) -> dict:
    """Build a summary dict from analysis results."""
    secrets = results.get('secrets', [])
    severity_counts = {}
    type_counts = {}
    validated = {'live': 0, 'invalid': 0, 'unvalidated': 0, 'format_validated': 0, 'incomplete': 0}

    for s in secrets:
        sev = s.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        stype = s.get('name', 'unknown')
        type_counts[stype] = type_counts.get(stype, 0) + 1
        vstatus = s.get('validation', {}).get('status', 'unvalidated')
        if vstatus == 'validated':
            validated['live'] += 1
        elif vstatus == 'invalid':
            validated['invalid'] += 1
        elif vstatus == 'format_validated':
            validated['format_validated'] += 1
        elif vstatus == 'incomplete':
            validated['incomplete'] += 1
        else:
            validated['unvalidated'] += 1

    filtered_stats = results.get('_filtered_stats', {})
    endpoint_validation = {'hittable': 0, 'not_hittable': 0, 'unvalidated': 0}

    for endpoint in results.get('endpoints', []):
        vstatus = endpoint.get('validation_status', 'unvalidated')
        endpoint_validation[vstatus] = endpoint_validation.get(vstatus, 0) + 1

    return {
        'secrets_by_severity': severity_counts,
        'secrets_by_type': type_counts,
        'validated_keys': validated,
        'endpoint_validation': endpoint_validation,
        'endpoints_hittable': endpoint_validation.get('hittable', 0),
        'false_positives_filtered': filtered_stats,
        'false_positives_filtered_total': sum(filtered_stats.values()),
        'dependency_confusion_count': len(results.get('dependencies', [])),
        'source_maps_exposed': len([sm for sm in results.get('source_maps', []) if sm.get('accessible')]),
        'endpoints_discovered': len(results.get('endpoints', [])),
        'dom_sinks_found': len(results.get('dom_sinks', [])),
        'frameworks_detected': [
            f"{f['name']}{' ' + f['version'] if f.get('version') else ''}"
            for f in results.get('frameworks', [])
        ],
        'cloud_assets_found': len(results.get('cloud_assets', [])),
        'emails_found': len(results.get('emails', [])),
        'internal_ips_found': len(results.get('ip_addresses', [])),
        'new_subdomains_discovered': len(results.get('discovered_subdomains', [])),
        'external_domains_found': len(results.get('external_domains', [])),
        'object_references_found': len(results.get('object_references', [])),
        'ai_sdk_findings_total': len(results.get('ai_sdk_findings', [])),
        'ai_sdk_findings_by_category': _count_by(results.get('ai_sdk_findings', []), 'category'),
        'ai_sdk_findings_by_severity': _count_by(results.get('ai_sdk_findings', []), 'severity'),
    }


def _count_by(items: list, key: str) -> dict:
    """Tally ``items`` by ``key`` for summary rollups."""
    out: dict = {}
    for item in items:
        v = item.get(key, 'unknown')
        out[v] = out.get(v, 0) + 1
    return out


def run_js_recon(combined_result: dict, settings: dict) -> dict:
    """
    Run JS Recon analysis on JS files from the recon pipeline.

    Mutates combined_result by adding 'js_recon' key.

    Args:
        combined_result: Pipeline results dict (must have 'resource_enum')
        settings: Project settings dict

    Returns:
        Updated combined_result
    """
    start_time = time.time()
    pid = os.getpid()
    work_dir = Path(f'/tmp/redamon/js_recon_{pid}')

    print("\n" + "=" * 60)
    print("[*][JsRecon] JS Recon Scanner -- Starting")
    print("=" * 60)

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "JsRecon",
        settings,
        keys=[
            ("JS_RECON_MAX_FILES", "File collection"),
            ("JS_RECON_CONCURRENCY", "Performance"),
            ("JS_RECON_TIMEOUT", "Performance"),
            ("JS_RECON_UPLOADED_FILES", "File collection"),
            ("JS_RECON_INCLUDE_CHUNKS", "Inclusion filters"),
            ("JS_RECON_INCLUDE_FRAMEWORK_JS", "Inclusion filters"),
            ("JS_RECON_INCLUDE_ARCHIVED_JS", "Inclusion filters"),
            ("JS_RECON_REGEX_PATTERNS", "Analysis modules"),
            ("JS_RECON_SOURCE_MAPS", "Analysis modules"),
            ("JS_RECON_DEPENDENCY_CHECK", "Analysis modules"),
            ("JS_RECON_EXTRACT_ENDPOINTS", "Analysis modules"),
            ("JS_RECON_FRAMEWORK_DETECT", "Analysis modules"),
            ("JS_RECON_DOM_SINKS", "Analysis modules"),
            ("JS_RECON_DEV_COMMENTS", "Analysis modules"),
            ("JS_RECON_MIN_CONFIDENCE", "Filtering"),
            ("JS_RECON_CUSTOM_PATTERNS", "Filtering"),
            ("JS_RECON_CUSTOM_FRAMEWORKS", "Filtering"),
            ("JS_RECON_VALIDATE_KEYS", "Validation"),
            ("JS_RECON_VALIDATION_TIMEOUT", "Validation"),
            ("JS_RECON_VALIDATE_ENDPOINTS", "Endpoint validation"),
            ("JS_RECON_ENDPOINT_ACCEPT_STATUS", "Endpoint validation"),
            ("JS_RECON_ENDPOINT_CUSTOM_HEADERS", "Endpoint validation"),
            ("JS_RECON_ENDPOINT_CONCURRENCY", "Endpoint validation"),
            ("JS_RECON_AI_SDK_DETECTION_ENABLED", "AI surface"),
        ],
    )

    try:
        # 1. Load uploaded JS files (manual uploads from UI)
        project_id = combined_result.get('metadata', {}).get('project_id', '')
        uploaded_setting = settings.get('JS_RECON_UPLOADED_FILES', [])
        print(f"[*][JsRecon] Project ID: {project_id}, uploaded files setting: {uploaded_setting}")
        uploaded_files = _load_uploaded_files(settings, project_id) if project_id else []

        # 2. Collect JS URLs from pipeline
        js_urls = _collect_js_urls(combined_result, settings)

        # 3. Download JS files from pipeline URLs
        js_files = []
        if js_urls:
            js_files = _download_js_files(
                js_urls,
                work_dir,
                max_files=settings.get('JS_RECON_MAX_FILES', 500),
                concurrency=settings.get('JS_RECON_CONCURRENCY', 10),
                timeout=settings.get('JS_RECON_TIMEOUT', 900),
            )

        # 4. Merge uploaded files with downloaded files
        js_files.extend(uploaded_files)

        if not js_files:
            print("[-][JsRecon] No JS files found (pipeline or uploaded)")
            combined_result['js_recon'] = {
                'scan_metadata': {'mode': 'post_recon', 'js_files_analyzed': 0},
                'secrets': [], 'endpoints': [], 'summary': {},
            }
            return combined_result

        print(f"[*][JsRecon] Running analysis on {len(js_files)} JS files "
              f"({len(js_files) - len(uploaded_files)} from pipeline, {len(uploaded_files)} uploaded)...")

        # 3. Run all analysis modules
        results = _run_analysis(js_files, settings)

        # 4. Log false-positive filter stats
        filtered_stats = results.get('_filtered_stats', {})
        total_filtered = sum(filtered_stats.values())
        if total_filtered:
            parts = ', '.join(f"{k}={v}" for k, v in filtered_stats.items() if v)
            print(f"[+][JsRecon] Filtered {total_filtered} false positives: {parts}")

        # 5. Validate secrets
        if results.get('secrets'):
            print(f"[*][JsRecon] Validating {len(results['secrets'])} discovered secrets...")
            results['secrets'] = _validate_secrets(results['secrets'], settings)

        # 6. Validate endpoints
        if results.get('endpoints'):
            print(f"[*][JsRecon] Validating {len(results['endpoints'])} discovered endpoints...")
            results['endpoints'] = _validate_extracted_endpoints(results['endpoints'], settings)
            hittable_count = sum(
                1 for endpoint in results['endpoints']
                if endpoint.get('validation_status') == 'hittable'
            )
            print(f"[+][JsRecon] Endpoint validation: {hittable_count} hittable")

        # 6. Subdomain feedback loop
        root_domain = combined_result.get('domain', '')
        known_subs = set()
        for sub in combined_result.get('dns', {}).get('subdomains', []):
            if isinstance(sub, dict):
                known_subs.add(sub.get('subdomain', '').lower())
            elif isinstance(sub, str):
                known_subs.add(sub.lower())

        # Collect URLs from all sources for subdomain extraction
        all_urls_for_subdomain_check = list(results.get('endpoints', []))
        # Add secrets that contain URLs
        for secret in results.get('secrets', []):
            matched = secret.get('matched_text', '')
            if matched.startswith(('http://', 'https://')):
                all_urls_for_subdomain_check.append({'full_url': matched})
        # Add source map URLs
        for sm in results.get('source_maps', []):
            if sm.get('map_url'):
                all_urls_for_subdomain_check.append({'full_url': sm['map_url']})
            if sm.get('js_url'):
                all_urls_for_subdomain_check.append({'full_url': sm['js_url']})
        # Add cloud asset URLs
        for ca in results.get('cloud_assets', []):
            if ca.get('url'):
                all_urls_for_subdomain_check.append({'full_url': ca['url']})

        new_subs, ext_domains = _extract_subdomains(
            all_urls_for_subdomain_check,
            root_domain,
            known_subs,
        )
        results['discovered_subdomains'] = new_subs
        results['external_domains'] = ext_domains

        if new_subs:
            print(f"[+][JsRecon] Discovered {len(new_subs)} new in-scope subdomains from JS")
            # dns.subdomains is a DICT in a full domain run; the old bare
            # `.append()` raised AttributeError inside run_js_recon, so the whole
            # call aborted and EVERY js_recon finding (secrets included) was
            # silently discarded whenever it found a new subdomain. Route through
            # the scope-safe dict merge instead.
            from recon.helpers.target_helpers import merge_discovered_hostnames
            merge_discovered_hostnames(
                combined_result, new_subs, source='js_recon',
                root_domain=root_domain, settings=settings,
            )

        # 6. Keep matched_text in output for copy-to-clipboard in the UI
        # The redacted_value is still used for display; matched_text holds the full secret

        # 7. Build output
        duration = time.time() - start_time
        total_size = sum(f['size'] for f in js_files)

        results['summary'] = _build_summary(results)

        combined_result['js_recon'] = {
            'scan_metadata': {
                'scan_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'mode': 'post_recon',
                'js_files_analyzed': len(js_files),
                'js_files_total_size_bytes': total_size,
                'duration_seconds': round(duration, 1),
            },
            # Where the downloaded JS lives. GROUP 5.5 (supply-chain recon)
            # hands this path to the DIRTY analyzer so retire.js can read the
            # served bytes - the only L2 source that yields a NAME **and a
            # VERSION**. Set only when the dir is preserved (see the finally
            # block); the supply-chain stage deletes it when it is done.
            'work_dir': str(work_dir) if _keep_work_dir(settings) else None,
            **results,
        }

        # Print summary
        summary = results['summary']
        secret_count = sum(summary.get('secrets_by_severity', {}).values())
        print(f"\n[+][JsRecon] === SCAN SUMMARY ===")
        print(f"[+][JsRecon] JS files analyzed: {len(js_files)}")
        print(f"[+][JsRecon] Secrets found: {secret_count}")
        if summary.get('validated_keys', {}).get('live', 0):
            print(f"[+][JsRecon] LIVE KEYS: {summary['validated_keys']['live']}")
        print(f"[+][JsRecon] Endpoints: {summary.get('endpoints_discovered', 0)}")
        print(f"[+][JsRecon] Dep. confusion: {summary.get('dependency_confusion_count', 0)}")
        print(f"[+][JsRecon] Source maps: {summary.get('source_maps_exposed', 0)}")
        print(f"[+][JsRecon] DOM sinks: {summary.get('dom_sinks_found', 0)}")
        if summary.get('frameworks_detected'):
            print(f"[+][JsRecon] Frameworks: {', '.join(summary['frameworks_detected'])}")
        print(f"[+][JsRecon] Duration: {duration:.1f}s")

    except Exception as e:
        print(f"[!][JsRecon] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        combined_result.setdefault('js_recon', {
            'scan_metadata': {'mode': 'post_recon', 'js_files_analyzed': 0, 'error': str(e)},
            'secrets': [], 'endpoints': [], 'summary': {},
        })
    finally:
        # Cleanup temp files. NOT when supply-chain recon is enabled: GROUP 5.5
        # runs after us and needs these exact bytes for the retire.js pass (it
        # must never re-fetch - that would add target traffic and an SSRF
        # surface, S4). That stage owns the cleanup from there.
        if work_dir.exists() and not _keep_work_dir(settings):
            try:
                shutil.rmtree(work_dir)
            except Exception:
                pass

    return combined_result
