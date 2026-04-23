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
from urllib.parse import urlparse
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
            resp = requests.get(
                url,
                timeout=min(timeout // 10, 30),
                headers={'User-Agent': 'Mozilla/5.0 (compatible; RedAmon/1.0)'},
                allow_redirects=True,
            )
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
    with ThreadPoolExecutor(max_workers=4) as executor:
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

        # Collect results
        for name, future in futures.items():
            try:
                result = future.result(timeout=settings.get('JS_RECON_TIMEOUT', 900))

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

            except Exception as e:
                print(f"[!][JsRecon] Analyzer '{name}' failed: {e}")

    return results


def _validate_secrets(secrets: list, settings: dict) -> list:
    """
    Validate discovered secrets using service-specific validators.

    Only validates high-confidence findings that have a validator_ref.
    """
    if not settings.get('JS_RECON_VALIDATE_KEYS', True):
        for s in secrets:
            s['validation'] = {'status': 'skipped'}
        return secrets

    validation_timeout = settings.get('JS_RECON_VALIDATION_TIMEOUT', 5)
    validated_count = 0
    invalid_count = 0

    for secret in secrets:
        validator_ref = secret.get('validator_ref')
        if not validator_ref:
            secret['validation'] = {'status': 'unvalidated'}
            continue

        # Only validate high/medium confidence findings
        if secret.get('confidence') not in ('high', 'medium'):
            secret['validation'] = {'status': 'skipped'}
            continue

        result = validate_secret(
            secret['name'],
            secret['matched_text'],
            validator_ref=validator_ref,
            timeout=validation_timeout,
        )

        if result.get('error') == 'no_validator':
            secret['validation'] = {'status': 'unvalidated'}
        elif result.get('error') == 'incomplete_credentials':
            secret['validation'] = {'status': 'incomplete', 'info': result.get('info', '')}
        elif result.get('error') == 'format_only':
            secret['validation'] = {'status': 'format_validated', 'info': result.get('info', '')}
        elif result.get('error') == 'format_invalid':
            invalid_count += 1
            secret['validation'] = {
                'status': 'invalid',
                'valid': False,
                'info': result.get('info', ''),
                'error': 'format_invalid',
            }
        elif result.get('valid'):
            validated_count += 1
            secret['validation'] = {
                'status': 'validated',
                'valid': True,
                'scope': result.get('scope', ''),
                'info': result.get('info', ''),
                'checked_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            }
        else:
            invalid_count += 1
            secret['validation'] = {
                'status': 'invalid',
                'valid': False,
                'info': result.get('info', ''),
                'error': result.get('error', ''),
                'checked_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            }

    if validated_count or invalid_count:
        print(f"[+][JsRecon] Key validation: {validated_count} live, {invalid_count} invalid")

    return secrets


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

    return {
        'secrets_by_severity': severity_counts,
        'secrets_by_type': type_counts,
        'validated_keys': validated,
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
    }


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
            # Merge back into combined_result (Uncover pattern)
            dns_data = combined_result.setdefault('dns', {})
            existing_subs = dns_data.setdefault('subdomains', [])
            for sub in new_subs:
                existing_subs.append({
                    'subdomain': sub,
                    'source': 'js_recon',
                })

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
        # Cleanup temp files
        if work_dir.exists():
            try:
                shutil.rmtree(work_dir)
            except Exception:
                pass

    return combined_result


def run_js_recon_isolated(combined_result: dict, settings: dict) -> dict:
    """
    Thread-safe isolated version -- shallow-copies combined_result.

    Returns only the js_recon payload dict.
    """
    snapshot = dict(combined_result)
    run_js_recon(snapshot, settings)
    return snapshot.get('js_recon', {})
