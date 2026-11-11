"""
JS Recon Scanner -- Comprehensive JavaScript Reconnaissance

Orchestrates all 6 analysis modules (patterns, validators, sourcemap,
dependency, endpoints, framework) against JS files discovered by the
recon pipeline. Runs as a post-resource_enum phase.

Two input sources, read together in one run:
  1. JS URLs from combined_result['resource_enum'] (the full pipeline, or the
     graph-built result partial recon passes in)
  2. Manual upload: user-uploaded JS files
It never crawls a target on its own to find more JS files.
"""

import atexit
import ipaddress
import re
import json
import time
import shutil
import hashlib
import uuid
import requests
import urllib3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import NamedTuple, Optional

from recon.helpers import catchall
from recon.helpers.roe_scope import _is_roe_excluded

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from recon.helpers.js_recon.patterns import (
    SUPERSEDED_BY_TRUFFLEHOG, scan_js_content, scan_dev_comments, load_custom_patterns,
)
from recon.helpers.js_recon.validators import validate_secret
from recon.helpers.js_recon import trufflehog_bridge
from recon.helpers.js_recon.sourcemap import discover_and_analyze_sourcemaps, pseudo_file_base
from recon.helpers.js_recon.dependency import detect_dependency_confusion
from recon.helpers.js_recon.endpoints import extract_endpoints
from recon.helpers.js_recon.framework import (
    detect_frameworks, detect_dom_sinks, detect_dev_comments,
    load_custom_frameworks,
)
from recon.helpers.js_recon.urls import accept_js_response, is_js_content_type, is_js_url
from recon.helpers.ai_signal_catalog import match_ai_sdk

try:
    from recon.main_recon_modules.ip_filter import is_address_safe_to_scan, is_url_safe_to_probe
except ImportError:  # spawned-container path where CWD is on sys.path
    from ip_filter import is_address_safe_to_scan, is_url_safe_to_probe


# =============================================================================
# Scan-target health (recon/helpers/circuit_breaker.py HostHealth)
# =============================================================================
# JS lives on the target host and on third-party CDNs. A host another module
# (http_probe, security_checks) already found unreachable is skipped here, and
# every fetch RECORDS what it saw so a host that dies mid-phase stops costing
# ~8 guessed source-map paths + one validation probe per endpoint. Set for the
# duration of run_js_recon (one scan per process); None-safe everywhere else.
_JS_SCOPE = None


def _js_skip(url) -> bool:
    """True when `url`'s host is already known unreachable this run."""
    try:
        if _JS_SCOPE is not None:
            return _JS_SCOPE.skip_if_down(url)
        from recon.helpers import circuit_breaker as cb
        return cb.host_health.is_down(url)
    except Exception:  # noqa: BLE001 - a fault here scans as today
        return False


def _js_alive(url) -> None:
    try:
        if _JS_SCOPE is not None:
            _JS_SCOPE.host_alive(url)
        else:
            from recon.helpers import circuit_breaker as cb
            cb.host_health.record_alive(url)
    except Exception:  # noqa: BLE001
        pass


def _js_failed(url, exc) -> None:
    try:
        if _JS_SCOPE is not None:
            _JS_SCOPE.host_failed(url, exc)
        else:
            from recon.helpers import circuit_breaker as cb
            cb.host_health.record_failure(url, exc)
    except Exception:  # noqa: BLE001
        pass


def _safe_redirect_get(url, *, timeout, headers, max_redirects=5):
    """GET that validates the SSRF guard on every hop (STRIDE I14).

    Follows redirects manually (allow_redirects=False) so a target-hosted JS URL
    that 3xx-redirects into cloud metadata / an internal host is refused, while
    legitimate CDN redirects to public hosts still resolve. Returns the final
    ``requests.Response`` or ``None`` if a hop is unsafe / exceeds the hop cap.
    """
    current = url
    for _hop in range(max_redirects + 1):
        if not _download_allowed(current):
            print(f"[!][JsRecon] {current} -- blocked (SSRF guard)")
            return None
        # The target's own files: its certificate may be self-signed or from an
        # internal CA, as httpx and katana already accepted. Never the key
        # validators, which send a secret to a third party.
        resp = requests.get(current, timeout=timeout, headers=headers, allow_redirects=False,
                            verify=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get('Location') or resp.headers.get('location')
            if not loc:
                return None
            current = urljoin(current, loc)
            continue
        return resp
    print(f"[!][JsRecon] {url} -- too many redirects")
    return None


# The run's own hosts for a JS download; set for the duration of run_js_recon
# like _JS_SCOPE. Outside a run every URL takes the attacker-influenced rule.
_OWN_HOSTS = None


def _download_allowed(url) -> bool:
    """A file on one of the run's own hosts follows the pipeline's address rule,
    so an internal target's bundles are read as katana and httpx already read
    them; any other host (a CDN, a redirect hop off the run) must pass the
    attacker-influenced URL rule, which refuses every private address."""
    own = _OWN_HOSTS
    if own is not None:
        try:
            scheme = urlparse(url).scheme.lower()
        except ValueError:
            return False
        host = _host_of(url)
        if scheme in ('http', 'https') and host in own.hosts:
            return is_address_safe_to_scan(host, own.operator_hosts, own.operator_networks)
    return is_url_safe_to_probe(url)


class _OwnHosts(NamedTuple):
    hosts: frozenset = frozenset()
    operator_hosts: frozenset = frozenset()
    operator_networks: tuple = ()


def _own_hosts(combined_result: dict, settings: dict) -> _OwnHosts:
    from recon.helpers.openapi.discovery import operator_targets
    by_url = (combined_result.get('http_probe') or {}).get('by_url') or {}
    reached = [{'url': str(e.get('url') or u)} for u, e in by_url.items() if isinstance(e, dict)]
    hosts = _endpoint_probe_scope(combined_result, reached, settings).hosts
    op_hosts, op_nets = operator_targets(settings or {})
    return _OwnHosts(frozenset(hosts), frozenset(op_hosts), tuple(op_nets))


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
    # jQuery itself (core, slim, migrate, UI), not its plugins: a plugin such as
    # jquery.prettyPhoto.js is where hash-reading DOM XSS has lived, and the sink
    # detector already rates library code by whether a source is in sight.
    re.compile(r'/jquery(?:-ui|-migrate)?(?:[.-]\d+(?:\.\d+)*)?(?:\.slim)?(?:\.min)?\.js(?:[?#_~\-]|$)'),
    re.compile(r'bootstrap\.min\.js'),
    re.compile(r'lodash\.min\.js'),
    re.compile(r'react\.production\.min\.js'),
    re.compile(r'cdn\.cloudflare\.com'),
    re.compile(r'cdnjs\.cloudflare\.com'),
    re.compile(r'unpkg\.com'),
    re.compile(r'jsdelivr\.net'),
]

# Developer leftovers the secret patterns match: a localhost or internal/staging
# URL and a debug flag are reconnaissance leads, not credentials, so they are
# written as JsReconFinding dev_reference nodes instead of Secret nodes.
_DEV_REFERENCE_PATTERNS = frozenset({'Internal/Staging URL', 'Localhost with Port', 'Debug Flag'})

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


def _host_of(value) -> str:
    """Bare comparable host of a URL, ``host:port``, hostname or IP literal; '' if none."""
    if not isinstance(value, str) or not value.strip():
        return ''
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value.strip('[]')))
    except ValueError:
        pass
    try:
        host = urlparse(value if '://' in value else f'//{value}').hostname or ''
    except ValueError:
        return ''
    host = host.rstrip('.')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


class _ProbeScope(NamedTuple):
    """Where an extracted endpoint may be probed; built by ``_endpoint_probe_scope``."""
    roots: tuple = ()
    hosts: frozenset = frozenset()
    roe_excluded: tuple = ()


def _endpoint_probe_scope(combined_result: dict, js_files: list, settings: dict) -> _ProbeScope:
    """The hosts this run may send an endpoint probe to.

    A bundle names third-party hosts (analytics, social widgets, placeholder
    images) as freely as its own API, and the scan has no permission to send
    them traffic. Three rules, the last one winning:

    - ``hosts``: the run's own target list (``subdomains``, which every run
      type has already narrowed: a filtered or literal batch group to its
      listed hosts, the apex only when included, a partial run to the hosts
      its group rules admit), the IP-mode targets, and the hosts the pipeline
      JS files were fetched from.
    - ``roots``: any strict subdomain of a scanned root, so a host first seen
      in the JS is still probed, but only in a run that declares itself full
      discovery (``filtered_mode`` False). A filtered run, IP mode, a literal
      batch group and a partial run (which carries no such flag) never widen
      past their exact hosts.
    - ``roe_excluded``: a Rules-of-Engagement exclusion is never probed.
    """
    metadata = combined_result.get('metadata') or {}
    fetched_from = [
        f.get('url') for f in js_files
        if isinstance(f.get('url'), str) and urlparse(f['url']).scheme in ('http', 'https')
    ]
    hosts = {
        _host_of(h) for h in [
            *(combined_result.get('subdomains') or []),
            *(metadata.get('subdomain_filter') or []),
            *(metadata.get('expanded_ips') or []),
            *fetched_from,
        ]
    }
    hosts.discard('')

    roots = []
    if metadata.get('filtered_mode') is False:
        declared = [r for r in (combined_result.get('domains') or []) if isinstance(r, str) and r.strip()]
        roots = declared or [combined_result.get('domain') or '']
        roots = [r.strip().strip('.').lower() for r in roots if isinstance(r, str) and r.strip()]

    settings = settings or {}
    excluded = settings.get('ROE_EXCLUDED_HOSTS') if settings.get('ROE_ENABLED') else None
    return _ProbeScope(
        roots=tuple(roots),
        hosts=frozenset(hosts),
        roe_excluded=tuple(e for e in (excluded or []) if isinstance(e, str) and e.strip()),
    )


def _in_probe_scope(url: str, scope: _ProbeScope) -> bool:
    host = _host_of(url)
    if not host:
        return False
    if scope.roe_excluded and _is_roe_excluded(host, list(scope.roe_excluded)):
        return False
    return host in scope.hosts or any(host.endswith(f'.{r}') for r in scope.roots)


class _FirstParty(NamedTuple):
    """The hosts whose JS is the target's own code; see ``_first_party_scope``."""
    roots: tuple = ()
    hosts: frozenset = frozenset()


def _first_party_scope(combined_result: dict) -> _FirstParty:
    """The target's own hosts: the run's roots and target list. Unlike the
    endpoint probe scope this never counts a host just because a JS file was
    fetched from it, since the page loads third-party scripts too.

    A group's root here is its org (registrable domain), not its scan root: a
    script on www.example.com is the target's own code in a run scoped to
    *.api.example.com, though that run never scans www. A legacy file (no
    scope_mode) and a partial run keep their scan roots.
    """
    from recon.helpers.recon_scope import recon_scope
    metadata = combined_result.get('metadata') or {}
    declared = [r for r in (combined_result.get('domains') or []) if isinstance(r, str) and r.strip()]
    roots = declared or [combined_result.get('domain') or '']
    group = recon_scope(combined_result)
    if not declared and group.mode and not group.ip_mode and group.org_domain:
        roots = [group.org_domain]
    roots = [
        r.strip().strip('.').lower() for r in roots
        if isinstance(r, str) and r.strip() and not r.startswith('ip-targets.')
    ]
    hosts = {
        _host_of(h) for h in [
            *(combined_result.get('subdomains') or []),
            *(metadata.get('subdomain_filter') or []),
            *(metadata.get('expanded_ips') or []),
        ]
    }
    hosts.discard('')
    return _FirstParty(roots=tuple(roots), hosts=frozenset(hosts))


# Generic CDN and object-storage hostnames. A target often serves its OWN
# bundles from one (a CloudFront distribution, an S3 bucket), so a script there
# is not a third party's; only a vendor-branded host is.
_GENERIC_ASSET_HOST_SUFFIXES = (
    '.cloudfront.net', '.azureedge.net', '.azurefd.net', '.akamaized.net', '.akamaihd.net',
    '.b-cdn.net', '.fastly.net', '.fastlylb.net', '.amazonaws.com', '.googleapis.com',
    '.blob.core.windows.net', '.r2.dev', '.pages.dev', '.workers.dev', '.vercel.app',
    '.netlify.app', '.web.app', '.firebaseapp.com', '.kxcdn.com', '.cdn77.org',
    '.digitaloceanspaces.com', '.cdn.cloudflare.net',
)


def _is_third_party_url(url: str, first_party: _FirstParty) -> bool:
    """True only when the URL's host is known, outside the target and not a
    generic CDN/storage host. A run with no roots and no hosts cannot tell, so
    nothing is called third-party."""
    if not first_party.roots and not first_party.hosts:
        return False
    host = _host_of(url)
    if not host or urlparse(url).scheme not in ('http', 'https'):
        return False
    if host in first_party.hosts or host.endswith(_GENERIC_ASSET_HOST_SUFFIXES):
        return False
    return not any(host == r or host.endswith(f'.{r}') for r in first_party.roots)


def _downgrade_third_party_findings(results: dict, combined_result: dict) -> None:
    """A DOM sink in, or a source map of, a script served from a vendor's host
    (an analytics or marketing loader the page embeds) is that vendor's code,
    not the target's: keep it visible, at info. A sink with a user-controlled
    source next to it keeps its severity, since the target ships that code to
    its users either way."""
    first_party = _first_party_scope(combined_result)
    for sink in results.get('dom_sinks') or []:
        if not _is_third_party_url(sink.get('source_url', ''), first_party):
            continue
        sink['third_party'] = True
        if sink.get('user_source'):
            sink['confidence'] = 'low'
            continue
        if sink.get('vendor'):
            continue
        sink['vendor'] = True
        sink['severity'] = 'info'
        sink['confidence'] = 'low'
        sink['description'] = re.sub(r' \([^()]*\)$', '', sink.get('description', '')) + ' (in a third-party script)'
    for source_map in results.get('source_maps') or []:
        if _is_third_party_url(source_map.get('js_url', ''), first_party):
            source_map['third_party'] = True
            # Secret hits in the map's own source text are worth a look
            # whoever serves it.
            if not source_map.get('secrets_in_source'):
                source_map['severity'] = 'info'


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
    return is_js_url(url)


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
    - resource_enum js_urls: every in-scope JS URL the crawlers saw, before
      their exclude list (which hides /static/ and /_next/static bundles)
    - resource_enum discovered_urls (filtered to JS)
    - http_probe URLs
    - GAU/Wayback archived URLs (if JS_RECON_INCLUDE_ARCHIVED_JS)

    A Rules-of-Engagement exclusion is dropped whichever source named it.
    """
    js_urls = set()

    resource_enum = combined_result.get('resource_enum', {})
    discovered_urls = list(resource_enum.get('js_urls') or []) + list(resource_enum.get('discovered_urls') or [])

    for url in discovered_urls:
        if isinstance(url, str) and _is_js_url(url) and _should_include_url(url, settings):
            js_urls.add(url)

    # httpx probed URLs; one it saw answer with a JavaScript type counts
    # whatever its name.
    http_probe = combined_result.get('http_probe', {})
    if isinstance(http_probe, dict):
        for url, info in (http_probe.get('by_url') or {}).items():
            served_js = isinstance(info, dict) and is_js_content_type(info.get('content_type'))
            if isinstance(url, str) and (served_js or _is_js_url(url)) and _should_include_url(url, settings):
                js_urls.add(url)

    settings = settings or {}
    # archived_urls holds what only a web archive reported; http_probe's own
    # answer for a URL means the live site still serves it.
    if not settings.get('JS_RECON_INCLUDE_ARCHIVED_JS', True):
        archived = set(resource_enum.get('archived_urls') or [])
        probed = set((http_probe.get('by_url') or {}) if isinstance(http_probe, dict) else ())
        dropped = {u for u in js_urls if u in archived and u not in probed}
        if dropped:
            print(f"[-][JsRecon] Left out {len(dropped)} JS URL(s) seen only in web archives "
                  f"(JS_RECON_INCLUDE_ARCHIVED_JS off)")
            js_urls -= dropped

    excluded = settings.get('ROE_EXCLUDED_HOSTS') if settings.get('ROE_ENABLED') else None
    excluded = [e for e in (excluded or []) if isinstance(e, str) and e.strip()]
    if excluded:
        kept = {u for u in js_urls if not _is_roe_excluded(_host_of(u), excluded)}
        if len(kept) < len(js_urls):
            print(f"[-][JsRecon] Dropped {len(js_urls) - len(kept)} JS URL(s) on RoE-excluded hosts")
        js_urls = kept

    print(f"[*][JsRecon] Collected {len(js_urls)} JS URLs from pipeline")
    return sorted(js_urls)


def _default_max_files() -> int:
    from recon.project_settings import DEFAULT_SETTINGS
    return int(DEFAULT_SETTINGS['JS_RECON_MAX_FILES'])


# Which of a host's files to fetch first when the budget cannot cover them all.
# Library and bundler-runtime files are public code; the app's own entry
# points and page chunks are where its endpoints and keys live.
_VENDOR_JS_HINT = re.compile(
    r'(?:^|[/._~-])(?:vendors?|framework|polyfills?|runtime|webpack|react(?:-dom)?|jquery'
    r'|lodash|moment|core-js|libs?)(?:[/._~-]|$)|/node_modules/', re.IGNORECASE)
_FIRST_PARTY_JS_HINT = re.compile(r'(?:^|/)(?:main|app|index|_app)(?:[._~-]|$)|/pages/|/chunks/',
                                  re.IGNORECASE)


def _js_fetch_rank(url: str) -> tuple:
    path = urlparse(url).path
    if _VENDOR_JS_HINT.search(path):
        rank = 2
    elif _FIRST_PARTY_JS_HINT.search(path):
        rank = 0
    else:
        rank = 1
    return rank, url


def _select_js_urls(js_urls: list, max_files: int) -> tuple:
    """``(selected, by_host)``: at most ``max_files`` URLs, taken round-robin
    by host so one large site cannot take the whole budget, in a fixed order
    (hosts sorted; within a host, first-party bundles first, vendor files
    last). ``by_host`` maps each ``host:port`` to its candidates / selected /
    cut counts."""
    from recon.helpers import circuit_breaker as cb
    queues: dict = {}
    for url in sorted(set(u for u in js_urls if isinstance(u, str))):
        queues.setdefault(cb.host_key(url) or url, []).append(url)
    for files in queues.values():
        files.sort(key=_js_fetch_rank)

    budget = max(0, int(max_files))
    selected = []
    taken = {host: 0 for host in queues}
    hosts = sorted(queues)
    while len(selected) < budget:
        progressed = False
        for host in hosts:
            if len(selected) >= budget:
                break
            if taken[host] < len(queues[host]):
                selected.append(queues[host][taken[host]])
                taken[host] += 1
                progressed = True
        if not progressed:
            break
    by_host = {
        host: {'candidates': len(files), 'selected': taken[host], 'cut': len(files) - taken[host]}
        for host, files in queues.items()
    }
    return selected, by_host


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
    unreachable: Optional[list] = None,
) -> list:
    """
    Download JS files to local temp directory.

    Returns list of dicts with: url, filepath, content, headers, size.
    `unreachable` collects the URLs never fetched: a host already known down,
    or a request that raised.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []
    urls_to_fetch = js_urls[:max_files]
    if unreachable is None:
        unreachable = []

    print(f"[*][JsRecon] Downloading {len(urls_to_fetch)} JS files (max {max_files})...")

    def fetch_one(idx_url):
        idx, url = idx_url
        if _js_skip(url):
            unreachable.append(url)
            return None
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
            _js_alive(url)
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
            accepted, why = accept_js_response(url, resp.headers.get('Content-Type'), content)
            if not accepted:
                print(f"[-][JsRecon] {url} -- not a JS file ({why})")
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
            _js_failed(url, e)
            unreachable.append(url)
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
        'dev_references': [],
        'ai_sdk_findings': [],
    }
    # Files an analyzer produced nothing for, so the prune keeps their hosts'
    # findings. A list: workers still running after a timeout may append.
    unanalyzed: list = []

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
    started = time.monotonic()
    deadline = started + analysis_budget
    trufflehog_on = bool(settings.get('JS_RECON_TRUFFLEHOG_ENABLED', False))
    executor = ThreadPoolExecutor(max_workers=5 if trufflehog_on else 4)
    try:
        # Stage 1: discover and fetch the source maps. A map's first-party
        # sources come back as pseudo-files, which every analyzer in stage 2
        # reads like a downloaded file, so a key or an endpoint in the original
        # code becomes a finding of its own.
        served_files = js_files
        pseudo_files = []
        if settings.get('JS_RECON_SOURCE_MAPS', True):
            recovered, not_checked = [], []
            future = executor.submit(
                discover_and_analyze_sourcemaps, served_files, settings,
                pseudo_files=recovered, skipped=not_checked,
                deadline=started + analysis_budget * _SOURCE_MAP_BUDGET_SHARE,
            )
            try:
                results['source_maps'] = future.result(timeout=max(1.0, deadline - time.monotonic()))
                pseudo_files, cut = _cap_pseudo_files(recovered)
                unanalyzed.extend(f['url'] for f in cut)
            except Exception as e:
                unanalyzed.extend(f.get('url') for f in served_files)
                print(f"[!][JsRecon] Analyzer 'sourcemaps' failed: {type(e).__name__}: {e}")
            if not_checked:
                print(f"[!][JsRecon] Source-map budget spent: {len(not_checked)} JS file(s) not checked for a map")
                unanalyzed.extend(not_checked)
            if pseudo_files:
                print(f"[*][JsRecon] {len(pseudo_files)} first-party source(s) recovered from source maps")
        js_files = served_files + pseudo_files
        results['_source_map_files'] = len(pseudo_files)

        # Stage 2: every analyzer on the downloaded files and the pseudo-files.
        futures = {}

        # TruffleHog first: its container is the slowest analyzer. It is
        # collected on its own running-time budget, after the others, never on
        # the wall-clock deadline, which a recon pause would spend.
        trufflehog_future = None
        if trufflehog_on:
            verify = bool(settings.get('JS_RECON_VALIDATE_KEYS', True))
            th_budget = min(_TRUFFLEHOG_MAX_BUDGET_S, max(15.0, deadline - time.monotonic() - 10))
            print(f"[*][JsRecon] TruffleHog: scanning {len(js_files)} file(s), "
                  f"verification {'on' if verify else 'off'}, budget {int(th_budget)}s")
            trufflehog_future = executor.submit(
                trufflehog_bridge.run, list(js_files), verify=verify,
                concurrency=settings.get('JS_RECON_CONCURRENCY', 10),
                validation_timeout=settings.get('JS_RECON_VALIDATION_TIMEOUT', 5),
                budget_s=th_budget,
            )

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
                        unanalyzed.append(js_file.get('url'))
                        print(f"[!][JsRecon] Pattern scan failed for {js_file.get('url', '?')}: {e}")
                return all_findings, total_filtered
            futures['patterns'] = executor.submit(run_patterns)

        # 3. Dependency confusion
        npm_unchecked: list = []
        if settings.get('JS_RECON_DEPENDENCY_CHECK', True):
            futures['dependencies'] = executor.submit(
                detect_dependency_confusion, js_files, settings, unchecked=npm_unchecked
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
                    unanalyzed.append(js_file.get('url'))
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
                        unanalyzed.append(js_file.get('url'))
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
                        elif fname in _DEV_REFERENCE_PATTERNS:
                            results['dev_references'].append({
                                'id': finding.get('id', ''),
                                'type': fname,
                                'value': finding.get('matched_text', ''),
                                'source_url': finding.get('source_url', ''),
                                'line_number': finding.get('line_number'),
                                'context': finding.get('context', ''),
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

                elif name == 'dependencies':
                    results['dependencies'] = result
                    if npm_unchecked:
                        # A package the registry did not answer for is not
                        # "gone": its importing hosts keep their findings. One
                        # only an upload or the custom-package list names has
                        # no host to match, so the whole source is kept.
                        importers = [[u for u in urls if isinstance(u, str)
                                      and u.startswith(('http://', 'https://'))]
                                     for urls in npm_unchecked]
                        _note_unchecked("npm registry did not answer",
                                        [u for urls in importers for u in urls]
                                        if all(importers) else None)

                elif name == 'endpoints':
                    results['endpoints'] = result
                    results['_endpoint_extraction_files'] = len(js_files)

                elif name == 'framework':
                    results['frameworks'] = result.get('frameworks', [])
                    results['dom_sinks'] = result.get('dom_sinks', [])
                    results['dev_comments'] = result.get('dev_comments', [])

                elif name == 'ai_sdk':
                    results['ai_sdk_findings'] = result

            except Exception as e:
                unanalyzed.extend(f.get('url') for f in js_files)
                print(f"[!][JsRecon] Analyzer '{name}' failed: {type(e).__name__}: {e}")

        if trufflehog_future is not None:
            try:
                th_run = trufflehog_future.result()
            except Exception as e:  # noqa: BLE001 - run() never raises; a bug must not cost the scan
                th_run = trufflehog_bridge.ThRun('failed', type(e).__name__,
                                                 'redamon-trufflehog-net' if verify else 'none')
            results['_trufflehog'] = _merge_trufflehog(results, th_run, js_files, settings)
    finally:
        # cancel_futures drops tasks that have not started yet; tasks already
        # running cannot be killed (Python limitation) but the container exits
        # shortly after this function returns so the threads die with it.
        executor.shutdown(wait=False, cancel_futures=True)

    if pseudo_files:
        results['frameworks'] = _one_framework_per_map(results['frameworks'], pseudo_files)
    _count_source_map_secrets(results)
    results['_unanalyzed_urls'] = unanalyzed
    return results


#: TruffleHog's running-time budget never exceeds this, whatever JS_RECON_TIMEOUT.
_TRUFFLEHOG_MAX_BUDGET_S = 600.0
#: Verification counts as degraded when at least this share of at least
#: _TRUFFLEHOG_DEGRADED_MIN results errored: the provider checks, not the keys.
_TRUFFLEHOG_DEGRADED_SHARE = 0.5
_TRUFFLEHOG_DEGRADED_MIN = 5


def _trufflehog_keep(settings: dict, verify: bool) -> Optional[set]:
    """The TruffleHog-only results to keep (JS_RECON_TRUFFLEHOG_RESULTS). Empty
    or unreadable means all three; without verification every result is
    unverified, so the filter does not apply."""
    raw = settings.get('JS_RECON_TRUFFLEHOG_RESULTS') or []
    if isinstance(raw, str):
        raw = [p.strip() for p in raw.split(',')]
    keep = {str(v).strip().lower() for v in raw if str(v).strip()} & set(trufflehog_bridge.RESULT_CLASSES)
    keep = keep or set(trufflehog_bridge.RESULT_CLASSES)
    if not verify:
        if keep != set(trufflehog_bridge.RESULT_CLASSES):
            print("[*][JsRecon] TruffleHog result filter ignored: key validation is off, "
                  "so no result is verified")
        return None
    return keep


def _unconfirmed_superseded(secret: dict) -> bool:
    """A hit of a rule TruffleHog supersedes that TruffleHog did not match."""
    return (secret.get('name') in SUPERSEDED_BY_TRUFFLEHOG
            and secret.get('detection_method', 'regex') == 'regex'
            and not any(str(a).startswith('TruffleHog:') for a in secret.get('alternate_names') or []))


def _merge_trufflehog(results: dict, th_run, js_files: list, settings: dict) -> dict:
    """Merge one TruffleHog run into results['secrets'] and return its outcome
    record (scan_metadata.trufflehog). A failure is logged and recorded; it
    never drops or prunes a regex finding."""
    verify = bool(settings.get('JS_RECON_VALIDATE_KEYS', True))
    keep = _trufflehog_keep(settings, verify)
    secrets, stats = trufflehog_bridge.merge(
        results.get('secrets') or [], th_run.results, th_run.manifest, verify=verify, keep=keep)
    superseded = 0
    if th_run.status == 'ran':
        # Only a complete run can confirm: a failed or missing TruffleHog
        # leaves these rules reporting as they always did.
        kept = [s for s in secrets if not _unconfirmed_superseded(s)]
        superseded = len(secrets) - len(kept)
        secrets = kept
    results['secrets'] = secrets

    verification = 'off'
    if verify and th_run.status == 'ran':
        verification = 'ok'
        checked = stats.merged + stats.new + stats.filtered
        degraded = (checked >= _TRUFFLEHOG_DEGRADED_MIN
                    and stats.verify_errors >= _TRUFFLEHOG_DEGRADED_SHARE * checked)
        try:
            from recon.helpers import circuit_breaker as cb
            breaker = cb.get_breaker('secretval:trufflehog', label='SecretValidator',
                                     threshold=cb.INTERNAL_THRESHOLD)
            if degraded:
                breaker.record(cb.Outcome.TRANSIENT, 'verification degraded')
            else:
                breaker.record(cb.Outcome.OK)
        except Exception:  # noqa: BLE001 - bookkeeping never fails the scan
            pass
        if degraded:
            verification = 'degraded'
            print(f"[!][JsRecon] TruffleHog verification degraded: {stats.verify_errors}/{checked} checks errored")

    network = 'bridge' if th_run.network != 'none' else 'none'
    excluded = len(trufflehog_bridge.TRUFFLEHOG_EXCLUDED_DETECTORS)
    if th_run.status == 'skipped' and th_run.reason == 'image_missing':
        print(f"[-][JsRecon] TruffleHog image {trufflehog_bridge.TRUFFLEHOG_IMAGE} not found: "
              f"run ./redamon.sh update")
    elif th_run.status not in ('ran', 'stopped', 'skipped'):
        print(f"[!][JsRecon] TruffleHog {th_run.status}: {th_run.reason}")
        for line in th_run.stderr_tail if th_run.status == 'failed' else ():
            print(f"[!][JsRecon] TruffleHog stderr: {line}")
    if th_run.bad_lines:
        print(f"[!][JsRecon] TruffleHog: {th_run.bad_lines} output line(s) unreadable")
    if superseded:
        print(f"[*][JsRecon] TruffleHog: dropped {superseded} hit(s) it did not confirm, of rules it "
              f"supersedes ({', '.join(sorted(SUPERSEDED_BY_TRUFFLEHOG))})")
    print(f"[+][JsRecon] TruffleHog: {stats.results} results, {stats.merged} merged, {stats.new} new, "
          f"{stats.validated} validated, {stats.filtered} filtered, network={network}, "
          f"{excluded} detectors excluded, {th_run.duration_s}s")

    return {
        'status': th_run.status,
        'reason': th_run.reason,
        'network': network,
        'results': stats.results,
        'merged': stats.merged,
        'new': stats.new,
        'validated': stats.validated,
        'filtered': stats.filtered,
        'verify_errors': stats.verify_errors,
        'verification': verification,
        'superseded_dropped': superseded,
        'duration_s': th_run.duration_s,
        # The files TruffleHog was given, for the coverage reason on a failure.
        '_input_urls': [f.get('url') for f in js_files if (f.get('content') or '').strip()],
    }


# Stage 1 (source-map discovery) may use this share of JS_RECON_TIMEOUT, so a
# site with thousands of scripts still leaves the analyzers their time.
_SOURCE_MAP_BUDGET_SHARE = 0.5
# All recovered sources together, in characters: the analyzers read each one
# in full, and a monorepo's map can embed a whole codebase.
_PSEUDO_FILES_MAX_TOTAL_CHARS = 50 * 1024 * 1024


def _cap_pseudo_files(recovered: list) -> tuple:
    """``(kept, cut)``: the pseudo-files in a fixed order, up to the total size cap."""
    kept, cut, total = [], [], 0
    for f in sorted(recovered, key=lambda f: f['url']):
        if total + f['size'] > _PSEUDO_FILES_MAX_TOTAL_CHARS:
            cut.append(f)
            continue
        kept.append(f)
        total += f['size']
    if cut:
        print(f"[!][JsRecon] Source-map size cap: {len(cut)} recovered source(s) not analyzed")
    return kept, cut


def _one_framework_per_map(frameworks: list, pseudo_files: list) -> list:
    """Original sources import their framework in nearly every file
    (`next/router`, `@angular/core`), which a bundle does once. From a map's
    sources a framework is kept once per map, and not at all when a served
    file already showed it."""
    map_of = {f['url']: f.get('map_url') for f in pseudo_files}
    served = {fw.get('name') for fw in frameworks if fw.get('source_url') not in map_of}
    kept, seen = [], set()
    for fw in frameworks:
        source_map = map_of.get(fw.get('source_url'))
        if source_map is None:
            kept.append(fw)
            continue
        key = (fw.get('name'), source_map)
        if fw.get('name') in served or key in seen:
            continue
        seen.add(key)
        kept.append(fw)
    return kept


def _count_source_map_secrets(results: dict) -> None:
    """A map's secrets_in_source: the Secrets found in its own sources."""
    secret_urls = [s.get('source_url') or '' for s in results.get('secrets') or []]
    for source_map in results.get('source_maps') or []:
        if not source_map.get('accessible'):
            continue
        prefix = pseudo_file_base(source_map.get('map_url', ''), source_map.get('js_url', '')) + '#'
        source_map['secrets_in_source'] = sum(1 for u in secret_urls if u.startswith(prefix))


#: Validators that run even on a key TruffleHog verified: an open Firebase
#: database read and a key's Google API restriction are findings of their own.
_ALWAYS_RUN_VALIDATORS = frozenset({'validate_firebase', 'validate_google_maps'})


def _validate_secrets(secrets: list, settings: dict) -> list:
    """
    Validate discovered secrets using service-specific validators.

    Only validates high/medium-confidence findings that have a validator_ref.
    Network validations run in parallel (capped by JS_RECON_CONCURRENCY); each
    task mutates its own secret dict in place, so no shared-state lock needed.

    What TruffleHog said about a key (`validation['trufflehog']`, set by the
    merge) survives. A TruffleHog-only finding keeps the status TruffleHog
    gave it. A key TruffleHog verified costs no provider call, except the
    Firebase and Google Maps checks, which test what the key opens, not
    whether it lives. TruffleHog only ever promotes a key to `validated`: its
    "not verified" is no verdict (rule V1), so `rejected` stays ours alone.
    """
    th_of = {id(s): (s.get('validation') or {}).get('trufflehog') for s in secrets}

    def _with_th(secret: dict, validation: dict) -> dict:
        th = th_of.get(id(secret))
        return {**validation, 'trufflehog': th} if th else validation

    if not settings.get('JS_RECON_VALIDATE_KEYS', True):
        for s in secrets:
            s['validation'] = _with_th(s, {'status': 'skipped'})
        return secrets

    validation_timeout = settings.get('JS_RECON_VALIDATION_TIMEOUT', 5)

    def _validate_one(secret: dict, th: Optional[dict]) -> None:
        verified = bool(th and th.get('verified'))
        validator_ref = secret.get('validator_ref')
        if verified and validator_ref not in _ALWAYS_RUN_VALIDATORS:
            secret['validation'] = {'status': 'validated', 'valid': True, 'checked_by': 'trufflehog'}
            return
        _run_validator(secret)
        if verified and secret['validation'].get('status') != 'validated':
            secret['validation'] = {
                'status': 'validated', 'valid': True, 'checked_by': 'trufflehog',
                'info': secret['validation'].get('info', ''),
                'validator_status': secret['validation'].get('status'),
            }

    def _run_validator(secret: dict) -> None:
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
            state = result.get('state')
            checked_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            if err == 'no_validator':
                secret['validation'] = {'status': 'unvalidated'}
            elif err == 'incomplete_credentials':
                secret['validation'] = {'status': 'incomplete', 'info': result.get('info', '')}
            elif err == 'format_only':
                secret['validation'] = {'status': 'format_validated', 'info': result.get('info', '')}
            elif state == 'format_invalid':
                secret['validation'] = {
                    'status': 'format_invalid',
                    'valid': False,
                    'info': result.get('info', ''),
                    'error': 'format_invalid',
                }
            elif state == 'valid':
                secret['validation'] = {
                    'status': 'validated',
                    'valid': True,
                    'scope': result.get('scope', ''),
                    'info': result.get('info', ''),
                    'checked_at': checked_at,
                }
            else:
                # 'rejected' is the provider's verdict; anything else (a
                # timeout, a 429 or 5xx, a breaker skip, a 403) is 'unknown',
                # never a dead key.
                secret['validation'] = {
                    'status': 'rejected' if state == 'rejected' else 'unknown',
                    'valid': False,
                    'info': result.get('info', ''),
                    'error': result.get('error', ''),
                    'checked_at': checked_at,
                }
        except Exception as e:
            secret['validation'] = {'status': 'unknown', 'error': f'{type(e).__name__}: {e}'}

    # One provider call per distinct key: the same key in a bundle and in the
    # source map's original file is one credential.
    same_key: dict = {}
    for secret in secrets:
        if secret.get('detection_method') == 'trufflehog':
            continue
        key = (secret.get('name'), secret.get('matched_text'), secret.get('validator_ref'),
               secret.get('confidence'))
        same_key.setdefault(key, []).append(secret)

    def _validate_group(group: list) -> None:
        infos = [th_of.get(id(s)) for s in group if th_of.get(id(s))]
        th = next((i for i in infos if i.get('verified')), infos[0] if infos else None)
        _validate_one(group[0], th)
        for other in group[1:]:
            other['validation'] = dict(group[0].get('validation') or {})
        for s in group:
            s['validation'] = _with_th(s, s['validation'])

    workers = max(1, min(settings.get('JS_RECON_CONCURRENCY', 10), 20))
    if secrets:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_validate_group, same_key.values()))

    def _count(status):
        return sum(1 for s in secrets if s.get('validation', {}).get('status') == status)
    live, rejected, unknown = _count('validated'), _count('rejected'), _count('unknown')
    if live or rejected or unknown:
        print(f"[+][JsRecon] Key validation: {live} live, {rejected} rejected, {unknown} could not be checked")

    return secrets


def _validate_extracted_endpoints(endpoints: list, settings: dict, scope: _ProbeScope, request_func=None) -> list:
    """Validate extracted endpoints with lightweight non-following HTTP probes.

    ``scope`` comes from ``_endpoint_probe_scope``. Required, so a caller
    cannot forget it and probe every host a bundle mentions.
    """
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
    # One cache per probe method: a HEAD or OPTIONS control says nothing
    # about a GET hit.
    controls = {m: catchall.ControlCache() for m in ('GET', 'HEAD', 'OPTIONS')}

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
        if not _in_probe_scope(resolved_url, scope):
            endpoint['validation_status'] = 'unvalidated'
            endpoint['validation_error'] = 'out_of_scope'
            return
        if _js_skip(resolved_url):
            endpoint['validation_status'] = 'unvalidated'
            endpoint['validation_error'] = 'host_unreachable'
            return
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
                verify=False,
            )
            status_code = int(getattr(response, 'status_code', 0))
            _js_alive(resolved_url)  # any response is life
            endpoint['status_code'] = status_code
            endpoint['validation_status'] = (
                'hittable' if status_code in accepted_statuses else 'not_hittable'
            )
            endpoint['validation_error'] = ''
        except requests.Timeout as exc:
            _js_failed(resolved_url, exc)
            endpoint['validation_status'] = 'not_hittable'
            endpoint['validation_error'] = 'timeout'
            return
        except Exception as exc:
            _js_failed(resolved_url, exc)
            endpoint['validation_status'] = 'not_hittable'
            endpoint['validation_error'] = type(exc).__name__
            return

        if endpoint['validation_status'] != 'hittable':
            return

        def fetch_control(url):
            try:
                answer = requester(probe_method, url, timeout=timeout, headers=headers,
                                   allow_redirects=False, verify=False)
            except Exception as exc:
                _js_failed(url, exc)
                raise
            _js_alive(url)
            return answer

        # A server that answers every path alike (an SPA shell) makes any
        # status "hittable": a path that cannot exist decides. A catch-all
        # host is still alive (recorded above); only its endpoint is dropped.
        verdict = catchall.control_probe(
            fetch_control, resolved_url, response, url_guard=is_url_safe_to_probe,
            cache=controls[probe_method], roe_excluded=scope.roe_excluded,
            note_module='js_recon')
        if verdict.catch_all:
            endpoint['validation_status'] = 'catch_all'

    if endpoints:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_validate_one, endpoints))

    sent = sum(cache.requests for cache in controls.values())
    if sent:
        caught = sum(1 for e in endpoints if e.get('validation_status') == 'catch_all')
        print(f"[*][JsRecon] Catch-all control probes sent: {sent} ({caught} endpoint(s) answered "
              f"like a made-up path)")
    return endpoints


def _extract_subdomains(
    endpoints: list,
    root_domain,
    known_subdomains: set,
    in_scope_hosts: frozenset = frozenset(),
    first_party_roots: tuple = (),
) -> tuple:
    """
    Extract unique subdomains and external domains from JS-discovered endpoints.

    ``root_domain`` is one root, or a list: a partial run over a Domain batch
    covers several, and a host under any of them is in scope, not external.
    ``in_scope_hosts`` are the target's own hosts outside every root: an IP-mode
    run's root is the synthetic ``ip-targets.<id>``, so without them the
    scanned IPs were reported as external domains of themselves.
    ``first_party_roots`` are the group's org(s): a host under one but outside
    every scanned root is the target's own (no third party), yet not this
    group's to scan, so it lands in neither list.

    Returns (new_subdomains: list, external_domains: list)
    """
    roots = [root_domain] if isinstance(root_domain, str) else list(root_domain or [])
    roots = [r.lower() for r in roots if r]
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

        if any(hostname == root or hostname.endswith(f'.{root}') for root in roots):
            if hostname not in known_subdomains:
                new_subdomains.add(hostname)
        elif hostname in in_scope_hosts:
            continue
        elif any(hostname == r or hostname.endswith(f'.{r}') for r in first_party_roots):
            continue
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
    validated = {'live': 0, 'rejected': 0, 'unknown': 0, 'format_invalid': 0,
                 'format_validated': 0, 'incomplete': 0, 'unvalidated': 0, 'skipped': 0}

    for s in secrets:
        sev = s.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        stype = s.get('name', 'unknown')
        type_counts[stype] = type_counts.get(stype, 0) + 1
        vstatus = s.get('validation', {}).get('status', 'unvalidated')
        key = 'live' if vstatus == 'validated' else vstatus
        validated[key if key in validated else 'unvalidated'] += 1

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
        'dev_references_found': len(results.get('dev_references', [])),
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


def _has_live_urls(combined_result: dict) -> bool:
    """http_probe got an answer from at least one URL: a status under 500, as
    subdomain_takeover._collect_alive_urls counts a URL live."""
    http_probe = combined_result.get('http_probe') or {}
    for url, info in (http_probe.get('by_url') or {}).items():
        if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
            continue
        status = info.get('status_code') if isinstance(info, dict) else None
        if status is None or (isinstance(status, int) and status < 500):
            return True
    return any(isinstance(h, dict) and h.get('live_urls')
               for h in (http_probe.get('by_host') or {}).values())


def _note_unchecked(reason: str, urls=None) -> None:
    """Tell the end-of-run prune what this run did not re-check. Never raises.

    run_js_recon catches its own errors, so main's _note_phase_error never sees
    them, and the prune reads "not reported this run" as "gone". With `urls`,
    only their hosts keep their js_recon findings, so a capped run still prunes
    the hosts it analyzed; with none, the whole source is kept.
    """
    try:
        from recon.helpers import circuit_breaker as cb
        if urls is None:
            cb.note_degraded('js_recon', sources=['js_recon'], reason=reason)
            return
        hosts = {cb.host_key(u) for u in urls
                 if isinstance(u, str) and u.startswith(('http://', 'https://'))}
        hosts.discard('')
        if hosts:
            cb.note_degraded('js_recon', hosts=sorted(hosts), host_source='js_recon',
                             source_only_hosts=True, reason=reason)
    except Exception:  # noqa: BLE001 - coverage bookkeeping never fails the scan
        pass


# Below this many files an app can genuinely call no endpoint from its JS.
_TOOL_MISS_MIN_FILES = 20


def _note_endpoint_miss(files: int) -> None:
    """Many files read and not one endpoint out: more likely the extractor
    missing this app's call style than an app that calls nothing. Said in the
    log and the report's Coverage Limitations; no prune effect."""
    print(f"[!][JsRecon] Endpoint extraction found 0 endpoints in {files} files: the app's request "
          f"style is probably one the extractor does not read (TOOL MISS)")
    try:
        from recon.helpers import circuit_breaker as cb
        cb.note_degraded('js_recon', entries=[
            {"source": "js_endpoint_extraction", "reason": f"0 endpoints from {files} files", "skipped": 0}])
    except Exception:  # noqa: BLE001 - coverage bookkeeping never fails the scan
        pass


def _note_file_cap(skipped: int, max_files: int) -> None:
    """The cut as a coverage note, so the report's Coverage Limitations block
    names it. No prune effect: _note_unchecked keeps the cut hosts."""
    try:
        from recon.helpers import circuit_breaker as cb
        print(f"[!][JsRecon] JS_RECON_MAX_FILES ({max_files}) cut {skipped} JS file(s)")
        cb.note_degraded('js_recon', entries=[
            {"source": "js_recon_file_cap", "reason": f"file cap ({max_files})", "skipped": skipped}])
    except Exception:  # noqa: BLE001 - coverage bookkeeping never fails the scan
        pass


# Every list the graph writer turns into a finding node; endpoints are assets.
_COVERAGE_FINDING_KEYS = (
    'secrets', 'dependencies', 'source_maps', 'dom_sinks', 'dev_comments', 'frameworks',
    'emails', 'ip_addresses', 'object_references', 'dev_references', 'cloud_assets',
    'ai_sdk_findings',
)


def _considered_base_urls(combined_result: dict, settings: dict, js_urls) -> set:
    """The web hosts this run looked at, as base_url_key: each one http_probe
    got a live answer from (the _has_live_urls test), each one it was handed a
    page on, and each one serving a JS candidate. A host the Rules of
    Engagement exclude was never looked at."""
    from recon.helpers.coverage_stamps import base_url_key
    urls = list(js_urls or [])
    http_probe = combined_result.get('http_probe') or {}
    for url, info in ((http_probe.get('by_url') or {}) if isinstance(http_probe, dict) else {}).items():
        status = info.get('status_code') if isinstance(info, dict) else None
        if status is None or (isinstance(status, int) and status < 500):
            urls.append(url)
    resource_enum = combined_result.get('resource_enum') or {}
    if isinstance(resource_enum, dict):
        urls += list(resource_enum.get('discovered_urls') or []) + list(resource_enum.get('js_urls') or [])

    settings = settings or {}
    excluded = settings.get('ROE_EXCLUDED_HOSTS') if settings.get('ROE_ENABLED') else None
    excluded = [e for e in (excluded or []) if isinstance(e, str) and e.strip()]
    keys = set()
    for url in urls:
        if not isinstance(url, str) or (excluded and _is_roe_excluded(_host_of(url), excluded)):
            continue
        key = base_url_key(url)
        if key:
            keys.add(key)
    return keys


def _js_coverage(combined_result: dict, settings: dict, at: str, *, js_urls=(), selected=(),
                 downloaded=(), unreachable=(), unanalyzed=(), results=None, error=None,
                 trufflehog_reason=None, trufflehog_urls=()) -> dict:
    """``{"at", "hosts": {base_url_key: row}}``, one row per considered host.

    A host with no JS candidate, or whose candidates all turned out not to be
    JavaScript, is ``no_input``. One whose files were all lost to an
    unreachable host or a failed analyzer is ``failed``; one that lost some,
    or had files cut by JS_RECON_MAX_FILES, is ``partial``, with the reasons.
    A fatal error fails every host, since none of its findings reached output.

    ``trufflehog_reason`` (a TruffleHog run that did not complete) is added to
    the reason of each host whose files TruffleHog was given
    (``trufflehog_urls``), without changing its status: js_recon's own
    analysis of those files is complete.
    """
    from collections import Counter
    from recon.helpers.coverage_stamps import base_url_key, coverage_row

    def by_host(urls):
        counts = Counter()
        for url in urls:
            key = base_url_key(url)
            if key:
                counts[key] += 1
        return counts

    candidates = by_host(set(js_urls))
    chosen = by_host(selected)
    read = by_host(f.get('url') for f in downloaded)
    lost = by_host(unreachable)
    dropped = by_host(u for u in unanalyzed if u)
    found = by_host(
        f.get('source_url') or f.get('js_url')
        for key in _COVERAGE_FINDING_KEYS for f in (results or {}).get(key) or [] if isinstance(f, dict)
    )

    trufflehog_hosts = by_host(trufflehog_urls) if trufflehog_reason else {}

    hosts = {}
    for key in sorted(_considered_base_urls(combined_result, settings, js_urls)):
        if error:
            hosts[key] = coverage_row('failed', reason=error)
            continue
        reasons = [reason for reason, hit in (
            ('file cap', candidates[key] > chosen[key]),
            ('host unreachable', lost[key]),
            ('analyzer failed or timed out', dropped[key]),
        ) if hit]
        if not candidates[key] or (not read[key] and not reasons):
            status = 'no_input'
        elif not reasons:
            status = 'complete'
        elif not read[key] and 'file cap' not in reasons:
            status = 'failed'
        else:
            status = 'partial'
        if trufflehog_hosts.get(key):
            reasons.append(trufflehog_reason)
        hosts[key] = coverage_row(status, read[key], found[key], ', '.join(reasons))
    return {'at': at, 'hosts': hosts}


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
    # /tmp/redamon is shared by every concurrent scan, and the recon process is
    # pid 1 in every container, so the directory is unique to this run: the
    # supply-chain stage reads it (via 'work_dir' below) as this run's JS only.
    work_dir = Path(f'/tmp/redamon/js_recon_{uuid.uuid4().hex[:12]}')

    global _JS_SCOPE, _OWN_HOSTS
    from recon.helpers import circuit_breaker as _cb
    _JS_SCOPE = _cb.scope(("npm",), label="JsRecon", unit="package(s)")
    try:
        _OWN_HOSTS = _own_hosts(combined_result, settings)
    except Exception as e:  # noqa: BLE001 - every download then takes the strict rule
        print(f"[!][JsRecon] Run hosts unavailable ({type(e).__name__}); private hosts are not fetched")
        _OWN_HOSTS = None

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
            ("JS_RECON_TRUFFLEHOG_ENABLED", "Validation"),
            ("JS_RECON_TRUFFLEHOG_RESULTS", "Validation"),
            ("JS_RECON_VALIDATE_ENDPOINTS", "Endpoint validation"),
            ("JS_RECON_ENDPOINT_ACCEPT_STATUS", "Endpoint validation"),
            ("JS_RECON_ENDPOINT_CUSTOM_HEADERS", "Endpoint validation"),
            ("JS_RECON_ENDPOINT_CONCURRENCY", "Endpoint validation"),
            ("JS_RECON_AI_SDK_DETECTION_ENABLED", "AI surface"),
        ],
    )

    from recon.helpers.coverage_stamps import run_started_at
    coverage_at = run_started_at()
    js_urls, selected_urls, downloaded, unreachable = [], [], [], []
    try:
        # 1. Load uploaded JS files (manual uploads from UI)
        project_id = combined_result.get('metadata', {}).get('project_id', '')
        uploaded_setting = settings.get('JS_RECON_UPLOADED_FILES', [])
        print(f"[*][JsRecon] Project ID: {project_id}, uploaded files setting: {uploaded_setting}")
        uploaded_files = _load_uploaded_files(settings, project_id) if project_id else []

        # 2. Collect JS URLs from pipeline
        js_urls = _collect_js_urls(combined_result, settings)

        # 3. Download JS files from pipeline URLs, the budget shared by host
        max_files = settings.get('JS_RECON_MAX_FILES') or _default_max_files()
        selected_urls, by_host = _select_js_urls(js_urls, max_files)
        file_budget = {
            'max_files': max_files,
            'candidates': len(set(js_urls)),
            'selected': len(selected_urls),
            'cut': len(set(js_urls)) - len(selected_urls),
            'by_host': by_host,
        }
        js_files = []
        if selected_urls:
            js_files = _download_js_files(
                selected_urls,
                work_dir,
                max_files=max_files,
                concurrency=settings.get('JS_RECON_CONCURRENCY', 10),
                timeout=settings.get('JS_RECON_TIMEOUT', 900),
                unreachable=unreachable,
            )
        downloaded = list(js_files)
        if file_budget['cut']:
            chosen = set(selected_urls)
            _note_unchecked("file cap", [u for u in js_urls if u not in chosen])
            _note_file_cap(file_budget['cut'], max_files)
        # Uploads do not count: they re-check none of the pipeline's files. A
        # run with no live target at all had nothing to re-check, so no gap.
        if not js_files and _has_live_urls(combined_result):
            _note_unchecked("no JS input")

        # 4. Merge uploaded files with downloaded files
        js_files.extend(uploaded_files)

        if not js_files:
            print("[-][JsRecon] No JS files found (pipeline or uploaded)")
            combined_result['js_recon'] = {
                'scan_metadata': {
                    'mode': 'post_recon', 'js_files_analyzed': 0, 'file_budget': file_budget,
                    'coverage': _js_coverage(combined_result, settings, coverage_at, js_urls=js_urls,
                                             selected=selected_urls, unreachable=unreachable),
                },
                'secrets': [], 'endpoints': [], 'summary': {},
            }
            return combined_result

        print(f"[*][JsRecon] Running analysis on {len(js_files)} JS files "
              f"({len(js_files) - len(uploaded_files)} from pipeline, {len(uploaded_files)} uploaded)...")

        # 3. Run all analysis modules
        results = _run_analysis(js_files, settings)
        trufflehog = results.pop('_trufflehog', None)
        trufflehog_urls = trufflehog.pop('_input_urls', []) if trufflehog else []
        trufflehog_reason = (f"trufflehog {trufflehog['status']}: {trufflehog['reason']}"
                             if trufflehog and trufflehog['status'] not in ('ran', 'stopped') else None)
        if trufflehog and trufflehog['status'] != 'ran':
            # The graph writer keeps this run's earlier TruffleHog-only findings
            # of these files alive: a failed run must not prune them.
            trufflehog['analyzed_urls'] = trufflehog_urls
        source_map_files = results.pop('_source_map_files', 0)
        extracted_from = results.pop('_endpoint_extraction_files', 0)
        endpoint_miss = extracted_from >= _TOOL_MISS_MIN_FILES and not results.get('endpoints')
        if endpoint_miss:
            _note_endpoint_miss(extracted_from)
        unanalyzed = results.pop('_unanalyzed_urls', None)
        if unanalyzed:
            _note_unchecked("analyzer failed or timed out", unanalyzed)
        _downgrade_third_party_findings(results, combined_result)

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
            results['endpoints'] = _validate_extracted_endpoints(
                results['endpoints'], settings, _endpoint_probe_scope(combined_result, js_files, settings),
            )
            hittable_count = sum(
                1 for endpoint in results['endpoints']
                if endpoint.get('validation_status') == 'hittable'
            )
            print(f"[+][JsRecon] Endpoint validation: {hittable_count} hittable")
            out_of_scope = sum(
                1 for endpoint in results['endpoints']
                if endpoint.get('validation_error') == 'out_of_scope'
            )
            if out_of_scope:
                print(f"[*][JsRecon] Endpoint validation: {out_of_scope} out-of-scope endpoints not probed")

        # 6. Subdomain feedback loop. A partial run over a Domain batch carries
        # every root it covers; a host under any of them is in scope.
        root_domain = combined_result.get('domain', '')
        scope_roots = [r for r in (combined_result.get('domains') or []) if r] or root_domain
        known_subs = set()
        for sub in combined_result.get('dns', {}).get('subdomains', []):
            if isinstance(sub, dict):
                known_subs.add(sub.get('subdomain', '').lower())
            elif isinstance(sub, str):
                known_subs.add(sub.lower())

        # Collect URLs from all sources for subdomain extraction
        all_urls_for_subdomain_check = list(results.get('endpoints', []))
        # Add secrets and developer references that contain URLs
        for secret in results.get('secrets', []):
            matched = secret.get('matched_text', '')
            if matched.startswith(('http://', 'https://')):
                all_urls_for_subdomain_check.append({'full_url': matched})
        for ref in results.get('dev_references', []):
            value = ref.get('value', '')
            if value.startswith(('http://', 'https://')):
                all_urls_for_subdomain_check.append({'full_url': value})
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

        first_party = _first_party_scope(combined_result)
        new_subs, ext_domains = _extract_subdomains(
            all_urls_for_subdomain_check,
            scope_roots,
            known_subs,
            first_party.hosts,
            first_party.roots,
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
            # The same cap as the certificate paths: every name costs a blocking
            # DNS lookup here and then a scan target, and a JS bundle can name
            # any number of hosts.
            merge_discovered_hostnames(
                combined_result, new_subs, source='js_recon',
                root_domain=scope_roots, settings=settings,
                max_injected=(settings or {}).get('TLSX_MAX_INJECTED_HOSTNAMES', 200),
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
                # First-party sources recovered from source maps, analyzed too.
                'source_map_files_analyzed': source_map_files,
                'endpoint_extraction_miss': endpoint_miss,
                'js_files_total_size_bytes': total_size,
                'duration_seconds': round(duration, 1),
                'file_budget': file_budget,
                'coverage': _js_coverage(
                    combined_result, settings, coverage_at, js_urls=js_urls, selected=selected_urls,
                    downloaded=downloaded, unreachable=unreachable, unanalyzed=unanalyzed or (),
                    results=results, trufflehog_reason=trufflehog_reason,
                    trufflehog_urls=trufflehog_urls),
                **({'trufflehog': trufflehog} if trufflehog else {}),
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
        _note_unchecked(f"fatal: {type(e).__name__}")
        combined_result.setdefault('js_recon', {
            'scan_metadata': {
                'mode': 'post_recon', 'js_files_analyzed': 0, 'error': str(e),
                'coverage': _js_coverage(combined_result, settings, coverage_at, js_urls=js_urls,
                                         error=f"fatal: {type(e).__name__}"),
            },
            'secrets': [], 'endpoints': [], 'summary': {},
        })
    finally:
        # Hosts skipped as unreachable: js_recon findings carry a host field
        # (source_url/base_url), so the prune keeps a dead host's findings.
        try:
            _JS_SCOPE.finish("js_recon", host_source="js_recon",
                             payload=combined_result.get("js_recon"))
        except Exception:  # noqa: BLE001
            pass
        _JS_SCOPE = None
        _OWN_HOSTS = None
        # Cleanup temp files. NOT when supply-chain recon is enabled: GROUP 5.5
        # runs after us and needs these exact bytes for the retire.js pass (it
        # must never re-fetch - that would add target traffic and an SSRF
        # surface, S4). That stage owns the cleanup from there.
        if work_dir.exists() and not _keep_work_dir(settings):
            try:
                shutil.rmtree(work_dir)
            except Exception:
                pass
        elif _keep_work_dir(settings) and not (settings or {}).get('JS_RECON_KEEP_WORK_DIR'):
            # Only some callers run the supply-chain stage after us (IP mode and
            # partial supply-chain do; domain mode and partial JS recon do not),
            # so a dir kept for it goes when the process ends, whoever used it.
            atexit.register(shutil.rmtree, str(work_dir), ignore_errors=True)

    return combined_result
