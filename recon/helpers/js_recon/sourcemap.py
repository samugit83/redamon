"""
JS Recon Source Map Discovery + Analysis

Discovers .map source map files for JS files and analyzes them
to extract original source code, file paths, and embedded secrets.
"""

import re
import json
import hashlib
import threading
import time
import uuid
import requests
import urllib3
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextvars import ContextVar
from urllib.parse import urljoin, urlparse
from typing import Callable, Optional

try:
    from recon.main_recon_modules.ip_filter import is_url_safe_to_probe
except ImportError:  # spawned-container path where CWD is on sys.path
    from ip_filter import is_url_safe_to_probe
from recon.helpers.js_recon.hop_guard import (
    NOT_ADMITTED, OUT_OF_SCOPE, ROE_EXCLUDED, TOO_MANY_REDIRECTS, UNSAFE,
    admit_any, fetch_hop_by_hop, url_host,
)
from recon.helpers.user_agent import DEFAULT_BROWSER_UA

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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


_REFERENCE_WORTH_REPORTING = frozenset({'http_401', 'http_403'})
_REFERENCE_WORTH_REPORTING_ELSEWHERE = frozenset({UNSAFE, 'unreachable', OUT_OF_SCOPE})
_REFUSED_BY_HOP_GUARD = frozenset({UNSAFE, ROE_EXCLUDED, OUT_OF_SCOPE, NOT_ADMITTED})

# The hop rules of one discover_and_analyze_sourcemaps call (RoE settings, the
# map scope, the caller's admit) for every _fetch_sourcemap it makes, so that
# fetch keeps its (url, timeout, outcome) call shape.
_HOP_RULES: ContextVar[Optional[dict]] = ContextVar('sourcemap_hop_rules', default=None)

# Object storage refuses a key it does not hold with 403 AccessDenied when the
# caller may not list the bucket (S3, and CloudFront in front of it with OAC),
# so on such an answer a 403 says nothing about whether the map exists.
_STORAGE_DENIAL_BODY = re.compile(r'<Code>\s*AccessDenied\s*</Code>', re.IGNORECASE)


def _storage_denial(resp) -> bool:
    headers = {str(k).lower(): str(v) for k, v in (getattr(resp, 'headers', None) or {}).items()}
    if 'amazons3' in headers.get('server', '').lower() or any(k.startswith('x-amz-') for k in headers):
        return True
    try:
        body = resp.text or ''
    except Exception:  # noqa: BLE001
        body = ''
    return bool(_STORAGE_DENIAL_BODY.search(body[:4096]))


def _roe_excluded(url: str, settings: dict) -> bool:
    """True when the URL's host is one the Rules of Engagement exclude."""
    settings = settings or {}
    excluded = settings.get('ROE_EXCLUDED_HOSTS') if settings.get('ROE_ENABLED') else None
    excluded = [e for e in (excluded or []) if isinstance(e, str) and e.strip()]
    if not excluded or not isinstance(url, str) or url.startswith('data:'):
        return False
    from recon.helpers.roe_scope import _is_roe_excluded
    return _is_roe_excluded(urlparse(url).hostname or '', excluded)


def _send_map_hop(method: str, url: str, *, timeout, headers, allow_redirects):
    """One hop of a map fetch (fetch_hop_by_hop's sender). The target's own
    file: a self-signed or internal-CA certificate is accepted, as by the
    bundle download."""
    if method == 'HEAD':
        return requests.head(url, timeout=timeout, headers=headers, allow_redirects=allow_redirects,
                             verify=False)
    return requests.get(url, timeout=timeout, headers=headers, allow_redirects=allow_redirects,
                        verify=False)


def _missing_key_control(map_url: str, timeout: int) -> str:
    """Fetch a sibling that cannot exist (``<map_url>.<nonce>``): ``'denied'``
    when it is refused alike, ``'passed'`` when it is not, ``'failed'`` when no
    answer came (an error is no evidence either way). Same guard, user agent
    and timeout as the map fetch itself."""
    control = f"{map_url}.{uuid.uuid4().hex[:12]}"
    if not is_url_safe_to_probe(control):
        return 'failed'
    try:
        resp = requests.get(control, timeout=timeout, headers={'User-Agent': DEFAULT_BROWSER_UA},
                            allow_redirects=False, verify=False)
    except requests.RequestException:
        return 'failed'
    return 'denied' if resp.status_code == 403 else 'passed'


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


def _is_valid_sourcemap(data) -> bool:
    """A Source Map v3: `version` 3 with `sources` + string `mappings`, or an
    index map with `sections`. A JSON API catch-all (`{"error": ...}`) or a
    manifest that merely lists `sources` is not one."""
    if not isinstance(data, dict) or str(data.get('version')) != '3':
        return False
    if isinstance(data.get('sections'), list):
        return True
    return isinstance(data.get('sources'), list) and isinstance(data.get('mappings'), str)


# Anti-JSON-hijacking prefix some servers put in front of JSON bodies.
_XSSI_PREFIX = re.compile(r"^\s*\)\]\}'?[^\n]*\n?")


def _parse_sourcemap_body(text: str, outcome: dict) -> Optional[dict]:
    text = text.lstrip('\ufeff')
    if text.lstrip().startswith('<'):
        outcome['reason'] = 'html'
        return None
    try:
        data = json.loads(_XSSI_PREFIX.sub('', text, count=1))
    except ValueError:
        outcome['reason'] = 'not_json'
        return None
    if not _is_valid_sourcemap(data):
        outcome['reason'] = 'invalid_schema'
        return None
    outcome['reason'] = 'ok'
    return data


def _fetch_sourcemap(url: str, timeout: int = 10, outcome: Optional[dict] = None) -> Optional[dict]:
    """Fetch and parse a source map JSON file. Uses HEAD to skip guaranteed misses.

    `outcome`, when given, receives `reason` (and `status` for an HTTP
    answer): ok, html, not_json, invalid_schema, not_found, unreachable,
    http_<status>, or the hop guard's refusal (unsafe, roe_excluded,
    out_of_scope, not_admitted). A single-page app answers every unknown path,
    `.map` included, with its HTML shell and a 200, so a 200 alone proves
    nothing: the body must parse as a v3 source map.

    The URL comes from target JS and may redirect anywhere, so HEAD and GET
    each follow it hop by hop (STRIDE I14, R-14): every hop passes the SSRF
    guard, and inside discovery the RoE, the map scope and the caller's admit.
    """
    outcome = outcome if outcome is not None else {}
    if url.startswith('data:'):
        # Inline base64-encoded source map
        try:
            import base64
            _, data = url.split(',', 1)
            content = base64.b64decode(data).decode('utf-8')
        except Exception:
            outcome['reason'] = 'not_json'
            return None
        return _parse_sourcemap_body(content, outcome)

    headers = {'User-Agent': DEFAULT_BROWSER_UA}
    rules = _HOP_RULES.get() or {}

    def fetch(method: str, wait: float):
        refusal: dict = {}
        resp = fetch_hop_by_hop(method, url, timeout=wait, headers=headers, url_guard=is_url_safe_to_probe,
                                refusal=refusal, send=_send_map_hop, **rules)
        if resp is None:
            # A redirect loop reads as requests' own TooManyRedirects did.
            reason = refusal.get('reason')
            outcome['reason'] = 'unreachable' if reason == TOO_MANY_REDIRECTS else reason
        return resp

    try:
        head = fetch('HEAD', min(timeout, 5))
        if head is None:
            return None
        # Skip definite misses without paying for a body download. Other statuses
        # (200, 403, 405, 5xx) fall through to GET — some servers misreport HEAD.
        if head.status_code in (404, 410):
            outcome.update(reason='not_found', status=head.status_code)
            return None
    except requests.RequestException:
        # Connection-level failure on HEAD: GET would fail too.
        outcome['reason'] = 'unreachable'
        return None

    try:
        resp = fetch('GET', timeout)
        if resp is None:
            return None
    except requests.RequestException:
        outcome['reason'] = 'unreachable'
        return None
    outcome['status'] = resp.status_code
    if resp.status_code in (404, 410):
        outcome['reason'] = 'not_found'
        return None
    if resp.status_code != 200:
        outcome['reason'] = f'http_{resp.status_code}'
        if resp.status_code == 403:
            outcome['storage_denial'] = _storage_denial(resp)
        return None
    # Any content type: S3 and CDNs serve maps as octet-stream, and the body
    # check rejects an HTML page whatever it is labelled. The bytes are decoded
    # directly, so a multi-MB map skips charset sniffing.
    try:
        raw = resp.content
        text = raw.decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else (resp.text or '')
        return _parse_sourcemap_body(text, outcome)
    except Exception:
        outcome['reason'] = 'not_json'
        return None


# Package-manager and bundler-runtime sources: library code the target ships
# but did not write. Matched after the `webpack:///`-style scheme is removed.
_VENDOR_SOURCE_RE = re.compile(
    r'(?:^|/)(?:node_modules|bower_components|jspm_packages)/'
    # Unanchored: Next.js prefixes its own runtime (`webpack://_N_E/webpack/runtime/...`).
    r'|(?:^|/)webpack/(?:bootstrap|runtime|universalModuleDefinition)'
    r'|\(webpack\)|^external[ "]|^~/',
    re.IGNORECASE,
)
_SOURCE_SCHEME = re.compile(r'^[a-z][a-z0-9+.-]*:/*', re.IGNORECASE)


def _is_vendor_source(source: str) -> bool:
    path = _SOURCE_SCHEME.sub('', source or '').lstrip('./')
    return bool(_VENDOR_SOURCE_RE.search(path)) or bool(_VENDOR_SOURCE_RE.search(source or ''))


def _map_sources(map_data: dict) -> tuple:
    """(sources, sourcesContent) of a flat map, or of every inline section of
    an index map."""
    # A null source keeps its slot (as ""): sourcesContent pairs by index.
    def flat(m: dict) -> tuple:
        s = [x if isinstance(x, str) else '' for x in (m.get('sources') or [])]
        c = list(m.get('sourcesContent') or [])
        return s, c + [None] * (len(s) - len(c))

    if isinstance(map_data.get('sections'), list):
        sources, contents = [], []
        for section in map_data['sections']:
            inner = (section or {}).get('map') if isinstance(section, dict) else None
            if isinstance(inner, dict):
                s, c = flat(inner)
                sources.extend(s)
                contents.extend(c[:len(s)])
        return sources, contents
    return flat(map_data)


def analyze_sourcemap(
    map_data: dict,
    map_url: str,
    js_url: str,
) -> dict:
    """
    Analyze a parsed source map.

    Args:
        map_data: Parsed source map JSON
        map_url: URL of the source map
        js_url: URL of the original JS file

    The map's own sources are not scanned here: they become pseudo-files
    (sourcemap_pseudo_files) that every js_recon detector reads, so a key or
    an endpoint in them is a Secret or an Endpoint of its own. The exposure
    finding itself is therefore modest: low when it embeds first-party source
    text, info for first-party file paths only, low when every source is a
    library (node_modules, the bundler runtime). ``secrets_in_source`` is
    filled by js_recon from the Secrets found in the pseudo-files.

    Returns:
        dict with: js_url, map_url, sources, source_count, secrets_in_source, file_paths
    """
    sources, sources_content = _map_sources(map_data)
    first_party = [i for i, s in enumerate(sources) if s and not _is_vendor_source(s)]
    first_party_content = any(
        isinstance(sources_content[i], str) and sources_content[i].strip()
        for i in first_party if i < len(sources_content)
    )
    if first_party_content:
        severity = 'low'
    elif first_party:
        severity = 'info'
    else:
        severity = 'low'

    finding_id = hashlib.sha256(f"srcmap:{js_url}:{map_url}".encode()).hexdigest()[:16]
    result = {
        'id': finding_id,
        'js_url': js_url,
        'map_url': map_url,
        'accessible': True,
        'discovery_method': 'probe',
        'files_count': len([x for x in sources if x]),
        'first_party_files': len(first_party),
        'has_sources_content': first_party_content,
        'source_files': [sources[i] for i in first_party][:100] or [x for x in sources if x][:100],
        'secrets_in_source': 0,
        'severity': severity,
        'finding_type': 'source_map_exposure',
    }
    return result


# One recovered source is analyzed as one file; a larger one is a bundled
# blob, not hand-written code.
PSEUDO_FILE_MAX_CHARS = 2 * 1024 * 1024


def _source_label(source: str) -> str:
    """`webpack:///./src/config.ts` -> `src/config.ts`: the path a person reads."""
    path = _SOURCE_SCHEME.sub('', source or '')
    parts = [p for p in path.replace('\\', '/').split('/') if p not in ('', '.')]
    return '/'.join(parts) or (source or '')


def pseudo_file_base(map_url: str, js_url: str) -> str:
    """What a pseudo-file's URL is built on: the map's URL, or the script's for
    an inline `data:` map (that URL is the whole map)."""
    return js_url if (map_url or '').startswith('data:') else map_url


def sourcemap_pseudo_files(map_data: dict, map_url: str, js_url: str,
                           max_chars: int = PSEUDO_FILE_MAX_CHARS) -> list:
    """The map's first-party sources with text, as files js_recon analyzes:
    ``{"url": "<map_url>#<source>", "content": ..., "from_source_map": True}``.
    Library sources are public code full of example keys, so they are left
    out, and so is a source over ``max_chars``."""
    sources, contents = _map_sources(map_data)
    base = pseudo_file_base(map_url, js_url)
    files, seen = [], set()
    for i, source in enumerate(sources):
        if not source or _is_vendor_source(source) or i >= len(contents):
            continue
        text = contents[i]
        if not isinstance(text, str) or not text.strip() or len(text) > max_chars:
            continue
        url = f"{base}#{_source_label(source)}"
        if url in seen:
            continue
        seen.add(url)
        files.append({
            'url': url,
            'content': text,
            'headers': {},
            'size': len(text),
            'from_source_map': True,
            'map_url': map_url,
            'js_url': js_url,
        })
    return files


def discover_and_analyze_sourcemaps(
    js_files: list,
    settings: dict,
    pseudo_files: Optional[list] = None,
    deadline: Optional[float] = None,
    skipped: Optional[list] = None,
    in_scope: Optional[Callable[[str], bool]] = None,
    admit: Callable[[str], bool] = admit_any,
) -> list:
    """
    Discover and analyze source maps for a list of JS files.

    Args:
        js_files: List of dicts with 'url', 'content', and optionally 'headers'
        settings: Project settings dict
        pseudo_files: when given, receives each served map's first-party
            sources (sourcemap_pseudo_files) for the detectors to read
        deadline: a time.monotonic() value after which no further JS file is
            checked for a map; each one left out is appended to ``skipped``
        in_scope: the run's scope, ``url -> bool``; a map URL (and each of
            its redirect hops) is requested only on a host a JS file came
            from or one this admits
        admit: the caller's own rule for every hop (fetch_hop_by_hop)

    Returns:
        List of source map finding dicts
    """
    if not settings.get('JS_RECON_SOURCE_MAPS', True):
        return []

    # A script names third-party hosts as freely as its own, so a map URL is
    # in scope only on a host the run already fetched JS from, as for an
    # extracted endpoint, or one the caller's scope admits. Any other host is
    # never requested; a direct reference to it is reported, unfetched.
    js_hosts = frozenset(
        url_host(f['url']) for f in js_files
        if isinstance(f, dict) and isinstance(f.get('url'), str)
        and f['url'].lower().startswith(('http://', 'https://'))
    ) - {''}

    def map_in_scope(url: str) -> bool:
        return url_host(url) in js_hosts or bool(in_scope is not None and in_scope(url))

    hop_rules = {'settings': settings, 'in_scope': map_in_scope, 'admit': admit}
    refused: Counter = Counter()

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

    checked_map_urls = set()
    checked_lock = threading.Lock()
    # Use fraction of overall timeout for each sourcemap fetch, minimum 10s
    timeout = max(settings.get('JS_RECON_TIMEOUT', 900) // 60, 10)

    def _claim(url: str) -> bool:
        """Atomically reserve a probe URL. Returns False if already claimed."""
        with checked_lock:
            if url in checked_map_urls:
                return False
            checked_map_urls.add(url)
            return True

    def _past_deadline() -> bool:
        return deadline is not None and time.monotonic() > deadline

    def _served(map_data: dict, map_url: str, js_url: str, method: str) -> list:
        result = analyze_sourcemap(map_data, map_url, js_url)
        result['discovery_method'] = method
        if pseudo_files is not None:
            recovered = sourcemap_pseudo_files(map_data, map_url, js_url)
            with checked_lock:
                pseudo_files.extend(recovered)
        return [result]

    def _fetch(url: str, outcome: dict) -> Optional[dict]:
        map_data = _fetch_sourcemap(url, timeout=timeout, outcome=outcome)
        if outcome.get('reason') in _REFUSED_BY_HOP_GUARD:
            with checked_lock:
                refused[outcome['reason']] += 1
        return map_data

    def _process(js_file: dict) -> list:
        token = _HOP_RULES.set(hop_rules)
        try:
            js_url = js_file.get('url', '')
            content = js_file.get('content', '')
            headers = js_file.get('headers', {})

            if not js_url:
                return []
            if _past_deadline():
                if skipped is not None:
                    with checked_lock:
                        skipped.append(js_url)
                return []

            # Skip a host already known unreachable this run: otherwise each JS
            # file costs up to 8 guessed .map probes (HEAD+GET) against a dead
            # host. is_down is inert under the off switch. (HostHealth,
            # recon/helpers/circuit_breaker.py)
            try:
                from recon.helpers import circuit_breaker as _cb
                if _cb.host_health.is_down(js_url):
                    return []
            except Exception:  # noqa: BLE001 - a fault here scans as today
                pass

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
                if _roe_excluded(js_url, settings):
                    return []
                for probe_url in _build_probe_urls(js_url, custom_paths):
                    if _past_deadline():
                        if skipped is not None:
                            with checked_lock:
                                skipped.append(js_url)
                        return []
                    if not _claim(probe_url):
                        continue
                    map_data = _fetch(probe_url, {})
                    if map_data:
                        return _served(map_data, probe_url, js_url, 'probe')
                return []

            # Fetch and analyze the discovered source map. A reference to a
            # host the Rules of Engagement exclude is not fetched at all.
            if _roe_excluded(map_url, settings) or not _claim(map_url):
                return []
            outcome: dict = {}
            map_data = _fetch(map_url, outcome)
            if map_data:
                return _served(map_data, map_url, js_url, discovery_method)
            # Referenced but not served. An access refusal can mean the map
            # exists, and a reference to ANOTHER host we could not or may not
            # reach (unsafe, out of scope) leaks that host (an internal build
            # server); a 404, an SPA's HTML shell or a JSON error page says
            # nothing, and reporting those buried the board in rows.
            reason = outcome.get('reason')
            other_host = urlparse(map_url).hostname not in (None, urlparse(js_url).hostname)
            if reason not in _REFERENCE_WORTH_REPORTING and not (
                    other_host and reason in _REFERENCE_WORTH_REPORTING_ELSEWHERE):
                return []
            # A 403 is only evidence when a key that cannot exist is not
            # refused alike: object storage answers 403 for missing keys.
            control_check = None
            if reason == 'http_403':
                if outcome.get('storage_denial'):
                    return []
                control_check = _missing_key_control(map_url, timeout)
                if control_check == 'denied':
                    return []
            finding_id = hashlib.sha256(f"srcmap-ref:{js_url}:{map_url}".encode()).hexdigest()[:16]
            return [{
                'id': finding_id,
                'js_url': js_url,
                'map_url': map_url,
                'accessible': False,
                'fetch_result': outcome['reason'],
                'control_check': control_check,
                'discovery_method': discovery_method,
                'files_count': 0,
                'first_party_files': 0,
                'has_sources_content': False,
                'source_files': [],
                'secrets_in_source': 0,
                'severity': 'info',
                'finding_type': 'source_map_reference',
            }]
        except Exception as e:
            print(f"[!][JsRecon] Error processing sourcemap for {js_file.get('url', '?')}: {e}")
            return []
        finally:
            _HOP_RULES.reset(token)

    workers = max(1, min(settings.get('JS_RECON_CONCURRENCY', 10), 20))
    findings = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed(ex.submit(_process, jf) for jf in js_files):
            findings.extend(fut.result())

    if refused:
        print("[-][JsRecon] Source-map requests not sent (hop guard): "
              + ", ".join(f"{reason} {n}" for reason, n in sorted(refused.items())))
    return findings
