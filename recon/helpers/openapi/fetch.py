"""Fetch specification documents without forwarding credentials between origins."""
import json
import math
import re
import time
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

import requests
import urllib3
import yaml
from urllib3.exceptions import HTTPError

from helpers import proxy_routing
from recon.helpers.request_pacer import RequestPacer

# Fetches use verify=False like the rest of recon; one warning per request
# would flood the run log.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OpenApiLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise DocumentError('Document mapping keys must be strings')
            if key in keys:
                raise DocumentError('Duplicate document key')
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


# PyYAML's YAML 1.1 coercions turn API enum strings like "on" into booleans
# and date examples into non-JSON objects. OpenAPI uses the YAML 1.2 data model.
OpenApiLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in entries
          if tag not in ('tag:yaml.org,2002:bool', 'tag:yaml.org,2002:timestamp')]
    for key, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
OpenApiLoader.add_implicit_resolver('tag:yaml.org,2002:bool',
                                  re.compile(r'^(?:true|false|True|False|TRUE|FALSE)$'), list('tTfF'))


class DocumentError(ValueError):
    """``code`` is the fixed status a failure reports; the message is detail."""

    def __init__(self, message='', code='invalid_document'):
        super().__init__(message)
        self.code = code


def http_url(value):
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 33 for c in value) or '\\' in value:
        raise DocumentError('Invalid HTTP document URL')
    try:
        parts = urlsplit(value)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
            raise ValueError()
        host = parts.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        port = parts.port
    except (ValueError, UnicodeError):
        raise DocumentError('Invalid HTTP document URL') from None
    if ':' in host:
        host = f'[{host}]'
    netloc = host + (f':{port}' if port and port != {'http': 80, 'https': 443}[parts.scheme] else '')
    return urlunsplit((parts.scheme, netloc, parts.path or '/', parts.query, ''))


def origin(url):
    parts = urlsplit(http_url(url))
    return f'{parts.scheme}://{parts.netloc}'


def public_url(url):
    """Query values can carry credentials; provenance retains only the location."""
    try:
        parts = urlsplit(http_url(url))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))
    except DocumentError:
        return '<invalid URL>'


def parse_headers(lines):
    result = {}
    for line in lines or []:
        if not isinstance(line, str) or ':' not in line or '\n' in line or '\r' in line:
            raise DocumentError('Invalid fetch header')
        name, value = line.split(':', 1)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name.strip()):
            raise DocumentError('Invalid fetch header name')
        if name.strip().lower() in ('host', 'content-length', 'transfer-encoding'):
            raise DocumentError('Unsupported fetch header')
        result[name.strip()] = value.strip()
    return result


def decode_document(text):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DocumentError('Duplicate document key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise DocumentError('Non-finite JSON number')
    try:
        doc = json.loads(text, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
    except (json.JSONDecodeError, RecursionError):
        try:
            doc = yaml.load(text, Loader=OpenApiLoader)
        except (yaml.YAMLError, RecursionError):
            raise DocumentError('Invalid JSON or YAML document') from None
    if not isinstance(doc, dict):
        raise DocumentError('Expected a JSON or YAML object')
    # YAML aliases may be cyclic or expand exponentially during traversal.
    def check(value, ancestors, budget):
        budget[0] -= 1
        if budget[0] < 0 or len(ancestors) > 80:
            raise DocumentError('Document structure exceeds limits')
        if isinstance(value, (dict, list)):
            if id(value) in ancestors:
                raise DocumentError('Cyclic YAML aliases are unsupported')
            ancestors = ancestors | {id(value)}
            if isinstance(value, dict) and not all(isinstance(key, str) for key in value):
                raise DocumentError('Document mapping keys must be strings')
            for child in (value.values() if isinstance(value, dict) else value):
                check(child, ancestors, budget)
        elif not isinstance(value, (str, int, float, bool, type(None))):
            raise DocumentError('Unsupported non-JSON YAML value')
        elif isinstance(value, float) and not math.isfinite(value):
            raise DocumentError('Non-finite document number')
    check(doc, set(), [100000])
    return doc


class Fetcher:
    def __init__(self, timeout=10, max_requests=500, max_rps=0, *, pacer=None, address_guard=None,
                 health=None, on_request=None):
        self.timeout = min(max(float(timeout), 1), 60)
        self.max_requests = min(max(int(max_requests), 1), 1000)
        self.pacer = pacer if pacer is not None else RequestPacer(max_rps)
        # host -> bool, asked before every hop; None trusts every host (tests).
        self.address_guard = address_guard
        # Circuit-breaker hooks (skip_if_down / host_alive / host_failed).
        self.health = health
        # (url, code, session_headers, routed) for every request actually sent.
        self.on_request = on_request
        self.count = 0
        self.total_bytes = 0
        self.max_total_bytes = 32 * 1024 * 1024
        self.cache = {}
        self.session = requests.Session()
        # Do not pick up ambient .netrc credentials or cross-scan cookies.
        self.session.trust_env = False

    def close(self):
        self.session.close()

    def fetch(self, url, headers, allowed_origin):
        url = http_url(urldefrag(url)[0])
        if origin(url) != allowed_origin:
            raise DocumentError('Cross-origin document navigation blocked', code='out_of_scope')
        key = (url, tuple(sorted(headers.items())))
        if key in self.cache:
            return self.cache[key]
        deadline = time.monotonic() + self.timeout
        for _ in range(6):
            if origin(url) != allowed_origin:
                raise DocumentError('Cross-origin document navigation blocked', code='out_of_scope')
            if self.count >= self.max_requests:
                raise DocumentError('Document request limit reached', code='limit_reached')
            if self.total_bytes >= self.max_total_bytes:
                raise DocumentError('Total document byte limit reached', code='limit_reached')
            # Every hop: a name can resolve elsewhere by the time a redirect is
            # followed. A refusal sends nothing and is not counted.
            if self.address_guard is not None and not self.address_guard(urlsplit(url).hostname or ''):
                raise DocumentError('Document host resolves to an address recon never scans',
                                    code='blocked_address')
            if self.health is not None and self.health.skip_if_down(url):
                raise DocumentError('Document host is unreachable this run', code='host_down')
            proxy_url, token = proxy_routing.get_capture_routing('openapi')
            routed = bool(proxy_url and token)
            request_headers = {key: value for key, value in headers.items()
                               if key.lower() != 'x-redamon-ctx'}
            proxies = {}
            if routed:
                proxies = {'http': proxy_url, 'https': proxy_url}
                request_headers['X-Redamon-Ctx'] = token
            # Batch groups share pacing, while cache and request budgets remain
            # local to each fetcher. Redirects and references use the same clock.
            # The wait for a slot is the RoE ceiling's, not the target's, so it
            # extends the deadline: other requesters share the clock, and a long
            # queue must not read as a slow server.
            deadline += self.pacer.acquire()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DocumentError('Document fetch deadline exceeded', code='transport_error')
            self.count += 1
            self.session.cookies.clear()
            try:
                # TLS is not verified, as for every recon fetcher: the capture
                # proxy terminates TLS with its own CA, and targets often serve
                # self-signed certificates. Only routed requests carry the tag.
                response = self.session.get(url, headers=request_headers, timeout=remaining,
                                            proxies=proxies, verify=False,
                                            allow_redirects=False, stream=True)
            except (requests.RequestException, HTTPError, OSError) as exc:
                if self.health is not None:
                    self.health.host_failed(url, exc)
                self._record(url, 'transport_error', headers, routed)
                raise DocumentError('Document transport error', code='transport_error') from None
            if self.health is not None:
                self.health.host_alive(url)
            self._record(url, response.status_code, headers, routed)
            try:
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location') or response.headers.get('location')
                    if not location:
                        raise DocumentError('Redirect without location')
                    url = http_url(urljoin(url, location))
                    continue
                if response.status_code != 200:
                    raise DocumentError(f'Document HTTP status {response.status_code}',
                                        code=f'http_{int(response.status_code)}')
                chunks, size = [], 0
                raw = getattr(response, 'raw', None)
                if raw is not None and hasattr(raw, 'read1'):
                    # read1 returns available bytes, unlike iter_content's
                    # full-chunk reads which can hide an endless trickle.
                    def chunks_available():
                        while True:
                            chunk = raw.read1(65536, decode_content=True)
                            if not chunk:
                                break
                            yield chunk
                    stream = chunks_available()
                else:
                    stream = response.iter_content(chunk_size=1)
                for chunk in stream:
                    if time.monotonic() >= deadline:
                        raise DocumentError('Document fetch deadline exceeded', code='transport_error')
                    size += len(chunk)
                    self.total_bytes += len(chunk)
                    if self.total_bytes > self.max_total_bytes:
                        raise DocumentError('Total document byte limit reached', code='limit_reached')
                    if size > 5 * 1024 * 1024:
                        raise DocumentError('Document exceeds 5 MiB limit', code='limit_reached')
                    chunks.append(chunk)
                body = b''.join(chunks)
            except (requests.RequestException, HTTPError, OSError):
                raise DocumentError('Document transport error', code='transport_error') from None
            finally:
                response.close()
            try:
                text = body.decode('utf-8-sig')
            except UnicodeError:
                raise DocumentError('Document is not UTF-8 text') from None
            self.cache[key] = (url, text)
            return url, text
        raise DocumentError('Document redirect limit reached', code='limit_reached')

    def _record(self, url, code, headers, routed):
        if self.on_request is not None:
            try:
                self.on_request(url, code, bool(headers), routed)
            except Exception:  # noqa: BLE001 - the ledger must never stop a fetch
                pass
