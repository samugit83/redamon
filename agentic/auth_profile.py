"""
Agent-side AuthProfile header builder.

The agent image does not carry the recon source, so this mirrors
``recon/helpers/auth_profile.py`` the same way ``redamon_ctx.py`` is copied
across images. Keep the sanitizing rules identical: a target-controlled value
must not inject headers or spoof the internal ``X-Redamon-Ctx`` tag.

Used by the ``/traffic/replay`` and ``/traffic/browser`` paths to give the agent
an authenticated identity for in-scope target hosts, layered UNDER the origin
transaction's own headers and any explicit ``mutate`` (so IDOR/BOLA swaps still
win).
"""

import base64
import ipaddress
import re
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlsplit

AUTH_TYPES = frozenset({'bearer', 'cookie', 'header', 'basic', 'apikey'})
_DEFAULT_HEADER_NAMES = {'header': 'X-Auth-Token', 'apikey': 'X-API-Key'}
MAX_HEADER_NAME_LEN = 256
MAX_HEADER_VALUE_LEN = 8192

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0a-\x1f\x7f]')
_RESERVED_HEADER_NAMES = frozenset({'x-redamon-ctx'})


def _sanitize_name(name) -> Optional[str]:
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or len(name) > MAX_HEADER_NAME_LEN or not _HEADER_NAME_RE.match(name):
        return None
    if name.lower() in _RESERVED_HEADER_NAMES:
        return None
    return name


def _sanitize_value(value) -> Optional[str]:
    if not isinstance(value, str) or _CONTROL_CHARS_RE.search(value) or ';;' in value:
        return None
    value = value.strip()
    if not value or len(value) > MAX_HEADER_VALUE_LEN:
        return None
    return value


def build_auth_headers(profile: Optional[dict]) -> Dict[str, str]:
    """Headers this profile contributes; primary auth wins over a same-name extra."""
    profile = profile or {}
    headers: Dict[str, str] = {}

    auth_type = str(profile.get('authType') or '').strip().lower()
    raw_value = profile.get('authValue') or ''
    value = _sanitize_value(raw_value)
    if auth_type in AUTH_TYPES and value:
        if auth_type == 'bearer':
            headers['Authorization'] = value if value.lower().startswith('bearer ') else f'Bearer {value}'
        elif auth_type == 'cookie':
            headers['Cookie'] = value
        elif auth_type == 'basic':
            if ':' in value:
                headers['Authorization'] = 'Basic ' + base64.b64encode(value.encode()).decode()
        else:
            requested = profile.get('authHeaderName')
            requested = requested.strip() if isinstance(requested, str) else ''
            name = _sanitize_name(requested or _DEFAULT_HEADER_NAMES[auth_type])
            if name:
                headers[name] = value

    extras = profile.get('extraHeaders') or {}
    if isinstance(extras, dict):
        taken = {n.lower() for n in headers}
        for raw_name, raw_extra in extras.items():
            name = _sanitize_name(raw_name)
            val = _sanitize_value(raw_extra)
            if name and val and name.lower() not in taken:
                headers[name] = val
                taken.add(name.lower())
    return headers


def _normalize_host(host) -> str:
    if not isinstance(host, str):
        return ''
    host = host.strip()
    if '://' in host:
        host = _url_hostname(host)
    elif host.startswith('['):
        host = host[1:].split(']', 1)[0]
    elif host.count(':') == 1:
        host = host.split(':', 1)[0]
    return host.strip().rstrip('.').lower()


def _url_hostname(url: str) -> str:
    # urlsplit raises on an unbalanced or non-IP bracket (`https://[a.example.com]/`);
    # one such entry, or one such URL, must not abort the whole check.
    try:
        return urlsplit(url).hostname or ''
    except ValueError:
        return ''


def host_in_scope(host, scope_hosts: Iterable[str]) -> bool:
    """Exact host, ``*.suffix`` (subdomains only) or CIDR match."""
    h = _normalize_host(host)
    if not h:
        return False
    for entry in scope_hosts or ():
        entry = (entry or '').strip().lower()
        if not entry:
            continue
        if entry.startswith('*.'):
            if h.endswith(entry[1:]):
                return True
        elif '/' in entry:
            try:
                if ipaddress.ip_address(h) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        elif h == entry:
            return True
    return False


def _is_network(entry: str) -> bool:
    """An IP followed by a prefix length or an IPv4 mask: what ``ip_network``
    reads. A malformed one (``10.0.0.0/33``) stays a network that matches
    nothing rather than becoming the exact IP before its slash."""
    head, _, tail = entry.partition('/')
    try:
        ipaddress.ip_address(head)
    except ValueError:
        return False
    if tail.isascii() and tail.isdigit():
        return True
    try:
        ipaddress.IPv4Address(tail)
        return True
    except ValueError:
        return False


def _entry_host(entry: str) -> str:
    """The host of an entry written with a path (``admin.example.com/login``,
    ``192.0.2.10/``). Exclusions are per host, so the path is dropped, as it is
    for an entry with a scheme."""
    head = entry.split('/', 1)[0]
    try:
        # A bare IPv6 has colons urlsplit would read as a port.
        ipaddress.ip_address(head)
        return head.lower()
    except ValueError:
        return _normalize_host(_url_hostname('//' + entry))


def _normalize_scope_entry(entry) -> str:
    if not isinstance(entry, str):
        return ''
    entry = entry.strip()
    if entry.startswith('*.'):
        rest = entry[2:]
        return '*.' + (_entry_host(rest) if '/' in rest and '://' not in rest
                       else _normalize_host(rest))
    if '/' in entry and '://' not in entry:
        return entry.lower() if _is_network(entry) else _entry_host(entry)
    return _normalize_host(entry)


def is_roe_excluded(host, excluded_list) -> bool:
    """True when ``host`` matches an RoE exclusion (mirrors ``_is_roe_excluded``
    in ``recon/helpers/roe_scope.py``): an exact host or IP; a domain, which also
    excludes its subdomains; ``*.domain``, its subdomains only; or a CIDR."""
    host = _normalize_host(host)
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for value in excluded_list or ():
        entry = _normalize_scope_entry(value)
        if not entry:
            continue
        if entry.startswith('*.'):
            if host.endswith(entry[1:]):
                return True
        elif '/' in entry or address is not None:
            try:
                if address is not None and address in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
        elif host == entry or host.endswith('.' + entry):
            return True
    return False


def resolve_scope_hosts(profile: Optional[dict], scope_patterns: Iterable[str],
                        roe_excluded: Iterable[str] = ()) -> List[str]:
    """The project's auth scope (``auth_scope_patterns``), NARROWED by the
    profile's explicit ``scopeHosts`` when set (D-22: the intersection, never a
    replacement), less the RoE-excluded hosts.

    Fails closed: an unconfigured project yields no scope, so no auth is
    attached. A wildcard survives the RoE filter; the per-request check in
    ``auth_headers_for_host`` catches an excluded host under it.
    """
    from scope_groups import intersect_explicit_scope

    patterns = [e for e in (_normalize_scope_entry(p) for p in scope_patterns or ()) if e]
    explicit = (profile or {}).get('scopeHosts') or []
    scope = intersect_explicit_scope(explicit, patterns) if explicit else patterns
    roe = list(roe_excluded or ())
    seen: Dict[str, None] = {}
    for entry in scope:
        if roe and not entry.startswith('*.') and is_roe_excluded(entry, roe):
            continue
        seen.setdefault(entry, None)
    return list(seen)


def agent_enabled(profile: Optional[dict]) -> bool:
    """Whether the agent consumer gate is on (default on when absent)."""
    return bool(profile) and profile.get('agentEnabled', True) is not False


def auth_headers_for_host(profile: Optional[dict], target_host, scope_patterns: Iterable[str],
                          roe_excluded: Iterable[str] = ()) -> Dict[str, str]:
    """The profile's headers for ``target_host``, or ``{}`` when out of scope.

    ``roe_excluded`` is the project's RoE excluded-hosts list when RoE is on:
    the request's own host is checked against it, since a pattern like
    ``*.example.com`` survives an exclusion of ``admin.example.com``.

    Honors the independent agent consumer gate (default on): with it off the
    agent's replay/browser/curl all send anonymously, even if recon is authed.
    """
    if not profile or not agent_enabled(profile):
        return {}
    if roe_excluded and is_roe_excluded(target_host, roe_excluded):
        return {}
    scope = resolve_scope_hosts(profile, scope_patterns, roe_excluded)
    if not host_in_scope(target_host, scope):
        return {}
    return build_auth_headers(profile)
