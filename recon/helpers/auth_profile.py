"""
RedAmon - Project AuthProfile header builder
=============================================
Turns the project's single AuthProfile (manual entry or a recorded browser
session) into HTTP headers for every recon tool and the agent.

Two controls live here and nowhere else, so every consumer gets them:

* Sanitizing. A recorded value is target-controlled (the target sets the
  Set-Cookie) and ends up in each tool's ``-H``. Values carrying CR/LF split the
  request (header injection / smuggling), and hakrawler (``;;``) and arjun
  (``\\n``) pack every header, including the internal ``X-Redamon-Ctx`` tag, into
  one joined argument, so those delimiters could split or spoof the tag. A bad
  value is rejected outright rather than stripped: a stripped cookie is a
  different, silently broken cookie.
* Scope. Auth lines are produced only for in-scope hosts, so a crawl that
  wanders to a CDN or a third party never carries the session with it.
"""

import base64
import ipaddress
import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from .roe_scope import _is_roe_excluded

AUTH_TYPES = frozenset({'bearer', 'cookie', 'header', 'basic', 'apikey'})
_DEFAULT_HEADER_NAMES = {'header': 'X-Auth-Token', 'apikey': 'X-API-Key'}

MAX_HEADER_NAME_LEN = 256
MAX_HEADER_VALUE_LEN = 8192

# RFC 9110 field-name token.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# Every C0 control except TAB (legal inside a field value), plus DEL.
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0a-\x1f\x7f]')
_TOOL_JOIN_DELIMITERS = (';;',)
# Set only by the capture-proxy routing branch; a profile must never spoof it.
_RESERVED_HEADER_NAMES = frozenset({'x-redamon-ctx'})


def mask_auth_value(auth_value: str, auth_type: str = '') -> str:
    """Mask an authentication value for safe logging."""
    if not auth_value:
        return ''
    if auth_type == 'basic' and ':' in auth_value:
        username, _ = auth_value.split(':', 1)
        return f"{username}:***"
    if len(auth_value) > 10:
        return f"{auth_value[:4]}...{auth_value[-4:]}"
    if len(auth_value) > 4:
        return f"{auth_value[:2]}***"
    return "***"


def sanitize_header_name(name) -> Optional[str]:
    """Return the trimmed header name, or None if it is unsafe to send."""
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or len(name) > MAX_HEADER_NAME_LEN:
        return None
    if not _HEADER_NAME_RE.match(name):
        return None
    if name.lower() in _RESERVED_HEADER_NAMES:
        return None
    return name


def sanitize_header_value(value) -> Optional[str]:
    """Return the trimmed header value, or None if it is unsafe to send."""
    if not isinstance(value, str):
        return None
    if _CONTROL_CHARS_RE.search(value):
        return None
    if any(delim in value for delim in _TOOL_JOIN_DELIMITERS):
        return None
    value = value.strip()
    if not value or len(value) > MAX_HEADER_VALUE_LEN:
        return None
    return value


def _log(log_prefix: Optional[str], message: str) -> None:
    if log_prefix is not None:
        print(message.replace('{prefix}', log_prefix))


def _primary_header(auth_type: str, raw_value: str, header_name,
                    log_prefix: Optional[str]) -> Optional[tuple]:
    value = sanitize_header_value(raw_value)
    if value is None:
        _log(log_prefix, f"[!]{{prefix}} Rejected {auth_type} auth value: control "
                         f"characters, ';;' or longer than {MAX_HEADER_VALUE_LEN} chars")
        return None

    if auth_type == 'bearer':
        # A recorded Authorization header already carries the scheme.
        token = value if value.lower().startswith('bearer ') else f'Bearer {value}'
        return 'Authorization', token
    if auth_type == 'cookie':
        return 'Cookie', value
    if auth_type == 'basic':
        if ':' not in value:
            _log(log_prefix, "[!]{prefix} Basic auth value should be in format 'username:password'")
            return None
        return 'Authorization', 'Basic ' + base64.b64encode(value.encode()).decode()

    # header / apikey: an empty name falls back to the conventional one, but an
    # invalid one is refused rather than silently renamed.
    requested = header_name.strip() if isinstance(header_name, str) else ''
    name = sanitize_header_name(requested or _DEFAULT_HEADER_NAMES[auth_type])
    if name is None:
        _log(log_prefix, f"[!]{{prefix}} Rejected auth header name {requested[:40]!r}")
        return None
    return name, value


def build_auth_headers(profile: Optional[dict], log_prefix: Optional[str] = '[Auth]') -> Dict[str, str]:
    """Build the headers an AuthProfile contributes to a request.

    ``profile`` uses the ProjectAuthProfile field names (``authType``,
    ``authValue``, ``authHeaderName``, ``extraHeaders``). The primary auth header
    wins over an extra header of the same name. ``log_prefix=None`` is silent,
    for per-request callers.
    """
    profile = profile or {}
    headers: Dict[str, str] = {}

    auth_type = str(profile.get('authType') or '').strip().lower()
    raw_value = profile.get('authValue') or ''
    if auth_type in AUTH_TYPES and raw_value:
        primary = _primary_header(auth_type, raw_value, profile.get('authHeaderName'), log_prefix)
        if primary:
            name, value = primary
            headers[name] = value
            _log(log_prefix, f"[*]{{prefix}} Using {auth_type} authentication: "
                             f"{name} = {mask_auth_value(raw_value, auth_type)}")
    elif auth_type not in ('', 'none') and raw_value:
        _log(log_prefix, f"[!]{{prefix}} Unknown auth type: {auth_type[:40]}")

    extras = profile.get('extraHeaders') or {}
    if isinstance(extras, dict):
        taken = {n.lower() for n in headers}
        for raw_name, raw_extra in extras.items():
            name = sanitize_header_name(raw_name)
            value = sanitize_header_value(raw_extra)
            if name is None or value is None:
                _log(log_prefix, f"[!]{{prefix}} Rejected extra header {str(raw_name)[:40]!r}")
                continue
            if name.lower() in taken:
                continue
            headers[name] = value
            taken.add(name.lower())

    return headers


def _normalize_host(host) -> str:
    """Lower-cased hostname/IP with any scheme, path, port and trailing dot removed."""
    if not isinstance(host, str):
        return ''
    host = host.strip()
    if '://' in host:
        host = urlsplit(host).hostname or ''
    elif host.startswith('['):
        host = host[1:].split(']', 1)[0]
    elif host.count(':') == 1:
        host = host.split(':', 1)[0]
    return host.strip().rstrip('.').lower()


def _normalize_scope_entry(entry) -> str:
    if not isinstance(entry, str):
        return ''
    entry = entry.strip()
    if entry.startswith('*.'):
        return '*.' + _normalize_host(entry[2:])
    if '/' in entry and '://' not in entry:
        return entry.lower()
    return _normalize_host(entry)


def _dedupe(entries: Iterable[str]) -> List[str]:
    seen: Dict[str, None] = {}
    for e in entries:
        if e:
            seen.setdefault(e, None)
    return list(seen)


def default_scope_hosts(settings: dict, extra_hosts: Iterable[str] = ()) -> List[str]:
    """The project's own target hosts and their subdomains, minus RoE exclusions.

    RoE is exclusion-based, so there is no allowlist to inherit: the default is
    exactly what the project targets, INCLUDING its subdomains (``*.<root>``).
    The subdomains ARE the project's attack surface — they are what recon
    discovers and what every crawler is restricted to — so a default scope that
    covered only the apex silently degraded every authenticated scan to an
    anonymous one the moment discovery found anything.

    Residual risk, accepted deliberately: a discovered subdomain CNAME'd to a
    third party is in scope. An operator who cannot accept that sets explicit
    ``scopeHosts`` on the profile, which replaces this default entirely.
    """
    hosts: List[str] = []
    if settings.get('IP_MODE'):
        hosts.extend(settings.get('TARGET_IPS') or [])
    else:
        roots: List[str] = []
        root = _normalize_host(settings.get('TARGET_DOMAIN') or '')
        if root:
            roots.append(root)
        # A domain-batch project leaves TARGET_DOMAIN empty and keeps its scope
        # in the derived groups; without this it would have no scope at all.
        for group in settings.get('DOMAIN_BATCH_GROUPS') or []:
            if isinstance(group, dict):
                g = _normalize_host(group.get('rootDomain') or '')
                if g and g not in roots:
                    roots.append(g)
        for r in roots:
            hosts.append(r)
            hosts.append(f"*.{r}")
        if root:
            for prefix in settings.get('SUBDOMAIN_LIST') or []:
                clean = str(prefix).strip().rstrip('.')
                if clean:
                    hosts.append(f"{clean}.{root}")
    hosts.extend(extra_hosts or ())

    scope = _dedupe(_normalize_scope_entry(h) for h in hosts)
    if settings.get('ROE_ENABLED') and settings.get('ROE_EXCLUDED_HOSTS'):
        scope = [h for h in scope if not _is_roe_excluded(h, settings['ROE_EXCLUDED_HOSTS'])]
    return scope


def resolve_scope_hosts(profile: Optional[dict], settings: Optional[dict] = None,
                        extra_hosts: Iterable[str] = ()) -> List[str]:
    """Explicit ``scopeHosts`` if the operator set any, else the project default."""
    explicit = (profile or {}).get('scopeHosts') or []
    if explicit:
        return _dedupe(_normalize_scope_entry(h) for h in explicit)
    return default_scope_hosts(settings or {}, extra_hosts)


def host_in_scope(host, scope_hosts: Iterable[str]) -> bool:
    """Exact host, ``*.suffix`` (subdomains only, not the apex) or CIDR match."""
    h = _normalize_host(host)
    if not h:
        return False
    for entry in scope_hosts:
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


def recon_enabled(profile: Optional[dict]) -> bool:
    """Whether the recon consumer gate is on (default on when absent)."""
    return bool(profile) and profile.get('reconEnabled', True) is not False


def profile_from_settings(settings: Optional[dict]) -> Optional[dict]:
    """The AuthProfile row out of a recon settings dict, or None when unusable."""
    profile = (settings or {}).get('AUTH_PROFILE')
    if not isinstance(profile, dict):
        return None
    # Independent recon consumer gate (default on). Off => recon runs anonymous.
    if not recon_enabled(profile):
        return None
    if str(profile.get('authType') or 'none').lower() == 'none':
        # An extras-only profile is still usable.
        if not (isinstance(profile.get('extraHeaders'), dict) and profile['extraHeaders']):
            return None
    return profile


def merge_auth_headers(custom_headers: Optional[Iterable[str]], settings: Optional[dict],
                       hosts: Iterable[str]) -> List[str]:
    """Prepend the profile's in-scope auth lines to a tool's ``custom_headers``.

    ``hosts`` is the set the command will hit (the crawl's ``allowed_hosts`` or a
    single target). Most recon tools send ONE ``-H`` set for a whole targets file,
    so the session is attached only when EVERY host is in scope; a single
    out-of-scope host means no auth at all (fail closed), never a cross-origin
    leak. Auth lines go FIRST so a tool that packs headers into one delimited
    argument (hakrawler ``;;``, arjun ``\\n``) keeps them ahead of, and separate
    from, the ``X-Redamon-Ctx`` tag it appends last.
    """
    base = [h for h in (custom_headers or []) if h]
    profile = profile_from_settings(settings)
    hosts = [h for h in (hosts or []) if h]
    if not profile or not hosts:
        return base

    # Scope is the profile's explicit hosts or the project target hosts — never
    # the command's own hosts, or every host would trivially match itself.
    scope = resolve_scope_hosts(profile, settings or {})
    roe_on = bool((settings or {}).get('ROE_ENABLED') and (settings or {}).get('ROE_EXCLUDED_HOSTS'))
    for host in hosts:
        # Every drop is logged: an unattached session is otherwise invisible, and
        # "the scan silently ran logged-out" is the worst failure this code has.
        if not host_in_scope(host, scope):
            print(f"[!][Auth] Session NOT attached: host '{host}' is outside the auth "
                  f"scope {scope}. Add it to the project's Authenticated Session "
                  f"scope hosts to scan this host authenticated.")
            return base
        if roe_on and _is_roe_excluded(_normalize_host(host), settings['ROE_EXCLUDED_HOSTS']):
            print(f"[!][Auth] Session NOT attached: host '{host}' is RoE-excluded.")
            return base

    auth_lines = [f"{name}: {value}" for name, value in build_auth_headers(profile, log_prefix=None).items()]
    if auth_lines:
        print(f"[*][Auth] Session attached ({profile.get('authType')}) to "
              f"{len(hosts)} in-scope host(s).")
        # Drop any operator-supplied custom header the profile already sets, so
        # the profile is authoritative and the same header is not sent twice.
        profile_names = {line.split(':', 1)[0].strip().lower() for line in auth_lines}
        base = [h for h in base if h.split(':', 1)[0].strip().lower() not in profile_names]
    return auth_lines + base


def merge_auth_headers_ex(custom_headers: Optional[Iterable[str]], settings: Optional[dict],
                          hosts: Iterable[str]) -> Tuple[List[str], bool]:
    """``merge_auth_headers`` plus whether a session was actually attached.

    Callers need the flag to tighten a tool's own cross-host behaviour (httpx and
    nuclei re-send ``-H`` headers on a redirect to ANY host, so an authenticated
    run must confine them to the scope-checked host). Counting the returned lines
    cannot answer it: the merge also drops base headers the profile overrides, so
    attaching auth can leave the list the same length.
    """
    base = [h for h in (custom_headers or []) if h]
    merged = merge_auth_headers(custom_headers, settings, hosts)
    return merged, merged != base


def auth_header_lines(profile: Optional[dict], target_host, settings: Optional[dict] = None,
                      scope_hosts: Optional[Iterable[str]] = None) -> List[str]:
    """``["Name: value", ...]`` for ``target_host``, or ``[]`` when it is out of scope.

    RoE exclusions apply even to an explicitly scoped host. Fails closed: no
    resolvable scope means no auth anywhere.
    """
    settings = settings or {}
    # Recon consumer gate (default on). ai_surface_recon / graphql call this
    # directly, so honor it here too. GraphQL passes its own typed triple (no
    # reconEnabled key) -> default on, unchanged.
    if not recon_enabled(profile):
        return []
    scope = list(scope_hosts) if scope_hosts is not None else resolve_scope_hosts(profile, settings)
    if not host_in_scope(target_host, scope):
        return []
    if settings.get('ROE_ENABLED') and settings.get('ROE_EXCLUDED_HOSTS'):
        if _is_roe_excluded(_normalize_host(target_host), settings['ROE_EXCLUDED_HOSTS']):
            return []
    return [f"{name}: {value}" for name, value in build_auth_headers(profile, log_prefix=None).items()]
