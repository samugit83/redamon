"""
RedAmon - Rules of Engagement scope helpers
============================================
Excluded-host matching and the time window for the RoE governor. Extracted
from ``recon.main`` so active scanners (e.g. origin_discovery, AI Surface Recon)
can enforce them without importing ``recon.main``, which would re-run the
pipeline's top level as a second module. ``recon.main`` re-exports these names,
so ``from main import _is_roe_excluded`` still resolves.

It imports no other recon module: the auth profile and the OpenAPI scope build
on its normalizers.
"""

import ipaddress
from urllib.parse import urlsplit


def _is_roe_excluded(host: str, excluded_list: list) -> bool:
    """True when ``host`` matches an RoE exclusion.

    An exclusion is an exact host or IP; a domain, which also excludes its
    subdomains; ``*.domain``, which excludes its subdomains only; or a CIDR.
    Case, port, scheme, path and a trailing dot are ignored on both sides, and
    an IPv6 address matches in any spelling. A bare string suffix is never an
    IP rule: ``0.5`` does not exclude ``10.0.0.5``.
    """
    host = _normalize_host(host)
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for value in excluded_list:
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


def _normalize_host(host) -> str:
    """Lower-cased hostname/IP with any scheme, path, port and trailing dot removed."""
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
    # one such entry, or one such crawled URL, must not abort the whole check.
    try:
        return urlsplit(url).hostname or ''
    except ValueError:
        return ''


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


def _filter_roe_excluded(hosts: list, settings: dict, label: str = "host") -> list:
    """Filter a list of hosts/IPs against ROE_EXCLUDED_HOSTS. Returns the filtered list."""
    roe_excluded = settings.get('ROE_EXCLUDED_HOSTS', [])
    if not settings.get('ROE_ENABLED', False) or not roe_excluded:
        return hosts
    before_count = len(hosts)
    filtered = [h for h in hosts if not _is_roe_excluded(h, roe_excluded)]
    removed = before_count - len(filtered)
    if removed:
        print(f"[RoE] Excluded {removed} {label}(s) per Rules of Engagement")
    return filtered


def _check_roe_time_window(settings: dict, _now=None) -> tuple[bool, str]:
    """Check if current time is within the RoE-allowed window.

    Returns (allowed, reason_message). Always returns (True, "") if
    RoE or its time window is disabled. Pass _now for testing.

    The orchestrator mirrors this in its own image
    (recon_orchestrator/api.py ``_check_roe_time_window``) and admits a scan
    start by it, so the two must agree on every case: both run
    recon/tests/fixtures/roe_time_window_vectors.json. The end minute is
    inclusive, an end before the start crosses midnight, and an unknown
    timezone refuses rather than being read as UTC, which could shift the
    window by hours.
    """
    if not settings.get('ROE_ENABLED') or not settings.get('ROE_TIME_WINDOW_ENABLED'):
        return True, ""

    from datetime import datetime as _dt
    import zoneinfo as _zi

    tz_name = settings.get('ROE_TIME_WINDOW_TIMEZONE', 'UTC')
    try:
        tz = _zi.ZoneInfo(tz_name)
    except Exception:
        return False, f"Unknown RoE time-window timezone '{tz_name}'; fix the project's time-window timezone setting"

    now = (_now or _dt.now(tz)).astimezone(tz)

    allowed_days = [str(d).lower() for d in settings.get('ROE_TIME_WINDOW_DAYS') or []]
    current_day = now.strftime('%A').lower()
    if current_day not in allowed_days:
        return False, f"Current day ({current_day}) is not in allowed days: {', '.join(allowed_days)} ({tz_name})"

    start = settings.get('ROE_TIME_WINDOW_START_TIME', '09:00')
    end = settings.get('ROE_TIME_WINDOW_END_TIME', '18:00')
    current_time = now.strftime('%H:%M')
    if not _time_in_window(current_time, start, end):
        return False, f"Current time ({current_time} {tz_name}) is outside allowed window ({start}\u2013{end})"

    return True, ""


def _time_in_window(current: str, start: str, end: str) -> bool:
    """HH:MM strings; both ends inclusive, and a start after the end wraps midnight."""
    if start <= end:
        return start <= current <= end
    return current >= start or current <= end
