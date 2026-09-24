"""Dependency-free target matching shared by recon authentication and graph ingestion."""

import ipaddress
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlsplit


def _is_roe_excluded(host: str, excluded_list: list) -> bool:
    """Match exact IPs, CIDRs, domain suffixes and subdomain-only wildcards."""
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

    That trade is only defensible where the operator chose a ROOT and asked for
    its subdomains. A Domain batch is per GROUP: a literal group names its hosts
    exactly, so it gets exactly those, and only a wildcard group — where the
    operator wrote ``*.domain.com``, i.e. "the whole domain" — gets ``*.<root>``.
    Blanket-wildcarding every batch root would attach the operator's session to
    thousands of discovered names they never listed.
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
            if not isinstance(group, dict):
                continue
            g = _normalize_host(group.get('rootDomain') or '')
            if not g:
                continue
            prefixes = [p for p in (group.get('prefixes') or []) if isinstance(p, str)]
            if '*' in prefixes:
                # Enumerated group: the operator asked for the whole domain.
                if g not in roots:
                    roots.append(g)
                continue
            # Literal group: exactly the hosts it named, and the apex only when
            # '.' put it in scope.
            for p in prefixes:
                clean = p.strip().rstrip('.')
                hosts.append(g if not clean else f"{clean}.{g}")
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

