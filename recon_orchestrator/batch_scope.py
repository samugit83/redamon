"""
Domain batch: which domains a project would actually scan.

Kept OUT of api.py deliberately. This feeds the hard guardrail, the one control an
operator cannot switch off, and api.py cannot be imported without FastAPI and the
Docker client - so the security decision would have been untestable in the unit
tier. Mirrors auth.py, which is standalone for the same reason.

The contract, and why each half matters:

  - a Domain-batch project has an EMPTY targetDomain and keeps its scope in
    domainBatchGroups, so a guardrail that reads targetDomain alone waves every
    batch target through;
  - a root that fails the charset check is DROPPED, never repaired: a repaired
    hostname would be a target the operator never approved;
  - an empty result in batch mode means "cannot determine scope", which the caller
    must treat as a refusal, not as "nothing to check". Fail closed.
"""
from __future__ import annotations

import re

_BATCH_ROOT_CHARSET = re.compile(r'^[a-z0-9.-]+$')


def batch_guardrail_targets(project: dict) -> list[str]:
    """Every root domain a Domain-batch project would scan, deduplicated, in order."""
    groups = project.get('domainBatchGroups')
    if not isinstance(groups, list):
        return []

    roots: list[str] = []
    for entry in groups:
        if not isinstance(entry, dict):
            continue
        root = str(entry.get('rootDomain') or '').strip().lower()
        if not root or not _BATCH_ROOT_CHARSET.match(root) or '..' in root:
            continue
        if root not in roots:
            roots.append(root)
    return roots


# ---------------------------------------------------------------------------
# Partial recon. The orchestrator is the only authority on which roots a run
# may touch: the client names at most a subset, never a root of its own.
# ---------------------------------------------------------------------------

# The only settings a partial run may override: the Nuclei checkboxes, the one
# thing the modal sends. The recon modules apply every override they receive,
# so an open dict would let a crafted request switch off ROE_ENABLED or empty
# ROE_EXCLUDED_HOSTS. Mirrors ALLOWED_SETTINGS_OVERRIDES in recon/partial_recon.py,
# which drops anything else again inside the container.
PARTIAL_OVERRIDE_KEYS = frozenset({
    'CVE_LOOKUP_ENABLED',
    'MITRE_ENABLED',
    'SECURITY_CHECK_ENABLED',
})

# Same ceiling as a Domain batch (MAX_BATCH_GROUPS in webapp/src/lib/domainBatch.ts).
MAX_REQUESTED_ROOTS = 50


class PartialScopeError(ValueError):
    """A partial-recon start to refuse, with the HTTP status to refuse it with."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _usable_root(root: str) -> bool:
    # The charset is checked on the lowercased name but the stored spelling is
    # kept: a single-domain target is saved trimmed, not lowercased, and the
    # graph's Domain node carries exactly that name.
    low = root.strip().lower()
    return bool(low) and bool(_BATCH_ROOT_CHARSET.match(low)) and '..' not in low


def partial_project_roots(project: dict, project_id: str) -> list[str]:
    """Every root this project scans, re-validated. Raises PartialScopeError(400)."""
    if project.get('ipMode', False):
        # The name recon/main.py mints for IP mode's synthetic Domain node.
        roots = [f"ip-targets.{project_id}"]
    elif project.get('domainBatchMode', False):
        roots = ([g['scanRoot'] for g in scope_groups(project)] if 'scopeGroups' in project
                 else batch_guardrail_targets(project))
        if not roots:
            raise PartialScopeError(
                400,
                "Domain batch project has no valid domain groups. "
                "Re-save the project's hostname list before scanning.",
            )
    else:
        target = str(project.get('targetDomain') or '').strip()
        roots = [target] if target else []

    roots = [r for r in roots if _usable_root(r)]
    if not roots:
        raise PartialScopeError(400, "This project has no usable scan target.")
    return roots


def narrow_partial_roots(roots: list[str], graph_inputs: dict) -> list[str]:
    """The project roots this run covers, narrowed by the request. Sorted.

    `graph_inputs.domains` is intersected with the roots. A legacy request (a
    job queued before multi-root partial recon) carries only `domain`, which
    must be a current root. Neither means every root.
    """
    graph_inputs = graph_inputs if isinstance(graph_inputs, dict) else {}
    by_key = {r.lower(): r for r in roots}

    requested = graph_inputs.get('domains')
    if requested is not None:
        if (not isinstance(requested, list) or len(requested) > MAX_REQUESTED_ROOTS
                or not all(isinstance(x, str) for x in requested)):
            raise PartialScopeError(
                400, f"graph_inputs.domains must be a list of at most "
                     f"{MAX_REQUESTED_ROOTS} domain names.")
        chosen = {by_key[x.strip().lower()] for x in requested if x.strip().lower() in by_key}
        if not chosen:
            raise PartialScopeError(400, "None of the requested domains is a target of this project.")
        return sorted(chosen)

    legacy = graph_inputs.get('domain')
    if legacy:
        if not isinstance(legacy, str) or legacy.strip().lower() not in by_key:
            raise PartialScopeError(400, f"{legacy!r} is not a target of this project.")
        return [by_key[legacy.strip().lower()]]

    return sorted(roots)


def validate_partial_overrides(overrides) -> dict:
    """The settings overrides, or PartialScopeError(400) for anything not allowed."""
    if overrides is None:
        return {}
    if not isinstance(overrides, dict):
        raise PartialScopeError(400, "settings_overrides must be an object.")
    unknown = sorted(k for k in overrides if k not in PARTIAL_OVERRIDE_KEYS)
    if unknown:
        raise PartialScopeError(
            400, f"settings_overrides may only set {sorted(PARTIAL_OVERRIDE_KEYS)}; "
                 f"refused: {unknown}")
    not_bool = sorted(k for k, v in overrides.items() if not isinstance(v, bool))
    if not_bool:
        raise PartialScopeError(400, f"settings_overrides must be true/false: {not_bool}")
    return dict(overrides)


_GROUP_MODES = ('exact', 'enumerate')


def _clean_host(value) -> str:
    host = str(value or '').strip().lower()
    return host if host and _BATCH_ROOT_CHARSET.match(host) and '..' not in host else ''


def _group_from_webapp(entry) -> dict | None:
    """One validated `scopeGroups` entry, or None. Dropped, never repaired: the
    field crosses a trust boundary, and a repaired name is a target nobody approved."""
    if not isinstance(entry, dict):
        return None
    root, org = _clean_host(entry.get('scanRoot')), _clean_host(entry.get('orgDomain'))
    mode = entry.get('mode')
    hosts = entry.get('exactHosts')
    if not root or not org or mode not in _GROUP_MODES or not isinstance(hosts, list):
        return None
    if not (root == org or root.endswith('.' + org)):
        return None
    exact = [_clean_host(h) for h in hosts]
    if any(not h or h == root or not h.endswith('.' + root) for h in exact):
        return None
    if mode == 'exact' and not exact and entry.get('includeRoot') is not True:
        return None
    entries = [str(e).strip().lower() for e in entry.get('entries') or [] if isinstance(e, str)]
    return {'scanRoot': root, 'orgDomain': org, 'mode': mode,
            'includeRoot': entry.get('includeRoot') is True, 'exactHosts': exact, 'entries': entries}


def _groups_from_legacy(project: dict) -> list[dict]:
    """The pre-scopeGroups shape, read only when the webapp sends no scopeGroups
    (an older webapp). The org is unknown here (no PSL in the orchestrator), so
    the scan root stands in for it, exactly as the old model named its Domain."""
    groups: list[dict] = []
    if project.get('domainBatchMode', False):
        for entry in project.get('domainBatchGroups') or []:
            if not isinstance(entry, dict):
                continue
            root = _clean_host(entry.get('rootDomain'))
            prefixes = [str(p) for p in entry.get('prefixes') or []]
            if not root:
                continue
            exact = [_clean_host(f"{p.rstrip('.')}.{root}") for p in prefixes if p not in ('*', '.') and '*' not in p]
            groups.append({'scanRoot': root, 'orgDomain': root,
                           'mode': 'enumerate' if '*' in prefixes else 'exact',
                           'includeRoot': '.' in prefixes, 'exactHosts': [h for h in exact if h], 'entries': []})
        return groups
    target = _clean_host(project.get('targetDomain'))
    if not target:
        return []
    subs = [str(s).strip().lower() for s in project.get('subdomainList') or []]
    exact = [_clean_host(f"{s.rstrip('.')}.{target}") for s in subs if s and s != '.' and '*' not in s]
    return [{'scanRoot': target, 'orgDomain': target, 'mode': 'exact' if exact else 'enumerate',
             'includeRoot': '.' in subs, 'exactHosts': [h for h in exact if h], 'entries': []}]


def scope_groups(project: dict) -> list[dict]:
    """The project's scope groups, as the webapp derived them (GET `scopeGroups`),
    each re-validated. IP mode has none. Only when the field is ABSENT (an older
    webapp) are the legacy fields read. Batch mode with nothing valid returns []:
    the caller must refuse, never read it as "nothing to check"."""
    if project.get('ipMode', False):
        return []
    if 'scopeGroups' in project:
        groups = project.get('scopeGroups')
        return [g for g in (_group_from_webapp(e) for e in (groups if isinstance(groups, list) else [])) if g]
    return _groups_from_legacy(project)


def admits_partial_host(groups: list[dict], host: str) -> bool:
    """§4.6, partial-recon user-typed hosts: strictly under an ENUMERATE scan root,
    or one of an EXACT group's hosts; a scan root itself only when it is a target."""
    host = _clean_host(host)
    if not host:
        return False
    for g in groups:
        if host == g['scanRoot']:
            if g['includeRoot']:
                return True
            continue
        if host in g['exactHosts']:
            return True
        if g['mode'] == 'enumerate' and host.endswith('.' + g['scanRoot']):
            return True
    return False


def _batch_hosts(project: dict) -> list[str]:
    """The listed hosts of a Domain-batch project, from its derived groups.

    A wildcard entry is stored as `*.<root>`: its marker is stripped. Anything
    with a `*` elsewhere, or outside the charset, is dropped rather than repaired.
    """
    groups = project.get('domainBatchGroups')
    hosts: list[str] = []
    for entry in groups if isinstance(groups, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get('hosts'), list):
            continue
        for raw in entry['hosts']:
            host = str(raw or '').strip().lower()
            if host.startswith('*.'):
                host = host[2:]
            if host and _BATCH_ROOT_CHARSET.match(host) and '..' not in host and host not in hosts:
                hosts.append(host)
    return hosts


def ip_hostname_include_bases(project: dict) -> list[str]:
    """The base name of every hostname include entry (`*.x` and `x` both give x).

    An IP-mode record_filter run scans names under these, so they get the hard
    guardrail the webapp gives them at write: a row edited in the database or
    imported from an older release did not come through that write. Checked in
    every hostname mode, because the mode can be rescoped to record_filter later
    without the list being written again.
    """
    raw = project.get('ipHostnameInclude')
    names: list[str] = []
    for entry in raw if isinstance(raw, list) else []:
        name = str(entry or '').strip().lower().rstrip('.')
        name = name[2:] if name.startswith('*.') else name[1:] if name.startswith('*') else name
        if name and name not in names:
            names.append(name)
    return names


def guardrail_targets(project: dict) -> list[str]:
    """Every name to hard-guardrail before starting a recon, whatever the mode.

    IP mode returns the base names of the hostname include entries
    (ip_hostname_include_bases): the addresses themselves are not hard-blocked
    (hard_guardrail.is_hard_blocked), the names a record_filter run scans are.
    Otherwise the union of two sources, so neither can hide a name:

      - the webapp's `scopeGroups`: every entry, exact host, scan root and org;
      - the stored fields: each batch host and group root (a host under a
        multi-label government name, `www.isa.org.jm`, groups under a root no
        rule names, `org.jm`), or the single target and its prefix hosts. A
        target the webapp refused (its scopeGroups is then empty) is still named.
    """
    if project.get('ipMode', False):
        return ip_hostname_include_bases(project)
    names: list[str] = []

    def add(name: str) -> None:
        if name and '*' not in name and name not in names:
            names.append(name)

    for g in scope_groups(project) if 'scopeGroups' in project else []:
        for n in [*(e[2:] if e.startswith('*.') else e for e in g['entries']), *g['exactHosts'],
                  g['scanRoot'], g['orgDomain']]:
            add(n)
    if project.get('domainBatchMode', False):
        for n in _batch_hosts(project) + batch_guardrail_targets(project):
            add(n)
        return names
    target = str(project.get('targetDomain') or '').strip()
    if target:
        add(target)
        subs = project.get('subdomainList')
        for raw in subs if isinstance(subs, list) else []:
            prefix = str(raw or '').strip().lower().rstrip('.')
            if prefix:
                add(f'{prefix}.{target}')
    return names


# ---------------------------------------------------------------------------
# Partial recon: what the operator typed. The modal checks it, but the queue
# and the HTTP API accept any payload, so the orchestrator checks it again.
# ---------------------------------------------------------------------------

_IP_PREFIX_LIMITS = {4: (24, 32), 6: (120, 128)}


def _valid_user_ip(value: str) -> bool:
    """An address, or a CIDR no wider than the modal allows (/24 v4, /120 v6)."""
    import ipaddress
    try:
        if '/' in value:
            net = ipaddress.ip_network(value, strict=False)
            low, high = _IP_PREFIX_LIMITS[net.version]
            return low <= net.prefixlen <= high
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _url_host(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return (urlsplit(url.strip()).hostname or '').lower()
    except ValueError:
        return ''


# ---------------------------------------------------------------------------
# Partial recon: the RoE exclusion list. This image carries no recon/, so the
# matcher below is a copy of recon/helpers/roe_scope.py's _is_roe_excluded. It
# runs recon/tests/fixtures/roe_exclusion_vectors.json, as recon's, the agent's
# and the webapp's copies do, so none of them can drift alone.
# ---------------------------------------------------------------------------

def _roe_url_hostname(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return urlsplit(url).hostname or ''
    except ValueError:
        return ''


def _roe_normalize_host(host) -> str:
    if not isinstance(host, str):
        return ''
    host = host.strip()
    if '://' in host:
        host = _roe_url_hostname(host)
    elif host.startswith('['):
        host = host[1:].split(']', 1)[0]
    elif host.count(':') == 1:
        host = host.split(':', 1)[0]
    return host.strip().rstrip('.').lower()


def _roe_is_network(entry: str) -> bool:
    import ipaddress
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


def _roe_entry_host(entry: str) -> str:
    import ipaddress
    head = entry.split('/', 1)[0]
    try:
        ipaddress.ip_address(head)
        return head.lower()
    except ValueError:
        return _roe_normalize_host(_roe_url_hostname('//' + entry))


def _roe_normalize_entry(entry) -> str:
    if not isinstance(entry, str):
        return ''
    entry = entry.strip()
    if entry.startswith('*.'):
        rest = entry[2:]
        return '*.' + (_roe_entry_host(rest) if '/' in rest and '://' not in rest
                       else _roe_normalize_host(rest))
    if '/' in entry and '://' not in entry:
        return entry.lower() if _roe_is_network(entry) else _roe_entry_host(entry)
    return _roe_normalize_host(entry)


def is_roe_excluded(host: str, excluded_list: list) -> bool:
    """True when ``host`` matches an RoE exclusion (exact host or IP, a domain
    and its subdomains, ``*.domain`` for its subdomains only, or a CIDR)."""
    import ipaddress
    host = _roe_normalize_host(host)
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for value in excluded_list:
        entry = _roe_normalize_entry(value)
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


def _is_target_label(value, targets) -> bool:
    """``value`` is the IP-mode label of one of ``targets`` (a TargetSet): the
    address with each dot or colon as a dash, as recon/helpers/ip_placeholders.py
    spells it. A real name has a dot, or is no address once the dashes are undone."""
    import ipaddress
    if not isinstance(value, str):
        return False
    label = value.strip().lower()
    if "." in label or "-" not in label:
        return False
    for separator in (".", ":"):
        address = label.replace("-", separator)
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        return address in targets
    return False


_IP_HOSTNAME_MODE_LABELS = {'ip_only': 'IP only', 'record_only': 'Record hostnames',
                            'record_filter': 'Record + scan matching', 'scan_all': 'Record + scan all'}


def ip_typed_name_refusal(project: dict, name: str) -> str | None:
    """Why an IP-mode project refuses a hostname typed for a partial run, or None.

    The pattern half of the hostname rule, read from the project row: no name
    in ip_only or record_only (or an unknown mode); in record_filter the
    include and exclude entries decide (exclude wins, an unreadable list
    admits nothing); in scan_all any name. The hard guardrail applies to each
    typed name: accepting names here widens what partial recon takes, and no
    guardrailed root sits above them. The live DNS half (every address a
    target) runs in the container, which resolves from the scan's network.
    Mirrors typed_name_refusal in recon/partial_recon_modules/helpers.py.
    """
    from hard_guardrail import is_hard_blocked
    from recon_settings.ip_hostnames import MODES, matches, normalize_name, parse_entries
    mode = project.get('ipHostnameMode')
    mode = mode if mode in MODES else 'ip_only'
    if mode not in ('record_filter', 'scan_all'):
        return f'Hostnames on target IPs is {_IP_HOSTNAME_MODE_LABELS[mode]}: no typed hostname is scanned'
    canonical = normalize_name(name)
    if canonical is None:
        return 'not a hostname'
    blocked, why = is_hard_blocked(canonical)
    if blocked:
        return f'hard guardrail: {why}'
    if mode == 'record_filter':
        include, exclude = project.get('ipHostnameInclude'), project.get('ipHostnameExclude')
        if not isinstance(include, list) or not isinstance(exclude, list):
            return 'the hostname filter cannot be read'
        include_patterns, include_invalid = parse_entries(include)
        exclude_patterns, exclude_invalid = parse_entries(exclude)
        if include_invalid or exclude_invalid:
            return 'the hostname filter cannot be read'
        verdict = matches(canonical, include_patterns, exclude_patterns)
        if verdict.excluded:
            return f'matches an exclude entry of the hostname filter: {verdict.matched_by}'
        if not verdict.included:
            return 'matches no include entry of the hostname filter'
    return None


def filter_partial_user_input(project: dict, roots: list[str], user_inputs, user_targets, *,
                              dns_budget_s: float = 5.0):
    """The operator-typed inputs a partial run may use, and those it may not.

    Hosts (typed subdomains, URL hosts, attach targets) pass the §4.6 partial
    rule for the groups of the run's roots and the hard guardrail; in IP mode a
    URL host must be one of the project's own addresses. IPs and CIDRs get the
    modal's prefix limits. Then the RoE exclusion list: an excluded host, URL
    host, address or attach target is dropped, and a typed CIDR holding an
    excluded address becomes its other hosts. Under RoE IP or CIDR entries a
    typed name (host, URL host, the name typed IPs attach to) with an excluded
    address among those it resolves to is dropped too (D2). The container
    repeats this (recon/partial_recon_modules/helpers.py); both run
    recon/tests/fixtures/partial_typed_input_roe_vectors.json.

    One difference, on purpose: this service resolves from the compose
    network, and the scan resolves from the host's (a lab or split-horizon
    zone answers only there), so a name with no answer here is left to the
    container, which refuses it if the scan's resolver has none either. The
    lookups run inside the start request, so together they take at most
    ``dns_budget_s``; a name not answered within it is left to the container.

    IP mode (B-20, B-22): a typed address, URL host or CIDR host must be one of
    the project's targets, by address (CIDR-aware, any IPv6 spelling); a typed
    CIDR keeps only its target hosts, and IPs attach only to a target's own
    label. A typed name (host or URL host) passes ip_typed_name_refusal (none
    in ip_only / record_only, the filter in record_filter, any name in
    scan_all, the hard guardrail on each) and the RoE; the container then
    keeps it only when every address it resolves to is a target. The job
    queue and the scheduler reach this without the modal (webapp
    startScan.ts), so this is a control, not a convenience.
    Returns (user_inputs, user_targets, refused).
    """
    import ipaddress
    from hard_guardrail import is_hard_blocked
    from recon_settings.engagement import derive_roe_enabled
    refused: list[str] = []
    wanted = {r.lower() for r in roots}
    groups = [g for g in scope_groups(project) if g['scanRoot'] in wanted]
    ip_mode = bool(project.get('ipMode', False))
    ip_targets = None
    if ip_mode:
        # The listed entries: the RoE half below refuses an excluded target
        # as excluded, which is how the run report must name it.
        from recon_settings.ip_hostnames import TargetSet
        ip_targets = TargetSet.from_entries(project.get('targetIps') or [])
    # roeEnabled is derived from the limits, never read from its column.
    excluded = [e for e in project.get('roeExcludedHosts') or [] if isinstance(e, str) and e.strip()] \
        if derive_roe_enabled(project) else []

    def is_address(value: str) -> bool:
        try:
            ipaddress.ip_address(value.strip('[]'))
            return True
        except ValueError:
            return False

    # IP mode resolves no typed name here: the container checks each one
    # against the targets, which the RoE already took its addresses from.
    check_addresses = bool(excluded) and not ip_mode and any(
        entry and (_roe_is_network(entry) or is_address(entry))
        for entry in (_roe_normalize_entry(e) for e in excluded))
    answers: dict[str, list[str]] = {}
    dns_deadline = None

    def resolve(name: str) -> list[str]:
        """The addresses ``name`` has, [] when none answered within the budget."""
        import socket
        import threading
        import time
        nonlocal dns_deadline
        if dns_deadline is None:
            dns_deadline = time.monotonic() + dns_budget_s
        left = dns_deadline - time.monotonic()
        if left <= 0:
            return []
        found: list[str] = []

        def lookup() -> None:
            try:
                found.extend(sorted({info[4][0].split('%')[0] for info in socket.getaddrinfo(name, None)}))
            except (OSError, UnicodeError):
                pass

        # A daemon thread, so a resolver that hangs past the budget costs the
        # request nothing more.
        worker = threading.Thread(target=lookup, daemon=True)
        worker.start()
        worker.join(left)
        return [] if worker.is_alive() else list(found)

    def host_refusal(host: str):
        """None when the scope admits ``host`` (lower-cased), else what the
        refusal line adds after the value ('' for the plain scope refusal)."""
        if ip_mode:
            h = host.strip().rstrip('.')
            if is_address(h) or '/' in h:
                return None if h.strip('[]') in ip_targets else ''
            why = ip_typed_name_refusal(project, h)
            return None if why is None else f' ({why})'
        return None if admits_partial_host(groups, host) and not is_hard_blocked(host)[0] else ''

    def typed_host(value: str) -> str:
        """An IP-mode name in the rule's canonical spelling, as the container's S holds it."""
        host = value.strip().lower()
        if ip_mode and not is_address(host):
            from recon_settings.ip_hostnames import normalize_name
            return normalize_name(host) or host
        return host

    def keep_targets(ip: str, hosts: list[str]) -> list[str]:
        """IP mode: the target addresses among what ``ip`` stands for (itself,
        or a typed CIDR's hosts), the rest refused."""
        if not ip_mode:
            return hosts
        inside = [h for h in hosts if h in ip_targets]
        if len(inside) < len(hosts):
            outside = [h for h in hosts if h not in inside]
            shown = ', '.join(outside[:5]) + (', ...' if len(outside) > 5 else '')
            refused.append(f'ip {shown}' + (f' in {ip!r}' if '/' in ip else '')
                           + " (not one of the project's target IPs)")
        return inside

    def roe_out(host_or_ip: str) -> bool:
        return bool(excluded) and is_roe_excluded(host_or_ip, excluded)

    def refuse_roe(what: str) -> None:
        refused.append(f'{what} (excluded by the Rules of Engagement)')

    def address_refused(what: str, host: str) -> bool:
        """Refuse a typed name with an excluded address among those it
        resolves to; True when refused. Each name is resolved once."""
        name = host.strip().rstrip('.').lower()
        if not check_addresses or not name or is_address(name):
            return False
        if name not in answers:
            answers[name] = resolve(name)
        cut = [a for a in answers[name] if is_roe_excluded(a, excluded)]
        if not cut:
            return False
        refused.append(f"{what} (resolves to {', '.join(cut[:5])}{', ...' if len(cut) > 5 else ''},"
                       f" excluded by the Rules of Engagement)")
        return True

    def keep_hosts(values, label):
        kept = []
        for v in values if isinstance(values, list) else []:
            why = host_refusal(v.strip().lower()) if isinstance(v, str) else ''
            if why is not None:
                refused.append(f'{label} {v!r}{why}')
            elif roe_out(v):
                refuse_roe(f'{label} {v!r}')
            elif not address_refused(f'{label} {v!r}', v):
                kept.append(typed_host(v))
        return kept

    inputs = keep_hosts(user_inputs, 'subdomain')
    targets = None
    if isinstance(user_targets, dict):
        targets = dict(user_targets)
        if 'subdomains' in targets:
            targets['subdomains'] = keep_hosts(targets['subdomains'], 'subdomain')
        if 'urls' in targets:
            kept = []
            for u in targets['urls'] if isinstance(targets['urls'], list) else []:
                why = host_refusal(_url_host(u)) if isinstance(u, str) else ''
                if why is not None:
                    refused.append(f'url {u!r}{why}')
                elif roe_out(_url_host(u)):
                    refuse_roe(f'url {u!r}')
                elif not address_refused(f'url {u!r}', _url_host(u)):
                    kept.append(u.strip())
            targets['urls'] = kept
        if 'ips' in targets:
            kept = []
            for ip in targets['ips'] if isinstance(targets['ips'], list) else []:
                if not (isinstance(ip, str) and _valid_user_ip(ip.strip())):
                    refused.append(f'ip {ip!r}')
                    continue
                ip = ip.strip()
                if '/' not in ip:
                    if roe_out(ip):
                        refuse_roe(f'ip {ip!r}')
                    else:
                        kept.extend(keep_targets(ip, [ip]))
                    continue
                # The container's modules expand a CIDR to .hosts(); the same
                # expansion here keeps exactly the addresses they would scan.
                network = ipaddress.ip_network(ip, strict=False)
                hosts = [str(h) for h in network.hosts()] if excluded or ip_mode else []
                cut = {h for h in hosts if roe_out(h)}
                if cut and len(cut) == len(hosts):
                    refuse_roe(f'ip {ip!r}')
                    continue
                if cut:
                    shown = ', '.join(sorted(cut)[:5]) + (', ...' if len(cut) > 5 else '')
                    refuse_roe(f'ip {shown} in {ip!r}')
                left = [h for h in hosts if h not in cut]
                inside = keep_targets(ip, left)
                if not cut and len(inside) == len(left):
                    kept.append(ip)
                else:
                    kept.extend(inside)
            targets['ips'] = kept
        # ip_attach_to names a Subdomain, url_attach_to a BaseURL. In IP mode
        # url_attach_to is a graph node the container looks up, and ip_attach_to
        # may only be a target's own label: every module writes it as a
        # source-less RESOLVES_TO that later runs read as forward DNS (B-20).
        # An excluded one is dropped in either mode. An ip_attach_to name is
        # also checked on its addresses, as modules hand it to tools that
        # resolve it (httpx's by_host); url_attach_to is only a graph link.
        for key, host_of in (('ip_attach_to', str), ('url_attach_to', _url_host)):
            value = targets.get(key)
            if value and ip_mode and key == 'ip_attach_to' and not _is_target_label(value, ip_targets):
                refused.append(f"{key} {value!r} (not a target's own label)")
                targets[key] = None
            elif value and not ip_mode and not (
                    isinstance(value, str) and host_refusal(host_of(value).strip().lower()) is None):
                refused.append(f'{key} {value!r}')
                targets[key] = None
            elif value and isinstance(value, str) and roe_out(host_of(value)):
                refuse_roe(f'{key} {value!r}')
                targets[key] = None
            elif value and key == 'ip_attach_to' and isinstance(value, str) and address_refused(
                    f'{key} {value!r}', value):
                targets[key] = None
        if 'ports' in targets:
            ports = targets['ports'] if isinstance(targets['ports'], list) else []
            targets['ports'] = [p for p in ports if isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535]
            refused.extend(f'port {p!r}' for p in ports if p not in targets['ports'])
    return inputs, targets, refused
