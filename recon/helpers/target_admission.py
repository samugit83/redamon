"""
RedAmon - target admission (design decision D2)
===============================================
One gate for every tool target list, called at the last point before traffic
leaves. A name is checked against the RoE host entries; every address it
resolved to is checked against the RoE IP and CIDR entries; a bare IP is checked
against both. ``ROE_EXCLUDED_HOSTS`` is matched by ``roe_scope._is_roe_excluded``,
so a host, a domain, ``*.domain``, an IP and a CIDR mean here what they mean
everywhere else.

With no RoE exclusion in force the gate is inert: every admit function hands its
input back unchanged (the same objects), logs nothing and notes nothing, so a
builder that calls it builds byte-identical target files.

Scope is not re-checked here: every builder's input is already scoped
(``merge_group_hosts``, ``merge_discovered_hostnames``, partial recon's
``_GraphScope``).

IP mode (the recon dict's ``metadata.ip_mode`` with its ``expanded_ips``) adds
the target-list rule, and the gate is never inert then: an address is admitted
only when it is one of the targets (CIDR-aware, any IPv6 spelling), a name only
when it has a known address and every one is a target, and an IP-mode label
(``ip_placeholders``) is never a name, only the address it stands for. Private
targets pass: the rule is membership, never routability. Membership is
``recon_settings.ip_hostnames.TargetSet``, the one implementation every service
shares, imported only on the IP-mode path.
"""

import ipaddress
import socket
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Union
from urllib.parse import urlsplit

from recon.helpers.ip_placeholders import is_placeholder
from recon.helpers.roe_scope import _is_network, _is_roe_excluded, _normalize_scope_entry

# Refusal reasons, also coverage tokens: [a-z0-9_], at most 64 characters.
REASON_ROE_EXCLUDED = "roe_excluded"
REASON_ROE_UNRESOLVED = "roe_unresolved"
# IP mode: not one of the run's target addresses. A decision, not a coverage
# gap: logged, never noted, so it changes no prune.
REASON_OUTSIDE_TARGETS = "outside_targets"

# Every RoE refusal is recorded under this coverage source, so the report's
# Coverage Limitations block can say what the RoE kept out of the run.
COVERAGE_SOURCE = "roe_excluded"

_ADDRESS_DETAIL = {REASON_ROE_EXCLUDED: "address excluded",
                   REASON_OUTSIDE_TARGETS: "address outside the targets"}
# (every address refused, some addresses refused)
_NAME_DETAIL = {REASON_ROE_EXCLUDED: ("every address excluded", "resolves to an excluded address"),
                REASON_OUTSIDE_TARGETS: ("no address is a target", "resolves outside the targets")}

_LOG_SHOWN = 10

# target_set's memo: a few lists at most (one run per process; a test may build
# several).
_TARGET_SETS: "OrderedDict[Tuple[str, ...], object]" = OrderedDict()
_TARGET_SETS_LOCK = threading.Lock()
_TARGET_SETS_MAX = 4


@dataclass(frozen=True)
class AdmissionContext:
    excluded: Tuple[str, ...]
    ip_rules: bool              # an IP or CIDR entry is among ``excluded``
    ip_mode: bool
    expanded_ips: Tuple[str, ...]
    metadata: Mapping = field(default_factory=dict, compare=False, hash=False)
    # IP mode's target list as a recon_settings TargetSet; None outside IP
    # mode, and for a dict that declares no ``expanded_ips`` at all (a
    # declared empty list admits nothing).
    targets: Optional[object] = field(default=None, compare=False, hash=False)

    @property
    def active(self) -> bool:
        return bool(self.excluded) or self.targets is not None

    def authorized(self, address: str) -> bool:
        """IP mode: ``address`` is one of the IPs the operator listed (already
        RoE-filtered when the run expanded them), so it passes as is."""
        return self.targets is not None and is_target(address, self.targets)


def admission_context(settings: Optional[Mapping], recon_data: Optional[Mapping] = None) -> AdmissionContext:
    """The run's admission rules, from its settings, else from the recon dict.

    A partial-recon graph builder stamps the RoE into ``metadata.roe`` for the
    readers that get no settings; the settings win when they carry the switch.
    """
    settings = settings or {}
    metadata = (recon_data or {}).get("metadata") or {}
    roe = settings if "ROE_ENABLED" in settings else (metadata.get("roe") or {})
    entries = roe.get("ROE_EXCLUDED_HOSTS") if roe.get("ROE_ENABLED") else None
    excluded = tuple(e for e in (entries or ()) if isinstance(e, str) and e.strip())
    ip_mode = bool(metadata.get("ip_mode"))
    expanded = tuple(str(ip) for ip in (metadata.get("expanded_ips") or ()) if ip)
    return AdmissionContext(
        excluded=excluded,
        ip_rules=any(_is_ip_entry(e) for e in excluded),
        ip_mode=ip_mode,
        expanded_ips=expanded,
        metadata=metadata,
        targets=target_set(expanded) if ip_mode and "expanded_ips" in metadata else None,
    )


def target_set(entries: Iterable[str]):
    """The expanded target list (after the RoE filter) as a TargetSet.

    Built once per distinct list: every builder of a run asks for the same one,
    and a /16 takes about a third of a second to build. The set is never
    changed after it is built, so the threads of a fan-out share it.
    """
    key = tuple(str(e) for e in entries)
    with _TARGET_SETS_LOCK:
        cached = _TARGET_SETS.get(key)
        if cached is not None:
            _TARGET_SETS.move_to_end(key)
            return cached
    from recon_settings.ip_hostnames import TargetSet
    built = TargetSet.from_entries(list(key))
    with _TARGET_SETS_LOCK:
        _TARGET_SETS[key] = built
        while len(_TARGET_SETS) > _TARGET_SETS_MAX:
            _TARGET_SETS.popitem(last=False)
    return built


def is_target(address, targets) -> bool:
    """``address`` (any spelling, brackets allowed) is in ``targets``."""
    ip = _as_ip(address)
    return ip is not None and str(ip) in targets


def ip_mode_targets(recon_data: Optional[Mapping]):
    """The run's IP-mode TargetSet, or None when the gate has no target list."""
    return admission_context(None, recon_data).targets


def clamp_to_targets(recon_data: Optional[Mapping], addresses: Iterable[str]) -> List[str]:
    """IP mode: the addresses that are targets, in input order. Otherwise every
    address, unchanged: domain mode keeps its own rules."""
    targets = ip_mode_targets(recon_data)
    if targets is None:
        return list(addresses)
    return [a for a in addresses if is_target(a, targets)]


def forward_verdict(addresses: Iterable[str], targets) -> Optional[str]:
    """None when a name may be scanned on this answer: at least one address and
    every one a target. Else the selection rule's reason code
    (``no_current_resolution``, ``never_scannable_address``,
    ``resolves_outside_targets``)."""
    from recon_settings.ip_hostnames import address_verdict
    canonical = []
    for address in addresses:
        ip = _as_ip(address)
        canonical.append(str(ip) if ip is not None else address)
    return address_verdict(canonical, targets)


def ip_mode_url_admission(recon_data: Optional[Mapping], *,
                          resolve: Optional[Callable[[str], List[str]]] = None
                          ) -> Optional[Callable[[str], bool]]:
    """IP mode: ``admit(url)`` for a fetch a target steers (a JS download,
    every redirect hop, a source map, an endpoint probe). None outside IP mode,
    so the caller keeps its own default (hop_guard.admit_any).

    A URL passes when its host is a target address, or one of the run's scope
    names whose every current address is a target (resolved once per name per
    admission). A label, an unknown name or a name that does not resolve is
    refused.
    """
    targets = ip_mode_targets(recon_data)
    if targets is None:
        return None
    names = _scope_names(recon_data or {})
    resolve = resolve or _resolve
    verdicts: Dict[str, bool] = {}

    def admit(url: str) -> bool:
        host = _url_host(url)
        if not host:
            return False
        if _as_ip(host) is not None:
            return is_target(host, targets)
        if host not in names:
            return False
        if host not in verdicts:
            verdicts[host] = forward_verdict(resolve(host), targets) is None
        return verdicts[host]

    return admit


def _scope_names(recon_data: Mapping) -> Set[str]:
    """The run's names: its scope list, its subdomains and its DNS entries,
    without labels and address literals."""
    metadata = recon_data.get("metadata") or {}
    raw = [*(metadata.get("subdomain_filter") or ()), *(recon_data.get("subdomains") or ()),
           *((recon_data.get("dns") or {}).get("subdomains") or {})]
    out: Set[str] = set()
    for name in raw:
        if not isinstance(name, str):
            continue
        key = name.strip().rstrip(".").lower()
        if key and _as_ip(key) is None and not is_placeholder(key):
            out.add(key)
    return out


def _resolve(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return []
    return sorted({info[4][0].split("%")[0] for info in infos})


@dataclass(frozen=True)
class Refusal:
    target: str
    reason: str
    detail: str
    name: str = ""              # the name an address was refused for


@dataclass
class Admission:
    """What may be sent. ``names``: names a tool may resolve itself, each with
    its admitted addresses. ``split``: names some of whose addresses are
    excluded, reachable only through the admitted ones, never by name.
    ``ips``: bare IPs."""
    names: Dict[str, List[str]] = field(default_factory=dict)
    split: Dict[str, List[str]] = field(default_factory=dict)
    ips: List[str] = field(default_factory=list)
    refusals: List[Refusal] = field(default_factory=list)

    def addresses(self) -> List[str]:
        """Every admitted address, in input order, once."""
        seen = dict.fromkeys(a for addrs in (*self.names.values(), *self.split.values()) for a in addrs)
        seen.update(dict.fromkeys(self.ips))
        return list(seen)

    def ip_to_names(self) -> Dict[str, List[str]]:
        """Admitted address -> the admitted names (whole or split) behind it."""
        out: Dict[str, List[str]] = {}
        for group in (self.names, self.split):
            for name, addrs in group.items():
                for addr in addrs:
                    holders = out.setdefault(addr, [])
                    if name not in holders:
                        holders.append(name)
        return out

    def refused(self, reason: Optional[str] = None) -> List[str]:
        return [r.target for r in self.refusals if reason is None or r.reason == reason]


def admit_targets(settings: Optional[Mapping], recon_data: Optional[Mapping] = None, *,
                  names: Optional[Mapping[str, Iterable[str]]] = None,
                  ips: Iterable[str] = (),
                  module: str,
                  resolves_names: bool = False,
                  record: bool = True) -> Admission:
    """Admit the targets one tool is about to receive.

    ``names`` maps each name to the addresses the run resolved it to; ``ips``
    are bare addresses. A name with an excluded address lands in ``split``
    with its other addresses, for a tool that targets addresses (naabu by
    address, masscan, nmap). ``resolves_names``: the tool resolves names
    itself (httpx, nuclei, a crawler) and could reach such a name on the
    excluded address, so the name is also recorded as refused.

    A name with no known address is refused when RoE IP or CIDR entries exist:
    nothing shows it stays off them. That refusal is "not checked", not "gone",
    so its host is recorded cut for every source and the prune keeps its
    findings. ``record=False`` computes without logging or noting, for a reader
    that sends nothing.
    """
    ctx = admission_context(settings, recon_data)
    names = names or {}
    if not ctx.active:
        return Admission(names={n: list(a or ()) for n, a in names.items()}, ips=list(ips))

    adm = Admission()
    verdicts: Dict[str, Optional[str]] = {}

    def refused(address: str) -> Optional[str]:
        """Why ``address`` may not be sent, or None. A listed IP-mode target
        passes as is; RoE is asked before the target list, so an address both
        rules refuse is reported as the RoE's."""
        if address not in verdicts:
            if ctx.authorized(address):
                verdicts[address] = None
            elif ctx.excluded and _is_roe_excluded(address, ctx.excluded):
                verdicts[address] = REASON_ROE_EXCLUDED
            elif ctx.targets is not None:
                verdicts[address] = REASON_OUTSIDE_TARGETS
            else:
                verdicts[address] = None
        return verdicts[address]

    def admit_ip(address: str, name: str = "") -> None:
        reason = refused(address)
        if reason:
            adm.refusals.append(Refusal(address, reason, _ADDRESS_DETAIL[reason], name=name))
        elif address not in adm.ips:
            adm.ips.append(address)

    for name, given in names.items():
        addrs = list(dict.fromkeys(a for a in (given or ()) if isinstance(a, str) and a))
        if ctx.targets is not None and is_placeholder(name):
            # A label is no name a tool could resolve: only its address goes.
            for address in addrs:
                admit_ip(address)
            continue
        if _as_ip(name) is not None and name not in addrs:
            addrs.insert(0, name)
        if not addrs and _as_ip(name) is None:
            if _is_roe_excluded(name, ctx.excluded):
                adm.refusals.append(Refusal(name, REASON_ROE_EXCLUDED, "host excluded"))
            elif ctx.targets is not None:
                adm.refusals.append(Refusal(name, REASON_OUTSIDE_TARGETS, "no known address"))
            elif ctx.ip_rules:
                adm.refusals.append(Refusal(name, REASON_ROE_UNRESOLVED, "no known address"))
            else:
                adm.names[name] = []
            continue
        if _as_ip(name) is None and _is_roe_excluded(name, ctx.excluded):
            adm.refusals.append(Refusal(name, REASON_ROE_EXCLUDED, "host excluded"))
            # IP mode: an authorized address stays a target even when its PTR
            # name is excluded; the name is only a label for it.
            kept = [a for a in addrs if ctx.authorized(a)]
            if kept:
                adm.ips.extend(a for a in kept if a not in adm.ips)
            continue
        kept = [a for a in addrs if not refused(a)]
        for address in addrs:
            if address not in kept:
                reason = refused(address)
                adm.refusals.append(Refusal(address, reason, _ADDRESS_DETAIL[reason], name=name))
        # A name is refused for the target list when any of its addresses is
        # outside it, else for the RoE.
        name_reason = (REASON_OUTSIDE_TARGETS
                       if any(refused(a) == REASON_OUTSIDE_TARGETS for a in addrs)
                       else REASON_ROE_EXCLUDED)
        if not kept:
            if _as_ip(name) is None:
                adm.refusals.append(Refusal(name, name_reason, _NAME_DETAIL[name_reason][0]))
        elif len(kept) == len(addrs):
            adm.names[name] = kept
        else:
            adm.split[name] = kept
            if resolves_names:
                adm.refusals.append(Refusal(name, name_reason, _NAME_DETAIL[name_reason][1]))

    for ip in ips:
        if not isinstance(ip, str) or not ip or ip in adm.ips:
            continue
        admit_ip(ip)

    if record:
        _record(module, adm.refusals)
    return adm


def admit_ip_map(settings: Optional[Mapping], recon_data: Optional[Mapping],
                 ips: List[str], ip_to_hostnames: Dict[str, List[str]], *,
                 module: str, record: bool = True) -> Tuple[List[str], Dict[str, List[str]], Admission]:
    """For an IP-target tool (masscan, nmap): the admitted IPs, in input order,
    and the address -> names map without the refused names and addresses.

    An address reached only through excluded names is dropped with them: it is
    a target only because of those names. Inert: the inputs come back as they are.
    """
    ctx = admission_context(settings, recon_data)
    if not ctx.active:
        return ips, ip_to_hostnames, Admission(ips=list(ips))
    by_name: Dict[str, List[str]] = {}
    for ip, hostnames in (ip_to_hostnames or {}).items():
        for host in hostnames if isinstance(hostnames, list) else [hostnames]:
            if isinstance(host, str) and host:
                by_name.setdefault(host, []).append(ip)
    bare = [ip for ip in ips if not (ip_to_hostnames or {}).get(ip)]
    adm = admit_targets(settings, recon_data, names=by_name, ips=bare, module=module,
                        record=record)
    admitted = set(adm.addresses())
    holders = adm.ip_to_names()
    kept_ips = [ip for ip in ips if ip in admitted]
    kept_map: Dict[str, List[str]] = {}
    for ip, hostnames in (ip_to_hostnames or {}).items():
        if ip not in admitted:
            continue
        names = [h for h in (hostnames if isinstance(hostnames, list) else [hostnames])
                 if h in holders.get(ip, ())]
        if names:
            kept_map[ip] = names
    return kept_ips, kept_map, adm


def admit_host_targets(settings: Optional[Mapping], recon_data: Optional[Mapping],
                       ips: Set[str], hostnames: Set[str], ip_to_hostnames: Dict[str, List[str]], *,
                       module: str, resolves_names: bool = True,
                       record: bool = True) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """The ``(ips, hostnames, ip_to_hostnames)`` triple the DNS target
    extractors return, admitted.

    ``hostnames`` keeps the names a tool may resolve itself; ``ips`` every
    admitted address, a mixed name's allowed ones included; the map loses the
    refused names and addresses. Inert: the inputs come back as they are.

    IP mode: a label whose address is admitted stays in ``hostnames``, as it
    always was there (every URL builder skips a label, and a reader that lists
    the run's hosts, such as the prune's keep list, knows the host by it), but
    never in the map, so no tool is handed it as a name.
    """
    ctx = admission_context(settings, recon_data)
    if not ctx.active:
        return ips, hostnames, ip_to_hostnames
    by_name: Dict[str, List[str]] = {h: [] for h in sorted(hostnames)}
    for ip, names in (ip_to_hostnames or {}).items():
        for name in names if isinstance(names, list) else [names]:
            if isinstance(name, str) and name:
                by_name.setdefault(name, []).append(ip)
    bare = [ip for ip in sorted(ips) if not (ip_to_hostnames or {}).get(ip)]
    adm = admit_targets(settings, recon_data, names=by_name, ips=bare, module=module,
                        resolves_names=resolves_names, record=record)
    admitted = set(adm.addresses())
    holders = adm.ip_to_names()
    kept_map: Dict[str, List[str]] = {}
    for ip, names in (ip_to_hostnames or {}).items():
        if ip in admitted:
            kept = [h for h in (names if isinstance(names, list) else [names]) if h in holders.get(ip, ())]
            if kept:
                kept_map[ip] = kept
    labels = ({h for h in hostnames if is_placeholder(h) and any(a in admitted for a in by_name.get(h, ()))}
              if ctx.targets is not None else set())
    return ({ip for ip in ips if ip in admitted},
            {h for h in hostnames if h in adm.names or h in labels},
            kept_map)


def admit_urls(settings: Optional[Mapping], recon_data: Optional[Mapping], urls: List[str], *,
               module: str, record: bool = True) -> Tuple[List[str], Admission]:
    """For a tool that is handed URLs and resolves their hosts itself (httpx).

    A URL survives when its host does: an IP literal not excluded, or a name
    whose every known address (``known_addresses``) is admitted. Order kept.
    """
    ctx = admission_context(settings, recon_data)
    if not ctx.active:
        return urls, Admission()
    hosts = list(dict.fromkeys(h for h in (_url_host(u) for u in urls) if h))
    known = known_addresses(recon_data or {})
    adm = admit_targets(settings, recon_data,
                        names={h: known.get(h, []) for h in hosts if _as_ip(h) is None},
                        ips=[h for h in hosts if _as_ip(h) is not None],
                        module=module, resolves_names=True, record=record)
    ok = {*adm.names, *adm.ips}
    return [u for u in urls if not _url_host(u) or _url_host(u) in ok], adm


def known_addresses(recon_data: Mapping) -> Dict[str, List[str]]:
    """Every address the run saw each name resolve to: DNS, and the port
    scan's own name map (which also carries partial recon's graph rows)."""
    out: Dict[str, List[str]] = {}

    def add(name, address) -> None:
        if not isinstance(name, str) or not isinstance(address, str) or not address:
            return
        key = name.strip().rstrip(".").lower()
        if key:
            holders = out.setdefault(key, [])
            if address not in holders:
                holders.append(address)

    def add_ips(name, ips) -> None:
        ips = ips or {}
        for address in (ips.get("ipv4") or []) + (ips.get("ipv6") or []):
            add(name, address)

    dns = recon_data.get("dns") or {}
    domain = recon_data.get("domain") or ""
    if domain:
        add_ips(domain, (dns.get("domain") or {}).get("ips"))
    for name, entry in (dns.get("subdomains") or {}).items():
        if isinstance(entry, dict):
            add_ips(name, entry.get("ips"))
            add(name, entry.get("actual_ip"))
    port_scan = recon_data.get("port_scan") or {}
    for name, entry in (port_scan.get("by_host") or {}).items():
        if isinstance(entry, dict):
            add(name, entry.get("ip"))
            for detail in entry.get("port_details") or []:
                if isinstance(detail, dict):
                    add(name, detail.get("ip"))
    for address, names in (port_scan.get("ip_to_hostnames") or {}).items():
        for name in names if isinstance(names, list) else [names]:
            add(name, address)
    for address, entry in (port_scan.get("by_ip") or {}).items():
        if isinstance(entry, dict):
            for name in entry.get("hostnames") or []:
                add(name, address)
    return out


def _record(module: str, refusals: List[Refusal]) -> None:
    """Log each refusal once per run, and note each once per module.

    Excluded targets are a report gap only (no prune effect). A name refused
    for want of an address is cut for every source, so the prune keeps what it
    found there before. An IP-mode refusal is logged only: what is not a
    target was never the run's to check. A failure here loses the record,
    never the refusal.
    """
    if not refusals:
        return
    try:
        from recon.helpers import circuit_breaker as cb
        logged = cb.run_cache("target_admission_logged")
        noted = cb.run_cache("target_admission_noted")
        fresh_log: List[Refusal] = []
        new_excluded: List[Refusal] = []
        new_unresolved: List[Refusal] = []
        for refusal in refusals:
            key = (refusal.reason, refusal.target.lower(), refusal.name.lower())
            if not logged.get(key)[0]:
                logged.put(key, True)
                fresh_log.append(refusal)
            if refusal.reason == REASON_OUTSIDE_TARGETS:
                continue
            if not noted.get((module, *key))[0]:
                noted.put((module, *key), True)
                (new_unresolved if refusal.reason == REASON_ROE_UNRESOLVED else new_excluded).append(refusal)
        label = module or "recon"
        _log(label, [r for r in fresh_log if r.reason == REASON_ROE_EXCLUDED],
             "not sent to {n} target(s) the Rules of Engagement exclude")
        _log(label, [r for r in fresh_log if r.reason == REASON_ROE_UNRESOLVED],
             "not sent to {n} name(s) with no known address while RoE IP/CIDR exclusions are set "
             "(kept as not checked)")
        _log(label, [r for r in fresh_log if r.reason == REASON_OUTSIDE_TARGETS],
             "not sent to {n} host(s) outside the IP target list", tool="IpMode")
        if new_excluded:
            cb.note_degraded(module, entries=[{
                "source": COVERAGE_SOURCE,
                "reason": "RoE exclusion: " + _shown(new_excluded, 3),
                "skipped": len(new_excluded),
            }])
        if new_unresolved:
            cb.note_degraded(module, hosts=[r.target for r in new_unresolved],
                             host_source=COVERAGE_SOURCE,
                             reason="no known address while RoE IP/CIDR exclusions are set")
    except Exception:  # noqa: BLE001 - the refusal stands; only its record is lost
        pass


def _log(label: str, refusals: List[Refusal], text: str, tool: str = "RoE") -> None:
    if refusals:
        print(f"[-][{tool}] {label}: {text.format(n=len(refusals))}: {_shown(refusals, _LOG_SHOWN)}")


def _shown(refusals: List[Refusal], limit: int) -> str:
    from recon.helpers.circuit_breaker import safe_text
    parts = [safe_text(r.target) + (f" ({safe_text(r.name)})" if r.name else "")
             for r in refusals[:limit]]
    more = len(refusals) - limit
    return ", ".join(parts) + (f" +{more} more" if more > 0 else "")


def _is_ip_entry(entry: str) -> bool:
    normalized = _normalize_scope_entry(entry)
    return bool(normalized) and (_is_network(normalized) or _as_ip(normalized) is not None)


def _as_ip(value) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def _url_host(url) -> str:
    try:
        return (urlsplit(url).hostname or "").rstrip(".").lower() if isinstance(url, str) else ""
    except ValueError:
        return ""
