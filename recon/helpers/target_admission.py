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
``_GraphScope``). The context carries IP mode and its authorized addresses so a
mode rule can live inside ``admit_targets`` beside the RoE one.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

from recon.helpers.roe_scope import _is_network, _is_roe_excluded, _normalize_scope_entry

# Refusal reasons, also coverage tokens: [a-z0-9_], at most 64 characters.
REASON_ROE_EXCLUDED = "roe_excluded"
REASON_ROE_UNRESOLVED = "roe_unresolved"

# Every refusal is recorded under this coverage source, so the report's
# Coverage Limitations block can say what the RoE kept out of the run.
COVERAGE_SOURCE = "roe_excluded"

_LOG_SHOWN = 10


@dataclass(frozen=True)
class AdmissionContext:
    excluded: Tuple[str, ...]
    ip_rules: bool              # an IP or CIDR entry is among ``excluded``
    ip_mode: bool
    expanded_ips: Tuple[str, ...]
    metadata: Mapping = field(default_factory=dict, compare=False, hash=False)

    @property
    def active(self) -> bool:
        return bool(self.excluded)

    def authorized(self, address: str) -> bool:
        """IP mode: ``address`` is one of the IPs the operator listed (already
        RoE-filtered when the run expanded them), so it passes as is."""
        if not self.ip_mode or not self.expanded_ips:
            return False
        if address in self.expanded_ips:
            return True
        ip = _as_ip(address)
        if ip is None:
            return False
        for entry in self.expanded_ips:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False


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
    return AdmissionContext(
        excluded=excluded,
        ip_rules=any(_is_ip_entry(e) for e in excluded),
        ip_mode=bool(metadata.get("ip_mode")),
        expanded_ips=tuple(str(ip) for ip in (metadata.get("expanded_ips") or ()) if ip),
        metadata=metadata,
    )


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
    verdicts: Dict[str, bool] = {}

    def excluded(address: str) -> bool:
        if address not in verdicts:
            verdicts[address] = not ctx.authorized(address) and _is_roe_excluded(address, ctx.excluded)
        return verdicts[address]

    for name, given in names.items():
        addrs = list(dict.fromkeys(a for a in (given or ()) if isinstance(a, str) and a))
        if _as_ip(name) is not None and name not in addrs:
            addrs.insert(0, name)
        if not addrs and _as_ip(name) is None:
            if _is_roe_excluded(name, ctx.excluded):
                adm.refusals.append(Refusal(name, REASON_ROE_EXCLUDED, "host excluded"))
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
        kept = [a for a in addrs if not excluded(a)]
        for address in addrs:
            if address not in kept:
                adm.refusals.append(Refusal(address, REASON_ROE_EXCLUDED, "address excluded", name=name))
        if not kept:
            if _as_ip(name) is None:
                adm.refusals.append(Refusal(name, REASON_ROE_EXCLUDED, "every address excluded"))
        elif len(kept) == len(addrs):
            adm.names[name] = kept
        else:
            adm.split[name] = kept
            if resolves_names:
                adm.refusals.append(Refusal(name, REASON_ROE_EXCLUDED, "resolves to an excluded address"))

    for ip in ips:
        if not isinstance(ip, str) or not ip or ip in adm.ips:
            continue
        if excluded(ip):
            adm.refusals.append(Refusal(ip, REASON_ROE_EXCLUDED, "address excluded"))
        else:
            adm.ips.append(ip)

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
    found there before. A failure here loses the record, never the refusal.
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
            if not noted.get((module, *key))[0]:
                noted.put((module, *key), True)
                (new_unresolved if refusal.reason == REASON_ROE_UNRESOLVED else new_excluded).append(refusal)
        label = module or "recon"
        _log(label, [r for r in fresh_log if r.reason != REASON_ROE_UNRESOLVED],
             "not sent to {n} target(s) the Rules of Engagement exclude")
        _log(label, [r for r in fresh_log if r.reason == REASON_ROE_UNRESOLVED],
             "not sent to {n} name(s) with no known address while RoE IP/CIDR exclusions are set "
             "(kept as not checked)")
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


def _log(label: str, refusals: List[Refusal], text: str) -> None:
    if refusals:
        print(f"[-][RoE] {label}: {text.format(n=len(refusals))}: {_shown(refusals, _LOG_SHOWN)}")


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
