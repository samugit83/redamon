"""F2: a host name added after GROUP 1 gets what a discovered name gets.

``merge_discovered_hostnames`` adds uncover (GROUP 2b), tlsx (3.6), certificate
SAN (after GROUP 4) and JS Recon (5b) names with ``has_records`` alone. The
port scan reads IPs and httpx reads the port scan (its DNS fallback runs only
when the port scan found nothing), so those names were never port-scanned and,
after GROUP 4, never probed: crawlers and nuclei only guessed http(s)://host.

Here, after the helper's own guards (apex suffix, group scope, RoE, syntax,
non-routable IPs, cap, wildcard), a late name gets its DNS through the domain
step's lookup and its resolver breaker. A name added before the port scan
needs nothing else. A name added after it takes the open ports its addresses
already showed (no packet), an address nobody scanned gets the port scan, and
a name added after httpx gets one httpx probe of its own, merged into the
run's results so resource enumeration and the vulnerability scan see it.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from typing import Optional


def _dns_subdomains(combined_result: dict) -> dict:
    dns = combined_result.setdefault("dns", {})
    subs = dns.get("subdomains")
    if not isinstance(subs, dict):
        subs = dns["subdomains"] = {}
    return subs


def _ips(entry: dict) -> list:
    ips = (entry or {}).get("ips") or {}
    return [a for a in list(ips.get("ipv4") or []) + list(ips.get("ipv6") or []) if a]


def give_dns(combined_result: dict, names: list, settings: dict, lookup=None) -> list:
    """Store each name's records and A/AAAA in dns.subdomains, keeping the
    entry's `source`. Returns the names that resolved to an address. An
    address the scanner may never probe (loopback, private, metadata) drops
    the name, as discovery's guard does."""
    settings = settings or {}
    names = [n for n in dict.fromkeys(names or []) if isinstance(n, str) and n]
    if not names or not settings.get("DNS_ENABLED", True):
        return []
    if lookup is None:
        from recon.main_recon_modules.domain_recon import dns_lookup
        parallel = bool(settings.get("DNS_RECORD_PARALLELISM", True))

        def lookup(name):
            return dns_lookup(name, 3, parallel)
    from recon.main_recon_modules.ip_filter import is_non_routable_ip
    try:
        workers = max(1, min(int(settings.get("DNS_MAX_WORKERS") or 10), 20, len(names)))
    except (TypeError, ValueError):
        workers = 1
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="late-dns") as pool:
        answers = dict(zip(names, pool.map(lambda n: _safe(lookup, n), names)))
    subs = _dns_subdomains(combined_result)
    resolved = []
    for name in names:
        answer = answers.get(name)
        if not isinstance(answer, dict):
            continue
        addresses = _ips(answer)
        if any(is_non_routable_ip(a) for a in addresses):
            print(f"[!][Scope] Dropped late name {name} -> {addresses}: never a scan target")
            subs.pop(name, None)
            continue
        entry = subs.setdefault(name, {})
        source = entry.get("source")
        entry["records"] = answer.get("records") or {}
        entry["ips"] = answer.get("ips") or {"ipv4": [], "ipv6": []}
        # Kept True as the helper set it: an unresolved name stays a DNS-
        # fallback candidate, as before.
        entry["has_records"] = True
        if source:
            entry["source"] = source
        if addresses:
            resolved.append(name)
    return resolved


def _safe(fn, *args):
    try:
        return fn(*args)
    except Exception:  # noqa: BLE001
        return None


def attach_known_ports(combined_result: dict, names: list) -> list:
    """A name whose address the port scan already scanned takes that address's
    open ports (by_host, and by_ip's host list): no packet is sent. Returns the
    names with no scanned address."""
    port_scan = combined_result.get("port_scan")
    subs = _dns_subdomains(combined_result)
    if not isinstance(port_scan, dict):
        return list(names)
    by_ip = port_scan.setdefault("by_ip", {})
    by_host = port_scan.setdefault("by_host", {})
    details_of_ip = {}
    for row in by_host.values():
        if isinstance(row, dict) and row.get("ip") and row.get("port_details"):
            details_of_ip.setdefault(row["ip"], row["port_details"])
    unscanned = []
    for name in names:
        scanned = [ip for ip in _ips(subs.get(name) or {}) if ip in by_ip]
        if not scanned:
            unscanned.append(name)
            continue
        for ip in scanned:
            hosts = by_ip[ip].setdefault("hostnames", [])
            if name not in hosts:
                hosts.append(name)
        if name in by_host:
            continue
        first = by_ip[scanned[0]]
        ports = sorted({p for ip in scanned for p in by_ip[ip].get("ports") or []})
        known = {d.get("port"): d for ip in scanned for d in details_of_ip.get(ip) or []}
        by_host[name] = {
            "host": name, "ip": scanned[0], "ports": ports,
            "port_details": [copy.deepcopy(known[p]) if p in known else
                             {"port": p, "protocol": "tcp", "service": _service(p)} for p in ports],
            "cdn": first.get("cdn"), "is_cdn": bool(first.get("is_cdn")),
        }
    return unscanned


def _service(port: int) -> str:
    try:
        from recon.main_recon_modules.port_scan import get_service_name
        return get_service_name(port)
    except Exception:  # noqa: BLE001
        return "unknown"


def _subset(combined_result: dict, names: list) -> dict:
    """A recon dict holding only `names`, with the run's metadata (its scope)."""
    subs = _dns_subdomains(combined_result)
    sub = {
        "domain": combined_result.get("domain"),
        "domains": combined_result.get("domains"),
        "metadata": copy.deepcopy(combined_result.get("metadata") or {}),
        "subdomains": list(names),
        "dns": {"domain": {}, "subdomains": {n: copy.deepcopy(subs[n]) for n in names if n in subs}},
    }
    port_scan = combined_result.get("port_scan") or {}
    by_host = {n: copy.deepcopy(port_scan.get("by_host", {})[n]) for n in names
               if n in (port_scan.get("by_host") or {})}
    if by_host:
        ips = {row.get("ip") for row in by_host.values()}
        sub["port_scan"] = {"by_host": by_host,
                            "by_ip": {ip: copy.deepcopy(row) for ip, row in
                                      (port_scan.get("by_ip") or {}).items() if ip in ips}}
    return sub


def _merge_port_scan(combined_result: dict, fresh: dict) -> None:
    port_scan = combined_result.setdefault("port_scan", {"by_host": {}, "by_ip": {}, "all_ports": []})
    for key in ("by_host", "by_ip"):
        port_scan.setdefault(key, {}).update(fresh.get(key) or {})
    port_scan["all_ports"] = sorted(set(port_scan.get("all_ports") or []) | set(fresh.get("all_ports") or []))


def _merge_http_probe(combined_result: dict, fresh: dict) -> list:
    http_probe = combined_result.setdefault("http_probe", {})
    new_urls = [u for u in (fresh.get("by_url") or {}) if u not in (http_probe.get("by_url") or {})]
    for key in ("by_url", "by_host", "technologies_found"):
        if isinstance(fresh.get(key), dict):
            http_probe.setdefault(key, {}).update(fresh[key])
    return new_urls


def scan_late_names(combined_result: dict, names: list, settings: dict, *, probe_http: bool,
                    label: str, port_scanner=None, http_prober=None) -> Optional[dict]:
    """The F2 step for names merged after the port scan. Returns the subset
    recon dict the caller writes to the graph (its DNS, ports and pages), or
    None when no name resolved. Never raises."""
    settings = settings or {}
    try:
        resolved = give_dns(combined_result, names, settings)
        if not resolved:
            return None
        unscanned = attach_known_ports(combined_result, resolved)
        if unscanned and "port_scan" in combined_result and settings.get("NAABU_ENABLED", True):
            if port_scanner is None:
                from recon.main_recon_modules.port_scan import run_port_scan as port_scanner
            print(f"[*][{label}] Port scan of {len(unscanned)} late name(s) on unscanned addresses")
            sub = _subset(combined_result, unscanned)
            port_scanner(sub, output_file=None, settings=settings)
            if sub.get("port_scan"):
                _merge_port_scan(combined_result, sub["port_scan"])
        sub = _subset(combined_result, resolved)
        if probe_http and settings.get("HTTPX_ENABLED", True):
            if http_prober is None:
                from recon.main_recon_modules.http_probe import run_http_probe as http_prober
            print(f"[*][{label}] httpx probe of {len(resolved)} late name(s)")
            probed = _subset(combined_result, resolved)
            http_prober(probed, output_file=None, settings=settings)
            if probed.get("http_probe"):
                new_urls = _merge_http_probe(combined_result, probed["http_probe"])
                sub["http_probe"] = probed["http_probe"]
                print(f"[+][{label}] {len(new_urls)} new live URL(s) from late names")
        return sub
    except Exception as e:  # noqa: BLE001
        print(f"[!][{label}] late-name scan failed: {e}")
        return None
