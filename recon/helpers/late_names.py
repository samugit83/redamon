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

IP mode (``targets`` given) scans only names the hostname selection rule
pinned, on that pinned answer (design §5.5): no second lookup, every address a
target, no second port scan.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional


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


def give_pinned(combined_result: dict, names: list, pinned: dict, targets) -> list:
    """IP mode: store each name's pinned answer as its DNS and return the names
    kept. A name whose answer is empty, never scannable or not wholly on the
    targets is dropped: the late scan sends nothing anywhere else (I-1)."""
    from recon_settings.ip_hostnames import address_verdict
    subs = _dns_subdomains(combined_result)
    kept = []
    for name in dict.fromkeys(n for n in names or [] if isinstance(n, str) and n):
        answer = [str(a) for a in (pinned or {}).get(name) or []]
        if address_verdict(answer, targets) is not None:
            print(f"[!][Scope] Dropped late name {name} -> {answer}: not every address is a target")
            subs.pop(name, None)
            continue
        v4 = [a for a in answer if ":" not in a]
        v6 = [a for a in answer if ":" in a]
        entry = subs.setdefault(name, {})
        entry["ips"] = {"ipv4": v4, "ipv6": v6}
        entry.setdefault("records", {k: v for k, v in (("A", v4), ("AAAA", v6)) if v})
        entry["has_records"] = True
        kept.append(name)
    return kept


def attach_known_ports(combined_result: dict, names: list, targets=None) -> list:
    """A name whose address the port scan already scanned takes that address's
    open ports (by_host, and by_ip's host list): no packet is sent. Returns the
    names with no scanned address.

    With ``targets`` (IP mode) the port scan covered every target IP, so a
    target it did not report is one with no open port: the name is scanned
    with zero ports, never handed to a second port scan."""
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
        addresses = _ips(subs.get(name) or {})
        scanned = [ip for ip in addresses if ip in by_ip]
        if not scanned and targets is not None and addresses and all(ip in targets for ip in addresses):
            if name not in by_host:
                by_host[name] = {"host": name, "ip": addresses[0], "ports": [], "port_details": [],
                                 "cdn": None, "is_cdn": False}
            continue
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
        if targets is None:
            details = _details_per_address(by_host, by_ip, scanned, ports)
        else:
            known = {d.get("port"): d for ip in scanned for d in details_of_ip.get(ip) or []}
            details = [copy.deepcopy(known[p]) if p in known else
                       {"port": p, "protocol": "tcp", "service": _service(p)} for p in ports]
        by_host[name] = {
            "host": name, "ip": scanned[0], "ports": ports, "port_details": details,
            "cdn": first.get("cdn"), "is_cdn": bool(first.get("is_cdn")),
        }
    return unscanned


def _details_per_address(by_host: dict, by_ip: dict, scanned: list, ports: list) -> list:
    """A domain run's late name on several addresses: one detail per address
    and port, a copy of that address's own (its banner, product), naming the
    address so the graph writer puts it there and not on the first one."""
    known = {}
    for row in by_host.values():
        if isinstance(row, dict) and row.get("ip"):
            for d in row.get("port_details") or []:
                if isinstance(d, dict):
                    known.setdefault((d.get("ip") or row["ip"], d.get("port")), d)
    details = []
    for p in ports:
        for ip in scanned:
            if p not in (by_ip[ip].get("ports") or []):
                continue
            seen = known.get((ip, p))
            detail = copy.deepcopy(seen) if seen else {"port": p, "protocol": "tcp", "service": _service(p)}
            detail["ip"] = ip
            details.append(detail)
    return details


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


# Summary counters that are not a function of the merged rows: each probe
# counted its own, so a merge adds them.
_SUMMED_COUNTERS = ("filtered_out_of_scope", "ai_header_matches", "ai_favicon_matches",
                    "ai_title_matches", "ai_wappalyzer_matches", "wappalyzer_additions")


def _names(value) -> set:
    return {v for v in value if isinstance(v, str) and v} if isinstance(value, list) else set()


def _recount(http_probe: dict, added: Optional[dict] = None, merge: bool = False) -> None:
    """Rebuild the counts http_probe.parse_httpx_output derives from its rows,
    after rows were merged in (`merge`) or dropped; `added` is the other probe's
    summary, whose own counters are summed in.

    Technologies and servers are read from the rows too: Wappalyzer's finds
    are folded into each row's technologies and the summary, never into
    technologies_found. A merge also keeps both summaries' names and never
    lowers the run's counts, so Domain.http_probe_technology_count never
    shrinks because names were added."""
    by_url = http_probe.get("by_url") or {}
    by_host = http_probe.get("by_host") or {}
    rows = [i for i in by_url.values() if isinstance(i, dict)]
    summary = dict(http_probe.get("summary") or {})
    techs = set(http_probe.get("technologies_found") or {}) | {t for i in rows for t in _names(i.get("technologies"))}
    servers = set(http_probe.get("servers_found") or {}) | _names([i.get("server") for i in rows])
    if merge:
        for side in (summary, added or {}):
            techs |= _names(side.get("unique_technologies"))
            servers |= _names(side.get("unique_servers"))
    codes: dict = {}
    for info in rows:
        code = info.get("status_code")
        if code:
            codes[str(code)] = codes.get(str(code), 0) + 1

    def floor(key, count):
        old = summary.get(key)
        return max(count, old) if merge and isinstance(old, int) else count

    summary.update({
        "total_urls_probed": len(by_url),
        "live_urls": sum(1 for i in rows if isinstance(i.get("status_code"), int) and i["status_code"] < 500),
        "total_hosts": len(by_host),
        "by_status_code": codes,
        "unique_technologies": sorted(techs),
        "technology_count": floor("technology_count", len(techs)),
        "unique_servers": sorted(servers),
        "server_count": floor("server_count", len(servers)),
        "cdn_hosts": sum(1 for h in by_host.values() if isinstance(h, dict) and any(
            (by_url.get(u) or {}).get("is_cdn") for u in h.get("urls") or [])),
    })
    for key in _SUMMED_COUNTERS:
        if added and isinstance(added.get(key), int):
            summary[key] = int(summary.get(key) or 0) + added[key]
    http_probe["summary"] = summary


def _merge_http_probe(combined_result: dict, fresh: dict) -> list:
    """Merge a late probe into the run's http_probe: rows, the per-technology
    and per-server URL lists (unions: both probes may see one technology), the
    redirects off the host, and a summary that counts both (B-30)."""
    http_probe = combined_result.setdefault("http_probe", {})
    new_urls = [u for u in (fresh.get("by_url") or {}) if u not in (http_probe.get("by_url") or {})]
    for key in ("by_url", "by_host"):
        if isinstance(fresh.get(key), dict):
            http_probe.setdefault(key, {}).update(fresh[key])
    for key in ("technologies_found", "servers_found"):
        if isinstance(fresh.get(key), dict):
            merged = http_probe.setdefault(key, {})
            for item, urls in fresh[key].items():
                holders = merged.setdefault(item, [])
                holders.extend(u for u in urls or [] if u not in holders)
    if isinstance(fresh.get("external_domains"), list):
        known = http_probe.setdefault("external_domains", [])
        known.extend(e for e in fresh["external_domains"] if e not in known)
    if new_urls or isinstance(fresh.get("summary"), dict):
        _recount(http_probe, fresh.get("summary") if isinstance(fresh.get("summary"), dict) else None,
                 merge=True)
    return new_urls


def _with_run_summary(fresh: dict, combined_result: dict) -> dict:
    """The late probe's rows for the graph, with the RUN's merged summary: the
    http writer stamps the summary's counts on the Domain, and the late probe's
    own would replace the run's live URLs with its few."""
    summary = (combined_result.get("http_probe") or {}).get("summary")
    return {**fresh, "summary": dict(summary)} if isinstance(summary, dict) else fresh


def drop_http_rows(http_probe: dict, host: str) -> list:
    """Remove every row of ``host`` from an http_probe block and recount it.
    Returns the URLs removed. The IP-mode post-probe guard uses it when a
    selected name answered from an address outside the targets."""
    by_url = (http_probe or {}).get("by_url") or {}
    dropped = [u for u, info in by_url.items()
               if isinstance(info, dict) and str(info.get("host") or "").lower().rstrip(".") == host]
    if not dropped:
        return []
    for url in dropped:
        by_url.pop(url, None)
    (http_probe.get("by_host") or {}).pop(host, None)
    for key in ("technologies_found", "servers_found"):
        lists = http_probe.get(key) or {}
        for item in list(lists):
            lists[item] = [u for u in lists[item] or [] if u not in dropped]
            if not lists[item]:
                del lists[item]
    _recount(http_probe)
    return dropped


def _scan_pinned(combined_result: dict, names: list, settings: dict, *, probe_http: bool, label: str,
                 pinned: dict, targets, http_prober, on_error) -> Optional[dict]:
    try:
        resolved = give_pinned(combined_result, names, pinned, targets)
        if not resolved:
            return None
        has_port_scan = isinstance(combined_result.get("port_scan"), dict)
        attach_known_ports(combined_result, resolved, targets=targets)
        sub = _subset(combined_result, resolved)
        by_host = (combined_result.get("port_scan") or {}).get("by_host") or {}
        # A name on addresses with no open port has nothing to probe; the
        # subset still carries the port scan, so httpx never guesses ports
        # for it (it does that only without port data, as for a run with no
        # port scanner at all, where the names follow the addresses).
        probe = ([n for n in resolved if (by_host.get(n) or {}).get("ports")] if has_port_scan
                 else list(resolved))
        sub["late_probed"] = []
        if probe_http and settings.get("HTTPX_ENABLED", True) and probe:
            if http_prober is None:
                from recon.main_recon_modules.http_probe import run_http_probe as http_prober
            print(f"[*][{label}] httpx probe of {len(probe)} selected hostname(s) on target IPs")
            probed = _subset(combined_result, probe)
            if has_port_scan:
                probed.setdefault("port_scan", {"by_host": {}, "by_ip": {}})
            # The post-probe guard reads the address httpx reached.
            http_prober(probed, output_file=None, settings={**settings, "HTTPX_PROBE_IP": True})
            sub["late_probed"] = probe
            if probed.get("http_probe"):
                new_urls = _merge_http_probe(combined_result, probed["http_probe"])
                sub["http_probe"] = _with_run_summary(probed["http_probe"], combined_result)
                print(f"[+][{label}] {len(new_urls)} new live URL(s) from selected hostnames")
        return sub
    except Exception as e:  # noqa: BLE001 - the names lose their probe, never the run
        print(f"[!][{label}] late-name scan failed ({type(e).__name__}): "
              f"earlier findings on {len(names)} hostname(s) are kept")
        try:
            from recon.helpers import circuit_breaker
            circuit_breaker.note_degraded("ip_hostnames", hosts=list(names), host_source="ip_hostnames",
                                          reason="late-name scan failed")
            if on_error is not None:
                on_error(e)
        except Exception:  # noqa: BLE001
            pass
        return None


def scan_late_names(combined_result: dict, names: list, settings: dict, *, probe_http: bool,
                    label: str, port_scanner=None, http_prober=None, pinned: Optional[dict] = None,
                    targets=None, on_error: Optional[Callable[[Exception], None]] = None) -> Optional[dict]:
    """The F2 step for names merged after the port scan. Returns the subset
    recon dict the caller writes to the graph (its DNS, ports and pages), or
    None when no name resolved. Never raises.

    IP mode passes ``targets`` (the run's TargetSet) and ``pinned`` (each
    name's answer from the selection rule): see _scan_pinned. A failure there
    notes the names degraded and calls ``on_error``, so the caller can report
    the http_probe phase."""
    settings = settings or {}
    if targets is not None:
        return _scan_pinned(combined_result, names, settings, probe_http=probe_http, label=label,
                            pinned=pinned or {}, targets=targets, http_prober=http_prober, on_error=on_error)
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
                sub["http_probe"] = _with_run_summary(probed["http_probe"], combined_result)
                print(f"[+][{label}] {len(new_urls)} new live URL(s) from late names")
        return sub
    except Exception as e:  # noqa: BLE001
        print(f"[!][{label}] late-name scan failed: {e}")
        return None
