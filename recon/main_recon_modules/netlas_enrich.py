"""
Netlas Pipeline Enrichment Module

Passive OSINT using Netlas Responses search API. Domain mode uses
`host:{domain}`; IP mode uses `host:{ip}` per address. Optional key rotation
via NETLAS_KEY_ROTATOR.
"""
from __future__ import annotations

import time
import logging
import threading
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from recon.main_recon_modules.ip_filter import (
        collect_cdn_ips, filter_ips_for_enrichment, in_published_cdn_range, is_shared_edge_org)
except ImportError:
    from ip_filter import (
        collect_cdn_ips, filter_ips_for_enrichment, in_published_cdn_range, is_shared_edge_org)

logger = logging.getLogger(__name__)

NETLAS_API_BASE = "https://app.netlas.io/api"


class _RateLimiter:
    """Thread-safe rate limiter."""
    def __init__(self, interval: float):
        self._interval = interval
        self._lock = threading.Lock()
        self._last = 0.0
    def wait(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            delay = self._interval - elapsed if elapsed < self._interval else 0.0
            self._last = now + delay
        if delay > 0:
            time.sleep(delay)


def _extract_ips_from_recon(combined_result: dict) -> list[str]:
    """Extract unique IPv4 addresses from domain discovery results."""
    ips: set[str] = set()
    dns_data = combined_result.get("dns", {})

    domain_dns = dns_data.get("domain", {})
    for ip in domain_dns.get("ips", {}).get("ipv4", []):
        if ip:
            ips.add(ip)

    for _sub, info in dns_data.get("subdomains", {}).items():
        for ip in info.get("ips", {}).get("ipv4", []):
            if ip:
                ips.add(ip)

    # IP mode: the target list only. A DNS answer (a PTR name's forward
    # address) need not be a target, and the lookup would be about it. A dict
    # that declares no list asks about nothing (every IP-mode builder declares it).
    metadata = combined_result.get("metadata") or {}
    if metadata.get("ip_mode"):
        return sorted({ip for ip in metadata.get("expanded_ips") or [] if ip})

    return sorted(ips)


def _netlas_breaker():
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker("netlas:responses", label="Netlas", parent="netlas")


def _netlas_classify(resp):
    """Netlas refuses an unknown key with HTTP 400 "API key not found", not 401.

    The body is read only to tell that 400 from a malformed query; it is never kept.
    """
    from recon.helpers import circuit_breaker as cb
    if cb.status_of(resp) == 400:
        try:
            refused = "api key" in str(resp.text or "").lower()
        except Exception:  # noqa: BLE001
            refused = False
        if refused:
            return cb.CallResult(None, cb.Outcome.FATAL, "400 key rejected")
    return cb.json_result(resp, keyed=True)


def _netlas_responses_get(q: str, keys, size: int, *, admitted: bool = False):
    """GET /responses/ with X-API-Key through the Netlas breaker; returns a CallResult."""
    from recon.helpers import circuit_breaker as cb
    url = f"{NETLAS_API_BASE}/responses/"
    params = {"q": q, "size": max(1, min(int(size), 1000))}

    def send(key):
        return requests.get(url, headers={"X-API-Key": key}, params=params, timeout=30)

    return cb.guarded_call(_netlas_breaker(), send, _netlas_classify, keys=keys,
                           admitted=admitted)


def _transport_protocol(data: dict) -> str:
    """The item's layer-4 protocol, the Port's key: tcp unless Netlas says udp.

    A Port keyed on the application protocol is a second node beside the port
    scan's {443, tcp} for the same socket.
    """
    prot4 = str(data.get("prot4") or "").strip().lower()
    return prot4 if prot4 in ("tcp", "udp") else "tcp"


def _netlas_item_to_result(data: dict) -> dict | None:
    """Map one responses item's data blob to output row."""
    if not isinstance(data, dict):
        return None
    http = data.get("http") or {}
    if not isinstance(http, dict):
        http = {}
    title = http.get("title") or ""
    http_status_code = http.get("status_code")

    geo = data.get("geo") or {}
    if not isinstance(geo, dict):
        geo = {}
    country = str(geo.get("country") or "")
    city = str(geo.get("city") or "")
    latitude = geo.get("latitude")
    longitude = geo.get("longitude")
    timezone = str(geo.get("time_zone") or "")

    geo_asn = geo.get("asn") or {}
    if not isinstance(geo_asn, dict):
        geo_asn = {}
    asn_number = str(geo_asn.get("number") or "")   # e.g. "AS14618"
    asn_route = str(geo_asn.get("route") or "")      # e.g. "44.224.0.0/11"

    whois = data.get("whois") or {}
    if not isinstance(whois, dict):
        whois = {}
    asn_block = whois.get("asn") or {}
    if not isinstance(asn_block, dict):
        asn_block = {}
    asn_name = asn_block.get("name") or ""

    # Protocol-specific service banners
    banner = ""
    for bk in ("ssh", "ftp", "smtp", "imap", "pop3", "telnet", "rdp"):
        proto_block = data.get(bk) or {}
        if isinstance(proto_block, dict) and proto_block.get("banner"):
            banner = str(proto_block["banner"])
            break

    # CVE/vulnerability data (passive NVD-based detection)
    cve_raw = data.get("cve") or []
    cve_list: list[dict] = []
    if isinstance(cve_raw, list):
        for cve_item in cve_raw:
            if not isinstance(cve_item, dict):
                continue
            cve_id = cve_item.get("name") or cve_item.get("id") or ""
            if not cve_id:
                continue
            cve_list.append({
                "id": str(cve_id),
                "base_score": cve_item.get("base_score"),
                "severity": str(cve_item.get("severity") or "").lower(),
                "has_exploit": bool(cve_item.get("has_exploit", False)),
            })

    host = data.get("host") or ""
    ip = data.get("ip") or ""
    port = data.get("port")
    try:
        port_i = int(port) if port is not None else 0
    except (TypeError, ValueError):
        port_i = 0
    # The application protocol (http, ssh): it names the Service, never the Port.
    protocol = data.get("protocol") or data.get("prot7") or ""

    return {
        "host": str(host) if host is not None else "",
        "ip": str(ip) if ip is not None else "",
        "port": port_i,
        "protocol": str(protocol) if protocol is not None else "",
        "transport": _transport_protocol(data),
        "title": str(title) if title is not None else "",
        "http_status_code": http_status_code,
        "country": country,
        "city": city,
        "latitude": latitude,
        "longitude": longitude,
        "timezone": timezone,
        "isp": str(data.get("isp") or ""),
        "asn_name": str(asn_name),
        "asn_number": asn_number,
        "asn_route": asn_route,
        "banner": banner,
        "cve_list": cve_list,
    }


def _parse_netlas_body(body: dict | None) -> tuple[list[dict], int]:
    if not body:
        return [], 0
    items = body.get("items") or []
    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        d = item.get("data")
        row = _netlas_item_to_result(d if isinstance(d, dict) else {})
        if row:
            results.append(row)
    total = body.get("total")
    if total is None:
        total = body.get("count")
    if total is None:
        total = len(results)
    return results, int(total)


def _attribute_rows(rows: list[dict], dns_ips, combined_result: dict) -> None:
    """Tag the rows that must not become a finding.

    Netlas answers from its index, history included: domain mode asks for
    every response it ever stored for the name. A row for an IP this run's
    DNS does not give is `historical` and stays out of the graph entirely: the
    IP may be another tenant's machine now, and an IP node would put it in
    later scans' targets. A row for a CDN or shared edge IP is `shared_edge`:
    its ports are the provider's, and its CVEs describe the provider and its
    other tenants, so it gets no CVE finding. In a partial run that includes
    the IPs the graph's IP attribution tag names (the full run applies the tag
    later, with retag_shared_edge).
    """
    from recon.main_recon_modules.ip_attribution import shared_edge_ips
    current = set(dns_ips)
    cdn = collect_cdn_ips(combined_result) | shared_edge_ips(combined_result)
    for row in rows:
        ip = row.get("ip")
        if ip not in current:
            row["attribution"] = "historical"
        elif (ip in cdn or in_published_cdn_range(ip)
              or is_shared_edge_org(f"{row.get('isp') or ''} {row.get('asn_name') or ''}")):
            row["attribution"] = "shared_edge"


def retag_shared_edge(netlas_data: dict, edge_ips) -> int:
    """Mark the rows of the IPs IP attribution tagged shared_edge. Returns how many.

    In a full run Netlas answers before http_probe, so _attribute_rows could
    not see the tag; the pipeline holds the write back and applies it here. A
    `historical` row stays historical: it never reaches the graph at all.
    """
    edge_ips = set(edge_ips or ())
    marked = 0
    for row in netlas_data.get("results") or []:
        if (isinstance(row, dict) and row.get("ip") in edge_ips
                and row.get("attribution") not in ("historical", "shared_edge")):
            row["attribution"] = "shared_edge"
            marked += 1
    return marked


def run_netlas_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run Netlas Responses enrichment for domain or per-IP host queries.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'netlas' key added
    """
    if not settings.get("NETLAS_ENABLED", False):
        return combined_result

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "Netlas",
        settings,
        keys=[
            ("NETLAS_ENABLED", "Toggle"),
            ("NETLAS_MAX_RESULTS", "Limits"),
            ("NETLAS_WORKERS", "Performance"),
            ("NETLAS_API_KEY", "API credentials"),
            ("NETLAS_KEY_ROTATOR", "API credentials"),
        ],
    )

    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(settings.get("NETLAS_KEY_ROTATOR"), settings.get("NETLAS_API_KEY", "") or "",
                      label="Netlas")
    if not keys.has_key:
        logger.warning("Netlas API key missing — skipping enrichment")
        print("[!][Netlas] NETLAS_API_KEY not configured — skipping")
        return combined_result

    max_results = int(settings.get("NETLAS_MAX_RESULTS", 100) or 100)
    max_results = max(1, min(max_results, 1000))

    domain = combined_result.get("domain", "") or ""
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    all_ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(all_ips, combined_result, "Netlas")

    print(f"[*][Netlas] Starting OSINT enrichment")

    netlas_data: dict[str, Any] = {"results": [], "total": 0}
    all_rows: list[dict] = []
    total_hint = 0
    netlas_scope = cb.scope("netlas", label="Netlas", unit="query(ies)")
    breaker = _netlas_breaker()
    # IPs whose every Netlas row this run saw; the prune keeps the others' CVEs.
    checked: set[str] = set()
    reached = False
    failed = False

    try:
        if is_ip_mode:
            print(f"[+][Netlas] IP mode — querying host: for {len(ips)} IP(s)")

            def _enrich_single_ip_netlas(ip, rate_limiter):
                nonlocal reached
                # Before the wait: the limiter reserves a slot before sleeping.
                if not breaker.allow():
                    return ip, [], 0
                rate_limiter.wait()
                q = f"host:{ip}"
                res = _netlas_responses_get(q, keys, max_results, admitted=True)
                if res.answered:
                    reached = True
                if res.answered and not res.ok:
                    checked.add(ip)
                if not res.ok:
                    return ip, [], 0
                rows, t = _parse_netlas_body(res.data)
                if t <= len(rows):
                    checked.add(ip)
                return ip, rows, t

            max_workers = settings.get('NETLAS_WORKERS', 5)
            rl = _RateLimiter(1.0)
            futures = {}
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for ip in ips:
                    futures[executor.submit(_enrich_single_ip_netlas, ip, rl)] = ip
                for fut in as_completed(futures):
                    try:
                        _ip, rows, t = fut.result()
                        total_hint = max(total_hint, t)
                        all_rows.extend(rows)
                    except Exception as e:
                        logger.warning(f"Netlas worker error: {type(e).__name__}")
            # Preserve original IP ordering
            ip_order = {ip: i for i, ip in enumerate(ips)}
            all_rows.sort(key=lambda r: ip_order.get(r.get("ip", ""), 0))
            # The row cap is across every IP: one that lost a row to it was not
            # fully re-checked.
            checked -= {r.get("ip") for r in all_rows[max_results:]}
        else:
            if not domain:
                print("[!][Netlas] No domain in scope — skipping")
            else:
                print(f"[+][Netlas] Domain mode — host:{domain}")
                q = f"host:{domain}"
                res = _netlas_responses_get(q, keys, max_results)
                if res.ok:
                    rows, total_hint = _parse_netlas_body(res.data)
                    all_rows = rows[:max_results]
                # One query answers for every IP of the domain; a cut answer
                # re-checked none of them for sure.
                reached = res.answered
                if res.answered and total_hint <= len(all_rows):
                    checked.update(ips)
                time.sleep(1)

        netlas_data["results"] = all_rows[:max_results]
        netlas_data["total"] = total_hint if total_hint else len(netlas_data["results"])
        print(f"[+][Netlas] Collected {len(netlas_data['results'])} row(s) (total: {netlas_data['total']})")

    except Exception as e:
        logger.error(f"Netlas enrichment failed: {type(e).__name__}")
        print(f"[!][Netlas] Enrichment error: {type(e).__name__}")
        print(f"[!][Netlas] Pipeline continues with partial or empty Netlas data")
        netlas_data["results"] = all_rows[:max_results]
        netlas_data["total"] = total_hint if total_hint else len(netlas_data["results"])
        failed = True

    _attribute_rows(netlas_data["results"], all_ips, combined_result)
    historical = sum(1 for r in netlas_data["results"] if r.get("attribution") == "historical")
    if historical:
        print(f"[*][Netlas] {historical} row(s) for IPs this run's DNS does not give are "
              f"kept as history, not written to the graph")
    netlas_scope.finish("netlas_enrich", payload=netlas_data)
    from recon.helpers.passive_cve_coverage import note_cve_coverage
    note_cve_coverage("netlas", "netlas_enrich", ips, checked, considered=all_ips,
                      reached=reached, failed=failed,
                      no_input=not all_ips or (not is_ip_mode and not domain))
    combined_result["netlas"] = netlas_data
    return combined_result


def run_netlas_enrichment_isolated(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run Netlas enrichment and return only the 'netlas' data dict.

    Thread-safe: does not mutate combined_result.

    Args:
        combined_result: The pipeline's combined result dictionary (read-only)
        settings: Project settings dict

    Returns:
        The 'netlas' data dictionary
    """
    import copy
    snapshot = copy.deepcopy(combined_result)
    run_netlas_enrichment(snapshot, settings)
    return snapshot.get("netlas", {})
