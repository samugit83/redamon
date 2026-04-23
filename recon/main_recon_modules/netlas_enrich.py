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
    from recon.main_recon_modules.ip_filter import filter_ips_for_enrichment
except ImportError:
    from ip_filter import filter_ips_for_enrichment

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

    if combined_result.get("metadata", {}).get("ip_mode"):
        for ip in combined_result["metadata"].get("expanded_ips", []):
            if ip:
                ips.add(ip)

    return sorted(ips)


def _netlas_effective_key(settings: dict, key_rotator) -> str:
    api_key = settings.get("NETLAS_API_KEY", "") or ""
    if key_rotator and getattr(key_rotator, "has_keys", False):
        return key_rotator.current_key or api_key
    return api_key


def _netlas_responses_get(
    q: str,
    api_key: str,
    size: int,
    key_rotator=None,
) -> dict | None:
    """GET /responses/ with X-API-Key. Returns body dict or None on 429 / errors."""
    url = f"{NETLAS_API_BASE}/responses/"
    headers = {"X-API-Key": api_key}
    params = {"q": q, "size": max(1, min(int(size), 1000))}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if key_rotator:
            key_rotator.tick()
        if resp.status_code == 429:
            logger.warning("Netlas rate limit (429)")
            print("[!][Netlas] Rate limit hit — stopping Netlas queries for this run")
            return None
        if resp.status_code != 200:
            logger.warning(f"Netlas {resp.status_code}: {resp.text[:200]}")
            return None
        return resp.json()
    except requests.RequestException as e:
        logger.warning(f"Netlas request failed: {e}")
        return None


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
    protocol = data.get("protocol") or data.get("prot7") or ""

    return {
        "host": str(host) if host is not None else "",
        "ip": str(ip) if ip is not None else "",
        "port": port_i,
        "protocol": str(protocol) if protocol is not None else "",
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

    key_rotator = settings.get("NETLAS_KEY_ROTATOR")
    api_key = _netlas_effective_key(settings, key_rotator)
    if not api_key:
        logger.warning("Netlas API key missing — skipping enrichment")
        print("[!][Netlas] NETLAS_API_KEY not configured — skipping")
        return combined_result

    max_results = int(settings.get("NETLAS_MAX_RESULTS", 100) or 100)
    max_results = max(1, min(max_results, 1000))

    domain = combined_result.get("domain", "") or ""
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "Netlas")

    print(f"[*][Netlas] Starting OSINT enrichment")

    netlas_data: dict[str, Any] = {"results": [], "total": 0}
    all_rows: list[dict] = []
    total_hint = 0

    try:
        if is_ip_mode:
            print(f"[+][Netlas] IP mode — querying host: for {len(ips)} IP(s)")

            def _enrich_single_ip_netlas(ip, rate_limiter):
                rate_limiter.wait()
                q = f"host:{ip}"
                body = _netlas_responses_get(q, api_key, max_results, key_rotator=key_rotator)
                if body is None:
                    return ip, [], 0
                rows, t = _parse_netlas_body(body)
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
                        ip = futures[fut]
                        logger.warning(f"Netlas worker error for {ip}: {e}")
            # Preserve original IP ordering
            ip_order = {ip: i for i, ip in enumerate(ips)}
            all_rows.sort(key=lambda r: ip_order.get(r.get("ip", ""), 0))
        else:
            if not domain:
                print("[!][Netlas] No domain in scope — skipping")
            else:
                print(f"[+][Netlas] Domain mode — host:{domain}")
                q = f"host:{domain}"
                body = _netlas_responses_get(q, api_key, max_results, key_rotator=key_rotator)
                if body is not None:
                    rows, total_hint = _parse_netlas_body(body)
                    all_rows = rows[:max_results]
                time.sleep(1)

        netlas_data["results"] = all_rows[:max_results]
        netlas_data["total"] = total_hint if total_hint else len(netlas_data["results"])
        print(f"[+][Netlas] Collected {len(netlas_data['results'])} row(s) (total: {netlas_data['total']})")

    except Exception as e:
        logger.error(f"Netlas enrichment failed: {e}")
        print(f"[!][Netlas] Enrichment error: {e}")
        print(f"[!][Netlas] Pipeline continues with partial or empty Netlas data")
        netlas_data["results"] = all_rows[:max_results]
        netlas_data["total"] = total_hint if total_hint else len(netlas_data["results"])

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
