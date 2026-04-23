"""
Censys Pipeline Enrichment Module

Passive OSINT enrichment using the Censys Platform API v3.
Queries host records for discovered IPv4 addresses: services, geo location,
autonomous system, and operating system metadata.

Requires CENSYS_API_TOKEN (Personal Access Token) and CENSYS_ORG_ID
(Organization ID).  Uses Bearer-token auth against api.platform.censys.io.
"""
from __future__ import annotations

import time
import threading
import logging
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from recon.main_recon_modules.ip_filter import filter_ips_for_enrichment
except ImportError:
    from ip_filter import filter_ips_for_enrichment

import requests

logger = logging.getLogger(__name__)

CENSYS_API_BASE = "https://api.platform.censys.io/v3/global"


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


def _censys_os_to_str(os_val) -> str:
    if os_val is None:
        return ""
    if isinstance(os_val, dict):
        return (
            os_val.get("uniform_resource_identifier")
            or os_val.get("product")
            or os_val.get("name")
            or str(os_val)
        )
    return str(os_val)


def _censys_normalize_software(svc: dict) -> list:
    software = svc.get("software", [])
    if not isinstance(software, list):
        return [software] if software is not None else []
    out = []
    for s in software:
        if isinstance(s, dict):
            out.append(s.get("product") or s.get("name") or str(s))
        else:
            out.append(str(s))
    return out


def _censys_get_host(ip: str, api_token: str, org_id: str) -> tuple[dict | None, bool]:
    """GET /v3/global/asset/host/{ip} with Bearer token auth.

    Returns (result_or_none, rate_limited). If rate_limited, caller should stop.
    """
    url = f"{CENSYS_API_BASE}/asset/host/{ip}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
    }
    params = {"organization_id": org_id}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 200:
            body = resp.json()
            result = body.get("result")
            if isinstance(result, dict):
                return result, False
            logger.debug(f"Censys: unexpected body for {ip}")
            return None, False
        if resp.status_code == 404:
            logger.debug(f"Censys 404 — no host data for {ip}")
            return None, False
        if resp.status_code == 429:
            logger.warning("Censys rate limit (429) — stopping host fetches for this run")
            print("[!][Censys] Rate limit hit — skipping remaining hosts")
            return None, True
        if resp.status_code in (401, 403):
            logger.warning(f"Censys {resp.status_code} — auth failed (check token/org-id)")
            print(f"[!][Censys] Auth error {resp.status_code} — verify API Token and Organization ID")
            return None, True
        logger.warning(f"Censys {resp.status_code} for {ip}: {resp.text[:200]}")
        return None, False
    except requests.RequestException as e:
        logger.warning(f"Censys request failed for {ip}: {e}")
        return None, False


def _censys_extract_tls(svc: dict) -> dict | None:
    """Extract TLS certificate data from a service object."""
    tls = svc.get("tls")
    if not isinstance(tls, dict):
        return None
    certs = tls.get("certificates") or {}
    if not isinstance(certs, dict):
        return None
    leaf = certs.get("leaf_data") or {}
    if not isinstance(leaf, dict):
        return None

    subject = leaf.get("subject") or {}
    issuer = leaf.get("issuer") or {}
    subject_cn = (
        subject.get("common_name")
        if isinstance(subject, dict)
        else None
    )
    if not subject_cn:
        return None

    issuer_cn = issuer.get("common_name") if isinstance(issuer, dict) else ""
    issuer_org = issuer.get("organization") if isinstance(issuer, dict) else ""
    if isinstance(issuer_org, list):
        issuer_org = issuer_org[0] if issuer_org else ""
    issuer_str = f"{issuer_cn} ({issuer_org})" if issuer_org else issuer_cn or ""

    names = leaf.get("names") or []
    if not isinstance(names, list):
        names = []

    validity = leaf.get("validity") or {}
    fingerprint = leaf.get("fingerprint") or ""

    return {
        "subject_cn": subject_cn,
        "issuer": issuer_str,
        "san": [n for n in names if n != subject_cn],
        "not_before": validity.get("start") if isinstance(validity, dict) else None,
        "not_after": validity.get("end") if isinstance(validity, dict) else None,
        "fingerprint": fingerprint,
        "tls_version": tls.get("version_selected") or "",
        "cipher": tls.get("cipher_selected") or "",
    }


def _censys_extract_http(svc: dict) -> dict | None:
    """Extract HTTP response metadata from a service object."""
    http = svc.get("http")
    if not isinstance(http, dict):
        return None
    resp = http.get("response") or {}
    if not isinstance(resp, dict):
        return None
    title = resp.get("html_title") or ""
    status_code = resp.get("status_code")
    if not title and not status_code:
        return None
    return {
        "title": title,
        "status_code": status_code,
    }


def _build_censys_host_entry(ip: str, result: dict) -> dict:
    services_out = []
    for svc in result.get("services") or []:
        if not isinstance(svc, dict):
            continue
        labels = svc.get("labels") or []
        if not isinstance(labels, list):
            labels = []
        entry = {
            "port": svc.get("port"),
            "transport_protocol": svc.get("transport_protocol") or svc.get("transport") or "",
            "service_name": svc.get("service_name") or svc.get("name") or "",
            "extended_service_name": svc.get("extended_service_name") or "",
            "banner": (svc.get("banner") or "")[:500],
            "labels": labels,
            "software": _censys_normalize_software(svc),
        }
        tls = _censys_extract_tls(svc)
        if tls:
            entry["tls"] = tls
        http = _censys_extract_http(svc)
        if http:
            entry["http"] = http
        services_out.append(entry)

    loc = result.get("location") or {}
    if not isinstance(loc, dict):
        loc = {}
    coords = loc.get("coordinates") or {}
    location = {
        "country": loc.get("country") or "",
        "country_code": loc.get("country_code") or "",
        "city": loc.get("city") or "",
        "timezone": loc.get("timezone") or "",
        "registered_country": loc.get("registered_country") or "",
        "latitude": coords.get("latitude") if isinstance(coords, dict) else None,
        "longitude": coords.get("longitude") if isinstance(coords, dict) else None,
    }

    asn = result.get("autonomous_system") or {}
    if not isinstance(asn, dict):
        asn = {}
    autonomous_system = {
        "asn": asn.get("asn"),
        "name": asn.get("name") or "",
        "bgp_prefix": asn.get("bgp_prefix") or "",
        "country_code": asn.get("country_code") or "",
        "description": asn.get("description") or "",
        "rir": asn.get("rir") or "",
    }

    # Reverse DNS hostnames from the top-level dns field
    dns_field = result.get("dns")
    if isinstance(dns_field, dict):
        rdns = dns_field.get("reverse_dns")
        if isinstance(rdns, dict):
            reverse_dns_names = [h for h in (rdns.get("names") or []) if isinstance(h, str) and h]
        else:
            reverse_dns_names = []
    else:
        reverse_dns_names = []

    last_updated = (
        result.get("last_updated_at")
        or result.get("last_updated")
        or ""
    )

    return {
        "ip": ip,
        "services": services_out,
        "location": location,
        "autonomous_system": autonomous_system,
        "os": _censys_os_to_str(result.get("operating_system")),
        "last_updated": str(last_updated) if last_updated is not None else "",
        "reverse_dns_names": reverse_dns_names,
    }


def run_censys_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run Censys host enrichment on discovered IPv4 addresses.

    Runs after domain discovery / IP recon, before port scanning.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'censys' key added
    """
    if not settings.get("CENSYS_ENABLED", False):
        return combined_result

    api_token = settings.get("CENSYS_API_TOKEN", "") or ""
    org_id = settings.get("CENSYS_ORG_ID", "") or ""
    if not api_token or not org_id:
        logger.warning("Censys API Token or Organization ID missing — skipping enrichment")
        print("[!][Censys] CENSYS_API_TOKEN / CENSYS_ORG_ID not configured — skipping")
        return combined_result

    print(f"[*][Censys] Starting OSINT enrichment")

    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "Censys")
    print(f"[+][Censys] Extracted {len(ips)} unique IPs for enrichment")

    censys_data: dict[str, Any] = {"hosts": []}

    try:
        if not ips:
            print("[*][Censys] No IPs to query -- empty hosts list")
        else:
            max_workers = settings.get("CENSYS_WORKERS", 5)
            rate_limiter = _RateLimiter(0.5)
            stop_rl = threading.Event()

            def _enrich_single_ip(ip, api_token, org_id, rate_limiter):
                """Enrich a single IP via Censys. Returns entry dict or None."""
                if stop_rl.is_set():
                    return None
                rate_limiter.wait()
                result, rate_limited = _censys_get_host(ip, api_token, org_id)
                if rate_limited:
                    stop_rl.set()
                    return None
                if result is None:
                    return None
                entry = _build_censys_host_entry(ip, result)
                logger.info(f"  Censys host: {ip} -- {len(entry['services'])} services")
                return entry

            print(f"[*][Censys] Querying host view for {len(ips)} IPs...")
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_enrich_single_ip, ip, api_token, org_id, rate_limiter): ip
                    for ip in ips
                }
                for future in as_completed(futures):
                    try:
                        entry = future.result()
                        if entry is not None:
                            censys_data["hosts"].append(entry)
                    except Exception as exc:
                        logger.warning(f"Censys enrichment thread error for {futures[future]}: {exc}")

            print(f"[+][Censys] Enrichment complete: {len(censys_data['hosts'])} hosts")

    except Exception as e:
        logger.error(f"Censys enrichment failed: {e}")
        print(f"[!][Censys] Enrichment error: {e}")
        print(f"[!][Censys] Pipeline continues with partial or empty Censys data")

    combined_result["censys"] = censys_data
    return combined_result


def run_censys_enrichment_isolated(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run Censys enrichment and return only the 'censys' data dict.

    Thread-safe: does not mutate combined_result. Reads DNS/IP data from
    it but writes nothing back.

    Args:
        combined_result: The pipeline's combined result dictionary (read-only)
        settings: Project settings dict

    Returns:
        The 'censys' data dictionary (just the enrichment payload)
    """
    import copy
    snapshot = copy.deepcopy(combined_result)
    run_censys_enrichment(snapshot, settings)
    return snapshot.get("censys", {})
