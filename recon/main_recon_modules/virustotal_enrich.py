"""
VirusTotal Pipeline Enrichment Module

Passive OSINT via VirusTotal API v3 (domain and IP reports).
Respects free-tier limits: enforce spacing between requests (default 4 req/min).
"""
from __future__ import annotations

import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from recon.main_recon_modules.ip_filter import filter_ips_for_enrichment
except ImportError:
    from ip_filter import filter_ips_for_enrichment

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3/"


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


def _effective_key(api_key: str, key_rotator) -> str:
    if key_rotator and getattr(key_rotator, "has_keys", False):
        return (key_rotator.current_key or "").strip()
    return (api_key or "").strip()


def _vt_get(
    path: str,
    api_key: str,
    key_rotator,
    timeout: int = 30,
) -> dict | None:
    """GET VirusTotal v3 path (relative to base). Handles 429 with one retry."""
    eff = _effective_key(api_key, key_rotator)
    if not eff:
        return None
    url = f"{VIRUSTOTAL_API_BASE.rstrip('/')}/{path.lstrip('/')}"
    headers = {"x-apikey": eff}

    for attempt in range(2):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if key_rotator:
                key_rotator.tick()
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                logger.debug(f"VirusTotal 404 for {path}")
                return None
            if resp.status_code == 429:
                logger.warning("VirusTotal rate limit (429), backing off and retrying once")
                if attempt == 0:
                    time.sleep(65)
                    continue
                return None
            logger.warning(
                f"VirusTotal {resp.status_code} for {path}: {resp.text[:200]}"
            )
            return None
        except requests.RequestException as e:
            logger.warning(f"VirusTotal request failed for {path}: {e}")
            return None
    return None


def _parse_domain_attrs(data: dict | None) -> dict | None:
    if not data:
        return None
    attrs = (data.get("data") or {}).get("attributes") or {}
    ranks = attrs.get("popularity_ranks") or {}
    return {
        "reputation": attrs.get("reputation"),
        "analysis_stats": attrs.get("last_analysis_stats") or {},
        "categories": attrs.get("categories") or {},
        "registrar": attrs.get("registrar"),
        "total_votes": attrs.get("total_votes") or {},
        "tags": attrs.get("tags") or [],
        "last_analysis_date": attrs.get("last_analysis_date"),
        "jarm": attrs.get("jarm"),
        "popularity_ranks": ranks,
        "popularity_alexa": (ranks.get("Alexa") or {}).get("rank"),
        "popularity_umbrella": (ranks.get("Cisco Umbrella") or {}).get("rank"),
        "last_dns_records_date": attrs.get("last_dns_records_date"),
        "last_https_certificate_date": attrs.get("last_https_certificate_date"),
    }


def _parse_ip_attrs(data: dict | None) -> dict | None:
    if not data:
        return None
    attrs = (data.get("data") or {}).get("attributes") or {}
    asn = attrs.get("asn")
    if asn is not None and not isinstance(asn, int):
        try:
            asn = int(asn)
        except (TypeError, ValueError):
            asn = None
    return {
        "reputation": attrs.get("reputation"),
        "analysis_stats": attrs.get("last_analysis_stats") or {},
        "asn": asn,
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "total_votes": attrs.get("total_votes") or {},
        "tags": attrs.get("tags") or [],
        "last_analysis_date": attrs.get("last_analysis_date"),
        "network": attrs.get("network"),
        "regional_internet_registry": attrs.get("regional_internet_registry"),
        "continent": attrs.get("continent"),
        "jarm": attrs.get("jarm"),
    }


def run_virustotal_enrichment(combined_result: dict, settings: dict) -> dict:
    """
    Run VirusTotal enrichment on the target domain (domain mode) and discovered IPs.

    Mutates combined_result in place with key ``virustotal``.
    """
    if not settings.get("VIRUSTOTAL_ENABLED", False):
        return combined_result

    api_key = settings.get("VIRUSTOTAL_API_KEY", "")
    key_rotator = settings.get("VIRUSTOTAL_KEY_ROTATOR")
    _rl = settings.get("VIRUSTOTAL_RATE_LIMIT", 4)
    rate_limit = max(1, int(_rl if _rl is not None else 4))
    _mt = settings.get("VIRUSTOTAL_MAX_TARGETS", 20)
    max_targets = max(0, int(_mt if _mt is not None else 20))

    if not _effective_key(api_key, key_rotator):
        print(f"[!][VirusTotal] No API key configured — skipping")
        return combined_result

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "VirusTotal")
    ip_slice = ips[:max_targets] if max_targets else []

    print(f"[*][VirusTotal] Starting OSINT enrichment")
    print(f"[+][VirusTotal] Extracted {len(ips)} unique IPs (enriching up to {max_targets})")

    vt_data: dict = {
        "domain_report": None,
        "ip_reports": [],
    }

    throttle = 60.0 / rate_limit
    need_sleep = False

    try:
        if domain and not is_ip_mode:
            if need_sleep:
                time.sleep(throttle)
            need_sleep = True
            print(f"[*][VirusTotal] Fetching domain report for {domain}...")
            raw = _vt_get(f"domains/{domain}", api_key, key_rotator)
            parsed = _parse_domain_attrs(raw)
            if parsed:
                vt_data["domain_report"] = {
                    "domain": domain,
                    "reputation": parsed["reputation"],
                    "analysis_stats": parsed["analysis_stats"],
                    "categories": parsed["categories"],
                    "registrar": parsed["registrar"],
                    "total_votes": parsed["total_votes"],
                    "tags": parsed["tags"],
                    "last_analysis_date": parsed["last_analysis_date"],
                    "jarm": parsed["jarm"],
                    "popularity_alexa": parsed["popularity_alexa"],
                    "popularity_umbrella": parsed["popularity_umbrella"],
                    "last_dns_records_date": parsed["last_dns_records_date"],
                    "last_https_certificate_date": parsed["last_https_certificate_date"],
                }
                print(f"[+][VirusTotal] Domain report retrieved for {domain}")
            else:
                print(f"[!][VirusTotal] No domain report data for {domain}")

        def _enrich_single_ip(ip, rate_limiter):
            rate_limiter.wait()
            print(f"[*][VirusTotal] Fetching IP report for {ip}...")
            raw = _vt_get(f"ip_addresses/{ip}", api_key, key_rotator)
            parsed = _parse_ip_attrs(raw)
            if not parsed:
                logger.warning(f"VirusTotal: no IP data for {ip}")
                return None
            report = {
                "ip": ip,
                "reputation": parsed["reputation"],
                "analysis_stats": parsed["analysis_stats"],
                "asn": parsed["asn"],
                "as_owner": parsed["as_owner"],
                "country": parsed["country"],
                "total_votes": parsed["total_votes"],
                "tags": parsed["tags"],
                "last_analysis_date": parsed["last_analysis_date"],
                "network": parsed["network"],
                "regional_internet_registry": parsed["regional_internet_registry"],
                "continent": parsed["continent"],
                "jarm": parsed["jarm"],
            }
            print(f"[+][VirusTotal] IP report retrieved for {ip}")
            return report

        max_workers = settings.get('VIRUSTOTAL_WORKERS', 3)
        rl = _RateLimiter(throttle)
        # Honour the domain request's timing: seed the rate limiter if we already made a request
        if need_sleep:
            rl._last = time.time()
        futures = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for ip in ip_slice:
                futures[executor.submit(_enrich_single_ip, ip, rl)] = ip
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                    if result is not None:
                        vt_data["ip_reports"].append(result)
                except Exception as e:
                    ip = futures[fut]
                    logger.warning(f"VirusTotal worker error for {ip}: {e}")
        # Preserve original ordering (sorted IPs)
        ip_order = {ip: i for i, ip in enumerate(ip_slice)}
        vt_data["ip_reports"].sort(key=lambda r: ip_order.get(r["ip"], 0))

        print(
            f"[+][VirusTotal] Enrichment complete: "
            f"domain={'yes' if vt_data['domain_report'] else 'no'}, "
            f"{len(vt_data['ip_reports'])} IP reports"
        )
    except Exception as e:
        logger.error(f"VirusTotal enrichment failed: {e}")
        print(f"[!][VirusTotal] Enrichment error: {e}")
        print(f"[!][VirusTotal] Pipeline continues without full VirusTotal data")

    combined_result["virustotal"] = vt_data
    return combined_result


def run_virustotal_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Deep copy of combined_result, run enrichment, return only the ``virustotal`` dict."""
    import copy

    snapshot = copy.deepcopy(combined_result)
    run_virustotal_enrichment(snapshot, settings)
    return snapshot.get("virustotal", {})
