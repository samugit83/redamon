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

    # IP mode: the target list only. A DNS answer (a PTR name's forward
    # address) need not be a target, and the lookup would be about it.
    metadata = combined_result.get("metadata") or {}
    if metadata.get("ip_mode") and "expanded_ips" in metadata:
        return sorted({ip for ip in metadata["expanded_ips"] or [] if ip})

    return sorted(ips)


def _effective_key(api_key: str, key_rotator) -> str:
    # A pool whose every key was refused is empty for the run: falling back to
    # the plain key would resurrect the pool's first member.
    if key_rotator and getattr(key_rotator, "exhausted", False) is True:
        return ""
    if key_rotator and getattr(key_rotator, "has_keys", False):
        return (key_rotator.current_key or "").strip()
    return (api_key or "").strip()


# The free API allows 4 lookups a minute, so a 429 without Retry-After pauses
# every worker for the rest of that window (the helper caps a pause at 60s)
# instead of retrying straight back into the same quota.
_VT_RETRY_AFTER_DEFAULT_S = 60.0


def _vt_breaker():
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker("virustotal:report", label="VirusTotal", parent="virustotal")


def _vt_classify(resp):
    from recon.helpers import circuit_breaker as cb
    if cb.status_of(resp) == 429:
        return cb.CallResult(None, cb.Outcome.RATE_LIMIT, "HTTP 429",
                             cb.retry_after_seconds(resp, default=_VT_RETRY_AFTER_DEFAULT_S))
    return cb.json_result(resp, keyed=True)


def _vt_call(path: str, keys, timeout: int = 30, *, admitted: bool = False):
    """GET a VirusTotal v3 path through the VirusTotal breaker; returns a CallResult.

    A first 429 pauses every worker and the call is sent once more; a second
    one in a row stops VirusTotal. A refused key moves on to the next pooled
    key, and stops VirusTotal only when none is left.
    """
    from recon.helpers import circuit_breaker as cb
    url = f"{VIRUSTOTAL_API_BASE.rstrip('/')}/{path.lstrip('/')}"
    return cb.guarded_call(
        _vt_breaker(),
        lambda key: requests.get(url, headers={"x-apikey": key}, timeout=timeout),
        _vt_classify, keys=keys, admitted=admitted)


def _vt_get(
    path: str,
    api_key: str,
    key_rotator,
    timeout: int = 30,
) -> dict | None:
    """GET VirusTotal v3 path (relative to base). Returns the body, or None."""
    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(key_rotator, (api_key or "").strip(), label="VirusTotal")
    if not keys.has_key:
        return None
    res = _vt_call(path, keys, timeout)
    return res.data if res.ok else None


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

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "VirusTotal",
        settings,
        keys=[
            ("VIRUSTOTAL_ENABLED", "Toggle"),
            ("VIRUSTOTAL_RATE_LIMIT", "Performance"),
            ("VIRUSTOTAL_MAX_TARGETS", "Limits"),
            ("VIRUSTOTAL_WORKERS", "Performance"),
            ("VIRUSTOTAL_API_KEY", "API credentials"),
            ("VIRUSTOTAL_KEY_ROTATOR", "API credentials"),
        ],
    )

    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(settings.get("VIRUSTOTAL_KEY_ROTATOR"),
                      (settings.get("VIRUSTOTAL_API_KEY", "") or "").strip(), label="VirusTotal")
    _rl = settings.get("VIRUSTOTAL_RATE_LIMIT", 4)
    rate_limit = max(1, int(_rl if _rl is not None else 4))
    _mt = settings.get("VIRUSTOTAL_MAX_TARGETS", 20)
    max_targets = max(0, int(_mt if _mt is not None else 20))

    if not keys.has_key:
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
    vt_scope = cb.scope("virustotal", label="VirusTotal", unit="lookup(s)")
    breaker = _vt_breaker()

    try:
        def _domain_report(d):
            """The org's VirusTotal domain report, or None without one."""
            print(f"[*][VirusTotal] Fetching domain report for {d}...")
            res = _vt_call(f"domains/{d}", keys)
            parsed = _parse_domain_attrs(res.data if res.ok else None)
            if parsed:
                report = {
                    "domain": d,
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
                print(f"[+][VirusTotal] Domain report retrieved for {d}")
                return report
            print(f"[!][VirusTotal] No domain report data for {d}")
            return None

        if domain and not is_ip_mode:
            # The org, once per run; only a request made spends a rate slot.
            from recon.helpers.org_work import once_per_org, org_of
            vt_data["domain_report"], need_sleep = once_per_org(
                "virustotal_domain", org_of(combined_result), _domain_report, label="VirusTotal")

        def _enrich_single_ip(ip, rate_limiter):
            # Before the wait: each slot is 60/rate seconds, so a breaker checked
            # only after it would idle through every reserved slot.
            if not breaker.allow():
                return None
            rate_limiter.wait()
            print(f"[*][VirusTotal] Fetching IP report for {ip}...")
            res = _vt_call(f"ip_addresses/{ip}", keys, admitted=True)
            parsed = _parse_ip_attrs(res.data if res.ok else None)
            if not parsed:
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
                    logger.warning(f"VirusTotal worker error: {type(e).__name__}")
        # Preserve original ordering (sorted IPs)
        ip_order = {ip: i for i, ip in enumerate(ip_slice)}
        vt_data["ip_reports"].sort(key=lambda r: ip_order.get(r["ip"], 0))

        print(
            f"[+][VirusTotal] Enrichment complete: "
            f"domain={'yes' if vt_data['domain_report'] else 'no'}, "
            f"{len(vt_data['ip_reports'])} IP reports"
        )
    except Exception as e:
        logger.error(f"VirusTotal enrichment failed: {type(e).__name__}")
        print(f"[!][VirusTotal] Enrichment error: {type(e).__name__}")
        print(f"[!][VirusTotal] Pipeline continues without full VirusTotal data")

    vt_scope.finish("virustotal_enrich", payload=vt_data)
    combined_result["virustotal"] = vt_data
    return combined_result


def run_virustotal_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Deep copy of combined_result, run enrichment, return only the ``virustotal`` dict."""
    import copy

    snapshot = copy.deepcopy(combined_result)
    run_virustotal_enrichment(snapshot, settings)
    return snapshot.get("virustotal", {})
