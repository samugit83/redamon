"""
FOFA Pipeline Enrichment Module

Passive OSINT enrichment using the FOFA search API (base64 query).
Domain mode queries `domain="<domain>"`; IP mode runs `ip="<ip>"` per address.
Supports optional API key rotation via FOFA_KEY_ROTATOR.
"""
from __future__ import annotations

import base64
import time
import threading
import logging
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from recon.main_recon_modules.ip_filter import filter_ips_for_enrichment
except ImportError:
    from ip_filter import filter_ips_for_enrichment

logger = logging.getLogger(__name__)

FOFA_API_URL = "https://fofa.info/api/v1/search/all"


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

FOFA_FIELDS = (
    "ip,port,host,domain,title,server,protocol,country,country_name,region,city,"
    "isp,as_number,as_organization,os,product,version,jarm,tls_version,"
    "certs_subject_cn,certs_subject_org,certs_issuer_cn,certs_valid,"
    "icon_hash,cname,fid,lastupdatetime"
)


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


def _fofa_effective_key(settings: dict, key_rotator) -> str:
    api_key = settings.get("FOFA_API_KEY", "") or ""
    if key_rotator and getattr(key_rotator, "has_keys", False):
        return key_rotator.current_key or api_key
    return api_key


def _fofa_auth_params(api_key: str) -> dict:
    """
    Return FOFA auth params from a raw API key string.

    FOFA supports two formats:
      - Legacy: "email:apikey"  → separate email + key params
      - Modern: "apikey"        → key param only (FOFA API key-only auth)

    Both are handled transparently so users can enter either format.
    """
    if ":" in api_key:
        email, _, key = api_key.partition(":")
        return {"email": email.strip(), "key": key.strip()}
    return {"key": api_key.strip()}


def _fofa_search(
    query: str,
    api_key: str,
    size: int,
    key_rotator=None,
) -> dict | None:
    """Run FOFA search/all. Returns API JSON dict or None on hard failure / 429."""
    q_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    params = {
        **_fofa_auth_params(api_key),
        "qbase64": q_b64,
        "fields": FOFA_FIELDS,
        "size": size,
    }
    try:
        resp = requests.get(FOFA_API_URL, params=params, timeout=30)
        if key_rotator:
            key_rotator.tick()
        if resp.status_code == 429:
            logger.warning("FOFA rate limit (429)")
            print("[!][FOFA] Rate limit hit — stopping FOFA queries for this run")
            return None
        if resp.status_code != 200:
            logger.warning(f"FOFA {resp.status_code}: {resp.text[:200]}")
            return None
        data = resp.json()
        if data.get("error"):
            logger.warning(f"FOFA API error: {data.get('errmsg', data)}")
            return None
        return data
    except requests.RequestException as e:
        logger.warning(f"FOFA request failed: {e}")
        return None


_FOFA_FIELD_NAMES = [
    "ip", "port", "host", "domain", "title", "server", "protocol",
    "country", "country_name", "region", "city",
    "isp", "as_number", "as_organization", "os",
    "product", "version", "jarm", "tls_version",
    "certs_subject_cn", "certs_subject_org", "certs_issuer_cn", "certs_valid",
    "icon_hash", "cname", "fid", "lastupdatetime",
]

_FOFA_STR_FIELDS = [f for f in _FOFA_FIELD_NAMES if f != "port"]


def _parse_fofa_rows(data: dict) -> tuple[list[dict], int]:
    """Parse FOFA results array-of-arrays into dict rows. Returns (rows, total)."""
    raw = data.get("results") or []
    total = data.get("size")
    if total is None:
        total = len(raw)
    rows = []
    for row in raw:
        if not isinstance(row, (list, tuple)):
            continue
        d = {}
        for i, name in enumerate(_FOFA_FIELD_NAMES):
            d[name] = row[i] if i < len(row) else ""
        port_val = d.get("port")
        try:
            d["port"] = int(port_val) if port_val not in (None, "", []) else 0
        except (TypeError, ValueError):
            d["port"] = 0
        for k in _FOFA_STR_FIELDS:
            if d.get(k) is None:
                d[k] = ""
            else:
                d[k] = str(d[k])
        rows.append(d)
    return rows, int(total) if total is not None else len(rows)


def run_fofa_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run FOFA passive enrichment for the target domain or discovered IPs.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'fofa' key added
    """
    if not settings.get("FOFA_ENABLED", False):
        return combined_result

    key_rotator = settings.get("FOFA_KEY_ROTATOR")
    api_key = _fofa_effective_key(settings, key_rotator)
    if not api_key:
        logger.warning("FOFA API key missing — skipping enrichment")
        print("[!][FOFA] FOFA_API_KEY not configured — skipping")
        return combined_result

    max_results = int(settings.get("FOFA_MAX_RESULTS", 100) or 100)
    max_results = max(1, min(max_results, 10000))
    per_request_size = min(100, max_results)

    domain = combined_result.get("domain", "") or ""
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "FOFA")

    print(f"[*][FOFA] Starting OSINT enrichment")

    fofa_data: dict[str, Any] = {"results": [], "total": 0}
    aggregated: list[dict] = []
    total_hint = 0

    try:
        if is_ip_mode:
            print(f"[+][FOFA] IP mode -- {len(ips)} address(es)")
            max_workers = settings.get("FOFA_WORKERS", 5)
            rate_limiter = _RateLimiter(1.0)
            stop_flag = threading.Event()
            results_lock = threading.Lock()

            def _enrich_single_ip(ip, api_key, key_rotator, rate_limiter):
                """Query FOFA for a single IP. Returns (rows, total_hint) or None."""
                if stop_flag.is_set():
                    return None
                rate_limiter.wait()
                if stop_flag.is_set():
                    return None
                q = f'ip="{ip}"'
                size = min(per_request_size, max_results)
                data = _fofa_search(q, api_key, size, key_rotator=key_rotator)
                if data is None:
                    stop_flag.set()
                    return None
                rows, t = _parse_fofa_rows(data)
                return rows, t

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_enrich_single_ip, ip, api_key, key_rotator, rate_limiter): ip
                    for ip in ips
                }
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result is not None:
                            rows, t = result
                            with results_lock:
                                total_hint = max(total_hint, t)
                                aggregated.extend(rows)
                    except Exception as exc:
                        logger.warning(f"FOFA enrichment thread error for {futures[future]}: {exc}")
        else:
            if not domain:
                print("[!][FOFA] No domain in scope — skipping")
            else:
                print(f"[+][FOFA] Domain mode — {domain}")
                q = f'domain="{domain}"'
                data = _fofa_search(q, api_key, per_request_size, key_rotator=key_rotator)
                if data is not None:
                    rows, total_hint = _parse_fofa_rows(data)
                    aggregated = rows[:max_results]
                time.sleep(1)

        fofa_data["results"] = aggregated[:max_results]
        fofa_data["total"] = total_hint if total_hint else len(fofa_data["results"])
        print(f"[+][FOFA] Collected {len(fofa_data['results'])} result row(s) (total hint: {fofa_data['total']})")

    except Exception as e:
        logger.error(f"FOFA enrichment failed: {e}")
        print(f"[!][FOFA] Enrichment error: {e}")
        print(f"[!][FOFA] Pipeline continues with partial or empty FOFA data")
        fofa_data["results"] = aggregated[:max_results]
        fofa_data["total"] = total_hint if total_hint else len(fofa_data["results"])

    combined_result["fofa"] = fofa_data
    return combined_result


def run_fofa_enrichment_isolated(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run FOFA enrichment and return only the 'fofa' data dict.

    Thread-safe: does not mutate combined_result.

    Args:
        combined_result: The pipeline's combined result dictionary (read-only)
        settings: Project settings dict

    Returns:
        The 'fofa' data dictionary
    """
    import copy
    snapshot = copy.deepcopy(combined_result)
    run_fofa_enrichment(snapshot, settings)
    return snapshot.get("fofa", {})
