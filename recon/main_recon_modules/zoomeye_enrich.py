"""
ZoomEye Pipeline Enrichment Module

Host search enrichment via ZoomEye API (hostname or IP queries).
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

ZOOMEYE_API_BASE = "https://api.zoomeye.ai/"


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


def _geoinfo_country(geoinfo) -> str:
    if not geoinfo or not isinstance(geoinfo, dict):
        return ""
    c = geoinfo.get("country")
    if isinstance(c, str):
        return c
    if isinstance(c, dict):
        names = c.get("names")
        if isinstance(names, dict):
            return str(names.get("en") or names.get("zh") or next(iter(names.values()), ""))
        return str(c.get("code") or c.get("name") or "")
    return str(c or "")


def _geoinfo_city(geoinfo) -> str:
    if not geoinfo or not isinstance(geoinfo, dict):
        return ""
    city = geoinfo.get("city")
    if isinstance(city, str):
        return city
    if isinstance(city, dict):
        names = city.get("names") or city.get("name")
        if isinstance(names, dict):
            return str(names.get("en") or names.get("zh-cn") or next(iter(names.values()), ""))
        return str(names or city.get("code") or "")
    return str(city or "")


def _geoinfo_latlon(geoinfo) -> tuple:
    """Return (latitude, longitude) floats or (None, None)."""
    if not geoinfo or not isinstance(geoinfo, dict):
        return None, None
    loc = geoinfo.get("location")
    if not isinstance(loc, dict):
        return None, None
    try:
        lat = float(loc.get("lat") or loc.get("latitude") or 0) or None
        lon = float(loc.get("lng") or loc.get("longitude") or 0) or None
        return lat, lon
    except (TypeError, ValueError):
        return None, None


def _geoinfo_asn(geoinfo) -> str:
    if not geoinfo or not isinstance(geoinfo, dict):
        return ""
    return str(geoinfo.get("asn") or "")


def _geoinfo_isp(geoinfo) -> str:
    if not geoinfo or not isinstance(geoinfo, dict):
        return ""
    return str(geoinfo.get("isp") or geoinfo.get("organization") or geoinfo.get("aso") or "")


def _zoomeye_search(
    query: str,
    api_key: str,
    key_rotator,
    max_results: int,
    timeout: int = 30,
) -> tuple[list[dict], int]:
    """
    Paginate host/search until max_results rows or no more pages.
    Returns (flattened result rows, total from API if given).
    """
    eff = _effective_key(api_key, key_rotator)
    if not eff:
        return [], 0

    url = f"{ZOOMEYE_API_BASE.rstrip('/')}/host/search"
    headers = {"API-KEY": eff}
    out: list[dict] = []
    total = 0
    page = 1

    while len(out) < max_results:
        params = {"query": query, "page": page}
        last_body = None
        for attempt in range(2):
            try:
                resp = requests.get(
                    url, headers=headers, params=params, timeout=timeout
                )
                if key_rotator:
                    key_rotator.tick()
                if resp.status_code == 200:
                    last_body = resp.json()
                    break
                if resp.status_code == 429:
                    logger.warning("ZoomEye rate limit (429), sleeping and retrying once")
                    if attempt == 0:
                        time.sleep(2)
                        continue
                    return out, total
                logger.warning(
                    f"ZoomEye {resp.status_code} page={page}: {resp.text[:200]}"
                )
                return out, total
            except requests.RequestException as e:
                logger.warning(f"ZoomEye request failed page={page}: {e}")
                return out, total

        if not last_body:
            break

        matches = last_body.get("matches") or []
        if not matches:
            break

        try:
            total = int(last_body.get("total") or last_body.get("available") or total)
        except (TypeError, ValueError):
            pass

        for m in matches:
            if len(out) >= max_results:
                break
            portinfo = m.get("portinfo") or {}
            port = portinfo.get("port")
            if port is not None:
                try:
                    port = int(port)
                except (TypeError, ValueError):
                    port = 0
            geoinfo = m.get("geoinfo")
            lat, lon = _geoinfo_latlon(geoinfo)
            ssl = m.get("ssl") or {}
            # Prefer root-level hostname/rdns, fall back to portinfo
            hostname = str(m.get("hostname") or portinfo.get("hostname") or "")
            rdns = str(m.get("rdns") or portinfo.get("rdns") or "")
            out.append(
                {
                    "ip": str(m.get("ip") or ""),
                    "port": port,
                    "protocol": str(portinfo.get("protocol") or "tcp").lower() or "tcp",
                    "app": str(portinfo.get("app") or ""),
                    "service": str(portinfo.get("service") or ""),
                    "product": str(portinfo.get("product") or ""),
                    "version": str(portinfo.get("version") or ""),
                    "title": str(portinfo.get("title") or ""),
                    "banner": str(portinfo.get("banner") or ""),
                    "os": str(portinfo.get("os") or ""),
                    "device": str(portinfo.get("device") or ""),
                    "hostname": hostname,
                    "rdns": rdns,
                    "country": _geoinfo_country(geoinfo),
                    "city": _geoinfo_city(geoinfo),
                    "latitude": lat,
                    "longitude": lon,
                    "asn": _geoinfo_asn(geoinfo),
                    "isp": _geoinfo_isp(geoinfo),
                    "update_time": str(m.get("update_time") or ""),
                    "ssl_jarm": str(ssl.get("jarm") or ""),
                    "ssl_ja3s": str(ssl.get("ja3s") or ""),
                }
            )

        if len(matches) < 1:
            break
        page += 1
        time.sleep(1)

    return out, total


def run_zoomeye_enrichment(combined_result: dict, settings: dict) -> dict:
    """
    Run ZoomEye host search (domain: hostname query; IP mode: per-IP ip: queries).

    Mutates combined_result in place with key ``zoomeye``.
    """
    if not settings.get("ZOOMEYE_ENABLED", False):
        return combined_result

    api_key = settings.get("ZOOMEYE_API_KEY", "")
    key_rotator = settings.get("ZOOMEYE_KEY_ROTATOR")
    max_results = int(settings.get("ZOOMEYE_MAX_RESULTS", 1000) or 1000)
    max_results = max(1, max_results)

    if not _effective_key(api_key, key_rotator):
        print(f"[!][ZoomEye] No API key configured — skipping")
        return combined_result

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "ZoomEye")

    print(f"[*][ZoomEye] Starting OSINT enrichment")

    ze_data: dict = {"results": [], "total": 0}

    try:
        if is_ip_mode:
            print(f"[+][ZoomEye] IP mode: {len(ips)} target(s)")
            grand_total = 0

            def _enrich_single_ip_zoomeye(ip, rate_limiter):
                rate_limiter.wait()
                print(f"[*][ZoomEye] Searching ip:{ip}...")
                rows, t = _zoomeye_search(
                    f"ip:{ip}",
                    api_key,
                    key_rotator,
                    max_results,
                )
                print(f"[+][ZoomEye] ip:{ip} -- {len(rows)} row(s)")
                return ip, rows, t

            max_workers = settings.get('ZOOMEYE_WORKERS', 5)
            rl = _RateLimiter(1.0)
            ip_results: list[tuple[str, list, int]] = []
            futures = {}
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for ip in ips:
                    futures[executor.submit(_enrich_single_ip_zoomeye, ip, rl)] = ip
                for fut in as_completed(futures):
                    try:
                        _ip, rows, t = fut.result()
                        ip_results.append((_ip, rows, t))
                        grand_total = max(grand_total, t, len(rows))
                    except Exception as e:
                        ip = futures[fut]
                        logger.warning(f"ZoomEye worker error for {ip}: {e}")
            # Preserve original IP ordering
            ip_order = {ip: i for i, ip in enumerate(ips)}
            ip_results.sort(key=lambda r: ip_order.get(r[0], 0))
            for _ip, rows, _t in ip_results:
                ze_data["results"].extend(rows)
            ze_data["total"] = grand_total or len(ze_data["results"])
        else:
            if not domain:
                print(f"[!][ZoomEye] No domain in combined_result — skipping")
                combined_result["zoomeye"] = ze_data
                return combined_result
            print(f"[*][ZoomEye] Searching hostname:{domain}...")
            rows, t = _zoomeye_search(
                f"hostname:{domain}",
                api_key,
                key_rotator,
                max_results,
            )
            ze_data["results"] = rows
            ze_data["total"] = t or len(rows)
            print(f"[+][ZoomEye] hostname:{domain} — {len(rows)} row(s), total≈{ze_data['total']}")

        print(f"[+][ZoomEye] Enrichment complete: {len(ze_data['results'])} results")
    except Exception as e:
        logger.error(f"ZoomEye enrichment failed: {e}")
        print(f"[!][ZoomEye] Enrichment error: {e}")
        print(f"[!][ZoomEye] Pipeline continues without full ZoomEye data")

    combined_result["zoomeye"] = ze_data
    return combined_result


def run_zoomeye_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Deep copy of combined_result, run enrichment, return only the ``zoomeye`` dict."""
    import copy

    snapshot = copy.deepcopy(combined_result)
    run_zoomeye_enrichment(snapshot, settings)
    return snapshot.get("zoomeye", {})
