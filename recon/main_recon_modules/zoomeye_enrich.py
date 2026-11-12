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

    # IP mode: the target list only. A DNS answer (a PTR name's forward
    # address) need not be a target, and the lookup would be about it. A dict
    # that declares no list asks about nothing (every IP-mode builder declares it).
    metadata = combined_result.get("metadata") or {}
    if metadata.get("ip_mode"):
        return sorted({ip for ip in metadata.get("expanded_ips") or [] if ip})

    return sorted(ips)


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


def _zoomeye_breaker():
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker("zoomeye:search", label="ZoomEye", parent="zoomeye")


def _zoomeye_classify(resp):
    """Status first (401/403 refuse the key, 402 = no credit, 429 = rate
    limit); then an error reported inside a 200 body. The body is read only
    to classify."""
    from recon.helpers import circuit_breaker as cb
    res = cb.json_result(resp, keyed=True)
    if not res.ok:
        return res
    body = res.data if isinstance(res.data, dict) else {}
    err = body.get("error")
    if err and not body.get("matches"):
        text = f"{err} {body.get('message') or ''}".lower()
        if any(m in text for m in ("credit", "insufficient", "quota")):
            return cb.CallResult(None, cb.Outcome.FATAL, "credit exhausted")
        if any(m in text for m in ("login", "token", "key", "auth", "forbidden")):
            return cb.CallResult(None, cb.Outcome.FATAL, "key rejected")
        return cb.CallResult(None, cb.Outcome.TRANSIENT, "ZoomEye error body")
    return cb.CallResult(body, cb.Outcome.OK, res.detail)


def _zoomeye_query(query: str, keys, max_results: int, timeout: int = 30, *,
                   admitted: bool = False):
    """Paginate host/search until max_results rows or no more pages.

    Every page goes through the ZoomEye breaker, so a provider that stops
    answering mid-way ends the query with what it already returned. Returns a
    CallResult whose data is (rows, total): OK with rows, NO_DATA when the
    search matched nothing, else the failure of the page that ended it.
    """
    from recon.helpers import circuit_breaker as cb
    breaker = _zoomeye_breaker()
    url = f"{ZOOMEYE_API_BASE.rstrip('/')}/host/search"
    out: list[dict] = []
    total = 0
    page = 1
    last = None

    while len(out) < max_results:
        params = {"query": query, "page": page}

        def send(key, params=params):
            return requests.get(url, headers={"API-KEY": key}, params=params, timeout=timeout)

        last = cb.guarded_call(breaker, send, _zoomeye_classify, keys=keys,
                               admitted=admitted and page == 1)
        if not last.ok:
            break
        last_body = last.data
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

        page += 1
        time.sleep(1)

    if out:
        return cb.CallResult((out, total), cb.Outcome.OK)
    if last is None or last.ok or last.answered:
        return cb.CallResult(([], total), cb.Outcome.NO_DATA)
    return cb.CallResult(([], 0), last.outcome, last.detail)


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
    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(key_rotator, (api_key or "").strip(), label="ZoomEye")
    if not keys.has_key:
        return [], 0
    return _zoomeye_query(query, keys, max_results, timeout).data


def run_zoomeye_enrichment(combined_result: dict, settings: dict) -> dict:
    """
    Run ZoomEye host search (domain: hostname query; IP mode: per-IP ip: queries).

    Mutates combined_result in place with key ``zoomeye``.
    """
    if not settings.get("ZOOMEYE_ENABLED", False):
        return combined_result

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "ZoomEye",
        settings,
        keys=[
            ("ZOOMEYE_ENABLED", "Toggle"),
            ("ZOOMEYE_MAX_RESULTS", "Limits"),
            ("ZOOMEYE_WORKERS", "Performance"),
            ("ZOOMEYE_API_KEY", "API credentials"),
            ("ZOOMEYE_KEY_ROTATOR", "API credentials"),
        ],
    )

    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(settings.get("ZOOMEYE_KEY_ROTATOR"),
                      (settings.get("ZOOMEYE_API_KEY", "") or "").strip(), label="ZoomEye")
    max_results = int(settings.get("ZOOMEYE_MAX_RESULTS", 1000) or 1000)
    max_results = max(1, max_results)

    if not keys.has_key:
        print(f"[!][ZoomEye] No API key configured — skipping")
        return combined_result

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "ZoomEye")

    print(f"[*][ZoomEye] Starting OSINT enrichment")

    ze_data: dict = {"results": [], "total": 0}
    ze_scope = cb.scope("zoomeye", label="ZoomEye", unit="query(ies)")
    breaker = _zoomeye_breaker()

    try:
        if is_ip_mode:
            print(f"[+][ZoomEye] IP mode: {len(ips)} target(s)")
            grand_total = 0

            def _enrich_single_ip_zoomeye(ip, rate_limiter):
                # Before the wait: the limiter reserves a slot before sleeping.
                if not breaker.allow():
                    return ip, [], 0
                rate_limiter.wait()
                print(f"[*][ZoomEye] Searching ip:{ip}...")
                rows, t = _zoomeye_query(f"ip:{ip}", keys, max_results, admitted=True).data
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
                        logger.warning(f"ZoomEye worker error: {type(e).__name__}")
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
            rows, t = _zoomeye_query(f"hostname:{domain}", keys, max_results).data
            ze_data["results"] = rows
            ze_data["total"] = t or len(rows)
            print(f"[+][ZoomEye] hostname:{domain} — {len(rows)} row(s), total≈{ze_data['total']}")

        print(f"[+][ZoomEye] Enrichment complete: {len(ze_data['results'])} results")
    except Exception as e:
        logger.error(f"ZoomEye enrichment failed: {type(e).__name__}")
        print(f"[!][ZoomEye] Enrichment error: {type(e).__name__}")
        print(f"[!][ZoomEye] Pipeline continues without full ZoomEye data")

    ze_scope.finish("zoomeye_enrich", payload=ze_data)
    combined_result["zoomeye"] = ze_data
    return combined_result


def run_zoomeye_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Deep copy of combined_result, run enrichment, return only the ``zoomeye`` dict."""
    import copy

    snapshot = copy.deepcopy(combined_result)
    run_zoomeye_enrichment(snapshot, settings)
    return snapshot.get("zoomeye", {})
