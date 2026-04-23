"""
Criminal IP Pipeline Enrichment Module

IP intelligence and domain risk reports via Criminal IP API v1.
"""
from __future__ import annotations

import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from recon.main_recon_modules.ip_filter import filter_ips_for_enrichment
except ImportError:
    from ip_filter import filter_ips_for_enrichment

logger = logging.getLogger(__name__)

CRIMINALIP_API_BASE = "https://api.criminalip.io/v1/"


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


STOP_AUTH = "auth"
STOP_CREDIT = "credit"
STOP_RATE = "rate"


def _classify_stop_reason(status: int, body_text: str) -> str | None:
    """Return a stop reason if the response indicates further requests are futile."""
    if status in (401, 403):
        return STOP_AUTH
    if status == 402:
        return STOP_CREDIT
    lower = body_text.lower()
    if any(kw in lower for kw in ("credit", "quota", "exceeded", "limit reached", "insufficient")):
        return STOP_CREDIT
    if "unauthorized" in lower or "invalid api key" in lower or "invalid key" in lower:
        return STOP_AUTH
    return None


def _cip_get(
    path: str,
    api_key: str,
    key_rotator,
    params: dict | None = None,
    timeout: int = 30,
) -> tuple[dict | None, str | None]:
    """GET Criminal IP v1 with 429 retry once.

    Returns (body_or_none, stop_reason).  stop_reason is non-None when further
    requests should be skipped (auth failure, credit exhaustion, rate limit).
    """
    eff = _effective_key(api_key, key_rotator)
    if not eff:
        return None, STOP_AUTH
    url = f"{CRIMINALIP_API_BASE.rstrip('/')}/{path.lstrip('/')}"
    headers = {"x-api-key": eff}
    merged = dict(params or {})

    for attempt in range(2):
        try:
            resp = requests.get(url, headers=headers, params=merged, timeout=timeout)
            if key_rotator:
                key_rotator.tick()
            if resp.status_code == 200:
                try:
                    return resp.json(), None
                except ValueError:
                    logger.warning(f"CriminalIP invalid JSON for {path}")
                    return None, None
            if resp.status_code == 404:
                logger.debug(f"CriminalIP 404 for {path}")
                return None, None
            if resp.status_code == 429:
                logger.warning("CriminalIP rate limit (429), sleeping and retrying once")
                if attempt == 0:
                    time.sleep(2)
                    continue
                return None, STOP_RATE

            body_text = resp.text[:300]
            stop = _classify_stop_reason(resp.status_code, body_text)
            if stop:
                logger.warning(
                    f"CriminalIP {resp.status_code} for {path}: {body_text}"
                )
                return None, stop

            logger.warning(
                f"CriminalIP {resp.status_code} for {path}: {body_text[:200]}"
            )
            return None, None
        except requests.RequestException as e:
            logger.warning(f"CriminalIP request failed for {path}: {e}")
            return None, None
    return None, STOP_RATE


def _parse_ip_report(ip: str, body: dict | None) -> dict | None:
    """
    Parse /v1/ip/data response (with full=true).

    Real API structure:
      {
        "tags": {"is_vpn": bool, "is_cloud": bool, "is_tor": bool,
                 "is_proxy": bool, "is_hosting": bool, "is_mobile": bool,
                 "is_darkweb": bool, "is_scanner": bool, "is_snort": bool},
        "score": {"inbound": int, "outbound": int},
        "whois": {"count": N, "data": [{"org_name": str, "org_country_code": str,
                                         "city": str, "latitude": float, "longitude": float,
                                         "as_name": str, "as_no": int}]},
        "port": {"count": N, "data": [{"open_port_no": int, "app_name": str,
                                        "app_version": str, "banner": str,
                                        "socket": str, "protocol": str}]},
        "vulnerability": {"count": N, "data": [{"cve_id": str, "cvssv3_score": float, ...}]},
        "ip_category": {"count": N, "data": [{"type": str, "detect_source": str}]},
        "ids": {"count": N, ...},
        "scanning_record": {"count": N, ...}
      }
    """
    if not body:
        return None
    data = body.get("data")
    if data is None:
        data = body
    if not isinstance(data, dict):
        return None

    # --- Score ---
    score_raw = data.get("score") or {}
    if not isinstance(score_raw, dict):
        score_raw = {}
    score = {
        "inbound": str(score_raw.get("inbound", "") or score_raw.get("inbound_score", "") or ""),
        "outbound": str(score_raw.get("outbound", "") or score_raw.get("outbound_score", "") or ""),
    }

    # --- Tags/flags: real API uses "tags", older/mock format may use "issues" ---
    tags_raw = data.get("tags") or data.get("issues") or {}
    if not isinstance(tags_raw, dict):
        tags_raw = {}
    issues = {
        "is_vpn":     tags_raw.get("is_vpn"),
        "is_proxy":   tags_raw.get("is_proxy"),
        "is_tor":     tags_raw.get("is_tor"),
        "is_hosting": tags_raw.get("is_hosting"),
        "is_cloud":   tags_raw.get("is_cloud"),
        "is_mobile":  tags_raw.get("is_mobile"),
        "is_darkweb": tags_raw.get("is_darkweb"),
        "is_scanner": tags_raw.get("is_scanner"),
        "is_snort":   tags_raw.get("is_snort"),
    }

    # --- Whois: real API wraps in {"count": N, "data": [...]} ---
    whois_container = data.get("whois") or {}
    if isinstance(whois_container, dict) and "data" in whois_container:
        whois_list = whois_container.get("data") or []
        whois_raw = whois_list[0] if whois_list else {}
    else:
        whois_raw = whois_container if isinstance(whois_container, dict) else {}
    whois = {
        "org_name":    whois_raw.get("org_name") or whois_raw.get("organization"),
        "country":     whois_raw.get("org_country_code") or whois_raw.get("country") or whois_raw.get("country_code"),
        "city":        whois_raw.get("city"),
        "latitude":    whois_raw.get("latitude"),
        "longitude":   whois_raw.get("longitude"),
        "postal_code": whois_raw.get("postal_code"),
        "asn_name":    whois_raw.get("as_name"),
        "asn_no":      whois_raw.get("as_no"),
    }

    # --- Ports: real API wraps in {"count": N, "data": [...]} ---
    port_container = data.get("port") or data.get("ports") or {}
    if isinstance(port_container, dict) and "data" in port_container:
        ports_raw = port_container.get("data") or []
    elif isinstance(port_container, list):
        ports_raw = port_container
    else:
        ports_raw = []
    ports = []
    for entry in ports_raw:
        if isinstance(entry, dict):
            ports.append({
                "port":        entry.get("open_port_no") or entry.get("port"),
                "socket":      entry.get("socket") or entry.get("socket_type") or "tcp",
                "protocol":    entry.get("protocol"),
                "app_name":    entry.get("app_name"),
                "app_version": entry.get("app_version"),
                "banner":      entry.get("banner"),
            })
        else:
            try:
                ports.append({"port": int(entry), "socket": "tcp", "protocol": None,
                               "app_name": None, "app_version": None, "banner": None})
            except (TypeError, ValueError):
                continue

    # --- Vulnerabilities (CVE data, requires full=true param) ---
    vuln_container = data.get("vulnerability") or {}
    if isinstance(vuln_container, dict) and "data" in vuln_container:
        vulns_raw = vuln_container.get("data") or []
    elif isinstance(vuln_container, list):
        vulns_raw = vuln_container
    else:
        vulns_raw = []
    vulnerabilities = []
    for v in vulns_raw:
        if not isinstance(v, dict):
            continue
        cve_id = v.get("cve_id")
        if not cve_id:
            continue
        vulnerabilities.append({
            "cve_id":       cve_id,
            "description":  v.get("cve_description"),
            "cvssv2_score": v.get("cvssv2_score"),
            "cvssv3_score": v.get("cvssv3_score"),
            "app_name":     v.get("app_name"),
            "app_version":  v.get("app_version"),
        })

    # --- IP categories (threat classification labels) ---
    cat_container = data.get("ip_category") or {}
    if isinstance(cat_container, dict) and "data" in cat_container:
        cats_raw = cat_container.get("data") or []
    elif isinstance(cat_container, list):
        cats_raw = cat_container
    else:
        cats_raw = []
    categories = [c.get("type") for c in cats_raw if isinstance(c, dict) and c.get("type")]

    # --- IDS alert count and scanning record count ---
    ids_container = data.get("ids") or {}
    ids_count = ids_container.get("count", 0) if isinstance(ids_container, dict) else 0

    scan_container = data.get("scanning_record") or {}
    scanning_count = scan_container.get("count", 0) if isinstance(scan_container, dict) else 0

    return {
        "ip":              ip,
        "score":           score,
        "issues":          issues,
        "whois":           whois,
        "ports":           ports,
        "vulnerabilities": vulnerabilities,
        "categories":      categories,
        "ids_count":       ids_count,
        "scanning_count":  scanning_count,
    }


def _parse_domain_report(domain: str, body: dict | None) -> dict | None:
    if not body:
        return None
    data = body.get("data")
    if data is None:
        data = body
    if not isinstance(data, dict):
        return None

    risk = {
        "score": data.get("score") or data.get("risk_score"),
        "grade": data.get("grade") or data.get("risk_grade"),
        "abuse_record_count": data.get("abuse_record_count") or data.get("abuse_count"),
        "current_service": data.get("current_service"),
        "report": data.get("report") or data.get("risk_report"),
    }
    out = {
        "domain": domain,
        "risk": {k: v for k, v in risk.items() if v is not None},
    }
    if not out["risk"]:
        out["risk"] = dict(data)
    return out


_STOP_MESSAGES = {
    STOP_AUTH: "API key is invalid or expired — skipping remaining Criminal IP requests",
    STOP_CREDIT: "API credit/quota exhausted — skipping remaining Criminal IP requests",
    STOP_RATE: "Rate limit exceeded — skipping remaining Criminal IP requests",
}

_MAX_CONSECUTIVE_FAILURES = 3


def run_criminalip_enrichment(combined_result: dict, settings: dict) -> dict:
    """
    Run Criminal IP enrichment: domain report (domain mode) and per-IP data.

    Stops early on auth/credit errors (single message) or after
    ``_MAX_CONSECUTIVE_FAILURES`` consecutive data failures.

    Mutates combined_result in place with key ``criminalip``.
    """
    if not settings.get("CRIMINALIP_ENABLED", False):
        return combined_result

    api_key = settings.get("CRIMINALIP_API_KEY", "")
    key_rotator = settings.get("CRIMINALIP_KEY_ROTATOR")

    if not _effective_key(api_key, key_rotator):
        print("[!][CriminalIP] No API key configured — skipping")
        return combined_result

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "CriminalIP")

    print("[*][CriminalIP] Starting OSINT enrichment")
    print(f"[+][CriminalIP] Extracted {len(ips)} unique IPs for enrichment")

    cip_data: dict = {
        "ip_reports": [],
        "domain_report": None,
    }

    def _handle_stop(reason: str) -> None:
        msg = _STOP_MESSAGES.get(reason, f"Stopping Criminal IP requests ({reason})")
        print(f"[!][CriminalIP] {msg}")

    try:
        need_sleep = False
        stopped = False

        if domain and not is_ip_mode:
            print(f"[*][CriminalIP] Fetching domain report for {domain}...")
            raw, stop = _cip_get(
                "domain/report",
                api_key,
                key_rotator,
                params={"query": domain},
            )
            if stop:
                _handle_stop(stop)
                stopped = True
            else:
                cip_data["domain_report"] = _parse_domain_report(domain, raw)
                if cip_data["domain_report"]:
                    print(f"[+][CriminalIP] Domain report retrieved for {domain}")
                else:
                    print(f"[!][CriminalIP] No domain report data for {domain}")
            need_sleep = True

        max_workers = settings.get("CRIMINALIP_WORKERS", 5)
        rate_limiter = _RateLimiter(1.0)
        stop_event = threading.Event()
        if stopped:
            stop_event.set()

        def _enrich_single_ip(ip, api_key, key_rotator, rate_limiter):
            """Enrich a single IP via Criminal IP. Returns (report_or_None, stop_reason_or_None)."""
            if stop_event.is_set():
                return None, None
            rate_limiter.wait()
            if stop_event.is_set():
                return None, None
            print(f"[*][CriminalIP] Fetching IP data for {ip}...")
            raw, stop = _cip_get("ip/data", api_key, key_rotator, params={"ip": ip, "full": "true"})
            if stop:
                stop_event.set()
                return None, stop
            report = _parse_ip_report(ip, raw)
            if report:
                vuln_count = len(report.get("vulnerabilities") or [])
                print(
                    f"[+][CriminalIP] IP data retrieved for {ip} "
                    f"(ports={len(report['ports'])}, vulns={vuln_count})"
                )
            else:
                logger.warning(f"CriminalIP: no data for {ip}")
            return report, None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_enrich_single_ip, ip, api_key, key_rotator, rate_limiter): ip
                for ip in ips
            }
            consecutive_fails = 0
            for future in as_completed(futures):
                try:
                    report, stop_reason = future.result()
                    if stop_reason:
                        _handle_stop(stop_reason)
                        stopped = True
                    elif report is not None:
                        cip_data["ip_reports"].append(report)
                        consecutive_fails = 0
                    else:
                        consecutive_fails += 1
                        if consecutive_fails >= _MAX_CONSECUTIVE_FAILURES:
                            print(
                                f"[!][CriminalIP] {consecutive_fails} consecutive failures "
                                f"-- skipping remaining IPs"
                            )
                            stopped = True
                            stop_event.set()
                except Exception as exc:
                    logger.warning(f"CriminalIP enrichment thread error for {futures[future]}: {exc}")

        if stopped:
            print(f"[!][CriminalIP] Some IPs may have been skipped due to early stop")
        print(
            f"[+][CriminalIP] Enrichment complete: "
            f"{len(cip_data['ip_reports'])} IP report(s), "
            f"domain={'yes' if cip_data['domain_report'] else 'no'}"
        )
    except Exception as e:
        logger.error(f"CriminalIP enrichment failed: {e}")
        print(f"[!][CriminalIP] Enrichment error: {e}")
        print(f"[!][CriminalIP] Pipeline continues without full Criminal IP data")

    combined_result["criminalip"] = cip_data
    return combined_result


def run_criminalip_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Deep copy of combined_result, run enrichment, return only the ``criminalip`` dict."""
    import copy

    snapshot = copy.deepcopy(combined_result)
    run_criminalip_enrichment(snapshot, settings)
    return snapshot.get("criminalip", {})
