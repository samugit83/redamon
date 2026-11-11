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


_STOP_DETAILS = {STOP_AUTH: "key rejected", STOP_CREDIT: "credit exhausted"}


def _cip_breaker(endpoint: str):
    """Three consecutive failures stop an endpoint (Criminal IP credits are
    scarce); a refused key, exhausted credit or a second 429 in a row stops
    the provider."""
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker(f"criminalip:{endpoint}", label="CriminalIP", parent="criminalip",
                          threshold=cb.INTERNAL_THRESHOLD)


def _cip_classify(resp):
    """404 and a 200 with nothing parseable are answers, never failures.

    Any other non-200 is FATAL when ``_classify_stop_reason`` says further
    requests are futile (bad key, exhausted credit), else TRANSIENT. The body
    is read only to classify.
    """
    from recon.helpers import circuit_breaker as cb
    status = cb.status_of(resp)
    if status == 200:
        try:
            return cb.CallResult(resp.json(), cb.Outcome.OK, "HTTP 200")
        except ValueError:
            return cb.CallResult(None, cb.Outcome.TRANSIENT, "non-JSON response")
    if status == 404:
        return cb.CallResult(None, cb.Outcome.NO_DATA, "HTTP 404")
    if status == 429:
        return cb.CallResult(None, cb.Outcome.RATE_LIMIT, "HTTP 429",
                             cb.retry_after_seconds(resp))
    try:
        body_text = str(resp.text or "")[:300]
    except Exception:  # noqa: BLE001
        body_text = ""
    stop = _classify_stop_reason(status or 0, body_text)
    if stop:
        return cb.CallResult(None, cb.Outcome.FATAL, f"{status} {_STOP_DETAILS.get(stop, stop)}")
    return cb.CallResult(None, cb.Outcome.TRANSIENT, f"HTTP {status}")


def _cip_get(path: str, keys, params: dict | None = None, *, admitted: bool = False,
             timeout: int = 30):
    """GET Criminal IP v1 through its breaker; returns a CallResult.

    A 429 waits out Retry-After and is sent once more (guarded_call).
    """
    from recon.helpers import circuit_breaker as cb
    breaker = _cip_breaker("domain" if path.startswith("domain") else "ip")
    url = f"{CRIMINALIP_API_BASE.rstrip('/')}/{path.lstrip('/')}"
    merged = dict(params or {})

    def send(key):
        return requests.get(url, headers={"x-api-key": key}, params=merged, timeout=timeout)

    return cb.guarded_call(breaker, send, _cip_classify, keys=keys, admitted=admitted)


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


def run_criminalip_enrichment(combined_result: dict, settings: dict) -> dict:
    """
    Run Criminal IP enrichment: domain report (domain mode) and per-IP data.

    Stops early on a refused key or exhausted credit (one line), and an
    endpoint after three consecutive real failures; no-data answers never
    count (recon/helpers/circuit_breaker.py).

    Mutates combined_result in place with key ``criminalip``.
    """
    if not settings.get("CRIMINALIP_ENABLED", False):
        return combined_result

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "CriminalIP",
        settings,
        keys=[
            ("CRIMINALIP_ENABLED", "Toggle"),
            ("CRIMINALIP_WORKERS", "Performance"),
            ("CRIMINALIP_API_KEY", "API credentials"),
            ("CRIMINALIP_KEY_ROTATOR", "API credentials"),
        ],
    )

    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(settings.get("CRIMINALIP_KEY_ROTATOR"),
                      (settings.get("CRIMINALIP_API_KEY", "") or "").strip(), label="CriminalIP")

    if not keys.has_key:
        print("[!][CriminalIP] No API key configured — skipping")
        return combined_result

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    all_ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(all_ips, combined_result, "CriminalIP")

    print("[*][CriminalIP] Starting OSINT enrichment")
    print(f"[+][CriminalIP] Extracted {len(ips)} unique IPs for enrichment")

    cip_data: dict = {
        "ip_reports": [],
        "domain_report": None,
    }
    cip_scope = cb.scope("criminalip", label="CriminalIP", unit="IP(s)")
    # IPs Criminal IP answered for, "no data" included; the prune keeps the
    # others' CVEs.
    checked: set[str] = set()
    failed = False

    try:
        def _domain_report(d):
            """The org's Criminal IP domain report, or None without one."""
            print(f"[*][CriminalIP] Fetching domain report for {d}...")
            res = _cip_get("domain/report", keys, params={"query": d})
            if res.answered:
                report = _parse_domain_report(d, res.data)
                if report:
                    print(f"[+][CriminalIP] Domain report retrieved for {d}")
                else:
                    print(f"[!][CriminalIP] No domain report data for {d}")
                return report
            if res.outcome is not cb.Outcome.SKIPPED:
                print(f"[!][CriminalIP] Domain report unavailable ({res.detail})")
            return None

        if domain and not is_ip_mode:
            # The org, once per run; the org's other groups reuse the answer.
            from recon.helpers.org_work import once_per_org, org_of
            cip_data["domain_report"], _ = once_per_org(
                "criminalip_domain", org_of(combined_result), _domain_report, label="CriminalIP")

        max_workers = settings.get("CRIMINALIP_WORKERS", 5)
        rate_limiter = _RateLimiter(1.0)
        ip_breaker = _cip_breaker("ip")

        def _enrich_single_ip(ip):
            """Enrich a single IP via Criminal IP. Returns the report or None."""
            # Before the wait: the limiter reserves a slot before sleeping.
            if not ip_breaker.allow():
                return None
            rate_limiter.wait()
            print(f"[*][CriminalIP] Fetching IP data for {ip}...")
            res = _cip_get("ip/data", keys, params={"ip": ip, "full": "true"}, admitted=True)
            if res.answered:
                checked.add(ip)
            if not res.ok:
                return None
            report = _parse_ip_report(ip, res.data)
            if report:
                vuln_count = len(report.get("vulnerabilities") or [])
                print(
                    f"[+][CriminalIP] IP data retrieved for {ip} "
                    f"(ports={len(report['ports'])}, vulns={vuln_count})"
                )
            return report

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_enrich_single_ip, ip): ip for ip in ips}
            for future in as_completed(futures):
                try:
                    report = future.result()
                    if report is not None:
                        cip_data["ip_reports"].append(report)
                except Exception as exc:
                    logger.warning(f"CriminalIP enrichment thread error: {type(exc).__name__}")

        print(
            f"[+][CriminalIP] Enrichment complete: "
            f"{len(cip_data['ip_reports'])} IP report(s), "
            f"domain={'yes' if cip_data['domain_report'] else 'no'}"
        )
    except Exception as e:
        logger.error(f"CriminalIP enrichment failed: {type(e).__name__}")
        print(f"[!][CriminalIP] Enrichment error: {type(e).__name__}")
        print(f"[!][CriminalIP] Pipeline continues without full Criminal IP data")
        failed = True

    cip_scope.finish("criminalip_enrich", payload=cip_data)
    from recon.helpers.passive_cve_coverage import note_cve_coverage
    note_cve_coverage("criminalip", "criminalip_enrich", ips, checked, considered=all_ips,
                      no_input=not all_ips, failed=failed)
    combined_result["criminalip"] = cip_data
    return combined_result


def run_criminalip_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Deep copy of combined_result, run enrichment, return only the ``criminalip`` dict."""
    import copy

    snapshot = copy.deepcopy(combined_result)
    run_criminalip_enrichment(snapshot, settings)
    return snapshot.get("criminalip", {})
