"""
FOFA Pipeline Enrichment Module

Passive OSINT enrichment using the FOFA search API (base64 query).
Domain mode queries `domain="<domain>"`; IP mode runs `ip="<ip>"` per address.
Supports optional API key rotation via FOFA_KEY_ROTATOR.
"""
from __future__ import annotations

import base64
import re
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

    # IP mode: the target list only. A DNS answer (a PTR name's forward
    # address) need not be a target, and the lookup would be about it.
    metadata = combined_result.get("metadata") or {}
    if metadata.get("ip_mode") and "expanded_ips" in metadata:
        return sorted({ip for ip in metadata["expanded_ips"] or [] if ip})

    return sorted(ips)


def _fofa_effective_key(settings: dict, key_rotator) -> str:
    """The key to use now; "" once every pooled key has been refused (the main
    key was the pool's first member, so falling back to it would resurrect it)."""
    from recon.helpers import circuit_breaker as cb
    return cb.KeyPool(key_rotator, settings.get("FOFA_API_KEY", "") or "", label="FOFA").current()


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


def _fofa_breaker():
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker("fofa:search", label="FOFA", parent="fofa")


# FOFA reports most errors inside an HTTP 200 body ({"error": true, "errmsg":
# ...}), in English or Chinese. The message is read to classify, never logged:
# only its numeric error code reaches a detail.
_FOFA_KEY_MARKERS = ("account invalid", "invalid key", "key invalid", "api key",
                     "账号无效", "[-700]")
_FOFA_CREDIT_MARKERS = ("余额不足", "insufficient", "f点", "quota", "credit", "[820031]")
_FOFA_RATE_MARKERS = ("too fast", "too frequent", "too many", "频繁", "过快")
_FOFA_ERROR_CODE = re.compile(r"\[(-?\d{1,7})\]")


def _fofa_classify(resp):
    from recon.helpers import circuit_breaker as cb
    res = cb.json_result(resp, keyed=True)
    if not res.ok:
        return res
    data = res.data if isinstance(res.data, dict) else {}
    if data.get("error"):
        msg = str(data.get("errmsg") or "").lower()
        code = _FOFA_ERROR_CODE.search(msg)
        tag = f"FOFA error {code.group(1)}" if code else "FOFA error"
        if any(m in msg for m in _FOFA_KEY_MARKERS):
            return cb.CallResult(None, cb.Outcome.FATAL, f"{tag}: key rejected")
        if any(m in msg for m in _FOFA_CREDIT_MARKERS):
            return cb.CallResult(None, cb.Outcome.FATAL, f"{tag}: credit exhausted")
        if any(m in msg for m in _FOFA_RATE_MARKERS):
            return cb.CallResult(None, cb.Outcome.RATE_LIMIT, f"{tag}: rate limited")
        return cb.CallResult(None, cb.Outcome.TRANSIENT, tag)
    if not data.get("results"):
        return cb.CallResult(data, cb.Outcome.NO_DATA, res.detail)
    return cb.CallResult(data, cb.Outcome.OK, res.detail)


def _fofa_query(query: str, keys, size: int, *, admitted: bool = False, page: int = 1):
    """Run FOFA search/all through the FOFA breaker; returns a CallResult.

    ``keys`` is a KeyPool: the key is read per request, so rotation happens,
    and a refused key moves on to the next pooled one.
    """
    from recon.helpers import circuit_breaker as cb
    q_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")

    def send(key):
        params = {
            **_fofa_auth_params(key),
            "qbase64": q_b64,
            "fields": FOFA_FIELDS,
            "size": size,
        }
        # FOFA's default page is 1, so the first request is sent unchanged.
        if page > 1:
            params["page"] = page
        return requests.get(FOFA_API_URL, params=params, timeout=30)

    return cb.guarded_call(_fofa_breaker(), send, _fofa_classify, keys=keys, admitted=admitted)


def _fofa_search(
    query: str,
    api_key: str,
    size: int,
    key_rotator=None,
) -> dict | None:
    """Run FOFA search/all. Returns API JSON dict, or None on a failure, a
    refused key, a rate limit or a paused FOFA."""
    from recon.helpers import circuit_breaker as cb
    res = _fofa_query(query, cb.KeyPool(key_rotator, api_key, label="FOFA"), size)
    return res.data if res.answered else None


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


def _fofa_fetch_pages(query: str, keys, per_page: int, max_results: int, *,
                      admitted: bool = False, before_next_page=None, sink: list | None = None):
    """Rows for ``query``, page by page, until ``max_results`` rows, a short
    page, or FOFA's reported total. Returns (rows, total_hint, answered).

    One request returns at most ``per_page`` rows, so a single call silently
    capped FOFA_MAX_RESULTS at 100. A page that fails ends the walk and keeps
    the pages already fetched. ``before_next_page`` paces the next request and
    may return False to stop (a paused breaker). Rows are appended to ``sink``
    as they arrive, so a caller's error path still holds them.
    """
    rows_out = sink if sink is not None else []
    total_hint = 0
    answered = False
    page = 1
    while True:
        res = _fofa_query(query, keys, per_page, admitted=admitted, page=page)
        if not res.answered:
            break
        answered = True
        rows, total = _parse_fofa_rows(res.data or {})
        if page == 1:
            total_hint = total
        rows_out.extend(rows)
        if (len(rows_out) >= max_results or len(rows) < per_page
                or (total and page * per_page >= total)):
            break
        page += 1
        if before_next_page is not None and before_next_page() is False:
            break
    return rows_out, total_hint, answered


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

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "FOFA",
        settings,
        keys=[
            ("FOFA_ENABLED", "Toggle"),
            ("FOFA_MAX_RESULTS", "Limits"),
            ("FOFA_WORKERS", "Performance"),
            ("FOFA_API_KEY", "API credentials"),
            ("FOFA_KEY_ROTATOR", "API credentials"),
        ],
    )

    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(settings.get("FOFA_KEY_ROTATOR"), settings.get("FOFA_API_KEY", "") or "",
                      label="FOFA")
    if not keys.has_key:
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
    fofa_scope = cb.scope("fofa", label="FOFA", unit="query(ies)")
    breaker = _fofa_breaker()

    try:
        if is_ip_mode:
            print(f"[+][FOFA] IP mode -- {len(ips)} address(es)")
            max_workers = settings.get("FOFA_WORKERS", 5)
            rate_limiter = _RateLimiter(1.0)
            results_lock = threading.Lock()

            def _enrich_single_ip(ip, rate_limiter):
                """Query FOFA for a single IP. Returns (rows, total_hint) or None."""
                # Before the wait: the limiter reserves a slot before sleeping.
                if not breaker.allow():
                    return None
                rate_limiter.wait()
                q = f'ip="{ip}"'
                size = min(per_request_size, max_results)
                # One request per IP, never paged: max_results caps the
                # combined list in completion order, so paging would let one
                # shared-hosting IP spend the whole budget (in IPs x max/100
                # requests) and crowd out the target's own IPs, differently
                # every run.
                res = _fofa_query(q, keys, size, admitted=True)
                if not res.answered:
                    return None
                return _parse_fofa_rows(res.data or {})

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_enrich_single_ip, ip, rate_limiter): ip
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
                        logger.warning(f"FOFA enrichment thread error: {type(exc).__name__}")
        else:
            if not domain:
                print("[!][FOFA] No domain in scope — skipping")
            else:
                # FOFA indexes registrable domains: `domain=` on a deeper scan
                # root returns nothing. The org, once per run.
                from recon.helpers.org_work import once_per_org, org_of

                def _org_rows(d):
                    print(f"[+][FOFA] Domain mode — {d}")
                    rows: list[dict] = []
                    try:
                        _, hint, answered = _fofa_fetch_pages(
                            f'domain="{d}"', keys, per_request_size, max_results,
                            before_next_page=lambda: time.sleep(1), sink=rows)
                    except Exception:
                        aggregated.extend(rows)    # the error path keeps what arrived
                        raise
                    time.sleep(1)
                    return {"rows": rows, "total": hint, "answered": answered}

                answer, _ = once_per_org("fofa_domain", org_of(combined_result), _org_rows,
                                         answered=lambda a: a["answered"], label="FOFA")
                aggregated.extend(answer["rows"])
                total_hint = answer["total"]

        fofa_data["results"] = aggregated[:max_results]
        fofa_data["total"] = total_hint if total_hint else len(fofa_data["results"])
        print(f"[+][FOFA] Collected {len(fofa_data['results'])} result row(s) (total hint: {fofa_data['total']})")

    except Exception as e:
        logger.error(f"FOFA enrichment failed: {type(e).__name__}")
        print(f"[!][FOFA] Enrichment error: {type(e).__name__}")
        print(f"[!][FOFA] Pipeline continues with partial or empty FOFA data")
        fofa_data["results"] = aggregated[:max_results]
        fofa_data["total"] = total_hint if total_hint else len(fofa_data["results"])

    fofa_scope.finish("fofa_enrich", payload=fofa_data)
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
