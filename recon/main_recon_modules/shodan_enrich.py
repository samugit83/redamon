"""
Shodan Pipeline Enrichment Module

Passive OSINT enrichment using the Shodan REST API.
Each feature is independently toggled via project settings.
When no API key is configured, Host Lookup, Reverse DNS, and Passive CVEs
use Shodan's free InternetDB API (no key required). Domain DNS requires a paid plan.

Features:
  - Host Lookup: IP geolocation, OS, ISP, open ports, services, banners
  - Reverse DNS: Discover hostnames for known IPs
  - Domain DNS: Subdomain enumeration + DNS records (paid Shodan plan)
  - Passive CVEs: Extract known CVEs from Shodan host data
"""
import os
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

import requests


class _RateLimiter:
    """Thread-safe rate limiter ensuring a minimum interval between requests.

    Reserves time slots under the lock but sleeps outside to allow
    other threads to reserve their own slots concurrently.
    """
    def __init__(self, interval: float):
        self._interval = interval
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            delay = self._interval - elapsed if elapsed < self._interval else 0.0
            self._last = now + delay  # reserve the slot
        if delay > 0:
            time.sleep(delay)

try:
    from recon.main_recon_modules.ip_filter import (
        collect_cdn_ips, filter_ips_for_enrichment, in_published_cdn_range, is_shared_edge_org)
except ImportError:
    from ip_filter import (
        collect_cdn_ips, filter_ips_for_enrichment, in_published_cdn_range, is_shared_edge_org)

logger = logging.getLogger(__name__)

# The two overrides let a test lab stand a stub API in for Shodan. Unset in any
# real deployment: whatever they name receives the Shodan API key.
SHODAN_API_BASE = os.environ.get("SHODAN_API_BASE") or "https://api.shodan.io"
INTERNETDB_BASE = os.environ.get("SHODAN_INTERNETDB_BASE") or "https://internetdb.shodan.io"


def _normalize_shodan_ssl(ssl_block) -> dict:
    """Normalise Shodan's per-service ``ssl`` block to RedAmon's cert shape.

    Phase 0.6: this block was parsed by Shodan and thrown away, despite
    carrying CN, issuer, serial, expiry, JARM and JA3S for free -- data the
    pipeline otherwise pays TLS handshakes to obtain.
    """
    if not isinstance(ssl_block, dict):
        return {}
    cert = ssl_block.get("cert") or {}
    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}
    fingerprint = (cert.get("fingerprint") or {}) if isinstance(cert.get("fingerprint"), dict) else {}
    issuer_parts = [issuer.get("CN"), issuer.get("O")]
    cipher = ssl_block.get("cipher") or {}
    out = {
        "subject_cn": subject.get("CN") or "",
        "issuer": ", ".join([x for x in issuer_parts if x]),
        "issuer_cn": issuer.get("CN") or "",
        "serial": str(cert.get("serial") or "") or None,
        "expired": bool(cert.get("expired")) if cert.get("expired") is not None else None,
        "not_before": cert.get("issued") or None,
        "not_after": cert.get("expires") or None,
        "fingerprint_sha256": fingerprint.get("sha256") or None,
        "jarm": ssl_block.get("jarm") or None,
        "ja3s": ssl_block.get("ja3s") or None,
        "cipher": cipher.get("name") if isinstance(cipher, dict) else None,
        "versions": [v for v in (ssl_block.get("versions") or []) if isinstance(v, str)],
    }
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def _extract_ips_from_recon(combined_result: dict) -> list[str]:
    """Extract unique IPv4 addresses from domain discovery results."""
    ips: set[str] = set()
    dns_data = combined_result.get("dns", {})

    # Root domain IPs
    domain_dns = dns_data.get("domain", {})
    for ip in domain_dns.get("ips", {}).get("ipv4", []):
        if ip:
            ips.add(ip)

    # Subdomain IPs
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


class ShodanApiKeyError(Exception):
    """Raised when the Shodan API key is invalid (401) or lacks access (403) to abort early.

    ``local`` marks a plan-gated 403: that endpoint is closed to this plan, the
    key itself still works for the others.
    """

    def __init__(self, message: str, *, local: bool = False, detail: str = ""):
        super().__init__(message)
        self.local = local
        self.detail = detail or ("403 plan-gated" if local else "401 key rejected")


def _shodan_endpoint(endpoint: str) -> str:
    if endpoint.startswith("/shodan/host/search"):
        return "search"
    if endpoint.startswith("/shodan/host/"):
        return "host"
    if endpoint.startswith("/dns/reverse"):
        return "dns_reverse"
    if endpoint.startswith("/dns/domain/"):
        return "dns_domain"
    return "api"


def _shodan_breaker(name: str):
    """A refused key or a second 429 in a row stops every Shodan endpoint; a
    plan-gated 403, timeouts and 5xx stop only the endpoint that failed."""
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker(f"shodan:{name}", label="Shodan", parent="shodan")


def _shodan_classify(resp):
    from recon.helpers import circuit_breaker as cb
    status = cb.status_of(resp)
    if status == 401:
        return cb.CallResult(None, cb.Outcome.FATAL, "401 key rejected")
    if status == 403:
        return cb.CallResult(None, cb.Outcome.FATAL, "403 plan-gated", local=True)
    return cb.json_result(resp, keyed=True)


def _shodan_call(endpoint: str, keys, params: dict | None = None, *, admitted: bool = False):
    """GET the Shodan API through the endpoint's breaker; returns a CallResult.

    ``keys`` is a KeyPool. The key travels as the ``key`` query parameter,
    which is why no exception text ever reaches a log line.
    """
    from recon.helpers import circuit_breaker as cb
    url = f"{SHODAN_API_BASE}{endpoint}"

    def send(key):
        all_params = {"key": key}
        if params:
            all_params.update(params)
        return requests.get(url, params=all_params, timeout=30)

    return cb.guarded_call(_shodan_breaker(_shodan_endpoint(endpoint)), send, _shodan_classify,
                           keys=keys, admitted=admitted)


def _shodan_get(endpoint: str, api_key: str, params: dict | None = None, key_rotator=None,
                *, admitted: bool = False) -> dict | None:
    """GET the Shodan API through the endpoint's breaker, with optional key rotation.

    Returns the parsed body, or None for no data, a failure, or a paused
    endpoint. A 429 waits out Retry-After and is sent once more. Raises
    ShodanApiKeyError when the key is refused (401, after every pooled key) or
    the endpoint is plan-gated (403), and again on every later call while
    that stays true, so callers keep taking their fallback path.
    """
    from recon.helpers import circuit_breaker as cb
    breaker = _shodan_breaker(_shodan_endpoint(endpoint))
    res = _shodan_call(endpoint, cb.KeyPool(key_rotator, api_key, label="Shodan"), params,
                       admitted=admitted)
    if res.answered:
        cb.run_cache("shodan_answered").put(endpoint, True)
    if res.ok:
        return res.data
    if res.outcome is cb.Outcome.FATAL or (res.outcome is cb.Outcome.SKIPPED and breaker.is_fatal):
        local = res.local if res.outcome is cb.Outcome.FATAL else not bool(
            breaker.parent and breaker.parent.is_fatal)
        if local:
            raise ShodanApiKeyError("Shodan API requires paid membership for this feature (403)",
                                    local=True)
        raise ShodanApiKeyError("Shodan API key is invalid or expired (401)")
    return None


def _internetdb_breaker():
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker("internetdb", label="InternetDB")


def _internetdb_get(ip: str) -> dict | None:
    """Query Shodan InternetDB (free, no key required) for basic host data.

    Host lookup, reverse DNS and passive CVEs all ask for the same IPs, so an
    answer (including "no data") is cached for the run; a failure is not.
    """
    from recon.helpers import circuit_breaker as cb
    cache = cb.run_cache("internetdb")
    hit, cached = cache.get(ip)
    if hit:
        return cached
    res = cb.guarded_call(
        _internetdb_breaker(),
        lambda: requests.get(f"{INTERNETDB_BASE}/{ip}", timeout=15),
        lambda resp: cb.json_result(resp, keyed=False),
    )
    if res.ok:
        cache.put(ip, res.data)
        return res.data
    if res.answered:
        cache.put(ip, None)
    return None


def _shodan_answered(endpoint: str, data) -> bool:
    """The Shodan API answered `endpoint` this run: data, or a genuine "no data"."""
    from recon.helpers import circuit_breaker as cb
    return data is not None or cb.run_cache("shodan_answered").get(endpoint)[0]


def _internetdb_answered(ip: str, data) -> bool:
    """InternetDB answered for `ip` this run (its run cache holds answers only)."""
    from recon.helpers import circuit_breaker as cb
    return data is not None or cb.run_cache("internetdb").get(ip)[0]


def _lookup_single_ip(ip: str, use_internetdb: bool, api_key: str, key_rotator,
                      rate_limiter: _RateLimiter, answered: set | None = None) -> dict | None:
    """Lookup a single IP via Shodan API or InternetDB. Thread-safe.

    Takes the InternetDB branch itself once the host API is refused or
    paused, so no IP is lost to a fallback that happens elsewhere. An IP that
    got an answer, "no data" included, is added to `answered`: the prune
    keeps the CVEs of the others.
    """
    if answered is None:
        answered = set()
    if not use_internetdb:
        from recon.helpers.circuit_breaker import Outcome
        host_breaker = _shodan_breaker("host")
        # Checked BEFORE the rate-limiter wait, which reserves its slot first.
        if host_breaker.allow():
            rate_limiter.wait()
            try:
                data = _shodan_get(f"/shodan/host/{ip}", api_key, key_rotator=key_rotator,
                                   admitted=True)
            except ShodanApiKeyError as e:
                # _shodan_get has recorded it; recording again keeps a stubbed
                # _shodan_get honest too, and a second FATAL is a no-op.
                host_breaker.record(Outcome.FATAL, e.detail, local=e.local)
                data = None
                use_internetdb = True
            if not use_internetdb:
                if _shodan_answered(f"/shodan/host/{ip}", data):
                    answered.add(ip)
                if data:
                    host_entry = {
                        "ip": ip,
                        "os": data.get("os"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "country_name": data.get("country_name"),
                        "city": data.get("city"),
                        "ports": data.get("ports", []),
                        "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
                        "tags": data.get("tags", []) or [],
                        "services": [],
                        "source": "shodan_api",
                    }
                    for svc in data.get("data", []):
                        host_entry["services"].append({
                            "port": svc.get("port"),
                            "transport": svc.get("transport", "tcp"),
                            "product": svc.get("product", ""),
                            "version": svc.get("version", ""),
                            "banner": (svc.get("data", "") or "")[:500],
                            "module": svc.get("_shodan", {}).get("module", ""),
                            "ssl": _normalize_shodan_ssl(svc.get("ssl")),
                            "vulns": _service_vulns(svc.get("vulns")),
                        })
                    logger.info(f"  Shodan host lookup: {ip} — {len(host_entry['ports'])} ports, "
                                f"{len(host_entry['vulns'])} vulns")
                    return host_entry
                return None
        else:
            use_internetdb = True

    # InternetDB path
    rate_limiter.wait()
    idb = _internetdb_get(ip)
    if _internetdb_answered(ip, idb):
        answered.add(ip)
    if idb:
        host_entry = {
            "ip": ip,
            "os": None,
            "isp": None,
            "org": None,
            "country_name": None,
            "city": None,
            "ports": idb.get("ports", []),
            "vulns": idb.get("vulns", []),
            "hostnames": idb.get("hostnames", []),
            "cpes": idb.get("cpes", []),
            "tags": idb.get("tags", []),
            "services": [],
            "source": "internetdb",
        }
        logger.info(f"  InternetDB host: {ip} — {len(host_entry['ports'])} ports, "
                    f"{len(host_entry['vulns'])} vulns")
        return host_entry
    return None


def _run_host_lookup(ips: list[str], api_key: str, key_rotator=None, max_workers: int = 5,
                     answered: set | None = None) -> list[dict]:
    """Fetch Shodan host data for each IP using parallel workers.

    Tries the full /shodan/host/{ip} API first. Once that is refused (401,
    or 403 = paid membership required), paused by its breaker, or no API key
    is configured, each IP takes the free InternetDB API
    (https://internetdb.shodan.io/{ip}) instead: ports, hostnames, CPEs, CVEs
    and tags -- no banners or geo data.

    The first IP is looked up alone, so a refused key costs one call rather
    than one per worker. Every IP that got an answer goes into `answered`.
    """
    if answered is None:
        answered = set()
    hosts = []
    use_internetdb = not api_key  # No key -> go straight to InternetDB

    if use_internetdb:
        logger.info("No Shodan API key — using InternetDB (free, no key required)")
        print("[*][Shodan] No API key — using InternetDB (free, no key required)")

    # Rate limiter: 1 req/sec for Shodan API, 0.5s for InternetDB
    rate_limiter = _RateLimiter(0.5 if use_internetdb else 1.0)
    if not ips:
        return hosts

    first = _lookup_single_ip(ips[0], use_internetdb, api_key, key_rotator, rate_limiter, answered)
    if first:
        hosts.append(first)
    rest = ips[1:]
    if not use_internetdb and _shodan_breaker("host").is_fatal:
        logger.info("Paid API unavailable — falling back to InternetDB (free)")
        print("[*][Shodan] Falling back to InternetDB (free, no key required)")

    workers = min(max_workers, len(rest))
    if workers <= 1:
        for ip in rest:
            result = _lookup_single_ip(ip, use_internetdb, api_key, key_rotator, rate_limiter,
                                       answered)
            if result:
                hosts.append(result)
        return hosts

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_lookup_single_ip, ip, use_internetdb, api_key, key_rotator,
                            rate_limiter, answered): ip
            for ip in rest
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    hosts.append(result)
            except Exception as e:
                logger.warning(f"Host lookup failed: {type(e).__name__}")

    return hosts


def _run_reverse_dns(ips: list[str], api_key: str, hosts: list[dict] | None = None, key_rotator=None, max_workers: int = 5) -> dict[str, list[str]]:
    """Batch reverse DNS lookup.

    Tries the Shodan /dns/reverse API first. On 403, falls back to
    extracting hostnames from InternetDB host data (if available) or
    querying InternetDB per-IP.
    """
    results: dict[str, list[str]] = {}

    # Try Shodan API first (only if we have a key)
    if api_key:
        try:
            for i in range(0, len(ips), 100):
                batch = ips[i:i + 100]
                data = _shodan_get("/dns/reverse", api_key, params={"ips": ",".join(batch)}, key_rotator=key_rotator)
                if data:
                    for ip, hostnames in data.items():
                        if hostnames:
                            results[ip] = hostnames
                            logger.info(f"  Shodan reverse DNS: {ip} → {hostnames}")
                time.sleep(1)
            if not _shodan_breaker("dns_reverse").is_open:
                return results
            print("[*][Shodan] Reverse DNS API paused — InternetDB for the IPs it did not cover")
        except ShodanApiKeyError:
            logger.info("Paid DNS API unavailable — extracting hostnames from InternetDB data")
            print("[*][Shodan] Falling back to InternetDB for reverse DNS")
    else:
        logger.info("No Shodan API key — using InternetDB for reverse DNS")
        print("[*][Shodan] No API key — using InternetDB for reverse DNS")

    # Fallback: extract hostnames from existing InternetDB host data
    if hosts:
        for host in hosts:
            hns = host.get("hostnames", [])
            if hns:
                results[host["ip"]] = hns
                logger.info(f"  InternetDB reverse DNS: {host['ip']} → {hns}")

    # For IPs not covered by host data, query InternetDB directly (parallel)
    covered = set(results.keys())
    uncovered = [ip for ip in ips if ip not in covered]
    if uncovered:
        rate_limiter = _RateLimiter(0.5)
        workers = min(max_workers, len(uncovered))

        def _lookup_rdns(ip):
            rate_limiter.wait()
            idb = _internetdb_get(ip)
            if idb and idb.get("hostnames"):
                return ip, idb["hostnames"]
            return ip, None

        with ThreadPoolExecutor(max_workers=workers) as executor:
            for ip, hostnames in executor.map(lambda ip: _lookup_rdns(ip), uncovered):
                if hostnames:
                    results[ip] = hostnames
                    logger.info(f"  InternetDB reverse DNS: {ip} → {hostnames}")

    return results


def _run_domain_dns(domain: str, api_key: str, key_rotator=None) -> dict:
    """Domain DNS enumeration (GET /dns/domain/{domain}) — requires paid plan.

    No free fallback exists for domain DNS. On 403 or missing key returns
    empty dict and logs a clear message (no abort — pipeline continues).
    """
    if not api_key:
        print("[!][Shodan] Domain DNS requires an API key — skipping")
        return {}

    try:
        data = _shodan_get(f"/dns/domain/{domain}", api_key, key_rotator=key_rotator)
    except ShodanApiKeyError:
        print("[!][Shodan] Domain DNS requires a paid plan — skipping (other features continue)")
        return {}

    if not data:
        return {}

    # The name asked: the writer builds each record's host on it, never on the
    # group's scan root (a deeper root would turn `mail` into mail.<root>).
    result = {
        "domain": domain,
        "subdomains": data.get("subdomains", []),
        "records": [],
    }
    for record in data.get("data", []):
        result["records"].append({
            "subdomain": record.get("subdomain", ""),
            "type": record.get("type", ""),
            "value": record.get("value", ""),
        })
    sub_count = len(result["subdomains"])
    rec_count = len(result["records"])
    logger.info(f"  Shodan domain DNS: {domain} — {sub_count} subdomains, {rec_count} records")
    return result


def _service_vulns(raw) -> list[dict]:
    """A Shodan banner's `vulns` map ({CVE: {cvss, verified, ...}}) as a list."""
    if not isinstance(raw, dict):
        return []
    out = []
    for cve_id, info in raw.items():
        info = info if isinstance(info, dict) else {}
        try:
            cvss = float(info["cvss"]) if info.get("cvss") is not None else None
        except (TypeError, ValueError):
            cvss = None
        out.append({"cve_id": cve_id, "cvss": cvss, "verified": bool(info.get("verified"))})
    return out


def _is_shared_edge_host(host: dict) -> bool:
    """True when Shodan itself tags the IP as a CDN, or attributes it to a
    shared edge provider. A CVE Shodan correlates to such an IP describes
    whatever answered there for whichever customer, not the target; Akamai,
    G-Core and StackPath also rent VMs, so their edges are recognised by the
    `cdn` tag rather than the org name (see is_shared_edge_org)."""
    tags = {str(t).lower() for t in (host.get("tags") or [])}
    if "cdn" in tags:
        return True
    return is_shared_edge_org(" ".join(str(host.get(k) or "") for k in ("org", "isp")))


_GRADE_RANK = {"passive_catalog": 0, "passive_version_match": 1, "passive_verified": 2}


def _passive_cve_entry(cve_id: str, ip: str, source: str, svc: Optional[dict] = None,
                       cvss: Optional[float] = None, verified: bool = False) -> dict:
    """One CVE as the graph writer stores it.

    `detection_method` grades the evidence: passive_verified (Shodan checked
    it), passive_version_match (a banner with product and version), or
    passive_catalog (the IP's CVE list alone, no service or version seen).
    """
    product = (svc or {}).get("product") or None
    version = (svc or {}).get("version") or None
    if verified:
        method = "passive_verified"
    elif product and version:
        method = "passive_version_match"
    else:
        method = "passive_catalog"
    return {
        "cve_id": cve_id,
        "ip": ip,
        "source": source,
        "port": (svc or {}).get("port"),
        "product": product,
        "version": version,
        "cvss": cvss,
        "verified": verified,
        "detection_method": method,
    }


def _extract_passive_cves(hosts: list[dict], ips: list[str], api_key: str, key_rotator=None,
                          max_workers: int = 5, covered: set | None = None,
                          host_answered: set | None = None) -> list[dict]:
    """Extract CVEs from host lookup data.

    If host data exists (from host lookup, which may be InternetDB data),
    CVEs are extracted directly. If no host data, queries InternetDB per-IP
    (free, no key required) using parallel workers.

    A banner's own CVEs carry its port, product and version; the IP-level
    list fills in the rest as catalog matches. A shared CDN/edge IP yields
    none: its banners belong to the provider and its other tenants.

    `covered` receives every IP whose CVEs this run re-checked: the IPs the
    host lookup got an answer for (`host_answered`), or those InternetDB
    answered here. A "no data" answer counts; a failure does not.
    """
    if covered is None:
        covered = set()
    cves: list[dict] = []
    seen_cve_ip: set[tuple[str, str]] = set()
    skipped_edge = 0

    # If host lookup already ran, extract from existing data (works for both
    # Shodan API and InternetDB sources since both populate 'vulns')
    if hosts:
        covered.update(host_answered or ())
        covered.update(h["ip"] for h in hosts)
        for host in hosts:
            ip = host["ip"]
            if _is_shared_edge_host(host):
                skipped_edge += 1
                continue
            source = host.get("source", "shodan_host_lookup")
            # One entry per CVE per IP: the best-evidenced banner wins (a
            # verified one over a version match over a bare listing).
            best: dict[str, dict] = {}
            for svc in host.get("services", []):
                for v in svc.get("vulns") or []:
                    entry = _passive_cve_entry(v["cve_id"], ip, source, svc, v.get("cvss"), v.get("verified", False))
                    held = best.get(v["cve_id"])
                    if held is None or _GRADE_RANK[entry["detection_method"]] > _GRADE_RANK[held["detection_method"]]:
                        best[v["cve_id"]] = entry
            for cve_id in host.get("vulns", []):
                best.setdefault(cve_id, _passive_cve_entry(cve_id, ip, source))
            for cve_id, entry in best.items():
                if (cve_id, ip) not in seen_cve_ip:
                    seen_cve_ip.add((cve_id, ip))
                    cves.append(entry)
    else:
        # No host data -- query InternetDB directly (free, no key needed)
        print("[*][Shodan] Querying InternetDB for passive CVEs (free)")
        rate_limiter = _RateLimiter(0.5)
        workers = min(max_workers, len(ips))

        def _query_cves(ip):
            rate_limiter.wait()
            return ip, _internetdb_get(ip)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            for ip, idb in executor.map(_query_cves, ips):
                if _internetdb_answered(ip, idb):
                    covered.add(ip)
                if idb:
                    if _is_shared_edge_host(idb):
                        skipped_edge += 1
                        continue
                    for cve_id in idb.get("vulns", []):
                        key = (cve_id, ip)
                        if key not in seen_cve_ip:
                            seen_cve_ip.add(key)
                            cves.append(_passive_cve_entry(cve_id, ip, "internetdb"))

    if skipped_edge:
        print(f"[*][Shodan] Skipped passive CVEs on {skipped_edge} shared CDN/edge IP(s)")
    logger.info(f"  Shodan passive CVEs: {len(cves)} CVEs across {len(set(c['ip'] for c in cves))} IPs")
    return cves


def run_shodan_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run Shodan OSINT enrichment on discovered IPs and domains.

    Runs after domain discovery / IP recon, before port scanning.
    Each feature is independently gated by its own toggle + the global API key.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'shodan' key added
    """
    api_key = settings.get("SHODAN_API_KEY", "")
    key_rotator = settings.get("SHODAN_KEY_ROTATOR")
    shodan_workers = settings.get("SHODAN_WORKERS", 5)

    # IP only asks no name and keeps none (I-7), whatever the stored toggle
    # says: a run that skipped the settings overrides still gets no PTR here.
    from recon.helpers.ip_hostnames import names_off
    no_names = names_off(combined_result, settings)

    do_host = settings.get("SHODAN_HOST_LOOKUP", False)
    do_rdns = settings.get("SHODAN_REVERSE_DNS", False) and not no_names
    do_ddns = settings.get("SHODAN_DOMAIN_DNS", False)
    do_cves = settings.get("SHODAN_PASSIVE_CVES", False)

    if not any([do_host, do_rdns, do_ddns, do_cves]):
        return combined_result

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "Shodan",
        settings,
        keys=[
            ("SHODAN_HOST_LOOKUP", "Lookups"),
            ("SHODAN_REVERSE_DNS", "Lookups"),
            ("SHODAN_DOMAIN_DNS", "Lookups"),
            ("SHODAN_PASSIVE_CVES", "Lookups"),
            ("SHODAN_WORKERS", "Performance"),
            ("SHODAN_API_KEY", "API credentials"),
            ("SHODAN_KEY_ROTATOR", "API credentials"),
        ],
    )

    print(f"\n[PHASE] Shodan OSINT Enrichment")
    print("-" * 40)

    all_ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(all_ips, combined_result, "Shodan")
    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)

    print(f"[+][Shodan] Extracted {len(ips)} unique IPs for enrichment")

    shodan_data: dict[str, Any] = {
        "hosts": [],
        "reverse_dns": {},
        "domain_dns": {},
        "cves": [],
    }
    from recon.helpers import circuit_breaker as cb
    shodan_scope = cb.scope(("shodan", "internetdb"), label="Shodan", unit="call(s)")
    host_answered: set[str] = set()
    cve_checked: set[str] = set()
    failed = False

    try:
        # 1. Host Lookup (falls back to InternetDB on 403)
        if do_host and ips:
            print(f"[*][Shodan] Running host lookup on {len(ips)} IPs...")
            shodan_data["hosts"] = _run_host_lookup(ips, api_key, key_rotator=key_rotator,
                                                    max_workers=shodan_workers,
                                                    answered=host_answered)
            if no_names:
                for host in shodan_data["hosts"]:
                    if isinstance(host, dict) and host.get("hostnames"):
                        host["hostnames"] = []
            print(f"[+][Shodan] Host lookup complete: {len(shodan_data['hosts'])} hosts enriched")

        # 2. Reverse DNS (falls back to InternetDB hostnames on 403)
        if do_rdns and ips:
            print(f"[*][Shodan] Running reverse DNS on {len(ips)} IPs...")
            shodan_data["reverse_dns"] = _run_reverse_dns(ips, api_key, shodan_data["hosts"], key_rotator=key_rotator, max_workers=shodan_workers)
            print(f"[+][Shodan] Reverse DNS complete: {len(shodan_data['reverse_dns'])} IPs resolved")

        # 3. Domain DNS (domain mode only, paid Shodan plan — no free fallback).
        # Asked of the org, once per run; the org's other groups reuse it.
        if do_ddns and domain and not is_ip_mode:
            from recon.helpers.org_work import once_per_org, org_of
            org = org_of(combined_result)
            print(f"[*][Shodan] Running domain DNS for {org}...")
            shodan_data["domain_dns"], _ = once_per_org(
                "shodan_domain_dns", org,
                lambda o: _run_domain_dns(o, api_key, key_rotator=key_rotator), label="Shodan")
            sub_count = len(shodan_data["domain_dns"].get("subdomains", []))
            print(f"[+][Shodan] Domain DNS complete: {sub_count} subdomains found")

        # 4. Passive CVEs (reuses host data, falls back with hosts to InternetDB)
        if do_cves and ips:
            print(f"[*][Shodan] Extracting passive CVEs...")
            shodan_data["cves"] = _extract_passive_cves(
                shodan_data["hosts"], ips, api_key, key_rotator=key_rotator,
                max_workers=shodan_workers, covered=cve_checked, host_answered=host_answered,
            )
            print(f"[+][Shodan] Passive CVEs complete: {len(shodan_data['cves'])} CVEs found")

    except ShodanApiKeyError as e:
        # Only reaches here for 401 (invalid key) — 403 is handled per-function
        print(f"[!][Shodan] API key error: {e}")
        print(f"[!][Shodan] Aborting enrichment — pipeline continues")
        failed = True

    except Exception as e:
        logger.error(f"Shodan enrichment failed: {type(e).__name__}")
        print(f"[!][Shodan] Enrichment error: {type(e).__name__}")
        print(f"[!][Shodan] Pipeline continues without Shodan data")
        failed = True

    shodan_scope.finish("shodan_enrich", payload=shodan_data)
    if do_cves:
        from recon.helpers.passive_cve_coverage import note_cve_coverage
        note_cve_coverage("shodan", "shodan_enrich", ips, cve_checked, considered=all_ips,
                          no_input=not all_ips, failed=failed)
    combined_result["shodan"] = shodan_data
    return combined_result


def drop_cdn_ips(shodan_data: dict, combined_result: dict) -> int:
    """Drop Shodan results for IPs that turned out to be CDN edges. Returns how many.

    In the full pipeline Shodan runs beside the port scan, on a snapshot taken
    before naabu flagged any CDN IP, so its own filter could not skip them. An
    edge's ports and CVEs belong to the CDN, not to the target. Domain DNS
    records are kept: they say what the names resolve to, not what runs there.
    """
    hosts = shodan_data.get("hosts") or []
    cdn_ips = collect_cdn_ips(combined_result) | {
        h.get("ip") for h in hosts if h.get("ip") and _is_shared_edge_host(h)
    }

    def is_cdn(ip) -> bool:
        return bool(ip) and (ip in cdn_ips or in_published_cdn_range(ip))

    reverse_dns = shodan_data.get("reverse_dns") or {}
    cves = shodan_data.get("cves") or []
    dropped = ({h.get("ip") for h in hosts if is_cdn(h.get("ip"))}
               | {ip for ip in reverse_dns if is_cdn(ip)}
               | {c.get("ip") for c in cves if is_cdn(c.get("ip"))})
    if not dropped:
        return 0
    if "hosts" in shodan_data:
        shodan_data["hosts"] = [h for h in hosts if h.get("ip") not in dropped]
    if "reverse_dns" in shodan_data:
        shodan_data["reverse_dns"] = {ip: v for ip, v in reverse_dns.items() if ip not in dropped}
    if "cves" in shodan_data:
        shodan_data["cves"] = [c for c in cves if c.get("ip") not in dropped]
    return len(dropped)


def drop_shared_edge_cves(shodan_data: dict, edge_ips) -> int:
    """Drop the CVEs on the IPs IP attribution tagged shared_edge. Returns how many.

    A shared edge's CVEs describe the provider and its other tenants, not the
    target. Only the CVEs go: in a full run the hosts, ports and names were
    written at GROUP 3, before the tag existed.
    """
    edge_ips = set(edge_ips or ())
    cves = shodan_data.get("cves") or []
    if not edge_ips or not cves:
        return 0
    kept = [c for c in cves if c.get("ip") not in edge_ips]
    shodan_data["cves"] = kept
    return len(cves) - len(kept)


def reachcheck_cves(shodan_data: dict, covers, *, clear_unknown: bool = True) -> dict:
    """Set each CVE's `port_confirmed` from `covers(ip, port)`. No traffic.

    True: this run's port scan found the port open; False: it looked at the
    port and did not; None: it did not look, so nothing is known. With
    `clear_unknown` an unknown is written as None, which removes an older
    value: a full run is the authority on its own scan. Partial recon has no
    scan and passes False, so it only ever confirms. A UDP banner is unknown:
    the port scans are TCP. Returns how many of each.
    """
    transport = {
        (h.get("ip"), svc.get("port")): str(svc.get("transport") or "tcp").lower()
        for h in shodan_data.get("hosts") or [] for svc in h.get("services") or []
    }
    counts = {"open": 0, "closed": 0, "unknown": 0}
    for cve in shodan_data.get("cves") or []:
        ip, port = cve.get("ip"), cve.get("port")
        state = None
        if ip and isinstance(port, int) and transport.get((ip, port), "tcp") == "tcp":
            state = covers(ip, port)
        counts["open" if state is True else "closed" if state is False else "unknown"] += 1
        if state is not None or clear_unknown:
            cve["port_confirmed"] = state
    return counts


def run_shodan_enrichment_isolated(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run Shodan enrichment and return only the 'shodan' data dict.

    Thread-safe: does not mutate combined_result. Reads DNS/IP data from
    it but writes nothing back. Designed for parallel execution alongside
    other modules (e.g., port scan).

    Args:
        combined_result: The pipeline's combined result dictionary (read-only)
        settings: Project settings dict

    Returns:
        The 'shodan' data dictionary (just the enrichment payload)
    """
    import copy
    snapshot = copy.deepcopy(combined_result)
    run_shodan_enrichment(snapshot, settings)
    return snapshot.get("shodan", {})
