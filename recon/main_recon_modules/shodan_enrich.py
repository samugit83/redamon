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
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

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
    from recon.main_recon_modules.ip_filter import filter_ips_for_enrichment
except ImportError:
    from ip_filter import filter_ips_for_enrichment

logger = logging.getLogger(__name__)

SHODAN_API_BASE = "https://api.shodan.io"
INTERNETDB_BASE = "https://internetdb.shodan.io"


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

    # IP mode: expanded IPs from metadata
    if combined_result.get("metadata", {}).get("ip_mode"):
        for ip in combined_result["metadata"].get("expanded_ips", []):
            if ip:
                ips.add(ip)

    return sorted(ips)


class ShodanApiKeyError(Exception):
    """Raised when the Shodan API key is invalid (401) or lacks access (403) to abort early."""
    pass


def _shodan_get(endpoint: str, api_key: str, params: dict | None = None, key_rotator=None) -> dict | None:
    """Make a GET request to the Shodan API with error handling and optional key rotation."""
    effective_key = key_rotator.current_key if key_rotator and key_rotator.has_keys else api_key
    url = f"{SHODAN_API_BASE}{endpoint}"
    all_params = {"key": effective_key}
    if params:
        all_params.update(params)
    try:
        resp = requests.get(url, params=all_params, timeout=30)
        if key_rotator:
            key_rotator.tick()
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.debug(f"Shodan 404 for {endpoint}")
            return None
        elif resp.status_code == 401:
            logger.error("Shodan API key is invalid or expired")
            raise ShodanApiKeyError("Shodan API key is invalid or expired (401)")
        elif resp.status_code == 403:
            logger.error(f"Shodan access denied (403) — requires paid membership")
            raise ShodanApiKeyError("Shodan API requires paid membership for this feature (403)")
        elif resp.status_code == 429:
            logger.warning("Shodan rate limit hit, waiting 2s")
            time.sleep(2)
            return None
        else:
            logger.warning(f"Shodan {resp.status_code} for {endpoint}: {resp.text[:200]}")
            return None
    except ShodanApiKeyError:
        raise  # Re-raise auth/access errors for early abort
    except requests.RequestException as e:
        logger.warning(f"Shodan request failed for {endpoint}: {e}")
        return None


def _internetdb_get(ip: str) -> dict | None:
    """Query Shodan InternetDB (free, no key required) for basic host data."""
    try:
        resp = requests.get(f"{INTERNETDB_BASE}/{ip}", timeout=15)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.debug(f"InternetDB: no data for {ip}")
            return None
        else:
            logger.warning(f"InternetDB {resp.status_code} for {ip}")
            return None
    except requests.RequestException as e:
        logger.warning(f"InternetDB request failed for {ip}: {e}")
        return None


def _lookup_single_ip(ip: str, use_internetdb: bool, api_key: str, key_rotator, rate_limiter: _RateLimiter) -> dict | None:
    """Lookup a single IP via Shodan API or InternetDB. Thread-safe."""
    if not use_internetdb:
        try:
            rate_limiter.wait()
            data = _shodan_get(f"/shodan/host/{ip}", api_key, key_rotator=key_rotator)
        except ShodanApiKeyError:
            # Caller will detect and switch to InternetDB
            raise
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
                })
            logger.info(f"  Shodan host lookup: {ip} — {len(host_entry['ports'])} ports, "
                        f"{len(host_entry['vulns'])} vulns")
            return host_entry
        return None

    # InternetDB path
    rate_limiter.wait()
    idb = _internetdb_get(ip)
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


def _run_host_lookup(ips: list[str], api_key: str, key_rotator=None, max_workers: int = 5) -> list[dict]:
    """Fetch Shodan host data for each IP using parallel workers.

    Tries the full /shodan/host/{ip} API first. If that returns 403
    (paid membership required) or no API key is configured, automatically
    falls back to the free InternetDB API (https://internetdb.shodan.io/{ip})
    which provides ports, hostnames, CPEs, CVEs, and tags -- no banners or geo data.
    """
    hosts = []
    use_internetdb = not api_key  # No key -> go straight to InternetDB

    if use_internetdb:
        logger.info("No Shodan API key — using InternetDB (free, no key required)")
        print("[*][Shodan] No API key — using InternetDB (free, no key required)")

    # Rate limiter: 1 req/sec for Shodan API, 0.5s for InternetDB
    rate_limiter = _RateLimiter(0.5 if use_internetdb else 1.0)
    workers = min(max_workers, len(ips))

    if workers <= 1 or len(ips) <= 1:
        # Sequential fallback for single IP or single worker
        for ip in ips:
            result = _lookup_single_ip(ip, use_internetdb, api_key, key_rotator, rate_limiter)
            if result:
                hosts.append(result)
        return hosts

    # Try parallel execution; fall back to InternetDB if Shodan API fails
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_lookup_single_ip, ip, use_internetdb, api_key, key_rotator, rate_limiter): ip
            for ip in ips
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                if result:
                    hosts.append(result)
            except ShodanApiKeyError:
                # Switch to InternetDB for remaining IPs
                logger.info("Paid API unavailable — falling back to InternetDB (free)")
                print("[*][Shodan] Falling back to InternetDB (free, no key required)")
                # Cancel remaining futures and re-run sequentially with InternetDB
                executor.shutdown(wait=False, cancel_futures=True)
                remaining_ips = [ip2 for ip2 in ips if ip2 not in {futures[f] for f in futures if f.done()}]
                idb_limiter = _RateLimiter(0.5)
                for rip in remaining_ips:
                    result = _lookup_single_ip(rip, True, api_key, key_rotator, idb_limiter)
                    if result:
                        hosts.append(result)
                break
            except Exception as e:
                logger.warning(f"Host lookup failed for {ip}: {e}")

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
            return results
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

    result = {
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


def _extract_passive_cves(hosts: list[dict], ips: list[str], api_key: str, key_rotator=None, max_workers: int = 5) -> list[dict]:
    """Extract CVEs from host lookup data.

    If host data exists (from host lookup, which may be InternetDB data),
    CVEs are extracted directly. If no host data, queries InternetDB per-IP
    (free, no key required) using parallel workers.
    """
    cves: list[dict] = []
    seen_cve_ip: set[tuple[str, str]] = set()

    # If host lookup already ran, extract from existing data (works for both
    # Shodan API and InternetDB sources since both populate 'vulns')
    if hosts:
        for host in hosts:
            ip = host["ip"]
            source = host.get("source", "shodan_host_lookup")
            for cve_id in host.get("vulns", []):
                key = (cve_id, ip)
                if key not in seen_cve_ip:
                    seen_cve_ip.add(key)
                    cves.append({
                        "cve_id": cve_id,
                        "ip": ip,
                        "source": source,
                    })
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
                if idb:
                    for cve_id in idb.get("vulns", []):
                        key = (cve_id, ip)
                        if key not in seen_cve_ip:
                            seen_cve_ip.add(key)
                            cves.append({
                                "cve_id": cve_id,
                                "ip": ip,
                                "source": "internetdb",
                            })

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

    do_host = settings.get("SHODAN_HOST_LOOKUP", False)
    do_rdns = settings.get("SHODAN_REVERSE_DNS", False)
    do_ddns = settings.get("SHODAN_DOMAIN_DNS", False)
    do_cves = settings.get("SHODAN_PASSIVE_CVES", False)

    if not any([do_host, do_rdns, do_ddns, do_cves]):
        return combined_result

    print(f"\n[PHASE] Shodan OSINT Enrichment")
    print("-" * 40)

    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "Shodan")
    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)

    print(f"[+][Shodan] Extracted {len(ips)} unique IPs for enrichment")

    shodan_data: dict[str, Any] = {
        "hosts": [],
        "reverse_dns": {},
        "domain_dns": {},
        "cves": [],
    }

    try:
        # 1. Host Lookup (falls back to InternetDB on 403)
        if do_host and ips:
            print(f"[*][Shodan] Running host lookup on {len(ips)} IPs...")
            shodan_data["hosts"] = _run_host_lookup(ips, api_key, key_rotator=key_rotator, max_workers=shodan_workers)
            print(f"[+][Shodan] Host lookup complete: {len(shodan_data['hosts'])} hosts enriched")

        # 2. Reverse DNS (falls back to InternetDB hostnames on 403)
        if do_rdns and ips:
            print(f"[*][Shodan] Running reverse DNS on {len(ips)} IPs...")
            shodan_data["reverse_dns"] = _run_reverse_dns(ips, api_key, shodan_data["hosts"], key_rotator=key_rotator, max_workers=shodan_workers)
            print(f"[+][Shodan] Reverse DNS complete: {len(shodan_data['reverse_dns'])} IPs resolved")

        # 3. Domain DNS (domain mode only, paid Shodan plan — no free fallback)
        if do_ddns and domain and not is_ip_mode:
            print(f"[*][Shodan] Running domain DNS for {domain}...")
            shodan_data["domain_dns"] = _run_domain_dns(domain, api_key, key_rotator=key_rotator)
            sub_count = len(shodan_data["domain_dns"].get("subdomains", []))
            print(f"[+][Shodan] Domain DNS complete: {sub_count} subdomains found")

        # 4. Passive CVEs (reuses host data, falls back with hosts to InternetDB)
        if do_cves and ips:
            print(f"[*][Shodan] Extracting passive CVEs...")
            shodan_data["cves"] = _extract_passive_cves(
                shodan_data["hosts"], ips, api_key, key_rotator=key_rotator, max_workers=shodan_workers
            )
            print(f"[+][Shodan] Passive CVEs complete: {len(shodan_data['cves'])} CVEs found")

    except ShodanApiKeyError as e:
        # Only reaches here for 401 (invalid key) — 403 is handled per-function
        print(f"[!][Shodan] API key error: {e}")
        print(f"[!][Shodan] Aborting enrichment — pipeline continues")

    except Exception as e:
        logger.error(f"Shodan enrichment failed: {e}")
        print(f"[!][Shodan] Enrichment error: {e}")
        print(f"[!][Shodan] Pipeline continues without Shodan data")

    combined_result["shodan"] = shodan_data
    return combined_result


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
