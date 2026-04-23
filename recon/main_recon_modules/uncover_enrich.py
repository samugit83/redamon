"""
Uncover Pipeline Enrichment Module
====================================
Target expansion using ProjectDiscovery's uncover tool.
Queries multiple search engines (Shodan, Censys, FOFA, ZoomEye, Netlas,
CriminalIP, Quake, Hunter, PublicWWW, HunterHow, Google, Onyphe, Driftnet)
to discover exposed hosts associated with the target domain/org.

Runs as a Docker container (projectdiscovery/uncover) with a dynamically
generated provider-config.yaml containing only engines that have API keys.

This module is a DISCOVERY tool (finds new IPs/hosts), not an enrichment
tool.  Its output is merged back into the pipeline's DNS structures so
downstream modules (Shodan, port scan, OSINT enrichment, HTTP probe) can
process the newly discovered assets.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Set
from urllib.parse import urlparse

try:
    from recon.main_recon_modules.ip_filter import filter_ips_for_enrichment, is_non_routable_ip
except ImportError:
    from ip_filter import filter_ips_for_enrichment, is_non_routable_ip


def _is_valid_ip(value: str) -> bool:
    """Return True if value is a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_hostname_from_url(url: str) -> str:
    """Extract hostname from a URL string, returning '' on failure."""
    if not url:
        return ''
    try:
        if '://' not in url:
            url = 'https://' + url
        return urlparse(url).hostname or ''
    except Exception:
        return ''

UNCOVER_DOCKER_IMAGE_DEFAULT = "projectdiscovery/uncover:latest"
UNCOVER_TIMEOUT = 600  # 10 minutes max


def _build_provider_config(settings: dict) -> tuple[dict, list[str]]:
    """Build uncover provider-config.yaml content and matching engine list.

    Only includes engines that have valid credentials configured.
    Reuses existing OSINT keys (Shodan, FOFA, ZoomEye, Netlas, CriminalIP)
    alongside uncover-specific keys (Quake, Hunter, etc.).

    Returns (yaml_dict, enabled_engines).
    """
    config: Dict[str, list] = {}
    engines: list[str] = []

    # Shodan (reuses existing pipeline key)
    shodan_key = settings.get('SHODAN_API_KEY', '')
    if shodan_key:
        config['shodan'] = [shodan_key]
        engines.append('shodan')

    # Censys (platform token + org ID)
    censys_token = settings.get('CENSYS_API_TOKEN', '')
    censys_org = settings.get('CENSYS_ORG_ID', '')
    if censys_token and censys_org:
        config['censys'] = [f"{censys_token}:{censys_org}"]
        engines.append('censys')

    # FOFA (reuses existing key, format: email:key or key-only)
    fofa_key = settings.get('FOFA_API_KEY', '')
    if fofa_key:
        config['fofa'] = [fofa_key]
        engines.append('fofa')

    # ZoomEye (reuses existing key)
    ze_key = settings.get('ZOOMEYE_API_KEY', '')
    if ze_key:
        config['zoomeye'] = [ze_key]
        engines.append('zoomeye')

    # Netlas (reuses existing key)
    netlas_key = settings.get('NETLAS_API_KEY', '')
    if netlas_key:
        config['netlas'] = [netlas_key]
        engines.append('netlas')

    # CriminalIP (reuses existing key)
    cip_key = settings.get('CRIMINALIP_API_KEY', '')
    if cip_key:
        config['criminalip'] = [cip_key]
        engines.append('criminalip')

    # Uncover-only engines
    quake_key = settings.get('UNCOVER_QUAKE_API_KEY', '')
    if quake_key:
        config['quake'] = [quake_key]
        engines.append('quake')

    hunter_key = settings.get('UNCOVER_HUNTER_API_KEY', '')
    if hunter_key:
        config['hunter'] = [hunter_key]
        engines.append('hunter')

    publicwww_key = settings.get('UNCOVER_PUBLICWWW_API_KEY', '')
    if publicwww_key:
        config['publicwww'] = [publicwww_key]
        engines.append('publicwww')

    hunterhow_key = settings.get('UNCOVER_HUNTERHOW_API_KEY', '')
    if hunterhow_key:
        config['hunterhow'] = [hunterhow_key]
        engines.append('hunterhow')

    google_key = settings.get('UNCOVER_GOOGLE_API_KEY', '')
    google_cx = settings.get('UNCOVER_GOOGLE_API_CX', '')
    if google_key and google_cx:
        config['google'] = [f"{google_key}:{google_cx}"]
        engines.append('google')

    onyphe_key = settings.get('UNCOVER_ONYPHE_API_KEY', '')
    if onyphe_key:
        config['onyphe'] = [onyphe_key]
        engines.append('onyphe')

    driftnet_key = settings.get('UNCOVER_DRIFTNET_API_KEY', '')
    if driftnet_key:
        config['driftnet'] = [driftnet_key]
        engines.append('driftnet')

    # shodan-idb works without keys, always include for IP lookups
    if 'shodan' not in engines:
        engines.append('shodan-idb')

    return config, engines


def _build_queries(domain: str, settings: dict) -> list[str]:
    """Build search queries for the target domain.

    Uses hostname and SSL certificate org searches to maximize coverage.
    """
    queries = [domain]

    whois_org = settings.get('_WHOIS_ORG', '')
    if whois_org and whois_org.lower() not in ('n/a', 'unknown', '', 'none'):
        queries.append(f'ssl:"{whois_org}"')

    return queries


def _run_uncover_docker(
    queries: list[str],
    engines: list[str],
    config_path: str,
    max_results: int,
    temp_dir: str,
    docker_image: str = UNCOVER_DOCKER_IMAGE_DEFAULT,
) -> list[dict]:
    """Run uncover via Docker and parse JSON output.

    Returns list of parsed JSON result dicts.
    """
    output_file = os.path.join(temp_dir, "uncover_output.jsonl")

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{temp_dir}:/config:ro",
        "-v", f"{temp_dir}:/output",
        docker_image,
        "-pc", "/config/provider-config.yaml",
        "-e", ",".join(engines),
        "-json",
        "-silent",
        "-l", str(max_results),
        "-timeout", "60",
        "-o", "/output/uncover_output.jsonl",
    ]

    for q in queries:
        cmd.extend(["-q", q])

    print(f"[*][Uncover] Running: engines={engines}, queries={queries}")

    result = None
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=UNCOVER_TIMEOUT,
        )

        if result.returncode != 0:
            stderr = (result.stderr or '').strip()
            if stderr:
                for line in stderr.split('\n')[:5]:
                    line = line.strip()
                    if line and not line.startswith('[WRN]'):
                        print(f"[!][Uncover] stderr: {line}")

    except subprocess.TimeoutExpired:
        print("[!][Uncover] Timed out — partial results may be available")
    except FileNotFoundError:
        print("[!][Uncover] Docker not found — skipping")
        return []
    except Exception as e:
        print(f"[!][Uncover] Error: {e}")
        return []

    results = []
    if os.path.isfile(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not results and result is not None and result.stdout:
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return results


def _deduplicate_results(results: list[dict]) -> list[dict]:
    """Deduplicate results keeping the first occurrence per unique key.

    Uses (ip, port) as key when IP is present, falls back to
    (host, port) for engines like PublicWWW that return no IP.
    Entries with neither ip nor host are skipped.
    """
    seen: Set[tuple] = set()
    unique = []
    for r in results:
        ip = r.get('ip', '')
        host = r.get('host', '')
        try:
            port = int(r.get('port', 0) or 0)
        except (ValueError, TypeError):
            port = 0
        if ip:
            key = (ip, port)
        elif host:
            key = (host, port)
        else:
            continue
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def _extract_hosts_and_ips(
    results: list[dict],
    domain: str,
    combined_result: dict,
) -> tuple[list[str], list[str], dict, list[str]]:
    """Extract unique IPs, hostnames, per-IP port data, and URLs from uncover results.

    Handles engine quirks:
    - Google puts URLs in the 'ip' field (not a real IP) -- extracts hostname.
    - PublicWWW returns host/url but no IP -- captures hostname.
    - Censys/PublicWWW/Google populate the 'url' field -- collected as URLs.

    Filters out non-routable and CDN IPs.
    Returns (new_ips, new_hostnames, ip_ports_map, urls).
    """
    all_ips: Set[str] = set()
    all_hosts: Set[str] = set()
    all_urls: Set[str] = set()
    ip_ports: Dict[str, Set[int]] = {}

    for r in results:
        ip = r.get('ip', '')
        host = r.get('host', '')
        url = r.get('url', '')

        try:
            port = int(r.get('port', 0) or 0)
        except (ValueError, TypeError):
            port = 0

        # Google puts URL in ip field -- detect and extract hostname
        if ip and not _is_valid_ip(ip):
            extracted = _extract_hostname_from_url(ip)
            if extracted:
                host = host or extracted
            if ip.startswith(('http://', 'https://')):
                all_urls.add(ip)
            ip = ''

        if ip:
            all_ips.add(ip)
            if port > 0:
                ip_ports.setdefault(ip, set()).add(port)

        # Collect url field (Censys, PublicWWW, Google)
        if url and url.startswith(('http://', 'https://')):
            all_urls.add(url)
            # Extract host from url if we don't have one yet
            if not host:
                host = _extract_hostname_from_url(url)

        if host and host != ip:
            h = host.lower().strip().rstrip('.')
            if h and (h == domain or h.endswith('.' + domain)):
                all_hosts.add(h)

    # Filter IPs
    filtered_ips = filter_ips_for_enrichment(
        sorted(all_ips), combined_result, "Uncover"
    )

    # Build ip_ports map for filtered IPs only
    filtered_ip_ports = {}
    for ip in filtered_ips:
        if ip in ip_ports:
            filtered_ip_ports[ip] = sorted(ip_ports[ip])

    # Filter URLs to in-scope only
    in_scope_urls = []
    for u in sorted(all_urls):
        h = _extract_hostname_from_url(u)
        if h and (h == domain or h.endswith('.' + domain)):
            in_scope_urls.append(u)

    return filtered_ips, sorted(all_hosts), filtered_ip_ports, in_scope_urls


def run_uncover_expansion(
    combined_result: dict,
    settings: dict[str, Any],
) -> dict:
    """Run uncover target expansion and merge new hosts/IPs into combined_result.

    Designed to run BEFORE Shodan + port scan (GROUP 3) so newly discovered
    assets are processed by all downstream modules.

    Args:
        combined_result: Pipeline's combined result dict (mutated in place)
        settings: Project settings dict

    Returns:
        Uncover data dict with discovered hosts, or empty dict.
    """
    if not settings.get('UNCOVER_ENABLED', False):
        return {}

    print("\n[*][Uncover] Starting multi-engine target expansion")
    print("-" * 40)

    config, engines = _build_provider_config(settings)
    if not engines or (len(engines) == 1 and engines[0] == 'shodan-idb'):
        print("[!][Uncover] No API keys configured for any search engine — skipping")
        return {}

    keyed_engines = [e for e in engines if e != 'shodan-idb']
    print(f"[+][Uncover] Engines: {', '.join(keyed_engines)}")

    domain = combined_result.get('domain', '')
    if not domain:
        print("[!][Uncover] No target domain — skipping")
        return {}

    # Extract org name from whois if available
    whois_data = combined_result.get('whois', {})
    if isinstance(whois_data, dict):
        org = whois_data.get('registrant_org', '') or whois_data.get('org', '')
        if org:
            settings['_WHOIS_ORG'] = org

    queries = _build_queries(domain, settings)
    max_results = int(settings.get('UNCOVER_MAX_RESULTS', 500))

    print(f"[*][Uncover] Queries: {queries}")
    print(f"[*][Uncover] Max results: {max_results}")

    os.makedirs("/tmp/redamon", exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="redamon_uncover_", dir="/tmp/redamon")

    try:
        # Write provider config (no yaml dependency -- write manually)
        config_path = os.path.join(temp_dir, "provider-config.yaml")
        with open(config_path, 'w') as f:
            for engine_name, keys in config.items():
                f.write(f"{engine_name}:\n")
                for k in keys:
                    f.write(f"  - {k}\n")

        docker_image = settings.get('UNCOVER_DOCKER_IMAGE', UNCOVER_DOCKER_IMAGE_DEFAULT)
        raw_results = _run_uncover_docker(
            queries, engines, config_path, max_results, temp_dir,
            docker_image=docker_image,
        )

        if not raw_results:
            print("[*][Uncover] No results found")
            return {}

        deduped = _deduplicate_results(raw_results)
        print(f"[+][Uncover] Raw: {len(raw_results)} results, deduplicated: {len(deduped)}")

        # Collect source stats
        source_counts: Dict[str, int] = {}
        for r in deduped:
            src = r.get('source', 'unknown')
            source_counts[src] = source_counts.get(src, 0) + 1

        new_ips, new_hosts, ip_ports, urls = _extract_hosts_and_ips(
            deduped, domain, combined_result,
        )

        print(f"[+][Uncover] Discovered: {len(new_ips)} unique IPs, {len(new_hosts)} subdomains")
        if urls:
            print(f"[+][Uncover] Discovered: {len(urls)} in-scope URLs")
        for src, cnt in sorted(source_counts.items()):
            print(f"    [{src}] {cnt} results")

        uncover_data = {
            "hosts": new_hosts,
            "ips": new_ips,
            "ip_ports": ip_ports,
            "urls": urls,
            "sources": list(source_counts.keys()),
            "source_counts": source_counts,
            "total_raw": len(raw_results),
            "total_deduped": len(deduped),
        }

        return uncover_data

    except Exception as e:
        print(f"[!][Uncover] Expansion failed: {e}")
        return {}
    finally:
        # Cleanup entire temp directory (unique per run)
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except OSError:
            pass


def merge_uncover_into_pipeline(
    combined_result: dict,
    uncover_data: dict,
    domain: str,
) -> int:
    """Merge uncover discoveries into the pipeline's DNS/subdomain structures.

    New subdomains go into dns.subdomains so downstream modules
    (port scan, HTTP probe, OSINT enrichment) process them.

    Returns count of new assets merged.
    """
    if not uncover_data:
        return 0

    dns = combined_result.setdefault("dns", {})
    subdomains = dns.setdefault("subdomains", {})
    merged = 0

    # Merge new hostnames as subdomains with their IPs
    for host in uncover_data.get("hosts", []):
        if host not in subdomains:
            subdomains[host] = {
                "ips": {"ipv4": [], "ipv6": []},
                "source": "uncover",
            }
            merged += 1

    # For IPs discovered without a hostname, track them
    # so OSINT enrichment modules can process them
    ip_ports = uncover_data.get("ip_ports", {})
    existing_ips = set()
    domain_dns = dns.get("domain", {})
    for ip in domain_dns.get("ips", {}).get("ipv4", []):
        existing_ips.add(ip)
    for _sub, info in subdomains.items():
        for ip in info.get("ips", {}).get("ipv4", []):
            existing_ips.add(ip)

    new_ip_count = 0
    for ip in uncover_data.get("ips", []):
        if ip not in existing_ips:
            new_ip_count += 1

    # Store the uncover IP data for OSINT enrichment modules to consume
    if uncover_data.get("ips"):
        expanded = combined_result.get("metadata", {}).get("expanded_ips", [])
        if isinstance(expanded, list):
            existing_expanded = set(expanded)
            for ip in uncover_data["ips"]:
                if ip not in existing_expanded:
                    expanded.append(ip)
            combined_result.setdefault("metadata", {})["expanded_ips"] = expanded

    total = merged + new_ip_count
    if total:
        print(f"[+][Uncover] Merged: {merged} new subdomains, {new_ip_count} new IPs into pipeline")

    return total


def run_uncover_expansion_isolated(combined_result: dict, settings: dict[str, Any]) -> dict:
    """Run uncover expansion and return only the uncover data dict.

    Thread-safe: does not mutate combined_result. Reads DNS/IP data from
    it but writes nothing back.

    Args:
        combined_result: The pipeline's combined result dictionary (read-only)
        settings: Project settings dict

    Returns:
        The uncover data dictionary (just the expansion payload)
    """
    import copy
    snapshot = copy.copy(combined_result)
    return run_uncover_expansion(snapshot, settings)
