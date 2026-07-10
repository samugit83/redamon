"""
RedAmon - IP Filtering Helpers
===============================
Classify and filter IPs before OSINT enrichment to avoid wasting API
credits on non-routable, reserved, or CDN addresses.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# Cloud metadata hostnames that resolve OFF-host (so an IP check alone misses
# them). Mirrors the agent-side llm_url_guard blocklist.
_METADATA_HOSTNAMES = frozenset({
    "metadata.google.internal",
    "metadata.goog",
})


def is_non_routable_ip(ip_str: str) -> bool:
    """Return True if *ip_str* should NOT be sent to external OSINT APIs.

    Covers RFC 1918 private, loopback, link-local, CGNAT (100.64.0.0/10),
    and IETF reserved ranges.

    Leading/trailing whitespace and IPv6 bracket notation (``[::1]``) are
    stripped before parsing so callers don't need to normalise the string
    themselves.
    """
    # Normalise: strip whitespace, remove surrounding brackets for IPv6
    ip_str = ip_str.strip().strip("[]")
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    # IPv4-mapped IPv6 (::ffff:169.254.169.254) is judged on the embedded v4.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or addr in CGNAT_NETWORK
    )


def is_url_safe_to_probe(url: str) -> bool:
    """SSRF guard for probing URLs derived from a target's JavaScript (STRIDE I14).

    Endpoints extracted from a scanned target's JS are attacker-influenced; a
    planted ``http://169.254.169.254/...`` or ``http://10.0.0.5/`` would turn the
    recon container into an SSRF probe against cloud metadata / the internal
    network. Returns True only for an http(s) URL whose host is not a metadata
    hostname and every resolved address is routable/public. An unresolvable host
    is treated as unsafe (fail closed) since recon has no reason to probe it.
    """
    try:
        parsed = urlparse((url or "").strip())
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    if host.lower().rstrip(".") in _METADATA_HOSTNAMES:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False  # fail closed: don't probe hosts we can't resolve
    resolved = {info[4][0].split("%")[0] for info in infos}
    if not resolved:
        return False
    return all(not is_non_routable_ip(ip) for ip in resolved)


def collect_cdn_ips(combined_result: dict) -> Set[str]:
    """Gather IPs flagged as CDN by Naabu/httpx from port_scan and http_probe data."""
    cdn_ips: Set[str] = set()

    port_scan = combined_result.get("port_scan") or {}
    for ip, info in (port_scan.get("by_ip") or {}).items():
        if isinstance(info, dict) and info.get("is_cdn"):
            cdn_ips.add(ip)

    http_probe = combined_result.get("http_probe") or {}
    for _url, info in (http_probe.get("by_url") or {}).items():
        if isinstance(info, dict) and info.get("is_cdn"):
            ip = info.get("ip")
            if ip:
                cdn_ips.add(ip)

    return cdn_ips


def filter_ips_for_enrichment(
    ips: list[str],
    combined_result: dict,
    module_name: str = "OSINT",
) -> list[str]:
    """Filter an IP list, removing non-routable and CDN IPs.

    Logs a summary of skipped IPs once (not per-IP) to keep output clean.
    """
    cdn_ips = collect_cdn_ips(combined_result)

    kept: list[str] = []
    skipped_private = 0
    skipped_cdn = 0

    for ip in ips:
        if is_non_routable_ip(ip):
            skipped_private += 1
            continue
        if ip in cdn_ips:
            skipped_cdn += 1
            continue
        kept.append(ip)

    parts: list[str] = []
    if skipped_private:
        parts.append(f"{skipped_private} non-routable/reserved")
    if skipped_cdn:
        parts.append(f"{skipped_cdn} CDN")
    if parts:
        print(f"[*][{module_name}] Skipped {', '.join(parts)} IP(s) from enrichment")

    return kept
