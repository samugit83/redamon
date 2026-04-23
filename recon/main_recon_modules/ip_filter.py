"""
RedAmon - IP Filtering Helpers
===============================
Classify and filter IPs before OSINT enrichment to avoid wasting API
credits on non-routable, reserved, or CDN addresses.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Set

logger = logging.getLogger(__name__)

CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def is_non_routable_ip(ip_str: str) -> bool:
    """Return True if *ip_str* should NOT be sent to external OSINT APIs.

    Covers RFC 1918 private, loopback, link-local, CGNAT (100.64.0.0/10),
    and IETF reserved ranges.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or addr in CGNAT_NETWORK
    )


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
