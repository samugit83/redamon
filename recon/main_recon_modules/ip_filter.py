"""
RedAmon - IP Filtering Helpers
===============================
Classify and filter IPs before OSINT enrichment to avoid wasting API
credits on non-routable, reserved, or CDN addresses.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# The per-user Kali sandboxes' address pool: SUBNET_POOL in
# recon_orchestrator/sandbox_contract.py (and its agentic/ twin), which the
# recon image does not ship. Recon and its tools run on the host network, which
# reaches every sandbox bridge, so an address in here is another person's Kali
# sandbox and never an engagement host, whoever typed it. The stdlib copy in
# recon_settings/ip_hostnames.py must say the same (test_ip_hostname_rule.py).
SANDBOX_POOL_NETWORK = ipaddress.ip_network("10.214.0.0/16")

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
    """
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


def is_never_scannable_ip(ip_str: str) -> bool:
    """Return True for an address a DISCOVERED hostname must never drag in.

    Deliberately narrower than :func:`is_non_routable_ip`. That one answers
    "may this go to an external OSINT API", and refuses RFC-1918 as well - which
    is correct there and wrong here, because RedAmon scans internal estates on
    purpose (Single Domain advertises "public or internal (incl. AD)"). Dropping
    every private address would silently break those engagements.

    What is left is the set that is wrong for a SCANNER no matter whose estate
    it is:

    - loopback: the name points at the recon container itself, so scanning it
      means scanning ourselves. `localhost.<domain> -> 127.0.0.1` is a real and
      common record; vulnweb.com publishes one.
    - link-local: includes 169.254.169.254, i.e. cloud metadata.
    - unspecified / multicast: not a host.
    - the Kali sandbox pool (:data:`SANDBOX_POOL_NETWORK`): another person's
      sandbox. A typed target in it is refused too (:func:`in_sandbox_pool`).

    Private and CGNAT addresses are deliberately KEPT and logged by the caller,
    so an operator can see a discovered name pointing inward without the scan
    quietly deciding for them.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
        or (addr.version == 4 and addr in SANDBOX_POOL_NETWORK)
    )


def in_sandbox_pool(ip_str) -> bool:
    """True for an address of the Kali sandbox pool (IPv4-mapped included).

    Unlike :func:`is_never_scannable_ip`, the operator's own targets are refused
    by it as well: a sandbox is no estate anyone engages. Not an address: False.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.version == 4 and addr in SANDBOX_POOL_NETWORK


def resolves_into_sandbox_pool(host: str) -> bool:
    """True when ``host`` is, or resolves to, an address of the sandbox pool.
    A name that does not resolve is not in it (there is nothing to reach)."""
    name = (host or "").strip().strip("[]").rstrip(".")
    if not name:
        return False
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return in_sandbox_pool(name)
    try:
        infos = socket.getaddrinfo(name, None)
    except (OSError, UnicodeError):
        return False
    return any(in_sandbox_pool(info[4][0].split("%")[0]) for info in infos)


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


def is_address_safe_to_scan(host: str, operator_hosts=(), operator_networks=()) -> bool:
    """Address guard for a request to a host recon reached on its own.

    The pipeline's rule for discovered names, applied per request. A host the
    operator typed (``operator_hosts``, or an IP inside ``operator_networks``)
    is scanned whatever it resolves to, as recon/main.py does for
    operator-supplied hosts and IP mode does for its targets. Any other host is
    resolved, and refused if it is a cloud-metadata name or ANY of its
    addresses is never scannable (:func:`is_never_scannable_ip`). An
    unresolvable host is refused: there is nothing to scan. Private and CGNAT
    addresses stay allowed, as for the pipeline. The Kali sandbox pool is
    refused before any of the operator's own hosts and networks.

    The check and the connection resolve separately; that DNS-rebinding window
    is the recon-wide limitation in README.SECURITY_POSTURE.md.
    """
    name = (host or "").strip().strip("[]").rstrip(".").lower()
    if not name:
        return False
    try:
        addr = ipaddress.ip_address(name)
    except ValueError:
        addr = None
    if addr is not None and in_sandbox_pool(name):
        return False
    if name in operator_hosts:
        return addr is not None or not resolves_into_sandbox_pool(name)
    if addr is not None:
        candidates = [addr]
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            candidates.append(addr.ipv4_mapped)
        if any(a in net for a in candidates for net in operator_networks if a.version == net.version):
            return True
        return not is_never_scannable_ip(name)
    if name in _METADATA_HOSTNAMES:
        return False
    try:
        infos = socket.getaddrinfo(name, None)
    except (OSError, UnicodeError):
        return False
    resolved = {info[4][0].split("%")[0] for info in infos}
    if not resolved:
        return False
    return not any(is_never_scannable_ip(ip) for ip in resolved)


def in_published_cdn_range(ip_str: str) -> bool:
    """True for an address inside a CDN's published edge prefixes.

    The CDN flags collect_cdn_ips reads come from naabu and httpx, which have
    not run yet when Uncover (GROUP 2b) and Shodan (GROUP 3, beside the port
    scan) filter their IPs; the published prefixes need no scan. The list is
    cdn_ranges' static one, so this never makes a request.
    """
    try:
        from recon.helpers.cdn_ranges import edge_cdn_for_ip
        return edge_cdn_for_ip(ip_str) is not None
    except Exception:  # noqa: BLE001 - a missing list only means fewer IPs skipped
        return False


# Providers whose IPs front many unrelated tenants, as a passive source names
# the IP's owner (Shodan's org/isp, Netlas's isp/ASN). The published prefixes do
# not cover every edge provider, so the provider's attribution is used as well. Only
# providers that sell no servers are named: Akamai (which now runs Linode),
# G-Core and StackPath also rent VMs, so an org name alone cannot say an IP of
# theirs is an edge.
SHARED_EDGE_ORG = re.compile(
    r"\b(?:cloudflare|fastly|vercel|netlify|incapsula|imperva|sucuri"
    r"|edgecast|edgio|limelight|bunnyway|bunny\.net|cdn77|cloudfront)\b",
    re.IGNORECASE,
)


def is_shared_edge_org(owner: str) -> bool:
    """True when a passive source attributes an IP to a shared edge provider."""
    return bool(SHARED_EDGE_ORG.search(str(owner or "")))


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
        if ip in cdn_ips or in_published_cdn_range(ip):
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
