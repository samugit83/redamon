"""
RedAmon - CDN Identification Helpers
====================================
Identify IPs and HTTP responses belonging to known CDN / edge providers so that
'Direct IP Access' security findings on shared infrastructure are suppressed.

Three layers, in order of cost / reliability:

1. Published prefix lists  -> is_cloudflare_ip(ip)
   Authoritative; the provider tells you which IPs are theirs.

2. ASN match               -> cdn_name_from_asn(asn)
   Cheap when ASN data is already in the recon data (httpx -asn or enrichers).

3. Response fingerprint    -> response_is_cdn_edge(response)
   Header / body markers visible only at probe time. Used as a safety net
   when prefix and ASN data are missing (e.g. user-injected custom IPs).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional

import requests


# =============================================================================
# Phase 1 scope: Cloudflare only.
# Add CloudFront / Akamai / Fastly / Cloud LB providers in Phase 2.
# =============================================================================

CDN_ASNS: dict[int, str] = {
    13335: "cloudflare",
    209242: "cloudflare",
}

# Certificate-issuer fragments that RELIABLY identify a CDN edge (Phase 2.3).
#
# A TLS handshake attributes a CDN where naabu cannot: it needs no HTTP
# response, so it works on a non-HTTP TLS port, which is exactly where
# response_is_cdn_edge() cannot help (it takes a requests.Response).
#
# Deliberately NOT here: "amazon"/"aws". ACM issues certificates for bare ALB
# and EC2 origins that DO serve the application directly, so treating an Amazon
# issuer as CDN edge would suppress genuine Direct-IP findings -- the same
# reason RELIABLE_EDGE_CDN_NAMES below excludes those names. Only issuers whose
# presence means "this is an edge, not the origin" belong here.
CDN_CERT_ISSUER_MARKERS: dict[str, str] = {
    "cloudflare": "cloudflare",
    "akamai": "akamai",
    "fastly": "fastly",
    "sucuri": "sucuri",
    "incapsula": "incapsula",
    "imperva": "imperva",
}


def cdn_from_certificate(issuer) -> Optional[str]:
    """Return a CDN name from a certificate issuer, or None.

    JARM would be a second signal here, but a JARM->CDN table is only as good as
    the hashes in it and there is no verified offline source to build one from;
    inventing fingerprints would be worse than attributing nothing.
    """
    if not issuer:
        return None
    if isinstance(issuer, (list, tuple)):
        issuer = ", ".join(str(x) for x in issuer if x)
    lowered = str(issuer).lower()
    for marker, name in CDN_CERT_ISSUER_MARKERS.items():
        if marker in lowered:
            return name
    return None


# CDN names that httpx / naabu emit which RELIABLY indicate the IP is an
# edge node and does NOT serve the origin application directly. Suppressing
# Direct-IP findings on these is safe.
#
# Excluded on purpose: "aws", "amazon", "azure", "gcp", "google" — those
# cover bare EC2/ALB/Cloud-LB origins where the IP often DOES serve the
# app (e.g. an ALB IP returns the real site to a direct-IP request).
# Treating those as CDN would suppress real Direct IP Access findings.
RELIABLE_EDGE_CDN_NAMES: set[str] = {
    "cloudflare",
    "cloudfront",
    "akamai",
    "akamaighost",
    "fastly",
    "imperva",
    "incapsula",
    "sucuri",
    "stackpath",
    "azurefrontdoor",
    "azure-cdn",
    "gcore",
}


def is_reliable_edge_cdn_name(cdn_name) -> bool:
    """True if *cdn_name* is a known edge-only CDN provider."""
    if not cdn_name:
        return False
    return str(cdn_name).strip().lower() in RELIABLE_EDGE_CDN_NAMES


def collect_reliable_edge_ips(recon_data: dict) -> set[str]:
    """
    Like collect_cdn_ips but only counts IPs whose cdn name is in
    RELIABLE_EDGE_CDN_NAMES. Drops generic cloud-provider labels
    (aws/amazon/azure/gcp/google) that mislabel bare origin IPs.
    """
    matches: set[str] = set()

    port_scan = recon_data.get("port_scan") or {}
    for ip, info in (port_scan.get("by_ip") or {}).items():
        if not isinstance(info, dict):
            continue
        if info.get("is_cdn") and is_reliable_edge_cdn_name(info.get("cdn")):
            matches.add(ip)

    http_probe = recon_data.get("http_probe") or {}
    for _url, info in (http_probe.get("by_url") or {}).items():
        if not isinstance(info, dict):
            continue
        if info.get("is_cdn") and is_reliable_edge_cdn_name(info.get("cdn")):
            ip = info.get("ip")
            if ip:
                matches.add(ip)

    return matches

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"

# Hardcoded fallback used when the live fetch fails. Kept tight on purpose:
# Cloudflare publishes the canonical list and changes it rarely. If this drifts
# the live fetch will catch up; if both fail we still get reasonable coverage.
_CLOUDFLARE_FALLBACK_V4 = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)
_CLOUDFLARE_FALLBACK_V6 = (
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

_cloudflare_networks_cache: Optional[list] = None


def _fetch_prefix_list(url: str, timeout: int = 5) -> list[str]:
    """Return non-empty stripped lines from *url*, or [] on any failure."""
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []
        return [line.strip() for line in resp.text.splitlines() if line.strip()]
    except requests.exceptions.RequestException:
        return []


def _load_cloudflare_networks() -> list:
    """Lazy-load + cache Cloudflare prefixes parsed as ip_network objects."""
    global _cloudflare_networks_cache
    if _cloudflare_networks_cache is not None:
        return _cloudflare_networks_cache

    raw = _fetch_prefix_list(CLOUDFLARE_IPV4_URL) + _fetch_prefix_list(CLOUDFLARE_IPV6_URL)
    if not raw:
        raw = list(_CLOUDFLARE_FALLBACK_V4) + list(_CLOUDFLARE_FALLBACK_V6)
        print("[!][cdn-ranges] Cloudflare prefix fetch failed, using hardcoded fallback")
    else:
        print(f"[*][cdn-ranges] Loaded {len(raw)} Cloudflare prefixes")

    networks = []
    for entry in raw:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue

    _cloudflare_networks_cache = networks
    return networks


def is_cloudflare_ip(ip: str) -> bool:
    """True if *ip* is inside a published Cloudflare prefix."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _load_cloudflare_networks():
        if addr.version == net.version and addr in net:
            return True
    return False


_ASN_NUMBER_RE = re.compile(r"AS?(\d+)", re.IGNORECASE)


def extract_asn_number(asn_value) -> Optional[int]:
    """
    Pull the ASN integer out of strings like 'AS13335', '13335', or
    'AS13335 Cloudflare, Inc.'. Returns None if no number is found.
    """
    if asn_value is None:
        return None
    if isinstance(asn_value, int):
        return asn_value
    s = str(asn_value).strip()
    if not s:
        return None
    if s.isdigit():
        return int(s)
    m = _ASN_NUMBER_RE.search(s)
    return int(m.group(1)) if m else None


def cdn_name_from_asn(asn_value) -> Optional[str]:
    """Return CDN name for a known CDN ASN, else None."""
    asn = extract_asn_number(asn_value)
    if asn is None:
        return None
    return CDN_ASNS.get(asn)


# =============================================================================
# Response fingerprint (Phase 1: Cloudflare markers)
# =============================================================================

_CDN_HEADER_KEYS = {
    "cf-ray": "cloudflare",
    "cf-cache-status": "cloudflare",
    "cf-connecting-ip": "cloudflare",
}

_CDN_SERVER_PATTERNS = (
    ("cloudflare", "cloudflare"),
)

_CDN_BODY_MARKERS = (
    ("direct ip access not allowed", "cloudflare"),
    ("error 1003", "cloudflare"),
    ("attention required! | cloudflare", "cloudflare"),
)


def response_is_cdn_edge(response) -> Optional[str]:
    """
    Inspect a *requests.Response* for CDN-edge fingerprints.
    Returns the CDN name on match, None otherwise. Body inspection is
    capped at 2 KB and only runs for plausibly-CDN status codes.
    """
    if response is None:
        return None

    headers = response.headers or {}
    lowered = {k.lower(): (v or "") for k, v in headers.items()}

    for key, name in _CDN_HEADER_KEYS.items():
        if key in lowered:
            return name

    server = lowered.get("server", "").lower()
    for needle, name in _CDN_SERVER_PATTERNS:
        if needle in server:
            return name

    if response.status_code in (400, 403, 404, 421, 409):
        try:
            body = (response.text or "")[:2048].lower()
        except Exception:
            body = ""
        for needle, name in _CDN_BODY_MARKERS:
            if needle in body:
                return name

    return None


# =============================================================================
# IP set assembly
# =============================================================================

def collect_asn_cdn_ips(recon_data: dict) -> set[str]:
    """
    Walk recon_data for ASN information attached to IPs (currently from
    http_probe.by_url) and return IPs whose ASN is in CDN_ASNS.
    """
    matches: set[str] = set()

    http_probe = recon_data.get("http_probe") or {}
    for _url, info in (http_probe.get("by_url") or {}).items():
        if not isinstance(info, dict):
            continue
        ip = info.get("ip")
        if not ip:
            continue
        if cdn_name_from_asn(info.get("asn")):
            matches.add(ip)

    port_scan = recon_data.get("port_scan") or {}
    for ip, info in (port_scan.get("by_ip") or {}).items():
        if isinstance(info, dict) and cdn_name_from_asn(info.get("asn")):
            matches.add(ip)

    return matches


def collect_prefix_cdn_ips(ips: Iterable[str]) -> set[str]:
    """Return the subset of *ips* that fall inside a published CDN prefix."""
    return {ip for ip in ips if ip and is_cloudflare_ip(ip)}
