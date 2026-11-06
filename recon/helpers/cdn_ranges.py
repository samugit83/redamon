"""
RedAmon - CDN Identification Helpers
====================================
The one place recon asks "is this a CDN / shared edge?": origin discovery,
ip_filter (Shodan, Netlas, Uncover, the OSINT enrichers), security checks and
vhost/SNI all read these lists, so they cannot drift apart.

Four layers, in order of cost / reliability:

1. Published prefix lists  -> edge_cdn_for_ip(ip), is_cloudflare_ip(ip)
   Authoritative; the provider tells you which IPs are theirs. Static, from
   recon/helpers/cdn_edge_prefixes.py (plus Cloudflare's shipped list).

2. ASN match               -> cdn_name_from_asn(asn)
   Cheap when ASN data is already in the recon data (httpx -asn or enrichers).

3. Certificate issuer      -> cdn_from_certificate(issuer)

4. Response fingerprint    -> edge_from_headers(headers), response_is_cdn_edge(response)
   Header / body markers visible only at probe time. Used as a safety net
   when prefix and ASN data are missing (e.g. user-injected custom IPs).

classify_ip(ip, ...) combines layers 1, 2 and 4 with the CDN name a scanner
reported; the IP attribution step labels every IP of a run from it.

Never in any list: a generic cloud provider's ranges or ASN (Amazon, Microsoft,
Google, Akamai's Linode compute). Real origins run there.

Refreshing the lists: nothing here is fetched at run time except Cloudflare's
optional live list. Each list names its source and retrieval date beside it;
refresh one by hand from that source and move the date. CDN_ASNS is checked
against RDAP (rdap.org/autnum/<n>), the prefixes in cdn_edge_prefixes.py against
each provider's published list. No script: the sources share no format (JSON
with different keys, a weekly Azure file under a new name, an HTML page).
"""
from __future__ import annotations

import ipaddress
import os
import re
from typing import Iterable, Mapping, Optional

import requests

from recon.helpers.cdn_edge_prefixes import EDGE_PREFIXES


# Edge-only ASNs, each verified against RDAP (rdap.org/autnum/<n>) on
# 2026-10-25. CloudFront, Azure Front Door and Google Cloud CDN have none of
# their own: they announce from the provider's general ASN (16509, 8075, 15169),
# which also carries customer servers, so they are recognised by prefix or header.
CDN_ASNS: dict[int, str] = {
    13335: "cloudflare",     # CLOUDFLARENET
    209242: "cloudflare",    # CLOUDFLARESPECTRUM
    54113: "fastly",         # FASTLY
    20940: "akamai",         # AKAMAI-ASN1
    16625: "akamai",         # AKAMAI-AS
    21342: "akamai",         # AKAMAI-ASN2
    32787: "akamai",         # PROLEXIC (Akamai's DDoS scrubbing proxies)
    19551: "imperva",        # INCAPSULA
    30148: "sucuri",         # SUCURI-SEC
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


_static_edge_networks: Optional[list] = None


def _edge_networks() -> list:
    """[(network, cdn)] for every shipped edge prefix, parsed once.

    Cloudflare's live list is used when this run already fetched it; the
    shipped copy otherwise. Never fetches: a caller on the OSINT path would
    otherwise wait up to 5 s per list.
    """
    global _static_edge_networks
    if _static_edge_networks is None:
        parsed = []
        cloudflare = list(_CLOUDFLARE_FALLBACK_V4) + list(_CLOUDFLARE_FALLBACK_V6)
        for cdn, prefixes in (("cloudflare", cloudflare), *EDGE_PREFIXES.items()):
            for entry in prefixes:
                try:
                    parsed.append((ipaddress.ip_network(entry, strict=False), cdn))
                except ValueError:
                    continue
        _static_edge_networks = parsed
    live = _cloudflare_networks_cache
    if isinstance(live, list) and live:
        return [(net, "cloudflare") for net in live] + [
            (net, cdn) for net, cdn in _static_edge_networks if cdn != "cloudflare"] + _lab_edge_networks()
    return _static_edge_networks + _lab_edge_networks()


def _lab_edge_networks() -> list:
    """[(network, 'cloudflare')] for REDAMON_LAB_CDN_PREFIXES (comma-separated CIDRs).

    The urlscan lab's edge sits on a test subnet no real CDN publishes, so a full
    run would never see its hosts as fronted. Unset in any real deployment; the
    orchestrator forwards it only to the projects listed in REDAMON_LAB_PROJECT_IDS.
    """
    nets = []
    for entry in (os.environ.get("REDAMON_LAB_CDN_PREFIXES") or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            nets.append((ipaddress.ip_network(entry, strict=False), "cloudflare"))
        except ValueError:
            continue
    return nets


def edge_cdn_for_ip(ip) -> Optional[str]:
    """The CDN whose published edge prefixes hold *ip*, or None. Static only."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    for net, cdn in _edge_networks():
        if addr.version == net.version and addr in net:
            return cdn
    return None


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
    return {ip for ip in ips if ip and (edge_cdn_for_ip(ip) or is_cloudflare_ip(ip))}


# =============================================================================
# Edge response headers
# =============================================================================
#
# A response carrying one of these came through an edge (a CDN, a WAF proxy or a
# hosting edge), so the address that sent it is not an origin. Ported from
# unwaf waf.go @ c8302eb, plus the CDN markers below.
#
# (header, value fragment or "" for any value, edge name). The value fragment
# keeps a generic header name honest: an origin's own nginx or Squid also sets
# x-cache, and an app may set x-served-by, so those count only with a value
# that names the CDN.
EDGE_HEADER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("cf-ray", "", "cloudflare"), ("cf-cache-status", "", "cloudflare"),
    ("cf-request-id", "", "cloudflare"),
    ("x-akamai-transformed", "", "akamai"), ("akamai-origin-hop", "", "akamai"),
    ("x-amz-cf-id", "", "cloudfront"), ("x-amz-cf-pop", "", "cloudfront"),
    ("x-cache", "cloudfront", "cloudfront"), ("via", "cloudfront", "cloudfront"),
    ("x-fastly-request-id", "", "fastly"), ("fastly-io-info", "", "fastly"),
    # Fastly names its cache node: "cache-fra-etou8220036-FRA".
    ("x-served-by", "cache-", "fastly"),
    # Fastly's Varnish says "1.1 varnish". A self-hosted Varnish says the same,
    # but it already sends x-varnish, which this list has always treated as an edge.
    ("via", "varnish", "fastly"), ("x-varnish", "", "varnish"),
    ("via", "1.1 google", "google"), ("x-goog-bot-verification", "", "google"),
    ("x-sucuri-id", "", "sucuri"), ("x-sucuri-cache", "", "sucuri"),
    ("x-iinfo", "", "imperva"), ("x-cdn", "", "imperva"),
    ("x-azure-ref", "", "azurefrontdoor"), ("x-fd-healthprobe", "", "azurefrontdoor"),
    ("x-sp-url", "", "stackpath"), ("x-sp-waf", "", "stackpath"),
    ("barra_counter_session", "", "barracuda"), ("x-wa-info", "", "f5"),
    ("x-cnection", "", "f5"), ("ddos-guard", "", "ddos-guard"),
    ("ar-asg", "", "arvancloud"), ("ar-poweredby", "", "arvancloud"),
    ("fortiwafsid", "", "fortiweb"), ("x-rdwr", "", "radware"),
    ("x-vercel-id", "", "vercel"), ("x-vercel-cache", "", "vercel"),
    ("x-nf-request-id", "", "netlify"),
)
EDGE_HEADER_PREFIXES: tuple[tuple[str, str], ...] = (
    ("x-akamai-", "akamai"),
)
EDGE_SERVER_TOKENS: tuple[tuple[str, str], ...] = (
    ("cloudflare", "cloudflare"), ("akamaighost", "akamai"), ("akamai", "akamai"),
    ("sucuri", "sucuri"), ("incapsula", "imperva"), ("imperva", "imperva"),
    ("ddos-guard", "ddos-guard"), ("fortiweb", "fortiweb"), ("netlify", "netlify"),
)


def edge_from_headers(headers: Optional[Mapping]) -> Optional[str]:
    """The edge a response's headers name, or None. Header names are case-free."""
    if not headers:
        return None
    try:
        lowered = {str(k).lower(): str(v or "") for k, v in headers.items()}
    except Exception:  # noqa: BLE001 - a header object we cannot read names nothing
        return None
    for name, fragment, edge in EDGE_HEADER_SIGNATURES:
        value = lowered.get(name)
        if value and (not fragment or fragment in value.lower()):
            return edge
    for prefix, edge in EDGE_HEADER_PREFIXES:
        if any(k.startswith(prefix) for k in lowered):
            return edge
    server = lowered.get("server", "").lower()
    for token, edge in EDGE_SERVER_TOKENS:
        if token in server:
            return edge
    return None


# =============================================================================
# One verdict per IP
# =============================================================================
#
# The reasons are fixed phrases: they are stored on the IP (ownership_reasons)
# and shown in the graph drawer, and the attribution step compares them to tell
# an ASN-only match from the others.
EDGE_REASON_RANGE = "in a published CDN edge range"
EDGE_REASON_SCANNER = "a scanner's CDN check named an edge CDN"
EDGE_REASON_HEADERS = "response headers name an edge CDN"
EDGE_REASON_ASN = "its ASN belongs to an edge-only CDN"


def _asn_value(asn):
    """httpx -asn reports {"as_number": "AS13335", ...}; every other source a string."""
    if isinstance(asn, Mapping):
        return asn.get("as_number")
    return asn


def classify_ip(ip, *, asn=None, headers: Optional[Mapping] = None,
                cdn_name=None) -> tuple[bool, Optional[str], list[str]]:
    """(is_edge, provider, reasons): is *ip* a shared CDN edge?

    Any one signal is enough: a published edge prefix, an edge-only CDN a
    scanner named (naabu, httpx or tlsx's ``cdn_name``), a response header only
    an edge sets, an edge-only ASN. ``reasons`` lists every signal that fired,
    in that order, and ``provider`` is the first one's CDN. A cloud label (aws,
    google, azure) or a header an origin can set itself (Varnish, an on-premises
    WAF) is no signal. Never fetches.
    """
    fired: list[tuple[str, str]] = []
    in_range = edge_cdn_for_ip(ip) if ip else None
    if in_range:
        fired.append((EDGE_REASON_RANGE, in_range))
    if is_reliable_edge_cdn_name(cdn_name):
        fired.append((EDGE_REASON_SCANNER, str(cdn_name).strip().lower()))
    if headers:
        try:
            dashed = {str(k).replace("_", "-"): v for k, v in headers.items()}
        except Exception:  # noqa: BLE001 - a header object we cannot read names nothing
            dashed = {}
        by_header = edge_from_headers(dashed)
        if is_reliable_edge_cdn_name(by_header):
            fired.append((EDGE_REASON_HEADERS, by_header))
    by_asn = cdn_name_from_asn(_asn_value(asn))
    if by_asn:
        fired.append((EDGE_REASON_ASN, by_asn))
    if not fired:
        return False, None, []
    return True, fired[0][1], [reason for reason, _ in fired]
