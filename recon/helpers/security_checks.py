"""
RedAmon - Vulnerability Scan Helper Functions
=============================================
Security check functions for detecting misconfigurations and vulnerabilities.
These are custom checks that complement Nuclei template scanning.

Security Check Categories:
1. Direct IP Access Checks - Detect WAF bypass, direct IP exposure
2. TLS/SSL Security Checks - Certificate validation, cipher strength, HSTS
"""

import ipaddress
import json
import re
import socket
import ssl
import time
import requests
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import quote, urlparse
import concurrent.futures

from recon.helpers import catchall
from recon.helpers import page_signals
from recon.helpers.user_agent import DEFAULT_BROWSER_UA
from recon.helpers.cdn_ranges import (
    collect_asn_cdn_ips,
    collect_prefix_cdn_ips,
    collect_reliable_edge_ips,
    response_is_cdn_edge,
)

# Suppress SSL warnings for security testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# Scan-target health (recon/helpers/circuit_breaker.py HostHealth)
# =============================================================================
# Every request below goes through these wrappers. They RECORD what they saw -
# any HTTP response (403/404/500/a WAF page) is life, only a connection failure
# counts against the host - but never refuse a request: the skip decision is
# taken once per host at each check_single_* closure (_host_down), so a leaf a
# test drives with a fixed side_effect list sends exactly the requests it did.

# The run's report scope while run_security_checks runs (one scan per process).
_HH_SCOPE = None
# The run's catch-all controls (one per host and path prefix) and the RoE
# exclusions no control may be sent to, for the same span.
_CONTROL_CACHE: Optional[catchall.ControlCache] = None
_ROE_EXCLUDED: Tuple[str, ...] = ()


def _hh_alive(url) -> None:
    try:
        from recon.helpers import circuit_breaker as cb
        if _HH_SCOPE is not None:
            _HH_SCOPE.host_alive(url)
        else:
            cb.host_health.record_alive(url)
    except Exception:  # noqa: BLE001 - recording must never break a check
        pass


def _hh_failed(url, exc) -> None:
    try:
        from recon.helpers import circuit_breaker as cb
        if _HH_SCOPE is not None:
            _HH_SCOPE.host_failed(url, exc)
        else:
            cb.host_health.record_failure(url, exc)
    except Exception:  # noqa: BLE001
        pass


def _hh_get(url, *args, **kwargs):
    try:
        resp = requests.get(url, *args, **kwargs)
    except Exception as exc:
        _hh_failed(url, exc)
        raise
    _hh_alive(url)
    return resp


def _hh_post(url, *args, **kwargs):
    try:
        resp = requests.post(url, *args, **kwargs)
    except Exception as exc:
        _hh_failed(url, exc)
        raise
    _hh_alive(url)
    return resp


def _hh_request(method, url, *args, **kwargs):
    try:
        resp = requests.request(method, url, *args, **kwargs)
    except Exception as exc:
        _hh_failed(url, exc)
        raise
    _hh_alive(url)
    return resp


def _url_host(host: str) -> str:
    """`host` as a URL authority needs it: an IPv6 literal in brackets (RFC 3986).

    requests raises InvalidURL for an unbracketed IPv6 address, and every check
    swallows RequestException, so without brackets an IPv6 target is silently
    never tested. IPv4 addresses and hostnames come back unchanged.
    """
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


def _host_down(host: str) -> bool:
    """True when both :443 and :80 of `host` are known unreachable this run.

    A hostname gives two keys; a host that only lost HTTPS still has checks
    that apply over HTTP, so it is skipped only when both are down. Uses
    is_down, which never takes a probe: a later request that gets through
    (another check's) is what revives it.
    """
    try:
        from recon.helpers import circuit_breaker as cb
        authority = _url_host(host)
        down = (cb.host_health.is_down(f"https://{authority}")
                and cb.host_health.is_down(f"http://{authority}"))
        if down and _HH_SCOPE is not None:
            _HH_SCOPE.note_host_skipped(cb.host_key(f"https://{authority}"))
        return down
    except Exception:  # noqa: BLE001 - a fault here scans as today
        return False


# =============================================================================
# Direct IP Access Security Checks
# =============================================================================

def _is_ip_address(host: str) -> bool:
    """Check if a string is an IP address (v4 or v6)."""
    import re
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    return bool(re.match(ipv4_pattern, host) or re.match(ipv6_pattern, host))


def _is_synthetic_ip_host(name: str) -> bool:
    """True for the dashed-IP placeholder recon assigns to an IP with no PTR.

    IP-mode recon has no real hostname, so it names each host `ip.replace('.',
    '-').replace(':', '-')` (e.g. ``192-88-96-10``, or ``2001-db8--1`` for v6).
    That label never resolves, so probing it by name only raises ConnectionError
    - wasted work that would also open a HostHealth breaker for a host whose IP
    is alive and already checked directly. A real hostname has a dot or is not
    an IP once the dashes are undone, so it is never matched here.
    """
    import ipaddress
    if not name or "." in name:
        return False
    for sep in (".", ":"):
        try:
            ipaddress.ip_address(name.replace("-", sep))
            return True
        except ValueError:
            continue
    return False


def _analyze_redirect_chain(ip: str, scheme: str, timeout: int = 10) -> Dict:
    """
    Analyze redirect behavior when accessing IP directly.
    
    Returns:
        Dict with redirect analysis:
        - redirects: bool - whether it redirects
        - final_url: str - final destination URL
        - final_host: str - final destination host
        - redirects_to_hostname: bool - whether final destination is a hostname (not IP)
        - redirect_count: int - number of redirects
    """
    url = f"{scheme}://{_url_host(ip)}"
    result = {
        "redirects": False,
        "final_url": url,
        "final_host": ip,
        "redirects_to_hostname": False,
        "redirect_count": 0,
        "initial_status_code": None,
    }
    
    try:
        # First, check initial response without following redirects
        initial_response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )
        result["initial_status_code"] = initial_response.status_code
        
        # Check if it's a redirect
        if initial_response.status_code in [301, 302, 303, 307, 308]:
            result["redirects"] = True
            
            # Now follow redirects to see where it goes
            try:
                final_response = _hh_get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": DEFAULT_BROWSER_UA}
                )
                result["final_url"] = final_response.url
                result["redirect_count"] = len(final_response.history)
                
                # .hostname, not netloc.split(':'): an IPv6 netloc is "[2001:db8::1]:8080".
                final_host = urlparse(final_response.url).hostname or ""
                result["final_host"] = final_host
                
                # Check if final destination is a hostname (not an IP)
                result["redirects_to_hostname"] = not _is_ip_address(final_host)
                
            except requests.exceptions.RequestException:
                # If following redirects fails, we still know it redirects
                pass
    
    except requests.exceptions.RequestException:
        pass
    
    return result


# Headers that, when present on a hostname response but absent on the
# direct-IP response, indicate a real WAF/CDN front layer being bypassed.
_WAF_CDN_HEADER_NAMES = (
    "cf-ray", "cf-cache-status", "x-amz-cf-id", "x-served-by",
    "x-akamai-staging", "x-akamai-transformed", "x-cache", "x-cdn",
    "x-fastly-request-id", "x-azure-ref", "x-azure-fdid",
)
_WAF_CDN_SERVER_TOKENS = (
    "cloudflare", "cloudfront", "akamai", "fastly", "varnish",
    "imperva", "sucuri", "stackpath",
)


# Per-scan AI classifier context. Initialized once at the top of
# run_security_checks() and consumed by _has_cdn_markers() and
# check_waf_bypass(). A module-level dict keeps the call signatures of
# every check function unchanged while still letting the WAF-AI cascade
# fall back deterministically when AI is off.
_AI_CTX: Dict[str, Any] = {
    "enabled": False,
    "model": "",
    "user_id": "",
    "project_id": "",
    "engine": "llm",
    "cache": None,  # populated when enabled
}

# Confidence thresholds used by the cascade. >=70 on the hostname response
# means "AI is confident this is a WAF". <30 on the IP response means "AI
# is confident the origin has no WAF" (so a real bypass is plausible).
_AI_WAF_PRESENT_THRESHOLD = 70
_AI_WAF_ABSENT_THRESHOLD = 30

#: detection_method values for a WAF found by the AI cascade, one per engine. Every
#: branch that attaches the AI fields to a finding tests membership here, so a new
#: engine is added in one place and cannot be recorded but then handled as "static".
_AI_DETECTION_METHODS = ("ai_classifier", "jev_classifier")


def _set_ai_ctx(enabled: bool, model: str, user_id: str, project_id: str, engine: str = "llm") -> None:
    """Initialize the per-scan AI classifier context. Called from
    run_security_checks() based on the WAF_AI_CLASSIFIER setting."""
    _AI_CTX["enabled"] = bool(enabled and model)
    _AI_CTX["model"] = model or ""
    _AI_CTX["user_id"] = user_id or ""
    _AI_CTX["project_id"] = project_id or ""
    _AI_CTX["engine"] = engine or "llm"
    _AI_CTX["cache"] = {} if _AI_CTX["enabled"] else None


def _classify_waf_ai(response, response_time_ms: int = 0) -> Optional[Dict]:
    """Lazy wrapper around the AI classifier. Returns None if AI is not
    enabled, the response is None, or the classifier returns its safe
    fallback (so callers can keep the static behavior)."""
    if not _AI_CTX["enabled"] or response is None:
        return None
    try:
        from recon.helpers.ai_planner.waf_classifier import classify_waf, SAFE_FALLBACK
    except Exception as exc:
        print(f"[!][WAF-AI] Cannot import waf_classifier: {exc}")
        return None
    result = classify_waf(
        response,
        model=_AI_CTX["model"],
        cache=_AI_CTX["cache"],
        user_id=_AI_CTX["user_id"],
        project_id=_AI_CTX["project_id"],
        response_time_ms=response_time_ms,
        engine=_AI_CTX["engine"],
    )
    if result.get("source") == "ai_unavailable":
        return None
    return result


def _has_cdn_markers(response) -> bool:
    """True if *response* carries any header / Server token that indicates
    it came through a CDN or WAF front layer.

    When the WAF AI classifier is enabled (per-scan via _set_ai_ctx), a
    static-negative response gets a second pass through the LLM. Confidence
    >= _AI_WAF_PRESENT_THRESHOLD flips the verdict to True so the
    bare-origin comparison in _is_bare_origin_match correctly recognises a
    rebranded/header-stripped WAF."""
    if response is None:
        return False
    headers_lower = {k.lower(): v for k, v in (response.headers or {}).items()}
    if any(h in headers_lower for h in _WAF_CDN_HEADER_NAMES):
        return True
    server = headers_lower.get("server", "").lower()
    if any(tok in server for tok in _WAF_CDN_SERVER_TOKENS):
        return True

    ai_result = _classify_waf_ai(response)
    if ai_result and ai_result.get("waf_detected") and ai_result.get("confidence", 0) >= _AI_WAF_PRESENT_THRESHOLD:
        return True
    return False


def _is_bare_origin_match(ip: str, hostnames: List[str], scheme: str, timeout: int) -> bool:
    """
    Probe both the IP directly and each candidate hostname, then decide
    whether the IP is simply the bare origin (architecture, not a vuln).

    Returns True iff at least one hostname response matches the IP response
    closely enough to conclude there is no protection layer in between
    (same status, same Server header, similar content size, neither carries
    CDN/WAF markers). Reasoning: if hitting the hostname goes through nothing
    that hitting the IP does not also go through, there is nothing being
    bypassed — the IP just IS the public endpoint (e.g. bare AWS ALB).

    Returns False if any hostname response carries CDN/WAF markers absent
    from the IP response (real bypass — caller should still emit), if all
    hostname probes fail (cannot decide), or if responses diverge enough
    that bare-origin equivalence cannot be claimed.
    """
    try:
        ip_resp = _hh_get(
            f"{scheme}://{_url_host(ip)}",
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA},
        )
    except requests.exceptions.RequestException:
        return False

    ip_server = (ip_resp.headers.get("Server") or "").strip().lower()
    ip_status = ip_resp.status_code
    ip_len = len(ip_resp.content or b"")
    ip_has_cdn = _has_cdn_markers(ip_resp)

    for hostname in hostnames:
        try:
            host_resp = _hh_get(
                f"{scheme}://{hostname}",
                timeout=timeout,
                allow_redirects=False,
                verify=False,
                headers={"User-Agent": DEFAULT_BROWSER_UA},
            )
        except requests.exceptions.RequestException:
            continue

        host_has_cdn = _has_cdn_markers(host_resp)
        # Real bypass: hostname goes through CDN/WAF but IP does not.
        # Don't suppress — caller must emit.
        if host_has_cdn and not ip_has_cdn:
            return False

        host_server = (host_resp.headers.get("Server") or "").strip().lower()
        host_status = host_resp.status_code
        host_len = len(host_resp.content or b"")

        same_status = ip_status == host_status
        same_server = ip_server == host_server
        size_delta = abs(ip_len - host_len)
        similar_size = size_delta < 500 or size_delta < max(host_len, ip_len, 1) * 0.1
        no_cdn_either = not ip_has_cdn and not host_has_cdn

        if same_status and same_server and similar_size and no_cdn_either:
            return True

    return False


def check_direct_ip_http(ip: str, hostnames: Optional[List[str]] = None, timeout: int = 10) -> Optional[Dict]:
    """
    Check if HTTP is accessible directly via IP without TLS.
    This can indicate WAF bypass opportunities or exposed services.
    
    Intelligently handles redirects:
    - If IP redirects to a hostname: Low/Info severity (mitigated)
    - If IP serves content or redirects to same IP: Medium severity

    Args:
        ip: IP address to check
        timeout: Request timeout in seconds

    Returns:
        Vulnerability dict if HTTP is accessible, None otherwise
    """
    try:
        url = f"http://{_url_host(ip)}"
        response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        if response.status_code < 500:
            cdn_match = response_is_cdn_edge(response)
            if cdn_match:
                return None

            # Bare-origin / architecture suppression (case 7).
            # If hostname response matches IP response closely with no CDN
            # markers either side, the IP IS the public endpoint and there
            # is no protection layer being bypassed -> not a vuln.
            if hostnames and _is_bare_origin_match(ip, hostnames, "http", timeout):
                return None

            # Analyze redirect behavior
            redirect_info = _analyze_redirect_chain(ip, "http", timeout)
            
            # Determine severity based on redirect behavior
            if redirect_info["redirects"] and redirect_info["redirects_to_hostname"]:
                # Redirects to a hostname - mitigated, lower severity
                severity = "info"
                description = (
                    f"HTTP service on IP {ip} redirects to hostname {redirect_info['final_host']}. "
                    f"This is a mitigated configuration - the server enforces hostname-based access. "
                    f"However, the IP still responds which reveals server existence."
                )
                evidence = (
                    f"HTTP {response.status_code} redirect → {redirect_info['final_url']} "
                    f"({redirect_info['redirect_count']} redirect(s))"
                )
            elif redirect_info["redirects"]:
                # Redirects but stays on IP - still concerning
                severity = "medium"
                description = (
                    f"HTTP service is accessible directly via IP {ip} without TLS encryption. "
                    f"Server redirects but final destination is still IP-based. "
                    "This may allow attackers to bypass WAF/CDN protections or intercept traffic."
                )
                evidence = f"HTTP {response.status_code} redirect to {redirect_info['final_url']}"
            else:
                # Serves content directly - most concerning
                severity = "medium"
                description = (
                    f"HTTP service is accessible directly via IP {ip} without TLS encryption. "
                    "Server serves content directly on IP without redirecting to hostname. "
                    "This may allow attackers to bypass WAF/CDN protections or intercept traffic."
                )
                evidence = f"HTTP {response.status_code} response - content served directly"
            
            return {
                "type": "direct_ip_http",
                "severity": severity,
                "name": "Direct IP HTTP Access",
                "description": description,
                "url": url,
                "matched_ip": ip,
                "status_code": response.status_code,
                "server": response.headers.get("Server", ""),
                "evidence": evidence,
                "redirects": redirect_info["redirects"],
                "redirects_to_hostname": redirect_info["redirects_to_hostname"],
                "final_url": redirect_info["final_url"] if redirect_info["redirects"] else None,
            }
    except requests.exceptions.RequestException:
        pass

    return None


def check_direct_ip_https(ip: str, hostnames: Optional[List[str]] = None, timeout: int = 10) -> Optional[Dict]:
    """
    Check if HTTPS is accessible directly via IP.
    Less severe than HTTP but still indicates direct IP exposure.

    Intelligently handles redirects:
    - If IP redirects to a hostname: Info severity (mitigated)
    - If IP serves content or redirects to same IP: Low severity

    Args:
        ip: IP address to check
        hostnames: Hostnames that resolve to this IP (used for the
                   bare-origin / architecture suppression test).
        timeout: Request timeout in seconds

    Returns:
        Vulnerability dict if HTTPS is accessible, None otherwise
    """
    try:
        url = f"https://{_url_host(ip)}"
        response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,  # Ignore cert errors for IP-based access
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        if response.status_code < 500:
            cdn_match = response_is_cdn_edge(response)
            if cdn_match:
                return None

            # Bare-origin / architecture suppression (case 7) — see
            # check_direct_ip_http for the full rationale.
            if hostnames and _is_bare_origin_match(ip, hostnames, "https", timeout):
                return None

            # Analyze redirect behavior
            redirect_info = _analyze_redirect_chain(ip, "https", timeout)
            
            # Determine severity based on redirect behavior
            if redirect_info["redirects"] and redirect_info["redirects_to_hostname"]:
                # Redirects to a hostname - mitigated, info only
                severity = "info"
                description = (
                    f"HTTPS service on IP {ip} redirects to hostname {redirect_info['final_host']}. "
                    f"This is a properly mitigated configuration. "
                    f"The IP responds but enforces hostname-based access with TLS."
                )
                evidence = (
                    f"HTTPS {response.status_code} redirect → {redirect_info['final_url']} "
                    f"({redirect_info['redirect_count']} redirect(s))"
                )
            elif redirect_info["redirects"]:
                # Redirects but stays on IP - low concern
                severity = "low"
                description = (
                    f"HTTPS service is accessible directly via IP {ip}. "
                    f"Server redirects but final destination is still IP-based. "
                    "While encrypted, this may allow bypassing CDN/WAF protections."
                )
                evidence = f"HTTPS {response.status_code} redirect to {redirect_info['final_url']}"
            else:
                # Serves content directly - concerning
                severity = "low"
                description = (
                    f"HTTPS service is accessible directly via IP {ip}. "
                    "Server serves content directly on IP without redirecting to hostname. "
                    "While encrypted, this may allow bypassing CDN/WAF protections."
                )
                evidence = f"HTTPS {response.status_code} response - content served directly"
            
            return {
                "type": "direct_ip_https",
                "severity": severity,
                "name": "Direct IP HTTPS Access",
                "description": description,
                "url": url,
                "matched_ip": ip,
                "status_code": response.status_code,
                "server": response.headers.get("Server", ""),
                "evidence": evidence,
                "redirects": redirect_info["redirects"],
                "redirects_to_hostname": redirect_info["redirects_to_hostname"],
                "final_url": redirect_info["final_url"] if redirect_info["redirects"] else None,
            }
    except requests.exceptions.RequestException:
        pass

    return None


def check_ip_api_exposed(ip: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if API endpoints are exposed directly on IP without TLS.
    Common API paths that shouldn't be accessible via direct IP.

    Args:
        ip: IP address to check
        timeout: Request timeout in seconds

    Returns:
        Vulnerability dict if API is exposed, None otherwise
    """
    api_paths = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/rest",
        "/v1",
        "/v2",
    ]

    headers = {
        "User-Agent": DEFAULT_BROWSER_UA,
        "Accept": "application/json",
    }

    def fetch(u):
        return _hh_get(u, timeout=timeout, allow_redirects=False, headers=headers)

    controls = _CONTROL_CACHE if _CONTROL_CACHE is not None else catchall.ControlCache()
    for path in api_paths:
        try:
            url = f"http://{_url_host(ip)}{path}"
            response = fetch(url)

            # Look for API-like responses (JSON or specific status codes)
            content_type = response.headers.get("Content-Type", "")
            is_json = "application/json" in content_type or "text/json" in content_type

            # A bot challenge is the edge answering, not the API: never a
            # finding, and the rest of the paths would only meet it again.
            if catchall.is_challenge(response):
                catchall.note_challenge("vuln_scan", ip)
                break

            if response_is_cdn_edge(response):
                continue

            if response.status_code == 200 and is_json:
                # A server that answers 200 JSON to any path says nothing
                # about this one: ask it for a path that cannot exist.
                verdict = catchall.control_probe(fetch, url, response, cache=controls,
                                                 roe_excluded=_ROE_EXCLUDED, note_module="vuln_scan")
                if verdict.catch_all:
                    continue
                return {
                    "type": "ip_api_exposed",
                    "severity": "high",
                    "name": "API Endpoint Exposed on IP",
                    "description": f"API endpoint {path} is accessible via direct IP {ip} without TLS. "
                                  "This exposes the API to interception and WAF bypass attacks.",
                    "url": url,
                    "matched_ip": ip,
                    "path": path,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "evidence": (f"API endpoint returned {response.status_code} with {content_type}; "
                                 f"control_check: {verdict.control_check} ({verdict.reason})"),
                    "control_check": verdict.control_check,
                }

            # Every web server answers 401/403 somewhere (a default nginx page,
            # a WAF block), so only an API's own refusal says an API lives here.
            if response.status_code in (401, 403) and _is_api_response(response, content_type):
                return {
                    "type": "ip_api_exposed",
                    "severity": "medium",
                    "name": "Authenticated API Endpoint Exposed on IP",
                    "description": f"API endpoint {path} answers on direct IP {ip} over plain HTTP and "
                                  f"requires authentication (HTTP {response.status_code}). The API is "
                                  "reachable around any edge WAF/CDN, and credentials sent to it "
                                  "travel unencrypted.",
                    "url": url,
                    "matched_ip": ip,
                    "path": path,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "evidence": f"API endpoint returned {response.status_code} with "
                                f"{content_type or 'an API error body'}",
                }
        except requests.exceptions.RequestException:
            continue

    return None


def _is_api_response(response, content_type: str) -> bool:
    """True when a response reads as an API's: JSON (any +json type or a JSON
    body) or a Bearer token challenge. An HTML or plain-text error page is not."""
    if "json" in (content_type or "").lower():
        return True
    headers = {str(k).lower(): str(v) for k, v in (response.headers or {}).items()}
    if headers.get("www-authenticate", "").strip().lower().startswith("bearer"):
        return True
    try:
        body = (response.text or "").strip()
    except Exception:  # noqa: BLE001 - an undecodable body is not JSON
        return False
    if not body or body[0] not in "{[":
        return False
    try:
        json.loads(body)
    except ValueError:
        return False
    return True


# Canonical WAF-signature probes for the blocked-vs-allowed differential (class 13).
# These are the standard strings every WAF ships a detection rule for; sent as a
# throwaway query parameter they exercise the ruleset without touching application
# logic. The FINDING is the differential (edge blocks, origin serves) -- never the
# payload -- so this is a WAF-efficacy test, not an exploit.
_WAF_PROBE_PARAM = "rdmnwafprobe"
_WAF_PROBES = [
    ("xss", "<script>alert(1)</script>"),
    ("sqli", "' OR '1'='1"),
    ("traversal", "../../../../etc/passwd"),
]
# Status codes an edge WAF typically returns when it blocks a request.
_WAF_BLOCK_CODES = {403, 406, 429, 501, 999, 202}


def _looks_blocked(status: int) -> bool:
    return status in _WAF_BLOCK_CODES


# The origin's answer to a probe must share at least this share of tokens with
# the page the edge serves for a benign request. The two pass through different
# paths (a CDN injects scripts, rewrites e-mail links, adds a banner), so the
# bar sits below the catch-all control's 0.90; an unrelated default page or an
# error template shares far less than 0.80 with a real site.
_WAF_ORIGIN_SIMILARITY = 0.80


def _waf_payload_differential(subdomain: str, ip: str, timeout: int = 10) -> Optional[Dict]:
    """Blocked-vs-allowed payload differential (class 13).

    A probe the edge WAF blocks for the hostname but the origin SERVES when
    addressed directly by IP (with the real Host header) is concrete proof the
    WAF is bypassable -- stronger than comparing Server-header tokens. "Serves"
    means a 2xx page like the one the edge serves for a benign request: a 302 to
    login, a 401, a 404 or a 421 (the no-SNI default vhost) is the origin
    refusing. The benign baseline is fetched once, only when a probe is a
    candidate, through the same _hh_get. Returns a finding dict or None.
    """
    ua = {"User-Agent": DEFAULT_BROWSER_UA}
    origin_base = f"https://{_url_host(ip)}/"
    baseline = None
    for kind, payload in _WAF_PROBES:
        q = f"?{_WAF_PROBE_PARAM}={quote(payload)}"
        try:
            edge = _hh_get(f"https://{subdomain}/{q}", timeout=timeout, verify=False,
                                allow_redirects=False, headers=ua)
            origin = _hh_get(f"{origin_base}{q}", timeout=timeout, verify=False,
                                  allow_redirects=False, headers={**ua, "Host": subdomain})
        except requests.exceptions.RequestException:
            continue
        if not _looks_blocked(edge.status_code) or not 200 <= origin.status_code < 300:
            continue
        if baseline is None:
            try:
                baseline = _hh_get(f"https://{subdomain}/", timeout=timeout, verify=False,
                                   allow_redirects=False, headers=ua)
            except requests.exceptions.RequestException:
                return None
            if not 200 <= baseline.status_code < 300:
                return None     # the edge serves no page to compare the origin's with
        hostnames = [subdomain, ip]
        echoes = [q[1:], payload, quote(payload)]
        ratio = catchall.similarity(
            catchall.normalise_body(catchall.body_bytes(origin), hostnames=hostnames, echoes=echoes),
            catchall.normalise_body(catchall.body_bytes(baseline), hostnames=hostnames, echoes=echoes))
        if ratio < _WAF_ORIGIN_SIMILARITY:
            continue
        return {
            "type": "waf_bypass",
            "severity": "high",
            "name": "WAF Bypass via Direct Origin Access (payload differential)",
            "description": (
                f"A {kind} signature probe is blocked at the edge for {subdomain} "
                f"(HTTP {edge.status_code}) but served by the origin {ip} "
                f"(HTTP {origin.status_code}, the same page the edge serves for a "
                "benign request) addressed directly with the real Host header. The "
                "WAF can be bypassed by reaching the origin directly."
            ),
            "url": origin_base,
            "matched_ip": ip,
            "subdomain": subdomain,
            "evidence": (f"probe_class={kind}; edge_status={edge.status_code}; "
                         f"origin_status={origin.status_code}; "
                         f"edge_baseline_status={baseline.status_code}; "
                         f"body_similarity={ratio:.2f}; control_check: passed"),
            "detection_method": "payload_differential",
            "control_check": "passed",
        }
    return None


def check_cache_purge_exposed(ip: str, hostnames: Optional[List[str]] = None,
                              timeout: int = 10) -> Optional[Dict]:
    """Unauthenticated cache-purge endpoint (class 14, CDN misconfiguration).

    Caches (Varnish, nginx proxy_cache, some CDNs) expose PURGE/BAN methods to flush
    cached objects. Left unauthenticated, anyone can evict a competitor's cache (cache
    DoS) or force re-fetches. Detected with a METHOD DIFFERENTIAL to stay low-FP: a
    bogus control method must be refused (else the server accepts any method and we
    cannot tell), while PURGE or BAN is accepted (2xx).
    """
    headers = {"User-Agent": DEFAULT_BROWSER_UA}
    if hostnames:
        headers["Host"] = hostnames[0]
    for scheme in ("http", "https"):
        base = f"{scheme}://{_url_host(ip)}/"
        try:
            control = _hh_request("RDMNNOOP", base, timeout=timeout, verify=False,
                                       allow_redirects=False, headers=headers)
        except requests.exceptions.RequestException:
            continue
        if 200 <= control.status_code < 300:
            continue  # server 2xx's an arbitrary method -> cannot distinguish; no claim
        for method in ("PURGE", "BAN"):
            try:
                r = _hh_request(method, base, timeout=timeout, verify=False,
                                     allow_redirects=False, headers=headers)
            except requests.exceptions.RequestException:
                continue
            if 200 <= r.status_code < 300:
                return {
                    "type": "cache_purge_exposed",
                    "severity": "high",
                    "name": f"Unauthenticated Cache Purge Endpoint ({method})",
                    "description": (
                        f"The cache at {ip} accepts an unauthenticated {method} request "
                        f"(HTTP {r.status_code}) while a bogus control method is refused "
                        f"(HTTP {control.status_code}). Anyone can flush cached content, "
                        "enabling cache denial-of-service and forced origin re-fetches."
                    ),
                    "url": base,
                    "matched_ip": ip,
                    "evidence": (f"method={method}; purge_status={r.status_code}; "
                                 f"control_status={control.status_code}"),
                    "detection_method": "method_differential",
                }
    return None


def check_waf_bypass(
    subdomain: str,
    ip: str,
    timeout: int = 10
) -> Optional[Dict]:
    """
    Check if WAF can be bypassed by accessing the origin server directly via IP.
    Compares responses from subdomain vs direct IP access.

    Args:
        subdomain: The hostname/subdomain
        ip: The resolved IP address
        timeout: Request timeout in seconds

    Returns:
        Vulnerability dict if WAF bypass is possible, None otherwise
    """
    # Strongest signal first: a real blocked-vs-allowed payload differential. A token
    # comparison only infers "a WAF is present"; this proves the WAF is bypassable.
    payload_finding = _waf_payload_differential(subdomain, ip, timeout)
    if payload_finding:
        return payload_finding

    try:
        # Try accessing via subdomain (through WAF/CDN)
        subdomain_url = f"https://{subdomain}"
        subdomain_response = _hh_get(
            subdomain_url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        # Try accessing via direct IP with Host header
        ip_url = f"https://{_url_host(ip)}"
        ip_response = _hh_get(
            ip_url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={
                "User-Agent": DEFAULT_BROWSER_UA,
                "Host": subdomain,  # Set Host header to bypass virtual hosting
            }
        )

        # Check if both return similar content (WAF bypass)
        subdomain_server = subdomain_response.headers.get("Server", "").lower()
        ip_server = ip_response.headers.get("Server", "").lower()

        # Detect if subdomain is behind WAF/CDN
        waf_indicators = ["cloudflare", "akamai", "cloudfront", "fastly", "imperva", "sucuri"]
        subdomain_has_waf = any(waf in subdomain_server for waf in waf_indicators)
        ip_has_waf = any(waf in ip_server for waf in waf_indicators)
        detection_method = "static_headers"
        ai_subdomain: Optional[Dict] = None
        ai_ip: Optional[Dict] = None

        # AI cascade: when the static Server-token check missed a WAF on the
        # hostname, ask the classifier. A high-confidence "WAF on hostname"
        # paired with a low-confidence "no WAF on IP" is a real bypass.
        if not subdomain_has_waf:
            ai_subdomain = _classify_waf_ai(subdomain_response)
            if ai_subdomain and ai_subdomain.get("waf_detected") and ai_subdomain.get("confidence", 0) >= _AI_WAF_PRESENT_THRESHOLD:
                subdomain_has_waf = True
                detection_method = ("jev_classifier"
                                    if ai_subdomain.get("source") == "jev_classifier"
                                    else "ai_classifier")
                if not ai_ip:
                    ai_ip = _classify_waf_ai(ip_response)
                if ai_ip and (ai_ip.get("waf_detected") and ai_ip.get("confidence", 0) >= _AI_WAF_PRESENT_THRESHOLD):
                    # AI sees a WAF on the IP too, so treat the origin as also
                    # protected -- not a bypass.
                    ip_has_waf = True

        # WAF bypass: subdomain has WAF but IP doesn't, and IP returns valid response
        if subdomain_has_waf and not ip_has_waf and ip_response.status_code < 500:
            waf_label = (
                ai_subdomain.get("waf_type") if (detection_method in _AI_DETECTION_METHODS and ai_subdomain)
                else (subdomain_server or "unknown")
            )
            evidence = (
                f"AI classifier flagged subdomain as {waf_label} (confidence={ai_subdomain.get('confidence')}); IP response did not match WAF fingerprint"
                if detection_method in _AI_DETECTION_METHODS and ai_subdomain
                else f"WAF detected on subdomain ({subdomain_server}) but not on IP"
            )
            finding = {
                "type": "waf_bypass",
                "severity": "high",
                "name": "WAF Bypass via Direct IP Access",
                "description": f"The subdomain {subdomain} is protected by WAF ({waf_label}), "
                              f"but the origin server at {ip} is directly accessible. "
                              "This allows bypassing WAF protections.",
                "url": ip_url,
                "matched_ip": ip,
                "subdomain": subdomain,
                "subdomain_server": subdomain_server,
                "ip_server": ip_server,
                "evidence": evidence,
                "detection_method": detection_method,
            }
            if detection_method in _AI_DETECTION_METHODS and ai_subdomain:
                finding["waf_type"] = ai_subdomain.get("waf_type")
                finding["waf_confidence"] = ai_subdomain.get("confidence")
                finding["ai_reasoning"] = ai_subdomain.get("reasoning")
            return finding

        # Also check if IP returns content without Host header (direct origin exposure)
        if not subdomain_has_waf and ip_response.status_code == 200:
            # Check if responses are similar (same origin)
            if abs(len(subdomain_response.text) - len(ip_response.text)) < 1000:
                return {
                    "type": "waf_bypass",
                    "severity": "medium",
                    "name": "Origin Server Directly Accessible",
                    "description": f"The origin server for {subdomain} is directly accessible at {ip}. "
                                  "Consider restricting access to only allow traffic from CDN/WAF.",
                    "url": ip_url,
                    "matched_ip": ip,
                    "subdomain": subdomain,
                    "evidence": "Similar content served via direct IP access with Host header",
                }
    except requests.exceptions.RequestException:
        pass

    return None


def run_direct_ip_checks(
    ips: List[str],
    subdomains_to_ips: Dict[str, List[str]],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10,
    cdn_ips: Optional[Set[str]] = None,
) -> List[Dict]:
    """
    Run all enabled direct IP access security checks.

    Args:
        ips: List of IP addresses to check
        subdomains_to_ips: Mapping of subdomains to their IPs
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout in seconds
        max_workers: Maximum concurrent workers
        cdn_ips: IPs already classified as CDN/edge, excluded from probing
                 (cases 1, 2, 3 prefilter)

    Returns:
        List of vulnerability findings
    """
    findings = []
    cdn_ips = cdn_ips or set()

    if cdn_ips:
        before = len(ips)
        ips = [ip for ip in ips if ip not in cdn_ips]
        skipped = before - len(ips)
        if skipped:
            print(f"[*][SecurityCheck] Skipping {skipped} CDN/edge IP(s) from Direct IP checks")

    # Build IP -> [hostnames] mapping for the bare-origin comparison test
    # inside check_direct_ip_*.
    ip_to_hostnames: Dict[str, List[str]] = {}
    for host, host_ips in (subdomains_to_ips or {}).items():
        for ip in host_ips or []:
            ip_to_hostnames.setdefault(ip, []).append(host)

    def check_single_ip(ip: str) -> List[Dict]:
        if _host_down(ip):
            return []
        ip_findings = []
        hostnames = ip_to_hostnames.get(ip) or None

        if enabled_checks.get("direct_ip_http", True):
            result = check_direct_ip_http(ip, hostnames=hostnames, timeout=timeout)
            if result:
                ip_findings.append(result)

        if enabled_checks.get("direct_ip_https", True):
            result = check_direct_ip_https(ip, hostnames=hostnames, timeout=timeout)
            if result:
                ip_findings.append(result)

        if enabled_checks.get("ip_api_exposed", True):
            result = check_ip_api_exposed(ip, timeout)
            if result:
                ip_findings.append(result)

        if enabled_checks.get("cache_purge_exposed", True):
            result = check_cache_purge_exposed(ip, hostnames=hostnames, timeout=timeout)
            if result:
                ip_findings.append(result)

        return ip_findings

    # Run IP checks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(check_single_ip, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                ip_findings = future.result()
                findings.extend(ip_findings)
            except Exception:
                pass

    # Run WAF bypass checks (requires subdomain-to-IP mapping)
    if enabled_checks.get("waf_bypass", True):
        for subdomain, subdomain_ips in subdomains_to_ips.items():
            for ip in subdomain_ips:
                if ip in cdn_ips:
                    continue
                result = check_waf_bypass(subdomain, ip, timeout)
                if result:
                    findings.append(result)

    return findings


# =============================================================================
# TLS/SSL Security Checks
# =============================================================================

def get_ssl_certificate(hostname: str, port: int = 443, timeout: int = 10) -> Optional[Dict]:
    """
    Retrieve SSL certificate information for a host.

    Args:
        hostname: Hostname to check
        port: Port number (default 443)
        timeout: Connection timeout

    Returns:
        Certificate info dict or None if failed
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Allow self-signed for testing

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_binary = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()

                return {
                    "cert": cert,
                    "cert_binary": cert_binary,
                    "cipher": cipher,
                    "version": version,
                }
    except Exception:
        return None


def parse_cert_date(date_str: str) -> Optional[datetime]:
    """Parse certificate date string to datetime."""
    try:
        # Format: 'Jan  1 00:00:00 2024 GMT'
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        try:
            # Alternative format
            return datetime.strptime(date_str, "%b  %d %H:%M:%S %Y %Z")
        except ValueError:
            return None


def check_tls_expiring_soon(
    hostname: str,
    port: int = 443,
    days_threshold: int = 30,
    timeout: int = 10
) -> Optional[Dict]:
    """
    Check if TLS certificate is expiring soon.

    Args:
        hostname: Hostname to check
        port: Port number
        days_threshold: Days before expiry to warn
        timeout: Connection timeout

    Returns:
        Vulnerability dict if expiring soon, None otherwise
    """
    cert_info = get_ssl_certificate(hostname, port, timeout)
    if not cert_info or not cert_info.get("cert"):
        return None

    cert = cert_info["cert"]
    not_after = cert.get("notAfter")

    if not_after:
        expiry_date = parse_cert_date(not_after)
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if expiry_date and expiry_date <= now:
            # ALREADY expired. The old code required expiry_date > now, so an
            # expired certificate produced ZERO findings -- the most severe case
            # was the one silently dropped.
            days_expired = (now - expiry_date).days
            return {
                "type": "tls_expired",
                "severity": "high",
                "name": "TLS Certificate Expired",
                "description": f"The TLS certificate for {hostname} expired {days_expired} days ago ({not_after}). "
                              "Clients will reject the connection or present a security warning.",
                "url": f"https://{hostname}:{port}",
                "hostname": hostname,
                "port": port,
                "expiry_date": not_after,
                "days_until_expiry": -days_expired,
                "evidence": f"Certificate expired {days_expired} days ago",
            }

        if expiry_date and expiry_date > now:
            days_until_expiry = (expiry_date - now).days
            if days_until_expiry <= days_threshold:
                return {
                    "type": "tls_expiring_soon",
                    "severity": "low",
                    "name": "TLS Certificate Expiring Soon",
                    "description": f"The TLS certificate for {hostname} will expire in {days_until_expiry} days ({not_after}). "
                                  "Consider renewing the certificate to avoid service disruption.",
                    "url": f"https://{hostname}:{port}",
                    "hostname": hostname,
                    "port": port,
                    "expiry_date": not_after,
                    "days_until_expiry": days_until_expiry,
                    "evidence": f"Certificate expires in {days_until_expiry} days",
                }

    return None


def run_tls_checks(
    hostnames: List[str],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    expiry_days_threshold: int = 30,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run TLS expiring soon check (other TLS checks are covered by Nuclei).

    Args:
        hostnames: List of hostnames to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Connection timeout in seconds
        expiry_days_threshold: Days before expiry to warn
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_host(hostname: str) -> List[Dict]:
        if _host_down(hostname):
            return []
        host_findings = []

        if enabled_checks.get("tls_expiring_soon", True):
            result = check_tls_expiring_soon(hostname, days_threshold=expiry_days_threshold, timeout=timeout)
            if result:
                host_findings.append(result)

        return host_findings

    # Run checks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


# tlsx emits negotiated-version tokens like these, NOT "TLS 1.0"; a deny list
# written against pretty names would silently never match.
WEAK_TLS_VERSIONS = {"ssl30", "ssl20", "tls10", "tls11"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "_DES_", "-DES-", "NULL", "EXPORT", "MD5", "ANON")
_WILDCARD_SAN_OVERBROAD = 20


def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _cert_is_wildcard(san) -> bool:
    return any(isinstance(x, str) and x.strip().startswith("*.") for x in (san or []))


def _cert_names_host(host: str, subject_cn, san) -> bool:
    """One level of wildcard matching, mirroring TLS name-check semantics."""
    if not host:
        return True
    host = host.strip().lower().rstrip(".")
    names = ([subject_cn] if subject_cn else []) + list(san or [])
    for raw in names:
        if not isinstance(raw, str) or not raw:
            continue
        name = raw.strip().lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            if host.endswith(suffix) and host[: -len(suffix)].count(".") == 0:
                return True
    return False


def _expired_from_not_after(not_after) -> Optional[bool]:
    if not not_after:
        return None
    try:
        dt = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return None


def _iter_cert_targets(recon_data: Dict[str, Any], nameless: bool = False):
    """Yield (host, ip, port, verdicts) for EVERY certificate already in memory.

    httpx certificates with no subject CN and no SAN are skipped (a name check
    would only guess), unless `nameless`: the issuer rules of the Page Content
    group read the issuer alone, and a default ingress certificate often names
    nobody.

    Phase 1.0's rule is to gate the consumers on cert-data AVAILABILITY, not on
    which tool produced it. tlsx is the richer source (it reports the verdict
    booleans directly) and wins for any target it covers; httpx fills in the
    rest, with the derivable verdicts computed here and the underivable ones
    left as None so they are skipped rather than guessed.

    httpx and tlsx are both ProjectDiscovery tools and share the TLS version
    vocabulary ("tls12"), so one deny list matches both.
    """
    from urllib.parse import urlparse

    seen = set()
    by_target = ((recon_data.get("tlsx") or {}).get("by_target")) or {}
    for e in by_target.values():
        if not isinstance(e, dict) or not e.get("probe_status"):
            continue
        host = e.get("host") or e.get("scanned_ip") or ""
        port = e.get("port")
        seen.add((str(host).lower(), port))
        yield host, (e.get("scanned_ip") or e.get("ip")), port, {
            "subject_cn": e.get("subject_cn"), "san": e.get("san") or [],
            "subject_dn": e.get("subject_dn"), "not_after": e.get("not_after"),
            "expired": bool(e.get("expired")),
            "self_signed": bool(e.get("self_signed")),
            "mismatched": bool(e.get("mismatched")),
            "wildcard": bool(e.get("wildcard")),
            "tls_version": e.get("tls_version"), "cipher": e.get("cipher"),
            "version_enum": e.get("version_enum") or [],
            "cipher_enum": e.get("cipher_enum") or [],
            "covers_siblings": e.get("mismatch_cert_covers_siblings") or [],
            "issuer_dn": e.get("issuer_dn"), "issuer_cn": e.get("issuer_cn"),
            "source": "tlsx",
        }

    by_url = ((recon_data.get("http_probe") or {}).get("by_url")) or {}
    for url, info in by_url.items():
        if not isinstance(info, dict):
            continue
        tls = info.get("tls") or {}
        cert = tls.get("certificate") or {}
        if not (cert.get("subject_cn") or cert.get("san")) and not (
                nameless and (cert.get("issuer") or cert.get("issuer_cn"))):
            continue
        try:
            parsed = urlparse(str(url))
            host = (parsed.hostname or info.get("host") or "")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except (ValueError, TypeError):
            host, port = (info.get("host") or ""), None
        if (str(host).lower(), port) in seen:
            continue          # tlsx already covered this target, and knows more
        san = [x for x in (cert.get("san") or []) if isinstance(x, str)]
        # httpx reports the same verdicts as tlsx. They are absent only on data
        # captured before http_probe kept them, so derive what can be derived;
        # self_signed stays UNKNOWN rather than False, since these fields cannot
        # prove a cert is properly issued.
        expired, self_signed = cert.get("expired"), cert.get("self_signed")
        mismatched, wildcard = cert.get("mismatched"), cert.get("wildcard")
        yield host, info.get("ip"), port, {
            "subject_cn": cert.get("subject_cn"), "san": san,
            "subject_dn": cert.get("subject_dn"), "not_after": cert.get("not_after"),
            "expired": (bool(expired) if expired is not None
                        else _expired_from_not_after(cert.get("not_after"))),
            "self_signed": bool(self_signed) if self_signed is not None else None,
            "mismatched": (bool(mismatched) if mismatched is not None
                           else (not _cert_names_host(host, cert.get("subject_cn"), san))),
            "wildcard": bool(wildcard) if wildcard is not None else _cert_is_wildcard(san),
            "tls_version": tls.get("version"), "cipher": tls.get("cipher"),
            "version_enum": [], "cipher_enum": [],
            "issuer_dn": cert.get("issuer_dn") or cert.get("issuer"),
            "issuer_cn": cert.get("issuer_cn"),
            "source": "http_probe",
        }


def _weak_ciphers_from_enum(cipher_enum) -> List[str]:
    """Flatten tlsx's `-ce -ct weak` output into the cipher names it found.

    tlsx reports one envelope per TLS version it could enumerate, and the
    `ciphers` map inside is EMPTY when that version offered nothing weak:

        [{"version": "tls12", "ciphers": {}}, {"version": "tls10", "ciphers": {}}]

    Verified against tlsx v1 output; a plain list of names is also accepted
    because older builds emitted that shape.
    """
    names: List[str] = []
    for entry in cipher_enum or []:
        if isinstance(entry, str):
            names.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        ciphers = entry.get("ciphers")
        if isinstance(ciphers, dict):
            for bucket in ciphers.values():
                if isinstance(bucket, list):
                    names.extend(str(c) for c in bucket if c)
                elif bucket:
                    names.append(str(bucket))
        elif isinstance(ciphers, list):
            names.extend(str(c) for c in ciphers if c)
    # Order-stable dedup: the same cipher usually recurs across versions.
    seen = set()
    return [n for n in names if not (n in seen or seen.add(n))]


def _assemble_security_result(all_findings: List[Dict], enabled_checks: Dict[str, bool],
                              hostname_count: int, ip_count: int) -> Dict[str, Any]:
    """The `security_checks` envelope the graph writer and the report both read.

    One definition, because a partial run (certificate hygiene only) has to be
    indistinguishable in shape from a full one downstream.
    """
    by_type: Dict[str, List[Dict]] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in all_findings:
        by_type.setdefault(finding.get("type", "unknown"), []).append(finding)
        severity = finding.get("severity", "info")
        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "security_checks": {
            "scan_timestamp": datetime.now().isoformat(),
            "checks_enabled": enabled_checks,
            "targets_checked": {"hostnames": hostname_count, "ips": ip_count},
            "findings": all_findings,
            "by_type": by_type,
            "summary": {"total_findings": len(all_findings), **severity_counts},
        }
    }


def run_cert_hygiene_checks_only(recon_data: Dict[str, Any],
                                 enabled_checks: Dict[str, bool]) -> Dict[str, Any]:
    """Certificate-hygiene findings alone, with no network traffic whatsoever.

    H2: the full `run_security_checks` lives inside the vuln_scan module, and
    the pipeline skips that whole module when httpx found no live URL
    (`should_skip_active_scans`). A host serving TLS only on a non-HTTP port is
    exactly that case -- and exactly the case tlsx exists for -- so its
    certificates were stored and then never evaluated, silently.

    This is the subset that is safe to run there: it reads certificates already
    in memory and sends no packets, so it does not resurrect any of the active
    probing the skip is there to prevent.
    """
    findings = run_tls_data_checks(recon_data, enabled_checks)
    findings += run_page_content_checks(recon_data, enabled_checks, pages=False)
    return _assemble_security_result(findings, enabled_checks, 0, 0)


# =============================================================================
# Page Content checks (item 5): titles, Server headers and certificate issuers
# httpx and tlsx already collected, against the page_signals catalog. No
# request: the data is in memory.
# =============================================================================

#: Live check type -> (catalog family, the setting that switches it).
PAGE_CONTENT_CHECKS = {
    "open_console": ("open_console", "SECURITY_CHECK_OPEN_CONSOLES"),
    "debug_page": ("debug_page", "SECURITY_CHECK_DEBUG_PAGES"),
    "unfinished_installer": ("unfinished_installer", "SECURITY_CHECK_UNFINISHED_INSTALLERS"),
    "dev_server": ("dev_server", "SECURITY_CHECK_DEV_SERVERS"),
    "directory_listing": ("directory_listing", "SECURITY_CHECK_DIRECTORY_LISTING"),
    "defaced_page": ("defaced_page", "SECURITY_CHECK_DEFACED_PAGES"),
    "takeover_error_page": ("takeover", "SECURITY_CHECK_TAKEOVER_ERROR_PAGES"),
    "test_certificate": ("test_certificate", "SECURITY_CHECK_TEST_CERTIFICATES"),
}

_PAGE_CONTENT_ADVICE = {
    "open_console": "Put it behind a login, or take it off the internet: anyone can use it as it is.",
    "debug_page": "Turn debug mode off in production: the page shows code or settings.",
    "unfinished_installer": "Finish the installation or remove the installer: whoever completes it owns the site.",
    "dev_server": "Serve the site through a production web server: a development server is not built for the internet.",
    "directory_listing": "Turn directory listing off: every file in the folder can be downloaded.",
    "defaced_page": "Treat it as an incident: someone else changed the site.",
    "takeover": "Remove the DNS record, or claim the name on the provider again. Turn on Subdomain Takeover for the full verdict.",
    "test_certificate": "Install a real certificate: a test or default certificate means a test deployment, or a host the ingress does not know.",
}


def page_content_enabled(settings: Dict[str, Any]) -> Dict[str, bool]:
    """The Page Content entries of an enabled-checks dict, from the settings."""
    return {check: bool(settings.get(key, True)) for check, (_family, key) in PAGE_CONTENT_CHECKS.items()}


def _dns_cname(dns_subdomains: Dict[str, Any], host: str) -> list:
    records = ((dns_subdomains or {}).get(host) or {}).get("records") or {}
    cname = records.get("CNAME")
    if isinstance(cname, str):
        return [cname]
    return [c for c in cname if isinstance(c, str)] if isinstance(cname, list) else []


def run_page_content_checks(recon_data: Dict[str, Any], enabled_checks: Dict[str, bool],
                            pages: bool = True) -> List[Dict]:
    """The live Page Content findings: one per host, path and problem for a
    page (one per host for a server or a certificate). Pages are described by
    httpx's last hop, so paths, the root-only rule and the finding's URL use
    `final_url`. A status the partial builder did not know (`status_unknown`)
    satisfies no status condition. `pages=False` runs the certificate rules
    alone (the certificate-only fallback when the active scans are skipped)."""
    family_type = {family: check for check, (family, _key) in PAGE_CONTENT_CHECKS.items()}
    on = {family for check, (family, _key) in PAGE_CONTENT_CHECKS.items()
          if enabled_checks.get(check, True)}
    findings: List[Dict] = []
    seen: Set[Tuple[str, str]] = set()

    def _add_finding(family, match, url, hostname, ip, evidence_of, extra):
        check_type = family_type[family]
        key = (check_type, url)
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "type": check_type, "severity": match["severity"],
            "name": f"{match['label']}: {page_signals.FAMILY_LABEL[family]}",
            "description": (f"{evidence_of} in this scan ({match['matched']}). "
                            f"{_PAGE_CONTENT_ADVICE[family]}"),
            "evidence": match["matched"], "url": url, "source": "security_check",
            "family": family, "matched": match["matched"], "problem": match["problem"],
            **({"provider": match["provider"], "outcome": match["outcome"]} if family == "takeover" else {}),
            **({"hostname": hostname} if hostname else {"matched_ip": ip}),
            **extra,
        })

    if pages and on - {"test_certificate"}:
        dns_subdomains = (recon_data.get("dns") or {}).get("subdomains") or {}
        by_url = (recon_data.get("http_probe") or {}).get("by_url") or {}
        for url in sorted(by_url):
            info = by_url[url]
            if not isinstance(info, dict) or not info.get("status_code"):
                continue
            final = str(info.get("final_url") or url)
            try:
                parsed = urlparse(final)
                host = (parsed.hostname or info.get("host") or "").lower()
            except ValueError:
                continue
            if not host:
                continue
            status = None if info.get("status_unknown") else info.get("status_code")
            cname = info.get("cname")
            cname = ([cname] if isinstance(cname, str) else cname) or _dns_cname(dns_subdomains, host)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for match in page_signals.match_page(
                    info.get("title"), info.get("server"), status, parsed.path or "/",
                    info.get("content_type"), host, final, cname):
                family = match["family"]
                if family not in on:
                    continue
                per_host = family in page_signals.PER_HOST_FAMILIES
                target = origin if per_host else f"{origin}{parsed.path or '/'}"
                is_ip = _looks_like_ip(host)
                _add_finding(family, match, target, None if is_ip else host, host,
                             f"httpx got a {page_signals.FAMILY_LABEL[family]} at {target}",
                             {"status_code": info.get("status_code"), "server": info.get("server")})

    if "test_certificate" in on:
        targets = sorted(_iter_cert_targets(recon_data, nameless=True),
                         key=lambda t: (str(t[0] or t[1] or ""), int(t[2] or 0)))
        for host, ip, port, c in targets:
            match = next(iter(page_signals.match_certificate(c.get("issuer_dn"), c.get("issuer_cn"))), None)
            if not match:
                continue
            is_ip = _looks_like_ip(str(host))
            hostname = host if host and not is_ip else None
            name = _url_host(host or ip or "")
            if not name:
                continue
            _add_finding("test_certificate", match, f"https://{name}", hostname, ip or host,
                         f"{host or ip}:{port} presented a {match['label']}", {"port": port})
    return findings


def run_tls_data_checks(recon_data: Dict[str, Any], enabled_checks: Dict[str, bool]) -> List[Dict]:
    """Derive TLS-hygiene findings from certificate data already in memory.

    Zero extra network cost. Works from the 443 certificates httpx captured when
    tlsx is off (every passive preset), and additionally covers non-HTTP TLS
    ports and bare IPs when tlsx is on. A verdict the available source cannot
    determine is None and produces no finding -- unknown is not a vulnerability.

    Each finding carries type/severity/name/description/url and EXACTLY ONE of
    hostname / matched_ip: vuln_mixin keys the node on
    (type, url, matched_ip or hostname), so emitting both would diverge from the
    network TLS check's id and report one exposure twice.
    """
    findings: List[Dict] = []

    for host, ip, port, c in _iter_cert_targets(recon_data):
        # tlsx reports a bare IPv6 address as the host when it had no name, and
        # unbracketed the writer reads the URL's host as "2001".
        url = f"https://{_url_host(host)}:{port}" if host else None
        is_ip = _looks_like_ip(str(host))
        hostname = host if host and not is_ip else None

        def _add(check_type, severity, name, description, evidence):
            findings.append({
                "type": check_type, "severity": severity, "name": name,
                "description": description, "evidence": evidence,
                "url": url, "port": port, "source": "security_check",
                # XOR: see the docstring. A hostname target anchors on the
                # hostname (matching the network check); a bare IP on the IP.
                **({"hostname": hostname} if hostname else {"matched_ip": ip or host}),
            })

        target_desc = host or ip or "target"

        if enabled_checks.get("tls_expired", True) and c["expired"]:
            _add("tls_expired", "high", "TLS Certificate Expired",
                 f"The TLS certificate presented on {target_desc}:{port} is expired "
                 f"(not_after {c['not_after']}).", f"not_after={c['not_after']}")
        if enabled_checks.get("tls_self_signed", True) and c["self_signed"]:
            _add("tls_self_signed", "medium", "Self-Signed TLS Certificate",
                 f"{target_desc}:{port} presents a self-signed certificate (subject == issuer).",
                 f"subject_dn={c['subject_dn']}")
        # `not is_ip` belongs here too, not just in the tlsx parser: the
        # httpx-sourced verdict is derived from the URL's host, so an
        # IP-addressed URL mismatches every certificate that names a hostname.
        if enabled_checks.get("tls_hostname_mismatch", True) and c["mismatched"] and not is_ip:
            siblings = c.get("covers_siblings") or []
            if siblings:
                # tlsx tests one of the IP's names, an arbitrary pick: a cert
                # valid for a sibling is most likely the service's real name,
                # and the tested one may be a name no client uses for it.
                shown = ", ".join(siblings)
                _add("tls_hostname_mismatch", "low", "TLS Certificate Hostname Mismatch",
                     f"The certificate on {target_desc}:{port} does not name the host it was "
                     f"served for, but it is valid for {shown} on the same IP. {target_desc} "
                     "is one of several names that share this address; verify which name "
                     "clients use to reach this service.",
                     f"subject_cn={c['subject_cn']} san={c['san']} valid_for_same_ip={shown}")
            else:
                _add("tls_hostname_mismatch", "medium", "TLS Certificate Hostname Mismatch",
                     f"The certificate on {target_desc}:{port} does not name the host it was served for.",
                     f"subject_cn={c['subject_cn']} san={c['san']}")

        version = (c["tls_version"] or "").lower()
        if enabled_checks.get("tls_weak_version", True) and version in WEAK_TLS_VERSIONS:
            _add("tls_weak_version", "medium", "Weak TLS Version Negotiated",
                 f"{target_desc}:{port} negotiated {version}, a deprecated TLS version.", version)

        cipher = (c["cipher"] or "").upper()
        if enabled_checks.get("tls_weak_cipher", True) and cipher and any(m in cipher for m in WEAK_CIPHER_MARKERS):
            _add("tls_weak_cipher", "medium", "Weak TLS Cipher Negotiated",
                 f"{target_desc}:{port} negotiated a weak cipher ({cipher}).", cipher)

        san = c["san"] or []
        if enabled_checks.get("tls_wildcard_overbroad", True) and c["wildcard"] and len(san) > _WILDCARD_SAN_OVERBROAD:
            _add("tls_wildcard_overbroad", "low", "Overbroad Wildcard Certificate",
                 f"The wildcard certificate on {target_desc}:{port} names {len(san)} SAN entries; "
                 "broad wildcard reuse widens the blast radius of a key compromise.",
                 f"{len(san)} SAN entries")

        # Flag-gated: populated only when the tlsx enum flags were on. A server
        # can SUPPORT a weak version while negotiating a strong one.
        weak_supported = [str(v).lower() for v in c["version_enum"]
                          if str(v).lower() in WEAK_TLS_VERSIONS]
        if enabled_checks.get("tls_weak_version", True) and weak_supported:
            _add("tls_weak_version_supported", "medium", "Weak TLS Version Supported",
                 f"{target_desc}:{port} still supports {', '.join(weak_supported)}.",
                 ", ".join(weak_supported))
        # H3: `-ct weak` returns ONE ENTRY PER VERSION it managed to enumerate,
        # with an empty `ciphers` map when that version offered no weak cipher:
        #   [{"version":"tls12","ciphers":{}},{"version":"tls10","ciphers":{}}]
        # Treating the list as the signal reported every enumerable server as
        # supporting weak ciphers. Count the ciphers, not the envelopes.
        weak_ciphers = _weak_ciphers_from_enum(c["cipher_enum"])
        if enabled_checks.get("tls_weak_cipher", True) and weak_ciphers:
            shown = ", ".join(weak_ciphers[:5])
            _add("tls_weak_cipher_supported", "medium", "Weak TLS Cipher Supported",
                 f"{target_desc}:{port} supports {len(weak_ciphers)} weak cipher(s): {shown}.",
                 shown)

    return findings


# =============================================================================
# Security Headers Checks
# =============================================================================

# Security headers to check (only headers NOT covered by Nuclei templates)
# Note: CSP, X-Frame-Options, X-Content-Type-Options, CORS are covered by Nuclei
SECURITY_HEADERS = {
    "Referrer-Policy": {
        "check_name": "missing_referrer_policy",
        "severity": "low",
        "name": "Referrer-Policy Header Missing",
        "description": "The Referrer-Policy header is not set. "
                      "This may leak sensitive URL information to third-party sites.",
        "recommendation": "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    "Permissions-Policy": {
        "check_name": "missing_permissions_policy",
        "severity": "low",
        "name": "Permissions-Policy Header Missing",
        "description": "The Permissions-Policy (formerly Feature-Policy) header is not set. "
                      "This header controls which browser features can be used.",
        "recommendation": "Implement Permissions-Policy to restrict access to sensitive browser APIs.",
    },
    "Cross-Origin-Opener-Policy": {
        "check_name": "missing_coop",
        "severity": "info",
        "name": "Cross-Origin-Opener-Policy Header Missing",
        "description": "The Cross-Origin-Opener-Policy header is not set. "
                      "This header helps prevent cross-origin attacks like Spectre.",
        "recommendation": "Set Cross-Origin-Opener-Policy to 'same-origin' for enhanced isolation.",
    },
    "Cross-Origin-Resource-Policy": {
        "check_name": "missing_corp",
        "severity": "info",
        "name": "Cross-Origin-Resource-Policy Header Missing",
        "description": "The Cross-Origin-Resource-Policy header is not set. "
                      "This header prevents other origins from loading your resources.",
        "recommendation": "Set Cross-Origin-Resource-Policy to 'same-origin' or 'same-site'.",
    },
    "Cross-Origin-Embedder-Policy": {
        "check_name": "missing_coep",
        "severity": "info",
        "name": "Cross-Origin-Embedder-Policy Header Missing",
        "description": "The Cross-Origin-Embedder-Policy header is not set. "
                      "Required for SharedArrayBuffer and high-resolution timers.",
        "recommendation": "Set Cross-Origin-Embedder-Policy to 'require-corp' if using advanced features.",
    },
}


def check_security_headers(
    hostname: str,
    port: int = 443,
    timeout: int = 10,
    enabled_headers: Dict[str, bool] = None
) -> List[Dict]:
    """
    Check for missing security headers on a web application.

    Args:
        hostname: Hostname to check
        port: Port number (443 for HTTPS, 80 for HTTP)
        timeout: Request timeout
        enabled_headers: Dict of header_check_name -> enabled (bool)

    Returns:
        List of vulnerability dicts for missing headers
    """
    findings = []

    # Determine protocol based on port
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{hostname}" if port in [80, 443] else f"{protocol}://{hostname}:{port}"

    try:
        response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,  # Allow self-signed for testing
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        # Only check successful responses
        if response.status_code != 200:
            return findings

        response_headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name, header_info in SECURITY_HEADERS.items():
            check_name = header_info["check_name"]

            # Skip if this specific check is disabled
            if enabled_headers and not enabled_headers.get(check_name, True):
                continue

            header_lower = header_name.lower()

            if header_lower not in response_headers:
                findings.append({
                    "type": check_name,
                    "severity": header_info["severity"],
                    "name": header_info["name"],
                    "description": header_info["description"],
                    "url": url,
                    "hostname": hostname,
                    "port": port,
                    "missing_header": header_name,
                    "recommendation": header_info["recommendation"],
                    "evidence": f"Header '{header_name}' not present in response",
                })

    except requests.exceptions.RequestException:
        pass

    return findings


def check_cache_control_missing(hostname: str, port: int = 443, timeout: int = 10) -> Optional[Dict]:
    """
    Check for missing or weak Cache-Control headers on sensitive pages.

    Args:
        hostname: Hostname to check
        port: Port number
        timeout: Request timeout

    Returns:
        Vulnerability dict if cache control is missing/weak, None otherwise
    """
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{hostname}" if port in [80, 443] else f"{protocol}://{hostname}:{port}"

    try:
        response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        if response.status_code != 200:
            return None

        cache_control = response.headers.get("Cache-Control", "").lower()
        pragma = response.headers.get("Pragma", "").lower()

        # Check if caching is properly disabled for the main page
        has_no_store = "no-store" in cache_control
        has_no_cache = "no-cache" in cache_control or "no-cache" in pragma
        has_private = "private" in cache_control

        # If none of these protective measures are present
        if not has_no_store and not has_no_cache and not has_private:
            return {
                "type": "cache_control_missing",
                "severity": "info",
                "name": "Cache-Control Header Missing or Weak",
                "description": f"The server at {hostname} does not set proper Cache-Control headers. "
                              "Sensitive pages may be cached by proxies or browsers.",
                "url": url,
                "hostname": hostname,
                "port": port,
                "cache_control": cache_control if cache_control else None,
                "pragma": pragma if pragma else None,
                "evidence": "No 'no-store', 'no-cache', or 'private' directive found",
                "recommendation": "Set 'Cache-Control: no-store, no-cache, must-revalidate' for sensitive pages.",
            }

    except requests.exceptions.RequestException:
        pass

    return None


# =============================================================================
# Authentication Security Checks
# =============================================================================

def check_login_no_https(hostname: str, timeout: int = 10) -> List[Dict]:
    """
    Check if login forms are served over HTTP (insecure).

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        List of vulnerability findings
    """
    findings = []

    # Common login paths to check
    login_paths = [
        "/login", "/signin", "/sign-in", "/auth", "/authenticate",
        "/admin", "/admin/login", "/wp-login.php", "/user/login",
        "/account/login", "/members/login", "/portal/login",
    ]

    # Check HTTP (insecure)
    for path in login_paths:
        url = f"http://{hostname}{path}"
        try:
            response = _hh_get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": DEFAULT_BROWSER_UA}
            )

            # Check if response contains login form indicators
            if response.status_code == 200:
                content = response.text.lower()
                has_login_form = any([
                    'type="password"' in content,
                    "type='password'" in content,
                    'name="password"' in content,
                    'id="password"' in content,
                    '<form' in content and 'login' in content,
                ])

                if has_login_form:
                    findings.append({
                        "type": "login_no_https",
                        "severity": "high",
                        "name": "Login Form Served Over HTTP",
                        "description": f"A login form at {url} is served over unencrypted HTTP. "
                                      "User credentials can be intercepted by attackers.",
                        "url": url,
                        "hostname": hostname,
                        "path": path,
                        "evidence": "Login form with password field found on HTTP",
                        "recommendation": "Serve all login pages exclusively over HTTPS and redirect HTTP to HTTPS.",
                    })
                    break  # Found one, no need to check more paths

        except requests.exceptions.RequestException:
            pass

    return findings


def check_session_cookies(hostname: str, timeout: int = 10) -> List[Dict]:
    """
    Check session cookies for missing Secure and HttpOnly flags.

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        List of vulnerability findings
    """
    findings = []
    url = f"https://{hostname}/"

    try:
        response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        session_indicators = ['session', 'sess', 'sid', 'token', 'auth', 'jwt', 'phpsessid', 'jsessionid', 'asp.net_sessionid']

        for name, secure, httponly in _cookies_set_by(response):
            if not any(ind in name.lower() for ind in session_indicators):
                continue

            if not secure:
                findings.append({
                    "type": "session_no_secure",
                    "severity": "medium",
                    "name": "Session Cookie Missing Secure Flag",
                    "description": f"The session cookie '{name}' does not have the Secure flag. "
                                  "It can be transmitted over unencrypted HTTP connections.",
                    "url": url,
                    "hostname": hostname,
                    "cookie_name": name,
                    "evidence": f"Cookie '{name}' missing Secure attribute",
                    "recommendation": "Add the Secure flag to all session cookies.",
                })

            if not httponly:
                findings.append({
                    "type": "session_no_httponly",
                    "severity": "medium",
                    "name": "Session Cookie Missing HttpOnly Flag",
                    "description": f"The session cookie '{name}' does not have the HttpOnly flag. "
                                  "It can be accessed by JavaScript, enabling XSS-based session theft.",
                    "url": url,
                    "hostname": hostname,
                    "cookie_name": name,
                    "evidence": f"Cookie '{name}' missing HttpOnly attribute",
                    "recommendation": "Add the HttpOnly flag to all session cookies.",
                })

    except requests.exceptions.RequestException:
        pass

    return findings


def _set_cookie_lines(response) -> List[str]:
    """Each Set-Cookie header of one response, unmerged.

    requests folds repeated Set-Cookie headers into one comma-joined value, so
    a flag on one cookie looks like a flag on all of them. urllib3 still holds
    them apart; the comma split is only a fallback, and stops before a comma
    inside an Expires date ("Wed, 21 Oct 2015").
    """
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    getlist = getattr(raw_headers, "getlist", None)
    if callable(getlist):
        try:
            lines = getlist("Set-Cookie")
        except Exception:  # noqa: BLE001 - fall back to the merged header
            lines = None
        if isinstance(lines, list) and all(isinstance(v, str) for v in lines):
            return lines
    merged = (response.headers or {}).get("Set-Cookie") or ""
    if not isinstance(merged, str) or not merged:
        return []
    return [part for part in re.split(r",\s*(?=[^;,=\s]+=)", merged) if part.strip()]


def _cookie_is_cleared(attrs: Dict[str, str]) -> bool:
    """A Set-Cookie that deletes the cookie (Max-Age <= 0 or an Expires in the
    past) leaves the browser nothing to steal; the cookie jar drops it too."""
    max_age = attrs.get("max-age")
    if max_age is not None:
        try:
            return int(max_age) <= 0
        except ValueError:
            pass
    expires = attrs.get("expires")
    if expires:
        try:
            when = parsedate_to_datetime(expires)
        except (TypeError, ValueError, IndexError):
            return False
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when <= datetime.now(timezone.utc)
    return False


def _cookies_set_by(response) -> List[Tuple[str, bool, bool]]:
    """(name, secure, httponly) for every cookie the response chain leaves set.

    Redirect hops count: a session cookie issued on a 302 is as exposed as one
    on the final page. A cookie set twice is judged as the browser keeps it,
    by its last Set-Cookie.
    """
    final: Dict[str, Tuple[str, bool, bool]] = {}
    for hop in list(getattr(response, "history", None) or []) + [response]:
        for line in _set_cookie_lines(hop):
            parts = line.split(";")
            name, sep, _value = parts[0].partition("=")
            name = name.strip()
            if not sep or not name:
                continue
            attrs: Dict[str, str] = {}
            for attr in parts[1:]:
                key, _, val = attr.strip().partition("=")
                attrs[key.strip().lower()] = val.strip()
            if _cookie_is_cleared(attrs):
                final.pop(name, None)
                continue
            final[name] = (name, "secure" in attrs, "httponly" in attrs)
    return list(final.values())


def check_basic_auth_no_tls(hostname: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if Basic Authentication is used over HTTP (insecure).

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        Vulnerability dict if found, None otherwise
    """
    url = f"http://{hostname}/"

    try:
        response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        # Check for WWW-Authenticate header with Basic auth
        www_auth = response.headers.get('WWW-Authenticate', '')
        if 'basic' in www_auth.lower():
            return {
                "type": "basic_auth_no_tls",
                "severity": "high",
                "name": "Basic Authentication Over HTTP",
                "description": f"The server at {hostname} uses Basic Authentication over unencrypted HTTP. "
                              "Credentials are sent in base64 encoding which can be easily decoded.",
                "url": url,
                "hostname": hostname,
                "www_authenticate": www_auth,
                "evidence": f"WWW-Authenticate: {www_auth}",
                "recommendation": "Use Basic Authentication only over HTTPS, or switch to a more secure authentication method.",
            }

    except requests.exceptions.RequestException:
        pass

    return None


def run_auth_checks(
    hostnames: List[str],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run all enabled authentication security checks.

    Args:
        hostnames: List of hostnames to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_host(hostname: str) -> List[Dict]:
        if _host_down(hostname):
            return []
        host_findings = []

        if enabled_checks.get("login_no_https", True):
            results = check_login_no_https(hostname, timeout=timeout)
            host_findings.extend(results)

        if enabled_checks.get("session_no_secure", True) or enabled_checks.get("session_no_httponly", True):
            results = check_session_cookies(hostname, timeout=timeout)
            # Filter based on which checks are enabled
            for finding in results:
                if finding["type"] == "session_no_secure" and enabled_checks.get("session_no_secure", True):
                    host_findings.append(finding)
                elif finding["type"] == "session_no_httponly" and enabled_checks.get("session_no_httponly", True):
                    host_findings.append(finding)

        if enabled_checks.get("basic_auth_no_tls", True):
            result = check_basic_auth_no_tls(hostname, timeout=timeout)
            if result:
                host_findings.append(result)

        return host_findings

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# DNS Security Checks
# =============================================================================

import dns.resolver
import dns.zone
import dns.query
import dns.xfr

#: The org-level checks, one finding type each; their findings name only the org.
DNS_CHECK_TYPES = ("spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer")


class CheckUnknown(Exception):
    """A check that reached no verdict: the resolver or the service did not
    answer (a timeout, a reset, a SERVFAIL). It is neither a finding nor
    clean, so the finding an earlier run reported must survive the prune."""


def _note_check_outcome(check_type: str, host: str, no_verdict: str = "") -> None:
    """Record one check on one host for the positive-coverage prune (D1).

    A verdict (a finding or clean) marks ``host`` checked for ``check_type``
    alone, so the prune may delete that type's stale finding there and
    nowhere else. No verdict still records the type, with no host: its
    finding on ``host`` is kept instead of falling back to the source-level
    rule, and a coverage gap says why.
    """
    from recon.helpers import circuit_breaker as cb
    cb.note_checked("security_check", hosts=[] if no_verdict else [host],
                    checks=[check_type], module="security_checks")
    if no_verdict:
        print(f"[!][SecurityCheck] {check_type} on {host}: no verdict ({no_verdict}); "
              f"its earlier finding is kept")
        cb.note_degraded("security_checks", entries=[{
            "source": "security_check",
            "reason": f"{check_type} on {host} not checked: {no_verdict}",
            "skipped": 1,
        }])


def _no_answer(exc: BaseException) -> CheckUnknown:
    return CheckUnknown(type(exc).__name__)


def check_spf_missing(domain: str) -> Optional[Dict]:
    """
    Check if SPF record is missing for email security.

    Args:
        domain: Domain to check

    Returns:
        Vulnerability dict if SPF is missing, None otherwise

    Raises:
        CheckUnknown: the resolver gave no answer (NXDOMAIN and NoAnswer are answers)
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata).strip('"')
            if txt_record.startswith('v=spf1'):
                return None  # SPF exists

        # No SPF record found
        return {
            "type": "spf_missing",
            "severity": "medium",
            "name": "SPF Record Missing",
            "description": f"The domain {domain} does not have an SPF record. "
                          "This allows attackers to send spoofed emails appearing to come from this domain.",
            "domain": domain,
            "evidence": "No TXT record starting with 'v=spf1' found",
            "recommendation": "Add an SPF record to specify which mail servers can send email for your domain.",
        }

    except dns.resolver.NXDOMAIN:
        return None  # Domain doesn't exist
    except dns.resolver.NoAnswer:
        return {
            "type": "spf_missing",
            "severity": "medium",
            "name": "SPF Record Missing",
            "description": f"The domain {domain} does not have an SPF record.",
            "domain": domain,
            "evidence": "No TXT records found",
            "recommendation": "Add an SPF record to specify which mail servers can send email for your domain.",
        }
    except Exception as exc:  # noqa: BLE001 - a timeout or SERVFAIL is not "record present"
        raise _no_answer(exc) from exc


def check_dmarc_missing(domain: str) -> Optional[Dict]:
    """
    Check if DMARC record is missing for email security.

    Args:
        domain: Domain to check

    Returns:
        Vulnerability dict if DMARC is missing, None otherwise

    Raises:
        CheckUnknown: the resolver gave no answer (NXDOMAIN and NoAnswer are answers)
    """
    dmarc_domain = f"_dmarc.{domain}"

    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata).strip('"')
            if txt_record.startswith('v=DMARC1'):
                return None  # DMARC exists

        return {
            "type": "dmarc_missing",
            "severity": "medium",
            "name": "DMARC Record Missing",
            "description": f"The domain {domain} does not have a DMARC record. "
                          "Without DMARC, receiving mail servers cannot verify email authenticity.",
            "domain": domain,
            "evidence": f"No TXT record at _dmarc.{domain} starting with 'v=DMARC1'",
            "recommendation": "Add a DMARC record to define your email authentication policy.",
        }

    except dns.resolver.NXDOMAIN:
        return {
            "type": "dmarc_missing",
            "severity": "medium",
            "name": "DMARC Record Missing",
            "description": f"The domain {domain} does not have a DMARC record.",
            "domain": domain,
            "evidence": f"_dmarc.{domain} does not exist",
            "recommendation": "Add a DMARC record to define your email authentication policy.",
        }
    except dns.resolver.NoAnswer:
        return {
            "type": "dmarc_missing",
            "severity": "medium",
            "name": "DMARC Record Missing",
            "description": f"The domain {domain} does not have a DMARC record.",
            "domain": domain,
            "evidence": f"No TXT records at _dmarc.{domain}",
            "recommendation": "Add a DMARC record to define your email authentication policy.",
        }
    except Exception as exc:  # noqa: BLE001 - a timeout or SERVFAIL is not "record present"
        raise _no_answer(exc) from exc


def check_dnssec_missing(domain: str) -> Optional[Dict]:
    """
    Check if DNSSEC is not enabled for the domain.

    Args:
        domain: Domain to check

    Returns:
        Vulnerability dict if DNSSEC is missing, None otherwise

    Raises:
        CheckUnknown: the resolver gave no answer (NXDOMAIN and NoAnswer are answers)
    """
    try:
        # Try to get DNSKEY records - their presence indicates DNSSEC
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        if answers:
            return None  # DNSSEC is enabled

    except dns.resolver.NoAnswer:
        return {
            "type": "dnssec_missing",
            "severity": "low",
            "name": "DNSSEC Not Enabled",
            "description": f"The domain {domain} does not have DNSSEC enabled. "
                          "DNS responses are not cryptographically signed, allowing DNS spoofing attacks.",
            "domain": domain,
            "evidence": "No DNSKEY records found",
            "recommendation": "Enable DNSSEC to cryptographically sign DNS records.",
        }
    except dns.resolver.NXDOMAIN:
        return None
    except Exception as exc:  # noqa: BLE001 - a timeout or SERVFAIL is not "signed"
        raise _no_answer(exc) from exc

    return None


def _nameserver_addresses(ns_host: str) -> Tuple[List[str], bool]:
    """A nameserver's A and AAAA addresses, and whether a lookup gave no
    answer. A name with neither record has none, which is an answer."""
    addresses: List[str] = []
    failed = False
    for rtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(ns_host, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:  # noqa: BLE001 - a timeout or SERVFAIL
            failed = True
            continue
        for rdata in answers:
            try:
                addresses.append(ipaddress.ip_address(str(rdata).strip()).compressed)
            except ValueError:
                continue
    return addresses, failed


def check_zone_transfer(domain: str, timeout: int = 10,
                        roe_excluded_hosts: Optional[List[str]] = None) -> Optional[Dict]:
    """
    Check if DNS zone transfer (AXFR) is enabled.

    The transfer is asked of each nameserver's addresses, one at a time with
    the check's timeout: dnspython's xfr takes an IP, and given a name it
    raises before sending anything. A nameserver name or address the RoE
    excludes is never asked (an excluded name is not even resolved).

    Args:
        domain: Domain to check
        timeout: Query timeout
        roe_excluded_hosts: ROE_EXCLUDED_HOSTS when RoE is on

    Returns:
        Vulnerability dict if a nameserver allows the transfer, None when
        every address refused it or the domain has no nameserver

    Raises:
        CheckUnknown: no transfer succeeded and some nameserver gave no
            answer, or was not asked because of the RoE
    """
    from recon.helpers.roe_scope import _is_roe_excluded
    excluded = [h for h in (roe_excluded_hosts or ()) if isinstance(h, str) and h.strip()]
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception as exc:  # noqa: BLE001 - a timeout or SERVFAIL is not "no nameserver"
        raise _no_answer(exc) from exc

    unchecked: List[str] = []
    asked: Set[str] = set()
    for ns in ns_answers:
        ns_host = str(ns.target).rstrip('.').lower()
        if excluded and _is_roe_excluded(ns_host, excluded):
            unchecked.append(f"{ns_host} RoE excluded")
            continue
        addresses, failed = _nameserver_addresses(ns_host)
        if failed:
            unchecked.append(f"{ns_host} not resolved")
        for address in addresses:
            if address in asked:
                continue
            asked.add(address)
            if excluded and _is_roe_excluded(address, excluded):
                unchecked.append(f"{address} RoE excluded")
                continue
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(address, domain, timeout=timeout, lifetime=timeout))
            except (dns.xfr.TransferError, ConnectionRefusedError):
                continue
            except Exception as exc:  # noqa: BLE001 - a timeout or a reset is no answer
                unchecked.append(f"{address} {type(exc).__name__}")
                continue
            record_count = len(zone.nodes)
            return {
                "type": "zone_transfer",
                "severity": "high",
                "name": "DNS Zone Transfer Enabled",
                "description": f"The nameserver {ns_host} allows zone transfers for {domain}. "
                              f"An attacker can download all DNS records ({record_count} records found).",
                "domain": domain,
                "nameserver": ns_host,
                "record_count": record_count,
                "evidence": f"AXFR query to {ns_host} ({address}) succeeded",
                "recommendation": "Restrict zone transfers to authorized secondary nameservers only.",
            }

    if unchecked:
        raise CheckUnknown("; ".join(unchecked[:3]))
    return None


def run_dns_checks(
    domain: str,
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    roe_excluded_hosts: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Run all enabled DNS security checks.

    Each check ends in a finding, clean, or no verdict (CheckUnknown). The
    org is recorded as checked only for the checks that reached a verdict,
    so a lookup that timed out keeps that check's earlier finding instead of
    reading as "record present".

    Args:
        domain: Domain to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Query timeout
        roe_excluded_hosts: the nameservers the zone transfer must not ask;
            the run's RoE list (set by run_security_checks) when None

    Returns:
        List of vulnerability findings
    """
    excluded = _ROE_EXCLUDED if roe_excluded_hosts is None else roe_excluded_hosts
    findings = []
    checks = (
        ("spf_missing", lambda: check_spf_missing(domain)),
        ("dmarc_missing", lambda: check_dmarc_missing(domain)),
        ("dnssec_missing", lambda: check_dnssec_missing(domain)),
        ("zone_transfer", lambda: check_zone_transfer(domain, timeout=timeout,
                                                       roe_excluded_hosts=excluded)),
    )
    for check_type, check in checks:
        if not enabled_checks.get(check_type, True):
            continue
        try:
            result = check()
        except CheckUnknown as exc:
            _note_check_outcome(check_type, domain, str(exc) or "no answer")
            continue
        _note_check_outcome(check_type, domain)
        if result:
            findings.append(result)

    return findings


# =============================================================================
# Port/Service Security Checks
# =============================================================================

# Sensitive ports to check
ADMIN_PORTS = {
    22: ("SSH", "Remote shell access"),
    23: ("Telnet", "Unencrypted remote access"),
    3389: ("RDP", "Remote Desktop"),
    5900: ("VNC", "Virtual Network Computing"),
    5901: ("VNC", "Virtual Network Computing"),
}

DATABASE_PORTS = {
    3306: ("MySQL", "MySQL Database"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    27017: ("MongoDB", "MongoDB Database"),
    27018: ("MongoDB", "MongoDB Database"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle Database"),
    6379: ("Redis", "Redis Cache/Database"),
    9200: ("Elasticsearch", "Elasticsearch"),
    9300: ("Elasticsearch", "Elasticsearch Transport"),
}


def check_admin_ports_exposed(ip: str, open_ports: List[int], timeout: int = 5) -> List[Dict]:
    """
    Check if administrative ports are exposed publicly.

    Args:
        ip: IP address to check
        open_ports: List of open ports from port scan
        timeout: Connection timeout

    Returns:
        List of vulnerability findings
    """
    findings = []

    for port in open_ports:
        if port in ADMIN_PORTS:
            service_name, description = ADMIN_PORTS[port]
            findings.append({
                "type": "admin_port_exposed",
                "severity": "medium",
                "name": f"{service_name} Port Exposed",
                "description": f"{description} port {port} is publicly accessible on {ip}. "
                              "Administrative services should not be directly exposed to the internet.",
                "ip": ip,
                "port": port,
                "service": service_name,
                "evidence": f"Port {port} ({service_name}) is open",
                "recommendation": f"Restrict access to {service_name} using firewall rules or VPN.",
            })

    return findings


def check_database_ports_exposed(ip: str, open_ports: List[int], timeout: int = 5) -> List[Dict]:
    """
    Check if database ports are exposed publicly.

    Args:
        ip: IP address to check
        open_ports: List of open ports from port scan
        timeout: Connection timeout

    Returns:
        List of vulnerability findings
    """
    findings = []

    for port in open_ports:
        if port in DATABASE_PORTS:
            service_name, description = DATABASE_PORTS[port]
            severity = "high" if port != 6379 else "medium"  # Redis handled separately
            findings.append({
                "type": "database_exposed",
                "severity": severity,
                "name": f"{service_name} Port Exposed",
                "description": f"{description} port {port} is publicly accessible on {ip}. "
                              "Database services should never be directly exposed to the internet.",
                "ip": ip,
                "port": port,
                "service": service_name,
                "evidence": f"Port {port} ({service_name}) is open",
                "recommendation": f"Move {service_name} behind a firewall. Only allow access from application servers.",
            })

    return findings


def check_redis_no_auth(ip: str, port: int = 6379, timeout: int = 5) -> Optional[Dict]:
    """
    Check if Redis is accessible without authentication.

    Args:
        ip: IP address to check
        port: Redis port
        timeout: Connection timeout

    Returns:
        Vulnerability dict if Redis has no auth, None when the port is closed
        or Redis refuses the command

    Raises:
        CheckUnknown: no answer (a timeout, a reset, an empty reply)
    """
    try:
        # create_connection, not an AF_INET socket: it also reaches IPv6.
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return None
    except Exception as exc:  # noqa: BLE001 - unreachable now is not "closed"
        raise _no_answer(exc) from exc
    try:
        sock.send(b"PING\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
    except Exception as exc:  # noqa: BLE001
        raise _no_answer(exc) from exc
    finally:
        sock.close()

    if "+PONG" in response:
        return {
            "type": "redis_no_auth",
            "severity": "critical",
            "name": "Redis Without Authentication",
            "description": f"Redis at {ip}:{port} responds to commands without authentication. "
                          "An attacker can read/write data, execute Lua scripts, or potentially get shell access.",
            "ip": ip,
            "port": port,
            "evidence": "PING command returned PONG without authentication",
            "recommendation": "Enable Redis AUTH and use strong passwords. Never expose Redis to the internet.",
        }
    if not response.strip():
        raise CheckUnknown("no reply")
    return None


KUBERNETES_API_PORTS = (6443, 8443, 443)

# What GET /api (or a sibling discovery path) returns from a kube-apiserver:
# the document kind and the list field that kind always carries.
_K8S_DISCOVERY_KINDS = {
    "APIVersions": "versions",
    "APIGroupList": "groups",
    "APIResourceList": "resources",
}


def _is_kubernetes_api_response(status: int, body: str) -> bool:
    """True only for a kube-apiserver document, not a page that mentions it.

    200: a discovery document (APIVersions with its `versions` list, ...).
    401/403: the API's own Status object, `{"kind": "Status", "apiVersion":
    "v1", "status": "Failure", "code": <the HTTP status>}`.
    """
    try:
        doc = json.loads(body or "")
    except (TypeError, ValueError):
        return False
    if not isinstance(doc, dict):
        return False
    kind = doc.get("kind")
    if status == 200:
        field = _K8S_DISCOVERY_KINDS.get(kind)
        return bool(field) and isinstance(doc.get(field), list)
    if status in (401, 403):
        return (kind == "Status" and doc.get("apiVersion") == "v1"
                and doc.get("status") == "Failure" and doc.get("code") == status)
    return False


def check_kubernetes_api_exposed(ip: str, timeout: int = 10,
                                 ports: Optional[List[int]] = None) -> Optional[Dict]:
    """
    Check if Kubernetes API is publicly exposed.

    Args:
        ip: IP address to check
        timeout: Request timeout
        ports: Ports to probe; defaults to KUBERNETES_API_PORTS. The port-scan
            caller passes only the ones the scan found open.

    Returns:
        Vulnerability dict if K8s API is exposed, None otherwise
    """
    k8s_ports = list(KUBERNETES_API_PORTS) if ports is None else list(ports)

    for port in k8s_ports:
        url = f"https://{_url_host(ip)}:{port}/api"
        try:
            # A redirect lands on whatever page the server points at (a login
            # portal, a marketing site): only /api's own answer is evidence.
            response = _hh_get(
                url,
                timeout=timeout,
                allow_redirects=False,
                verify=False,
                headers={"User-Agent": DEFAULT_BROWSER_UA}
            )

            if response.status_code in [200, 401, 403]:
                if _is_kubernetes_api_response(response.status_code, response.text):
                    severity = "critical" if response.status_code == 200 else "high"
                    return {
                        "type": "kubernetes_api_exposed",
                        "severity": severity,
                        "name": "Kubernetes API Exposed",
                        "description": f"Kubernetes API is accessible at {ip}:{port}. "
                                      "This could allow attackers to control the entire cluster.",
                        "ip": ip,
                        "port": port,
                        "url": url,
                        "status_code": response.status_code,
                        "evidence": f"Kubernetes API responded with status {response.status_code}",
                        "recommendation": "Restrict Kubernetes API access using network policies and authentication.",
                    }

        except requests.exceptions.RequestException:
            pass

    return None


#: A greeting or an EHLO answer is a few hundred bytes; past this the peer is
#: not answering one command, and the read stops with no verdict.
_SMTP_REPLY_CAP = 64 * 1024
_SMTP_REPLY_LINE = re.compile(r"^(\d{3})([ -]|$)")


class _SmtpReplies:
    """Reads one complete SMTP reply at a time (RFC 5321 4.2).

    A reply is ``NNN-`` continuation lines ending in one ``NNN `` line, and
    TCP may split it anywhere or join it to the next, so bytes past a reply's
    end stay buffered for the next one. ``timeout`` bounds a whole reply, not
    each recv(), so a server dripping continuation lines still ends it.
    """

    def __init__(self, sock, timeout: float):
        self.sock = sock
        self.timeout = timeout
        self.buffer = b""

    def next(self) -> Tuple[str, str]:
        """(final code, text); ("", line) when a line is not an SMTP reply line.

        Raises CheckUnknown when the reply never completes (closed, too long,
        out of time); a socket error propagates as it is.
        """
        deadline = time.monotonic() + self.timeout
        lines: List[str] = []
        size = 0
        while True:
            while b"\n" not in self.buffer:
                if size + len(self.buffer) > _SMTP_REPLY_CAP:
                    raise CheckUnknown("SMTP reply too long")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CheckUnknown("SMTP reply incomplete")
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise CheckUnknown("connection closed mid-reply"
                                       if lines or self.buffer else "no reply")
                self.buffer += chunk
            raw, _, self.buffer = self.buffer.partition(b"\n")
            size += len(raw) + 1
            line = raw.rstrip(b"\r").decode("utf-8", errors="ignore")
            match = _SMTP_REPLY_LINE.match(line)
            if not match:
                return "", line
            lines.append(line)
            if match.group(2) != "-":
                return match.group(1), "\n".join(lines)


def check_smtp_open_relay(ip: str, port: int = 25, timeout: int = 10) -> Optional[Dict]:
    """
    Check if SMTP server is an open relay.

    Args:
        ip: IP address to check
        port: SMTP port
        timeout: Connection timeout

    Returns:
        Vulnerability dict if open relay, None when the port is closed, the
        server refuses the relay (a 5xx), or its greeting is not SMTP at all

    Raises:
        CheckUnknown: no answer (a timeout, a reset, a closed connection, a
            reply cut short), a 4xx reply (busy, greylisting, try again
            later), or a reply mid-dialogue that is not an SMTP reply
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return None
    except Exception as exc:  # noqa: BLE001 - unreachable now is not "closed"
        raise _no_answer(exc) from exc

    replies = _SmtpReplies(sock, timeout)

    def ask(command: bytes) -> str:
        sock.sendall(command)
        return replies.next()[0]

    def refused(code: str) -> None:
        """Return when ``code`` is a final no; raise when it is no answer."""
        if not code:
            raise CheckUnknown("not an SMTP reply")
        if code.startswith("4"):
            raise CheckUnknown(f"SMTP reply {code}")

    def quit_politely() -> None:
        try:
            sock.sendall(b"QUIT\r\n")
        except OSError:
            pass

    try:
        code, _ = replies.next()
        if code != "220":
            # A banner that is no SMTP line is another service on the port:
            # it relays nothing, as before. Only a 4xx greeting is "later".
            if code:
                refused(code)
            return None
        code = ask(b"HELO test.example.com\r\n")
        if code.startswith("2"):
            code = ask(b"MAIL FROM:<test@external-domain.com>\r\n")
            if code == "250":
                code = ask(b"RCPT TO:<test@another-external-domain.com>\r\n")
                if code in ("250", "251"):
                    quit_politely()
                    return {
                        "type": "smtp_open_relay",
                        "severity": "high",
                        "name": "SMTP Open Relay",
                        "description": f"SMTP server at {ip}:{port} accepts mail relay from external sources. "
                                      "This can be abused for spam campaigns and email spoofing.",
                        "ip": ip,
                        "port": port,
                        "evidence": "Server accepted RCPT TO for external domain",
                        "recommendation": "Configure SMTP to only relay mail for authenticated users or authorized domains.",
                    }
        refused(code)
        quit_politely()
        return None
    except CheckUnknown:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _no_answer(exc) from exc
    finally:
        sock.close()


def _port_number(value) -> Optional[int]:
    """A port from an int, a numeric string or a port_details {"port": n} entry."""
    if isinstance(value, dict):
        value = value.get("port")
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _open_ports_by_ip(port_scan: Dict[str, Any]) -> Dict[str, Tuple[List[int], Dict[str, Any]]]:
    """{ip: (sorted open ports, its by_ip entry)} from the port scan section.

    Both the full pipeline and partial recon put one entry per IP under
    port_scan["by_ip"] - {"ip", "hostnames", "ports": [int], "port_details",
    "cdn", "is_cdn"} - and every listed port is open. A top-level
    {ip: {port: {"state": "open"}}} map is read as well, but only under a key
    that is an IP literal, so the section names (scan_metadata, by_host, ...)
    are never taken for hosts.
    """
    found: Dict[str, Tuple[Set[int], Dict[str, Any]]] = {}
    by_ip = port_scan.get("by_ip")
    if isinstance(by_ip, dict):
        for key, entry in by_ip.items():
            if not isinstance(entry, dict):
                continue
            ip = str(entry.get("ip") or key)
            ports = found.setdefault(ip, (set(), entry))[0]
            for value in list(entry.get("ports") or []) + list(entry.get("port_details") or []):
                port = _port_number(value)
                if port:
                    ports.add(port)
    for key, ports_data in port_scan.items():
        if not (isinstance(ports_data, dict) and _looks_like_ip(key)):
            continue
        ports = found.setdefault(key, (set(), {}))[0]
        for port_str, port_info in ports_data.items():
            if isinstance(port_info, dict) and port_info.get("state") == "open":
                port = _port_number(port_str)
                if port:
                    ports.add(port)
    return {ip: (sorted(ports), entry) for ip, (ports, entry) in found.items() if ports}


#: The port checks that send a probe, and the port each one needs open. The
#: others read the port scan alone, so they always reach a verdict.
_PROBED_PORT_CHECKS = {"redis_no_auth": 6379, "smtp_open_relay": 25}


def _probed_port_check(check_type: str, ip: str, open_ports: List[int], probe) -> Optional[Dict]:
    """One service probe on one IP under the three outcomes (R-24).

    A port the scan did not find open is a verdict, as it always was: clean.
    No verdict leaves ``ip`` unchecked for ``check_type``, so its earlier
    finding is kept.
    """
    if _PROBED_PORT_CHECKS[check_type] not in open_ports:
        _note_check_outcome(check_type, ip)
        return None
    try:
        result = probe()
    except CheckUnknown as exc:
        _note_check_outcome(check_type, ip, str(exc) or "no answer")
        return None
    _note_check_outcome(check_type, ip)
    return result


def run_port_service_checks(
    recon_data: Dict[str, Any],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10,
    cdn_ips: Optional[Set[str]] = None,
    roe_excluded_hosts: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Run all enabled port/service security checks.

    Args:
        recon_data: Reconnaissance data with port scan results
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Connection timeout
        max_workers: Maximum concurrent workers
        cdn_ips: IPs already classified as CDN edge (the direct-IP prefilter)
        roe_excluded_hosts: The RoE exclusion list when RoE is on

    Returns:
        List of vulnerability findings
    """
    findings = []

    # The probed checks are tracked per IP from here on: an IP this run does
    # not reach (no port data, a CDN edge, RoE, a host down) keeps its
    # findings rather than reading as clean.
    probed = [c for c in _PROBED_PORT_CHECKS if enabled_checks.get(c, True)]
    if probed:
        from recon.helpers import circuit_breaker as _cb
        _cb.note_checked("security_check", checks=probed, module="security_checks")

    port_scan = recon_data.get("port_scan") or {}
    if not isinstance(port_scan, dict):
        return findings

    # A CDN edge's open ports are the CDN's, not the target's. Same rule as the
    # direct-IP checks: a reliable edge name or a CDN ASN, never a generic cloud
    # label ("aws" also marks EC2/ALB origins, whose ports ARE the target's).
    edge_ips: Set[str] = set(cdn_ips or ())
    try:
        edge_ips |= collect_reliable_edge_ips(recon_data)
        edge_ips |= collect_asn_cdn_ips(recon_data)
    except Exception as exc:  # noqa: BLE001 - same fallback as the direct-IP prefilter
        print(f"[!][SecurityCheck] CDN prefilter failed for port checks: {exc}")

    from recon.helpers.roe_scope import _is_roe_excluded

    ips_to_check = []
    for ip, (open_ports, _entry) in _open_ports_by_ip(port_scan).items():
        if ip in edge_ips:
            continue
        if roe_excluded_hosts and _is_roe_excluded(ip, roe_excluded_hosts):
            continue
        ips_to_check.append((ip, open_ports))

    def check_single_ip(ip: str, open_ports: List[int]) -> List[Dict]:
        if _host_down(ip):
            return []
        ip_findings = []

        if enabled_checks.get("admin_port_exposed", True):
            results = check_admin_ports_exposed(ip, open_ports, timeout)
            ip_findings.extend(results)

        if enabled_checks.get("database_exposed", True):
            results = check_database_ports_exposed(ip, open_ports, timeout)
            ip_findings.extend(results)

        if enabled_checks.get("redis_no_auth", True):
            result = _probed_port_check("redis_no_auth", ip, open_ports,
                                        lambda: check_redis_no_auth(ip, timeout=timeout))
            if result:
                ip_findings.append(result)

        k8s_ports = [p for p in KUBERNETES_API_PORTS if p in open_ports]
        if enabled_checks.get("kubernetes_api_exposed", True) and k8s_ports:
            result = check_kubernetes_api_exposed(ip, timeout=timeout, ports=k8s_ports)
            if result:
                ip_findings.append(result)

        if enabled_checks.get("smtp_open_relay", True):
            result = _probed_port_check("smtp_open_relay", ip, open_ports,
                                        lambda: check_smtp_open_relay(ip, timeout=timeout))
            if result:
                ip_findings.append(result)

        return ip_findings

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(check_single_ip, ip, ports): ip for ip, ports in ips_to_check}
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                ip_findings = future.result()
                findings.extend(ip_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# Application Security Checks
# =============================================================================

def check_csp_unsafe_inline(hostname: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if CSP header allows unsafe-inline (weakens XSS protection).

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        Vulnerability dict if unsafe-inline found, None otherwise
    """
    url = f"https://{hostname}/"

    try:
        response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        csp = response.headers.get('Content-Security-Policy', '')

        if csp and "'unsafe-inline'" in csp.lower():
            # Check which directives have unsafe-inline
            unsafe_directives = []
            for directive in csp.split(';'):
                directive = directive.strip()
                if "'unsafe-inline'" in directive.lower():
                    unsafe_directives.append(directive.split()[0] if directive.split() else directive)

            return {
                "type": "csp_unsafe_inline",
                "severity": "medium",
                "name": "CSP Allows Unsafe Inline",
                "description": f"The Content-Security-Policy for {hostname} allows 'unsafe-inline'. "
                              "This weakens XSS protection by allowing inline scripts/styles.",
                "url": url,
                "hostname": hostname,
                "csp_header": csp[:500],  # Truncate if very long
                "unsafe_directives": unsafe_directives,
                "evidence": f"'unsafe-inline' found in: {', '.join(unsafe_directives)}",
                "recommendation": "Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
            }

    except requests.exceptions.RequestException:
        pass

    return None


def check_insecure_form_action(hostname: str, timeout: int = 10) -> List[Dict]:
    """
    Check if HTTPS pages have forms that post to HTTP endpoints.

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        List of vulnerability findings
    """
    import re
    findings = []
    url = f"https://{hostname}/"

    try:
        response = _hh_get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": DEFAULT_BROWSER_UA}
        )

        if response.status_code == 200:
            content = response.text

            # Find form actions pointing to HTTP
            form_pattern = r'<form[^>]*action\s*=\s*["\']?(http://[^"\'>\s]+)["\']?'
            matches = re.findall(form_pattern, content, re.IGNORECASE)

            for http_action in matches:
                findings.append({
                    "type": "insecure_form_action",
                    "severity": "high",
                    "name": "HTTPS Form Posts to HTTP",
                    "description": f"A form on {url} posts data to an unencrypted HTTP endpoint: {http_action}. "
                                  "Form data including credentials may be intercepted.",
                    "url": url,
                    "hostname": hostname,
                    "insecure_action": http_action,
                    "evidence": f"Form action points to {http_action}",
                    "recommendation": "Ensure all form actions use HTTPS endpoints.",
                })

    except requests.exceptions.RequestException:
        pass

    return findings


def run_app_security_checks(
    hostnames: List[str],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run all enabled application security checks.

    Args:
        hostnames: List of hostnames to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_host(hostname: str) -> List[Dict]:
        if _host_down(hostname):
            return []
        host_findings = []

        if enabled_checks.get("csp_unsafe_inline", True):
            result = check_csp_unsafe_inline(hostname, timeout=timeout)
            if result:
                host_findings.append(result)

        if enabled_checks.get("insecure_form_action", True):
            results = check_insecure_form_action(hostname, timeout=timeout)
            host_findings.extend(results)

        return host_findings

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# Rate Limiting Checks
# =============================================================================

# Throttling wording, matched as words: separate "rate" and "limit" substrings
# are on any page that says "generate" and "unlimited".
_RATE_LIMIT_TEXT = re.compile(
    r"\brate[\s_-]?limit|too many requests|too many (?:\w+ )?attempts", re.IGNORECASE)


def _login_attempt_processed(status: int) -> bool:
    """True when the answer shows the endpoint evaluated the credentials.

    2xx/3xx: it rendered a page or redirected after the attempt; 401: it
    rejected the credentials. Nothing else is evidence of an attempt being
    processed: 404/405/410/501 mean no such endpoint or method, 400/422 a
    request refused before any credential check (malformed body, missing CSRF
    token), 403 a WAF or CSRF block, 5xx a server failure, 429 throttling.
    """
    return 200 <= status < 400 or status == 401


def check_no_rate_limiting(urls: List[str], hostname: str, timeout: int = 5) -> List[Dict]:
    """
    Check if rate limiting is missing on login/auth endpoints.

    Args:
        urls: List of URLs discovered from recon (e.g., from resource_enum)
        hostname: Hostname being checked
        timeout: Request timeout per request

    Returns:
        List of vulnerability findings for endpoints without rate limiting
    """
    findings = []

    # Login-like URLs of exactly this host (a subdomain's URLs are its own
    # host's pass), by the words of the PATH: a host named auth.* or a ?token=
    # query says nothing about the page.
    auth_urls = set()
    host = (hostname or "").lower()
    for url in urls:
        try:
            parsed = urlparse(url)
            # .hostname, not netloc: "app.example.com:8443" is still this host.
            url_host = parsed.hostname or ""
            if url_host == host and _is_login_path(parsed.path) and not _never_request(url):
                # Normalize to base URL without query params for rate limit test
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                auth_urls.add(base_url)
        except Exception:
            pass

    # Fallback: also check common endpoints if no auth URLs found from recon
    if not auth_urls:
        fallback_endpoints = [
            "/login", "/signin", "/sign-in", "/auth", "/authenticate",
            "/admin/login", "/wp-login.php", "/user/login", "/api/login",
            "/api/auth", "/api/v1/login", "/oauth/token"
        ]
        for endpoint in fallback_endpoints:
            auth_urls.add(f"https://{hostname}{endpoint}")

    # Test each auth URL for rate limiting
    tested_urls = set()  # Avoid testing same URL twice

    for url in auth_urls:
        if url in tested_urls:
            continue
        tested_urls.add(url)

        try:
            parsed = urlparse(url)
            endpoint = parsed.path

            # First check if endpoint exists
            response = _hh_get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": DEFAULT_BROWSER_UA}
            )

            # Skip if endpoint doesn't exist
            if response.status_code == 404:
                continue

            # Send multiple rapid requests (10 requests)
            success_count = 0
            rate_limit_detected = False

            for i in range(10):
                try:
                    resp = _hh_post(
                        url,
                        timeout=timeout,
                        verify=False,
                        data={"username": f"test{i}", "password": "test"},
                        headers={"User-Agent": DEFAULT_BROWSER_UA}
                    )

                    # Check for rate limiting indicators
                    if resp.status_code == 429:  # Too Many Requests
                        rate_limit_detected = True
                        break
                    if _RATE_LIMIT_TEXT.search(resp.text or ""):
                        rate_limit_detected = True
                        break
                    if resp.headers.get('Retry-After'):
                        rate_limit_detected = True
                        break
                    if resp.headers.get('X-RateLimit-Remaining', '999') == '0':
                        rate_limit_detected = True
                        break

                    # All ten must be processed attempts for a finding, so the
                    # first refusal ends the burst.
                    if not _login_attempt_processed(resp.status_code):
                        break

                    success_count += 1

                except requests.exceptions.RequestException:
                    break

            if success_count >= 10 and not rate_limit_detected:
                findings.append({
                    "type": "no_rate_limiting",
                    "severity": "medium",
                    "name": "No Rate Limiting on Login",
                    "description": f"The login endpoint {url} does not appear to have rate limiting. "
                                  "This allows brute force attacks against user accounts.",
                    "url": url,
                    "hostname": hostname,
                    "endpoint": endpoint,
                    "requests_sent": success_count,
                    "evidence": f"Sent {success_count} requests without triggering rate limit",
                    "recommendation": "Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute).",
                })

        except requests.exceptions.RequestException:
            continue

    return findings


#: Path words of a login or credential endpoint, matched as whole words of a
#: segment (split on - _ .), so `/blog/authors` or `/tokens-of-appreciation` is not one.
_LOGIN_PATH_WORDS = frozenset({
    "login", "signin", "auth", "authenticate", "session", "token", "oauth", "sso",
    "password", "credential", "credentials", "register", "signup", "forgot", "logon",
})
_LOGIN_PATH_PHRASES = frozenset({"sign-in", "sign_in", "sign-up", "sign_up", "reset-password",
                                 "log-in", "log_in"})


def _is_login_path(path: str) -> bool:
    for segment in (path or "").lower().split("/"):
        if not segment:
            continue
        if segment in _LOGIN_PATH_PHRASES or any(p in segment for p in _LOGIN_PATH_PHRASES):
            return True
        if set(re.split(r"[-_.]+", segment)) & _LOGIN_PATH_WORDS:
            return True
    return False


def _never_request(url: str) -> bool:
    """A quarantined URL (a leaked one-time link or token: recon/helpers/url_leaks.py),
    or one already stored masked (a `{token}` path)."""
    if "{" in url or "***" in url:
        return True
    try:
        from recon.helpers.url_leaks import inspect_url
        return bool(inspect_url(url)["quarantined"])
    except Exception:  # noqa: BLE001 - fail closed
        return True


def run_rate_limit_checks(
    hostnames: List[str],
    recon_data: Dict[str, Any],
    enabled_checks: Dict[str, bool],
    timeout: int = 5,
    max_workers: int = 5  # Lower concurrency to avoid false positives
) -> List[Dict]:
    """
    Run all enabled rate limiting checks.

    Args:
        hostnames: List of hostnames to check
        recon_data: Reconnaissance data containing discovered URLs
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    if not enabled_checks.get("no_rate_limiting", True):
        return findings

    # Extract all discovered URLs from recon data. Only live sources: a URL
    # only a web archive reported (urlscan, GAU, ParamSpider) is someone's old
    # link, and this check sends it a GET and ten POSTs.
    discovered_urls = []

    # From resource_enum
    resource_enum = recon_data.get("resource_enum", {})
    archived = set((resource_enum or {}).get("archived_urls") or [])
    if resource_enum:
        discovered_urls.extend(resource_enum.get("discovered_urls", []))

    # Nuclei's URL lists, which vuln_scan.py stores under vuln_scan.discovered_urls
    nuclei_urls = (recon_data.get("vuln_scan") or {}).get("discovered_urls") or {}
    if isinstance(nuclei_urls, dict):
        discovered_urls.extend(nuclei_urls.get("all_scanned_urls") or [])
        discovered_urls.extend(nuclei_urls.get("dast_urls_with_params") or [])

    # Live URLs from httpx, keyed by URL under http_probe.by_url
    by_url = (recon_data.get("http_probe") or {}).get("by_url") or {}
    for url, entry in by_url.items():
        discovered_urls.append((entry.get("url") if isinstance(entry, dict) else None) or url)

    # Deduplicate, then drop every URL whose path only an archive knows (the
    # nuclei lists rebuild those URLs with their own query values).
    def _key(u: str) -> str:
        try:
            p = urlparse(u)
            return f"{p.scheme}://{p.netloc}{p.path}".lower()
        except Exception:  # noqa: BLE001
            return u
    live_keys = {_key(u) for u in (resource_enum or {}).get("discovered_urls", []) or []
                 if isinstance(u, str) and u not in archived}
    live_keys |= {_key(u) for u in by_url}
    archive_only = {_key(u) for u in archived} - live_keys
    discovered_urls = list({u for u in discovered_urls
                            if isinstance(u, str) and u and _key(u) not in archive_only})

    def check_single_host(hostname: str) -> List[Dict]:
        if _host_down(hostname):
            return []
        host_findings = check_no_rate_limiting(
            urls=discovered_urls,
            hostname=hostname,
            timeout=timeout
        )
        return host_findings

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


def run_security_headers_checks(
    hostnames: List[str],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run all enabled security headers checks.

    Args:
        hostnames: List of hostnames to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout in seconds
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_host(hostname: str) -> List[Dict]:
        if _host_down(hostname):
            return []
        host_findings = []

        # Check missing security headers (HTTPS)
        any_header_check_enabled = any(
            enabled_checks.get(info["check_name"], True)
            for info in SECURITY_HEADERS.values()
        )

        if any_header_check_enabled:
            header_findings = check_security_headers(
                hostname=hostname,
                port=443,
                timeout=timeout,
                enabled_headers=enabled_checks
            )
            host_findings.extend(header_findings)

        # Check cache control
        if enabled_checks.get("cache_control_missing", True):
            result = check_cache_control_missing(hostname, port=443, timeout=timeout)
            if result:
                host_findings.append(result)

        return host_findings

    # Run checks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# Main Entry Point
# =============================================================================

#: The root recon gives an IP-mode scan, "ip-targets.<project_id>". The project
#: id is a cuid (lower-case, digits, no hyphen), so a real domain - whose TLD is
#: letters, or "xn--..." - never has this shape.
_SYNTHETIC_IP_ROOT = re.compile(r"^ip-targets\.(?=[a-z0-9]*[0-9])[a-z0-9]+$")


def _dns_check_domains(recon_data: Dict[str, Any]) -> List[str]:
    """The names whose mail and zone records to check: each root's registrable
    domain (org), from recon_data["domains"], else "domain".

    SPF, DMARC and DNSSEC are properties of the org (§4.9): checking a deeper
    scan root reports records "missing" that the org holds. The org comes
    from the root's group (metadata.org_domain, or the run's scope_groups); a
    file written before scope groups keeps checking the root itself.

    An IP-mode scan has no domain: its root is a name in no DNS zone, so every
    record would read as "missing" and SPF/DMARC/DNSSEC would report findings
    about a domain that does not exist.
    """
    if (recon_data.get("metadata") or {}).get("ip_mode"):
        return []
    roots = recon_data.get("domains")
    if not isinstance(roots, list) or not roots:
        roots = [recon_data.get("domain", "")]
    orgs = {str(g.get("scan_root") or "").lower(): str(g.get("org_domain") or "").lower()
            for g in recon_data.get("scope_groups") or [] if isinstance(g, dict)}
    own_org = str((recon_data.get("metadata") or {}).get("org_domain") or "").lower()
    own_root = str(recon_data.get("domain") or "").lower()
    seen = []
    for root in roots:
        if not (isinstance(root, str) and root.strip()) or _SYNTHETIC_IP_ROOT.match(root.strip().lower()):
            continue
        name = orgs.get(root.strip().lower()) or (own_org if root.strip().lower() == own_root else "") or root
        if name not in seen:
            seen.append(name)
    return seen


def _dns_check_claims(names: List[str], roe_excluded_hosts) -> List[str]:
    """The orgs this call checks: each org once per run (§4.9). The first group
    of an org to reach the checks runs them; its later groups find the org
    claimed. An org the RoE excludes is never checked."""
    from recon.helpers.org_work import claim_org
    from recon.helpers.roe_scope import _is_roe_excluded
    out = []
    for name in names:
        if roe_excluded_hosts and _is_roe_excluded(name, roe_excluded_hosts):
            print(f"[-][SecurityCheck] DNS checks skipped for {name}: RoE excluded")
            continue
        if claim_org("dns_checks", name.lower()):
            out.append(name)
        else:
            print(f"[-][SecurityCheck] DNS checks for {name} already ran this run")
    return out


def run_security_checks(
    recon_data: Dict[str, Any],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    tls_expiry_days: int = 30,
    max_workers: int = 10,
    ai_classifier_enabled: bool = False,
    ai_model: str = '',
    ai_user_id: str = '',
    ai_project_id: str = '',
    ai_engine: str = 'llm',
    roe_excluded_hosts: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run all enabled security checks on recon data.

    Args:
        recon_data: The reconnaissance data dictionary
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request/connection timeout
        tls_expiry_days: Days before TLS expiry to warn
        max_workers: Maximum concurrent workers
        ai_classifier_enabled: Enable LLM-based WAF classification cascade.
            When True, _has_cdn_markers and check_waf_bypass fall back to the
            agent's /llm/waf-classify endpoint on a static-negative match.
        ai_model: LLM model id forwarded to the agent (e.g. 'claude-opus-4-6').
        ai_user_id, ai_project_id: Forwarded for per-user provider key resolution.
        roe_excluded_hosts: ROE_EXCLUDED_HOSTS when RoE is on. The port/service
            checks read IPs straight from the port scan, so they apply it here.

    Returns:
        Dictionary with security check findings
    """
    global _HH_SCOPE, _CONTROL_CACHE, _ROE_EXCLUDED
    from recon.helpers import circuit_breaker as _cb
    _HH_SCOPE = _cb.scope((), label="SecurityCheck", unit="host(s)")
    _CONTROL_CACHE = catchall.ControlCache()
    _ROE_EXCLUDED = tuple(h for h in (roe_excluded_hosts or ()) if isinstance(h, str) and h.strip())
    try:
        return _run_security_checks(
            recon_data, enabled_checks, timeout, tls_expiry_days, max_workers,
            ai_classifier_enabled, ai_model, ai_user_id, ai_project_id, ai_engine,
            roe_excluded_hosts=roe_excluded_hosts)
    finally:
        if _CONTROL_CACHE.requests:
            print(f"[*][SecurityCheck] Catch-all control probes sent: {_CONTROL_CACHE.requests}")
        _HH_SCOPE = None
        _CONTROL_CACHE = None
        _ROE_EXCLUDED = ()


def _run_security_checks(recon_data, enabled_checks, timeout, tls_expiry_days, max_workers,
                         ai_classifier_enabled, ai_model, ai_user_id, ai_project_id, ai_engine='llm',
                         roe_excluded_hosts=None):
    _set_ai_ctx(ai_classifier_enabled, ai_model, ai_user_id, ai_project_id, ai_engine)
    if _AI_CTX["enabled"]:
        print(f"[*][WAF-AI] Classifier cascade enabled, model={_AI_CTX['model']}")

    print("\n" + "=" * 70)
    print("[*][SecurityCheck] Custom Security Checks")
    print("=" * 70)

    # Extract IPs and hostnames from recon data
    ips = set()
    hostnames = set()
    subdomains_to_ips = {}

    dns_data = recon_data.get("dns", {})

    # From root domain, only when it is a target: a `*`-only group must never
    # TLS/header-check its apex, nor its addresses (a legacy file keeps it).
    from recon.helpers.recon_scope import recon_scope
    domain = recon_data.get("domain", "") or recon_data.get("metadata", {}).get("target", "")
    domain_dns = dns_data.get("domain", {}) if recon_scope(recon_data).include_root else {}
    if domain_dns:
        domain_ips = domain_dns.get("ips", {})
        ipv4_list = domain_ips.get("ipv4", [])
        ipv6_list = domain_ips.get("ipv6", [])
        ips.update(ipv4_list)
        ips.update(ipv6_list)
        if domain:
            hostnames.add(domain)
            subdomains_to_ips[domain] = list(set(ipv4_list + ipv6_list))

    # From subdomains
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, subdomain_data in subdomains_dns.items():
        if subdomain_data and subdomain_data.get("has_records"):
            hostnames.add(subdomain)
            if subdomain_data.get("ips"):
                ipv4_list = subdomain_data["ips"].get("ipv4", [])
                ipv6_list = subdomain_data["ips"].get("ipv6", [])
                ips.update(ipv4_list)
                ips.update(ipv6_list)
                subdomains_to_ips[subdomain] = list(set(ipv4_list + ipv6_list))

    # Filter empty values
    ips = [ip for ip in ips if ip]
    # Drop the dashed-IP placeholders recon uses for an IP with no PTR (e.g.
    # "192-88-96-10"): they never resolve, so a by-name probe only ever raises
    # ConnectionError. That is wasted work, and it would open a HostHealth
    # breaker for a host whose IP is alive and already checked directly (the
    # direct-IP checks own those IPs), falsely reporting IP-mode scans as
    # degraded. The IPs themselves are already in `ips`.
    hostnames = [h for h in hostnames if h and not _is_synthetic_ip_host(h)]
    subdomains_to_ips = {k: v for k, v in subdomains_to_ips.items()
                         if not _is_synthetic_ip_host(k)}

    print(f"[*][SecurityCheck] Targets: {len(hostnames)} hostnames, {len(ips)} IPs")
    print(f"[*][SecurityCheck] Timeout: {timeout}s")
    print(f"[*][SecurityCheck] Workers: {max_workers}")

    # Count enabled checks by category
    ip_checks = ["direct_ip_http", "direct_ip_https", "ip_api_exposed", "waf_bypass"]
    tls_checks = [
        "tls_expiring_soon",
        # tlsx-data-derived hygiene checks (zero extra network cost)
        "tls_expired", "tls_self_signed", "tls_hostname_mismatch",
        "tls_weak_version", "tls_weak_cipher", "tls_wildcard_overbroad",
    ]
    header_checks = [
        "missing_referrer_policy", "missing_permissions_policy",
        "missing_coop", "missing_corp", "missing_coep",
        "cache_control_missing"
    ]
    auth_checks = ["login_no_https", "session_no_secure", "session_no_httponly", "basic_auth_no_tls"]
    dns_checks = ["spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer"]
    port_checks = ["admin_port_exposed", "database_exposed", "redis_no_auth", "kubernetes_api_exposed", "smtp_open_relay"]
    app_checks = ["csp_unsafe_inline", "insecure_form_action"]
    rate_checks = ["no_rate_limiting"]

    enabled_ip = sum(1 for c in ip_checks if enabled_checks.get(c, False))
    enabled_tls = sum(1 for c in tls_checks if enabled_checks.get(c, False))
    enabled_headers = sum(1 for c in header_checks if enabled_checks.get(c, False))
    enabled_auth = sum(1 for c in auth_checks if enabled_checks.get(c, False))
    enabled_dns = sum(1 for c in dns_checks if enabled_checks.get(c, False))
    enabled_port = sum(1 for c in port_checks if enabled_checks.get(c, False))
    enabled_app = sum(1 for c in app_checks if enabled_checks.get(c, False))
    enabled_rate = sum(1 for c in rate_checks if enabled_checks.get(c, False))
    enabled_page = sum(1 for c in PAGE_CONTENT_CHECKS if enabled_checks.get(c, False))

    print(f"[*][SecurityCheck] Enabled checks:")
    print(f"[*][SecurityCheck]   - Direct IP: {enabled_ip}, TLS: {enabled_tls}, Headers: {enabled_headers}")
    print(f"[*][SecurityCheck]   - Auth: {enabled_auth}, DNS: {enabled_dns}, Port/Service: {enabled_port}")
    print(f"[*][SecurityCheck]   - App Security: {enabled_app}, Rate Limit: {enabled_rate}, "
          f"Page Content: {enabled_page}")
    print("=" * 70 + "\n")

    all_findings = []
    cdn_ips: Set[str] = set()

    # Run direct IP access checks
    if enabled_ip > 0 and ips:
        # Build the CDN/edge IP set used to prefilter findings.
        # Case 1+2: IPs flagged is_cdn by Naabu/httpx with a RELIABLE edge
        #           CDN name (cloudflare/cloudfront/akamai/...). Generic
        #           cloud labels like "aws"/"azure" are excluded on purpose
        #           because they mislabel bare ALB/EC2 origins that DO
        #           serve the application directly.
        # Case 3 layer 1: IPs inside published Cloudflare prefixes.
        # Case 3 layer 2: IPs whose ASN matches a known CDN ASN.
        try:
            cdn_ips |= collect_reliable_edge_ips(recon_data)
            cdn_ips |= collect_asn_cdn_ips(recon_data)
            cdn_ips |= collect_prefix_cdn_ips(ips)
        except Exception as exc:
            print(f"[!][SecurityCheck] CDN prefilter failed, probing all IPs: {exc}")
            cdn_ips = set()

        print(f"[*][SecurityCheck] Running Direct IP Access checks on {len(ips)} IPs...")
        ip_findings = run_direct_ip_checks(
            ips=list(ips),
            subdomains_to_ips=subdomains_to_ips,
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers,
            cdn_ips=cdn_ips,
        )
        all_findings.extend(ip_findings)
        print(f"[+][SecurityCheck] Found {len(ip_findings)} issues")

    # Run TLS/SSL checks
    if enabled_tls > 0 and hostnames:
        print(f"[*][SecurityCheck] Running TLS/SSL checks on {len(hostnames)} hostnames...")
        tls_findings = run_tls_checks(
            hostnames=list(hostnames),
            enabled_checks=enabled_checks,
            timeout=timeout,
            expiry_days_threshold=tls_expiry_days,
            max_workers=max_workers
        )
        all_findings.extend(tls_findings)
        print(f"[+][SecurityCheck] Found {len(tls_findings)} issues")

    # TLS hygiene from certificate data already in memory. Gated on cert-data
    # AVAILABILITY, not on tlsx (Phase 1.0): with tlsx off this still evaluates
    # the 443 certificates httpx captured, which is what every passive preset
    # relies on. Runs independently of the hostname-only network check above so
    # it also covers non-HTTP TLS ports and bare IPs, at zero extra network cost.
    if recon_data.get("tlsx") or recon_data.get("http_probe"):
        tls_data_findings = run_tls_data_checks(recon_data, enabled_checks)
        if tls_data_findings:
            all_findings.extend(tls_data_findings)
            print(f"[+][SecurityCheck] Found {len(tls_data_findings)} TLS-hygiene issues from cert data")

    # Page Content (item 5): the titles, Server headers and issuers already in
    # memory, against the problem-page catalog. No request.
    if enabled_page > 0 and (recon_data.get("tlsx") or recon_data.get("http_probe")):
        page_findings = run_page_content_checks(recon_data, enabled_checks)
        if page_findings:
            all_findings.extend(page_findings)
            print(f"[+][SecurityCheck] Found {len(page_findings)} page-content issues from httpx and tlsx data")

    # Run Security Headers checks
    if enabled_headers > 0 and hostnames:
        print(f"[*][SecurityCheck] Running Security Headers checks on {len(hostnames)} hostnames...")
        headers_findings = run_security_headers_checks(
            hostnames=list(hostnames),
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers
        )
        all_findings.extend(headers_findings)
        print(f"[+][SecurityCheck] Found {len(headers_findings)} issues")

    # Run Authentication checks
    if enabled_auth > 0 and hostnames:
        print(f"[*][SecurityCheck] Running Authentication checks on {len(hostnames)} hostnames...")
        auth_findings = run_auth_checks(
            hostnames=list(hostnames),
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers
        )
        all_findings.extend(auth_findings)
        print(f"[+][SecurityCheck] Found {len(auth_findings)} issues")

    # Run DNS Security checks, once per root: a Domain batch run covers several,
    # each with its own mail and zone records.
    if enabled_dns > 0:
        for domain in _dns_check_claims(_dns_check_domains(recon_data), roe_excluded_hosts):
            print(f"[*][SecurityCheck] Running DNS Security checks on {domain}...")
            dns_findings = run_dns_checks(
                domain=domain,
                enabled_checks=enabled_checks,
                timeout=timeout
            )
            all_findings.extend(dns_findings)
            print(f"[+][SecurityCheck] Found {len(dns_findings)} issues")

    # Run Port/Service Security checks
    if enabled_port > 0:
        print(f"[*][SecurityCheck] Running Port/Service Security checks...")
        port_findings = run_port_service_checks(
            recon_data=recon_data,
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers,
            cdn_ips=cdn_ips,
            roe_excluded_hosts=roe_excluded_hosts,
        )
        all_findings.extend(port_findings)
        print(f"[+][SecurityCheck] Found {len(port_findings)} issues")

    # Run Application Security checks
    if enabled_app > 0 and hostnames:
        print(f"[*][SecurityCheck] Running Application Security checks on {len(hostnames)} hostnames...")
        app_findings = run_app_security_checks(
            hostnames=list(hostnames),
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers
        )
        all_findings.extend(app_findings)
        print(f"[+][SecurityCheck] Found {len(app_findings)} issues")

    # Run Rate Limiting checks
    if enabled_rate > 0 and hostnames:
        print(f"[*][SecurityCheck] Running Rate Limiting checks on {len(hostnames)} hostnames...")
        rate_findings = run_rate_limit_checks(
            hostnames=list(hostnames),
            recon_data=recon_data,
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=min(max_workers, 5)  # Lower concurrency for rate limit checks
        )
        all_findings.extend(rate_findings)
        print(f"[+][SecurityCheck] Found {len(rate_findings)} issues")

    # Organize findings by type and severity
    result = _assemble_security_result(
        all_findings, enabled_checks, len(hostnames), len(ips))
    # Hosts skipped as unreachable: their previous findings are kept by the
    # prune (keep_hosts), and the payload lists them only when there are any.
    if _HH_SCOPE is not None:
        _HH_SCOPE.finish("security_checks", host_source="security_check",
                         payload=result["security_checks"])
    by_type = result["security_checks"]["by_type"]
    severity_counts = {k: v for k, v in result["security_checks"]["summary"].items()
                       if k != "total_findings"}

    # Print summary
    print(f"\n{'=' * 70}")
    print(f"[+][SecurityCheck] SECURITY CHECKS COMPLETE")
    print(f"[+][SecurityCheck] Total findings: {len(all_findings)}")

    if any(severity_counts[s] > 0 for s in ["critical", "high", "medium", "low"]):
        print(f"\n[+][SecurityCheck] SEVERITY SUMMARY:")
        if severity_counts['critical'] > 0:
            print(f"[!][SecurityCheck] CRITICAL: {severity_counts['critical']}")
        if severity_counts['high'] > 0:
            print(f"[!][SecurityCheck] HIGH: {severity_counts['high']}")
        if severity_counts['medium'] > 0:
            print(f"[*][SecurityCheck] MEDIUM: {severity_counts['medium']}")
        if severity_counts['low'] > 0:
            print(f"[*][SecurityCheck] LOW: {severity_counts['low']}")

    if by_type:
        print(f"\n[+][SecurityCheck] FINDINGS BY TYPE:")
        for finding_type, findings_list in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"[*][SecurityCheck]   {finding_type}: {len(findings_list)}")

    print(f"{'=' * 70}")

    return result
