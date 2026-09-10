"""
RedAmon - Origin-IP Discovery (behind CDN/WAF)
==============================================
Unmask the real origin server hiding behind a CDN/WAF by gathering candidate
origin IPs from many fingerprint sources, then confirming each with a
weighted-similarity validator. A Python reimplementation of the behavior of
`unwaf` (github.com/mmarting/unwaf @ commit c8302eb) — see
`_local/internal/origin_discovery_unwaf_mapping.md` for the source→function map.
The `unwaf` binary is a dev-time reference only; nothing here vendors its Go code.

Contract (recon-tool-integration):
- `run_origin_discovery_enrichment(combined_result, settings)` mutates
  `combined_result["origin_discovery"]` and returns `combined_result`.
- `run_origin_discovery_enrichment_isolated(...)` deep-copies, runs, and returns
  only the payload — the GROUP 6 Phase A fan-out AND test call path.

Every discovery source is NEVER-RAISE: on any error it records a soft marker
under `candidates_meta[host]["errors"]` and returns nothing, so one dead source
never sinks the module. Every candidate IP is untrusted third-party/target data,
so it is fail-closed SSRF-filtered (`is_non_routable_ip` / `is_url_safe_to_probe`)
and RoE-filtered before it is ever probed or recorded.
"""

from __future__ import annotations

import base64
import copy
import difflib
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus, urlparse

import requests

try:
    import mmh3  # already in recon/requirements.txt (mmh3>=4.1.0)
except Exception:  # pragma: no cover - dependency guaranteed by the image
    mmh3 = None

from recon.main_recon_modules.ip_filter import is_non_routable_ip, is_url_safe_to_probe
from recon.helpers.roe_scope import _is_roe_excluded

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Ported constants (unwaf network.go / waf.go)
# ---------------------------------------------------------------------------

# Subdomains that commonly point straight at the origin, not the CDN edge.
ORIGIN_SUBDOMAINS = [
    "mail", "webmail", "smtp", "pop", "imap",
    "ftp", "sftp",
    "cpanel", "whm", "plesk", "webmin",
    "direct", "origin", "origin-www", "direct-connect",
    "dev", "staging", "stage", "test", "qa", "uat",
    "api", "backend", "admin", "panel",
    "old", "legacy", "backup", "bak",
    "ns1", "ns2", "dns",
    "vpn", "remote", "gateway",
    "mx", "mx1", "mx2", "mailgw",
    "autodiscover", "autoconfig",
    "portal", "intranet", "internal",
]

# Web ports probed on a candidate IP (unwaf webPorts).
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8008, 8888, 9443]
_TLS_PORTS = {443, 8443, 9443}

# MX hosts belonging to managed mail providers never point at the origin.
_MX_SKIP_VENDORS = ("google", "outlook", "microsoft", "mimecast", "proofpoint", "barracuda", "pphosted")

# Known CDN/WAF IP ranges — a candidate inside one is the edge, not the origin
# (ported from unwaf waf.go wafCIDRs; broader than RedAmon's Cloudflare-only
# prefix layer, so used in addition to the combined_result is_cdn flags).
_WAF_CDN_CIDRS = [
    # Cloudflare
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
    "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    # Akamai
    "23.0.0.0/12", "104.64.0.0/10", "2600:1400::/24", "2600:1480::/24",
    # Fastly
    "151.101.0.0/16", "2a04:4e40::/32", "2a04:4e42::/32",
    # Imperva / Incapsula
    "199.83.128.0/21", "198.143.32.0/19",
    # Sucuri
    "192.88.134.0/23", "185.93.228.0/22",
    # AWS CloudFront
    "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14",
    "18.64.0.0/14", "18.154.0.0/15", "18.160.0.0/12",
    "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16",
    "54.230.0.0/17", "54.239.128.0/18", "99.84.0.0/16",
    "143.204.0.0/16", "205.251.192.0/19", "204.246.164.0/22", "2600:9000::/28",
]

# WAF/CDN response-header signatures (unwaf waf.go): a candidate whose response
# carries one of these is still routed through the edge, so it is not a bypass.
_WAF_HEADER_SIGNATURES = [
    "cf-ray", "cf-cache-status", "cf-request-id",
    "x-akamai-transformed", "akamai-origin-hop",
    "x-amz-cf-id", "x-amz-cf-pop",
    "x-fastly-request-id", "fastly-io-info",
    "x-sucuri-id", "x-sucuri-cache",
    "x-iinfo", "x-cdn",
    "x-varnish", "x-sp-url", "x-sp-waf",
    "barra_counter_session", "x-wa-info", "x-cnection",
    "ddos-guard", "ar-asg", "ar-poweredby", "fortiwafsid", "x-rdwr",
    "x-azure-ref", "x-fd-healthprobe", "x-goog-bot-verification",
    "x-vercel-id", "x-vercel-cache", "x-nf-request-id",
]
_WAF_SERVER_TOKENS = ("cloudflare", "akamaighost", "akamai", "sucuri", "incapsula",
                      "imperva", "ddos-guard", "fortiweb", "netlify")

# Weighted-similarity model (unwaf verify.go calculateOverallScore).
_W_HTML = 0.60
_W_CERT = 0.25
_W_HEADER = 0.15

# Cap the body compared for HTML similarity. unwaf compares the full extracted
# text; we bound memory (a handful of candidates each holding a body) but stay
# far above the 4 KB LLM-prompt cap, which would destroy the similarity signal.
_MAX_HTML_BYTES = 1_000_000
# Cap the extracted text fed to difflib per comparison (F7 — quadratic guard).
_SIMILARITY_MAX_CHARS = 65_536

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

_TAG_RE = re.compile(rb"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _log(symbol: str, msg: str) -> None:
    """`[symbol][OriginDiscovery] msg` — recon stdout is tailed into the SSE drawer."""
    print(f"[{symbol}][OriginDiscovery] {msg}")


# ---------------------------------------------------------------------------
# Rate limiter (copied from fofa_enrich._RateLimiter) + per-scan search budget
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Thread-safe minimum-interval rate limiter (gates active probe traffic)."""

    def __init__(self, interval: float):
        self._interval = max(0.0, interval)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self._interval <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            delay = self._interval - elapsed if elapsed < self._interval else 0.0
            self._last = now + delay
        if delay > 0:
            time.sleep(delay)


class _SearchBudget:
    """Per-scan ceiling on genuine (non-cached) keyed search calls (G3).

    Keyed sources (Shodan/Censys/FOFA/ZoomEye search endpoints) burn query
    credits distinct from the host-lookup credits the sibling enrichers spend.
    A cached hit does NOT draw the budget down.
    """

    def __init__(self, limit: int):
        self._remaining = max(0, int(limit))
        self._lock = threading.Lock()
        self.exhausted_logged = False

    def take(self) -> bool:
        with self._lock:
            if self._remaining <= 0:
                return False
            self._remaining -= 1
            return True

    @property
    def remaining(self) -> int:
        with self._lock:
            return self._remaining


class _RunCtx:
    """Per-run shared state: rate limiter, budget, and the (source, key) cache."""

    def __init__(self, settings: dict):
        self.settings = settings
        self.timeout = int(settings.get("ORIGIN_DISCOVERY_TIMEOUT", 10) or 10)
        self.threshold = float(settings.get("ORIGIN_DISCOVERY_THRESHOLD", 60) or 60)
        self.max_candidates = int(settings.get("ORIGIN_DISCOVERY_MAX_CANDIDATES", 25) or 25)
        workers = int(settings.get("ORIGIN_DISCOVERY_WORKERS", 10) or 10)
        self.workers = max(1, workers)
        # rps ceiling: explicit ORIGIN_DISCOVERY_RATE (0 = unlimited) wins; else
        # unthrottled. ROE caps ORIGIN_DISCOVERY_RATE upstream in project_settings.
        rate = float(settings.get("ORIGIN_DISCOVERY_RATE", 0) or 0)
        self.rate = _RateLimiter(1.0 / rate if rate > 0 else 0.0)
        self.budget = _SearchBudget(int(settings.get("ORIGIN_DISCOVERY_MAX_SEARCH_CALLS", 50) or 50))
        self.roe_enabled = bool(settings.get("ROE_ENABLED"))
        self.roe_excluded = settings.get("ROE_EXCLUDED_HOSTS", []) or []
        self._cache: Dict[Tuple[str, str], List[str]] = {}
        self._cache_lock = threading.Lock()

    def cached(self, source: str, key: str, producer) -> List[str]:
        """Memoize a per-domain search by (source, key) for the whole run (G3).

        Only NON-EMPTY results are cached. A source that returns nothing is often
        a transient failure (a producer swallows a 429/timeout and returns []); if
        that empty were cached, every later host sharing the key would inherit the
        blackout silently. Not caching empties costs a re-query for a genuinely
        empty source (bounded by the rate limiter and the keyed-search budget) and
        eliminates the poisoning.
        """
        ck = (source, key)
        with self._cache_lock:
            if ck in self._cache:
                return self._cache[ck]
        result = producer() or []
        if result:
            with self._cache_lock:
                self._cache[ck] = result
        return result


# ---------------------------------------------------------------------------
# Favicon mmh3 (unwaf favicon.go computeMMH3) — matches httpx favicon_hash
# ---------------------------------------------------------------------------

def _compute_favicon_mmh3(body: bytes) -> Optional[int]:
    """Shodan/FOFA favicon hash: mmh3 over MIME-wrapped base64 of the raw bytes."""
    if not body or mmh3 is None:
        return None
    try:
        encoded = base64.encodebytes(body).decode("utf-8")  # inserts \n every 76 chars
        return mmh3.hash(encoded)
    except Exception:
        return None


def _favicon_hash_for_host(host: str, existing: Any, ctx: _RunCtx) -> Optional[int]:
    """Prefer the hash httpx already computed; self-fetch /favicon.ico otherwise.

    The self-fetch is active traffic to the target, so it is rate-limited and only
    kept when the host is safe to probe (fail-closed via is_url_safe_to_probe).
    """
    if existing not in (None, "", 0):
        try:
            return int(existing)
        except (TypeError, ValueError):
            pass
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/favicon.ico"
        if not is_url_safe_to_probe(url):
            continue
        try:
            ctx.rate.wait()
            resp = requests.get(url, timeout=ctx.timeout, verify=False,
                                headers={"User-Agent": _UA}, stream=True)
            if resp.status_code != 200:
                resp.close()
                continue
            body = resp.raw.read(_MAX_HTML_BYTES, decode_content=True)
            resp.close()
            h = _compute_favicon_mmh3(body)
            if h is not None:
                return h
        except requests.RequestException:
            continue
    return None


# ---------------------------------------------------------------------------
# Fronted-host selection
# ---------------------------------------------------------------------------

# Common multi-label public suffixes. A naive last-two-labels registrable domain
# turns `www.acme.co.uk` into `co.uk`, so SPF/crt.sh/passive-DNS get queried for
# the public suffix and the real origin is silently never a candidate — a whole
# class of ccTLD targets. This is a curated subset of the Public Suffix List
# (the image ships no PSL library); it covers the common cases, not every entry.
_MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz",
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in", "edu.in", "res.in",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.kr", "or.kr", "ne.kr", "re.kr", "pe.kr", "go.kr", "ac.kr",
    "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "bel.tr",
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk",
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il", "k12.il",
    "co.id", "or.id", "net.id", "web.id", "ac.id", "go.id", "sch.id", "my.id",
    "co.th", "or.th", "net.th", "in.th", "ac.th", "go.th",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw", "idv.tw",
    "com.ua", "net.ua", "org.ua", "in.ua", "kiev.ua",
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl",
    "com.gr", "net.gr", "org.gr", "edu.gr", "gov.gr",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
})


def _registrable_domain(host: str) -> str:
    """Registrable domain (unwaf extractMainDomain, PSL-aware for common ccTLDs).

    `www.acme.co.uk` -> `acme.co.uk` (not `co.uk`); `a.b.acme.com` -> `acme.com`.
    """
    parts = (host or "").strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts) if parts != [""] else host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    return last2


def _resolve_ips(host: str) -> Set[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return set()
    return {info[4][0].split("%")[0] for info in infos}


def _port_open(ip: str, port: int, timeout: float) -> bool:
    """Fast TCP connect check (unwaf checkWebServer): skip ports that aren't open
    so a filtered port doesn't cost a full HTTP + TLS timeout each."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _select_fronted_hosts(combined_result: dict, ctx: _RunCtx) -> Dict[str, dict]:
    """CDN-fronted hosts from http_probe.by_url: is_cdn flag or a CDN edge IP.

    Returns {host: {favicon_hash, cdn_name, edge_ip, resolved_ips}}.
    """
    http_probe = combined_result.get("http_probe") or {}
    by_url = http_probe.get("by_url") or {}
    fronted: Dict[str, dict] = {}
    for url, info in by_url.items():
        if not isinstance(info, dict):
            continue
        edge_ip = info.get("ip")
        is_cdn = bool(info.get("is_cdn")) or (edge_ip and _ip_in_cdn_ranges(edge_ip))
        if not is_cdn:
            continue
        host = info.get("host") or urlparse(url).hostname
        if not host:
            continue
        entry = fronted.setdefault(host, {
            "favicon_hash": None, "cdn_name": None, "edge_ip": None, "resolved_ips": set(),
        })
        if info.get("favicon_hash") not in (None, ""):
            entry["favicon_hash"] = info.get("favicon_hash")
        entry["cdn_name"] = entry["cdn_name"] or info.get("cdn")
        entry["edge_ip"] = entry["edge_ip"] or edge_ip
        if edge_ip:
            entry["resolved_ips"].add(edge_ip)
    # current DNS resolution — a candidate equal to it is the edge, not a find
    for host, entry in fronted.items():
        entry["resolved_ips"] |= _resolve_ips(host)
    return fronted


# ---------------------------------------------------------------------------
# CDN / candidate filtering
# ---------------------------------------------------------------------------

import ipaddress as _ipaddress

_PARSED_CDN_NETS = []
for _c in _WAF_CDN_CIDRS:
    try:
        _PARSED_CDN_NETS.append(_ipaddress.ip_network(_c, strict=False))
    except ValueError:
        pass


def _ip_in_cdn_ranges(ip: str) -> bool:
    try:
        addr = _ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PARSED_CDN_NETS)


# ---------------------------------------------------------------------------
# Keyless discovery sources
# ---------------------------------------------------------------------------

def _discover_via_subdomains(domain: str, ctx: _RunCtx) -> List[str]:
    """Resolve ~30 origin-leaking subdomains, keep the off-CDN routable ones."""
    found: Set[str] = set()

    def _one(sub: str):
        fqdn = f"{sub}.{domain}"
        for ip in _resolve_ips(fqdn):
            if not is_non_routable_ip(ip) and not _ip_in_cdn_ranges(ip):
                found.add(ip)

    with ThreadPoolExecutor(max_workers=ctx.workers) as ex:
        list(ex.map(_one, ORIGIN_SUBDOMAINS))
    return list(found)


def _discover_via_email_records(domain: str, ctx: _RunCtx) -> List[str]:
    """SPF ip4:/ip6: ranges + non-vendor MX host IPs (unwaf extractIPsFromSPF/MX)."""
    ips: Set[str] = set()
    try:
        import dns.resolver  # dnspython, used pipeline-wide
    except Exception:
        return []
    # SPF (TXT)
    try:
        for rr in dns.resolver.resolve(domain, "TXT"):
            txt = b"".join(getattr(rr, "strings", []) or []).decode("utf-8", "replace") if getattr(rr, "strings", None) else str(rr).strip('"')
            if not txt.startswith("v=spf1"):
                continue
            for part in txt.split():
                if part.startswith("ip4:") or part.startswith("ip6:"):
                    val = part.split(":", 1)[1]
                    if "/" in val:
                        try:
                            net = _ipaddress.ip_network(val, strict=False)
                            # expand only small ranges (<= /24) like unwaf
                            if net.num_addresses <= 256:
                                ips.update(str(h) for h in net.hosts())
                            else:
                                ips.add(str(net.network_address))
                        except ValueError:
                            continue
                    else:
                        ips.add(val)
    except Exception:
        pass
    # MX
    try:
        for rr in dns.resolver.resolve(domain, "MX"):
            host = str(rr.exchange).rstrip(".")
            low = host.lower()
            if any(v in low for v in _MX_SKIP_VENDORS):
                continue
            ips |= _resolve_ips(host)
    except Exception:
        pass
    return list(ips)


def _discover_via_crtsh(domain: str, ctx: _RunCtx) -> List[str]:
    """crt.sh SAN subdomains, resolved to off-CDN IPs (reuses RedAmon query_crtsh)."""
    try:
        from recon.main_recon_modules.domain_recon import query_crtsh
        subs = query_crtsh(domain, ctx.settings) or {}
    except Exception:
        return []
    names = list(subs.keys()) if isinstance(subs, dict) else list(subs)
    ips: Set[str] = set()

    def _one(name: str):
        for ip in _resolve_ips(name):
            if not is_non_routable_ip(ip) and not _ip_in_cdn_ranges(ip):
                ips.add(ip)

    if names:
        with ThreadPoolExecutor(max_workers=ctx.workers) as ex:
            list(ex.map(_one, names[:500]))
    return list(ips)


# ---------------------------------------------------------------------------
# Keyed scanner sources (reuse RedAmon clients/keys)
# ---------------------------------------------------------------------------

def _discover_via_shodan(host: str, favicon_hash: Optional[int], ctx: _RunCtx) -> List[str]:
    """Shodan /shodan/host/search on cert-CN, hostname and favicon (unwaf)."""
    key = (ctx.settings.get("SHODAN_API_KEY") or "").strip()
    rotator = ctx.settings.get("SHODAN_KEY_ROTATOR")
    if not key and not (rotator and getattr(rotator, "has_keys", False)):
        return []
    try:
        from recon.main_recon_modules.shodan_enrich import _shodan_get
    except Exception:
        return []
    try:
        from recon.main_recon_modules.shodan_enrich import ShodanApiKeyError
    except Exception:  # pragma: no cover
        ShodanApiKeyError = ()  # nothing to catch-and-reraise
    queries = [f"ssl.cert.subject.cn:{host}", f"hostname:{host}"]
    if favicon_hash not in (None, "", 0):
        queries.append(f"http.favicon.hash:{favicon_hash}")
    ips: Set[str] = set()
    for q in queries:
        def _producer(q=q):
            if not ctx.budget.take():
                return []
            try:
                data = _shodan_get("/shodan/host/search", key, {"query": q, "minify": "true"}, rotator)
            except ShodanApiKeyError:
                raise  # surface an invalid/paid-only key to the caller -> meta + log
            except Exception:
                return []
            out = []
            for m in (data or {}).get("matches", []) or []:
                ip = m.get("ip_str")
                if ip:
                    out.append(ip)
            return out
        ips.update(ctx.cached("shodan", q, _producer))
    return list(ips)


def _discover_via_censys(host: str, ctx: _RunCtx) -> List[str]:
    """Censys cert.names search for the host (unwaf fetchIPsFromCensys)."""
    token = (ctx.settings.get("CENSYS_API_TOKEN") or "").strip()
    org = (ctx.settings.get("CENSYS_ORG_ID") or "").strip()
    if not token:
        return []

    def _producer():
        if not ctx.budget.take():
            return []
        url = "https://api.platform.censys.io/v3/global/search/query"
        if org:
            url += "?organization_id=" + quote_plus(org)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        if org:
            headers["X-Organization-ID"] = org
        body = {"query": f"cert.names: {host}", "page_size": 50}
        try:
            ctx.rate.wait()
            resp = requests.post(url, json=body, headers=headers, timeout=ctx.timeout)
            if resp.status_code in (401, 403):
                # surface an invalid / unauthorized Censys token -> meta + log
                raise ValueError(f"Censys auth failed (HTTP {resp.status_code})")
            if resp.status_code != 200:
                return []
            hits = (resp.json().get("result") or {}).get("hits", []) or []
        except requests.RequestException:
            return []
        out = []
        for hit in hits:
            if hit.get("ip") and not _ip_in_cdn_ranges(hit["ip"]):
                out.append(hit["ip"])
            for svc in hit.get("services", []) or []:
                if svc.get("ip") and not _ip_in_cdn_ranges(svc["ip"]):
                    out.append(svc["ip"])
        return out

    return ctx.cached("censys", host, _producer)


def _discover_via_fofa(host: str, favicon_hash: Optional[int], ctx: _RunCtx) -> List[str]:
    """FOFA cert + favicon search (RedAmon addition; reuses the fofa client)."""
    key = (ctx.settings.get("FOFA_API_KEY") or "").strip()
    rotator = ctx.settings.get("FOFA_KEY_ROTATOR")
    if not key and not (rotator and getattr(rotator, "has_keys", False)):
        return []
    try:
        from recon.main_recon_modules.fofa_enrich import (
            _fofa_search, _fofa_effective_key, _parse_fofa_rows,
        )
    except Exception:
        return []
    eff = _fofa_effective_key(ctx.settings, rotator)
    if not eff:
        return []
    clauses = [f'cert="{host}"']
    if favicon_hash not in (None, "", 0):
        clauses.append(f'icon_hash="{favicon_hash}"')
    ips: Set[str] = set()
    for clause in clauses:
        def _producer(clause=clause):
            if not ctx.budget.take():
                return []
            try:
                data = _fofa_search(clause, eff, 100, rotator)
                rows, _ = _parse_fofa_rows(data or {})
            except Exception:
                return []
            out = []
            for row in rows:
                ip = row.get("ip") if isinstance(row, dict) else None
                if ip and not _ip_in_cdn_ranges(ip):
                    out.append(ip)
            return out
        ips.update(ctx.cached("fofa", clause, _producer))
    return list(ips)


def _discover_via_zoomeye(host: str, favicon_hash: Optional[int], ctx: _RunCtx) -> List[str]:
    """ZoomEye cert + favicon search (RedAmon addition; reuses the zoomeye client)."""
    key = (ctx.settings.get("ZOOMEYE_API_KEY") or "").strip()
    rotator = ctx.settings.get("ZOOMEYE_KEY_ROTATOR")
    if not key and not (rotator and getattr(rotator, "has_keys", False)):
        return []
    try:
        from recon.main_recon_modules.zoomeye_enrich import _zoomeye_search
    except Exception:
        return []
    queries = [f'ssl.cert.subject.cn="{host}"']
    if favicon_hash not in (None, "", 0):
        queries.append(f'iconhash="{favicon_hash}"')
    ips: Set[str] = set()
    for q in queries:
        def _producer(q=q):
            if not ctx.budget.take():
                return []
            try:
                rows, _ = _zoomeye_search(q, key, rotator, 100, timeout=ctx.timeout)
            except Exception:
                return []
            out = []
            for row in (rows or []):
                ip = row.get("ip") if isinstance(row, dict) else None
                if ip and not _ip_in_cdn_ranges(ip):
                    out.append(ip)
            return out
        ips.update(ctx.cached("zoomeye", q, _producer))
    return list(ips)


def _discover_via_otx(domain: str, ctx: _RunCtx) -> List[str]:
    """AlienVault OTX passive DNS A/AAAA records (unwaf fetchIPsFromOTX)."""
    from recon.main_recon_modules.virustotal_enrich import _effective_key
    key = _effective_key(ctx.settings.get("OTX_API_KEY", ""), ctx.settings.get("OTX_KEY_ROTATOR"))

    def _producer():
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"User-Agent": _UA}
        if key:
            headers["X-OTX-API-KEY"] = key
        try:
            resp = requests.get(url, headers=headers, timeout=ctx.timeout)
            if resp.status_code != 200:
                return []
            records = resp.json().get("passive_dns", []) or []
        except (requests.RequestException, ValueError):
            return []
        out = []
        for rec in records:
            if rec.get("record_type") in ("A", "AAAA"):
                ip = rec.get("address")
                if ip and _is_ip(ip):
                    out.append(ip)
        return out

    return ctx.cached("otx", domain, _producer)


def _discover_via_virustotal(domain: str, ctx: _RunCtx) -> List[str]:
    """VirusTotal passive DNS (RedAmon addition; reuses the VT resolutions client)."""
    from recon.main_recon_modules.virustotal_enrich import _effective_key, _vt_get
    key = _effective_key(ctx.settings.get("VIRUSTOTAL_API_KEY", ""), ctx.settings.get("VIRUSTOTAL_KEY_ROTATOR"))
    if not key:
        return []

    def _producer():
        try:
            data = _vt_get(f"domains/{domain}/resolutions?limit=40",
                           ctx.settings.get("VIRUSTOTAL_API_KEY", ""),
                           ctx.settings.get("VIRUSTOTAL_KEY_ROTATOR"),
                           timeout=ctx.timeout)
        except Exception:
            return []
        out = []
        for item in (data or {}).get("data", []) or []:
            ip = (item.get("attributes") or {}).get("ip_address")
            if ip and _is_ip(ip):
                out.append(ip)
        return out

    return ctx.cached("virustotal", domain, _producer)


# ---------------------------------------------------------------------------
# Passive-DNS sources (new keys)
# ---------------------------------------------------------------------------

def _discover_via_securitytrails(domain: str, ctx: _RunCtx) -> List[str]:
    """SecurityTrails DNS-A history (unwaf fetchIPsFromSecurityTrails)."""
    from recon.main_recon_modules.virustotal_enrich import _effective_key
    key = _effective_key(ctx.settings.get("SECURITYTRAILS_API_KEY", ""),
                         ctx.settings.get("SECURITYTRAILS_KEY_ROTATOR"))
    if not key:
        return []

    def _producer():
        # Key rides in the APIKEY header — never in the URL, so error logs are safe.
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        try:
            resp = requests.get(url, headers={"APIKEY": key, "Accept": "application/json"},
                                timeout=ctx.timeout)
            if resp.status_code != 200:
                return []
            records = resp.json().get("records", []) or []
        except (requests.RequestException, ValueError):
            return []
        out = []
        for rec in records:
            for val in rec.get("values", []) or []:
                ip = val.get("ip")
                if ip and _is_ip(ip):
                    out.append(ip)
        return out

    return ctx.cached("securitytrails", domain, _producer)


def _discover_via_viewdns(domain: str, ctx: _RunCtx) -> List[str]:
    """ViewDNS IP-history (unwaf fetchIPsFromViewDNS). Key is in the query string."""
    from recon.main_recon_modules.virustotal_enrich import _effective_key
    key = _effective_key(ctx.settings.get("VIEWDNS_API_KEY", ""),
                         ctx.settings.get("VIEWDNS_KEY_ROTATOR"))
    if not key:
        return []

    def _producer():
        url = f"https://api.viewdns.info/iphistory/?domain={quote_plus(domain)}&apikey={quote_plus(key)}&output=json"
        try:
            resp = requests.get(url, timeout=ctx.timeout, headers={"User-Agent": _UA})
            if resp.status_code != 200:
                # ViewDNS puts the key in the URL — never log resp.url / the URL.
                return []
            records = ((resp.json().get("response") or {}).get("records") or [])
        except (requests.RequestException, ValueError):
            return []
        out = []
        for rec in records:
            ip = rec.get("ip")
            if ip and _is_ip(ip):
                out.append(ip)
        return out

    return ctx.cached("viewdns", domain, _producer)


def _is_ip(s: str) -> bool:
    try:
        _ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _url_host(ip: str) -> str:
    """Bracket an IPv6 literal for use in a URL (`2001:db8::1` -> `[2001:db8::1]`).
    Without this, requests raises InvalidURL on `https://2001:db8::1:443` and every
    IPv6 candidate is silently dropped."""
    return f"[{ip}]" if ":" in ip else ip


# ---------------------------------------------------------------------------
# SSRF + RoE + CDN + current-resolution candidate filter (G11, G2)
# ---------------------------------------------------------------------------

def _dedup_and_filter(candidates: Dict[str, str], entry: dict, ctx: _RunCtx,
                      meta: dict) -> List[Tuple[str, str]]:
    """Fail-closed filter. `candidates` maps ip -> source. Returns [(ip, source)].

    Drops (and counts): non-routable/metadata/reserved IPs (SSRF, G11), known CDN
    edge IPs, IPs equal to the host's current DNS resolution, and RoE-excluded
    IPs (G2). Caps at ORIGIN_DISCOVERY_MAX_CANDIDATES.
    """
    resolved = entry.get("resolved_ips") or set()
    kept: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    dropped = {"ssrf": 0, "cdn": 0, "current_resolution": 0, "roe": 0}
    for ip, source in candidates.items():
        if ip in seen:
            continue
        seen.add(ip)
        if is_non_routable_ip(ip):          # G11 — the safety-critical drop
            dropped["ssrf"] += 1
            continue
        if _ip_in_cdn_ranges(ip):
            dropped["cdn"] += 1
            continue
        if ip in resolved:
            dropped["current_resolution"] += 1
            continue
        if ctx.roe_enabled and _is_roe_excluded(ip, ctx.roe_excluded):  # G2
            dropped["roe"] += 1
            continue
        kept.append((ip, source))
        if len(kept) >= ctx.max_candidates:
            break
    meta["dropped"] = dropped
    return kept


# ---------------------------------------------------------------------------
# Weighted-similarity validation (unwaf verify.go + main.go verification loop)
# ---------------------------------------------------------------------------

def _extract_text(body: bytes) -> str:
    """Strip tags, keep text (unwaf tokenizes and keeps TextTokens)."""
    if not body:
        return ""
    stripped = _TAG_RE.sub(b" ", body)
    try:
        text = stripped.decode("utf-8", "replace")
    except Exception:
        text = stripped.decode("latin-1", "replace")
    return _WS_RE.sub(" ", text).strip()


def _fetch(url: str, host_header: str, ctx: _RunCtx, allow_redirects: bool = False) -> Optional[dict]:
    """GET url (optionally with a forged Host), returning text/headers/status.

    allow_redirects defaults False and MUST stay False for candidate-IP probes:
    the candidate is attacker-influenced and a 3xx Location could point at an
    internal or cloud-metadata host the G11 IP filter never saw, turning the
    probe into an SSRF pivot. The trusted reference fetch (the in-scope fronted
    host) passes allow_redirects=True so a canonical 301 (apex->www, http->https)
    doesn't collapse its body and destroy the HTML-similarity signal.
    """
    headers = {"User-Agent": _UA}
    if host_header:
        headers["Host"] = host_header
    try:
        ctx.rate.wait()
        resp = requests.get(url, timeout=ctx.timeout, verify=False, allow_redirects=allow_redirects,
                            headers=headers, stream=True)
        body = resp.raw.read(_MAX_HTML_BYTES, decode_content=True) or b""
        status = resp.status_code
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        cookies = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else resp.headers.get("Set-Cookie", "")
        resp.close()
        return {"text": _extract_text(body), "status": status, "headers": hdrs, "cookies": cookies}
    except requests.RequestException:
        return None


def _compare_html(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    # difflib.SequenceMatcher is ~quadratic; cap the compared text so a large body
    # (up to the 1 MB read) times (candidates x ports x methods) can't stall the
    # scoring phase. The leading text of a page is more than enough signal.
    a = a[:_SIMILARITY_MAX_CHARS]
    b = b[:_SIMILARITY_MAX_CHARS]
    return difflib.SequenceMatcher(None, a, b).ratio()


def _compare_headers(ref: dict, cand: dict) -> float:
    """Server + X-Powered-By exact match + Set-Cookie name overlap (unwaf)."""
    matches = 0
    total = 0
    for h in ("server", "x-powered-by"):
        rv, cv = ref["headers"].get(h, ""), cand["headers"].get(h, "")
        if rv or cv:
            total += 1
            if rv == cv:
                matches += 1
    ref_names = _cookie_names(ref.get("cookies"))
    cand_names = _cookie_names(cand.get("cookies"))
    if ref_names or cand_names:
        total += 1
        if ref_names and (ref_names & cand_names):
            matches += 1
    return (matches / total) if total else 0.0


def _cookie_names(cookies) -> Set[str]:
    names: Set[str] = set()
    if not cookies:
        return names
    items = cookies if isinstance(cookies, list) else [cookies]
    for c in items:
        for piece in str(c).split(","):
            name = piece.split("=", 1)[0].strip()
            # a stray comma inside an expires date can split a cookie; keep tokens
            if name and " " not in name and ";" not in name:
                names.add(name)
    return names


def _status_adjustment(ref_status: int, cand_status: int) -> float:
    if ref_status == cand_status:
        return -0.10 if ref_status >= 400 else 0.05
    ref_ok = 200 <= ref_status < 400
    cand_ok = 200 <= cand_status < 400
    if ref_ok != cand_ok:
        return -0.20
    return 0.0


def _overall_score(html_sim: float, cert: float, hdr: float, ref_status: int, cand_status: int) -> float:
    score = _W_HTML * html_sim + _W_CERT * cert + _W_HEADER * hdr
    score += _status_adjustment(ref_status, cand_status)
    return max(0.0, min(1.0, score))


def _response_has_waf_headers(resp: dict) -> bool:
    hdrs = resp.get("headers", {})
    for sig in _WAF_HEADER_SIGNATURES:
        if hdrs.get(sig):
            return True
    server = (hdrs.get("server") or "").lower()
    return any(tok in server for tok in _WAF_SERVER_TOKENS)


def _fetch_peer_cert(host_or_ip: str, sni: str, port: int, timeout: int) -> Optional[dict]:
    """TLS-dial host_or_ip:port with SNI=sni, return {serial, cn, sans}."""
    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = False
    ctx_ssl.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host_or_ip, port), timeout=timeout) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=sni) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()  # decoded (verify off still returns fields on 3.11+? no)
    except (OSError, ssl.SSLError, ValueError):
        return None
    # getpeercert() returns {} with CERT_NONE, so parse the DER for the fields.
    return _parse_cert_der(der, cert)


def _parse_cert_der(der: bytes, decoded: dict) -> Optional[dict]:
    serial = None
    cn = None
    sans: Set[str] = set()
    # decoded is usually {} under CERT_NONE; fall back to a DER parse via cryptography
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        c = x509.load_der_x509_certificate(der, default_backend())
        serial = str(c.serial_number)
        try:
            cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = None
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = {n.lower() for n in ext.value.get_values_for_type(x509.DNSName)}
        except Exception:
            sans = set()
    except Exception:
        if decoded:
            serial = decoded.get("serialNumber")
            for tup in decoded.get("subject", ()):
                for k, v in tup:
                    if k == "commonName":
                        cn = v
            sans = {v.lower() for (k, v) in decoded.get("subjectAltName", ()) if k == "DNS"}
    if serial is None and cn is None and not sans:
        return None
    return {"serial": serial, "cn": cn, "sans": sans}


def _compare_certs(host: str, ip: str, port: int, ctx: _RunCtx) -> float:
    ref = _fetch_peer_cert(host, host, port, timeout=min(ctx.timeout, 5))
    cand = _fetch_peer_cert(ip, host, port, timeout=min(ctx.timeout, 5))
    if not ref or not cand:
        return 0.0
    score = 0.0
    if ref["serial"] and cand["serial"] and ref["serial"] == cand["serial"]:
        score += 0.50
    if ref["cn"] and ref["cn"] == cand["cn"]:
        score += 0.25
    if ref["sans"]:
        overlap = len(ref["sans"] & cand["sans"])
        if overlap:
            score += 0.25 * overlap / len(ref["sans"])
    return score


def _score_candidate(host: str, reference: dict, ip: str, ctx: _RunCtx) -> Optional[dict]:
    """Probe the candidate IP (direct + host-header) across web ports; return the
    best confirmed match >= threshold, mirroring unwaf's verification loop."""
    best: Optional[dict] = None
    port_timeout = max(2.0, min(ctx.timeout / 5.0, 5.0))  # unwaf: timeout/5, floor 2s
    for port in WEB_PORTS:
        if not _port_open(ip, port, port_timeout):
            continue  # closed/filtered — don't spend HTTP + TLS timeouts on it
        scheme = "https" if port in _TLS_PORTS else "http"
        url = f"{scheme}://{_url_host(ip)}:{port}"
        cert = _compare_certs(host, ip, port, ctx) if port in _TLS_PORTS else 0.0
        for method, host_header in (("direct", ""), ("host-header", host)):
            resp = _fetch(url, host_header, ctx)
            if resp is None or resp["status"] >= 500 or _response_has_waf_headers(resp):
                continue
            html_sim = _compare_html(reference["text"], resp["text"])
            hdr = 0.0 if resp["status"] >= 400 else _compare_headers(reference, resp)
            score = _overall_score(html_sim, cert, hdr, reference["status"], resp["status"]) * 100.0
            # F4: when the fronted host serves no comparable HTML (empty body / a
            # JSON API), the 60% HTML weight is unavailable and the score can't
            # reach the threshold — but an exact TLS match (cert >= 0.5 = serial or
            # CN+SAN) is a definitive same-server signal, so confirm on it.
            cert_definitive = (not reference["text"]) and port in _TLS_PORTS and cert >= 0.5
            passed = score > ctx.threshold or cert_definitive
            eff_score = max(score, cert * 100.0) if cert_definitive else score
            if passed and (best is None or eff_score > best["confidence_score"]):
                best = {
                    "matched_ip": ip, "port": port, "method": method,
                    "confidence_score": round(eff_score, 1),
                    "html_similarity": round(html_sim * 100, 1),
                    "cert_match": round(cert * 100, 1),
                    "header_match": round(hdr * 100, 1),
                    "status_code": resp["status"],
                    "url": url,
                }
    return best


# ---------------------------------------------------------------------------
# Per-host orchestration
# ---------------------------------------------------------------------------

def _gather_candidates(host: str, entry: dict, ctx: _RunCtx, meta: dict) -> Dict[str, str]:
    """Run every enabled source for one host; map ip -> first source. Never raises."""
    domain = _registrable_domain(host)
    favicon = _favicon_hash_for_host(host, entry.get("favicon_hash"), ctx)
    if favicon is not None:
        entry["favicon_hash"] = favicon
    candidates: Dict[str, str] = {}
    methods: Set[str] = set()

    def _run(name: str, method: str, fn):
        try:
            for ip in fn() or []:
                candidates.setdefault(ip, name)
                methods.add(method)
        except Exception as e:  # never-raise per source
            meta.setdefault("errors", {})[name] = str(e)[:200]
            # surface it (e.g. an invalid API key) instead of a silent empty result
            _log("-", f"{host}: source '{name}' failed: {str(e)[:120]}")

    if ctx.settings.get("ORIGIN_DISCOVERY_KEYLESS", True):
        # Keyed by the registrable domain so N fronted subdomains of one domain
        # don't each re-resolve the same ~30 subdomains / SPF+MX / up-to-500 crt.sh
        # SANs (F2). Cache stores only non-empty results (transient failures retry).
        _run("dns", "subdomain", lambda: ctx.cached("od_subdomains", domain, lambda: _discover_via_subdomains(domain, ctx)))
        _run("dns", "email_record", lambda: ctx.cached("od_email", domain, lambda: _discover_via_email_records(domain, ctx)))
        _run("crtsh", "cert_san", lambda: ctx.cached("od_crtsh", domain, lambda: _discover_via_crtsh(domain, ctx)))
    if ctx.settings.get("ORIGIN_DISCOVERY_SCANNERS", True):
        _run("shodan", "favicon_hash", lambda: _discover_via_shodan(host, favicon, ctx))
        _run("censys", "cert_san", lambda: _discover_via_censys(host, ctx))
        _run("fofa", "cert_san", lambda: _discover_via_fofa(host, favicon, ctx))
        _run("zoomeye", "cert_san", lambda: _discover_via_zoomeye(host, favicon, ctx))
        _run("otx", "passive_dns", lambda: _discover_via_otx(domain, ctx))
        _run("virustotal", "passive_dns", lambda: _discover_via_virustotal(domain, ctx))
    if ctx.settings.get("ORIGIN_DISCOVERY_PASSIVE_DNS", True):
        _run("securitytrails", "passive_dns", lambda: _discover_via_securitytrails(domain, ctx))
        _run("viewdns", "passive_dns", lambda: _discover_via_viewdns(domain, ctx))

    meta["methods"] = sorted(methods)
    if not ctx.budget.remaining and not ctx.budget.exhausted_logged:
        ctx.budget.exhausted_logged = True
        meta.setdefault("errors", {})["budget"] = "keyed-search budget exhausted"
        _log("!", "keyed-search budget exhausted; remaining keyed sources skipped this scan")
    return candidates


_METHOD_LABEL = {
    "dns": "subdomain", "crtsh": "cert_san", "shodan": "favicon_hash",
    "censys": "cert_san", "fofa": "cert_san", "zoomeye": "cert_san",
    "otx": "passive_dns", "virustotal": "passive_dns",
    "securitytrails": "passive_dns", "viewdns": "passive_dns",
}


def _process_host(host: str, entry: dict, ctx: _RunCtx) -> Tuple[List[dict], dict]:
    meta: dict = {"candidates": [], "methods": [], "errors": {}}
    candidates = _gather_candidates(host, entry, ctx, meta)
    kept = _dedup_and_filter(candidates, entry, ctx, meta)
    meta["candidates"] = [ip for ip, _ in kept]
    if not kept:
        return [], meta

    # Reference is the in-scope fronted host: follow its canonical redirects so a
    # 301 doesn't yield an empty body (candidate probes below never follow — SSRF).
    reference = (_fetch(f"https://{host}", "", ctx, allow_redirects=True)
                 or _fetch(f"http://{host}", "", ctx, allow_redirects=True))
    if reference is None:
        meta["errors"]["reference"] = "could not fetch the fronted host for comparison"
        return [], meta

    confirmed: List[dict] = []
    with ThreadPoolExecutor(max_workers=ctx.workers) as ex:
        futs = {ex.submit(_score_candidate, host, reference, ip, ctx): (ip, source)
                for ip, source in kept}
        for fut in as_completed(futs):
            ip, source = futs[fut]
            try:
                match = fut.result()
            except Exception:
                match = None
            if not match:
                continue
            confirmed.append({
                "type": "waf_bypass",
                "severity": "high",
                "name": "Origin Server Exposed (CDN Bypass)",
                "subdomain": host,
                "matched_ip": match["matched_ip"],
                "url": match["url"],
                "origin_discovery_method": _METHOD_LABEL.get(source, source),
                "origin_source": source,
                "confidence_score": match["confidence_score"],
                "cdn_fronting": entry.get("cdn_name"),
                "port": match["port"],
                "match_method": match["method"],
                "html_similarity": match["html_similarity"],
                "cert_match": match["cert_match"],
                "header_match": match["header_match"],
                "status_code": match["status_code"],
                "evidence": (f"{host} → {match['matched_ip']}:{match['port']} "
                             f"({source}, {match['method']}, score {match['confidence_score']}%)"),
                "source": "origin_discovery",
            })
            _log("+", f"{host} -> {match['matched_ip']}:{match['port']} "
                      f"(method={_METHOD_LABEL.get(source, source)}, source={source}, "
                      f"score={match['confidence_score']}%)")
    return confirmed, meta


# ---------------------------------------------------------------------------
# Public entrypoints
# ---------------------------------------------------------------------------

def run_origin_discovery_enrichment(combined_result: dict, settings: dict) -> dict:
    """Mutate combined_result['origin_discovery'] and return combined_result."""
    payload = {"confirmed": [], "candidates_meta": {}}
    combined_result["origin_discovery"] = payload

    if not settings.get("ORIGIN_DISCOVERY_ENABLED", False):
        return combined_result

    ctx = _RunCtx(settings)
    fronted = _select_fronted_hosts(combined_result, ctx)
    if not fronted:
        _log("-", "no CDN-fronted hosts in http_probe — nothing to unmask")
        return combined_result

    _log("*", f"selecting {len(fronted)} CDN-fronted host(s); "
              f"threshold={ctx.threshold:.0f}% budget={ctx.budget.remaining} search calls")

    all_confirmed: List[dict] = []
    for host, entry in fronted.items():
        try:
            confirmed, meta = _process_host(host, entry, ctx)
        except Exception as e:  # a host never sinks the whole module
            payload["candidates_meta"][host] = {"errors": {"fatal": str(e)[:200]}}
            _log("!", f"{host}: {e}")
            continue
        all_confirmed.extend(confirmed)
        payload["candidates_meta"][host] = meta

    payload["confirmed"] = all_confirmed
    _log("*" if all_confirmed else "-",
         f"origin discovery complete: {len(all_confirmed)} confirmed origin(s) "
         f"across {len(fronted)} fronted host(s)")
    return combined_result


def run_origin_discovery_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Thread-safe fan-out + test call path: deep-copy, run, return only the payload."""
    snapshot = copy.deepcopy(combined_result)
    run_origin_discovery_enrichment(snapshot, settings)
    return snapshot.get("origin_discovery", {})
