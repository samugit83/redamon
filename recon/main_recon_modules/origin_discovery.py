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
from recon.helpers.cdn_ranges import edge_cdn_for_ip, edge_from_headers, is_reliable_edge_cdn_name
from recon.helpers.peer_cert import (
    cert_covers as _cert_covers,
    tls_failure_reason as _tls_failure_reason,
    tls_handshake_cert as _tls_handshake_cert,
)
from recon.helpers.public_suffix import org_domain
from recon.helpers import request_pacer

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

# CDN / WAF edge ranges, ASNs and response-header signatures live in
# recon/helpers/cdn_ranges.py, the list every module shares.

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


#: Retry-After is the target's to set: one answer holds every in-process
#: requester back this long at most.
_BACK_OFF_MAX_S = 30.0


def _back_off_if_throttled(resp) -> None:
    """A 429 from a target pushes the next slot of every in-process requester
    back (the RoE clock; inert with no ceiling): Retry-After seconds, else 1 s,
    capped."""
    if getattr(resp, "status_code", None) != 429:
        return
    try:
        seconds = float(resp.headers.get("Retry-After"))
    except (AttributeError, TypeError, ValueError):
        seconds = 1.0
    request_pacer.pacer().back_off(min(_BACK_OFF_MAX_S, max(1.0, seconds)))


class _SearchBudget:
    """Per-scan ceiling on genuine (non-cached) keyed search calls (G3).

    Keyed sources (Shodan/Censys/FOFA/ZoomEye search endpoints) burn query
    credits distinct from the host-lookup credits the sibling enrichers spend.
    A cached hit does NOT draw the budget down.
    """

    def __init__(self, limit: int):
        self._remaining = max(0, int(limit))
        self._refused = 0
        self._lock = threading.Lock()
        self.exhausted_logged = False

    def take(self) -> bool:
        with self._lock:
            if self._remaining <= 0:
                self._refused += 1
                return False
            self._remaining -= 1
            return True

    @property
    def remaining(self) -> int:
        with self._lock:
            return self._remaining

    @property
    def refused(self) -> int:
        """Searches the budget turned away; a host that saw one was not fully checked."""
        with self._lock:
            return self._refused


class _RunCtx:
    """Per-run shared state: rate limiter, budget, the (source, key) cache and
    the fronted hosts' reference certificates."""

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
        from recon.helpers.target_admission import admission_context
        self.redirect_hops_admitted = bool(admission_context(settings).excluded)
        self._cache: Dict[Tuple[str, str], List[str]] = {}
        self._cache_lock = threading.Lock()
        self._misses = 0
        self._ref_certs: Dict[Tuple[str, int], Optional[dict]] = {}
        self._ref_cert_locks: Dict[Tuple[str, int], threading.Lock] = {}

    def reference_cert(self, host: str, port: int, dial) -> Optional[dict]:
        """The fronted host's certificate on ``port``, dialled once per run.

        Every candidate is compared against the same certificate, so one
        handshake to the host serves them all. A failed dial is kept as well:
        an edge that does not serve TLS on a port would otherwise cost one
        timeout per candidate. Candidates checked at the same time wait for
        the first dial instead of each sending one.
        """
        key = (host.lower(), port)
        with self._cache_lock:
            lock = self._ref_cert_locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._ref_certs:
                self._ref_certs[key] = dial()
            return self._ref_certs[key]

    def pace(self) -> None:
        """Before every packet to a target (a connect, a handshake, a GET, a
        redirect hop): the module's own rate, then a slot of the RoE clock
        every in-process requester shares (inert with no ceiling). A search
        API is not the target's traffic: it waits on ``rate`` alone."""
        self.rate.wait()
        request_pacer.acquire()

    def note_miss(self) -> None:
        """A candidate source gave no answer for the host being processed."""
        with self._cache_lock:
            self._misses += 1

    @property
    def misses(self) -> int:
        """Hosts are processed one at a time, so the change across one host's
        gathering is that host's: _process_host compares it before and after."""
        with self._cache_lock:
            return self._misses

    def cached(self, source: str, key: str, producer) -> List[str]:
        """Memoize a per-domain search by (source, key) for the whole run (G3).

        A keyed producer returns a typed CallResult: any ANSWER - hits, or a
        genuine "nothing found" (NO_DATA) - is cached for every later host that
        shares the key, and a failure (timeout, 5xx, refused key, a paused
        source, an exhausted budget) never is, so a transient error cannot
        black out the key for the rest of the run; it counts as a miss for the
        host being processed instead. A keyless producer returns a
        plain list, which cannot tell "none" from "failed", so only a non-empty
        one is cached.
        """
        from recon.helpers.circuit_breaker import CallResult
        ck = (source, key)
        with self._cache_lock:
            if ck in self._cache:
                return self._cache[ck]
        result = producer()
        if isinstance(result, CallResult):
            ips = list(result.data or [])
            if result.answered:
                with self._cache_lock:
                    self._cache[ck] = ips
            else:
                self.note_miss()
            return ips
        ips = list(result or [])
        if ips:
            with self._cache_lock:
                self._cache[ck] = ips
        return ips

    def admit(self, breaker):
        """None when a keyed search may go out; else the typed skip to return.

        The breaker is checked BEFORE the budget, so a paused or refused source
        never draws the keyed-search budget down. A budget refusal leaves the
        breaker's skip count alone, which would cut the whole source: the
        budget counts it, and _process_host cuts only the host it was for.
        """
        from recon.helpers.circuit_breaker import CallResult, Outcome
        if not breaker.allow():
            return CallResult([], Outcome.SKIPPED, breaker.detail)
        if not self.budget.take():
            breaker._release_probe()
            return CallResult([], Outcome.SKIPPED, "search budget exhausted")
        return None


def _run_ctx(settings: dict) -> _RunCtx:
    """The run's one context: a Domain batch's groups share its per-key cache
    and its search budget (a key every group of an org shares is asked once).
    Held in a circuit_breaker run cache, so reset_registry() drops it."""
    from recon.helpers import circuit_breaker
    cache = circuit_breaker.run_cache("origin_discovery_ctx")
    hit, ctx = cache.get("ctx")
    if not hit:
        ctx = _RunCtx(settings)
        cache.put("ctx", ctx)
    return ctx


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
            ctx.pace()
            resp = requests.get(url, timeout=ctx.timeout, verify=False,
                                headers={"User-Agent": _UA}, stream=True)
            _back_off_if_throttled(resp)
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


# httpx's cdn labels that mean plain cloud hosting, where the IP serves the
# application itself: no edge stands in front of it to bypass.
# ("google" is not here: httpx's cdncheck files it under CDN, for Google's
# load balancer and Cloud CDN edge.)
_CLOUD_HOSTING_LABELS = frozenset({
    "aws", "amazon", "azure", "gcp", "google-cloud", "oracle", "oci",
    "digitalocean", "linode", "alibaba", "aliyun", "ibm", "hetzner", "ovh", "vultr",
})


def _is_edge_cdn_label(cdn_name) -> bool:
    """A known edge CDN, or any other CDN label httpx names that is not plain
    cloud hosting (an edge outside the shared list: Bunny, KeyCDN, ...)."""
    name = str(cdn_name or "").strip().lower()
    return bool(name) and (is_reliable_edge_cdn_name(name) or name not in _CLOUD_HOSTING_LABELS)


def _select_fronted_hosts(combined_result: dict, ctx: _RunCtx) -> Dict[str, dict]:
    """CDN/WAF-fronted hosts from http_probe.by_url: an edge CDN named by httpx,
    or an edge IP in a known CDN/WAF range.

    httpx also sets is_cdn for plain cloud hosting (aws, azure, gcp); a host
    served straight from such an IP has no edge to bypass, so its own address
    would be reported as an "exposed origin".

    Returns {host: {favicon_hash, cdn_name, edge_ip, resolved_ips}}.
    """
    http_probe = combined_result.get("http_probe") or {}
    by_url = http_probe.get("by_url") or {}
    fronted: Dict[str, dict] = {}
    for url, info in by_url.items():
        if not isinstance(info, dict):
            continue
        edge_ip = info.get("ip")
        named_edge = bool(info.get("is_cdn")) and _is_edge_cdn_label(info.get("cdn"))
        # A subdomain a person entered in partial recon is fronted on their word.
        is_cdn = named_edge or bool(info.get("user_fronted")) or bool(edge_ip and _ip_in_cdn_ranges(edge_ip))
        if not is_cdn:
            continue
        host = info.get("host") or urlparse(url).hostname
        # An origin serves a NAME the CDN fronts. The edge's own address, which
        # the port scan probes too (naabu reports addresses only), fronts
        # nothing: unmasking it would credit a name's origin to the edge.
        if not host or _is_ip(str(host)):
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
    # current DNS resolution — a candidate equal to it is the edge, not a find.
    # Live resolution only: recorded DNS in a partial run comes from the graph,
    # which keeps historical (pre-CDN) addresses, the very origins sought here.
    for host, entry in fronted.items():
        entry["resolved_ips"] |= _resolve_ips(host)
    return fronted


# ---------------------------------------------------------------------------
# CDN / candidate filtering
# ---------------------------------------------------------------------------

import ipaddress as _ipaddress


def _ip_in_cdn_ranges(ip: str) -> bool:
    """Inside a published CDN / WAF edge prefix: the edge, never the origin."""
    return edge_cdn_for_ip(ip) is not None


def _cdn_flagged_ips(combined_result: dict) -> Set[str]:
    """IPs naabu, httpx or tlsx flagged with an edge CDN this run, and those IP
    attribution tagged shared_edge: a shared edge is never anyone's origin.

    A label for plain cloud hosting (aws, azure, gcp) does not count: those IPs
    serve the application themselves and are exactly where origins are found.
    """
    by_ip = ((combined_result.get("ip_attribution") or {}).get("by_ip")) or {}
    flagged: Set[str] = {ip for ip, entry in by_ip.items()
                         if isinstance(entry, dict) and entry.get("ownership") == "shared_edge"}
    for ip, info in (((combined_result.get("port_scan") or {}).get("by_ip")) or {}).items():
        if isinstance(info, dict) and info.get("is_cdn") and _is_edge_cdn_label(info.get("cdn")):
            flagged.add(ip)
    for info in (((combined_result.get("http_probe") or {}).get("by_url")) or {}).values():
        if (isinstance(info, dict) and info.get("ip") and info.get("is_cdn")
                and _is_edge_cdn_label(info.get("cdn"))):
            flagged.add(info["ip"])
    return flagged


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

def _typed_ips(res, ips):
    """The IPs as a CallResult with the call's outcome (OK only when non-empty)."""
    from recon.helpers.circuit_breaker import CallResult, Outcome
    if res.ok:
        return CallResult(ips, Outcome.OK if ips else Outcome.NO_DATA, res.detail)
    return CallResult([], res.outcome, res.detail)


def _discover_via_shodan(host: str, favicon_hash: Optional[int], ctx: _RunCtx) -> List[str]:
    """Shodan /shodan/host/search on cert-CN, hostname and favicon (unwaf)."""
    key = (ctx.settings.get("SHODAN_API_KEY") or "").strip()
    rotator = ctx.settings.get("SHODAN_KEY_ROTATOR")
    if not key and not (rotator and getattr(rotator, "has_keys", False)):
        return []
    try:
        from recon.main_recon_modules.shodan_enrich import (
            ShodanApiKeyError, _shodan_breaker, _shodan_call,
        )
        from recon.helpers import circuit_breaker as cb
    except Exception:
        return []
    keys = cb.KeyPool(rotator, key, label="Shodan")
    breaker = _shodan_breaker("search")
    queries = [f"ssl.cert.subject.cn:{host}", f"hostname:{host}"]
    if favicon_hash not in (None, "", 0):
        queries.append(f"http.favicon.hash:{favicon_hash}")
    ips: Set[str] = set()
    for q in queries:
        def _producer(q=q):
            skip = ctx.admit(breaker)
            if skip is not None:
                return skip
            res = _shodan_call("/shodan/host/search", keys, {"query": q, "minify": "true"},
                               admitted=True)
            if res.outcome is cb.Outcome.FATAL:
                # surface an invalid/paid-only key to the caller -> meta + log, once:
                # later searches find the breaker open and skip quietly.
                raise ShodanApiKeyError(f"Shodan search refused ({res.detail})",
                                        local=res.local, detail=res.detail)
            found = [m.get("ip_str") for m in ((res.data or {}).get("matches") or [])
                     if isinstance(m, dict) and m.get("ip_str")] if res.ok else []
            return _typed_ips(res, found)
        ips.update(ctx.cached("shodan", q, _producer))
    return list(ips)


def _censys_search_breaker():
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker("censys:search", label="Censys", parent="censys")


def _discover_via_censys(host: str, ctx: _RunCtx) -> List[str]:
    """Censys cert.names search for the host (unwaf fetchIPsFromCensys)."""
    token = (ctx.settings.get("CENSYS_API_TOKEN") or "").strip()
    org = (ctx.settings.get("CENSYS_ORG_ID") or "").strip()
    if not token:
        return []
    from recon.helpers import circuit_breaker as cb
    breaker = _censys_search_breaker()

    def _producer():
        skip = ctx.admit(breaker)
        if skip is not None:
            return skip
        url = "https://api.platform.censys.io/v3/global/search/query"
        if org:
            url += "?organization_id=" + quote_plus(org)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        if org:
            headers["X-Organization-ID"] = org
        body = {"query": f"cert.names: {host}", "page_size": 50}
        ctx.rate.wait()
        res = cb.guarded_call(
            breaker, lambda: requests.post(url, json=body, headers=headers, timeout=ctx.timeout),
            lambda resp: cb.json_result(resp, keyed=True), admitted=True)
        if res.outcome is cb.Outcome.FATAL:
            # surface an invalid / unauthorized Censys token -> meta + log, once
            raise ValueError(f"Censys auth failed ({res.detail})")
        out = []
        if res.ok:
            hits = ((res.data or {}).get("result") or {}).get("hits", []) or []
            for hit in hits:
                if hit.get("ip") and not _ip_in_cdn_ranges(hit["ip"]):
                    out.append(hit["ip"])
                for svc in hit.get("services", []) or []:
                    if svc.get("ip") and not _ip_in_cdn_ranges(svc["ip"]):
                        out.append(svc["ip"])
        return _typed_ips(res, out)

    return ctx.cached("censys", host, _producer)


def _discover_via_fofa(host: str, favicon_hash: Optional[int], ctx: _RunCtx) -> List[str]:
    """FOFA cert + favicon search (RedAmon addition; reuses the fofa client)."""
    key = (ctx.settings.get("FOFA_API_KEY") or "").strip()
    rotator = ctx.settings.get("FOFA_KEY_ROTATOR")
    if not key and not (rotator and getattr(rotator, "has_keys", False)):
        return []
    try:
        from recon.main_recon_modules.fofa_enrich import (
            _fofa_breaker, _fofa_effective_key, _fofa_query, _parse_fofa_rows,
        )
        from recon.helpers import circuit_breaker as cb
    except Exception:
        return []
    if not _fofa_effective_key(ctx.settings, rotator):
        return []
    keys = cb.KeyPool(rotator, key, label="FOFA")
    breaker = _fofa_breaker()
    clauses = [f'cert="{host}"']
    if favicon_hash not in (None, "", 0):
        clauses.append(f'icon_hash="{favicon_hash}"')
    ips: Set[str] = set()
    for clause in clauses:
        def _producer(clause=clause):
            skip = ctx.admit(breaker)
            if skip is not None:
                return skip
            res = _fofa_query(clause, keys, 100, admitted=True)
            rows, _ = _parse_fofa_rows(res.data or {}) if res.answered else ([], 0)
            found = [row.get("ip") for row in rows
                     if isinstance(row, dict) and row.get("ip")
                     and not _ip_in_cdn_ranges(row.get("ip"))]
            if res.answered:
                return _typed_ips(cb.CallResult(res.data, cb.Outcome.OK), found)
            return _typed_ips(res, found)
        ips.update(ctx.cached("fofa", clause, _producer))
    return list(ips)


def _discover_via_zoomeye(host: str, favicon_hash: Optional[int], ctx: _RunCtx) -> List[str]:
    """ZoomEye cert + favicon search (RedAmon addition; reuses the zoomeye client)."""
    key = (ctx.settings.get("ZOOMEYE_API_KEY") or "").strip()
    rotator = ctx.settings.get("ZOOMEYE_KEY_ROTATOR")
    if not key and not (rotator and getattr(rotator, "has_keys", False)):
        return []
    try:
        from recon.main_recon_modules.zoomeye_enrich import _zoomeye_breaker, _zoomeye_query
        from recon.helpers import circuit_breaker as cb
    except Exception:
        return []
    keys = cb.KeyPool(rotator, key, label="ZoomEye")
    breaker = _zoomeye_breaker()
    queries = [f'ssl.cert.subject.cn="{host}"']
    if favicon_hash not in (None, "", 0):
        queries.append(f'iconhash="{favicon_hash}"')
    ips: Set[str] = set()
    for q in queries:
        def _producer(q=q):
            skip = ctx.admit(breaker)
            if skip is not None:
                return skip
            res = _zoomeye_query(q, keys, 100, timeout=ctx.timeout, admitted=True)
            rows = (res.data or ([], 0))[0]
            found = [row.get("ip") for row in rows
                     if isinstance(row, dict) and row.get("ip")
                     and not _ip_in_cdn_ranges(row.get("ip"))]
            if res.answered:
                return _typed_ips(cb.CallResult(rows, cb.Outcome.OK), found)
            return _typed_ips(res, found)
        ips.update(ctx.cached("zoomeye", q, _producer))
    return list(ips)


def _discover_via_otx(domain: str, ctx: _RunCtx) -> List[str]:
    """AlienVault OTX passive DNS A/AAAA records (unwaf fetchIPsFromOTX)."""
    from recon.helpers import circuit_breaker as cb
    from recon.main_recon_modules.otx_enrich import _otx_breaker
    keys = cb.KeyPool(ctx.settings.get("OTX_KEY_ROTATOR"), ctx.settings.get("OTX_API_KEY", "") or "",
                      label="OTX")
    breaker = _otx_breaker("passive_dns")

    def _producer():
        if not breaker.allow():
            return cb.CallResult([], cb.Outcome.SKIPPED, breaker.detail)
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

        def send(key):
            headers = {"User-Agent": _UA}
            if key:
                headers["X-OTX-API-KEY"] = key
            return requests.get(url, headers=headers, timeout=ctx.timeout), bool(key)

        def classify(sent):
            resp, keyed = sent
            return cb.json_result(resp, keyed=keyed)

        res = cb.guarded_call(breaker, send, classify, keys=keys, admitted=True)
        out = []
        if res.ok:
            for rec in (res.data or {}).get("passive_dns", []) or []:
                if rec.get("record_type") in ("A", "AAAA"):
                    ip = rec.get("address")
                    if ip and _is_ip(ip):
                        out.append(ip)
        return _typed_ips(res, out)

    return ctx.cached("otx", domain, _producer)


def _discover_via_virustotal(domain: str, ctx: _RunCtx) -> List[str]:
    """VirusTotal passive DNS (RedAmon addition; reuses the VT resolutions client)."""
    from recon.helpers import circuit_breaker as cb
    from recon.main_recon_modules.virustotal_enrich import _effective_key, _vt_breaker, _vt_call
    key = _effective_key(ctx.settings.get("VIRUSTOTAL_API_KEY", ""), ctx.settings.get("VIRUSTOTAL_KEY_ROTATOR"))
    if not key:
        return []
    keys = cb.KeyPool(ctx.settings.get("VIRUSTOTAL_KEY_ROTATOR"),
                      (ctx.settings.get("VIRUSTOTAL_API_KEY", "") or "").strip(), label="VirusTotal")
    breaker = _vt_breaker()

    def _producer():
        if not breaker.allow():
            return cb.CallResult([], cb.Outcome.SKIPPED, breaker.detail)
        res = _vt_call(f"domains/{domain}/resolutions?limit=40", keys, timeout=ctx.timeout,
                       admitted=True)
        out = []
        if res.ok:
            for item in (res.data or {}).get("data", []) or []:
                ip = (item.get("attributes") or {}).get("ip_address")
                if ip and _is_ip(ip):
                    out.append(ip)
        return _typed_ips(res, out)

    return ctx.cached("virustotal", domain, _producer)


# ---------------------------------------------------------------------------
# Passive-DNS sources (new keys)
# ---------------------------------------------------------------------------

def _passive_dns_breaker(provider: str, endpoint: str):
    from recon.helpers import circuit_breaker as cb
    label = {"securitytrails": "SecurityTrails", "viewdns": "ViewDNS"}.get(provider, provider)
    return cb.get_breaker(f"{provider}:{endpoint}", label=label, parent=provider)


def _discover_via_securitytrails(domain: str, ctx: _RunCtx) -> List[str]:
    """SecurityTrails DNS-A history (unwaf fetchIPsFromSecurityTrails)."""
    from recon.helpers import circuit_breaker as cb
    from recon.main_recon_modules.virustotal_enrich import _effective_key
    key = _effective_key(ctx.settings.get("SECURITYTRAILS_API_KEY", ""),
                         ctx.settings.get("SECURITYTRAILS_KEY_ROTATOR"))
    if not key:
        return []
    keys = cb.KeyPool(ctx.settings.get("SECURITYTRAILS_KEY_ROTATOR"),
                      (ctx.settings.get("SECURITYTRAILS_API_KEY", "") or "").strip(),
                      label="SecurityTrails")
    breaker = _passive_dns_breaker("securitytrails", "history")

    def _producer():
        if not breaker.allow():
            return cb.CallResult([], cb.Outcome.SKIPPED, breaker.detail)
        # Key rides in the APIKEY header — never in the URL, so error logs are safe.
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        res = cb.guarded_call(
            breaker,
            lambda k: requests.get(url, headers={"APIKEY": k, "Accept": "application/json"},
                                   timeout=ctx.timeout),
            lambda resp: cb.json_result(resp, keyed=True), keys=keys, admitted=True)
        out = []
        if res.ok:
            for rec in (res.data or {}).get("records", []) or []:
                for val in rec.get("values", []) or []:
                    ip = val.get("ip")
                    if ip and _is_ip(ip):
                        out.append(ip)
        return _typed_ips(res, out)

    return ctx.cached("securitytrails", domain, _producer)


def _viewdns_classify(resp):
    """ViewDNS reports errors inside a 200 body. Read only to classify."""
    from recon.helpers import circuit_breaker as cb
    res = cb.json_result(resp, keyed=True)
    if not res.ok:
        return res
    response = (res.data or {}).get("response") if isinstance(res.data, dict) else None
    if isinstance(response, dict) and response.get("error") and not response.get("records"):
        text = str(response.get("error")).lower()
        if "key" in text or "credit" in text or "quota" in text:
            return cb.CallResult(None, cb.Outcome.FATAL, "key or quota refused")
        return cb.CallResult(None, cb.Outcome.TRANSIENT, "ViewDNS error body")
    return res


def _discover_via_viewdns(domain: str, ctx: _RunCtx) -> List[str]:
    """ViewDNS IP-history (unwaf fetchIPsFromViewDNS). Key is in the query string."""
    from recon.helpers import circuit_breaker as cb
    from recon.main_recon_modules.virustotal_enrich import _effective_key
    key = _effective_key(ctx.settings.get("VIEWDNS_API_KEY", ""),
                         ctx.settings.get("VIEWDNS_KEY_ROTATOR"))
    if not key:
        return []
    keys = cb.KeyPool(ctx.settings.get("VIEWDNS_KEY_ROTATOR"),
                      (ctx.settings.get("VIEWDNS_API_KEY", "") or "").strip(), label="ViewDNS")
    breaker = _passive_dns_breaker("viewdns", "iphistory")

    def _producer():
        if not breaker.allow():
            return cb.CallResult([], cb.Outcome.SKIPPED, breaker.detail)

        def send(k):
            # ViewDNS puts the key in the URL: only a status or an exception
            # class name ever reaches a detail, never the URL.
            url = (f"https://api.viewdns.info/iphistory/?domain={quote_plus(domain)}"
                   f"&apikey={quote_plus(k)}&output=json")
            return requests.get(url, timeout=ctx.timeout, headers={"User-Agent": _UA})

        res = cb.guarded_call(breaker, send, _viewdns_classify, keys=keys, admitted=True)
        out = []
        if res.ok:
            records = ((res.data or {}).get("response") or {}).get("records") or []
            for rec in records:
                ip = rec.get("ip")
                if ip and _is_ip(ip):
                    out.append(ip)
        return _typed_ips(res, out)

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
                      meta: dict, flagged: Set[str] = frozenset()) -> List[Tuple[str, str]]:
    """Fail-closed filter. `candidates` maps ip -> source. Returns [(ip, source)].

    Drops (and counts): non-routable/metadata/reserved IPs (SSRF, G11), known CDN
    edge IPs (a published edge prefix, or ``flagged`` by this run's scanners),
    IPs equal to the host's current DNS resolution, and RoE-excluded IPs (G2).
    Caps at ORIGIN_DISCOVERY_MAX_CANDIDATES.
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
        if ip in flagged or _ip_in_cdn_ranges(ip):
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


def _pace_each_hop(ctx: _RunCtx):
    """A response hook: requests follows a redirect itself, and the hop it is
    about to send is one more request to the target, so it waits like the first."""
    def hook(response, *_args, **_kwargs):
        if response.is_redirect:
            ctx.pace()
    return hook


def _get_admitted_hops(url: str, headers: dict, ctx: _RunCtx):
    """The reference GET under RoE exclusions: requests would follow the
    fronted host's redirect into an excluded host unchecked, so every hop, the
    first URL included, is checked against the RoE before it is sent
    (hop_guard; R-2). None when a hop is refused: the host then has no
    reference and keeps its earlier findings. Each hop waits like the first:
    the module's rate here, the RoE clock in fetch_hop_by_hop."""
    from recon.helpers.js_recon.hop_guard import fetch_hop_by_hop

    def send(_method, hop_url, *, timeout, headers, allow_redirects):
        ctx.rate.wait()
        return requests.get(hop_url, timeout=timeout, verify=False, allow_redirects=False,
                            headers=headers, stream=True)

    refusal: dict = {}
    # The SSRF guard stays what it was for this fetch: none (the fronted host
    # is in scope); only the RoE is added.
    resp = fetch_hop_by_hop("GET", url, timeout=ctx.timeout, headers=headers,
                            settings={"ROE_ENABLED": ctx.roe_enabled,
                                      "ROE_EXCLUDED_HOSTS": ctx.roe_excluded},
                            url_guard=lambda _url: True, refusal=refusal, send=send,
                            module="origin_discovery")
    if resp is None:
        _log("-", f"reference fetch stopped at redirect hop {refusal.get('hop')} "
                  f"({refusal.get('reason')}): the host keeps its earlier findings")
    return resp


def _fetch(url: str, host_header: str, ctx: _RunCtx, allow_redirects: bool = False) -> Optional[dict]:
    """GET url (optionally with a forged Host), returning text/headers/status.

    allow_redirects defaults False and MUST stay False for candidate-IP probes:
    the candidate is attacker-influenced and a 3xx Location could point at an
    internal or cloud-metadata host the G11 IP filter never saw, turning the
    probe into an SSRF pivot. The trusted reference fetch (the in-scope fronted
    host) passes allow_redirects=True so a canonical 301 (apex->www, http->https)
    doesn't collapse its body and destroy the HTML-similarity signal; under
    RoE exclusions only through hops the RoE admits (_get_admitted_hops).

    That trusted reference fetch also returns the raw page (its ``<script
    src>`` are where the site's own file is found) and the URL it ended on,
    which a relative src resolves against.
    """
    headers = {"User-Agent": _UA}
    if host_header:
        headers["Host"] = host_header
    extra = {"hooks": {"response": _pace_each_hop(ctx)}} if allow_redirects else {}
    try:
        if allow_redirects and ctx.redirect_hops_admitted:
            resp = _get_admitted_hops(url, headers, ctx)
            if resp is None:
                return None
        else:
            ctx.pace()
            resp = requests.get(url, timeout=ctx.timeout, verify=False,
                                allow_redirects=allow_redirects, headers=headers, stream=True, **extra)
        _back_off_if_throttled(resp)
        body = resp.raw.read(_MAX_HTML_BYTES, decode_content=True) or b""
        status = resp.status_code
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        cookies = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else resp.headers.get("Set-Cookie", "")
        final_url = getattr(resp, "url", None) or url
        resp.close()
        out = {"text": _extract_text(body), "status": status, "headers": hdrs, "cookies": cookies}
        if allow_redirects:
            out.update({"html": body.decode("utf-8", "replace"), "final_url": str(final_url)})
        return out
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# The site's own build file (item 7): a fingerprint urlscan can search, and a
# stronger live check for every source
# ---------------------------------------------------------------------------

#: A file is big enough to fingerprint whole: a cut file gives a wrong SHA256.
_MAX_OWN_FILE_BYTES = 20 * 1024 * 1024
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)""", re.I)
#: A build code: 8 or more letters and digits (at least one digit) after ".",
#: "-" or "_", right before ".js" (app.8f3a91c2.js, index-BXy7a9Qe.js).
_BUILD_CODE_RE = re.compile(r"[._-](?=[A-Za-z0-9]*\d)[A-Za-z0-9]{8,}\.js$", re.I)
#: Names of files many sites ship byte for byte: their fingerprint finds
#: thousands of unrelated visits (hash: of jquery-3.7.1 returned 10,000+).
_SHARED_FILE_WORDS = ("framework", "webpack", "runtime", "polyfill", "vendor", "chunk-vendors",
                      "jquery", "react", "vue", "angular", "bootstrap", "lodash", "gtag", "analytics")
_PREFERRED_FILE_WORDS = ("main", "app", "index", "bundle")


def _qualifying_name(name: str) -> bool:
    low = name.lower()
    return bool(_BUILD_CODE_RE.search(low)) and not any(w in low for w in _SHARED_FILE_WORDS)


def _own_script(host: str, html: str, base_url: str, js_urls: List[str], in_scope) -> Optional[str]:
    """The site's own build file: on the fronted host or another in-scope host
    (``in_scope(host)`` applies the scope and the RoE), with a build code, not
    a shared framework file. From the reference page's ``<script src>`` first,
    then the crawler's JS list; ``main``/``app``/``index``/``bundle`` first."""
    from urllib.parse import urljoin
    found: List[str] = []
    for src in _SCRIPT_SRC_RE.findall(html or ""):
        found.append(urljoin(base_url or f"https://{host}/", src.strip()))
    found += [u for u in js_urls or [] if isinstance(u, str)]
    kept: List[str] = []
    for url in found:
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        name = (parsed.path or "").rsplit("/", 1)[-1]
        file_host = (parsed.hostname or "").lower()
        if (parsed.scheme in ("http", "https") and file_host and _qualifying_name(name)
                and (file_host == host.lower() or in_scope(file_host)) and url not in kept):
            kept.append(url)
    if not kept:
        return None
    preferred = [u for u in kept if any(urlparse(u).path.rsplit("/", 1)[-1].lower().startswith(w)
                                        for w in _PREFERRED_FILE_WORDS)]
    return (preferred or kept)[0]


def _file_sha256(url: str, host_header: str, ctx: _RunCtx, from_edge_ok: bool = False) -> Optional[str]:
    """SHA256 of the uncompressed body (what urlscan indexes), or None: a
    redirect is never followed and a body over 20 MB is skipped. A suspect's
    answer that carries an edge's headers went through the CDN, so it proves
    no bypass; the site's own copy, read from the fronted host, always does
    (``from_edge_ok``)."""
    import hashlib
    if not is_url_safe_to_probe(url):
        return None
    headers = {"User-Agent": _UA}
    if host_header:
        headers["Host"] = host_header
    try:
        ctx.pace()
        resp = requests.get(url, timeout=ctx.timeout, verify=False, allow_redirects=False,
                            headers=headers, stream=True)
        _back_off_if_throttled(resp)
        try:
            if resp.status_code != 200 or (not from_edge_ok and edge_from_headers(
                    {k.lower(): v for k, v in resp.headers.items()}) is not None):
                return None
            body = resp.raw.read(_MAX_OWN_FILE_BYTES + 1, decode_content=True) or b""
        finally:
            resp.close()
    except requests.RequestException:
        return None
    if not body or len(body) > _MAX_OWN_FILE_BYTES:
        return None
    return hashlib.sha256(body).hexdigest()


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
    return edge_from_headers(resp.get("headers")) is not None


def _fetch_peer_cert(host_or_ip: str, sni: str, port: int, timeout: int) -> Optional[dict]:
    """TLS-dial host_or_ip:port with SNI=sni, return {serial, cn, sans} or None."""
    try:
        return _tls_handshake_cert(host_or_ip, sni, port, timeout)
    except (OSError, ssl.SSLError, ValueError):
        return None


def _compare_certs(host: str, ip: str, port: int, ctx: _RunCtx) -> float:
    def dial(target: str) -> Optional[dict]:
        ctx.pace()
        return _fetch_peer_cert(target, host, port, timeout=min(ctx.timeout, 5))

    ref = ctx.reference_cert(host, port, lambda: dial(host))
    if not ref:
        return 0.0
    cand = dial(ip)
    if not cand:
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


# A candidate whose default certificate is not the target's is likely a shared
# edge serving the brand by name: never above Medium (severity is High at 80).
_SHARED_EDGE_MAX_CONFIDENCE = 79.0


def _default_cert_check(host: str, ip: str, port: int, ctx: _RunCtx) -> Tuple[str, str]:
    """The certificate ``ip`` presents to a client that sends no SNI.

    A dedicated origin answers with its own certificate; a shared edge answers
    with a generic or another tenant's one, even though it serves the brand's
    page and certificate when asked by name. Returns (status, detail), status
    one of "target", "foreign" or "not_checked". A check that could not run is
    never evidence either way.

    The candidate came from passive sources and is untrusted: the routability
    guard is applied again right before the dial, nothing it returns is
    followed, and the dial obeys the RoE, the module's rate limit, the RoE
    ceiling and host health.
    """
    from recon.helpers import circuit_breaker as cb
    if is_non_routable_ip(ip):
        return "not_checked", "non-routable address"
    if ctx.roe_enabled and _is_roe_excluded(ip, ctx.roe_excluded):
        return "not_checked", "excluded by the rules of engagement"
    target = f"https://{_url_host(ip)}:{port}"
    if not cb.host_health.allow(target):
        return "not_checked", "host marked unreachable"
    ctx.pace()
    try:
        cert = _tls_handshake_cert(ip, None, port, min(ctx.timeout, 5))
    except (OSError, ssl.SSLError, ValueError) as e:
        cb.host_health.record_failure(target, e)
        return "not_checked", _tls_failure_reason(e, port)
    cb.host_health.record_alive(target)
    if not cert:
        return "not_checked", "no certificate presented"
    domain = (org_domain(host) or host or "").lower()
    return ("target", "") if domain and _cert_covers(cert, domain) else ("foreign", "")


def _confirm_candidate(host: str, reference: dict, ip: str, ctx: _RunCtx,
                       own_file: Optional[dict] = None) -> Optional[dict]:
    """Score the candidate; if it passes, weigh its default certificate in."""
    match = _score_candidate(host, reference, ip, ctx, own_file=own_file)
    if not match:
        return None
    port = match["port"] if match["port"] in _TLS_PORTS else 443
    status, detail = _default_cert_check(host, ip, port, ctx)
    if status == "foreign":
        match["confidence_score"] = min(match["confidence_score"], _SHARED_EDGE_MAX_CONFIDENCE)
        match["default_cert_note"] = "default certificate does not belong to the target"
    elif status == "target":
        match["default_cert_note"] = "default certificate belongs to the target"
    else:
        match["default_cert_note"] = f"default certificate: not checked ({detail})"
    return match


#: An origin that served the site's own build file byte for byte is the site.
_FILE_MATCH_MIN_CONFIDENCE = 85.0


def _score_candidate(host: str, reference: dict, ip: str, ctx: _RunCtx,
                     own_file: Optional[dict] = None) -> Optional[dict]:
    """Probe the candidate IP (direct + host-header) across web ports; return the
    best confirmed match >= threshold, mirroring unwaf's verification loop.

    With the host's own build file (``own_file``: url path, its host, SHA256),
    the attempt with the best page score, passing or not, is asked for that
    file once: the same bytes confirm at 85 or more, even for a single-page app
    whose reference page has no text to compare."""
    best: Optional[dict] = None
    best_attempt: Optional[dict] = None
    port_timeout = max(2.0, min(ctx.timeout / 5.0, 5.0))  # unwaf: timeout/5, floor 2s
    for port in WEB_PORTS:
        # A connect is a packet to the candidate like any fetch: same rate limits.
        ctx.pace()
        if not _port_open(ip, port, port_timeout):
            continue  # closed/filtered — don't spend HTTP + TLS timeouts on it
        scheme = "https" if port in _TLS_PORTS else "http"
        url = f"{scheme}://{_url_host(ip)}:{port}"
        cert = _compare_certs(host, ip, port, ctx) if port in _TLS_PORTS else 0.0
        for method, host_header in (("direct", ""), ("host-header", host)):
            resp = _fetch(url, host_header, ctx)
            # A 403 from the candidate is a deny wall: two identical "access
            # denied" pages say nothing about bypassing anything. Another 4xx
            # (an API origin's 401/404 at /) is scored like any page.
            if (resp is None or resp["status"] >= 500 or resp["status"] == 403
                    or _response_has_waf_headers(resp)):
                continue
            html_sim = _compare_html(reference["text"], resp["text"])
            hdr = 0.0 if resp["status"] >= 400 else _compare_headers(reference, resp)
            score = _overall_score(html_sim, cert, hdr, reference["status"], resp["status"]) * 100.0
            attempt = {
                "matched_ip": ip, "port": port, "method": method,
                "confidence_score": round(score, 1),
                "html_similarity": round(html_sim * 100, 1),
                "cert_match": round(cert * 100, 1),
                "header_match": round(hdr * 100, 1),
                "status_code": resp["status"],
                "url": url,
            }
            if best_attempt is None or score > best_attempt["confidence_score"]:
                best_attempt = attempt
            # F4: when the fronted host serves no comparable HTML (empty body / a
            # JSON API), the 60% HTML weight is unavailable and the score can't
            # reach the threshold — but an exact TLS match (cert >= 0.5 = serial or
            # CN+SAN) is a definitive same-server signal, so confirm on it. Two
            # empty bodies compare as identical, so without that match there is
            # nothing to confirm.
            cert_definitive = (not reference["text"]) and port in _TLS_PORTS and cert >= 0.5
            if not reference["text"] and not cert_definitive:
                continue
            passed = score > ctx.threshold or cert_definitive
            eff_score = max(score, cert * 100.0) if cert_definitive else score
            if passed and (best is None or eff_score > best["confidence_score"]):
                best = {**attempt, "confidence_score": round(eff_score, 1)}
    if own_file and best_attempt is not None:
        base = best or best_attempt
        port = base["port"]
        scheme = "https" if port in _TLS_PORTS else "http"
        sha = _file_sha256(f"{scheme}://{_url_host(ip)}:{port}{own_file['path']}",
                           own_file["host"], ctx)
        if sha and sha == own_file["sha256"]:
            best = {**base, "file_match": True,
                    "confidence_score": max(base["confidence_score"], _FILE_MATCH_MIN_CONFIDENCE)}
        elif best is not None:
            best["file_match"] = False
    return best


# ---------------------------------------------------------------------------
# urlscan (item 7): old addresses from the visits the URLScan module already
# downloaded, and the visits that loaded the site's own build file
# ---------------------------------------------------------------------------

_URLSCAN_HISTORY_PER_HOST = 5
_URLSCAN_MAX_FILE_SEARCHES = 3
#: More than this many other registrable domains loaded the "own" file: it is
#: shared after all (a framework that slipped through), so none of it counts.
_SHARED_FILE_MAX_DOMAINS = 5
URLSCAN_HASH_BREAKER = "urlscan:hash"


class _UrlscanSource:
    """Origin Discovery's urlscan source for one run. It only proposes
    suspects; the module's filter and live check decide. It never submits a
    scan, and the queries hold only a fingerprint or a file name."""

    def __init__(self, combined_result: dict, ctx: _RunCtx):
        settings = ctx.settings
        self.ctx = ctx
        self.api_key = settings.get("URLSCAN_API_KEY", "") or ""
        self.key_rotator = settings.get("URLSCAN_KEY_ROTATOR")
        self.entries = [e for e in ((combined_result.get("urlscan") or {}).get("entries") or [])
                        if isinstance(e, dict)]
        self.js_urls = [u for u in ((combined_result.get("resource_enum") or {}).get("js_urls") or [])
                        if isinstance(u, str)]
        self._combined = combined_result
        self._lock = threading.Lock()
        self._searches = 0
        self._by_sha: Dict[str, List[Tuple[str, str]]] = {}

    def in_scope(self, host: str) -> bool:
        from graph_db.mixins.recon.scope import scan_root_for_host
        h = (host or "").lower()
        if not h or (self.ctx.roe_enabled and _is_roe_excluded(h, self.ctx.roe_excluded)):
            return False
        try:
            return bool(scan_root_for_host(h, self._combined))
        except Exception:  # noqa: BLE001
            return False

    def history(self, host: str, entry: dict, flagged: Set[str]) -> List[Tuple[str, str]]:
        """Clue 1: the addresses visits of exactly this host recorded, newest
        first, without the edge and the host's current addresses, at most 5."""
        resolved = entry.get("resolved_ips") or set()
        rows = sorted((e for e in self.entries
                       if (e.get("domain") or "").lower() == host.lower() and e.get("ip")),
                      key=lambda e: e.get("scan_time") or "", reverse=True)
        out: List[Tuple[str, str]] = []
        for e in rows:
            ip = str(e["ip"])
            if ip in resolved or ip in flagged or _ip_in_cdn_ranges(ip) or any(ip == o for o, _ in out):
                continue
            out.append((ip, (e.get("scan_time") or "")[:10]))
            if len(out) >= _URLSCAN_HISTORY_PER_HOST:
                break
        return out

    def own_file(self, host: str, reference: Optional[dict]) -> Optional[dict]:
        """The host's own build file, downloaded once: {url, path, host, name, sha256}."""
        if not reference:
            return None
        url = _own_script(host, reference.get("html") or "", reference.get("final_url") or "",
                          self.js_urls, self.in_scope)
        if not url:
            _log("-", f"{host}: no own file")
            return None
        parsed = urlparse(url)
        sha = _file_sha256(url, "", self.ctx, from_edge_ok=True)
        if not sha:
            return None
        return {"url": url, "path": parsed.path + (f"?{parsed.query}" if parsed.query else ""),
                "host": (parsed.hostname or "").lower(), "name": parsed.path.rsplit("/", 1)[-1],
                "sha256": sha}

    def _search(self, query: str, host: str) -> Optional[list]:
        """The visits found, or None when the cap or the budget refused the search."""
        with self._lock:
            refused = self._searches >= _URLSCAN_MAX_FILE_SEARCHES
            if not refused:
                self._searches += 1
        if refused or not self.ctx.budget.take():
            self.ctx.note_miss()
            return None
        from recon.main_recon_modules import urlscan_enrich as us
        results = us.urlscan_search(
            query, self.api_key, max_results=100, key_rotator=self.key_rotator,
            breaker_key=URLSCAN_HASH_BREAKER, caller="hash", root=host, page=False,
            local_refusals=True, budget=us.search_budget(self.ctx.settings))
        return [r for r in results if isinstance(r, dict)]

    def _filter(self, results: list) -> List[Tuple[str, str]]:
        """Keep a visit whose page is a bare IP or an in-scope host; other
        domains are counted, never stored or probed."""
        kept: List[Tuple[str, str]] = []
        others: Set[str] = set()
        for r in results:
            page = r.get("page") or {}
            domain = (page.get("domain") or "").lower()
            ip = str(page.get("ip") or "")
            if not domain or not ip:
                continue
            if _is_ip(domain) or self.in_scope(domain):
                kept.append((ip, (((r.get("task") or {}).get("time")) or "")[:10]))
            else:
                others.add(org_domain(domain) or domain)
        if len(others) > _SHARED_FILE_MAX_DOMAINS:
            _log("-", f"shared file: {len(others)} other domains loaded it; its visits are ignored")
            return []
        return kept

    def file_suspects(self, host: str, own: Optional[dict]) -> Tuple[List[Tuple[str, str]], str]:
        """Clue 2: hash:<sha256>, then filename:"<name>" only when the hash
        search found nothing. Hosts sharing the file share the search."""
        if not own:
            return [], ""
        with self._lock:
            if own["sha256"] in self._by_sha:
                return self._by_sha[own["sha256"]], "urlscan_hash"
        source = "urlscan_hash"
        results = self._search(f"hash:{own['sha256']}", host)
        if results is not None and not results and _BUILD_CODE_RE.search(own["name"]):
            source = "urlscan_filename"
            results = self._search(f'filename:"{own["name"]}"', host)
        if results is None:
            # Not an answer: a host sharing the file asks again, and is cut too.
            return [], source
        suspects = self._filter(results)
        with self._lock:
            self._by_sha[own["sha256"]] = suspects
        return suspects, source


def _urlscan_source_on(settings: dict) -> bool:
    # URLScan off means neither the URLScan module nor Origin Discovery
    # contacts urlscan, whatever this switch says (presets and the API set
    # settings without the form).
    return bool(settings.get("ORIGIN_DISCOVERY_URLSCAN", True) and settings.get("URLSCAN_ENABLED"))


# ---------------------------------------------------------------------------
# Per-host orchestration
# ---------------------------------------------------------------------------

_KEY_FROM_HOST = object()


def _gather_candidates(host: str, entry: dict, ctx: _RunCtx, meta: dict,
                       key=_KEY_FROM_HOST, urlscan: Optional[_UrlscanSource] = None,
                       own_file: Optional[dict] = None,
                       flagged: Set[str] = frozenset()) -> Dict[str, str]:
    """Run every enabled source for one host; map ip -> first source. Never raises.

    ``key`` is the name the domain-keyed sources (SPF/MX, crt.sh, the
    ``<word>.<key>`` wordlist, passive DNS) query: from ``_candidate_key_rule``,
    else the host's registrable domain. An IP literal, a name on a public
    suffix, or a None key gets none of them, so only the host-keyed scanners run.
    """
    domain = org_domain(host) if key is _KEY_FROM_HOST else key
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
            ctx.note_miss()
            meta.setdefault("errors", {})[name] = str(e)[:200]
            # surface it (e.g. an invalid API key) instead of a silent empty result
            _log("-", f"{host}: source '{name}' failed: {str(e)[:120]}")

    # First: the cheapest and most specific source, so the candidate cap
    # never pushes its suspects out. The visit date rides in meta.
    if urlscan is not None:
        seen = meta.setdefault("urlscan_seen", {})

        def _history():
            found = urlscan.history(host, entry, flagged)
            for ip, when in found:
                seen.setdefault(ip, when)
            return [ip for ip, _ in found]

        def _file(kind: str):
            def run():
                suspects, source = urlscan.file_suspects(host, own_file)
                if source != kind:
                    return []
                for ip, when in suspects:
                    seen.setdefault(ip, when)
                return [ip for ip, _ in suspects]
            return run
        _run("urlscan_history", "ip_history", _history)
        _run("urlscan_hash", "file_hash", _file("urlscan_hash"))
        _run("urlscan_filename", "file_name", _file("urlscan_filename"))

    if domain and ctx.settings.get("ORIGIN_DISCOVERY_KEYLESS", True):
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
        if domain:
            _run("otx", "passive_dns", lambda: _discover_via_otx(domain, ctx))
            _run("virustotal", "passive_dns", lambda: _discover_via_virustotal(domain, ctx))
    if domain and ctx.settings.get("ORIGIN_DISCOVERY_PASSIVE_DNS", True):
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
    "urlscan_history": "ip_history", "urlscan_hash": "file_hash", "urlscan_filename": "file_name",
}


def _candidate_key_rule(combined_result: dict):
    """host -> the candidate key (§4.9, REC-30).

    The org when the org is in scope (a group has it as its scan root, or
    ownership was proven at <prefix>.<org>), else the group's own scan root:
    the active probes then never reach an org-derived candidate the operator
    did not put in scope. A file without scope groups (a legacy file, partial
    recon, IP mode) keeps the host's registrable domain.
    """
    from recon.helpers.org_work import org_in_scope
    metadata = combined_result.get("metadata") or {}
    groups = combined_result.get("scope_groups") or []
    scan_root = str(metadata.get("root_domain") or combined_result.get("domain") or "").lower()
    org = str(metadata.get("org_domain") or "").lower()
    if not groups or not org or not scan_root or metadata.get("ip_mode"):
        return org_domain
    if org == scan_root or org_in_scope(org, groups):
        return lambda host: org if org_domain(host) else None
    _log("*", f"candidate key: {scan_root} (org not in scope)")

    def _scan_root_key(host):
        h = str(host or "").lower()
        under = h == scan_root or h.endswith("." + scan_root)
        return scan_root if under and org_domain(h) else None
    return _scan_root_key


def _reference(host: str, ctx: _RunCtx) -> Optional[dict]:
    # The in-scope fronted host: follow its canonical redirects so a 301
    # doesn't yield an empty body (candidate probes never follow: SSRF).
    return (_fetch(f"https://{host}", "", ctx, allow_redirects=True)
            or _fetch(f"http://{host}", "", ctx, allow_redirects=True))


def _own_file_source(ctx: _RunCtx, combined_result: dict, urlscan: Optional[_UrlscanSource]):
    """The own-file lookup the live check uses for every source, with or
    without the urlscan switch."""
    return urlscan if urlscan is not None else _UrlscanSource(combined_result, ctx)


#: Why a fronted host was not fully checked: the reason its coverage gap gives.
_CUT_BUDGET = "keyed-search budget exhausted"
_CUT_SOURCE = "a candidate source did not answer"
_CUT_REFERENCE = "the fronted host did not answer the reference fetch for comparison"
_CUT_CHECK = "a candidate check failed"
_CUT_CRASH = "processing the host failed"


def _process_host(host: str, entry: dict, ctx: _RunCtx, key=_KEY_FROM_HOST,
                  flagged: Set[str] = frozenset(), urlscan: Optional[_UrlscanSource] = None,
                  files: Optional[_UrlscanSource] = None) -> Tuple[List[dict], dict]:
    """The host's confirmed origins and its meta. ``meta["unchecked"]`` names
    why the host was not fully checked: a source or a candidate the run never
    asked would otherwise read as "no origin", and its findings be pruned."""
    meta: dict = {"candidates": [], "methods": [], "errors": {}}
    misses, refused = ctx.misses, ctx.budget.refused
    reference = own = None
    if urlscan is not None:
        # The file search needs the reference page's scripts: the same request, earlier.
        reference = _reference(host, ctx)
        own = urlscan.own_file(host, reference)
    candidates = _gather_candidates(host, entry, ctx, meta, key=key, urlscan=urlscan,
                                    own_file=own, flagged=flagged)
    if ctx.budget.refused > refused:
        meta["unchecked"] = _CUT_BUDGET
    elif ctx.misses > misses:
        meta["unchecked"] = _CUT_SOURCE
    elif urlscan is not None and reference is None:
        meta["unchecked"] = _CUT_REFERENCE
    kept = _dedup_and_filter(candidates, entry, ctx, meta, flagged=flagged)
    meta["candidates"] = [ip for ip, _ in kept]
    if not kept:
        return [], meta

    if reference is None:
        reference = _reference(host, ctx)
        if reference is not None and files is not None:
            own = files.own_file(host, reference)
    if reference is None:
        meta["errors"]["reference"] = "could not fetch the fronted host for comparison"
        meta["unchecked"] = _CUT_REFERENCE
        return [], meta
    if own:
        meta["own_file"] = own["path"]
    seen = meta.get("urlscan_seen") or {}

    confirmed: List[dict] = []
    with ThreadPoolExecutor(max_workers=ctx.workers) as ex:
        futs = {ex.submit(_confirm_candidate, host, reference, ip, ctx, own): (ip, source)
                for ip, source in kept}
        for fut in as_completed(futs):
            ip, source = futs[fut]
            try:
                match = fut.result()
            except Exception:
                meta.setdefault("unchecked", _CUT_CHECK)
                match = None
            if not match:
                continue
            seen_at = seen.get(ip) if source.startswith("urlscan") else None
            parts = [source] + ([f"seen {seen_at}"] if seen_at else []) + [
                match["method"], f"score {match['confidence_score']}%"]
            if match.get("file_match"):
                parts.append(f"same {own['name']}")
            confirmed.append({
                "type": "waf_bypass",
                "severity": "high" if match["confidence_score"] >= 80 else "medium",
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
                "evidence": (f"{host} → {match['matched_ip']}:{match['port']} ({', '.join(parts)})"
                             + (f"; {match['default_cert_note']}" if match.get("default_cert_note") else "")),
                "source": "origin_discovery",
                **({"file_match": bool(match.get("file_match")), "own_file": own["path"]} if own else {}),
                **({"urlscan_seen_at": seen_at} if seen_at else {}),
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

    # Its whole job is to find and probe origin addresses behind an edge, which
    # by design are not in an IP-mode target list (B-08).
    if (combined_result.get("metadata") or {}).get("ip_mode") or settings.get("IP_MODE"):
        _log("-", "skipped in IP mode: the origins it would probe are not targets")
        return combined_result

    ctx = _run_ctx(settings)
    key_for = _candidate_key_rule(combined_result)
    fronted = _select_fronted_hosts(combined_result, ctx)
    if not fronted:
        _log("-", "no CDN-fronted hosts in http_probe — nothing to unmask")
        return combined_result
    from recon.helpers import circuit_breaker as cb
    od_scope = cb.scope(_KEYED_PROVIDERS, label="Origin", unit="search(es)")

    _log("*", f"selecting {len(fronted)} CDN-fronted host(s); "
              f"threshold={ctx.threshold:.0f}% budget={ctx.budget.remaining} search calls")

    flagged = _cdn_flagged_ips(combined_result)
    urlscan = _UrlscanSource(combined_result, ctx) if _urlscan_source_on(settings) else None
    files = _own_file_source(ctx, combined_result, urlscan)
    all_confirmed: List[dict] = []
    for host, entry in fronted.items():
        try:
            confirmed, meta = _process_host(host, entry, ctx, key=key_for(host), flagged=flagged,
                                            urlscan=urlscan, files=files)
        except Exception as e:  # a host never sinks the whole module
            payload["candidates_meta"][host] = {"errors": {"fatal": str(e)[:200]},
                                                "unchecked": _CUT_CRASH}
            _log("!", f"{host}: {e}")
            continue
        all_confirmed.extend(confirmed)
        payload["candidates_meta"][host] = meta

    payload["confirmed"] = all_confirmed
    _log("*" if all_confirmed else "-",
         f"origin discovery complete: {len(all_confirmed)} confirmed origin(s) "
         f"across {len(fronted)} fronted host(s)")
    _note_unchecked_hosts(payload["candidates_meta"])
    # A provider it could not ask cuts its own findings: keep the previous ones.
    od_scope.finish("origin_discovery", sources=["origin_discovery"], payload=payload)
    return combined_result


def _note_unchecked_hosts(candidates_meta: Dict[str, dict]) -> None:
    """Keep the earlier origin findings of every host this run did not fully check.

    Cut for origin_discovery alone (the other tools did re-check these hosts),
    so a host checked to the end with no origin still prunes. Never raises.
    """
    by_reason: Dict[str, List[str]] = {}
    for host, meta in candidates_meta.items():
        reason = (meta or {}).get("unchecked")
        if reason:
            by_reason.setdefault(reason, []).append(host)
    if not by_reason:
        return
    from recon.helpers import circuit_breaker as cb
    for reason, hosts in sorted(by_reason.items()):
        cb.note_degraded("origin_discovery", hosts=sorted(hosts), host_source="origin_discovery",
                         source_only_hosts=True, reason=reason)
    _log("!", f"{sum(len(h) for h in by_reason.values())} fronted host(s) not fully checked "
              f"({'; '.join(sorted(by_reason))}): their earlier origin findings are kept")


# Every keyed provider origin discovery asks, by breaker key prefix.
_KEYED_PROVIDERS = ("shodan", "censys", "fofa", "zoomeye", "otx", "virustotal",
                    "securitytrails", "viewdns", "urlscan")


def run_origin_discovery_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Thread-safe fan-out + test call path: deep-copy, run, return only the payload."""
    snapshot = copy.deepcopy(combined_result)
    run_origin_discovery_enrichment(snapshot, settings)
    return snapshot.get("origin_discovery", {})
