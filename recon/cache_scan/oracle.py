"""
Cache Poisoning Scanner — Cache oracle (Phase 1 of the native engine).

Before any poison test we must answer: is this URL actually served through a
cache, and can we reliably tell a HIT from a MISS? If there's no cache, there's
nothing to poison — we skip the target and avoid wasting (and risking) requests.

Detection is primarily header-based (the FP-safe signal) across a broad set of
CDN/proxy fingerprints. When a target sits behind a *silent* cache (one that
strips or never emits cache-status headers — common with default Varnish/nginx
or security-hardened CDNs), header detection alone yields a false negative, so
we fall back to a behavioural probe: ask twice across a short delay and check
whether the origin's `Date` header is frozen (a cache replays a stored response
with its original Date; a live origin advances it). This is NOT response-time
inference (WCVS's `-stime`, deliberately disabled) — it reads a server-generated
header, which is far more reliable than latency deltas.
"""

import hashlib
import re
import time

import requests

# Headers that carry an explicit HIT/MISS *status* token. Presence proves a
# cache layer; the value is classified into hit / miss / stale / uncacheable.
_CACHE_STATUS_HEADERS = [
    "x-cache",            # generic / CloudFront / Akamai (TCP_HIT) / Squid
    "cf-cache-status",    # Cloudflare
    "x-cache-status",     # nginx proxy_cache (HIT/MISS/EXPIRED/STALE/UPDATING/REVALIDATED)
    "x-drupal-cache",     # Drupal
    "x-varnish-cache",    # Varnish (when a VCL exposes a HIT/MISS string)
    "x-proxy-cache",      # generic reverse proxies
    "x-cache-lookup",     # Squid
    "x-varnish",          # Varnish default: numeric id(s) — two ids = a cache hit
    "x-served-by",        # Fastly (cache node — presence implies caching)
    "x-cache-hits",       # Fastly hit counter
    "fastly-debug-digest",# Fastly
    "x-iinfo",            # Imperva / Incapsula
]

# Headers whose mere presence reveals a cache/CDN layer (no hit/miss token).
_CACHE_PRESENCE_HEADERS = [
    "via",                       # near-universal proxy/cache marker (Varnish, Squid, CloudFront, …)
    "surrogate-control",         # Fastly / Akamai edge directives
    "cdn-cache-control",         # standardized CDN cache-control
    "cloudflare-cdn-cache-control",  # Cloudflare tiered cache
    "warning",                   # RFC stale-response warnings (110/111)
    "x-cdn",                     # generic CDN marker
]

_HIT_TOKENS = ("hit",)
# Cacheable-but-not-currently-served-from-cache (or recently was).
_MISS_TOKENS = ("miss", "expired")
# Served from cache, just stale/being-refreshed — still proves caching.
_STALE_TOKENS = ("stale", "updating", "revalidated")
# Cache layer present but explicitly NOT caching this response. Crucially,
# Cloudflare's "dynamic"/"none" mean uncacheable — they must NOT count as cacheable.
_UNCACHEABLE_TOKENS = ("dynamic", "bypass", "pass", "uncacheable", "no-cache", "none")

# Matches both max-age (browser+shared) and s-maxage (shared/CDN-only) directives.
_MAX_AGE_RE = re.compile(r"(?:s-maxage|max-age)=(\d+)")


def _positive_max_age(cache_control_low: str) -> bool:
    """True if Cache-Control carries a non-zero max-age or s-maxage (shared cache)."""
    return any(int(v) > 0 for v in _MAX_AGE_RE.findall(cache_control_low))


def _classify_status(name: str, value: str) -> str:
    """Map a cache-status header value to hit | miss | stale | uncacheable | ''.

    '' means the header is present but its value is unrecognised (still a cache
    layer — the caller treats that as cacheable on presence).
    """
    low = value.lower()
    # Varnish default header is numeric ids: two ids => served from cache.
    if name == "x-varnish":
        ids = [t for t in low.split() if t.isdigit()]
        if len(ids) >= 2:
            return "hit"
        if len(ids) == 1:
            return "miss"
        return ""
    if any(t in low for t in _HIT_TOKENS):
        return "hit"
    if any(t in low for t in _STALE_TOKENS):
        return "stale"
    if any(t in low for t in _MISS_TOKENS):
        return "miss"
    if any(t in low for t in _UNCACHEABLE_TOKENS):
        return "uncacheable"
    return ""


def _body_hash(resp: requests.Response) -> str:
    body = getattr(resp, "text", "") or ""
    return hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()


def _behavioral_probe(url, session, timeout, verify_ssl, delay, sleep_fn) -> tuple:
    """Detect a *silent* cache (no cache headers) via a frozen-Date probe.

    Request the URL, wait `delay` seconds, request again. A live origin sets a
    fresh `Date` each time; a cache replays the stored response with its original
    Date. So an identical Date across the gap — together with an identical body —
    is strong evidence of caching without any cache-status header.

    Returns (cacheable: bool, indicator: str, signals: [str]).
    """
    try:
        r1 = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
        d1 = {k.lower(): v for k, v in r1.headers.items()}.get("date", "")
        h1 = _body_hash(r1)
        if not d1:
            return False, "", []  # no Date to compare — can't infer
        sleep_fn(delay)
        r2 = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
        d2 = {k.lower(): v for k, v in r2.headers.items()}.get("date", "")
        h2 = _body_hash(r2)
        if d1 and d1 == d2 and h1 == h2:
            return True, "behavioral:frozen-date", [f"date frozen across {delay}s: {d1}"]
    except requests.RequestException:
        return False, "", []
    return False, "", []


def _certificate_refused(exc: BaseException) -> bool:
    """The host answered the handshake and this client refused its
    certificate (the R-48 rule): a live host, not one that never answered."""
    try:
        from recon.helpers import circuit_breaker as cb
        return cb.is_certificate_refused(exc)
    except Exception:  # noqa: BLE001 - unknown: report it as no answer, as before
        return False


def detect_cache_oracle(url: str, session: requests.Session, timeout: int = 10,
                        verify_ssl: bool = True, *, behavioral: bool = True,
                        behavioral_delay: float = 1.1, sleep_fn=time.sleep,
                        max_probes: int = 3) -> dict:
    """Probe a URL and decide whether a usable cache oracle exists.

    Sends up to `max_probes` GETs (at least 2, to catch a MISS->HIT warm-up and
    caches that only store on a later request). If header detection finds no
    cache and `behavioral` is on, runs a frozen-Date fallback for silent caches.

    Returns:
      {
        "cacheable": bool,      # a cache is present / the URL is cache-eligible
        "indicator": str,       # the signal we keyed on (e.g. "cf-cache-status")
        "signals": [str],       # raw header/behavioural evidence collected
        "saw_hit": bool,        # observed content explicitly served from cache
        "cache_layer": bool,    # a cache/CDN is in the path (even if not caching)
        "vary": str,            # Vary header (keyed request headers), if any
        "behavioral": bool,     # detection came from the frozen-Date fallback
      }
    A request that failed returns the same keys with one ``error: ...`` signal,
    plus ``certificate_refused``: the failure was this client refusing the
    host's TLS certificate.
    """
    signals: list[str] = []
    indicator = ""
    saw_hit = False
    cacheable = False
    cache_layer = False
    vary = ""
    # The response itself said it must not be stored (a DYNAMIC/BYPASS status, or a
    # no-store/private Cache-Control). Other signals in the same response (nginx's
    # X-Cache-Status: MISS on every proxied response, a Via) only prove a cache sits
    # in the path, not that it keeps THIS page.
    declined = False

    try:
        for attempt in range(max(2, max_probes)):
            resp = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}

            # Explicit cache-status headers (hit/miss/stale/uncacheable).
            for name in _CACHE_STATUS_HEADERS:
                if name not in hdrs:
                    continue
                val = hdrs[name]
                cache_layer = True
                indicator = indicator or name
                signals.append(f"{name}: {val}")
                state = _classify_status(name, val)
                if state == "hit":
                    saw_hit = True
                    cacheable = True
                elif state == "stale":
                    saw_hit = True   # stale content is still served from cache
                    cacheable = True
                elif state == "miss":
                    cacheable = True
                elif state == "uncacheable":
                    declined = True  # cache layer present, but NOT caching this URL
                else:
                    cacheable = True  # present-but-unknown value => cache layer

            # Presence-only cache/CDN headers.
            for name in _CACHE_PRESENCE_HEADERS:
                if name in hdrs:
                    cache_layer = True
                    cacheable = True
                    indicator = indicator or name
                    signals.append(f"{name}: {hdrs[name]}")

            # Age header: a positive age proves the response sat in a cache.
            if "age" in hdrs:
                signals.append(f"age: {hdrs['age']}")
                indicator = indicator or "age"
                cacheable = True
                cache_layer = True
                try:
                    if int(hdrs["age"]) > 0:
                        saw_hit = True
                except ValueError:
                    pass

            # Cache-Control eligibility: public / non-zero max-age makes the
            # response cache-eligible (unless explicitly private/no-store).
            cc = hdrs.get("cache-control", "")
            if cc:
                low = cc.lower()
                disqualified = "no-store" in low or "private" in low
                declined = declined or disqualified
                if not disqualified and ("public" in low or _positive_max_age(low)):
                    signals.append(f"cache-control: {cc}")
                    indicator = indicator or "cache-control"
                    cacheable = True

            # Vary tells us which request headers are keyed — useful downstream.
            if "vary" in hdrs and not vary:
                vary = hdrs["vary"]
                signals.append(f"vary: {hdrs['vary']}")

            # Done at least 2 requests and the cache is established -> stop. A page that
            # declined caching gets every probe: an edge that stores it anyway may only
            # show its HIT on a later node or request.
            if attempt >= 1 and cacheable and (saw_hit or not declined):
                break

        # A cache that stores the page anyway (an edge rule overriding the origin)
        # shows it with a HIT on a repeat probe, or replays a frozen Date below.
        if declined and not saw_hit:
            cacheable = False

        # Fallback for silent caches that emit no cache headers at all.
        behavioral_hit = False
        if not cacheable and behavioral:
            # A non-positive delay would make the frozen-Date comparison meaningless
            # (two back-to-back requests share a Date second even on a live origin),
            # which is a false-positive risk — fall back to the safe default.
            eff_delay = behavioral_delay if behavioral_delay and behavioral_delay > 0 else 1.1
            b_cacheable, b_indicator, b_signals = _behavioral_probe(
                url, session, timeout, verify_ssl, eff_delay, sleep_fn
            )
            if b_cacheable:
                cacheable = True
                cache_layer = True
                behavioral_hit = True
                indicator = indicator or b_indicator
                signals.extend(b_signals)

        # de-dup signals, keep order
        seen = set()
        signals = [s for s in signals if not (s in seen or seen.add(s))]
    except requests.RequestException as e:
        return {"cacheable": False, "indicator": "", "signals": [f"error: {e}"],
                "saw_hit": False, "cache_layer": False, "vary": "", "behavioral": False,
                "certificate_refused": _certificate_refused(e)}

    return {
        "cacheable": cacheable,
        "indicator": indicator,
        "signals": signals,
        "saw_hit": saw_hit,
        "cache_layer": cache_layer,
        "vary": vary,
        "behavioral": behavioral_hit,
    }


def response_cache_state(resp: requests.Response) -> str:
    """Classify a single response as 'hit' / 'miss' / 'unknown' from headers.

    A hit marker from ANY layer wins. A cache replays the headers it stored, so a
    response it serves can carry an inner layer's MISS: Varnish in front of Drupal
    keeps the stored X-Drupal-Cache: MISS, Cloudflare passes an origin's X-Cache: MISS
    through. Scoring rejects a "miss" outright, so it is returned only when no layer
    says the response came from a cache.
    """
    hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
    states: set[str] = set()
    for name in _CACHE_STATUS_HEADERS:
        if name == "x-varnish" or name not in hdrs:
            continue
        val = hdrs[name]
        if any(t in val for t in _HIT_TOKENS) or any(t in val for t in _STALE_TOKENS):
            states.add("hit")
        elif any(t in val for t in _MISS_TOKENS) or any(t in val for t in _UNCACHEABLE_TOKENS):
            states.add("miss")
    # Varnish default numeric header: two ids => served from cache, one => miss.
    if "x-varnish" in hdrs:
        ids = [t for t in hdrs["x-varnish"].split() if t.isdigit()]
        if len(ids) >= 2:
            states.add("hit")
        elif len(ids) == 1:
            states.add("miss")
    if "age" in hdrs:
        # Age: 0 is no evidence either way: Varnish, Fastly and Apache's mod_cache
        # send it on a hit served within the same second.
        try:
            if int(hdrs["age"]) > 0:
                states.add("hit")
        except ValueError:
            pass
    if "hit" in states:
        return "hit"
    return "miss" if "miss" in states else "unknown"
