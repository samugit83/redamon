"""
Cache Poisoning Scanner - Web Cache Deception probe (taxonomy class 10).

Deception needs an AUTHENTICATED page. An attacker crafts a static-looking URL
(``/account/x.css``) that the origin serves as the sensitive page -- it ignores the
appended segment -- but the shared cache stores as a static asset, then reads the
victim's data from the cache with NO session. So this probe only runs when the project
has an auth profile in scope: it fetches the page authenticated, proves it is
personalised, then proves a crafted static-suffix URL is (a) served the sensitive
content by the origin and (b) returned FROM CACHE to an unauthenticated request.

Without the auth half a "deception" verdict is only WCVS's opinion wearing a native
label; this is the native, auth-aware confirmation the taxonomy asks for.
"""
import uuid
from urllib.parse import urlparse, urlunparse

from recon.cache_scan.buster import add_cache_buster
from recon.cache_scan.oracle import response_cache_state
from recon.helpers.auth_profile import auth_header_lines, profile_from_settings

# Static suffixes a cache commonly treats as a cacheable asset while the origin may
# route them to the base page (path confusion). Both the "/" and ";" delimiters are
# tried because caches and origins disagree on which starts the "static file".
_DECEPTION_SUFFIXES = (".css", ".js", ".jpg")

# Authenticated and anonymous reads taken to prove the page is personalised. With
# three of each, a two-variant public page passes about 3% of the time, not 50%.
_PERSONALISATION_SAMPLES = 3


def _auth_headers_for(url: str, settings: dict) -> dict:
    """The in-scope auth headers for this URL's host, or {} when none apply."""
    profile = profile_from_settings(settings)
    if not profile:
        return {}
    host = urlparse(url).hostname or ""
    headers = {}
    for line in auth_header_lines(profile, host, settings):
        name, _, value = line.partition(":")
        if name.strip():
            headers[name.strip()] = value.strip()
    return headers


def deception_vector(delimiter: str, suffix: str) -> str:
    """The finding's vector (`cache_param`): the URL shape that leaked, never the
    plant's random marker. It is an input of the finding id, so it must be the
    same on every run; tooling/scripts/cache_deception_rekey.py builds the same
    string for findings written before."""
    return f"static-suffix:{delimiter}{suffix}"


def _page_url(url: str) -> str:
    """The page a finding is about: the URL without the trailing slash the plant
    URLs drop, so `/account` and `/account/` (the same plant URLs) are one finding,
    and the page an old plant URL names is the one a scan writes now."""
    p = urlparse(url)
    return urlunparse(p._replace(path=p.path.rstrip("/") or "/"))


def _deception_urls(url: str, marker: str):
    """(plant URL, delimiter, suffix) for every shape tried, in a fixed order, so a
    target that leaks through several shapes reports the same one on every run."""
    p = urlparse(url)
    base_path = p.path.rstrip("/")
    for suffix in _DECEPTION_SUFFIXES:
        seg = f"{marker}{suffix}"
        for delimiter in ("/", ";"):                       # /account/x.css, /account;x.css
            yield urlunparse(p._replace(path=f"{base_path}{delimiter}{seg}")), delimiter, suffix


def deception_probe(url: str, oracle_info: dict, session, settings: dict,
                    timeout: int = 10, verify_ssl: bool = True):
    """Return a web-cache-deception finding dict (build_finding shape) or None.

    Runs only with an in-scope auth profile: deception is a leak of AUTHENTICATED
    content, so a native verdict is impossible without a session to plant it.
    `session` must not keep cookies (scanner._build_retry_session): one the
    authenticated responses re-set would ride on the "anonymous" reads, and a cache
    keyed on that cookie would then HIT with the planted copy for us alone.
    """
    auth = _auth_headers_for(url, settings)
    if not auth:
        return None

    def _get(u, headers=None):
        return session.get(u, headers=headers or None, timeout=timeout,
                           verify=verify_ssl, allow_redirects=False)

    try:
        # 1. The page must be personalised: the authenticated view is stable and no
        #    anonymous view matches it. One pair is not enough: a public page that
        #    alternates between two variants (an A/B test, a rotating banner) differs
        #    from itself on one pair half the time, and its cached copy leaks nothing.
        authed = [_get(add_cache_buster(url, "rdmncb", uuid.uuid4().hex[:8]), auth)
                  for _ in range(_PERSONALISATION_SAMPLES)]
        anon = [_get(add_cache_buster(url, "rdmncb", uuid.uuid4().hex[:8]))
                for _ in range(_PERSONALISATION_SAMPLES)]
        authed_body = authed[0].text or ""
        if (any(a.status_code >= 400 for a in authed) or not authed_body
                or any((a.text or "") != authed_body for a in authed[1:])
                or any((n.text or "") == authed_body for n in anon)):
            return None

        # The marker keeps the plant out of any entry a real visitor requests. It is
        # random per run, so it stays in the evidence: the finding is about `url`.
        marker = "rdmn" + uuid.uuid4().hex[:6]
        for dec_url, delimiter, suffix in _deception_urls(url, marker):
            cb = uuid.uuid4().hex[:8]
            # Plant: authed request to the static-looking URL. Vulnerable when the
            # origin ignores the suffix and serves the SAME sensitive page.
            plant = _get(add_cache_buster(dec_url, "rdmncb", cb), auth)
            if plant.status_code >= 400 or (plant.text or "") != authed_body:
                continue
            # Retrieve: SAME URL with NO session. A cache HIT that still returns the
            # sensitive body is the leak -> confirmed deception.
            victim = _get(add_cache_buster(dec_url, "rdmncb", cb))
            if (victim.text or "") == authed_body and response_cache_state(victim) == "hit":
                return {
                    "endpoint_url": _page_url(url),
                    "technique": "cache_deception",
                    "vector_type": "path",
                    "cache_header": "",
                    "cache_param": deception_vector(delimiter, suffix),
                    "impact": "deception",
                    "confidence": 0.95,
                    "confidence_tier": "Confirmed",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "cache_signals": oracle_info.get("signals", []),
                    "cache_buster": cb,
                    "source_engine": "hypothesis",
                    "detection_mode": "deception",
                    "evidence": {
                        "poc_link": dec_url,
                        "curl_verify": f"curl -s '{dec_url}'  # no session -> sensitive body",
                        "differential_change": "authenticated body served from cache to an "
                                               "unauthenticated request via a static-suffix URL",
                    },
                }
    except Exception:  # noqa: BLE001 - a probe must never break the scan
        return None
    return None
