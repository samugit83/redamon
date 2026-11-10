"""
Takeover AI False-Positive Classifier
=====================================
Disambiguates "third-party service unclaimed" pages (real subdomain takeover
candidates) from "WAF block" pages that look identical to subjack/nuclei
fingerprints.

The collision: a WAF gating a subdomain it doesn't recognize returns a 404
or 403 with body text like "The requested resource was not found" -- which
also matches Heroku's "There's nothing here yet" or generic SaaS unclaimed
fingerprints. Static signature matching can't distinguish.

The narrow scope (caller's responsibility): only invoke this classifier when
the takeover scanner already flagged a candidate AND the response carries no
clear vendor cookie/header (Heroku-Request-Id, x-amz-bucket-region, ...). In
that ambiguous middle case, ask the LLM whether the response looks like a
genuine third-party "unclaimed" page or a WAF block page.

The LLM call is delegated to the agent container's /llm/takeover-classify
endpoint so the recon image stays free of LLM SDKs and per-user API keys
live in one place. Mirrors waf_classifier.py and nuclei_response_filter.py.

All log lines use the `[symbol][Takeover-AI]` format so they surface in the
recon drawer SSE stream.
"""

import json
import os
from typing import Dict, Optional

import requests

from recon.helpers.ai_planner import agent_llm_gate, agent_jev_gate, internal_key_headers

# Returned on any failure (network, auth, schema, validation). Keeps the
# call graph defensive: callers always get a usable dict.
SAFE_FALLBACK: Dict = {
    "is_waf_block": False,
    "reason": "",
    "confidence": 0,
    "source": "ai_unavailable",
}

LLM_TIMEOUT = 20
RESPONSE_SAMPLE_BYTES = 4096

# Vendor-specific tokens that prove the response really is from the
# third-party SaaS (NOT a WAF). When any of these appear in the response
# headers/cookies, callers should skip the AI cascade entirely -- the
# takeover finding is already substantiated by the third-party fingerprint.
# Caller-side helper, exported for reuse.
THIRD_PARTY_VENDOR_TOKENS = {
    # Headers (lowercase)
    "headers": (
        "heroku-request-id", "heroku-dyno",
        "x-amz-bucket-region", "x-amz-request-id", "x-amz-id-2",
        "x-github-request-id",
        "x-served-by-netlify", "x-nf-request-id",
        "x-vercel-id", "x-vercel-cache",
        "x-fly-request-id",
        "x-render-origin-server",
        "x-bitbucket-pipeline-id",
        "x-firebase-cache-hit",
    ),
    # Server header values (substring, lowercase)
    "server_tokens": (
        "amazons3", "github.com", "atlassianproxy", "netlify",
        "surge", "vercel", "firebase", "fly/", "render",
    ),
}


def has_third_party_vendor_token(headers: Dict[str, str]) -> bool:
    """Return True if the response carries an unambiguous third-party
    vendor token (proves the page really is the SaaS, not a WAF block).
    Caller should skip the AI cascade in that case."""
    if not headers:
        return False
    lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    for h in THIRD_PARTY_VENDOR_TOKENS["headers"]:
        if h in lower:
            return True
    server = lower.get("server", "")
    for tok in THIRD_PARTY_VENDOR_TOKENS["server_tokens"]:
        if tok in server:
            return True
    return False


def _fingerprint(response_text: str, status_code: int) -> str:
    """Build a cache key from the response shape. Multiple subdomains
    fronted by the same WAF returning identical block pages should
    collapse to one LLM call."""
    body = (response_text or "")[:RESPONSE_SAMPLE_BYTES]
    size_bucket = len(body) // 256
    head = body[:96].encode('utf-8', errors='replace').hex()
    return f"status={status_code}|size={size_bucket}|head={head}"


def _validate_classification(raw, engine: str = 'llm') -> Optional[Dict]:
    """Sanitize the agent response. Returns None on schema mismatch."""
    if not isinstance(raw, dict):
        return None

    is_waf_block = raw.get("is_waf_block")
    if not isinstance(is_waf_block, bool):
        return None

    confidence = raw.get("confidence")
    if not isinstance(confidence, (int, float)):
        return None
    confidence = int(confidence)
    if confidence < 0 or confidence > 100:
        return None

    reason = raw.get("reason") or ""
    if not isinstance(reason, str):
        reason = ""
    reason = reason[:500]
    reason = ''.join(c for c in reason if 0x20 <= ord(c) <= 0x7e)

    return {
        "is_waf_block": is_waf_block,
        "reason": reason,
        "confidence": confidence,
        # Stamped from the engine the CALLER asked for, never from the response
        # body: provenance (detection_method, ai_engine) must not be forgeable
        # by whatever the agent or an injected answer says.
        "source": "jev_classifier" if engine == 'jev' else "ai_classifier",
    }


def classify_takeover_response(
    hostname: str,
    expected_provider: str,
    response_text: str,
    status_code: int,
    headers: Dict[str, str],
    model: str,
    cache: Optional[Dict[str, Dict]] = None,
    user_id: str = '',
    project_id: str = '',
    engine: str = 'llm',
) -> Dict:
    """
    Ask the agent whether *response_text* looks like a third-party SaaS
    "service unclaimed" page (real takeover candidate) or a WAF block
    page disguised as one. Never raises -- returns SAFE_FALLBACK on any
    failure so callers can keep the static finding.

    Args:
        hostname: The subdomain being probed.
        expected_provider: The takeover provider the static fingerprint
            matched (e.g. "heroku", "s3"). Helps the LLM decide whether
            the response actually matches that provider.
        response_text: Captured response body.
        status_code: HTTP status code of the response.
        headers: HTTP response headers.
        model: LLM model id.
        cache: Optional dict keyed by response fingerprint to dedupe.
        user_id, project_id: Forwarded to the agent for per-user LLM key
            resolution.

    Returns:
        Dict with keys: is_waf_block (bool), reason (str), confidence
        (0-100), source (str).
    """
    cache = cache if cache is not None else {}
    _TAG = 'Takeover-Jev' if engine == 'jev' else 'Takeover-AI'

    if not response_text or not response_text.strip():
        return dict(SAFE_FALLBACK)

    fp = _fingerprint(response_text, int(status_code or 0))
    if fp in cache:
        cached = cache[fp]
        print(f"[+][{_TAG}] Cache hit -> waf_block={cached.get('is_waf_block')} "
              f"conf={cached.get('confidence')} ({hostname})")
        return cached

    body_sample = response_text[:RESPONSE_SAMPLE_BYTES]

    # Trim headers to keep payload small; only include the ones useful
    # for vendor classification. Location rides along because the probe
    # judges a 3xx without following it: where it points (a WAF challenge,
    # the provider's claim page) is the model's only sign of what answers
    # there, and it reaches the model as data, never as a request.
    interesting_headers = {}
    for k, v in (headers or {}).items():
        kl = k.lower()
        if kl in ("server", "content-type", "x-powered-by", "set-cookie", "location") \
                or kl.startswith("x-") or kl.startswith("cf-"):
            interesting_headers[k] = v

    agent_api_url = os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')
    payload = {
        'hostname': hostname or '',
        'expected_provider': expected_provider or '',
        'status_code': int(status_code or 0),
        'headers': interesting_headers,
        'response_sample': body_sample,
        'model': model,
        'user_id': user_id,
        'project_id': project_id,
    }
    use_jev = engine == 'jev'
    route = 'jev' if use_jev else 'llm'
    endpoint = f"{agent_api_url}/{route}/takeover-classify"
    print(f"[*][{_TAG}] Calling agent {endpoint} with model={model} "
          f"(host={hostname}, provider={expected_provider}, status={status_code}, body={len(body_sample)}B)")

    gate = agent_jev_gate() if use_jev else agent_llm_gate()
    if not gate.allowed:
        print(f"[!][{_TAG}] Agent LLM paused (breaker open) - using the fallback.")
        return dict(SAFE_FALLBACK)
    try:
        resp = requests.post(endpoint, json=payload, headers=internal_key_headers(), timeout=LLM_TIMEOUT)
    except requests.RequestException as e:
        gate.record(exc=e)
        print(f"[!][{_TAG}] Agent request failed: {e}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    gate.record(resp=resp)
    if resp.status_code != 200:
        print(f"[!][{_TAG}] Agent returned HTTP {resp.status_code}: "
              f"{resp.text[:200]}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!][{_TAG}] Agent returned non-JSON response: {e}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    validated = _validate_classification(data, engine)
    if validated is None:
        print(f"[!][{_TAG}] Agent response failed schema validation: "
              f"{str(data)[:200]}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    cache[fp] = validated

    if validated["is_waf_block"]:
        print(f"[+][{_TAG}] WAF block masquerading as takeover (confidence={validated['confidence']}): "
              f"{validated['reason'][:120]}")
    else:
        print(f"[+][{_TAG}] Genuine {expected_provider or 'third-party'} unclaimed page (confidence={validated['confidence']})")

    return validated
