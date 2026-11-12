"""
FFuf AI Extension Planner
=========================
Replaces the static FFUF_EXTENSIONS list with per-target extensions chosen by
an LLM based on HTTP response headers (Server, X-Powered-By, etc.).

Inspired by ffufai (https://github.com/jthack/ffufai). The LLM call is
delegated to the agent container's /llm/ffuf-extensions endpoint so the
recon image stays free of LLM SDKs and per-user API keys live in one place.

All log lines use the `[symbol][FFuf-AI]` format so they surface in the
recon drawer SSE stream.
"""

import json
import os
import re
from typing import Dict, List, Optional

import requests

from recon.helpers.ai_planner import agent_llm_gate, agent_jev_gate, internal_key_headers

SAFE_FALLBACK = ['.bak', '.old', '.config', '.zip']
EXT_REGEX = re.compile(r'^\.[a-z0-9]{1,8}$')
FINGERPRINT_HEADERS = ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version')
HEAD_TIMEOUT = 10
LLM_TIMEOUT = 20


def _fingerprint(headers: Dict[str, str]) -> str:
    """Build a cache key from the headers that actually disclose tech stack."""
    parts = []
    lower = {k.lower(): v for k, v in headers.items()}
    for h in FINGERPRINT_HEADERS:
        v = lower.get(h.lower(), '')
        parts.append(f"{h}={v}")
    return '|'.join(parts)


def _validate_extensions(raw: List[str]) -> List[str]:
    """Reject anything that doesn't look like a normal file extension.
    Defends against prompt-injection through the Server header."""
    return [e for e in raw if isinstance(e, str) and EXT_REGEX.match(e)]


def get_ai_extensions(
    target_url: str,
    model: str,
    max_extensions: int = 6,
    cache: Optional[Dict[str, List[str]]] = None,
    user_id: str = '',
    project_id: str = '',
    engine: str = 'llm',
) -> List[str]:
    """
    Probe the target with HEAD, ask the agent for fitting extensions,
    validate, and return them. Never raises -- returns SAFE_FALLBACK on any
    failure. Returns an empty list only if the LLM legitimately decides no
    extensions are appropriate (e.g. /static/ paths).

    Args:
        target_url: Full URL to fingerprint (FUZZ keyword stripped if present).
        model: Model identifier in the same format as agentOpenaiModel.
        max_extensions: Cap on number of extensions returned.
        cache: Optional dict for cross-call deduplication keyed by header
               fingerprint. Pass the same dict across all targets in a scan.
        user_id, project_id: Forwarded to the agent so per-user LLM provider
               keys can be resolved.

    Returns:
        List of extensions like ['.php', '.bak'] (each beginning with a dot).
    """
    cache = cache if cache is not None else {}
    _TAG = 'FFuf-Jev' if engine == 'jev' else 'FFuf-AI'
    agent_api_url = os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')

    clean_url = target_url.replace('FUZZ', '').rstrip('/')
    print(f"[*][{_TAG}] Planning extensions for {clean_url}")

    try:
        # The first answer's headers are the target's own; a redirect could
        # name a host the RoE exclude, unchecked (R-2).
        head_resp = requests.head(clean_url, allow_redirects=False, timeout=HEAD_TIMEOUT)
        headers = dict(head_resp.headers)
    except Exception as e:
        print(f"[!][{_TAG}] HEAD request failed for {clean_url}: {e}. Using safe fallback.")
        return SAFE_FALLBACK[:max_extensions]

    fp = _fingerprint(headers)
    server = headers.get('Server', '<none>')
    powered = headers.get('X-Powered-By', '<none>')
    print(f"[*][{_TAG}] Headers: Server={server!r} X-Powered-By={powered!r}")
    print(f"[*][{_TAG}] Fingerprint: {fp}")

    if fp in cache:
        cached = cache[fp]
        print(f"[+][{_TAG}] Cache hit -> {cached}")
        return cached

    payload = {
        'url': clean_url,
        'headers': headers,
        'model': model,
        'max_extensions': max_extensions,
        'user_id': user_id,
        'project_id': project_id,
    }
    use_jev = engine == 'jev'
    route = 'jev' if use_jev else 'llm'
    endpoint = f"{agent_api_url}/{route}/ffuf-extensions"
    print(f"[*][{_TAG}] Calling agent {endpoint} with model={model}")

    gate = agent_jev_gate() if use_jev else agent_llm_gate()
    if not gate.allowed:
        print(f"[!][{_TAG}] Agent LLM paused (breaker open) - using the fallback.")
        return SAFE_FALLBACK[:max_extensions]
    try:
        resp = requests.post(endpoint, json=payload, headers=internal_key_headers(), timeout=LLM_TIMEOUT)
    except requests.RequestException as e:
        gate.record(exc=e)
        print(f"[!][{_TAG}] Agent request failed: {e}. Using safe fallback.")
        return SAFE_FALLBACK[:max_extensions]

    gate.record(resp=resp)
    if resp.status_code != 200:
        print(f"[!][{_TAG}] Agent returned HTTP {resp.status_code}: {resp.text[:200]}. Using safe fallback.")
        return SAFE_FALLBACK[:max_extensions]

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!][{_TAG}] Agent returned non-JSON response: {e}. Using safe fallback.")
        return SAFE_FALLBACK[:max_extensions]

    raw = data.get('extensions', None)
    if raw is None:
        print(f"[!][{_TAG}] Agent response missing 'extensions' key: {data}. Using safe fallback.")
        return SAFE_FALLBACK[:max_extensions]

    if not isinstance(raw, list):
        print(f"[!][{_TAG}] Agent returned non-list extensions: {raw!r}. Using safe fallback.")
        return SAFE_FALLBACK[:max_extensions]

    validated = _validate_extensions(raw)
    if len(validated) < len(raw):
        rejected = [e for e in raw if e not in validated]
        print(f"[!][{_TAG}] Rejected invalid extensions (regex): {rejected}")

    capped = validated[:max_extensions]
    cache[fp] = capped

    if not capped:
        print(f"[+][{_TAG}] Agent says no extensions for this target (path likely static).")
    else:
        print(f"[+][{_TAG}] Selected extensions for {clean_url}: {capped}")

    return capped
