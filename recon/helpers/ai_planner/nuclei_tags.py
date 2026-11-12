"""
Nuclei AI Tag Selector
======================
Replaces the static NUCLEI_TAGS list with a tech-aware tag set chosen by an
LLM based on the aggregated http_probe fingerprint (technologies + Server
headers).

The LLM call is delegated to the agent container's /llm/nuclei-tags endpoint
so the recon image stays free of LLM SDKs and per-user API keys live in one
place. Mirrors the FFuf AI extension planner.

All log lines use the `[symbol][Nuclei-AI]` format so they surface in the
recon drawer SSE stream.
"""

import json
import os
import re
from typing import Dict, List, Optional

import requests

from recon.helpers.ai_planner import agent_llm_gate, agent_jev_gate, internal_key_headers

TEMPLATES_STATS_PATH = '/opt/nuclei-templates-official/TEMPLATES-STATS.json'
MIN_TEMPLATE_COUNT = 50

TAG_REGEX = re.compile(r'^[a-z0-9-]{2,30}$')

HEAD_TIMEOUT = 5
HEAD_PROBE_LIMIT = 5
LLM_TIMEOUT = 30

_FALLBACK_CANDIDATES = (
    'cve', 'xss', 'sqli', 'rce', 'lfi', 'ssrf', 'xxe', 'ssti',
    'oast', 'kev', 'exposure', 'misconfig', 'default-login',
    'unauth', 'auth-bypass', 'takeover',
    'wordpress', 'wp-plugin', 'joomla', 'drupal',
    'apache', 'nginx', 'iis', 'tomcat',
    'java', 'php', 'dotnet', 'nodejs',
    'aws', 'azure', 'gcp',
)

_candidates_cache: Optional[List[str]] = None


def _load_candidates() -> List[str]:
    global _candidates_cache
    if _candidates_cache is not None:
        return _candidates_cache
    try:
        with open(TEMPLATES_STATS_PATH) as f:
            stats = json.load(f)
        tags = [
            t['name']
            for t in stats.get('tags', [])
            if isinstance(t.get('name'), str)
            and t.get('count', 0) >= MIN_TEMPLATE_COUNT
            and TAG_REGEX.match(t['name'])
        ]
        _candidates_cache = sorted(set(tags))
        print(f"[*][Nuclei-AI] Loaded {len(_candidates_cache)} candidate tags from {TEMPLATES_STATS_PATH}")
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        print(f"[!][Nuclei-AI] Could not load {TEMPLATES_STATS_PATH}: {e}. Using fallback list ({len(_FALLBACK_CANDIDATES)} tags).")
        _candidates_cache = list(_FALLBACK_CANDIDATES)
    return _candidates_cache


def _validate_tags(raw: List[str], candidates: List[str]) -> List[str]:
    candidate_set = set(candidates)
    out = []
    for t in raw:
        if not isinstance(t, str):
            continue
        if not TAG_REGEX.match(t):
            continue
        if t not in candidate_set:
            continue
        out.append(t)
    return out


def get_ai_tags(
    tech_fingerprint: Dict[str, List[str]],
    current_tags: List[str],
    model: str,
    max_tags: int = 15,
    user_id: str = '',
    project_id: str = '',
    fallback_urls: Optional[List[str]] = None,
    engine: str = 'llm',
) -> List[str]:
    """
    Ask the agent to prune the Nuclei tag list to ones that match the detected
    tech stack. Never raises -- returns ``current_tags`` on any failure so the
    scan keeps running with the user's static list.

    Args:
        tech_fingerprint: Aggregated {"technologies": [...], "servers": [...]}
            from the http_probe (or from an opportunistic HEAD probe).
        current_tags: User's configured NUCLEI_TAGS, used as the safe fallback.
        model: LLM model id (same format as agentOpenaiModel).
        max_tags: Cap on returned tags.
        user_id, project_id: Forwarded to the agent for per-user LLM key resolution.
        fallback_urls: Optional URL list to HEAD-probe when the fingerprint is
            empty (partial recon with bare user URLs).

    Returns:
        Validated tag list, or ``current_tags`` if the AI was unhelpful.
    """
    _TAG = 'Nuclei-Jev' if engine == 'jev' else 'Nuclei-AI'
    techs = list(tech_fingerprint.get('technologies') or [])
    servers = list(tech_fingerprint.get('servers') or [])

    if not techs and not servers and fallback_urls:
        probe_urls = fallback_urls[:HEAD_PROBE_LIMIT]
        print(f"[*][{_TAG}] No tech in fingerprint; probing {len(probe_urls)} URL(s) for headers...")
        for url in probe_urls:
            try:
                # The first answer's headers are the target's own; a redirect
                # could name a host the RoE exclude, unchecked (R-2).
                r = requests.head(url, allow_redirects=False, timeout=HEAD_TIMEOUT)
                srv = (r.headers.get('Server') or '').lower().split('/')[0].strip()
                pwr = (r.headers.get('X-Powered-By') or '').lower().strip()
                if srv:
                    servers.append(srv)
                if pwr:
                    techs.append(pwr)
            except Exception as e:
                print(f"[!][{_TAG}] HEAD probe failed for {url}: {e}")
        if techs or servers:
            print(f"[*][{_TAG}] HEAD probe yielded servers={sorted(set(servers))} techs={sorted(set(techs))}")

    if not techs and not servers:
        print(f"[!][{_TAG}] No tech fingerprint available -- skipping AI call.")
        return current_tags

    candidates = _load_candidates()

    agent_api_url = os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')
    payload = {
        'technologies': sorted(set(techs)),
        'servers': sorted(set(servers)),
        'current_tags': current_tags,
        'candidates': candidates,
        'model': model,
        'max_tags': max_tags,
        'user_id': user_id,
        'project_id': project_id,
    }
    use_jev = engine == 'jev'
    route = 'jev' if use_jev else 'llm'
    endpoint = f"{agent_api_url}/{route}/nuclei-tags"
    print(f"[*][{_TAG}] Calling agent {endpoint} with model={model} ({len(payload['technologies'])} techs, {len(payload['servers'])} servers, {len(candidates)} candidates)")

    gate = agent_jev_gate() if use_jev else agent_llm_gate()
    if not gate.allowed:
        print(f"[!][{_TAG}] Agent LLM paused (breaker open) - using the fallback.")
        return current_tags
    try:
        resp = requests.post(endpoint, json=payload, headers=internal_key_headers(), timeout=LLM_TIMEOUT)
    except requests.RequestException as e:
        gate.record(exc=e)
        print(f"[!][{_TAG}] Agent request failed: {e}. Using current tags as fallback.")
        return current_tags

    gate.record(resp=resp)
    if resp.status_code != 200:
        print(f"[!][{_TAG}] Agent returned HTTP {resp.status_code}: {resp.text[:200]}. Using current tags as fallback.")
        return current_tags

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!][{_TAG}] Agent returned non-JSON response: {e}. Using current tags as fallback.")
        return current_tags

    raw = data.get('tags', None)
    if raw is None or not isinstance(raw, list):
        print(f"[!][{_TAG}] Agent response missing 'tags' list: {data}. Using current tags as fallback.")
        return current_tags

    validated = _validate_tags(raw, candidates)
    if len(validated) < len(raw):
        rejected = [t for t in raw if t not in validated]
        print(f"[!][{_TAG}] Rejected invalid/non-candidate tags: {rejected}")

    capped = validated[:max_tags]
    if not capped:
        print(f"[!][{_TAG}] Validation produced no usable tags. Using current tags as fallback.")
        return current_tags

    return capped
