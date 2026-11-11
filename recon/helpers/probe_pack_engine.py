"""
Probe-pack engine — a Python reimplementation of the Julius (Praetorian,
Apache-2.0) HTTP fingerprint matcher.

Julius probe packs are declarative YAML descriptions of how to identify an AI /
LLM service from its HTTP responses. This engine loads the vendored packs and
evaluates them against a target, reproducing Julius's Go matcher semantics
exactly so results are comparable.

It is intentionally standalone (no graph, no settings) so the same engine can
later be reused by the ai_guardrail_probe container and the ai_offensive_server
MCP. The only network primitive is `requests`, and every request first takes a
slot of recon's process-wide RoE pacer (recon/helpers/request_pacer.py; inert
with no ceiling).

Matcher semantics (verbatim from the Julius Go source):
  * Rules within one request  -> AND (all must pass).
  * Requests within a probe    -> governed by `require`:
        - "any" (default): first matching request wins.
        - "all": every request must match.
  * Across probes              -> rank matches by `specificity` (desc);
        `port_hint == target_port` only reorders evaluation, ties broken by
        load order.
  * Per-rule:
        - status:         int equality of HTTP status code
        - body.contains:  case-SENSITIVE substring
        - body.prefix:    body startswith (case-sensitive)
        - content-type:   case-INSENSITIVE substring of the Content-Type header
        - header.contains:case-sensitive substring of the named header
        - header.prefix:  named header startswith (case-sensitive)
        - not: true       inverts the rule's final boolean
        - a missing header + not:true  => the rule PASSES
  * models.extract: a jq expression run against the parsed JSON body; only
        string outputs are collected (mirrors gojq behaviour).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import requests

from recon.helpers import request_pacer

try:  # PyYAML is already in the recon image
    import yaml
except Exception:  # pragma: no cover - defensive
    yaml = None


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class MatchRule:
    type: str
    value: Any = None
    negate: bool = False
    header: str = ""


@dataclass
class ProbeRequest:
    path: str = "/"
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    match: list = field(default_factory=list)  # list[MatchRule]


@dataclass
class Probe:
    name: str
    description: str = ""
    category: str = "generic"
    port_hint: int = 0
    specificity: int = 1
    require: str = "any"  # "any" | "all"
    requests: list = field(default_factory=list)  # list[ProbeRequest]
    models: Optional[dict] = None  # {path, method, headers, body, extract}


@dataclass
class ProbeResult:
    name: str
    category: str
    specificity: int
    matched_request_path: str
    model_ids: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def load_probe_packs(packs_dir: str | os.PathLike) -> list[Probe]:
    """Load and parse every *.yaml/*.yml probe pack in a directory.

    Malformed files are skipped (failure-soft); never raises on one bad pack.
    """
    probes: list[Probe] = []
    if yaml is None:
        return probes
    base = Path(packs_dir)
    if not base.is_dir():
        return probes
    for fp in sorted(base.glob("*.y*ml")):
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
            probe = _parse_probe(raw)
            if probe is not None:
                probes.append(probe)
        except Exception:
            # Skip a malformed pack; one bad file must not kill the engine.
            continue
    return probes


def _parse_probe(raw: Any) -> Optional[Probe]:
    if not isinstance(raw, dict) or not raw.get("name"):
        return None
    reqs: list[ProbeRequest] = []
    for r in raw.get("requests") or []:
        if not isinstance(r, dict):
            continue
        rules: list[MatchRule] = []
        for m in r.get("match") or []:
            if not isinstance(m, dict) or not m.get("type"):
                continue
            rules.append(
                MatchRule(
                    type=str(m.get("type")).strip().lower(),
                    value=m.get("value"),
                    negate=bool(m.get("not", False)),
                    header=str(m.get("header") or ""),
                )
            )
        reqs.append(
            ProbeRequest(
                path=r.get("path", "/") or "/",
                method=str(r.get("method", "GET") or "GET").upper(),
                headers=r.get("headers") or {},
                body=r.get("body"),
                match=rules,
            )
        )
    require = str(raw.get("require", "any") or "any").strip().lower()
    if require not in ("any", "all"):
        require = "any"
    return Probe(
        name=str(raw["name"]),
        description=raw.get("description", "") or "",
        category=raw.get("category", "generic") or "generic",
        port_hint=int(raw.get("port_hint", 0) or 0),
        specificity=int(raw.get("specificity", 1) or 1),
        require=require,
        requests=reqs,
        models=raw.get("models") if isinstance(raw.get("models"), dict) else None,
    )


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
def _match_rule(rule: MatchRule, status: int, body: str, headers: dict) -> bool:
    t = rule.type
    if t == "status":
        try:
            result = int(status) == int(rule.value)
        except (TypeError, ValueError):
            result = False
    elif t == "body.contains":
        result = str(rule.value) in (body or "")
    elif t == "body.prefix":
        result = (body or "").startswith(str(rule.value))
    elif t == "content-type":
        ct = ""
        for k, v in (headers or {}).items():
            if k.lower() == "content-type":
                ct = str(v)
                break
        result = str(rule.value).lower() in ct.lower()
    elif t in ("header.contains", "header.prefix"):
        hv = ""
        for k, v in (headers or {}).items():
            if k.lower() == rule.header.lower():
                hv = str(v)
                break
        if t == "header.contains":
            result = str(rule.value) in hv
        else:
            result = hv.startswith(str(rule.value))
    else:
        # Unknown rule type: treat as non-matching (conservative).
        result = False
    return (not result) if rule.negate else result


def _send(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    """One request, never a redirect followed, after a slot of the RoE pacer."""
    request_pacer.acquire()
    resp = session.request(method, url, allow_redirects=False, verify=False, **kwargs)
    request_pacer.back_off_on_429(resp)
    return resp


def _do_request(
    session: requests.Session, base_url: str, req: ProbeRequest, timeout: float
) -> bool:
    url = base_url.rstrip("/") + req.path
    try:
        resp = _send(session, req.method, url, headers=req.headers or None,
                     data=req.body, timeout=timeout)
    except requests.RequestException:
        return False
    # Cap body read to keep memory bounded.
    body = resp.text[:262144] if resp.text else ""
    headers = dict(resp.headers)
    return all(_match_rule(rule, resp.status_code, body, headers) for rule in req.match)


def evaluate_probe(
    session: requests.Session, base_url: str, probe: Probe, timeout: float
) -> Optional[str]:
    """Return the matched request path if the probe matches, else None."""
    if not probe.requests:
        return None
    if probe.require == "all":
        first_path = probe.requests[0].path
        for req in probe.requests:
            if not _do_request(session, base_url, req, timeout):
                return None
        return first_path
    # require == "any": first matching request wins
    for req in probe.requests:
        if _do_request(session, base_url, req, timeout):
            return req.path
    return None


def _extract_models(
    session: requests.Session, base_url: str, models_cfg: dict, timeout: float
) -> list[str]:
    """Run the probe's models.extract jq expression against its models endpoint."""
    if not models_cfg or not models_cfg.get("extract"):
        return []
    path = models_cfg.get("path", "/")
    method = str(models_cfg.get("method", "GET") or "GET").upper()
    try:
        resp = _send(session, method, base_url.rstrip("/") + path,
                     headers=models_cfg.get("headers") or None,
                     data=models_cfg.get("body"), timeout=timeout)
        data = resp.json()
    except Exception:
        return []
    try:
        import jq  # lazy: heavy dep, only when a probe actually extracts models
    except Exception:
        return []
    try:
        out = jq.compile(models_cfg["extract"]).input_value(data).all()
    except Exception:
        return []
    return [x for x in out if isinstance(x, str)]


def run_probe_packs(
    base_url: str,
    probes: list[Probe],
    *,
    target_port: int = 0,
    timeout: float = 10.0,
    user_agent: str = "RedAmon-AISurfaceRecon/1.0",
    extract_models: bool = True,
) -> list[ProbeResult]:
    """Run all probes against base_url, return matches ranked by specificity (desc).

    `target_port` only reorders evaluation (port-hinted probes first); the final
    ordering is by specificity, matching Julius.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})

    ordered = probes
    if target_port:
        ordered = sorted(probes, key=lambda p: 0 if p.port_hint == target_port else 1)

    results: list[ProbeResult] = []
    for probe in ordered:
        matched_path = evaluate_probe(session, base_url, probe, timeout)
        if matched_path is None:
            continue
        model_ids: list[str] = []
        if extract_models and probe.models:
            model_ids = _extract_models(session, base_url, probe.models, timeout)
        results.append(
            ProbeResult(
                name=probe.name,
                category=probe.category,
                specificity=probe.specificity,
                matched_request_path=matched_path,
                model_ids=model_ids,
            )
        )
    results.sort(key=lambda r: r.specificity, reverse=True)
    return results
