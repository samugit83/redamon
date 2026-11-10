"""Shape route-exposure verdicts into ``combined_result["route_exposure"]``.

One flat finding per (route, exposure kind), each mapping to one :Vulnerability
(route_exposure_mixin.py). Only scalars and lists of strings: a map would break
the graph's flat-property rule and land nowhere.
"""

from __future__ import annotations

from recon.route_exposure import signatures
from recon.route_exposure.signals import size_bucket
from recon.serialized_scan.normalizers import safe_snippet

SOURCE = "route_exposure"

#: exposure_kind -> vulnerability_type of the candidate kinds (plan §6.3). Never a
#: security-check type: the triage score model reads `type` before `source`.
CANDIDATE_TYPES = {
    "anonymous_access": "unauthenticated_endpoint",
    "sensitive_data": "sensitive_data_exposure",
    "cors_misconfig": "cors_credentialed_origin_reflection",
    "auth_cacheable": "authenticated_content_cacheable",
}
VULNERABILITY_TYPES = {**CANDIDATE_TYPES, **{k: v[0] for k, v in signatures.KINDS.items()}}

#: Artifacts: a later GET consumer would download them, so they never become
#: Endpoint nodes (plan §7.1 b).
ARTIFACT_KINDS = frozenset(signatures.KINDS)


def build_finding(obs, *, kind: str, route_class: str, auth_expected_by: list,
                  confidence: float, sig: dict | None = None, content=None,
                  extra: dict | None = None) -> dict:
    """One flat finding. ``content`` is the Signals the kind was decided on
    (the anonymous answer's unless the logged-in one carried the data); ``extra``
    carries a v2 rider's or the git walk's flat fields."""
    route = obs.route
    content = content if content is not None else obs.anon_signals
    candidate = kind in CANDIDATE_TYPES
    snippet = obs.snippet
    if not snippet and content.key_paths:
        # Decided on the logged-in answer: described by its keys, like any JSON.
        snippet = "keys: " + ", ".join(content.key_paths[:12])
    finding = {
        "endpoint_url": route.url,
        "baseurl": route.baseurl,
        "path": route.path,
        "http_method": "GET",
        "source": SOURCE,
        "exposure_kind": kind,
        "vulnerability_type": VULNERABILITY_TYPES[kind],
        "route_class": route_class,
        "needs_agent_confirmation": candidate,
        "severity": "info" if candidate else (sig or {}).get("severity", signatures.KINDS[kind][1]),
        "confidence": round(float(confidence), 3),
        "anon_content_class": obs.content_class,
        "anon_size_bucket": size_bucket(int(obs.size or 0)),
        "auth_expected_by": list(auth_expected_by),
        "leak_signals": list(content.leak_signals),
        "pii_types": list(content.pii_types),
        "pii_record_estimate": int(content.pii_record_estimate),
        "sensitive_fields": list(content.sensitive_fields),
        "secret_types": list(obs.anon_signals.secret_types),
        # Display only (graph_db/display_only.py): the secrets the anonymous
        # answer held and their detector names, index by index.
        "secret_values": list(obs.anon_signals.secret_values),
        "secret_value_types": list(obs.anon_signals.secret_value_types),
        "generated_by": route.generated_by,
        "variant_of": route.variant_of,
        "catch_all_check": obs.catch_all_check if obs.catch_all_check in ("passed", "failed") else "n/a",
        "signature": (sig or {}).get("signature", ""),
        "evidence_snippet": safe_snippet((sig or {}).get("evidence") or snippet),
    }
    # None means "not measured": the key is left out so a later SET += never
    # overwrites a value with null.
    if obs.anon_status is not None:
        finding["anon_status"] = int(obs.anon_status)
    if obs.authed_status is not None:
        finding["authed_status"] = int(obs.authed_status)
    if obs.bodies_match is not None:
        finding["bodies_match"] = bool(obs.bodies_match)
    jev_rank = getattr(route, "jev_rank", None)
    if isinstance(jev_rank, (int, float)) and not isinstance(jev_rank, bool):
        finding["route_jev_privacy"] = round(float(jev_rank) * 100)
    for key, value in (extra or {}).items():
        if value not in (None, "", [], {}):
            finding[key] = value
    return finding


def dedup_key(finding: dict) -> tuple:
    """Within-run identity; the same four fields make the graph id (identity only)."""
    return (finding.get("baseurl", ""), finding.get("path", ""),
            finding.get("http_method", "GET"), finding.get("exposure_kind", ""))


def is_artifact(finding: dict) -> bool:
    return finding.get("exposure_kind") in ARTIFACT_KINDS


def build_result(findings: list, *, endpoint_status: list | None = None,
                 new_endpoints: list | None = None, summary: dict | None = None,
                 error: str = "") -> dict:
    """The ``combined_result["route_exposure"]`` payload. Plain JSON only."""
    by_kind: dict = {}
    by_class: dict = {}
    candidates = 0
    for f in findings:
        by_kind[f["exposure_kind"]] = by_kind.get(f["exposure_kind"], 0) + 1
        by_class[f["route_class"]] = by_class.get(f["route_class"], 0) + 1
        candidates += 1 if f.get("needs_agent_confirmation") else 0
    base = {
        "routes_harvested": 0, "routes_generated": 0, "routes_requested": 0, "budget_cut": 0,
        "hosts": 0, "hosts_skipped": 0, "out_of_scope": 0,
        "dropped": {"denied": 0, "catch_all": 0, "wall": 0, "empty": 0, "unsafe": 0},
        "logged_in_compared": 0, "catalogs_followed": 0, "requests_sent": 0,
        "started_at": "", "finished_at": "",
    }
    base.update(summary or {})
    base.update({"candidates": candidates, "findings": len(findings) - candidates,
                 "by_kind": by_kind, "by_route_class": by_class, "error": error})
    return {
        "summary": base,
        "findings": findings,
        "endpoint_status": list(endpoint_status or []),
        # A generated artifact is never an Endpoint, whatever a caller passed.
        "new_endpoints": [e for e in (new_endpoints or [])
                          if not any(d in str(e.get("path", "")).lower() + "/"
                                     for d in ("/.git/", "/.svn/", "/.hg/"))],
    }
