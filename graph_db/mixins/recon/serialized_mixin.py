"""Serialized-object candidate graph updates (plan §5.5).

Writes :Vulnerability candidates with source="serialized_scan" (reusing the
existing Vulnerability label — no new node type). Each candidate carries
needs_agent_confirmation=true and severity="info" until the agent's
deserialization skill confirms it with a proof-typed CONFIRMS edge.

Attachment uses OPTIONAL MATCH, never a bare MATCH: clear_recon_data
DETACH-deletes every Endpoint/BaseURL at run start (base_mixin.py), so a
kept/confirmed candidate can outlive its anchor. OPTIONAL MATCH writes the node
regardless and re-attaches the edge on the next run that re-enumerates the host.

Properties written on each Vulnerability:
    id                        deterministic tenant-scoped hash
    user_id, project_id       tenant isolation (the MERGE key triple)
    source                    "serialized_scan"  (ON CREATE only)
    type / vulnerability_type "insecure_deserialization"
    severity                  "info"  (the quieting mechanism; T4 until proven)
    needs_agent_confirmation  true    (novel lifecycle marker, plan G7)
    confidence                0..1 detector belief that serialization is present
    deser_language            java | php | python | dotnet | ruby
    deser_format              native_java | jackson_json | ... (plan §3)
    deser_transport           cookie | param | header
    deser_location            cookie/param/header name
    deser_encoding_layers     list[str] of decode layers (+ "truncated")
    deser_magic               the matched marker
    evidence_snippet          printable-ASCII, <=120 chars (render-safe)
    name, description         human-readable
    matched_at, host          locator for the UI/report
    deser_jev_format, deser_jev_format_confidence, deser_jev_exploitability,
    deser_jev_source          TypeSafe Jev's assessment, only from a run that
                              asked Jev and got an answer for this blob
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse
from graph_db.endpoint_paths import normalize_endpoint_path

#: Jev's assessment (recon/helpers/ai_planner/serialized_assess.py). Each run
#: replaces them: a run without Jev, or one where Jev could not answer for this
#: blob, clears them, so a node never keeps a stale score from an earlier run.
_JEV_PROPS = ("deser_jev_format", "deser_jev_format_confidence",
              "deser_jev_exploitability", "deser_jev_source")


class SerializedScanMixin:
    def update_graph_from_serialized_scan(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
    ) -> dict:
        """Persist serialized-object candidates as Vulnerability nodes."""
        stats = {
            "vulnerabilities_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        serialized_data = recon_data.get("serialized_scan") or {}
        findings = serialized_data.get("findings") or []
        if not findings:
            return stats

        with self.driver.session() as session:
            for finding in findings:
                try:
                    endpoint_url = finding.get("endpoint_url") or ""
                    deser_format = finding.get("deser_format") or ""
                    magic = finding.get("deser_magic") or ""
                    location = finding.get("deser_location") or ""
                    transport = finding.get("deser_transport") or ""
                    baseurl = finding.get("baseurl") or ""
                    path = normalize_endpoint_path(finding.get("path") or "/")
                    method = (finding.get("http_method") or "GET").upper()
                    if not endpoint_url or not deser_format:
                        continue

                    vuln_id = _vuln_id(user_id, project_id, baseurl, path, location,
                                       deser_format, transport)
                    host = urlparse(endpoint_url).hostname or ""
                    language = finding.get("deser_language") or ""

                    props = {
                        "type": "insecure_deserialization",
                        "vulnerability_type": "insecure_deserialization",
                        "severity": "info",
                        "needs_agent_confirmation": True,
                        "confidence": finding.get("confidence"),
                        "deser_language": language,
                        "deser_format": deser_format,
                        "deser_transport": transport,
                        "deser_location": location,
                        "deser_encoding_layers": finding.get("deser_encoding_layers") or [],
                        "deser_magic": magic,
                        "evidence_snippet": finding.get("evidence_snippet") or "",
                        "name": _finding_name(deser_format, transport),
                        "description": _finding_description(finding, host),
                        "matched_at": endpoint_url,
                        "host": host,
                        "is_dast_finding": False,
                    }
                    # Drop None so SET += never wipes an existing value
                    # (takeover_mixin pattern). created_at stays ON CREATE only;
                    # no triage_*/muted/stale_since here.
                    props = {k: v for k, v in props.items() if v is not None}
                    jev_props = {k: finding[k] for k in _JEV_PROPS if finding.get(k) is not None}

                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $vuln_id, user_id: $user_id,
                                                project_id: $project_id})
                          ON CREATE SET v.source = 'serialized_scan',
                                        v.created_at = datetime()
                        SET v += $props,
                            v.updated_at = datetime()
                        REMOVE v.deser_jev_format, v.deser_jev_format_confidence,
                               v.deser_jev_exploitability, v.deser_jev_source
                        SET v += $jev_props
                        WITH v
                        OPTIONAL MATCH (e:Endpoint {path: $path, method: $method,
                                                    baseurl: $baseurl,
                                                    user_id: $user_id,
                                                    project_id: $project_id})
                        FOREACH (_ IN CASE WHEN e IS NULL THEN [] ELSE [1] END |
                          MERGE (e)-[:HAS_VULNERABILITY]->(v))
                        WITH v
                        OPTIONAL MATCH (bu:BaseURL {url: $baseurl,
                                                    user_id: $user_id,
                                                    project_id: $project_id})
                        FOREACH (_ IN CASE WHEN bu IS NULL THEN [] ELSE [1] END |
                          MERGE (bu)-[:HAS_VULNERABILITY]->(v))
                        """,
                        vuln_id=vuln_id, props=props, jev_props=jev_props, path=path,
                        method=method, baseurl=baseurl, user_id=user_id, project_id=project_id,
                    )
                    stats["vulnerabilities_created"] += 1

                except Exception as e:  # noqa: BLE001 - one bad finding never fails the batch
                    stats["errors"].append(
                        f"serialized finding {finding.get('deser_format', '?')} failed: {e}"
                    )

        if stats["vulnerabilities_created"] > 0:
            print(
                f"[+][graph-db] Created/updated {stats['vulnerabilities_created']} "
                f"serialized-object candidate(s)"
            )
        if stats["errors"]:
            print(f"[!][graph-db] serialized_scan: {len(stats['errors'])} error(s) during graph update")

        return stats


def _vuln_id(user_id: str, project_id: str, baseurl: str, path: str,
             location: str, deser_format: str, transport: str = "") -> str:
    """Tenant-scoped deterministic id (the graph-db-writes MERGE key): one node per
    sink and format, the scanner's dedup key.

    `transport` is in it so a param and a cookie sharing a name stay two nodes.
    The matched marker (deser_magic) is not: it is evidence, and it changes with
    the sample (a PHP object one run, an array the next), which would prune the
    node and recreate it, losing its triage state.
    """
    raw = f"serialized_{user_id}_{project_id}_{baseurl}_{path}_{location}_{deser_format}_{transport}"
    return "serialized_" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def _finding_name(deser_format: str, transport: str) -> str:
    return f"Serialized object candidate: {deser_format} via {transport}"


def _finding_description(finding: dict, host: str) -> str:
    language = finding.get("deser_language") or "unknown"
    magic = finding.get("deser_magic") or "signature"
    transport = finding.get("deser_transport") or "request"
    location = finding.get("deser_location") or ""
    endpoint = finding.get("endpoint_url") or host
    return (
        f"Recon flagged a {language} serialized-object signature ({magic}) in the "
        f"{transport} '{location}' at {endpoint}. Candidate awaiting agent confirmation "
        f"via a non-destructive out-of-band oracle."
    )
