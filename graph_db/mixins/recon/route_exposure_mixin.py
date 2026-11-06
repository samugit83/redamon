"""Route exposure graph updates (plan §7.1).

One session, in order:

(a) ``Endpoint.anon_status`` on the routes recon already had: MATCH, never
    MERGE, so a status never creates a node.
(b) the generated routes that answered with content (``new_endpoints``): new
    Endpoints under an existing BaseURL only. An artifact (a ``.git`` file, an
    archive, a heap dump) never becomes an Endpoint: every Endpoint is
    requested again by later GET consumers (the partial nuclei, cache and
    serialized builders, the agent), which would download what this module
    only touched with HEAD or a Range read.
(c) one :Vulnerability per finding, source="route_exposure". A candidate
    (needs_agent_confirmation) stays severity "info" until the agent's
    CONFIRMS edge promotes it; a signature finding carries its real severity.

The id is identity only (baseurl, path, method, exposure kind): statuses,
signals, the route class and Jev's opinions change between runs, and an id that
moved with them would prune the node and lose its triage state.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse
from graph_db.endpoint_paths import normalize_endpoint_path

#: Jev's opinions (plan §13), replaced on every run so a node never keeps a
#: stale one from a run that asked.
_JEV_PROPS = ("route_jev_kind", "route_jev_kind_confidence", "route_jev_sensitivity",
              "route_jev_source", "route_jev_privacy", "anon_page_class",
              "anon_page_class_confidence", "anon_page_class_source")

#: Finding fields copied onto the node as they are (flat scalars and string lists).
_FINDING_PROPS = (
    "exposure_kind", "vulnerability_type", "route_class", "needs_agent_confirmation",
    "severity", "confidence", "anon_status", "authed_status", "bodies_match",
    "anon_content_class", "anon_size_bucket", "auth_expected_by", "leak_signals",
    "pii_types", "pii_record_estimate", "sensitive_fields", "secret_types",
    "generated_by", "variant_of", "catch_all_check", "signature", "cors_variants",
    "cache_signals", "git_walk_proof", "git_tree_prefix", "evidence_snippet", "http_method",
    "path", "baseurl",
)

_ARTIFACT_KINDS = frozenset({
    "vcs_exposure", "env_file", "config_file", "backup_file", "debug_console",
    "debug_endpoint", "debug_page", "route_catalog", "secret_in_response",
})
_ARTIFACT_DIRS = ("/.git/", "/.svn/", "/.hg/")

_KIND_NAMES = {
    "anonymous_access": "Route answers without authentication",
    "sensitive_data": "Response exposes sensitive data",
    "cors_misconfig": "Credentialed CORS origin reflection",
    "auth_cacheable": "Logged-in content marked cacheable",
    "vcs_exposure": "Exposed version control metadata",
    "env_file": "Exposed environment file",
    "config_file": "Exposed configuration file",
    "backup_file": "Exposed backup file",
    "debug_console": "Exposed debug console",
    "debug_endpoint": "Exposed debug or management endpoint",
    "debug_page": "Detailed error or debug page",
    "route_catalog": "Exposed route catalog",
    "secret_in_response": "Secret in a response",
}


def is_artifact_path(path: str) -> bool:
    low = (path or "").lower() + "/"
    return any(d in low for d in _ARTIFACT_DIRS)


def _vuln_id(user_id: str, project_id: str, baseurl: str, path: str, method: str, kind: str) -> str:
    raw = f"route_exposure_{user_id}_{project_id}_{baseurl}_{path}_{method}_{kind}"
    return "route_exposure_" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def _name(finding: dict) -> str:
    kind = finding.get("exposure_kind") or ""
    return f"{_KIND_NAMES.get(kind, 'Route exposure')}: {finding.get('path') or '/'}"


def _description(finding: dict) -> str:
    kind = finding.get("exposure_kind") or ""
    url = finding.get("endpoint_url") or ""
    if finding.get("needs_agent_confirmation"):
        expected = ", ".join(finding.get("auth_expected_by") or []) or "none"
        leaks = ", ".join(finding.get("leak_signals") or []) or "none"
        return (f"Recon's route exposure scan flagged {url} ({kind}, route class "
                f"{finding.get('route_class') or 'unknown'}): anonymous status "
                f"{finding.get('anon_status', 'n/a')}, logged-in status "
                f"{finding.get('authed_status', 'n/a')}. Auth expected by: {expected}. "
                f"Leak signals: {leaks}. A lead awaiting the agent's confirmation.")
    return (f"Recon's route exposure scan matched the {finding.get('signature') or kind} "
            f"signature at {url} (anonymous status {finding.get('anon_status', 'n/a')}).")


class RouteExposureMixin:
    def update_graph_from_route_exposure(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """Persist the route exposure scan: Endpoint statuses, new Endpoints, Vulnerabilities."""
        stats = {"endpoint_status_set": 0, "endpoints_created": 0, "vulnerabilities_created": 0,
                 "errors": []}
        data = recon_data.get("route_exposure") or {}
        findings = data.get("findings") or []
        statuses = [s for s in data.get("endpoint_status") or []
                    if isinstance(s, dict) and s.get("baseurl") and s.get("path")
                    and isinstance(s.get("anon_status"), int)]
        new_endpoints = [e for e in data.get("new_endpoints") or []
                         if isinstance(e, dict) and e.get("baseurl") and e.get("path")
                         and not is_artifact_path(e["path"])]
        if not (findings or statuses or new_endpoints):
            return stats

        with self.driver.session() as session:
            if statuses:
                try:
                    rows = [{"baseurl": s["baseurl"], "path": normalize_endpoint_path(s["path"]),
                             "method": str(s.get("method") or "GET").upper(),
                             "anon_status": int(s["anon_status"])} for s in statuses]
                    session.run(
                        """
                        UNWIND $rows AS r
                        MATCH (e:Endpoint {path: r.path, method: r.method, baseurl: r.baseurl,
                                           user_id: $user_id, project_id: $project_id})
                        SET e.anon_status = r.anon_status,
                            e.anon_status_at = datetime()
                        """,
                        rows=rows, user_id=user_id, project_id=project_id,
                    )
                    stats["endpoint_status_set"] = len(rows)
                except Exception as e:  # noqa: BLE001
                    stats["errors"].append(f"endpoint status update failed: {e}")

            for endpoint in new_endpoints:
                try:
                    session.run(
                        """
                        MATCH (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                        MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $baseurl,
                                           user_id: $user_id, project_id: $project_id})
                          ON CREATE SET e.source = 'route_exposure', e.created_at = datetime(),
                                        e.category = $category, e.has_parameters = false,
                                        e.query_param_count = 0, e.body_param_count = 0,
                                        e.path_param_count = 0, e.urls_found = 1,
                                        e.url = $url
                        SET e.updated_at = datetime()
                        SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                        SET e.sources = CASE WHEN e.sources IS NULL THEN ['route_exposure']
                                             WHEN 'route_exposure' IN e.sources THEN e.sources
                                             ELSE e.sources + 'route_exposure' END,
                            e.anon_status = $anon_status, e.anon_status_at = datetime(),
                            e.generated_by = $generated_by
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        """,
                        baseurl=endpoint["baseurl"], path=normalize_endpoint_path(endpoint["path"]),
                        url=endpoint["baseurl"].rstrip("/") + endpoint["path"],
                        category=str(endpoint.get("category") or "other"),
                        anon_status=int(endpoint.get("anon_status") or 0),
                        generated_by=str(endpoint.get("generated_by") or ""),
                        user_id=user_id, project_id=project_id,
                    )
                    stats["endpoints_created"] += 1
                except Exception as e:  # noqa: BLE001
                    stats["errors"].append(f"route endpoint failed: {e}")

            for finding in findings:
                try:
                    self._write_route_exposure_finding(session, finding, user_id, project_id)
                    stats["vulnerabilities_created"] += 1
                except Exception as e:  # noqa: BLE001 - one bad finding never fails the batch
                    stats["errors"].append(
                        f"route exposure finding {finding.get('exposure_kind', '?')} failed: {e}")

        if stats["vulnerabilities_created"]:
            print(f"[+][graph-db] Created/updated {stats['vulnerabilities_created']} route exposure "
                  f"finding(s), {stats['endpoints_created']} new endpoint(s)")
        if stats["errors"]:
            print(f"[!][graph-db] route_exposure: {len(stats['errors'])} error(s) during graph update")
        return stats

    def _write_route_exposure_finding(self, session, finding: dict, user_id: str, project_id: str) -> None:
        baseurl = finding.get("baseurl") or ""
        path = normalize_endpoint_path(finding.get("path") or "/")
        method = (finding.get("http_method") or "GET").upper()
        kind = finding.get("exposure_kind") or ""
        if not baseurl or not kind:
            raise ValueError("finding without baseurl or exposure_kind")
        endpoint_url = finding.get("endpoint_url") or (baseurl.rstrip("/") + path)
        props = {k: finding[k] for k in _FINDING_PROPS if finding.get(k) is not None}
        props.update({
            "type": finding.get("vulnerability_type") or "",
            "name": _name(finding),
            "description": _description(finding),
            "matched_at": endpoint_url,
            "host": urlparse(endpoint_url).hostname or "",
            "is_dast_finding": False,
        })
        jev_props = {k: finding[k] for k in _JEV_PROPS if finding.get(k) is not None}
        # An artifact attaches to its BaseURL only: it has no Endpoint (see (b)).
        attach_endpoint = kind not in _ARTIFACT_KINDS and not is_artifact_path(path)
        session.run(
            """
            MERGE (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
              ON CREATE SET v.source = 'route_exposure', v.created_at = datetime()
            SET v += $props, v.updated_at = datetime()
            REMOVE v.route_jev_kind, v.route_jev_kind_confidence, v.route_jev_sensitivity,
                   v.route_jev_source, v.route_jev_privacy, v.anon_page_class,
                   v.anon_page_class_confidence, v.anon_page_class_source
            SET v += $jev_props
            WITH v
            OPTIONAL MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl,
                                        user_id: $user_id, project_id: $project_id})
            WHERE $attach_endpoint
            FOREACH (_ IN CASE WHEN e IS NULL THEN [] ELSE [1] END | MERGE (e)-[:HAS_VULNERABILITY]->(v))
            WITH v
            OPTIONAL MATCH (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
            FOREACH (_ IN CASE WHEN bu IS NULL THEN [] ELSE [1] END | MERGE (bu)-[:HAS_VULNERABILITY]->(v))
            """,
            vuln_id=_vuln_id(user_id, project_id, baseurl, path, method, kind),
            props=props, jev_props=jev_props, path=path, method=method, baseurl=baseurl,
            attach_endpoint=attach_endpoint, user_id=user_id, project_id=project_id,
        )

    def link_route_exposure_user_input(self, user_input_id: str, findings: list,
                                       user_id: str, project_id: str) -> int:
        """UserInput -[:PRODUCED]-> the Vulnerability each finding was written to.

        The partial run deletes a UserInput with no PRODUCED edge as an orphan,
        so without these the URLs an operator typed leave no trace. Returns the
        number of findings linked.
        """
        ids = sorted({
            _vuln_id(user_id, project_id, f["baseurl"], f.get("path") or "/",
                     (f.get("http_method") or "GET").upper(), f["exposure_kind"])
            for f in findings if f.get("baseurl") and f.get("exposure_kind")
        })
        if not ids:
            return 0
        with self.driver.session() as session:
            session.run(
                """
                MATCH (ui:UserInput {id: $ui_id, user_id: $user_id, project_id: $project_id})
                UNWIND $ids AS vid
                MATCH (v:Vulnerability {id: vid, user_id: $user_id, project_id: $project_id})
                MERGE (ui)-[:PRODUCED]->(v)
                """,
                ui_id=user_input_id, ids=ids, user_id=user_id, project_id=project_id,
            )
        return len(ids)
