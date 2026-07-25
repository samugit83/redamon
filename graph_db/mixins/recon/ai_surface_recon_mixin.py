"""AI Surface Recon graph updates (central ai_surface_recon module).

Writes property annotations onto existing Endpoint / Parameter / Technology
nodes (zero new node labels) plus Vulnerability nodes for MCP tool-poisoning
findings. All AI fields use the ai_* / is_ai_* prefix convention and COALESCE
so re-runs never clobber prior values.

Consumes combined_result["ai_surface_recon"] produced by
recon/main_recon_modules/ai_surface_recon.py.

Part of the recon_mixin.py split.
"""

import json

# NOTE: `recon.helpers.ai_signal_catalog` is imported lazily inside
# `_aisr_annotate_host` (the only consumer). The `recon` package ships in the
# scan containers (which volume-mount it) but NOT in the persistent agent image,
# which bakes in `graph_db` only. A top-level import here would crash-loop the
# agent on startup (ModuleNotFoundError: No module named 'recon').


class AiSurfaceReconMixin:
    def update_graph_from_ai_surface_recon(self, recon_data: dict, user_id: str,
                                           project_id: str) -> dict:
        stats = {"endpoints_annotated": 0, "parameters_created": 0,
                 "vulnerabilities_created": 0, "technologies_promoted": 0,
                 "errors": []}

        data = recon_data.get("ai_surface_recon", {})
        if not data:
            stats["errors"].append("No ai_surface_recon data found")
            return stats

        by_url = data.get("by_url", {}) or {}
        findings = data.get("findings", []) or []
        vector_db = data.get("vector_db", []) or []

        with self.driver.session() as session:
            for base_url, rec in by_url.items():
                try:
                    self._aisr_annotate_host(session, base_url, rec, user_id,
                                             project_id, stats)
                except Exception as e:  # one bad host must not abort the rest
                    stats["errors"].append(f"{base_url}: {e}")

            for finding in findings:
                try:
                    self._aisr_write_finding(session, finding, user_id,
                                             project_id, stats)
                except Exception as e:
                    stats["errors"].append(f"finding {finding.get('id')}: {e}")

            for vdb in vector_db:
                try:
                    self._aisr_promote_vector_db(session, vdb, user_id,
                                                 project_id, stats)
                except Exception as e:
                    stats["errors"].append(f"vdb {vdb.get('host')}: {e}")

        return stats

    # ------------------------------------------------------------------ #
    def _aisr_annotate_host(self, session, base_url, rec, user_id, project_id, stats):
        # Lazy import: `recon` is only present in scan containers, not the agent
        # image. This method is never called from the agent, so the import is safe.
        from recon.helpers import ai_signal_catalog as cat
        chat = rec.get("chat") or {}
        mcp = rec.get("mcp") or {}
        oa = rec.get("openapi") or {}
        julius = rec.get("julius") or {}

        # Representative endpoint path for host-level (chat/openapi/julius) props.
        # Never borrow the MCP path here — the MCP endpoint is written separately
        # as POST /mcp; reusing it would spawn a spurious GET /mcp twin.
        primary_path = chat.get("path") or "/"
        model_family = (chat.get("model_family_guess") or oa.get("model_family_guess")
                        or julius.get("model_family_guess"))

        # Streaming: True if EITHER the live chat probe saw text/event-stream OR
        # the OpenAPI spec advertises streaming. The spec can only promote to True
        # (it never emits an explicit False), so an explicit chat False is kept.
        streaming = chat.get("supports_streaming")
        if oa.get("supports_streaming"):
            streaming = True

        # Discovered model ids (OpenAPI /v1/models + Julius probe-pack extract),
        # order-preserving dedupe, capped. Empty -> None so COALESCE keeps prior.
        model_ids = list(dict.fromkeys(
            (oa.get("model_ids") or []) + (julius.get("model_ids") or [])))[:50] or None

        # 1) Chat / host-level Endpoint annotations. Only when there is a real
        # interface classification or OpenAPI data — a latency-only chat probe
        # must not create a bare host endpoint.
        if chat.get("ai_interface_type") or oa:
            session.run(
                """
                MERGE (b:BaseURL {url: $baseurl, user_id: $uid, project_id: $pid})
                MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $baseurl,
                                   user_id: $uid, project_id: $pid})
                SET b.first_seen = coalesce(b.first_seen, datetime($recon_job_started_at)),
                    b.first_seen_job_id = coalesce(b.first_seen_job_id, $recon_job_id),
                    b.last_seen = datetime($recon_job_started_at),
                    b.last_seen_job_id = $recon_job_id,
                    e.user_id = $uid, e.project_id = $pid,
                    e.source = COALESCE(e.source, 'ai_surface_recon'),
                    e.ai_interface_type     = COALESCE($iface, e.ai_interface_type),
                    e.ai_supports_streaming = COALESCE($streaming, e.ai_supports_streaming),
                    e.ai_supports_tools     = COALESCE($tools, e.ai_supports_tools),
                    e.ai_supports_vision    = COALESCE($vision, e.ai_supports_vision),
                    e.ai_model_family_guess = COALESCE($family, e.ai_model_family_guess),
                    e.ai_model_ids          = COALESCE($model_ids, e.ai_model_ids),
                    e.ai_tool_schema_ref    = COALESCE($schema_ref, e.ai_tool_schema_ref),
                    e.ai_latency_p50_ms     = COALESCE($latency, e.ai_latency_p50_ms),
                    e.updated_at = datetime(),
                    e.first_seen = coalesce(e.first_seen, datetime($recon_job_started_at)),
                    e.first_seen_job_id = coalesce(e.first_seen_job_id, $recon_job_id),
                    e.last_seen = datetime($recon_job_started_at),
                    e.last_seen_job_id = $recon_job_id
                MERGE (b)-[:HAS_ENDPOINT]->(e)
                """,
                path=primary_path, baseurl=base_url, uid=user_id, pid=project_id,
                iface=chat.get("ai_interface_type"),
                streaming=streaming,
                tools=oa.get("supports_tools"),
                vision=oa.get("supports_vision"),
                family=model_family,
                model_ids=model_ids,
                schema_ref=oa.get("tool_schema_ref"),
                latency=chat.get("latency_p50_ms"),
                **self._recon_job_params(),
            )
            stats["endpoints_annotated"] += 1

        # 2) MCP Endpoint + capability props + per-tool Parameters
        if mcp:
            mcp_path = mcp.get("path") or "/mcp"
            session.run(
                """
                MERGE (b:BaseURL {url: $baseurl, user_id: $uid, project_id: $pid})
                MERGE (e:Endpoint {path: $path, method: 'POST', baseurl: $baseurl,
                                   user_id: $uid, project_id: $pid})
                SET b.first_seen = coalesce(b.first_seen, datetime($recon_job_started_at)),
                    b.first_seen_job_id = coalesce(b.first_seen_job_id, $recon_job_id),
                    b.last_seen = datetime($recon_job_started_at),
                    b.last_seen_job_id = $recon_job_id,
                    e.user_id = $uid, e.project_id = $pid,
                    e.source = COALESCE(e.source, 'ai_surface_recon'),
                    e.ai_interface_type        = COALESCE('mcp', e.ai_interface_type),
                    e.ai_mcp_server_name       = COALESCE($name, e.ai_mcp_server_name),
                    e.ai_mcp_server_version    = COALESCE($ver, e.ai_mcp_server_version),
                    e.ai_mcp_protocol_version  = COALESCE($proto, e.ai_mcp_protocol_version),
                    e.ai_mcp_tool_count        = COALESCE($tcount, e.ai_mcp_tool_count),
                    e.ai_mcp_resource_count    = COALESCE($rcount, e.ai_mcp_resource_count),
                    e.ai_mcp_prompt_count      = COALESCE($pcount, e.ai_mcp_prompt_count),
                    e.ai_mcp_caps              = COALESCE($caps, e.ai_mcp_caps),
                    e.ai_mcp_auth_required     = COALESCE($auth, e.ai_mcp_auth_required),
                    e.ai_mcp_tools_hash        = COALESCE($thash, e.ai_mcp_tools_hash),
                    e.ai_mcp_instructions_hash = COALESCE($ihash, e.ai_mcp_instructions_hash),
                    e.updated_at = datetime(),
                    e.first_seen = coalesce(e.first_seen, datetime($recon_job_started_at)),
                    e.first_seen_job_id = coalesce(e.first_seen_job_id, $recon_job_id),
                    e.last_seen = datetime($recon_job_started_at),
                    e.last_seen_job_id = $recon_job_id
                MERGE (b)-[:HAS_ENDPOINT]->(e)
                """,
                path=mcp_path, baseurl=base_url, uid=user_id, pid=project_id,
                name=mcp.get("server_name"), ver=mcp.get("server_version"),
                proto=mcp.get("protocol_version"), tcount=mcp.get("tool_count"),
                rcount=mcp.get("resource_count"), pcount=mcp.get("prompt_count"),
                caps=mcp.get("capabilities"), auth=mcp.get("auth_required"),
                thash=mcp.get("tools_hash"), ihash=mcp.get("instructions_hash"),
                **self._recon_job_params(),
            )
            stats["endpoints_annotated"] += 1

            for tool in mcp.get("tools", []) or []:
                props = ((tool.get("input_schema") or {}).get("properties") or {})
                if not isinstance(props, dict):
                    continue
                for arg_name in props.keys():
                    # The mcp-tools-list dialect resolves against the full tool
                    # object (inputSchema.properties.<arg>), so wrap the inner
                    # schema back under "inputSchema" before resolving.
                    arg_path = cat.resolve_ai_tool_arg_path(
                        {"inputSchema": tool.get("input_schema") or {}},
                        "mcp-tools-list", arg_name)
                    injectable = cat.is_ai_prompt_param(arg_name)
                    session.run(
                        """
                        MERGE (p:Parameter {name: $name, position: 'body',
                               endpoint_path: $epath, baseurl: $baseurl,
                               user_id: $uid, project_id: $pid})
                        SET p.user_id = $uid, p.project_id = $pid,
                            p.is_ai_prompt_injectable = COALESCE($inj, p.is_ai_prompt_injectable),
                            p.ai_tool_arg_path = COALESCE($apath, p.ai_tool_arg_path),
                            p.updated_at = datetime(),
                            p.first_seen = coalesce(p.first_seen, datetime($recon_job_started_at)),
                            p.first_seen_job_id = coalesce(p.first_seen_job_id, $recon_job_id),
                            p.last_seen = datetime($recon_job_started_at),
                            p.last_seen_job_id = $recon_job_id
                        WITH p
                        MATCH (e:Endpoint {path: $epath, method: 'POST', baseurl: $baseurl,
                                           user_id: $uid, project_id: $pid})
                        MERGE (e)-[:HAS_PARAMETER]->(p)
                        """,
                        name=arg_name, epath=mcp_path, baseurl=base_url,
                        uid=user_id, pid=project_id,
                        inj=(True if injectable else None), apath=arg_path,
                        **self._recon_job_params(),
                    )
                    stats["parameters_created"] += 1

        # 3) Julius fingerprint -> confirmed Technology(category=ai-*) linked to the host endpoint
        svc = julius.get("service")
        if svc:
            cat_val = julius.get("category") or "ai-runtime"
            if not str(cat_val).startswith("ai-"):
                cat_val = "ai-runtime"
            session.run(
                """
                MERGE (t:Technology {name: $name, version: '', user_id: $uid, project_id: $pid})
                SET t.category = $cat, t.source = 'ai-surface-recon', t.updated_at = datetime(),
                    t.first_seen = coalesce(t.first_seen, datetime($recon_job_started_at)),
                    t.first_seen_job_id = coalesce(t.first_seen_job_id, $recon_job_id),
                    t.last_seen = datetime($recon_job_started_at),
                    t.last_seen_job_id = $recon_job_id
                WITH t
                MERGE (b:BaseURL {url: $baseurl, user_id: $uid, project_id: $pid})
                MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $baseurl,
                                   user_id: $uid, project_id: $pid})
                ON CREATE SET e.source = 'ai_surface_recon', e.updated_at = datetime()
                SET b.first_seen = coalesce(b.first_seen, datetime($recon_job_started_at)),
                    b.first_seen_job_id = coalesce(b.first_seen_job_id, $recon_job_id),
                    b.last_seen = datetime($recon_job_started_at),
                    b.last_seen_job_id = $recon_job_id,
                    e.first_seen = coalesce(e.first_seen, datetime($recon_job_started_at)),
                    e.first_seen_job_id = coalesce(e.first_seen_job_id, $recon_job_id),
                    e.last_seen = datetime($recon_job_started_at),
                    e.last_seen_job_id = $recon_job_id
                MERGE (b)-[:HAS_ENDPOINT]->(e)
                MERGE (e)-[r:USES_TECHNOLOGY]->(t)
                SET r.detected_by = 'ai-surface-recon-julius',
                    r.confidence = COALESCE(r.confidence, 100)
                """,
                name=svc, cat=cat_val, path=primary_path, baseurl=base_url,
                uid=user_id, pid=project_id,
                **self._recon_job_params(),
            )
            stats["technologies_promoted"] += 1

    # ------------------------------------------------------------------ #
    def _aisr_write_finding(self, session, finding, user_id, project_id, stats):
        props = {
            "id": finding["id"], "user_id": user_id, "project_id": project_id,
            "source": "ai_surface_recon", "type": finding.get("type"),
            "name": finding.get("name"),
            "severity": (finding.get("severity") or "medium").lower(),
            "description": finding.get("name"),
            "evidence": finding.get("evidence"),
            "ai_owasp_llm_id": finding.get("owasp_llm_id"),
            "ai_atlas_technique": finding.get("atlas_technique"),
            "ai_payload_class": "mcp_static",
        }
        # Create the Vulnerability, then attach to the most-specific existing node.
        session.run(
            """
            MERGE (v:Vulnerability {id: $id})
            SET v += $props, v.updated_at = datetime(),
                v.first_seen = coalesce(v.first_seen, datetime($recon_job_started_at)),
                v.first_seen_job_id = coalesce(v.first_seen_job_id, $recon_job_id),
                v.last_seen = datetime($recon_job_started_at),
                v.last_seen_job_id = $recon_job_id
            """,
            id=finding["id"], props=props,
            **self._recon_job_params(),
        )
        base_url = finding.get("baseurl")
        path = finding.get("path") or "/"
        host = ""
        if base_url:
            from urllib.parse import urlparse
            host = urlparse(base_url).hostname or ""
        # Try Endpoint (POST then GET), then BaseURL, then Subdomain, then Domain
        linked = session.run(
            """
            MATCH (v:Vulnerability {id: $id})
            OPTIONAL MATCH (e:Endpoint {baseurl: $baseurl, user_id: $uid, project_id: $pid})
              WHERE e.path = $path
            // Prefer the typed endpoint (e.g. POST /mcp with ai_interface_type)
            // over any bare sibling on the same path.
            WITH v, e ORDER BY (CASE WHEN e.ai_interface_type IS NOT NULL THEN 0 ELSE 1 END) LIMIT 1
            FOREACH (_ IN CASE WHEN e IS NOT NULL THEN [1] ELSE [] END |
                MERGE (e)-[:HAS_VULNERABILITY]->(v))
            RETURN e IS NOT NULL AS linked
            """,
            id=finding["id"], baseurl=base_url, path=path,
            uid=user_id, pid=project_id,
        ).single()
        if not (linked and linked.get("linked")):
            session.run(
                """
                MATCH (v:Vulnerability {id: $id})
                OPTIONAL MATCH (b:BaseURL {url: $baseurl, user_id: $uid, project_id: $pid})
                OPTIONAL MATCH (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
                OPTIONAL MATCH (d:Domain {name: $host, user_id: $uid, project_id: $pid})
                WITH v, coalesce(b, s, d) AS parent
                FOREACH (_ IN CASE WHEN parent IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (parent)-[:HAS_VULNERABILITY]->(v))
                """,
                id=finding["id"], baseurl=base_url, host=host,
                uid=user_id, pid=project_id,
            )
        stats["vulnerabilities_created"] += 1

    # ------------------------------------------------------------------ #
    def _aisr_promote_vector_db(self, session, vdb, user_id, project_id, stats):
        tech = vdb.get("tech_name") or vdb.get("service")
        ip = vdb.get("ip")
        port = vdb.get("port")
        if not tech:
            return
        session.run(
            """
            MERGE (t:Technology {name: $name, version: '', user_id: $uid, project_id: $pid})
            SET t.category = 'ai-vector-db', t.source = 'ai-surface-recon',
                t.updated_at = datetime(),
                t.first_seen = coalesce(t.first_seen, datetime($recon_job_started_at)),
                t.first_seen_job_id = coalesce(t.first_seen_job_id, $recon_job_id),
                t.last_seen = datetime($recon_job_started_at),
                t.last_seen_job_id = $recon_job_id
            WITH t
            OPTIONAL MATCH (ip:IP {address: $ip, user_id: $uid, project_id: $pid})
                          -[:HAS_PORT]->(p:Port {number: $port, user_id: $uid, project_id: $pid})
            FOREACH (_ IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
                MERGE (p)-[r:HAS_TECHNOLOGY]->(t)
                SET r.detected_by = 'ai-surface-recon-probe')
            // Fallback so the Technology never orphans if the Port wasn't matched:
            // attach to the IP, else any BaseURL on this host.
            WITH t, p
            OPTIONAL MATCH (ip2:IP {address: $ip, user_id: $uid, project_id: $pid})
            OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
              WHERE p IS NULL AND ip2 IS NULL AND (b.url CONTAINS ($ip + ':' + toString($port))
                    OR b.url CONTAINS (':' + toString($port)))
            WITH t, p, ip2, b
            FOREACH (_ IN CASE WHEN p IS NULL AND ip2 IS NOT NULL THEN [1] ELSE [] END |
                MERGE (ip2)-[r2:HAS_TECHNOLOGY]->(t)
                SET r2.detected_by = 'ai-surface-recon-probe')
            FOREACH (_ IN CASE WHEN p IS NULL AND ip2 IS NULL AND b IS NOT NULL THEN [1] ELSE [] END |
                MERGE (b)-[r3:USES_TECHNOLOGY]->(t)
                SET r3.detected_by = 'ai-surface-recon-probe')
            """,
            name=tech, ip=ip, port=port, uid=user_id, pid=project_id,
            **self._recon_job_params(),
        )
        stats["technologies_promoted"] += 1
