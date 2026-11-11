"""Resource enumeration graph updates (Endpoint, Parameter).

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address
from graph_db.mixins.recon.scope import build_host_scope, host_in_scope, org_for_scan_root
from graph_db.endpoint_paths import normalize_endpoint_path

def _jsluice_secret_values(data) -> tuple:
    """(the key, the pair's other half) out of a jsluice secret's `data`: AWS
    gives {key, secret}, the other kinds {key} or a config object."""
    if isinstance(data, dict):
        for name in ("key", "value", "match", "token"):
            if isinstance(data.get(name), str) and data[name]:
                secret = data.get("secret")
                return data[name], secret if isinstance(secret, str) and name != "secret" else ""
        if isinstance(data.get("secret"), str) and data["secret"]:
            return data["secret"], ""
        return (json.dumps(data, sort_keys=True) if data else ""), ""
    return (str(data) if data else ""), ""


def _redact_sample(text: str) -> str:
    """The stored `sample`: its first and last characters, as JS Recon's."""
    if len(text) > 12:
        return text[:6] + '...' + text[-4:]
    if len(text) > 4:
        return text[:3] + '...'
    return '***' if text else ''


def _openapi_params(endpoint_info: dict, method: str) -> dict:
    """Cypher parameters for an endpoint's OpenAPI fields; None keeps what is stored.

    Every source other than OpenAPI passes oa_declared_only = False: an
    endpoint a tool found is observed. Only short sanitized identifiers reach
    the graph; the merge dropped every free-text field of the specification.
    """
    declared_only = endpoint_info.get("declared_only")
    meta = (endpoint_info.get("openapi") or {}).get(method) or {}
    spec = endpoint_info.get("openapi_spec") if method == "GET" else None
    spec = spec if isinstance(spec, dict) else {}
    return {
        "oa_declared_only": declared_only if isinstance(declared_only, bool) else False,
        "oa_declared": True if meta else None,
        "oa_templates": (endpoint_info.get("openapi_path_templates") or None) if meta else None,
        "oa_operation_id": meta.get("operation_id"),
        "oa_deprecated": meta.get("deprecated") if meta else None,
        "oa_security": meta.get("security") if meta else None,
        "oa_tags": meta.get("tags") or None,
        "oa_spec_urls": meta.get("spec_urls") or None,
        "oa_spec": True if spec else None,
        "oa_spec_version": spec.get("version"),
        "oa_op_count": spec.get("operation_count"),
    }


def openapi_status_entry(scan_root: str, entry: str) -> str:
    """`<scanRoot>|<id>|<hash>|<code>|<time>` (§4.11.5): the writer files every
    entry under the scan root it came from, whatever form recon produced."""
    if entry.startswith(scan_root + "|") and entry.count("|") == 4:
        return entry
    return f"{scan_root}|{entry}"


def write_openapi_source_status(tx, user_id: str, project_id: str, org: str,
                                scan_root: str, statuses: list) -> None:
    """Replace ONE scan root's entries on its org Domain, keeping every other
    root's (§4.11.5).

    Several scan roots share the org Domain, and parallel partial OpenAPI runs
    can write it at once, so the node is locked in the statement's first
    clause and the read-modify-write is that one statement (GDB-11). A
    pre-scan-root (4-segment) entry belonged to the Domain's own name, so it
    is dropped only when this scan root IS the org.
    """
    from graph_db.mixins.recon.domain_mixin import ORG_DOMAIN_LOCK
    tx.run(
        f"""
        MATCH (d:Domain {{user_id: $user_id, project_id: $project_id}})
        WHERE toLower(d.name) = $org
        {ORG_DOMAIN_LOCK}
        WITH d
        SET d.openapi_source_status =
            [s IN coalesce(d.openapi_source_status, [])
             WHERE NOT s STARTS WITH $root + '|'
               AND NOT (size(split(s, '|')) = 4 AND toLower(d.name) = $root)] + $new
        """,
        user_id=user_id, project_id=project_id, org=str(org or "").lower(),
        root=str(scan_root or "").lower(),
        new=[openapi_status_entry(str(scan_root or "").lower(), e) for e in statuses],
    )


class ResourceMixin:
    def update_graph_from_resource_enum(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with resource enumeration data.

        This function creates/updates:
        - Endpoint nodes (discovered paths with their HTTP methods)
        - Parameter nodes (query/body parameters)
        - Form nodes (POST forms discovered)
        - Relationships: BaseURL -[:HAS_ENDPOINT]-> Endpoint -[:HAS_PARAMETER]-> Parameter

        Args:
            recon_data: The recon JSON data containing resource_enum results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "endpoints_created": 0,
            "parameters_created": 0,
            "forms_created": 0,
            "secrets_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        resource_enum_data = recon_data.get("resource_enum", {})
        if not resource_enum_data:
            stats["errors"].append("No resource_enum data found in recon_data")
            return stats

        # Only create nodes for hosts inside the scan scope. In IP mode the
        # scope is the IP literals, not the dashed placeholder names that end
        # up in recon_data["subdomains"] -- see build_host_scope.
        target_hosts = build_host_scope(recon_data)

        def is_in_scope(base_url: str) -> bool:
            """Check if a base URL's hostname is within the scan scope."""
            return host_in_scope(base_url, target_hosts)

        with self.driver.session() as session:
            # Ensure schema is initialized

            by_base_url = resource_enum_data.get("by_base_url", {})
            forms = resource_enum_data.get("forms", [])

            # Track created items to avoid duplicates
            created_endpoints = set()
            created_parameters = set()
            skipped_out_of_scope = 0

            # Process endpoints by base URL
            for base_url, base_data in by_base_url.items():
                # Skip base URLs that are not in scan scope
                if not is_in_scope(base_url):
                    skipped_out_of_scope += 1
                    continue
                endpoints = base_data.get("endpoints", {})

                for path, endpoint_info in endpoints.items():
                    path = normalize_endpoint_path(path)
                    try:
                        methods = endpoint_info.get("methods", ["GET"])
                        category = endpoint_info.get("category", "other")
                        param_count = endpoint_info.get("parameter_count") or {}

                        for method in methods:
                            endpoint_key = (base_url, path, method)
                            if endpoint_key in created_endpoints:
                                continue

                            # Create Endpoint node. AI surface annotations
                            # (ai_interface_type, is_ai_rag_ingest) are set
                            # only when the resource_enum AI classifier (lap-2)
                            # has stamped them onto the endpoint_info dict.
                            # Null-skip: the SET clauses below use COALESCE so
                            # re-runs don't clobber prior values when the
                            # classifier toggle is off.
                            ai_interface_type = endpoint_info.get("ai_interface_type")
                            is_ai_rag_ingest = endpoint_info.get("is_ai_rag_ingest")

                            # `source` (singular) is the high-level phase tag
                            # ('resource_enum', 'vuln_scan', 'js_recon', etc.)
                            # used by report queries to bucket by stage.
                            # `sources` (plural) is the fine-grained tool list
                            # ('katana', 'hakrawler', 'zap_ajax_spider', etc.)
                            # set by each crawler's merge_X_into_by_base_url
                            # helper. On overlap (multiple crawlers find the
                            # same endpoint), we union the lists instead of
                            # clobbering — preserves prior tool attribution.
                            # Defensive normalisation: filter blanks/None and
                            # dedup while preserving order, so a sloppy helper
                            # output doesn't leak dupes into the graph on the
                            # first MERGE (the Cypher CASE branch only dedups
                            # against EXISTING sources on subsequent merges).
                            ep_sources = list(dict.fromkeys(
                                s for s in (endpoint_info.get("sources") or [])
                                if s and isinstance(s, str)
                            ))
                            oa = _openapi_params(endpoint_info, method)
                            # openapi_declared_only: an endpoint that already
                            # existed was observed by some tool, so a
                            # declaration reaching it does not make it
                            # declared-only; an observing source clears it. A
                            # node an earlier release declared (openapi_declared
                            # without the flag) counts as declared-only, so a
                            # declared node this run creates on an observed path
                            # stores false rather than leaving the flag unset.
                            # source is first-writer provenance (an Endpoint's and a
                            # Parameter's), and urls_found, the parameter counts, a
                            # Parameter's category, sample_values, input_type and
                            # required keep what is stored when this caller did not
                            # measure them (D5): a partial run hands this writer
                            # only what its tool saw.
                            # A full run clears assets first, so a node this writer
                            # creates gets the same values as before.
                            session.run(
                                """
                                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET e.openapi_declared_only = CASE WHEN $oa_declared_only THEN true
                                                                              WHEN $oa_declared THEN false ELSE null END,
                                              e.source = 'resource_enum'
                                ON MATCH SET e.openapi_declared_only = CASE
                                    WHEN $oa_declared_only IS NULL THEN e.openapi_declared_only
                                    WHEN NOT $oa_declared_only THEN
                                        CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false)
                                             THEN false ELSE e.openapi_declared_only END
                                    WHEN e.openapi_declared_only IS NOT NULL THEN e.openapi_declared_only
                                    WHEN coalesce(e.openapi_declared, false) THEN true
                                    ELSE false
                                END
                                SET e.user_id = $user_id,
                                    e.project_id = $project_id,
                                    // A category an earlier writer knew (httpx from a page
                                    // title, a crawler from the path) is not lost to a
                                    // later source that only says "other".
                                    e.category = CASE WHEN $category = 'other' AND e.category IS NOT NULL
                                                           AND e.category <> 'other'
                                                      THEN e.category ELSE $category END,
                                    e.ffuf_category = coalesce($ffuf_category, e.ffuf_category),
                                    // A tool that counted no parameter (FFuf, Kiterunner, a
                                    // partial that only names a path) did not look; this
                                    // writer never removes a Parameter node, so neither
                                    // does a zero count.
                                    e.has_parameters = $has_params OR coalesce(e.has_parameters, false),
                                    e.query_param_count = CASE WHEN $query_count > 0 THEN $query_count
                                                               ELSE coalesce(e.query_param_count, 0) END,
                                    e.body_param_count = CASE WHEN $body_count > 0 THEN $body_count
                                                              ELSE coalesce(e.body_param_count, 0) END,
                                    e.path_param_count = CASE WHEN $path_count > 0 THEN $path_count
                                                              ELSE coalesce(e.path_param_count, 0) END,
                                    e.urls_found = coalesce($urls_found, e.urls_found, 1),
                                    e.sources = CASE
                                        WHEN e.sources IS NULL THEN $sources
                                        ELSE e.sources + [s IN $sources WHERE NOT s IN e.sources]
                                    END,
                                    e.ai_interface_type = COALESCE($ai_interface_type, e.ai_interface_type),
                                    e.is_ai_rag_ingest = COALESCE($is_ai_rag_ingest, e.is_ai_rag_ingest),
                                    e.openapi_declared = coalesce($oa_declared, e.openapi_declared),
                                    e.openapi_path_templates = coalesce($oa_templates, e.openapi_path_templates),
                                    e.openapi_operation_id = coalesce($oa_operation_id, e.openapi_operation_id),
                                    e.openapi_deprecated = coalesce($oa_deprecated, e.openapi_deprecated),
                                    e.openapi_security = coalesce($oa_security, e.openapi_security),
                                    e.openapi_tags = coalesce($oa_tags, e.openapi_tags),
                                    e.openapi_spec_urls = CASE WHEN $oa_spec_urls IS NULL THEN e.openapi_spec_urls
                                        ELSE coalesce(e.openapi_spec_urls, [])
                                             + [u IN $oa_spec_urls WHERE NOT u IN coalesce(e.openapi_spec_urls, [])] END,
                                    e.openapi_spec = coalesce($oa_spec, e.openapi_spec),
                                    e.openapi_spec_version = coalesce($oa_spec_version, e.openapi_spec_version),
                                    e.openapi_operation_count = coalesce($oa_op_count, e.openapi_operation_count),
                                    e.updated_at = datetime()
                                """,
                                path=path, method=method, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                category=category,
                                ffuf_category=endpoint_info.get("ffuf_category"),
                                has_params=param_count.get('total', 0) > 0,
                                query_count=param_count.get('query', 0),
                                body_count=param_count.get('body', 0),
                                path_count=param_count.get('path', 0),
                                urls_found=endpoint_info.get('urls_found'),
                                sources=ep_sources,
                                ai_interface_type=ai_interface_type,
                                is_ai_rag_ingest=is_ai_rag_ingest,
                                **oa,
                            )
                            stats["endpoints_created"] += 1
                            created_endpoints.add(endpoint_key)

                            # Create BaseURL node if it doesn't exist and relationship
                            session.run(
                                """
                                MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET bu.source = 'resource_enum',
                                              bu.updated_at = datetime()
                                WITH bu
                                MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (bu)-[:HAS_ENDPOINT]->(e)
                                """,
                                baseurl=base_url, path=path, method=method,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create Parameter nodes
                        parameters = endpoint_info.get("parameters", {})

                        # Process query parameters
                        for param in parameters.get("query", []):
                            param_name = param.get("name")
                            if not param_name:
                                continue

                            param_key = (base_url, path, param_name, "query")
                            if param_key in created_parameters:
                                continue

                            sample_values = param.get("sample_values", [])

                            # AI surface annotations for this parameter, set
                            # by the resource_enum AI classifier (lap-2) only
                            # when the parent endpoint is AI-classified.
                            is_ai_prompt_injectable = param.get("is_ai_prompt_injectable")
                            ai_tool_arg_path = param.get("ai_tool_arg_path")
                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    // A specific type (url, integer...) another source
                                    // inferred is kept over a plain "string".
                                    p.type = CASE WHEN $param_type = 'string' AND p.type IS NOT NULL
                                                       AND p.type <> 'string'
                                                  THEN p.type ELSE $param_type END,
                                    p.category = CASE WHEN coalesce($category, 'other') = 'other' AND p.category IS NOT NULL
                                                           AND p.category <> 'other'
                                                      THEN p.category ELSE $category END,
                                    p.sample_values = CASE WHEN size($sample_values) > 0 THEN $sample_values
                                                           ELSE coalesce(p.sample_values, $sample_values) END,
                                    p.is_injectable = coalesce(p.is_injectable, false),
                                    p.source = coalesce(p.source, 'resource_enum'),
                                    p.is_ai_prompt_injectable = COALESCE($is_ai_prompt_injectable, p.is_ai_prompt_injectable),
                                    p.ai_tool_arg_path = COALESCE($ai_tool_arg_path, p.ai_tool_arg_path),
                                    p.updated_at = datetime()
                                """,
                                name=param_name, position="query", endpoint_path=path, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                param_type=param.get("type", "string"),
                                category=param.get("category", "other"),
                                sample_values=sample_values[:5],  # Limit sample values
                                is_ai_prompt_injectable=is_ai_prompt_injectable,
                                ai_tool_arg_path=ai_tool_arg_path,
                            )
                            stats["parameters_created"] += 1
                            created_parameters.add(param_key)

                            # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
                            for method in methods:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, method=method, baseurl=base_url,
                                    param_name=param_name, position="query",
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                        # Process path parameters (an API specification declares them)
                        for param in parameters.get("path", []):
                            param_name = param.get("name")
                            if not param_name:
                                continue

                            param_key = (base_url, path, param_name, "path")
                            if param_key in created_parameters:
                                continue

                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    // A specific type (url, integer...) another source
                                    // inferred is kept over a plain "string".
                                    p.type = CASE WHEN $param_type = 'string' AND p.type IS NOT NULL
                                                       AND p.type <> 'string'
                                                  THEN p.type ELSE $param_type END,
                                    p.category = CASE WHEN coalesce($category, 'other') = 'other' AND p.category IS NOT NULL
                                                           AND p.category <> 'other'
                                                      THEN p.category ELSE $category END,
                                    p.sample_values = CASE WHEN size($sample_values) > 0 THEN $sample_values
                                                           ELSE coalesce(p.sample_values, $sample_values) END,
                                    p.required = coalesce($required, p.required, true),
                                    p.is_injectable = coalesce(p.is_injectable, false),
                                    p.source = coalesce(p.source, 'resource_enum'),
                                    p.is_ai_prompt_injectable = COALESCE($is_ai_prompt_injectable, p.is_ai_prompt_injectable),
                                    p.ai_tool_arg_path = COALESCE($ai_tool_arg_path, p.ai_tool_arg_path),
                                    p.updated_at = datetime()
                                """,
                                name=param_name, position="path", endpoint_path=path, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                param_type=param.get("type", "string"),
                                category=param.get("category", "other"),
                                sample_values=(param.get("sample_values") or [])[:5],
                                required=param.get("required"),
                                is_ai_prompt_injectable=param.get("is_ai_prompt_injectable"),
                                ai_tool_arg_path=param.get("ai_tool_arg_path"),
                            )
                            stats["parameters_created"] += 1
                            created_parameters.add(param_key)

                            for method in methods:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, method=method, baseurl=base_url,
                                    param_name=param_name, position="path",
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                        # Process body parameters
                        for param in parameters.get("body", []):
                            param_name = param.get("name")
                            if not param_name:
                                continue

                            param_key = (base_url, path, param_name, "body")
                            if param_key in created_parameters:
                                continue

                            is_ai_prompt_injectable = param.get("is_ai_prompt_injectable")
                            ai_tool_arg_path = param.get("ai_tool_arg_path")
                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    // A specific type (url, integer...) another source
                                    // inferred is kept over a plain "string".
                                    p.type = CASE WHEN $param_type = 'string' AND p.type IS NOT NULL
                                                       AND p.type <> 'string'
                                                  THEN p.type ELSE $param_type END,
                                    p.category = CASE WHEN coalesce($category, 'other') = 'other' AND p.category IS NOT NULL
                                                           AND p.category <> 'other'
                                                      THEN p.category ELSE $category END,
                                    // input_type comes from a form, required from a form or
                                    // an API specification; a tool that only names the
                                    // field (Arjun) says neither.
                                    p.input_type = coalesce($input_type, p.input_type, 'text'),
                                    p.required = coalesce($required, p.required, false),
                                    p.is_injectable = coalesce(p.is_injectable, false),
                                    p.source = coalesce(p.source, 'resource_enum'),
                                    p.is_ai_prompt_injectable = COALESCE($is_ai_prompt_injectable, p.is_ai_prompt_injectable),
                                    p.ai_tool_arg_path = COALESCE($ai_tool_arg_path, p.ai_tool_arg_path),
                                    p.updated_at = datetime()
                                """,
                                name=param_name, position="body", endpoint_path=path, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                param_type=param.get("type", "string"),
                                category=param.get("category", "other"),
                                input_type=param.get("input_type"),
                                required=param.get("required"),
                                is_ai_prompt_injectable=is_ai_prompt_injectable,
                                ai_tool_arg_path=ai_tool_arg_path,
                            )
                            stats["parameters_created"] += 1
                            created_parameters.add(param_key)

                            # Create relationship for POST method (body params are only relevant for POST)
                            # First ensure the POST endpoint exists (in case it wasn't in methods list)
                            if 'POST' in methods:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'POST', baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, baseurl=base_url,
                                    param_name=param_name, position="body",
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Endpoint {path} processing failed: {e}")

            # Process forms - aggregate by endpoint to collect all found_at locations
            form_data_by_endpoint = {}  # key: (baseurl, path, method) -> {found_at_pages, enctype, input_names}

            for form in forms:
                try:
                    action = form.get("action", "")
                    method = form.get("method", "POST").upper()
                    found_at = form.get("found_at", "")

                    if not action:
                        continue

                    # Parse action URL
                    parsed = urlparse(action)
                    path = parsed.path or "/"
                    baseurl = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""

                    if not baseurl and found_at:
                        # Extract baseurl from found_at
                        found_parsed = urlparse(found_at)
                        baseurl = f"{found_parsed.scheme}://{found_parsed.netloc}"

                    endpoint_key = (baseurl, path, method)

                    if endpoint_key not in form_data_by_endpoint:
                        form_data_by_endpoint[endpoint_key] = {
                            "found_at_pages": set(),
                            "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
                            "input_names": set(),
                            "input_types": {}  # name -> type mapping
                        }

                    # Collect found_at page
                    if found_at:
                        form_data_by_endpoint[endpoint_key]["found_at_pages"].add(found_at)

                    # Collect input names and types
                    for inp in form.get("inputs", []):
                        inp_name = inp.get("name", "")
                        inp_type = inp.get("type", "text")
                        if inp_name and inp_type != "submit":  # Skip submit buttons
                            form_data_by_endpoint[endpoint_key]["input_names"].add(inp_name)
                            form_data_by_endpoint[endpoint_key]["input_types"][inp_name] = inp_type

                except Exception as e:
                    stats["errors"].append(f"Form data collection failed: {e}")

            # Now update endpoints with aggregated form data
            for (baseurl, path, method), form_info in form_data_by_endpoint.items():
                try:
                    session.run(
                        """
                        MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                        SET e.is_form = true,
                            e.form_enctype = $enctype,
                            e.form_found_at_pages = $found_at_pages,
                            e.form_input_names = $input_names,
                            e.form_count = $form_count
                        """,
                        path=path, method=method, baseurl=baseurl,
                        user_id=user_id, project_id=project_id,
                        enctype=form_info["enctype"],
                        found_at_pages=list(form_info["found_at_pages"]),
                        input_names=list(form_info["input_names"]),
                        form_count=len(form_info["found_at_pages"])
                    )
                    stats["forms_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Form endpoint update failed: {e}")

            # ── Secret nodes from jsluice ──────────────────────────────
            jsluice_secrets = resource_enum_data.get("jsluice_secrets", [])
            created_secrets = set()

            for secret in jsluice_secrets:
                try:
                    base_url = secret.get("base_url", "")
                    if not base_url or not is_in_scope(base_url):
                        continue

                    secret_type = secret.get("kind", "unknown")
                    severity = secret.get("severity", "info")
                    source_url = secret.get("source_url", "")

                    # Extract the matched data for dedup and sample
                    data_field = secret.get("data", {})
                    if isinstance(data_field, dict):
                        data_str = json.dumps(data_field, sort_keys=True)
                    else:
                        data_str = str(data_field)

                    # Dedup hash: type + source_url + data + tenant
                    dedup_input = f"{secret_type}|{source_url}|{data_str}|{user_id}|{project_id}"
                    dedup_hash = hashlib.sha256(dedup_input.encode()).hexdigest()[:16]
                    node_id = f"secret-{user_id}-{project_id}-{dedup_hash}"

                    if node_id in created_secrets:
                        continue

                    secret_value, paired_secret = _jsluice_secret_values(data_field)
                    sample = _redact_sample(secret_value)
                    context = secret.get("context")
                    raw_context = (json.dumps(context, sort_keys=True) if isinstance(context, (dict, list))
                                   else str(context or ""))[:400] or None

                    scan_ts = resource_enum_data.get("scan_metadata", {}).get("scan_timestamp", "")

                    session.run(
                        """
                        MERGE (s:Secret {id: $id, user_id: $user_id,
                                         project_id: $project_id})
                        SET s.user_id = $user_id,
                            s.project_id = $project_id,
                            s.secret_type = $secret_type,
                            s.severity = $severity,
                            s.source = 'jsluice',
                            s.source_url = $source_url,
                            s.base_url = $base_url,
                            s.sample = $sample,
                            s.secret_value = $secret_value,
                            s.paired_secret = $paired_secret,
                            s.raw_context = $raw_context,
                            s.discovered_at = $discovered_at,
                            s.updated_at = datetime()
                        WITH s
                        MATCH (bu:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                        MERGE (bu)-[:HAS_SECRET]->(s)
                        """,
                        id=node_id, user_id=user_id, project_id=project_id,
                        secret_type=secret_type, severity=severity,
                        source_url=source_url, base_url=base_url,
                        sample=sample, discovered_at=scan_ts,
                        secret_value=secret_value or None, paired_secret=paired_secret or None,
                        raw_context=raw_context,
                    )
                    created_secrets.add(node_id)
                    stats["secrets_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Secret node creation failed: {e}")

            if stats["secrets_created"] > 0:
                print(f"[+][graph-db] Created {stats['secrets_created']} Secret nodes")

            # Update Domain node with resource_enum metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            # The flat per-tool stamp goes on the org Domain (§4.11.3): a scan
            # root below its org has no Domain node of its own.
            if root_domain:
                root_domain = metadata.get("org_domain") or org_for_scan_root(root_domain, recon_data)
            summary = resource_enum_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.resource_enum_timestamp = $scan_timestamp,
                            d.resource_enum_total_endpoints = $total_endpoints,
                            d.resource_enum_total_parameters = $total_parameters,
                            d.resource_enum_total_forms = $total_forms,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=resource_enum_data.get("scan_metadata", {}).get("scan_timestamp"),
                        total_endpoints=summary.get("total_endpoints", 0),
                        total_parameters=summary.get("total_parameters", 0),
                        total_forms=summary.get("total_forms", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            # Per-source OpenAPI status, on the org Domain of the scan root this
            # run covers (ip-targets.<project> in IP mode). Present whenever
            # OpenAPI ran, so a removed source's status is cleared.
            openapi_inventory = resource_enum_data.get("openapi")
            run_root = recon_data.get("domain")
            if isinstance(openapi_inventory, dict) and "source_status" in openapi_inventory and run_root:
                try:
                    statuses = [s for s in openapi_inventory.get("source_status") or [] if isinstance(s, str)]
                    session.execute_write(lambda tx: write_openapi_source_status(
                        tx, user_id, project_id, org_for_scan_root(run_root, recon_data), run_root, statuses))
                except Exception as e:
                    stats["errors"].append(f"OpenAPI source status update failed: {e}")

            # Connect orphaned BaseURLs to their Subdomain node.
            # BaseURLs created by resource_enum may not have a Service -[:SERVES_URL]-> link
            # if httpx didn't probe that URL (e.g., port 80 redirected to HTTPS).
            # Host match is exact (via apoc-free URL host parsing) to avoid the
            # CONTAINS substring trap (where "https://api.example.com" wrongly
            # matches Subdomain "example.com").
            try:
                orphan_result = session.run(
                    """
                    MATCH (bu:BaseURL {user_id: $user_id, project_id: $project_id})
                    WHERE NOT (bu)<-[:SERVES_URL]-()
                      AND NOT (:Subdomain)-[:HAS_BASE_URL]->(bu)
                    WITH bu,
                         split(split(replace(replace(bu.url, 'https://', ''), 'http://', ''), '/')[0], ':')[0] AS bu_host
                    MATCH (sub:Subdomain {user_id: $user_id, project_id: $project_id})
                    WHERE sub.name = bu_host
                    MERGE (sub)-[:HAS_BASE_URL]->(bu)
                    RETURN count(*) AS linked
                    """,
                    user_id=user_id, project_id=project_id
                )
                orphans_linked = orphan_result.single()["linked"]
                if orphans_linked > 0:
                    print(f"[+][graph-db] Linked {orphans_linked} orphaned BaseURL(s) to Subdomain")
                    stats["relationships_created"] += orphans_linked
            except Exception as e:
                stats["errors"].append(f"Orphan BaseURL cleanup failed: {e}")

            # Apex / root-domain pass.
            # Crawlers and Nuclei templates that target the bare domain produce
            # URLs like https://example.com -- the host is the Domain itself,
            # not a Subdomain. The Subdomain-only cleanup above can't link
            # those, so we attach them directly to the Domain node. Skips
            # BaseURLs already attached via Subdomain or via the httpx
            # Service -[:SERVES_URL]-> path.
            try:
                apex_result = session.run(
                    """
                    MATCH (bu:BaseURL {user_id: $user_id, project_id: $project_id})
                    WHERE NOT (bu)<-[:SERVES_URL]-()
                      AND NOT (:Subdomain)-[:HAS_BASE_URL]->(bu)
                      AND NOT (:Domain)-[:HAS_BASE_URL]->(bu)
                    WITH bu,
                         split(split(replace(replace(bu.url, 'https://', ''), 'http://', ''), '/')[0], ':')[0] AS bu_host
                    MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
                    WHERE d.name = bu_host
                    MERGE (d)-[:HAS_BASE_URL]->(bu)
                    RETURN count(*) AS linked
                    """,
                    user_id=user_id, project_id=project_id
                )
                apex_linked = apex_result.single()["linked"]
                if apex_linked > 0:
                    print(f"[+][graph-db] Linked {apex_linked} apex BaseURL(s) to Domain")
                    stats["relationships_created"] += apex_linked
            except Exception as e:
                stats["errors"].append(f"Apex BaseURL cleanup failed: {e}")

            print(f"[+][graph-db] Created {stats['endpoints_created']} Endpoint nodes")
            print(f"[+][graph-db] Created {stats['parameters_created']} Parameter nodes")
            print(f"[+][graph-db] Processed {stats['forms_created']} form endpoints")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            if skipped_out_of_scope > 0:
                print(f"[*][graph-db] Skipped {skipped_out_of_scope} base URLs out of scan scope")
                stats["skipped_out_of_scope"] = skipped_out_of_scope

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        if (resource_enum_data.get("archive_leaks") or {}) and hasattr(self, "update_graph_from_archive_leaks"):
            try:
                leaks = self.update_graph_from_archive_leaks(recon_data, user_id, project_id)
                stats["archive_findings_written"] = leaks.get("findings_written", 0)
                stats["secrets_created"] += leaks.get("secrets_written", 0)
                # The pipeline reads only the errors this writer returns: a
                # url_archive finding that failed here must not read as gone.
                stats["errors"].extend(f"Archive leaks: {e}" for e in leaks.get("errors") or [])
            except Exception as e:
                stats["errors"].append(f"Archive leaks failed: {e}")

        return stats

    def update_graph_from_endpoint_ai_classifier(self, by_base_url: dict, user_id: str,
                                                 project_id: str) -> dict:
        """Write the partial Endpoint AI Classifier's annotations and nothing else (D5).

        ``by_base_url`` is the resource_enum shape the classifier stamped. Only
        what it stamps is read: ai_interface_type and is_ai_rag_ingest per
        endpoint, is_ai_prompt_injectable per parameter. The classifier matches
        stored paths and parameter names, so the crawl's fields (category,
        urls_found, source, sample_values, counts) and updated_at stay as the
        last crawl left them. Nodes are matched on their full key and never
        created. A value the classifier did not produce keeps the stored one,
        and its "non-llm" (no path pattern matched) never replaces a type
        another source found, such as AI Surface Recon's live probe.
        """
        stats = {"endpoints_annotated": 0, "parameters_annotated": 0, "errors": []}
        endpoints, parameters = [], []
        for base_url, base_data in (by_base_url or {}).items():
            if not base_url or not isinstance(base_data, dict):
                continue
            for path, info in (base_data.get("endpoints") or {}).items():
                if not path or not isinstance(info, dict):
                    continue
                iface, rag = info.get("ai_interface_type"), info.get("is_ai_rag_ingest")
                if iface is not None or rag is not None:
                    endpoints.extend({"baseurl": base_url, "path": path, "method": method,
                                      "ai_interface_type": iface, "is_ai_rag_ingest": rag}
                                     for method in info.get("methods") or ["GET"])
                params = info.get("parameters")
                for position, plist in (params.items() if isinstance(params, dict) else ()):
                    for param in plist or []:
                        if (isinstance(param, dict) and param.get("name")
                                and param.get("is_ai_prompt_injectable") is not None):
                            parameters.append({"baseurl": base_url, "path": path, "name": param["name"],
                                               "position": position,
                                               "is_ai_prompt_injectable": param["is_ai_prompt_injectable"]})
        if not endpoints and not parameters:
            return stats

        def work(tx):
            annotated = tx.run(
                """
                UNWIND $rows AS row
                MATCH (e:Endpoint {path: row.path, method: row.method, baseurl: row.baseurl,
                                   user_id: $user_id, project_id: $project_id})
                SET e.ai_interface_type = CASE
                        WHEN row.ai_interface_type IS NULL THEN e.ai_interface_type
                        WHEN row.ai_interface_type = 'non-llm'
                             AND coalesce(e.ai_interface_type, 'non-llm') <> 'non-llm' THEN e.ai_interface_type
                        ELSE row.ai_interface_type END,
                    e.is_ai_rag_ingest = coalesce(row.is_ai_rag_ingest, e.is_ai_rag_ingest)
                RETURN count(e) AS n
                """,
                rows=endpoints, user_id=user_id, project_id=project_id,
            ).single()
            flagged = tx.run(
                """
                UNWIND $rows AS row
                MATCH (p:Parameter {name: row.name, position: row.position, endpoint_path: row.path,
                                    baseurl: row.baseurl, user_id: $user_id, project_id: $project_id})
                SET p.is_ai_prompt_injectable = coalesce(row.is_ai_prompt_injectable, p.is_ai_prompt_injectable)
                RETURN count(p) AS n
                """,
                rows=parameters, user_id=user_id, project_id=project_id,
            ).single()
            return (annotated["n"] if annotated else 0), (flagged["n"] if flagged else 0)

        try:
            with self.driver.session() as session:
                stats["endpoints_annotated"], stats["parameters_annotated"] = session.execute_write(work)
        except Exception as e:
            stats["errors"].append(f"Endpoint AI annotations failed: {e}")
        return stats

    def prune_withdrawn_openapi_declarations(self, user_id: str, project_id: str, reread_spec_urls,
                                             run_started_at: str, redeclared=None) -> dict:
        """Withdraw what a re-read specification no longer declares (D17).

        Partial OpenAPI runs only: a full run clears every recon asset first,
        and a partial run is the project's only writer while it runs.
        ``reread_spec_urls`` are the documents this run fetched AND parsed, so a
        failed fetch withdraws nothing. ``redeclared`` maps
        ``"<METHOD> <baseurl><path>"`` to the spec URLs that declared that
        endpoint this run.

        An endpoint carrying a re-read URL that did not declare it again loses
        that URL. When no URL is left, an endpoint known only from a
        specification, with no finding on it or its parameters and not written
        by this run, is deleted; any other one stops being declared. The write
        lock is taken before anything attached is read (the prune_unseen_findings
        idiom), so a finding committed meanwhile is never deleted with its node.
        """
        stats = {"deleted": 0, "withdrawn": 0}
        urls = sorted({u for u in reread_spec_urls or [] if isinstance(u, str) and u})
        if not urls:
            return stats
        params = dict(user_id=user_id, project_id=project_id)

        def work(tx):
            rows = tx.run(
                """
                MATCH (e:Endpoint {user_id: $user_id, project_id: $project_id})
                WHERE any(u IN coalesce(e.openapi_spec_urls, []) WHERE u IN $urls)
                WITH e, coalesce($redeclared[e.method + ' ' + e.baseurl + e.path], []) AS again
                WITH e, [u IN e.openapi_spec_urls WHERE u IN $urls AND NOT u IN again] AS dropped
                WHERE size(dropped) > 0
                SET e._prune_lock = true
                REMOVE e._prune_lock
                WITH e, [u IN e.openapi_spec_urls WHERE NOT u IN dropped] AS remaining
                RETURN elementId(e) AS eid, remaining,
                       size(remaining) = 0
                       AND coalesce(e.openapi_declared_only, e.openapi_declared, false)
                       AND (e.updated_at IS NULL OR e.updated_at < datetime($run_started_at))
                       AND NOT EXISTS { (e)-[:HAS_VULNERABILITY]->() }
                       AND NOT EXISTS { ()-[:FOUND_AT]->(e) }
                       AND NOT EXISTS {
                           MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
                           WHERE EXISTS { ()-[:AFFECTS_PARAMETER]->(p) }
                              OR EXISTS { (p)-[:HAS_VULNERABILITY]->() }
                       } AS delete_it
                """,
                urls=urls, redeclared=redeclared or {}, run_started_at=run_started_at, **params,
            ).data()
            gone = [r["eid"] for r in rows if r["delete_it"]]
            kept = [{"eid": r["eid"], "remaining": r["remaining"]} for r in rows if not r["delete_it"]]
            tx.run(
                """
                UNWIND $rows AS row
                MATCH (e:Endpoint {user_id: $user_id, project_id: $project_id})
                WHERE elementId(e) = row.eid
                SET e.openapi_spec_urls = CASE WHEN size(row.remaining) = 0 THEN null ELSE row.remaining END
                WITH e, row WHERE size(row.remaining) = 0
                SET e.openapi_declared = false
                REMOVE e.openapi_declared_only, e.openapi_operation_id, e.openapi_deprecated,
                       e.openapi_security, e.openapi_tags, e.openapi_path_templates
                """,
                rows=kept, **params,
            ).consume()
            orphans = tx.run(
                """
                UNWIND $ids AS eid
                MATCH (e:Endpoint {user_id: $user_id, project_id: $project_id})
                WHERE elementId(e) = eid
                OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
                WITH e, collect(elementId(p)) AS pids
                DETACH DELETE e
                RETURN pids
                """,
                ids=gone, **params,
            ).data()
            pids = sorted({pid for r in orphans for pid in r["pids"] if pid})
            # Parameters are keyed per path; one another method still uses stays.
            tx.run(
                """
                UNWIND $pids AS pid
                MATCH (p:Parameter {user_id: $user_id, project_id: $project_id})
                WHERE elementId(p) = pid
                  AND NOT EXISTS { ()-[:HAS_PARAMETER]->(p) }
                  AND NOT EXISTS { ()-[:AFFECTS_PARAMETER]->(p) }
                  AND NOT EXISTS { (p)-[:HAS_VULNERABILITY]->() }
                DETACH DELETE p
                """,
                pids=pids, **params,
            ).consume()
            return len(gone), len(kept)

        with self.driver.session() as session:
            stats["deleted"], stats["withdrawn"] = session.execute_write(work)
        return stats
