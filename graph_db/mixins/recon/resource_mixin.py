"""Resource enumeration graph updates (Endpoint, Parameter).

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address

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

        # Get target subdomains from scan scope - only create nodes for these
        target_subdomains = set(recon_data.get("subdomains", []))
        target_domain = recon_data.get("domain", "")

        # Also include the main domain if no subdomains specified
        if target_domain and not target_subdomains:
            target_subdomains.add(target_domain)

        def is_in_scope(base_url: str) -> bool:
            """Check if a base URL's hostname is within the scan scope."""
            if not target_subdomains:
                return True  # No filter if no subdomains defined
            parsed = urlparse(base_url)
            host = parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc
            return host in target_subdomains

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
                    try:
                        methods = endpoint_info.get("methods", ["GET"])
                        category = endpoint_info.get("category", "other")
                        param_count = endpoint_info.get("parameter_count", {})

                        for method in methods:
                            endpoint_key = (base_url, path, method)
                            if endpoint_key in created_endpoints:
                                continue

                            # Create Endpoint node
                            session.run(
                                """
                                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET e.user_id = $user_id,
                                    e.project_id = $project_id,
                                    e.category = $category,
                                    e.has_parameters = $has_params,
                                    e.query_param_count = $query_count,
                                    e.body_param_count = $body_count,
                                    e.path_param_count = $path_count,
                                    e.urls_found = $urls_found,
                                    e.source = 'resource_enum',
                                    e.updated_at = datetime()
                                """,
                                path=path, method=method, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                category=category,
                                has_params=param_count.get('total', 0) > 0,
                                query_count=param_count.get('query', 0),
                                body_count=param_count.get('body', 0),
                                path_count=param_count.get('path', 0),
                                urls_found=endpoint_info.get('urls_found', 1)
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

                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    p.type = $param_type,
                                    p.category = $category,
                                    p.sample_values = $sample_values,
                                    p.is_injectable = false,
                                    p.source = 'resource_enum',
                                    p.updated_at = datetime()
                                """,
                                name=param_name, position="query", endpoint_path=path, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                param_type=param.get("type", "string"),
                                category=param.get("category", "other"),
                                sample_values=sample_values[:5]  # Limit sample values
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

                        # Process body parameters
                        for param in parameters.get("body", []):
                            param_name = param.get("name")
                            if not param_name:
                                continue

                            param_key = (base_url, path, param_name, "body")
                            if param_key in created_parameters:
                                continue

                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    p.type = $param_type,
                                    p.category = $category,
                                    p.input_type = $input_type,
                                    p.required = $required,
                                    p.is_injectable = false,
                                    p.source = 'resource_enum',
                                    p.updated_at = datetime()
                                """,
                                name=param_name, position="body", endpoint_path=path, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                param_type=param.get("type", "string"),
                                category=param.get("category", "other"),
                                input_type=param.get("input_type", "text"),
                                required=param.get("required", False)
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

                    # Redacted sample: first 6 chars + ...
                    matched = data_field.get("match", "") if isinstance(data_field, dict) else str(data_field)
                    sample = (matched[:6] + "...") if len(matched) > 6 else matched

                    scan_ts = resource_enum_data.get("scan_metadata", {}).get("scan_timestamp", "")

                    session.run(
                        """
                        MERGE (s:Secret {id: $id})
                        SET s.user_id = $user_id,
                            s.project_id = $project_id,
                            s.secret_type = $secret_type,
                            s.severity = $severity,
                            s.source = 'jsluice',
                            s.source_url = $source_url,
                            s.base_url = $base_url,
                            s.sample = $sample,
                            s.discovered_at = $discovered_at,
                            s.updated_at = datetime()
                        WITH s
                        MATCH (bu:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                        MERGE (bu)-[:HAS_SECRET]->(s)
                        """,
                        id=node_id, user_id=user_id, project_id=project_id,
                        secret_type=secret_type, severity=severity,
                        source_url=source_url, base_url=base_url,
                        sample=sample, discovered_at=scan_ts
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

            # Connect orphaned BaseURLs to their Subdomain node
            # BaseURLs created by resource_enum may not have a Service -[:SERVES_URL]-> link
            # if httpx didn't probe that URL (e.g., port 80 redirected to HTTPS).
            # Link them to the Subdomain to prevent disconnected graph clusters.
            orphan_result = session.run(
                """
                MATCH (bu:BaseURL {user_id: $user_id, project_id: $project_id})
                WHERE NOT (bu)<-[:SERVES_URL]-()
                MATCH (sub:Subdomain {user_id: $user_id, project_id: $project_id})
                WHERE bu.url CONTAINS sub.name
                MERGE (sub)-[:HAS_BASE_URL]->(bu)
                RETURN count(*) AS linked
                """,
                user_id=user_id, project_id=project_id
            )
            orphans_linked = orphan_result.single()["linked"]
            if orphans_linked > 0:
                print(f"[+][graph-db] Linked {orphans_linked} orphaned BaseURL(s) to Subdomain")
                stats["relationships_created"] += orphans_linked

            print(f"[+][graph-db] Created {stats['endpoints_created']} Endpoint nodes")
            print(f"[+][graph-db] Created {stats['parameters_created']} Parameter nodes")
            print(f"[+][graph-db] Processed {stats['forms_created']} form endpoints")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            if skipped_out_of_scope > 0:
                print(f"[*][graph-db] Skipped {skipped_out_of_scope} base URLs out of scan scope")
                stats["skipped_out_of_scope"] = skipped_out_of_scope

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats
