"""HTTP probe graph updates (BaseURL, Endpoint, Technology, Header, Certificate).

Lap-1 Patch D refactor: each httpx output URL is split into

  - BaseURL  (one per scheme+host+port — the HTTP service identity)
  - Endpoint (one per probed path — carries status/headers/title/AI annotations)

linked by ``(BaseURL)-[:HAS_ENDPOINT]->(Endpoint)``.

Previously the mixin MERGEd ``BaseURL {url: <full URL with path>}`` which
conflated "service" and "path" — when httpxPaths probed multiple paths per
port the result was N BaseURL nodes per HTTP service, all sharing the same
scheme+host+port. The viewer label collapsed them to identical strings;
the schema semantics were violated. Patch D restores the intended shape:
ONE BaseURL per service, MANY Endpoints per BaseURL.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address
from graph_db.cert_key import build_cert_key
from graph_db.schema import NON_RECON_SOURCES


#: Every relationship type a Technology node can carry, and which way it points
#: relative to the Technology. Used when a versioned detection absorbs a
#: versionless twin: each is re-parented before the twin is removed.
#:
#: USES_TECHNOLOGY    (Endpoint|Service|Port|IP) -> Technology
#: HAS_TECHNOLOGY     (Port|IP|Parameter)        -> Technology
#: HAS_KNOWN_CVE      Technology -> CVE
#: HAS_VULNERABILITY  Technology -> Vulnerability   (GVM)
_TECH_TWIN_RELATIONSHIPS = (
    ("USES_TECHNOLOGY", "in"),
    ("HAS_TECHNOLOGY", "in"),
    ("HAS_KNOWN_CVE", "out"),
    ("HAS_VULNERABILITY", "out"),
)


def resolve_tech_version(session, name: str, version: str,
                         user_id: str, project_id: str) -> str:
    """Return the version to MERGE a Technology node on, collapsing duplicates.

    Technology identity is ``(name, version, user_id, project_id)`` and a
    versionless detection is stored with ``version: ''`` (Neo4j cannot MERGE on
    null, so the empty string is the sentinel). Two detectors disagreeing about
    whether they can read a version therefore produced TWO nodes for the same
    technology - observed live as React ``18.2.0`` (httpx) alongside React ``''``
    (wappalyzer). That inflates technology counts, splits the graph view, and
    can hide a version from version-based matching.

    Both directions are handled:
      - a versionless detection arrives and a versioned node already exists
        -> reuse the versioned node, do not create the '' twin
      - a versioned detection arrives and a versionless node exists
        -> absorb it: move its USES_TECHNOLOGY edges onto the versioned node
           and delete the twin

    Returns the version string the caller should MERGE on.
    """
    if version:
        # Absorb an existing versionless twin into this versioned node.
        #
        # Every relationship moves, not just USES_TECHNOLOGY. The original
        # re-parented that one type and then DETACH DELETEd, so a twin that had
        # already collected `(Port|IP)-[:HAS_TECHNOLOGY]->`, `-[:HAS_KNOWN_CVE]->`
        # or GVM's `-[:HAS_VULNERABILITY]->` lost them silently - and the port
        # scan, which reports versionless services, usually runs BEFORE the HTTP
        # probe that supplies a version, so the twin normally HAS those edges.
        session.run(
            """
            MERGE (new:Technology {name: $name, version: $version,
                                   user_id: $uid, project_id: $pid})
            SET new.updated_at = datetime()
            """,
            name=name, version=version, uid=user_id, pid=project_id,
        )
        for rel, direction in _TECH_TWIN_RELATIONSHIPS:
            if direction == "in":
                existing, moved = f"(other)-[r:`{rel}`]->(old)", f"(other)-[:`{rel}`]->(new)"
            else:
                existing, moved = f"(old)-[r:`{rel}`]->(other)", f"(new)-[:`{rel}`]->(other)"
            # DELETE r is not optional: re-creating the edge on `new` without
            # dropping it from `old` leaves the twin holding a relationship, and
            # the zero-degree guard below then refuses to remove it forever.
            session.run(
                f"""
                MATCH (old:Technology {{name: $name, version: '',
                                       user_id: $uid, project_id: $pid}})
                MATCH (new:Technology {{name: $name, version: $version,
                                       user_id: $uid, project_id: $pid}})
                WITH old, new
                MATCH {existing}
                MERGE {moved}
                DELETE r
                """,
                name=name, version=version, uid=user_id, pid=project_id,
            )

        # Delete the twin only once it holds nothing. A relationship type this
        # list does not know about would otherwise be destroyed with no trace;
        # leaving a duplicate node behind is the far cheaper failure.
        record = session.run(
            """
            MATCH (old:Technology {name: $name, version: '',
                                   user_id: $uid, project_id: $pid})
            WHERE NOT (old)--()
            DELETE old
            RETURN count(old) AS absorbed
            """,
            name=name, uid=user_id, pid=project_id,
        ).single()
        if record is not None and not record["absorbed"]:
            leftover = session.run(
                """
                MATCH (old:Technology {name: $name, version: '',
                                       user_id: $uid, project_id: $pid})-[r]-()
                RETURN collect(DISTINCT type(r)) AS types
                """,
                name=name, uid=user_id, pid=project_id,
            ).single()
            if leftover and leftover["types"]:
                print(f"[!][graph-db] versionless {name} twin kept: unmoved "
                      f"relationship type(s) {leftover['types']} - add them to "
                      f"_TECH_TWIN_RELATIONSHIPS")
        return version

    # Versionless detection: prefer an existing versioned node for this name.
    rec = session.run(
        """
        MATCH (t:Technology {name: $name, user_id: $uid, project_id: $pid})
        WHERE t.version <> ''
        RETURN t.version AS version
        ORDER BY t.version DESC
        LIMIT 1
        """,
        name=name, uid=user_id, pid=project_id,
    ).single()
    return rec["version"] if rec and rec["version"] else ""


def _split_url(url: str) -> tuple[str, str]:
    """Return ``(base_url, path)`` where ``base_url = scheme://host:port``
    and ``path`` is the URL path (defaults to ``'/'``). Query string and
    fragment are dropped — Endpoint identity is ``(path, method, baseurl)``
    per the existing Redamon convention (matches js_recon + vuln_scan mixins)."""
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    return base_url, path


class HttpMixin:
    def update_graph_from_http_probe(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with HTTP probe data.

        Lap-1 model:
        - BaseURL nodes  — one per scheme+host+port (the HTTP service identity)
        - Endpoint nodes — one per probed path (carries response data + AI annotations)
        - Technology nodes for detected technologies (attached to Endpoint)
        - Header nodes for response headers (attached to Endpoint)
        - Certificate nodes (attached to Endpoint when TLS data is present)
        - Service nodes (if not existing) for the HTTP/HTTPS service

        Relationships:
        - Service  -[:SERVES_URL]->        BaseURL
        - BaseURL  -[:HAS_ENDPOINT]->      Endpoint
        - Endpoint -[:HAS_HEADER]->        Header
        - Endpoint -[:HAS_CERTIFICATE]->   Certificate
        - Endpoint -[:USES_TECHNOLOGY]->   Technology

        Args:
            recon_data: The recon JSON data containing http_probe results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "baseurls_created": 0,
            "certificates_created": 0,
            "services_created": 0,
            "technologies_created": 0,
            "headers_created": 0,
            "relationships_created": 0,
            "subdomains_updated": 0,
            "errors": []
        }

        http_probe_data = recon_data.get("http_probe", {})
        if not http_probe_data:
            stats["errors"].append("No http_probe data found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_metadata = http_probe_data.get("scan_metadata", {})
            by_url = http_probe_data.get("by_url", {})
            wappalyzer = http_probe_data.get("wappalyzer", {})
            all_technologies = wappalyzer.get("all_technologies", {})

            # Process each URL
            for url, url_info in by_url.items():
                try:
                    # Extract URL components
                    host = url_info.get("host", "")
                    scheme = "https" if url.startswith("https://") else "http"

                    # Lap-1 Patch D: split URL into base_url (one per service) and
                    # path (one per Endpoint). MERGE BaseURL as a thin node keyed
                    # by base_url; MERGE Endpoint with all the response data.
                    base_url, path = _split_url(url)

                    # ---- BaseURL: thin "HTTP service" identity node ----------
                    baseurl_props = {
                        "url": base_url,
                        "user_id": user_id,
                        "project_id": project_id,
                        "scheme": scheme,
                        "host": host,
                        "source": "http_probe",
                    }
                    baseurl_props = {k: v for k, v in baseurl_props.items() if v is not None}
                    session.run(
                        """
                        MERGE (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                        SET u += $props,
                            u.updated_at = datetime()
                        """,
                        base_url=base_url, user_id=user_id, project_id=project_id, props=baseurl_props
                    )
                    stats["baseurls_created"] += 1

                    # ---- Endpoint: path-level data + AI annotations ----------
                    endpoint_props = {
                        "path": path,
                        "method": "GET",  # httpx default; the URL identity uses (path, method, baseurl)
                        "baseurl": base_url,
                        "url": url,                                       # convenience: full URL
                        "user_id": user_id,
                        "project_id": project_id,
                        "status_code": url_info.get("status_code"),
                        "content_length": url_info.get("content_length"),
                        "content_type": url_info.get("content_type"),
                        "title": url_info.get("title"),
                        "server": url_info.get("server"),
                        "response_time_ms": url_info.get("response_time_ms"),
                        "word_count": url_info.get("word_count"),
                        "line_count": url_info.get("line_count"),
                        "resolved_ip": url_info.get("ip"),
                        "cname": url_info.get("cname"),
                        "cdn": url_info.get("cdn"),
                        "is_cdn": url_info.get("is_cdn", False),
                        "asn": url_info.get("asn"),
                        "favicon_hash": url_info.get("favicon_hash"),
                        "is_live": url_info.get("status_code") is not None,
                        "source": "http_probe",
                        # AI surface recon (lap-1 Patch D — moved from BaseURL to Endpoint)
                        "is_ai_framework_detected": url_info.get("is_ai_framework_detected"),
                        "ai_framework_name": url_info.get("ai_framework_name"),
                        "ai_frontend_product_guess": url_info.get("ai_frontend_product_guess"),
                    }
                    body_hash = url_info.get("body_hash", {})
                    if body_hash:
                        endpoint_props["body_sha256"] = body_hash.get("body_sha256")
                        endpoint_props["header_sha256"] = body_hash.get("header_sha256")
                    tls_data = url_info.get("tls", {})
                    if tls_data:
                        endpoint_props["tls_cipher"] = tls_data.get("cipher")
                        endpoint_props["tls_version"] = tls_data.get("version")
                    endpoint_props = {k: v for k, v in endpoint_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                        SET e += $props,
                            e.updated_at = datetime()
                        """,
                        path=path, base_url=base_url, user_id=user_id, project_id=project_id, props=endpoint_props
                    )
                    stats.setdefault("endpoints_created", 0)
                    stats["endpoints_created"] += 1

                    # ---- BaseURL -[:HAS_ENDPOINT]-> Endpoint ------------------
                    session.run(
                        """
                        MATCH (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                        MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                        MERGE (u)-[:HAS_ENDPOINT]->(e)
                        """,
                        base_url=base_url, path=path,
                        user_id=user_id, project_id=project_id,
                    )
                    stats["relationships_created"] += 1

                    # Certificate from TLS data. Keyed on cert_key (not subject_cn),
                    # so empty-CN / SAN-only certs are stored and two scanners
                    # observing the same cert converge on one node.
                    if tls_data and tls_data.get("certificate"):
                        cert_data = tls_data.get("certificate", {})
                        subject_cn = cert_data.get("subject_cn") or ""
                        issuer_raw = cert_data.get("issuer")
                        issuer_str = ", ".join(issuer_raw) if isinstance(issuer_raw, list) else issuer_raw
                        not_before = cert_data.get("not_before")
                        not_after = cert_data.get("not_after")
                        fingerprint = cert_data.get("fingerprint_sha256") or cert_data.get("fingerprint")
                        cert_key = build_cert_key(
                            fingerprint_sha256=fingerprint, subject_cn=subject_cn,
                            issuer=issuer_str, not_before=not_before, not_after=not_after,
                        )

                        cert_props = {
                            "subject_cn": subject_cn or None,
                            "issuer": issuer_str,
                            "not_before": not_before,
                            "not_after": not_after,
                            "san": cert_data.get("san", []),  # full SAN list as presented
                            "cipher": tls_data.get("cipher"),
                            "tls_version": tls_data.get("version"),
                            # Phase 0.6: httpx already pays ~10 TLS handshakes for
                            # -jarm (default on) and writes it at the URL level,
                            # NOT inside tls.certificate -- so reading it from the
                            # cert dict found nothing and the fingerprint was
                            # thrown away every scan.
                            "jarm": (cert_data.get("jarm") or tls_data.get("jarm")
                                     or url_info.get("jarm")),
                        }
                        if fingerprint:
                            cert_props["fingerprint_sha256"] = fingerprint
                        # Empty is "this scanner saw nothing", not "the cert has
                        # nothing". Since re-keying on cert_key makes sources
                        # converge on ONE node, a `SET c += {san: []}` here would
                        # erase a SAN list another source already stored.
                        cert_props = {k: v for k, v in cert_props.items()
                                      if v is not None and v != "" and v != []}

                        # source is first-writer provenance (ON CREATE); observed_by
                        # accumulates so a cross-source clear can tell sole vs shared.
                        session.run(
                            """
                            MERGE (c:Certificate {cert_key: $cert_key, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET c.source = 'http_probe'
                            SET c += $props,
                                c.observed_by = CASE WHEN 'http_probe' IN coalesce(c.observed_by, [])
                                                     THEN c.observed_by
                                                     ELSE coalesce(c.observed_by, []) + 'http_probe' END,
                                c.updated_at = datetime()
                            """,
                            cert_key=cert_key, user_id=user_id, project_id=project_id, props=cert_props
                        )
                        stats["certificates_created"] += 1

                        # Reconcile a pre-migration 'legacy:'-keyed duplicate of THIS
                        # cert. Scoped to recon-owned rows: matching on subject_cn
                        # alone deleted a GVM certificate that merely shared a
                        # common name, which is the cross-source data loss Phase
                        # 0.3 exists to prevent.
                        if subject_cn:
                            session.run(
                                """
                                MATCH (old:Certificate {subject_cn: $subject_cn, user_id: $user_id, project_id: $project_id})
                                WHERE old.cert_key STARTS WITH 'legacy:'
                                  AND NOT coalesce(old.source, '') IN $non_recon
                                DETACH DELETE old
                                """,
                                subject_cn=subject_cn, user_id=user_id, project_id=project_id,
                                non_recon=list(NON_RECON_SOURCES)
                            )

                        # BaseURL -[:HAS_CERTIFICATE]-> Certificate: the documented
                        # anchor (a cert is presented per host:port, not per path).
                        session.run(
                            """
                            MATCH (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                            MATCH (c:Certificate {cert_key: $cert_key, user_id: $user_id, project_id: $project_id})
                            MERGE (u)-[:HAS_CERTIFICATE]->(c)
                            """,
                            base_url=base_url, cert_key=cert_key,
                            project_id=project_id, user_id=user_id
                        )
                        stats["relationships_created"] += 1

                    # Create relationship: Service -[:SERVES_URL]-> BaseURL
                    # BaseURLs are served by HTTP/HTTPS services running on ports
                    if host:
                        resolved_ip = url_info.get("ip")
                        # Extract actual port from URL (e.g., http://example.com:8080)
                        # Only use default ports (80/443) if no explicit port in URL
                        parsed_url = urlparse(url)
                        port_number = parsed_url.port or (443 if scheme == "https" else 80)
                        default_service_name = "https" if scheme == "https" else "http"

                        if resolved_ip:
                            # Check if a service already exists for this port/IP (from port scan)
                            # If so, reuse it instead of creating a duplicate with different name
                            existing_service = session.run(
                                """
                                MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                RETURN svc.name as name LIMIT 1
                                """,
                                port_number=port_number, ip_addr=resolved_ip,
                                user_id=user_id, project_id=project_id
                            ).single()

                            if existing_service:
                                # Use the existing service name (e.g., http-proxy from port scan)
                                service_name = existing_service["name"]
                            else:
                                # No existing service, create one with default name (http/https)
                                service_name = default_service_name
                                session.run(
                                    """
                                    MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                    SET svc.updated_at = datetime()
                                    """,
                                    service_name=service_name, port_number=port_number, ip_addr=resolved_ip,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["services_created"] += 1

                            # Create relationship: Service -[:SERVES_URL]-> BaseURL
                            # (Patch D: BaseURL is now host-level — one per Service)
                            session.run(
                                """
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                                MERGE (svc)-[:SERVES_URL]->(u)
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=resolved_ip, base_url=base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                            # Also ensure Port node exists and is connected to Service
                            session.run(
                                """
                                MERGE (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET p.state = 'open',
                                    p.updated_at = datetime()
                                WITH p
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                port_number=port_number, ip_addr=resolved_ip,
                                service_name=service_name,
                                user_id=user_id, project_id=project_id
                            )

                            # Also ensure IP -[:HAS_PORT]-> Port relationship exists
                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                ip_addr=resolved_ip, port_number=port_number,
                                user_id=user_id, project_id=project_id
                            )

                    # Process technologies from both httpx and wappalyzer
                    # Track processed tech names to avoid duplicates
                    processed_techs = set()

                    # 1. Process technologies from httpx first
                    httpx_technologies = url_info.get("technologies", [])
                    for tech_str in httpx_technologies:
                        try:
                            # Parse technology string (e.g., "Nginx:1.19.0" or "Ubuntu")
                            if ":" in tech_str:
                                tech_name, tech_version = tech_str.split(":", 1)
                            else:
                                tech_name = tech_str
                                tech_version = None

                            # Get additional info from wappalyzer if available
                            wap_info = all_technologies.get(tech_name, {})
                            categories = wap_info.get("categories", [])
                            confidence = wap_info.get("confidence", 100)

                            tech_props = {
                                "name": tech_name,
                                "user_id": user_id,
                                "project_id": project_id,
                                "version": tech_version,
                                "categories": categories,
                                "confidence": confidence,
                                "detected_by": "httpx"
                            }

                            # Remove None values
                            tech_props = {k: v for k, v in tech_props.items() if v is not None}

                            # Collapse a versionless/versioned twin of the same
                            # technology onto one node before merging.
                            tech_version = resolve_tech_version(
                                session, tech_name, tech_version, user_id, project_id)
                            tech_props["version"] = tech_version

                            # Create Technology node (unique by name + version + tenant)
                            if tech_version:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                    SET t += $props,
                                        t.updated_at = datetime()
                                    """,
                                    name=tech_name, version=tech_version, props=tech_props,
                                    user_id=user_id, project_id=project_id
                                )
                                processed_techs.add((tech_name, tech_version))
                            else:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET t += $props, t.updated_at = datetime()
                                    ON MATCH SET t.updated_at = datetime()
                                    """,
                                    name=tech_name, props=tech_props,
                                    user_id=user_id, project_id=project_id
                                )
                                processed_techs.add((tech_name, None))
                            stats["technologies_created"] += 1

                            # Create relationship: Endpoint -[:USES_TECHNOLOGY]-> Technology
                            # (Patch D: technologies are detected per-path-response → Endpoint)
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    path=path, base_url=base_url, tech_name=tech_name, tech_version=tech_version, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: '', user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    path=path, base_url=base_url, tech_name=tech_name, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Technology {tech_str} failed: {e}")

                    # AI surface recon: MERGE Technology(category=ai-*) when the
                    # url_entry carries an AI framework / frontend annotation.
                    # (Patch D: edge now hangs off Endpoint, not BaseURL —
                    #  AI signals are observed at the response/path level.)
                    ai_name = url_info.get("ai_framework_name")
                    ai_category = url_info.get("ai_framework_category")
                    if ai_name and ai_category:
                        # Pick a precise detected_by based on which signal fired
                        if url_info.get("is_ai_framework_detected") and ai_name != url_info.get("ai_frontend_product_guess"):
                            ai_detected_by = "httpx-ai-header"
                        elif url_info.get("ai_frontend_product_guess") == ai_name:
                            # Favicon vs title — favicon wins when both fire. The
                            # parse_httpx_output annotator already prefers favicon,
                            # so distinguishing here requires inspecting the entry
                            # for an explicit favicon hit. We default to header
                            # for safety; favicon/title operators can refine in
                            # later phases when the favicon catalogue is filled.
                            ai_detected_by = "httpx-ai-favicon" if url_info.get("favicon_hash") else "httpx-ai-title"
                        else:
                            ai_detected_by = "httpx-ai-header"

                        try:
                            session.run(
                                """
                                MERGE (t:Technology {name: $name, user_id: $user_id, project_id: $project_id})
                                SET t.category = $category,
                                    t.source = 'ai-surface-recon',
                                    t.updated_at = datetime()
                                """,
                                name=ai_name, category=ai_category,
                                user_id=user_id, project_id=project_id,
                            )
                            stats.setdefault("ai_technologies_created", 0)
                            stats["ai_technologies_created"] += 1

                            session.run(
                                """
                                MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                MATCH (t:Technology {name: $name, user_id: $user_id, project_id: $project_id})
                                MERGE (e)-[r:USES_TECHNOLOGY]->(t)
                                SET r.detected_by = $detected_by,
                                    r.confidence = coalesce(r.confidence, 100)
                                """,
                                path=path, base_url=base_url, name=ai_name, detected_by=ai_detected_by,
                                user_id=user_id, project_id=project_id,
                            )
                            stats["relationships_created"] += 1
                        except Exception as e:
                            stats["errors"].append(
                                f"AI Technology {ai_name!r} on {url} failed: {e}"
                            )

                    # 2. Process wappalyzer technologies not found by httpx
                    # wappalyzer.by_url contains complete tech list per URL
                    # (plugins, analytics, security_tools, frameworks are just filtered subsets by category)
                    wappalyzer_by_url = wappalyzer.get("by_url", {})
                    wap_techs_for_url = wappalyzer_by_url.get(url, [])

                    for wap_tech in wap_techs_for_url:
                        try:
                            tech_name = wap_tech.get("name", "")
                            tech_version = wap_tech.get("version")  # Can be None

                            # Skip if already processed from httpx
                            if (tech_name, tech_version) in processed_techs:
                                continue
                            # Also skip if httpx found it without version but wappalyzer has version
                            if (tech_name, None) in processed_techs:
                                continue

                            categories = wap_tech.get("categories", [])
                            confidence = wap_tech.get("confidence", 100)

                            tech_props = {
                                "name": tech_name,
                                "user_id": user_id,
                                "project_id": project_id,
                                "version": tech_version,
                                "categories": categories,
                                "confidence": confidence,
                                "detected_by": "wappalyzer"
                            }

                            # Remove None values
                            tech_props = {k: v for k, v in tech_props.items() if v is not None}

                            # Same twin-collapsing as the httpx path above: the two
                            # detectors disagree on version presence often (React
                            # 18.2.0 from httpx vs bare React from wappalyzer).
                            tech_version = resolve_tech_version(
                                session, tech_name, tech_version, user_id, project_id)
                            tech_props["version"] = tech_version

                            # Create Technology node
                            if tech_version:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                    SET t += $props,
                                        t.updated_at = datetime()
                                    """,
                                    name=tech_name, version=tech_version, props=tech_props,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET t += $props, t.updated_at = datetime()
                                    ON MATCH SET t.updated_at = datetime()
                                    """,
                                    name=tech_name, props=tech_props,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["technologies_created"] += 1

                            # Create relationship: Endpoint -[:USES_TECHNOLOGY]-> Technology
                            # (Patch D: wappalyzer detects technologies from per-path responses → Endpoint)
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    path=path, base_url=base_url, tech_name=tech_name, tech_version=tech_version, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: '', user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    path=path, base_url=base_url, tech_name=tech_name, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Wappalyzer technology {tech_name} failed: {e}")

                    # Process headers
                    headers = url_info.get("headers", {})
                    security_headers = ["x-frame-options", "x-xss-protection", "content-security-policy",
                                        "strict-transport-security", "x-content-type-options"]
                    tech_revealing_headers = ["server", "x-powered-by", "x-aspnet-version"]

                    for header_name, header_value in headers.items():
                        try:
                            is_security = header_name.lower() in security_headers
                            reveals_tech = header_name.lower() in tech_revealing_headers

                            # (Patch D: Header keyed by full URL is fine — headers are
                            # response-specific. We MERGE per (name, value, full url)
                            # then link to the Endpoint that produced the response.)
                            session.run(
                                """
                                MERGE (h:Header {name: $name, value: $value, baseurl: $url, user_id: $user_id, project_id: $project_id})
                                SET h.user_id = $user_id,
                                    h.project_id = $project_id,
                                    h.is_security_header = $is_security,
                                    h.reveals_technology = $reveals_tech,
                                    h.updated_at = datetime()
                                """,
                                name=header_name, value=str(header_value), url=url,
                                user_id=user_id, project_id=project_id,
                                is_security=is_security, reveals_tech=reveals_tech
                            )
                            stats["headers_created"] += 1

                            # Create relationship: Endpoint -[:HAS_HEADER]-> Header
                            # (Patch D: headers come from a specific path response → Endpoint)
                            session.run(
                                """
                                MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                MATCH (h:Header {name: $name, value: $value, baseurl: $url, user_id: $user_id, project_id: $project_id})
                                MERGE (e)-[:HAS_HEADER]->(h)
                                """,
                                path=path, base_url=base_url, url=url,
                                name=header_name, value=str(header_value),
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Header {header_name} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"URL {url} processing failed: {e}")

            # Update Domain node with http probe metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            summary = http_probe_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.http_probe_timestamp = $scan_timestamp,
                            d.http_probe_live_urls = $live_urls,
                            d.http_probe_technology_count = $tech_count,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        live_urls=summary.get("live_urls", 0),
                        tech_count=summary.get("technology_count", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            # --- Update Subdomain nodes with HTTP probe status ---
            by_host = http_probe_data.get("by_host", {})
            for hostname, host_info in by_host.items():
                try:
                    status_codes = host_info.get("status_codes", [])  # already sorted int list
                    live_urls = host_info.get("live_urls", [])

                    # Determine status as the primary HTTP status code (string)
                    # Priority: lowest non-5xx code, then lowest overall
                    if status_codes:
                        non_error = [c for c in status_codes if c < 500]
                        primary = min(non_error) if non_error else min(status_codes)
                        http_status = str(primary)
                    else:
                        http_status = "no_http"

                    session.run(
                        """
                        MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                        SET s.status = $status,
                            s.status_codes = $status_codes,
                            s.http_live_url_count = $live_count,
                            s.http_probed_at = datetime(),
                            s.updated_at = datetime()
                        """,
                        hostname=hostname, user_id=user_id, project_id=project_id,
                        status=http_status, status_codes=status_codes,
                        live_count=len(live_urls)
                    )
                    stats["subdomains_updated"] += 1
                except Exception as e:
                    stats["errors"].append(f"Subdomain status update for {hostname}: {e}")

            # Mark resolved subdomains that got no HTTP response at all as "no_http"
            all_probed_hosts = set(by_host.keys())
            # IP mode probes the IP literal while the Subdomain node carries the
            # placeholder name minted for that IP ("21.40.250.84" -> "21-40-250-84"),
            # so translate before the diff or every live IP-mode host is demoted.
            ip_to_hostname = (recon_data.get("metadata") or {}).get("ip_to_hostname", {})
            all_probed_hosts |= {ip_to_hostname[h] for h in all_probed_hosts if h in ip_to_hostname}
            all_target_subs = set(recon_data.get("subdomains", []))
            no_response_hosts = all_target_subs - all_probed_hosts
            if no_response_hosts:
                session.run(
                    """
                    UNWIND $hosts AS hostname
                    MATCH (s:Subdomain {name: hostname, user_id: $user_id, project_id: $project_id})
                    WHERE s.status = 'resolved'
                    SET s.status = 'no_http',
                        s.http_probed_at = datetime(),
                        s.updated_at = datetime()
                    """,
                    hosts=list(no_response_hosts), user_id=user_id, project_id=project_id
                )

            print(f"[+][graph-db] Created {stats['baseurls_created']} BaseURL nodes")
            print(f"[+][graph-db] Created/Updated {stats['services_created']} Service nodes")
            print(f"[+][graph-db] Created {stats['technologies_created']} Technology nodes")
            print(f"[+][graph-db] Created {stats['headers_created']} Header nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            print(f"[+][graph-db] Updated {stats['subdomains_updated']} Subdomain statuses")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats
