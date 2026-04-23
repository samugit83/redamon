"""
Neo4j Graph Database Client for RedAmon Reconnaissance Data

This client initializes the graph database with reconnaissance data
after the domain_discovery module completes.

Usage:
    from graph_db import Neo4jClient

    client = Neo4jClient()
    client.update_graph_from_domain_discovery(recon_data, user_id, project_id)
    client.close()
"""

import os
import hashlib
import re
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Load environment variables from local .env file
load_dotenv(Path(__file__).parent / ".env")


# =============================================================================
# CPE Parsing & Resolution Helpers (for GVM Technology Integration)
# =============================================================================

# Curated display names for non-HTTP technologies detected by GVM
_GVM_DISPLAY_NAMES = {
    # SSH / Security
    ("openbsd", "openssh"): "OpenSSH",
    ("openssl", "openssl"): "OpenSSL",
    # Operating Systems
    ("canonical", "ubuntu_linux"): "Ubuntu",
    ("linux", "kernel"): "Linux",
    ("debian", "debian_linux"): "Debian",
    ("centos", "centos"): "CentOS",
    ("redhat", "enterprise_linux"): "Red Hat Enterprise Linux",
    ("microsoft", "windows"): "Windows",
    ("freebsd", "freebsd"): "FreeBSD",
    ("apple", "mac_os_x"): "macOS",
    ("alpinelinux", "alpine_linux"): "Alpine Linux",
    ("fedoraproject", "fedora"): "Fedora",
    ("oracle", "linux"): "Oracle Linux",
    ("suse", "linux_enterprise_server"): "SUSE Linux",
    ("amazon", "linux"): "Amazon Linux",
    # FTP / Mail / DNS
    ("proftpd", "proftpd"): "ProFTPD",
    ("vsftpd_project", "vsftpd"): "vsftpd",
    ("pureftpd", "pure-ftpd"): "Pure-FTPd",
    ("postfix", "postfix"): "Postfix",
    ("exim", "exim"): "Exim",
    ("dovecot", "dovecot"): "Dovecot",
    ("isc", "bind"): "BIND",
    ("samba", "samba"): "Samba",
}

# Reverse CPE mappings: (vendor, product) -> display name
# Inlined from recon/helpers/cve_helpers.py CPE_MAPPINGS to avoid cross-module imports
_REVERSE_CPE_MAPPINGS = {
    ("f5", "nginx"): "Nginx",
    ("apache", "http_server"): "Apache HTTP Server",
    ("microsoft", "internet_information_services"): "IIS",
    ("apache", "tomcat"): "Apache Tomcat",
    ("lighttpd", "lighttpd"): "Lighttpd",
    ("caddyserver", "caddy"): "Caddy",
    ("litespeedtech", "litespeed_web_server"): "LiteSpeed",
    ("gunicorn", "gunicorn"): "Gunicorn",
    ("encode", "uvicorn"): "Uvicorn",
    ("traefik", "traefik"): "Traefik",
    ("envoyproxy", "envoy"): "Envoy",
    ("php", "php"): "PHP",
    ("python", "python"): "Python",
    ("nodejs", "node.js"): "Node.js",
    ("ruby-lang", "ruby"): "Ruby",
    ("perl", "perl"): "Perl",
    ("golang", "go"): "Go",
    ("oracle", "mysql"): "MySQL",
    ("mariadb", "mariadb"): "MariaDB",
    ("postgresql", "postgresql"): "PostgreSQL",
    ("mongodb", "mongodb"): "MongoDB",
    ("redis", "redis"): "Redis",
    ("elastic", "elasticsearch"): "Elasticsearch",
    ("apache", "couchdb"): "CouchDB",
    ("memcached", "memcached"): "Memcached",
    ("wordpress", "wordpress"): "WordPress",
    ("drupal", "drupal"): "Drupal",
    ("joomla", "joomla"): "Joomla",
    ("djangoproject", "django"): "Django",
    ("laravel", "laravel"): "Laravel",
    ("vmware", "spring_framework"): "Spring",
    ("palletsprojects", "flask"): "Flask",
    ("expressjs", "express"): "Express",
    ("rubyonrails", "rails"): "Rails",
    ("jquery", "jquery"): "jQuery",
    ("angular", "angular"): "Angular",
    ("facebook", "react"): "React",
    ("vuejs", "vue.js"): "Vue.js",
    ("getbootstrap", "bootstrap"): "Bootstrap",
    ("vercel", "next.js"): "Next.js",
    ("grafana", "grafana"): "Grafana",
    ("jenkins", "jenkins"): "Jenkins",
    ("gitlab", "gitlab"): "GitLab",
    ("sonarsource", "sonarqube"): "SonarQube",
    ("sonatype", "nexus_repository_manager"): "Nexus",
    ("vmware", "rabbitmq"): "RabbitMQ",
    ("apache", "kafka"): "Kafka",
    ("apache", "zookeeper"): "ZooKeeper",
    ("eclipse", "jetty"): "Jetty",
    ("redhat", "wildfly"): "WildFly",
    ("phusion", "passenger"): "Passenger",
    ("phpmyadmin", "phpmyadmin"): "phpMyAdmin",
    ("webmin", "webmin"): "Webmin",
    ("roundcube", "webmail"): "Roundcube",
    ("minio", "minio"): "MinIO",
    ("squid-cache", "squid"): "Squid",
    ("haproxy", "haproxy"): "HAProxy",
    ("varnish-software", "varnish_cache"): "Varnish",
}

# Protocol-level CPEs to skip (not actual products)
_CPE_SKIP_LIST = {
    ("ietf", "secure_shell_protocol"),
}

# Lazy-loaded Wappalyzer reverse CPE cache
_WAPPALYZER_REVERSE_CPE = None


def _parse_cpe_string(cpe: str):
    """
    Parse a CPE string (2.2 or 2.3 format) into structured components.

    CPE 2.2: cpe:/a:apache:http_server:2.4.49
    CPE 2.3: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

    Returns dict {part, vendor, product, version} or None.
    """
    if not cpe:
        return None

    if cpe.startswith("cpe:2.3:"):
        # CPE 2.3: cpe:2.3:part:vendor:product:version:...
        parts = cpe.split(":")
        if len(parts) >= 6:
            version = parts[5] if parts[5] not in ("*", "-", "") else None
            return {
                "part": parts[2],
                "vendor": parts[3],
                "product": parts[4],
                "version": version,
            }
    elif cpe.startswith("cpe:/"):
        # CPE 2.2: cpe:/part:vendor:product:version
        body = cpe[5:]  # strip "cpe:/"
        parts = body.split(":")
        if len(parts) >= 3:
            version = parts[3] if len(parts) > 3 and parts[3] else None
            return {
                "part": parts[0],
                "vendor": parts[1],
                "product": parts[2],
                "version": version,
            }

    return None


def _load_wappalyzer_reverse_cpe():
    """
    Lazy-load the Wappalyzer technology cache and build a reverse CPE lookup.

    Returns dict mapping (vendor, product) -> technology display name.
    """
    global _WAPPALYZER_REVERSE_CPE
    if _WAPPALYZER_REVERSE_CPE is not None:
        return _WAPPALYZER_REVERSE_CPE

    _WAPPALYZER_REVERSE_CPE = {}
    # Try multiple paths (works from different execution contexts)
    candidates = [
        Path(__file__).parent.parent / "recon" / "data" / "wappalyzer_cache" / "technologies.json",
        Path(__file__).parent.parent.parent / "recon" / "data" / "wappalyzer_cache" / "technologies.json",
    ]
    for cache_path in candidates:
        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    data = json.load(f)
                for name, info in data.get("technologies", {}).items():
                    cpe = info.get("cpe", "")
                    if not cpe:
                        continue
                    parsed = _parse_cpe_string(cpe)
                    if parsed:
                        key = (parsed["vendor"], parsed["product"])
                        # First match wins (don't overwrite)
                        _WAPPALYZER_REVERSE_CPE.setdefault(key, name)
                print(f"[+] Loaded Wappalyzer reverse CPE cache: {len(_WAPPALYZER_REVERSE_CPE)} entries")
                break
            except Exception as e:
                print(f"[!] Failed to load Wappalyzer cache from {cache_path}: {e}")

    return _WAPPALYZER_REVERSE_CPE


def _resolve_cpe_to_display_name(vendor: str, product: str) -> str:
    """
    Resolve a CPE (vendor, product) pair to a Technology display name
    that matches httpx/Wappalyzer naming conventions.

    Resolution order:
    1. Wappalyzer reverse CPE lookup (exact match)
    2. _GVM_DISPLAY_NAMES (curated non-HTTP technologies)
    3. _REVERSE_CPE_MAPPINGS (from CPE_MAPPINGS in cve_helpers.py)
    4. Humanized CPE product name (replace underscores, title-case)
    """
    key = (vendor, product)

    # 1. Wappalyzer reverse CPE (best match for recon name consistency)
    wap_cache = _load_wappalyzer_reverse_cpe()
    if key in wap_cache:
        return wap_cache[key]

    # 2. Curated GVM display names (non-HTTP technologies)
    if key in _GVM_DISPLAY_NAMES:
        return _GVM_DISPLAY_NAMES[key]

    # 3. Reverse CPE mappings (from cve_helpers)
    if key in _REVERSE_CPE_MAPPINGS:
        return _REVERSE_CPE_MAPPINGS[key]

    # 4. Humanized fallback: replace underscores, title-case
    return product.replace("_", " ").title()


def _is_ip_address(host: str) -> bool:
    """Check if a string is an IP address (IPv4 or IPv6)."""
    if not host:
        return False
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    return bool(re.match(ipv4_pattern, host) or re.match(ipv6_pattern, host))


class Neo4jClient:
    def __init__(self, uri=None, user=None, password=None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))

    def close(self):
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def verify_connection(self):
        """Verify the connection to Neo4j is working."""
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS test")
                return result.single()["test"] == 1
        except Exception as e:
            print(f"[!][graph-db] Neo4j connection failed: {e}")
            return False

    def _init_schema(self, session):
        """Initialize constraints and indexes for the graph schema."""
        # Drop old global constraints that conflict with tenant-scoped ones
        for stmt in [
            "DROP CONSTRAINT subdomain_unique IF EXISTS",
            "DROP CONSTRAINT ip_unique IF EXISTS",
            "DROP CONSTRAINT baseurl_unique IF EXISTS",
        ]:
            try:
                session.run(stmt)
            except Exception:
                pass

        # Constraints (tenant-scoped for per-project nodes, global for shared reference nodes)
        constraints = [
            "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE (d.name, d.user_id, d.project_id) IS UNIQUE",
            "CREATE CONSTRAINT subdomain_unique IF NOT EXISTS FOR (s:Subdomain) REQUIRE (s.name, s.user_id, s.project_id) IS UNIQUE",
            "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IP) REQUIRE (i.address, i.user_id, i.project_id) IS UNIQUE",
            "CREATE CONSTRAINT baseurl_unique IF NOT EXISTS FOR (u:BaseURL) REQUIRE (u.url, u.user_id, u.project_id) IS UNIQUE",
            "CREATE CONSTRAINT port_unique IF NOT EXISTS FOR (p:Port) REQUIRE (p.number, p.protocol, p.ip_address, p.user_id, p.project_id) IS UNIQUE",
            "CREATE CONSTRAINT service_unique IF NOT EXISTS FOR (svc:Service) REQUIRE (svc.name, svc.port_number, svc.ip_address, svc.user_id, svc.project_id) IS UNIQUE",
            "CREATE CONSTRAINT technology_unique IF NOT EXISTS FOR (t:Technology) REQUIRE (t.name, t.version, t.user_id, t.project_id) IS UNIQUE",
            "CREATE CONSTRAINT endpoint_unique IF NOT EXISTS FOR (e:Endpoint) REQUIRE (e.path, e.method, e.baseurl, e.user_id, e.project_id) IS UNIQUE",
            "CREATE CONSTRAINT parameter_unique IF NOT EXISTS FOR (p:Parameter) REQUIRE (p.name, p.position, p.endpoint_path, p.baseurl, p.user_id, p.project_id) IS UNIQUE",
            "CREATE CONSTRAINT header_unique IF NOT EXISTS FOR (h:Header) REQUIRE (h.name, h.value, h.baseurl, h.user_id, h.project_id) IS UNIQUE",
            "CREATE CONSTRAINT dnsrecord_unique IF NOT EXISTS FOR (dns:DNSRecord) REQUIRE (dns.type, dns.value, dns.subdomain, dns.user_id, dns.project_id) IS UNIQUE",
            "CREATE CONSTRAINT certificate_unique IF NOT EXISTS FOR (c:Certificate) REQUIRE (c.subject_cn, c.user_id, c.project_id) IS UNIQUE",
            "CREATE CONSTRAINT traceroute_unique IF NOT EXISTS FOR (tr:Traceroute) REQUIRE (tr.target_ip, tr.user_id, tr.project_id) IS UNIQUE",
            "CREATE CONSTRAINT cve_unique IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT mitredata_unique IF NOT EXISTS FOR (m:MitreData) REQUIRE m.id IS UNIQUE",
            "CREATE CONSTRAINT capec_unique IF NOT EXISTS FOR (cap:Capec) REQUIRE cap.capec_id IS UNIQUE",
            "CREATE CONSTRAINT vulnerability_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT exploit_unique IF NOT EXISTS FOR (e:Exploit) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT exploitgvm_unique IF NOT EXISTS FOR (e:ExploitGvm) REQUIRE e.id IS UNIQUE",
            # GitHub Secret Hunt constraints
            "CREATE CONSTRAINT githubhunt_unique IF NOT EXISTS FOR (gh:GithubHunt) REQUIRE gh.id IS UNIQUE",
            "CREATE CONSTRAINT githubrepo_unique IF NOT EXISTS FOR (gr:GithubRepository) REQUIRE gr.id IS UNIQUE",
            "CREATE CONSTRAINT githubpath_unique IF NOT EXISTS FOR (gp:GithubPath) REQUIRE gp.id IS UNIQUE",
            "CREATE CONSTRAINT githubsecret_unique IF NOT EXISTS FOR (gs:GithubSecret) REQUIRE gs.id IS UNIQUE",
            "CREATE CONSTRAINT githubsensitivefile_unique IF NOT EXISTS FOR (gsf:GithubSensitiveFile) REQUIRE gsf.id IS UNIQUE",
            # TruffleHog Secret Scanner constraints
            "CREATE CONSTRAINT trufflehogscan_unique IF NOT EXISTS FOR (ts:TrufflehogScan) REQUIRE ts.id IS UNIQUE",
            "CREATE CONSTRAINT trufflehogrepository_unique IF NOT EXISTS FOR (tr:TrufflehogRepository) REQUIRE tr.id IS UNIQUE",
            "CREATE CONSTRAINT trufflehogfinding_unique IF NOT EXISTS FOR (tf:TrufflehogFinding) REQUIRE tf.id IS UNIQUE",
            # Secret constraints
            "CREATE CONSTRAINT secret_unique IF NOT EXISTS FOR (s:Secret) REQUIRE (s.id) IS UNIQUE",
            # External Domain constraints
            "CREATE CONSTRAINT externaldomain_unique IF NOT EXISTS FOR (ed:ExternalDomain) REQUIRE (ed.domain, ed.user_id, ed.project_id) IS UNIQUE",
            # OTX Threat Intelligence constraints
            "CREATE CONSTRAINT threatpulse_unique IF NOT EXISTS FOR (tp:ThreatPulse) REQUIRE (tp.pulse_id, tp.user_id, tp.project_id) IS UNIQUE",
            "CREATE CONSTRAINT malware_unique IF NOT EXISTS FOR (m:Malware) REQUIRE (m.hash, m.user_id, m.project_id) IS UNIQUE",
            # Attack Chain Graph constraints
            "CREATE CONSTRAINT attack_chain_id IF NOT EXISTS FOR (ac:AttackChain) REQUIRE ac.chain_id IS UNIQUE",
            "CREATE CONSTRAINT chain_step_id IF NOT EXISTS FOR (s:ChainStep) REQUIRE s.step_id IS UNIQUE",
            "CREATE CONSTRAINT chain_finding_id IF NOT EXISTS FOR (f:ChainFinding) REQUIRE f.finding_id IS UNIQUE",
            "CREATE CONSTRAINT chain_decision_id IF NOT EXISTS FOR (d:ChainDecision) REQUIRE d.decision_id IS UNIQUE",
            "CREATE CONSTRAINT chain_failure_id IF NOT EXISTS FOR (fl:ChainFailure) REQUIRE fl.failure_id IS UNIQUE",
        ]

        # Tenant composite indexes
        tenant_indexes = [
            "CREATE INDEX idx_domain_tenant IF NOT EXISTS FOR (d:Domain) ON (d.user_id, d.project_id)",
            "CREATE INDEX idx_subdomain_tenant IF NOT EXISTS FOR (s:Subdomain) ON (s.user_id, s.project_id)",
            "CREATE INDEX idx_ip_tenant IF NOT EXISTS FOR (i:IP) ON (i.user_id, i.project_id)",
            "CREATE INDEX idx_port_tenant IF NOT EXISTS FOR (p:Port) ON (p.user_id, p.project_id)",
            "CREATE INDEX idx_dnsrecord_tenant IF NOT EXISTS FOR (dns:DNSRecord) ON (dns.user_id, dns.project_id)",
            "CREATE INDEX idx_baseurl_tenant IF NOT EXISTS FOR (u:BaseURL) ON (u.user_id, u.project_id)",
            "CREATE INDEX idx_technology_tenant IF NOT EXISTS FOR (t:Technology) ON (t.user_id, t.project_id)",
            "CREATE INDEX idx_header_tenant IF NOT EXISTS FOR (h:Header) ON (h.user_id, h.project_id)",
            "CREATE INDEX idx_endpoint_tenant IF NOT EXISTS FOR (e:Endpoint) ON (e.user_id, e.project_id)",
            "CREATE INDEX idx_parameter_tenant IF NOT EXISTS FOR (p:Parameter) ON (p.user_id, p.project_id)",
            "CREATE INDEX idx_vulnerability_tenant IF NOT EXISTS FOR (v:Vulnerability) ON (v.user_id, v.project_id)",
            "CREATE INDEX idx_exploit_tenant IF NOT EXISTS FOR (e:Exploit) ON (e.user_id, e.project_id)",
            "CREATE INDEX idx_exploitgvm_tenant IF NOT EXISTS FOR (e:ExploitGvm) ON (e.user_id, e.project_id)",
            # GitHub Secret Hunt tenant indexes
            "CREATE INDEX idx_githubhunt_tenant IF NOT EXISTS FOR (gh:GithubHunt) ON (gh.user_id, gh.project_id)",
            "CREATE INDEX idx_githubrepo_tenant IF NOT EXISTS FOR (gr:GithubRepository) ON (gr.user_id, gr.project_id)",
            "CREATE INDEX idx_githubpath_tenant IF NOT EXISTS FOR (gp:GithubPath) ON (gp.user_id, gp.project_id)",
            "CREATE INDEX idx_githubsecret_tenant IF NOT EXISTS FOR (gs:GithubSecret) ON (gs.user_id, gs.project_id)",
            "CREATE INDEX idx_githubsensitivefile_tenant IF NOT EXISTS FOR (gsf:GithubSensitiveFile) ON (gsf.user_id, gsf.project_id)",
            # TruffleHog Secret Scanner tenant indexes
            "CREATE INDEX idx_trufflehogscan_tenant IF NOT EXISTS FOR (ts:TrufflehogScan) ON (ts.user_id, ts.project_id)",
            "CREATE INDEX idx_trufflehogrepository_tenant IF NOT EXISTS FOR (tr:TrufflehogRepository) ON (tr.user_id, tr.project_id)",
            "CREATE INDEX idx_trufflehogfinding_tenant IF NOT EXISTS FOR (tf:TrufflehogFinding) ON (tf.user_id, tf.project_id)",
            # Secret tenant indexes
            "CREATE INDEX idx_secret_tenant IF NOT EXISTS FOR (s:Secret) ON (s.user_id, s.project_id)",
            # External Domain tenant indexes
            "CREATE INDEX idx_externaldomain_tenant IF NOT EXISTS FOR (ed:ExternalDomain) ON (ed.user_id, ed.project_id)",
            # OTX Threat Intelligence tenant indexes
            "CREATE INDEX idx_threatpulse_tenant IF NOT EXISTS FOR (tp:ThreatPulse) ON (tp.user_id, tp.project_id)",
            "CREATE INDEX idx_malware_tenant IF NOT EXISTS FOR (m:Malware) ON (m.user_id, m.project_id)",
            # Attack Chain Graph tenant indexes
            "CREATE INDEX idx_attackchain_tenant IF NOT EXISTS FOR (ac:AttackChain) ON (ac.user_id, ac.project_id)",
            "CREATE INDEX idx_chainstep_tenant IF NOT EXISTS FOR (s:ChainStep) ON (s.user_id, s.project_id)",
            "CREATE INDEX idx_chainfinding_tenant IF NOT EXISTS FOR (f:ChainFinding) ON (f.user_id, f.project_id)",
            "CREATE INDEX idx_chaindecision_tenant IF NOT EXISTS FOR (d:ChainDecision) ON (d.user_id, d.project_id)",
            "CREATE INDEX idx_chainfailure_tenant IF NOT EXISTS FOR (fl:ChainFailure) ON (fl.user_id, fl.project_id)",
        ]

        # Additional indexes
        additional_indexes = [
            "CREATE INDEX subdomain_name IF NOT EXISTS FOR (s:Subdomain) ON (s.name)",
            "CREATE INDEX idx_subdomain_status IF NOT EXISTS FOR (s:Subdomain) ON (s.status)",
            "CREATE INDEX ip_address IF NOT EXISTS FOR (i:IP) ON (i.address)",
            "CREATE INDEX idx_service_tenant IF NOT EXISTS FOR (svc:Service) ON (svc.user_id, svc.project_id)",
            "CREATE INDEX tech_name IF NOT EXISTS FOR (t:Technology) ON (t.name)",
            "CREATE INDEX tech_name_version IF NOT EXISTS FOR (t:Technology) ON (t.name, t.version)",
            # Vulnerability indexes
            "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
            "CREATE INDEX vuln_category IF NOT EXISTS FOR (v:Vulnerability) ON (v.category)",
            "CREATE INDEX vuln_template IF NOT EXISTS FOR (v:Vulnerability) ON (v.template_id)",
            # Parameter indexes
            "CREATE INDEX param_injectable IF NOT EXISTS FOR (p:Parameter) ON (p.is_injectable)",
            # CVE indexes
            "CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity)",
            "CREATE INDEX cve_cvss IF NOT EXISTS FOR (c:CVE) ON (c.cvss)",
            "CREATE INDEX idx_cve_tenant IF NOT EXISTS FOR (c:CVE) ON (c.user_id, c.project_id)",
            # MitreData indexes
            "CREATE INDEX idx_mitredata_tenant IF NOT EXISTS FOR (m:MitreData) ON (m.user_id, m.project_id)",
            # Capec indexes
            "CREATE INDEX capec_id IF NOT EXISTS FOR (c:Capec) ON (c.capec_id)",
            "CREATE INDEX idx_capec_tenant IF NOT EXISTS FOR (c:Capec) ON (c.user_id, c.project_id)",
            # Exploit indexes
            "CREATE INDEX idx_exploit_type IF NOT EXISTS FOR (e:Exploit) ON (e.attack_type)",
            # GitHub Secret Hunt indexes
            "CREATE INDEX idx_githubrepo_name IF NOT EXISTS FOR (gr:GithubRepository) ON (gr.name)",
            "CREATE INDEX idx_githubpath_path IF NOT EXISTS FOR (gp:GithubPath) ON (gp.path)",
            "CREATE INDEX idx_githubsecret_secret_type IF NOT EXISTS FOR (gs:GithubSecret) ON (gs.secret_type)",
            # TruffleHog functional indexes
            "CREATE INDEX idx_trufflehogfinding_detector IF NOT EXISTS FOR (tf:TrufflehogFinding) ON (tf.detector_name)",
            "CREATE INDEX idx_trufflehogrepository_name IF NOT EXISTS FOR (tr:TrufflehogRepository) ON (tr.name)",
            # Secret functional indexes
            "CREATE INDEX idx_secret_type IF NOT EXISTS FOR (s:Secret) ON (s.secret_type)",
            "CREATE INDEX idx_secret_severity IF NOT EXISTS FOR (s:Secret) ON (s.severity)",
            "CREATE INDEX idx_secret_source IF NOT EXISTS FOR (s:Secret) ON (s.source)",
            # Attack Chain Graph functional indexes
            "CREATE INDEX idx_chainstep_chain IF NOT EXISTS FOR (s:ChainStep) ON (s.chain_id)",
            "CREATE INDEX idx_chainfinding_type IF NOT EXISTS FOR (f:ChainFinding) ON (f.finding_type)",
            "CREATE INDEX idx_chainfinding_severity IF NOT EXISTS FOR (f:ChainFinding) ON (f.severity)",
            "CREATE INDEX idx_chainfailure_type IF NOT EXISTS FOR (fl:ChainFailure) ON (fl.failure_type)",
            "CREATE INDEX idx_attackchain_status IF NOT EXISTS FOR (ac:AttackChain) ON (ac.status)",
        ]

        for query in constraints + tenant_indexes + additional_indexes:
            try:
                session.run(query)
            except Exception as e:
                # Ignore if constraint/index already exists
                if "already exists" not in str(e).lower():
                    print(f"[!][graph-db] Schema warning: {e}")

    def clear_project_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete all nodes and relationships for a specific project.

        This should be called before re-running a recon scan to ensure
        old data is removed and replaced with fresh results.

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted nodes and relationships
        """
        stats = {"nodes_deleted": 0, "relationships_deleted": 0}

        with self.driver.session() as session:
            # Delete all nodes and relationships for this project
            # DETACH DELETE removes the node and all its relationships
            result = session.run(
                """
                MATCH (n)
                WHERE n.user_id = $user_id AND n.project_id = $project_id
                DETACH DELETE n
                RETURN count(n) as deleted_count
                """,
                user_id=user_id, project_id=project_id
            )
            record = result.single()
            if record:
                stats["nodes_deleted"] = record["deleted_count"]

            print(f"[*][graph-db] Cleared project data: {stats['nodes_deleted']} nodes deleted")

        return stats

    def clear_gvm_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only GVM-specific nodes and relationships for a project.

        Preserves all recon data (Domain, Subdomain, IP, Port, BaseURL,
        Endpoint, Parameter, Service, etc.). Only removes:
        - Vulnerability nodes with source='gvm'
        - GVM-only CVE nodes (not shared with recon)
        - GVM-only Technology nodes (detected_by='gvm')
        - GVM enrichments on shared Technology nodes (CPE data)
        - USES_TECHNOLOGY relationships with detected_by='gvm'
        - Domain node GVM metadata properties

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted/cleaned items
        """
        stats = {
            "vulnerabilities_deleted": 0,
            "cves_deleted": 0,
            "technologies_deleted": 0,
            "technologies_cleaned": 0,
            "traceroutes_deleted": 0,
            "certificates_deleted": 0,
            "exploits_gvm_deleted": 0,
            "relationships_deleted": 0,
        }

        with self.driver.session() as session:
            # 1. Delete GVM Vulnerability nodes (and all their relationships)
            result = session.run(
                """
                MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
                WHERE v.source = 'gvm'
                DETACH DELETE v
                RETURN count(v) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["vulnerabilities_deleted"] = record["deleted"]

            # 1b. Delete Traceroute nodes
            result = session.run(
                """
                MATCH (tr:Traceroute {user_id: $uid, project_id: $pid})
                DETACH DELETE tr
                RETURN count(tr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["traceroutes_deleted"] = record["deleted"]

            # 1c. Delete GVM-sourced Certificate nodes (preserve recon/httpx certificates)
            result = session.run(
                """
                MATCH (c:Certificate {user_id: $uid, project_id: $pid})
                WHERE c.source = 'gvm'
                DETACH DELETE c
                RETURN count(c) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["certificates_deleted"] = record["deleted"]

            # 1d. Delete ExploitGvm nodes
            result = session.run(
                """
                MATCH (e:ExploitGvm {user_id: $uid, project_id: $pid})
                DETACH DELETE e
                RETURN count(e) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["exploits_gvm_deleted"] = record["deleted"]

            # 2. Delete GVM-only CVE nodes (created by ExploitGvm, not linked to non-GVM sources)
            result = session.run(
                """
                MATCH (c:CVE {user_id: $uid, project_id: $pid, source: 'gvm'})
                DETACH DELETE c
                RETURN count(c) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["cves_deleted"] = record["deleted"]

            # 3. Delete GVM-only Technology nodes (detected_by exactly 'gvm')
            result = session.run(
                """
                MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE t.detected_by = 'gvm'
                DETACH DELETE t
                RETURN count(t) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["technologies_deleted"] = record["deleted"]

            # 4. Clean shared Technology nodes (strip GVM enrichment)
            result = session.run(
                """
                MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE t.detected_by CONTAINS ',gvm'
                SET t.detected_by = replace(t.detected_by, ',gvm', ''),
                    t.cpe = null, t.cpe_vendor = null, t.cpe_product = null
                RETURN count(t) as cleaned
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["technologies_cleaned"] = record["cleaned"]

            # 5. Delete GVM USES_TECHNOLOGY relationships (Port→Tech and IP→Tech)
            result = session.run(
                """
                MATCH ({user_id: $uid, project_id: $pid})-[r:USES_TECHNOLOGY]->()
                WHERE r.detected_by = 'gvm'
                DELETE r
                RETURN count(r) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["relationships_deleted"] = record["deleted"]

            # 6. Clear Domain node GVM metadata properties
            session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                WHERE d.gvm_scan_timestamp IS NOT NULL
                REMOVE d.gvm_scan_timestamp, d.gvm_total_vulnerabilities,
                       d.gvm_critical, d.gvm_high, d.gvm_medium, d.gvm_low
                """,
                uid=user_id, pid=project_id
            )

            total = (stats["vulnerabilities_deleted"] + stats["cves_deleted"] +
                     stats["technologies_deleted"] + stats["traceroutes_deleted"] +
                     stats["certificates_deleted"] + stats["exploits_gvm_deleted"] +
                     stats["relationships_deleted"])
            print(f"[*][graph-db] Cleared GVM data: {total} items removed, "
                  f"{stats['technologies_cleaned']} shared technologies cleaned")

        return stats

    def update_graph_from_domain_discovery(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Initialize the Neo4j graph database with reconnaissance data after domain_discovery.

        This function creates:
        - Domain node (root) with WHOIS data
        - Subdomain nodes
        - IP nodes
        - DNSRecord nodes
        - All relationships between them

        Args:
            recon_data: The recon JSON data from domain_discovery module
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created nodes/relationships
        """
        stats = {
            "domain_created": False,
            "subdomains_created": 0,
            "ips_created": 0,
            "dns_records_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        with self.driver.session() as session:
            # Initialize schema first
            self._init_schema(session)

            # Extract data from recon_data
            metadata = recon_data.get("metadata", {})
            whois_data = recon_data.get("whois", {})
            subdomains = recon_data.get("subdomains", [])
            dns_data = recon_data.get("dns", {})

            root_domain = metadata.get("root_domain", "")
            target = metadata.get("target", "")
            filtered_mode = metadata.get("filtered_mode", False)
            subdomain_filter = metadata.get("subdomain_filter", [])

            if not root_domain:
                stats["errors"].append("No root_domain found in metadata")
                return stats

            # 1. Create Domain node with WHOIS data
            try:
                domain_props = {
                    "name": root_domain,
                    "user_id": user_id,
                    "project_id": project_id,
                    "scan_timestamp": metadata.get("scan_timestamp"),
                    "scan_type": metadata.get("scan_type"),
                    "target": target,
                    "filtered_mode": filtered_mode,
                    "subdomain_filter": subdomain_filter,
                    "modules_executed": metadata.get("modules_executed", []),
                    "anonymous_mode": metadata.get("anonymous_mode", False),
                    "bruteforce_mode": metadata.get("bruteforce_mode", False),
                    # WHOIS data
                    "registrar": whois_data.get("registrar"),
                    "registrar_url": whois_data.get("registrar_url"),
                    "whois_server": whois_data.get("whois_server"),
                    "dnssec": whois_data.get("dnssec"),
                    "organization": whois_data.get("org"),
                    "country": whois_data.get("country"),
                    "city": whois_data.get("city"),
                    "state": whois_data.get("state"),
                    "address": whois_data.get("address"),
                    "registrant_postal_code": whois_data.get("registrant_postal_code"),
                    "registrant_name": whois_data.get("name"),
                    "admin_name": whois_data.get("admin_name"),
                    "admin_org": whois_data.get("admin_org"),
                    "tech_name": whois_data.get("tech_name"),
                    "tech_org": whois_data.get("tech_org"),
                    "domain_name": whois_data.get("domain_name"),
                    "referral_url": whois_data.get("referral_url"),
                    "reseller": whois_data.get("reseller"),
                    "name_servers": whois_data.get("name_servers", []),
                    "whois_emails": whois_data.get("emails", []),
                    "updated_at": datetime.now().isoformat()
                }

                # Handle date fields (can be list or single value)
                for date_field in ["creation_date", "expiration_date", "updated_date"]:
                    date_val = whois_data.get(date_field)
                    if isinstance(date_val, list) and date_val:
                        domain_props[date_field] = date_val[0]
                    elif date_val:
                        domain_props[date_field] = date_val

                # Handle status (can be list)
                status = whois_data.get("status", [])
                if isinstance(status, list):
                    # Clean status strings (remove URL part)
                    domain_props["status"] = [s.split()[0] if " " in s else s for s in status]
                elif status:
                    domain_props["status"] = [status.split()[0] if " " in status else status]

                # Remove None values
                domain_props = {k: v for k, v in domain_props.items() if v is not None}

                session.run(
                    """
                    MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                    SET d += $props
                    """,
                    name=root_domain, user_id=user_id, project_id=project_id, props=domain_props
                )
                stats["domain_created"] = True
                print(f"[+][graph-db] Created Domain node: {root_domain}")
            except Exception as e:
                stats["errors"].append(f"Domain creation failed: {e}")
                print(f"[!][graph-db] Domain creation failed: {e}")

            # 2. Create Subdomain nodes and relationships
            subdomain_dns = dns_data.get("subdomains", {})
            domain_dns = dns_data.get("domain", {})  # DNS data for root domain
            subdomain_status_map = recon_data.get("subdomain_status_map", {})

            for subdomain in subdomains:
                try:
                    # Get DNS info: use domain_dns if subdomain equals root_domain, else use subdomain_dns
                    if subdomain == root_domain:
                        subdomain_info = domain_dns  # Root domain DNS is in dns.domain
                    else:
                        subdomain_info = subdomain_dns.get(subdomain, {})
                    has_records = subdomain_info.get("has_records", False)

                    # Create Subdomain node
                    status = subdomain_status_map.get(subdomain)  # None for unresolved subs
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        SET s.has_dns_records = $has_records,
                            s.status = coalesce(s.status, $status),
                            s.discovered_at = coalesce(s.discovered_at, datetime()),
                            s.updated_at = datetime()
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                        has_records=has_records, status=status
                    )
                    stats["subdomains_created"] += 1

                    # Create relationship: Subdomain -[:BELONGS_TO]-> Domain
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                        MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        """,
                        domain=root_domain, subdomain=subdomain,
                        user_id=user_id, project_id=project_id
                    )
                    stats["relationships_created"] += 1

                    # 3. Create DNS records and IP addresses
                    records = subdomain_info.get("records", {})
                    ips_data = subdomain_info.get("ips", {})

                    # Create IP nodes from resolved IPs
                    for ip_version in ["ipv4", "ipv6"]:
                        ip_list = ips_data.get(ip_version, [])
                        for ip_addr in ip_list:
                            if ip_addr:
                                try:
                                    # Create IP node
                                    session.run(
                                        """
                                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                        SET i.version = $version,
                                            i.updated_at = datetime()
                                        """,
                                        address=ip_addr, user_id=user_id, project_id=project_id,
                                        version=ip_version
                                    )
                                    stats["ips_created"] += 1

                                    # Create relationship: Subdomain -[:RESOLVES_TO]-> IP
                                    record_type = "A" if ip_version == "ipv4" else "AAAA"
                                    session.run(
                                        """
                                        MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[:RESOLVES_TO {record_type: $record_type}]->(i)
                                        """,
                                        subdomain=subdomain, ip=ip_addr, record_type=record_type,
                                        user_id=user_id, project_id=project_id
                                    )
                                    stats["relationships_created"] += 1
                                except Exception as e:
                                    stats["errors"].append(f"IP {ip_addr} creation failed: {e}")

                    # Create DNSRecord nodes for other record types
                    for record_type, record_values in records.items():
                        if record_values and record_type not in ["A", "AAAA"]:  # A/AAAA handled via IP nodes
                            if not isinstance(record_values, list):
                                record_values = [record_values]

                            for value in record_values:
                                if value:
                                    try:
                                        # Create DNSRecord node
                                        session.run(
                                            """
                                            MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain, user_id: $user_id, project_id: $project_id})
                                            SET dns.user_id = $user_id,
                                                dns.project_id = $project_id,
                                                dns.updated_at = datetime()
                                            """,
                                            type=record_type, value=str(value), subdomain=subdomain,
                                            user_id=user_id, project_id=project_id
                                        )
                                        stats["dns_records_created"] += 1

                                        # Create relationship: Subdomain -[:HAS_DNS_RECORD]-> DNSRecord
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                            MATCH (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain, user_id: $user_id, project_id: $project_id})
                                            MERGE (s)-[:HAS_DNS_RECORD]->(dns)
                                            """,
                                            subdomain=subdomain, type=record_type, value=str(value),
                                            user_id=user_id, project_id=project_id
                                        )
                                        stats["relationships_created"] += 1
                                    except Exception as e:
                                        stats["errors"].append(f"DNSRecord {record_type}={value} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain} processing failed: {e}")
                    print(f"[!][graph-db] Subdomain {subdomain} processing failed: {e}")

            print(f"[+][graph-db] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+][graph-db] Created {stats['ips_created']} IP nodes")
            print(f"[+][graph-db] Created {stats['dns_records_created']} DNSRecord nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_ip_recon(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Initialize the Neo4j graph for IP-based reconnaissance.

        Creates:
        - Mock Domain node (ip-targets.{project_id}) with ip_mode: True
        - Subdomain nodes (real hostnames from PTR or mock IP-based names)
        - IP nodes and RESOLVES_TO relationships
        - BELONGS_TO relationships from subdomains to mock domain
        - Per-IP WHOIS data on IP nodes
        """
        stats = {
            "domain_created": False,
            "subdomains_created": 0,
            "ips_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        with self.driver.session() as session:
            self._init_schema(session)

            metadata = recon_data.get("metadata", {})
            whois_data = recon_data.get("whois", {})
            subdomains = recon_data.get("subdomains", [])
            dns_data = recon_data.get("dns", {})
            ip_to_hostname = metadata.get("ip_to_hostname", {})
            ip_whois = whois_data.get("ip_whois", {})

            mock_domain = metadata.get("root_domain", f"ip-targets.{project_id}")

            # 1. Create mock Domain node
            try:
                domain_props = {
                    "name": mock_domain,
                    "user_id": user_id,
                    "project_id": project_id,
                    "ip_mode": True,
                    "is_mock": True,
                    "scan_timestamp": metadata.get("scan_timestamp"),
                    "scan_type": metadata.get("scan_type"),
                    "target_ips": metadata.get("target_ips", []),
                    "expanded_ips": metadata.get("expanded_ips", []),
                    "modules_executed": metadata.get("modules_executed", []),
                    "updated_at": datetime.now().isoformat()
                }
                domain_props = {k: v for k, v in domain_props.items() if v is not None}

                session.run(
                    """
                    MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                    SET d += $props
                    """,
                    name=mock_domain, user_id=user_id, project_id=project_id, props=domain_props
                )
                stats["domain_created"] = True
                print(f"[+][graph-db] Created mock Domain node: {mock_domain}")
            except Exception as e:
                stats["errors"].append(f"Domain creation failed: {e}")
                print(f"[!][graph-db] Domain creation failed: {e}")

            # 2. Create Subdomain nodes, IP nodes, and relationships
            subdomains_dns = dns_data.get("subdomains", {})

            for subdomain_name in subdomains:
                try:
                    sub_dns = subdomains_dns.get(subdomain_name, {})
                    is_mock = sub_dns.get("is_mock", False)
                    actual_ip = sub_dns.get("actual_ip", "")

                    # Create Subdomain node
                    sub_props = {
                        "name": subdomain_name,
                        "user_id": user_id,
                        "project_id": project_id,
                        "has_records": sub_dns.get("has_records", False),
                        "is_mock": is_mock,
                        "ip_mode": True,
                        "updated_at": datetime.now().isoformat()
                    }
                    if actual_ip:
                        sub_props["actual_ip"] = actual_ip

                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        ON CREATE SET s += $props, s.status = 'resolved'
                        ON MATCH SET s += $props
                        WITH s
                        WHERE s.status IS NULL
                        SET s.status = 'resolved'
                        """,
                        name=subdomain_name, user_id=user_id, project_id=project_id, props=sub_props
                    )
                    stats["subdomains_created"] += 1

                    # Create BELONGS_TO relationship to mock domain
                    session.run(
                        """
                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        """,
                        sub=subdomain_name, domain=mock_domain, uid=user_id, pid=project_id
                    )
                    stats["relationships_created"] += 1

                    # Create IP nodes and RESOLVES_TO relationships
                    ips = sub_dns.get("ips", {})
                    all_ips = (ips.get("ipv4", []) or []) + (ips.get("ipv6", []) or [])

                    for ip in all_ips:
                        # Get WHOIS info for this IP if available
                        whois_info = ip_whois.get(ip, {})

                        ip_props = {
                            "address": ip,
                            "user_id": user_id,
                            "project_id": project_id,
                            "version": "v6" if ":" in ip else "v4",
                            "ip_mode": True,
                            "updated_at": datetime.now().isoformat()
                        }
                        if whois_info:
                            ip_props["organization"] = whois_info.get("org", "")
                            ip_props["country"] = whois_info.get("country", "")

                        session.run(
                            """
                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            SET i += $props
                            """,
                            addr=ip, uid=user_id, pid=project_id, props=ip_props
                        )
                        stats["ips_created"] += 1

                        # RESOLVES_TO
                        session.run(
                            """
                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                            MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                            MERGE (s)-[:RESOLVES_TO]->(i)
                            """,
                            sub=subdomain_name, ip=ip, uid=user_id, pid=project_id
                        )
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain_name}: {e}")
                    print(f"[!][graph-db] Error processing {subdomain_name}: {e}")

            print(f"[+][graph-db] IP Recon graph update complete:")
            print(f"[+][graph-db] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+][graph-db] Created {stats['ips_created']} IP nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_port_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with port scan data.

        This function creates/updates:
        - Port nodes with open ports
        - Service nodes for detected services
        - Updates IP nodes with CDN information
        - Relationships: IP -[:HAS_PORT]-> Port, Port -[:RUNS_SERVICE]-> Service

        Args:
            recon_data: The recon JSON data containing port_scan results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "ports_created": 0,
            "services_created": 0,
            "ips_updated": 0,
            "relationships_created": 0,
            "errors": []
        }

        port_scan_data = recon_data.get("port_scan", {})
        if not port_scan_data:
            stats["errors"].append("No port_scan data found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized
            self._init_schema(session)

            scan_metadata = port_scan_data.get("scan_metadata", {})
            by_ip = port_scan_data.get("by_ip", {})
            by_host = port_scan_data.get("by_host", {})

            # Process by_ip data - this gives us IP -> ports mapping
            # Only update IPs that already exist in the graph (from DNS) or have open ports.
            # Skip IPs with no ports and no hostnames to avoid orphaned nodes.
            for ip_addr, ip_info in by_ip.items():
                try:
                    ports = ip_info.get("ports", [])
                    hostnames = ip_info.get("hostnames", [])

                    # Skip IPs that have no open ports and no hostname associations
                    if not ports and not hostnames:
                        continue

                    # Update IP node with CDN info if available
                    cdn_name = ip_info.get("cdn")
                    is_cdn = ip_info.get("is_cdn", False)

                    session.run(
                        """
                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        SET i.is_cdn = $is_cdn,
                            i.cdn_name = $cdn_name,
                            i.updated_at = datetime()
                        """,
                        address=ip_addr, user_id=user_id, project_id=project_id,
                        is_cdn=is_cdn, cdn_name=cdn_name
                    )
                    stats["ips_updated"] += 1

                except Exception as e:
                    stats["errors"].append(f"IP {ip_addr} update failed: {e}")

            # Process by_host data - this gives us hostname -> port details with services
            for hostname, host_info in by_host.items():
                ip_addr = host_info.get("ip")
                port_details = host_info.get("port_details", [])
                cdn_name = host_info.get("cdn")
                is_cdn = host_info.get("is_cdn", False)

                # Update IP node with CDN info (if not already done)
                if ip_addr:
                    try:
                        session.run(
                            """
                            MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            SET i.is_cdn = $is_cdn,
                                i.cdn_name = $cdn_name,
                                i.updated_at = datetime()
                            """,
                            address=ip_addr, user_id=user_id, project_id=project_id,
                            is_cdn=is_cdn, cdn_name=cdn_name
                        )
                    except Exception as e:
                        stats["errors"].append(f"IP {ip_addr} update failed: {e}")

                # Create Port and Service nodes
                for port_info in port_details:
                    port_number = port_info.get("port")
                    protocol = port_info.get("protocol", "tcp")
                    service_name = port_info.get("service")

                    if not port_number:
                        continue

                    try:
                        # Create Port node linked to IP
                        # Port uniqueness is per IP + port + protocol + tenant
                        session.run(
                            """
                            MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            SET p.state = 'open',
                                p.updated_at = datetime()
                            """,
                            port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                            user_id=user_id, project_id=project_id
                        )
                        stats["ports_created"] += 1

                        # Create relationship: IP -[:HAS_PORT]-> Port
                        if ip_addr:
                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                ip_addr=ip_addr, port_number=port_number, protocol=protocol,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create Service node if service detected
                        if service_name:
                            session.run(
                                """
                                MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET svc.updated_at = datetime()
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=ip_addr,
                                user_id=user_id, project_id=project_id
                            )
                            stats["services_created"] += 1

                            # Create relationship: Port -[:RUNS_SERVICE]-> Service
                            session.run(
                                """
                                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                                service_name=service_name, user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Port {port_number}/{protocol} on {ip_addr} failed: {e}")

            # Update Domain node with port scan metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.port_scan_timestamp = $scan_timestamp,
                            d.port_scan_type = $scan_type,
                            d.port_scan_ports_config = $ports_config,
                            d.port_scan_total_open_ports = $total_open_ports,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        scan_type=scan_metadata.get("scan_type"),
                        ports_config=scan_metadata.get("ports_config"),
                        total_open_ports=port_scan_data.get("summary", {}).get("total_open_ports", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+][graph-db] Updated {stats['ips_updated']} IP nodes with CDN info")
            print(f"[+][graph-db] Created {stats['ports_created']} Port nodes")
            print(f"[+][graph-db] Created {stats['services_created']} Service nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_http_probe(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with HTTP probe data.

        This function creates/updates:
        - BaseURL nodes with HTTP response data (root/base URLs discovered by httpx)
        - Technology nodes for detected technologies
        - Header nodes for HTTP response headers
        - Service nodes (if not existing) for the HTTP/HTTPS service
        - Relationships: Service -[:SERVES_URL]-> BaseURL, BaseURL -[:USES_TECHNOLOGY]-> Technology, BaseURL -[:HAS_HEADER]-> Header

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
            self._init_schema(session)

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

                    # Create BaseURL node (root/base URL discovered by http_probe)
                    baseurl_props = {
                        "url": url,
                        "user_id": user_id,
                        "project_id": project_id,
                        "scheme": scheme,
                        "host": host,
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
                        "source": "http_probe"
                    }

                    # Add body hash info if available
                    body_hash = url_info.get("body_hash", {})
                    if body_hash:
                        baseurl_props["body_sha256"] = body_hash.get("body_sha256")
                        baseurl_props["header_sha256"] = body_hash.get("header_sha256")

                    # Add TLS cipher if available (store on BaseURL for quick reference)
                    tls_data = url_info.get("tls", {})
                    if tls_data:
                        baseurl_props["tls_cipher"] = tls_data.get("cipher")
                        baseurl_props["tls_version"] = tls_data.get("version")

                    # Remove None values
                    baseurl_props = {k: v for k, v in baseurl_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                        SET u += $props,
                            u.updated_at = datetime()
                        """,
                        url=url, user_id=user_id, project_id=project_id, props=baseurl_props
                    )
                    stats["baseurls_created"] += 1

                    # Create Certificate node from TLS data if available
                    if tls_data and tls_data.get("certificate"):
                        cert_data = tls_data.get("certificate", {})
                        subject_cn = cert_data.get("subject_cn", "")
                        
                        if subject_cn:
                            # Build certificate properties
                            cert_props = {
                                "subject_cn": subject_cn,
                                "user_id": user_id,
                                "project_id": project_id,
                                "issuer": ", ".join(cert_data.get("issuer", [])) if isinstance(cert_data.get("issuer"), list) else cert_data.get("issuer"),
                                "not_before": cert_data.get("not_before"),
                                "not_after": cert_data.get("not_after"),
                                "san": cert_data.get("san", []),  # Subject Alternative Names as list
                                "cipher": tls_data.get("cipher"),
                                "tls_version": tls_data.get("version"),
                                "source": "http_probe"
                            }
                            
                            # Remove None values
                            cert_props = {k: v for k, v in cert_props.items() if v is not None}
                            
                            # Create Certificate node (unique by subject_cn + project_id)
                            session.run(
                                """
                                MERGE (c:Certificate {subject_cn: $subject_cn, user_id: $user_id, project_id: $project_id})
                                SET c += $props,
                                    c.updated_at = datetime()
                                """,
                                subject_cn=subject_cn, user_id=user_id, project_id=project_id, props=cert_props
                            )
                            stats["certificates_created"] += 1
                            
                            # Create relationship: BaseURL -[:HAS_CERTIFICATE]-> Certificate
                            session.run(
                                """
                                MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                MATCH (c:Certificate {subject_cn: $subject_cn, user_id: $user_id, project_id: $project_id})
                                MERGE (u)-[:HAS_CERTIFICATE]->(c)
                                """,
                                url=url, subject_cn=subject_cn, project_id=project_id, user_id=user_id
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
                            session.run(
                                """
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                MERGE (svc)-[:SERVES_URL]->(u)
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=resolved_ip, url=url,
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

                            # Create relationship: BaseURL -[:USES_TECHNOLOGY]-> Technology
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version, user_id: $user_id, project_id: $project_id})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, tech_version=tech_version, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: '', user_id: $user_id, project_id: $project_id})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Technology {tech_str} failed: {e}")

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

                            # Create relationship: BaseURL -[:USES_TECHNOLOGY]-> Technology
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version, user_id: $user_id, project_id: $project_id})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, tech_version=tech_version, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: '', user_id: $user_id, project_id: $project_id})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, confidence=confidence,
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

                            # Create relationship: BaseURL -[:HAS_HEADER]-> Header
                            session.run(
                                """
                                MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                MATCH (h:Header {name: $name, value: $value, baseurl: $url, user_id: $user_id, project_id: $project_id})
                                MERGE (u)-[:HAS_HEADER]->(h)
                                """,
                                url=url, name=header_name, value=str(header_value),
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

    def _find_cwes_with_capec(self, cwe_node: dict, results: list):
        """
        Recursively traverse CWE hierarchy and collect only CWEs that have non-empty related_capec.

        Args:
            cwe_node: CWE hierarchy node
            results: List to collect CWEs with CAPEC (passed by reference)
        """
        if not cwe_node:
            return

        # Check if this CWE has related_capec
        related_capec = cwe_node.get("related_capec", [])
        if related_capec:
            results.append(cwe_node)

        # Recursively check child
        child = cwe_node.get("child")
        if child:
            self._find_cwes_with_capec(child, results)

    def _process_cwe_with_capec(self, session, cwe_node: dict, cve_id: str, user_id: str,
                                 project_id: str, stats_mitre: dict):
        """
        Create MitreData (CWE) node and its related Capec nodes, directly connected to CVE.

        Args:
            session: Neo4j session
            cwe_node: CWE node that has related_capec
            cve_id: The CVE ID to connect to
            user_id: User identifier
            project_id: Project identifier
            stats_mitre: Dictionary to track created nodes
        """
        import json

        # Get CWE ID (support both "cwe_id" and "id" keys)
        cwe_id = cwe_node.get("cwe_id") or cwe_node.get("id")
        if not cwe_id:
            return

        # Generate unique MitreData node ID (per CVE + CWE combination)
        mitre_id = f"{cve_id}-{cwe_id}"

        # Create MitreData node with CWE properties
        mitre_props = {
            "id": mitre_id,
            "user_id": user_id,
            "project_id": project_id,
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "cwe_name": cwe_node.get("name"),
            "cwe_description": cwe_node.get("description"),
            "cwe_url": cwe_node.get("url"),
            "abstraction": cwe_node.get("abstraction"),
        }

        # Add additional fields if available
        if cwe_node.get("mapping"):
            mitre_props["mapping"] = cwe_node.get("mapping")
        if cwe_node.get("structure"):
            mitre_props["structure"] = cwe_node.get("structure")
        if cwe_node.get("consequences"):
            mitre_props["consequences"] = json.dumps(cwe_node.get("consequences"))
        if cwe_node.get("mitigations"):
            mitre_props["mitigations"] = json.dumps(cwe_node.get("mitigations"))
        if cwe_node.get("detection_methods"):
            mitre_props["detection_methods"] = json.dumps(cwe_node.get("detection_methods"))

        # Remove None values
        mitre_props = {k: v for k, v in mitre_props.items() if v is not None}

        session.run(
            """
            MERGE (m:MitreData {id: $id})
            SET m += $props,
                m.updated_at = datetime()
            """,
            id=mitre_id, props=mitre_props
        )
        stats_mitre["nodes"] += 1

        # Create relationship: CVE -[:HAS_CWE]-> MitreData (directly connected)
        session.run(
            """
            MATCH (c:CVE {id: $cve_id})
            MATCH (m:MitreData {id: $mitre_id})
            MERGE (c)-[:HAS_CWE]->(m)
            """,
            cve_id=cve_id, mitre_id=mitre_id
        )
        stats_mitre["rels"] += 1

        # Process related CAPEC entries
        related_capec = cwe_node.get("related_capec", [])
        for capec in related_capec:
            capec_id_raw = capec.get("id")
            if not capec_id_raw:
                continue

            # Handle both formats: "CAPEC-475" (string) or 475 (numeric)
            if isinstance(capec_id_raw, str) and capec_id_raw.startswith("CAPEC-"):
                capec_node_id = capec_id_raw
                try:
                    numeric_id = int(capec_id_raw.replace("CAPEC-", ""))
                except ValueError:
                    numeric_id = None
            else:
                capec_node_id = f"CAPEC-{capec_id_raw}"
                numeric_id = capec_id_raw if isinstance(capec_id_raw, int) else None

            # Create Capec node with all properties
            capec_props = {
                "capec_id": capec_node_id,
                "user_id": user_id,
                "project_id": project_id,
                "numeric_id": numeric_id,
                "name": capec.get("name"),
                "description": capec.get("description"),
                "url": capec.get("url"),
                "likelihood": capec.get("likelihood"),
                "severity": capec.get("severity"),
                "prerequisites": capec.get("prerequisites"),
                "examples": capec.get("examples"),
            }

            # Add execution flow if available
            execution_flow = capec.get("execution_flow", [])
            if execution_flow:
                capec_props["execution_flow"] = json.dumps(execution_flow)

            # Add related CWEs
            related_cwes = capec.get("related_cwes", [])
            if related_cwes:
                capec_props["related_cwes"] = related_cwes

            # Remove None values
            capec_props = {k: v for k, v in capec_props.items() if v is not None}

            session.run(
                """
                MERGE (cap:Capec {capec_id: $capec_id})
                SET cap += $props,
                    cap.updated_at = datetime()
                """,
                capec_id=capec_node_id, props=capec_props
            )
            stats_mitre["capec"] += 1

            # Create relationship: MitreData -[:HAS_CAPEC]-> Capec
            session.run(
                """
                MATCH (m:MitreData {id: $mitre_id})
                MATCH (cap:Capec {capec_id: $capec_id})
                MERGE (m)-[:HAS_CAPEC]->(cap)
                """,
                mitre_id=mitre_id, capec_id=capec_node_id
            )
            stats_mitre["rels"] += 1

    def update_graph_from_vuln_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with vulnerability scan data.

        This function creates/updates:
        - Endpoint nodes (discovered paths/URLs with parameters from Katana crawling)
        - Parameter nodes (query/body parameters discovered and tested)
        - Vulnerability nodes (DAST findings from Nuclei scanning)
        - Relationships: BaseURL -[:HAS_ENDPOINT]-> Endpoint -[:HAS_PARAMETER]-> Parameter
        - Relationships: Vulnerability -[:AFFECTS_PARAMETER]-> Parameter, Vulnerability -[:FOUND_AT]-> Endpoint
        - Relationships: BaseURL -[:HAS_VULNERABILITY]-> Vulnerability

        Args:
            recon_data: The recon JSON data containing vuln_scan results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "endpoints_created": 0,
            "parameters_created": 0,
            "vulnerabilities_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        vuln_scan_data = recon_data.get("vuln_scan", {})
        if not vuln_scan_data:
            stats["errors"].append("No vuln_scan data found in recon_data")
            return stats

        # Get target subdomains from scan scope - only create nodes for these
        target_subdomains = set(recon_data.get("subdomains", []))
        target_domain = recon_data.get("domain", "")

        # Also include the main domain if no subdomains specified
        if target_domain and not target_subdomains:
            target_subdomains.add(target_domain)

        def is_in_scope(hostname: str) -> bool:
            """Check if a hostname is within the scan scope (target subdomains)."""
            if not target_subdomains:
                return True  # No filter if no subdomains defined
            # Remove port if present
            host_only = hostname.split(":")[0] if ":" in hostname else hostname
            return host_only in target_subdomains

        with self.driver.session() as session:
            # Ensure schema is initialized
            self._init_schema(session)

            scan_metadata = vuln_scan_data.get("scan_metadata", {})
            discovered_urls = vuln_scan_data.get("discovered_urls", {})
            by_target = vuln_scan_data.get("by_target", {})

            # Track created endpoints and parameters for deduplication
            created_endpoints = set()  # (baseurl, path, method)
            created_parameters = set()  # (endpoint_path, param_name, param_position)
            skipped_out_of_scope = 0  # Track skipped URLs

            # Process discovered URLs with parameters (from Katana crawling)
            dast_urls = discovered_urls.get("dast_urls_with_params", [])
            base_urls = discovered_urls.get("base_urls", [])

            for dast_url in dast_urls:
                try:
                    # Parse the URL to extract components
                    from urllib.parse import urlparse, parse_qs
                    parsed = urlparse(dast_url)

                    # Determine scheme, host, path
                    scheme = parsed.scheme or "http"
                    host = parsed.netloc
                    path = parsed.path or "/"
                    query_string = parsed.query

                    # Skip URLs that are not in scan scope (discovered subdomains only)
                    if not is_in_scope(host):
                        skipped_out_of_scope += 1
                        continue

                    # Construct base URL (scheme://host)
                    base_url = f"{scheme}://{host}"

                    # Determine HTTP method (default to GET for URLs with query params)
                    method = "GET"

                    # Create Endpoint node
                    endpoint_key = (base_url, path, method)
                    if endpoint_key not in created_endpoints:
                        has_parameters = bool(query_string)

                        session.run(
                            """
                            MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            SET e.user_id = $user_id,
                                e.project_id = $project_id,
                                e.has_parameters = $has_parameters,
                                e.full_url = $full_url,
                                e.source = 'katana_crawl',
                                e.updated_at = datetime()
                            """,
                            path=path, method=method, baseurl=base_url,
                            user_id=user_id, project_id=project_id,
                            has_parameters=has_parameters,
                            full_url=dast_url.split('?')[0]  # URL without query params
                        )
                        stats["endpoints_created"] += 1
                        created_endpoints.add(endpoint_key)

                        # Create BaseURL node if it doesn't exist and relationship
                        # BaseURL may not exist if endpoint was discovered by crawling a different subdomain
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


                    # Parse and create Parameter nodes from query string
                    if query_string:
                        params = parse_qs(query_string, keep_blank_values=True)
                        for param_name, param_values in params.items():
                            param_key = (path, param_name, "query")
                            if param_key not in created_parameters:
                                sample_value = param_values[0] if param_values else ""

                                session.run(
                                    """
                                    MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    SET p.user_id = $user_id,
                                        p.project_id = $project_id,
                                        p.sample_value = $sample_value,
                                        p.is_injectable = false,
                                        p.updated_at = datetime()
                                    """,
                                    name=param_name, position="query", endpoint_path=path, baseurl=base_url,
                                    user_id=user_id, project_id=project_id,
                                    sample_value=sample_value
                                )
                                stats["parameters_created"] += 1
                                created_parameters.add(param_key)

                                # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
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

                except Exception as e:
                    stats["errors"].append(f"DAST URL {dast_url} processing failed: {e}")

            # Process vulnerability findings by target
            for target_host, target_data in by_target.items():
                # Skip targets that are not in scan scope
                target_host_only = target_host.split(":")[0] if ":" in target_host else target_host
                if not is_in_scope(target_host_only):
                    skipped_out_of_scope += 1
                    continue

                findings = target_data.get("findings", [])

                for finding in findings:
                    try:
                        # Extract raw data for detailed information
                        raw = finding.get("raw", {})
                        raw_info = raw.get("info", {})
                        raw_metadata = raw_info.get("metadata", {})

                        # Generate unique vulnerability ID
                        template_id = finding.get("template_id", "unknown")
                        matched_at = finding.get("matched_at", "")
                        fuzzing_param = raw.get("fuzzing_parameter", "")
                        vuln_id = f"{template_id}-{target_host}-{fuzzing_param}-{hash(matched_at) % 10000}"

                        # Extract path from matched_at URL
                        from urllib.parse import urlparse
                        matched_parsed = urlparse(matched_at)
                        vuln_path = matched_parsed.path or "/"
                        vuln_scheme = matched_parsed.scheme or "http"
                        vuln_host = matched_parsed.netloc or target_host

                        # Also check if matched_at URL host is in scope
                        vuln_host_only = vuln_host.split(":")[0] if ":" in vuln_host else vuln_host
                        if not is_in_scope(vuln_host_only):
                            skipped_out_of_scope += 1
                            continue

                        vuln_base_url = f"{vuln_scheme}://{vuln_host}"

                        # Create Vulnerability node with all fields
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "source": "nuclei",
                            "template_id": template_id,
                            "template_path": finding.get("template_path"),
                            "template_url": raw.get("template-url"),
                            "name": finding.get("name"),
                            "description": finding.get("description"),
                            "severity": finding.get("severity"),
                            "category": finding.get("category"),
                            "tags": finding.get("tags", []),
                            "authors": raw_info.get("author", []),
                            "references": finding.get("reference", []),

                            # Classification
                            "cwe_ids": finding.get("cwe_id", []),
                            "cves": finding.get("cves", []),
                            "cvss_score": finding.get("cvss_score"),
                            "cvss_metrics": finding.get("cvss_metrics"),

                            # Attack details
                            "matched_at": matched_at,
                            "matcher_name": finding.get("matcher_name"),
                            "matcher_status": raw.get("matcher-status", False),
                            "extractor_name": raw.get("extractor-name"),
                            "extracted_results": finding.get("extracted_results", []),

                            # Request/Response details
                            "request_type": raw.get("type"),
                            "scheme": raw.get("scheme"),
                            "host": raw.get("host"),
                            "port": raw.get("port"),
                            "path": vuln_path,
                            "matched_ip": raw.get("ip"),

                            # DAST specific
                            "is_dast_finding": raw.get("is_fuzzing_result", False),
                            "fuzzing_method": raw.get("fuzzing_method"),
                            "fuzzing_parameter": raw.get("fuzzing_parameter"),
                            "fuzzing_position": raw.get("fuzzing_position"),

                            # Template metadata
                            "max_requests": raw_metadata.get("max-request"),

                            # Reproduction
                            "curl_command": finding.get("curl_command"),

                            # Raw request/response (for evidence)
                            "raw_request": finding.get("request"),
                            "raw_response": finding.get("response", "")[:5000] if finding.get("response") else None,  # Truncate long responses

                            # Timestamp
                            "timestamp": finding.get("timestamp"),
                            "discovered_at": finding.get("timestamp")
                        }

                        # Remove None values
                        vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (v:Vulnerability {id: $id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        stats["vulnerabilities_created"] += 1

                        # Note: We don't create BaseURL -[:HAS_VULNERABILITY]-> Vulnerability
                        # because the vulnerability is connected via:
                        # BaseURL -> Endpoint <- Vulnerability (FOUND_AT)
                        # and optionally: Endpoint -> Parameter <- Vulnerability (AFFECTS_PARAMETER)
                        # This avoids redundant connections in the graph.

                        # Create Endpoint node for the vulnerability path if not exists
                        fuzzing_method = raw.get("fuzzing_method", "GET")
                        endpoint_key = (vuln_base_url, vuln_path, fuzzing_method)

                        if endpoint_key not in created_endpoints:
                            session.run(
                                """
                                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET e.user_id = $user_id,
                                    e.project_id = $project_id,
                                    e.has_parameters = true,
                                    e.source = 'vuln_scan',
                                    e.updated_at = datetime()
                                """,
                                path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["endpoints_created"] += 1
                            created_endpoints.add(endpoint_key)

                            # Create BaseURL node if it doesn't exist and relationship
                            session.run(
                                """
                                MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET bu.source = 'vuln_scan',
                                              bu.updated_at = datetime()
                                WITH bu
                                MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (bu)-[:HAS_ENDPOINT]->(e)
                                """,
                                baseurl=vuln_base_url, path=vuln_path, method=fuzzing_method,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create relationship: Vulnerability -[:FOUND_AT]-> Endpoint
                        session.run(
                            """
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            MERGE (v)-[:FOUND_AT]->(e)
                            """,
                            vuln_id=vuln_id, path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                        # Create Parameter node and mark as injectable if this is a DAST finding
                        fuzzing_param = raw.get("fuzzing_parameter")
                        fuzzing_position = raw.get("fuzzing_position", "query")

                        if fuzzing_param:
                            param_key = (vuln_path, fuzzing_param, fuzzing_position)

                            # Create or update Parameter node (mark as injectable)
                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    p.is_injectable = true,
                                    p.updated_at = datetime()
                                """,
                                name=fuzzing_param, position=fuzzing_position, endpoint_path=vuln_path, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )

                            if param_key not in created_parameters:
                                stats["parameters_created"] += 1
                                created_parameters.add(param_key)

                                # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                    param_name=fuzzing_param, position=fuzzing_position,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                            # Create relationship: Vulnerability -[:AFFECTS_PARAMETER]-> Parameter
                            session.run(
                                """
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (v)-[:AFFECTS_PARAMETER]->(p)
                                """,
                                vuln_id=vuln_id, param_name=fuzzing_param, position=fuzzing_position,
                                path=vuln_path, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Finding {finding.get('template_id', 'unknown')} processing failed: {e}")

            # =========================================================================
            # Process technology_cves - CVE, MitreData, and Capec nodes
            # =========================================================================
            technology_cves = recon_data.get("technology_cves", {})
            by_technology = technology_cves.get("by_technology", {})

            cves_created = 0
            mitre_stats = {"nodes": 0, "capec": 0, "rels": 0}  # Shared stats for MITRE processing
            cve_relationships_created = 0

            for tech_name, tech_data in by_technology.items():
                tech_product = tech_data.get("product", tech_name)
                tech_version = tech_data.get("version")  # Version from CVE lookup
                cves = tech_data.get("cves", [])

                # Extract clean technology name from key by stripping version suffix
                # e.g. "Apache HTTP Server:2.4.49" → "Apache HTTP Server"
                # e.g. "Apache/2.4.49" → "Apache"
                tech_name_clean = tech_name
                if tech_version:
                    for sep in [":", "/"]:
                        suffix = f"{sep}{tech_version}"
                        if tech_name_clean.endswith(suffix):
                            tech_name_clean = tech_name_clean[:-len(suffix)]
                            break

                for cve in cves:
                    try:
                        cve_id = cve.get("id")
                        if not cve_id:
                            continue

                        # Create CVE node with all properties
                        cve_props = {
                            "id": cve_id,
                            "cve_id": cve_id,
                            "name": cve_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "cvss": cve.get("cvss"),
                            "severity": cve.get("severity"),
                            "description": cve.get("description"),
                            "published": cve.get("published"),
                            "source": cve.get("source"),
                            "url": cve.get("url"),
                        }

                        # Handle references (can be a list)
                        references = cve.get("references", [])
                        if references:
                            cve_props["references"] = references

                        # Remove None values
                        cve_props = {k: v for k, v in cve_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (c:CVE {id: $id})
                            SET c += $props,
                                c.updated_at = datetime()
                            """,
                            id=cve_id, props=cve_props
                        )
                        cves_created += 1

                        # Create relationship: Technology -[:HAS_KNOWN_CVE]-> CVE
                        # Match Technology node by name (case-insensitive)
                        # Matching strategies (in order):
                        # 1. Exact match by clean name (key without version suffix)
                        # 2. Exact match by NVD product name or raw key
                        # 3. CONTAINS fallback (product name within technology name)
                        # Version matching:
                        # - First try exact version match
                        # - Then fallback to version-less match (handles httpx detecting
                        #   "Apache Tomcat" without version while NVD uses "Apache-Coyote/1.1")
                        name_where = """
                            (toLower(t.name) = toLower($tech_name_clean)
                             OR toLower(t.name) = toLower($tech_product)
                             OR toLower(t.name) = toLower($tech_key)
                             OR toLower(t.name) CONTAINS toLower($tech_product))
                        """

                        matched = 0

                        if tech_version:
                            # Try 1: exact name + exact version
                            result = session.run(
                                f"""
                                MATCH (t:Technology {{user_id: $user_id, project_id: $project_id}})
                                WHERE {name_where} AND t.version = $tech_version
                                MATCH (c:CVE {{id: $cve_id}})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                user_id=user_id, project_id=project_id, tech_name_clean=tech_name_clean,
                                tech_product=tech_product, tech_key=tech_name,
                                tech_version=tech_version, cve_id=cve_id
                            )
                            matched = result.single()["matched"]

                        if matched == 0:
                            # Try 2: name match ignoring version (fallback for version mismatch)
                            result = session.run(
                                f"""
                                MATCH (t:Technology {{user_id: $user_id, project_id: $project_id}})
                                WHERE {name_where}
                                MATCH (c:CVE {{id: $cve_id}})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                user_id=user_id, project_id=project_id, tech_name_clean=tech_name_clean,
                                tech_product=tech_product, tech_key=tech_name, cve_id=cve_id
                            )
                            matched = result.single()["matched"]

                        if matched > 0:
                            cve_relationships_created += 1

                        # Process MITRE data if available
                        mitre_attack = cve.get("mitre_attack", {})
                        if mitre_attack.get("enriched"):
                            cwe_hierarchy = mitre_attack.get("cwe_hierarchy")

                            if cwe_hierarchy:
                                # Find all CWEs that have related_capec (traverse hierarchy)
                                cwes_with_capec = []
                                self._find_cwes_with_capec(cwe_hierarchy, cwes_with_capec)

                                # Create MitreData and Capec nodes for each CWE with CAPEC
                                for cwe_node in cwes_with_capec:
                                    self._process_cwe_with_capec(
                                        session, cwe_node, cve_id, user_id, project_id,
                                        stats_mitre=mitre_stats
                                    )

                            # Process additional CWE hierarchies if present
                            additional_hierarchies = mitre_attack.get("additional_cwe_hierarchies", [])
                            for add_hierarchy in additional_hierarchies:
                                cwes_with_capec = []
                                self._find_cwes_with_capec(add_hierarchy, cwes_with_capec)

                                for cwe_node in cwes_with_capec:
                                    self._process_cwe_with_capec(
                                        session, cwe_node, cve_id, user_id, project_id,
                                        stats_mitre=mitre_stats
                                    )

                    except Exception as e:
                        stats["errors"].append(f"CVE {cve.get('id', 'unknown')} processing failed: {e}")

            if cves_created > 0:
                print(f"[+][graph-db] Created {cves_created} CVE nodes")
                print(f"[+][graph-db] Created {cve_relationships_created} Technology-CVE relationships")
            if mitre_stats["nodes"] > 0:
                print(f"[+][graph-db] Created {mitre_stats['nodes']} MitreData (CWE) nodes")
            if mitre_stats["capec"] > 0:
                print(f"[+][graph-db] Created {mitre_stats['capec']} Capec nodes")

            # =========================================================================
            # Process security_checks - Direct IP access, WAF bypass, etc.
            # =========================================================================
            security_checks_created = 0
            waf_bypass_rels = 0

            for target_host, target_data in by_target.items():
                security_checks = target_data.get("security_checks", {})

                if not security_checks:
                    continue

                # Process direct_ip_access checks
                direct_ip_access = security_checks.get("direct_ip_access", {})
                ip_address = direct_ip_access.get("ip")
                checks = direct_ip_access.get("checks", [])

                for check in checks:
                    try:
                        check_type = check.get("check_type", "unknown")
                        severity = check.get("severity", "info")
                        url = check.get("url", "")
                        finding = check.get("finding", "")
                        evidence = check.get("evidence")
                        status_code = check.get("status_code")
                        content_length = check.get("content_length")

                        # Generate unique vulnerability ID
                        vuln_id = f"sec_{check_type}_{ip_address}_{hash(url) % 10000}"

                        # Human-readable names for check types
                        check_names = {
                            "direct_ip_http": "HTTP accessible directly via IP",
                            "direct_ip_https": "HTTPS accessible directly via IP",
                            "ip_api_exposed": "API endpoint exposed on IP without TLS",
                            "waf_bypass": "WAF bypass via direct IP access",
                            "tls_mismatch": "TLS certificate mismatch",
                            "http_on_ip": "HTTP service on direct IP",
                        }

                        # Create Vulnerability node (source='security_check')
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "source": "security_check",
                            "type": check_type,
                            "severity": severity,
                            "name": check_names.get(check_type, f"Security check: {check_type}"),
                            "description": finding,
                            "url": url,
                            "matched_at": url,
                            "host": target_host,
                            "matched_ip": ip_address,
                            "template_id": None,
                            "is_dast_finding": False,
                        }

                        if evidence:
                            vuln_props["evidence"] = evidence
                        if status_code:
                            vuln_props["status_code"] = status_code
                        if content_length:
                            vuln_props["content_length"] = content_length

                        vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (v:Vulnerability {id: $id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        security_checks_created += 1
                        stats["vulnerabilities_created"] += 1

                        # Create relationship: IP -[:HAS_VULNERABILITY]-> Vulnerability
                        # These are IP-level findings (direct IP access), so IP relationship is correct
                        if ip_address:
                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i.updated_at = datetime()
                                """,
                                address=ip_address, user_id=user_id, project_id=project_id
                            )

                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                """,
                                ip_addr=ip_address, vuln_id=vuln_id,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # For WAF bypass: create WAF_BYPASS_VIA relationship (not HAS_VULNERABILITY)
                        # The vulnerability is already connected to IP; WAF_BYPASS_VIA shows the bypass path
                        if check_type == "waf_bypass" and target_host:
                            # Subdomain -[:WAF_BYPASS_VIA]-> IP (shows which subdomain can bypass WAF via IP)
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:WAF_BYPASS_VIA {
                                    discovered_at: datetime(),
                                    evidence: $evidence
                                }]->(i)
                                """,
                                subdomain=target_host, ip_addr=ip_address,
                                evidence=evidence or "",
                                user_id=user_id, project_id=project_id
                            )
                            waf_bypass_rels += 1

                    except Exception as e:
                        stats["errors"].append(f"Security check {check_type} failed: {e}")

            if security_checks_created > 0:
                print(f"[+][graph-db] Created {security_checks_created} security check Vulnerability nodes")
            if waf_bypass_rels > 0:
                print(f"[+][graph-db] Created {waf_bypass_rels} WAF_BYPASS_VIA relationships")

            # =========================================================================
            # Process top-level security_checks.findings (new structure)
            # =========================================================================
            top_level_security_checks = vuln_scan_data.get("security_checks", {})
            security_findings = top_level_security_checks.get("findings", [])

            for finding in security_findings:
                try:
                    finding_type = finding.get("type", "unknown")
                    severity = finding.get("severity", "info")
                    name = finding.get("name", f"Security Issue: {finding_type}")
                    description = finding.get("description", "")
                    url = finding.get("url", "")
                    matched_ip = finding.get("matched_ip")
                    hostname = finding.get("hostname")
                    evidence = finding.get("evidence")
                    status_code = finding.get("status_code")
                    server = finding.get("server")
                    recommendation = finding.get("recommendation")
                    missing_header = finding.get("missing_header")
                    port = finding.get("port")

                    # Generate unique vulnerability ID
                    unique_key = f"{finding_type}_{url}_{matched_ip or hostname or ''}"
                    vuln_id = f"seccheck_{finding_type}_{hash(unique_key) % 100000}"

                    # Create Vulnerability node
                    vuln_props = {
                        "id": vuln_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "source": "security_check",
                        "type": finding_type,
                        "severity": severity,
                        "name": name,
                        "description": description,
                        "url": url,
                        "matched_at": url,
                        "is_dast_finding": False,
                    }

                    if matched_ip:
                        vuln_props["matched_ip"] = matched_ip
                    if hostname:
                        vuln_props["hostname"] = hostname
                    if evidence:
                        vuln_props["evidence"] = evidence
                    if status_code:
                        vuln_props["status_code"] = status_code
                    if server:
                        vuln_props["server"] = server
                    if recommendation:
                        vuln_props["recommendation"] = recommendation
                    if missing_header:
                        vuln_props["missing_header"] = missing_header
                    if port:
                        vuln_props["port"] = port

                    vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id})
                        SET v += $props,
                            v.updated_at = datetime()
                        """,
                        id=vuln_id, props=vuln_props
                    )
                    security_checks_created += 1
                    stats["vulnerabilities_created"] += 1

                    # Create relationships based on finding type
                    # Priority: IP (for IP-based URLs) > BaseURL (for hostname URLs) > Subdomain/Domain > IP
                    # Only ONE relationship is created per vulnerability to avoid redundancy
                    # (You can always traverse: BaseURL <- Service <- Port <- IP <- Subdomain <- Domain)
                    
                    relationship_created = False
                    
                    # For URL-based findings
                    if url and (url.startswith("http://") or url.startswith("https://")):
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        url_host = parsed.netloc.split(':')[0]  # Remove port if present
                        
                        # If URL host is an IP address, connect to IP node (not BaseURL)
                        # This keeps the vulnerability connected to the existing IP node in the graph
                        if _is_ip_address(url_host):
                            result = session.run(
                                """
                                MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                address=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True
                        else:
                            # URL host is a hostname - connect to existing BaseURL if it exists
                            base_url = f"{parsed.scheme}://{parsed.netloc}"
                            result = session.run(
                                """
                                MATCH (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (bu)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                baseurl=base_url, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True
                            else:
                                # BaseURL doesn't exist, try Subdomain/Domain
                                result = session.run(
                                    """
                                    MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                    MATCH (v:Vulnerability {id: $vuln_id})
                                    MERGE (s)-[:HAS_VULNERABILITY]->(v)
                                    RETURN count(*) as matched
                                    """,
                                    hostname=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                                )
                                if result.single()["matched"] > 0:
                                    stats["relationships_created"] += 1
                                    relationship_created = True
                                else:
                                    # Try Domain
                                    session.run(
                                        """
                                        MATCH (d:Domain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                        MATCH (v:Vulnerability {id: $vuln_id})
                                        MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                        """,
                                        hostname=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                                    )
                                    stats["relationships_created"] += 1
                                    relationship_created = True

                    # For hostname-only findings (no URL): connect to Subdomain/Domain
                    elif hostname and not relationship_created:
                        # Try to link to Subdomain node
                        result = session.run(
                            """
                            MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MERGE (s)-[:HAS_VULNERABILITY]->(v)
                            RETURN count(*) as matched
                            """,
                            hostname=hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                        )
                        if result.single()["matched"] > 0:
                            stats["relationships_created"] += 1
                            relationship_created = True
                        else:
                            # Try Domain node if not a subdomain
                            session.run(
                                """
                                MATCH (d:Domain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                """,
                                hostname=hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            stats["relationships_created"] += 1
                            relationship_created = True

                    # For IP-only findings (no URL, no hostname): connect to IP
                    elif matched_ip and not relationship_created:
                        session.run(
                            """
                            MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MERGE (i)-[:HAS_VULNERABILITY]->(v)
                            """,
                            address=matched_ip, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                        )
                        stats["relationships_created"] += 1
                        relationship_created = True

                    # For domain-only findings (e.g., SPF/DMARC missing): connect to Domain
                    if not relationship_created:
                        finding_domain = finding.get("domain")
                        if finding_domain:
                            result = session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                domain=finding_domain, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True

                except Exception as e:
                    stats["errors"].append(f"Security finding {finding.get('type', 'unknown')} failed: {e}")

            if security_checks_created > 0:
                print(f"[+][graph-db] Created {security_checks_created} SecurityCheck Vulnerability nodes")

            # Update Domain node with vuln_scan metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            summary = vuln_scan_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.vuln_scan_timestamp = $scan_timestamp,
                            d.vuln_scan_dast_mode = $dast_mode,
                            d.vuln_scan_total_urls_scanned = $total_urls,
                            d.vuln_scan_dast_urls_discovered = $dast_urls,
                            d.vuln_scan_critical_count = $critical_count,
                            d.vuln_scan_high_count = $high_count,
                            d.vuln_scan_medium_count = $medium_count,
                            d.vuln_scan_low_count = $low_count,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        dast_mode=scan_metadata.get("dast_mode", False),
                        total_urls=scan_metadata.get("total_urls_scanned", 0),
                        dast_urls=scan_metadata.get("dast_urls_discovered", 0),
                        critical_count=summary.get("critical", 0),
                        high_count=summary.get("high", 0),
                        medium_count=summary.get("medium", 0),
                        low_count=summary.get("low", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+][graph-db] Created {stats['endpoints_created']} Endpoint nodes")
            print(f"[+][graph-db] Created {stats['parameters_created']} Parameter nodes")
            print(f"[+][graph-db] Created {stats['vulnerabilities_created']} Vulnerability nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            if skipped_out_of_scope > 0:
                print(f"[*][graph-db] Skipped {skipped_out_of_scope} items out of scan scope")
                stats["skipped_out_of_scope"] = skipped_out_of_scope

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

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
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            host = parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc
            return host in target_subdomains

        with self.driver.session() as session:
            # Ensure schema is initialized
            self._init_schema(session)

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
            from urllib.parse import urlparse
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

    def _extract_gvm_technologies(self, raw_data: dict, scan: dict) -> list:
        """
        Extract technology detections from GVM host details.

        Parses 'App', 'OS', 'OS-Detection', and 'best_os_cpe' entries from
        raw_data.report.host.detail, resolves CPE strings to display names,
        and maps CPEs to ports.

        Returns list of dicts with keys: name, version, cpe, cpe_vendor,
        cpe_product, port, protocol, categories, target_ip.
        """
        technologies = []

        report = raw_data.get("report", {})
        host_data = report.get("host", {})

        # Handle both single host (dict) and multiple hosts (list)
        hosts = [host_data] if isinstance(host_data, dict) else (
            host_data if isinstance(host_data, list) else []
        )

        for host in hosts:
            host_ip = host.get("ip", "") or scan.get("target_ip", "")
            details = host.get("detail", [])
            if isinstance(details, dict):
                details = [details]
            if not details:
                continue

            # Pass 1: Build CPE-to-port map
            cpe_port_map = {}
            for detail in details:
                name = detail.get("name", "")
                value = detail.get("value", "")
                if name.startswith("cpe:/") or name.startswith("cpe:2.3:"):
                    cpe_port_map[name] = value

            # Pass 2: Extract App and OS CPE entries
            seen_cpes = set()
            capture_names = {"App", "OS", "OS-Detection", "best_os_cpe"}

            for detail in details:
                name = detail.get("name", "")
                value = detail.get("value", "")

                if name not in capture_names:
                    continue
                if not value.startswith("cpe:/") and not value.startswith("cpe:2.3:"):
                    continue
                if value in seen_cpes:
                    continue
                seen_cpes.add(value)

                parsed = _parse_cpe_string(value)
                if not parsed:
                    continue

                vendor = parsed["vendor"]
                product = parsed["product"]
                cpe_version = parsed["version"]
                part = parsed["part"]  # "a" for app, "o" for OS

                # Skip protocol-level CPEs
                if (vendor, product) in _CPE_SKIP_LIST:
                    continue

                # Resolve to display name
                display_name = _resolve_cpe_to_display_name(vendor, product)

                # Look up port from CPE-to-port map
                port_str = cpe_port_map.get(value, "")
                port_number = None
                port_protocol = None
                if "/" in port_str:
                    port_part, proto_part = port_str.split("/", 1)
                    if port_part.isdigit():
                        port_number = int(port_part)
                        port_protocol = proto_part

                # Categorize
                categories = ["Operating systems"] if part == "o" else []

                technologies.append({
                    "name": display_name,
                    "version": cpe_version,
                    "cpe": value,
                    "cpe_vendor": vendor,
                    "cpe_product": product,
                    "port": port_number,
                    "protocol": port_protocol,
                    "categories": categories,
                    "target_ip": host_ip,
                })

        return technologies

    def _merge_gvm_technology(self, session, tech: dict, user_id: str, project_id: str, stats: dict):
        """
        Merge a GVM-detected technology into the graph.

        Uses the same MERGE key as the recon pipeline ({name, version} or {name})
        to avoid duplicates. Enriches existing nodes with CPE data.

        Port-specific technologies (e.g. Apache on 8080, OpenSSH on 22):
            Port -[:USES_TECHNOLOGY {detected_by: 'gvm'}]-> Technology
        OS / general technologies (e.g. Ubuntu, Linux — no specific port):
            IP -[:USES_TECHNOLOGY {detected_by: 'gvm'}]-> Technology
        """
        name = tech["name"]
        version = tech["version"]
        cpe = tech["cpe"]
        target_ip = tech["target_ip"]
        port = tech.get("port")          # int or None
        protocol = tech.get("protocol")  # str or None

        tech_props = {
            "name": name,
            "user_id": user_id,
            "project_id": project_id,
            "cpe": cpe,
            "cpe_vendor": tech.get("cpe_vendor"),
            "cpe_product": tech.get("cpe_product"),
        }
        if tech.get("categories"):
            tech_props["categories"] = tech["categories"]

        # Remove None values
        tech_props = {k: v for k, v in tech_props.items() if v is not None}

        # Step 1: MERGE the Technology node (tenant-scoped)
        if version:
            session.run(
                """
                MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                ON CREATE SET t += $props,
                              t.detected_by = 'gvm',
                              t.confidence = 100,
                              t.updated_at = datetime()
                ON MATCH SET  t.cpe = $cpe,
                              t.cpe_vendor = $cpe_vendor,
                              t.cpe_product = $cpe_product,
                              t.detected_by = CASE
                                  WHEN t.detected_by IS NULL THEN 'gvm'
                                  WHEN t.detected_by CONTAINS 'gvm' THEN t.detected_by
                                  ELSE t.detected_by + ',gvm'
                              END,
                              t.updated_at = datetime()
                """,
                name=name, version=version, props=tech_props,
                cpe=cpe,
                cpe_vendor=tech.get("cpe_vendor"),
                cpe_product=tech.get("cpe_product"),
                user_id=user_id, project_id=project_id,
            )
        else:
            session.run(
                """
                MERGE (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                ON CREATE SET t += $props,
                              t.detected_by = 'gvm',
                              t.confidence = 100,
                              t.updated_at = datetime()
                ON MATCH SET  t.cpe = COALESCE($cpe, t.cpe),
                              t.cpe_vendor = COALESCE($cpe_vendor, t.cpe_vendor),
                              t.cpe_product = COALESCE($cpe_product, t.cpe_product),
                              t.detected_by = CASE
                                  WHEN t.detected_by IS NULL THEN 'gvm'
                                  WHEN t.detected_by CONTAINS 'gvm' THEN t.detected_by
                                  ELSE t.detected_by + ',gvm'
                              END,
                              t.updated_at = datetime()
                """,
                name=name, props=tech_props,
                cpe=cpe,
                cpe_vendor=tech.get("cpe_vendor"),
                cpe_product=tech.get("cpe_product"),
                user_id=user_id, project_id=project_id,
            )
        stats["technologies_created"] += 1

        # Step 2: Create relationship based on whether we have a port
        if not target_ip:
            return

        is_os = "Operating systems" in (tech.get("categories") or [])

        if port is not None and not is_os:
            # PORT-SPECIFIC technology: chain through Port node
            effective_protocol = protocol or "tcp"

            # MERGE Port node (may already exist from recon port_scan)
            session.run(
                """
                MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                SET p.state = 'open',
                    p.updated_at = datetime()
                """,
                port_number=port, protocol=effective_protocol, ip_addr=target_ip,
                user_id=user_id, project_id=project_id,
            )
            stats["ports_created"] += 1

            # MERGE IP -[:HAS_PORT]-> Port (in case recon didn't create it)
            session.run(
                """
                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                MERGE (i)-[:HAS_PORT]->(p)
                """,
                ip=target_ip, user_id=user_id, project_id=project_id,
                port_number=port, protocol=effective_protocol,
            )

            # MERGE Port -[:USES_TECHNOLOGY]-> Technology
            if version:
                session.run(
                    """
                    MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                    MATCH (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                    MERGE (p)-[r:USES_TECHNOLOGY]->(t)
                    SET r.detected_by = 'gvm'
                    """,
                    port_number=port, protocol=effective_protocol, ip=target_ip,
                    name=name, version=version,
                    user_id=user_id, project_id=project_id,
                )
            else:
                session.run(
                    """
                    MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                    MATCH (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                    MERGE (p)-[r:USES_TECHNOLOGY]->(t)
                    SET r.detected_by = 'gvm'
                    """,
                    port_number=port, protocol=effective_protocol, ip=target_ip,
                    name=name,
                    user_id=user_id, project_id=project_id,
                )
            stats["relationships_created"] += 1
        else:
            # OS / GENERAL technology (no port, or OS category): link to IP directly
            rel_props = {"detected_by": "gvm"}

            if version:
                session.run(
                    """
                    MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                    MATCH (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                    MERGE (i)-[r:USES_TECHNOLOGY]->(t)
                    SET r += $rel_props
                    """,
                    ip=target_ip, user_id=user_id, project_id=project_id,
                    name=name, version=version, rel_props=rel_props,
                )
            else:
                session.run(
                    """
                    MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                    MATCH (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                    MERGE (i)-[r:USES_TECHNOLOGY]->(t)
                    SET r += $rel_props
                    """,
                    ip=target_ip, user_id=user_id, project_id=project_id,
                    name=name, rel_props=rel_props,
                )
            stats["relationships_created"] += 1

    @staticmethod
    def _parse_traceroute(description: str) -> dict:
        """
        Parse a GVM Traceroute description into structured data.

        Expected format:
            Network route from scanner (172.20.0.4) to target (15.160.68.117):

            172.20.0.4
            192.168.1.1
            ...
            15.160.68.117

            Network distance between scanner and target: 7
        """
        import re

        result = {"scanner_ip": "", "target_ip": "", "hops": [], "distance": 0}

        # Extract scanner and target IPs from header line
        header_match = re.search(
            r"Network route from scanner \(([^)]+)\) to target \(([^)]+)\)", description
        )
        if header_match:
            result["scanner_ip"] = header_match.group(1)
            result["target_ip"] = header_match.group(2)

        # Extract distance from footer line
        dist_match = re.search(r"Network distance between scanner and target:\s*(\d+)", description)
        if dist_match:
            result["distance"] = int(dist_match.group(1))

        # Extract hop IPs (lines that look like IP addresses)
        ip_pattern = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$", re.MULTILINE)
        result["hops"] = ip_pattern.findall(description)

        return result

    def update_graph_from_gvm_scan(self, gvm_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with GVM/OpenVAS vulnerability scan data.

        This function creates/updates:
        - Technology nodes (from GVM product/service/OS detections via CPE)
        - Port nodes (MERGE'd for port-specific technologies)
        - Vulnerability nodes (from GVM findings with source="gvm")
        - Traceroute nodes (from log-level Traceroute findings)

        Relationships (preferred chain):
        - Port -[:USES_TECHNOLOGY {detected_by: 'gvm'}]-> Technology
        - Technology -[:HAS_VULNERABILITY]-> Vulnerability

        Fallback relationships:
        - IP -[:USES_TECHNOLOGY]-> Technology (for OS-level tech with no port)
        - Port -[:HAS_VULNERABILITY]-> Vulnerability (port with no tech detected)
        - IP -[:HAS_VULNERABILITY]-> Vulnerability (no port, no tech)
        - Subdomain -[:HAS_VULNERABILITY]-> Vulnerability (always, for subdomain context)

        Args:
            gvm_data: The GVM scan JSON data
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "vulnerabilities_created": 0,
            "cves_linked": 0,
            "ips_linked": 0,
            "subdomains_linked": 0,
            "technologies_linked": 0,
            "ports_created": 0,
            "mitre_nodes": 0,
            "capec_nodes": 0,
            "technologies_created": 0,
            "traceroutes_created": 0,
            "exploits_gvm_created": 0,
            "cisa_kev_count": 0,
            "closed_cves_processed": 0,
            "certificates_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        metadata = gvm_data.get("metadata", {})
        scans = gvm_data.get("scans", [])

        if not scans:
            stats["errors"].append("No scans found in GVM data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized
            self._init_schema(session)

            scan_timestamp = metadata.get("scan_timestamp", "")
            target_domain = metadata.get("target_domain", "")

            # Process each scan
            for scan in scans:
                # Extract and merge technology detections FIRST
                # (so vulnerability linking can find Technology nodes)
                raw_data = scan.get("raw_data", {})
                gvm_technologies = self._extract_gvm_technologies(raw_data, scan)
                for tech in gvm_technologies:
                    try:
                        self._merge_gvm_technology(session, tech, user_id, project_id, stats)
                    except Exception as e:
                        stats["errors"].append(f"GVM technology {tech.get('name')} failed: {e}")

                vulnerabilities = scan.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    try:
                        # Skip log-level findings (informational only)
                        severity_class = vuln.get("severity_class", "log")
                        if severity_class == "log":
                            continue

                        # Extract data from vulnerability
                        nvt = vuln.get("nvt", {})
                        host_data = vuln.get("host", {})
                        qod_data = vuln.get("qod", {})

                        # Get target IP and hostname
                        target_ip = host_data.get("#text", "")
                        target_hostname = host_data.get("hostname", "")

                        # Parse port info (format: "80/tcp" or "general/tcp")
                        port_str = vuln.get("port", "")
                        target_port = None
                        port_protocol = None
                        if "/" in port_str:
                            port_part, protocol_part = port_str.split("/", 1)
                            if port_part.isdigit():
                                target_port = int(port_part)
                            port_protocol = protocol_part

                        # Get OID for unique identification
                        oid = nvt.get("@oid", "")

                        # Generate unique vulnerability ID
                        vuln_id = f"gvm-{oid}-{target_ip}-{target_port or 'general'}"

                        # Extract severity info
                        severities = nvt.get("severities", {})
                        severity_info = severities.get("severity", {})
                        cvss_vector = severity_info.get("value", "")
                        cvss_score = vuln.get("severity_float", 0.0)

                        # Extract solution info
                        solution_data = nvt.get("solution", {})
                        solution_text = solution_data.get("#text", "") if isinstance(solution_data, dict) else ""
                        solution_type = solution_data.get("@type", "") if isinstance(solution_data, dict) else ""

                        # Extract CVE IDs and CISA KEV flag from refs
                        cve_ids = vuln.get("cves_extracted", [])
                        cisa_kev = False
                        refs = nvt.get("refs", {})
                        if refs:
                            ref_list = refs.get("ref", [])
                            if isinstance(ref_list, dict):
                                ref_list = [ref_list]
                            for ref in ref_list:
                                if ref.get("@type") == "cve":
                                    cve_id = ref.get("@id", "")
                                    if cve_id and cve_id not in cve_ids:
                                        cve_ids.append(cve_id)
                                elif ref.get("@type") == "cisa":
                                    cisa_kev = True

                        # Check QoD — if 100, this is a confirmed active exploit
                        qod_value = int(qod_data.get("value", 0)) if qod_data.get("value") else 0

                        if qod_value == 100:
                            # Confirmed active exploit — create ExploitGvm node instead of Vulnerability
                            exploit_id = f"gvm-exploit-{oid}-{target_ip}-{target_port or 'general'}"

                            exploit_props = {
                                "id": exploit_id,
                                "user_id": user_id,
                                "project_id": project_id,
                                "attack_type": "cve_exploit",
                                "severity": "critical",
                                "name": nvt.get("name", vuln.get("name", "")),
                                "target_ip": target_ip,
                                "target_port": target_port,
                                "target_hostname": target_hostname,
                                "port_protocol": port_protocol,
                                "cve_ids": cve_ids,
                                "cisa_kev": cisa_kev,
                                "description": vuln.get("description", ""),
                                "evidence": vuln.get("description", ""),
                                "solution": solution_text,
                                "oid": oid,
                                "family": nvt.get("family", ""),
                                "qod": qod_value,
                                "cvss_score": cvss_score,
                                "cvss_vector": cvss_vector,
                                "source": "gvm",
                                "scanner": "OpenVAS",
                                "scan_timestamp": scan_timestamp,
                            }
                            exploit_props = {k: v for k, v in exploit_props.items() if v is not None}

                            session.run(
                                """
                                MERGE (e:ExploitGvm {id: $id})
                                SET e += $props, e.updated_at = datetime()
                                """,
                                id=exploit_id, props=exploit_props
                            )
                            stats["exploits_gvm_created"] += 1
                            if cisa_kev:
                                stats["cisa_kev_count"] += 1

                            # Link ExploitGvm → CVE (only connection)
                            # MERGE CVE node — creates it if not found from previous scan
                            for cve_id_link in cve_ids:
                                severity_label = "CRITICAL" if cvss_score >= 9.0 else "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
                                session.run(
                                    """
                                    MATCH (e:ExploitGvm {id: $exploit_id})
                                    MERGE (c:CVE {id: $cve_id})
                                    ON CREATE SET c.severity = $severity,
                                                  c.cvss = $cvss,
                                                  c.source = 'gvm',
                                                  c.user_id = $uid,
                                                  c.project_id = $pid
                                    MERGE (e)-[:EXPLOITED_CVE]->(c)
                                    """,
                                    exploit_id=exploit_id, cve_id=cve_id_link,
                                    severity=severity_label, cvss=cvss_score,
                                    uid=user_id, pid=project_id
                                )
                                stats["cves_linked"] += 1

                            continue  # Skip Vulnerability node creation

                        # Create Vulnerability node (non-exploit findings)
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "oid": oid,
                            "name": nvt.get("name", vuln.get("name", "")),
                            "severity": severity_class,
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "threat": vuln.get("threat", ""),
                            "description": vuln.get("description", ""),
                            "solution": solution_text,
                            "solution_type": solution_type,
                            "target_ip": target_ip,
                            "target_port": target_port,
                            "target_hostname": target_hostname,
                            "port_protocol": port_protocol,
                            "family": nvt.get("family", ""),
                            "qod": qod_value,
                            "qod_type": qod_data.get("type"),
                            "cve_ids": cve_ids,
                            "cisa_kev": cisa_kev,
                            "source": "gvm",
                            "scanner": "OpenVAS",
                            "scan_timestamp": scan_timestamp,
                        }

                        # Remove None values
                        vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (v:Vulnerability {id: $id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        stats["vulnerabilities_created"] += 1
                        if cisa_kev:
                            stats["cisa_kev_count"] += 1

                        # Link Vulnerability to Technology (preferred) or fallback
                        vuln_linked = False

                        if target_ip and target_port is not None:
                            # TIER 1: Link via Technology on the same Port
                            effective_protocol = port_protocol or "tcp"
                            result = session.run(
                                """
                                MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                                      -[:USES_TECHNOLOGY]->(t:Technology)
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (t)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(t) as matched
                                """,
                                port=target_port, protocol=effective_protocol,
                                ip=target_ip, vuln_id=vuln_id,
                                user_id=user_id, project_id=project_id,
                            )
                            record = result.single()
                            if record and record["matched"] > 0:
                                stats["technologies_linked"] += record["matched"]
                                stats["relationships_created"] += record["matched"]
                                vuln_linked = True

                        if target_ip and not vuln_linked and target_port is None:
                            # TIER 2: "general/tcp" vuln — link to OS Technology on IP
                            result = session.run(
                                """
                                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                      -[:USES_TECHNOLOGY]->(t:Technology)
                                WHERE 'Operating systems' IN t.categories
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (t)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(t) as matched
                                """,
                                ip=target_ip, user_id=user_id, project_id=project_id,
                                vuln_id=vuln_id,
                            )
                            record = result.single()
                            if record and record["matched"] > 0:
                                stats["technologies_linked"] += record["matched"]
                                stats["relationships_created"] += record["matched"]
                                vuln_linked = True

                        if target_ip and not vuln_linked and target_port is not None:
                            # TIER 3: Port exists but no Technology — link to Port
                            effective_protocol = port_protocol or "tcp"
                            result = session.run(
                                """
                                MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (p)-[:HAS_VULNERABILITY]->(v)
                                RETURN p
                                """,
                                port=target_port, protocol=effective_protocol,
                                ip=target_ip, vuln_id=vuln_id,
                                user_id=user_id, project_id=project_id,
                            )
                            if result.single():
                                stats["relationships_created"] += 1
                                vuln_linked = True

                        if target_ip and not vuln_linked:
                            # TIER 4 (FALLBACK): No Technology, no Port — link to IP
                            result = session.run(
                                """
                                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                RETURN i
                                """,
                                ip=target_ip, user_id=user_id, project_id=project_id,
                                vuln_id=vuln_id,
                            )
                            if result.single():
                                stats["ips_linked"] += 1
                                stats["relationships_created"] += 1

                        # Link to Subdomain node (if hostname matches a subdomain)
                        if target_hostname:
                            result = session.run(
                                """
                                MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (s)-[:HAS_VULNERABILITY]->(v)
                                RETURN s
                                """,
                                hostname=target_hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single():
                                stats["subdomains_linked"] += 1
                                stats["relationships_created"] += 1

                        # CVE IDs are stored as cve_ids property on the Vulnerability node
                        # No separate CVE nodes created — avoids bare CVE node clutter

                    except Exception as e:
                        stats["errors"].append(f"Vulnerability processing failed: {e}")

                # Process Traceroute from log-level findings
                for vuln in vulnerabilities:
                    try:
                        nvt = vuln.get("nvt", {})
                        if nvt.get("@oid") != "1.3.6.1.4.1.25623.1.0.51662":
                            continue

                        tr_data = self._parse_traceroute(vuln.get("description", ""))
                        if not tr_data["hops"]:
                            continue

                        target_ip = tr_data["target_ip"]

                        # MERGE Traceroute node
                        session.run(
                            """
                            MERGE (tr:Traceroute {target_ip: $target_ip, user_id: $user_id, project_id: $project_id})
                            SET tr.scanner_ip = $scanner_ip,
                                tr.hops = $hops,
                                tr.distance = $distance,
                                tr.source = 'gvm',
                                tr.scan_timestamp = $scan_timestamp,
                                tr.updated_at = datetime()
                            """,
                            target_ip=target_ip, user_id=user_id, project_id=project_id,
                            scanner_ip=tr_data["scanner_ip"],
                            hops=tr_data["hops"],
                            distance=tr_data["distance"],
                            scan_timestamp=scan_timestamp,
                        )
                        stats["traceroutes_created"] += 1

                        # Link Traceroute to IP node
                        result = session.run(
                            """
                            MATCH (i:IP {address: $target_ip, user_id: $user_id, project_id: $project_id})
                            MATCH (tr:Traceroute {target_ip: $target_ip, user_id: $user_id, project_id: $project_id})
                            MERGE (i)-[:HAS_TRACEROUTE]->(tr)
                            RETURN i
                            """,
                            target_ip=target_ip, user_id=user_id, project_id=project_id,
                        )
                        if result.single():
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Traceroute processing failed: {e}")

                # Process Closed CVEs from raw report data
                try:
                    raw_data = scan.get("raw_data", {})
                    report = raw_data.get("report", raw_data)

                    closed_cves_data = report.get("closed_cves", {})
                    closed_count = int(closed_cves_data.get("count", "0")) if closed_cves_data else 0

                    if closed_count > 0:
                        closed_list = closed_cves_data.get("closed_cve", [])
                        if isinstance(closed_list, dict):
                            closed_list = [closed_list]

                        for closed in closed_list:
                            cve_id = closed.get("cve", {}).get("@id", "")
                            if not cve_id:
                                continue

                            # Mark existing Vulnerability node as remediated
                            session.run(
                                """
                                MATCH (v:Vulnerability {user_id: $uid, project_id: $pid, source: 'gvm'})
                                WHERE $cve_id IN v.cve_ids
                                SET v.remediated = true, v.updated_at = datetime()
                                """,
                                uid=user_id, pid=project_id, cve_id=cve_id
                            )
                            stats["closed_cves_processed"] += 1

                except Exception as e:
                    stats["errors"].append(f"Closed CVEs processing failed: {e}")

                # Process TLS Certificates from raw report data
                try:
                    if not raw_data:
                        raw_data = scan.get("raw_data", {})
                        report = raw_data.get("report", raw_data)

                    tls_certs = report.get("tls_certificates")
                    if tls_certs and tls_certs.get("count", "0") != "0":
                        cert_list = tls_certs.get("tls_certificate", [])
                        if isinstance(cert_list, dict):
                            cert_list = [cert_list]

                        for cert_data in cert_list:
                            cert_name = cert_data.get("name", "")
                            if not cert_name:
                                continue

                            subject_cn = cert_name
                            issuer_dn = cert_data.get("issuer_dn", "")
                            serial = cert_data.get("serial", "")
                            sha256 = cert_data.get("sha256_fingerprint", "")
                            activation = cert_data.get("activation_time", "")
                            expiration = cert_data.get("expiration_time", "")

                            # Extract host:port binding
                            host_info = cert_data.get("host", {})
                            cert_ip = host_info.get("ip", "") if isinstance(host_info, dict) else str(host_info)

                            cert_props = {
                                "subject_cn": subject_cn,
                                "user_id": user_id,
                                "project_id": project_id,
                                "issuer": issuer_dn,
                                "serial": serial,
                                "sha256_fingerprint": sha256,
                                "not_before": activation,
                                "not_after": expiration,
                                "source": "gvm",
                                "scan_timestamp": scan_timestamp,
                            }
                            cert_props = {k: v for k, v in cert_props.items() if v}

                            session.run(
                                """
                                MERGE (c:Certificate {subject_cn: $subject_cn, user_id: $user_id, project_id: $project_id})
                                SET c += $props, c.updated_at = datetime()
                                """,
                                subject_cn=subject_cn, user_id=user_id, project_id=project_id, props=cert_props
                            )

                            # Link to IP node if available
                            if cert_ip:
                                session.run(
                                    """
                                    MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                                    MATCH (c:Certificate {subject_cn: $cn, user_id: $uid, project_id: $pid})
                                    MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                    """,
                                    ip=cert_ip, uid=user_id, pid=project_id, cn=subject_cn
                                )

                            stats["certificates_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"TLS Certificates processing failed: {e}")

            # Update Domain node with GVM scan metadata
            if target_domain:
                try:
                    summary = gvm_data.get("summary", {})
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.gvm_scan_timestamp = $scan_timestamp,
                            d.gvm_total_vulnerabilities = $total_vulns,
                            d.gvm_critical = $critical,
                            d.gvm_high = $high,
                            d.gvm_medium = $medium,
                            d.gvm_low = $low,
                            d.updated_at = datetime()
                        """,
                        root_domain=target_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_timestamp,
                        total_vulns=summary.get("total_vulnerabilities", 0),
                        critical=summary.get("critical", 0),
                        high=summary.get("high", 0),
                        medium=summary.get("medium", 0),
                        low=summary.get("low", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+][graph-db] Created/enriched {stats['technologies_created']} Technology nodes from GVM")
            print(f"[+][graph-db] Created {stats['ports_created']} Port nodes from GVM")
            print(f"[+][graph-db] Created {stats['vulnerabilities_created']} GVM Vulnerability nodes")
            print(f"[+][graph-db] Created {stats['exploits_gvm_created']} ExploitGvm nodes (confirmed active exploits)")
            print(f"[+][graph-db] Created {stats['traceroutes_created']} Traceroute nodes")
            print(f"[+][graph-db] CISA KEV flagged: {stats['cisa_kev_count']} vulnerabilities")
            print(f"[+][graph-db] Closed CVEs processed: {stats['closed_cves_processed']}")
            print(f"[+][graph-db] TLS Certificates created: {stats['certificates_created']}")
            print(f"[+][graph-db] Linked {stats['technologies_linked']} vulnerabilities to technologies")
            print(f"[+][graph-db] Linked {stats['cves_linked']} CVEs")
            print(f"[+][graph-db] Linked {stats['ips_linked']} IPs (fallback)")
            print(f"[+][graph-db] Linked {stats['subdomains_linked']} Subdomains")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def clear_github_hunt_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only GitHub Secret Hunt nodes and relationships for a project.

        Preserves all recon and GVM data. Only removes:
        - GithubSecret / GithubSensitiveFile nodes (leaf findings)
        - GithubPath nodes
        - GithubRepository nodes
        - GithubHunt nodes
        - All relationships between them and to Domain

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted items
        """
        stats = {
            "secrets_deleted": 0,
            "sensitive_files_deleted": 0,
            "paths_deleted": 0,
            "repositories_deleted": 0,
            "hunts_deleted": 0,
        }

        with self.driver.session() as session:
            # 1. Delete leaf nodes first (GithubSecret)
            result = session.run(
                """
                MATCH (gs:GithubSecret {user_id: $uid, project_id: $pid})
                DETACH DELETE gs
                RETURN count(gs) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["secrets_deleted"] = record["deleted"]

            # 2. Delete leaf nodes (GithubSensitiveFile)
            result = session.run(
                """
                MATCH (gsf:GithubSensitiveFile {user_id: $uid, project_id: $pid})
                DETACH DELETE gsf
                RETURN count(gsf) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["sensitive_files_deleted"] = record["deleted"]

            # 3. Delete old GithubFinding nodes (from previous schema version)
            session.run(
                "MATCH (gf:GithubFinding {user_id: $uid, project_id: $pid}) DETACH DELETE gf",
                uid=user_id, pid=project_id
            )

            # 4. Delete GithubPath nodes
            result = session.run(
                """
                MATCH (gp:GithubPath {user_id: $uid, project_id: $pid})
                DETACH DELETE gp
                RETURN count(gp) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["paths_deleted"] = record["deleted"]

            # 5. Delete GithubRepository nodes
            result = session.run(
                """
                MATCH (gr:GithubRepository {user_id: $uid, project_id: $pid})
                DETACH DELETE gr
                RETURN count(gr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["repositories_deleted"] = record["deleted"]

            # 6. Delete GithubHunt nodes
            result = session.run(
                """
                MATCH (gh:GithubHunt {user_id: $uid, project_id: $pid})
                DETACH DELETE gh
                RETURN count(gh) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["hunts_deleted"] = record["deleted"]

            total = sum(stats.values())
            print(f"[*][graph-db] Cleared GitHub Hunt data: {total} items removed")

        return stats

    def update_graph_from_github_hunt(self, github_hunt_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with GitHub Secret Hunt scan results.

        Node hierarchy (5 levels):
        - GithubHunt node (scan metadata: target, timestamps, statistics)
        - GithubRepository nodes (each scanned repository)
        - GithubPath nodes (each unique file path within a repository)
        - GithubSecret nodes (SECRET findings — leaked credentials, API keys, etc.)
        - GithubSensitiveFile nodes (SENSITIVE_FILE findings — .env, config files, etc.)

        Relationships:
        - Domain -[:HAS_GITHUB_HUNT]-> GithubHunt
        - GithubHunt -[:HAS_REPOSITORY]-> GithubRepository
        - GithubRepository -[:HAS_PATH]-> GithubPath
        - GithubPath -[:CONTAINS_SECRET]-> GithubSecret
        - GithubPath -[:CONTAINS_SENSITIVE_FILE]-> GithubSensitiveFile

        Filtering: HIGH_ENTROPY findings are excluded (too noisy).
        Deduplication: Findings across commits are deduplicated by repository+path+secret_type.

        Args:
            github_hunt_data: The GitHub hunt JSON data (top-level with target, findings, statistics)
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created nodes/relationships
        """
        stats = {
            "hunt_created": 0,
            "repositories_created": 0,
            "paths_created": 0,
            "secrets_created": 0,
            "sensitive_files_created": 0,
            "relationships_created": 0,
            "findings_skipped_high_entropy": 0,
            "findings_deduplicated": 0,
            "errors": []
        }

        # Validate input
        target = github_hunt_data.get("target")
        findings = github_hunt_data.get("findings", [])
        if not target:
            stats["errors"].append("No target found in github_hunt_data")
            return stats

        scan_statistics = github_hunt_data.get("statistics", {})

        with self.driver.session() as session:
            self._init_schema(session)

            # Clear previous GitHub hunt data for this project
            clear_stats = self.clear_github_hunt_data(user_id, project_id)
            print(f"[*][graph-db] Pre-cleared: {clear_stats}")

            # 1. Create GithubHunt node (scan metadata)
            hunt_id = f"github-hunt-{user_id}-{project_id}"
            hunt_props = {
                "id": hunt_id,
                "user_id": user_id,
                "project_id": project_id,
                "target": target,
                "scan_start_time": github_hunt_data.get("scan_start_time", ""),
                "scan_end_time": github_hunt_data.get("scan_end_time", ""),
                "duration_seconds": github_hunt_data.get("duration_seconds", 0),
                "status": github_hunt_data.get("status", "unknown"),
                "repos_scanned": scan_statistics.get("repos_scanned", 0),
                "files_scanned": scan_statistics.get("files_scanned", 0),
                "commits_scanned": scan_statistics.get("commits_scanned", 0),
                "secrets_found": scan_statistics.get("secrets_found", 0),
                "sensitive_files": scan_statistics.get("sensitive_files", 0),
            }

            try:
                session.run(
                    """
                    MERGE (gh:GithubHunt {id: $id})
                    SET gh += $props, gh.updated_at = datetime()
                    """,
                    id=hunt_id, props=hunt_props
                )
                stats["hunt_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to create GithubHunt node: {e}")
                print(f"[!][graph-db] GithubHunt creation failed: {e}")
                return stats

            # 2. Link GithubHunt to Domain node
            try:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    MATCH (gh:GithubHunt {id: $hunt_id})
                    MERGE (d)-[:HAS_GITHUB_HUNT]->(gh)
                    RETURN count(*) as linked
                    """,
                    uid=user_id, pid=project_id, hunt_id=hunt_id
                )
                record = result.single()
                if record and record["linked"] > 0:
                    stats["relationships_created"] += 1
                else:
                    print(f"[!][graph-db] Warning: No Domain node found for user_id={user_id}, project_id={project_id}")
            except Exception as e:
                stats["errors"].append(f"Failed to link GithubHunt to Domain: {e}")

            # 3. Process findings (skip HIGH_ENTROPY, deduplicate across commits)
            seen_findings = set()  # dedup key: repo:path:secret_type
            created_repos = set()
            created_paths = set()  # dedup key: repo:path

            for finding in findings:
                finding_type = finding.get("type", "")

                # Skip HIGH_ENTROPY findings
                if finding_type == "HIGH_ENTROPY":
                    stats["findings_skipped_high_entropy"] += 1
                    continue

                # Only process SECRET and SENSITIVE_FILE
                if finding_type not in ("SECRET", "SENSITIVE_FILE"):
                    continue

                repository = finding.get("repository", "")
                path = finding.get("path", "")
                secret_type = finding.get("secret_type", "")

                if not repository or not secret_type:
                    continue

                # Strip commit hash from path: "file.py (commit: abc123)" → "file.py"
                clean_path = path.split(" (commit:")[0].strip()

                # Deduplicate: same repo + path + secret_type across commits
                dedup_key = f"{repository}:{clean_path}:{secret_type}"
                if dedup_key in seen_findings:
                    stats["findings_deduplicated"] += 1
                    continue
                seen_findings.add(dedup_key)

                repo_id = f"github-repo-{user_id}-{project_id}-{repository}"
                path_id = f"github-path-{user_id}-{project_id}-{hash(f'{repository}:{clean_path}') & 0xFFFFFFFF:08x}"

                # 3a. Create/merge GithubRepository node
                if repository not in created_repos:
                    repo_props = {
                        "id": repo_id,
                        "name": repository,
                        "user_id": user_id,
                        "project_id": project_id,
                    }
                    try:
                        session.run(
                            "MERGE (gr:GithubRepository {id: $id}) SET gr += $props, gr.updated_at = datetime()",
                            id=repo_id, props=repo_props
                        )
                        stats["repositories_created"] += 1
                        created_repos.add(repository)

                        # Link GithubHunt → GithubRepository
                        session.run(
                            """
                            MATCH (gh:GithubHunt {id: $hunt_id})
                            MATCH (gr:GithubRepository {id: $repo_id})
                            MERGE (gh)-[:HAS_REPOSITORY]->(gr)
                            """,
                            hunt_id=hunt_id, repo_id=repo_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create repo {repository}: {e}")
                        continue

                # 3b. Create/merge GithubPath node
                path_key = f"{repository}:{clean_path}"
                if path_key not in created_paths:
                    path_props = {
                        "id": path_id,
                        "path": clean_path,
                        "repository": repository,
                        "user_id": user_id,
                        "project_id": project_id,
                    }
                    try:
                        session.run(
                            "MERGE (gp:GithubPath {id: $id}) SET gp += $props, gp.updated_at = datetime()",
                            id=path_id, props=path_props
                        )
                        stats["paths_created"] += 1
                        created_paths.add(path_key)

                        # Link GithubRepository → GithubPath
                        session.run(
                            """
                            MATCH (gr:GithubRepository {id: $repo_id})
                            MATCH (gp:GithubPath {id: $path_id})
                            MERGE (gr)-[:HAS_PATH]->(gp)
                            """,
                            repo_id=repo_id, path_id=path_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create path {path_key}: {e}")
                        continue

                # 3c. Create leaf finding node (GithubSecret or GithubSensitiveFile)
                finding_hash = f"{hash(dedup_key) & 0xFFFFFFFF:08x}"
                details = finding.get("details", {})

                if finding_type == "SECRET":
                    node_id = f"github-secret-{user_id}-{project_id}-{finding_hash}"
                    node_props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "secret_type": secret_type,
                        "repository": repository,
                        "path": clean_path,
                        "timestamp": finding.get("timestamp", ""),
                    }
                    if details.get("matches"):
                        node_props["matches"] = details["matches"]
                    if details.get("sample"):
                        node_props["sample"] = details["sample"]

                    try:
                        session.run(
                            "MERGE (gs:GithubSecret {id: $id}) SET gs += $props, gs.updated_at = datetime()",
                            id=node_id, props=node_props
                        )
                        stats["secrets_created"] += 1

                        # Link GithubPath → GithubSecret
                        session.run(
                            """
                            MATCH (gp:GithubPath {id: $path_id})
                            MATCH (gs:GithubSecret {id: $node_id})
                            MERGE (gp)-[:CONTAINS_SECRET]->(gs)
                            """,
                            path_id=path_id, node_id=node_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create secret {dedup_key}: {e}")

                elif finding_type == "SENSITIVE_FILE":
                    node_id = f"github-sensitivefi-{user_id}-{project_id}-{finding_hash}"
                    node_props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "secret_type": secret_type,
                        "repository": repository,
                        "path": clean_path,
                        "timestamp": finding.get("timestamp", ""),
                    }

                    try:
                        session.run(
                            "MERGE (gsf:GithubSensitiveFile {id: $id}) SET gsf += $props, gsf.updated_at = datetime()",
                            id=node_id, props=node_props
                        )
                        stats["sensitive_files_created"] += 1

                        # Link GithubPath → GithubSensitiveFile
                        session.run(
                            """
                            MATCH (gp:GithubPath {id: $path_id})
                            MATCH (gsf:GithubSensitiveFile {id: $node_id})
                            MERGE (gp)-[:CONTAINS_SENSITIVE_FILE]->(gsf)
                            """,
                            path_id=path_id, node_id=node_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create sensitive file {dedup_key}: {e}")

            # Print summary
            print(f"\n[+] GitHub Hunt Graph Update Summary:")
            print(f"[+][graph-db] Created {stats['hunt_created']} GithubHunt node")
            print(f"[+][graph-db] Created {stats['repositories_created']} GithubRepository nodes")
            print(f"[+][graph-db] Created {stats['paths_created']} GithubPath nodes")
            print(f"[+][graph-db] Created {stats['secrets_created']} GithubSecret nodes")
            print(f"[+][graph-db] Created {stats['sensitive_files_created']} GithubSensitiveFile nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            print(f"[+][graph-db] Skipped {stats['findings_skipped_high_entropy']} HIGH_ENTROPY findings")
            print(f"[+][graph-db] Deduplicated {stats['findings_deduplicated']} cross-commit findings")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    # =========================================================================
    # TruffleHog Secret Scanner — Graph Integration
    # =========================================================================

    def clear_trufflehog_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only TruffleHog Secret Scanner nodes and relationships for a project.

        Preserves all recon, GVM, and GitHub Hunt data. Only removes:
        - TrufflehogFinding nodes (leaf findings)
        - TrufflehogRepository nodes
        - TrufflehogScan nodes
        - All relationships between them and to Domain

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted items
        """
        stats = {
            "findings_deleted": 0,
            "repositories_deleted": 0,
            "scans_deleted": 0,
        }

        with self.driver.session() as session:
            # 1. Delete leaf nodes first (TrufflehogFinding)
            result = session.run(
                """
                MATCH (tf:TrufflehogFinding {user_id: $uid, project_id: $pid})
                DETACH DELETE tf
                RETURN count(tf) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["findings_deleted"] = record["deleted"]

            # 2. Delete TrufflehogRepository nodes
            result = session.run(
                """
                MATCH (tr:TrufflehogRepository {user_id: $uid, project_id: $pid})
                DETACH DELETE tr
                RETURN count(tr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["repositories_deleted"] = record["deleted"]

            # 3. Delete TrufflehogScan nodes
            result = session.run(
                """
                MATCH (ts:TrufflehogScan {user_id: $uid, project_id: $pid})
                DETACH DELETE ts
                RETURN count(ts) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["scans_deleted"] = record["deleted"]

            total = sum(stats.values())
            print(f"[*][graph-db] Cleared TruffleHog data: {total} items removed")

        return stats

    def update_graph_from_trufflehog(self, trufflehog_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with TruffleHog scan results.

        Node hierarchy (3 levels):
        - TrufflehogScan node (scan metadata: target, timestamps, statistics)
        - TrufflehogRepository nodes (each scanned repository)
        - TrufflehogFinding nodes (each secret finding with verification status)

        Relationships:
        - Domain -[:HAS_TRUFFLEHOG_SCAN]-> TrufflehogScan
        - TrufflehogScan -[:HAS_REPOSITORY]-> TrufflehogRepository
        - TrufflehogRepository -[:HAS_FINDING]-> TrufflehogFinding

        Deduplication: Findings are deduplicated by repository+file+line+detector_name.

        Args:
            trufflehog_data: The TruffleHog scan JSON data (top-level with target, findings, statistics)
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created nodes/relationships
        """
        stats = {
            "scan_created": 0,
            "repositories_created": 0,
            "findings_created": 0,
            "relationships_created": 0,
            "findings_deduplicated": 0,
            "errors": []
        }

        # Validate input
        target = trufflehog_data.get("target")
        findings = trufflehog_data.get("findings", [])
        if not target:
            stats["errors"].append("No target found in trufflehog_data")
            return stats

        scan_statistics = trufflehog_data.get("statistics", {})

        with self.driver.session() as session:
            self._init_schema(session)

            # Clear previous TruffleHog data for this project
            clear_stats = self.clear_trufflehog_data(user_id, project_id)
            print(f"[*][graph-db] Pre-cleared: {clear_stats}")

            # 1. Create TrufflehogScan node (scan metadata)
            scan_id = f"trufflehog-scan-{user_id}-{project_id}"
            scan_props = {
                "id": scan_id,
                "user_id": user_id,
                "project_id": project_id,
                "target": target,
                "scan_start_time": trufflehog_data.get("scan_start_time", ""),
                "scan_end_time": trufflehog_data.get("scan_end_time", ""),
                "duration_seconds": trufflehog_data.get("duration_seconds", 0),
                "status": trufflehog_data.get("status", "unknown"),
                "total_findings": scan_statistics.get("total_findings", 0),
                "verified_findings": scan_statistics.get("verified_findings", 0),
                "unverified_findings": scan_statistics.get("unverified_findings", 0),
                "repositories_scanned": scan_statistics.get("repositories_scanned", 0),
            }

            try:
                session.run(
                    """
                    MERGE (ts:TrufflehogScan {id: $id})
                    SET ts += $props, ts.updated_at = datetime()
                    """,
                    id=scan_id, props=scan_props
                )
                stats["scan_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to create TrufflehogScan node: {e}")
                print(f"[!][graph-db] TrufflehogScan creation failed: {e}")
                return stats

            # 2. Link TrufflehogScan to Domain node
            try:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    MATCH (ts:TrufflehogScan {id: $scan_id})
                    MERGE (d)-[:HAS_TRUFFLEHOG_SCAN]->(ts)
                    RETURN count(*) as linked
                    """,
                    uid=user_id, pid=project_id, scan_id=scan_id
                )
                record = result.single()
                if record and record["linked"] > 0:
                    stats["relationships_created"] += 1
                else:
                    print(f"[!][graph-db] Warning: No Domain node found for user_id={user_id}, project_id={project_id}")
            except Exception as e:
                stats["errors"].append(f"Failed to link TrufflehogScan to Domain: {e}")

            # 3. Process findings (deduplicate by repo+file+line+detector)
            seen_findings = set()
            created_repos = set()

            for finding in findings:
                repository = finding.get("repository", "")
                file_path = finding.get("file", "")
                line = finding.get("line", 0)
                detector_name = finding.get("detector_name", "")

                if not detector_name:
                    continue

                # Deduplicate
                dedup_key = f"{repository}:{file_path}:{line}:{detector_name}"
                if dedup_key in seen_findings:
                    stats["findings_deduplicated"] += 1
                    continue
                seen_findings.add(dedup_key)

                # Generate IDs
                repo_hash = f"{hash(f'{user_id}:{project_id}:{repository}') & 0xFFFFFFFF:08x}"
                repo_id = f"trufflehog-repo-{user_id}-{project_id}-{repo_hash}"
                finding_hash = f"{hash(dedup_key) & 0xFFFFFFFF:08x}"
                finding_id = f"trufflehog-finding-{user_id}-{project_id}-{finding_hash}"

                # 3a. Create/merge TrufflehogRepository node
                if repository and repository not in created_repos:
                    repo_props = {
                        "id": repo_id,
                        "name": repository,
                        "user_id": user_id,
                        "project_id": project_id,
                    }
                    try:
                        session.run(
                            "MERGE (tr:TrufflehogRepository {id: $id}) SET tr += $props, tr.updated_at = datetime()",
                            id=repo_id, props=repo_props
                        )
                        stats["repositories_created"] += 1
                        created_repos.add(repository)

                        # Link TrufflehogScan → TrufflehogRepository
                        session.run(
                            """
                            MATCH (ts:TrufflehogScan {id: $scan_id})
                            MATCH (tr:TrufflehogRepository {id: $repo_id})
                            MERGE (ts)-[:HAS_REPOSITORY]->(tr)
                            """,
                            scan_id=scan_id, repo_id=repo_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create repo {repository}: {e}")
                        continue

                # 3b. Create TrufflehogFinding node
                finding_props = {
                    "id": finding_id,
                    "user_id": user_id,
                    "project_id": project_id,
                    "detector_name": detector_name,
                    "detector_description": finding.get("detector_description", ""),
                    "verified": finding.get("verified", False),
                    "redacted": finding.get("redacted", ""),
                    "repository": repository,
                    "file": file_path,
                    "commit": finding.get("commit", ""),
                    "line": line,
                    "link": finding.get("link", ""),
                    "timestamp": finding.get("timestamp", ""),
                    "extra_data": finding.get("extra_data", "{}"),
                }

                try:
                    session.run(
                        "MERGE (tf:TrufflehogFinding {id: $id}) SET tf += $props, tf.updated_at = datetime()",
                        id=finding_id, props=finding_props
                    )
                    stats["findings_created"] += 1

                    # Link TrufflehogRepository → TrufflehogFinding
                    if repository:
                        session.run(
                            """
                            MATCH (tr:TrufflehogRepository {id: $repo_id})
                            MATCH (tf:TrufflehogFinding {id: $finding_id})
                            MERGE (tr)-[:HAS_FINDING]->(tf)
                            """,
                            repo_id=repo_id, finding_id=finding_id
                        )
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Failed to create finding {dedup_key}: {e}")

            # Print summary
            print(f"\n[+] TruffleHog Graph Update Summary:")
            print(f"[+][graph-db] Created {stats['scan_created']} TrufflehogScan node")
            print(f"[+][graph-db] Created {stats['repositories_created']} TrufflehogRepository nodes")
            print(f"[+][graph-db] Created {stats['findings_created']} TrufflehogFinding nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            print(f"[+][graph-db] Deduplicated {stats['findings_deduplicated']} findings")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats


    def update_graph_from_shodan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with Shodan OSINT enrichment data.

        Creates/updates:
        - IP nodes with geo/ISP/OS metadata (from host lookup)
        - Port + Service nodes (from host lookup services)
        - Subdomain nodes + RESOLVES_TO (from reverse DNS / domain DNS)
        - DNSRecord nodes (from domain DNS)
        - Vulnerability + CVE nodes (from passive CVEs)

        Uses MERGE for automatic deduplication with data from other tools.
        """
        stats = {
            "ips_enriched": 0,
            "ports_created": 0,
            "services_created": 0,
            "subdomains_created": 0,
            "dns_records_created": 0,
            "vulnerabilities_created": 0,
            "cves_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        shodan_data = recon_data.get("shodan", {})
        if not shodan_data:
            stats["errors"].append("No shodan data found in recon_data")
            return stats

        domain = recon_data.get("domain", "")

        with self.driver.session() as session:

            # ── 1. IP Enrichment (from host lookup) ──
            for host in shodan_data.get("hosts", []):
                ip = host.get("ip")
                if not ip:
                    continue
                try:
                    props = {k: v for k, v in {
                        "os": host.get("os"),
                        "isp": host.get("isp"),
                        "organization": host.get("org"),
                        "country": host.get("country_name"),
                        "city": host.get("city"),
                        "shodan_enriched": True,
                    }.items() if v is not None}

                    session.run(
                        """
                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        SET i += $props, i.updated_at = datetime()
                        """,
                        address=ip, user_id=user_id, project_id=project_id, props=props
                    )
                    stats["ips_enriched"] += 1

                    # Port + Service nodes from host services
                    # (InternetDB ports are NOT graphed here — Naabu already
                    # handles port discovery in both active and passive mode)
                    for svc in host.get("services", []):
                        port_num = svc.get("port")
                        if not port_num:
                            continue
                        protocol = svc.get("transport", "tcp")

                        # MERGE Port
                        session.run(
                            """
                            MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                           user_id: $user_id, project_id: $project_id})
                            ON CREATE SET p.state = 'open', p.source = 'shodan', p.updated_at = datetime()
                            ON MATCH SET p.updated_at = datetime()
                            MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                            MERGE (i)-[:HAS_PORT]->(p)
                            """,
                            port=port_num, protocol=protocol, ip=ip,
                            user_id=user_id, project_id=project_id
                        )
                        stats["ports_created"] += 1
                        stats["relationships_created"] += 1

                        # MERGE Service (if product is known)
                        product = svc.get("product", "").strip()
                        if product:
                            svc_props = {k: v for k, v in {
                                "version": svc.get("version"),
                                "banner": svc.get("banner"),
                                "source": "shodan",
                                "module": svc.get("module"),
                            }.items() if v is not None}

                            session.run(
                                """
                                MERGE (svc:Service {name: $name, port_number: $port, ip_address: $ip,
                                                    user_id: $user_id, project_id: $project_id})
                                ON CREATE SET svc += $props, svc.updated_at = datetime()
                                ON MATCH SET svc.updated_at = datetime()
                                WITH svc
                                MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                               user_id: $user_id, project_id: $project_id})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                name=product, port=port_num, protocol=protocol, ip=ip,
                                user_id=user_id, project_id=project_id, props=svc_props
                            )
                            stats["services_created"] += 1
                            stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to enrich IP {ip}: {e}")

            # ── 2. Reverse DNS → Subdomain or ExternalDomain nodes ──
            for ip, hostnames in shodan_data.get("reverse_dns", {}).items():
                for hostname in hostnames:
                    if not hostname:
                        continue
                    try:
                        # Check if hostname is in scope (belongs to target domain)
                        is_in_scope = domain and (hostname == domain or hostname.endswith("." + domain))

                        if is_in_scope:
                            session.run(
                                """
                                MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET s.source = 'shodan_rdns', s.status = 'resolved',
                                              s.discovered_at = datetime(), s.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:RESOLVES_TO {record_type: 'A', timestamp: datetime()}]->(i)
                                """,
                                name=hostname, ip=ip, user_id=user_id, project_id=project_id
                            )
                            stats["subdomains_created"] += 1
                            stats["relationships_created"] += 1

                            # Link to domain
                            if domain:
                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                    MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    """,
                                    name=hostname, domain=domain,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1
                        else:
                            # Out-of-scope hostname → ExternalDomain
                            session.run(
                                """
                                MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET ed.first_seen_at = datetime()
                                SET ed.sources = coalesce(ed.sources, []) + CASE WHEN NOT 'shodan_rdns' IN coalesce(ed.sources, []) THEN ['shodan_rdns'] ELSE [] END,
                                    ed.ips_seen = coalesce(ed.ips_seen, []) + CASE WHEN NOT $ip IN coalesce(ed.ips_seen, []) THEN [$ip] ELSE [] END,
                                    ed.updated_at = datetime()
                                WITH ed
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (ed)-[:DISCOVERED_BY]->(d)
                                """,
                                ed_domain=hostname, ip=ip, domain=domain,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Failed to create subdomain {hostname}: {e}")

            # ── 3. Domain DNS → Subdomain + DNSRecord nodes ──
            domain_dns = shodan_data.get("domain_dns", {})
            for sub_name in domain_dns.get("subdomains", []):
                if not sub_name:
                    continue
                fqdn = f"{sub_name}.{domain}" if domain and not sub_name.endswith(domain) else sub_name

                # Check if the FQDN is in scope
                is_in_scope = domain and (fqdn == domain or fqdn.endswith("." + domain))

                try:
                    if is_in_scope:
                        session.run(
                            """
                            MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET s.source = 'shodan_dns', s.status = 'resolved',
                                          s.discovered_at = datetime(), s.updated_at = datetime()
                            """,
                            name=fqdn, user_id=user_id, project_id=project_id
                        )
                        stats["subdomains_created"] += 1

                        if domain:
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:BELONGS_TO]->(d)
                                """,
                                name=fqdn, domain=domain,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1
                    else:
                        # Out-of-scope → ExternalDomain
                        session.run(
                            """
                            MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET ed.first_seen_at = datetime()
                            SET ed.sources = coalesce(ed.sources, []) + CASE WHEN NOT 'shodan_dns' IN coalesce(ed.sources, []) THEN ['shodan_dns'] ELSE [] END,
                                ed.updated_at = datetime()
                            WITH ed
                            MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                            MERGE (ed)-[:DISCOVERED_BY]->(d)
                            """,
                            ed_domain=fqdn, domain=domain,
                            user_id=user_id, project_id=project_id
                        )

                except Exception as e:
                    stats["errors"].append(f"Failed to create subdomain {fqdn}: {e}")

            for record in domain_dns.get("records", []):
                rec_type = record.get("type", "")
                rec_value = record.get("value", "")
                rec_sub = record.get("subdomain", "")
                if not rec_type or not rec_value:
                    continue
                fqdn = f"{rec_sub}.{domain}" if rec_sub and domain else domain
                try:
                    session.run(
                        """
                        MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain,
                                              user_id: $user_id, project_id: $project_id})
                        ON CREATE SET dns.source = 'shodan', dns.updated_at = datetime()
                        """,
                        type=rec_type, value=rec_value, subdomain=fqdn,
                        user_id=user_id, project_id=project_id
                    )
                    stats["dns_records_created"] += 1

                    # Link A/AAAA records to IP nodes
                    if rec_type in ("A", "AAAA"):
                        session.run(
                            """
                            MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                            MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                            MERGE (s)-[:RESOLVES_TO {record_type: $type, timestamp: datetime()}]->(i)
                            """,
                            subdomain=fqdn, ip=rec_value, type=rec_type,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to create DNS record {rec_type}={rec_value}: {e}")

            # ── 4. Passive CVEs → Vulnerability + CVE nodes ──
            for cve_entry in shodan_data.get("cves", []):
                cve_id = cve_entry.get("cve_id", "")
                ip = cve_entry.get("ip", "")
                cve_source = cve_entry.get("source", "shodan")
                if not cve_id or not ip:
                    continue
                vuln_id = f"shodan-{cve_id}-{ip}"
                try:
                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $vuln_id})
                        ON CREATE SET v.source = $source, v.name = $cve_id,
                                      v.cves = [$cve_id], v.user_id = $user_id,
                                      v.project_id = $project_id, v.updated_at = datetime()
                        """,
                        vuln_id=vuln_id, cve_id=cve_id, source=cve_source,
                        user_id=user_id, project_id=project_id
                    )
                    stats["vulnerabilities_created"] += 1

                    session.run(
                        """
                        MERGE (c:CVE {id: $cve_id})
                        ON CREATE SET c.source = $source, c.user_id = $user_id,
                                      c.project_id = $project_id, c.updated_at = datetime()
                        """,
                        cve_id=cve_id, source=cve_source,
                        user_id=user_id, project_id=project_id
                    )
                    stats["cves_created"] += 1

                    session.run(
                        """
                        MATCH (v:Vulnerability {id: $vuln_id})
                        MATCH (c:CVE {id: $cve_id})
                        MERGE (v)-[:INCLUDES_CVE]->(c)
                        """,
                        vuln_id=vuln_id, cve_id=cve_id
                    )
                    stats["relationships_created"] += 1

                    session.run(
                        """
                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                        MATCH (v:Vulnerability {id: $vuln_id})
                        MERGE (i)-[:HAS_VULNERABILITY]->(v)
                        """,
                        ip=ip, vuln_id=vuln_id,
                        user_id=user_id, project_id=project_id
                    )
                    stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to create CVE {cve_id} for {ip}: {e}")

            # Print summary
            print(f"\n[+][graph-db] Shodan Graph Update Summary:")
            print(f"[+][graph-db] Enriched {stats['ips_enriched']} IP nodes")
            print(f"[+][graph-db] Created {stats['ports_created']} Port nodes")
            print(f"[+][graph-db] Created {stats['services_created']} Service nodes")
            print(f"[+][graph-db] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+][graph-db] Created {stats['dns_records_created']} DNSRecord nodes")
            print(f"[+][graph-db] Created {stats['vulnerabilities_created']} Vulnerability nodes")
            print(f"[+][graph-db] Created {stats['cves_created']} CVE nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats


    def update_graph_from_urlscan_discovery(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Phase A: Update graph with URLScan discovery data (before port scan).

        Creates/updates:
        - Subdomain nodes discovered by URLScan
        - IP nodes with ASN/country enrichment
        - Domain node with domain_age_days
        """
        stats = {
            "subdomains_created": 0,
            "ips_enriched": 0,
            "domain_enriched": False,
            "relationships_created": 0,
            "errors": [],
        }

        urlscan_data = recon_data.get("urlscan", {})
        if not urlscan_data or urlscan_data.get("results_count", 0) == 0:
            return stats

        domain = recon_data.get("domain", "")

        with self.driver.session() as session:

            # ── 1. Subdomain + IP discovery ──
            seen_subs = set()
            seen_ips = set()
            seen_sub_ip_links = set()
            for entry in urlscan_data.get("entries", []):
                subdomain = entry.get("domain", "")
                ip = entry.get("ip", "")
                asn = entry.get("asn", "")
                asn_name = entry.get("asn_name", "")
                country = entry.get("country", "")

                # Create/update subdomain or external domain node
                if subdomain and subdomain != domain and subdomain not in seen_subs:
                    seen_subs.add(subdomain)
                    is_in_scope = domain and (subdomain == domain or subdomain.endswith("." + domain))
                    try:
                        if is_in_scope:
                            session.run(
                                """
                                MERGE (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (s:Subdomain {name: $subdomain, user_id: $uid, project_id: $pid})
                                ON CREATE SET s.discovered_by = 'urlscan', s.status = 'resolved',
                                              s.updated_at = datetime()
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                """,
                                domain=domain, subdomain=subdomain,
                                uid=user_id, pid=project_id
                            )
                            stats["subdomains_created"] += 1
                            stats["relationships_created"] += 1
                        else:
                            session.run(
                                """
                                MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $uid, project_id: $pid})
                                ON CREATE SET ed.first_seen_at = datetime()
                                SET ed.sources = coalesce(ed.sources, []) + CASE WHEN NOT 'urlscan' IN coalesce(ed.sources, []) THEN ['urlscan'] ELSE [] END,
                                    ed.updated_at = datetime()
                                WITH ed
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (ed)-[:DISCOVERED_BY]->(d)
                                """,
                                ed_domain=subdomain, domain=domain,
                                uid=user_id, pid=project_id
                            )
                    except Exception as e:
                        stats["errors"].append(f"Subdomain {subdomain}: {e}")

                # Enrich IP with ASN/country (deduplicate — many entries share the same IP)
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    try:
                        props = {k: v for k, v in {
                            "country": country or None,
                            "asn": asn or None,
                            "asn_name": asn_name or None,
                            "urlscan_enriched": True,
                        }.items() if v is not None}

                        session.run(
                            """
                            MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                            SET i += $props, i.updated_at = datetime()
                            """,
                            ip=ip, uid=user_id, pid=project_id, props=props
                        )
                        stats["ips_enriched"] += 1
                    except Exception as e:
                        stats["errors"].append(f"IP {ip}: {e}")

                # Link subdomain -> IP (deduplicate the pair, skip root domain)
                if subdomain and ip and subdomain != domain:
                    link_key = (subdomain, ip)
                    if link_key not in seen_sub_ip_links:
                        seen_sub_ip_links.add(link_key)
                        try:
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $subdomain, user_id: $uid, project_id: $pid})
                                MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                                MERGE (s)-[:RESOLVES_TO]->(i)
                                """,
                                subdomain=subdomain, ip=ip,
                                uid=user_id, pid=project_id
                            )
                            stats["relationships_created"] += 1
                        except Exception as e:
                            stats["errors"].append(f"Link {subdomain}->{ip}: {e}")

            # ── 2. Domain age enrichment ──
            domain_age = urlscan_data.get("domain_age_days")
            apex_age = urlscan_data.get("apex_domain_age_days")
            if domain and (domain_age is not None or apex_age is not None):
                try:
                    props = {k: v for k, v in {
                        "domain_age_days": domain_age,
                        "apex_domain_age_days": apex_age,
                        "urlscan_enriched": True,
                    }.items() if v is not None}

                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        SET d += $props, d.updated_at = datetime()
                        """,
                        domain=domain, uid=user_id, pid=project_id, props=props
                    )
                    stats["domain_enriched"] = True
                except Exception as e:
                    stats["errors"].append(f"Domain age: {e}")

            print(f"[+][graph-db] URLScan discovery: {stats['subdomains_created']} subdomains, "
                  f"{stats['ips_enriched']} IPs enriched")
            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_urlscan_enrichment(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Phase B: Enrich existing graph nodes with URLScan data (after http_probe).

        MATCH-only for BaseURL/Certificate (never creates from stale data).
        Creates Endpoint/Parameter nodes only where parent BaseURL exists.
        """
        stats = {
            "baseurls_enriched": 0,
            "baseurls_not_found": 0,
            "endpoints_created": 0,
            "endpoints_skipped": 0,
            "parameters_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        urlscan_data = recon_data.get("urlscan", {})
        if not urlscan_data or urlscan_data.get("results_count", 0) == 0:
            return stats

        with self.driver.session() as session:

            # ── 1. Enrich existing BaseURL nodes with screenshot/server/title ──
            # Group entries by base_url for efficient enrichment
            from urllib.parse import urlparse as _urlparse
            baseurl_data: dict[str, dict] = {}
            for entry in urlscan_data.get("entries", []):
                url = entry.get("url", "")
                if not url:
                    continue
                try:
                    parsed = _urlparse(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                except Exception:
                    continue

                if base_url not in baseurl_data:
                    baseurl_data[base_url] = {
                        "screenshot_url": entry.get("screenshot_url", ""),
                        "server": entry.get("server", ""),
                        "title": entry.get("title", ""),
                    }

            for base_url, data in baseurl_data.items():
                try:
                    props = {k: v for k, v in {
                        "urlscan_screenshot_url": data["screenshot_url"] or None,
                        "urlscan_server": data["server"] or None,
                        "urlscan_title": data["title"] or None,
                        "urlscan_enriched": True,
                    }.items() if v is not None}

                    if props:
                        result = session.run(
                            """
                            MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                            SET bu += $props, bu.updated_at = datetime()
                            RETURN bu.url AS url
                            """,
                            base_url=base_url, uid=user_id, pid=project_id, props=props
                        )
                        if result.single():
                            stats["baseurls_enriched"] += 1
                        else:
                            stats["baseurls_not_found"] += 1
                except Exception as e:
                    stats["errors"].append(f"BaseURL {base_url}: {e}")

            # ── 2. Create Endpoint + Parameter nodes for URLs with paths ──
            for url_entry in urlscan_data.get("urls_with_paths", []):
                base_url = url_entry.get("base_url", "")
                path = url_entry.get("path", "")
                full_url = url_entry.get("full_url", "")
                params = url_entry.get("params", {})

                if not base_url or not path:
                    continue

                try:
                    has_params = bool(params)
                    # Only create endpoint if BaseURL exists (confirmed live by http_probe)
                    result = session.run(
                        """
                        MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                        MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url,
                                           user_id: $uid, project_id: $pid})
                        ON CREATE SET e.source = 'urlscan', e.full_url = $full_url,
                                      e.has_parameters = $has_params, e.updated_at = datetime()
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        RETURN e.path AS path
                        """,
                        base_url=base_url, path=path, full_url=full_url,
                        has_params=has_params, uid=user_id, pid=project_id
                    )
                    record = result.single()
                    if record:
                        stats["endpoints_created"] += 1
                        stats["relationships_created"] += 1

                        # Create Parameter nodes from query string
                        for param_name, param_value in params.items():
                            try:
                                sample_val = param_value if isinstance(param_value, str) else str(param_value)
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url,
                                                       user_id: $uid, project_id: $pid})
                                    MERGE (p:Parameter {name: $param_name, position: 'query',
                                                        endpoint_path: $path, baseurl: $base_url,
                                                        user_id: $uid, project_id: $pid})
                                    ON CREATE SET p.source = 'urlscan', p.sample_value = $sample_val,
                                                  p.is_injectable = false, p.updated_at = datetime()
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, base_url=base_url, param_name=param_name,
                                    sample_val=sample_val[:500],
                                    uid=user_id, pid=project_id
                                )
                                stats["parameters_created"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e:
                                stats["errors"].append(f"Parameter {param_name}: {e}")
                    else:
                        stats["endpoints_skipped"] += 1

                except Exception as e:
                    stats["errors"].append(f"Endpoint {path}: {e}")

            print(f"[+][graph-db] URLScan enrichment: {stats['baseurls_enriched']} BaseURLs enriched, "
                  f"{stats['endpoints_created']} endpoints, {stats['parameters_created']} parameters")
            if stats["baseurls_not_found"]:
                print(f"[*][graph-db] {stats['baseurls_not_found']} BaseURLs not in graph (stale URLScan data, expected)")
            if stats["endpoints_skipped"]:
                print(f"[*][graph-db] {stats['endpoints_skipped']} endpoints skipped (BaseURL not live)")
            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats


    def update_graph_from_external_domains(self, recon_data, user_id, project_id):
        """Update graph with aggregated external (out-of-scope) domains.

        Creates ExternalDomain nodes and links them to the target Domain node
        via HAS_EXTERNAL_DOMAIN relationship. These nodes are informational only —
        they are never scanned or attacked.
        """
        external_domains = recon_data.get("external_domains_aggregated", [])
        domain = recon_data.get("domain", "")
        if not external_domains:
            return

        print(f"\n[GRAPH] External Domains: {len(external_domains)} foreign domains")

        created = 0
        with self.driver.session() as session:
            for ed in external_domains:
                ed_domain = ed.get("domain", "")
                if not ed_domain:
                    continue
                try:
                    result = session.run("""
                        MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $uid, project_id: $pid})
                        ON CREATE SET ed.first_seen_at = datetime()
                        SET ed.sources = $sources,
                            ed.redirect_from_urls = $redirect_from,
                            ed.redirect_to_urls = $redirect_to,
                            ed.status_codes_seen = $status_codes,
                            ed.titles_seen = $titles,
                            ed.servers_seen = $servers,
                            ed.ips_seen = $ips,
                            ed.countries_seen = $countries,
                            ed.times_seen = $times_seen,
                            ed.updated_at = datetime()
                        RETURN ed.first_seen_at = ed.updated_at AS is_new
                    """, ed_domain=ed_domain, uid=user_id, pid=project_id,
                        sources=ed.get("sources", []),
                        redirect_from=ed.get("redirect_from_urls", []),
                        redirect_to=ed.get("redirect_to_urls", []),
                        status_codes=ed.get("status_codes_seen", []),
                        titles=ed.get("titles_seen", []),
                        servers=ed.get("servers_seen", []),
                        ips=ed.get("ips_seen", []),
                        countries=ed.get("countries_seen", []),
                        times_seen=ed.get("times_seen", 0),
                    )
                    record = result.single()
                    if record and record["is_new"]:
                        created += 1

                    # Link to Domain node
                    if domain:
                        session.run("""
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                            MATCH (ed:ExternalDomain {domain: $ed_domain, user_id: $uid, project_id: $pid})
                            MERGE (d)-[:HAS_EXTERNAL_DOMAIN]->(ed)
                        """, domain=domain, ed_domain=ed_domain, uid=user_id, pid=project_id)
                except Exception as e:
                    logger.warning(f"ExternalDomain graph error for {ed_domain}: {e}")

        print(f"[+][graph-db] External domains: {created} created, {len(external_domains) - created} updated")

    def update_graph_from_censys(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0, "ports_merged": 0, "services_merged": 0,
            "certificates_merged": 0, "subdomains_merged": 0,
            "relationships_created": 0, "errors": [],
        }
        domain = recon_data.get("domain", "") or ""
        try:
            hosts = (recon_data.get("censys") or {}).get("hosts") or []
            if not hosts:
                stats["errors"].append("No censys hosts in recon_data")
            else:
                with self.driver.session() as session:
                    for host in hosts:
                        ip = host.get("ip")
                        if not ip:
                            continue
                        try:
                            asn = host.get("autonomous_system") or {}
                            if not isinstance(asn, dict):
                                asn = {}
                            loc = host.get("location") or {}
                            if not isinstance(loc, dict):
                                loc = {}

                            ip_props: dict = {"censys_enriched": True}
                            # ASN
                            for src_key, dst_key in (
                                ("name",        "autonomous_system_name"),
                                ("bgp_prefix",  "asn_bgp_prefix"),
                                ("description", "asn_description"),
                                ("country_code","asn_country_code"),
                                ("rir",         "asn_rir"),
                            ):
                                v = asn.get(src_key)
                                if v:
                                    ip_props[dst_key] = v
                            if asn.get("asn") is not None:
                                ip_props["autonomous_system_number"] = asn["asn"]
                            # Location
                            for src_key, dst_key in (
                                ("country",            "country"),
                                ("country_code",       "country_code"),
                                ("city",               "city"),
                                ("timezone",           "timezone"),
                                ("registered_country", "registered_country"),
                            ):
                                v = loc.get(src_key)
                                if v:
                                    ip_props[dst_key] = v
                            lat = loc.get("latitude")
                            lon = loc.get("longitude")
                            if lat is not None:
                                ip_props["latitude"] = lat
                            if lon is not None:
                                ip_props["longitude"] = lon
                            # OS / last seen
                            os_v = host.get("os")
                            if os_v:
                                ip_props["os"] = os_v
                            lu = host.get("last_updated")
                            if lu:
                                ip_props["censys_last_seen"] = str(lu)

                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            # Services → Port + Service + Certificate
                            for svc in host.get("services") or []:
                                if not isinstance(svc, dict):
                                    continue
                                port_num = svc.get("port")
                                if port_num is None:
                                    continue
                                protocol = (svc.get("transport_protocol") or "tcp").lower() or "tcp"
                                session.run(
                                    """
                                    MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                    SET p.source = 'censys', p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_PORT]->(p)
                                    """,
                                    port=int(port_num), protocol=protocol, ip=ip,
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["ports_merged"] += 1
                                stats["relationships_created"] += 1

                                sname = (svc.get("service_name") or "").strip()
                                if sname:
                                    svc_props: dict = {"source": "censys"}
                                    ext = (svc.get("extended_service_name") or "").strip()
                                    if ext:
                                        svc_props["extended_service_name"] = ext
                                    banner = (svc.get("banner") or "").strip()
                                    if banner:
                                        svc_props["banner"] = banner
                                    labels = svc.get("labels") or []
                                    if labels:
                                        svc_props["labels"] = labels
                                    http_meta = svc.get("http") or {}
                                    if isinstance(http_meta, dict):
                                        if http_meta.get("title"):
                                            svc_props["http_title"] = http_meta["title"]
                                        if http_meta.get("status_code") is not None:
                                            svc_props["http_status_code"] = http_meta["status_code"]
                                    software = svc.get("software") or []
                                    if software:
                                        sw_strs = [
                                            f"{s.get('product', '')} {s.get('version', '')}".strip()
                                            for s in software if isinstance(s, dict) and s.get("product")
                                        ]
                                        if sw_strs:
                                            svc_props["software_products"] = sw_strs
                                    session.run(
                                        """
                                        MERGE (svc:Service {name: $name, port_number: $port, ip_address: $ip,
                                                            user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET svc.updated_at = datetime()
                                        SET svc += $props, svc.updated_at = datetime()
                                        WITH svc
                                        MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                       user_id: $user_id, project_id: $project_id})
                                        MERGE (p)-[:RUNS_SERVICE]->(svc)
                                        """,
                                        name=sname, port=int(port_num), protocol=protocol, ip=ip,
                                        user_id=user_id, project_id=project_id, props=svc_props,
                                    )
                                    stats["services_merged"] += 1
                                    stats["relationships_created"] += 1

                                # TLS → Certificate node linked to IP
                                tls_data = svc.get("tls")
                                if isinstance(tls_data, dict):
                                    subject_cn = tls_data.get("subject_cn") or ""
                                    if subject_cn:
                                        cert_props = {k: v for k, v in {
                                            "issuer":      tls_data.get("issuer"),
                                            "san":         tls_data.get("san"),
                                            "not_before":  tls_data.get("not_before"),
                                            "not_after":   tls_data.get("not_after"),
                                            "fingerprint": tls_data.get("fingerprint"),
                                            "tls_version": tls_data.get("tls_version"),
                                            "cipher":      tls_data.get("cipher"),
                                            "source":      "censys",
                                        }.items() if v is not None and v != "" and v != []}
                                        try:
                                            session.run(
                                                """
                                                MERGE (c:Certificate {subject_cn: $subject_cn,
                                                                       user_id: $user_id,
                                                                       project_id: $project_id})
                                                SET c += $props, c.updated_at = datetime()
                                                WITH c
                                                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                                MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                                """,
                                                subject_cn=subject_cn, user_id=user_id,
                                                project_id=project_id, props=cert_props, ip=ip,
                                            )
                                            stats["certificates_merged"] += 1
                                            stats["relationships_created"] += 1
                                        except Exception as e:
                                            stats["errors"].append(f"Censys cert {subject_cn}: {e}")

                            # Reverse DNS → Subdomain nodes
                            for hostname in host.get("reverse_dns_names") or []:
                                if not hostname or not domain:
                                    continue
                                if not (hostname == domain or hostname.endswith("." + domain)):
                                    continue
                                try:
                                    session.run(
                                        """
                                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET s.discovered_at = datetime(), s.updated_at = datetime()
                                        SET s.source = 'censys_rdns', s.status = 'unverified',
                                            s.updated_at = datetime()
                                        MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[:RESOLVES_TO {record_type: 'A', timestamp: datetime()}]->(i)
                                        """,
                                        name=hostname, ip=ip, user_id=user_id, project_id=project_id,
                                    )
                                    session.run(
                                        """
                                        MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[:BELONGS_TO]->(d)
                                        """,
                                        name=hostname, domain=domain,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["subdomains_merged"] += 1
                                    stats["relationships_created"] += 2
                                except Exception as e:
                                    stats["errors"].append(f"Censys rdns {hostname}: {e}")

                        except Exception as e:
                            stats["errors"].append(f"Censys host {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_censys: {e}")
        print(f"[graph-db] update_graph_from_censys complete: {stats}")
        return stats

    def update_graph_from_fofa(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0, "ports_merged": 0, "services_merged": 0,
            "subdomains_merged": 0, "certificates_merged": 0,
            "relationships_created": 0, "errors": [],
        }
        try:
            rows = (recon_data.get("fofa") or {}).get("results") or []
            domain = recon_data.get("domain", "") or ""
            if not rows:
                stats["errors"].append("No fofa results in recon_data")
            else:
                with self.driver.session() as session:
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        ip = row.get("ip")
                        if not ip:
                            continue
                        try:
                            # --- IP node ---
                            ip_props = {"fofa_enriched": True}
                            if row.get("country"):
                                ip_props["country_code"] = row["country"]
                            if row.get("country_name"):
                                ip_props["country"] = row["country_name"]
                            if row.get("city"):
                                ip_props["city"] = row["city"]
                            if row.get("region"):
                                ip_props["region"] = row["region"]
                            if row.get("isp"):
                                ip_props["isp"] = row["isp"]
                            if row.get("as_organization"):
                                ip_props["asn_org"] = row["as_organization"]
                            if row.get("as_number"):
                                asn_raw = str(row["as_number"]).strip()
                                ip_props["asn"] = asn_raw if asn_raw.upper().startswith("AS") else f"AS{asn_raw}"
                            if row.get("os"):
                                ip_props["os"] = row["os"]
                            if row.get("lastupdatetime"):
                                ip_props["fofa_last_seen"] = row["lastupdatetime"]
                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            # --- Port node ---
                            port_raw = row.get("port")
                            try:
                                pnum = int(port_raw) if port_raw not in (None, "", 0) else None
                            except (TypeError, ValueError):
                                pnum = None
                            if pnum is None:
                                continue
                            session.run(
                                """
                                MERGE (p:Port {number: $port, protocol: 'tcp', ip_address: $ip,
                                               user_id: $user_id, project_id: $project_id})
                                ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                SET p.source = 'fofa', p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                port=pnum, ip=ip, user_id=user_id, project_id=project_id,
                            )
                            stats["ports_merged"] += 1
                            stats["relationships_created"] += 1

                            # --- Service node ---
                            # Prefer server software name; fall back to application protocol label
                            server = (row.get("server") or "").strip()
                            app_proto = (row.get("protocol") or "").strip()
                            svc_name = server or app_proto
                            if svc_name:
                                session.run(
                                    """
                                    MERGE (svc:Service {name: $name, port_number: $port, ip_address: $ip,
                                                        user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET svc.updated_at = datetime()
                                    SET svc.source = 'fofa', svc.updated_at = datetime(),
                                        svc.http_title   = CASE WHEN $http_title <> '' THEN $http_title ELSE svc.http_title END,
                                        svc.product      = CASE WHEN $product <> '' THEN $product ELSE svc.product END,
                                        svc.version      = CASE WHEN $version <> '' THEN $version ELSE svc.version END,
                                        svc.app_protocol = CASE WHEN $app_proto <> '' THEN $app_proto ELSE svc.app_protocol END,
                                        svc.jarm         = CASE WHEN $jarm <> '' THEN $jarm ELSE svc.jarm END,
                                        svc.tls_version  = CASE WHEN $tls_ver <> '' THEN $tls_ver ELSE svc.tls_version END
                                    WITH svc
                                    MATCH (p:Port {number: $port, protocol: 'tcp', ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    MERGE (p)-[:RUNS_SERVICE]->(svc)
                                    """,
                                    name=svc_name, port=pnum, ip=ip,
                                    http_title=row.get("title") or "",
                                    product=row.get("product") or "",
                                    version=row.get("version") or "",
                                    app_proto=app_proto,
                                    jarm=row.get("jarm") or "",
                                    tls_ver=row.get("tls_version") or "",
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["services_merged"] += 1
                                stats["relationships_created"] += 1

                            # --- Certificate node ---
                            cert_cn = (row.get("certs_subject_cn") or "").strip()
                            if cert_cn:
                                session.run(
                                    """
                                    MERGE (c:Certificate {subject_cn: $cn, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET c.source = 'fofa', c.updated_at = datetime()
                                    SET c.issuer       = CASE WHEN $issuer_cn <> '' THEN $issuer_cn ELSE c.issuer END,
                                        c.subject_org  = CASE WHEN $subject_org <> '' THEN $subject_org ELSE c.subject_org END,
                                        c.tls_version  = CASE WHEN $tls_ver <> '' THEN $tls_ver ELSE c.tls_version END,
                                        c.is_valid     = CASE WHEN $cert_valid <> '' THEN ($cert_valid = 'true') ELSE c.is_valid END,
                                        c.updated_at   = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                    """,
                                    cn=cert_cn,
                                    issuer_cn=row.get("certs_issuer_cn") or "",
                                    subject_org=row.get("certs_subject_org") or "",
                                    tls_ver=row.get("tls_version") or "",
                                    cert_valid=str(row.get("certs_valid") or "").lower(),
                                    ip=ip, user_id=user_id, project_id=project_id,
                                )
                                stats["certificates_merged"] += 1
                                stats["relationships_created"] += 1

                            # --- Subdomain node ---
                            # FOFA host may carry port suffix (e.g. "sub.example.com:8080") — strip it
                            host_raw = (row.get("host") or "").strip()
                            host = host_raw.split(":")[0] if ":" in host_raw else host_raw
                            if host and domain and host != ip and (
                                host == domain or host.endswith("." + domain)
                            ):
                                session.run(
                                    """
                                    MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET s.status = 'unverified', s.discovered_at = datetime(), s.updated_at = datetime()
                                    SET s.source = 'fofa', s.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (s)-[:RESOLVES_TO {record_type: 'A', timestamp: datetime()}]->(i)
                                    """,
                                    name=host, ip=ip, user_id=user_id, project_id=project_id,
                                )
                                stats["subdomains_merged"] += 1
                                stats["relationships_created"] += 1
                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                    MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    """,
                                    name=host, domain=domain, user_id=user_id, project_id=project_id,
                                )
                                stats["relationships_created"] += 1
                        except Exception as e:
                            stats["errors"].append(f"FOFA row {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_fofa: {e}")
        print(f"[graph-db] update_graph_from_fofa complete: {stats}")
        return stats

    def update_graph_from_otx(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0,
            "subdomains_merged": 0,
            "external_domains_merged": 0,
            "domains_updated": 0,
            "threat_pulses_merged": 0,
            "malware_merged": 0,
            "relationships_created": 0,
            "errors": [],
        }
        try:
            otx = recon_data.get("otx") or {}
            reports = otx.get("ip_reports") or []
            domain = recon_data.get("domain", "") or ""
            dr = otx.get("domain_report")
            if not reports and not (dr and isinstance(dr, dict) and dr.get("domain")):
                stats["errors"].append("No otx ip_reports or domain_report in recon_data")
                print(f"[graph-db] update_graph_from_otx complete: {stats}")
                return stats

            with self.driver.session() as session:
                # ── IP reports ──────────────────────────────────────────────
                for rep in reports:
                    if not isinstance(rep, dict):
                        continue
                    ip = rep.get("ip")
                    if not ip:
                        continue
                    try:
                        geo = rep.get("geo") or {}
                        pulse_details = rep.get("pulse_details") or {}
                        session.run(
                            """
                            MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            SET i.otx_enriched = true,
                                i.otx_pulse_count = $pulse,
                                i.otx_reputation = $reputation,
                                i.otx_url_count = $url_count,
                                i.otx_adversaries = $adversaries,
                                i.otx_malware_families = $malware_families,
                                i.otx_tlp = $tlp,
                                i.otx_attack_ids = $attack_ids,
                                i.country_name = CASE WHEN i.country_name IS NULL OR i.country_name = '' THEN $country_name ELSE i.country_name END,
                                i.city = CASE WHEN i.city IS NULL OR i.city = '' THEN $city ELSE i.city END,
                                i.asn = CASE WHEN i.asn IS NULL OR i.asn = '' THEN $asn ELSE i.asn END,
                                i.updated_at = datetime()
                            """,
                            address=ip, user_id=user_id, project_id=project_id,
                            pulse=rep.get("pulse_count"),
                            reputation=rep.get("reputation"),
                            url_count=rep.get("url_count", 0),
                            adversaries=pulse_details.get("adversaries") or [],
                            malware_families=pulse_details.get("malware_families") or [],
                            tlp=pulse_details.get("tlp") or "",
                            attack_ids=pulse_details.get("attack_ids") or [],
                            country_name=geo.get("country_name") or "",
                            city=geo.get("city") or "",
                            asn=geo.get("asn") or "",
                        )
                        stats["ips_enriched"] += 1

                        # ── passive DNS hostnames ────────────────────────
                        pdns_records = rep.get("passive_dns") or []
                        # Fallback to legacy hostname list if new format absent
                        if not pdns_records:
                            pdns_records = [
                                {"hostname": h, "first": "", "last": "", "record_type": ""}
                                for h in (rep.get("passive_dns_hostnames") or [])
                            ]

                        for rec in pdns_records:
                            if not isinstance(rec, dict):
                                continue
                            hostname = rec.get("hostname") or ""
                            if not hostname:
                                continue
                            record_type = rec.get("record_type") or "A"
                            first_seen = rec.get("first") or ""
                            last_seen = rec.get("last") or ""

                            if domain and (hostname == domain or hostname.endswith("." + domain)):
                                # In-scope → Subdomain node
                                try:
                                    session.run(
                                        """
                                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET s.discovered_at = datetime(), s.updated_at = datetime()
                                        SET s.source = 'otx_passive_dns', s.status = 'unverified', s.updated_at = datetime()
                                        WITH s
                                        MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[r:RESOLVES_TO {record_type: $record_type}]->(i)
                                        ON CREATE SET r.first_seen = $first_seen, r.last_seen = $last_seen, r.timestamp = datetime()
                                        SET r.last_seen = CASE WHEN $last_seen <> '' THEN $last_seen ELSE r.last_seen END
                                        """,
                                        name=hostname, ip=ip, user_id=user_id, project_id=project_id,
                                        record_type=record_type, first_seen=first_seen, last_seen=last_seen,
                                    )
                                    stats["subdomains_merged"] += 1
                                    stats["relationships_created"] += 1
                                    if domain:
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                            MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                            MERGE (s)-[:BELONGS_TO]->(d)
                                            """,
                                            name=hostname, domain=domain, user_id=user_id, project_id=project_id,
                                        )
                                        stats["relationships_created"] += 1
                                except Exception as e2:
                                    stats["errors"].append(f"OTX pdns in-scope {hostname}: {e2}")
                            elif hostname and "@" not in hostname:
                                # Out-of-scope → ExternalDomain node
                                try:
                                    session.run(
                                        """
                                        MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET ed.first_seen_at = datetime()
                                        SET ed.sources = coalesce(ed.sources, []) + CASE WHEN NOT 'otx_passive_dns' IN coalesce(ed.sources, []) THEN ['otx_passive_dns'] ELSE [] END,
                                            ed.ips_seen = coalesce(ed.ips_seen, []) + CASE WHEN NOT $ip IN coalesce(ed.ips_seen, []) THEN [$ip] ELSE [] END,
                                            ed.updated_at = datetime()
                                        WITH ed
                                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                        MERGE (d)-[:HAS_EXTERNAL_DOMAIN]->(ed)
                                        """,
                                        ed_domain=hostname, ip=ip, domain=domain,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["external_domains_merged"] += 1
                                    stats["relationships_created"] += 1
                                except Exception as e2:
                                    stats["errors"].append(f"OTX pdns external {hostname}: {e2}")

                        # ── Malware samples ──────────────────────────────
                        for sample in rep.get("malware") or []:
                            if not isinstance(sample, dict):
                                continue
                            h = sample.get("hash")
                            if not h:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (m:Malware {hash: $hash, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET m.first_seen = datetime()
                                    SET m.hash_type = $hash_type,
                                        m.file_type = $file_type,
                                        m.file_name = $file_name,
                                        m.source = 'otx',
                                        m.updated_at = datetime()
                                    WITH m
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:ASSOCIATED_WITH_MALWARE]->(m)
                                    """,
                                    hash=h, user_id=user_id, project_id=project_id,
                                    hash_type=sample.get("hash_type") or "",
                                    file_type=sample.get("file_type") or "",
                                    file_name=sample.get("file_name") or "",
                                    ip=ip,
                                )
                                stats["malware_merged"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX malware {h} (ip {ip}): {e2}")

                        # ── ThreatPulse nodes ────────────────────────────
                        for pulse in (pulse_details.get("pulses") or []):
                            if not isinstance(pulse, dict):
                                continue
                            pulse_id = pulse.get("pulse_id") or ""
                            if not pulse_id:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (tp:ThreatPulse {pulse_id: $pulse_id, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET tp.created_at = datetime()
                                    SET tp.name = $name,
                                        tp.adversary = $adversary,
                                        tp.malware_families = $malware_families,
                                        tp.attack_ids = $attack_ids,
                                        tp.tags = $tags,
                                        tp.tlp = $tlp,
                                        tp.author_name = $author_name,
                                        tp.targeted_countries = $targeted_countries,
                                        tp.modified = $modified,
                                        tp.updated_at = datetime()
                                    WITH tp
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:APPEARS_IN_PULSE]->(tp)
                                    """,
                                    pulse_id=pulse_id, user_id=user_id, project_id=project_id,
                                    name=pulse.get("name") or "",
                                    adversary=pulse.get("adversary") or "",
                                    malware_families=pulse.get("malware_families") or [],
                                    attack_ids=pulse.get("attack_ids") or [],
                                    tags=pulse.get("tags") or [],
                                    tlp=pulse.get("tlp") or "",
                                    author_name=pulse.get("author_name") or "",
                                    targeted_countries=pulse.get("targeted_countries") or [],
                                    modified=pulse.get("modified") or "",
                                    ip=ip,
                                )
                                stats["threat_pulses_merged"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX ThreatPulse {pulse_id} (ip {ip}): {e2}")

                    except Exception as e:
                        stats["errors"].append(f"OTX IP {ip}: {e}")

                # ── Domain report ────────────────────────────────────────
                if dr and isinstance(dr, dict) and dr.get("domain"):
                    try:
                        dom_name = dr["domain"]
                        dom_pulse_details = dr.get("pulse_details") or {}
                        whois = dr.get("whois") or {}

                        # Safely extract registrar/nameservers from OTX whois dict
                        registrar = str(whois.get("registrar") or "")
                        raw_ns = whois.get("nameservers") or []
                        nameservers = raw_ns if isinstance(raw_ns, list) else [str(raw_ns)]
                        registrant_email = str(whois.get("registrant_email") or whois.get("emails") or "")

                        session.run(
                            """
                            MATCH (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                            SET d.otx_pulse_count = $pulse,
                                d.otx_url_count = $url_count,
                                d.otx_adversaries = $adversaries,
                                d.otx_malware_families = $malware_families,
                                d.otx_tlp = $tlp,
                                d.otx_attack_ids = $attack_ids,
                                d.registrar = CASE WHEN d.registrar IS NULL OR d.registrar = '' THEN $registrar ELSE d.registrar END,
                                d.name_servers = CASE WHEN d.name_servers IS NULL OR size(d.name_servers) = 0 THEN $nameservers ELSE d.name_servers END,
                                d.updated_at = datetime()
                            """,
                            name=dom_name, user_id=user_id, project_id=project_id,
                            pulse=dr.get("pulse_count"),
                            url_count=dr.get("url_count", 0),
                            adversaries=dom_pulse_details.get("adversaries") or [],
                            malware_families=dom_pulse_details.get("malware_families") or [],
                            tlp=dom_pulse_details.get("tlp") or "",
                            attack_ids=dom_pulse_details.get("attack_ids") or [],
                            registrar=registrar,
                            nameservers=nameservers,
                        )
                        stats["domains_updated"] += 1

                        # ── Domain malware samples ───────────────────────
                        for sample in dr.get("malware") or []:
                            if not isinstance(sample, dict):
                                continue
                            h = sample.get("hash")
                            if not h:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (m:Malware {hash: $hash, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET m.first_seen = datetime()
                                    SET m.hash_type = $hash_type,
                                        m.file_type = $file_type,
                                        m.file_name = $file_name,
                                        m.source = 'otx',
                                        m.updated_at = datetime()
                                    WITH m
                                    MATCH (d:Domain {name: $dom_name, user_id: $user_id, project_id: $project_id})
                                    MERGE (d)-[:ASSOCIATED_WITH_MALWARE]->(m)
                                    """,
                                    hash=h, user_id=user_id, project_id=project_id,
                                    hash_type=sample.get("hash_type") or "",
                                    file_type=sample.get("file_type") or "",
                                    file_name=sample.get("file_name") or "",
                                    dom_name=dom_name,
                                )
                                stats["malware_merged"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX domain malware {h}: {e2}")

                        # ── Domain ThreatPulse nodes ─────────────────────
                        for pulse in (dom_pulse_details.get("pulses") or []):
                            if not isinstance(pulse, dict):
                                continue
                            pulse_id = pulse.get("pulse_id") or ""
                            if not pulse_id:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (tp:ThreatPulse {pulse_id: $pulse_id, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET tp.created_at = datetime()
                                    SET tp.name = $name,
                                        tp.adversary = $adversary,
                                        tp.malware_families = $malware_families,
                                        tp.attack_ids = $attack_ids,
                                        tp.tags = $tags,
                                        tp.tlp = $tlp,
                                        tp.author_name = $author_name,
                                        tp.targeted_countries = $targeted_countries,
                                        tp.modified = $modified,
                                        tp.updated_at = datetime()
                                    WITH tp
                                    MATCH (d:Domain {name: $dom_name, user_id: $user_id, project_id: $project_id})
                                    MERGE (d)-[:APPEARS_IN_PULSE]->(tp)
                                    """,
                                    pulse_id=pulse_id, user_id=user_id, project_id=project_id,
                                    name=pulse.get("name") or "",
                                    adversary=pulse.get("adversary") or "",
                                    malware_families=pulse.get("malware_families") or [],
                                    attack_ids=pulse.get("attack_ids") or [],
                                    tags=pulse.get("tags") or [],
                                    tlp=pulse.get("tlp") or "",
                                    author_name=pulse.get("author_name") or "",
                                    targeted_countries=pulse.get("targeted_countries") or [],
                                    modified=pulse.get("modified") or "",
                                    dom_name=dom_name,
                                )
                                stats["threat_pulses_merged"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX domain ThreatPulse {pulse_id}: {e2}")

                        # ── Domain historical IPs (domain/passive_dns) ───
                        for hist in dr.get("historical_ips") or []:
                            if not isinstance(hist, dict):
                                continue
                            addr = hist.get("address")
                            if not addr:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET i.created_at = datetime()
                                    SET i.updated_at = datetime()
                                    WITH i
                                    MATCH (d:Domain {name: $dom_name, user_id: $user_id, project_id: $project_id})
                                    MERGE (d)-[r:HISTORICALLY_RESOLVED_TO]->(i)
                                    ON CREATE SET r.first_seen = $first_seen, r.last_seen = $last_seen, r.record_type = $record_type
                                    """,
                                    address=addr, dom_name=dom_name,
                                    user_id=user_id, project_id=project_id,
                                    first_seen=hist.get("first") or "",
                                    last_seen=hist.get("last") or "",
                                    record_type=hist.get("record_type") or "A",
                                )
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX hist IP {addr}: {e2}")

                    except Exception as e:
                        stats["errors"].append(f"OTX domain_report: {e}")

        except Exception as e:
            stats["errors"].append(f"update_graph_from_otx: {e}")
        print(f"[graph-db] update_graph_from_otx complete: {stats}")
        return stats

    def update_graph_from_netlas(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0, "ports_merged": 0, "services_merged": 0,
            "vulnerabilities_merged": 0, "relationships_created": 0, "errors": [],
        }
        try:
            rows = (recon_data.get("netlas") or {}).get("results") or []
            if not rows:
                stats["errors"].append("No netlas results in recon_data")
            else:
                with self.driver.session() as session:
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        ip = row.get("ip")
                        if not ip:
                            continue
                        try:
                            # --- IP node enrichment ---
                            ip_props: dict = {"netlas_enriched": True}
                            for src, dst in (
                                ("isp",        "isp"),
                                ("country",    "country"),
                                ("city",       "city"),
                                ("timezone",   "timezone"),
                                ("asn_name",   "asn_org"),
                                ("asn_number", "asn"),
                                ("asn_route",  "asn_bgp_prefix"),
                            ):
                                v = row.get(src)
                                if v:
                                    ip_props[dst] = v
                            lat = row.get("latitude")
                            lon = row.get("longitude")
                            if lat is not None:
                                ip_props["latitude"] = lat
                            if lon is not None:
                                ip_props["longitude"] = lon

                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            # --- Port node ---
                            port_raw = row.get("port")
                            try:
                                pnum = int(port_raw) if port_raw is not None else 0
                            except (TypeError, ValueError):
                                pnum = 0
                            if not pnum:
                                continue
                            proto = (row.get("protocol") or "tcp")
                            protocol = (proto.lower() if isinstance(proto, str) else "tcp") or "tcp"
                            session.run(
                                """
                                MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                               user_id: $user_id, project_id: $project_id})
                                ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                SET p.source = 'netlas', p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                port=pnum, protocol=protocol, ip=ip, user_id=user_id, project_id=project_id,
                            )
                            stats["ports_merged"] += 1
                            stats["relationships_created"] += 1

                            # --- Service node (enriched) ---
                            prot_name = (row.get("protocol") or "").strip()
                            if prot_name:
                                svc_props: dict = {"source": "netlas"}
                                title = row.get("title") or ""
                                if title:
                                    svc_props["http_title"] = title
                                http_sc = row.get("http_status_code")
                                if http_sc is not None:
                                    try:
                                        svc_props["http_status_code"] = int(http_sc)
                                    except (TypeError, ValueError):
                                        pass
                                banner = row.get("banner") or ""
                                if banner:
                                    svc_props["banner"] = banner
                                session.run(
                                    """
                                    MERGE (svc:Service {name: $name, port_number: $port, ip_address: $ip,
                                                        user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET svc.updated_at = datetime()
                                    SET svc += $props, svc.updated_at = datetime()
                                    WITH svc
                                    MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    MERGE (p)-[:RUNS_SERVICE]->(svc)
                                    """,
                                    name=prot_name, port=pnum, protocol=protocol, ip=ip,
                                    user_id=user_id, project_id=project_id, props=svc_props,
                                )
                                stats["services_merged"] += 1
                                stats["relationships_created"] += 1

                                # --- CVE Vulnerability nodes ---
                                for cve in (row.get("cve_list") or []):
                                    if not isinstance(cve, dict):
                                        continue
                                    cve_id = cve.get("id") or ""
                                    if not cve_id:
                                        continue
                                    try:
                                        vuln_props: dict = {
                                            "source": "netlas",
                                            "name": cve_id,
                                        }
                                        severity = cve.get("severity") or ""
                                        if severity:
                                            vuln_props["severity"] = severity
                                        base_score = cve.get("base_score")
                                        if base_score is not None:
                                            try:
                                                vuln_props["cvss_score"] = float(base_score)
                                            except (TypeError, ValueError):
                                                pass
                                        vuln_props["has_exploit"] = bool(cve.get("has_exploit", False))
                                        session.run(
                                            """
                                            MERGE (v:Vulnerability {id: $cve_id,
                                                                     user_id: $user_id,
                                                                     project_id: $project_id})
                                            ON CREATE SET v.created_at = datetime()
                                            SET v += $props, v.updated_at = datetime()
                                            WITH v
                                            MATCH (svc:Service {name: $svc_name, port_number: $port,
                                                                ip_address: $ip,
                                                                user_id: $user_id,
                                                                project_id: $project_id})
                                            MERGE (svc)-[:HAS_VULNERABILITY]->(v)
                                            """,
                                            cve_id=cve_id, user_id=user_id, project_id=project_id,
                                            props=vuln_props, svc_name=prot_name, port=pnum, ip=ip,
                                        )
                                        stats["vulnerabilities_merged"] += 1
                                        stats["relationships_created"] += 1
                                    except Exception as e:
                                        stats["errors"].append(f"Netlas CVE {cve_id} on {ip}:{pnum}: {e}")

                        except Exception as e:
                            stats["errors"].append(f"Netlas row {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_netlas: {e}")
        print(f"[graph-db] update_graph_from_netlas complete: {stats}")
        return stats

    def update_graph_from_virustotal(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {"domains_updated": 0, "ips_enriched": 0, "errors": []}
        try:
            vt = recon_data.get("virustotal") or {}
            dr = vt.get("domain_report")
            reports = vt.get("ip_reports") or []
            if dr is None and not reports:
                stats["errors"].append("No virustotal domain_report or ip_reports in recon_data")
            else:
                with self.driver.session() as session:
                    if dr and isinstance(dr, dict) and dr.get("domain"):
                        try:
                            _ast = (dr.get("analysis_stats") or {}) if isinstance(dr.get("analysis_stats"), dict) else {}
                            cats = dr.get("categories")
                            cats_stored = json.dumps(cats) if cats is not None else None
                            votes = dr.get("total_votes") or {}
                            session.run(
                                """
                                MATCH (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                                SET d.vt_enriched = true,
                                    d.vt_reputation = $reputation,
                                    d.vt_malicious_count = $malicious,
                                    d.vt_suspicious_count = $suspicious,
                                    d.vt_harmless_count = $harmless,
                                    d.vt_undetected_count = $undetected,
                                    d.vt_categories = $categories,
                                    d.vt_registrar = $registrar,
                                    d.vt_tags = $tags,
                                    d.vt_community_malicious = $community_malicious,
                                    d.vt_community_harmless = $community_harmless,
                                    d.vt_last_analysis_date = $last_analysis_date,
                                    d.vt_jarm = $jarm,
                                    d.vt_popularity_alexa = $popularity_alexa,
                                    d.vt_popularity_umbrella = $popularity_umbrella,
                                    d.updated_at = datetime()
                                """,
                                name=dr["domain"], user_id=user_id, project_id=project_id,
                                reputation=dr.get("reputation"),
                                malicious=_ast.get("malicious"),
                                suspicious=_ast.get("suspicious"),
                                harmless=_ast.get("harmless"),
                                undetected=_ast.get("undetected"),
                                categories=cats_stored,
                                registrar=dr.get("registrar"),
                                tags=dr.get("tags") or [],
                                community_malicious=votes.get("malicious"),
                                community_harmless=votes.get("harmless"),
                                last_analysis_date=dr.get("last_analysis_date"),
                                jarm=dr.get("jarm"),
                                popularity_alexa=dr.get("popularity_alexa"),
                                popularity_umbrella=dr.get("popularity_umbrella"),
                            )
                            stats["domains_updated"] += 1
                        except Exception as e:
                            stats["errors"].append(f"VirusTotal domain_report: {e}")
                    for rep in reports:
                        if not isinstance(rep, dict):
                            continue
                        ip = rep.get("ip")
                        if not ip:
                            continue
                        try:
                            _ast = (rep.get("analysis_stats") or {}) if isinstance(rep.get("analysis_stats"), dict) else {}
                            votes = rep.get("total_votes") or {}
                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i.vt_enriched = true,
                                    i.vt_reputation = $reputation,
                                    i.vt_malicious_count = $malicious,
                                    i.vt_suspicious_count = $suspicious,
                                    i.vt_harmless_count = $harmless,
                                    i.vt_undetected_count = $undetected,
                                    i.vt_tags = $tags,
                                    i.vt_community_malicious = $community_malicious,
                                    i.vt_community_harmless = $community_harmless,
                                    i.vt_last_analysis_date = $last_analysis_date,
                                    i.vt_network = $network,
                                    i.vt_rir = $rir,
                                    i.vt_continent = $continent,
                                    i.vt_jarm = $jarm,
                                    i.asn = CASE WHEN i.asn IS NOT NULL THEN i.asn ELSE $asn END,
                                    i.as_owner = CASE WHEN i.as_owner IS NOT NULL THEN i.as_owner ELSE $as_owner END,
                                    i.country = CASE WHEN i.country IS NOT NULL THEN i.country ELSE $country END,
                                    i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id,
                                reputation=rep.get("reputation"),
                                malicious=_ast.get("malicious"),
                                suspicious=_ast.get("suspicious"),
                                harmless=_ast.get("harmless"),
                                undetected=_ast.get("undetected"),
                                tags=rep.get("tags") or [],
                                community_malicious=votes.get("malicious"),
                                community_harmless=votes.get("harmless"),
                                last_analysis_date=rep.get("last_analysis_date"),
                                network=rep.get("network"),
                                rir=rep.get("regional_internet_registry"),
                                continent=rep.get("continent"),
                                jarm=rep.get("jarm"),
                                asn=rep.get("asn"),
                                as_owner=rep.get("as_owner"),
                                country=rep.get("country"),
                            )
                            stats["ips_enriched"] += 1
                        except Exception as e:
                            stats["errors"].append(f"VirusTotal IP {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_virustotal: {e}")
        print(f"[graph-db] update_graph_from_virustotal complete: {stats}")
        return stats

    def update_graph_from_zoomeye(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {"ips_enriched": 0, "ports_merged": 0, "services_merged": 0,
                 "subdomains_merged": 0, "relationships_created": 0, "errors": []}
        try:
            rows = (recon_data.get("zoomeye") or {}).get("results") or []
            domain = recon_data.get("domain", "")
            if not rows:
                stats["errors"].append("No zoomeye results in recon_data")
            else:
                with self.driver.session() as session:
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        ip = row.get("ip")
                        if not ip:
                            continue
                        try:
                            # Build IP props dict — only set non-empty values to avoid
                            # overwriting richer data from other tools with empty strings
                            ip_props: dict = {"zoomeye_enriched": True}
                            for field, prop in (
                                ("os",          "os"),
                                ("country",     "country"),
                                ("city",        "city"),
                                ("isp",         "isp"),
                                ("asn",         "asn"),
                                ("update_time", "zoomeye_last_seen"),
                            ):
                                val = row.get(field)
                                if val:
                                    ip_props[prop] = val
                            lat = row.get("latitude")
                            lon = row.get("longitude")
                            if lat is not None:
                                ip_props["latitude"] = lat
                            if lon is not None:
                                ip_props["longitude"] = lon

                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            port_raw = row.get("port")
                            try:
                                pnum = int(port_raw) if port_raw is not None else 0
                            except (TypeError, ValueError):
                                pnum = 0
                            if not pnum:
                                # Even without a port, try hostname/rdns → Subdomain
                                pass
                            else:
                                protocol = (row.get("protocol") or "tcp").lower() or "tcp"
                                session.run(
                                    """
                                    MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                    SET p.source = 'zoomeye', p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_PORT]->(p)
                                    """,
                                    port=pnum, protocol=protocol, ip=ip,
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["ports_merged"] += 1
                                stats["relationships_created"] += 1

                                # Service node — use app name; fall back to service field
                                svc_name = (row.get("app") or row.get("service") or "").strip()
                                if svc_name:
                                    svc_props: dict = {"source": "zoomeye"}
                                    banner = (row.get("banner") or "")[:500]
                                    if banner:
                                        svc_props["banner"] = banner
                                    version = (row.get("version") or "").strip()
                                    if version:
                                        svc_props["version"] = version
                                    product = (row.get("product") or "").strip()
                                    if product:
                                        svc_props["product"] = product
                                    title = (row.get("title") or "").strip()
                                    if title:
                                        svc_props["http_title"] = title
                                    session.run(
                                        """
                                        MERGE (svc:Service {name: $name, port_number: $port,
                                                            ip_address: $ip,
                                                            user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET svc.updated_at = datetime()
                                        SET svc += $props, svc.updated_at = datetime()
                                        WITH svc
                                        MATCH (p:Port {number: $port, protocol: $protocol,
                                                       ip_address: $ip,
                                                       user_id: $user_id, project_id: $project_id})
                                        MERGE (p)-[:RUNS_SERVICE]->(svc)
                                        """,
                                        name=svc_name, port=pnum, protocol=protocol, ip=ip,
                                        props=svc_props, user_id=user_id, project_id=project_id,
                                    )
                                    stats["services_merged"] += 1
                                    stats["relationships_created"] += 1

                            # Hostname / rDNS → Subdomain node (in-scope only)
                            for hostname_val in {row.get("hostname"), row.get("rdns")}:
                                if not hostname_val:
                                    continue
                                hostname_val = hostname_val.strip().lower()
                                if not hostname_val:
                                    continue
                                is_in_scope = domain and (
                                    hostname_val == domain
                                    or hostname_val.endswith("." + domain)
                                )
                                if is_in_scope:
                                    session.run(
                                        """
                                        MERGE (s:Subdomain {name: $name, user_id: $user_id,
                                                            project_id: $project_id})
                                        ON CREATE SET s.source = 'zoomeye_rdns',
                                                      s.status = 'resolved',
                                                      s.discovered_at = datetime(),
                                                      s.updated_at = datetime()
                                        MERGE (i:IP {address: $ip, user_id: $user_id,
                                                     project_id: $project_id})
                                        MERGE (s)-[:RESOLVES_TO {record_type: 'A',
                                                                  timestamp: datetime()}]->(i)
                                        """,
                                        name=hostname_val, ip=ip,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["subdomains_merged"] += 1
                                    stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"ZoomEye row {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_zoomeye: {e}")
        print(f"[graph-db] update_graph_from_zoomeye complete: {stats}")
        return stats

    def update_graph_from_criminalip(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0, "ports_merged": 0, "services_created": 0,
            "vulnerabilities_created": 0, "cves_created": 0,
            "domains_updated": 0, "relationships_created": 0, "errors": [],
        }
        try:
            cip = recon_data.get("criminalip") or {}
            reports = cip.get("ip_reports") or []
            domain_report = cip.get("domain_report")

            if not reports and not domain_report:
                stats["errors"].append("No criminalip data in recon_data")
            else:
                with self.driver.session() as session:
                    # ── 1. Domain report → Domain node enrichment ──
                    if domain_report and isinstance(domain_report, dict):
                        domain_name = domain_report.get("domain")
                        risk = domain_report.get("risk") or {}
                        if domain_name and isinstance(risk, dict):
                            try:
                                session.run(
                                    """
                                    MATCH (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                                    SET d.criminalip_enriched = true,
                                        d.criminalip_risk_score = $risk_score,
                                        d.criminalip_risk_grade = $risk_grade,
                                        d.criminalip_abuse_count = $abuse_count,
                                        d.criminalip_current_service = $current_service,
                                        d.updated_at = datetime()
                                    """,
                                    name=domain_name, user_id=user_id, project_id=project_id,
                                    risk_score=risk.get("score"),
                                    risk_grade=risk.get("grade"),
                                    abuse_count=risk.get("abuse_record_count"),
                                    current_service=risk.get("current_service"),
                                )
                                stats["domains_updated"] += 1
                            except Exception as e:
                                stats["errors"].append(f"CriminalIP domain_report: {e}")

                    # ── 2. Per-IP reports ──
                    for rep in reports:
                        if not isinstance(rep, dict):
                            continue
                        ip = rep.get("ip")
                        if not ip:
                            continue
                        try:
                            score = rep.get("score") or {}
                            if not isinstance(score, dict):
                                score = {}
                            issues = rep.get("issues") or {}
                            if not isinstance(issues, dict):
                                issues = {}
                            whois = rep.get("whois") or {}
                            if not isinstance(whois, dict):
                                whois = {}

                            ip_props: dict = {"criminalip_enriched": True}

                            # Scores
                            ins, outs = score.get("inbound"), score.get("outbound")
                            if ins is not None:
                                ip_props["criminalip_score_inbound"] = ins
                            if outs is not None:
                                ip_props["criminalip_score_outbound"] = outs

                            # Boolean threat flags
                            for fk, dk in (
                                ("is_vpn",     "criminalip_is_vpn"),
                                ("is_proxy",   "criminalip_is_proxy"),
                                ("is_tor",     "criminalip_is_tor"),
                                ("is_hosting", "criminalip_is_hosting"),
                                ("is_cloud",   "criminalip_is_cloud"),
                                ("is_mobile",  "criminalip_is_mobile"),
                                ("is_darkweb", "criminalip_is_darkweb"),
                                ("is_scanner", "criminalip_is_scanner"),
                                ("is_snort",   "criminalip_is_snort"),
                            ):
                                if fk in issues:
                                    ip_props[dk] = issues[fk]

                            # Whois / geolocation / ASN
                            for fk, dk in (
                                ("org_name",    "criminalip_org_name"),
                                ("country",     "criminalip_country"),
                                ("city",        "criminalip_city"),
                                ("latitude",    "criminalip_latitude"),
                                ("longitude",   "criminalip_longitude"),
                                ("asn_name",    "criminalip_asn_name"),
                                ("asn_no",      "criminalip_asn_no"),
                            ):
                                val = whois.get(fk)
                                if val is not None:
                                    ip_props[dk] = val

                            # IDS / scanning counts and categories
                            ids_count = rep.get("ids_count")
                            if ids_count is not None:
                                ip_props["criminalip_ids_count"] = ids_count
                            scanning_count = rep.get("scanning_count")
                            if scanning_count is not None:
                                ip_props["criminalip_scanning_count"] = scanning_count
                            categories = rep.get("categories")
                            if categories:
                                ip_props["criminalip_categories"] = json.dumps(categories)

                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            # ── 3. Ports + Services ──
                            for pentry in rep.get("ports") or []:
                                if not isinstance(pentry, dict):
                                    continue
                                try:
                                    pnum = int(pentry.get("port") or 0)
                                except (TypeError, ValueError):
                                    continue
                                if pnum <= 0:
                                    continue
                                proto = (pentry.get("socket") or "tcp").lower()
                                session.run(
                                    """
                                    MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                    SET p.source = 'criminalip', p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_PORT]->(p)
                                    """,
                                    port=pnum, protocol=proto, ip=ip,
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["ports_merged"] += 1
                                stats["relationships_created"] += 1

                                app_name = pentry.get("app_name")
                                if app_name:
                                    svc_name = app_name.lower()
                                    svc_props: dict = {"source": "criminalip", "updated_at": "datetime()"}
                                    if pentry.get("app_version"):
                                        svc_props["version"] = pentry["app_version"]
                                    if pentry.get("banner"):
                                        svc_props["banner"] = pentry["banner"][:500]
                                    if pentry.get("protocol"):
                                        svc_props["name"] = svc_name
                                    session.run(
                                        """
                                        MERGE (svc:Service {name: $svc_name, port_number: $port,
                                                            ip_address: $ip, user_id: $user_id,
                                                            project_id: $project_id})
                                        SET svc.source = 'criminalip',
                                            svc.version = $version,
                                            svc.banner  = $banner,
                                            svc.updated_at = datetime()
                                        WITH svc
                                        MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                       user_id: $user_id, project_id: $project_id})
                                        MERGE (p)-[:RUNS_SERVICE]->(svc)
                                        """,
                                        svc_name=svc_name, port=pnum, protocol=proto, ip=ip,
                                        version=pentry.get("app_version"),
                                        banner=(pentry.get("banner") or "")[:500] or None,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["services_created"] += 1
                                    stats["relationships_created"] += 1

                            # ── 4. Vulnerabilities (CVE data from full=true) ──
                            for vuln in rep.get("vulnerabilities") or []:
                                if not isinstance(vuln, dict):
                                    continue
                                cve_id = vuln.get("cve_id")
                                if not cve_id:
                                    continue
                                vuln_id = f"criminalip-{cve_id}-{ip}"
                                try:
                                    cvss = vuln.get("cvssv3_score") or vuln.get("cvssv2_score")
                                    session.run(
                                        """
                                        MERGE (v:Vulnerability {id: $vuln_id})
                                        ON CREATE SET v.source = 'criminalip', v.name = $cve_id,
                                                      v.cves = [$cve_id], v.cvss = $cvss,
                                                      v.user_id = $user_id, v.project_id = $project_id,
                                                      v.updated_at = datetime()
                                        """,
                                        vuln_id=vuln_id, cve_id=cve_id, cvss=cvss,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["vulnerabilities_created"] += 1

                                    session.run(
                                        """
                                        MERGE (c:CVE {id: $cve_id})
                                        ON CREATE SET c.source = 'criminalip',
                                                      c.user_id = $user_id, c.project_id = $project_id,
                                                      c.updated_at = datetime()
                                        SET c.cvss = $cvss, c.description = $description
                                        """,
                                        cve_id=cve_id, cvss=cvss,
                                        description=vuln.get("description"),
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["cves_created"] += 1

                                    session.run(
                                        """
                                        MATCH (v:Vulnerability {id: $vuln_id})
                                        MATCH (c:CVE {id: $cve_id})
                                        MERGE (v)-[:INCLUDES_CVE]->(c)
                                        """,
                                        vuln_id=vuln_id, cve_id=cve_id,
                                    )
                                    session.run(
                                        """
                                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MATCH (v:Vulnerability {id: $vuln_id})
                                        MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                        """,
                                        ip=ip, vuln_id=vuln_id,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["relationships_created"] += 2
                                except Exception as e:
                                    stats["errors"].append(f"CriminalIP CVE {cve_id} for {ip}: {e}")

                        except Exception as e:
                            stats["errors"].append(f"CriminalIP {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_criminalip: {e}")
        print(f"[graph-db] update_graph_from_criminalip complete: {stats}")
        return stats


if __name__ == "__main__":
    # Quick connection test
    print("[*] Testing Neo4j connection...")
    with Neo4jClient() as client:
        if client.verify_connection():
            print("[+] Successfully connected to Neo4j!")
        else:
            print("[-] Failed to connect to Neo4j")
