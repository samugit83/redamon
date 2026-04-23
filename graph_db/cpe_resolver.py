"""
CPE Parsing & Resolution Helpers

Provides functions to parse CPE strings and resolve (vendor, product) pairs
to human-readable technology display names, using a 4-level resolution order:
  1. Wappalyzer reverse CPE cache (technologies.json)
  2. _GVM_DISPLAY_NAMES (curated non-HTTP technologies)
  3. _REVERSE_CPE_MAPPINGS (HTTP servers, DBs, frameworks)
  4. Humanized fallback (title-case, underscore → space)
"""

import re
import json
from pathlib import Path


# =============================================================================
# Curated display name lookup tables
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


# =============================================================================
# CPE parsing and resolution functions
# =============================================================================

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
