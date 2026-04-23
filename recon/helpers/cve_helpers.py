"""
RedAmon - CVE Lookup Helpers
============================
Functions for looking up CVEs from NVD and Vulners APIs based on detected technologies.
"""

import re
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# =============================================================================
# API URLs
# =============================================================================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"


# =============================================================================
# CPE Mappings for Common Technologies
# =============================================================================

CPE_MAPPINGS = {
    # Web Servers
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "cherokee": ("cherokee-project", "cherokee"),
    "gunicorn": ("gunicorn", "gunicorn"),
    "uvicorn": ("encode", "uvicorn"),
    "traefik": ("traefik", "traefik"),
    "envoy": ("envoyproxy", "envoy"),
    "openresty": ("openresty", "openresty"),
    "deno": ("deno", "deno"),
    "tengine": ("alibaba", "tengine"),
    # Languages/Runtimes
    "php": ("php", "php"),
    "python": ("python", "python"),
    "node.js": ("nodejs", "node.js"),
    "ruby": ("ruby-lang", "ruby"),
    "perl": ("perl", "perl"),
    "go": ("golang", "go"),
    # Databases
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "couchdb": ("apache", "couchdb"),
    "memcached": ("memcached", "memcached"),
    "sqlite": ("sqlite", "sqlite"),
    "solr": ("apache", "solr"),
    "adminer": ("adminer", "adminer"),
    # CMS
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "magento": ("adobe", "magento"),
    "ghost": ("ghost", "ghost"),
    "typo3": ("typo3", "typo3"),
    "concrete cms": ("concretecms", "concrete_cms"),
    "craft cms": ("craftcms", "craft_cms"),
    "strapi": ("strapi", "strapi"),
    "umbraco": ("umbraco", "umbraco_cms"),
    "adobe experience manager": ("adobe", "experience_manager"),
    "sitecore": ("sitecore", "experience_platform"),
    "dnn": ("dnnsoftware", "dotnetnuke"),
    "kentico": ("kentico", "kentico"),
    # Web Frameworks
    "django": ("djangoproject", "django"),
    "laravel": ("laravel", "laravel"),
    "spring": ("vmware", "spring_framework"),
    "flask": ("palletsprojects", "flask"),
    "express": ("expressjs", "express"),
    "rails": ("rubyonrails", "rails"),
    "codeigniter": ("codeigniter", "codeigniter"),
    "symfony": ("sensiolabs", "symfony"),
    "cakephp": ("cakephp", "cakephp"),
    "yii": ("yiiframework", "yii"),
    "nuxt.js": ("nuxt", "nuxt.js"),
    "struts": ("apache", "struts"),
    "coldfusion": ("adobe", "coldfusion"),
    # JavaScript Frameworks & Libraries
    "jquery": ("jquery", "jquery"),
    "angular": ("angular", "angular"),
    "react": ("facebook", "react"),
    "vue": ("vuejs", "vue.js"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    "next.js": ("vercel", "next.js"),
    "moment.js": ("momentjs", "moment"),
    "lodash": ("lodash", "lodash"),
    "handlebars": ("handlebarsjs", "handlebars"),
    "ember.js": ("emberjs", "ember.js"),
    "backbone.js": ("backbonejs", "backbone.js"),
    "dojo": ("dojotoolkit", "dojo"),
    "ckeditor": ("ckeditor", "ckeditor"),
    "tinymce": ("tiny", "tinymce"),
    "prototype": ("prototypejs", "prototype"),
    # E-commerce
    "prestashop": ("prestashop", "prestashop"),
    "opencart": ("opencart", "opencart"),
    "oscommerce": ("oscommerce", "oscommerce"),
    "zen cart": ("zen-cart", "zen_cart"),
    "woocommerce": ("automattic", "woocommerce"),
    # Message Boards / Community
    "discourse": ("discourse", "discourse"),
    "phpbb": ("phpbb", "phpbb"),
    "vbulletin": ("vbulletin", "vbulletin"),
    "mybb": ("mybb", "mybb"),
    "flarum": ("flarum", "flarum"),
    "nodebb": ("nodebb", "nodebb"),
    "mastodon": ("joinmastodon", "mastodon"),
    "mattermost": ("mattermost", "mattermost_server"),
    # Wikis
    "mediawiki": ("mediawiki", "mediawiki"),
    "confluence": ("atlassian", "confluence_server"),
    "dokuwiki": ("dokuwiki", "dokuwiki"),
    "xwiki": ("xwiki", "xwiki"),
    # Mail Servers / Webmail
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "zimbra": ("synacor", "zimbra_collaboration_suite"),
    "squirrelmail": ("squirrelmail", "squirrelmail"),
    # DNS
    "bind": ("isc", "bind"),
    # FTP
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "pureftpd": ("pureftpd", "pure-ftpd"),
    # Security / Proxies / Network
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "squid": ("squid-cache", "squid"),
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-software", "varnish_cache"),
    "kong": ("konghq", "kong_gateway"),
    "f5 big-ip": ("f5", "big-ip_access_policy_manager"),
    "pulse secure": ("pulsesecure", "pulse_connect_secure"),
    # CI/CD, DevOps & Issue Trackers
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "sonarqube": ("sonarsource", "sonarqube"),
    "nexus": ("sonatype", "nexus_repository_manager"),
    "rabbitmq": ("vmware", "rabbitmq"),
    "kafka": ("apache", "kafka"),
    "zookeeper": ("apache", "zookeeper"),
    "jira": ("atlassian", "jira"),
    "bitbucket": ("atlassian", "bitbucket"),
    "bugzilla": ("mozilla", "bugzilla"),
    "redmine": ("redmine", "redmine"),
    "gitea": ("gitea", "gitea"),
    "teamcity": ("jetbrains", "teamcity"),
    "artifactory": ("jfrog", "artifactory"),
    # Java Application Servers
    "jetty": ("eclipse", "jetty"),
    "wildfly": ("redhat", "wildfly"),
    "passenger": ("phusion", "passenger"),
    # Hosting Panels
    "cpanel": ("cpanel", "cpanel"),
    "plesk": ("plesk", "plesk"),
    "directadmin": ("directadmin", "directadmin"),
    # Other
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "webmin": ("webmin", "webmin"),
    "roundcube": ("roundcube", "webmail"),
    "minio": ("minio", "minio"),
}


# =============================================================================
# Technology Parsing Utilities
# =============================================================================

def _extract_semver(version: str) -> Optional[str]:
    """
    Extract the semantic version from a version string,
    stripping distro suffixes, patch identifiers, etc.

    Examples:
        "8.1.2-1ubuntu2.14" → "8.1.2"
        "2.4.49"            → "2.4.49"
        "1.19.0p1"          → "1.19.0"
        "9.0.65"            → "9.0.65"
        "8.9p1"             → "8.9"
        "10"                → "10"
        "v5.22.1"           → "5.22.1"
        ""                  → None
    """
    if not version:
        return None
    # Strip leading 'v' prefix (e.g., "v5.22.1" → "5.22.1")
    version = re.sub(r'^[vV]', '', version)
    # Try multi-part version first (x.y or x.y.z)
    match = re.match(r'(\d+(?:\.\d+)+)', version)
    if match:
        return match.group(1)
    # Fall back to single major version (e.g. "10" from "IIS/10")
    match = re.match(r'(\d+)', version)
    return match.group(1) if match else None


def split_server_header(header: str) -> List[str]:
    """
    Split a compound HTTP Server header into individual product tokens.

    Server headers can contain multiple products separated by spaces, but
    multi-word names like "Apache Tomcat" complicate naive splitting.

    Strategy: use regex to find all "Name/Version" or "Name_Version" tokens,
    then also catch standalone "(qualifier)" groups and skip them.

    Examples:
        "Apache/2.4.49 (Unix) OpenSSL/1.1.1l PHP/8.1.2-1ubuntu2.14"
            → ["Apache/2.4.49", "OpenSSL/1.1.1l", "PHP/8.1.2-1ubuntu2.14"]

        "Apache/2.4.49 (Unix)"
            → ["Apache/2.4.49"]

        "nginx/1.18.0 (Ubuntu)"
            → ["nginx/1.18.0"]

        "Apache Tomcat/9.0.65"
            → ["Apache Tomcat/9.0.65"]

        "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
            → ["OpenSSH_8.9p1"]

        "Nginx:1.19.0"
            → ["Nginx:1.19.0"]

        "jQuery"
            → ["jQuery"]
    """
    if not header or not header.strip():
        return []

    # Also match underscore-joined tokens like "OpenSSH_8.9p1"
    # but NOT "mod_wsgi/4.6.8" (has slash, so handled by slash_pattern)
    underscore_pattern = re.compile(
        r'([A-Za-z][A-Za-z0-9-]*_\d[\w.]*)'
    )

    products = []
    remaining = header.strip()

    # First extract underscore-joined tokens WITHOUT a slash/colon after them
    for m in underscore_pattern.finditer(remaining):
        token = m.group(1)
        end_pos = m.end()
        # Skip if this token is followed by / or : (it's part of a slash-product)
        if end_pos < len(remaining) and remaining[end_pos] in '/:':
            continue
        products.append(token)

    if products:
        # Remove extracted tokens from remaining
        for p in products:
            remaining = remaining.replace(p, ' ')

    # Now find slash/colon-delimited products in the remaining string
    # Match: "Name/version" or "Multi-Word_Name/version"
    # Name can contain letters, digits, spaces, hyphens, underscores
    # Version can optionally start with 'v' prefix (e.g., "Perl/v5.22.1")
    slash_pattern = re.compile(
        r'([A-Za-z][A-Za-z0-9 _-]*?)\s*[/:]\s*(v?\d[\w._-]*)'
    )
    for m in slash_pattern.finditer(remaining):
        full = m.group(0).strip()
        products.append(full)

    # If nothing was found with delimiters, return the original string as-is
    if not products:
        return [header.strip()]

    return products


def parse_technology_string(tech: str) -> Tuple[str, Optional[str]]:
    """
    Parse a SINGLE technology string into (name, version).

    For compound server headers with multiple products (e.g.,
    "Apache/2.4.49 (Unix) OpenSSL/1.1.1l"), use split_server_header()
    first to split into individual tokens, then parse each one.

    Handles formats:
        "Nginx:1.19.0"                          → ("nginx", "1.19.0")
        "Apache/2.4.49 (Unix)"                  → ("apache", "2.4.49")
        "PHP/8.1.2-1ubuntu2.14"                 → ("php", "8.1.2")
        "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"       → ("openssh", "8.9")
        "Apache Tomcat/9.0.65"                  → ("apache tomcat", "9.0.65")
        "jQuery"                                → ("jquery", None)
        "Microsoft-IIS/10.0"                    → ("microsoft-iis", "10.0")
        "mini_httpd/1.30"                       → ("mini_httpd", "1.30")
    """
    tech = tech.strip()
    if not tech:
        return "", None

    # Skip strings that are just a bare version number (no product name)
    if re.match(r'^\d+[\d.]*$', tech):
        return "", None

    # Handle parenthesized version (e.g., "Jetty(9.4.44.v20210927)")
    paren_match = re.match(r'^([A-Za-z][A-Za-z0-9 _-]*?)\((.+?)\)$', tech)
    if paren_match:
        name = paren_match.group(1).strip().lower()
        version = _extract_semver(paren_match.group(2))
        return name, version

    # Handle underscore-joined name_version (e.g., "OpenSSH_8.9p1 Ubuntu-3")
    # But NOT "name_name/version" patterns like "mini_httpd/1.30"
    underscore_match = re.match(r'^([A-Za-z][A-Za-z0-9-]*)_(\d[\w.]*)', tech)
    if underscore_match and '/' not in tech and ':' not in tech:
        name = underscore_match.group(1).lower()
        version = _extract_semver(underscore_match.group(2))
        return name, version

    # Prefer colon and slash over space — they are explicit version delimiters.
    # Colon: Wappalyzer format "Name:version" — split on first occurrence
    # Slash: Server header format "Name/version" — split on first occurrence
    #   This correctly handles "Apache/2.4.49 (Unix) OpenSSL/1.1.1l" → ("apache", "2.4.49")
    #   For multi-word names like "Apache Tomcat/9.0.65", first split gives the right result too
    for delimiter in [':', '/']:
        if delimiter in tech:
            parts = tech.split(delimiter, 1)
            name = parts[0].strip().lower()
            raw_version = parts[1].strip() if len(parts) > 1 else None
            if raw_version:
                # Remove everything from the first space onward
                # (handles "2.4.49 (Unix) OpenSSL/1.1.1l" → "2.4.49")
                raw_version = raw_version.split()[0]
            version = _extract_semver(raw_version) if raw_version else None
            # If what we extracted as "version" doesn't look numeric, it's not a real version
            # Return just the name part (e.g., "MinIO/RELEASE.2023..." → "minio", None)
            if version is None and raw_version and not re.match(r'\d', raw_version):
                return name, None
            return name, version

    # Space delimiter — check if the LAST token looks like a version
    if ' ' in tech:
        tokens = tech.split()
        last_token = tokens[-1]
        if re.match(r'\d', last_token):
            # Last token starts with digit → treat as version, rest is the name
            name = ' '.join(tokens[:-1]).lower()
            version = _extract_semver(last_token)
            return name, version
        # Multi-word name without version (e.g., "Apache Tomcat")
        return tech.lower(), None

    return tech.lower(), None


def normalize_product_name(name: str) -> str:
    """Normalize product name for lookup."""
    name = name.lower().strip()
    aliases = {
        # Apache variants
        "apache httpd": "apache", "apache http server": "apache",
        "apache2": "apache", "httpd": "apache",
        "apache-coyote": "tomcat", "apache coyote": "tomcat",
        "apache tomcat": "tomcat",
        "apache couchdb": "couchdb", "apache kafka": "kafka",
        "apache zookeeper": "zookeeper",
        "apache struts": "struts", "apache solr": "solr",
        # Microsoft
        "microsoft-iis": "iis", "microsoft iis": "iis",
        "microsoft-httpapi": "iis",
        # Node/JS
        "node": "node.js", "nodejs": "node.js",
        "nextjs": "next.js",
        "nuxtjs": "nuxt.js", "nuxt": "nuxt.js",
        "expressjs": "express",
        "ruby on rails": "rails", "rubyonrails": "rails",
        # Databases
        "postgres": "postgresql", "mongo": "mongodb",
        # CMS
        "wp": "wordpress",
        "concrete5": "concrete cms",
        "aem": "adobe experience manager",
        "dotnetnuke": "dnn",
        "adobe coldfusion": "coldfusion",
        # Atlassian (Wappalyzer outputs "Atlassian Jira", etc.)
        "atlassian jira": "jira",
        "atlassian confluence": "confluence",
        "atlassian bitbucket": "bitbucket",
        # JS libraries
        "moment": "moment.js", "momentjs": "moment.js",
        "ember": "ember.js", "emberjs": "ember.js",
        "backbone": "backbone.js", "backbonejs": "backbone.js",
        "handlebarsjs": "handlebars",
        "dojo toolkit": "dojo",
        "prototype.js": "prototype",
        # E-commerce
        "zencart": "zen cart",
        # Webmail / Network
        "zimbra collaboration suite": "zimbra",
        "big-ip": "f5 big-ip",
        "pulse connect secure": "pulse secure",
        # Hosting
        "cpanel whm": "cpanel",
        # Servers
        "open resty": "openresty",
        # Community
        "mattermost server": "mattermost",
        # SSH/FTP
        "ssh": "openssh", "pure-ftpd": "pureftpd",
        # Proxies
        "squid-cache": "squid",
        "varnish cache": "varnish",
        # Multi-word server names
        "phusion passenger": "passenger",
        "eclipse jetty": "jetty",
    }
    return aliases.get(name, name)


def classify_cvss_score(score: float) -> str:
    """Classify CVSS score into severity level."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"


# =============================================================================
# NVD API Lookup
# =============================================================================

def lookup_cves_nvd(
    product: str,
    version: str = None,
    max_results: int = 20,
    api_key: str = None,
    key_rotator=None,
) -> List[Dict]:
    """
    Query NVD API for CVEs affecting a product/version.
    
    Args:
        product: Product name (e.g., 'nginx')
        version: Version string (e.g., '1.19.0')
        max_results: Maximum results to return
        api_key: Optional NVD API key for higher rate limits
        
    Returns:
        List of CVE dictionaries
    """
    cves = []
    product_normalized = normalize_product_name(product)
    cpe_info = CPE_MAPPINGS.get(product_normalized)

    params = {"resultsPerPage": max_results}
    headers = {}

    # Add API key if available (use rotator if present)
    effective_key = key_rotator.current_key if key_rotator and key_rotator.has_keys else api_key
    if effective_key:
        headers["apiKey"] = effective_key

    if cpe_info and version:
        vendor, prod = cpe_info
        params["cpeName"] = f"cpe:2.3:a:{vendor}:{prod}:{version}:*:*:*:*:*:*:*"
    elif cpe_info:
        vendor, prod = cpe_info
        params["cpeName"] = f"cpe:2.3:a:{vendor}:{prod}:*:*:*:*:*:*:*:*"
    else:
        # Fallback to keyword search for unknown products
        keyword = product
        if version:
            keyword += f" {version}"
        params["keywordSearch"] = keyword

    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        if key_rotator:
            key_rotator.tick()

        # Handle rate limiting (NVD returns 403 or 429 when rate limited)
        if response.status_code == 403:
            print(f"[!][CVE] NVD API rate limited. Configure NVD API Key in Global Settings → Tool API Keys for higher limits.")
            return cves
        if response.status_code == 404:
            # 404 can occur with invalid CPE format or when service is unavailable
            print(f"[!][CVE] NVD API returned 404 for {product}. Skipping CVE lookup.")
            return cves
        if response.status_code == 429:
            print(f"[!][CVE] NVD API rate limited (429). Waiting...")
            time.sleep(6)  # Wait 6 seconds and continue
            return cves

        response.raise_for_status()
        data = response.json()

        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            metrics = cve_data.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else None
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else None
            
            cvss_score = None
            severity = None
            
            if cvss_v3:
                cvss_score = cvss_v3.get("cvssData", {}).get("baseScore")
                severity = cvss_v3.get("cvssData", {}).get("baseSeverity")
            elif cvss_v2:
                cvss_score = cvss_v2.get("cvssData", {}).get("baseScore")
                severity = cvss_v2.get("baseSeverity")
            
            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            
            refs = cve_data.get("references", [])
            reference_urls = [ref.get("url") for ref in refs[:3] if ref.get("url")]
            
            cves.append({
                "id": cve_id,
                "cvss": cvss_score,
                "severity": severity,
                "description": description[:300] if description else "",
                "published": cve_data.get("published"),
                "references": reference_urls,
                "source": "nvd",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
            
    except Exception as e:
        print(f"[!][CVE] NVD API error: {str(e)[:80]}")
    
    return cves


# =============================================================================
# Vulners API Lookup
# =============================================================================

def lookup_cves_vulners(product: str, version: str, api_key: str = None, key_rotator=None) -> List[Dict]:
    """
    Query Vulners API for CVEs (like Nmap's vulners script).

    Args:
        product: Product name
        version: Version string (required for Vulners)
        api_key: Vulners API key
        key_rotator: Optional KeyRotator for key rotation

    Returns:
        List of CVE dictionaries
    """
    cves = []
    if not version:
        return cves

    effective_key = key_rotator.current_key if key_rotator and key_rotator.has_keys else api_key
    params = {"software": f"{product} {version}", "version": version, "type": "software"}
    if effective_key:
        params["apiKey"] = effective_key

    try:
        response = requests.get(VULNERS_API_URL, params=params, timeout=30)
        if key_rotator:
            key_rotator.tick()
        response.raise_for_status()
        data = response.json()
        
        if data.get("result") == "OK":
            for vuln in data.get("data", {}).get("search", []):
                vuln_id = vuln.get("id", "")
                cvss_data = vuln.get("cvss", {})
                
                cves.append({
                    "id": vuln_id,
                    "cvss": cvss_data.get("score"),
                    "severity": classify_cvss_score(cvss_data.get("score")),
                    "description": vuln.get("description", "")[:300],
                    "published": vuln.get("published"),
                    "references": [vuln.get("href")] if vuln.get("href") else [],
                    "source": "vulners",
                    "url": f"https://vulners.com/{vuln.get('type', 'cve')}/{vuln_id}",
                })
    except Exception as e:
        print(f"[!][CVE] Vulners API error: {str(e)[:80]}")
    
    return cves


# =============================================================================
# Main CVE Lookup Orchestration
# =============================================================================

def run_cve_lookup(
    recon_data: dict,
    enabled: bool = True,
    source: str = "nvd",
    max_cves: int = 20,
    min_cvss: float = 0.0,
    vulners_api_key: str = None,
    nvd_api_key: str = None,
    nvd_key_rotator=None,
    vulners_key_rotator=None,
) -> Dict:
    """
    Lookup CVEs for all technologies detected by httpx.
    
    Args:
        recon_data: Reconnaissance data containing httpx results
        enabled: Whether CVE lookup is enabled
        source: API source ('nvd' or 'vulners')
        max_cves: Maximum CVEs per technology
        min_cvss: Minimum CVSS score to include
        vulners_api_key: Vulners API key
        nvd_api_key: NVD API key
        
    Returns:
        Dictionary to add to recon_data
    """
    if not enabled:
        return {}
    
    print(f"\n{'='*60}")
    print("[*][CVE] Technology-Based Vulnerability Discovery")
    print(f"{'='*60}")
    print(f"[*][CVE] Source: {source.upper()}")
    print(f"[*][CVE] Min CVSS: {min_cvss}")
    
    # Extract technologies from httpx
    technologies = set()
    httpx_data = recon_data.get("http_probe", {})

    for url_data in httpx_data.get("by_url", {}).values():
        techs = url_data.get("technologies", [])
        technologies.update(techs)
        server = url_data.get("server")
        if server:
            # Split compound server headers like
            # "Apache/2.4.49 (Unix) OpenSSL/1.1.1l PHP/8.1.2"
            # into individual product strings
            for product in split_server_header(server):
                technologies.add(product)

    # Also extract technologies from banner grab (non-HTTP services like SSH, FTP, MySQL)
    banner_data = recon_data.get("banner_grab", {})
    for service_type, instances in banner_data.get("services_found", {}).items():
        for instance in instances:
            version_str = instance.get("version")
            if version_str:
                technologies.add(version_str)

    # Also extract technologies from Nmap service version detection
    nmap_data = recon_data.get("nmap_scan", {})
    for svc in nmap_data.get("services_detected", []):
        product = svc.get("product", "")
        version = svc.get("version", "")
        if product and version:
            technologies.add(f"{product}/{version}")

    # Filter and deduplicate technologies to lookup
    tech_to_lookup = []
    seen_normalized = set()
    skip_list = ["ubuntu", "debian", "centos", "linux", "windows",
                 "dreamweaver", "frontpage", "html", "css", "aws",
                 "cloudflare", "google analytics", "google tag manager",
                 "facebook pixel", "hotjar", "google font api"]

    for tech in technologies:
        name, version = parse_technology_string(tech)
        name = normalize_product_name(name)
        if not version or name in skip_list:
            continue
        key = (name.lower(), version.lower())
        if key in seen_normalized:
            continue
        seen_normalized.add(key)
        tech_to_lookup.append(tech)
    
    print(f"\n[*][CVE] Technologies with versions: {len(tech_to_lookup)}")
    
    if not tech_to_lookup:
        print("[!][CVE] No technologies with versions found")
        return {"technology_cves": {"summary": {"total_cves": 0}}}
    
    # Lookup CVEs
    cve_results = {}
    all_cves = []
    
    for i, tech in enumerate(tech_to_lookup, 1):
        name, version = parse_technology_string(tech)
        name = normalize_product_name(name)
        
        print(f"[*][CVE] [{i}/{len(tech_to_lookup)}] {tech}...", end=" ", flush=True)
        
        if source == "vulners" and vulners_api_key:
            cves = lookup_cves_vulners(name, version, vulners_api_key, key_rotator=vulners_key_rotator)
        else:
            cves = lookup_cves_nvd(name, version, max_cves, nvd_api_key, key_rotator=nvd_key_rotator)
        
        # Filter by min CVSS
        if min_cvss > 0:
            cves = [c for c in cves if (c.get("cvss") or 0) >= min_cvss]
        
        cves.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
        cves = cves[:max_cves]
        
        if cves:
            cve_results[tech] = {
                "technology": tech,
                "product": name,
                "version": version,
                "cve_count": len(cves),
                "critical": len([c for c in cves if c.get("severity") == "CRITICAL"]),
                "high": len([c for c in cves if c.get("severity") == "HIGH"]),
                "cves": cves,
            }
            all_cves.extend(cves)
            print(f"✓ {len(cves)} CVEs found")
        else:
            print("no CVEs")
        
        # Rate limiting for NVD API
        if source == "nvd" and i < len(tech_to_lookup):
            time.sleep(6)
    
    # Count unique CVEs
    unique_cve_ids = set()
    for tech_data in cve_results.values():
        for cve in tech_data.get("cves", []):
            unique_cve_ids.add(cve["id"])

    # Count severity distribution
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for tech_data in cve_results.values():
        for cve in tech_data.get("cves", []):
            sev = cve.get("severity", "").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

    # Build result
    result = {
        "technology_cves": {
            "lookup_timestamp": datetime.now().isoformat(),
            "source": source,
            "technologies_checked": len(tech_to_lookup),
            "technologies_with_cves": len(cve_results),
            "by_technology": cve_results,
            "summary": {
                "total_unique_cves": len(unique_cve_ids),
                "critical": severity_counts["CRITICAL"],
                "high": severity_counts["HIGH"],
                "medium": severity_counts["MEDIUM"],
                "low": severity_counts["LOW"],
            }
        }
    }
    
    # Print summary
    summary = result["technology_cves"]["summary"]
    print(f"\n[+][CVE] CVE LOOKUP SUMMARY:")
    print(f"[+][CVE] Total unique CVEs: {summary['total_unique_cves']}")
    if summary['critical'] > 0:
        print(f"[!][CVE] CRITICAL: {summary['critical']}")
    if summary['high'] > 0:
        print(f"[!][CVE] HIGH: {summary['high']}")
    if summary['medium'] > 0:
        print(f"[*][CVE] MEDIUM: {summary['medium']}")
    print(f"{'='*60}")
    
    return result

