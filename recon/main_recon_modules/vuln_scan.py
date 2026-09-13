"""
RedAmon - Vulnerability Scanner Module
======================================
Template-based vulnerability scanning.
Enriches reconnaissance data with comprehensive web application vulnerability detection:
- CVE detection (8000+ templates)
- Web application vulnerabilities (SQLi, XSS, RCE, etc.)
- Exposed panels and sensitive files
- Misconfigurations
- Default credentials
- Cloud security issues
- Technology fingerprinting

Scans both IPs and hostnames (subdomains) for complete coverage.
Organizes results by target in the JSON output.
Supports proxy/Tor for anonymous scanning.
"""

import copy
import ipaddress
import json
import os
import subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import sys


def _url_host_is_ip(url: str) -> bool:
    """Return True if the URL's host is a literal IPv4/IPv6 address."""
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False


def _build_tech_fingerprint(http_probe: dict) -> dict:
    """Aggregate Wappalyzer technologies and Server headers from http_probe
    into a single fingerprint for the Nuclei AI tag selector."""
    techs, servers = set(), set()
    for entry in (http_probe.get('by_url') or {}).values():
        for t in (entry.get('technologies') or []):
            techs.add(str(t).lower())
        srv = (entry.get('server') or '').lower().split('/')[0].strip()
        if srv:
            servers.add(srv)
    for k in (http_probe.get('technologies_found') or {}).keys():
        techs.add(str(k).lower())
    return {"technologies": sorted(techs), "servers": sorted(servers)}

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Settings are passed from main.py to avoid multiple database queries

# Import helpers from organized modules
from recon.helpers import (
    # Docker utilities
    is_docker_installed,
    is_docker_running,
    fix_file_ownership,
    pull_nuclei_docker_image,
    ensure_templates_volume,
    # Target extraction
    extract_targets_from_recon,
    build_target_urls,
    # Nuclei helpers
    build_nuclei_command,
    parse_nuclei_finding,
    is_false_positive,
    set_fp_ai_ctx,
    # CVE lookup
    run_cve_lookup,
    # Security checks
    run_security_checks,
)


def _execute_nuclei_pass(cmd: list, output_file: str, label: str) -> tuple:
    """
    Run a single nuclei invocation and parse the JSONL output.

    Returns (findings, false_positives, duration_seconds, return_code).
    """
    print(f"[*][Nuclei] Running {label} pass [DOCKER]...")
    print(f"[*][Nuclei] {label} command: {' '.join(cmd[:12])}...")

    start_time = datetime.now()
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    stderr_lines = []
    for line in process.stdout:
        line = line.rstrip()
        if not line:
            continue
        print(f"[*][Nuclei][{label}] {line}", flush=True)
        stderr_lines.append(line)
    process.wait()
    duration = (datetime.now() - start_time).total_seconds()

    if process.returncode != 0 and stderr_lines:
        # Skip noise: nuclei [WRN]/[INF] lines, the pipe-format stats heartbeat
        # (`| Duration: 0:00:30 | ...`), and the JSON-format stats heartbeat
        # ({"duration":...,"matched":...}) so they don't masquerade as errors.
        error_lines = [
            l for l in stderr_lines
            if l
            and 'WRN' not in l
            and 'INF' not in l
            and '| Duration:' not in l
            and not (l.lstrip().startswith('{') and '"duration"' in l)
        ]
        if error_lines:
            print(f"[!][Nuclei] {label} warnings: {error_lines[0][:100]}")

    findings = []
    false_positives = []
    if Path(output_file).exists():
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_finding = json.loads(line)
                    is_fp, fp_reason = is_false_positive(raw_finding)
                    if is_fp:
                        false_positives.append({
                            "template_id": raw_finding.get("template-id", "unknown"),
                            "matched_at": raw_finding.get("matched-at", "unknown"),
                            "reason": fp_reason,
                        })
                        continue
                    findings.append(parse_nuclei_finding(raw_finding))
                except json.JSONDecodeError:
                    continue

    return findings, false_positives, duration, process.returncode


# =============================================================================
# Severity Definitions
# =============================================================================

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

SEVERITY_COLORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "unknown": "⚫"
}


def run_vuln_scan(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict:
    """
    Run nuclei scan on all URLs derived from recon data.

    Args:
        recon_data: Domain reconnaissance data dictionary
        output_file: Optional path to save incremental results
        settings: Settings dictionary from main.py

    Returns:
        Updated recon_data with nuclei results added
    """
    print("\n" + "=" * 70)
    print("[*][Nuclei] RedAmon - Nuclei Vulnerability Scanner")
    print("=" * 70)

    # Use passed settings or empty dict as fallback
    if settings is None:
        settings = {}

    # Extract settings from passed dict
    NUCLEI_SEVERITY = settings.get('NUCLEI_SEVERITY', ['critical', 'high', 'medium', 'low'])
    NUCLEI_TEMPLATES = settings.get('NUCLEI_TEMPLATES', [])
    NUCLEI_EXCLUDE_TEMPLATES = settings.get('NUCLEI_EXCLUDE_TEMPLATES', [])
    NUCLEI_RATE_LIMIT = settings.get('NUCLEI_RATE_LIMIT', 100)
    NUCLEI_BULK_SIZE = settings.get('NUCLEI_BULK_SIZE', 25)
    NUCLEI_CONCURRENCY = settings.get('NUCLEI_CONCURRENCY', 25)
    NUCLEI_TIMEOUT = settings.get('NUCLEI_TIMEOUT', 10)
    NUCLEI_RETRIES = settings.get('NUCLEI_RETRIES', 1)
    NUCLEI_TAGS = settings.get('NUCLEI_TAGS', ['cve', 'xss', 'sqli', 'rce', 'lfi', 'ssrf', 'xxe', 'ssti'])
    NUCLEI_EXCLUDE_TAGS = settings.get('NUCLEI_EXCLUDE_TAGS', ['dos', 'fuzz'])
    NUCLEI_DAST_MODE = settings.get('NUCLEI_DAST_MODE', False)
    NUCLEI_NEW_TEMPLATES_ONLY = settings.get('NUCLEI_NEW_TEMPLATES_ONLY', False)
    NUCLEI_CUSTOM_TEMPLATES = settings.get('NUCLEI_CUSTOM_TEMPLATES', [])
    NUCLEI_SELECTED_CUSTOM_TEMPLATES = settings.get('NUCLEI_SELECTED_CUSTOM_TEMPLATES', [])
    NUCLEI_HEADLESS = settings.get('NUCLEI_HEADLESS', False)
    NUCLEI_SYSTEM_RESOLVERS = settings.get('NUCLEI_SYSTEM_RESOLVERS', True)
    NUCLEI_FOLLOW_REDIRECTS = settings.get('NUCLEI_FOLLOW_REDIRECTS', True)
    NUCLEI_MAX_REDIRECTS = settings.get('NUCLEI_MAX_REDIRECTS', 10)
    NUCLEI_SCAN_ALL_IPS = settings.get('NUCLEI_SCAN_ALL_IPS', False)
    NUCLEI_INTERACTSH = settings.get('NUCLEI_INTERACTSH', True)
    NUCLEI_DOCKER_IMAGE = settings.get('NUCLEI_DOCKER_IMAGE', 'projectdiscovery/nuclei:latest')
    NUCLEI_AI_TAGS = settings.get('NUCLEI_AI_TAGS', False)
    WAF_AI_CLASSIFIER = settings.get('WAF_AI_CLASSIFIER', False)
    NUCLEI_AI_RESPONSE_FILTER = settings.get('NUCLEI_AI_RESPONSE_FILTER', False)
    AI_PIPELINE_MODEL = settings.get('AI_PIPELINE_MODEL', 'claude-opus-4-6')
    KATANA_DEPTH = settings.get('KATANA_DEPTH', 2)
    NUCLEI_AUTO_UPDATE_TEMPLATES = settings.get('NUCLEI_AUTO_UPDATE_TEMPLATES', True)
    CVE_LOOKUP_ENABLED = settings.get('CVE_LOOKUP_ENABLED', True)
    CVE_LOOKUP_SOURCE = settings.get('CVE_LOOKUP_SOURCE', 'nvd')
    CVE_LOOKUP_MAX_CVES = settings.get('CVE_LOOKUP_MAX_CVES', 20)
    CVE_LOOKUP_MIN_CVSS = settings.get('CVE_LOOKUP_MIN_CVSS', 0.0)
    VULNERS_API_KEY = settings.get('VULNERS_API_KEY', '')
    NVD_API_KEY = settings.get('NVD_API_KEY', '')
    NVD_KEY_ROTATOR = settings.get('NVD_KEY_ROTATOR')
    VULNERS_KEY_ROTATOR = settings.get('VULNERS_KEY_ROTATOR')
    SECURITY_CHECK_ENABLED = settings.get('SECURITY_CHECK_ENABLED', True)
    SECURITY_CHECK_DIRECT_IP_HTTP = settings.get('SECURITY_CHECK_DIRECT_IP_HTTP', True)
    SECURITY_CHECK_DIRECT_IP_HTTPS = settings.get('SECURITY_CHECK_DIRECT_IP_HTTPS', True)
    SECURITY_CHECK_IP_API_EXPOSED = settings.get('SECURITY_CHECK_IP_API_EXPOSED', True)
    SECURITY_CHECK_WAF_BYPASS = settings.get('SECURITY_CHECK_WAF_BYPASS', True)
    SECURITY_CHECK_TLS_EXPIRING_SOON = settings.get('SECURITY_CHECK_TLS_EXPIRING_SOON', True)
    SECURITY_CHECK_TLS_EXPIRY_DAYS = settings.get('SECURITY_CHECK_TLS_EXPIRY_DAYS', 30)
    SECURITY_CHECK_MISSING_REFERRER_POLICY = settings.get('SECURITY_CHECK_MISSING_REFERRER_POLICY', True)
    SECURITY_CHECK_MISSING_PERMISSIONS_POLICY = settings.get('SECURITY_CHECK_MISSING_PERMISSIONS_POLICY', True)
    SECURITY_CHECK_MISSING_COOP = settings.get('SECURITY_CHECK_MISSING_COOP', True)
    SECURITY_CHECK_MISSING_CORP = settings.get('SECURITY_CHECK_MISSING_CORP', True)
    SECURITY_CHECK_MISSING_COEP = settings.get('SECURITY_CHECK_MISSING_COEP', True)
    SECURITY_CHECK_CACHE_CONTROL_MISSING = settings.get('SECURITY_CHECK_CACHE_CONTROL_MISSING', True)
    SECURITY_CHECK_LOGIN_NO_HTTPS = settings.get('SECURITY_CHECK_LOGIN_NO_HTTPS', True)
    SECURITY_CHECK_SESSION_NO_SECURE = settings.get('SECURITY_CHECK_SESSION_NO_SECURE', True)
    SECURITY_CHECK_SESSION_NO_HTTPONLY = settings.get('SECURITY_CHECK_SESSION_NO_HTTPONLY', True)
    SECURITY_CHECK_BASIC_AUTH_NO_TLS = settings.get('SECURITY_CHECK_BASIC_AUTH_NO_TLS', True)
    SECURITY_CHECK_SPF_MISSING = settings.get('SECURITY_CHECK_SPF_MISSING', True)
    SECURITY_CHECK_DMARC_MISSING = settings.get('SECURITY_CHECK_DMARC_MISSING', True)
    SECURITY_CHECK_DNSSEC_MISSING = settings.get('SECURITY_CHECK_DNSSEC_MISSING', True)
    SECURITY_CHECK_ZONE_TRANSFER = settings.get('SECURITY_CHECK_ZONE_TRANSFER', True)
    SECURITY_CHECK_ADMIN_PORT_EXPOSED = settings.get('SECURITY_CHECK_ADMIN_PORT_EXPOSED', True)
    SECURITY_CHECK_DATABASE_EXPOSED = settings.get('SECURITY_CHECK_DATABASE_EXPOSED', True)
    SECURITY_CHECK_REDIS_NO_AUTH = settings.get('SECURITY_CHECK_REDIS_NO_AUTH', True)
    SECURITY_CHECK_KUBERNETES_API_EXPOSED = settings.get('SECURITY_CHECK_KUBERNETES_API_EXPOSED', True)
    SECURITY_CHECK_SMTP_OPEN_RELAY = settings.get('SECURITY_CHECK_SMTP_OPEN_RELAY', True)
    SECURITY_CHECK_CSP_UNSAFE_INLINE = settings.get('SECURITY_CHECK_CSP_UNSAFE_INLINE', True)
    SECURITY_CHECK_INSECURE_FORM_ACTION = settings.get('SECURITY_CHECK_INSECURE_FORM_ACTION', True)
    SECURITY_CHECK_NO_RATE_LIMITING = settings.get('SECURITY_CHECK_NO_RATE_LIMITING', True)
    SECURITY_CHECK_TIMEOUT = settings.get('SECURITY_CHECK_TIMEOUT', 10)
    SECURITY_CHECK_MAX_WORKERS = settings.get('SECURITY_CHECK_MAX_WORKERS', 10)

    # Check if Nuclei scanner is enabled
    NUCLEI_ENABLED = settings.get('NUCLEI_ENABLED', True)

    if not NUCLEI_ENABLED:
        print("[*][Nuclei] Vulnerability scanner disabled -- skipping")
        # Initialize empty vuln_scan structure so downstream code doesn't break
        recon_data["vuln_scan"] = {
            "scan_metadata": {
                "scan_timestamp": datetime.now().isoformat(),
                "scan_duration_seconds": 0,
                "nuclei_version": "N/A (disabled)",
                "templates_available": 0,
                "execution_mode": "disabled",
                "docker_image": NUCLEI_DOCKER_IMAGE,
                "anonymous_mode": False,
                "severity_filter": NUCLEI_SEVERITY,
                "tags_filter": NUCLEI_TAGS,
                "exclude_tags": NUCLEI_EXCLUDE_TAGS,
                "rate_limit": NUCLEI_RATE_LIMIT,
                "dast_mode": NUCLEI_DAST_MODE,
                "dast_urls_discovered": 0,
                "katana_crawl_depth": None,
                "total_urls_scanned": 0,
                "total_hostnames": 0,
                "total_ips": 0,
                "false_positives_filtered": 0,
            },
            "discovered_urls": {
                "base_urls": [],
                "dast_urls_with_params": [],
                "all_scanned_urls": [],
            },
            "by_target": {},
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            },
            "vulnerabilities": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            },
            "all_cves": [],
            "by_category": {},
            "by_template": {},
            "false_positives": [],
        }

    if NUCLEI_ENABLED:
        from recon.helpers import print_effective_settings
        print_effective_settings(
            "Nuclei",
            settings,
            keys=[
                ("NUCLEI_ENABLED", "Toggle"),
                ("NUCLEI_DOCKER_IMAGE", "Image"),
                ("NUCLEI_SEVERITY", "Severity & templates"),
                ("NUCLEI_TEMPLATES", "Severity & templates"),
                ("NUCLEI_EXCLUDE_TEMPLATES", "Severity & templates"),
                ("NUCLEI_TAGS", "Severity & templates"),
                ("NUCLEI_EXCLUDE_TAGS", "Severity & templates"),
                ("NUCLEI_CUSTOM_TEMPLATES", "Severity & templates"),
                ("NUCLEI_SELECTED_CUSTOM_TEMPLATES", "Severity & templates"),
                ("NUCLEI_DAST_MODE", "Advanced modes"),
                ("NUCLEI_NEW_TEMPLATES_ONLY", "Advanced modes"),
                ("NUCLEI_HEADLESS", "Advanced modes"),
                ("NUCLEI_RATE_LIMIT", "Performance"),
                ("NUCLEI_BULK_SIZE", "Performance"),
                ("NUCLEI_CONCURRENCY", "Performance"),
                ("NUCLEI_TIMEOUT", "Performance"),
                ("NUCLEI_RETRIES", "Performance"),
                ("NUCLEI_SYSTEM_RESOLVERS", "Network"),
                ("NUCLEI_FOLLOW_REDIRECTS", "Network"),
                ("NUCLEI_MAX_REDIRECTS", "Network"),
                ("NUCLEI_INTERACTSH", "Network"),
                ("NUCLEI_AI_TAGS", "AI cascade"),
                ("NUCLEI_AUTO_UPDATE_TEMPLATES", "Templates lifecycle"),
                ("NUCLEI_SCAN_ALL_IPS", "Targeting"),
                ("KATANA_DEPTH", "Targeting"),
                ("CVE_LOOKUP_ENABLED", "CVE enrichment"),
                ("CVE_LOOKUP_SOURCE", "CVE enrichment"),
                ("CVE_LOOKUP_MAX_CVES", "CVE enrichment"),
                ("CVE_LOOKUP_MIN_CVSS", "CVE enrichment"),
                ("VULNERS_API_KEY", "CVE enrichment credentials"),
                ("NVD_API_KEY", "CVE enrichment credentials"),
                ("VULNERS_KEY_ROTATOR", "CVE enrichment credentials"),
                ("NVD_KEY_ROTATOR", "CVE enrichment credentials"),
            ],
        )

        # Docker mode is required
        if not is_docker_installed():
            print("[!][Nuclei] Docker not found. Please install Docker to use Nuclei scanner.")
            print("[!][Nuclei] Skipping nuclei scan.")
            return recon_data

        if not is_docker_running():
            print("[!][Nuclei] Docker daemon is not running. Start it with: sudo systemctl start docker")
            print("[!][Nuclei] Skipping nuclei scan.")
            return recon_data

        # Pull image if needed (will skip if already present)
        pull_nuclei_docker_image(NUCLEI_DOCKER_IMAGE)

        # Ensure templates volume exists and has templates
        if not ensure_templates_volume(NUCLEI_DOCKER_IMAGE, NUCLEI_AUTO_UPDATE_TEMPLATES):
            print("[!][Nuclei] Could not setup nuclei templates. Skipping scan.")
            return recon_data

        print(f"[*][Nuclei] Execution Mode: DOCKER ({NUCLEI_DOCKER_IMAGE})")
        nuclei_version = f"Docker: {NUCLEI_DOCKER_IMAGE}"
        template_count = 8000  # Approximate, Docker image includes templates

        print(f"[*][Nuclei] Nuclei Version: {nuclei_version}")
        print(f"[*][Nuclei] Templates Available: ~{template_count}")

        # Extract targets
        ips, hostnames, ip_to_hostnames = extract_targets_from_recon(recon_data)
    
        if not hostnames and not ips:
            print("[!][Nuclei] No targets found in recon data")
            return recon_data
    
        # Build target URLs using httpx/naabu data if available
        target_urls = build_target_urls(hostnames, ips, recon_data, scan_all_ips=NUCLEI_SCAN_ALL_IPS)

        # Initialize the per-scan AI context for the false-positive response
        # filter. Consumed by is_false_positive() in _execute_nuclei_pass().
        # Safe to call unconditionally -- when off, the cascade is a no-op.
        set_fp_ai_ctx(
            enabled=NUCLEI_AI_RESPONSE_FILTER,
            model=AI_PIPELINE_MODEL,
            user_id=os.environ.get('USER_ID', ''),
            project_id=os.environ.get('PROJECT_ID', ''),
        )
        if NUCLEI_AI_RESPONSE_FILTER:
            print(f"[*][Nuclei-FP-AI] Response filter cascade enabled, model={AI_PIPELINE_MODEL}")

        # AI tag pruning (cascade-gated; replaces NUCLEI_TAGS with a tech-aware
        # subset chosen by an LLM based on http_probe fingerprint). Applies to
        # the detection pass only; the DAST pass ignores tags by design.
        ai_tags_used = False
        if NUCLEI_AI_TAGS and NUCLEI_TAGS:
            from recon.helpers.ai_planner.nuclei_tags import get_ai_tags
            tech_fp = _build_tech_fingerprint(recon_data.get('http_probe', {}))
            fallback_urls = (
                target_urls if not tech_fp['technologies'] and not tech_fp['servers']
                else None
            )
            ai_tags = get_ai_tags(
                tech_fingerprint=tech_fp,
                current_tags=NUCLEI_TAGS,
                model=AI_PIPELINE_MODEL,
                user_id=os.environ.get('USER_ID', ''),
                project_id=os.environ.get('PROJECT_ID', ''),
                fallback_urls=fallback_urls,
            )
            if ai_tags != NUCLEI_TAGS:
                ai_tags_used = True
                print(f"[*][Nuclei-AI] Tag pruning: {len(NUCLEI_TAGS)} -> {len(ai_tags)} tags")
                print(f"[*][Nuclei-AI] Selected: {ai_tags}")
                NUCLEI_TAGS = ai_tags
            else:
                print(f"[*][Nuclei-AI] Falling back to user tags (no signal or LLM unavailable)")

        # For DAST mode, we need URLs with parameters from resource_enum
        dast_urls = []
        if NUCLEI_DAST_MODE:
            print(f"[*][Nuclei] DAST Mode: ENABLED (active fuzzing for XSS, SQLi, etc.)")

            # Get URLs with parameters from resource_enum (must be run before vuln_scan)
            resource_enum_data = recon_data.get("resource_enum")
            if resource_enum_data:
                discovered_urls = resource_enum_data.get("discovered_urls", [])
                # Filter for URLs with parameters
                dast_urls = [url for url in discovered_urls if '?' in url and '=' in url]
                if dast_urls:
                    print(f"[*][Nuclei] Using {len(dast_urls)} URLs with parameters from resource_enum")
                else:
                    print(f"[!][Nuclei] No URLs with parameters found in resource_enum - DAST scan may not find vulnerabilities")
            else:
                print(f"[!][Nuclei] resource_enum not found - run resource_enum before vuln_scan for DAST mode")
    
        # Break down what will actually be scanned (target_urls is the real list)
        ip_target_count = sum(1 for u in target_urls if _url_host_is_ip(u))
        host_target_count = len(target_urls) - ip_target_count
        print(f"[*][Nuclei] Hostnames discovered: {len(hostnames)} | IPs discovered: {len(ips)}")
        print(f"[*][Nuclei] Targets to scan: {len(target_urls)} URLs ({host_target_count} hostname-based, {ip_target_count} IP-based)")
        if NUCLEI_DAST_MODE and dast_urls:
            print(f"[*][Nuclei] DAST URLs (with params): {len(dast_urls)}")
        print(f"[*][Nuclei] Scan IPs: {'YES' if NUCLEI_SCAN_ALL_IPS else 'NO (hostnames only)'}")
        print(f"[*][Nuclei] Severity Filter: {', '.join(NUCLEI_SEVERITY) if NUCLEI_SEVERITY else 'ALL'}")
        print(f"[*][Nuclei] Rate Limit: {NUCLEI_RATE_LIMIT} req/s")
        print(f"[*][Nuclei] Bulk Size: {NUCLEI_BULK_SIZE}")
        print(f"[*][Nuclei] Concurrency: {NUCLEI_CONCURRENCY}")
        print(f"[*][Nuclei] Timeout: {NUCLEI_TIMEOUT}s")
        print(f"[*][Nuclei] Retries: {NUCLEI_RETRIES}")
        if NUCLEI_TAGS:
            print(f"[*][Nuclei] Tags: {', '.join(NUCLEI_TAGS)}")
        if NUCLEI_EXCLUDE_TAGS:
            print(f"[*][Nuclei] Exclude Tags: {', '.join(NUCLEI_EXCLUDE_TAGS)}")
        if NUCLEI_TEMPLATES:
            print(f"[*][Nuclei] Templates: {', '.join(NUCLEI_TEMPLATES)}")
        if NUCLEI_EXCLUDE_TEMPLATES:
            print(f"[*][Nuclei] Exclude Templates: {', '.join(NUCLEI_EXCLUDE_TEMPLATES)}")
        print(f"[*][Nuclei] Headless: {NUCLEI_HEADLESS}")
        print(f"[*][Nuclei] Interactsh: {NUCLEI_INTERACTSH}")
        print(f"[*][Nuclei] Follow Redirects: {NUCLEI_FOLLOW_REDIRECTS} (max {NUCLEI_MAX_REDIRECTS})")
        print(f"[*][Nuclei] New Templates Only: {NUCLEI_NEW_TEMPLATES_ONLY}")
        print(f"[*][Nuclei] Auto Update Templates: {NUCLEI_AUTO_UPDATE_TEMPLATES}")
        if NUCLEI_SELECTED_CUSTOM_TEMPLATES:
            print(f"[*][Nuclei] Custom Templates Selected: {len(NUCLEI_SELECTED_CUSTOM_TEMPLATES)}")
            for tpl in NUCLEI_SELECTED_CUSTOM_TEMPLATES:
                print(f"[*][Nuclei]   - {tpl}")
        # CVE lookup settings
        print(f"[*][Nuclei] CVE Lookup: {CVE_LOOKUP_ENABLED}")
        if CVE_LOOKUP_ENABLED:
            print(f"[*][Nuclei]   Source: {CVE_LOOKUP_SOURCE}")
            print(f"[*][Nuclei]   Max CVEs: {CVE_LOOKUP_MAX_CVES}")
            print(f"[*][Nuclei]   Min CVSS: {CVE_LOOKUP_MIN_CVSS}")
        # Security checks summary
        print(f"[*][Nuclei] Security Checks: {SECURITY_CHECK_ENABLED}")
        if SECURITY_CHECK_ENABLED:
            sec_checks_count = sum(1 for v in [
                SECURITY_CHECK_DIRECT_IP_HTTP, SECURITY_CHECK_DIRECT_IP_HTTPS,
                SECURITY_CHECK_IP_API_EXPOSED, SECURITY_CHECK_WAF_BYPASS,
                SECURITY_CHECK_TLS_EXPIRING_SOON, SECURITY_CHECK_MISSING_REFERRER_POLICY,
                SECURITY_CHECK_MISSING_PERMISSIONS_POLICY, SECURITY_CHECK_MISSING_COOP,
                SECURITY_CHECK_MISSING_CORP, SECURITY_CHECK_MISSING_COEP,
                SECURITY_CHECK_CACHE_CONTROL_MISSING, SECURITY_CHECK_LOGIN_NO_HTTPS,
                SECURITY_CHECK_SESSION_NO_SECURE, SECURITY_CHECK_SESSION_NO_HTTPONLY,
                SECURITY_CHECK_BASIC_AUTH_NO_TLS, SECURITY_CHECK_SPF_MISSING,
                SECURITY_CHECK_DMARC_MISSING, SECURITY_CHECK_DNSSEC_MISSING,
                SECURITY_CHECK_ZONE_TRANSFER, SECURITY_CHECK_ADMIN_PORT_EXPOSED,
                SECURITY_CHECK_DATABASE_EXPOSED, SECURITY_CHECK_REDIS_NO_AUTH,
                SECURITY_CHECK_KUBERNETES_API_EXPOSED, SECURITY_CHECK_SMTP_OPEN_RELAY,
                SECURITY_CHECK_CSP_UNSAFE_INLINE, SECURITY_CHECK_INSECURE_FORM_ACTION,
                SECURITY_CHECK_NO_RATE_LIMITING,
            ] if v)
            print(f"[*][Nuclei]   Active checks: {sec_checks_count}/27")
            print(f"[*][Nuclei]   Timeout: {SECURITY_CHECK_TIMEOUT}s")
            print(f"[*][Nuclei]   Max workers: {SECURITY_CHECK_MAX_WORKERS}")
        print("=" * 70 + "\n")
    
        # Create a temporary directory for nuclei files
        # Use /tmp/redamon to avoid spaces in paths (snap Docker issue)
        nuclei_temp_dir = Path("/tmp/redamon/.nuclei_temp")
        nuclei_temp_dir.mkdir(parents=True, exist_ok=True)
    
        # Two-pass design:
        #   Pass A (DETECTION) — always runs when Nuclei is enabled. Honours all
        #     user-configured templates, tags, custom templates. Targets the
        #     full base URL set.
        #   Pass B (DAST) — only when NUCLEI_DAST_MODE is on AND we have URLs
        #     with parameters from resource_enum. Forces -dast and ignores
        #     tags/templates filters (they would empty-intersect with the DAST
        #     template set). Targets the parameterized URLs only.
        do_dast_pass = NUCLEI_DAST_MODE and bool(dast_urls)
        if NUCLEI_DAST_MODE and not dast_urls:
            print(f"[!][Nuclei] DAST pass skipped (no parameterized URLs available); detection pass still runs")

        # Empty Include Tags now means "no built-in templates". The detection
        # pass only has something to scan if either tags is non-empty OR the
        # user picked custom templates. If both are empty, refuse before
        # building the command -- otherwise nuclei would fall back to scanning
        # all ~8000 default templates which is the OPPOSITE of what we want.
        has_tags = bool(NUCLEI_TAGS)
        has_custom = bool(NUCLEI_SELECTED_CUSTOM_TEMPLATES) or bool(NUCLEI_TEMPLATES) or bool(NUCLEI_CUSTOM_TEMPLATES)
        if not has_tags and not has_custom:
            print("[!][Nuclei] Include Tags is empty AND no custom templates are selected.")
            print("[!][Nuclei] Skipping detection pass (empty tags now means 'custom templates only').")
            print("[!][Nuclei] Either add tags (e.g. cve, xss, sqli) or select a custom template.")
            # If DAST has parameterized URLs we can still run the DAST pass --
            # DAST has its own template set and doesn't depend on tags.
            if not do_dast_pass:
                return recon_data
            # Mark detection as skipped; downstream merge handles empty findings.
            skip_detection_pass = True
        else:
            skip_detection_pass = False

        # Detection pass targets
        detection_targets_file = str(nuclei_temp_dir / "targets_detection.txt")
        with open(detection_targets_file, 'w') as f:
            for url in target_urls:
                f.write(url + "\n")
        detection_output_file = str(nuclei_temp_dir / "nuclei_detection.jsonl")

        # DAST pass targets (parameterized URLs only)
        dast_targets_file = None
        dast_output_file = None
        if do_dast_pass:
            dast_targets_file = str(nuclei_temp_dir / "targets_dast.txt")
            with open(dast_targets_file, 'w') as f:
                for url in dast_urls:
                    f.write(url + "\n")
            dast_output_file = str(nuclei_temp_dir / "nuclei_dast.jsonl")
            print(f"[*][Nuclei] Two-pass plan: DETECTION on {len(target_urls)} URLs + DAST on {len(dast_urls)} parameterized URLs")
        else:
            print(f"[*][Nuclei] Single-pass plan: DETECTION on {len(target_urls)} URLs")

        # scan_urls is the union for reporting/metadata
        scan_urls = sorted(set(target_urls + (dast_urls if do_dast_pass else [])))

        # Authenticated-session profile: attach the operator's auth headers to
        # nuclei when every scanned host is in scope (no-op otherwise). Nuclei
        # has no header support of its own, so these flow via the new
        # build_nuclei_command auth_headers arg.
        from urllib.parse import urlparse as _urlparse
        from recon.helpers.auth_profile import merge_auth_headers as _merge_auth
        _nuclei_hosts = sorted({_urlparse(u).hostname for u in scan_urls if _urlparse(u).hostname})
        _nuclei_auth = _merge_auth([], settings, _nuclei_hosts)

        try:
            findings = []
            false_positives_filtered = []

            # ---- Pass A: DETECTION ----
            start_time = datetime.now()
            d_duration = 0
            if skip_detection_pass:
                print("[*][Nuclei] DETECTION pass skipped (no tags + no custom templates)")
                d_findings, d_fps = [], []
            else:
                detection_cmd = build_nuclei_command(
                    targets_file=detection_targets_file,
                    output_file=detection_output_file,
                    docker_image=NUCLEI_DOCKER_IMAGE,
                    severity=NUCLEI_SEVERITY,
                    templates=NUCLEI_TEMPLATES,
                    exclude_templates=NUCLEI_EXCLUDE_TEMPLATES,
                    custom_templates=NUCLEI_CUSTOM_TEMPLATES,
                    selected_custom_templates=NUCLEI_SELECTED_CUSTOM_TEMPLATES,
                    tags=NUCLEI_TAGS,
                    exclude_tags=NUCLEI_EXCLUDE_TAGS,
                    rate_limit=NUCLEI_RATE_LIMIT,
                    bulk_size=NUCLEI_BULK_SIZE,
                    concurrency=NUCLEI_CONCURRENCY,
                    timeout=NUCLEI_TIMEOUT,
                    retries=NUCLEI_RETRIES,
                    dast_mode=False,
                    new_templates_only=NUCLEI_NEW_TEMPLATES_ONLY,
                    headless=NUCLEI_HEADLESS,
                    system_resolvers=NUCLEI_SYSTEM_RESOLVERS,
                    follow_redirects=NUCLEI_FOLLOW_REDIRECTS,
                    max_redirects=NUCLEI_MAX_REDIRECTS,
                    interactsh=NUCLEI_INTERACTSH,
                    auth_headers=_nuclei_auth,
                )
                d_findings, d_fps, d_duration, _ = _execute_nuclei_pass(
                    detection_cmd, detection_output_file, label="DETECTION"
                )
            findings.extend(d_findings)
            false_positives_filtered.extend(d_fps)

            # ---- Pass B: DAST (additive) ----
            dast_duration = 0
            if do_dast_pass:
                dast_cmd = build_nuclei_command(
                    targets_file=dast_targets_file,
                    output_file=dast_output_file,
                    docker_image=NUCLEI_DOCKER_IMAGE,
                    severity=NUCLEI_SEVERITY,
                    rate_limit=NUCLEI_RATE_LIMIT,
                    bulk_size=NUCLEI_BULK_SIZE,
                    concurrency=NUCLEI_CONCURRENCY,
                    timeout=NUCLEI_TIMEOUT,
                    retries=NUCLEI_RETRIES,
                    headless=NUCLEI_HEADLESS,
                    system_resolvers=NUCLEI_SYSTEM_RESOLVERS,
                    follow_redirects=NUCLEI_FOLLOW_REDIRECTS,
                    max_redirects=NUCLEI_MAX_REDIRECTS,
                    interactsh=NUCLEI_INTERACTSH,
                    force_dast_pass=True,
                    auth_headers=_nuclei_auth,
                )
                b_findings, b_fps, b_duration, _ = _execute_nuclei_pass(
                    dast_cmd, dast_output_file, label="DAST"
                )
                findings.extend(b_findings)
                false_positives_filtered.extend(b_fps)
                dast_duration = b_duration

            duration = d_duration + dast_duration

            # Log filtered false positives
            if false_positives_filtered:
                print(f"[*][Nuclei] Filtered {len(false_positives_filtered)} false positive(s):")
                for fp in false_positives_filtered[:5]:
                    print(f"[*][Nuclei]   - {fp['template_id']}: {fp['reason'][:60]}...")
                if len(false_positives_filtered) > 5:
                    print(f"[*][Nuclei]   ... and {len(false_positives_filtered) - 5} more")
        
            # Organize results
            nuclei_results = {
                "scan_metadata": {
                    "scan_timestamp": start_time.isoformat(),
                    "scan_duration_seconds": duration,
                    "nuclei_version": nuclei_version,
                    "templates_available": template_count,
                    "execution_mode": "docker",
                    "docker_image": NUCLEI_DOCKER_IMAGE,
                    "anonymous_mode": False,
                    "severity_filter": NUCLEI_SEVERITY,
                    "tags_filter": NUCLEI_TAGS,
                    "tags_ai_selected": ai_tags_used,
                    "exclude_tags": NUCLEI_EXCLUDE_TAGS,
                    "rate_limit": NUCLEI_RATE_LIMIT,
                    "dast_mode": NUCLEI_DAST_MODE,
                    "dast_pass_executed": do_dast_pass,
                    "dast_urls_discovered": len(dast_urls) if NUCLEI_DAST_MODE else 0,
                    "katana_crawl_depth": KATANA_DEPTH if NUCLEI_DAST_MODE else None,
                    "total_urls_scanned": len(scan_urls),
                    "total_hostnames": len(hostnames),
                    "total_ips": len(ips),
                    "false_positives_filtered": len(false_positives_filtered),
                },
                "discovered_urls": {
                    "base_urls": sorted(target_urls),
                    "dast_urls_with_params": sorted(dast_urls) if dast_urls else [],
                    "all_scanned_urls": sorted(scan_urls),
                },
                "by_target": {},
                "summary": {
                    "total_findings": len(findings),
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "unknown": 0,
                },
                "vulnerabilities": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "unknown": 0,
                },
                "all_cves": [],
                "by_category": {},
                "by_template": {},
                "false_positives": false_positives_filtered if false_positives_filtered else [],
            }
        
            # Process findings
            all_cves = []
        
            for finding in findings:
                severity = finding["severity"]
                target = finding["target"]
                template_id = finding["template_id"]
                category = finding["category"]
            
                # Count by severity
                if severity in nuclei_results["summary"]:
                    nuclei_results["summary"][severity] += 1
                else:
                    nuclei_results["summary"]["unknown"] += 1
            
                # Group by target
                if target not in nuclei_results["by_target"]:
                    nuclei_results["by_target"][target] = {
                        "findings": [],
                        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                    }
                nuclei_results["by_target"][target]["findings"].append(finding)
                if severity in nuclei_results["by_target"][target]["severity_counts"]:
                    nuclei_results["by_target"][target]["severity_counts"][severity] += 1
            
                # Add to severity-based vulnerability list
                finding_summary = {
                    "template_id": template_id,
                    "name": finding["name"],
                    "target": target,
                    "matched_at": finding["matched_at"],
                    "category": category,
                    "cves": [c["id"] for c in finding["cves"]],
                    "cvss": finding["cvss_score"],
                }
            
                if severity in nuclei_results["vulnerabilities"]:
                    nuclei_results["vulnerabilities"][severity] += 1
                else:
                    nuclei_results["vulnerabilities"]["unknown"] += 1
            
                # Collect CVEs
                all_cves.extend(finding["cves"])
            
                # Group by category
                if category not in nuclei_results["by_category"]:
                    nuclei_results["by_category"][category] = []
                nuclei_results["by_category"][category].append(finding_summary)
            
                # Group by template
                if template_id not in nuclei_results["by_template"]:
                    nuclei_results["by_template"][template_id] = {
                        "name": finding["name"],
                        "severity": severity,
                        "findings_count": 0,
                        "targets": []
                    }
                nuclei_results["by_template"][template_id]["findings_count"] += 1
                if target not in nuclei_results["by_template"][template_id]["targets"]:
                    nuclei_results["by_template"][template_id]["targets"].append(target)
        
            # Deduplicate and sort CVEs
            seen_cves = set()
            unique_cves = []
            for cve in all_cves:
                if cve["id"] not in seen_cves:
                    seen_cves.add(cve["id"])
                    unique_cves.append(cve)
            unique_cves.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
            nuclei_results["all_cves"] = unique_cves
        
            # Add to recon data
            recon_data["vuln_scan"] = nuclei_results
        
            # Save incrementally if output file provided
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(recon_data, f, indent=2)
                fix_file_ownership(output_file)  # Ensure correct ownership when running under sudo
        
            # Print summary
            print(f"\n{'=' * 70}")
            print(f"[+][Nuclei] NUCLEI SCAN COMPLETE")
            print(f"[+][Nuclei] Duration: {duration:.2f} seconds")
            print(f"[+][Nuclei] Execution mode: DOCKER")
            if do_dast_pass:
                print(f"[+][Nuclei] URLs scanned: {len(target_urls)} (detection) + {len(dast_urls)} (DAST)")
            else:
                print(f"[+][Nuclei] URLs scanned: {len(target_urls)}")
            print(f"[+][Nuclei] Total findings: {len(findings)}")
        
            # Vulnerability summary
            summary = nuclei_results["summary"]
            vuln_total = summary["total_findings"]

            if vuln_total > 0:
                print(f"\n[+][Nuclei] VULNERABILITY SUMMARY:")
                if summary['critical'] > 0:
                    print(f"[+][Nuclei]   CRITICAL: {summary['critical']}")
                if summary['high'] > 0:
                    print(f"[+][Nuclei]   HIGH: {summary['high']}")
                if summary['medium'] > 0:
                    print(f"[+][Nuclei]   MEDIUM: {summary['medium']}")
                if summary['low'] > 0:
                    print(f"[+][Nuclei]   LOW: {summary['low']}")

            if summary['info'] > 0:
                print(f"[*][Nuclei]   INFO: {summary['info']}")
        
            # CVE summary
            cve_count = len(unique_cves)
            if cve_count > 0:
                print(f"\n[+][Nuclei] CVEs FOUND: {cve_count}")
                for cve in unique_cves[:5]:
                    cvss_str = f"CVSS {cve['cvss']}" if cve.get('cvss') else "CVSS N/A"
                    print(f"[+][Nuclei]   - {cve['id']} ({cvss_str})")
                if cve_count > 5:
                    print(f"[+][Nuclei]   ... and {cve_count - 5} more")
        
            # Top affected targets
            if nuclei_results["by_target"]:
                print(f"\n[+][Nuclei] FINDINGS BY TARGET:")
                sorted_targets = sorted(
                    nuclei_results["by_target"].items(),
                    key=lambda x: len(x[1]["findings"]),
                    reverse=True
                )[:5]
                for target, data in sorted_targets:
                    counts = data["severity_counts"]
                    count_str = ", ".join([
                        f"{SEVERITY_COLORS.get(s, '')}{counts[s]}" 
                        for s in ["critical", "high", "medium", "low", "info"] 
                        if counts.get(s, 0) > 0
                    ])
                    print(f"[+][Nuclei]   - {target[:50]}: {len(data['findings'])} findings ({count_str})")
        
            # Top categories
            if nuclei_results["by_category"]:
                print(f"\n[+][Nuclei] TOP VULNERABILITY CATEGORIES:")
                sorted_cats = sorted(
                    nuclei_results["by_category"].items(),
                    key=lambda x: len(x[1]),
                    reverse=True
                )[:5]
                for cat, findings_list in sorted_cats:
                    print(f"[+][Nuclei]   - {cat}: {len(findings_list)} findings")
        
            print(f"{'=' * 70}")

        finally:
            # Cleanup temporary files and directory.
            # Docker may create output files as root, so fall back to a docker-based
            # rm when a PermissionError is raised.
            cleanup_paths = [
                detection_targets_file,
                detection_output_file,
                dast_targets_file,
                dast_output_file,
            ]
            for path_str in cleanup_paths:
                if not path_str:
                    continue
                try:
                    Path(path_str).unlink(missing_ok=True)
                except PermissionError:
                    subprocess.run(
                        ["docker", "run", "--rm", "-v", f"{nuclei_temp_dir}:/cleanup",
                         "alpine", "rm", "-f", f"/cleanup/{Path(path_str).name}"],
                        capture_output=True,
                    )

            try:
                nuclei_temp_dir.rmdir()  # Only removes if empty
            except Exception:
                pass

    # Run CVE lookup for detected technologies (like Nmap's vulners)
    if CVE_LOOKUP_ENABLED and recon_data.get("http_probe"):
        cve_results = run_cve_lookup(
            recon_data=recon_data,
            enabled=CVE_LOOKUP_ENABLED,
            source=CVE_LOOKUP_SOURCE,
            max_cves=CVE_LOOKUP_MAX_CVES,
            min_cvss=CVE_LOOKUP_MIN_CVSS,
            vulners_api_key=VULNERS_API_KEY,
            nvd_api_key=NVD_API_KEY,
            nvd_key_rotator=NVD_KEY_ROTATOR,
            vulners_key_rotator=VULNERS_KEY_ROTATOR,
        )
        recon_data.update(cve_results)

        # Save with CVE data
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2)
            fix_file_ownership(output_file)

    # Run custom security checks (Direct IP Access, TLS/SSL, Security Headers)
    # Skip entirely if global switch is disabled
    if not SECURITY_CHECK_ENABLED:
        print(f"\n[-][Nuclei] Custom security checks disabled (SECURITY_CHECK_ENABLED=False)")
    else:
        security_checks_enabled = {
            # Direct IP Access checks (unique - not covered by Nuclei)
            "direct_ip_http": SECURITY_CHECK_DIRECT_IP_HTTP,
            "direct_ip_https": SECURITY_CHECK_DIRECT_IP_HTTPS,
            "ip_api_exposed": SECURITY_CHECK_IP_API_EXPOSED,
            "waf_bypass": SECURITY_CHECK_WAF_BYPASS,
            # TLS/SSL checks
            "tls_expiring_soon": SECURITY_CHECK_TLS_EXPIRING_SOON,
            # TLS-hygiene checks derived from tlsx/httpx certificate data
            "tls_expired": settings.get('SECURITY_CHECK_TLS_EXPIRED', True),
            "tls_self_signed": settings.get('SECURITY_CHECK_TLS_SELF_SIGNED', True),
            "tls_hostname_mismatch": settings.get('SECURITY_CHECK_TLS_HOSTNAME_MISMATCH', True),
            "tls_weak_version": settings.get('SECURITY_CHECK_TLS_WEAK_VERSION', True),
            "tls_weak_cipher": settings.get('SECURITY_CHECK_TLS_WEAK_CIPHER', True),
            "tls_wildcard_overbroad": settings.get('SECURITY_CHECK_TLS_WILDCARD_OVERBROAD', True),
            # Security Headers checks (only headers not covered by Nuclei)
            "missing_referrer_policy": SECURITY_CHECK_MISSING_REFERRER_POLICY,
            "missing_permissions_policy": SECURITY_CHECK_MISSING_PERMISSIONS_POLICY,
            "missing_coop": SECURITY_CHECK_MISSING_COOP,
            "missing_corp": SECURITY_CHECK_MISSING_CORP,
            "missing_coep": SECURITY_CHECK_MISSING_COEP,
            "cache_control_missing": SECURITY_CHECK_CACHE_CONTROL_MISSING,
            # Authentication security checks
            "login_no_https": SECURITY_CHECK_LOGIN_NO_HTTPS,
            "session_no_secure": SECURITY_CHECK_SESSION_NO_SECURE,
            "session_no_httponly": SECURITY_CHECK_SESSION_NO_HTTPONLY,
            "basic_auth_no_tls": SECURITY_CHECK_BASIC_AUTH_NO_TLS,
            # DNS security checks
            "spf_missing": SECURITY_CHECK_SPF_MISSING,
            "dmarc_missing": SECURITY_CHECK_DMARC_MISSING,
            "dnssec_missing": SECURITY_CHECK_DNSSEC_MISSING,
            "zone_transfer": SECURITY_CHECK_ZONE_TRANSFER,
            # Port/Service security checks
            "admin_port_exposed": SECURITY_CHECK_ADMIN_PORT_EXPOSED,
            "database_exposed": SECURITY_CHECK_DATABASE_EXPOSED,
            "redis_no_auth": SECURITY_CHECK_REDIS_NO_AUTH,
            "kubernetes_api_exposed": SECURITY_CHECK_KUBERNETES_API_EXPOSED,
            "smtp_open_relay": SECURITY_CHECK_SMTP_OPEN_RELAY,
            # Application security checks
            "csp_unsafe_inline": SECURITY_CHECK_CSP_UNSAFE_INLINE,
            "insecure_form_action": SECURITY_CHECK_INSECURE_FORM_ACTION,
            # Rate limiting checks
            "no_rate_limiting": SECURITY_CHECK_NO_RATE_LIMITING,
        }

        # Only run if at least one check is enabled
        if any(security_checks_enabled.values()):
            security_results = run_security_checks(
                recon_data=recon_data,
                enabled_checks=security_checks_enabled,
                timeout=SECURITY_CHECK_TIMEOUT,
                tls_expiry_days=SECURITY_CHECK_TLS_EXPIRY_DAYS,
                max_workers=SECURITY_CHECK_MAX_WORKERS,
                ai_classifier_enabled=WAF_AI_CLASSIFIER,
                ai_model=AI_PIPELINE_MODEL,
                ai_user_id=os.environ.get('USER_ID', ''),
                ai_project_id=os.environ.get('PROJECT_ID', ''),
            )

            # Merge security checks into vuln_scan results
            if "vuln_scan" in recon_data:
                recon_data["vuln_scan"]["security_checks"] = security_results.get("security_checks", {})
            else:
                recon_data["vuln_scan"] = {"security_checks": security_results.get("security_checks", {})}

            # Save with security check data
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(recon_data, f, indent=2)
                fix_file_ownership(output_file)

    return recon_data


def enrich_recon_file(recon_file: Path) -> dict:
    """
    Load a recon JSON file, enrich it with nuclei data, and save it back.

    Args:
        recon_file: Path to the recon JSON file

    Returns:
        Enriched recon data
    """
    # Load settings for standalone usage
    from recon.project_settings import get_settings
    settings = get_settings()

    # Load existing data
    with open(recon_file, 'r') as f:
        recon_data = json.load(f)

    # Run nuclei scan
    enriched_data = run_vuln_scan(recon_data, output_file=recon_file, settings=settings)

    # Save enriched data
    with open(recon_file, 'w') as f:
        json.dump(enriched_data, f, indent=2)

    print(f"[+][Nuclei] Enriched data saved to: {recon_file}")

    return enriched_data



def run_vuln_scan_isolated(combined_result: dict, settings: dict) -> dict:
    """
    Thread-safe isolated wrapper for Nuclei vuln scanning.

    Deep-copies combined_result, runs the scan on the copy (without incremental
    file saves), and returns only the resulting vuln_scan dict. Used by Group 6
    Phase A fan-out in main.py so Nuclei and GraphQL can run concurrently
    without racing on shared state.
    """
    snapshot = copy.deepcopy(combined_result)
    # output_file=None => skip the function's own incremental saves (main.py
    # persists the merged result after the fan-out completes).
    run_vuln_scan(snapshot, output_file=None, settings=settings)
    return snapshot.get("vuln_scan", {})
