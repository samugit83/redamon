"""
RedAmon - Vulnerability Scan Helpers
=====================================

This package contains helper functions organized by category:

- docker_helpers: Docker utilities (container management, image pulls, permissions)
- target_helpers: Target extraction and URL building from recon data
- nuclei_helpers: Nuclei command building, output parsing, false positive detection
- katana_helpers: Katana web crawler for URL discovery
- cve_helpers: CVE lookup from NVD and Vulners APIs
- security_checks: Custom security checks (direct IP access, TLS, headers, etc.)
"""

# Docker utilities
from .docker_helpers import (
    is_docker_installed,
    is_docker_running,
    get_real_user_ids,
    fix_file_ownership,
    pull_nuclei_docker_image,
    pull_katana_docker_image,
    ensure_templates_volume,
    is_tor_running,
    NUCLEI_TEMPLATES_VOLUME,
)

# Target extraction and URL building
from .target_helpers import (
    extract_targets_from_recon,
    build_target_urls_from_httpx,
    build_target_urls_from_resource_enum,
    build_target_urls,
)

# Nuclei-specific helpers
from .nuclei_helpers import (
    build_nuclei_command,
    parse_nuclei_finding,
    is_false_positive,
)

# Katana web crawler
from .katana_helpers import (
    run_katana_crawler,
)

# CVE lookup
from .cve_helpers import (
    split_server_header,
    parse_technology_string,
    normalize_product_name,
    classify_cvss_score,
    lookup_cves_nvd,
    lookup_cves_vulners,
    run_cve_lookup,
    CPE_MAPPINGS,
    NVD_API_URL,
    VULNERS_API_URL,
)

# Security checks
from .security_checks import (
    run_security_checks,
)

# Subdomain takeover helpers
from .takeover_helpers import (
    build_subjack_command,
    build_baddns_command,
    normalize_subjack_result,
    normalize_nuclei_takeover,
    normalize_baddns_finding,
    dedupe_findings,
    score_finding,
    finding_id,
    provider_from_cname,
    provider_from_signal,
    AUTO_EXPLOITABLE_PROVIDERS,
    PROVIDER_FROM_SIGNAL,
    BADDNS_MODULES,
    BADDNS_DEFAULT_MODULES,
)

# Anonymity/Tor utilities
from .anonymity import (
    is_tor_running as is_tor_running_anonymity,
    is_proxychains_available,
    get_proxychains_cmd,
    get_tor_session,
    get_tor_exit_ip,
    check_tor_connection,
    print_anonymity_status,
    run_through_tor,
    run_command_anonymous,
    get_real_ip,
    require_tor,
    TorProxy,
)

__all__ = [
    # Docker
    "is_docker_installed",
    "is_docker_running",
    "get_real_user_ids",
    "fix_file_ownership",
    "pull_nuclei_docker_image",
    "pull_katana_docker_image",
    "ensure_templates_volume",
    "is_tor_running",
    "NUCLEI_TEMPLATES_VOLUME",
    # Targets
    "extract_targets_from_recon",
    "build_target_urls_from_httpx",
    "build_target_urls_from_resource_enum",
    "build_target_urls",
    # Nuclei
    "build_nuclei_command",
    "parse_nuclei_finding",
    "is_false_positive",
    # Katana
    "run_katana_crawler",
    # CVE
    "split_server_header",
    "parse_technology_string",
    "normalize_product_name",
    "classify_cvss_score",
    "lookup_cves_nvd",
    "lookup_cves_vulners",
    "run_cve_lookup",
    "CPE_MAPPINGS",
    "NVD_API_URL",
    "VULNERS_API_URL",
    # Security checks
    "run_security_checks",
    # Takeover
    "build_subjack_command",
    "build_baddns_command",
    "normalize_subjack_result",
    "normalize_nuclei_takeover",
    "normalize_baddns_finding",
    "dedupe_findings",
    "score_finding",
    "finding_id",
    "provider_from_cname",
    "provider_from_signal",
    "AUTO_EXPLOITABLE_PROVIDERS",
    "PROVIDER_FROM_SIGNAL",
    "BADDNS_MODULES",
    "BADDNS_DEFAULT_MODULES",
    # Anonymity/Tor
    "is_tor_running_anonymity",
    "is_proxychains_available",
    "get_proxychains_cmd",
    "get_tor_session",
    "get_tor_exit_ip",
    "check_tor_connection",
    "print_anonymity_status",
    "run_through_tor",
    "run_command_anonymous",
    "get_real_ip",
    "require_tor",
    "TorProxy",
]

