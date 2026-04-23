"""
RedAmon - Resource Enumeration Helpers
======================================

This package contains helper functions for resource enumeration:

- form_helpers: HTML form parsing and extraction
- classification: Parameter and endpoint classification
- gau_helpers: GAU passive URL discovery from web archives
- kiterunner_helpers: Kiterunner API endpoint bruteforcing
- katana_helpers: Katana active web crawling
- endpoint_helpers: Endpoint organization and structuring
"""

# Form parsing
from .form_helpers import (
    FormParser,
    parse_forms_from_html,
)

# Classification
from .classification import (
    PARAM_PATTERNS,
    classify_parameter,
    infer_parameter_type,
    classify_endpoint,
)

# GAU helpers
from .gau_helpers import (
    pull_gau_docker_image,
    filter_gau_url,
    run_gau_for_domain,
    run_gau_discovery,
    parse_gau_url_to_endpoint,
    verify_gau_urls,
    detect_gau_methods,
    merge_gau_into_by_base_url,
)

# Kiterunner helpers
from .kiterunner_helpers import (
    ensure_kiterunner_binary,
    run_kiterunner_discovery,
    merge_kiterunner_into_by_base_url,
    detect_kiterunner_methods,
)

# Katana helpers
from .katana_helpers import (
    run_katana_crawler,
    fetch_forms_from_urls,
    pull_katana_docker_image,
)

# Hakrawler helpers
from .hakrawler_helpers import (
    run_hakrawler_crawler,
    pull_hakrawler_docker_image,
    merge_hakrawler_into_by_base_url,
)

# jsluice helpers
from .jsluice_helpers import (
    run_jsluice_analysis,
    merge_jsluice_into_by_base_url,
)

# FFuf helpers
from .ffuf_helpers import (
    run_ffuf_discovery,
    pull_ffuf_binary_check,
    merge_ffuf_into_by_base_url,
)

# Arjun helpers
from .arjun_helpers import (
    arjun_binary_check,
    run_arjun_discovery,
    merge_arjun_into_by_base_url,
)

# ParamSpider helpers
from .paramspider_helpers import (
    run_paramspider_discovery,
    merge_paramspider_into_by_base_url,
)

# Endpoint organization
from .endpoint_helpers import (
    organize_endpoints,
)

__all__ = [
    # Form parsing
    "FormParser",
    "parse_forms_from_html",
    # Classification
    "PARAM_PATTERNS",
    "classify_parameter",
    "infer_parameter_type",
    "classify_endpoint",
    # GAU
    "pull_gau_docker_image",
    "filter_gau_url",
    "run_gau_for_domain",
    "run_gau_discovery",
    "parse_gau_url_to_endpoint",
    "verify_gau_urls",
    "detect_gau_methods",
    "merge_gau_into_by_base_url",
    # Kiterunner
    "ensure_kiterunner_binary",
    "run_kiterunner_discovery",
    "merge_kiterunner_into_by_base_url",
    "detect_kiterunner_methods",
    # Katana
    "run_katana_crawler",
    "fetch_forms_from_urls",
    "pull_katana_docker_image",
    # Hakrawler
    "run_hakrawler_crawler",
    "pull_hakrawler_docker_image",
    "merge_hakrawler_into_by_base_url",
    # jsluice
    "run_jsluice_analysis",
    "merge_jsluice_into_by_base_url",
    # FFuf
    "run_ffuf_discovery",
    "pull_ffuf_binary_check",
    "merge_ffuf_into_by_base_url",
    # Arjun
    "arjun_binary_check",
    "run_arjun_discovery",
    "merge_arjun_into_by_base_url",
    # ParamSpider
    "run_paramspider_discovery",
    "merge_paramspider_into_by_base_url",
    # Endpoint organization
    "organize_endpoints",
]
