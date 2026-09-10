"""
RedAmon - Rules of Engagement scope helpers
============================================
Excluded-host matching for the RoE governor. Extracted from ``recon.main`` so
active scanners (e.g. origin_discovery) can enforce the excluded-hosts list
without importing ``recon.main`` (which pulls the whole pipeline). ``recon.main``
re-exports these names, so ``from main import _is_roe_excluded`` still resolves.
"""

import ipaddress


def _is_roe_excluded(host: str, excluded_list: list) -> bool:
    """Check if a host (IP or domain) matches any RoE exclusion entry.

    Supports:
    - Exact IP/domain match: "10.0.0.5" matches "10.0.0.5"
    - CIDR match: "10.0.0.5" matches "10.0.0.0/24"
    - Subdomain match: "payments.example.com" matches "payments.example.com"
    """
    for entry in excluded_list:
        entry = entry.strip()
        if not entry:
            continue
        # Exact string match (works for both IPs and domains)
        if host == entry:
            return True
        # CIDR match: check if host IP falls within an excluded network
        if '/' in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                try:
                    if ipaddress.ip_address(host) in network:
                        return True
                except ValueError:
                    pass  # host is a domain, not an IP — skip CIDR check
            except ValueError:
                pass  # invalid CIDR in exclusion list
        # Domain suffix match: "payments.example.com" should be excluded
        # if the exclusion is a parent domain pattern
        elif host.endswith('.' + entry):
            return True
    return False


def _filter_roe_excluded(hosts: list, settings: dict, label: str = "host") -> list:
    """Filter a list of hosts/IPs against ROE_EXCLUDED_HOSTS. Returns the filtered list."""
    roe_excluded = settings.get('ROE_EXCLUDED_HOSTS', [])
    if not settings.get('ROE_ENABLED', False) or not roe_excluded:
        return hosts
    before_count = len(hosts)
    filtered = [h for h in hosts if not _is_roe_excluded(h, roe_excluded)]
    removed = before_count - len(filtered)
    if removed:
        print(f"[RoE] Excluded {removed} {label}(s) per Rules of Engagement")
    return filtered
