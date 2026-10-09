"""
RedAmon - Rules of Engagement scope helpers
============================================
Excluded-host matching for the RoE governor. Extracted from ``recon.main`` so
active scanners (e.g. origin_discovery) can enforce the excluded-hosts list
without importing ``recon.main`` (which pulls the whole pipeline). ``recon.main``
re-exports these names, so ``from main import _is_roe_excluded`` still resolves.
"""

from recon_settings.scope import _is_roe_excluded


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
