"""
RedAmon - IP-mode placeholder names
===================================
An IP-mode run gives every target address a dashed label (``203.0.113.2`` ->
``203-0-113-2``, ``2001:db8::1`` -> ``2001-db8--1``) so the graph has a
Subdomain to hang the address off. The label is not a hostname: it has no DNS
record, so a tool handed it as a name probes nothing (or, for the crawlers,
silently throws away every real seed beside it). Every reader that must tell a
label from a real name asks here.
"""

import ipaddress
from typing import Optional


def placeholder_for(ip: str) -> str:
    """The label for ``ip``, spelled from the address as the run listed it."""
    return str(ip).strip().replace(".", "-").replace(":", "-")


def is_placeholder(name, ip: Optional[str] = None) -> bool:
    """True when ``name`` is a placeholder label, not a hostname.

    With ``ip``: only that address's own label. Without: any label that maps
    back to an address. A real name has a dot or is not an address once the
    dashes are undone, so ``mail-01.example.com`` or ``1-2-3`` never match.
    """
    if not isinstance(name, str):
        return False
    candidate = name.strip().lower()
    if not candidate:
        return False
    if ip is not None:
        return candidate == placeholder_for(ip).lower()
    if "." in candidate or "-" not in candidate:
        return False
    for separator in (".", ":"):
        try:
            ipaddress.ip_address(candidate.replace("-", separator))
            return True
        except ValueError:
            continue
    return False
