"""The scan's own DNS resolver, for the ProjectDiscovery tools it runs.

httpx, katana, tlsx and naabu resolve through ProjectDiscovery's dialer,
whose built-in list includes public resolvers. A name only the local DNS
knows (an internal or split-horizon target; a lab's private zone) then
fails at random, and the host drops out of that tool's run without a word
(found by the urlscan lab: the same input gave httpx 4, 2 and 3 URLs,
katana 8, 9 and 6 results). The recon container shares the host network,
so its resolv.conf names the resolver the DNS step itself used.
"""
from __future__ import annotations

from typing import List


def system_resolvers(resolv_conf: str = "/etc/resolv.conf") -> List[str]:
    """Every nameserver of resolv.conf, once, in order; [] when unreadable."""
    try:
        with open(resolv_conf, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    found: List[str] = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] not in found:
            found.append(parts[1])
    return found


def resolver_args(flag: str = "-r") -> List[str]:
    """``[flag, "a,b"]`` for a tool command, or [] when no resolver is known
    (the tool then keeps its own list)."""
    found = system_resolvers()
    return [flag, ",".join(found)] if found else []
