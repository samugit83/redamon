"""Which IP:port pairs this run's active port scan looked at, for passive data.

Shodan and the other passive sources report ports from their own past crawls,
weeks old at times. Whether a port they name is open NOW is known only when
this run's port scan looked at that exact IP and port: found open is open,
looked at and not found is closed, and anything the scan did not look at is
unknown, never closed.

What a scan looked at comes from what it recorded (`scan_metadata`): the
custom port list it ran, or "top-N", and for a naabu run cut by its timeout
the targets it never reached. naabu's and masscan's top-100/1000 lists
are their own and are not shipped here, so a top-N scan can confirm an open
port but never call one closed; "top-full" is every port. naabu's passive
mode reads InternetDB rather than scanning, so it confirms nothing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

ALL_TCP_PORTS = frozenset(range(1, 65536))

_RANGE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def parse_port_spec(spec) -> Optional[frozenset]:
    """The TCP ports a naabu or masscan `-p` list names, or None when unsure.

    "22,80,443", ranges ("8000-8100"), "-" for every port, and `t:`/`u:`
    prefixes; UDP entries are left out, as both scans are TCP here.
    """
    if not isinstance(spec, str) or not spec.strip():
        return None
    if spec.strip() == "-":
        return ALL_TCP_PORTS
    ports: set[int] = set()
    for raw in spec.split(","):
        token = raw.strip().lower()
        if token.startswith("u:"):
            continue
        if token.startswith("t:"):
            token = token[2:]
        match = _RANGE.match(token)
        if not match:
            return None
        low = int(match.group(1))
        high = int(match.group(2) or low)
        if low > high or high > 65535:
            return None
        ports.update(range(max(low, 1), high + 1))
    return frozenset(ports)


def ports_from_config(config) -> Optional[frozenset]:
    """The TCP ports a scan's recorded `ports_config` covered, or None when unsure."""
    if not isinstance(config, str):
        return None
    if config.lower().startswith("top-"):
        return ALL_TCP_PORTS if config[4:].strip().lower() == "full" else None
    return parse_port_spec(config)


@dataclass(frozen=True)
class _Scan:
    ips: frozenset
    ports: Optional[frozenset]
    open_ports: dict

    def covered(self, ip: str, port: int) -> bool:
        return self.ports is not None and ip in self.ips and port in self.ports


def _open_by_ip(section: dict) -> dict:
    out = {}
    for ip, info in ((section or {}).get("by_ip") or {}).items():
        ports = (info or {}).get("ports") if isinstance(info, dict) else None
        out[ip] = {int(p) for p in (ports or []) if str(p).isdigit()}
    return out


def _scans(combined_result: dict, settings: dict) -> list[_Scan]:
    from recon.helpers import extract_targets_from_recon
    from recon.main_recon_modules.ip_filter import collect_cdn_ips
    from recon.main_recon_modules.masscan_scan import resolve_targets_to_ips

    scans = []
    port_scan = combined_result.get("port_scan") or {}
    meta = port_scan.get("scan_metadata") or {}
    masscan_only = meta.get("scanner") == "masscan"

    if port_scan and not masscan_only and not meta.get("passive_mode"):
        ips = set(extract_targets_from_recon(combined_result, settings)[0])
        if meta.get("cdn_exclusion"):
            # naabu -exclude-cdn probes a CDN IP on 80 and 443 only.
            ips -= collect_cdn_ips(combined_result)
        if meta.get("timed_out"):
            # A naabu run cut by its timeout (R-9) did not reach the targets it
            # lists as unchecked; without that list, none counts as looked at.
            unchecked = meta.get("unchecked_targets")
            ips = ips - set(unchecked) if isinstance(unchecked, list) else set()
        scans.append(_Scan(frozenset(ips), ports_from_config(meta.get("ports_config")),
                           _open_by_ip(port_scan)))

    masscan = combined_result.get("masscan_scan") or (port_scan if masscan_only else {})
    if masscan:
        mmeta = masscan.get("scan_metadata") or {}
        # An exclusion list leaves IPs unprobed that this cannot tell apart.
        ports = (None if (settings or {}).get("MASSCAN_EXCLUDE_TARGETS")
                 else ports_from_config(mmeta.get("ports_config")))
        scans.append(_Scan(frozenset(resolve_targets_to_ips(combined_result, settings)[0]), ports,
                           _open_by_ip(masscan)))
    return scans


def port_scan_coverage(combined_result: dict,
                       settings: dict | None = None) -> Callable[[str, int], Optional[bool]]:
    """`covers(ip, port)`: True found open, False looked at and not open, None unknown."""
    scans = _scans(combined_result, settings or {})

    def covers(ip: str, port: int) -> Optional[bool]:
        if any(port in scan.open_ports.get(ip, ()) for scan in scans):
            return True
        if any(scan.covered(ip, port) for scan in scans):
            return False
        return None

    return covers
