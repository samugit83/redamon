"""Serializable target scope shared by OpenAPI discovery and graph ingestion."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
import re
from typing import Any
from urllib.parse import urlsplit


def _normalize_host(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        if parsed.username is not None or parsed.password is not None:
            return ""
        host = parsed.hostname
    except (TypeError, ValueError):
        return ""
    if not host:
        return ""
    host = host.rstrip(".").lower()
    try:
        return str(ip_address(host))
    except ValueError:
        pass
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _normalize_scope_host(value: Any) -> str:
    """Normalize a host token without accepting URL or host:port syntax."""
    if not isinstance(value, str) or not value.strip():
        return ""
    candidate = value.strip()
    if any(marker in candidate for marker in ("/", "?", "#", "@", "://")):
        return ""
    try:
        return str(ip_address(candidate))
    except ValueError:
        pass
    if ":" in candidate:
        return ""
    candidate = candidate.rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(candidate) > 253:
        return ""
    labels = candidate.split(".")
    if not labels or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        return ""
    return candidate


class Scope:
    """Fail-closed OpenAPI target scope with a stable JSON payload shape."""

    def __init__(
        self,
        *,
        root: str = "",
        hosts=(),
        include_subdomains: bool = False,
        include_root: bool = False,
        ip_networks=(),
        excluded_hosts=(),
        _valid: bool = True,
    ):
        self.root = root
        self.hosts = tuple(hosts)
        self.include_subdomains = include_subdomains
        self.include_root = include_root
        self.ip_networks = tuple(ip_networks)
        self.excluded_hosts = tuple(excluded_hosts)
        self._valid = _valid and bool(root or self.ip_networks)

    @classmethod
    def from_payload(cls, payload: Any) -> "Scope":
        required = {
            "root", "hosts", "include_subdomains", "include_root",
            "ip_networks", "excluded_hosts",
        }
        if not isinstance(payload, dict) or not required.issubset(payload):
            return cls(_valid=False)
        if not isinstance(payload["root"], str):
            return cls(_valid=False)
        if not isinstance(payload["include_subdomains"], bool):
            return cls(_valid=False)
        if not isinstance(payload["include_root"], bool):
            return cls(_valid=False)
        if not all(isinstance(payload[name], list) for name in (
            "hosts", "ip_networks", "excluded_hosts",
        )):
            return cls(_valid=False)

        root = _normalize_scope_host(payload["root"]) if payload["root"] else ""
        if payload["root"] and not root:
            return cls(_valid=False)

        hosts = []
        for value in payload["hosts"]:
            host = _normalize_scope_host(value)
            if not host:
                return cls(_valid=False)
            hosts.append(host)

        networks = []
        for value in payload["ip_networks"]:
            if not isinstance(value, str):
                return cls(_valid=False)
            try:
                networks.append(ip_network(value, strict=False))
            except ValueError:
                return cls(_valid=False)

        if root and networks:
            return cls(_valid=False)
        if not root and (payload["include_subdomains"] or payload["include_root"]):
            return cls(_valid=False)
        for host in hosts:
            if root:
                try:
                    ip_address(host)
                    return cls(_valid=False)
                except ValueError:
                    pass
                if host == root:
                    if not payload["include_root"]:
                        return cls(_valid=False)
                elif not host.endswith(f".{root}"):
                    return cls(_valid=False)
                continue
            try:
                address = ip_address(host)
            except ValueError:
                return cls(_valid=False)
            if not any(address in network for network in networks):
                return cls(_valid=False)

        exclusions = []
        for value in payload["excluded_hosts"]:
            if not isinstance(value, str):
                return cls(_valid=False)
            try:
                exclusions.append(ip_network(value, strict=False))
                continue
            except ValueError:
                pass
            host = _normalize_scope_host(value)
            if not host:
                return cls(_valid=False)
            exclusions.append(host)

        return cls(
            root=root,
            hosts=sorted(set(hosts)),
            include_subdomains=payload["include_subdomains"],
            include_root=payload["include_root"],
            ip_networks=sorted(set(networks), key=lambda item: (item.version, str(item))),
            excluded_hosts=sorted(
                set(exclusions), key=lambda item: (0 if isinstance(item, str) else item.version, str(item))
            ),
        )

    @property
    def is_valid(self) -> bool:
        return self._valid

    def to_payload(self) -> dict:
        if not self._valid:
            return {
                "root": "",
                "hosts": [],
                "include_subdomains": False,
                "include_root": False,
                "ip_networks": [],
                "excluded_hosts": [],
            }
        return {
            "root": self.root,
            "hosts": list(self.hosts),
            "include_subdomains": self.include_subdomains,
            "include_root": self.include_root,
            "ip_networks": [str(network) for network in self.ip_networks],
            "excluded_hosts": [str(value) for value in self.excluded_hosts],
        }

    def allows(self, url: str) -> bool:
        if not self._valid or not isinstance(url, str):
            return False
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
                return False
            if parsed.username is not None or parsed.password is not None:
                return False
            host = _normalize_host(url)
        except (TypeError, ValueError):
            return False
        if not host:
            return False

        try:
            address = ip_address(host)
        except ValueError:
            address = None

        for excluded in self.excluded_hosts:
            if isinstance(excluded, str):
                if host == excluded or host.endswith(f".{excluded}"):
                    return False
            elif address is not None and address in excluded:
                return False

        if host in self.hosts:
            return True
        if address is not None:
            return any(address in network for network in self.ip_networks)
        if not self.root:
            return False
        if host == self.root:
            return self.include_root
        return self.include_subdomains and host.endswith(f".{self.root}")
