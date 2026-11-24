"""SSRF guard for user-supplied custom LLM ``baseUrl`` values.

A custom OpenAI-compatible / Anthropic provider lets the operator point the
agent at a self-hosted model (Ollama, LM Studio, an internal gateway). Those
live on ``localhost`` / LAN, so the guard must *preserve* private and loopback
targets. What it rejects is the narrow set that is never a legitimate model
endpoint and that turns the key-holding agent container into an SSRF probe:

  * non-``http(s)`` schemes (``file://``, ``gopher://`` ...);
  * cloud metadata / link-local addresses (AWS/GCP/Azure ``169.254.169.254``,
    AWS ECS ``169.254.170.2``, Alibaba ``100.100.100.200``, AWS IPv6 IMDS
    ``fd00:ec2::254``, and the ``metadata.google.internal`` host);
  * disabling TLS verification (``sslVerify=false``) for a *public* host: the
    self-signed use case is internal-only, and turning verification off on a
    public connection that carries ``Authorization: Bearer <key>`` + the prompt
    is the I16 MITM exposure;
  * the per-user Kali sandbox pool (``SUBNET_POOL``, 10.214.0.0/16): the agent
    sits on every person's sandbox network, where ngrok's API (4040) and the
    reverse-shell listener check nothing, so a baseUrl there would hand one
    person another person's sandbox. No model is ever served from it.

The check of the configured host is advisory: a redirect, or a name that
resolves elsewhere by the time the client connects (rebinding), would pass it.
So the model clients built for a custom baseUrl, and the HTTP clients of MCP
servers a user adds, follow no redirect and judge the peer address of every
connection they open (``llm_guarded_clients``, ``pool_guarded_async_transport``),
resolving off the event loop.

This addresses STRIDE threats I15 (baseUrl SSRF) and I16 (TLS-off MITM) without
breaking the self-hosted-model feature. See
``internal/security/README.TM.STRIDE.md``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Callable, Optional, Tuple
from urllib.parse import urlparse

import httpcore
import httpx

import sandbox_contract


class BaseUrlValidationError(ValueError):
    """Raised when a custom LLM ``baseUrl`` is rejected by the SSRF guard."""


# Addresses that are never a legitimate LLM endpoint. Link-local (169.254/16,
# fe80::/10) is caught generically below; these are the extra metadata hosts
# that fall outside the link-local range.
_BLOCKED_IPS = frozenset({
    "169.254.169.254",  # AWS / GCP / Azure IMDS (also link-local)
    "169.254.170.2",    # AWS ECS task metadata (also link-local)
    "100.100.100.200",  # Alibaba Cloud metadata (CGNAT 100.64/10, not private)
    "fd00:ec2::254",    # AWS IPv6 IMDS (unique-local, not link-local)
})

_BLOCKED_HOSTNAMES = frozenset({
    "metadata.google.internal",
    "metadata.goog",
})

# Normalized objects so non-canonical IPv6 spellings (e.g. fd00:ec2:0::254)
# still match the blocklist rather than slipping through a string compare.
_BLOCKED_IP_OBJS = frozenset(ipaddress.ip_address(x) for x in _BLOCKED_IPS)

_SANDBOX_POOL = ipaddress.ip_network(sandbox_contract.SUBNET_POOL)


def _resolve_ips(host: str) -> list[str]:
    """Resolve ``host`` to all A/AAAA addresses. Empty list on failure.

    A literal IP returns itself. An unresolvable host returns ``[]``: it cannot
    be an SSRF into metadata, so the caller treats that as allowed.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        out.append(addr.split("%")[0])  # strip IPv6 scope id
    return out


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # IPv4-mapped IPv6 (::ffff:169.254.169.254) must be judged on the v4 value.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in _BLOCKED_IP_OBJS:
        return True
    # Link-local covers 169.254.0.0/16 (IMDS) and fe80::/10.
    return ip.is_link_local


def _in_sandbox_pool(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip in _SANDBOX_POOL


def _is_public_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


def validate_llm_base_url(base_url: str | None, *, ssl_verify: bool = True) -> None:
    """Validate a custom LLM ``baseUrl``; raise ``BaseUrlValidationError`` if unsafe.

    No-ops on an empty value (the provider falls back to its built-in default).
    Localhost / private / Docker-service / unresolvable hosts are allowed so the
    self-hosted-model feature keeps working.
    """
    if not base_url or not base_url.strip():
        return

    parsed = urlparse(base_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise BaseUrlValidationError(
            f"Custom LLM baseUrl must use http or https (got '{scheme or 'no scheme'}')."
        )

    host = parsed.hostname
    if not host:
        raise BaseUrlValidationError("Custom LLM baseUrl has no host.")

    if host.lower().rstrip(".") in _BLOCKED_HOSTNAMES:
        raise BaseUrlValidationError(
            "Custom LLM baseUrl points at a cloud metadata host, which is not allowed."
        )

    resolved = _resolve_ips(host)
    for ip in resolved:
        if _is_blocked_ip(ip):
            raise BaseUrlValidationError(
                f"Custom LLM baseUrl resolves to a blocked address ({ip}); "
                "cloud metadata and link-local endpoints are not allowed."
            )
        if _in_sandbox_pool(ip):
            raise BaseUrlValidationError(
                f"Custom LLM baseUrl resolves to a Kali sandbox address ({ip}); "
                "the sandbox network is not a model endpoint."
            )

    if not ssl_verify and any(_is_public_ip(ip) for ip in resolved):
        raise BaseUrlValidationError(
            "TLS verification cannot be disabled (sslVerify=false) for a public "
            "LLM endpoint; it is only permitted for private/internal hosts."
        )


# =============================================================================
# Connect-time guard: every connection's peer is judged, not the configured host
# =============================================================================

class OutboundAddressRefused(ConnectionError):
    """A connection whose resolved peer the guard refuses. Not an httpcore error, so
    httpx raises it unmapped and a caller can tell "refused" from "network failed"."""


Refusal = Callable[[str], Optional[str]]


def sandbox_pool_refusal(ip: str) -> Optional[str]:
    """Why a connection to ``ip`` is refused, for an MCP server a user adds: the sandbox
    pool only."""
    return "a Kali sandbox address" if _in_sandbox_pool(ip) else None


def llm_endpoint_refusal(ip: str) -> Optional[str]:
    """Why a connection to ``ip`` is refused, for a custom model endpoint: the pool, and
    the metadata and link-local addresses the baseUrl check refuses."""
    if _in_sandbox_pool(ip):
        return "a Kali sandbox address"
    if _is_blocked_ip(ip):
        return "a cloud metadata or link-local address"
    return None


def _judged_addresses(host: str, refuse: Refusal, connect_error) -> list:
    if refuse is llm_endpoint_refusal and host.lower().rstrip(".") in _BLOCKED_HOSTNAMES:
        raise OutboundAddressRefused(f"refusing to connect to {host}: a cloud metadata host")
    ips = list(dict.fromkeys(_resolve_ips(host)))
    if not ips:
        raise connect_error(f"could not resolve {host}")
    for ip in ips:
        reason = refuse(ip)
        if reason:
            raise OutboundAddressRefused(f"refusing to connect to {host}: it resolves to {reason} ({ip})")
    return ips


def _guarded_backends(core):
    """The async and sync network backends that resolve (the async one in a thread, never
    on the event loop), judge and dial in one step, for every TCP connection: the
    rebinding window closes, and each redirect hop opens its own connection here. TLS
    still verifies the original hostname (httpcore takes SNI from the request origin, not
    from the address dialled). `core` is httpcore, or httpcore2 for the clients of the
    model SDKs built on httpx2."""

    class _GuardedAsyncBackend(core.AsyncNetworkBackend):
        def __init__(self, inner, refuse: Refusal) -> None:
            self._inner = inner
            self._refuse = refuse

        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            try:
                ips = await asyncio.wait_for(
                    asyncio.to_thread(_judged_addresses, host, self._refuse, core.ConnectError),
                    timeout=timeout)
            except asyncio.TimeoutError:
                raise core.ConnectTimeout(f"resolving {host} timed out") from None
            last_error: Exception = core.ConnectError(f"could not connect to {host}")
            for ip in ips:
                try:
                    return await self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                                         socket_options=socket_options)
                except core.ConnectError as exc:
                    last_error = exc
            raise last_error

        async def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise OutboundAddressRefused("refusing to connect to a unix socket")

        async def sleep(self, seconds):
            await self._inner.sleep(seconds)

    class _GuardedSyncBackend(core.NetworkBackend):
        def __init__(self, inner, refuse: Refusal) -> None:
            self._inner = inner
            self._refuse = refuse

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            last_error: Exception = core.ConnectError(f"could not connect to {host}")
            for ip in _judged_addresses(host, self._refuse, core.ConnectError):
                try:
                    return self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                                   socket_options=socket_options)
                except core.ConnectError as exc:
                    last_error = exc
            raise last_error

        def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise OutboundAddressRefused("refusing to connect to a unix socket")

        def sleep(self, seconds):
            self._inner.sleep(seconds)

    return _GuardedAsyncBackend, _GuardedSyncBackend


_BACKENDS = {}


def _guard(transport, core, asynchronous: bool, refuse: Refusal):
    """httpx has no public hook for the network backend, so this wraps the one the
    connection pool dials with; a future httpcore that renames it raises here instead of
    handing back an unguarded transport."""
    if core.__name__ not in _BACKENDS:
        _BACKENDS[core.__name__] = _guarded_backends(core)
    guarded_async, guarded_sync = _BACKENDS[core.__name__]
    base = core.AsyncNetworkBackend if asynchronous else core.NetworkBackend
    pool = transport._pool
    if not isinstance(getattr(pool, "_network_backend", None), base):
        raise RuntimeError("httpcore pool has no _network_backend; cannot guard egress")
    pool._network_backend = (guarded_async if asynchronous else guarded_sync)(pool._network_backend, refuse)
    return transport


def pool_guarded_async_transport(*, verify: bool = True,
                                 refuse: Refusal = sandbox_pool_refusal) -> httpx.AsyncHTTPTransport:
    return _guard(httpx.AsyncHTTPTransport(verify=verify), httpcore, True, refuse)


def _sdk_http():
    """(httpx, httpcore) as the model SDKs use them: httpx2 where it is installed (the
    Anthropic SDK accepts only its clients; the OpenAI SDK accepts either)."""
    try:
        import httpcore2
        import httpx2
        return httpx2, httpcore2
    except ImportError:
        return httpx, httpcore


def llm_guarded_clients(*, verify: bool = True):
    """The HTTP clients (sync, async) of a model on a custom baseUrl: no redirect followed,
    and every connection's peer judged (``llm_endpoint_refusal``). The model SDK applies
    its own timeout to each request."""
    hx, core = _sdk_http()
    sync = hx.Client(transport=_guard(hx.HTTPTransport(verify=verify), core, False, llm_endpoint_refusal),
                     follow_redirects=False)
    async_ = hx.AsyncClient(
        transport=_guard(hx.AsyncHTTPTransport(verify=verify), core, True, llm_endpoint_refusal),
        follow_redirects=False)
    return sync, async_
