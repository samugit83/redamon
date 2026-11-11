"""
Hop-by-hop fetch for URLs a target controls (STRIDE I14, R-14)
================================================================
A URL taken from a target's JavaScript (a source map, a bundle, an endpoint)
may answer with a redirect to anywhere: cloud metadata, an internal host, a
third party, a host the Rules of Engagement exclude. requests' own redirect
following checks none of that, so it is never used here: every hop, the first
URL included, is checked before it is sent with ``allow_redirects=False``.
"""

import ipaddress
import socket
from typing import Callable, Mapping, Optional
from urllib.parse import urljoin, urlparse

import requests

try:
    from recon.main_recon_modules.ip_filter import is_url_safe_to_probe
except ImportError:  # spawned-container path where CWD is on sys.path
    from ip_filter import is_url_safe_to_probe
from recon.helpers import request_pacer
from recon.helpers.target_admission import admission_context, admit_targets

MAX_REDIRECTS = 5
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Refusal reasons; a caller may store them as outcome tokens ([a-z_]).
UNSAFE = 'unsafe'
ROE_EXCLUDED = 'roe_excluded'
OUT_OF_SCOPE = 'out_of_scope'
NOT_ADMITTED = 'not_admitted'
TOO_MANY_REDIRECTS = 'too_many_redirects'

# Dropped on a hop to another host, as requests' own redirect handling does,
# so a probe's credentials never reach a host they were not written for.
_CREDENTIAL_HEADERS = frozenset({'authorization', 'proxy-authorization', 'cookie'})

# requests.<method> by name, looked up per call, as the per-module fetches this
# replaces called requests.get / requests.head.
_REQUESTS_METHODS = frozenset({'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'})

# The coverage module RoE refusals are noted under (target_admission).
_ADMISSION_MODULE = 'js_recon'


def admit_any(url: str) -> bool:
    return True


def url_host(url) -> str:
    """Comparable host of a URL: lower case, no trailing dot, an IP in its
    canonical spelling; '' when there is none."""
    try:
        host = (urlparse(url).hostname or '') if isinstance(url, str) else ''
    except ValueError:
        return ''
    host = host.rstrip('.').lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


def roe_refuses(url: str, settings: Optional[Mapping], module: str = _ADMISSION_MODULE) -> bool:
    """True when the Rules of Engagement exclude ``url``'s host: the name, or,
    with IP or CIDR entries, any address it resolves to (a name that does not
    resolve is refused then, as D2's gate does). Inert without an exclusion.
    ``module`` names the caller in the refusal's log line and coverage note."""
    context = admission_context(settings)
    if not context.active:
        return False
    host = url_host(url)
    if _is_ip(host):
        return host not in admit_targets(settings, ips=[host], module=module).ips
    addresses = _resolve(host) if context.ip_rules else []
    admission = admit_targets(settings, names={host: addresses}, module=module,
                              resolves_names=True)
    return host not in admission.names


def hop_refusal(url: str, *, settings: Optional[Mapping] = None,
                in_scope: Optional[Callable[[str], bool]] = None,
                admit: Callable[[str], bool] = admit_any,
                url_guard: Optional[Callable[[str], bool]] = None,
                module: str = _ADMISSION_MODULE) -> Optional[str]:
    """Why ``url`` may not be requested, or None. The checks of
    ``fetch_hop_by_hop``, in its order; a check that raises refuses. ``module``
    is the caller an RoE refusal is logged and noted under."""
    try:
        scheme = urlparse(url).scheme.lower()
    except (TypeError, ValueError):
        return UNSAFE
    if scheme not in ('http', 'https') or not url_host(url):
        return UNSAFE
    guard = url_guard or is_url_safe_to_probe
    checks = (
        (ROE_EXCLUDED, lambda: not roe_refuses(url, settings, module)),
        (OUT_OF_SCOPE, lambda: in_scope is None or in_scope(url)),
        (NOT_ADMITTED, lambda: admit(url)),
        (UNSAFE, lambda: guard(url)),
    )
    for reason, passes in checks:
        try:
            if not passes():
                return reason
        except Exception:  # noqa: BLE001 - a guard that fails refuses (fail closed)
            return reason
    return None


def fetch_hop_by_hop(method: str, url: str, *, timeout: float,
                     headers: Optional[Mapping[str, str]] = None,
                     settings: Optional[Mapping] = None,
                     in_scope: Optional[Callable[[str], bool]] = None,
                     admit: Callable[[str], bool] = admit_any,
                     url_guard: Optional[Callable[[str], bool]] = None,
                     max_redirects: int = MAX_REDIRECTS,
                     refusal: Optional[dict] = None,
                     send: Optional[Callable[..., requests.Response]] = None,
                     verify: bool = False) -> Optional[requests.Response]:
    """Send ``method`` to ``url`` and follow its redirects by hand, checking
    every hop, the first URL included, before it is sent. The first check a
    hop fails names the refusal:

    - ``unsafe``: not an http(s) URL with a host;
    - ``roe_excluded``: ``settings``' Rules of Engagement (``ROE_ENABLED``,
      ``ROE_EXCLUDED_HOSTS``) exclude the host, or with IP/CIDR entries an
      address it resolves to (``target_admission.admit_targets``, which logs
      and notes the refusal once);
    - ``out_of_scope``: ``in_scope(url)`` is false (the run's scope; None
      skips the check);
    - ``not_admitted``: ``admit(url)`` is false (the caller's own rule, e.g.
      IP mode; admits everything by default);
    - ``unsafe``: ``url_guard(url)`` is false (the SSRF guard;
      ``is_url_safe_to_probe`` by default).

    A check that raises refuses the hop. Returns the first answer that is not
    a redirect to follow (a 3xx with no Location is such an answer), or None
    when a hop is refused or more than ``max_redirects`` redirects come; then
    ``refusal``, when given, receives ``reason`` (above, or
    ``too_many_redirects``), ``url`` (the refused hop) and ``hop`` (0 for
    ``url`` itself). A connection error raises, as requests does.

    Every hop is sent with ``allow_redirects=False``: through
    ``send(method, url, *, timeout, headers, allow_redirects)`` when given (it
    owns TLS verification), else through requests with ``verify`` (False: a
    target's self-signed or internal-CA certificate is accepted, as httpx and
    katana accept it). Each hop that is sent, whoever sends it, first takes a
    slot of the process-wide RoE pacer (``request_pacer``, inert with no
    ceiling); a refused hop takes none, and a 429 backs off every in-process
    requester. A 303 turns the method into GET (HEAD stays HEAD); credential
    headers are dropped on a hop to another host.
    """
    method = method.upper()
    current = url
    headers = dict(headers or {})
    for hop in range(max_redirects + 1):
        reason = hop_refusal(current, settings=settings, in_scope=in_scope, admit=admit,
                             url_guard=url_guard)
        if reason:
            if refusal is not None:
                refusal.update(reason=reason, url=current, hop=hop)
            return None
        request_pacer.acquire()
        resp = _send(send, method, current, timeout=timeout, headers=headers, verify=verify)
        request_pacer.back_off_on_429(resp)
        location = _redirect_location(resp)
        if location is None:
            return resp
        target = urljoin(current, location)
        if url_host(target) != url_host(current):
            headers = {k: v for k, v in headers.items() if k.lower() not in _CREDENTIAL_HEADERS}
        if resp.status_code == 303 and method != 'HEAD':
            method = 'GET'
        current = target
    if refusal is not None:
        refusal.update(reason=TOO_MANY_REDIRECTS, url=current, hop=max_redirects + 1)
    return None


def _send(send, method: str, url: str, *, timeout, headers, verify) -> requests.Response:
    if send is not None:
        return send(method, url, timeout=timeout, headers=headers, allow_redirects=False)
    kwargs = dict(timeout=timeout, headers=headers, allow_redirects=False, verify=verify)
    if method in _REQUESTS_METHODS:
        return getattr(requests, method.lower())(url, **kwargs)
    return requests.request(method, url, **kwargs)


def _redirect_location(resp) -> Optional[str]:
    if getattr(resp, 'status_code', None) not in REDIRECT_STATUSES:
        return None
    headers = getattr(resp, 'headers', None) or {}
    location = headers.get('Location') or headers.get('location')
    return location if isinstance(location, str) and location.strip() else None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _resolve(host: str) -> list:
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return []
    return sorted({info[4][0].split('%')[0] for info in infos})
