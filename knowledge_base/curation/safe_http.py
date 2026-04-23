import json as _json
import logging
import httpx
from dataclasses import dataclass
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Hosts KB clients are allowed to talk to. Update this when adding a new
# data source. Each entry is matched as an exact hostname (case-insensitive).
#
#   - services.nvd.nist.gov         NVD REST API v2
#   - github.com                    Initial URL for repo tarballs
#   - codeload.github.com           Where github.com/…/archive/… redirects
#   - raw.githubusercontent.com     Raw file fetches (e.g. custom clients)
#   - objects.githubusercontent.com Where some GitHub downloads redirect
#   - gitlab.com                    ExploitDB raw CSV
DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = (
    "services.nvd.nist.gov",
    "github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "gitlab.com",
)

# Hard ceiling on a single downloaded response body
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MB

# Per-source caps
MAX_TARBALL_BYTES = 200 * 1024 * 1024      # tarball downloads (nuclei is ~35 MB)
MAX_EXPLOITDB_CSV_BYTES = 200 * 1024 * 1024  # exploitdb CSV (~50 MB today)
MAX_NVD_PAGE_BYTES = 50 * 1024 * 1024       # single NVD API page (~5-10 MB today)

# Max redirects per request. GitHub tarball URLs typically do exactly
# one hop (github.com → codeload.github.com). Five gives headroom for
# chained CDN redirects without letting a malicious upstream loop.
MAX_REDIRECTS = 5

# Streaming chunk size while reading the body.
_READ_CHUNK_SIZE = 64 * 1024


class UntrustedHostError(ValueError):
    """Raised when a URL or redirect targets a host not on the allowlist."""


class ResponseTooLargeError(ValueError):
    """Raised when a downloaded response exceeds ``max_bytes``."""


class SafeHTTPStatusError(RuntimeError):
    """
    Raised by ``SafeResponse.raise_for_status()`` on a non-2xx response.

    Mimics httpx.HTTPStatusError's role without requiring callers to
    import httpx just for the exception type.
    """

    def __init__(self, status_code: int, url: str):
        super().__init__(f"HTTP {status_code} for {url}")
        self.status_code = status_code
        self.url = url


@dataclass
class SafeResponse:
    """
    Minimal response object returned by ``safe_get``.

    Provides the subset of httpx.Response that KB clients use today.
    Keeping this an in-house type (rather than a real httpx.Response)
    avoids any chance of leaking a streaming transport handle across
    the safe_get boundary and forces all clients through the
    hostname-validated path.
    """

    status_code: int
    content: bytes
    headers: dict
    url: str

    @property
    def text(self) -> str:
        """Decoded response body (UTF-8 with replacement on errors)."""
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """Parse the response body as JSON."""
        return _json.loads(self.content)

    def raise_for_status(self) -> None:
        """Raise ``SafeHTTPStatusError`` on a non-2xx status."""
        if self.status_code >= 400:
            raise SafeHTTPStatusError(self.status_code, self.url)


def _host_allowed(hostname: Optional[str], allowed: Iterable[str]) -> bool:
    """Case-insensitive exact-match hostname check."""
    if not hostname:
        return False
    hostname = hostname.lower()
    return any(hostname == allowed_host.lower() for allowed_host in allowed)


def _assert_safe(url: str, allowed: Iterable[str]) -> None:
    """Raise UntrustedHostError unless ``url`` is an http(s) URL with an
    allowlisted hostname."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UntrustedHostError(
            f"Refusing non-http(s) URL: {url!r} (scheme={parsed.scheme!r})"
        )
    if not _host_allowed(parsed.hostname, allowed):
        raise UntrustedHostError(
            f"Refusing request to host {parsed.hostname!r} — not on allowlist. "
            f"(Add it to DEFAULT_ALLOWED_HOSTS or pass allowed_hosts=.)"
        )


def safe_get(
    url: str,
    *,
    allowed_hosts: Iterable[str] = DEFAULT_ALLOWED_HOSTS,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    timeout: float = 60.0,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
) -> SafeResponse:
    """
    Perform a hostname-allowlisted, size-capped HTTP GET.

    Redirects are followed manually, with each hop's target host validated
    against ``allowed_hosts`` *before* any request is sent. A redirect to
    an off-allowlist host (or to a non-http(s) scheme) raises
    ``UntrustedHostError``. A body larger than ``max_bytes`` raises
    ``ResponseTooLargeError`` either via Content-Length pre-check or
    during streaming.

    Args:
        url: Absolute URL to fetch.
        allowed_hosts: Iterable of allowed hostnames. Exact match,
            case-insensitive. Defaults to ``DEFAULT_ALLOWED_HOSTS``.
        max_bytes: Hard cap on the downloaded body in bytes. Defaults
            to ``MAX_DOWNLOAD_BYTES`` (200 MB).
        timeout: Per-request timeout in seconds.
        headers: Optional request headers. Sensitive headers (like
            ``apiKey``) stay in-process — the caller is responsible for
            not logging the response object.
        params: Query parameters. Only applied to the initial request,
            not to redirect targets.

    Returns:
        SafeResponse with the fully-read body.

    Raises:
        UntrustedHostError: URL or a redirect target is not allowlisted,
            uses a non-http(s) scheme, has too many hops, or is missing
            a Location header on a redirect.
        ResponseTooLargeError: Body exceeded ``max_bytes``.
        httpx.HTTPError: Underlying transport errors propagate.
    """

    allowed = tuple(allowed_hosts)
    _assert_safe(url, allowed)

    current_url = url
    current_params = params
    hops = 0

    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        while True:
            req = client.build_request(
                "GET",
                current_url,
                headers=headers or {},
                params=current_params,
            )
            resp = client.send(req, stream=True)
            try:
                if resp.is_redirect:
                    if hops >= MAX_REDIRECTS:
                        raise UntrustedHostError(
                            f"Refusing: more than {MAX_REDIRECTS} redirects "
                            f"for {url!r}"
                        )
                    location = resp.headers.get("location", "")
                    if not location:
                        raise UntrustedHostError(
                            f"Refusing redirect without Location header "
                            f"(from {current_url!r})"
                        )
                    next_url = str(httpx.URL(current_url).join(location))
                    _assert_safe(next_url, allowed)
                    logger.debug(
                        f"safe_get: redirect hop {hops + 1}: "
                        f"{urlparse(current_url).hostname} → "
                        f"{urlparse(next_url).hostname}"
                    )
                    current_url = next_url
                    # Query params only apply to the first request; the
                    # redirect target's Location header already encodes
                    # whatever params the server wants preserved.
                    current_params = None
                    hops += 1
                    continue

                # Non-redirect: enforce size cap on the body.
                cl_hdr = resp.headers.get("content-length")
                if cl_hdr is not None:
                    try:
                        cl = int(cl_hdr)
                    except ValueError:
                        cl = None
                    if cl is not None and cl > max_bytes:
                        raise ResponseTooLargeError(
                            f"{current_url!r}: Content-Length {cl} exceeds "
                            f"cap {max_bytes}"
                        )

                buf = bytearray()
                for chunk in resp.iter_bytes(chunk_size=_READ_CHUNK_SIZE):
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise ResponseTooLargeError(
                            f"{current_url!r}: body exceeded cap {max_bytes} "
                            f"while streaming"
                        )

                return SafeResponse(
                    status_code=resp.status_code,
                    content=bytes(buf),
                    headers=dict(resp.headers),
                    url=str(resp.url),
                )
            finally:
                resp.close()
