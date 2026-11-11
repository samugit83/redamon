"""S4: the request engine of the route exposure scan.

Every request goes through one ``Prober``: the SSRF/scope guard, the RoE
exclusion, the host breaker, the stop flag, the scan's own process-wide pacer
and then the RoE ceiling's (recon/helpers/request_pacer.py, shared by every
in-process requester), a capped streamed body read and the capture routing.
Sessions never keep a cookie, so an anonymous request can never carry a
session a logged-in answer set.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from http.cookiejar import DefaultCookiePolicy
from typing import Callable, Optional
from urllib.parse import urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from recon.helpers import catchall
from recon.helpers import request_pacer

try:
    from recon.helpers.user_agent import DEFAULT_BROWSER_UA
except ImportError:  # pragma: no cover - spawned-container import shim
    from helpers.user_agent import DEFAULT_BROWSER_UA

# Every request is unverified (the recon convention: self-signed internal hosts,
# and the capture proxy's own CA); without this each one prints a warning naming
# the host, which floods the drawer and leaks targets into the phase parser.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_BODY_BYTES = 256 * 1024
RANGE_BYTES = 1024
_CHUNK = 16 * 1024
_RETRY_AFTER_MAX_S = 30.0

#: Profiles whose logged-in requests may go through the capture proxy: the
#: ingest masks Authorization and Cookie, but not an arbitrary header name.
_CAPTURE_SAFE_AUTH_TYPES = frozenset({"bearer", "basic", "cookie"})


# ---------------------------------------------------------------------------
# Pacer: one clock for the process, shared by every worker and every group
# ---------------------------------------------------------------------------

class _Pacer:
    """A locked request clock. ``wait`` reserves the next slot under the lock and
    sleeps outside it, so N workers together never exceed the rate."""

    def __init__(self, rps: float, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = self._clock()
            at = max(now, self._next)
            self._next = at + self.interval
        delay = at - now
        if delay > 0:
            self._sleep(delay)

    def back_off(self, seconds: float) -> None:
        """A 429 pushes every worker's next slot back, not only the caller's."""
        with self._lock:
            self._next = max(self._next, self._clock() + max(0.0, seconds))


_PACER: Optional[_Pacer] = None
_PACER_LOCK = threading.Lock()


def _pacer_for(rps: float) -> _Pacer:
    """The process-wide pacer: a Domain batch's groups run in sequence in one
    process, and the rate must not reset between them."""
    global _PACER
    with _PACER_LOCK:
        if _PACER is None:
            _PACER = _Pacer(rps)
        return _PACER


def _reset_pacer(pacer: Optional[_Pacer] = None) -> None:
    """Tests only: drop (or replace) the process-wide pacer."""
    global _PACER
    with _PACER_LOCK:
        _PACER = pacer


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------

@dataclass
class Answer:
    """A requests-like answer whose body was read up to a cap, then dropped."""
    url: str
    method: str
    status_code: Optional[int] = None
    headers: dict = field(default_factory=dict)
    content: bytes = b""
    truncated: bool = False
    error: str = ""
    with_auth: bool = False
    range_read: bool = False

    @property
    def ok(self) -> bool:
        return self.status_code is not None

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class _PacedRetry(Retry):
    """A retry is one more request: it waits for the same slots as the first try."""

    def __init__(self, *args, pace: Optional[Callable[[], None]] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.pace = pace or request_pacer.acquire

    def new(self, **kw) -> "_PacedRetry":
        kw.setdefault("pace", self.pace)
        return super().new(**kw)

    def sleep(self, response=None) -> None:
        super().sleep(response)
        self.pace()


def _session(pace: Optional[Callable[[], None]] = None) -> requests.Session:
    """One per worker thread (Sessions are not thread-safe).

    No status retries: a real debug page answers 500 and must be read once,
    and a 429 is paced by ``_Pacer.back_off`` rather than retried behind its
    back. One connect retry only, before any byte reached the server; it
    takes its slots through ``pace`` like the first try.
    """
    retry = _PacedRetry(total=1, connect=1, read=0, status=0, redirect=0, other=0,
                        allowed_methods=frozenset(["GET", "HEAD"]), raise_on_status=False,
                        pace=pace)
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=4)
    session = requests.Session()
    session.trust_env = False
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
    return session


def _read_capped(response, limit: int) -> tuple[bytes, bool]:
    chunks, size = [], 0
    for chunk in response.iter_content(chunk_size=_CHUNK):
        if not chunk:
            continue
        room = limit - size
        if len(chunk) >= room:
            chunks.append(chunk[:room])
            return b"".join(chunks), True
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks), False


def _retry_after(headers: dict) -> float:
    raw = headers.get("retry-after", "")
    try:
        return min(_RETRY_AFTER_MAX_S, max(1.0, float(raw)))
    except (TypeError, ValueError):
        return 1.0


# ---------------------------------------------------------------------------
# The prober
# ---------------------------------------------------------------------------

class Prober:
    """Sends the scan's requests. Thread-safe; never raises from ``send``."""

    def __init__(self, settings: dict, *, guard: Callable[[str], bool], timeout: float,
                 rps: float, breaker_scope=None, roe_excluded=(), pacer: Optional[_Pacer] = None,
                 transport: Optional[Callable] = None):
        self.settings = settings or {}
        self.guard = guard
        self.timeout = timeout
        self.pacer = pacer or _pacer_for(rps)
        self.scope = breaker_scope
        self.roe_excluded = tuple(roe_excluded or ())
        self._transport = transport
        self._local = threading.local()
        self._lock = threading.Lock()
        self._auth_cache: dict = {}
        self.sent = 0
        self.sent_with_auth = 0
        self.refused = 0
        self._controls: dict = {}
        self._profile = _profile(self.settings)

    # -- auth ----------------------------------------------------------------

    def auth_headers(self, url: str) -> dict:
        """The profile's headers for this URL's host, or {} when none apply
        (no profile, host out of the auth scope, or RoE-excluded)."""
        if not self._profile:
            return {}
        host = (urlsplit(url).hostname or "").lower()
        with self._lock:
            if host in self._auth_cache:
                return dict(self._auth_cache[host])
        headers = _auth_headers_for(url, self.settings)
        with self._lock:
            self._auth_cache[host] = dict(headers)
        return headers

    def capture_allowed(self, with_auth: bool) -> bool:
        """Anonymous requests are always eligible; logged-in ones only when every
        value they carry is one the capture ingest masks."""
        if not with_auth:
            return True
        profile = self._profile or {}
        auth_type = str(profile.get("authType") or "").lower()
        return auth_type in _CAPTURE_SAFE_AUTH_TYPES and not profile.get("extraHeaders")

    # -- sending -------------------------------------------------------------

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = self._local.session = _session(self._pace)
        return session

    def _pace(self) -> None:
        """Both clocks before every request: the scan's own rate, then the RoE
        ceiling every in-process requester shares (inert with no ceiling)."""
        self.pacer.wait()
        request_pacer.acquire()

    def _routing(self, with_auth: bool) -> tuple[dict, str]:
        if not self.capture_allowed(with_auth):
            return {}, ""
        try:
            from helpers import proxy_routing
            proxy_url, token = proxy_routing.get_capture_routing("route_exposure")
        except Exception:  # noqa: BLE001 - capture is fail-open
            return {}, ""
        if proxy_url and token:
            return {"http": proxy_url, "https": proxy_url}, token
        return {}, ""

    def send(self, method: str, url: str, *, auth: Optional[dict] = None,
             headers: Optional[dict] = None, range_bytes: Optional[int] = None,
             max_bytes: int = MAX_BODY_BYTES) -> Optional[Answer]:
        """One request, or None when it was never sent (stop, guard, host down)."""
        if _stop_requested():
            return None
        try:
            allowed = bool(self.guard(url))
        except Exception:  # noqa: BLE001 - a faulting guard fails closed
            allowed = False
        if not allowed:
            with self._lock:
                self.refused += 1
            return None
        if self.scope is not None and not self.scope.allow_host(url):
            return None
        request_headers = {"User-Agent": DEFAULT_BROWSER_UA, "Accept": "*/*"}
        request_headers.update(headers or {})
        if range_bytes:
            request_headers["Range"] = f"bytes=0-{int(range_bytes) - 1}"
        with_auth = bool(auth)
        if with_auth:
            request_headers.update(auth)
        proxies, token = self._routing(with_auth)
        if token:
            request_headers["X-Redamon-Ctx"] = token
        answer = self._send_once(method, url, request_headers, proxies, max_bytes, with_auth)
        if answer.status_code == 429:
            # Slow every worker down, and every other in-process requester
            # under the RoE ceiling, then try this route once more.
            wait = _retry_after(answer.headers)
            self.pacer.back_off(wait)
            request_pacer.pacer().back_off(wait)
            if not _stop_requested():
                answer = self._send_once(method, url, request_headers, proxies, max_bytes, with_auth)
        answer.range_read = bool(range_bytes)
        return answer

    def _send_once(self, method, url, headers, proxies, max_bytes, with_auth) -> Answer:
        self._pace()
        with self._lock:
            self.sent += 1
            if with_auth:
                self.sent_with_auth += 1
        answer = Answer(url=url, method=method, with_auth=with_auth)
        try:
            if self._transport is not None:
                response = self._transport(method, url, headers=headers, timeout=self.timeout,
                                           proxies=proxies, allow_redirects=False)
            else:
                response = self._session().request(
                    method, url, headers=headers, timeout=self.timeout, proxies=proxies,
                    verify=False, allow_redirects=False, stream=True)
        except Exception as exc:  # noqa: BLE001 - one failed request costs one route
            answer.error = type(exc).__name__
            self._host_failed(url, exc)
            return answer
        self._host_alive(url)
        try:
            answer.status_code = int(response.status_code)
            answer.headers = {str(k).lower(): str(v) for k, v in dict(response.headers or {}).items()}
            if method != "HEAD":
                answer.content, answer.truncated = _read_capped(response, max_bytes)
        except Exception as exc:  # noqa: BLE001 - a body that breaks mid-read is what was read
            answer.error = answer.error or type(exc).__name__
        finally:
            try:
                response.close()
            except Exception:  # noqa: BLE001
                pass
        return answer

    def _host_alive(self, url: str) -> None:
        if self.scope is not None:
            try:
                self.scope.host_alive(url)
            except Exception:  # noqa: BLE001
                pass

    def _host_failed(self, url: str, exc: BaseException) -> None:
        if self.scope is None:
            return
        try:
            from recon.helpers import circuit_breaker as cb
            if cb.is_connection_failure(exc):
                self.scope.host_failed(url, exc)
        except Exception:  # noqa: BLE001
            pass

    # -- control probe --------------------------------------------------------

    def control(self, answer: Answer, *, shape: str, auth: Optional[dict] = None,
                range_bytes: Optional[int] = None) -> catchall.ControlVerdict:
        """Does a made-up path next to ``answer.url`` get the same answer?

        The control is sent exactly as the hit was (method, Range, auth), and
        each shape keeps its own cache: a Range control never answers for a
        full GET, an anonymous one never for a logged-in one.
        """
        with self._lock:
            cache = self._controls.setdefault(shape, catchall.ControlCache())

        def fetch(control_url: str):
            sent = self.send(answer.method, control_url, auth=auth, range_bytes=range_bytes,
                             max_bytes=catchall.BODY_CAP)
            if sent is None or not sent.ok:
                raise ConnectionError(sent.error if sent else "not sent")
            return sent

        return catchall.control_probe(fetch, answer.url, answer, url_guard=self.guard,
                                      cache=cache, roe_excluded=self.roe_excluded or None,
                                      note_module="route_exposure")

    @property
    def control_requests(self) -> int:
        with self._lock:
            return sum(c.requests for c in self._controls.values())


def _profile(settings: dict) -> Optional[dict]:
    try:
        from recon.helpers.auth_profile import profile_from_settings
        return profile_from_settings(settings)
    except Exception:  # noqa: BLE001 - no usable profile means anonymous only
        return None


def _auth_headers_for(url: str, settings: dict) -> dict:
    """cache_scan.deception._auth_headers_for: the in-scope auth headers for the
    URL's host, {} out of the auth scope or for an RoE-excluded host."""
    from recon.helpers.auth_profile import auth_header_lines, profile_from_settings
    profile = profile_from_settings(settings)
    if not profile:
        return {}
    host = urlsplit(url).hostname or ""
    headers = {}
    for line in auth_header_lines(profile, host, settings):
        name, _, value = line.partition(":")
        if name.strip():
            headers[name.strip()] = value.strip()
    return headers


def _stop_requested() -> bool:
    try:
        from recon.helpers import shutdown
        return shutdown.stop_requested()
    except Exception:  # noqa: BLE001
        return False
