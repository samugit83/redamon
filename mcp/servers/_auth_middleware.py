"""Shared bearer-token authentication for the Kali MCP SSE servers.

STRIDE S10 defense-in-depth. The MCP tool servers are consumed ONLY by the agent
over the internal Docker bridge (``http://kali-sandbox:PORT/sse``); their host
ports are loopback-only (see docker-compose.yml). This middleware adds a second
control: every HTTP/WebSocket request must carry
``Authorization: Bearer <MCP_AUTH_TOKEN>`` when ``MCP_AUTH_TOKEN`` is set.

Behaviour:
- ``MCP_AUTH_TOKEN`` set    -> require a matching bearer token (constant-time),
                               otherwise reply 401 (HTTP) / close 1008 (WS).
- ``MCP_AUTH_TOKEN`` unset  -> FAIL CLOSED: reject every http/websocket request
  or empty                    (401 / close 1008). Auth is not opportunistic; an
                               absent token means "refuse", not "serve everyone".
                               Fresh installs always get a token from redamon.sh
                               ``ensure_auth_secrets`` (STRIDE S9). The ASGI
                               ``lifespan`` scope still passes through so the
                               server can boot.

Implemented as a pure-ASGI wrapper (no Starlette/FastMCP-version coupling) so it
composes with whatever SSE app the installed FastMCP builds. ``lifespan`` and any
non-http/websocket scope pass straight through untouched.

``BearerAuthHTTPHandlerMixin`` applies the same rule to the stdlib
``http.server`` progress/session servers (:8013, :8014).
"""

import hmac
import logging
import os
import threading
import time

logger = logging.getLogger("mcp-auth")

# Warn once per process that MCP_AUTH_TOKEN is unset and requests are refused.
_warned_failopen = False


def configured_token() -> str:
    """Return the expected bearer token from the environment (may be empty)."""
    return os.environ.get("MCP_AUTH_TOKEN", "") or ""


def _bearer_from_value(text) -> str:
    """The token of an ``Authorization: Bearer <token>`` value, or ""."""
    if isinstance(text, str) and text[:7].lower() == "bearer ":
        return text[7:].strip()
    return ""


def _extract_bearer(headers) -> str:
    """Pull the bearer token out of raw ASGI headers (list[(bytes, bytes)])."""
    for key, value in headers or []:
        if key == b"authorization":
            try:
                text = value.decode("latin-1")
            except Exception:
                return ""
            return _bearer_from_value(text)
    return ""


def _warn_unset_token_once() -> None:
    global _warned_failopen
    if not _warned_failopen:
        logger.warning(
            "MCP_AUTH_TOKEN is not set - MCP servers are REJECTING all "
            "requests (fail-closed). Set MCP_AUTH_TOKEN (redamon.sh does "
            "this automatically) to enable tool serving."
        )
        _warned_failopen = True


_UNAUTHORIZED_BODY = b'{"error":"unauthorized","detail":"missing or invalid bearer token"}'

# Probers on pentest-net can send requests in a loop: one log line per minute
# with a count, never the presented value.
_REFUSAL_LOG_INTERVAL_S = 60.0
_refusal_lock = threading.Lock()
_refusals_since_log = 0
_last_refusal_log = 0.0


def _reset_http_refusal_log_for_tests() -> None:
    global _refusals_since_log, _last_refusal_log
    with _refusal_lock:
        _refusals_since_log = 0
        _last_refusal_log = 0.0


def _note_http_refusal(server_name: str) -> None:
    global _refusals_since_log, _last_refusal_log
    with _refusal_lock:
        _refusals_since_log += 1
        now = time.monotonic()
        if _last_refusal_log and now - _last_refusal_log < _REFUSAL_LOG_INTERVAL_S:
            return
        count, _refusals_since_log, _last_refusal_log = _refusals_since_log, 0, now
    logger.warning("[rbac] %s refused %d request(s) without the agent's bearer", server_name, count)


class BearerAuthHTTPHandlerMixin:
    """The bearer rule of BearerAuthASGI for a stdlib ``BaseHTTPRequestHandler``.

    The Kali progress/session servers (:8013 Metasploit, :8014 Hydra) are
    ``http.server`` servers, which an ASGI wrapper cannot wrap. The check runs in
    ``parse_request``, before ``handle_one_request`` picks a ``do_*`` method, so
    every method and path (unknown ones included) answers 401 without the token,
    and an unset token refuses everything. List it before BaseHTTPRequestHandler.
    """

    def parse_request(self):
        if not super().parse_request():
            return False
        expected = configured_token()
        if not expected:
            _warn_unset_token_once()
        else:
            presented = _bearer_from_value(self.headers.get("Authorization"))
            if presented and hmac.compare_digest(presented.encode(), expected.encode()):
                return True
        _note_http_refusal(type(self).__name__)
        # The request body is never read: close rather than parse it as a next request.
        self.close_connection = True
        try:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_UNAUTHORIZED_BODY)))
            self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(_UNAUTHORIZED_BODY)
        except (BrokenPipeError, ConnectionResetError):
            pass
        return False


class BearerAuthASGI:
    """Wrap an ASGI app, gating http/websocket requests on a bearer token."""

    def __init__(self, app, token_getter=configured_token):
        self.app = app
        self._token_getter = token_getter

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in ("http", "websocket"):
            # lifespan / other — never gate these, so the ASGI server can boot.
            await self.app(scope, receive, send)
            return

        expected = self._token_getter()
        if not expected:
            # Fail CLOSED (STRIDE S9): an unset/empty MCP_AUTH_TOKEN means refuse,
            # never serve-everyone. Log a one-time warning so the operator sees
            # WHY every request is being rejected, then reject.
            _warn_unset_token_once()
            await self._reject(scope, send)
            return

        presented = _extract_bearer(scope.get("headers"))
        if presented and hmac.compare_digest(presented, expected):
            await self.app(scope, receive, send)
            return

        await self._reject(scope, send)

    async def _reject(self, scope, send):
        if scope.get("type") == "websocket":
            # Reject the handshake with a policy-violation close code.
            await send({"type": "websocket.close", "code": 1008})
            return
        body = b'{"error":"unauthorized","detail":"missing or invalid bearer token"}'
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"www-authenticate", b"Bearer"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _build_sse_app(mcp):
    """Get the SSE ASGI app from a FastMCP instance across FastMCP 2.x variants."""
    builders = (
        lambda: mcp.sse_app(),
        lambda: mcp.http_app(transport="sse"),
    )
    last_err = None
    for build in builders:
        try:
            return build()
        except (AttributeError, TypeError) as exc:
            last_err = exc
            continue
    raise RuntimeError(f"no usable SSE app builder on this FastMCP: {last_err}")


def serve_sse_with_auth(mcp, host: str, port: int) -> None:
    """Serve a FastMCP instance over SSE with the bearer wrapper applied.

    Fails CLOSED (STRIDE S9): if the wrapped app cannot be built/served on the
    installed FastMCP version, the error propagates and the process crash-loops
    (visible, fail-closed) instead of silently degrading to an UNAUTHENTICATED
    ``mcp.run()``. There is no unwrapped fallback path.
    """
    import uvicorn

    app = _build_sse_app(mcp)
    wrapped = BearerAuthASGI(app)
    token_state = "enforced" if configured_token() else "fail-closed (no token)"
    logger.info("MCP SSE server on %s:%s - bearer auth %s", host, port, token_state)
    uvicorn.run(wrapped, host=host, port=port, log_level="info")
