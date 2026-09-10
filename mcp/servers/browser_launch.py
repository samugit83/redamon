"""
Shared chromium-launch constants + capture-proxy wiring for the kali browser
tools. Dependency-free (NO fastmcp) so both the long-running playwright_server
and the in-process `redamon` SDK (proxy_brain's `redamon.browser`) can import it
without dragging the MCP framework into the agent's unit image.

`playwright_server.py` renders Playwright *scripts* (string fragments); the
`redamon` SDK drives Playwright *in-process* (real kwargs). This module gives the
in-process path what it needs and shares the launch constants with both.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

# Chromium flags required to run headless as root inside the container. Shared so
# the two browser code paths cannot drift (a missing --no-sandbox crash-loads the
# launch under root).
BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
]

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def capture_kwargs(ctx_token: str, header_tag: Optional[str] = None) -> Tuple[Optional[Dict[str, str]], Dict[str, str]]:
    """Real-dict launch/context kwargs for an IN-PROCESS chromium, routed through
    the capture proxy — or (None, {}) when capture is off/unreachable.

    Returns ``(proxy, extra_http_headers)``:
      - ``proxy`` is ``{"server": <cap_url>}`` for ``chromium.launch(proxy=...)``,
        or ``None`` (launch direct, no capture).
      - ``extra_http_headers`` carries the opaque ``X-Redamon-Ctx`` tag for
        ``browser.new_context(extra_http_headers=...)``, or ``{}``.

    §20.2 tag-leak guard: the proxy flag and the header are emitted TOGETHER, only
    when the proxy is reachable — never the header on a direct connection.
    `header_tag` overrides the header value with a distinct capture-lineage tag
    (e.g. proxy_brain's browser tag, minted server-side); it defaults to the raw
    `ctx_token` the caller already holds.
    """
    try:
        from capture_routing import agent_capture_routing
        cap_url, cap_tok = agent_capture_routing(ctx_token)
    except Exception:  # noqa: BLE001 - capture is best-effort; never break the launch
        cap_url, cap_tok = (None, None)
    if not (cap_url and cap_tok):
        return (None, {})
    return ({"server": cap_url}, {"X-Redamon-Ctx": header_tag or cap_tok})
