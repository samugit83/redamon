"""The render half of the fetcher contract on the real sandbox browser (live tier).

Talks to the kali sandbox's Playwright MCP server and builds its own page with
``page.set_content`` (no network). Self-skips when the server is not reachable, which is
the case in the gate's containers; run it with the host's network:

    MCP_AUTH_TOKEN="$(grep -m1 '^MCP_AUTH_TOKEN=' .env | cut -d= -f2-)" \
    docker run --rm --network host -v "$PWD:/repo" -w /repo/agentic -e MCP_AUTH_TOKEN \
        -e PYTHONPATH=/repo/agentic:/repo:/repo/mcp/servers:/repo/recon_orchestrator:/repo/services \
        --entrypoint python redamon-agent:latest -m pytest tests/test_tradecraft_fetcher_contract_live.py

``TC_LIVE_PLAYWRIGHT_MCP_URL`` overrides the server (default ``http://127.0.0.1:8005/sse``,
the port the stack publishes on loopback); ``MCP_AUTH_TOKEN`` is the sandbox's bearer token.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.net import GuardedFetcher  # noqa: E402
from tradecraft_doubles import ContractHarness, RenderContractSuite, run  # noqa: E402

MCP_URL = os.environ.get("TC_LIVE_PLAYWRIGHT_MCP_URL", "http://127.0.0.1:8005/sse")


def _reachable(url: str) -> bool:
    parts = urlsplit(url)
    try:
        with socket.create_connection((parts.hostname, parts.port or 80), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _reachable(MCP_URL), reason=f"Playwright MCP not reachable at {MCP_URL}")


class LiveMcp:
    """The sandbox's execute_playwright, counting the calls that reach it."""

    def __init__(self):
        self.calls = 0

    async def get_tools(self):
        from langchain_mcp_adapters.client import MultiServerMCPClient

        # The sandbox asks for the agent's bearer token (tools.py: BearerAuth MCP_AUTH_TOKEN).
        token = os.environ.get("MCP_AUTH_TOKEN", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        client = MultiServerMCPClient({"playwright": {"url": MCP_URL, "transport": "sse", "headers": headers}})
        tools = await client.get_tools()
        outer = self

        class Counting:
            def __init__(self, tool):
                self.name = tool.name
                self._tool = tool

            async def ainvoke(self, args):
                outer.calls += 1
                return await self._tool.ainvoke(args)

        return [Counting(t) for t in tools]


def live_harness() -> ContractHarness:
    mcp = LiveMcp()
    return ContractHarness(
        fetcher=GuardedFetcher(mcp),
        base=lambda host: f"http://{host}",
        requests=lambda: [],
        browser_calls=lambda: mcp.calls,
        can_render_fixture_pages=False,
    )


class TestGuardedRenderLive(RenderContractSuite):
    def make_harness(self):
        return live_harness()


def test_live_set_content_round_trip():
    fetcher = GuardedFetcher(LiveMcp())
    script = ("page.set_content('<html><body><h1>tc-live-marker</h1><a href=\"/x\">x</a></body></html>')\n"
              "print(page.content())")
    out, error = run(fetcher.run_browser_script(script))
    assert error == ""
    assert "tc-live-marker" in out and 'href="/x"' in out


def test_live_unresolvable_host_is_navigation_failed():
    # The trailing dot keeps a resolver's search domain (some home routers answer every
    # name under theirs) from turning the name into an address.
    r = run(GuardedFetcher(LiveMcp()).render("http://nothing.tc-fixture.test./"))
    assert r.error == "navigation_failed" and r.html == ""
