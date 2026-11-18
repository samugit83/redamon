"""The fetcher contract on the test double, and the rules of the web boundary.

The same behaviour suite (``tradecraft_doubles.FetcherContractSuite``) runs on the real
``GuardedFetcher`` in ``test_tradecraft_fetcher_contract_integration.py`` (a local
server) and its render part on the sandbox browser in ``..._live.py``, so the double
cannot drift from production.

Also here: ``net.py`` is the only module of ``agentic/tradecraft/`` that reaches the
web (a scan of the package that grows with it), and ``render`` never hands the sandbox
a capture context.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Dict, Iterable, Set
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator_helpers import fetch_guard  # noqa: E402
from orchestrator_helpers.fetch_guard import guarded_browser_script  # noqa: E402
from tradecraft import net  # noqa: E402
from tradecraft.net import GuardedFetcher, carries_same_host_headers, url_problem  # noqa: E402
from tradecraft_doubles import (  # noqa: E402
    FetcherContractSuite,
    RecordingMcp,
    RenderContractSuite,
    double_harness,
    run,
)

TRADECRAFT_DIR = Path(__file__).resolve().parent.parent / "tradecraft"


class TestFixtureFetcherContract(FetcherContractSuite):
    def make_harness(self):
        return double_harness()


class TestFixtureFetcherRender(RenderContractSuite):
    def make_harness(self):
        return double_harness()


# ---------------------------------------------------------------------------
# Only net.py reaches the web
# ---------------------------------------------------------------------------

# Modules that open a connection, directly or through the egress guard.
CONNECTING_MODULES = (
    "aiohttp", "asyncpg", "http.client", "httpcore", "httpx", "psycopg", "psycopg2",
    "psycopg_pool", "requests", "socket", "urllib.request", "urllib3", "websockets",
    "orchestrator_helpers.fetch_guard",
)

# Every module of agentic/tradecraft/ allowed to open a connection, and why.
ALLOWED_CONNECTIONS: Dict[str, Set[str]] = {
    # The web boundary itself: httpx over the pinned transport, the browser guard.
    "net.py": {"httpx", "orchestrator_helpers.fetch_guard"},
    # The page store's Postgres pool (T1.4).
    "db.py": {"psycopg", "psycopg_pool"},
    # The coverage map's query over the store (T5.4).
    "library/coverage.py": {"psycopg", "psycopg_pool"},
    # The owner's provider list, read from the webapp's internal route (T1.5).
    "models.py": {"httpx"},
}


def _imported_names(source: str) -> Iterable[str]:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module
            for alias in node.names:
                yield f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in ("import_module", "__import__") and node.args and isinstance(node.args[0], ast.Constant):
                yield str(node.args[0].value)


def connecting_imports(source: str) -> Set[str]:
    found = set()
    for name in _imported_names(source):
        for mod in CONNECTING_MODULES:
            if name == mod or name.startswith(mod + "."):
                found.add(mod)
    return found


def violations(root: Path) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for f in sorted(root.rglob("*.py")):
        rel = f.relative_to(root).as_posix()
        extra = connecting_imports(f.read_text(encoding="utf-8")) - ALLOWED_CONNECTIONS.get(rel, set())
        if extra:
            out[rel] = extra
    return out


def test_only_net_opens_connections():
    scanned = {f.relative_to(TRADECRAFT_DIR).as_posix() for f in TRADECRAFT_DIR.rglob("*.py")}
    assert "net.py" in scanned
    # The scan really sees net.py's own imports, so an empty result means something.
    assert connecting_imports((TRADECRAFT_DIR / "net.py").read_text()) == {"httpx", "orchestrator_helpers.fetch_guard"}
    assert violations(TRADECRAFT_DIR) == {}


@pytest.mark.parametrize("source", [
    "import httpx",
    "import urllib.request as u",
    "from urllib import request",
    "from orchestrator_helpers.fetch_guard import pinned_async_transport",
    "from orchestrator_helpers import fetch_guard",
    "import psycopg.rows",
    "import importlib\nimportlib.import_module('socket')",
    "__import__('aiohttp')",
])
def test_scan_catches_a_connecting_import(source):
    assert connecting_imports(source)


def test_scan_ignores_harmless_imports():
    assert connecting_imports("import json\nfrom urllib.parse import urlsplit\nfrom . import net\n") == set()


# ---------------------------------------------------------------------------
# GuardedFetcher.render: what the sandbox receives, and how its output maps
# ---------------------------------------------------------------------------

PUBLIC_IP = ["93.184.216.34"]
PAGE = "https://wiki.tc-fixture.test/sqli/union-based/"


def _render(mcp, url=PAGE):
    with patch.object(fetch_guard, "_resolve_ips", lambda _host: PUBLIC_IP):
        return run(GuardedFetcher(mcp).render(url))


def test_render_passes_no_capture_context():
    mcp = RecordingMcp()
    r = _render(mcp)
    assert r.error == "" and "ok" in r.html
    # The script and nothing else: without _redamon_ctx the sandbox never routes the
    # page through the capture proxy into a project's recorded traffic.
    assert mcp.calls == [{"script": guarded_browser_script(PAGE)}]
    assert "_redamon_ctx" not in mcp.calls[0]


@pytest.mark.parametrize("reply, error", [
    ("[BLOCKED] navigation reached a non-public address: http://10.0.0.1/", "unsafe_address"),
    ("[ERROR] Navigation failed: net::ERR_NAME_NOT_RESOLVED", "navigation_failed"),
    ("", "navigation_failed"),
    ([{"type": "text", "text": "<html>block</html>"}], ""),
])
def test_render_maps_browser_output(reply, error):
    r = _render(RecordingMcp(reply=reply))
    assert r.error == error
    assert (r.html != "") == (error == "")


def test_render_without_browser():
    assert _render(None).error == "browser_unavailable"

    class NoPlaywright:
        async def get_tools(self):
            return []

    assert _render(NoPlaywright()).error == "browser_unavailable"


def test_render_browser_failure_is_a_code_not_text():
    def boom(_args):
        raise RuntimeError("secret page text must not leak")

    r = _render(RecordingMcp(reply=boom))
    assert r.error == "browser_error" and r.html == ""


def test_render_refuses_before_browser_when_guard_refuses():
    mcp = RecordingMcp()
    with patch.object(fetch_guard, "_resolve_ips", lambda _host: ["10.1.2.3"]):
        r = run(GuardedFetcher(mcp).render(PAGE))
    assert r.error == "unsafe_address" and mcp.calls == []


# ---------------------------------------------------------------------------
# Small rules
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("first, hop, carries", [
    ("https://a.test/x", "https://a.test/y", True),
    ("https://a.test/x", "https://A.TEST./y", True),
    ("http://a.test/x", "https://a.test/y", True),       # upgrade
    ("https://a.test/x", "http://a.test/y", False),      # downgrade
    ("https://a.test/x", "https://a.test:8443/y", False),
    ("https://a.test/x", "https://b.a.test/y", False),
    ("https://a.test/x", "https://evil.test/a.test", False),
])
def test_carries_same_host_headers(first, hop, carries):
    assert carries_same_host_headers(first, hop) is carries


@pytest.mark.parametrize("url, problem", [
    ("https://a.test/x", ""),
    ("https://user:pw@a.test/", "userinfo_refused"),
    ("https://user@a.test/", "userinfo_refused"),
    ("https://@a.test/", "userinfo_refused"),
    ("ftp://a.test/", "bad_url"),
    ("javascript:alert(1)", "bad_url"),
    ("", "bad_url"),
    ("http://a.test:99999/", "bad_url"),
    ("http://a.test:http/", "bad_url"),
    ("http://[::1/", "bad_url"),
    ("https://a..b/", "bad_url"),
    ("https://" + "a" * 64 + ".test/", "bad_url"),
    ("http://[::1]/", ""),
    ("http://nothing.tc-fixture.test./", ""),
])
def test_url_problem(url, problem):
    assert url_problem(url) == problem


@pytest.mark.parametrize("url", ["http://[::1/", "https://wiki.tc-fixture.test]/", "https://a..b/"])
def test_guarded_fetcher_never_raises_on_a_bad_host(url, caplog):
    with caplog.at_level("WARNING"):
        assert run(GuardedFetcher().get(url)).error == "bad_url"
        assert run(GuardedFetcher(RecordingMcp()).render(url)).error == "bad_url"
    assert any("[tradecraft] net bad_url host=" in r.getMessage() for r in caplog.records)


def test_render_maps_a_resolver_value_error_to_bad_url():
    # A host url_problem lets through but the resolver cannot encode: the same code as get().
    def raising(_host):
        raise UnicodeError("label empty or too long")

    mcp = RecordingMcp()
    with patch.object(fetch_guard, "_resolve_ips", raising):
        assert run(GuardedFetcher(mcp).render(PAGE)).error == "bad_url"
        assert run(GuardedFetcher().get(PAGE)).error == "bad_url"
    assert mcp.calls == []


def test_url_httpx_cannot_parse_is_bad_url_not_an_exception():
    with patch.object(fetch_guard, "_resolve_ips", lambda _host: PUBLIC_IP):
        r = run(GuardedFetcher().get("http://wiki.tc-fixture.test:99999/"))
    assert r.error == "bad_url" and r.status == 0


def test_errors_are_a_closed_set():
    assert {"bad_url", "userinfo_refused", "unsafe_address", "too_many_redirects", "unreachable",
            "timeout", "http_error", "browser_unavailable", "browser_error",
            "navigation_failed"} == net.ERRORS
