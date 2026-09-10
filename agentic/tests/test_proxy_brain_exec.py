"""Runtime-wrapper guards for proxy_brain — the layer unit tests missed.

The live NameError ("redamon is not defined") slipped through because every other
test imports `redamon` directly and never exercised the proxy_brain MCP wrapper,
which writes the agent's code to a file and runs it in a fresh interpreter. These
tests pin the wrapper contract (auto-import + SDK on path) via source AST (the
wrapper itself needs fastmcp, kali-only) and the SDK runtime behaviour that the
wrapper depends on (Txn parsing, fail-closed without a ctx tag).
"""
import ast
import os
import sys

import pytest

_MCP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "mcp", "servers",
)
if _MCP not in sys.path:
    sys.path.insert(0, _MCP)

import redamon  # noqa: E402


def test_proxy_brain_wrapper_pre_imports_redamon():
    # Regression guard for the live NameError: the wrapper MUST prepend an import
    # so `redamon.*` works in agent code that does not import it. Asserted from
    # source (the wrapper imports fastmcp, absent from the agent test image).
    src_path = os.path.join(_MCP, "network_recon_server.py")
    with open(src_path, "r", encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "proxy_brain")
    body = ast.get_source_segment(src, fn)
    assert "import redamon" in body, "proxy_brain must pre-import redamon for the child"
    assert "/opt/mcp_servers" in body, "proxy_brain must put the SDK on the child's path"


def test_txn_parses_summary_line():
    # search() returns Txn rows; the agent naturally reaches for .method/.status/.url.
    t = redamon.Txn("abc123", "abc123  GET 200 pbtarget:5000/api/x?y=1  75b  agent [auth]")
    assert t.id == "abc123"
    assert t.method == "GET"
    assert t.status == 200
    assert t.url == "pbtarget:5000/api/x?y=1"
    assert t.host == "pbtarget:5000"
    assert t.path == "/api/x?y=1"


def test_txn_tolerates_short_or_empty_line():
    t = redamon.Txn("id", "id")
    assert t.method is None and t.status is None and t.url is None and t.host is None


def test_sdk_fails_closed_without_ctx():
    # Without the injected REDAMON_CTX the SDK must refuse (SystemExit from _die),
    # never issue a tenant-less request.
    old = os.environ.pop("REDAMON_CTX", None)
    try:
        with pytest.raises(SystemExit):
            redamon.search(host="x")
    finally:
        if old is not None:
            os.environ["REDAMON_CTX"] = old
