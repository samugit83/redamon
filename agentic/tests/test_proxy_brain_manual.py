"""Anti-drift + reachability tests for the proxy_brain manual.

The manual (mcp/servers/proxy_brain_manual.md) is what the agent reads via
`redamon.manual()` before writing complex code. If it documents a function that
does not exist, or the SDK grows a function the manual never mentions, the agent
is misled. These tests lock the manual to the real SDK surface and check the
on-demand section retrieval (incl. path-traversal rejection).
"""
import os
import re
import sys

_MCP_SERVERS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "mcp", "servers",
)
if _MCP_SERVERS not in sys.path:
    sys.path.insert(0, _MCP_SERVERS)

import redamon  # noqa: E402

# The public SDK the manual promises the agent. Keep in sync with redamon.py.
PUBLIC_API = {
    "search", "get", "sitemap", "params", "grep", "diff", "to_curl", "query",
    "decode", "jwt", "replay", "batch", "fuzz", "browser", "finding", "emit",
    "manual",
}


def test_manual_file_present_and_core_complete():
    core = redamon.manual()
    assert "not found" not in core, "manual file missing next to the SDK"
    assert "THE SDK" in core
    assert "SECTION INDEX" in core
    assert "HOW YOU BUILD" in core  # the capability map (web-proxy workflows)
    assert "OAST" in core          # the NOT-available caveat


def test_every_documented_function_exists():
    # Scan the WHOLE manual (every recipe in every section), not just the core, so
    # a section that calls a renamed/removed function is caught.
    with open(redamon._MANUAL_PATH, "r", encoding="utf-8") as fh:
        full = fh.read()
    documented = set(re.findall(r"redamon\.(\w+)\s*\(", full))
    # ignore private helpers a recipe might reference
    documented = {d for d in documented if not d.startswith("_")}
    missing = sorted(d for d in documented
                     if not callable(getattr(redamon, d, None)))
    assert not missing, f"manual documents non-existent redamon.* functions: {missing}"


def test_manual_recipes_use_no_private_helpers():
    # Recipes must use the PUBLIC API only — no redamon._b64u / _run / _post etc.,
    # which are internal and may change without notice.
    with open(redamon._MANUAL_PATH, "r", encoding="utf-8") as fh:
        full = fh.read()
    privates = sorted(set(re.findall(r"redamon\.(_\w+)", full)))
    assert not privates, f"manual leaks private SDK helpers into recipes: {privates}"


def test_every_public_function_is_documented():
    core = redamon.manual()
    undocumented = sorted(fn for fn in PUBLIC_API if f"redamon.{fn}" not in core)
    assert not undocumented, f"public SDK functions absent from the manual core: {undocumented}"


def test_public_api_matches_sdk():
    # The declared PUBLIC_API must all be real callables (guards the test itself
    # and catches a renamed/removed SDK function).
    missing = sorted(fn for fn in PUBLIC_API if not callable(getattr(redamon, fn, None)))
    assert not missing, f"PUBLIC_API lists functions not on the SDK: {missing}"


def test_section_retrieval_and_index_consistency():
    core = redamon.manual()
    secs = [s for s in redamon._manual_sections() if s]
    # every section named in the index resolves to real content
    for name in ("recon", "intruder", "sqli", "authz", "jwt", "race",
                 "smuggling", "cache", "injection", "decode", "sequencer",
                 "flows", "report", "nosql", "graphql", "lfi", "cmdi",
                 "cors", "xxe", "auth", "browser"):
        assert name in secs, f"index lists '{name}' but no such section"
        body = redamon.manual(name)
        assert len(body) > 50 and "no section" not in body


def test_bad_section_is_rejected_no_path_traversal():
    for evil in ("../redamon.py", "../../etc/passwd", "/etc/passwd", "nope"):
        out = redamon.manual(evil)
        assert "no section" in out, f"unexpected content for section {evil!r}"
        assert "def " not in out and "root:" not in out  # never leaked a file


def test_core_fits_a_lowered_output_cap():
    # The default read must stay small enough to survive even a reduced
    # TOOL_OUTPUT_MAX_CHARS; sections are read individually.
    assert len(redamon.manual()) < 12000
