"""Verify the agent attaches MCP_AUTH_TOKEN bearer auth to the 5 Kali MCP servers.

STRIDE S10 (client side). Two layers:
  1. mcp_registry plumbing: BearerAuth(token_env_var=...) -> to_mcp_servers_dict
     renders `Authorization: Bearer <token>` when the env var is set, and OMITS
     the header when it is unset (the server, which fails closed, then refuses).
  2. tools._build_system_mcp_servers(): all 5 system servers carry that auth.

Requires pydantic (mcp_registry). Layer 2 additionally needs the agent runtime
deps (langchain_mcp_adapters); it is skipped gracefully if those are absent, so
the file is safe to run on the host and full in the agent container:
    python3 agentic/tests/test_system_mcp_auth.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # agentic/

results = []


def check(name, cond):
    results.append((name, bool(cond)))


def main():
    try:
        from mcp_registry import MCPServer, BearerAuth, to_mcp_servers_dict
    except Exception as exc:  # pydantic missing on a bare host
        print(f"SKIP: mcp_registry unimportable ({exc})")
        return 0

    # --- Layer 1: plumbing renders / omits the header correctly ---
    # A system id: token_env_var is read for the operator's servers only (OQ-R1).
    srv = MCPServer(
        id="network_recon",
        name="probe",
        transport="sse",
        url="http://kali-sandbox:8000/sse",
        tools=[],
        auth=BearerAuth(token_env_var="MCP_AUTH_TOKEN"),
    )

    os.environ["MCP_AUTH_TOKEN"] = "unit-test-token"
    cfg, _warn = to_mcp_servers_dict([srv])
    hdr = cfg["network_recon"].get("headers", {})
    check("header present when token set", hdr.get("Authorization") == "Bearer unit-test-token")

    os.environ.pop("MCP_AUTH_TOKEN", None)
    cfg2, warn2 = to_mcp_servers_dict([srv])
    hdr2 = cfg2["network_recon"].get("headers", {})
    check("no Authorization header when token unset", "Authorization" not in hdr2)
    check("env_var_unset warning surfaced", any(w.code == "env_var_unset" for w in warn2))

    # --- Layer 2: the 5 system servers all carry the token auth ---
    try:
        from tools import _build_system_mcp_servers, SYSTEM_MCP_TOOL_NAMES  # noqa: F401
    except Exception as exc:
        print(f"(layer 2 skipped: tools import needs agent runtime — {exc})")
    else:
        servers = _build_system_mcp_servers()
        check("exactly 5 system MCP servers", len(servers) == 5)
        for s in servers:
            check(
                f"{s.id} carries MCP_AUTH_TOKEN bearer",
                s.auth is not None
                and getattr(s.auth, "type", None) == "bearer"
                and s.auth.token_env_var == "MCP_AUTH_TOKEN",
            )

    failed = [n for n, ok in results if not ok]
    for n, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'} {n}")
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 0 if not failed else 1


def test_all():
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
