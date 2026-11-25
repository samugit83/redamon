"""Verify the agent attaches bearer auth to the 5 Kali MCP servers of a sandbox.

STRIDE S10 (client side). Two layers:
  1. mcp_registry plumbing: BearerAuth(token_env_var=...) -> to_mcp_servers_dict
     never reads the agent's environment, even for a system id: no header from
     MCP_AUTH_TOKEN whether it is set or not (the server, which fails closed, then
     refuses), and nothing is reported missing.
  2. tools._build_system_mcp_servers(host, token): all 5 system servers of one sandbox
     carry that instance's own literal bearer, on that instance's host, and read no
     environment variable (the old shared MCP_AUTH_TOKEN is set and must not show).

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

    # --- Layer 1: no server's bearer comes from the environment, a system id's included ---
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
    check("no header from the set MCP_AUTH_TOKEN", "Authorization" not in hdr)
    check("the shared token is never rendered", "unit-test-token" not in repr(cfg))

    os.environ.pop("MCP_AUTH_TOKEN", None)
    cfg2, warn2 = to_mcp_servers_dict([srv])
    hdr2 = cfg2["network_recon"].get("headers", {})
    check("no Authorization header when token unset", "Authorization" not in hdr2)
    check("nothing is reported missing (nothing is read)", not any(w.code == "env_var_unset" for w in warn2))

    # --- Layer 2: the 5 system servers all carry the token auth ---
    try:
        from tools import _build_system_mcp_servers, SYSTEM_MCP_TOOL_NAMES  # noqa: F401
    except Exception as exc:
        print(f"(layer 2 skipped: tools import needs agent runtime — {exc})")
    else:
        import sandbox_contract

        os.environ["MCP_AUTH_TOKEN"] = "old-shared-token"
        host = sandbox_contract.container_name("alice", "own", "a1b2c3")
        servers = _build_system_mcp_servers(host, "instance-token-0123456789")
        check("exactly 5 system MCP servers", len(servers) == 5)
        for s in servers:
            check(
                f"{s.id} carries its instance's own bearer",
                s.auth is not None
                and getattr(s.auth, "type", None) == "bearer"
                and s.auth.token == "instance-token-0123456789"
                and not s.auth.token_env_var,
            )
            check(f"{s.id} is on its instance's host",
                  s.url == f"http://{host}:{sandbox_contract.PORTS[s.id]}/sse")
        cfg3, _ = to_mcp_servers_dict(servers)
        check("the old shared token is never sent", "old-shared-token" not in repr(cfg3))
        os.environ.pop("MCP_AUTH_TOKEN", None)

    failed = [n for n, ok in results if not ok]
    for n, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'} {n}")
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 0 if not failed else 1


def test_all():
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
