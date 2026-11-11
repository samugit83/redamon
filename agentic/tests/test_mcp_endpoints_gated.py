"""
Regression: the agent's /mcp/* endpoints take the master key only (NF-01, NF-14).

/mcp/test spawns an operator-supplied stdio command, and /mcp/manifest returns
server config; leaving them unauthenticated let any agent-bridge peer reach
them, and the scanner key every scan container holds opened them until step 1.9.
This test asserts each carries the require_configured_master_auth dependency.

Runs inside the agent container (imports the FastAPI app + its deps):
    python /app/test_mcp_endpoints_gated.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402

GATED = {"/mcp/test", "/mcp/reload", "/mcp/manifest"}


def _dep_names(route):
    names = []
    for d in list(getattr(route, "dependencies", []) or []):
        call = getattr(d, "dependency", None)
        names.append(getattr(call, "__name__", str(call)))
    return names


class McpEndpointsGatedTests(unittest.TestCase):
    def test_mcp_endpoints_require_the_configured_master_key(self):
        found = {}
        for r in api.app.routes:
            p = getattr(r, "path", "")
            if p in GATED:
                found[p] = _dep_names(r)
        for p in GATED:
            self.assertIn(p, found, f"{p} route not registered")
            self.assertIn(
                "require_configured_master_auth",
                found[p],
                f"{p} is not master-key gated (deps: {found[p]})",
            )
            self.assertNotIn("require_internal_auth_only", found[p], f"{p} still takes the scanner key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
