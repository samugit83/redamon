"""P0-3 — `redagraph ask` must authenticate to /text-to-cypher like /graph/exec.

`cmd_ask` once sent no header at all while `_agent_post` (the /graph/exec path)
did; once /text-to-cypher was authenticated (P0-3) a header-less `ask` returned
401 and the Graph -> Terminal `ask` command broke. Both now present the
terminal's run credential (RBAC 1.15: the sandbox no longer holds the scanner
key, which they sent before). This pins the header on both paths so they cannot
drift apart again.

Run:
    python -m unittest mcp.tests.test_redagraph_ask_auth -v
"""

from __future__ import annotations

import os
import sys
import types
import unittest
from unittest import mock

_mcp_servers_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "servers")
sys.path.insert(0, _mcp_servers_dir)

import redagraph  # noqa: E402


class _Resp:
    status_code = 200

    def json(self):
        return {"cypher": "MATCH (i:IP) RETURN i.address"}

    @property
    def text(self):
        return ""


def _args(question="list ips"):
    return types.SimpleNamespace(question=question, show=False, format="plain")


class RedagraphAskAuthTests(unittest.TestCase):
    def _post_headers(self, env):
        captured = {}

        def fake_post(url, **kw):
            captured["url"] = url
            captured["headers"] = kw.get("headers")
            return _Resp()

        with mock.patch.dict(os.environ, env, clear=False):
            if "REDAMON_RUN_CREDENTIAL" not in env:
                os.environ.pop("REDAMON_RUN_CREDENTIAL", None)
            with mock.patch.object(redagraph, "_execute", return_value=[]):
                with mock.patch("requests.post", side_effect=fake_post):
                    redagraph.cmd_ask(_args(), "u1", "p1")
        return captured

    def test_ask_sends_the_run_credential(self):
        captured = self._post_headers({"REDAMON_RUN_CREDENTIAL": "run-tok"})
        self.assertIn("text-to-cypher", captured["url"])
        self.assertEqual(captured["headers"], {"X-Redamon-Run": "run-tok"})

    def test_ask_without_a_credential_sends_nothing(self):
        # A shell the terminal did not open: say so, rather than a bare 401.
        env = {k: v for k, v in os.environ.items() if k != "REDAMON_RUN_CREDENTIAL"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("sys.stderr"), \
                mock.patch("requests.post") as post, self.assertRaises(SystemExit):
            redagraph.cmd_ask(_args(), "u1", "p1")
        post.assert_not_called()

    def test_ask_never_sends_the_master_or_the_scanner_key(self):
        # The worker is the least-trusted tier and must not present either.
        captured = self._post_headers(
            {"REDAMON_RUN_CREDENTIAL": "run-tok", "SCANNER_API_KEY": "scan-tok", "INTERNAL_API_KEY": "master-secret"}
        )
        self.assertNotIn("master-secret", str(captured["headers"]))
        self.assertNotIn("scan-tok", str(captured["headers"]))


if __name__ == "__main__":
    unittest.main()
