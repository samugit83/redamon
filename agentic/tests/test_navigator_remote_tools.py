"""AI Navigator's callbacks to the webapp (plan §8.9): the headers, the manifest filter, timeouts
and every failure turned into a tool result; it never raises."""
import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from navigator import remote_tools as rt  # noqa: E402

CRED = "k" * 43


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(coro):
    return asyncio.run(coro)


class RemoteToolsTest(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "master-key", "WEBAPP_API_URL": "http://webapp:3000"})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_call_sends_the_master_key_and_credential_and_reads_ok(self):
        seen = {}

        def handler(req: httpx.Request):
            seen["url"] = str(req.url)
            seen["headers"] = dict(req.headers)
            seen["body"] = json.loads(req.content)
            return httpx.Response(200, json={"ok": True, "result": {"rows": [1, 2]}})

        async def go():
            async with client(handler) as c:
                return await rt.call_tool("run_cypher", {"cypher": "MATCH (n:IP) RETURN n LIMIT 1"}, CRED, c)
        out = run(go())
        self.assertEqual(seen["url"], "http://webapp:3000/api/internal/navigator/tools/run_cypher")
        self.assertEqual(seen["headers"]["x-internal-key"], "master-key")
        self.assertEqual(seen["headers"]["x-redamon-navigator"], CRED)
        self.assertEqual(seen["body"], {"args": {"cypher": "MATCH (n:IP) RETURN n LIMIT 1"}})
        self.assertTrue(out.ok)
        self.assertEqual(json.loads(out.content), {"rows": [1, 2]})
        self.assertEqual(out.detail, "MATCH (n:IP) RETURN n LIMIT 1")

    def test_a_refusal_becomes_a_readable_result(self):
        def handler(req):
            return httpx.Response(403, json={"ok": False, "code": "tool_refused", "message": "You may not read this."})

        async def go():
            async with client(handler) as c:
                return await rt.call_tool("workspace_read", {"path": "a.txt"}, CRED, c)
        out = run(go())
        self.assertFalse(out.ok)
        self.assertEqual(out.error_code, "tool_refused")
        self.assertEqual(json.loads(out.content)["message"], "You may not read this.")

    def test_transport_errors_timeouts_and_garbage_never_raise(self):
        def boom(req):
            raise httpx.ConnectError("refused")

        def slow(req):
            raise httpx.ReadTimeout("slow")

        def html(req):
            return httpx.Response(502, text="<html>bad gateway</html>")

        for handler, code in ((boom, "tool_unreachable"), (slow, "tool_timeout"), (html, "tool_failed")):
            async def go(h=handler):
                async with client(h) as c:
                    return await rt.call_tool("graph_summary", {}, CRED, c)
            out = run(go())
            self.assertFalse(out.ok)
            self.assertEqual(out.error_code, code)

    def test_manifest_keeps_only_well_formed_data_tools(self):
        def handler(req):
            self.assertEqual(req.headers["x-redamon-navigator"], CRED)
            return httpx.Response(200, json={"tools": [
                {"name": "graph_summary", "route": "graph", "description": "d", "parameters": {"type": "object"}},
                {"name": "Bad Name", "route": "graph", "description": "d", "parameters": {"type": "object"}},
                {"name": "evil", "route": "docs", "description": "d", "parameters": {"type": "object"}},
                {"name": "no_params", "route": "records", "description": "d"},
            ]})

        async def go():
            async with client(handler) as c:
                return await rt.fetch_manifest(CRED, c)
        self.assertEqual([t["name"] for t in run(go())], ["graph_summary"])

    def test_manifest_failure_is_none(self):
        for handler in (lambda r: httpx.Response(404, json={}), lambda r: httpx.Response(200, text="x")):
            async def go(h=handler):
                async with client(h) as c:
                    return await rt.fetch_manifest(CRED, c)
            self.assertIsNone(run(go()))


if __name__ == "__main__":
    unittest.main()
