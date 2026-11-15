"""AI Navigator's agent routes (plan §8.2, §8.11): the master key only, the NDJSON contract, the
stop endpoints, and a disconnect that cancels the run and makes no further callback."""
import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import llm_guard  # noqa: E402
from navigator import api as nav_api  # noqa: E402
from navigator import runs  # noqa: E402
from navigator.wiki_index import build_index  # noqa: E402
from navigator_fakes import FakeLLM, route_json, text, tool_call  # noqa: E402

MASTER = "navigator-test-master-key"


def body(**over):
    b = {"run_id": "run-1", "credential": "c" * 43, "user_id": "person-1", "actor_id": None, "project_id": "P1",
         "tenant_id": "owner-1", "model": "openai/gpt-x", "history": [], "message": "hello",
         "allowed_routes": ["docs", "direct"]}
    b.update(over)
    return b


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": "scanner-key"})
        self.env.start()
        llm_guard.reset_state()
        runs.clear_for_tests()
        app = FastAPI()
        app.include_router(nav_api.router)
        self.client = TestClient(app)
        self.index = mock.patch("navigator.graph.wiki_index", lambda: build_index("/nonexistent"))
        self.index.start()

    def tearDown(self):
        self.index.stop()
        self.env.stop()
        runs.clear_for_tests()

    def test_every_route_needs_the_master_key(self):
        deps = {r.path: {d.call for d in r.dependant.dependencies} for r in nav_api.router.routes if isinstance(r, APIRoute)}
        self.assertIn(llm_guard.require_master_internal_auth, deps["/navigator/chat"])
        self.assertIn(llm_guard.require_internal_auth, deps["/navigator/chat"])
        for path in ("/navigator/stop", "/navigator/stop-all", "/navigator/health"):
            self.assertIn(llm_guard.require_configured_master_auth, deps[path])
        for d in deps.values():
            self.assertNotIn(llm_guard.require_internal_auth_only, d)
        for headers in ({}, {"x-internal-key": "scanner-key"}, {"x-internal-key": "wrong"}):
            self.assertEqual(self.client.post("/navigator/chat", json=body(), headers=headers).status_code, 401)
            self.assertEqual(self.client.post("/navigator/stop-all", headers=headers).status_code, 401)

    def test_no_master_key_fails_closed(self):
        for env in ({"INTERNAL_API_KEY": ""}, {"INTERNAL_API_KEY": "changeme"}):
            with mock.patch.dict(os.environ, env):
                r = self.client.post("/navigator/chat", json=body(), headers={"x-internal-key": env["INTERNAL_API_KEY"]})
                self.assertIn(r.status_code, (401, 503))

    def test_ndjson_contract(self):
        llm = FakeLLM([route_json(["direct"]), text("Hi! I answer questions about RedAmon.")])

        async def build(model, user):
            return llm, None
        with mock.patch.object(nav_api, "_build_llm", build):
            r = self.client.post("/navigator/chat", json=body(), headers={"x-internal-key": MASTER})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-type"].startswith("application/x-ndjson"))
        lines = [json.loads(ln) for ln in r.text.strip().split("\n")]
        self.assertEqual(lines[0], {"type": "meta", "run_id": "run-1", "model_used": "openai/gpt-x"})
        self.assertEqual(lines[1]["type"], "route")
        self.assertEqual(lines[-1], {"type": "done", "status": "complete"})
        self.assertEqual("".join(e["text"] for e in lines if e["type"] == "delta"), "Hi! I answer questions about RedAmon.")
        self.assertEqual(runs.count(), 0)

    def test_a_model_build_failure_is_an_error_event(self):
        async def build(model, user):
            return None, "loop_model_not_supported_here"
        with mock.patch.object(nav_api, "_build_llm", build):
            r = self.client.post("/navigator/chat", json=body(model="loop/mcp"), headers={"x-internal-key": MASTER})
        lines = [json.loads(ln) for ln in r.text.strip().split("\n")]
        self.assertEqual(lines[-1]["type"], "error")
        self.assertEqual(lines[-1]["code"], "loop_model_not_supported_here")

    def test_the_real_builder_refuses_a_loop_model(self):
        code = asyncio.run(nav_api._build_llm("loop/mcp", "person-1"))
        self.assertEqual(code, (None, "loop_model_not_supported_here"))

    def test_busy_agent(self):
        with mock.patch.object(runs, "at_capacity", return_value=True):
            r = self.client.post("/navigator/chat", json=body(), headers={"x-internal-key": MASTER})
        self.assertEqual(json.loads(r.text.strip().split("\n")[-1])["code"], "agent_busy")

    def test_body_ids_and_sizes_are_validated(self):
        for bad in (body(message=""), body(message="x" * 4001), body(allowed_routes=["shell"]), body(credential="short")):
            self.assertEqual(self.client.post("/navigator/chat", json=bad, headers={"x-internal-key": MASTER}).status_code, 422)

    def test_stop_and_stop_all(self):
        async def scenario():
            t1 = asyncio.create_task(asyncio.sleep(30))
            t2 = asyncio.create_task(asyncio.sleep(30))
            runs.register("a", t1, "u", "p")
            runs.register("b", t2, "u", "p")
            self.assertTrue(runs.stop("a"))
            self.assertFalse(runs.stop("a"))
            self.assertEqual(runs.stop_all(), 1)
            await asyncio.sleep(0)
            return t1.cancelled(), t2.cancelled()
        self.assertEqual(asyncio.run(scenario()), (True, True))
        r = self.client.post("/navigator/stop", json={"run_id": "nope"}, headers={"x-internal-key": MASTER})
        self.assertEqual(r.json(), {"stopped": False})
        self.assertEqual(self.client.post("/navigator/stop-all", headers={"x-internal-key": MASTER}).json(), {"stopped": 0})

    def test_health(self):
        r = self.client.get("/navigator/health", headers={"x-internal-key": MASTER})
        self.assertEqual(r.json()["wiki"]["present"], False)

    def test_a_disconnect_cancels_the_run_and_makes_no_further_callback(self):
        callbacks = []

        async def fake_manifest(credential):
            callbacks.append("manifest")
            return [{"name": "graph_summary", "route": "graph", "description": "d", "parameters": {"type": "object"}}]

        async def fake_call(name, args, credential, client=None):
            callbacks.append(name)

        llm = FakeLLM([route_json(["graph"]), tool_call("graph_summary", {}), text("never")])

        class Req:
            def __init__(self):
                self.disconnected = False

            async def is_disconnected(self):
                return self.disconnected

        async def scenario():
            req = Req()

            async def build(model, user):
                return llm, None
            with mock.patch.object(nav_api, "_build_llm", build), \
                    mock.patch("navigator.graph.fetch_manifest", fake_manifest), \
                    mock.patch("navigator.remote_tools.call_tool", fake_call):
                resp = await nav_api.navigator_chat(nav_api.ChatBody(**body(allowed_routes=["docs", "direct", "graph"])), req)
                it = resp.body_iterator
                first = await it.__anext__()
                self.assertEqual(json.loads(first)["type"], "meta")
                req.disconnected = True
                await it.aclose()
                await asyncio.sleep(0.05)
            return runs.count()
        self.assertEqual(asyncio.run(scenario()), 0)
        self.assertNotIn("graph_summary", callbacks)


if __name__ == "__main__":
    unittest.main()
