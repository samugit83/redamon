"""Session-less paths never wait on Agent in the Loop: the guardrail endpoint, NL
graph queries, the model list, /health and the live-sessions answer."""
from __future__ import annotations

import asyncio
import os
import unittest
from contextlib import asynccontextmanager
from unittest import mock

from agent_in_the_loop import LoopSettings, broker as broker_mod
from agent_in_the_loop.broker import StepBroker
from agent_in_the_loop.model import LoopChatModel
from orchestrator_helpers.model_providers import fetch_all_models

ON = {"AGENT_IN_THE_LOOP_ENABLED": "true", "INTERNAL_API_KEY": ""}


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with mock.patch("api.lifespan", fake_lifespan):
            import api as api_module
            from fastapi.testclient import TestClient
        cls.api = api_module
        cls.client = TestClient(api_module.app)

    def setUp(self):
        env = mock.patch.dict(os.environ, ON)
        env.start()
        self.addCleanup(env.stop)

    def test_guardrail_check_target_never_calls_a_loop_adapter(self):
        loop_llm = LoopChatModel()
        orch = mock.MagicMock(_initialized=True, llm=loop_llm)
        orch._apply_project_settings = mock.MagicMock()
        spy = mock.AsyncMock(return_value={"allowed": False, "reason": "x"})
        with mock.patch.object(self.api, "orchestrator", orch), \
                mock.patch("orchestrator_helpers.guardrail.check_target_allowed", spy), \
                mock.patch("requests.get", side_effect=RuntimeError("no webapp")):
            resp = self.client.post("/guardrail/check-target",
                                    json={"target_domain": "example.com", "user_id": "u1"})
        self.assertEqual(resp.json(), {"allowed": True, "reason": "LLM not configured, guardrail skipped"})
        spy.assert_not_called()

    def test_guardrail_hard_block_still_runs_first(self):
        orch = mock.MagicMock(_initialized=True, llm=LoopChatModel())
        with mock.patch.object(self.api, "orchestrator", orch):
            resp = self.client.post("/guardrail/check-target", json={"target_domain": "whitehouse.gov"})
        self.assertFalse(resp.json()["allowed"])
        self.assertTrue(resp.json().get("hard_blocked"))

    def nl_routes(self):
        settings = {"OPENAI_MODEL": "loop/mcp"}
        # /text-to-cypher fails closed without a master key (RBAC 1.15): the webapp's call.
        master = {"INTERNAL_API_KEY": "loop-test-master-key"}
        with mock.patch("project_settings.fetch_agent_settings", return_value=settings), \
                mock.patch("requests.get", side_effect=AssertionError("providers must not be fetched")):
            with mock.patch.dict(os.environ, master):
                yield self.client.post("/text-to-cypher", headers={"x-internal-key": master["INTERNAL_API_KEY"]},
                                       json={"question": "list domains", "user_id": "u1", "project_id": "p1"})
            yield self.client.post("/graph/nl-query", json={
                "question": "list domains", "user_id": "u1", "project_id": "p1"})

    def test_nl_graph_queries_refuse_a_loop_project(self):
        for resp in self.nl_routes():
            with self.subTest(path=str(resp.url)):
                self.assertEqual(resp.status_code, 409)
                body = resp.json()
                self.assertEqual(body["code"], "loop_model_out_of_session")
                self.assertIn("raw Cypher still works", body["error"])

    def test_health_has_only_the_switch(self):
        resp = self.client.get("/health")
        body = resp.json()
        self.assertIs(body["loop_enabled"], True)
        for key in ("open_steps", "claimed_steps", "waiting_sessions", "drivers_seen_5m"):
            self.assertNotIn(key, body)
        for key in ("status", "version", "tools_loaded", "active_sessions", "fireteam_enabled",
                    "persistent_checkpointer", "active_waves"):
            self.assertIn(key, body)
        with mock.patch.dict(os.environ, {"AGENT_IN_THE_LOOP_ENABLED": "false"}):
            self.assertIs(self.client.get("/health").json()["loop_enabled"], False)

    def test_live_sessions_carry_the_loop_state_of_loop_runs_only(self):
        broker = StepBroker(config=LoopSettings(
            step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=40000,
            answer_max_chars=262144, max_open_steps_per_user=16, no_driver_grace_s=300,
            driver_seen_s=60, state_ttl_s=3600))
        manager = mock.MagicMock()
        manager.live_session_ids.return_value = ["s_loop", "s_prov"]

        async def scenario():
            loop_cm = broker.run_scope("u1", "p1", "s_loop", None, uses_loop=True)
            prov_cm = broker.run_scope("u1", "p1", "s_prov", None, uses_loop=False)
            scope = await loop_cm.__aenter__()
            await prov_cm.__aenter__()
            step = broker.new_step(scope, purpose="think", meta={}, messages=[],
                                   answer_format="json", last_instruction="")
            await broker.open_step(step, scope)
            states = broker.loop_states_for_project("p1")
            await prov_cm.__aexit__(None, None, None)
            await loop_cm.__aexit__(None, None, None)
            return states

        states = asyncio.run(scenario())
        self.assertEqual(states, {"s_loop": "waiting_for_agent"})
        with mock.patch.object(broker_mod, "_broker", broker), \
                mock.patch.object(self.api, "ws_manager", manager):
            body = self.client.get("/agent-sessions/live", params={"project_id": "p1"}).json()
        self.assertEqual(body, {"project_id": "p1", "session_ids": ["s_loop", "s_prov"]})


class ModelList(unittest.IsolatedAsyncioTestCase):
    async def test_no_provider_still_lists_the_loop_model(self):
        with mock.patch.dict(os.environ, {"AGENT_IN_THE_LOOP_ENABLED": "true"}):
            groups = await fetch_all_models(None)
        self.assertEqual(list(groups), ["Agent in the Loop"])
        self.assertEqual(groups["Agent in the Loop"][0]["id"], "loop/mcp")
        self.assertEqual(groups["Agent in the Loop"][0]["name"], "Agent in the Loop")
        self.assertIsNone(groups["Agent in the Loop"][0]["context_length"])

    async def test_switch_off_lists_nothing_new(self):
        with mock.patch.dict(os.environ, {"AGENT_IN_THE_LOOP_ENABLED": "false"}):
            self.assertEqual(await fetch_all_models(None), {})
            groups = await fetch_all_models([{"providerType": "openai_compatible", "id": "c1",
                                              "name": "mine", "modelIdentifier": "m"}])
        self.assertEqual(list(groups), ["Custom"])

    async def test_with_providers_the_loop_group_is_added(self):
        with mock.patch.dict(os.environ, {"AGENT_IN_THE_LOOP_ENABLED": "true"}):
            groups = await fetch_all_models([{"providerType": "openai_compatible", "id": "c1",
                                              "name": "mine", "modelIdentifier": "m"}])
        self.assertEqual(list(groups), ["Custom", "Agent in the Loop"])


if __name__ == "__main__":
    unittest.main()
