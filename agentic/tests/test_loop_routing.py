"""loop/ ids route to the adapter in a chat run and are refused everywhere else."""
from __future__ import annotations

import os
import unittest
from contextlib import asynccontextmanager
from unittest import mock

from agent_in_the_loop.errors import LoopModelNotSupportedHere
from agent_in_the_loop.model import LoopChatModel
from orchestrator_helpers.llm_setup import llm_setup_failure, parse_model_provider, setup_llm

ON = {"AGENT_IN_THE_LOOP_ENABLED": "true"}
OFF = {"AGENT_IN_THE_LOOP_ENABLED": "false"}


class Routing(unittest.TestCase):
    def test_loop_prefix(self):
        self.assertEqual(parse_model_provider("loop/mcp"), ("loop", "mcp"))

    def test_existing_prefixes_unchanged(self):
        cases = {
            "custom/abc": ("custom", "abc"),
            "openai_compat/m": ("openai_compat", "m"),
            "openrouter/a/b": ("openrouter", "a/b"),
            "bedrock/x": ("bedrock", "x"),
            "deepseek/x": ("deepseek", "x"),
            "gemini/x": ("gemini", "x"),
            "glm/x": ("glm", "x"),
            "kimi/x": ("kimi", "x"),
            "qwen/x": ("qwen", "x"),
            "xai/x": ("xai", "x"),
            "mistral/x": ("mistral", "x"),
            "claude-opus-4-6": ("anthropic", "claude-opus-4-6"),
            "gpt-4o": ("openai", "gpt-4o"),
            "looper": ("openai", "looper"),
        }
        for model, expected in cases.items():
            with self.subTest(model=model):
                self.assertEqual(parse_model_provider(model), expected)


class SetupLlm(unittest.TestCase):
    def test_switch_on_builds_the_adapter_with_no_key(self):
        with mock.patch.dict(os.environ, ON):
            self.assertIsInstance(setup_llm("loop/mcp"), LoopChatModel)

    def test_switch_off_is_a_setup_failure_not_a_missing_key(self):
        with mock.patch.dict(os.environ, OFF):
            with self.assertRaises(ValueError) as ctx:
                setup_llm("loop/mcp")
        self.assertIn("turned off", str(ctx.exception))
        failure = llm_setup_failure("loop/mcp", ctx.exception)
        self.assertEqual(failure["code"], "llm_setup_failed")
        self.assertEqual(failure["model"], "loop/mcp")


class Builders(unittest.TestCase):
    def test_build_llm_from_providers_refuses(self):
        from llm_builder import build_llm_from_providers
        with mock.patch.dict(os.environ, ON):
            with self.assertRaises(LoopModelNotSupportedHere) as ctx:
                build_llm_from_providers("loop/mcp", [])
        self.assertEqual(ctx.exception.code, "loop_model_not_supported_here")


class Endpoints(unittest.TestCase):
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

    def post(self, path, body):
        # The master key: the /llm/* routes fail closed without one (step 1.16).
        master = "loop-routing-test-master-key"
        with mock.patch.dict(os.environ, {**ON, "INTERNAL_API_KEY": master}), \
                mock.patch("requests.get", side_effect=AssertionError("providers must not be fetched")):
            return self.client.post(path, json=body, headers={"x-internal-key": master})

    def assert_refused(self, resp):
        self.assertEqual(resp.status_code, 400, resp.text)
        body = resp.json()
        self.assertEqual(body["code"], "loop_model_not_supported_here")
        self.assertEqual(body["error"], LoopModelNotSupportedHere.message)

    def test_recon_ai_endpoint(self):
        self.assert_refused(self.post("/llm/ffuf-extensions", {
            "url": "https://target.example.com/", "headers": {}, "model": "loop/mcp",
            "max_extensions": 4, "user_id": "u1"}))

    def test_feature_endpoint(self):
        self.assert_refused(self.post("/command-whisperer", {
            "prompt": "list files", "session_type": "shell", "project_id": "p1",
            "user_id": "u1", "model": "loop/mcp"}))

    def test_build_llm_for_user_refuses_a_loop_project_model(self):
        with mock.patch("project_settings.get_settings", return_value={"OPENAI_MODEL": "loop/mcp"}):
            with self.assertRaises(LoopModelNotSupportedHere):
                self.api._build_llm_for_user("u1")

    def test_build_llm_with_model_for_user_refuses_before_any_fetch(self):
        with mock.patch("requests.get", side_effect=AssertionError("no fetch")):
            with self.assertRaises(LoopModelNotSupportedHere):
                self.api._build_llm_with_model_for_user("loop/mcp", "u1")


if __name__ == "__main__":
    unittest.main()
