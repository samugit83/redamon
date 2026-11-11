"""/llm-provider/test against a local OpenAI-compatible stub that rejects temperature.

The two layers that keep Test Connection working for a model that rejects
``temperature=0``: an OpenAI reasoning family is built without it (one request),
and any other model is healed by ``retry_llm_call`` (a second request without
it). The stub answers with each provider's error text as recorded in
orchestrator_helpers/llm_retry.py. Assertions are on the requests the stub saw.

Run with: python -m unittest tests.test_llm_provider_test_self_heal -v
"""

import json
import os
import sys
import threading
import unittest
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

# /llm-provider/test takes the configured master key only (NF-01, step 1.9): every request
# here carries it; test_scanner_key_scope.py covers the refusals.
MASTER = "step19-master-key"
MASTER_HEADERS = {"x-internal-key": MASTER}
_master_env = patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})


def setUpModule():
    _master_env.start()


def tearDownModule():
    _master_env.stop()

_OPENAI_TEMPERATURE_ERROR = (
    "Unsupported value: 'temperature' does not support 0 with this model. "
    "Only the default (1) value is supported."
)
_REJECTIONS = {
    "gpt-6-luna": _OPENAI_TEMPERATURE_ERROR,
    "deepseek-reasoner": "deepseek-reasoner does not support the parameter `temperature`",
    "kimi-k3": "invalid temperature: only 1 is allowed for this model.",
}
_ABSENT = "<absent>"


class _StubHandler(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *args):
        pass

    def _reject(self, message):
        raw = json.dumps({"error": {"message": message, "type": "invalid_request_error"}}).encode()
        self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        model = body["model"]
        _StubHandler.seen.append(body.get("temperature", _ABSENT))
        if model == "missing-model":
            return self._reject("The model `missing-model` does not exist")
        if model == "busy-model":
            raw = json.dumps({"error": {
                "message": "Rate limit reached for busy-model on requests per min (RPM). "
                           "Please try again in 20s.",
                "type": "requests", "code": "rate_limit_exceeded"}}).encode()
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            # The SDK's own retries off, so every request seen is one of ours.
            self.send_header("x-should-retry", "false")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if model in _REJECTIONS and body.get("temperature", 1) != 1:
            return self._reject(_REJECTIONS[model])
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        chunk = {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": model,
                 "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hello."},
                              "finish_reason": "stop"}]}
        self.wfile.write(f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n".encode())


class ProviderTestSelfHealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            from fastapi.testclient import TestClient
            cls.client = TestClient(api_module.app, headers=MASTER_HEADERS)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _StubHandler.seen = []

    def _test_connection(self, model):
        resp = self.client.post("/llm-provider/test", json={
            "providerType": "openai_compatible",
            "apiKey": "fake-key",
            "baseUrl": self.base_url,
            "modelIdentifier": model,
        })
        return resp.json()

    def test_openai_reasoning_model_is_built_without_temperature(self):
        self.assertTrue(self._test_connection("gpt-6-luna")["success"])
        self.assertEqual(_StubHandler.seen, [_ABSENT])

    def test_other_models_rejecting_temperature_are_healed(self):
        for model in ("deepseek-reasoner", "kimi-k3"):
            with self.subTest(model=model):
                _StubHandler.seen = []
                self.assertTrue(self._test_connection(model)["success"])
                self.assertEqual(_StubHandler.seen, [0, _ABSENT])

    def test_classic_model_keeps_temperature_zero(self):
        self.assertTrue(self._test_connection("gpt-4o")["success"])
        self.assertEqual(_StubHandler.seen, [0])

    def test_the_anthropic_test_uses_claude_opus_5(self):
        # claude-opus-4-6 failed the test once the SDK sent API version
        # 2026-10-21 with temperature; Opus 5 is the model the person asked for.
        from langchain_core.messages import AIMessage
        built = []

        class _Answers:
            async def ainvoke(self, _messages):
                return AIMessage(content="Hello.")

        def fake_setup(model, **kwargs):
            built.append((model, kwargs.get("anthropic_api_key")))
            return _Answers()

        with patch("orchestrator_helpers.llm_setup.setup_llm", fake_setup):
            resp = self.client.post("/llm-provider/test", json={
                "providerType": "anthropic", "apiKey": "fake-key"})
        self.assertTrue(resp.json()["success"])
        self.assertEqual(built, [("claude-opus-5", "fake-key")])

    def test_a_rate_limit_is_reported_at_once_not_waited_out(self):
        data = self._test_connection("busy-model")
        self.assertFalse(data["success"])
        self.assertEqual(_StubHandler.seen, [0], "one request: no 20 s wait, no retry")

    def test_unrelated_rejection_still_fails_without_retry(self):
        data = self._test_connection("missing-model")
        self.assertFalse(data["success"])
        self.assertEqual(_StubHandler.seen, [0])


if __name__ == "__main__":
    unittest.main()
