"""
Regression + unit tests for the /models endpoint API-key leak fix.

Pre-fix shape: `GET /models?providers=<URL-encoded JSON with apiKey>` — uvicorn
access logs persist the full query string to stdout / agent.log / docker logs.

Post-fix shape: `POST /models` with `{providers: [...]}` JSON body — uvicorn
does not log request bodies, so apiKey values never reach disk.

The tests below would fail pre-fix:
  - test_get_method_is_rejected: pre-fix returned 200; now 405.
  - test_post_with_providers_passes_body_through: pre-fix /models didn't accept
    POST at all, so this would 405 against the unfixed handler.

Run inside the agent container:
    python -m unittest tests.test_models_endpoint_security
"""
from __future__ import annotations

import asyncio
import os
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch, AsyncMock

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


CANARY_KEY = "sk-ant-api03-LEAK-CANARY-DO-NOT-LOG-XXXXXXXXXX"

# /models takes the configured master key only (NF-01, step 1.9): every request
# here carries it; test_scanner_key_scope.py covers the refusals.
MASTER = "models-endpoint-master-key"
_master_env = patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})


def setUpModule():
    _master_env.start()


def tearDownModule():
    _master_env.stop()


class ModelsEndpointSecurityTests(unittest.TestCase):
    """Confirm /models is POST-only and that apiKey-bearing payloads travel in
    the request body (not the URL)."""

    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module
            from fastapi.testclient import TestClient
            cls.TestClient = TestClient

    def _client(self):
        return self.TestClient(self.api_module.app, headers={"x-internal-key": MASTER})

    # ------------------------------------------------------------------
    # Regression: GET must not work — pre-fix this was the leak path.
    # ------------------------------------------------------------------

    def test_get_method_is_rejected(self):
        """GET /models with a `providers` query string must 405. Pre-fix it
        returned 200 and the query string (with apiKey) hit uvicorn access logs."""
        with patch(
            "orchestrator_helpers.model_providers.fetch_all_models",
            new=AsyncMock(return_value={}),
        ):
            r = self._client().get(
                "/models",
                params={"providers": f'[{{"apiKey": "{CANARY_KEY}"}}]'},
            )
        self.assertEqual(r.status_code, 405)

    def test_get_method_is_rejected_without_query(self):
        """Plain GET also 405s — the route is POST-only, period."""
        r = self._client().get("/models")
        self.assertEqual(r.status_code, 405)

    # ------------------------------------------------------------------
    # POST behavior — body is parsed and forwarded to fetch_all_models.
    # ------------------------------------------------------------------

    def test_post_with_empty_body_falls_back_to_env(self):
        """No body at all → fetch_all_models called with providers=None."""
        mock = AsyncMock(return_value={"anthropic": []})
        with patch("orchestrator_helpers.model_providers.fetch_all_models", new=mock):
            r = self._client().post("/models")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"anthropic": []})
        mock.assert_awaited_once_with(providers=None)

    def test_post_with_explicit_null_providers(self):
        """{providers: null} → fetch_all_models called with providers=None."""
        mock = AsyncMock(return_value={})
        with patch("orchestrator_helpers.model_providers.fetch_all_models", new=mock):
            r = self._client().post("/models", json={"providers": None})
        self.assertEqual(r.status_code, 200)
        mock.assert_awaited_once_with(providers=None)

    def test_post_with_providers_passes_body_through(self):
        """Providers list in body is forwarded verbatim to fetch_all_models."""
        providers_payload = [
            {
                "id": "p1",
                "userId": "u1",
                "providerType": "anthropic",
                "name": "Anthropic",
                "apiKey": CANARY_KEY,
            }
        ]
        mock = AsyncMock(return_value={"anthropic": [{"id": "claude-x"}]})
        with patch("orchestrator_helpers.model_providers.fetch_all_models", new=mock):
            r = self._client().post("/models", json={"providers": providers_payload})
        self.assertEqual(r.status_code, 200)
        mock.assert_awaited_once_with(providers=providers_payload)

    def test_post_with_malformed_body_returns_422(self):
        """Pydantic rejects non-list `providers` with a 422. Pre-fix the GET
        handler silently fell back to env on malformed JSON (less strict)."""
        r = self._client().post("/models", json={"providers": "not-a-list"})
        self.assertEqual(r.status_code, 422)

    # ------------------------------------------------------------------
    # Regression: the request that reaches the ASGI app must carry the
    # apiKey in its BODY, never in its URL / query string.
    # ------------------------------------------------------------------

    def test_apikey_never_appears_in_request_url(self):
        """End-to-end through TestClient: when a canary apiKey is sent inside
        the body, the recorded request URL/path/query never echoes it. This is
        what prevents uvicorn from access-logging the secret."""
        captured: dict = {}

        async def capture_and_return(providers):
            # Mirror what the route handler does — capture for assertion.
            captured["providers"] = providers
            return {}

        with patch(
            "orchestrator_helpers.model_providers.fetch_all_models",
            new=AsyncMock(side_effect=capture_and_return),
        ):
            client = self._client()
            r = client.post(
                "/models",
                json={
                    "providers": [
                        {"providerType": "anthropic", "apiKey": CANARY_KEY}
                    ]
                },
            )

        self.assertEqual(r.status_code, 200)
        # The body parsed cleanly → key is there.
        self.assertEqual(captured["providers"][0]["apiKey"], CANARY_KEY)
        # The request URL must NOT carry it.
        sent_url = str(r.request.url)
        self.assertNotIn(CANARY_KEY, sent_url)
        self.assertNotIn("apiKey", sent_url)
        self.assertNotIn("providers", sent_url)

    # ------------------------------------------------------------------
    # Route-registration regression: only POST should be registered.
    # ------------------------------------------------------------------

    def test_only_post_method_is_registered_for_models(self):
        """Inspect FastAPI's route table to confirm GET is gone for /models.
        This catches a future regression that adds an alias GET handler."""
        models_routes = [
            r for r in self.api_module.app.routes
            if getattr(r, "path", None) == "/models"
        ]
        self.assertEqual(len(models_routes), 1, "expected exactly one /models route")
        methods = models_routes[0].methods
        self.assertIn("POST", methods)
        self.assertNotIn("GET", methods)


if __name__ == "__main__":
    unittest.main()
