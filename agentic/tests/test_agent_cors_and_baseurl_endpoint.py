"""Integration tests for the agent API CORS scoping (I17) and the
/llm-provider/test baseUrl SSRF guard (I15/I16).

Uses fastapi.testclient with a patched lifespan so the import doesn't spin a
real orchestrator / Neo4j / kali-sandbox.

Run with: python -m unittest tests.test_agent_cors_and_baseurl_endpoint -v
"""

import os
import sys
import unittest
from contextlib import asynccontextmanager
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


class _AppTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module
            from fastapi.testclient import TestClient
            cls.client = TestClient(api_module.app)


class CorsScopingTests(_AppTestBase):
    """I17: wildcard CORS removed; only the webapp origin is reflected."""

    def test_allowed_origin_is_reflected(self):
        resp = self.client.get(
            "/health",
            headers={"Origin": "http://localhost:3000"},
        )
        self.assertEqual(
            resp.headers.get("access-control-allow-origin"),
            "http://localhost:3000",
        )

    def test_evil_origin_not_reflected(self):
        # A malicious site must NOT receive an ACAO echoing its origin.
        resp = self.client.get(
            "/health",
            headers={"Origin": "http://evil.example.com"},
        )
        acao = resp.headers.get("access-control-allow-origin")
        self.assertNotEqual(acao, "http://evil.example.com")
        self.assertNotEqual(acao, "*")

    def test_no_wildcard_in_app_config(self):
        origins = self.api_module._cors_origins
        self.assertNotIn("*", origins)
        self.assertIn("http://localhost:3000", origins)


class BaseUrlGuardEndpointTests(_AppTestBase):
    """I15/I16: /llm-provider/test rejects metadata + TLS-off-public baseUrls."""

    def _post(self, body):
        return self.client.post("/llm-provider/test", json=body, headers=MASTER_HEADERS)

    def test_metadata_baseurl_rejected_400(self):
        resp = self._post({
            "providerType": "openai_compatible",
            "baseUrl": "http://169.254.169.254/v1",
            "modelIdentifier": "x",
        })
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.json()["success"])

    def test_bad_scheme_rejected_400(self):
        resp = self._post({
            "providerType": "openai_compatible",
            "baseUrl": "file:///etc/passwd",
            "modelIdentifier": "x",
        })
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.json()["success"])

    def test_tls_off_public_rejected_400(self):
        resp = self._post({
            "providerType": "openai_compatible",
            "baseUrl": "https://8.8.8.8/v1",
            "modelIdentifier": "x",
            "sslVerify": False,
        })
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.json()["success"])

    def test_localhost_passes_guard_then_fails_on_connect(self):
        # A localhost Ollama URL must CLEAR the SSRF guard. With nothing
        # listening it then fails at the live request. Both a guard reject and a
        # connect failure return 400 here, so we assert on the message: it must
        # be a connection error, NOT one of the guard's rejection messages —
        # proving the legitimate self-hosted target was not blocked.
        resp = self._post({
            "providerType": "openai_compatible",
            "baseUrl": "http://127.0.0.1:11434/v1",
            "modelIdentifier": "x",
        })
        data = resp.json()
        self.assertFalse(data["success"])
        err = (data.get("error") or "").lower()
        self.assertNotIn("metadata", err)
        self.assertNotIn("blocked address", err)
        self.assertNotIn("must use http", err)
        self.assertNotIn("tls verification cannot be disabled", err)


if __name__ == "__main__":
    unittest.main()
