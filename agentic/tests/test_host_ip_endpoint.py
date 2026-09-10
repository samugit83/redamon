"""Tests for the agent GET /host-ip endpoint (issue #180).

It returns the Docker host's LAN IP (from the HOST_LAN_IP env var) so the webapp
can suggest it as the reverse-shell LHOST. Uses fastapi.testclient with a patched
lifespan so importing api does not spin a real orchestrator / Neo4j / kali-sandbox.

Run: ./agentic/run_tests.sh tests/test_host_ip_endpoint.py
"""

import os
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


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


class HostIpEndpointTests(_AppTestBase):
    def test_returns_env_value(self):
        with patch.dict(os.environ, {"HOST_LAN_IP": "192.168.1.50"}, clear=False):
            resp = self.client.get("/host-ip")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"detectedHostIp": "192.168.1.50"})

    def test_empty_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HOST_LAN_IP", None)
            resp = self.client.get("/host-ip")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"detectedHostIp": ""})

    def test_whitespace_is_trimmed(self):
        with patch.dict(os.environ, {"HOST_LAN_IP": "  10.0.0.7 \n"}, clear=False):
            resp = self.client.get("/host-ip")
        self.assertEqual(resp.json(), {"detectedHostIp": "10.0.0.7"})


if __name__ == "__main__":
    unittest.main()
