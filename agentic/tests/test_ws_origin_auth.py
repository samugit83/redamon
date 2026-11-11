"""
STRIDE S3/S4 — WebSocket same-origin check + fail-closed ticket gate.

Pure, host-runnable: exercises ws_ticket.check_ws_origin and authorize_ws (the
shared gate the kali-terminal proxy and both cypherfix handlers now enforce).

Run: python -m unittest tests.test_ws_origin_auth -v   (from agentic/)
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from pathlib import Path

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from ws_ticket import check_ws_origin, authorize_ws  # noqa: E402

SECRET = "0" * 64


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sign(claims, secret=SECRET):
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = _b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def _claims(**over):
    base = {"sub": "u", "pid": "p", "sid": "s", "aud": "kali-terminal",
            "iat": int(time.time()), "exp": int(time.time()) + 60}
    base.update(over)
    return base


class OriginCheck(unittest.TestCase):
    def test_missing_origin_allowed(self):
        # Non-browser clients send no Origin; CSWSH is browser-only.
        self.assertTrue(check_ws_origin(None, "host:8090", []))

    def test_same_host_cross_port_allowed(self):
        # Local LAN: UI at :3000, agent at :8090, same host -> allowed.
        self.assertTrue(check_ws_origin("http://192.168.1.10:3000", "192.168.1.10:8090", []))

    def test_public_single_origin_allowed(self):
        self.assertTrue(check_ws_origin("https://redamon.example.com", "redamon.example.com", []))

    def test_cross_site_rejected(self):
        self.assertFalse(check_ws_origin("https://evil.example.com", "redamon.example.com", []))

    def test_extra_allowlist_superset(self):
        self.assertTrue(check_ws_origin("http://localhost:3000", "agent:8090",
                                        ["http://localhost:3000"]))


class AuthorizeGate(unittest.TestCase):
    def setUp(self):
        self._prev = os.environ.get("AGENT_WS_TICKET_SECRET")
        os.environ["AGENT_WS_TICKET_SECRET"] = SECRET

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("AGENT_WS_TICKET_SECRET", None)
        else:
            os.environ["AGENT_WS_TICKET_SECRET"] = self._prev

    def test_requires_ticket(self):
        ok, claims, _ = authorize_ws("https://x", "x", None, [], aud="kali-terminal")
        self.assertFalse(ok)
        self.assertIsNone(claims)

    def test_bad_origin_rejected_before_ticket(self):
        ok, _, reason = authorize_ws("https://evil", "good", _sign(_claims()), [], aud="kali-terminal")
        self.assertFalse(ok)
        self.assertIn("origin", reason)

    def test_valid_ticket_and_origin(self):
        ok, claims, _ = authorize_ws("https://good", "good",
                                     _sign(_claims(sub="real", pid="rp", sid="rs")), [], aud="kali-terminal")
        self.assertTrue(ok)
        self.assertEqual(claims["sub"], "real")

    def test_fail_closed_when_secret_unset(self):
        os.environ.pop("AGENT_WS_TICKET_SECRET", None)
        ok, _, reason = authorize_ws("https://good", "good", _sign(_claims()), [], aud="kali-terminal")
        self.assertFalse(ok)
        self.assertIn("not configured", reason)


class CypherfixHandlerWiring(unittest.TestCase):
    """S4: both cypherfix handlers must gate (authorize_ws) BEFORE accept() and
    bind identity from claims, not the self-asserted init frame."""

    def _read(self, rel):
        return (Path(_AGENTIC_DIR) / rel).read_text()

    def test_triage_gates_before_accept(self):
        src = self._read("cypherfix_triage/websocket_handler.py")
        i_auth = src.index("authorize_ws(")
        i_accept = src.index("await websocket.accept()")
        self.assertLess(i_auth, i_accept, "authorize_ws must run before accept()")
        self.assertIn('str(_claims["sub"])', src)
        self.assertNotIn('payload.get("user_id"', src)

    def test_codefix_gates_before_accept(self):
        src = self._read("cypherfix_codefix/websocket_handler.py")
        i_auth = src.index("authorize_ws(")
        i_accept = src.index("await websocket.accept()")
        self.assertLess(i_auth, i_accept, "authorize_ws must run before accept()")
        self.assertIn('str(_claims["sub"])', src)
        self.assertNotIn('payload.get("user_id"', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
