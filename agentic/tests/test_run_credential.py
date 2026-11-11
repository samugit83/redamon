"""
Run credentials: what the sandbox's two clients present instead of the scanner key (HD-19, DV-28).

The agent mints one for each proxy_brain run (aud "traffic", 15 minutes) and one
for each Kali terminal connection (aud "graph", 12 hours). It is the REDAMON_CTX
tag's shape, b64url(canonical JSON).b64url(HMAC-SHA256) with redamon_ctx's
base64url helpers, signed with hmac(INTERNAL_API_KEY, "redamon-run-credential-v1")
rather than the master key itself, so it never verifies as a ctx tag, a job
credential or the other way round. It names its audience and expires; a weak
master key mints and verifies nothing.

Run: ./agentic/run_tests.sh tests/test_run_credential.py
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

import machine_credential as mc  # noqa: E402
import redamon_ctx  # noqa: E402

MASTER = "master-key-for-run-credential-tests"
NOW = 1_800_000_000


def _env(master=MASTER):
    return mock.patch.dict(os.environ, {"INTERNAL_API_KEY": master})


def _refusal(test, token, aud, now, code):
    with test.assertRaises(mc.CredentialRefused) as cm:
        mc.verify_run_credential(token, aud, now=now)
    test.assertEqual(cm.exception.code, code)


class RoundTrip(unittest.TestCase):
    def test_round_trip(self):
        with _env():
            token = mc.mint_run_credential("traffic", "u1", "p1", "run-1", 900, now=NOW)
            claims = mc.verify_run_credential(token, "traffic", now=NOW + 899)
        self.assertEqual(claims, {"aud": "traffic", "ten": "u1", "pid": "p1", "run": "run-1", "exp": NOW + 900})

    def test_the_two_lifetimes(self):
        self.assertEqual(mc.TRAFFIC_TTL_SECONDS, 15 * 60)
        self.assertEqual(mc.TERMINAL_TTL_SECONDS, 12 * 60 * 60)

    def test_expired_refused(self):
        with _env():
            token = mc.mint_run_credential("graph", "u1", "p1", "term-1", 60, now=NOW)
            mc.verify_run_credential(token, "graph", now=NOW + 59)
            _refusal(self, token, "graph", NOW + 60, "expired")
            _refusal(self, token, "graph", NOW + 86_400, "expired")

    def test_other_audience_refused(self):
        with _env():
            graph = mc.mint_run_credential("graph", "u1", "p1", "term-1", 60, now=NOW)
            traffic = mc.mint_run_credential("traffic", "u1", "p1", "run-1", 60, now=NOW)
            _refusal(self, graph, "traffic", NOW, "wrong_audience")
            _refusal(self, traffic, "graph", NOW, "wrong_audience")

    def test_only_the_two_run_audiences_are_minted(self):
        with _env():
            for aud in ("scan", "", "agent", "kali-terminal"):
                with self.subTest(aud=aud), self.assertRaises(ValueError):
                    mc.mint_run_credential(aud, "u1", "p1", "run-1", 60, now=NOW)

    def test_a_credential_needs_its_tenant_project_and_run(self):
        with _env():
            for ten, pid, run in (("", "p1", "r"), ("u1", "", "r"), ("u1", "p1", "")):
                with self.subTest(ten=ten, pid=pid, run=run), self.assertRaises(ValueError):
                    mc.mint_run_credential("graph", ten, pid, run, 60, now=NOW)
            key = mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL)
            no_tenant = mc.mint({"aud": "graph", "pid": "p1", "run": "r", "exp": NOW + 60}, key)
            _refusal(self, no_tenant, "graph", NOW, "missing_claims")
            no_run = mc.mint({"aud": "graph", "ten": "u1", "pid": "p1", "exp": NOW + 60}, key)
            _refusal(self, no_run, "graph", NOW, "missing_claims")


class Tampering(unittest.TestCase):
    def setUp(self):
        self._e = _env()
        self._e.start()
        self.token = mc.mint_run_credential("graph", "u1", "p1", "term-1", 600, now=NOW)

    def tearDown(self):
        self._e.stop()

    def test_tampered_refused(self):
        body, sig = self.token.split(".")
        claims = json.loads(redamon_ctx._b64u_decode(body))
        claims["ten"] = "victim"
        forged_body = redamon_ctx._b64u_encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        _refusal(self, f"{forged_body}.{sig}", "graph", NOW, "bad_signature")
        _refusal(self, f"{body}.{sig[:-4]}AAAA", "graph", NOW, "bad_signature")

    def test_another_master_key_refused(self):
        with _env("another-master-key"):
            _refusal(self, self.token, "graph", NOW, "bad_signature")

    def test_malformed_refused(self):
        for bad in ("", "no-dot", "a.b.c", ".", "%%%.%%%", "x" * 5000 + ".y", None, 42):
            with self.subTest(token=str(bad)[:20]):
                _refusal(self, bad, "graph", NOW, "malformed")

    def test_unsigned_extra_claims_cannot_ride_along(self):
        key = mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL)
        raw = json.dumps({"aud": "graph", "exp": NOW + 60, "pid": "p1", "role": "admin", "run": "r", "ten": "u1"},
                         sort_keys=True, separators=(",", ":")).encode()
        token = redamon_ctx._b64u_encode(raw) + "." + redamon_ctx._b64u_encode(
            hmac.new(key, raw, hashlib.sha256).digest())
        _refusal(self, token, "graph", NOW, "malformed")

    def test_a_non_integer_expiry_is_refused(self):
        key = mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL)
        for exp in (str(NOW + 60), float(NOW + 60), True):
            with self.subTest(exp=exp):
                token = mc.mint({"aud": "graph", "ten": "u1", "pid": "p1", "run": "r", "exp": exp}, key)
                _refusal(self, token, "graph", NOW, "malformed")


class OneKeyPerKind(unittest.TestCase):
    def test_a_redamon_ctx_tag_is_not_a_run_credential(self):
        with _env():
            tag = redamon_ctx.sign_tag({"source": "agent", "user_id": "u1", "project_id": "p1"}, MASTER)
            _refusal(self, tag, "graph", NOW, "bad_signature")

    def test_a_job_credential_is_not_a_run_credential(self):
        with _env():
            job = mc.mint({"aud": "graph", "ten": "u1", "pid": "p1", "run": "r", "exp": NOW + 60},
                          mc.derive_key(MASTER, mc.JOB_CREDENTIAL_LABEL))
            _refusal(self, job, "graph", NOW, "bad_signature")

    def test_the_key_is_derived_never_the_master_itself(self):
        key = mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL)
        self.assertEqual(key, hmac.new(MASTER.encode(), b"redamon-run-credential-v1", hashlib.sha256).digest())
        self.assertNotEqual(key, MASTER.encode())
        self.assertNotEqual(key, mc.derive_key(MASTER, mc.JOB_CREDENTIAL_LABEL))


class WeakMasterKey(unittest.TestCase):
    def test_weak_master_key_refuses_to_mint(self):
        for weak in ("", "changeme"):
            with self.subTest(master=weak), _env(weak):
                with self.assertRaises(mc.CredentialRefused) as cm:
                    mc.mint_run_credential("graph", "u1", "p1", "r", 60, now=NOW)
                self.assertEqual(cm.exception.code, "weak_master_key")

    def test_weak_master_key_refuses_to_verify(self):
        with _env():
            token = mc.mint_run_credential("graph", "u1", "p1", "r", 60, now=NOW)
        for weak in ("", "changeme"):
            with self.subTest(master=weak), _env(weak):
                _refusal(self, token, "graph", NOW, "weak_master_key")


class SignedWithTheRedamonCtxHelpers(unittest.TestCase):
    def test_signed_with_the_redamon_ctx_helpers(self):
        self.assertIs(mc._b64u_encode, redamon_ctx._b64u_encode)
        self.assertIs(mc._b64u_decode, redamon_ctx._b64u_decode)
        with _env():
            token = mc.mint_run_credential("traffic", "u1", "p1", "run-1", 900, now=NOW)
        body, sig = token.split(".")
        raw = redamon_ctx._b64u_decode(body)
        # Canonical JSON, as the ctx tag: sorted keys, compact separators.
        self.assertEqual(raw, json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")).encode())
        expected = hmac.new(mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL), raw, hashlib.sha256).digest()
        self.assertEqual(redamon_ctx._b64u_decode(sig), expected)
        self.assertNotIn("=", token)


# --- the terminal proxy mints one per connection --------------------------------
try:
    import websocket_api  # noqa: F401
    from fastapi.testclient import TestClient
    _HAVE_APP = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE_APP = False

SECRET = "d" * 64


def _ticket(aud="kali-terminal", sub="uT", pid="pT", sid="sT"):
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"sub": sub, "pid": pid, "sid": sid, "aud": aud,
                           "iat": int(time.time()), "exp": int(time.time()) + 60}).encode())
    sig = hmac.new(SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


class _EchoKali:
    """Stands in for the sandbox's terminal server: echoes what the proxy sends."""

    def __init__(self):
        import asyncio
        self.queue = asyncio.Queue()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, message):
        await self.queue.put(message)

    def __aiter__(self):
        return self

    async def __anext__(self):
        return await self.queue.get()


@unittest.skipUnless(_HAVE_APP, "agent deps unavailable (run in-container)")
class TheTerminalProxyMintsAGraphCredential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with mock.patch("api.lifespan", fake_lifespan):
            import api as api_module
        cls.api = api_module
        cls.client = TestClient(api_module.app)

    def setUp(self):
        self._e = mock.patch.dict(os.environ, {
            "INTERNAL_API_KEY": MASTER, "AGENT_WS_TICKET_SECRET": SECRET, "MCP_AUTH_TOKEN": "mcp-token-for-test",
        })
        self._e.start()

    def tearDown(self):
        self._e.stop()

    def _open(self, **ticket):
        connect = mock.MagicMock(side_effect=lambda *a, **k: _EchoKali())
        with mock.patch.object(self.api.websockets, "connect", connect):
            with self.client.websocket_connect(f"/ws/kali-terminal?ticket={_ticket(**ticket)}") as ws:
                ws.send_text("hello")
                self.assertEqual(ws.receive_text(), "hello")
        return connect.call_args

    def test_the_proxy_hands_a_graph_credential_bound_to_the_tickets_user_and_project(self):
        before = int(time.time())
        call = self._open(sub="uT", pid="pT")
        headers = call.kwargs["additional_headers"]
        self.assertEqual(headers["Authorization"], "Bearer mcp-token-for-test")
        token = headers["X-Redamon-Run"]
        claims = mc.verify_run_credential(token, "graph")
        self.assertEqual((claims["aud"], claims["ten"], claims["pid"]), ("graph", "uT", "pT"))
        self.assertTrue(claims["run"])
        self.assertGreaterEqual(claims["exp"], before + mc.TERMINAL_TTL_SECONDS)
        self.assertLessEqual(claims["exp"], int(time.time()) + mc.TERMINAL_TTL_SECONDS)
        # Never in the query, which lands in access logs.
        self.assertNotIn(token, call.args[0])
        with self.assertRaises(mc.CredentialRefused):
            mc.verify_run_credential(token, "traffic")

    def test_each_connection_gets_its_own_run_id(self):
        first = mc.verify_run_credential(self._open().kwargs["additional_headers"]["X-Redamon-Run"], "graph")
        second = mc.verify_run_credential(self._open().kwargs["additional_headers"]["X-Redamon-Run"], "graph")
        self.assertNotEqual(first["run"], second["run"])

    def test_no_credential_without_a_master_key_the_terminal_still_opens(self):
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "changeme"}):
            call = self._open()
        self.assertEqual(call.kwargs["additional_headers"], {"Authorization": "Bearer mcp-token-for-test"})

    def test_the_credential_works_while_its_terminal_is_open_and_dies_when_it_closes(self):
        """HD-19: the proxy records the credential's run on its socket; /graph/exec honours
        the credential only while that socket is registered."""
        from fastapi.responses import JSONResponse

        ran = []

        def respond(final, params):
            ran.append(params)
            return JSONResponse(content={"records": []})

        def graph(token):
            return self.client.post("/graph/exec", headers={"X-Redamon-Run": token},
                                    json={"op": "types", "user_id": "uT", "project_id": "pT"})

        connect = mock.MagicMock(side_effect=lambda *a, **k: _EchoKali())
        with mock.patch.object(self.api.websockets, "connect", connect), \
                mock.patch.object(self.api, "_graph_exec_respond", side_effect=respond):
            with self.client.websocket_connect(f"/ws/kali-terminal?ticket={_ticket(sub='uT', pid='pT')}") as ws:
                ws.send_text("hello")
                self.assertEqual(ws.receive_text(), "hello")
                token = connect.call_args.kwargs["additional_headers"]["X-Redamon-Run"]
                run = mc.verify_run_credential(token, "graph")["run"]
                [entry] = [e for e in self.api.PROXIED_SOCKETS.matching(kinds=["kali-terminal"], user_id="uT")]
                self.assertEqual(entry.run, run)
                open_res = graph(token)
            closed_res = None
            for _ in range(50):  # the proxy's finally forgets the socket once the browser side has gone
                closed_res = graph(token)
                if closed_res.status_code != 200:
                    break
                time.sleep(0.05)
        self.assertEqual(open_res.status_code, 200, open_res.text)
        self.assertEqual(ran[0], {"tenant_user_id": "uT", "tenant_project_id": "pT"})
        self.assertEqual(closed_res.status_code, 401, closed_res.text)
        self.assertEqual(closed_res.json()["detail"]["code"], "run_credential_closed")
        self.assertEqual(self.api.PROXIED_SOCKETS.matching(kinds=["kali-terminal"], user_id="uT"), [])

    def test_a_terminal_opened_without_a_credential_records_no_run(self):
        connect = mock.MagicMock(side_effect=lambda *a, **k: _EchoKali())
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "changeme"}), \
                mock.patch.object(self.api.websockets, "connect", connect):
            with self.client.websocket_connect(f"/ws/kali-terminal?ticket={_ticket(sub='uN', pid='pN')}") as ws:
                ws.send_text("hello")
                self.assertEqual(ws.receive_text(), "hello")
                [entry] = self.api.PROXIED_SOCKETS.matching(kinds=["kali-terminal"], user_id="uN")
                self.assertIsNone(entry.run)


if __name__ == "__main__":
    unittest.main(verbosity=2)
