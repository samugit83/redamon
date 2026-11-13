"""The terminal's graph credential names the person beside the owner (5.3 review, finding 3; C1).

redagraph in the Kali terminal presents a graph run credential minted by the
/ws/kali-terminal proxy. Its `ten` is the project's owner: the graph and the
provider key are the owner's. Once a collaborator may open the terminal (W+X,
5.2b), a `redagraph ask` spends the owner's key on the collaborator's behalf, so
the credential also carries the person (`sub`, from the ticket's `sub`) and an
admin acting as them (`act`): the spend is attributed to that person, 5.6's
consent can be checked against them, and the billed gate counts the call against
both the owner and the person (the stricter refuses, as 6.11's budget rule).
A job credential never carries them.

Runs in the agent image: ./agentic/run_tests.sh tests/test_terminal_credential_actor.py
"""
from __future__ import annotations

import asyncio
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

_AGENTIC = Path(__file__).resolve().parents[1]
for _p in (str(_AGENTIC), str(_AGENTIC.parent / "recon_orchestrator")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import machine_credential as mc  # noqa: E402

MASTER = "terminal-actor-test-master-key-0123456789"
SECRET = "e" * 64


def _env(master: str = MASTER):
    return mock.patch.dict(os.environ, {"INTERNAL_API_KEY": master})


class TheRunCredentialCarriesThePerson(unittest.TestCase):
    def setUp(self):
        self._e = _env()
        self._e.start()
        self.addCleanup(self._e.stop)

    def test_the_person_and_the_admin_behind_them_ride_along(self):
        token = mc.mint_run_credential("graph", "owner-1", "p1", "r1", 60, actor="collab-1", real_actor="admin-1")
        claims = mc.verify_run_credential(token, "graph")
        self.assertEqual((claims["ten"], claims["sub"], claims["act"]), ("owner-1", "collab-1", "admin-1"))

    def test_without_a_person_the_credential_is_as_before(self):
        claims = mc.verify_run_credential(mc.mint_run_credential("traffic", "owner-1", "p1", "r1", 60), "traffic")
        self.assertNotIn("sub", claims)
        self.assertNotIn("act", claims)

    def test_the_person_is_signed(self):
        token = mc.mint_run_credential("graph", "owner-1", "p1", "r1", 60, actor="collab-1")
        body, sig = token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        claims["sub"] = "owner-1"
        forged = mc._canonical(claims)
        forged_body = base64.urlsafe_b64encode(forged).rstrip(b"=").decode()
        with self.assertRaises(mc.CredentialRefused) as ctx:
            mc.verify_run_credential(f"{forged_body}.{sig}", "graph")
        self.assertEqual(ctx.exception.code, "bad_signature")

    def test_an_empty_or_non_string_person_never_verifies(self):
        key = mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL)
        base = {"aud": "graph", "ten": "owner-1", "pid": "p1", "run": "r1", "exp": int(time.time()) + 60}
        for bad in ({"sub": ""}, {"sub": 7}, {"act": ""}, {"act": ["admin"]}):
            with self.subTest(bad):
                with self.assertRaises(mc.CredentialRefused) as ctx:
                    mc.verify_run_credential(mc.mint({**base, **bad}, key), "graph")
                self.assertIn(ctx.exception.code, ("missing_claims", "malformed"))

    def test_a_job_credential_never_carries_a_person(self):
        """The webapp and orchestrator twins sign aud/ten/pid/run/job/exp only; a job token with
        a person is refused by both Python verifiers alike."""
        import job_credential as orch
        key = mc.derive_key(MASTER, mc.JOB_CREDENTIAL_LABEL)
        good = {"aud": "scan", "ten": "owner-1", "pid": "p1", "job": "j1", "exp": int(time.time()) + 60}
        self.assertEqual(mc.verify_job_credential(mc.mint(good, key))["ten"], "owner-1")
        for extra in ({"sub": "collab-1"}, {"act": "admin-1"}):
            with self.subTest(extra):
                token = mc.mint({**good, **extra}, key)
                with self.assertRaises(mc.CredentialRefused) as agent:
                    mc.verify_job_credential(token)
                with self.assertRaises(orch.JobCredentialRefused) as orchestrator:
                    orch.verify_job_credential(token, "p1")
                self.assertEqual(agent.exception.code, orchestrator.exception.code)


def _ticket_claims(**over):
    claims = {"aud": "kali-terminal", "sub": "collab-1", "ten": "owner-1", "pid": "p1", "sid": "s1"}
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not None}


try:
    from fastapi import HTTPException
    from starlette.requests import Request

    with _env():
        @asynccontextmanager
        async def _no_lifespan(_app):
            yield

        with mock.patch("api.lifespan", _no_lifespan):
            import api  # noqa: E402
    import llm_guard  # noqa: E402
    _HAVE_APP = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE_APP = False


@unittest.skipUnless(_HAVE_APP, "agent deps unavailable (run in-container)")
class TheTerminalNamesWhoOpenedIt(unittest.TestCase):
    def setUp(self):
        self._e = _env()
        self._e.start()
        self.addCleanup(self._e.stop)

    def _minted(self, **ticket):
        token, run = api._terminal_run_credential(_ticket_claims(**ticket))
        self.assertTrue(token)
        claims = mc.verify_run_credential(token, "graph")
        self.assertEqual(claims["run"], run)
        return claims

    def test_a_collaborators_terminal_names_the_owner_and_the_collaborator(self):
        claims = self._minted()
        self.assertEqual((claims["ten"], claims["sub"], claims["pid"]), ("owner-1", "collab-1", "p1"))
        self.assertNotIn("act", claims)

    def test_an_owners_terminal_names_the_owner_twice(self):
        claims = self._minted(sub="owner-1")
        self.assertEqual((claims["ten"], claims["sub"]), ("owner-1", "owner-1"))

    def test_a_ticket_without_ten_is_its_persons_own_project(self):
        claims = self._minted(ten=None, sub="owner-1")
        self.assertEqual((claims["ten"], claims["sub"]), ("owner-1", "owner-1"))

    def test_an_admin_acting_as_the_person_is_named_too(self):
        claims = self._minted(act="admin-1")
        self.assertEqual((claims["sub"], claims["act"]), ("collab-1", "admin-1"))

    def test_the_proxy_hands_that_credential_to_the_shell(self):
        from fastapi.testclient import TestClient

        def b64(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = b64(json.dumps({**_ticket_claims(), "iat": int(time.time()), "exp": int(time.time()) + 60}).encode())
        sig = hmac.new(SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
        ticket = f"{head}.{body}.{b64(sig)}"

        class _Echo:
            def __init__(self):
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

        connect = mock.MagicMock(side_effect=lambda *a, **k: _Echo())
        with mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET, "MCP_AUTH_TOKEN": "mcp-t"}), \
                mock.patch.object(api.websockets, "connect", connect):
            with TestClient(api.app).websocket_connect(f"/ws/kali-terminal?ticket={ticket}") as ws:
                ws.send_text("hi")
                self.assertEqual(ws.receive_text(), "hi")
        claims = mc.verify_run_credential(connect.call_args.kwargs["additional_headers"]["X-Redamon-Run"], "graph")
        self.assertEqual((claims["ten"], claims["sub"]), ("owner-1", "collab-1"))
        self.assertIn("user_id=owner-1", connect.call_args.args[0])


def _request(token: str) -> "Request":
    return Request({"type": "http", "method": "POST", "path": "/text-to-cypher", "query_string": b"",
                    "headers": [(llm_guard.RUN_CREDENTIAL_HEADER.encode(), token.encode())],
                    "client": ("127.0.0.1", 1234)})


@unittest.skipUnless(_HAVE_APP, "agent deps unavailable (run in-container)")
class TheBilledGateCountsOwnerAndPerson(unittest.TestCase):
    def setUp(self):
        self._e = _env()
        self._e.start()
        self.addCleanup(self._e.stop)
        live = mock.patch.dict(llm_guard._RUN_LIVENESS, {"graph": lambda claims: True})
        live.start()
        self.addCleanup(live.stop)
        llm_guard.reset_state()
        self.addCleanup(llm_guard.reset_state)
        self.gate = llm_guard.require_master_or_run_credential("graph", billed=True)

    def _token(self, actor=None):
        return mc.mint_run_credential("graph", "owner-1", "p1", "r1", 60, actor=actor)

    def test_a_collaborators_call_counts_against_owner_and_collaborator(self):
        with mock.patch.object(llm_guard, "_enforce_llm_limits") as enforce:
            claims = asyncio.run(self.gate(_request(self._token(actor="collab-1"))))
        self.assertEqual(claims["sub"], "collab-1")
        self.assertEqual(sorted(c.args[1] for c in enforce.call_args_list), ["collab-1", "owner-1"])

    def test_an_owners_call_counts_once(self):
        for actor in ("owner-1", None):
            with self.subTest(actor), mock.patch.object(llm_guard, "_enforce_llm_limits") as enforce:
                asyncio.run(self.gate(_request(self._token(actor=actor))))
            self.assertEqual([c.args[1] for c in enforce.call_args_list], ["owner-1"])

    def test_the_collaborators_spent_budget_refuses_on_the_owners_project(self):
        with mock.patch.object(llm_guard, "_daily_cap", llm_guard._DailyCap(1)):
            llm_guard._daily_cap.allow("collab-1")
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(self.gate(_request(self._token(actor="collab-1"))))
        self.assertEqual(ctx.exception.status_code, 429)

    def test_the_owners_spent_budget_refuses_the_collaborator_too(self):
        with mock.patch.object(llm_guard, "_daily_cap", llm_guard._DailyCap(1)):
            llm_guard._daily_cap.allow("owner-1")
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(self.gate(_request(self._token(actor="collab-1"))))
        self.assertEqual(ctx.exception.status_code, 429)

    def test_the_actor_of_a_credential(self):
        self.assertEqual(llm_guard.run_credential_actor({"ten": "owner-1", "sub": "collab-1"}), "collab-1")
        self.assertEqual(llm_guard.run_credential_actor({"ten": "owner-1"}), "owner-1")


@unittest.skipUnless(_HAVE_APP, "agent deps unavailable (run in-container)")
class TextToCypherSpendsTheOwnersKeyForThePerson(unittest.TestCase):
    def test_the_owners_key_and_graph_the_persons_name_in_the_log(self):
        body = api.TextToCypherRequest(question="list domains", user_id="body-user", project_id="body-p")
        claims = {"aud": "graph", "ten": "owner-1", "sub": "collab-1", "pid": "p1", "run": "r1", "exp": 0}
        build = mock.AsyncMock(return_value=object())
        generate = mock.AsyncMock(return_value="MATCH (d:Domain) RETURN d")
        with mock.patch.object(api, "_build_cypher_manager", build), \
                mock.patch.object(api, "_generate_validated_cypher", generate), \
                self.assertLogs("api", level="INFO") as logs:
            res = asyncio.run(api.text_to_cypher(body, run_cred=claims))
        self.assertEqual(res.status_code, 200)
        build.assert_awaited_once_with("owner-1", "p1")
        self.assertEqual(generate.await_args.args[2:4], ("owner-1", "p1"))
        line = next(m for m in logs.output if "text-to-cypher" in m and "run-credential" in m)
        self.assertIn("tenant=owner-1", line)
        self.assertIn("actor=collab-1", line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
