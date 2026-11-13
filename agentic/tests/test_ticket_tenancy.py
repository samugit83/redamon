"""
A ticket opens a socket only for the project's current owner, never during its transfer (review of
RBAC step 5.12, finding 3).

A WebSocket ticket names the project's owner as `ten` and lives 60 s, reusable until then. An ownership
transfer moves the project and its graph to a new owner; the webapp refuses new tickets while it holds
the project and closes the open sockets, but a ticket minted just before would still open a socket
afterwards (a leaving owner, or a collaborator whose ticket named the old owner) and write attack-chain
nodes under the old owner, splitting the graph again. So at connect, after the signature, the agent asks
Postgres who owns the project and whether a transfer holds it (`activation_state` `transferring` or
`transfer_split`, webapp lib/graphHold.ts), and refuses a ticket whose `ten` is not the owner, a project
that is gone, a transfer in progress, and a database it cannot ask (fail closed). Every socket: the agent's
own (`ws_ticket_tenant`) and the three proxied ones through `authorize_ws`. An agent with no DATABASE_URL
(unit tests, a hand-run agent; compose requires it) skips the check with a warning.

The TS minter's side (`ten` = owner, written on every ticket) is pinned by auth.wsTicket.test.ts and the
cross-runtime case by test_ws_ticket_interop.py.

Run: ./agentic/run_tests.sh tests/test_ticket_tenancy.py
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

import ws_ticket  # noqa: E402

try:
    import websocket_api  # noqa: F401
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

if _HAVE:
    from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager  # noqa: E402

SECRET = "t" * 64
OLD, NEW, COLLAB = "owner-old", "owner-new", "collab-1"
PID, SID = "p-moving", "s-1"
DSN = {"DATABASE_URL": "postgresql://rbac:rbac@db.invalid:5432/redamon"}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ticket(aud="agent", **claims) -> str:
    payload = {"sub": COLLAB, "pid": PID, "sid": SID, "aud": aud, "ten": OLD,
               "iat": int(time.time()), "exp": int(time.time()) + 60, **claims}
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    sig = hmac.new(SECRET.encode(), f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


def _claims(**over):
    return {"sub": COLLAB, "pid": PID, "sid": SID, "aud": "agent", "ten": OLD, **over}


class TheTenancyCheck(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, DSN)
        env.start()
        self.addCleanup(env.stop)

    def _with(self, row=None, error=None):
        def project(dsn, pid):
            self.asked = (dsn, pid)
            if error:
                raise error
            return row
        patcher = mock.patch.object(ws_ticket, "_project_tenancy", side_effect=project)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_owner_named_by_the_ticket_opens_its_socket(self):
        self._with(row=(OLD, "idle"))
        self.assertIsNone(ws_ticket.ticket_tenancy_refusal(_claims()))
        self.assertEqual(self.asked, (DSN["DATABASE_URL"], PID))

    def test_a_ticket_minted_before_the_transfer_names_the_old_owner_and_is_refused(self):
        self._with(row=(NEW, "idle"))
        with self.assertLogs("ws_ticket", level="WARNING") as logs:
            self.assertEqual(ws_ticket.ticket_tenancy_refusal(_claims()), "ticket tenant no longer owns the project")
        self.assertIn("[rbac] ticket refused", logs.output[0])

    def test_a_ticket_without_ten_is_the_person_s_and_must_be_the_owner_too(self):
        self._with(row=(OLD, "idle"))
        legacy = _claims(sub=OLD)
        del legacy["ten"]
        self.assertIsNone(ws_ticket.ticket_tenancy_refusal(legacy))
        collab = _claims()
        del collab["ten"]
        self.assertIsNotNone(ws_ticket.ticket_tenancy_refusal(collab))

    def test_refused_while_a_transfer_holds_the_project_even_for_its_owner(self):
        for state in ("transferring", "transfer_split"):
            self._with(row=(OLD, state))
            self.assertEqual(ws_ticket.ticket_tenancy_refusal(_claims()), "project ownership transfer in progress")

    def test_an_activation_refuses_nothing_here(self):
        self._with(row=(OLD, "activating"))
        self.assertIsNone(ws_ticket.ticket_tenancy_refusal(_claims()))

    def test_a_project_that_is_gone_is_refused(self):
        self._with(row=None)
        self.assertEqual(ws_ticket.ticket_tenancy_refusal(_claims()), "project not found")

    def test_a_database_that_cannot_be_asked_fails_closed(self):
        self._with(error=OSError("connection refused"))
        with self.assertLogs("ws_ticket", level="WARNING") as logs:
            self.assertEqual(ws_ticket.ticket_tenancy_refusal(_claims()), "tenancy could not be verified")
        self.assertNotIn("refused\n", logs.output[0])
        self.assertIn("OSError", logs.output[0])

    def test_no_database_configured_skips_the_check(self):
        with mock.patch.dict(os.environ, {"DATABASE_URL": ""}):
            with mock.patch.object(ws_ticket, "_project_tenancy") as asked:
                self.assertIsNone(ws_ticket.ticket_tenancy_refusal(_claims()))
        asked.assert_not_called()

    def test_the_query_reads_the_owner_and_the_lock_by_project_id(self):
        seen = {}

        class _Cursor:
            def fetchone(self):
                return (NEW, "transfer_split")

        class _Conn:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params):
                seen["sql"], seen["params"] = sql, params
                return _Cursor()

        fake = mock.MagicMock()
        fake.connect.return_value = _Conn()
        with mock.patch.dict(sys.modules, {"psycopg": fake}):
            self.assertEqual(ws_ticket._project_tenancy(DSN["DATABASE_URL"], PID), (NEW, "transfer_split"))
        self.assertEqual(seen["params"], (PID,))
        self.assertIn("SELECT user_id, activation_state FROM projects WHERE id = %s", seen["sql"])
        self.assertEqual(fake.connect.call_args.kwargs.get("connect_timeout"), 3)


class TheProxiedSockets(unittest.TestCase):
    def test_authorize_ws_refuses_a_stale_tenant_after_the_signature(self):
        with mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET, **DSN}), \
                mock.patch.object(ws_ticket, "_project_tenancy", return_value=(NEW, "idle")):
            ok, claims, reason = ws_ticket.authorize_ws(None, None, _ticket(aud="kali-terminal"), aud="kali-terminal")
        self.assertEqual((ok, claims, reason), (False, None, "ticket tenant no longer owns the project"))

    def test_authorize_ws_admits_the_current_owner(self):
        with mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET, **DSN}), \
                mock.patch.object(ws_ticket, "_project_tenancy", return_value=(OLD, "idle")):
            ok, claims, reason = ws_ticket.authorize_ws(None, None, _ticket(aud="cypherfix-codefix"), aud="cypherfix-codefix")
        self.assertTrue(ok)
        self.assertEqual(claims["ten"], OLD)

    def test_a_bad_signature_never_reaches_the_database(self):
        with mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": "x" * 64, **DSN}), \
                mock.patch.object(ws_ticket, "_project_tenancy") as asked:
            ok, _claims_, _reason = ws_ticket.authorize_ws(None, None, _ticket(aud="cypherfix-triage"), aud="cypherfix-triage")
        self.assertFalse(ok)
        asked.assert_not_called()


class _WS:
    def __init__(self):
        self.sent = []
        self.client = "test"
        self.closed = None

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheAgentSocket(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET, **DSN})
        env.start()
        self.addCleanup(env.stop)

    def _init(self, row):
        async def main():
            handler = WebSocketHandler(orchestrator=mock.MagicMock(), ws_manager=WebSocketManager())
            conn = WebSocketConnection(_WS())
            await handler.handle_init(conn, {"user_id": "x", "project_id": "x", "session_id": "x", "ticket": _ticket()})
            return conn

        with mock.patch.object(ws_ticket, "_project_tenancy", return_value=row):
            return asyncio.run(main())

    def test_a_pre_transfer_ticket_is_refused_at_init_and_the_socket_closed(self):
        conn = self._init((NEW, "idle"))
        self.assertFalse(conn.authenticated)
        [err] = [m["payload"] for m in conn.websocket.sent if m["type"] == "error"]
        self.assertEqual(err["code"], "ws_ticket_tenant")
        self.assertEqual(conn.websocket.closed[0], 1008)

    def test_refused_while_the_project_is_held_by_its_transfer(self):
        conn = self._init((OLD, "transfer_split"))
        self.assertFalse(conn.authenticated)

    def test_the_owner_s_ticket_authenticates(self):
        conn = self._init((OLD, "idle"))
        self.assertTrue(conn.authenticated)
        self.assertEqual(conn.tenant_id, OLD)


if __name__ == "__main__":
    unittest.main(verbosity=2)
