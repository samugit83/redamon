"""
STRIDE S6 — cross-runtime integration: a ticket minted by the webapp (jose,
HS256) MUST verify with the agent's stdlib verifier, and MUST be rejected under
the wrong secret and on another socket than the one its `aud` names (HD-25). This guards the seam that unit tests (which sign with Python
hmac) can't: a format disagreement between jose and the Python verifier would
silently fail S6 open in production.

Runs the real `jose` SignJWT inside the webapp container, with the claim set
`createWsTicket` (webapp/src/lib/auth.ts) writes, then verifies the exact token
string here, and the `cap` claim of an `agent` ticket (step 3.9b) reads back as the
permissions it lists, and its `ten` (step 5.3) as the graph tenant beside the person in `sub`. `auth.wsTicket.test.ts` pins that claim set on the TypeScript side. SKIPs cleanly if the webapp container / docker is unavailable.

Run: python3 agentic/tests/test_ws_ticket_interop.py
"""
import subprocess
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

import os  # noqa: E402
from unittest import mock  # noqa: E402

import ws_ticket  # noqa: E402
from ws_ticket import ticket_cap, ticket_tenancy_refusal, ticket_tenant, verify_ws_ticket  # noqa: E402

SECRET = "interop-secret-0123456789abcdef"

_TERMINAL_CLAIMS = '{sub:"u1",pid:"p1",sid:"s1",aud:"kali-terminal",act:"a1"}'
# An `agent` ticket also carries `cap` (step 3.9b): the agent permissions its person holds.
_AGENT_CLAIMS = '{sub:"u1",pid:"p1",sid:"s1",aud:"agent",cap:["agent:approve_phase","agent:fireteam"]}'
# Every ticket names the project's owner as `ten` (step 5.3): here a collaborator's, owned by o1.
_SHARED_CLAIMS = '{sub:"u1",pid:"p1",sid:"s1",aud:"agent",ten:"o1",act:"a1",cap:[]}'


def _node_mint(claims: str) -> str:
    return (
        'const {SignJWT}=require("jose");'
        '(async()=>{const k=new TextEncoder().encode(process.argv[1]);'
        f'const t=await new SignJWT({claims})'
        '.setProtectedHeader({alg:"HS256"}).setIssuedAt().setExpirationTime("60s").sign(k);'
        'process.stdout.write(t);})();'
    )


def _mint_with_jose(secret: str, claims: str = _TERMINAL_CLAIMS) -> str | None:
    try:
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", "webapp", "node", "-e", _node_mint(claims), secret],
            cwd=str(Path(_AGENTIC_DIR).parent),
            capture_output=True, text=True, timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    tok = (out.stdout or "").strip()
    return tok if tok.count(".") == 2 else None


class TicketInterop(unittest.TestCase):
    def setUp(self):
        self.token = _mint_with_jose(SECRET)
        if not self.token:
            self.skipTest("webapp container / jose unavailable")

    def test_typescript_ticket_with_aud_verifies_in_python(self):
        claims = verify_ws_ticket(self.token, SECRET, expected_aud="kali-terminal")
        self.assertIsNotNone(claims, "jose-minted ticket rejected by Python verifier (interop bug)")
        self.assertEqual((claims["sub"], claims["pid"], claims["sid"], claims["aud"], claims["act"]),
                         ("u1", "p1", "s1", "kali-terminal", "a1"))

    def test_typescript_ticket_refused_on_another_socket(self):
        for other in ("agent", "cypherfix-triage", "cypherfix-codefix"):
            with self.subTest(socket=other):
                self.assertIsNone(verify_ws_ticket(self.token, SECRET, expected_aud=other))

    def test_wrong_secret_rejected(self):
        self.assertIsNone(verify_ws_ticket(self.token, "the-wrong-secret", expected_aud="kali-terminal"))

    def test_an_agent_ticket_s_cap_reads_as_the_permissions_it_lists(self):
        token = _mint_with_jose(SECRET, _AGENT_CLAIMS)
        if not token:
            self.skipTest("webapp container / jose unavailable")
        claims = verify_ws_ticket(token, SECRET, expected_aud="agent")
        self.assertIsNotNone(claims, "jose-minted agent ticket rejected by Python verifier (interop bug)")
        self.assertEqual(ticket_cap(claims), frozenset({"agent:approve_phase", "agent:fireteam"}))
        self.assertIsNone(ticket_cap(verify_ws_ticket(self.token, SECRET, expected_aud="kali-terminal")))

    def test_a_ticket_s_ten_reads_as_the_tenant_beside_the_person(self):
        token = _mint_with_jose(SECRET, _SHARED_CLAIMS)
        if not token:
            self.skipTest("webapp container / jose unavailable")
        claims = verify_ws_ticket(token, SECRET, expected_aud="agent")
        self.assertIsNotNone(claims, "jose-minted ticket with ten rejected by Python verifier (interop bug)")
        self.assertEqual((claims["sub"], ticket_tenant(claims), claims["act"]), ("u1", "o1", "a1"))
        # A ticket without `ten` (this class's terminal ticket) names its person, as before.
        self.assertEqual(ticket_tenant(verify_ws_ticket(self.token, SECRET, expected_aud="kali-terminal")), "u1")
        # An empty `ten` written by a buggy minter never verifies.
        empty = _mint_with_jose(SECRET, '{sub:"u1",pid:"p1",sid:"s1",aud:"agent",ten:""}')
        self.assertIsNone(verify_ws_ticket(empty, SECRET, expected_aud="agent"))

    def test_a_ticket_minted_before_an_ownership_transfer_opens_nothing_after_it(self):
        # Review of step 5.12: the webapp's ticket names the owner it saw (`ten`); the agent asks the database
        # at connect, so the same token opens a socket while o1 owns the project and not once o2 does.
        token = _mint_with_jose(SECRET, _SHARED_CLAIMS)
        if not token:
            self.skipTest("webapp container / jose unavailable")
        claims = verify_ws_ticket(token, SECRET, expected_aud="agent")
        with mock.patch.dict(os.environ, {"DATABASE_URL": "postgresql://rbac@db.invalid/redamon"}):
            for row, refused in ((("o1", "idle"), None), (("o2", "idle"), "ticket tenant no longer owns the project"),
                                 (("o1", "transfer_split"), "project ownership transfer in progress")):
                with self.subTest(row=row), mock.patch.object(ws_ticket, "_project_tenancy", return_value=row):
                    self.assertEqual(ticket_tenancy_refusal(claims), refused)


if __name__ == "__main__":
    unittest.main(verbosity=2)
