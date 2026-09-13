"""
Unit tests for the capture context tag (sign/verify) security primitive.

Run: python3 -m unittest capture_proxy.tests.test_redamon_ctx
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import redamon_ctx as ctx  # noqa: E402

SCANNER = "scanner-secret-AAAA"
INTERNAL = "internal-secret-BBBB"
KEYS = {"recon": SCANNER, "agent": INTERNAL}

RECON_PAYLOAD = {
    "source": "recon",
    "project_id": "p1",
    "user_id": "u1",
    "run_id": "run-1",
    "tool": "httpx",
    "phase": "informational",
}


class TestRoundTrip(unittest.TestCase):
    def test_recon_sign_verify(self):
        token = ctx.sign_tag(RECON_PAYLOAD, SCANNER)
        out = ctx.verify_tag(token, KEYS)
        self.assertEqual(out, {k: v for k, v in RECON_PAYLOAD.items() if v is not None})

    def test_agent_sign_verify(self):
        payload = {"source": "agent", "project_id": "p1", "user_id": "u1",
                   "session_id": "s1", "tool": "execute_curl", "phase": "exploitation"}
        token = ctx.sign_tag(payload, INTERNAL)
        self.assertEqual(ctx.verify_tag(token, KEYS), payload)

    def test_operator_sign_verify(self):
        # Operator-recording tags are minted by the webapp with INTERNAL_API_KEY.
        payload = {"source": "operator", "project_id": "p1", "user_id": "u1", "session_id": "rec-1"}
        token = ctx.sign_tag(payload, INTERNAL)
        keys = {"recon": SCANNER, "agent": INTERNAL, "operator": INTERNAL}
        self.assertEqual(ctx.verify_tag(token, keys), payload)
        self.assertIn("operator", ctx.VALID_SOURCES)

    def test_none_fields_are_dropped(self):
        payload = dict(RECON_PAYLOAD, session_id=None, member_id=None)
        out = ctx.verify_tag(ctx.sign_tag(payload, SCANNER), KEYS)
        self.assertNotIn("session_id", out)
        self.assertNotIn("member_id", out)

    def test_header_safe_token(self):
        token = ctx.sign_tag(RECON_PAYLOAD, SCANNER)
        # No '=' padding, no chars illegal in an HTTP header value.
        self.assertNotIn("=", token)
        self.assertTrue(all(32 <= ord(c) < 127 for c in token))
        self.assertEqual(token.count("."), 1)


class TestForgeryResistance(unittest.TestCase):
    def test_wrong_key_rejected(self):
        token = ctx.sign_tag(RECON_PAYLOAD, "attacker-key")
        self.assertIsNone(ctx.verify_tag(token, KEYS))

    def test_source_cannot_borrow_other_sources_key(self):
        # A token claiming source=agent but signed with the SCANNER key must fail
        # (verifier checks it against the INTERNAL key because source=agent).
        payload = dict(RECON_PAYLOAD, source="agent")
        token = ctx.sign_tag(payload, SCANNER)
        self.assertIsNone(ctx.verify_tag(token, KEYS))

    def test_tampered_body_rejected(self):
        token = ctx.sign_tag(RECON_PAYLOAD, SCANNER)
        body_b64, sig_b64 = token.split(".", 1)
        # Flip the tenant to another user, re-encode the body, keep the old sig.
        forged = dict(RECON_PAYLOAD, user_id="victim")
        forged_body = ctx._b64u_encode(ctx._canonical(forged))
        self.assertIsNone(ctx.verify_tag(forged_body + "." + sig_b64, KEYS))

    def test_unknown_source_rejected(self):
        payload = dict(RECON_PAYLOAD, source="webapp")
        token = ctx.sign_tag(payload, SCANNER)
        self.assertIsNone(ctx.verify_tag(token, KEYS))

    def test_missing_key_for_source_rejected(self):
        token = ctx.sign_tag(RECON_PAYLOAD, SCANNER)
        self.assertIsNone(ctx.verify_tag(token, {"agent": INTERNAL}))  # no recon key

    def test_garbage_tokens(self):
        for junk in ("", "nodot", "a.b.c.d", "!!!.???", "."):
            self.assertIsNone(ctx.verify_tag(junk, KEYS))

    def test_extra_unsigned_field_rejected(self):
        # Craft a body with an extra key the signer never included; even if the
        # sig matched the extra-field body it would not equal the canonical form.
        token = ctx.sign_tag(RECON_PAYLOAD, SCANNER)
        _, sig_b64 = token.split(".", 1)
        sneaky = dict(RECON_PAYLOAD, evil="x")
        sneaky_body = ctx._b64u_encode(json.dumps(sneaky, sort_keys=True, separators=(",", ":")).encode())
        self.assertIsNone(ctx.verify_tag(sneaky_body + "." + sig_b64, KEYS))


class TestSignerGuards(unittest.TestCase):
    def test_empty_key_raises(self):
        with self.assertRaises(ValueError):
            ctx.sign_tag(RECON_PAYLOAD, "")


if __name__ == "__main__":
    unittest.main()
