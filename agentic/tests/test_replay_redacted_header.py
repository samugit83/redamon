"""A redacted origin header must not outrank the AuthProfile on replay.

The ingest worker masks Cookie/Authorization at rest, so a captured transaction
stores `[redacted:<digest>]` rather than the credential. _apply_header_mutations
layers origin headers OVER the profile so the origin's own auth wins, which is
right for a real stored value and wrong for the mask: replaying any captured
authenticated request sent the placeholder and came back logged out. Verified
live against the auth_target guinea pig, which answered 302 before this and 200
with AUTHONLY-DASHBOARD after.

The swap the layering exists for (IDOR/BOLA: drop the Cookie, or replace it)
must keep working, so those are pinned here too.
"""
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import traffic_tools as tt  # noqa: E402

REDACTED = "[redacted:d457c673c7636bcb]"
AUTH = {"Cookie": "authpig_session=live-value", "csrf_token": "tok"}


def _apply(headers, mutate=None, base=AUTH):
    return tt._apply_header_mutations(headers, mutate or {}, base_headers=base)


class TestRedactedOriginHeader:
    def test_masked_cookie_does_not_shadow_the_profile(self):
        out = _apply({"cookie": REDACTED})
        assert out.get("Cookie") == "authpig_session=live-value"
        assert REDACTED not in out.values()

    def test_masked_authorization_too(self):
        out = _apply({"authorization": REDACTED}, base={"Authorization": "Bearer live"})
        assert out.get("Authorization") == "Bearer live"

    def test_a_real_origin_header_still_wins(self):
        # Only the mask is ignored. A genuinely stored value keeps precedence,
        # which is what lets a replay reproduce the captured request.
        out = _apply({"cookie": "origin_session=real"})
        assert out.get("cookie") == "origin_session=real"
        assert "authpig_session=live-value" not in out.values()

    def test_non_auth_headers_are_untouched(self):
        out = _apply({"user-agent": "curl/8", "cookie": REDACTED})
        assert out.get("user-agent") == "curl/8"

    def test_a_value_merely_containing_the_word_is_not_dropped(self):
        out = _apply({"x-note": "this was [redacted:abc] earlier"})
        assert out.get("x-note") == "this was [redacted:abc] earlier"


class TestAuthSwapStillWorks:
    def test_drop_cookie_beats_the_profile(self):
        # The logged-out view an access-control test needs.
        out = _apply({"cookie": REDACTED}, {"dropHeaders": ["Cookie"]})
        assert not any(k.lower() == "cookie" for k in out)

    def test_explicit_cookie_beats_the_profile(self):
        out = _apply({"cookie": REDACTED}, {"cookie": "authpig_session=other-user"})
        assert out.get("Cookie") == "authpig_session=other-user"

    def test_explicit_header_beats_the_profile(self):
        out = _apply({"cookie": REDACTED}, {"headers": {"Cookie": "sid=swapped"}})
        assert out.get("Cookie") == "sid=swapped"

    def test_empty_cookie_mutation_drops_it(self):
        out = _apply({"cookie": REDACTED}, {"cookie": ""})
        assert not any(k.lower() == "cookie" for k in out)


class TestIsRedacted:
    def test_recognises_the_mask(self):
        assert tt._is_redacted(REDACTED)
        assert tt._is_redacted("  " + REDACTED + " ")

    def test_rejects_everything_else(self):
        for v in ("[redacted:]", "[redacted:zz]", "sid=abc", "", None, 42, {"a": 1}):
            assert not tt._is_redacted(v)
