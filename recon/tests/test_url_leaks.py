"""recon/helpers/url_leaks.py: one-time links, secrets, the quarantine and masking.

Every URL here is invented on reserved names; tokens are random-looking strings
made up for the test.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import url_leaks as ul  # noqa: E402

TOK = "8f3a91c2d7e4b6a0f1c3e5d7b9a2c4e6"
TOK2 = "Zq7Pw3Lm9Xk2Rt5Vb8Nc"


def _jwt(payload: dict, alg: str = "HS256") -> str:
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': alg, 'typ': 'JWT'})}.{enc(payload)}.c2lnbmF0dXJlLWZha2U"


JWT_PAST = _jwt({"sub": "x", "exp": 1_000_000_000})
JWT_FUTURE = _jwt({"sub": "x", "exp": 4_000_000_000})


class TestLinkKinds:
    @pytest.mark.parametrize("url,kind", [
        (f"https://example.test/reset?token={TOK}", "password_reset"),
        (f"https://example.test/password/reset/{TOK}", "password_reset"),
        (f"https://example.test/reset/MQ/{TOK}/", "password_reset"),
        (f"https://example.test/activate?token={TOK}", "account_setup"),
        (f"https://example.test/set-password/{TOK}", "account_setup"),
        (f"https://example.test/invite/{TOK}", "invite"),
        (f"https://example.test/join?code={TOK2}", "invite"),
        (f"https://example.test/payment/{TOK}", "payment"),
        (f"https://example.test/invoice?key={TOK2}", "payment"),
        (f"https://example.test/login?token={TOK}", "login_link"),
        (f"https://example.test/auth/magic/{TOK}", "login_link"),
        (f"https://example.test/auth/magic/{JWT_FUTURE}", "login_link"),
        (f"https://example.test/verify?token={TOK}", "login_link"),
    ])
    def test_each_kind_in_a_parameter_and_in_the_path(self, url, kind):
        v = ul.inspect_url(url)
        assert v["link_kind"] == kind
        assert v["quarantined"]

    @pytest.mark.parametrize("url", [
        "https://example.test/x?monkey=1",
        "https://example.test/x?key=1",
        "https://example.test/reset?token=",
        "https://example.test/order/123",
        "https://example.test/x?code=US",
        "https://example.test/reset/{token}",
        "https://example.test/display?utm_source=newsletter&utm_medium=mail",
        "https://example.test/blog/how-to-reset-router",
        f"https://example.test/x?mkt_tok={TOK}",
        "https://example.test/border/5",
    ])
    def test_false_positives_stay_out(self, url):
        v = ul.inspect_url(url)
        assert v["link_kind"] is None
        assert v["secrets"] == []
        assert not v["quarantined"], v["reasons"]

    def test_oauth_code_is_not_a_one_time_link(self):
        v = ul.inspect_url(f"https://example.test/login/callback?code={TOK2}&state=abc")
        assert v["link_kind"] is None

    @pytest.mark.parametrize("url", [
        f"https://example.test/app?unsubscribe={TOK}",
        f"https://example.test/confirm/{TOK}",
        f"https://example.test/email/verify/42/{TOK}",
        "https://example.test/app/unsubscribe?u=someone",
    ])
    def test_quarantined_without_a_finding(self, url):
        v = ul.inspect_url(url)
        assert v["quarantined"], url
        assert v["link_kind"] is None
        assert v["secrets"] == []

    def test_a_bare_state_changing_word_is_not_quarantined(self):
        assert not ul.inspect_url("https://example.test/logout")["quarantined"]


class TestSecrets:
    @pytest.mark.parametrize("url,stype,name", [
        ("https://example.test/login?user=bob&pwd=hunter22", "password", "pwd"),
        ("https://example.test/x?pass=s3cretpw", "password", "pass"),
        (f"https://api.example.test/v1?apikey={TOK}", "api_key", "apikey"),
        (f"https://api.example.test/v1?key={TOK}", "api_key", "key"),
        (f"https://example.test/cb?access_token={TOK}", "token", "access_token"),
        (f"https://example.test/cb#access_token={TOK}", "token", "access_token"),
        (f"https://example.test/app;jsessionid={TOK}", "token", "jsessionid"),
        (f"https://example.test/x?session={TOK}", "token", "session"),
        (f"https://example.test/x?jwt={JWT_PAST}", "jwt", "jwt"),
        (f"https://example.test/x/{JWT_PAST}/y", "jwt", "path"),
    ])
    def test_each_secret_type(self, url, stype, name):
        v = ul.inspect_url(url)
        hits = [(s["secret_type"], s["param_name"]) for s in v["secrets"]]
        assert (stype, name) in hits
        assert v["quarantined"]

    @pytest.mark.parametrize("url", [
        "https://example.test/x?pass=1234", "https://example.test/x?pass=true",
        "https://example.test/x?session=abc", "https://example.test/x?sid=12",
        "https://example.test/x?secret=no",
    ])
    def test_shaped_names_need_a_shaped_value(self, url):
        assert ul.inspect_url(url)["secrets"] == []

    def test_no_value_is_ever_returned(self):
        url = f"https://example.test/reset?token={TOK}&pwd=hunter22"
        blob = json.dumps(ul.inspect_url(url, hmac_key="k"))
        assert TOK not in blob and "hunter22" not in blob

    def test_hmac_only_with_a_key(self):
        url = f"https://example.test/x?apikey={TOK}"
        assert "value_hmac" not in ul.inspect_url(url)["secrets"][0]
        a = ul.inspect_url(url, hmac_key="k1")["secrets"][0]["value_hmac"]
        b = ul.inspect_url(url, hmac_key="k1")["secrets"][0]["value_hmac"]
        c = ul.inspect_url(url, hmac_key="k2")["secrets"][0]["value_hmac"]
        assert a == b != c and len(a) == 64

    def test_jwt_decoded_locally_with_expiry(self):
        with patch("socket.socket", side_effect=AssertionError("network used")):
            past = ul.inspect_url(f"https://example.test/x?t={JWT_PAST}")["secrets"][0]
            future = ul.inspect_url(f"https://example.test/x?t={JWT_FUTURE}", now=2_000_000_000)["secrets"][0]
        assert (past["jwt_alg"], past["jwt_expired"]) == ("HS256", True)
        assert future["jwt_expired"] is False

    def test_reset_token_url_matches_both_switches(self):
        v = ul.inspect_url(f"https://example.test/reset?token={TOK}")
        assert v["link_kind"] == "password_reset"
        assert [s["secret_type"] for s in v["secrets"]] == ["token"]


class TestMasking:
    def test_values_and_path_tokens_are_masked(self):
        v = ul.inspect_url(f"https://example.test/password/reset/{TOK}?lang=en&token={TOK2}#a=1")
        assert v["masked_url"] == "https://example.test/password/reset/{token}?lang=***&token=***#a=***"
        assert v["masked_path"] == "/password/reset/{token}"

    def test_a_new_token_of_the_same_kind_masks_the_same(self):
        a = ul.mask_url(f"https://example.test/invite/{TOK}")
        b = ul.mask_url(f"https://example.test/invite/{TOK2}")
        assert a == b == "https://example.test/invite/{token}"

    def test_ordinary_paths_are_kept(self):
        assert ul.mask_path("/api/v1/orders/123") == "/api/v1/orders/123"
        assert ul.mask_url("https://example.test/a?b=1&c=") == "https://example.test/a?b=***&c="


class TestWebShell:
    def test_command_trace_quarantines_its_host_and_path(self):
        shell = "https://files.example.test/shell.php?cmd=cat+/etc/passwd"
        other = "https://files.example.test/shell.php?page=2"
        unrelated = "https://files.example.test/index.php?page=2"
        assert ul.inspect_url(shell)["web_shell"]
        kept, quarantined = ul.split_quarantined([other, shell, unrelated])
        assert kept == [unrelated]
        assert quarantined == [other, shell]

    def test_ordinary_values_are_not_a_trace(self):
        assert not ul.inspect_url("https://example.test/report?run=report")["web_shell"]


def test_never_raises_on_garbage():
    for junk in (None, "", "http://[::1", "%%%", "https://example.test/" + "a/" * 5000):
        ul.inspect_url(junk)
        ul.mask_url(junk or "")


def test_values_only_on_request_and_the_masked_form_is_unchanged():
    url = "https://auth.example.test/reset?token=Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd&pwd=hunter22x"
    plain = ul.inspect_url(url)
    full = ul.inspect_url(url, with_values=True)
    assert "url" not in plain and all("value" not in s for s in plain["secrets"])
    assert full["url"] == url
    assert {s["param_name"]: s["value"] for s in full["secrets"]} == {
        "token": "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd", "pwd": "hunter22x"}
    assert full["masked_url"] == plain["masked_url"]
    assert full["quarantined"] is plain["quarantined"] is True
