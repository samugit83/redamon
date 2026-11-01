"""Merging TruffleHog into js_recon's secrets, then validating, together.

`_validate_secrets` replaces each secret's `validation` wholesale, so the merge
is only right if what TruffleHog said survives it: the regex identity of a key
both engines find, the TruffleHog-only status, the skipped provider call for a
key TruffleHog verified (but never the Firebase and Google Maps checks), and
rule V1 (TruffleHog never writes `rejected`). `validate_secret` is mocked;
nothing leaves the process. Every value is synthetic and assembled at runtime.
"""
from __future__ import annotations

import random
import string
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.js_recon import patterns
from recon.helpers.js_recon import trufflehog_bridge as th
from recon.main_recon_modules import js_recon

ALNUM = string.ascii_letters + string.digits
URL = "https://app.example.com/main.js"
MAP_URL = "https://app.example.com/main.js.map#src/config.ts"
UPLOAD = "upload://keys.js"


def _rnd(label, n, alphabet=ALNUM):
    rng = random.Random(f"mv:{label}")
    return "".join(rng.choice(alphabet) for _ in range(n))


GH = "gh" + "p_" + _rnd("gh", 36)
GCP = "AI" + "zaSy" + _rnd("gcp", 33)
SHODAN = _rnd("shodan", 32)
STRIPE = "sk" + "_live_" + _rnd("stripe", 28)


@pytest.fixture(autouse=True)
def _isolated():
    cb.reset_registry()
    yield
    cb.reset_registry()


def _regex(content, url=URL):
    return patterns.scan_js_content(content, url)[0]


def _th(detector, raw, file="f_00001.js", verified=False, error=""):
    return th.ThResult(detector=detector, verified=verified, error=error, raw=raw, file=file,
                       line=1, extra={"version": "2"} if detector == "Github" else {})


def _manifest(*entries):
    return {f"f_{i:05d}.js": {"url": url, "content": content}
            for i, (url, content) in enumerate(entries, 1)}


def _validate(secrets, verify=True, answer=None):
    answer = answer or {"valid": False, "state": "rejected", "error": "", "info": "status=401"}
    with mock.patch.object(js_recon, "validate_secret", return_value=answer) as vs:
        out = js_recon._validate_secrets(secrets, {"JS_RECON_VALIDATE_KEYS": verify})
    return out, vs


def _by_name(secrets, name):
    found = [s for s in secrets if s["name"] == name]
    assert len(found) == 1, [s["name"] for s in secrets]
    return found[0]


class TestMatch:
    def test_keeps_the_regex_identity_and_gains_trufflehog(self):
        content = f'const t = "{GH}";'
        regex = _regex(content)
        before = _by_name(regex, "GitHub Token Classic")
        ident = (before["id"], before["name"], before["matched_text"], before["severity"])
        merged, stats = th.merge(regex, [_th("Github", GH)], _manifest((URL, content)), verify=True)
        secret = _by_name(merged, "GitHub Token Classic")
        assert (secret["id"], secret["name"], secret["matched_text"], secret["severity"]) == ident
        assert secret["detection_method"] == "regex"
        assert "TruffleHog:Github" in secret["alternate_names"]
        assert (stats.merged, stats.new) == (1, 0)
        out, _ = _validate(merged)
        assert out[0]["validation"]["trufflehog"]["detector"] == "Github"
        # Unverified by TruffleHog: our validator's verdict stands.
        assert out[0]["validation"]["status"] == "rejected"

    def test_verified_skips_the_provider_call(self):
        content = f'const t = "{GH}";'
        merged, _ = th.merge(_regex(content), [_th("Github", GH, verified=True)],
                             _manifest((URL, content)), verify=True)
        out, vs = _validate(merged)
        vs.assert_not_called()
        v = out[0]["validation"]
        assert (v["status"], v["checked_by"], v["trufflehog"]["verified"]) == ("validated", "trufflehog", True)
        assert "validated_at" not in v

    def test_google_maps_and_firebase_always_run(self):
        content = f'const k = "{GCP}";'
        merged, _ = th.merge(_regex(content), [_th("GoogleGeminiAPIKey", GCP, verified=True)],
                             _manifest((URL, content)), verify=True)
        gcp = _by_name(merged, "GCP API Key")
        assert gcp["validator_ref"] == "validate_google_maps"
        restricted = {"valid": False, "state": "unknown", "error": "", "info": "status=REQUEST_DENIED"}
        out, vs = _validate(merged, answer=restricted)
        vs.assert_called_once()
        v = _by_name(out, "GCP API Key")["validation"]
        # TruffleHog proved it live; the Maps answer is kept as information.
        assert (v["status"], v["checked_by"], v["validator_status"]) == ("validated", "trufflehog", "unknown")

        fire = "https://" + "demo-app" + ".firebaseio.com"
        content = f'const db = "{fire}";'
        regex = _regex(content)
        regex[0].setdefault("validation", {})["trufflehog"] = {"detector": "X", "verified": True,
                                                               "error_class": "", "extra": {}}
        valid = {"valid": True, "state": "valid", "scope": "read", "info": "open"}
        out, vs = _validate(regex, answer=valid)
        vs.assert_called_once()
        assert out[0]["validation"]["status"] == "validated"

    def test_a_match_in_a_pseudo_file_and_an_upload(self):
        for url in (MAP_URL, UPLOAD):
            content = f'export const t = "{GH}";'
            merged, stats = th.merge(_regex(content, url), [_th("Github", GH)],
                                     _manifest((url, content)), verify=False)
            assert stats.merged == 1
            assert _by_name(merged, "GitHub Token Classic")["source_url"] == url


class TestTruffleHogOnly:
    def test_id_formula_status_and_shape(self):
        content = f'const shodanKey = "{SHODAN}";'
        merged, stats = th.merge(_regex(content), [_th("Shodan", SHODAN, verified=True)],
                                 _manifest((URL, content)), verify=True)
        new = _by_name(merged, "Shodan")
        assert new["id"] == patterns._make_finding_id("Shodan", SHODAN, URL)
        assert (new["detection_method"], new["matched_text"], new["confidence"]) == ("trufflehog", SHODAN, "high")
        assert new["redacted_value"] == patterns.redact(SHODAN)
        assert new["line_number"] == 1
        assert SHODAN not in new["context"]
        assert stats.new == 1
        out, vs = _validate(merged)
        vs.assert_not_called()
        v = _by_name(out, "Shodan")["validation"]
        assert (v["status"], v["checked_by"]) == ("validated", "trufflehog")

    def test_unverified_and_errored_are_unknown_never_rejected(self):
        content = f'const shodanKey = "{SHODAN}";'
        for kw in ({}, {"error": "dial tcp: i/o timeout"}):
            merged, _ = th.merge([], [_th("Shodan", SHODAN, **kw)], _manifest((URL, content)), verify=True)
            out, _ = _validate(merged)
            assert out[0]["validation"]["status"] == "unknown"

    def test_validation_off_is_skipped_with_trufflehog_kept(self):
        content = f'const shodanKey = "{SHODAN}"; const t = "{GH}";'
        merged, _ = th.merge(_regex(content), [_th("Shodan", SHODAN), _th("Github", GH)],
                             _manifest((URL, content)), verify=False)
        out, vs = _validate(merged, verify=False)
        vs.assert_not_called()
        for s in out:
            assert s["validation"]["status"] == "skipped"
            assert s["validation"]["trufflehog"]["detector"] in ("Shodan", "Github")

    def test_a_public_type_is_info_and_public(self):
        content = f'k = atob("eA=="); // {GCP[:4]}'
        merged, _ = th.merge([], [_th("GoogleGeminiAPIKey", GCP)], _manifest((URL, content)), verify=False)
        f = merged[0]
        assert (f["name"], f["severity"], f["public_client_key"], f["context"]) == ("GCP API Key", "info", True, "")

    def test_the_filter_drops_only_new_findings(self):
        content = f'const shodanKey = "{SHODAN}"; const t = "{GH}";'
        merged, stats = th.merge(_regex(content), [_th("Shodan", SHODAN), _th("Github", GH)],
                                 _manifest((URL, content)), verify=True, keep={"verified"})
        names = [s["name"] for s in merged]
        assert "Shodan" not in names
        assert "GitHub Token Classic" in names
        assert (stats.filtered, stats.merged) == (1, 1)

    def test_aws_pairings_are_one_finding_the_verified_one(self):
        aws = "AK" + "IA" + _rnd("aws", 16, string.ascii_uppercase + string.digits)
        content = f'x = "{aws}";'
        results = [_th("AWS", aws), _th("AWS", aws, verified=True), _th("AWS", aws)]
        merged, stats = th.merge([], results, _manifest((URL, content)), verify=True)
        assert len(merged) == 1 and stats.new == 1
        assert merged[0]["validation"]["status"] == "validated"

    def test_order_is_deterministic(self):
        content = f'a = "{SHODAN}"; b = "{STRIPE}";'
        results = [_th("Shodan", SHODAN), _th("Stripe", STRIPE)]
        one, _ = th.merge([], results, _manifest((URL, content)), verify=False)
        two, _ = th.merge([], list(reversed(results)), _manifest((URL, content)), verify=False)
        assert [s["id"] for s in one] == [s["id"] for s in two]


class TestNoRejectedFromTruffleHog:
    def test_every_path(self):
        content = f'const shodanKey = "{SHODAN}";'
        for verify in (False, True):
            for kw in ({}, {"verified": True}, {"error": "x"}):
                merged, _ = th.merge([], [_th("Shodan", SHODAN, **kw)], _manifest((URL, content)), verify=verify)
                out, _ = _validate(merged, verify=verify)
                assert out[0]["validation"]["status"] != "rejected"
