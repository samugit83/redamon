"""The regex fixes of the TruffleHog plan's Phase 0 (items 0.1-0.7).

Each fix removes a false-positive class measured on real estates and clean
library code (the census, tooling/scripts/js_secret_fp_census.py) without
renaming a rule or changing a surviving match: test_regression_js_recon_
phase0_ids_stable.py pins the ids. Every case here has a negative (the noise
is gone) and a positive (the real key still reports). Every value is synthetic
and assembled at runtime, so no key-shaped string sits in the source.
"""

from __future__ import annotations

import random
import string
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns

URL = "https://app.example.com/assets/main.js"
ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"


def _rnd(label: str, alphabet: str, n: int) -> str:
    rng = random.Random(f"p0:{label}")
    return "".join(rng.choice(alphabet) for _ in range(n))


def _gcp(label: str) -> str:
    return "AI" + "za" + "Sy" + _rnd(label, ALNUM, 33)


def _uuid4(label: str) -> str:
    h = _rnd(label, "0123456789abcdef", 32)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-b{h[17:20]}-{h[20:32]}"


def _findings(js: str) -> list:
    return patterns.scan_js_content(js, URL)[0]


def _names(js: str) -> list:
    return sorted(f["name"] for f in _findings(js))


def _named(js: str, name: str) -> dict:
    found = [f for f in _findings(js) if f["name"] == name]
    if len(found) != 1:
        raise AssertionError(f"expected one {name!r}, got {_names(js)}")
    return found[0]


def _pem_body(label: str, n: int = 256) -> str:
    body = _rnd(label, B64, n)
    return "\\n".join(body[i:i + 64] for i in range(0, len(body), 64))


class GenericLosesToSpecific(unittest.TestCase):
    """0.1: a generic match whose span holds a specific credential's is dropped,
    and its name moves to the winner's alternate_names."""

    def test_api_key_holding_a_google_key_is_one_public_gcp_finding(self):
        js = 'const opts = {apiKey:"' + _gcp("a") + '"};'
        self.assertEqual(_names(js), ["GCP API Key"])
        gcp = _named(js, "GCP API Key")
        self.assertIn("Generic API Key", gcp["alternate_names"])
        self.assertEqual(gcp["severity"], "info")
        self.assertTrue(gcp["public_client_key"])

    def test_a_gemini_key_stays_critical_beside_the_public_gcp_rule(self):
        js = 'const cfg = {gemini_api_key:"' + _gcp("g") + '"};'
        names = _names(js)
        self.assertNotIn("Generic API Key", names)
        self.assertEqual(_named(js, "Google Gemini API Key")["severity"], "critical")
        # Specific never beats specific: the public GCP finding stays too.
        self.assertIn("GCP API Key", names)

    def test_secret_holding_a_stripe_key_keeps_the_stripe_id(self):
        key = "sk" + "_live_" + _rnd("s", ALNUM, 28)
        js = 'const secret = "' + key + '";'
        stripe = _named(js, "Stripe Secret Key")
        self.assertNotIn("Generic Secret", _names(js))
        self.assertIn("Generic Secret", stripe["alternate_names"])
        self.assertEqual(stripe["id"], patterns._make_finding_id("Stripe Secret Key", key, URL))

    def test_a_generic_alone_still_reports(self):
        self.assertEqual(_names('var api_key = "' + _rnd("ga", ALNUM, 24) + '";'), ["Generic API Key"])

    def test_a_password_next_to_but_not_holding_a_key_stays(self):
        js = 'var password = "Tr0' + _rnd("p", ALNUM, 9) + '!"; var k = "' + _gcp("n") + '";'
        self.assertIn("Hardcoded Password", _names(js))

    def test_an_email_inside_a_secret_does_not_drop_the_secret(self):
        js = 'const secret = "' + _rnd("e", ALNUM, 6) + '@corp-mail.org";'
        self.assertIn("Generic Secret", _names(js))


class PrivateKeysNeedKeyData(unittest.TestCase):
    """0.2: a BEGIN ... PRIVATE KEY marker reports only with key data after it."""

    KINDS = {
        "RSA Private Key": "RSA PRIVATE KEY",
        "DSA Private Key": "DSA PRIVATE KEY",
        "EC Private Key": "EC PRIVATE KEY",
        "OpenSSH Private Key": "OPENSSH PRIVATE KEY",
        "PGP Private Key": "PGP PRIVATE KEY BLOCK",
        "Generic Private Key": "PRIVATE KEY",
    }

    def _head(self, kind):
        return "-----BEGIN " + kind + "-----"

    def test_a_runtime_template_is_no_finding(self):
        for name, kind in self.KINDS.items():
            templates = (
                'var p = "' + self._head(kind) + '\\n" + n + "\\n-----END ' + kind + '-----";',
                "var p = `" + self._head(kind) + "\\n${n}\\n-----END " + kind + "-----`;",
                'if(t.indexOf("' + self._head(kind) + '")!=-1)return KJUR.asn1.ASN1Util.getHex(t);',
            )
            for js in templates:
                with self.subTest(rule=name, js=js[:60]):
                    self.assertNotIn(name, _names(js))

    def test_a_key_with_escaped_newlines_is_critical(self):
        for name, kind in self.KINDS.items():
            js = ('const pem = "' + self._head(kind) + "\\n" + _pem_body(name)
                  + "\\n-----END " + kind + '-----";')
            with self.subTest(rule=name):
                self.assertEqual(_named(js, name)["severity"], "critical")

    def test_a_key_split_over_concatenated_lines_reports(self):
        body = _rnd("concat", B64, 128)
        js = ('const pem = "' + self._head("RSA PRIVATE KEY") + '\\n" +\n  "' + body[:64] + '\\n" +\n  "'
              + body[64:] + '\\n" +\n  "-----END RSA PRIVATE KEY-----";')
        self.assertIn("RSA Private Key", _names(js))

    def test_a_pgp_block_with_armor_headers_reports(self):
        js = ('const k = "' + self._head("PGP PRIVATE KEY BLOCK") + "\\nVersion: GnuPG v2\\n\\n"
              + _pem_body("pgp") + '\\n-----END PGP PRIVATE KEY BLOCK-----";')
        self.assertIn("PGP Private Key", _names(js))

    def test_a_short_stub_after_the_marker_is_no_finding(self):
        js = 'const p = "' + self._head("PRIVATE KEY") + "\\nMIIBVQ" + '\\n-----END PRIVATE KEY-----";'
        self.assertNotIn("Generic Private Key", _names(js))


class CertificateIsInfo(unittest.TestCase):
    """0.3: a certificate is public; same name and category, severity info."""

    def test_certificate_is_info_with_the_same_identity(self):
        js = ('const ca = "-----BEGIN CERTIFICATE-----\\n' + _pem_body("cert")
              + '\\n-----END CERTIFICATE-----";')
        cert = _named(js, "PKCS12 Certificate")
        self.assertEqual(cert["severity"], "info")
        self.assertEqual(cert["category"], "secret")
        self.assertEqual(cert["id"], patterns._make_finding_id(
            "PKCS12 Certificate", "-----BEGIN CERTIFICATE-----", URL))


class YandexNeedsItsKeyword(unittest.TestCase):
    """0.4: `YC` + 38 is a webpack chunk id unless "yandex" is near it."""

    def test_chunk_ids_are_no_finding(self):
        js = ",".join(f'{i}:"Y' + "C" + _rnd(f"yc{i}", ALNUM + "_-", 38) + '"' for i in range(5))
        self.assertNotIn("Yandex AWS Access Token", _names("var c={" + js + "};"))

    def test_with_the_keyword_it_reports_with_the_same_id(self):
        value = "Y" + "C" + _rnd("ykey", ALNUM, 38)
        js = 'const yandexCloud = {accessKeyId: "' + value + '"};'
        finding = _named(js, "Yandex AWS Access Token")
        self.assertEqual(finding["id"], patterns._make_finding_id("Yandex AWS Access Token", value, URL))

    def test_the_keyword_on_the_line_above_counts(self):
        js = "const yandex = {\n  key: \"Y" + "C" + _rnd("yabove", ALNUM, 38) + '"\n};'
        self.assertIn("Yandex AWS Access Token", _names(js))

    def test_the_keyword_far_before_does_not(self):
        js = "// yandex\n" + "x" * 300 + ';var k="Y' + "C" + _rnd("yfar", ALNUM, 38) + '";'
        self.assertNotIn("Yandex AWS Access Token", _names(js))


class ShortPrefixBoundary(unittest.TestCase):
    """0.5: a short provider prefix inside a longer identifier is no key."""

    def test_resend_prefix_inside_an_identifier_is_no_finding(self):
        js = "function configu" + "re_" + _rnd("cfg", ALNUM, 24) + "(){return 1}"
        self.assertNotIn("Resend API Key", _names(js))

    def test_a_quoted_resend_key_still_reports(self):
        value = "re" + "_" + _rnd("resend", ALNUM, 24)
        finding = _named('const RESEND = "' + value + '";', "Resend API Key")
        self.assertEqual(finding["matched_text"], value)


class GenericUuidIsLow(unittest.TestCase):
    """0.6: a generic rule whose value is a bare UUIDv4 is kept, at low."""

    def test_api_key_bound_to_a_uuid_is_low(self):
        js = 'const settings = {apiKey: "' + _uuid4("u") + '"};'
        self.assertEqual(_named(js, "Generic API Key")["severity"], "low")

    def test_a_random_generic_value_keeps_medium(self):
        js = 'const settings = {apiKey: "' + _rnd("r", ALNUM, 32) + '"};'
        self.assertEqual(_named(js, "Generic API Key")["severity"], "medium")

    def test_a_provider_uuid_rule_is_unchanged(self):
        js = 'const herokuApiKey = "' + _uuid4("h") + '";'
        heroku = _named(js, "Heroku API Key")
        self.assertEqual(heroku["severity"], "high")


class NewRules(unittest.TestCase):
    """0.7: the four rules the gap report found missing."""

    def test_aws_session_key(self):
        value = "AS" + "IA" + _rnd("asia", string.ascii_uppercase + string.digits, 16)
        finding = _named('const creds = {accessKeyId: "' + value + '"};', "AWS Session Key")
        self.assertEqual((finding["severity"], finding["confidence"], finding["matched_text"]),
                         ("high", "medium", value))

    def test_stripe_webhook_secret(self):
        value = "wh" + "sec_" + _rnd("whsec", ALNUM, 32)
        finding = _named('const WEBHOOK = "' + value + '";', "Stripe Webhook Secret")
        self.assertEqual(finding["severity"], "high")

    def test_credentials_in_url(self):
        url = "https://svc" + "-user:" + _rnd("pw", ALNUM, 14) + "@db.internal.example.org:8443"
        finding = _named('fetch("' + url + '/v1")', "Credentials in URL")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["matched_text"], url)
        for scheme in ("ftp", "amqp", "amqps", "smtp", "http"):
            with self.subTest(scheme=scheme):
                self.assertIn("Credentials in URL", _names(
                    'x("' + scheme + "://ops:" + _rnd(scheme, ALNUM, 12) + '@mq.example.org")'))

    def test_credentials_in_url_placeholders_are_noise(self):
        for password in ("password", "${PASSWORD}", "<password>", "xxxx", "changeme", "{{pass}}"):
            with self.subTest(password=password):
                self.assertNotIn("Credentials in URL",
                                 _names('const u = "https://user:' + password + '@example.org";'))

    def test_jdbc_with_password(self):
        url = ("jdbc:" + "postgresql://db.example.org:5432/app?user=svc&password="
               + _rnd("jdbc", ALNUM, 16))
        finding = _named('const DSN = "' + url + '";', "JDBC with password")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["matched_text"], url)

    def test_jdbc_without_password_is_no_finding(self):
        self.assertNotIn("JDBC with password", _names('const DSN = "jdbc:h2:mem:testdb";'))


if __name__ == "__main__":
    unittest.main()
