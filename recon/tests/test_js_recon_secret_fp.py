"""False-positive regressions for JS Recon secret patterns.

A field report muted ~67 "secrets" that held no credential: UI labels and
i18n keys caught by the keyword-anchored generic patterns, localhost and
debug literals, internal-looking documentation URLs, field names. The generic
patterns now judge the captured VALUE, the internal-URL keyword must be a
whole host-label word, and localhost / internal URL / debug flag hits are
developer references, not Secret nodes. Each noise case has a positive twin.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns
from recon.main_recon_modules import js_recon


def names(js: str) -> list:
    findings, _ = patterns.scan_js_content(js, "https://app.example.com/main.js")
    return sorted(f["name"] for f in findings)


GENERIC = {"Generic Secret", "Generic API Key", "Generic Token", "Hardcoded Password"}


def generic(js: str) -> list:
    return [n for n in names(js) if n in GENERIC]


class TestGenericPatternsJudgeTheValue(unittest.TestCase):
    def test_ui_labels(self):
        self.assertEqual(generic('t({forgotPassword:"Forgot your password?",secret:"Keep this secret"})'), [])

    def test_routes_selectors_templates_and_urls(self):
        for js in (
            'const password = "/account/reset-password";',
            'secret: "#secret-field-wrapper"',
            'password = "${process.env.PASSWORD}"',
            'password: "{{ form.password }}"',
            'secret: "https://docs.vendor.test/secrets"',
            'password = "<password>"',
        ):
            self.assertEqual(generic(js), [], js)

    def test_i18n_keys_and_field_names(self):
        for js in (
            'password: "auth.form.passwordLabel"',
            'password = "confirmPassword"',
            'secret: "client_secret_input"',
            'pwd = "newPasswordField"',
        ):
            self.assertEqual(generic(js), [], js)

    def test_placeholders(self):
        for js in (
            'password = "changeme"',
            'secret: "YOUR_SECRET_HERE"',
            'password = "xxxxxxxx"',
            'secret: "my-api-key"',
            'apiKey: "__API_KEY__"',
        ):
            self.assertEqual(generic(js), [], js)

    def test_identifiers_as_key_values(self):
        self.assertEqual(generic('apiKey: getApiKeyFromStorageService'), [])
        self.assertEqual(generic('access_token = refreshAccessTokenHandler'), [])
        self.assertEqual(generic('api_key="EXAMPLEKEYEXAMPLEKEY"'), [])

    def test_real_values_still_report(self):
        # Both generic patterns match this span; the span collapse keeps one.
        self.assertEqual(generic('password = "S3cr3t!2024"'), ["Hardcoded Password"])
        self.assertEqual(generic('db_password: "hunter2hunter2"'), ["Generic Secret"])
        self.assertEqual(generic('apiKey: "a8f5f167f44f4964e6c998dee827110c"'), ["Generic API Key"])
        self.assertEqual(generic('auth_token="tK9vQ2xLm4Rz8bWn1pYc"'), ["Generic Token"])
        # A weak real password is still a hardcoded password.
        self.assertEqual(generic('password = "admin123"'), ["Hardcoded Password"])

    def test_real_values_with_spaces_or_leading_symbols_still_report(self):
        # Each of these was dropped by an earlier, broader filter.
        for js in ('DB_PASSWORD = "Summer 2024!"', 'password = "$Pr0d-Db!2024"',
                   'password = "#Welc0me2024"', 'pwd = "Enterprise2024"'):
            self.assertIn("Hardcoded Password", generic(js), js)
        self.assertIn("Generic Token", generic('auth_token: "enterprise_7f3a9b2c4d5e6f70"'))

    def test_more_real_value_shapes_still_report(self):
        self.assertIn("Hardcoded Password", generic('pwd = "$ecureP4ss2024"'))
        self.assertIn("Hardcoded Password", generic('pwd = "/Pa55w0rd"'))
        self.assertIn("Generic Secret", generic('client_secret: "/xYz9Ab3Cd/eFg1Hi2Jk7LmN0pQrStUvWx=="'))
        # A random key with no digit is still a key.
        self.assertIn("Generic API Key", generic('apiKey: "kGpqXRtLmzWcVbNhJsYdFaQe"'))

    def test_env_var_and_selector_shapes_are_still_noise(self):
        for js in ('password = "$DB_PASSWORD"', 'secret: ".secret-input"', 'password = "#pw"',
                   'secret: "[name=client_secret]"'):
            self.assertEqual(generic(js), [], js)

    def test_filter_reads_the_value_not_the_line(self):
        # UI text on the same line must not hide the credential beside it.
        js = 'label: "Forgot your password?", password = "Pr0d!Passw0rd#9"'
        self.assertIn("Hardcoded Password", generic(js))

    def test_filtered_count_is_reported(self):
        _, filtered = patterns.scan_js_content('password: "Enter your password"', "a.js")
        self.assertGreaterEqual(filtered["generic_noise"], 1)

    def test_precise_formats_are_untouched(self):
        self.assertIn("AWS Access Key ID", names('password: "Enter it", key = "AKIAIOSFODNN7EXAMPLE"'))


class TestCssModuleClassNames(unittest.TestCase):
    """Plan 05.3: a CSS-modules build names a form field's class after the
    field (`<Component>_<class>__<hash>`), and the generic patterns read the
    class name as the password."""

    def test_css_module_class_names_are_noise(self):
        for js in ('password:"LoginForm_password__3xYz9"',
                   'secret:"Secret_secret__a1B2c"',
                   'apiKey:"ApiKeyField_apiKey__x7Fq2"',
                   # css-loader's `[name]__[local]___[hash:base64:5]` and `--` forms
                   'password:"LoginForm__password___3xYz9"',
                   'password:"login-form__password--3xYz9"'):
            with self.subTest(js=js):
                self.assertEqual(generic(js), [])

    def test_a_real_looking_generic_secret_is_kept(self):
        self.assertEqual(generic('password:"Xk9_mP2vL7qR4tZ"'), ["Generic Secret"])
        self.assertEqual(generic('apiKey: "kGp_qXR4tLmzWcVb_NhJ9sYdF"'), ["Generic API Key"])

    def test_the_class_names_count_as_filtered_noise(self):
        _, filtered = patterns.scan_js_content('password:"LoginForm_password__3xYz9"', "a.js")
        self.assertGreaterEqual(filtered["generic_noise"], 1)


class TestInternalUrlNeedsAWholeWord(unittest.TestCase):
    def _hits(self, url):
        return "Internal/Staging URL" in names(f'fetch("{url}/v1")')

    def test_words_that_merely_contain_a_keyword(self):
        for url in ("https://developer.vendor.test", "https://latest.example.com",
                    "https://contest.example.com", "https://administration-docs.vendor.test"):
            self.assertFalse(self._hits(url), url)

    def test_keyword_labels(self):
        for url in ("https://dev.example.com", "https://api-dev.example.com", "https://staging2.example.com",
                    "https://internal.example.com", "https://admin.example.com", "https://qa-test.example.com",
                    "https://devapi.example.com", "https://testing.example.com", "https://development.example.com",
                    "https://localdev.example.com", "https://adminpanel.example.com", "https://internalapi.example.com",
                    "https://DEV.EXAMPLE.COM"):
            self.assertTrue(self._hits(url), url)


class TestDeveloperReferencesAreNotSecrets(unittest.TestCase):
    SETTINGS = {
        "JS_RECON_REGEX_PATTERNS": True, "JS_RECON_SOURCE_MAPS": False, "JS_RECON_DEPENDENCY_CHECK": False,
        "JS_RECON_EXTRACT_ENDPOINTS": False, "JS_RECON_FRAMEWORK_DETECT": False, "JS_RECON_DOM_SINKS": False,
        "JS_RECON_DEV_COMMENTS": False, "JS_RECON_AI_SDK_DETECTION_ENABLED": False,
        "JS_RECON_MIN_CONFIDENCE": "low", "JS_RECON_TIMEOUT": 30,
    }

    def test_localhost_internal_url_and_debug_flag_become_dev_references(self):
        js = "\n".join((
            'const api = "http://localhost:8080/api";',
            'const stg = "https://staging.example.com/graphql";',
            'window.config = {debug: true};',
            'const k = "AKIAIOSFODNN7EXAMPLE";',
        ))
        results = js_recon._run_analysis([{"url": "https://app.example.com/main.js", "content": js}], self.SETTINGS)
        self.assertEqual([s["name"] for s in results["secrets"]], ["AWS Access Key ID"])
        refs = sorted((r["type"], r["value"]) for r in results["dev_references"])
        self.assertEqual(refs, [
            ("Debug Flag", "debug: true"),
            ("Internal/Staging URL", "https://staging.example.com"),
            ("Localhost with Port", "localhost:8080"),
        ])
        self.assertTrue(all(r["source_url"] == "https://app.example.com/main.js" for r in results["dev_references"]))
        self.assertTrue(all(r["line_number"] for r in results["dev_references"]))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# A made-up service-role-shaped JWT: about 220 characters, signed with nothing.
LONG_JWT = ".".join((
    _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()),
    _b64url(json.dumps({"iss": "example-synthetic", "ref": "notarealprojectref00",
                        "role": "service_role", "iat": 1767225600, "exp": 2082758400},
                       separators=(",", ":")).encode()),
    _b64url(hashlib.sha256(b"synthetic signature").digest()),
))
SYNTHETIC_AWS = "AKIAZ3FPLB7QW4XN6R2T"


def scan(js: str):
    return patterns.scan_js_content(js, "https://app.example.com/main.js")


class TestLongSecretsAreNotABase64Blob(unittest.TestCase):
    """The blob filter measured the run INCLUDING the match, so every match over
    200 characters (a JWT, a Bearer header, a 1Password service token) read as
    "inside a base64 blob" and was dropped."""

    def test_the_fixture_is_long_enough_to_matter(self):
        self.assertGreater(len(LONG_JWT), 200)

    def test_a_long_quoted_jwt_is_kept(self):
        findings, filtered = scan(f'var serviceRoleKey = "{LONG_JWT}";')
        # Matched by the JWT pattern and named by its role claim (plan 05.6).
        self.assertIn(("Supabase service_role key", LONG_JWT),
                      [(f["name"], f["matched_text"]) for f in findings])
        self.assertEqual(filtered["base64_blob"], 0)

    def test_a_bearer_header_with_a_long_jwt_is_kept(self):
        findings, _ = scan(f'var h = {{Authorization: "Bearer {LONG_JWT}"}};')
        self.assertIn(f"Bearer {LONG_JWT}", [f["matched_text"] for f in findings if f["name"] == "Bearer Token"])

    def test_a_key_inside_an_embedded_image_is_still_dropped(self):
        body = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ" * 60
        # `/` is base64 and a token boundary: the key matches, then the blob
        # filter has to drop it (glued to a letter, the pattern never matches).
        js = f'var img = "data:image/png;base64,{body[:2499]}/{SYNTHETIC_AWS}{body[:2500]}";'
        findings, filtered = scan(js)
        self.assertNotIn(SYNTHETIC_AWS, [f["matched_text"] for f in findings])
        self.assertGreater(filtered["base64_blob"], 0)

    def test_the_run_must_reach_past_the_match_to_be_a_blob(self):
        line = '"' + "A" * 250 + '"'
        # The match IS the whole run: nothing surrounds it, so it is not inside a blob.
        self.assertFalse(patterns._is_inside_base64_blob(line, 1, 251))
        # Same run, the match a short slice of it: inside a blob.
        self.assertTrue(patterns._is_inside_base64_blob(line, 100, 120))


class TestBinaryContextIsLocalOnLongLines(unittest.TestCase):
    """For a file with more than 3 lines the font/binary check read the WHOLE
    line, so one `fontFamily` on a minified bundle hid every secret on it."""

    @staticmethod
    def _minified(js_line: str) -> str:
        return "\n".join(("/*! bundle */", "/* license: MIT */", '"use strict";',
                          'var VERSION="1.0.0";', js_line))

    @staticmethod
    def _filler(n: int) -> str:
        unit, out, i = "var p{0}=fn(q{0},[1,2]);", [], 0
        while sum(map(len, out)) < n:
            out.append(unit.format(i))
            i += 1
        return "".join(out)

    def test_a_key_far_from_a_font_marker_is_kept(self):
        head = '!function(){var theme={fontFamily:"Inter",size:14};'
        line = head + self._filler(8000) + f'var cfg={{k:"{SYNTHETIC_AWS}"}};'
        line += self._filler(20000 - len(line)) + "}();"
        self.assertGreaterEqual(len(line), 20000)
        findings, filtered = scan(self._minified(line))
        self.assertIn(SYNTHETIC_AWS, [f["matched_text"] for f in findings])
        self.assertEqual(filtered["binary_context"], 0)

    def test_a_key_right_after_a_font_marker_is_still_dropped(self):
        line = (self._filler(3000) + '@font-face{src:url(data:font/woff2;base64,d09GMgABAAAAA) format("woff2")}'
                + ';var k={a:"' + SYNTHETIC_AWS + '"};' + self._filler(3000))
        self.assertLess(line.index(SYNTHETIC_AWS) - line.index("base64,"), 100)
        findings, filtered = scan(self._minified(line))
        self.assertNotIn(SYNTHETIC_AWS, [f["matched_text"] for f in findings])
        self.assertGreater(filtered["binary_context"], 0)

    def test_a_short_line_still_reads_the_whole_line(self):
        js = self._minified(f'@font-face{{font-family:X}} var k="{SYNTHETIC_AWS}";')
        findings, filtered = scan(js)
        self.assertNotIn(SYNTHETIC_AWS, [f["matched_text"] for f in findings])
        self.assertGreater(filtered["binary_context"], 0)


if __name__ == "__main__":
    unittest.main()
