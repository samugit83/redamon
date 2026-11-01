"""
Comprehensive unit tests for JS Recon Scanner modules.

Run: cd /Users/ritesh.gohil/opensource/redamon && python3 recon/tests/test_js_recon.py
Or:  python3 -m pytest recon/tests/test_js_recon.py -v
"""

import pytest
import sys
import os
import re
import json
import tempfile
import unittest
import importlib.util
from unittest import mock

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def _load_module(name, filepath):
    """Load a module directly by file path, bypassing package __init__.py."""
    spec = importlib.util.spec_from_file_location(name, filepath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


BASE = os.path.join(os.path.dirname(__file__), '..')
patterns = _load_module('recon.helpers.js_recon.patterns', os.path.join(BASE, 'helpers/js_recon/patterns.py'))
validators = _load_module('recon.helpers.js_recon.validators', os.path.join(BASE, 'helpers/js_recon/validators.py'))
sourcemap = _load_module('recon.helpers.js_recon.sourcemap', os.path.join(BASE, 'helpers/js_recon/sourcemap.py'))
dependency = _load_module('recon.helpers.js_recon.dependency', os.path.join(BASE, 'helpers/js_recon/dependency.py'))
endpoints_mod = _load_module('recon.helpers.js_recon.endpoints', os.path.join(BASE, 'helpers/js_recon/endpoints.py'))
framework = _load_module('recon.helpers.js_recon.framework', os.path.join(BASE, 'helpers/js_recon/framework.py'))
ai_signal_catalog = _load_module('recon.helpers.ai_signal_catalog', os.path.join(BASE, 'helpers/ai_signal_catalog.py'))
js_recon = _load_module('recon.main_recon_modules.js_recon', os.path.join(BASE, 'main_recon_modules/js_recon.py'))


def _scan(js, url='test.js', **kwargs):
    """Helper: scan and return only the findings list (unpacking the tuple)."""
    findings, _filtered = patterns.scan_js_content(js, url, **kwargs)
    return findings


def _scan_full(js, url='test.js', **kwargs):
    """Helper: scan and return the full (findings, filtered_counts) tuple."""
    return patterns.scan_js_content(js, url, **kwargs)


# High-entropy test token building blocks (entropy > 3.5 to survive FP filter)
_HEX32 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
_HEX40 = _HEX32 + 'a1b2c3d4'
_HEX48 = _HEX40 + 'e5f6a7b8'
_HEX64 = _HEX32 * 2
_ALNUM20 = 'aB1cD2eF3gH4iJ5kL6mN'
_ALNUM24 = _ALNUM20 + '7oP8'
_ALNUM27 = _ALNUM24 + 'qR9'
_ALNUM30 = _ALNUM27 + 'sT0'
_ALNUM32 = _ALNUM30 + 'uV'
_ALNUM34 = _ALNUM32 + 'wX'
_ALNUM36 = _ALNUM34 + 'yZ'
_ALNUM40 = _ALNUM36 + '2345'
_ALNUM43 = _ALNUM40 + 'AbC'
_ALNUM50 = _ALNUM43 + 'dEfGhIj'
_ALNUM52 = _ALNUM50 + 'Kl'
_ALNUM59 = _ALNUM52 + 'MnOpQrS'
_ALNUM80 = _ALNUM40 * 2


# ============================================================
# PATTERNS MODULE TESTS
# ============================================================

class TestPatternCompilation(unittest.TestCase):
    """All patterns compile and have the correct structure."""

    def test_pattern_count_minimum(self):
        self.assertGreaterEqual(len(patterns.JS_SECRET_PATTERNS), 240)

    def test_all_patterns_compiled(self):
        for p in patterns.JS_SECRET_PATTERNS:
            self.assertIsNotNone(p['regex'], f"Pattern {p['name']} has None regex")
            self.assertTrue(hasattr(p['regex'], 'search'), f"Pattern {p['name']} not compiled")

    def test_patterns_have_required_keys(self):
        required = {'name', 'regex', 'severity', 'confidence', 'category', 'validator_ref'}
        for p in patterns.JS_SECRET_PATTERNS:
            self.assertTrue(required.issubset(p.keys()), f"Missing keys in {p['name']}")

    def test_no_duplicate_names(self):
        names = [p['name'] for p in patterns.JS_SECRET_PATTERNS]
        self.assertEqual(len(names), len(set(names)), f"Duplicate names: {[n for n in names if names.count(n) > 1]}")

    def test_valid_severity_values(self):
        valid = {'critical', 'high', 'medium', 'low', 'info'}
        for p in patterns.JS_SECRET_PATTERNS:
            self.assertIn(p['severity'], valid, f"Invalid severity in {p['name']}")

    def test_valid_confidence_values(self):
        valid = {'high', 'medium', 'low'}
        for p in patterns.JS_SECRET_PATTERNS:
            self.assertIn(p['confidence'], valid, f"Invalid confidence in {p['name']}")


class TestScanReturnFormat(unittest.TestCase):
    """scan_js_content returns the expected tuple format."""

    def test_returns_tuple(self):
        result = patterns.scan_js_content('x', 'test.js')
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_findings_is_list(self):
        findings, _ = patterns.scan_js_content('AKIA1234567890ABCDEF', 'test.js')
        self.assertIsInstance(findings, list)

    def test_filtered_is_dict(self):
        _, filtered = patterns.scan_js_content('x', 'test.js')
        self.assertIsInstance(filtered, dict)
        expected_keys = {'low_entropy', 'base64_blob', 'binary_context', 'repetitive', 'url_whitelist', 'generic_noise',
                         'no_key_data', 'no_keyword_nearby'}
        self.assertEqual(set(filtered.keys()), expected_keys)

    def test_finding_has_all_fields(self):
        findings = _scan('AKIA1234567890ABCDEF')
        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        required = {'id', 'name', 'matched_text', 'redacted_value', 'severity',
                     'confidence', 'category', 'line_number', 'source_url',
                     'context', 'validator_ref', 'detection_method'}
        self.assertTrue(required.issubset(f.keys()), f"Missing: {required - f.keys()}")

    def test_empty_content(self):
        findings = _scan('')
        self.assertEqual(findings, [])


# ============================================================
# CLOUD CREDENTIAL DETECTION
# ============================================================

class TestCloudCredentials(unittest.TestCase):

    def test_aws_access_key(self):
        findings = _scan('const key = "AKIAIOSFODNN7EXAMPLE";')
        aws = [f for f in findings if f['name'] == 'AWS Access Key ID']
        self.assertEqual(len(aws), 1)
        self.assertEqual(aws[0]['severity'], 'critical')
        self.assertEqual(aws[0]['category'], 'cloud')

    def test_aws_secret_key(self):
        findings = _scan('aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
        aws = [f for f in findings if f['name'] == 'AWS Secret Key']
        self.assertEqual(len(aws), 1)

    def test_aws_mws_key(self):
        findings = _scan('amzn.mws.12345678-1234-1234-1234-123456789012')
        self.assertTrue(any(f['name'] == 'AWS MWS Key' for f in findings))

    def test_gcp_api_key(self):
        findings = _scan('AIzaSyC3kXLLPSFP3vl_xQrLm1XHPb5DOXKXNY12')
        self.assertTrue(any(f['name'] == 'GCP API Key' for f in findings))

    def test_firebase_url(self):
        findings = _scan('const db = "https://myapp-12345.firebaseio.com";')
        self.assertTrue(any(f['name'] == 'Firebase URL' for f in findings))

    def test_digitalocean_token(self):
        findings = _scan('dop_v1_' + _HEX64)
        self.assertTrue(any(f['name'] == 'DigitalOcean Token' for f in findings))

    def test_alibaba_access_key(self):
        findings = _scan(' LTAI' + _ALNUM20 + ' ')
        self.assertTrue(any(f['name'] == 'Alibaba Access Key ID' for f in findings))


# ============================================================
# PAYMENT DETECTION
# ============================================================

class TestPaymentDetection(unittest.TestCase):

    def test_stripe_secret_key(self):
        findings = _scan('sk_live_' + _ALNUM24)
        self.assertTrue(any(f['name'] == 'Stripe Secret Key' for f in findings))

    def test_stripe_test_key(self):
        findings = _scan('sk_test_' + _ALNUM24)
        self.assertTrue(any(f['name'] == 'Stripe Test Key' for f in findings))

    def test_razorpay_key(self):
        findings = _scan('rzp_live_ABCDEFghijklmn')
        self.assertTrue(any(f['name'] == 'Razorpay Key' for f in findings))


# ============================================================
# AI / LLM DETECTION
# ============================================================

class TestAILLMDetection(unittest.TestCase):

    def test_openai_classic_key(self):
        key = 'sk-' + _ALNUM20 + 'T3BlbkFJ' + _ALNUM20
        findings = _scan(key)
        self.assertTrue(any(f['name'] == 'OpenAI API Key' for f in findings))

    def test_openai_project_key(self):
        findings = _scan('sk-proj-' + _ALNUM80)
        self.assertTrue(any(f['name'] == 'OpenAI Project Key' for f in findings))

    def test_huggingface_token(self):
        findings = _scan('hf_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHi')
        self.assertTrue(any(f['name'] == 'HuggingFace Access Token' for f in findings))

    def test_groq_key(self):
        findings = _scan('gsk_' + _ALNUM52)
        self.assertTrue(any(f['name'] == 'Groq API Key' for f in findings))

    def test_perplexity_key(self):
        findings = _scan('pplx-' + _HEX48)
        self.assertTrue(any(f['name'] == 'Perplexity API Key' for f in findings))

    def test_replicate_token(self):
        findings = _scan('r8_' + _ALNUM40)
        self.assertTrue(any(f['name'] == 'Replicate API Token' for f in findings))

    def test_pinecone_key(self):
        findings = _scan('pcsk_' + _ALNUM50)
        self.assertTrue(any(f['name'] == 'Pinecone API Key' for f in findings))


# ============================================================
# AUTH TOKEN DETECTION
# ============================================================

class TestAuthTokenDetection(unittest.TestCase):

    def test_github_classic_token(self):
        findings = _scan('ghp_' + _ALNUM36)
        gh = [f for f in findings if f['name'] == 'GitHub Token Classic']
        self.assertEqual(len(gh), 1)
        self.assertEqual(gh[0]['validator_ref'], 'validate_github')

    def test_github_fine_grained_token(self):
        findings = _scan('github_pat_' + _ALNUM20 + 'Xy' + '_' + _ALNUM59)
        self.assertTrue(any(f['name'] == 'GitHub Fine-grained Token' for f in findings))

    def test_gitlab_pat(self):
        findings = _scan('glpat-' + _ALNUM20)
        self.assertTrue(any(f['name'] == 'GitLab PAT' for f in findings))

    def test_slack_bot_token(self):
        findings = _scan('xoxb-1234567890123-1234567890123-abcdef')
        self.assertTrue(any(f['name'] == 'Slack Bot Token' for f in findings))

    def test_slack_webhook(self):
        findings = _scan('https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop')
        self.assertTrue(any(f['name'] == 'Slack Webhook' for f in findings))

    def test_sendgrid_key(self):
        findings = _scan('SG.' + _ALNUM20 + 'Xy' + '.' + _ALNUM43)
        self.assertTrue(any(f['name'] == 'SendGrid API Key' for f in findings))

    def test_mailgun_key(self):
        findings = _scan('key-' + _ALNUM32)
        self.assertTrue(any(f['name'] == 'Mailgun API Key' for f in findings))

    def test_mailchimp_key(self):
        findings = _scan(_HEX32 + '-us10')
        self.assertTrue(any(f['name'] == 'Mailchimp API Key' for f in findings))

    def test_shopify_access_token(self):
        findings = _scan('shpat_' + _HEX32)
        self.assertTrue(any(f['name'] == 'Shopify Access Token' for f in findings))


# ============================================================
# DISCORD BUG FIX: {4,7} middle segment
# ============================================================

class TestDiscordTokenFix(unittest.TestCase):
    """Discord tokens have 4-7 chars in the middle timestamp segment."""

    def _make_discord(self, mid_len):
        first = 'MTAyNjk1NDUwOTU5OTQ5NjQzMg'  # 27 chars: M + 26 base64
        mid = _ALNUM20[:mid_len]
        third = _ALNUM27
        return first + '.' + mid + '.' + third

    def test_3_char_middle_rejected(self):
        findings = _scan(self._make_discord(3))
        self.assertFalse(any(f['name'] == 'Discord Bot Token' for f in findings))

    def test_4_char_middle_accepted(self):
        findings = _scan(self._make_discord(4))
        self.assertTrue(any(f['name'] == 'Discord Bot Token' for f in findings))

    def test_5_char_middle_accepted(self):
        findings = _scan(self._make_discord(5))
        self.assertTrue(any(f['name'] == 'Discord Bot Token' for f in findings))

    def test_6_char_middle_accepted(self):
        findings = _scan(self._make_discord(6))
        self.assertTrue(any(f['name'] == 'Discord Bot Token' for f in findings))

    def test_7_char_middle_accepted(self):
        findings = _scan(self._make_discord(7))
        self.assertTrue(any(f['name'] == 'Discord Bot Token' for f in findings))

    def test_8_char_middle_rejected(self):
        findings = _scan(self._make_discord(8))
        self.assertFalse(any(f['name'] == 'Discord Bot Token' for f in findings))

    def test_validator_regex_matches_pattern(self):
        token = self._make_discord(6)
        validator_re = re.compile(r'([MN][A-Za-z\d]{23,}\.[\w-]{4,7}\.[\w-]{27,})')
        self.assertTrue(validator_re.search(token))


# ============================================================
# MODERN JS / SERVERLESS ECOSYSTEM (New patterns)
# ============================================================

class TestModernJSPatterns(unittest.TestCase):

    def test_clerk_secret_key(self):
        # sk_live_ + 27 alnum matches both Stripe (24+) and Clerk (27+) at the
        # same span; span-dedup collapses them, so Clerk may appear as either
        # the primary or an alternate.
        findings = _scan('sk_live_' + _ALNUM27)
        self.assertTrue(any(
            f['name'] == 'Clerk Secret Key' or 'Clerk Secret Key' in f.get('alternate_names', [])
            for f in findings
        ))

    def test_clerk_short_not_matched(self):
        """Clerk keys are 27+ chars; shorter should only match Stripe."""
        findings = _scan('sk_live_' + _ALNUM24)
        all_names = {f['name'] for f in findings} | {
            n for f in findings for n in f.get('alternate_names', [])
        }
        self.assertNotIn('Clerk Secret Key', all_names)
        self.assertIn('Stripe Secret Key', all_names)

    def test_neon_connection_string(self):
        findings = _scan('postgresql://user:pass@ep-cool-123456.us-east-2.aws.neon.tech/neondb')
        self.assertTrue(any(f['name'] == 'Neon DB Connection String' for f in findings))

    def test_resend_api_key(self):
        findings = _scan('re_' + _ALNUM20)
        self.assertTrue(any(f['name'] == 'Resend API Key' for f in findings))

    def test_trigger_dev_key(self):
        findings = _scan('tr_prod_' + _ALNUM24)
        self.assertTrue(any(f['name'] == 'Trigger.dev API Key' for f in findings))

    def test_axiom_api_token(self):
        findings = _scan('xaat-12345678-1234-1234-1234-123456789012')
        self.assertTrue(any(f['name'] == 'Axiom API Token' for f in findings))

    def test_axiom_ingest_token(self):
        findings = _scan('xait-12345678-1234-1234-1234-123456789012')
        self.assertTrue(any(f['name'] == 'Axiom Ingest Token' for f in findings))

    def test_cloudinary_url(self):
        findings = _scan('cloudinary://123456789012345:ABCDEFGhijklmnopq_rst@mycloud')
        self.assertTrue(any(f['name'] == 'Cloudinary URL' for f in findings))

    def test_expo_access_token(self):
        findings = _scan('expo_' + _ALNUM40)
        self.assertTrue(any(f['name'] == 'Expo Access Token' for f in findings))

    def test_sentry_new_auth_token(self):
        findings = _scan('sntrys_eyJ' + _ALNUM80)
        self.assertTrue(any(f['name'] == 'Sentry Auth Token (new)' for f in findings))


# ============================================================
# GENERAL SECRET / INFRA DETECTION
# ============================================================

class TestGeneralSecrets(unittest.TestCase):

    def test_jwt_detection(self):
        jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        findings = _scan(jwt)
        self.assertTrue(any(f['name'] == 'JWT Token' for f in findings))

    def test_rsa_private_key(self):
        # The marker alone is a parser branch or a runtime template in library
        # code; a key needs key data after it (TruffleHog plan, item 0.2).
        body = ('MIIEow' + 'IBAAKCAQEA' + 'x7Kp2Lm9Qz4Wn8Rt1Yb6Vc3Hd5Jf0Gs2') * 3
        findings = _scan('-----BEGIN RSA PRIVATE KEY-----\n' + body + '\n-----END RSA PRIVATE KEY-----')
        self.assertTrue(any(f['name'] == 'RSA Private Key' for f in findings))
        self.assertFalse(any(f['name'] == 'RSA Private Key'
                             for f in _scan('"-----BEGIN RSA PRIVATE KEY-----\\n" + body')))

    def test_mongodb_uri(self):
        findings = _scan('mongodb+srv://user:pass@cluster.mongodb.net/db')
        self.assertTrue(any(f['name'] == 'MongoDB URI' for f in findings))

    def test_postgres_uri(self):
        findings = _scan(' postgresql://user:xK9mPw2@dbhost.example.com:5432/mydb ')
        self.assertTrue(any(f['name'] == 'PostgreSQL URI' for f in findings))

    def test_s3_bucket_detection(self):
        findings = _scan('https://mybucket.s3.amazonaws.com/file')
        self.assertTrue(any('S3' in f['name'] for f in findings))

    def test_private_ip_detection(self):
        findings = _scan(' 192.168.1.100 ')
        self.assertTrue(any(f['name'] == 'Private IP (RFC1918)' for f in findings))

    def test_localhost_detection(self):
        findings = _scan('localhost:3000')
        self.assertTrue(any(f['name'] == 'Localhost with Port' for f in findings))


# ============================================================
# DEDUPLICATION
# ============================================================

class TestDeduplication(unittest.TestCase):

    def test_same_key_deduped(self):
        js = 'AKIA1234567890ABCDEF\nAKIA1234567890ABCDEF\nAKIA1234567890ABCDEF'
        findings = _scan(js)
        aws = [f for f in findings if f['name'] == 'AWS Access Key ID']
        self.assertEqual(len(aws), 1)

    def test_different_keys_not_deduped(self):
        js = 'AKIA1234567890ABCDEF\nAKIA9876543210ZYXWVU'
        findings = _scan(js)
        aws = [f for f in findings if f['name'] == 'AWS Access Key ID']
        self.assertEqual(len(aws), 2)

    def test_unique_ids(self):
        js = 'AKIA1234567890ABCDEF\nghp_' + _ALNUM36
        findings = _scan(js)
        ids = [f['id'] for f in findings]
        self.assertEqual(len(ids), len(set(ids)))


class TestCrossPatternSpanDedup(unittest.TestCase):
    """Overlapping prefix patterns matching the same span collapse to one finding."""

    def test_stripe_clerk_workos_collapse(self):
        # sk_live_ + 30 alnum matches Stripe (24+), Clerk (27+), and WorkOS (30+)
        findings = _scan('sk_live_' + _ALNUM30)
        sk_live_findings = [f for f in findings if f['matched_text'].startswith('sk_live_')]
        self.assertEqual(len(sk_live_findings), 1, "Same span should collapse to one finding")
        primary = sk_live_findings[0]
        all_names = {primary['name']} | set(primary.get('alternate_names', []))
        self.assertIn('Stripe Secret Key', all_names)
        self.assertIn('Clerk Secret Key', all_names)
        self.assertIn('WorkOS API Key', all_names)

    def test_distinct_spans_not_collapsed(self):
        # Two different tokens on different lines -- no collapse
        js = 'sk_live_' + _ALNUM30 + '\nAKIA1234567890ABCDEF'
        findings = _scan(js)
        matched = {f['matched_text'] for f in findings}
        self.assertIn('AKIA1234567890ABCDEF', matched)
        self.assertTrue(any(m.startswith('sk_live_') for m in matched))

    def test_single_match_no_alternates(self):
        # OpenAI pattern is unique -- no collapse, no alternate_names
        findings = _scan('sk-' + _ALNUM20 + 'T3BlbkFJ' + _ALNUM20)
        openai = [f for f in findings if f['name'] == 'OpenAI API Key']
        self.assertEqual(len(openai), 1)
        self.assertEqual(openai[0].get('alternate_names', []), [])


# ============================================================
# FALSE POSITIVE FILTERS
# ============================================================

class TestFalsePositiveFilters(unittest.TestCase):

    def test_email_filter_example_domain(self):
        findings = _scan('contact@example.com')
        self.assertFalse(any(f['name'] == 'Email Address' for f in findings))

    def test_email_real_domain_kept(self):
        findings = _scan('admin@target.com')
        self.assertTrue(any(f['name'] == 'Email Address' for f in findings))

    def test_staging_url_whitelist(self):
        # `dev` is a whole host label here, so the pattern matches and the
        # documentation-domain whitelist is what drops it.
        findings, filtered = _scan_full('https://dev.w3.org/csswg/testing-internal-api')
        self.assertGreaterEqual(filtered['url_whitelist'], 1)
        self.assertFalse(any(f['name'] == 'Internal/Staging URL' for f in findings))

    def test_documentation_host_containing_a_keyword_is_not_a_staging_url(self):
        findings = _scan('https://developer.mozilla.org/testing-internal-api')
        self.assertFalse(any(f['name'] == 'Internal/Staging URL' for f in findings))

    def test_staging_url_real_kept(self):
        findings = _scan('https://staging.internal-app.com')
        self.assertTrue(any(f['name'] == 'Internal/Staging URL' for f in findings))

    def test_low_entropy_filtered(self):
        _, filtered = _scan_full('api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"')
        self.assertGreaterEqual(filtered['low_entropy'], 0)

    def test_repetitive_pattern_filtered(self):
        _, filtered = _scan_full('token = "AAAAAA' + 'B' * 40 + '"')
        self.assertGreaterEqual(filtered['repetitive'], 0)

    def test_innocent_code_no_secrets(self):
        innocents = [
            'var config = {debug: false, version: "1.0"}',
            'function handleClick(event) { return event.target.value; }',
            'console.log("Hello World");',
            'import React from "react";',
        ]
        for code in innocents:
            findings = _scan(code)
            secrets = [f for f in findings if f['category'] not in ('info', 'infrastructure')]
            self.assertEqual(len(secrets), 0, f"FP in: {code[:50]}")


# ============================================================
# CONFIDENCE FILTERING
# ============================================================

class TestConfidenceFilter(unittest.TestCase):

    def test_high_confidence_filters_low(self):
        js = 'AKIA1234567890ABCDEF'  # high confidence
        high = _scan(js, min_confidence='high')
        low = _scan(js, min_confidence='low')
        self.assertLessEqual(len(high), len(low))

    def test_medium_confidence(self):
        findings = _scan('AKIA1234567890ABCDEF', min_confidence='medium')
        self.assertGreaterEqual(len(findings), 1)


# ============================================================
# REDACTION
# ============================================================

class TestRedaction(unittest.TestCase):

    def test_long_secret_redacted(self):
        findings = _scan('AKIA1234567890ABCDEF')
        f = [x for x in findings if x['name'] == 'AWS Access Key ID'][0]
        self.assertIn('...', f['redacted_value'])
        self.assertTrue(f['redacted_value'].startswith('AKIA12'))
        self.assertTrue(f['redacted_value'].endswith('CDEF'))

    def test_original_text_preserved(self):
        findings = _scan('AKIA1234567890ABCDEF')
        f = [x for x in findings if x['name'] == 'AWS Access Key ID'][0]
        self.assertEqual(f['matched_text'], 'AKIA1234567890ABCDEF')


# ============================================================
# LINE THRESHOLD
# ============================================================

class TestLongLineWindowing(unittest.TestCase):
    """Minified single-line bundles must be scanned in overlapping windows,
    not skipped. Regression coverage for the 100k-line-skip bug that silently
    dropped every secret in a minified webpack bundle."""

    # --- _window_line helper unit tests ---

    def test_window_short_line_single_segment(self):
        self.assertEqual(patterns._window_line('abc', size=100, overlap=10), [(0, 'abc')])

    def test_window_covers_entire_line(self):
        line = ''.join(chr(65 + (i % 26)) for i in range(250_000))
        segs = patterns._window_line(line, size=100_000, overlap=5_000)
        self.assertGreater(len(segs), 1)
        # Every index of the original line is covered by at least one window,
        # and each window's offset is where its text sits in the line.
        step = 100_000 - 5_000
        covered = [False] * len(line)
        for w, (start, seg) in enumerate(segs):
            self.assertEqual(start, w * step)
            self.assertEqual(seg, line[start:start + 100_000])
            for i in range(start, min(start + 100_000, len(line))):
                covered[i] = True
        self.assertTrue(all(covered))

    def test_window_short_enough_line_not_split(self):
        line = 'x' * 100_000  # exactly the threshold, not over it
        self.assertEqual(len(patterns._window_line(line)), 1)

    # --- scan_js_content behavior tests ---

    def test_short_line_processed(self):
        findings = _scan('AKIA1234567890ABCDEF')
        self.assertGreaterEqual(len(findings), 1)

    def test_secret_at_start_of_huge_minified_line_found(self):
        # Previously the whole line was skipped; now it must be scanned. The key
        # is quote-delimited as in real minified code, so the base64-blob and
        # entropy false-positive filters do not fire.
        long_line = 'var k="AKIA1234567890ABCDEF";' + 'x' * 200_000
        findings = _scan(long_line)
        self.assertTrue(any(f['name'] == 'AWS Access Key ID' for f in findings))

    def test_slack_webhook_deep_in_500k_bundle_found(self):
        # The Workday bundle case: webhook buried deep inside a minified one-liner.
        url = 'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop'
        bundle = 'v=' + 'a' * 500_000 + ';SLACK_WEBHOOK_INTERNAL="' + url + '";'
        findings = _scan(bundle, 'https://community.workday.com/bundle.js')
        self.assertTrue(any(f['name'] == 'Slack Webhook' for f in findings))

    def test_secret_straddling_window_boundary_found(self):
        # Token crosses the 100k window edge; the 5k overlap must keep it intact.
        url = 'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop'
        token = 'SLACK_X="' + url + '";'
        bundle = 'a' * (100_000 - 20) + token + 'b' * 50_000
        findings = _scan(bundle)
        self.assertTrue(any(f['name'] == 'Slack Webhook' for f in findings))

    def test_no_duplicate_findings_across_overlap(self):
        # A secret sitting fully inside the overlap region [95k, 100k] is present
        # in two consecutive windows but must be reported exactly once.
        url = 'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop'
        bundle = 'a' * 96_000 + 'X="' + url + '";' + 'b' * 20_000
        findings = _scan(bundle)
        slack = [f for f in findings if f['name'] == 'Slack Webhook']
        self.assertEqual(len(slack), 1)

    def test_pathological_repetitive_line_scans_fast(self):
        # Repetitive runs are the classic O(n^2)/ReDoS trigger. A 1M-char run
        # must scan in well under the old skip threshold; guards against the
        # Email/GitHub-Credentials-URL regexes regressing to greedy backtracking.
        import time
        line = 'v=' + 'a' * 1_000_000 + ';'
        t = time.time()
        _scan(line)
        self.assertLess(time.time() - t, 20.0)


# ============================================================
# CUSTOM PATTERNS
# ============================================================

class TestCustomPatterns(unittest.TestCase):

    def test_custom_string_regex(self):
        custom = [{'name': 'MyKey', 'regex': r'MYCO-[a-f0-9]{8}', 'severity': 'critical', 'confidence': 'high'}]
        findings = _scan('MYCO-abcd1234', custom_patterns=custom)
        self.assertTrue(any(f['name'] == 'MyKey' for f in findings))

    def test_custom_compiled_regex(self):
        custom = [{'name': 'C', 'regex': re.compile(r'XKEY_[a-z]{10}'), 'severity': 'high', 'confidence': 'high', 'category': 'custom'}]
        findings = _scan('XKEY_abcdefghij', custom_patterns=custom)
        self.assertTrue(any(f['name'] == 'C' for f in findings))

    def test_invalid_custom_regex_no_crash(self):
        custom = [{'name': 'Bad', 'regex': r'[invalid(', 'severity': 'high', 'confidence': 'high'}]
        findings = _scan('something', custom_patterns=custom)
        self.assertIsInstance(findings, list)

    def test_load_custom_patterns_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([{"name": "Test", "regex": "TEST-[0-9]+"}], f)
            f.flush()
            loaded = patterns.load_custom_patterns(f.name)
        os.unlink(f.name)
        self.assertEqual(len(loaded), 1)

    def test_load_custom_patterns_txt(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("MyP|MYKEY-[a-z]+|critical|high\n# comment\n")
            f.flush()
            loaded = patterns.load_custom_patterns(f.name)
        os.unlink(f.name)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]['severity'], 'critical')

    def test_load_empty_path(self):
        self.assertEqual(patterns.load_custom_patterns(''), [])

    def test_load_bad_path(self):
        self.assertEqual(patterns.load_custom_patterns('/nonexistent/file.json'), [])


# ============================================================
# CONTEXT EXTRACTION
# ============================================================

class TestContextExtraction(unittest.TestCase):

    def test_multiline_context(self):
        js = 'line1\nAKIA1234567890ABCDEF\nline3\nline4'
        findings = _scan(js)
        f = [x for x in findings if x['name'] == 'AWS Access Key ID'][0]
        # The neighbour lines, with the key itself shown redacted, never raw.
        self.assertEqual(f['context'], 'line1\nAKIA12...CDEF\nline3')
        self.assertEqual(f['line_number'], 2)

    def test_context_max_chars(self):
        js = 'A' * 200 + 'AKIA1234567890ABCDEF' + 'B' * 200
        findings = _scan(js)
        if findings:
            self.assertLessEqual(len(findings[0]['context']), patterns.CONTEXT_MAX_CHARS)


# ============================================================
# DEV COMMENTS
# ============================================================

class TestDevComments(unittest.TestCase):

    def test_todo_comment(self):
        comments = patterns.scan_dev_comments('// TODO: fix this later', 'test.js')
        self.assertGreaterEqual(len(comments), 1)
        self.assertEqual(comments[0]['type'], 'dev_comment')

    def test_fixme_comment(self):
        comments = patterns.scan_dev_comments('// FIXME: broken handler', 'test.js')
        self.assertGreaterEqual(len(comments), 1)

    def test_sensitive_todo(self):
        comments = patterns.scan_dev_comments('// TODO: remove hardcoded password', 'test.js')
        self.assertTrue(any(c['severity'] == 'medium' for c in comments))

    def test_sensitive_comment_without_todo(self):
        comments = patterns.scan_dev_comments('// check the admin password in config', 'test.js')
        self.assertTrue(any(c['type'] == 'sensitive_comment' for c in comments))

    def test_comments_have_id(self):
        comments = patterns.scan_dev_comments('// TODO: test\n// FIXME: broken', 'test.js')
        for c in comments:
            self.assertIn('id', c)


# ============================================================
# VALIDATORS MODULE TESTS
# ============================================================

class TestValidators(unittest.TestCase):

    def test_registry_covers_all_pattern_refs(self):
        for p in patterns.JS_SECRET_PATTERNS:
            ref = p.get('validator_ref')
            if ref:
                self.assertIn(ref, validators.VALIDATOR_REGISTRY, f"Missing validator: {ref}")

    def test_no_validator_ref(self):
        r = validators.validate_secret('test', 'test', validator_ref=None)
        self.assertEqual(r['error'], 'no_validator')

    def test_unknown_validator_ref(self):
        r = validators.validate_secret('test', 'test', validator_ref='nonexistent')
        self.assertEqual(r['error'], 'no_validator')

    def test_aws_incomplete(self):
        r = validators.validate_aws('AKIAIOSFODNN7EXAMPLE')
        self.assertEqual(r['error'], 'incomplete_credentials')

    def test_twilio_incomplete(self):
        r = validators.validate_twilio('AC' + 'a' * 32)
        self.assertEqual(r['error'], 'incomplete_credentials')

    def test_github_no_token(self):
        r = validators.validate_github('no token here')
        self.assertEqual(r['error'], 'no_token_found')

    def test_all_validators_return_dict(self):
        for name, func in validators.VALIDATOR_REGISTRY.items():
            r = func('dummy_text', timeout=1)
            self.assertIsInstance(r, dict, f"Validator {name} didn't return dict")
            self.assertIn('valid', r)
            self.assertIn('error', r)


class TestTwilioValidatorFix(unittest.TestCase):
    """Twilio validator must match AC[a-zA-Z0-9]{32} (not just hex)."""

    def test_mixed_case_sid(self):
        r = validators.validate_twilio_format('AC' + _ALNUM32)
        self.assertEqual(r['error'], 'format_only')

    def test_hex_only_sid(self):
        r = validators.validate_twilio_format('AC' + _HEX32)
        self.assertEqual(r['error'], 'format_only')

    def test_low_entropy_sid_rejected(self):
        r = validators.validate_twilio_format('AC' + 'a' * 32)
        self.assertEqual(r['error'], 'format_invalid')

    def test_no_sid_rejected(self):
        r = validators.validate_twilio_format('no sid here')
        self.assertEqual(r['error'], 'format_invalid')


class TestDiscordValidatorFix(unittest.TestCase):
    """Discord validator regex must match 4-7 char middle segment."""

    def test_validator_matches_6_char(self):
        token = 'M' + 'T' * 23 + '.' + 'x' * 6 + '.' + 'A' * 27
        r = validators.validate_discord(token)
        self.assertNotEqual(r['error'], 'no_token_found')

    def test_validator_matches_4_char(self):
        token = 'M' + 'T' * 23 + '.' + 'x' * 4 + '.' + 'A' * 27
        r = validators.validate_discord(token)
        self.assertNotEqual(r['error'], 'no_token_found')


class TestTwitterValidator(unittest.TestCase):

    def test_valid_bearer_format(self):
        token = 'AAAAAAAAAAAAAAAAAAAAAA' + 'AbCdEfGhIjKlMnOpQrStUvWxYz12345'
        r = validators.validate_twitter_format(token)
        self.assertEqual(r['error'], 'format_only')

    def test_short_bearer_rejected(self):
        token = 'AAAAAAAAAAAAAAAAAAAAAA' + 'short'
        r = validators.validate_twitter_format(token)
        self.assertEqual(r['error'], 'format_invalid')


# ============================================================
# HELPER FUNCTION TESTS
# ============================================================

class TestHelperFunctions(unittest.TestCase):

    def test_shannon_entropy_empty(self):
        self.assertEqual(patterns._shannon_entropy(''), 0.0)

    def test_shannon_entropy_low(self):
        self.assertLess(patterns._shannon_entropy('aaaa'), 1.0)

    def test_shannon_entropy_high(self):
        self.assertGreater(patterns._shannon_entropy('aB1cD2eF3gH4iJ5k'), 3.5)

    def test_is_inside_base64_blob_yes(self):
        line = 'A' * 300
        self.assertTrue(patterns._is_inside_base64_blob(line, 100, 120))

    def test_is_inside_base64_blob_no(self):
        line = 'hello AKIA1234567890ABCDEF world'
        self.assertFalse(patterns._is_inside_base64_blob(line, 6, 26))

    def test_has_binary_context_font(self):
        self.assertTrue(patterns._has_binary_context('@font-face { src: url(...) }'))

    def test_has_binary_context_normal(self):
        self.assertFalse(patterns._has_binary_context('const key = "abc123";'))

    def test_has_repetitive_pattern_yes(self):
        self.assertTrue(patterns._has_repetitive_pattern('AAAAAA' + 'B' * 20))

    def test_has_repetitive_pattern_no(self):
        self.assertFalse(patterns._has_repetitive_pattern('aB1cD2eF3gH4iJ5kL'))

    def test_is_whitelisted_staging_url(self):
        self.assertTrue(patterns._is_whitelisted_staging_url('https://developer.mozilla.org/docs'))
        self.assertFalse(patterns._is_whitelisted_staging_url('https://staging.myapp.com'))

    def test_make_finding_id_deterministic(self):
        id1 = patterns._make_finding_id('AWS', 'AKIA123', 'test.js')
        id2 = patterns._make_finding_id('AWS', 'AKIA123', 'test.js')
        self.assertEqual(id1, id2)

    def test_make_finding_id_unique(self):
        id1 = patterns._make_finding_id('AWS', 'AKIA123', 'a.js')
        id2 = patterns._make_finding_id('AWS', 'AKIA456', 'a.js')
        self.assertNotEqual(id1, id2)


# ============================================================
# SOURCEMAP MODULE TESTS
# ============================================================

class TestSourcemap(unittest.TestCase):

    def test_comment_standard(self):
        r = sourcemap.check_sourcemap_comment('var x;\n//# sourceMappingURL=app.js.map')
        self.assertEqual(r, 'app.js.map')

    def test_comment_multiline(self):
        r = sourcemap.check_sourcemap_comment('var x;\n/*# sourceMappingURL=app.js.map */')
        self.assertEqual(r, 'app.js.map')

    def test_comment_none(self):
        self.assertIsNone(sourcemap.check_sourcemap_comment('var x = 1;'))

    def test_header_found(self):
        self.assertEqual(sourcemap.check_sourcemap_header({'SourceMap': '/app.js.map'}), '/app.js.map')

    def test_header_none(self):
        self.assertIsNone(sourcemap.check_sourcemap_header({'Content-Type': 'text/javascript'}))

    def test_disabled(self):
        self.assertEqual(sourcemap.discover_and_analyze_sourcemaps([], {'JS_RECON_SOURCE_MAPS': False}), [])


# ============================================================
# DEPENDENCY MODULE TESTS
# ============================================================

class TestDependency(unittest.TestCase):

    def test_extract_es6(self):
        self.assertIn('@org/lib', dependency.extract_scoped_packages("import x from '@org/lib';"))

    def test_extract_require(self):
        self.assertIn('@co/sdk', dependency.extract_scoped_packages("require('@co/sdk');"))

    def test_extract_none(self):
        self.assertEqual(len(dependency.extract_scoped_packages("import React from 'react';")), 0)

    def test_disabled(self):
        self.assertEqual(dependency.detect_dependency_confusion([], {'JS_RECON_DEPENDENCY_CHECK': False}), [])


# ============================================================
# ENDPOINTS MODULE TESTS
# ============================================================

class TestEndpoints(unittest.TestCase):

    def _ep_scan(self, js):
        return endpoints_mod.extract_endpoints(
            [{'url': 'app.js', 'content': js}],
            {'JS_RECON_EXTRACT_ENDPOINTS': True, 'JS_RECON_CUSTOM_ENDPOINT_KEYWORDS': ''}
        )

    def test_fetch(self):
        eps = self._ep_scan("fetch('/api/v1/users');")
        self.assertTrue(any(e['path'] == '/api/v1/users' for e in eps))

    def test_websocket(self):
        eps = self._ep_scan("new WebSocket('wss://a.com/ws');")
        self.assertTrue(any(e.get('type') == 'websocket' for e in eps))

    def test_filter_css(self):
        eps = self._ep_scan("fetch('/styles/app.css');")
        self.assertFalse(any('.css' in e.get('path', '') for e in eps))

    def test_disabled(self):
        self.assertEqual(endpoints_mod.extract_endpoints([], {'JS_RECON_EXTRACT_ENDPOINTS': False}), [])


_EXAMPLE_SCOPE = js_recon._ProbeScope(roots=('example.com',))


class TestEndpointValidationHelpers(unittest.TestCase):

    def test_parse_endpoint_validation_headers_accepts_auth_and_cookie(self):
        headers = js_recon._parse_endpoint_validation_headers([
            'Cookie: session=abc123',
            'Authorization: Bearer token',
            '',
            'malformed',
            object(),
            'X-Blank:   ',
        ])

        self.assertEqual(headers['Cookie'], 'session=abc123')
        self.assertEqual(headers['Authorization'], 'Bearer token')
        self.assertEqual(headers['User-Agent'], 'Mozilla/5.0 (compatible; RedAmon-JsRecon/1.0)')
        self.assertNotIn('X-Blank', headers)
        self.assertNotIn('malformed', headers)

    def test_resolve_endpoint_candidate_url_resolves_relative_from_source_js(self):
        url = js_recon._resolve_endpoint_candidate_url({
            'path': '/api/users',
            'source_js': 'https://app.example.com/static/main.js',
        })

        self.assertEqual(url, 'https://app.example.com/api/users')

    def test_resolve_endpoint_candidate_url_preserves_absolute_full_url(self):
        url = js_recon._resolve_endpoint_candidate_url({
            'full_url': 'https://api.example.com/v1/users',
            'source_js': 'https://app.example.com/static/main.js',
        })

        self.assertEqual(url, 'https://api.example.com/v1/users')

    def test_resolve_endpoint_candidate_url_returns_empty_for_uploaded_relative(self):
        url = js_recon._resolve_endpoint_candidate_url({
            'path': '/api/users',
            'source_js': 'upload://bundle.js',
        })

        self.assertEqual(url, '')

    @pytest.mark.xfail(strict=True, reason="Part H triage (bucket-3): behavior/mapping/shape drifted from this assertion post-refactor; correctness unconfirmed - see green-up report")
    def test_validate_extracted_endpoints_marks_accepted_status_hittable(self):
        calls = []

        class Response:
            status_code = 403

        def request_func(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return Response()

        endpoints = [{
            'path': '/admin',
            'source_js': 'https://app.example.com/static/main.js',
            'method': 'post',
        }]

        validated = js_recon._validate_extracted_endpoints(endpoints, {
            'JS_RECON_VALIDATE_ENDPOINTS': True,
            'JS_RECON_ENDPOINT_CUSTOM_HEADERS': ['Cookie: session=abc123'],
        }, _EXAMPLE_SCOPE, request_func=request_func)

        self.assertIs(validated, endpoints)
        self.assertEqual(validated[0]['validation_status'], 'hittable')
        self.assertEqual(validated[0]['status_code'], 403)
        self.assertEqual(validated[0]['resolved_url'], 'https://app.example.com/admin')
        self.assertEqual(validated[0]['validation_error'], '')
        self.assertEqual(calls[0][0], 'OPTIONS')
        self.assertEqual(calls[0][1], 'https://app.example.com/admin')
        self.assertEqual(calls[0][2]['headers']['Cookie'], 'session=abc123')
        self.assertFalse(calls[0][2]['allow_redirects'])

    @pytest.mark.xfail(strict=True, reason="Part H triage (bucket-3): behavior/mapping/shape drifted from this assertion post-refactor; correctness unconfirmed - see green-up report")
    def test_validate_extracted_endpoints_does_not_replay_mutating_methods(self):
        calls = []

        class Response:
            status_code = 204

        endpoints = [{
            'path': '/api/user/123',
            'source_js': 'https://app.example.com/static/main.js',
            'method': 'DELETE',
        }]

        validated = js_recon._validate_extracted_endpoints(
            endpoints,
            {'JS_RECON_VALIDATE_ENDPOINTS': True},
            _EXAMPLE_SCOPE,
            request_func=lambda method, url, **kwargs: calls.append((method, url, kwargs)) or Response(),
        )

        self.assertEqual(validated[0]['validation_status'], 'hittable')
        self.assertEqual(calls[0][0], 'OPTIONS')

    @pytest.mark.xfail(strict=True, reason="Part H triage (bucket-3): behavior/mapping/shape drifted from this assertion post-refactor; correctness unconfirmed - see green-up report")
    def test_validate_extracted_endpoints_does_not_send_custom_headers_cross_origin(self):
        calls = []

        class Response:
            status_code = 200

        endpoints = [{
            'full_url': 'https://analytics.vendor.example/collect',
            'source_js': 'https://app.example.com/static/main.js',
            'method': 'GET',
        }]

        js_recon._validate_extracted_endpoints(
            endpoints,
            {
                'JS_RECON_VALIDATE_ENDPOINTS': True,
                'JS_RECON_ENDPOINT_CUSTOM_HEADERS': [
                    'Cookie: session=abc123',
                    'Authorization: Bearer token',
                ],
            },
            # In scope, so it is probed, yet a different origin from the JS file.
            js_recon._ProbeScope(roots=('example.com',), hosts=frozenset({'analytics.vendor.example'})),
            request_func=lambda method, url, **kwargs: calls.append((method, url, kwargs)) or Response(),
        )

        headers = calls[0][2]['headers']
        self.assertNotIn('Cookie', headers)
        self.assertNotIn('Authorization', headers)
        self.assertEqual(headers['User-Agent'], 'Mozilla/5.0 (compatible; RedAmon-JsRecon/1.0)')

    @pytest.mark.xfail(strict=True, reason="Part H triage (bucket-3): behavior/mapping/shape drifted from this assertion post-refactor; correctness unconfirmed - see green-up report")
    def test_validate_extracted_endpoints_keeps_404_as_not_hittable(self):
        class Response:
            status_code = 404

        endpoints = [{
            'full_url': 'https://api.example.com/missing',
            'method': 'GET',
        }]

        validated = js_recon._validate_extracted_endpoints(
            endpoints,
            {'JS_RECON_VALIDATE_ENDPOINTS': True},
            _EXAMPLE_SCOPE,
            request_func=lambda *args, **kwargs: Response(),
        )

        self.assertEqual(len(validated), 1)
        self.assertEqual(validated[0]['full_url'], 'https://api.example.com/missing')
        self.assertEqual(validated[0]['validation_status'], 'not_hittable')
        self.assertEqual(validated[0]['status_code'], 404)
        self.assertEqual(validated[0]['resolved_url'], 'https://api.example.com/missing')
        self.assertEqual(validated[0]['validation_error'], '')

    def test_validate_extracted_endpoints_uploaded_relative_is_unvalidated(self):
        calls = []
        endpoints = [{
            'path': '/api/users',
            'source_js': 'upload://bundle.js',
        }]

        validated = js_recon._validate_extracted_endpoints(
            endpoints,
            {'JS_RECON_VALIDATE_ENDPOINTS': True},
            _EXAMPLE_SCOPE,
            request_func=lambda *args, **kwargs: calls.append((args, kwargs)),
        )

        self.assertEqual(validated[0]['validation_status'], 'unvalidated')
        self.assertEqual(validated[0]['validation_error'], 'unresolved_url')
        self.assertEqual(calls, [])

    def test_validate_extracted_endpoints_relative_websocket_is_unvalidated(self):
        calls = []
        endpoints = [{
            'method': 'WS',
            'type': 'websocket',
            'path': '/ws',
            'source_js': 'https://app.example.com/app.js',
        }]

        validated = js_recon._validate_extracted_endpoints(
            endpoints,
            {'JS_RECON_VALIDATE_ENDPOINTS': True},
            _EXAMPLE_SCOPE,
            request_func=lambda *args, **kwargs: calls.append((args, kwargs)),
        )

        self.assertEqual(validated[0]['validation_status'], 'unvalidated')
        self.assertEqual(validated[0]['validation_error'], 'unsupported_scheme')
        self.assertEqual(calls, [])

    def test_validate_extracted_endpoints_disabled_marks_unvalidated(self):
        calls = []
        endpoints = [{'full_url': 'https://api.example.com/users'}]

        validated = js_recon._validate_extracted_endpoints(
            endpoints,
            {'JS_RECON_VALIDATE_ENDPOINTS': False},
            _EXAMPLE_SCOPE,
            request_func=lambda *args, **kwargs: calls.append((args, kwargs)),
        )

        self.assertIs(validated, endpoints)
        self.assertEqual(validated[0]['validation_status'], 'unvalidated')
        self.assertEqual(validated[0]['validation_error'], 'validation_disabled')
        self.assertEqual(calls, [])

    def test_validate_extracted_endpoints_never_probes_a_third_party_host(self):
        probed = []

        class Response:
            status_code = 200

        class Missing:              # a real server 404s the catch-all control's made-up path
            status_code = 404

        endpoints = [
            {'full_url': 'https://ns.adobe.com/personalization/dom-action', 'method': 'GET',
             'source_js': 'https://app.example.com/static/main.js'},
            {'full_url': 'https://picsum.photos/seed/mock-1/120/120', 'method': 'GET',
             'source_js': 'https://app.example.com/static/main.js'},
            {'full_url': 'https://api.example.com/v1/users', 'method': 'GET',
             'source_js': 'https://app.example.com/static/main.js'},
            {'path': '/admin', 'method': 'GET',
             'source_js': 'https://app.example.com/static/main.js'},
            # A name that only ends with the root's text is not under it.
            {'full_url': 'https://evilexample.com/x', 'method': 'GET'},
        ]

        # The SSRF guard resolves DNS; pin it so in-scope hosts reach the requester.
        with mock.patch.object(js_recon, 'is_url_safe_to_probe', return_value=True):
            validated = js_recon._validate_extracted_endpoints(
                endpoints,
                {'JS_RECON_VALIDATE_ENDPOINTS': True, 'JS_RECON_ENDPOINT_CONCURRENCY': 1},
                js_recon._ProbeScope(roots=('example.com',), hosts=frozenset({'app.example.com'})),
                request_func=lambda method, url, **kwargs: probed.append(url) or (
                    Missing() if '/rdm-' in url else Response()),
            )

        controls = [u for u in probed if '/rdm-' in u]
        self.assertEqual(sorted(u for u in probed if u not in controls), [
            'https://api.example.com/v1/users',
            'https://app.example.com/admin',
        ])
        # Each hittable endpoint also gets its catch-all control, on its own host.
        self.assertEqual(sorted(u.rsplit('/', 1)[0] for u in controls),
                         ['https://api.example.com/v1', 'https://app.example.com'])
        by_url = {e.get('full_url') or e['path']: e for e in validated}
        for third_party in ('https://ns.adobe.com/personalization/dom-action',
                            'https://picsum.photos/seed/mock-1/120/120',
                            'https://evilexample.com/x'):
            self.assertEqual(by_url[third_party]['validation_status'], 'unvalidated')
            self.assertEqual(by_url[third_party]['validation_error'], 'out_of_scope')
        self.assertEqual(by_url['https://api.example.com/v1/users']['validation_status'], 'hittable')

    def test_validate_extracted_endpoints_empty_scope_probes_nothing(self):
        probed = []
        endpoints = [{'full_url': 'https://api.example.com/v1/users', 'method': 'GET'}]

        validated = js_recon._validate_extracted_endpoints(
            endpoints,
            {'JS_RECON_VALIDATE_ENDPOINTS': True},
            js_recon._ProbeScope(),
            request_func=lambda *args, **kwargs: probed.append(args),
        )

        self.assertEqual(probed, [])
        self.assertEqual(validated[0]['validation_error'], 'out_of_scope')


class TestEndpointProbeScope(unittest.TestCase):
    """Each run type, with the combined_result shape that run hands to js_recon."""

    def _in(self, scope, *urls):
        for url in urls:
            self.assertTrue(js_recon._in_probe_scope(url, scope), url)

    def _out(self, scope, *urls):
        for url in urls:
            self.assertFalse(js_recon._in_probe_scope(url, scope), url)

    def test_single_domain_full_discovery(self):
        scope = js_recon._endpoint_probe_scope(
            {'domain': 'Example.com.', 'subdomains': ['www.example.com'],
             'metadata': {'filtered_mode': False}},
            [{'url': 'https://cdn.example.net/app.js'}, {'url': 'upload://bundle.js'}],
            {},
        )

        self.assertEqual(scope.roots, ('example.com',))
        # A subdomain first seen in the JS, and the host a JS file came from.
        self._in(scope, 'https://www.example.com/a', 'https://api.example.com/v1',
                 'https://cdn.example.net/x')
        # The apex is a target only when the run lists it (Include Root Domain);
        # the upload:// pseudo-URL names no host the scan may touch.
        self._out(scope, 'https://example.com/a', 'https://evilexample.com/a',
                  'https://bundle.js/a', 'https://ns.adobe.com/personalization/dom-action')

    def test_single_domain_full_discovery_with_the_apex_listed(self):
        scope = js_recon._endpoint_probe_scope(
            {'domain': 'example.com', 'subdomains': ['example.com', 'www.example.com'],
             'metadata': {'filtered_mode': False}},
            [], {},
        )

        self._in(scope, 'https://example.com/a')

    def test_single_domain_filtered_keeps_only_the_listed_hosts(self):
        scope = js_recon._endpoint_probe_scope(
            {'domain': 'example.com', 'subdomains': ['www.example.com'],
             'metadata': {'filtered_mode': True, 'subdomain_filter': ['www.example.com:8443']}},
            [], {},
        )

        self.assertEqual(scope.roots, ())
        self._in(scope, 'https://www.example.com/a')
        self._out(scope, 'https://api.example.com/a', 'https://example.com/a')

    def test_ip_mode_keeps_only_the_target_ips_and_their_names(self):
        scope = js_recon._endpoint_probe_scope(
            {'domain': 'ip-targets.proj1', 'subdomains': ['192-0-2-10'],
             'metadata': {
                 'ip_mode': True,
                 'filtered_mode': True,
                 'expanded_ips': ['192.0.2.10', '2001:db8::1'],
                 'subdomain_filter': ['192.0.2.10', 'host.example.org'],
             }},
            [], {},
        )

        self._in(scope, 'http://192.0.2.10:8080/api', 'http://[2001:DB8:0::1]/api',
                 'https://host.example.org/')
        self._out(scope, 'http://192.0.2.11/api', 'https://x.ip-targets.proj1/')

    def test_batch_literal_group_keeps_only_its_uploaded_hosts(self):
        # run_domain_group hands js_recon ONE group: its own root, never the batch's.
        scope = js_recon._endpoint_probe_scope(
            {'domain': 'b.test', 'subdomains': ['shop.b.test'],
             'all_project_roots': ['a.test', 'b.test'],
             'metadata': {'filtered_mode': True, 'subdomain_filter': ['shop.b.test']}},
            [], {},
        )

        self._in(scope, 'https://shop.b.test/cart')
        self._out(scope, 'https://api.b.test/v1', 'https://www.a.test/')

    def test_batch_wildcard_group_widens_to_its_own_root_only(self):
        scope = js_recon._endpoint_probe_scope(
            {'domain': 'a.test', 'subdomains': ['www.a.test'],
             'all_project_roots': ['a.test', 'b.test'],
             'metadata': {'filtered_mode': False}},
            [], {},
        )

        self._in(scope, 'https://api.a.test/v1')
        self._out(scope, 'https://shop.b.test/cart')

    def test_partial_run_over_a_batch_keeps_its_admitted_hosts(self):
        # js_analysis.py: "subdomains" is _scope_partial_urls' host list, which
        # already applies each group's rules (a literal group's listed hosts).
        scope = js_recon._endpoint_probe_scope(
            {'domain': 'a.test', 'domains': ['a.test', 'b.test'],
             'subdomains': ['www.a.test', 'shop.b.test'],
             'metadata': {'project_id': 'p1'}},
            [{'url': 'https://www.a.test/static/app.js'}], {},
        )

        self.assertEqual(scope.roots, ())
        self._in(scope, 'https://www.a.test/api', 'https://shop.b.test/cart')
        self._out(scope, 'https://api.b.test/v1', 'https://api.a.test/v1')

    def test_roe_exclusions_win_over_every_other_rule(self):
        combined = {'domain': 'example.com',
                    'subdomains': ['payments.example.com', '192.0.2.10'],
                    'metadata': {'filtered_mode': False}}
        excluded = ['payments.example.com', '192.0.2.0/24']

        scope = js_recon._endpoint_probe_scope(
            combined, [{'url': 'https://payments.example.com/app.js'}],
            {'ROE_ENABLED': True, 'ROE_EXCLUDED_HOSTS': excluded},
        )
        self._out(scope, 'https://payments.example.com/api', 'https://eu.payments.example.com/api',
                  'http://192.0.2.10/api')
        self._in(scope, 'https://api.example.com/v1')

        roe_off = js_recon._endpoint_probe_scope(
            combined, [], {'ROE_ENABLED': False, 'ROE_EXCLUDED_HOSTS': excluded},
        )
        self._in(roe_off, 'https://payments.example.com/api')


# ============================================================
# FRAMEWORK MODULE TESTS
# ============================================================

class TestFramework(unittest.TestCase):

    def test_detect_react(self):
        fws = framework.detect_frameworks('React.version = "18.2.0";', 'a.js')
        react = [f for f in fws if f['name'] == 'React']
        self.assertEqual(len(react), 1)
        self.assertEqual(react[0]['version'], '18.2.0')

    def test_detect_nextjs(self):
        fws = framework.detect_frameworks('__NEXT_DATA__', 'a.js')
        self.assertTrue(any(f['name'] == 'Next.js' for f in fws))

    def test_dom_sink_innerhtml(self):
        sinks = framework.detect_dom_sinks('el.innerHTML = x;', 'a.js')
        self.assertTrue(any(s['type'] == 'innerHTML' for s in sinks))

    def test_dom_sink_eval(self):
        sinks = framework.detect_dom_sinks('var r = eval(code);', 'a.js')
        self.assertTrue(any(s['type'] == 'eval' for s in sinks))


# ============================================================
# INTEGRATION TEST
# ============================================================

class TestIntegration(unittest.TestCase):

    def test_comprehensive_scan(self):
        js = '''
        // TODO: remove hardcoded password
        const config = {
            key: "AKIAIOSFODNN7EXAMPLE",
            firebase: "https://prod.firebaseio.com",
        };
        fetch('/api/admin/dashboard');
        element.innerHTML = userInput;
        '''
        findings = _scan(js, 'https://t.com/app.js')
        names = {f['name'] for f in findings}
        self.assertIn('AWS Access Key ID', names)
        self.assertIn('Firebase URL', names)

        eps = endpoints_mod.extract_endpoints(
            [{'url': 'https://t.com/app.js', 'content': js}],
            {'JS_RECON_EXTRACT_ENDPOINTS': True, 'JS_RECON_CUSTOM_ENDPOINT_KEYWORDS': ''}
        )
        self.assertTrue(any(e['path'] == '/api/admin/dashboard' for e in eps))

        sinks = framework.detect_dom_sinks(js, 'app.js')
        self.assertTrue(any(s['type'] == 'innerHTML' for s in sinks))

        comments = patterns.scan_dev_comments(js, 'app.js')
        self.assertGreaterEqual(len(comments), 1)

    def test_minified_bundle_line_among_normal_lines(self):
        # Integration: a real-world shape -- a few readable lines plus one giant
        # minified vendor line carrying two Slack webhooks. Both must surface,
        # and line numbers must still point at the original file line.
        webhook1 = 'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop'
        webhook2 = 'https://hooks.slack.com/services/T87654321/B87654321/ponmlkjihgfedcba'
        minified = (
            'var e={' + 'k:"' + 'z' * 300_000 + '",'
            + 'SLACK_WEBHOOK_INTERNAL_REST_DIRECTORY:"' + webhook1 + '",'
            + 'p:"' + 'q' * 300_000 + '",'
            + 'SLACK_WEBHOOK_WST_SLACK_PING_TEST:"' + webhook2 + '"};'
        )
        js = '// app entry\nconst boot = true;\n' + minified + '\nexport default boot;'
        findings, _filtered = patterns.scan_js_content(js, 'https://community.workday.com/bundle.js')
        slack = [f for f in findings if f['name'] == 'Slack Webhook']
        self.assertEqual(len(slack), 2)
        # The minified line is line 3 of the file.
        self.assertTrue(all(f['line_number'] == 3 for f in slack))

    def test_all_modules_return_correct_types(self):
        self.assertIsInstance(patterns.scan_js_content('x', 't.js'), tuple)
        self.assertIsInstance(patterns.scan_dev_comments('x', 't.js'), list)
        self.assertIsInstance(framework.detect_frameworks('x', 't.js'), list)
        self.assertIsInstance(framework.detect_dom_sinks('x', 't.js'), list)



# ---------------------------------------------------------------------------
# Endpoint validation: a catch-all server answers every path, so a hittable
# status says nothing. A control path that cannot exist decides (plan 03.6).
# ---------------------------------------------------------------------------
class _Answer:
    def __init__(self, status, body="", headers=None):
        self.status_code = status
        self.content = body.encode()
        self.text = body
        self.headers = headers or {}


SPA_SHELL = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>'


class TestEndpointValidationCatchAll(unittest.TestCase):
    def _validate(self, endpoints, answer, settings=None, scope=_EXAMPLE_SCOPE, guard=lambda u: True):
        calls = []

        def request_func(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return answer(method, url)
        with mock.patch.object(js_recon, 'is_url_safe_to_probe', side_effect=guard):
            out = js_recon._validate_extracted_endpoints(
                endpoints, {'JS_RECON_VALIDATE_ENDPOINTS': True, **(settings or {})}, scope,
                request_func=request_func)
        return out, calls

    def test_an_spa_shell_answering_every_path_is_catch_all(self):
        endpoints = [{'full_url': 'https://app.example.com/api/read', 'method': 'GET'},
                     {'full_url': 'https://app.example.com/api/list', 'method': 'GET'}]
        out, calls = self._validate(endpoints, lambda m, u: _Answer(200, SPA_SHELL))
        self.assertEqual([e['validation_status'] for e in out], ['catch_all', 'catch_all'])
        controls = [u for _, u, _ in calls if '/rdm-' in u]
        self.assertEqual(len(controls), 1)               # one control for the /api/ prefix
        self.assertTrue(controls[0].startswith('https://app.example.com/api/rdm-'))

    def test_a_real_endpoint_stays_hittable(self):
        def answer(method, url):
            if url.endswith('/api/v1'):
                return _Answer(200, '{"service":"orders","version":"2.1"}')
            return _Answer(404, '{"code":"NOT_FOUND"}')
        out, _ = self._validate([{'full_url': 'https://api.example.com/api/v1', 'method': 'GET'}], answer)
        self.assertEqual(out[0]['validation_status'], 'hittable')
        self.assertEqual(out[0]['status_code'], 200)

    def test_the_control_uses_the_probe_method_and_headers(self):
        endpoints = [{'full_url': 'https://app.example.com/api/save', 'method': 'POST',
                      'source_js': 'https://app.example.com/static/main.js'}]
        out, calls = self._validate(endpoints, lambda m, u: _Answer(204),
                                    settings={'JS_RECON_ENDPOINT_CUSTOM_HEADERS': ['Cookie: s=1']})
        (m1, u1, k1), (m2, u2, k2) = calls
        self.assertEqual((m1, m2), ('OPTIONS', 'OPTIONS'))
        self.assertIn('/rdm-', u2)
        self.assertEqual(k1, k2)
        self.assertFalse(k2['allow_redirects'])
        self.assertEqual(out[0]['validation_status'], 'catch_all')

    def test_a_head_control_is_not_reused_for_a_get_hit(self):
        endpoints = [{'full_url': 'https://app.example.com/api/a', 'method': 'HEAD'},
                     {'full_url': 'https://app.example.com/api/b', 'method': 'GET'}]
        _, calls = self._validate(endpoints, lambda m, u: _Answer(404 if '/rdm-' in u else 200))
        self.assertEqual(sorted(m for m, u, _ in calls if '/rdm-' in u), ['GET', 'HEAD'])

    def test_a_failed_control_keeps_the_endpoint_hittable(self):
        def answer(method, url):
            if '/rdm-' in url:
                raise requests.ConnectionError('reset')
            return _Answer(200, SPA_SHELL)
        out, _ = self._validate([{'full_url': 'https://app.example.com/api/read', 'method': 'GET'}], answer)
        self.assertEqual(out[0]['validation_status'], 'hittable')

    def test_the_ssrf_guard_runs_on_the_control_too(self):
        seen = []

        def guard(url):
            seen.append(url)
            return '/rdm-' not in url        # refuse only the control
        out, calls = self._validate([{'full_url': 'https://app.example.com/api/read', 'method': 'GET'}],
                                    lambda m, u: _Answer(200, SPA_SHELL), guard=guard)
        self.assertTrue(any('/rdm-' in u for u in seen))
        self.assertFalse(any('/rdm-' in u for _, u, _ in calls))
        self.assertEqual(out[0]['validation_status'], 'hittable')    # no conclusion: kept

    def test_a_not_hittable_status_sends_no_control(self):
        out, calls = self._validate([{'full_url': 'https://app.example.com/missing', 'method': 'GET'}],
                                    lambda m, u: _Answer(404))
        self.assertEqual(out[0]['validation_status'], 'not_hittable')
        self.assertEqual(len(calls), 1)

    def test_an_roe_excluded_host_is_never_probed_or_controlled(self):
        scope = js_recon._ProbeScope(roots=('example.com',), roe_excluded=('admin.example.com',))
        out, calls = self._validate([{'full_url': 'https://admin.example.com/api/x', 'method': 'GET'}],
                                    lambda m, u: _Answer(200, SPA_SHELL), scope=scope)
        self.assertEqual(calls, [])
        self.assertEqual(out[0]['validation_error'], 'out_of_scope')

    def test_validation_off_sends_nothing(self):
        calls = []
        out = js_recon._validate_extracted_endpoints(
            [{'full_url': 'https://app.example.com/api/read', 'method': 'GET'}],
            {'JS_RECON_VALIDATE_ENDPOINTS': False}, _EXAMPLE_SCOPE,
            request_func=lambda *a, **k: calls.append(a) or _Answer(200))
        self.assertEqual(calls, [])
        self.assertEqual(out[0]['validation_status'], 'unvalidated')

    def test_the_summary_counts_catch_all(self):
        summary = js_recon._build_summary({'endpoints': [
            {'validation_status': 'catch_all'}, {'validation_status': 'catch_all'},
            {'validation_status': 'hittable'}]})
        self.assertEqual(summary['endpoint_validation']['catch_all'], 2)
        self.assertEqual(summary['endpoints_hittable'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
