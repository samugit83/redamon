"""Reading TruffleHog's NDJSON and mapping a result to a js_recon finding.

Only DetectorName, Verified, VerificationError, Raw, the file and allowlisted
ExtraData keys are read; RawV2 and SecretParts serve masking only and never
reach a finding. The detector-to-type mapping is prefix-aware. Every value is
synthetic and assembled at runtime.
"""

from __future__ import annotations

import json
import random
import string
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import trufflehog_bridge as th

ALNUM = string.ascii_letters + string.digits


def _rnd(label, alphabet, n):
    rng = random.Random(f"parse:{label}")
    return "".join(rng.choice(alphabet) for _ in range(n))


def result(detector, raw, *, file="/scan/f_00001.js", verified=False, error=None, raw_v2="",
           parts=None, extra=None, redacted=""):
    obj = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": file, "line": 1}}},
        "SourceType": 15, "SourceName": "trufflehog - filesystem",
        "DetectorType": 2, "DetectorName": detector, "DecoderName": "PLAIN",
        "Verified": verified, "Raw": raw, "RawV2": raw_v2, "Redacted": redacted,
        "ExtraData": extra, "StructuredData": None, "SecretParts": parts or {},
    }
    if error:
        obj["VerificationError"] = error
    return json.dumps(obj)


AWS_ID = "AK" + "IA" + _rnd("awsid", string.ascii_uppercase + string.digits, 16)
AWS_SECRET = _rnd("awssec", ALNUM + "+/", 40)
GH = "gh" + "p_" + _rnd("gh", ALNUM, 36)


class ParseNdjson(unittest.TestCase):
    def test_reads_the_fields_and_never_keeps_rawv2_or_parts(self):
        line = result("AWS", AWS_ID, raw_v2=f"{AWS_ID}:{AWS_SECRET}",
                      parts={"access_key_id": AWS_ID, "secret_access_key": AWS_SECRET},
                      extra={"resource_type": "Access key", "arn": "arn:aws:iam::1:user/x", "account": "1"},
                      redacted=AWS_ID[:8])
        (r,), bad = th.parse_ndjson(line + "\n")
        self.assertEqual(bad, 0)
        self.assertEqual((r.detector, r.raw, r.file, r.verified, r.error), ("AWS", AWS_ID, "f_00001.js", False, ""))
        self.assertEqual(r.extra, {"resource_type": "Access key", "account": "1"})
        self.assertEqual(r.mask_values, (AWS_SECRET,))

    def test_bad_lines_are_counted_and_log_lines_are_skipped(self):
        log = json.dumps({"level": "info-0", "msg": "finished scanning"})
        out = "\n".join(["not json", log, result("Github", GH), "{\"DetectorName\": \"X\"}", ""])
        results, bad = th.parse_ndjson(out)
        self.assertEqual([r.detector for r in results], ["Github"])
        self.assertEqual(bad, 2)

    def test_verification_error_and_verified(self):
        (a, b), _ = th.parse_ndjson("\n".join([
            result("Github", GH, verified=True),
            result("Slack", "xo" + "xb-1", error="Get \"https://slack.com/api\": dial tcp: i/o timeout")]))
        self.assertTrue(a.verified)
        self.assertEqual(th.result_class(a), "verified")
        self.assertEqual(th.result_class(b), "unknown")
        self.assertEqual(th.error_class(b.error), "timeout")


class Mapping(unittest.TestCase):
    def test_prefix_aware_names(self):
        cases = {
            ("AWS", "AK" + "IA0"): "AWS Access Key ID",
            ("AWSSessionKey", "AS" + "IA0"): "AWS Session Key",
            ("Stripe", "sk" + "_live_x"): "Stripe Secret Key",
            ("Stripe", "rk" + "_live_x"): "Stripe Restricted Key",
            ("Github", "github" + "_pat_x"): "GitHub Fine-grained Token",
            ("Github", "gh" + "s_x"): "GitHub App Token",
            ("Slack", "xo" + "xp-1"): "Slack User Token",
            ("OpenAI", "sk-" + "proj-x"): "OpenAI Project Key",
            ("OpenAI", "sk-" + "x"): "OpenAI API Key",
            ("Anthropic", "sk-ant-" + "admin01-x"): "Anthropic Admin Key",
            ("Anthropic", "sk-ant-" + "api03-x"): "Anthropic API Key",
            ("GoogleGeminiAPIKey", "AI" + "zaSy"): "GCP API Key",
            ("SendGrid", "SG" + ".x"): "SendGrid API Key",
            ("Shodan", "x"): "Shodan",
        }
        for (detector, raw), name in cases.items():
            with self.subTest(detector=detector, raw=raw[:8]):
                self.assertEqual(th.mapped_name(detector, raw), name)

    def test_shopify_raw_is_the_token_joined_to_its_store(self):
        token = "sh" + "pat_" + _rnd("shop", "0123456789abcdef", 32)
        self.assertEqual(th.key_of("Shopify", token + "acme.myshopify.com"), token)
        self.assertEqual(th.key_of("Github", GH), GH)

    def _map(self, detector, raw, content, **kw):
        manifest = {"f_00001.js": {"url": "https://app.example.com/main.js", "content": content}}
        (r,), _ = th.parse_ndjson(result(detector, raw, **kw))
        return th.map_result(r, manifest, verify=kw.get("verified", False) or "error" in kw)

    def test_a_known_detector_takes_the_pattern_severity_and_category(self):
        f = self._map("Github", GH, f'var t="{GH}";')
        self.assertEqual((f["name"], f["severity"], f["category"]), ("GitHub Token Classic", "high", "auth"))
        self.assertEqual(f["detection_method"], "trufflehog")
        self.assertEqual(f["validation"]["trufflehog"]["detector"], "Github")
        self.assertFalse(f["public_client_key"])

    def test_an_unknown_detector_keeps_its_name_at_high(self):
        key = _rnd("shodan", ALNUM, 32)
        f = self._map("Shodan", key, f'const shodanKey = "{key}";')
        self.assertEqual((f["name"], f["severity"], f["category"]), ("Shodan", "high", "secret"))
        self.assertEqual(f["confidence"], "medium")

    def test_a_public_type_is_info(self):
        key = "AI" + "zaSy" + _rnd("gem", ALNUM, 33)
        f = self._map("GoogleGeminiAPIKey", key, f'k="{key}"')
        self.assertEqual((f["name"], f["severity"], f["public_client_key"]), ("GCP API Key", "info", True))

    def test_the_pair_is_kept_only_in_the_display_fields(self):
        f = self._map("AWS", AWS_ID, f'a="{AWS_ID}";b="{AWS_SECRET}";', raw_v2=f"{AWS_ID}:{AWS_SECRET}",
                      parts={"secret_access_key": AWS_SECRET})
        self.assertEqual(f["paired_secret"], AWS_SECRET)
        self.assertEqual(f["secret_value"], AWS_ID)
        self.assertIn(AWS_SECRET, f["raw_context"])
        self.assertNotIn(AWS_SECRET, f["context"])
        from graph_db.display_only import strip_display_only
        self.assertNotIn(AWS_SECRET, json.dumps(strip_display_only(f)))
        for key in ("RawV2", "SecretParts", "Redacted", "raw_v2", "mask_values"):
            self.assertNotIn(key, f)

    def test_the_pair_comes_from_rawv2_without_secret_parts(self):
        (r,), _ = th.parse_ndjson(result("AWS", AWS_ID, raw_v2=f"{AWS_ID}:{AWS_SECRET}") + "\n")
        self.assertEqual(r.paired, AWS_SECRET)

    def test_a_single_part_detector_has_no_pair(self):
        (r,), _ = th.parse_ndjson(result("Github", GH) + "\n")
        self.assertEqual(r.paired, "")
        f = self._map("Github", GH, f'k="{GH}"')
        self.assertIsNone(f["paired_secret"])

    def test_a_file_not_in_the_manifest_maps_to_nothing(self):
        (r,), _ = th.parse_ndjson(result("Github", GH, file="/scan/f_09999.js"))
        self.assertIsNone(th.map_result(r, {}, verify=False))


if __name__ == "__main__":
    unittest.main()


class PairOnARegexFinding(unittest.TestCase):
    def test_a_regex_key_truffleHog_also_found_gets_the_pair(self):
        content = f'a="{AWS_ID}";b="{AWS_SECRET}";'
        url = "https://app.example.com/main.js"
        regex, _ = th.patterns.scan_js_content(content, url)
        aws = [s for s in regex if s["matched_text"] == AWS_ID]
        self.assertTrue(aws)
        (r,), _ = th.parse_ndjson(result("AWS", AWS_ID, raw_v2=f"{AWS_ID}:{AWS_SECRET}",
                                         parts={"secret_access_key": AWS_SECRET}))
        merged, stats = th.merge(regex, [r], {"f_00001.js": {"url": url, "content": content}}, verify=False)
        self.assertEqual(stats.merged, 1)
        self.assertEqual(next(s for s in merged if s["matched_text"] == AWS_ID)["paired_secret"], AWS_SECRET)
