"""Priority Board evidence for the Secrets JS Recon's TruffleHog engine touched.

A key TruffleHog found gets two plain-language lines a reviewer can weigh:
who found it ("Found by: TruffleHog (<detector>)", or "JS Recon and
TruffleHog" when both engines did), and, when TruffleHog's check could not
confirm a TruffleHog-only key, that this is not proof the key is dead. Every
other Secret, a Phase 0 alternate name included, keeps byte-identical
evidence: its bundle hash, and so its review, must not change. The golden hash
was computed with the evidence builder before these lines existed.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import evidence  # noqa: E402

GCP = "AI" + "zaSy" + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko"
GH = "gh" + "p_" + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko4"
SHODAN = "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui"


def regex_secret(**over):
    finding = {
        "id": "s1", "label": "Secret", "source": "js_recon", "name": "GCP API Key", "severity": "info",
        "secret_type": "GCP API Key", "detector_name": "GCP API Key", "matched_text": GCP,
        "context": 'const opts = {apiKey:"AIzaSy...i2Ko"};', "validation_status": "unknown",
        "validation_info": json.dumps({"status": "unknown", "info": "status=REQUEST_DENIED"}),
        "triage_host": "https://app.example.com:443", "confidence": "high", "public_client_key": True,
    }
    finding.update(over)
    return finding


GOLDEN_HASH = "87461acb63504709e0a7391197165db2a7d1f260"


class UntouchedSecrets(unittest.TestCase):
    def test_byte_identical_with_a_phase0_alternate_name(self):
        for extra in ({}, {"detection_method": "regex", "alternate_names": ["Generic API Key"]},
                      {"detection_method": "regex", "alternate_names": []}, {"alternate_names": None}):
            with self.subTest(extra=extra):
                bundle = evidence.build_bundle(regex_secret(**extra))
                self.assertEqual(evidence.bundle_hash(bundle), GOLDEN_HASH)
                self.assertNotIn("TruffleHog", bundle)


class TruffleHogSecrets(unittest.TestCase):
    def test_a_trufflehog_only_key_it_could_not_confirm(self):
        info = {"status": "unknown", "checked_by": "trufflehog",
                "trufflehog": {"detector": "ShodanKey", "verified": False, "error_class": "", "extra": {}}}
        bundle = evidence.build_bundle(regex_secret(
            name="ShodanKey", secret_type="ShodanKey", detector_name="ShodanKey", matched_text=SHODAN,
            detection_method="trufflehog", context="", severity="high", public_client_key=False,
            validation_info=json.dumps(info)))
        self.assertIn("Found by: TruffleHog (ShodanKey)\n", bundle)
        self.assertIn("Validation: unknown — TruffleHog could not confirm it, which is not proof it is dead\n",
                      bundle)
        self.assertNotIn(SHODAN, bundle)

    def test_a_key_both_engines_found(self):
        info = {"status": "validated", "valid": True, "checked_by": "trufflehog",
                "trufflehog": {"detector": "Github", "verified": True, "error_class": "", "extra": {}}}
        bundle = evidence.build_bundle(regex_secret(
            name="GitHub Token Classic", secret_type="GitHub Token Classic", detector_name="GitHub Token Classic",
            matched_text=GH, validation_status="validated", validation_info=json.dumps(info),
            alternate_names=["TruffleHog:Github"], detection_method="regex", public_client_key=False))
        self.assertIn("Found by: JS Recon and TruffleHog (Github)\n", bundle)
        self.assertIn("Validation: validated\n", bundle)
        self.assertNotIn(GH, bundle)

    def test_the_line_changes_the_hash_so_an_old_review_expires(self):
        plain = evidence.bundle_hash(evidence.build_bundle(regex_secret()))
        touched = evidence.bundle_hash(evidence.build_bundle(regex_secret(alternate_names=["TruffleHog:GoogleGeminiAPIKey"])))
        self.assertNotEqual(plain, touched)

    def test_the_legacy_bundle_is_unchanged(self):
        finding = regex_secret(alternate_names=["TruffleHog:GoogleGeminiAPIKey"], detection_method="regex")
        self.assertEqual(evidence.build_bundle_legacy(finding), evidence.build_bundle_legacy(regex_secret()))


if __name__ == "__main__":
    unittest.main()
