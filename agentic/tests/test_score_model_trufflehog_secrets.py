"""How the Priority Board ranks the Secret names JS Recon's TruffleHog engine adds.

A key only TruffleHog finds is a `Secret {source: 'js_recon'}` named after the
js_recon rule it maps to, or after TruffleHog's own detector when no rule
matches (an OSINT provider's key). The class comes from that name by
substring (`classify_secret`), so each name that can appear is pinned here.
TruffleHog never writes `rejected`; its "could not confirm" is `unknown`, which
keeps a finding open. A public key TruffleHog verified (a Gemini-enabled
Google key) is spendable, so it takes the unrestricted-key class.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402


def secret(**kwargs):
    base = {"id": "s1", "label": "Secret", "source": "js_recon", "severity": "high", "host": "h1",
            "confidence": "medium"}
    base.update(kwargs)
    base.setdefault("detector_name", base.get("secret_type"))
    return base


#: secret_type -> the class it must take.
EXPECTED = {
    # js_recon rule names TruffleHog maps to (Appendix A of the plan)
    "AWS Access Key ID": "credential",
    "AWS Session Key": "credential",
    "Stripe Secret Key": "credential",
    "Stripe Restricted Key": "credential",
    "GitHub Token Classic": "credential",
    "GitHub Fine-grained Token": "credential",
    "Slack Bot Token": "credential",
    "SendGrid API Key": "credential",
    "GitLab PAT": "credential",
    "Twilio Account SID": "credential",
    "OpenAI API Key": "generic_secret",
    "OpenAI Project Key": "generic_secret",
    "Anthropic API Key": "generic_secret",
    "Mailgun API Key": "generic_secret",
    "HuggingFace Access Token": "credential",
    "Telegram Bot Token": "generic_secret",
    "Discord Bot Token": "generic_secret",
    "DigitalOcean Token": "generic_secret",
    "Shopify Access Token": "credential",
    "GCP API Key": "public_client_id",
    # Phase 0 rules a TruffleHog key can also merge into
    "Stripe Webhook Secret": "credential",
    "Credentials in URL": "credential",
    "JDBC with password": "credential",
    # TruffleHog detectors with no js_recon rule keep their own name: the
    # OSINT providers whose keys the end-to-end proof verifies.
    "ShodanKey": "generic_secret",
    "VirusTotal": "generic_secret",
    "Urlscan": "generic_secret",
    "Censys": "generic_secret",
    "AlienVault": "generic_secret",
}


class TruffleHogSecretClasses(unittest.TestCase):
    def test_each_name_takes_its_class(self):
        for name, want in EXPECTED.items():
            with self.subTest(secret_type=name):
                self.assertEqual(sm._class_for(secret(secret_type=name)).name, want)

    def test_an_unknown_verdict_stays_open(self):
        for name in ("ShodanKey", "GitHub Token Classic"):
            with self.subTest(secret_type=name):
                result = sm.score(secret(secret_type=name, validation_status="unknown"))
                self.assertEqual(result.state, sm.STATE_OPEN)

    def test_a_trufflehog_validated_key_is_open_and_ranks_above_its_unknown_twin(self):
        live = sm.score(secret(secret_type="ShodanKey", validation_status="validated", confidence="high"))
        unsure = sm.score(secret(secret_type="ShodanKey", validation_status="unknown"))
        self.assertEqual(live.state, sm.STATE_OPEN)
        self.assertGreaterEqual(live.score, unsure.score)

    def test_a_validated_public_key_takes_the_unrestricted_path(self):
        found = sm._class_for(secret(secret_type="GCP API Key", validation_status="validated",
                                     severity="info", public_client_key=True))
        self.assertIs(found, sm.SECRET_CLASSES["public_unrestricted"])
        unchecked = sm._class_for(secret(secret_type="GCP API Key", validation_status="unknown",
                                         severity="info", public_client_key=True))
        self.assertIs(unchecked, sm.SECRET_CLASSES["public"])

    def test_an_aws_key_ranks_above_a_public_gcp_key(self):
        aws = sm.score(secret(secret_type="AWS Access Key ID", severity="critical", confidence="high"))
        gcp = sm.score(secret(secret_type="GCP API Key", severity="info", public_client_key=True))
        self.assertGreater(aws.score, gcp.score)


if __name__ == "__main__":
    unittest.main()
