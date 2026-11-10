"""The display-only secret fields JS Recon and jsluice produce: the key itself,
the pair's other half and the unmasked context, beside the masked forms that
reviewers and models read. Keys are invented."""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.mixins.recon.resource_mixin import _jsluice_secret_values, _redact_sample  # noqa: E402
from recon.helpers.js_recon import patterns  # noqa: E402

AWS_ID = "AKIA" + "Q7R2M9X4K1T8B3V6"
AWS_SECRET = "wJalr" + "XUtnFEMIK7MDENGbPxRfiCYzz1AB2CD3EF"
GH = "ghp_" + "Zq8Rw2Lp7Nm4Kt9Vb3Cz6Hd1Jf5Gs0Ty2Uab"


class TestSecretValueOf:
    def test_a_keyword_rule_gives_the_quoted_value(self):
        assert patterns.secret_value_of("Hardcoded Password", 'password = "Pr0d-Db!2024x"') == "Pr0d-Db!2024x"
        assert patterns.secret_value_of("Generic Secret", "client_secret: 'abcDEF123ghiJKL456'") == \
            "abcDEF123ghiJKL456"

    def test_a_provider_rule_keeps_the_whole_match(self):
        assert patterns.secret_value_of("GitHub Token Classic", GH) == GH

    def test_a_keyword_rule_without_a_value_falls_back_to_the_match(self):
        assert patterns.secret_value_of("Generic Secret", "secret") == "secret"


class TestScanJsContent:
    def test_each_finding_has_the_key_and_an_unmasked_context(self):
        content = f'const gh = "{GH}";\nconst aws = "{AWS_ID}";\n'
        findings, _ = patterns.scan_js_content(content, "https://app.example.test/main.js")
        gh = next(f for f in findings if f["matched_text"] == GH)
        assert gh["secret_value"] == GH
        assert AWS_ID in gh["raw_context"] and GH in gh["raw_context"]
        assert AWS_ID not in gh["context"] and GH not in gh["context"]


class TestJsluiceValues:
    def test_an_aws_pair_gives_the_key_and_its_secret(self):
        assert _jsluice_secret_values({"key": AWS_ID, "secret": AWS_SECRET}) == (AWS_ID, AWS_SECRET)

    def test_a_single_key(self):
        assert _jsluice_secret_values({"key": GH}) == (GH, "")

    def test_a_config_object_is_kept_whole(self):
        value, paired = _jsluice_secret_values({"apiKey": "x1", "projectId": "demo"})
        assert value == '{"apiKey": "x1", "projectId": "demo"}' and paired == ""

    def test_a_plain_string_and_nothing(self):
        assert _jsluice_secret_values(AWS_ID) == (AWS_ID, "")
        assert _jsluice_secret_values({}) == ("", "")
        assert _jsluice_secret_values(None) == ("", "")

    def test_the_sample_is_redacted_like_js_recons(self):
        assert _redact_sample(AWS_ID) == patterns.redact(AWS_ID)
        assert _redact_sample("") == ""


class TestSecretValueEdges:
    def test_quotes_a_provider_rule_caught_are_dropped(self):
        assert patterns.secret_value_of("Google Gemini API Key", '"AIzaSyFAKE0FAKE0FAKE0FAKE0FAKE0FAKE"') == \
            "AIzaSyFAKE0FAKE0FAKE0FAKE0FAKE0FAKE"

    def test_a_pem_rule_gives_the_whole_block(self):
        body = "MIIEFAKEFAKE" * 30
        after = f"-----BEGIN PRIVATE KEY-----\\n{body}\\n-----END PRIVATE KEY-----\";\nconst x = 1;"
        value = patterns.secret_value_of("Generic Private Key", "-----BEGIN PRIVATE KEY-----", after)
        assert value.startswith("-----BEGIN PRIVATE KEY-----") and value.endswith("-----END PRIVATE KEY-----")
        assert body in value

    def test_a_pem_rule_without_its_footer_keeps_the_match(self):
        assert patterns.secret_value_of("Generic Private Key", "-----BEGIN PRIVATE KEY-----",
                                        "-----BEGIN PRIVATE KEY-----\\nMIIE") == "-----BEGIN PRIVATE KEY-----"

    def test_a_pem_key_in_a_bundle_gets_its_block(self):
        body = "".join(chr(65 + (i * 7) % 26) for i in range(400))
        content = f'var k = "-----BEGIN RSA PRIVATE KEY-----\\n{body}\\n-----END RSA PRIVATE KEY-----";\n'
        findings, _ = patterns.scan_js_content(content, "https://app.example.test/main.js")
        pem = [f for f in findings if "Private Key" in f["name"]]
        assert pem, [f["name"] for f in findings]
        assert all(f["secret_value"].endswith("-----END RSA PRIVATE KEY-----") for f in pem)
