"""The GitHub hunt's own copy of the secret patterns (plan 05).

05.4: the keyword-anchored patterns are bounded here as in js_recon, and the
Azure AD client secret must be assigned to the client-secret key.
05.9: `sample` holds the matched value, redacted, never the keyword a
capturing group happened to catch.

PyGithub is stubbed so the module imports without it, and the hunter is built
via __new__ so nothing touches the network. Every value is synthetic.
"""
import re
import sys
import time
import types
import unittest.mock as mock
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = str(REPO_ROOT / "scanners" / "github_secret_hunt")

AZURE_VALUE = "Qx7~Lm2.Rt9_Wn4-Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko"


@pytest.fixture(scope="module")
def ghh():
    stub = types.ModuleType("github")
    stub.Github = object
    stub.Auth = types.SimpleNamespace(Token=lambda *a, **k: None)
    exc = types.ModuleType("github.GithubException")
    exc.RateLimitExceededException = type("RateLimitExceededException", (Exception,), {})
    exc.GithubException = type("GithubException", (Exception,), {})
    stub.GithubException = exc
    with mock.patch.dict(sys.modules, {"github": stub, "github.GithubException": exc}), \
            mock.patch.object(sys, "path", [SCANNER_DIR] + sys.path):
        import github_secret_hunt
        yield github_secret_hunt


def _hits(ghh, name, text):
    return [m.group(0) for m in ghh.COMPILED_SECRET_PATTERNS[name].finditer(text)]


class TestBoundedPatterns:
    def test_no_pattern_has_a_bare_dot_star(self, ghh):
        unbounded = [n for n, rx in ghh.SECRET_PATTERNS.items() if re.search(r"(?<!\\)\.[*+]", rx)]
        assert unbounded == []

    def test_every_gap_is_lazy_and_at_most_120(self, ghh):
        assert [n for n, rx in ghh.SECRET_PATTERNS.items()
                if "[^\\n]{0," in rx and "[^\\n]{0,120}?" not in rx] == []

    def test_msal_empty_default_is_no_azure_hit(self, ghh):
        text = ('// azure msal\nconst cfg = {clientId: "x", clientSecret: "", '
                'build: "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"};')
        assert _hits(ghh, "Azure AD Client Secret", text) == []

    def test_an_assigned_azure_secret_is_a_hit(self, ghh):
        text = f'AZURE_AD = {{ "client_secret": "{AZURE_VALUE}" }}'
        assert len(_hits(ghh, "Azure AD Client Secret", text)) == 1

    def test_a_long_line_cannot_run_away(self, ghh):
        line = "etsy=1;" + "var q=function(a,b){return a+b};" * 1000 + 'x="k3x9q2m7a8b1c4d5e6f7g8h9";'
        start = time.monotonic()
        assert _hits(ghh, "Etsy Access Token", line) == []
        assert time.monotonic() - start < 5

    def test_a_mailgun_public_key_is_not_an_api_key(self, ghh):
        assert _hits(ghh, "Mailgun API Key", "pubkey-4e9a1c7f3b5d8e2a6c0f9b1d7e3a5c8f") == []
        assert _hits(ghh, "Mailgun API Key", 'k="key-8d2f6b0a4c9e1f7b3d5a8c2e6f0b4d9a"') != []


def _scan(ghh, content):
    """scan_file_content on a network-free hunter: (findings, stdout)."""
    import io
    from contextlib import redirect_stdout
    hunter = ghh.GitHubSecretHunter.__new__(ghh.GitHubSecretHunter)
    hunter.findings = []
    hunter.stats = {"secrets_found": 0, "sensitive_files": 0, "high_entropy": 0}
    hunter._save_incremental = lambda: None
    buf = io.StringIO()
    with redirect_stdout(buf):
        hunter.scan_file_content("acme/app", content, "config.py")
    return {f["secret_type"]: f for f in hunter.findings if f["type"] == "SECRET"}, buf.getvalue()


AWS_KEY = "AKIA" + "Q7R2M9X4K1T8B3V6"
PASSWORD = "Xk9mP2vL7qR4tZ8w"


class TestSampleIsTheRedactedValue:
    """05.9: `re.findall` returned the capturing group, which for the generic
    patterns is the KEYWORD, so the sample of every generic secret read
    "password"; for every other pattern it was the raw value."""

    def test_a_generic_secret_samples_its_value_not_its_keyword(self, ghh):
        found, _ = _scan(ghh, f'db_password = "{PASSWORD}"\n')
        sample = found["Generic Secret"]["details"]["sample"]
        assert sample != "password"
        assert sample == ghh.redact_sample(f'password = "{PASSWORD}"')
        assert sample.endswith(PASSWORD[-3:] + '"')
        assert PASSWORD not in sample

    def test_a_key_is_sampled_redacted(self, ghh):
        found, out = _scan(ghh, f'aws = "{AWS_KEY}"\n')
        details = found["AWS Access Key ID"]["details"]
        assert details["sample"] == AWS_KEY[:6] + "..." + AWS_KEY[-4:]
        # The on-disk artifact keeps the value (tracker decision); stdout never shows it.
        assert details["value"] == AWS_KEY
        assert AWS_KEY not in out

    def test_a_pattern_whose_group_is_the_value_samples_the_whole_match(self, ghh):
        url = "https://reports-bucket.s3.amazonaws.com/q3.pdf"
        found, _ = _scan(ghh, f'u = "{url}"\n')
        details = found["S3 Bucket (path-style)" if "S3 Bucket (path-style)" in found
                        else "S3 Bucket (virtual-hosted)"]["details"]
        assert details["sample"] == ghh.redact_sample(details["value"])
        assert details["value"].startswith("https://reports-bucket")

    def test_every_match_is_counted(self, ghh):
        other = "AKIA" + "Z3FPLB7QW4XN6R2T"
        found, _ = _scan(ghh, f'a = "{AWS_KEY}"\nb = "{other}"\n')
        assert found["AWS Access Key ID"]["details"]["matches"] == 2

    def test_redaction_is_the_js_recon_rule_and_idempotent(self, ghh):
        for value, want in ((AWS_KEY, AWS_KEY[:6] + "..." + AWS_KEY[-4:]),
                            ("abcdefgh", "abc..."), ("abc", "***")):
            assert ghh.redact_sample(value) == want
            assert ghh.redact_sample(want) == want

    def test_the_graph_writer_redacts_the_same_way(self, ghh):
        from graph_db.mixins.secret_mixin import _redact_sample
        for value in (AWS_KEY, f'password = "{PASSWORD}"', "abcdefgh", "abc", ""):
            assert _redact_sample(value) == ghh.redact_sample(value)


class TestPhase0Mirror:
    """The TruffleHog plan's Phase 0, items 0.2 and 0.4, mirrored from js_recon:
    a private-key marker needs key data after it, and the Yandex AWS rule needs
    "yandex" within 120 characters before it. Certificates (0.3) and generic
    UUID values (0.6) do not apply: the hunter has no severities."""

    BODY = ("MIIEow" + "IBAAKCAQEA" + "x7Kp2Lm9Qz4Wn8Rt1Yb6Vc3Hd5Jf0Gs2") * 3

    def test_a_pem_template_is_no_finding(self, ghh):
        head = "-----BEGIN " + "RSA PRIVATE KEY-----"
        for text in ('p = "' + head + '\\n" + body + "\\n-----END RSA PRIVATE KEY-----"\n',
                     "p = `" + head + "\\n${body}\\n-----END RSA PRIVATE KEY-----`\n"):
            found, _ = _scan(ghh, text)
            assert "RSA Private Key" not in found

    def test_a_key_with_key_data_is_a_finding(self, ghh):
        head = "-----BEGIN " + "RSA PRIVATE KEY-----"
        found, _ = _scan(ghh, head + "\n" + self.BODY + "\n-----END RSA PRIVATE KEY-----\n")
        assert "RSA Private Key" in found

    def test_yandex_needs_its_keyword(self, ghh):
        value = "Y" + "C" + "x7Kp2Lm9Qz4Wn8Rt1Yb6Vc3Hd5Jf0Gs2Ae8Ui4"
        found, _ = _scan(ghh, 'chunk = "' + value + '"\n')
        assert "Yandex AWS Access Token" not in found
        found, _ = _scan(ghh, 'yandex_cloud = {"key": "' + value + '"}\n')
        assert "Yandex AWS Access Token" in found
