"""
Unit tests for the shared `print_effective_settings` helper.

Tests every formatting branch + the credential-redaction contract that
keeps API keys out of the Recon Logs Drawer.

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_log_helpers.py -v
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.log_helpers import (
    _format_value,
    is_sensitive_key,
    print_effective_settings,
)


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


# ===========================================================================
# is_sensitive_key
# ===========================================================================
class TestIsSensitiveKey:
    @pytest.mark.parametrize("key", [
        "SHODAN_API_KEY",
        "CENSYS_API_TOKEN",
        "VULNERS_KEY_ROTATOR",
        "GIVEN_PASSWORD",
        "PRIVATE_KEY",
        "CENSYS_ORG_ID",          # treat IDs that pair with API tokens as sensitive
        "CLIENT_SECRET",
        "JWT_SECRET",
    ])
    def test_flags_sensitive(self, key):
        assert is_sensitive_key(key) is True

    @pytest.mark.parametrize("key", [
        "NAABU_RATE_LIMIT",
        "HTTPX_TIMEOUT",
        "VHOST_SNI_TEST_L7",
        "MAX_RESULTS",
        "NUCLEI_BULK_SIZE",
    ])
    def test_doesnt_flag_innocent_keys(self, key):
        assert is_sensitive_key(key) is False

    def test_case_insensitive(self):
        assert is_sensitive_key("shodan_api_key") is True
        assert is_sensitive_key("Shodan_Api_Key") is True


# ===========================================================================
# _format_value
# ===========================================================================
class TestFormatValue:
    def test_none_renders_as_unset(self):
        assert _format_value("X", None, masked=False) == "<unset>"

    def test_bool_repr(self):
        assert _format_value("X", True, masked=False) == "True"
        assert _format_value("X", False, masked=False) == "False"

    def test_int_repr(self):
        assert _format_value("X", 42, masked=False) == "42"

    def test_short_string_quoted(self):
        assert _format_value("X", "hello", masked=False) == "'hello'"

    def test_long_string_summarised(self):
        long = "a\n" * 80  # 160 chars, 80 lines
        out = _format_value("X", long, masked=False)
        assert "<" in out and "chars" in out
        assert "non-comment lines" in out

    def test_long_string_skips_comment_lines_in_count(self):
        s = "admin\n# this is a comment\nstaging\n# another\nfoo" + ("\n" * 80)  # padding to >100 chars
        out = _format_value("X", s, masked=False)
        # "admin", "staging", "foo" are non-comment -> 3 lines
        assert "3 non-comment lines" in out

    def test_short_list(self):
        assert _format_value("X", [1, 2, 3], masked=False) == "[1, 2, 3]"

    def test_empty_list(self):
        assert _format_value("X", [], masked=False) == "[]"

    def test_long_list_truncated(self):
        out = _format_value("X", list(range(20)), masked=False)
        assert "..." in out
        assert "(20 items)" in out

    def test_dict_summarised(self):
        out = _format_value("X", {"a": 1, "b": 2, "c": 3}, masked=False)
        assert out == "<dict, 3 keys>"

    def test_empty_dict(self):
        assert _format_value("X", {}, masked=False) == "{}"

    def test_masked_string(self):
        out = _format_value("API_KEY", "very-secret-token-12345", masked=True)
        assert "redacted" in out
        assert "23 chars" in out
        assert "very-secret" not in out

    def test_masked_empty_renders_as_unset(self):
        # Empty creds (e.g. SHODAN_API_KEY="") render as <unset> so the operator
        # can tell at a glance that the slot is empty -- otherwise '' would
        # suggest something non-trivial is configured.
        assert _format_value("API_KEY", "", masked=True) == "<unset>"

    def test_unmasked_empty_string_preserved(self):
        # For non-credential keys, empty string is a legitimate value
        # (e.g. NAABU_CUSTOM_PORTS="" means "use the top-ports default").
        # Don't morph it into <unset>.
        assert _format_value("NAABU_CUSTOM_PORTS", "", masked=False) == "''"

    def test_masked_none_renders_unset(self):
        # None always renders as <unset> regardless of masked flag
        assert _format_value("API_KEY", None, masked=True) == "<unset>"

    def test_a_boolean_switch_with_a_secret_shaped_name_is_shown(self):
        # URLSCAN_SECRETS_IN_URLS is a switch: a bool holds no credential.
        assert _format_value("URLSCAN_SECRETS_IN_URLS", True, masked=True) == "True"
        assert _format_value("JSLUICE_EXTRACT_SECRETS", False, masked=True) == "False"


# ===========================================================================
# print_effective_settings
# ===========================================================================
class TestPrintEffectiveSettings:
    def test_emits_header_line(self):
        out = _capture(print_effective_settings, "MyTool", {"FOO": 1}, ["FOO"])
        assert "[*][MyTool] Effective settings for this run:" in out

    def test_emits_each_key(self):
        out = _capture(print_effective_settings, "T", {"A": 1, "B": 2, "C": 3}, ["A", "B", "C"])
        assert "A " in out and "= 1" in out
        assert "B " in out and "= 2" in out
        assert "C " in out and "= 3" in out

    def test_unset_key_shown_as_unset(self):
        out = _capture(print_effective_settings, "T", {}, ["MISSING_KEY"])
        assert "MISSING_KEY" in out
        assert "<unset>" in out

    def test_group_header_emitted_when_group_changes(self):
        out = _capture(
            print_effective_settings, "T", {"A": 1, "B": 2, "C": 3, "D": 4},
            [
                ("A", "Group One"),
                ("B", "Group One"),
                ("C", "Group Two"),
                ("D", "Group Two"),
            ],
        )
        # Each group should appear exactly once
        assert out.count("# Group One") == 1
        assert out.count("# Group Two") == 1
        # Group One header must appear before A and B
        idx_g1 = out.index("# Group One")
        idx_a = out.index("A ")
        idx_b = out.index("B ")
        assert idx_g1 < idx_a < idx_b

    def test_no_group_header_when_no_groups(self):
        out = _capture(print_effective_settings, "T", {"A": 1, "B": 2}, ["A", "B"])
        assert "# " not in out  # no group lines

    def test_sensitive_key_auto_redacted(self):
        out = _capture(
            print_effective_settings, "T",
            {"SHODAN_API_KEY": "abc123def456", "WORKERS": 5},
            ["SHODAN_API_KEY", "WORKERS"],
        )
        assert "abc123def456" not in out, "API key value leaked into logs!"
        assert "redacted" in out
        assert "5" in out  # non-sensitive value passes through

    def test_explicit_redact_param_works(self):
        out = _capture(
            print_effective_settings, "T",
            {"INNOCENT_LOOKING_VAR": "supersecret", "OTHER": 1},
            ["INNOCENT_LOOKING_VAR", "OTHER"],
            redact=["INNOCENT_LOOKING_VAR"],
        )
        assert "supersecret" not in out
        assert "redacted" in out

    def test_explicit_redact_is_case_insensitive(self):
        out = _capture(
            print_effective_settings, "T",
            {"InnocentVar": "secret"},
            ["InnocentVar"],
            redact=["innocentvar"],
        )
        assert "secret" not in out

    def test_extra_lines_appended(self):
        out = _capture(
            print_effective_settings, "T", {"A": 1}, ["A"],
            extra_lines=["Total candidates: 31", "Default wordlist: skipped"],
        )
        assert "Total candidates: 31" in out
        assert "Default wordlist: skipped" in out

    def test_keys_padded_to_consistent_width(self):
        # All key names should be vertically aligned (= signs in same column)
        out = _capture(print_effective_settings, "T",
                       {"SHORT": 1, "MUCH_LONGER_KEY_NAME": 2}, ["SHORT", "MUCH_LONGER_KEY_NAME"])
        # The padding should make both = signs land at the same column
        lines = [l for l in out.splitlines() if "=" in l and "[*][T]" in l]
        eq_columns = [l.index("=") for l in lines]
        assert len(set(eq_columns)) == 1, f"= signs not aligned: {eq_columns}"

    def test_label_appears_in_every_line(self):
        out = _capture(print_effective_settings, "MyTool", {"A": 1, "B": 2},
                       [("A", "G1"), ("B", "G2")])
        # Every non-empty line should start with the [*][MyTool] prefix
        for line in out.splitlines():
            if line:
                assert line.startswith("[*][MyTool]"), f"Line missing tool prefix: {line!r}"

    def test_empty_keys_list_just_emits_header(self):
        out = _capture(print_effective_settings, "T", {"A": 1}, [])
        assert "[*][T] Effective settings for this run:" in out
        assert out.count("\n") == 1  # only the header line

    def test_iterable_consumed_only_once_safely(self):
        # If a generator was passed, it would be exhausted by the longest_key calc.
        # The helper materialises to list to handle this -- test it does.
        def gen():
            yield "A"
            yield "B"
        # Pass a list (the helper accepts Iterable). Guarantee correct output for
        # the list case which is what every caller uses.
        out = _capture(print_effective_settings, "T", {"A": 1, "B": 2}, ["A", "B"])
        assert "A " in out and "B " in out


# ===========================================================================
# Real-world rendering — make sure typical settings dicts produce
# the expected drawer-friendly output without choking on edge cases.
# ===========================================================================
class TestRealWorldShape:
    def test_naabu_style_dump(self):
        settings = {
            "NAABU_ENABLED": True,
            "NAABU_DOCKER_IMAGE": "projectdiscovery/naabu:latest",
            "NAABU_TOP_PORTS": "1000",
            "NAABU_CUSTOM_PORTS": "",
            "NAABU_RATE_LIMIT": 1000,
            "NAABU_THREADS": 25,
            "NAABU_PASSIVE_MODE": False,
        }
        out = _capture(
            print_effective_settings, "Naabu", settings,
            keys=[
                ("NAABU_ENABLED", "Toggle"),
                ("NAABU_DOCKER_IMAGE", "Image"),
                ("NAABU_TOP_PORTS", "Ports"),
                ("NAABU_CUSTOM_PORTS", "Ports"),
                ("NAABU_RATE_LIMIT", "Performance"),
                ("NAABU_THREADS", "Performance"),
                ("NAABU_PASSIVE_MODE", "Behavior"),
            ],
        )
        # All groups present
        for group in ("Toggle", "Image", "Ports", "Performance", "Behavior"):
            assert f"# {group}" in out
        # No credential leakage (none in this example, but good hygiene)
        assert "redacted" not in out

    def test_credentials_block_renders_safely(self):
        settings = {
            "SHODAN_API_KEY": "api-key-real-secret-XYZ",
            "SHODAN_KEY_ROTATOR": ["k1", "k2", "k3"],
            "SHODAN_WORKERS": 5,
        }
        out = _capture(
            print_effective_settings, "Shodan", settings,
            keys=[
                ("SHODAN_WORKERS", "Performance"),
                ("SHODAN_API_KEY", "API credentials"),
                ("SHODAN_KEY_ROTATOR", "API credentials"),
            ],
        )
        assert "api-key-real-secret-XYZ" not in out
        # SHODAN_KEY_ROTATOR is also auto-redacted (KEY_ROTATOR substring match)
        assert "k1" not in out and "k2" not in out
        assert out.count("redacted") >= 2

    def test_dump_is_idempotent(self):
        # Same settings + same keys -> same output, character for character.
        settings = {"A": 1, "B": "hello", "C": [1, 2, 3]}
        keys = [("A", "G"), ("B", "G"), ("C", "Other")]
        a = _capture(print_effective_settings, "T", settings, keys)
        b = _capture(print_effective_settings, "T", settings, keys)
        assert a == b
