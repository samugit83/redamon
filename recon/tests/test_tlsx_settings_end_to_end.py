"""A saved tlsx configuration must reach the command tlsx is actually run with.

The browser spec (testing/e2e/tests/tlsxSettings.spec.ts) proves the UI writes
the columns. This proves the other half: the columns become settings, and those
settings become argv. Those are two separate silent-failure points --
`fetch_project_settings` maps by hand, one key per line, and
`build_tlsx_command` gates each flag on its own setting -- and a value that
stops at either one leaves a control that visibly saves and changes nothing.

Also pins cross-language parity: every tlsx column in the Prisma schema must be
read in recon/project_settings.py. Adding a field to the form and the database
while forgetting the Python mapping is the failure this catches, and it cannot
be caught on either side alone.

Run: python -m pytest recon/tests/test_tlsx_settings_end_to_end.py
"""

import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


class _FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


def settings_for(project_row: dict) -> dict:
    """Run the real fetch mapping over a project row, with the HTTP call faked."""
    from recon.project_settings import fetch_project_settings
    # The row the webapp returns always carries an id; settings code may read it.
    row = {"id": "PROJ", "userId": "USER", **project_row}
    with patch("requests.get", return_value=_FakeResponse(row)):
        return fetch_project_settings("PROJ", "http://webapp")


def argv_for(project_row: dict) -> list:
    from recon.main_recon_modules.tls_scan import build_tlsx_command
    return build_tlsx_command("/t/targets.txt", "/t", settings_for(project_row))


def flag_value(argv: list, flag: str):
    """The token after `flag`, or None when the flag is absent."""
    return argv[argv.index(flag) + 1] if flag in argv else None


class DefaultsAreQuiet(unittest.TestCase):
    """Every loud probe is opt-in; the base grab is what runs unasked."""

    def setUp(self):
        self.argv = argv_for({})

    def test_the_base_grab_flags_are_always_present(self):
        for flag in ("-json", "-silent", "-duc", "-tps", "-se"):
            self.assertIn(flag, self.argv)
        self.assertEqual(flag_value(self.argv, "-hash"), "sha256")

    def test_no_loud_probe_is_on_by_default(self):
        for flag in ("-jarm", "-ja3", "-ve", "-ce", "-rps", "-delay", "-sm"):
            self.assertNotIn(flag, self.argv, f"{flag} runs without being asked for")

    def test_the_documented_defaults_are_the_ones_sent(self):
        self.assertEqual(flag_value(self.argv, "-c"), "50")
        self.assertEqual(flag_value(self.argv, "-timeout"), "5")
        self.assertEqual(flag_value(self.argv, "-retry"), "1")

    def test_output_filters_are_never_passed(self):
        """-ex/-ss/-mm/-re/-un would drop every healthy host from the results."""
        for flag in ("-ex", "-ss", "-mm", "-re", "-un"):
            self.assertNotIn(flag, self.argv)


class EachProbeTogglesItsOwnFlags(unittest.TestCase):
    def test_jarm_brings_ja3_with_it(self):
        argv = argv_for({"tlsxProbeJarm": True})
        self.assertIn("-jarm", argv)
        self.assertIn("-ja3", argv)
        self.assertNotIn("-ve", argv)
        self.assertNotIn("-ce", argv)

    def test_version_enum_only(self):
        argv = argv_for({"tlsxVersionEnum": True})
        self.assertIn("-ve", argv)
        self.assertNotIn("-ce", argv)
        self.assertNotIn("-jarm", argv)

    def test_cipher_enum_asks_for_weak_ciphers_at_its_own_concurrency(self):
        argv = argv_for({"tlsxCipherEnum": True, "tlsxCipherConcurrency": 7})
        self.assertIn("-ce", argv)
        self.assertEqual(flag_value(argv, "-ct"), "weak")
        self.assertEqual(flag_value(argv, "-cec"), "7")

    def test_reverse_ptr_sni_only(self):
        argv = argv_for({"tlsxRevPtrSni": True})
        self.assertIn("-rps", argv)
        self.assertNotIn("-ve", argv)

    def test_all_four_together(self):
        argv = argv_for({
            "tlsxProbeJarm": True, "tlsxVersionEnum": True,
            "tlsxCipherEnum": True, "tlsxRevPtrSni": True,
        })
        for flag in ("-jarm", "-ja3", "-ve", "-ce", "-rps"):
            self.assertIn(flag, argv)
        self.assertEqual(flag_value(argv, "-ct"), "weak")

    def test_no_flag_is_duplicated_with_everything_on(self):
        argv = argv_for({
            "tlsxProbeJarm": True, "tlsxVersionEnum": True,
            "tlsxCipherEnum": True, "tlsxRevPtrSni": True,
            "tlsxScanMode": "ctls", "tlsxDelay": "1s",
        })
        for flag in set(a for a in argv if a.startswith("-")):
            self.assertEqual(argv.count(flag), 1, f"{flag} appears twice")


class NumericAndStringSettingsArriveVerbatim(unittest.TestCase):
    def test_concurrency_timeout_and_retries(self):
        argv = argv_for({"tlsxConcurrency": 33, "tlsxTimeout": 9, "tlsxRetries": 3})
        self.assertEqual(flag_value(argv, "-c"), "33")
        self.assertEqual(flag_value(argv, "-timeout"), "9")
        self.assertEqual(flag_value(argv, "-retry"), "3")

    def test_scan_mode_auto_sends_no_flag_but_an_explicit_mode_does(self):
        self.assertNotIn("-sm", argv_for({"tlsxScanMode": "auto"}))
        self.assertEqual(flag_value(argv_for({"tlsxScanMode": "ctls"}), "-sm"), "ctls")

    def test_delay_is_only_sent_when_set(self):
        self.assertNotIn("-delay", argv_for({"tlsxDelay": ""}))
        self.assertEqual(flag_value(argv_for({"tlsxDelay": "2s"}), "-delay"), "2s")

    def test_an_allowlisted_image_is_used_verbatim(self):
        from recon.project_settings import DEFAULT_SETTINGS
        shipped = DEFAULT_SETTINGS['TLSX_DOCKER_IMAGE']
        self.assertIn(shipped, argv_for({"tlsxDockerImage": shipped}))

    def test_an_image_outside_the_allowlist_is_pinned_back(self):
        """`sanitize_image_settings` is the control that stops a project row
        from running an arbitrary image as a sibling container. The settings
        column is operator input, so this is a real boundary, not a formality."""
        from recon.project_settings import DEFAULT_SETTINGS
        argv = argv_for({"tlsxDockerImage": "attacker/evil:latest"})
        self.assertNotIn("attacker/evil:latest", argv)
        self.assertIn(DEFAULT_SETTINGS['TLSX_DOCKER_IMAGE'], argv)


class TargetSelectionSettings(unittest.TestCase):
    """These never reach argv: they shape the target list instead."""

    # 192.88.98.x, not 203.0.113.x: `is_non_routable_ip` rejects TEST-NET-3
    # before a packet is built, so a TEST-NET fixture yields an empty target
    # list and every assertion here would pass or fail for the wrong reason.
    # The 6to4 relay block reads as global, which is why the lab uses it too.
    IP = "192.88.98.10"
    PORT_SCAN = {"port_scan": {"by_ip": {IP: {
        "ip": IP, "hostnames": [], "ports": [443, 993, 636],
    }}}}

    def _targets(self, row):
        from recon.main_recon_modules.tls_scan import _build_tlsx_targets
        lines, _meta = _build_tlsx_targets(self.PORT_SCAN, settings_for(row))
        return lines

    def test_https_ports_are_skipped_by_default(self):
        targets = self._targets({})
        self.assertNotIn(f"{self.IP}:443", targets)
        self.assertIn(f"{self.IP}:993", targets)

    def test_include_http_ports_adds_them_back(self):
        targets = self._targets({"tlsxIncludeHttpPorts": True})
        self.assertIn(f"{self.IP}:443", targets)

    def test_max_targets_caps_the_list(self):
        self.assertEqual(len(self._targets({"tlsxMaxTargets": 1})), 1)

    def test_a_cap_of_zero_scans_nothing(self):
        self.assertEqual(self._targets({"tlsxMaxTargets": 0}), [])


class MockHostnameTargets(unittest.TestCase):
    """H8: the reverse-DNS placeholder must never be sent as an SNI target."""

    IP = "192.88.98.10"
    MOCK = "192-88-98-10"

    def _build(self, hostnames):
        from recon.main_recon_modules.tls_scan import _build_tlsx_targets
        recon = {"port_scan": {"by_ip": {self.IP: {
            "ip": self.IP, "hostnames": hostnames, "ports": [993],
        }}}}
        lines, meta = _build_tlsx_targets(recon, settings_for({}))
        return lines

    def test_the_dashed_ip_placeholder_is_replaced_by_the_ip(self):
        """A partial run reads targets from the graph, where IP mode left a
        Subdomain named after the dashed IP. tlsx cannot resolve it: every
        handshake failed with `no address found for host`."""
        lines = self._build([self.MOCK])
        self.assertEqual(lines, [f"{self.IP}:993"])

    def test_a_real_hostname_is_still_preferred_for_sni(self):
        lines = self._build(["mail.tlslab.test"])
        self.assertEqual(lines, ["mail.tlslab.test:993"])

    def test_a_real_hostname_survives_alongside_a_placeholder(self):
        lines = self._build([self.MOCK, "mail.tlslab.test"])
        self.assertEqual(lines, ["mail.tlslab.test:993"])

    def test_an_ipv6_placeholder_is_recognised_too(self):
        from recon.main_recon_modules.tls_scan import _is_mock_hostname
        self.assertTrue(_is_mock_hostname("2001-db8--1", "2001:db8::1"))
        self.assertFalse(_is_mock_hostname("mail.tlslab.test", "192.88.98.10"))


class PrismaToPythonParity(unittest.TestCase):
    def test_every_tlsx_column_is_read_by_the_settings_loader(self):
        schema = (_REPO / "webapp" / "prisma" / "schema.prisma").read_text()
        columns = set(re.findall(r"^\s+(tlsx[A-Za-z0-9]+)\s", schema, re.M))
        self.assertTrue(columns, "found no tlsx columns; did the schema move?")

        loader = (_RECON / "project_settings.py").read_text()
        missing = [c for c in sorted(columns) if f"'{c}'" not in loader]
        self.assertEqual(
            missing, [],
            "these columns exist in the database and the form but are never read "
            f"into settings, so changing them does nothing: {missing}")

    def test_every_mapped_setting_has_a_default(self):
        from recon.project_settings import DEFAULT_SETTINGS
        loader = (_RECON / "project_settings.py").read_text()
        keys = set(re.findall(r"settings\['(TLSX_[A-Z_]+)'\]", loader))
        missing = [k for k in sorted(keys) if k not in DEFAULT_SETTINGS]
        self.assertEqual(missing, [], f"mapped with no default: {missing}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
