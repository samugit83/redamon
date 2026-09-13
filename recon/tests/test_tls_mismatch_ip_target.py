"""H5: dialling a bare IP is not a certificate hostname mismatch.

tlsx compares the certificate against whatever it dialled. On a bare IP that is
an IP literal, which no normal certificate names, so tlsx reports
``mismatched: true`` for EVERY correctly configured TLS host. The parser trusted
that flag, so an IP-mode scan raised `tls_hostname_mismatch` on every TLS port
it found: 2 of the 5 findings in the first live run against
testing/guinea_pigs/tls_target were this, on certificates perfectly consistent
with their own hostnames.

The parser already documented the right rule ("only meaningful when we
submitted a hostname") and computed it correctly -- and then OR-ed tlsx's flag
back in, which undid it.

The row below is real tlsx output for the lab's 993 port, including the
``mismatched: true`` tlsx actually emitted for the bare-IP dial. Every fixture
here keeps the cert's own names, because editing the dialled host without
editing the cert is how a test like this fools itself.

Run: python -m pytest recon/tests/test_tls_mismatch_ip_target.py
"""

import copy
import json
import os
import sys
import unittest

_RECON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.dirname(_RECON)
for _p in (_REPO, _RECON):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_IP = "192.88.98.10"

# Captured from: tlsx -l all.txt -json -silent -duc -tps -se -hash sha256 -ve
_ROW_993 = {
    "host": _IP, "ip": _IP, "port": "993", "probe_status": True,
    "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256",
    "self_signed": True, "mismatched": True,          # <- tlsx, because it dialled an IP
    "not_before": "2026-09-12T15:11:00Z", "not_after": "2027-09-12T15:11:00Z",
    "subject_dn": "CN=mail.tlslab.test, O=RedAmon TLS Lab",
    "subject_cn": "mail.tlslab.test",
    "subject_an": ["mail.tlslab.test", "imap.tlslab.test", "outsider.example-evil.test"],
    "issuer_dn": "CN=mail.tlslab.test, O=RedAmon TLS Lab",
    "issuer_cn": "mail.tlslab.test",
    "serial": "4F:3B:41:E8", "fingerprint_hash": {"sha256": "7a7247"},
    "tls_connection": "ctls", "sni": _IP,
}


def _parse(row, submitted, port=993):
    from recon.main_recon_modules.tls_scan import _parse_tlsx_output
    by_target = _parse_tlsx_output(json.dumps(row), {f"{submitted}:{port}": _IP})
    return next(iter(by_target.values()))


def _row(host, *, tlsx_says_mismatched=None, **fields):
    row = copy.deepcopy(_ROW_993)
    row["host"] = host
    if tlsx_says_mismatched is None:
        row.pop("mismatched", None)       # tlsx omits it when there is no mismatch
    else:
        row["mismatched"] = tlsx_says_mismatched
    row.update(fields)
    return row


class ABareIpDialIsNotAMismatch(unittest.TestCase):
    def test_the_tlsx_flag_is_not_trusted_when_we_dialled_the_ip(self):
        entry = _parse(_ROW_993, _IP)
        self.assertFalse(
            entry["mismatched"],
            "every IP-mode scan reports a hostname mismatch on every TLS host")

    def test_the_other_verdicts_on_the_same_cert_are_untouched(self):
        """Only the mismatch verdict is undeterminable from an IP dial."""
        entry = _parse(_ROW_993, _IP)
        self.assertTrue(entry["self_signed"])
        self.assertEqual(entry["subject_cn"], "mail.tlslab.test")
        self.assertIn("imap.tlslab.test", entry["san"])

    def test_no_mismatch_finding_is_raised_for_an_ip_target(self):
        from recon.helpers.security_checks import run_tls_data_checks
        recon = {"tlsx": {"by_target": {f"{_IP}:993": _parse(_ROW_993, _IP)}}}
        types = [f["type"] for f in run_tls_data_checks(
            recon, {"tls_hostname_mismatch": True, "tls_self_signed": True})]
        self.assertNotIn("tls_hostname_mismatch", types)
        self.assertIn("tls_self_signed", types, "the real finding must survive")

    def test_an_httpx_sourced_cert_on_an_ip_url_is_also_exempt(self):
        """The httpx verdict is derived from the URL host, so an IP-addressed
        URL mismatches every certificate naming a hostname."""
        from recon.helpers.security_checks import run_tls_data_checks
        recon = {"http_probe": {"by_url": {f"https://{_IP}:8443": {
            "host": _IP, "ip": _IP,
            "tls": {"version": "tls13", "certificate": {
                "subject_cn": "mail.tlslab.test", "san": ["mail.tlslab.test"]}},
        }}}}
        types = [f["type"] for f in run_tls_data_checks(
            recon, {"tls_hostname_mismatch": True})]
        self.assertNotIn("tls_hostname_mismatch", types)


class AHostnameDialStillDecidesHonestly(unittest.TestCase):
    def test_a_hostname_the_cert_names_is_not_a_mismatch(self):
        self.assertFalse(_parse(_row("mail.tlslab.test"), "mail.tlslab.test")["mismatched"])

    def test_a_san_entry_counts_as_named(self):
        self.assertFalse(_parse(_row("imap.tlslab.test"), "imap.tlslab.test")["mismatched"])

    def test_a_hostname_the_cert_does_not_name_is_a_mismatch(self):
        self.assertTrue(_parse(_row("wrong.tlslab.test"), "wrong.tlslab.test")["mismatched"])

    def test_tlsx_is_still_believed_when_we_dialled_a_hostname(self):
        """tlsx saw the real SNI, so its verdict wins over our derivation."""
        row = _row("mail.tlslab.test", tlsx_says_mismatched=True)
        self.assertTrue(_parse(row, "mail.tlslab.test")["mismatched"])

    def test_one_wildcard_label_matches(self):
        row = _row("foo.wild.tlslab.test", subject_cn="*.wild.tlslab.test",
                   subject_an=["*.wild.tlslab.test"])
        self.assertFalse(_parse(row, "foo.wild.tlslab.test")["mismatched"])

    def test_two_labels_deep_under_a_wildcard_does_not_match(self):
        row = _row("a.b.wild.tlslab.test", subject_cn="*.wild.tlslab.test",
                   subject_an=["*.wild.tlslab.test"])
        self.assertTrue(_parse(row, "a.b.wild.tlslab.test")["mismatched"])

    def test_a_failed_probe_never_yields_a_mismatch(self):
        row = _row("wrong.tlslab.test", probe_status=False)
        self.assertFalse(_parse(row, "wrong.tlslab.test")["mismatched"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
