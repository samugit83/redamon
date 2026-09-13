"""H3: `-ct weak` envelopes are not evidence of a weak cipher.

tlsx's `-ce -ct weak` returns ONE ENVELOPE PER TLS VERSION it managed to
enumerate, and the `ciphers` map inside is empty when that version offered
nothing weak. The check fired on the list being non-empty, so any server tlsx
could enumerate at all was reported as supporting weak ciphers.

Every fixture below is the literal shape captured from tlsx run against
testing/guinea_pigs/tls_target, not a guess. That matters: the previous
generation of this bug in the codebase was a reader looking at a key nothing
wrote.

Also pins the version side, which is correct and must stay correct: a server
negotiating tls12 while still accepting tls10 is the realistic finding, and it
is the only one of the two that tlsx can actually observe (Go's TLS client
cannot negotiate 3DES or RC4, so a weak NEGOTIATED cipher is unreachable
through tlsx -- verified live against a 3DES-only listener, which tlsx reports
as probe_status=False).

Run: python -m pytest recon/tests/test_tls_enum_checks.py
"""

import os
import sys
import unittest

_RECON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.dirname(_RECON)
for _p in (_REPO, _RECON):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Captured verbatim from:
#   tlsx -l t.txt -json -silent -duc -tps -se -hash sha256 -ve -ce -ct weak -cec 10
# against an openssl s_server offering TLSv1-TLSv1.2 with DES-CBC3-SHA enabled.
# tlsx enumerated all three versions and found NO weak cipher it could negotiate.
_REAL_EMPTY_ENUM = [
    {"version": "tls12", "ciphers": {}},
    {"version": "tls10", "ciphers": {}},
    {"version": "tls11", "ciphers": {}},
]

# The same envelope shape when tlsx does find weak ciphers.
_ENUM_WITH_WEAK = [
    {"version": "tls10", "ciphers": {"insecure": ["TLS_RSA_WITH_RC4_128_SHA"]}},
    {"version": "tls11", "ciphers": {"weak": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                              "TLS_RSA_WITH_RC4_128_SHA"]}},
]


def _tlsx_recon(**overrides):
    entry = {
        "host": "weak.tlslab.test", "scanned_ip": "192.88.98.11", "port": 8443,
        "probe_status": True, "subject_cn": "weak.tlslab.test",
        "san": ["weak.tlslab.test"], "tls_version": "tls12",
        "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "version_enum": [], "cipher_enum": [],
        "expired": False, "self_signed": False, "mismatched": False, "wildcard": False,
    }
    entry.update(overrides)
    return {"tlsx": {"by_target": {"192.88.98.11:8443": entry}}}


def _types(recon, enabled=None):
    from recon.helpers.security_checks import run_tls_data_checks
    checks = enabled or {"tls_weak_version": True, "tls_weak_cipher": True,
                         "tls_expired": True, "tls_self_signed": True,
                         "tls_hostname_mismatch": True, "tls_wildcard_overbroad": True}
    return sorted(f["type"] for f in run_tls_data_checks(recon, checks))


class WeakCipherEnum(unittest.TestCase):
    def test_envelopes_with_no_ciphers_are_not_a_finding(self):
        types = _types(_tlsx_recon(cipher_enum=_REAL_EMPTY_ENUM))
        self.assertNotIn(
            "tls_weak_cipher_supported", types,
            "a server with no weak cipher was reported as supporting weak ciphers")

    def test_actual_weak_ciphers_are_a_finding(self):
        types = _types(_tlsx_recon(cipher_enum=_ENUM_WITH_WEAK))
        self.assertIn("tls_weak_cipher_supported", types)

    def test_the_finding_names_the_ciphers_it_found(self):
        from recon.helpers.security_checks import run_tls_data_checks
        findings = run_tls_data_checks(_tlsx_recon(cipher_enum=_ENUM_WITH_WEAK),
                                       {"tls_weak_cipher": True})
        f = next(x for x in findings if x["type"] == "tls_weak_cipher_supported")
        self.assertIn("RC4", f["evidence"])
        self.assertIn("3DES", f["evidence"])
        # Deduped across versions: RC4 appears under both tls10 and tls11.
        self.assertEqual(f["evidence"].count("TLS_RSA_WITH_RC4_128_SHA"), 1)

    def test_an_older_flat_list_shape_still_works(self):
        types = _types(_tlsx_recon(cipher_enum=["TLS_RSA_WITH_RC4_128_SHA"]))
        self.assertIn("tls_weak_cipher_supported", types)

    def test_no_enum_at_all_is_not_a_finding(self):
        self.assertNotIn("tls_weak_cipher_supported", _types(_tlsx_recon()))


class WeakVersionEnum(unittest.TestCase):
    def test_a_strong_negotiation_over_a_weak_supported_version_is_flagged(self):
        """The realistic case: negotiated tls12, still accepts tls10/tls11.
        version_enum value captured verbatim from the live run."""
        types = _types(_tlsx_recon(version_enum=["tls12", "tls10", "tls11"]))
        self.assertIn("tls_weak_version_supported", types)
        self.assertNotIn("tls_weak_version", types,
                         "the negotiated version was tls12 and is not weak")

    def test_an_all_modern_enum_is_not_a_finding(self):
        types = _types(_tlsx_recon(version_enum=["tls12", "tls13"]))
        self.assertNotIn("tls_weak_version_supported", types)

    def test_a_weak_negotiated_version_is_flagged_on_its_own(self):
        """tlsx CAN negotiate tls10: verified live, tls_version='tls10'."""
        types = _types(_tlsx_recon(tls_version="tls10"))
        self.assertIn("tls_weak_version", types)

    def test_each_check_respects_its_own_toggle(self):
        recon = _tlsx_recon(tls_version="tls10", version_enum=["tls10"],
                            cipher_enum=_ENUM_WITH_WEAK)
        types = _types(recon, {"tls_weak_version": False, "tls_weak_cipher": False})
        self.assertEqual(types, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
