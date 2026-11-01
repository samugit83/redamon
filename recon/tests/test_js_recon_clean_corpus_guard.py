"""A minified library with no secret in it yields nothing at medium or above.

The shapes are the false-positive classes the TruffleHog plan's Phase 0 fixed
(the gap report and the clean-library census): webpack chunk ids that start
`YC`, `re_` inside identifiers, `dapi` inside a hash, UUIDs that are object
ids, PEM templates and parser branches that hold no key, and a public
certificate. The bundle is generated from a fixed seed, so a rule that starts
firing on it again fails here, not on a customer's estate.
"""

from __future__ import annotations

import random
import string
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns

URL = "https://cdn.example.com/assets/vendor.3f9a.js"
ALNUM = string.ascii_letters + string.digits


def _bundle(seed: int = 7) -> str:
    rng = random.Random(seed)

    def rnd(alphabet, n):
        return "".join(rng.choice(alphabet) for _ in range(n))

    def uuid4():
        h = rnd("0123456789abcdef", 32)
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"

    begin, end = "-----BEGIN ", "-----END "
    cert_body = rnd(ALNUM + "+/", 512)
    parts = [
        "!function(e){var t={};",
        # webpack chunk ids
        "var c={" + ",".join(f'{i}:"Y' + "C" + rnd(ALNUM + "_-", 38) + '"' for i in range(12)) + "};",
        # `re_` inside identifiers
        "".join(f"function configu{'re_'}{rnd(ALNUM, 22)}(n){{return n}}" for _ in range(4)),
        "".join(f"var prepa{'re_'}{rnd(ALNUM, 24)}=1;" for _ in range(3)),
        # `dapi` inside a longer hash run
        'var integrity="sha384-' + rnd(ALNUM, 20) + "da" + "pi" + rnd("abcdefgh0123456789", 32) + '";',
        # UUIDs that are object ids, not keys
        "".join(f'{{id:"{uuid4()}",requestId:"{uuid4()}"}},' for _ in range(5)),
        # PEM templates and parser branches with no key data
        'function a(n){return"' + begin + 'PRIVATE KEY-----\\n"+n+"\\n' + end + 'PRIVATE KEY-----"}',
        "function b(n){return`" + begin + "RSA PRIVATE KEY-----\\n${n}\\n" + end + "RSA PRIVATE KEY-----`}",
        'if(s.indexOf("' + begin + 'EC PRIVATE KEY-----")!=-1)return KJUR.asn1.ASN1Util.getHex(s);',
        'var h="' + begin + 'OPENSSH PRIVATE KEY-----",j="' + begin + 'PGP PRIVATE KEY BLOCK-----";',
        # a public certificate
        'var ca="' + begin + 'CERTIFICATE-----\\n' + "\\n".join(cert_body[i:i + 64] for i in range(0, 512, 64))
        + "\\n" + end + 'CERTIFICATE-----";',
        # ordinary library code
        "".join(f"e.{rnd(string.ascii_lowercase, 6)}=function(n,r){{return n+r}};" for _ in range(40)),
        "}(window);",
    ]
    return "".join(parts)


class CleanCorpusGuard(unittest.TestCase):
    def test_no_finding_at_medium_or_above(self):
        findings, _ = patterns.scan_js_content(_bundle(), URL)
        loud = [(f["name"], f["severity"]) for f in findings
                if patterns.SEVERITY_ORDER[f["severity"]] >= patterns.SEVERITY_ORDER["medium"]]
        self.assertEqual(loud, [])

    def test_the_certificate_is_still_reported_at_info(self):
        findings, _ = patterns.scan_js_content(_bundle(), URL)
        self.assertIn(("PKCS12 Certificate", "info"), [(f["name"], f["severity"]) for f in findings])


if __name__ == "__main__":
    unittest.main()
