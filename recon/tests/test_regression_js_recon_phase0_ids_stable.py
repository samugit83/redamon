"""R8: the regex fixes of the TruffleHog plan's Phase 0 keep every surviving id.

A js_recon Secret's id is a hash of its rule name, its matched text and its
file (`patterns._make_finding_id`); mutes, Priority Board verdicts, fix items
and node-filter rules attach to that id. Phase 0 tightened the rules that made
the most noise (the generic-overlap collapse, the PEM key-data check, the
certificate severity, the Yandex keyword, short-prefix boundaries, generic UUID
values) without renaming a rule or changing a surviving match. This test pins
that: every true-positive sample yields the ids it yielded BEFORE the fixes,
recorded in `fixtures/js_recon_phase0_ids_golden.json` (ids only, never a
value). A finding a fix removes on purpose is listed in `_REMOVED`, each with
its plan item.

Every value is synthetic and assembled at runtime, so no key-shaped string sits
in the source. Regenerate the golden only from the pre-Phase-0 patterns:

    python recon/tests/test_regression_js_recon_phase0_ids_stable.py --regen
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

from recon.helpers.js_recon import patterns

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "js_recon_phase0_ids_golden.json"
URL = "https://app.example.com/assets/main.js"

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def _rnd(label: str, alphabet: str, n: int) -> str:
    rng = random.Random(f"r8:{label}")
    return "".join(rng.choice(alphabet) for _ in range(n))


def _uuid4(label: str) -> str:
    h = _rnd(label, HEX, 32)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def _pem(kind: str, label: str) -> str:
    body = _rnd(label, string.ascii_letters + string.digits + "+/", 256)
    lines = "\\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    head = "-----BEGIN " + kind + "-----"
    tail = "-----END " + kind + "-----"
    return f'const pem = "{head}\\n{lines}\\n{tail}";'


def samples() -> dict:
    """label -> JavaScript holding one true-positive shape per rule Phase 0 touches."""
    gcp = "AI" + "za" + _rnd("gcp", ALNUM, 35)
    return {
        # 0.1: a generic rule whose match contains a specific one's.
        "gcp_in_apikey": 'const firebaseConfig = {apiKey: "' + gcp + '", projectId: "demo"};',
        "gemini_in_api_key": 'const cfg = {gemini_api_key:"' + "AI" + "za" + _rnd("gem", ALNUM, 35) + '"};',
        "stripe_in_secret": 'const secret = "' + "sk" + "_live_" + _rnd("stripe", ALNUM, 28) + '";',
        # 0.1: generic rules alone keep their ids.
        "generic_api_key": 'var api_key = "' + _rnd("gak", ALNUM, 24) + '";',
        "generic_token": 'const access_token = "' + _rnd("gtok", ALNUM, 32) + '";',
        "generic_secret": 'const client = {secret: "' + _rnd("gsec", ALNUM, 20) + '"};',
        "hardcoded_password": 'var password = "' + "Tr0" + _rnd("pwd", ALNUM, 9) + '!";',
        # 0.2: private keys with key data.
        "pem_rsa": _pem("RSA PRIVATE KEY", "rsa"),
        "pem_dsa": _pem("DSA PRIVATE KEY", "dsa"),
        "pem_ec": _pem("EC PRIVATE KEY", "ec"),
        "pem_openssh": _pem("OPENSSH PRIVATE KEY", "ossh"),
        "pem_pgp": _pem("PGP PRIVATE KEY BLOCK", "pgp"),
        "pem_generic": _pem("PRIVATE KEY", "pkcs8"),
        # 0.3: a certificate keeps its name and id.
        "certificate": _pem("CERTIFICATE", "cert"),
        # 0.4: a Yandex key next to its provider word.
        "yandex_aws": 'const yandexCloud = {accessKeyId: "' + "Y" + "C" + _rnd("ycaws", ALNUM, 38) + '"};',
        # 0.5: short-prefix rules on a real-looking key.
        "resend": 'const RESEND_KEY = "' + "re" + "_" + _rnd("resend", ALNUM, 24) + '";',
        "databricks": 'const DATABRICKS = "' + "da" + "pi" + _rnd("dapi", "abcdefgh0123456789", 32) + '";',
        "nuget": 'const NUGET = "' + "oy" + "2" + _rnd("nuget", string.ascii_lowercase + string.digits, 43) + '";',
        "pulumi": 'const PULUMI = "' + "pul" + "-" + _rnd("pulumi", HEX, 40) + '";',
        "infracost": 'const INFRACOST = "' + "ico" + "-" + _rnd("ico", ALNUM, 32) + '";',
        "octopus": 'const OCTOPUS = "' + "API" + "-" + _rnd("octo", string.ascii_uppercase + string.digits, 25) + '";',
        "huggingface": 'const HF = "' + "hf" + "_" + _rnd("hf", string.ascii_letters, 34) + '";',
        "replicate": 'const REPLICATE = "' + "r8" + "_" + _rnd("r8", ALNUM, 40) + '";',
        "mapbox": 'mapboxgl.accessToken = "' + "pk" + "." + _rnd("mapbox", ALNUM, 72) + '";',
        # 0.6: generic rule on a UUID value, and a provider rule on one.
        "generic_uuid": 'const settings = {apiKey: "' + _uuid4("guuid") + '"};',
        "heroku_uuid": 'const herokuApiKey = "' + _uuid4("heroku") + '";',
    }


def _ids(js: str) -> list:
    findings, _ = patterns.scan_js_content(js, URL)
    return sorted([f["name"], f["id"]] for f in findings)


#: (sample, rule) pairs a Phase 0 fix removes on purpose: the generic match
#: whose span holds a specific credential's (item 0.1); the specific one keeps
#: its id and lists the generic name in alternate_names.
_REMOVED = {
    ("gcp_in_apikey", "Generic API Key"),
    ("gemini_in_api_key", "Generic API Key"),
    ("stripe_in_secret", "Generic Secret"),
}


class Phase0IdsStable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = json.loads(GOLDEN.read_text())

    def test_golden_covers_every_sample(self):
        self.assertEqual(set(self.golden), set(samples()))

    def test_every_surviving_id_is_unchanged(self):
        for label, js in samples().items():
            now = {tuple(p) for p in _ids(js)}
            for name, fid in self.golden[label]:
                if (label, name) in _REMOVED:
                    continue
                with self.subTest(sample=label, rule=name):
                    self.assertIn((name, fid), now)

    def test_removed_findings_are_gone_and_named_on_the_winner(self):
        for label, rule in sorted(_REMOVED):
            findings, _ = patterns.scan_js_content(samples()[label], URL)
            with self.subTest(sample=label, rule=rule):
                self.assertNotIn(rule, [f["name"] for f in findings])
                self.assertTrue(any(rule in f.get("alternate_names", []) for f in findings))


if __name__ == "__main__":
    if "--regen" in sys.argv:
        GOLDEN.write_text(json.dumps({k: _ids(v) for k, v in samples().items()}, indent=1, sort_keys=True) + "\n")
        print(f"wrote {GOLDEN}")
    else:
        unittest.main()
