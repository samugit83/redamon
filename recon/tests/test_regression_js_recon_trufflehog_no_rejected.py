"""R4: no TruffleHog path writes `rejected` (rule V1).

With no network, a TruffleHog verifier can swallow the error and answer
`Verified: false` exactly as it does for a dead key, so "not verified" is no
verdict: it maps to `unknown` (or `skipped` without verification), and only
js_recon's own validators may say a key is dead. Every result shape, with and
without verification, matched to a regex finding or not, is checked after the
merge AND after `_validate_secrets`. Values are synthetic.
"""
from __future__ import annotations

import itertools
import random
import string
from unittest import mock

from recon.helpers.js_recon import patterns
from recon.helpers.js_recon import trufflehog_bridge as th
from recon.main_recon_modules import js_recon

URL = "https://app.example.com/main.js"
rng = random.Random("r4")
GH = "gh" + "p_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))
OTHER = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(32))
CONTENT = f'const t = "{GH}"; const shodanKey = "{OTHER}";'
MANIFEST = {"f_00001.js": {"url": URL, "content": CONTENT}}
UNKNOWN = {"valid": False, "state": "unknown", "error": "", "info": "status=503"}


def test_no_trufflehog_path_is_rejected():
    shapes = [{}, {"verified": True}, {"error": "dial tcp: i/o timeout"}]
    for verify, shape, detector, raw in itertools.product((False, True), shapes,
                                                           ("Github", "Shodan"), (GH, OTHER)):
        result = th.ThResult(detector=detector, verified=shape.get("verified", False),
                             error=shape.get("error", ""), raw=raw, file="f_00001.js", line=1, extra={})
        regex = patterns.scan_js_content(CONTENT, URL)[0]
        merged, _ = th.merge(regex, [result], MANIFEST, verify=verify)
        for s in merged:
            if s.get("detection_method") == "trufflehog":
                assert s["validation"]["status"] in ("validated", "unknown", "skipped")
        with mock.patch.object(js_recon, "validate_secret", return_value=UNKNOWN):
            out = js_recon._validate_secrets(merged, {"JS_RECON_VALIDATE_KEYS": verify})
        assert all(s["validation"]["status"] != "rejected" for s in out), (verify, shape, detector)
