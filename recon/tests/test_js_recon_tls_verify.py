"""JS Recon reads the target's own files whatever certificate they present.

httpx and katana accept a self-signed or internal-CA certificate, so an
internal target's pages are crawled; JS Recon verified it and analysed none of
their JavaScript (found by the urlscan lab, whose hosts use a lab CA). Target
downloads (bundles, source maps and their control, endpoint checks) skip
verification; the key validators, which send a secret to a third party, keep
it. Nothing here leaves the test.
"""
import inspect
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import recon.main_recon_modules.js_recon as jr  # noqa: E402
from recon.helpers.js_recon import sourcemap as sm  # noqa: E402
from recon.helpers.js_recon import validators  # noqa: E402

PUBLIC = "https://93.184.216.34/static/app.js"


class _R:
    status_code = 200
    headers = {"Content-Type": "application/javascript"}
    text = ""
    content = b""


class TestTargetDownloadsSkipVerification(unittest.TestCase):
    def test_the_bundle_download(self):
        with patch.object(jr.requests, "get", return_value=_R()) as get:
            jr._safe_redirect_get(PUBLIC, timeout=5, headers={})
        self.assertIs(get.call_args.kwargs["verify"], False)

    def test_every_source_map_fetch(self):
        src = inspect.getsource(sm)
        calls = re.findall(r"requests\.(?:get|head)\((?:[^()]|\([^()]*\))*\)", src, re.S)
        self.assertGreaterEqual(len(calls), 3)
        for call in calls:
            self.assertIn("verify=False", call, call)

    def test_the_endpoint_checks(self):
        src = inspect.getsource(jr)
        calls = re.findall(r"requester\((?:[^()]|\([^()]*\))*\)", src, re.S)
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertIn("verify=False", call, call)


class TestKeyValidatorsKeepVerification(unittest.TestCase):
    def test_no_validator_turns_verification_off(self):
        self.assertNotIn("verify=False", inspect.getsource(validators))


if __name__ == "__main__":
    unittest.main()
