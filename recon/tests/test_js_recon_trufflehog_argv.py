"""The `docker run` JS Recon builds for its TruffleHog sidecar.

The sidecar reads hostile JavaScript, so the argv is the security boundary:
no network unless keys are verified, never the host network, every capability
dropped, a read-only root, the staged files mounted read-only, a memory cap
from the resource governor, and the V2 detector exclusions in both modes.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import trufflehog_bridge as th

STAGE = "/tmp/redamon/js_recon_th_run1_abcd1234"


def _argv(verify, **kw):
    kw.setdefault("concurrency", 10)
    kw.setdefault("validation_timeout", 7)
    kw.setdefault("name", "redamon-jsth-run1-abcd1234")
    kw.setdefault("memory", "805306368")
    return th.build_argv(STAGE, verify=verify, **kw)


def _value(argv, flag):
    return argv[argv.index(flag) + 1]


class Network(unittest.TestCase):
    def test_none_without_verification(self):
        self.assertEqual(_value(_argv(False), "--network"), "none")

    def test_the_named_bridge_with_verification(self):
        self.assertEqual(_value(_argv(True), "--network"), "redamon-trufflehog-net")
        self.assertEqual(_value(_argv(True, network="other-net"), "--network"), "other-net")

    def test_never_host(self):
        for verify in (False, True):
            argv = _argv(verify)
            self.assertNotIn("host", argv)
            self.assertFalse(any(a.startswith("--net=host") or a == "--network=host" for a in argv))
            self.assertNotIn("--privileged", argv)


class Hardening(unittest.TestCase):
    def test_flags(self):
        for verify in (False, True):
            argv = _argv(verify)
            self.assertEqual(_value(argv, "--cap-drop"), "ALL")
            self.assertIn("--read-only", argv)
            self.assertEqual(_value(argv, "--tmpfs"), "/tmp:size=256m")
            self.assertNotIn("--mount", argv)
            self.assertEqual(_value(argv, "--pids-limit"), "256")
            self.assertEqual(_value(argv, "--cpus"), "2")
            self.assertEqual(_value(argv, "--user"), "10001:10001")
            self.assertEqual(_value(argv, "-v"), f"{STAGE}:/scan:ro")
            self.assertEqual(_value(argv, "--entrypoint"), "trufflehog")
            self.assertIn("--rm", argv)

    def test_memory_comes_from_the_governor(self):
        with mock.patch.object(th, "sidecar_memory", return_value="1207959552") as mem:
            argv = th.build_argv(STAGE, verify=False, concurrency=4, validation_timeout=5, name="n")
        mem.assert_called_once()
        self.assertEqual(_value(argv, "--memory"), "1207959552")

    def test_the_governor_is_asked_for_the_sidecars_own_envelope(self):
        governor = mock.Mock()
        governor.tool_container_envelope.return_value = 805306368
        governor.container_cap.return_value = 1207959552
        with mock.patch.dict(sys.modules, {"graph_db.resource_governor": governor,
                                           "graph_db": mock.Mock(resource_governor=governor)}):
            self.assertEqual(th.sidecar_memory(), "1207959552")
        governor.tool_container_envelope.assert_called_once_with("trufflehog_js")
        governor.container_cap.assert_called_once_with(805306368)

    def test_no_secret_reaches_the_container_env(self):
        argv = _argv(True)
        self.assertNotIn("-e", argv)
        self.assertNotIn("--env", argv)
        self.assertFalse(any(a.startswith("--env") for a in argv))


class TruffleHogFlags(unittest.TestCase):
    def test_always(self):
        for verify in (False, True):
            argv = _argv(verify)
            image = argv.index(th.TRUFFLEHOG_IMAGE)
            self.assertEqual(argv[image + 1:image + 3], ["filesystem", "/scan"])
            for flag in ("--json", "--no-update", "--fail-on-scan-errors"):
                self.assertIn(flag, argv)
            self.assertFalse(any(a.startswith("--results") for a in argv))

    def test_without_verification(self):
        argv = _argv(False, concurrency=12)
        self.assertIn("--no-verification", argv)
        self.assertEqual(_value(argv, "--concurrency"), "12")
        self.assertFalse(any(a.startswith("--detector-timeout") for a in argv))

    def test_with_verification(self):
        argv = _argv(True, concurrency=12, validation_timeout=9)
        self.assertNotIn("--no-verification", argv)
        self.assertIn("--detector-timeout=9s", argv)
        self.assertEqual(_value(argv, "--concurrency"), "4")
        self.assertEqual(_value(_argv(True, concurrency=2), "--concurrency"), "2")
        # The cache keeps it to one provider call per distinct key per run.
        self.assertNotIn("--no-verification-cache", argv)

    def test_exclusions_in_both_modes(self):
        for verify in (False, True):
            flags = [a for a in _argv(verify) if a.startswith("--exclude-detectors=")]
            self.assertEqual(len(flags), 1)
            names = set(flags[0].split("=", 1)[1].split(","))
            self.assertEqual(names, set(th.TRUFFLEHOG_EXCLUDED_DETECTORS))
            self.assertTrue({"PrivateKey", "URI", "JDBC", "JWT"} <= names)

    def test_each_flag_once(self):
        for verify in (False, True):
            argv = _argv(verify)
            flags = [a.split("=", 1)[0] for a in argv if a.startswith("--")]
            self.assertEqual(len(flags), len(set(flags)), flags)

    def test_the_container_name(self):
        name = th.container_name("cmvx1234567890")
        self.assertTrue(name.startswith("redamon-jsth-cmvx1234-"))
        self.assertEqual(_value(_argv(False, name=name), "--name"), name)


if __name__ == "__main__":
    unittest.main()
