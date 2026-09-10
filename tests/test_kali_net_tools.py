"""
Regression: the Kali sandbox image must ship `iproute2` (the `ip` command).

Issue #180 — during exploitation the agent runs `ip addr` to inspect its own
interfaces; the image shipped only `net-tools` (ifconfig/route), so `ip` was
absent and the probe hard-failed with "ip: command not found". Pure text scan of
the Dockerfile; no docker, no deps:  python3 tests/test_kali_net_tools.py
"""

import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KALI_DF = os.path.join(REPO, "mcp", "kali-sandbox", "Dockerfile")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestKaliNetTooling(unittest.TestCase):
    def setUp(self):
        self.txt = _read(KALI_DF)

    def test_iproute2_installed(self):
        # Must appear as its own apt token in an install list, not inside a
        # comment or a longer word.
        self.assertRegex(
            self.txt,
            r"(?m)^\s*iproute2\b",
            "iproute2 (the `ip` command) is missing from the Kali Dockerfile",
        )

    def test_net_tools_still_present(self):
        # Kept alongside iproute2 for tools that still shell out to ifconfig.
        self.assertRegex(self.txt, r"(?m)^\s*net-tools\b")


if __name__ == "__main__":
    unittest.main()
