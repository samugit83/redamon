"""httpx, katana, tlsx and naabu resolve through the scan's own resolver.

Found by the urlscan lab: httpx's built-in resolver list includes public
resolvers, so a name only the local DNS knows (the lab's .test zones; an
internal or split-horizon name in an engagement) failed at random and whole
hosts dropped out of the probe (4 of 4 URLs, then 2, then 3, on the same
input). With the system resolver passed in, 6 of 6 runs were complete.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from recon.main_recon_modules import http_probe as hp  # noqa: E402


from recon.helpers import system_resolvers as sr  # noqa: E402


class TestSystemResolvers(unittest.TestCase):
    def test_reads_every_nameserver_once(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("# generated\nnameserver 127.0.0.53\nsearch lan\nnameserver 10.0.0.2\nnameserver 127.0.0.53\n")
        self.assertEqual(sr.system_resolvers(f.name), ["127.0.0.53", "10.0.0.2"])

    def test_missing_file_is_no_resolver(self):
        self.assertEqual(sr.system_resolvers("/nonexistent/resolv.conf"), [])

    def test_resolver_args(self):
        with patch.object(sr, "system_resolvers", return_value=["127.0.0.53", "10.0.0.2"]):
            self.assertEqual(sr.resolver_args(), ["-r", "127.0.0.53,10.0.0.2"])
        with patch.object(sr, "system_resolvers", return_value=[]):
            self.assertEqual(sr.resolver_args(), [])

    def test_tlsx_naabu_and_katana_use_it(self):
        root = Path(__file__).resolve().parent.parent
        for rel in ("main_recon_modules/tls_scan.py", "main_recon_modules/port_scan.py",
                    "helpers/resource_enum/katana_helpers.py"):
            self.assertIn("resolver_args()", (root / rel).read_text(), rel)

    def test_the_tlsx_command(self):
        from recon.main_recon_modules import tls_scan
        with patch.object(sr, "system_resolvers", return_value=["127.0.0.53"]):
            cmd = tls_scan.build_tlsx_command("/tmp/t/x.txt", "/tmp/t", {})
        self.assertEqual(cmd[-2:], ["-r", "127.0.0.53"])

    def test_the_command_passes_them(self):
        with patch.object(hp, "system_resolvers", return_value=["127.0.0.53"]):
            cmd = hp.build_httpx_command("/tmp/t.txt", "/tmp/o.json", {})
        cmd = cmd[0] if isinstance(cmd, tuple) else cmd
        self.assertIn("-r", cmd)
        self.assertEqual(cmd[cmd.index("-r") + 1], "127.0.0.53")
        with patch.object(hp, "system_resolvers", return_value=[]):
            cmd = hp.build_httpx_command("/tmp/t.txt", "/tmp/o.json", {})
        cmd = cmd[0] if isinstance(cmd, tuple) else cmd
        self.assertNotIn("-r", cmd)


if __name__ == "__main__":
    unittest.main()
