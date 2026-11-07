"""naabu 2.6 writes no "host": the run's names take their address's ports.

Found by the urlscan lab: every lab site shares one address, naabu answered
{"ip": ..., "port": ...} with no host even for hostname targets, by_host held
the bare addresses only, and httpx (which builds its targets from by_host)
probed no virtual host at all. Masscan's parser already fans out through
ip_to_hostnames; naabu's now does the same, for names the run asked about only.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules.port_scan import parse_naabu_output  # noqa: E402

LINES = [{"ip": "192.88.97.10", "port": 80, "protocol": "tcp"},
         {"ip": "192.88.97.10", "port": 443, "protocol": "tcp"},
         {"ip": "192.88.97.40", "port": 443, "protocol": "tcp"}]


def _parse(lines, ip_to_hostnames=None):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(json.dumps(x) for x in lines))
    return parse_naabu_output(f.name, settings={}, ip_to_hostnames=ip_to_hostnames)


class TestFanOut(unittest.TestCase):
    def test_every_name_of_an_address_takes_its_ports(self):
        out = _parse(LINES, {"192.88.97.10": ["app.example.test", "files.example.test"],
                             "192.88.97.40": ["www.example.test"]})
        by_host = out["by_host"]
        self.assertEqual(by_host["app.example.test"]["ports"], [80, 443])
        self.assertEqual(by_host["files.example.test"]["ip"], "192.88.97.10")
        self.assertEqual([d["port"] for d in by_host["www.example.test"]["port_details"]], [443])
        self.assertIn("192.88.97.10", by_host)           # the bare address stays
        self.assertEqual(sorted(out["by_ip"]["192.88.97.10"]["hostnames"]),
                         ["app.example.test", "files.example.test"])

    def test_httpx_now_gets_the_virtual_hosts(self):
        from recon.main_recon_modules.http_probe import build_targets_from_naabu
        out = _parse(LINES, {"192.88.97.10": ["app.example.test"]})
        urls = build_targets_from_naabu({"port_scan": out}, {})
        self.assertIn("https://app.example.test", urls)
        self.assertIn("http://app.example.test", urls)

    def test_no_mapping_no_invented_names_and_a_reported_host_wins(self):
        self.assertEqual(sorted(_parse(LINES)["by_host"]), ["192.88.97.10", "192.88.97.40"])
        named = _parse([{"host": "app.example.test", "ip": "192.88.97.10", "port": 8443}],
                       {"192.88.97.10": ["app.example.test"]})
        self.assertEqual(named["by_host"]["app.example.test"]["ports"], [8443])
        self.assertNotIn("x.example.test", _parse(LINES, {"192.88.97.99": ["x.example.test"]})["by_host"])

    def test_the_pipeline_passes_the_mapping(self):
        src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "port_scan.py").read_text()
        self.assertIn("ip_to_hostnames=ip_to_hostnames)", src)


if __name__ == "__main__":
    unittest.main()
