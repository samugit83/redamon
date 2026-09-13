"""A PTR-less bare IP must still produce ports, services and graph inputs.

naabu omits the "host" field entirely when the scanned target was a bare IP with
no reverse DNS. `by_host` is the ONLY source of Port and Service nodes
(`port_mixin` reads `by_ip` for CDN fields alone), so such a scan used to yield
an IP node with no ports hanging off it at all, and the summary reported
`hosts_with_open_ports: 0` while `unique_ports` listed the ports it had just
found.

Everything keyed on a port then had nothing to attach to: Service creation, the
IANA service label, tlsx's `tls_service_hint`, and the partial-recon input list
that reads Port nodes out of the graph.

Found by running the real pipeline against testing/guinea_pigs/tls_target, whose
192.88.98.10 has no PTR record on purpose.

Run: python -m pytest recon/tests/test_port_scan_bare_ip.py
"""

import json
import os
import sys
import tempfile
import unittest

_RECON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.dirname(_RECON)
for _p in (_REPO, _RECON):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _parse(lines):
    from recon.main_recon_modules.port_scan import parse_naabu_output
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")
        path = fh.name
    try:
        return parse_naabu_output(path, settings={})
    finally:
        os.unlink(path)


# What naabu actually emits for `-host 192.88.98.10 -p 993,636`: no "host" key.
_BARE_IP = [
    {"ip": "192.88.98.10", "port": 993},
    {"ip": "192.88.98.10", "port": 636},
]

# With a PTR record naabu fills "host" and this always worked.
_WITH_PTR = [
    {"host": "mail.tlslab.test", "ip": "192.88.98.10", "port": 993},
    {"host": "mail.tlslab.test", "ip": "192.88.98.10", "port": 636},
]


class BareIpWithNoReverseDns(unittest.TestCase):
    def test_ports_are_reachable_under_by_host_keyed_by_the_ip(self):
        res = _parse(_BARE_IP)
        self.assertIn("192.88.98.10", res["by_host"],
                      "by_host is empty, so no Port or Service node can be created")
        self.assertEqual(sorted(res["by_host"]["192.88.98.10"]["ports"]), [636, 993])

    def test_each_port_carries_its_protocol_and_iana_service_label(self):
        """port_mixin creates a Service node only when port_details has a
        service name, and tlsx then MATCHes that Service to add tls_service_hint."""
        res = _parse(_BARE_IP)
        details = {d["port"]: d for d in res["by_host"]["192.88.98.10"]["port_details"]}
        self.assertEqual(sorted(details), [636, 993])
        for port in (636, 993):
            self.assertEqual(details[port]["protocol"], "tcp")
            self.assertTrue(details[port].get("service"),
                            f"port {port} has no service label, so no Service node")

    def test_the_entry_still_records_the_ip_so_has_port_can_be_linked(self):
        res = _parse(_BARE_IP)
        self.assertEqual(res["by_host"]["192.88.98.10"]["ip"], "192.88.98.10")

    def test_the_summary_no_longer_contradicts_itself(self):
        res = _parse(_BARE_IP)
        summary = res["summary"]
        self.assertEqual(sorted(summary["unique_ports"]), [636, 993])
        self.assertEqual(summary["hosts_with_open_ports"], 1,
                         "reported 0 hosts with open ports while listing 2 open ports")
        self.assertEqual(summary["total_open_ports"], 2)

    def test_the_ip_is_not_smuggled_into_the_hostname_list(self):
        """by_ip[...]["hostnames"] is read as REAL hostnames (SNI, cert subject
        matching, httpx vhosts). An IP there would be probed as a vhost name."""
        res = _parse(_BARE_IP)
        self.assertEqual(res["by_ip"]["192.88.98.10"]["hostnames"], [])

    def test_by_ip_still_carries_the_ports(self):
        res = _parse(_BARE_IP)
        self.assertEqual(sorted(res["by_ip"]["192.88.98.10"]["ports"]), [636, 993])


class AHostnameTargetIsUnaffected(unittest.TestCase):
    def test_a_ptr_backed_host_is_still_keyed_by_its_hostname(self):
        res = _parse(_WITH_PTR)
        self.assertIn("mail.tlslab.test", res["by_host"])
        self.assertNotIn("192.88.98.10", res["by_host"],
                         "the IP must not shadow a real hostname entry")

    def test_a_real_hostname_still_reaches_the_hostname_list(self):
        res = _parse(_WITH_PTR)
        self.assertEqual(res["by_ip"]["192.88.98.10"]["hostnames"], ["mail.tlslab.test"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
