"""ZoomEye keys a Port on its transport protocol, the way naabu does (S-14).

Netlas used to key its Port on the application protocol (`https`), so naabu's
Port {443, tcp} and Netlas's Port {443, https} were two nodes for one socket
(L-4, 99772a32). ZoomEye's parser keeps `portinfo.protocol` as the row's
protocol and the writer MERGEs the Port on it. In the two host-search shapes
known here, the repo fixture's (tests/test_zoomeye_enrich.py) and the v1 one
with a protocol object at the match root, the application protocol is
`portinfo.service` (or `protocol.application`), never `portinfo.protocol`, so
the row is `tcp` and the Port is naabu's. This pins that, from the parsed API
body to the Cypher the writer sends. No live ZoomEye answer was checked: a body
that put `http` in portinfo.protocol would still be keyed on it.

requests.get is mocked and a fake session records the Cypher; synthetic
values only.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402
from recon.main_recon_modules import zoomeye_enrich as ze  # noqa: E402

IP = "192.0.2.44"

# The repo fixture's shape (tests/test_zoomeye_enrich.py): transport in portinfo.
FIXTURE_MATCH = {
    "ip": IP, "hostname": "www.example.test",
    "portinfo": {"port": 443, "protocol": "tcp", "service": "https", "app": "nginx",
                 "version": "1.24.0", "banner": "HTTP/1.1 200 OK"},
    "geoinfo": {"country": {"names": {"en": "Testland"}}},
}
# The host-search shape with the protocol object at the match root and no
# portinfo.protocol.
ROOT_PROTOCOL_MATCH = {
    "ip": IP, "hostname": "www.example.test",
    "portinfo": {"port": 443, "service": "https", "app": "nginx", "version": "1.24.0",
                 "banner": "HTTP/1.1 200 OK"},
    "protocol": {"application": "HTTPS", "probe": "GET", "transport": "tcp"},
    "geoinfo": {"country": {"names": {"en": "Testland"}}},
}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((" ".join(query.split()), params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _parse(match: dict) -> dict:
    resp = MagicMock(status_code=200, text="", headers={})
    resp.json.return_value = {"total": 1, "matches": [match]}
    combined = {"domain": "example.test", "metadata": {"ip_mode": False, "modules_executed": []},
                "dns": {"domain": {"ips": {"ipv4": [IP]}}, "subdomains": {}}}
    settings = {"ZOOMEYE_ENABLED": True, "ZOOMEYE_API_KEY": "ze-test-key",
                "ZOOMEYE_KEY_ROTATOR": None, "ZOOMEYE_MAX_RESULTS": 1}
    with patch.object(ze.requests, "get", return_value=resp), patch.object(ze.time, "sleep"):
        return ze.run_zoomeye_enrichment(combined, settings)


def _port_writes(writer) -> list:
    return [p for q, p in writer.session.calls if q.startswith("MERGE (p:Port")]


class ZoomEyePortProtocol(unittest.TestCase):
    def _check(self, match):
        out = _parse(match)
        [row] = out["zoomeye"]["results"]
        self.assertEqual(row["protocol"], "tcp")
        self.assertEqual(row["service"], "https")

        w = _Writer()
        w.update_graph_from_zoomeye(out, "u1", "p1")
        [port] = _port_writes(w)
        self.assertEqual((port["port"], port["protocol"], port["ip"]), (443, "tcp", IP))
        services = [p for q, p in w.session.calls if q.startswith("MERGE (svc:Service")]
        self.assertEqual([s["protocol"] for s in services], ["tcp"],
                         "the Service is attached through a Port keyed on another protocol")

    def test_fixture_shape_keys_the_port_on_tcp(self):
        self._check(FIXTURE_MATCH)

    def test_root_protocol_object_keys_the_port_on_tcp(self):
        self._check(ROOT_PROTOCOL_MATCH)


if __name__ == "__main__":
    unittest.main()
