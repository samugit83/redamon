"""Passive OSINT writers never overwrite a Subdomain's or a Service's status
and provenance that another writer set (audit L-2, sibling of plan 04.3).

Censys reverse DNS and OTX passive DNS ran a plain `SET s.status =
'unverified'` on a Subdomain DNS had already written as `resolved` (or
http_probe as an HTTP code); FOFA did the same with `s.source`. http_probe
demotes a host it got no answer from only `WHERE s.status = 'resolved'`, so a
flipped host never became `no_http`. Censys, FOFA, Netlas, ZoomEye and
CriminalIP likewise overwrote `Service.source` on a Service the port scan or
another provider had made. Status and provenance are first-writer fields: set
on create only.

Fake Neo4j sessions: these read which properties each statement writes when
the node already exists. tests/test_osint_owner_fields_graph_live.py proves the
same on a real database.
"""

import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402

IP = "198.51.100.50"
HOST = "www.example.com"

_CLAUSE = re.compile(
    r"^(ON CREATE SET|ON MATCH SET|SET|MERGE|MATCH|OPTIONAL MATCH|WITH|WHERE|RETURN|"
    r"UNWIND|DELETE|DETACH DELETE|REMOVE|CALL|FOREACH|CREATE)\b")


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _writes(query: str, params: dict, var: str) -> dict:
    """{'create': props, 'match': props} that `var` gets on create / on an existing node.

    A plain SET runs in both cases; `var.p = coalesce(var.p, ...)` keeps a
    value already there, so it is not an overwrite.
    """
    out = {"create": set(), "match": set()}
    modes: tuple = ()
    for raw in query.split("\n"):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        m = _CLAUSE.match(line)
        if m:
            kw = m.group(1)
            modes = {"ON CREATE SET": ("create",), "ON MATCH SET": ("match",),
                     "SET": ("create", "match")}.get(kw, ())
        for mode in modes:
            for prop, rhs in re.findall(rf"\b{var}\.(\w+)\s*=\s*([^,]*)", line):
                if mode == "match" and rhs.startswith(f"coalesce({var}.{prop},"):
                    continue
                out[mode].add(prop)
            for pname in re.findall(rf"\b{var}\s*\+=\s*\$(\w+)", line):
                out[mode].update((params.get(pname) or {}).keys())
    return out


def _merges(w: _Writer, label: str, var: str) -> list:
    return [(q, p) for q, p in w.session.calls if f"MERGE ({var}:{label} " in q]


def _recon(key, payload):
    return {"domain": "example.com", "domains": ["example.com"], key: payload}


SUBDOMAIN_WRITERS = {
    "censys": ("update_graph_from_censys", "censys_rdns",
               {"hosts": [{"ip": IP, "reverse_dns_names": [HOST]}]}),
    "otx": ("update_graph_from_otx", "otx_passive_dns",
            {"ip_reports": [{"ip": IP, "passive_dns": [{"hostname": HOST, "record_type": "A"}]}]}),
    "fofa": ("update_graph_from_fofa", "fofa",
             {"results": [{"ip": IP, "port": 443, "host": f"{HOST}:443"}]}),
}

SERVICE_WRITERS = {
    "censys": ("update_graph_from_censys",
               {"hosts": [{"ip": IP, "services": [{"port": 22, "service_name": "SSH",
                                                   "banner": "SSH-2.0-OpenSSH_8.9"}]}]}),
    "fofa": ("update_graph_from_fofa",
             {"results": [{"ip": IP, "port": 22, "protocol": "ssh", "server": "OpenSSH"}]}),
    "netlas": ("update_graph_from_netlas",
               {"results": [{"ip": IP, "port": 22, "protocol": "ssh",
                             "banner": "SSH-2.0-OpenSSH_8.9"}]}),
    "zoomeye": ("update_graph_from_zoomeye",
                {"results": [{"ip": IP, "port": 22, "app": "OpenSSH", "version": "8.9"}]}),
    "criminalip": ("update_graph_from_criminalip",
                   {"ip_reports": [{"ip": IP, "ports": [{"port": 22, "app_name": "OpenSSH",
                                                         "app_version": "8.9"}]}]}),
}


class TestSubdomainStatusAndSourceAreFirstWriter(unittest.TestCase):
    def _subdomain_writes(self, source):
        method, _, payload = SUBDOMAIN_WRITERS[source]
        w = _Writer()
        getattr(w, method)(_recon(source, payload), "u1", "p1")
        merges = [(q, p) for q, p in _merges(w, "Subdomain", "s") if p.get("name") == HOST]
        self.assertEqual(len(merges), 1, (source, w.session.calls))
        return _writes(*merges[0], "s")

    def test_an_existing_subdomain_keeps_its_status_and_source(self):
        # DNS wrote `resolved` (http_probe later an HTTP code) and the discovery
        # source: a passive sighting of the same name changes neither.
        for source in SUBDOMAIN_WRITERS:
            with self.subTest(source=source):
                on_match = self._subdomain_writes(source)["match"]
                self.assertNotIn("status", on_match)
                self.assertNotIn("source", on_match)

    def test_a_new_subdomain_is_unverified_and_names_its_source(self):
        for source, (method, expected_source, payload) in SUBDOMAIN_WRITERS.items():
            with self.subTest(source=source):
                w = _Writer()
                getattr(w, method)(_recon(source, payload), "u1", "p1")
                q, _ = next((q, p) for q, p in _merges(w, "Subdomain", "s")
                            if p.get("name") == HOST)
                on_create = q.split("ON CREATE SET", 1)[1]
                self.assertIn("s.status = 'unverified'", on_create)
                self.assertIn(f"s.source = '{expected_source}'", on_create)

    def test_updated_at_still_moves_on_every_run(self):
        for source in SUBDOMAIN_WRITERS:
            with self.subTest(source=source):
                self.assertIn("updated_at", self._subdomain_writes(source)["match"])


class TestServiceSourceIsFirstWriter(unittest.TestCase):
    def _service_writes(self, source):
        method, payload = SERVICE_WRITERS[source]
        w = _Writer()
        getattr(w, method)(_recon(source, payload), "u1", "p1")
        merges = _merges(w, "Service", "svc")
        self.assertEqual(len(merges), 1, (source, w.session.calls))
        return _writes(*merges[0], "svc")

    def test_an_existing_service_keeps_its_source(self):
        # A Service the port scan, Shodan or another provider made is not
        # re-attributed to whichever passive provider wrote it last.
        for source in SERVICE_WRITERS:
            with self.subTest(source=source):
                self.assertNotIn("source", self._service_writes(source)["match"])

    def test_a_new_service_names_its_provider(self):
        for source in SERVICE_WRITERS:
            with self.subTest(source=source):
                method, payload = SERVICE_WRITERS[source]
                w = _Writer()
                getattr(w, method)(_recon(source, payload), "u1", "p1")
                q, p = _merges(w, "Service", "svc")[0]
                on_create = q.split("ON CREATE SET", 1)[1].split("\n", 1)[0]
                self.assertIn(f"svc.source = '{source}'", on_create)
                self.assertIn("source", self._service_writes(source)["create"])

    def test_the_providers_own_fields_still_refresh(self):
        # Banner, version and title are the provider's own enrichment: a re-run
        # still updates them on the existing node.
        expected = {"censys": "banner", "fofa": "app_protocol", "netlas": "banner",
                    "zoomeye": "version", "criminalip": "version"}
        for source, prop in expected.items():
            with self.subTest(source=source):
                self.assertIn(prop, self._service_writes(source)["match"])


if __name__ == "__main__":
    unittest.main()
