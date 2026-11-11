"""A passive port listing with no version or banner keeps the Service's (S-15).

CriminalIP ran a plain `SET svc.version = $version, svc.banner = $banner` on a
Service MERGEd by (name, port, ip). It lists many ports with an app name and
no version or banner, and a null SET removes the property, so the version nmap
measured and the banner Censys or ZoomEye stored on the same Service were
deleted. ZoomEye shares the Service key and writes `svc += $props` with only
the values it has.

Fake Neo4j session: the Service statement each writer sends is applied to an
existing node by a small model of the SET forms these writers use, so an
unknown form fails instead of passing. tests/test_criminalip_service_null_graph_live.py
proves the same on a real database.
"""

import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402

IP = "198.51.100.61"
MEASURED = {"version": "8.9p1", "banner": "SSH-2.0-OpenSSH_8.9p1", "source": "nmap"}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return MagicMock()


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _service_statement(w: _Writer):
    stmts = [(q, p) for q, p in w.session.calls if "MERGE (svc:Service " in q]
    assert len(stmts) == 1, w.session.calls
    return stmts[0]


def _apply_to_existing(query: str, params: dict, node: dict) -> dict:
    """The properties an existing Service ends with after the statement's SET clauses.

    Models `svc.p = $x`, `svc.p = coalesce($x, svc.p)`, `svc += $map` and
    `svc.p = datetime()`, with Cypher's rule that SET to null removes the key.
    ON CREATE SET is skipped: the node exists.
    """
    node = dict(node)
    in_set = False
    for raw in query.split("\n"):
        line = raw.strip()
        if line.startswith("ON CREATE SET"):
            in_set = False
            continue
        if line.startswith("SET "):
            in_set = True
            line = line[4:]
        elif re.match(r"^(WITH|MATCH|MERGE|RETURN|WHERE)\b", line):
            in_set = False
        if not in_set:
            continue
        for pname in re.findall(r"\bsvc\s*\+=\s*\$(\w+)", line):
            for k, v in (params[pname] or {}).items():
                if v is None:
                    node.pop(k, None)
                else:
                    node[k] = v
        for prop, rhs in re.findall(r"\bsvc\.(\w+)\s*=\s*([^,(]+(?:\([^)]*\))?)", line):
            rhs = rhs.strip()
            if rhs == "datetime()":
                continue
            m = re.fullmatch(r"\$(\w+)", rhs)
            c = re.fullmatch(rf"coalesce\(\$(\w+),\s*svc\.{prop}\)", rhs)
            if m:
                value = params[m.group(1)]
            elif c:
                value = params[c.group(1)]
                value = node.get(prop) if value is None else value
            else:
                raise AssertionError(f"unmodelled SET form: svc.{prop} = {rhs}")
            if value is None:
                node.pop(prop, None)
            else:
                node[prop] = value
    return node


def _recon(key, payload):
    return {"domain": "example.test", "domains": ["example.test"], key: payload}


def _criminalip(port: dict) -> tuple:
    w = _Writer()
    stats = w.update_graph_from_criminalip(
        _recon("criminalip", {"ip_reports": [{"ip": IP, "ports": [port]}]}), "u1", "p1")
    assert stats["errors"] == [], stats["errors"]
    return _service_statement(w)


def _zoomeye(row: dict) -> tuple:
    w = _Writer()
    stats = w.update_graph_from_zoomeye(_recon("zoomeye", {"results": [row]}), "u1", "p1")
    assert stats["errors"] == [], stats["errors"]
    return _service_statement(w)


class TestCriminalIpServiceWrite(unittest.TestCase):
    def test_a_bare_listing_keeps_the_measured_version_and_banner(self):
        for bare in ({"app_version": None, "banner": None}, {}, {"app_version": "", "banner": ""},
                     {"app_version": "   "}):
            with self.subTest(bare=bare):
                q, p = _criminalip({"port": 22, "socket": "tcp", "app_name": "SSH", **bare})
                self.assertEqual(p["svc_name"], "ssh")
                self.assertIsNone(p["version"])
                self.assertIsNone(p["banner"])
                self.assertEqual(_apply_to_existing(q, p, MEASURED), MEASURED)

    def test_its_own_version_and_banner_still_refresh(self):
        q, p = _criminalip({"port": 22, "socket": "tcp", "app_name": "SSH",
                            "app_version": " 9.6 ", "banner": "SSH-2.0-OpenSSH_9.6"})
        self.assertEqual(_apply_to_existing(q, p, MEASURED),
                         {"version": "9.6", "banner": "SSH-2.0-OpenSSH_9.6", "source": "nmap"})

    def test_a_version_alone_leaves_the_banner(self):
        q, p = _criminalip({"port": 22, "app_name": "SSH", "app_version": "9.6"})
        self.assertEqual(_apply_to_existing(q, p, MEASURED),
                         {**MEASURED, "version": "9.6"})

    def test_the_banner_stays_capped(self):
        q, p = _criminalip({"port": 80, "app_name": "nginx", "banner": "X" * 600})
        self.assertEqual(len(_apply_to_existing(q, p, {})["banner"]), 500)


class TestZoomEyeServiceWrite(unittest.TestCase):
    # ZoomEye MERGEs the same Service key: it must not have the same wipe.
    def test_a_bare_row_keeps_the_measured_version_and_banner(self):
        q, p = _zoomeye({"ip": IP, "port": 22, "app": "ssh", "version": None, "banner": None})
        self.assertEqual(p["props"], {})
        self.assertEqual(_apply_to_existing(q, p, MEASURED), MEASURED)

    def test_its_own_version_still_refreshes(self):
        q, p = _zoomeye({"ip": IP, "port": 22, "app": "ssh", "version": "9.6"})
        self.assertEqual(_apply_to_existing(q, p, MEASURED), {**MEASURED, "version": "9.6"})


if __name__ == "__main__":
    unittest.main()
