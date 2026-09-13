"""Certificate props filter: an unobserved field must not overwrite a stored one.

Re-keying certificates on `cert_key` makes every scanner that sees the same
certificate converge on ONE node. Each writer does `SET c += $props`, so any
key present in `props` wins -- including a key whose value only means "I did
not observe this". `san` is the dangerous one: scope expansion, the shared-infra
clustering and the SAN backfill all read it, and a SAN-less observation used to
blank it out (H1).

The same filter must NOT drop `False`, or tlsx's hygiene flags vanish and every
truthiness check downstream silently reads "not expired / not self-signed".

The live tier proves which value survives in the database; this asserts the
props dict the writers hand to Cypher, so the gate catches a regression.

Run: python -m unittest tests.test_cert_props_filter
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())


class FakeResult:
    def single(self):
        return None

    def __iter__(self):
        return iter(())


class FakeSession:
    """Captures every (query, params) the writer issues."""

    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return FakeResult()

    def close(self):
        pass


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self, *a, **kw):
        return self._session


def _cert_props(session):
    """The props dict of the Certificate MERGE, whichever writer issued it."""
    for query, params in session.calls:
        if "MERGE (c:Certificate" in query and "props" in params:
            return params["props"]
        if "MERGE (c:Certificate" in query and "properties" in params:
            return params["properties"]
    raise AssertionError(
        "no Certificate MERGE was issued; queries: "
        + json.dumps([q.split("\n")[0].strip() for q, _ in session.calls]))


# --------------------------------------------------------------------------
# tlsx
# --------------------------------------------------------------------------
def _tlsx_payload(sans):
    from recon.main_recon_modules.tls_scan import _parse_tlsx_output
    line = json.dumps({
        "host": "mail.acme.test", "ip": "203.0.113.5", "port": "993",
        "probe_status": True, "tls_version": "tls13",
        "subject_cn": "mail.acme.test", "subject_an": sans,
        "issuer_cn": "R3", "issuer_dn": "CN=R3",
        "fingerprint_hash": {"sha256": "aabbccdd"},
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
    })
    by_target = _parse_tlsx_output(line, {"mail.acme.test:993": "203.0.113.5"})
    return {"domain": "acme.test", "tlsx": {"by_target": by_target}}


def _run_tlsx(sans):
    from graph_db.mixins.recon.tlsx_mixin import TlsxMixin
    session = FakeSession()
    client = TlsxMixin.__new__(TlsxMixin)
    client.driver = FakeDriver(session)
    client.update_graph_from_tlsx(_tlsx_payload(sans), "u1", "p1")
    return _cert_props(session)


class TlsxCertPropsFilter(unittest.TestCase):
    def test_a_san_less_observation_omits_san_instead_of_sending_an_empty_list(self):
        props = _run_tlsx([])
        self.assertNotIn(
            "san", props,
            "an empty SAN list is sent to Cypher and will erase stored SANs")

    def test_an_observed_san_list_is_still_sent(self):
        props = _run_tlsx(["mail.acme.test", "imap.acme.test"])
        self.assertEqual(props["san"], ["mail.acme.test", "imap.acme.test"])

    def test_false_hygiene_flags_survive_the_filter(self):
        props = _run_tlsx(["mail.acme.test"])
        for flag in ("expired", "self_signed", "mismatched", "revoked",
                     "untrusted", "wildcard"):
            self.assertIn(flag, props, f"{flag}=False was filtered out")
            self.assertIs(props[flag], False)


# --------------------------------------------------------------------------
# httpx
# --------------------------------------------------------------------------
def _run_httpx(cert_extra):
    from graph_db.mixins.recon.http_mixin import HttpMixin
    cert = {
        "subject_cn": "www.acme.test", "issuer": ["R3"],
        "fingerprint_sha256": "aabbccdd",
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
    }
    cert.update(cert_extra)
    recon = {"http_probe": {"by_url": {"https://www.acme.test": {
        "host": "www.acme.test", "ip": "203.0.113.5", "status_code": 200,
        "tls": {"version": "tls13", "certificate": cert},
    }}}}
    session = FakeSession()
    client = HttpMixin.__new__(HttpMixin)
    client.driver = FakeDriver(session)
    client.update_graph_from_http_probe(recon, "u1", "p1")
    return _cert_props(session)


class HttpxCertPropsFilter(unittest.TestCase):
    def test_a_cert_with_no_san_key_omits_san(self):
        """httpx reports certificates without a SAN list on hosts presenting a
        bare leaf. The writer defaults it to [], which must not be sent."""
        props = _run_httpx({})
        self.assertNotIn(
            "san", props,
            "httpx sends san=[] and erases SANs another source already stored")

    def test_an_explicitly_empty_san_list_is_also_omitted(self):
        props = _run_httpx({"san": []})
        self.assertNotIn("san", props)

    def test_an_observed_san_list_is_still_sent(self):
        props = _run_httpx({"san": ["www.acme.test", "acme.test"]})
        self.assertEqual(props["san"], ["www.acme.test", "acme.test"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
