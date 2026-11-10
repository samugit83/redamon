"""ip_api_exposed stores the same evidence on every run.

Its evidence ended in the control verdict's reason, which names the random
control path ("(/rdm-3f9a... answered 404, the hit 200)"). Each run draws a
new path, so the Recon Delta read every ip_api_exposed finding as changed. The
evidence now carries the verdict word only, as login_no_https does (L-21).

Addresses are RFC 5737 documentation addresses.
"""
from __future__ import annotations

from unittest import mock

import requests

from recon.helpers import catchall
from recon.helpers import security_checks as sc

V4 = "198.51.100.30"


def _resp(status, headers, text):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers
    r.text = text
    r.content = text.encode()
    r.history = []
    return r


API = _resp(200, {"Content-Type": "application/json"}, '{"service":"orders","version":"2.1"}')
NOT_FOUND = _resp(404, {"Content-Type": "text/html"}, "<h1>Not Found</h1>")


def _scan(control_answer):
    """One run: /api answers JSON, the control answers ``control_answer``
    (a response, or an exception to raise)."""
    def get(url, *a, **k):
        if f"/{catchall.CONTROL_PREFIX}" in url:
            if isinstance(control_answer, Exception):
                raise control_answer
            return control_answer
        return API if url.endswith("/api") else NOT_FOUND

    with mock.patch.object(sc.requests, "get", side_effect=get):
        return sc.check_ip_api_exposed(V4, timeout=1)


def _stored_values(finding):
    return [str(v) for v in finding.values()]


class TestTheEvidenceIsStableAcrossRuns:
    def test_two_runs_store_identical_findings(self):
        first, second = _scan(NOT_FOUND), _scan(NOT_FOUND)
        assert first == second
        assert first["evidence"] == ("API endpoint returned 200 with application/json; "
                                     "control_check: passed")
        assert first["control_check"] == "passed"

    def test_no_stored_property_names_the_control_path(self):
        finding = _scan(NOT_FOUND)
        assert not [v for v in _stored_values(finding) if catchall.CONTROL_PREFIX in v]

    def test_a_failed_control_is_stable_too(self):
        first = _scan(requests.ConnectionError("reset"))
        second = _scan(requests.ConnectionError("reset"))
        assert first == second
        assert first["control_check"] == "failed"
        assert first["evidence"] == ("API endpoint returned 200 with application/json; "
                                     "control_check: failed")
