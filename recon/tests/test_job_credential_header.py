"""
Every call a recon container makes back to the webapp or the agent sends its job
credential (step 1.16, experiment E7).

The webapp's scanner-key routes and the agent's /llm/* and /jev/* now accept the scanner
key only together with X-Redamon-Job, the credential the webapp minted for this scan and
the orchestrator put in the environment as REDAMON_JOB_CREDENTIAL. A call that forgets it
gets 403, which recon reads as "no settings" or "no AI answer": the scan would carry on
silently degraded. So each E7 caller is driven here, and a guard keeps any new caller
from building its own headers.
"""
import ast
import os
import unittest
from pathlib import Path
from unittest import mock

import pytest

RECON = Path(__file__).resolve().parents[1]
ENV = {"SCANNER_API_KEY": "scanner-test-key", "REDAMON_JOB_CREDENTIAL": "job.credential",
       "WEBAPP_API_URL": "http://webapp:3000", "PROJECT_ID": "proj-1", "USER_ID": "owner-1",
       "AGENT_API_URL": "http://agent:8080"}
WANT = {"X-Internal-Key": "scanner-test-key", "X-Redamon-Job": "job.credential"}


def _response(payload):
    resp = mock.Mock(status_code=200, ok=True)
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


def _sent(call) -> dict:
    return call.kwargs.get("headers") or {}


class ScanAuthHeaders(unittest.TestCase):
    def test_the_scanner_key_and_the_credential(self):
        from recon.helpers.scan_auth import scan_auth_headers
        with mock.patch.dict(os.environ, ENV, clear=True):
            self.assertEqual(scan_auth_headers(), WANT)

    def test_no_credential_no_header(self):
        """A CLI run outside a scan container has none: it sends the key it has."""
        from recon.helpers.scan_auth import scan_auth_headers
        with mock.patch.dict(os.environ, {"SCANNER_API_KEY": "k"}, clear=True):
            self.assertEqual(scan_auth_headers(), {"X-Internal-Key": "k"})

    def test_the_agent_hooks_send_it(self):
        from recon.helpers.ai_planner import internal_key_headers
        with mock.patch.dict(os.environ, ENV, clear=True):
            self.assertEqual(internal_key_headers(), WANT)


class EveryE7CallerSendsTheHeader(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, ENV, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def test_project_settings_fetch(self):
        from recon import project_settings as ps
        with mock.patch("requests.get", return_value=_response({"userId": "owner-1"})) as get:
            try:
                ps.fetch_project_settings("proj-1", "http://webapp:3000")
            except Exception:  # noqa: BLE001 - only the request it made matters here
                pass
        self.assertTrue(get.call_args_list)
        self.assertEqual(_sent(get.call_args_list[0]), WANT)

    def test_user_settings_fetches(self):
        from recon import project_settings as ps
        with mock.patch("requests.get", return_value=_response({"shodanApiKey": "x"})) as get:
            ps._fetch_user_api_key("owner-1", "http://webapp:3000", "shodanApiKey")
            ps._fetch_user_settings_full("owner-1", "http://webapp:3000")
        self.assertEqual(get.call_count, 2)
        for call in get.call_args_list:
            self.assertEqual(_sent(call), WANT)

    def test_node_filter_sweep_fetch(self):
        from recon import project_settings as ps
        with mock.patch("requests.get", return_value=_response({"nodeFilter": None})) as get:
            ps.fetch_node_filters("proj-1", "http://webapp:3000")
        self.assertEqual(_sent(get.call_args), WANT)

    def test_traffic_ingest(self):
        from recon.helpers import traffic_capture as tc
        entry = {"url": "http://app.example.test/", "status_code": 200, "headers": {}, "body": "hi"}
        with mock.patch("requests.post", return_value=_response({"stored": 1})) as post:
            tc.capture_httpx_transactions({"by_url": {entry["url"]: entry}}, {"CAPTURE_PROXY_ENABLED": True})
        self.assertEqual(post.call_count, 1)
        self.assertEqual(_sent(post.call_args), {**WANT, "Content-Type": "application/json"})


def _calls_with_a_literal_internal_key_header(path: Path):
    """Dict literals that spell out an X-Internal-Key header themselves."""
    tree = ast.parse(path.read_text())
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.lower() == "x-internal-key":
                    hits.append(f"{path.relative_to(RECON.parent)}:{node.lineno}")
    return hits


def test_no_recon_module_builds_its_own_scanner_headers():
    """The next caller of the webapp or the agent goes through scan_auth_headers, or the
    credential is forgotten and the call 403s in production only."""
    offenders = []
    for path in sorted(RECON.rglob("*.py")):
        rel = path.relative_to(RECON)
        if rel.parts[0] in ("tests", "output", "data") or path.name == "scan_auth.py":
            continue
        offenders += _calls_with_a_literal_internal_key_header(path)
    assert offenders == []


@pytest.mark.parametrize("module", ["ffuf_extensions", "nuclei_tags", "waf_classifier",
                                    "nuclei_response_filter", "takeover_classifier", "jev_shadow"])
def test_every_agent_hook_uses_the_shared_headers(module):
    text = (RECON / "helpers" / "ai_planner" / f"{module}.py").read_text()
    assert "headers=internal_key_headers()" in text
