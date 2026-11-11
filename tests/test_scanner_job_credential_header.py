"""
The GVM, GitHub hunt and supply-chain containers send their job credential on every
call back to the webapp (step 1.16, experiment E7).

The webapp reads a project, or its owner's settings, for the scanner key only beside the
job credential of a scan of that project (X-Redamon-Job), which the orchestrator puts in
the container's environment as REDAMON_JOB_CREDENTIAL. A fetch that forgets it gets 403,
and each of these scanners then runs on its defaults: the GVM case of issue #174 again.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from github_secret_hunt import project_settings as hunt_settings  # noqa: E402
from gvm_scan import project_settings as gvm_settings  # noqa: E402
from supply_chain_scan import project_settings as supply_settings  # noqa: E402

ENV = {"SCANNER_API_KEY": "scanner-test-key", "REDAMON_JOB_CREDENTIAL": "job.credential",
       "INTERNAL_API_KEY": "master-test-key", "USER_ID": "owner-1"}
WANT = {"X-Internal-Key": "scanner-test-key", "X-Redamon-Job": "job.credential"}


def _json_response(payload):
    resp = mock.Mock(status_code=200, ok=True)
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


class EveryScannerFetchSendsTheCredential(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, ENV, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def _assert_every_call(self, get, at_least):
        self.assertGreaterEqual(get.call_count, at_least)
        for call in get.call_args_list:
            self.assertEqual(call.kwargs["headers"], WANT)

    def test_gvm(self):
        with mock.patch("requests.get", return_value=_json_response({})) as get:
            gvm_settings.fetch_gvm_settings("proj-1", "http://webapp:3000")
        self._assert_every_call(get, 1)

    def test_github_hunt_project_and_owner_settings(self):
        with mock.patch("requests.get", return_value=_json_response({})) as get:
            hunt_settings.fetch_github_settings("proj-1", "http://webapp:3000")
        self._assert_every_call(get, 2)

    def test_supply_chain_project_and_owner_settings(self):
        project = {"supplyChainInputMode": "github", "supplyChainRepoUrl": "https://github.com/acme/app"}
        with mock.patch("requests.get", return_value=_json_response(project)) as get:
            supply_settings.fetch_supply_chain_settings("proj-1", "http://webapp:3000")
        self._assert_every_call(get, 2)

    def test_never_the_master_key_inside_a_scan(self):
        """A container has the scanner key; the master key in the env must not win."""
        for module, fetch in ((gvm_settings, "fetch_gvm_settings"), (hunt_settings, "fetch_github_settings"),
                              (supply_settings, "fetch_supply_chain_settings")):
            with self.subTest(module=module.__name__), \
                    mock.patch("requests.get", return_value=_json_response({})) as get:
                getattr(module, fetch)("proj-1", "http://webapp:3000")
                for call in get.call_args_list:
                    self.assertNotEqual(call.kwargs["headers"]["X-Internal-Key"], "master-test-key")

    def test_without_a_credential_no_header_is_invented(self):
        os.environ.pop("REDAMON_JOB_CREDENTIAL")
        with mock.patch("requests.get", return_value=_json_response({})) as get:
            gvm_settings.fetch_gvm_settings("proj-1", "http://webapp:3000")
        self.assertEqual(get.call_args.kwargs["headers"], {"X-Internal-Key": "scanner-test-key"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
