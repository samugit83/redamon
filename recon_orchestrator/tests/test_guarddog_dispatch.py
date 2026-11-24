"""L3 GuardDog one-shot dispatch (container_manager.run_guarddog_package).

The agent's execute_guarddog reaches the orchestrator here. GuardDog downloads an
attacker-authored tarball, so this is the SECURITY GATE at the privileged layer:
ecosystem allowlist + package/version charset, enforced before any docker call,
and the container spawned with the hardened, secret-free flags.

These build a ContainerManager without __init__ (no docker.from_env) and stub
self.client, so nothing real is spawned.

Run: docker exec redamon-recon-orchestrator sh -c 'cd /app && python -m unittest tests.test_guarddog_dispatch -v'
"""

import json
import unittest
from unittest import mock

from container_manager import ContainerManager


def _mgr(client):
    m = ContainerManager.__new__(ContainerManager)
    m.client = client
    m.supply_chain_analyzer_image = "redamon-supply-chain-analyzer:latest"
    m.supply_chain_analyzer_network = "redamon-supply-chain-net"
    m.supply_chain_analyzer_mem = "1500m"
    m.supply_chain_analyzer_nanocpus = 2_000_000_000
    m.supply_chain_analyzer_pids = 512
    # Neutralise helpers that read the governor / network. The analyzer is sized
    # from the TOOL envelope (see tests.test_supply_chain_admission); stubbed
    # here so these input-gate tests stay independent of host RAM.
    m._container_mem_limit = lambda *_a, **_k: None
    m._tool_container_mem_limit = lambda *_a, **_k: None
    m._container_cpu_limit = lambda *_a, **_k: None
    m._ensure_supply_chain_network = lambda: None
    return m


class _FakeContainer:
    def __init__(self, logs=b"{}"):
        self._logs = logs
        self.removed = False

    def wait(self, timeout=None):
        return {"StatusCode": 0}

    def logs(self, stdout=True, stderr=False):
        # stderr must be excluded so GuardDog's progress noise never corrupts JSON.
        return self._logs if stdout and not stderr else b"progress noise"

    def remove(self, force=False, v=False):
        self.removed = True


class InputGateTests(unittest.TestCase):
    def test_unsupported_ecosystem_never_touches_docker(self):
        client = mock.MagicMock()
        out = _mgr(client).run_guarddog_package("cargoX", "left-pad")
        self.assertIn("unsupported ecosystem", out["error"])
        client.containers.run.assert_not_called()

    def test_hostile_name_rejected_before_docker(self):
        client = mock.MagicMock()
        out = _mgr(client).run_guarddog_package("npm", "evil; rm -rf /")
        self.assertIn("charset", out["error"])
        client.containers.run.assert_not_called()

    def test_hostile_version_rejected(self):
        client = mock.MagicMock()
        out = _mgr(client).run_guarddog_package("npm", "evil", "1.0.0$(id)")
        self.assertIn("charset", out["error"])
        client.containers.run.assert_not_called()

    def test_leading_dash_name_rejected(self):
        # "--help" would reach guarddog argv as a flag; the gate forbids a
        # leading '-'.
        client = mock.MagicMock()
        out = _mgr(client).run_guarddog_package("npm", "--help")
        self.assertIn("charset", out["error"])
        client.containers.run.assert_not_called()

    def test_leading_dash_version_rejected(self):
        client = mock.MagicMock()
        out = _mgr(client).run_guarddog_package("npm", "lodash", "-rf")
        self.assertIn("charset", out["error"])
        client.containers.run.assert_not_called()

    def test_scoped_npm_name_accepted(self):
        client = mock.MagicMock()
        client.containers.run.return_value = _FakeContainer(logs=b'{"issues":0}')
        out = _mgr(client).run_guarddog_package("npm", "@angular/core", "12.0.0")
        self.assertIsNone(out["error"])
        client.containers.run.assert_called_once()


class DispatchTests(unittest.TestCase):
    def _run_with(self, logs):
        client = mock.MagicMock()
        cont = _FakeContainer(logs=logs)
        client.containers.run.return_value = cont
        out = _mgr(client).run_guarddog_package("npm", "event-stream", "3.3.6")
        return out, client, cont

    def test_hardened_flags_and_argv(self):
        raw = json.dumps({"issues": 2, "errors": {},
                          "results": {"typosquatting": "x", "clean-rule": []}}).encode()
        out, client, cont = self._run_with(raw)
        _, kwargs = client.containers.run.call_args
        self.assertEqual(kwargs["cap_drop"], ["ALL"])
        self.assertTrue(kwargs["read_only"])
        self.assertEqual(kwargs["entrypoint"], "guarddog")
        # ZERO secrets in the analyzer env: a full RCE in here finds no cred.
        env_blob = json.dumps(kwargs.get("environment", {}))
        for secret in ("NEO4J", "INTERNAL_API_KEY", "GITHUB", "API_KEY", "PASSWORD"):
            self.assertNotIn(secret, env_blob)
        self.assertEqual(kwargs["command"],
                         ["npm", "scan", "event-stream", "--no-sandbox",
                          "--output-format", "json", "--version", "3.3.6"])
        # only rules whose value is truthy are "fired"
        self.assertEqual(out["issues"], 2)
        self.assertEqual(out["rules_fired"], ["typosquatting"])
        self.assertIsNone(out["error"])
        self.assertTrue(cont.removed, "the ephemeral container must be removed")

    def test_non_json_output_is_an_error_not_a_false_clean(self):
        out, _c, _ = self._run_with(b"Traceback: guarddog blew up")
        self.assertIn("non-JSON", out["error"])
        self.assertEqual(out["issues"], 0)

    def test_version_omitted_when_absent(self):
        client = mock.MagicMock()
        client.containers.run.return_value = _FakeContainer(logs=b'{"issues":0}')
        _mgr(client).run_guarddog_package("pypi", "requests")
        _, kwargs = client.containers.run.call_args
        self.assertNotIn("--version", kwargs["command"])

    def test_spawn_failure_returns_error_and_no_false_clean(self):
        client = mock.MagicMock()
        client.containers.run.side_effect = RuntimeError("daemon down")
        out = _mgr(client).run_guarddog_package("npm", "evil")
        self.assertIn("dispatch failed", out["error"])
        self.assertEqual(out["issues"], 0)


if __name__ == "__main__":
    unittest.main()
