"""D1 / S3-E6 — unit tests for the per-container resource ceilings and the
scoped-scanner-token env applied to every scan spawn.

Covers the four pure decision helpers added in the STRIDE D1 / S3-E6 wave:
  * _container_cpu_limit  — core-proportional nano_cpus, fraction + abs clamp,
    fail-open when governor off / fraction <= 0.
  * _container_pids_limit — fixed fork-bomb ceiling, env-overridable, fail-open.
  * _scanner_env          — scoped SCANNER_API_KEY; with it unset/placeholder no
    key at all, never the master key (NF-16, step 1.16).
  * _scanner_hardening    — cap_drop:[ALL] only when drop_caps=True.

None of these touch the docker client, so we build a ContainerManager without
running __init__ (avoids docker.from_env).

Run:  docker exec redamon-recon-orchestrator sh -c 'cd /app && python -m unittest tests.test_d1_resource_ceilings -v'
"""

import os
import unittest
from unittest import mock

import resource_governor as rg
from container_manager import ContainerManager


def _mgr() -> ContainerManager:
    # Skip __init__ (which calls docker.from_env); the helpers under test only
    # read os.environ and the resource_governor module.
    return ContainerManager.__new__(ContainerManager)


def _env(**kv):
    """Context manager: set/clear env vars for the duration of a test."""
    return mock.patch.dict(os.environ, {k: v for k, v in kv.items() if v is not None},
                           clear=False)


class TestCpuLimit(unittest.TestCase):
    def setUp(self):
        self.m = _mgr()

    def test_failopen_when_governor_disabled(self):
        with _env(REDAMON_MEM_GOVERNOR="false"):
            self.assertIsNone(self.m._container_cpu_limit())

    def test_failopen_when_fraction_nonpositive(self):
        with _env(REDAMON_MEM_GOVERNOR="true", CONTAINER_CPU_FRACTION="0"):
            self.assertIsNone(self.m._container_cpu_limit())
        with _env(REDAMON_MEM_GOVERNOR="true", CONTAINER_CPU_FRACTION="-2"):
            self.assertIsNone(self.m._container_cpu_limit())

    def test_core_proportional(self):
        with _env(REDAMON_MEM_GOVERNOR="true", CONTAINER_CPU_FRACTION="0.5"), \
             mock.patch.object(rg, "cpu_cores", return_value=8):
            os.environ.pop("PER_CONTAINER_CPUS", None)
            # 8 cores * 0.5 = 4.0 cpus -> 4e9 nano_cpus
            self.assertEqual(self.m._container_cpu_limit(), 4_000_000_000)

    def test_absolute_clamp_wins(self):
        with _env(REDAMON_MEM_GOVERNOR="true", CONTAINER_CPU_FRACTION="0.5",
                  PER_CONTAINER_CPUS="2"), \
             mock.patch.object(rg, "cpu_cores", return_value=32):
            # 32*0.5=16 cpus, clamped to PER_CONTAINER_CPUS=2 -> 2e9
            self.assertEqual(self.m._container_cpu_limit(), 2_000_000_000)

    def test_minimum_one_cpu_on_tiny_host(self):
        with _env(REDAMON_MEM_GOVERNOR="true", CONTAINER_CPU_FRACTION="0.1"), \
             mock.patch.object(rg, "cpu_cores", return_value=1):
            os.environ.pop("PER_CONTAINER_CPUS", None)
            # max(1.0, 1*0.1) = 1.0 cpu -> never zero (would disable the cap)
            self.assertEqual(self.m._container_cpu_limit(), 1_000_000_000)


class TestPidsLimit(unittest.TestCase):
    def setUp(self):
        self.m = _mgr()

    def test_failopen_when_governor_disabled(self):
        with _env(REDAMON_MEM_GOVERNOR="false"):
            self.assertIsNone(self.m._container_pids_limit())

    def test_default_512(self):
        with _env(REDAMON_MEM_GOVERNOR="true"):
            os.environ.pop("CONTAINER_PIDS_MAX", None)
            self.assertEqual(self.m._container_pids_limit(), 512)

    def test_env_override(self):
        with _env(REDAMON_MEM_GOVERNOR="true", CONTAINER_PIDS_MAX="128"):
            self.assertEqual(self.m._container_pids_limit(), 128)

    def test_garbage_override_falls_back_to_512(self):
        with _env(REDAMON_MEM_GOVERNOR="true", CONTAINER_PIDS_MAX="not-a-number"):
            self.assertEqual(self.m._container_pids_limit(), 512)

    def test_never_below_one(self):
        with _env(REDAMON_MEM_GOVERNOR="true", CONTAINER_PIDS_MAX="0"):
            self.assertEqual(self.m._container_pids_limit(), 1)


class TestScannerEnv(unittest.TestCase):
    def setUp(self):
        self.m = _mgr()

    def test_uses_scoped_scanner_token(self):
        with _env(SCANNER_API_KEY="scan-tok", INTERNAL_API_KEY="master"):
            env = self.m._scanner_env()
            self.assertEqual(env, {"SCANNER_API_KEY": "scan-tok"})
            # the master key must NOT be handed to the scan spawn
            self.assertNotIn("INTERNAL_API_KEY", env)

    def test_no_master_key_when_scanner_unset(self):
        with _env(INTERNAL_API_KEY="master"):
            os.environ.pop("SCANNER_API_KEY", None)
            self.assertEqual(self.m._scanner_env(), {})

    def test_no_master_key_when_scanner_is_placeholder(self):
        with _env(SCANNER_API_KEY="changeme", INTERNAL_API_KEY="master"):
            self.assertEqual(self.m._scanner_env(), {})


class TestScannerHardening(unittest.TestCase):
    def setUp(self):
        self.m = _mgr()

    def test_cap_drop_all_when_requested(self):
        self.assertEqual(self.m._scanner_hardening(drop_caps=True), {"cap_drop": ["ALL"]})

    def test_no_cap_drop_by_default(self):
        self.assertEqual(self.m._scanner_hardening(), {})
        self.assertEqual(self.m._scanner_hardening(drop_caps=False), {})

    def test_does_not_add_cap_add(self):
        # cap_add is supplied at the call site; hardening must not duplicate it.
        self.assertNotIn("cap_add", self.m._scanner_hardening(drop_caps=True))


if __name__ == "__main__":
    unittest.main()
