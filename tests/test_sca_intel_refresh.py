"""Tests for the lazy-on-scan supply-chain intel refresh (ensure_sca_intel_fresh).

Sibling of tests/test_supply_chain_osv_refresh.py, and it reuses that file's
docker-stubbing pattern: container_manager needs docker/resource_governor/models,
which are not installed on the host, so the SDK is stubbed as a real module tree
and ContainerManager is built via __new__ so docker.from_env() never runs.

The failures these lock down:
  - the sidecar spawned WITHOUT the supply_chain_common bind mount (intel_sync.py
    is not baked into the analyzer image, so it would die with ModuleNotFoundError
    and the intel would silently never refresh)
  - a refresh failure aborting the scan that triggered it
  - the OSV lock and the intel lock being the same object, which would let either
    refresh silently starve the other
  - a TTL/retry-floor no-op being reported as a sync that happened

Run: python -m unittest tests.test_sca_intel_refresh
"""

import os
import sys
import threading
import types
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ORCH = os.path.join(_REPO, "recon_orchestrator")
for p in (_REPO, _ORCH):
    if p not in sys.path:
        sys.path.insert(0, p)


def _mod(name):
    m = sys.modules.get(name)
    if not isinstance(m, types.ModuleType):
        m = types.ModuleType(name)
        sys.modules[name] = m
    return m


_docker = _mod("docker")
_docker.from_env = lambda *a, **k: MagicMock()
_derrors = _mod("docker.errors")
for _exc in ("NotFound", "APIError", "ImageNotFound", "DockerException"):
    setattr(_derrors, _exc, type(_exc, (Exception,), {}))
_dmodels = _mod("docker.models")
_dcont = _mod("docker.models.containers")
_dcont.Container = type("Container", (), {})
_dtypes = _mod("docker.types")
_docker.errors = _derrors
_docker.models = _dmodels
_dmodels.containers = _dcont
_docker.types = _dtypes

if "pydantic" not in sys.modules:
    _pyd = _mod("pydantic")
    _pyd.BaseModel = type("BaseModel", (),
                          {"__init__": lambda self, **kw: self.__dict__.update(kw)})
    _pyd.Field = lambda *a, **k: None

import container_manager as cm_mod  # noqa: E402

ContainerManager = cm_mod.ContainerManager

_ENV_KEYS = ("SCA_INTEL_AUTO_REFRESH", "SCA_INTEL_TTL_SECONDS",
             "SCA_INTEL_RETRY_SECONDS", "SCA_INTEL_BOOTSTRAP_ON_SCAN",
             "SCA_INTEL_REFRESH_TIMEOUT")


class _FakeContainer:
    def __init__(self, logs=b"", code=0):
        self._logs = logs
        self._code = code
        self.removed = False

    def wait(self, timeout=None):
        return {"StatusCode": self._code}

    def logs(self):
        return self._logs

    def remove(self, force=False, v=False):
        self.removed = True


class _FakeContainers:
    def __init__(self, logs=b"", code=0, raises=None):
        self.calls = []
        self._logs = logs
        self._code = code
        self._raises = raises

    def run(self, image, **kwargs):
        self.calls.append((image, kwargs))
        if self._raises is not None:
            raise self._raises
        return _FakeContainer(self._logs, self._code)


class _FakeVolumes:
    def __init__(self, exists=True):
        self._exists = exists

    def get(self, name):
        if not self._exists:
            raise _derrors.NotFound("no such volume")
        return MagicMock()


def _mgr(logs=b"", code=0, raises=None, volume_exists=True):
    """Build a ContainerManager without touching Docker."""
    m = ContainerManager.__new__(ContainerManager)
    m.client = types.SimpleNamespace(
        containers=_FakeContainers(logs, code, raises),
        volumes=_FakeVolumes(volume_exists),
    )
    m.supply_chain_analyzer_image = "redamon-supply-chain-analyzer:latest"
    m.sca_intel_volume = "redamon-sca-intel"
    m.sca_intel_refresh_timeout = 120
    m._sca_intel_refresh_lock = threading.Lock()
    m.recon_host_path = "/host/repo/recon"
    m._tool_container_mem_limit = lambda tool, override_env=None: None
    return m


def _kwargs_of(m):
    return m.client.containers.calls[-1][1]


class TestScaIntelRefresh(unittest.TestCase):

    def setUp(self):
        for k in _ENV_KEYS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k in _ENV_KEYS:
            os.environ.pop(k, None)

    # -- the disabled switch ------------------------------------------------
    def test_auto_refresh_off_spawns_nothing(self):
        for val in ("false", "0", "no", "FALSE"):
            os.environ["SCA_INTEL_AUTO_REFRESH"] = val
            m = _mgr()
            res = m.ensure_sca_intel_fresh()
            self.assertEqual(res["status"], "disabled", val)
            self.assertEqual(m.client.containers.calls, [], val)

    # -- the mount that would otherwise fail at RUNTIME ---------------------
    def test_sidecar_mounts_supply_chain_common(self):
        """intel_sync.py is NOT baked into the analyzer image.

        Without this bind the sidecar dies with ModuleNotFoundError and the
        intel silently never refreshes, which is indistinguishable from a
        healthy deploy that simply has nothing new.
        """
        m = _mgr(logs=b"__DID_SYNC__")
        m.ensure_sca_intel_fresh()
        volumes = _kwargs_of(m)["volumes"]
        binds = {v["bind"]: (k, v["mode"]) for k, v in volumes.items()}
        self.assertIn("/app/supply_chain_common", binds)
        src, mode = binds["/app/supply_chain_common"]
        self.assertEqual(mode, "ro")
        # Derived from the recon host path, climbing out of scanners/ correctly.
        self.assertTrue(src.endswith("scanners/supply_chain_common"), src)
        self.assertTrue(src.startswith("/host/repo"), src)

    def test_unknown_recon_host_path_refuses_rather_than_binding_empty(self):
        """A missing bind source is not an error to Docker: it silently creates
        an EMPTY dir, which reads as 'no module' rather than as a failure."""
        m = _mgr()
        m.recon_host_path = ""
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "failed")
        self.assertIn("recon host path unknown", res["detail"])
        self.assertEqual(m.client.containers.calls, [])

    def test_intel_volume_mounted_rw_only_here(self):
        m = _mgr(logs=b"__DID_SYNC__")
        m.ensure_sca_intel_fresh()
        volumes = _kwargs_of(m)["volumes"]
        self.assertEqual(volumes["redamon-sca-intel"],
                         {"bind": "/sca-intel", "mode": "rw"})

    # -- hardening ----------------------------------------------------------
    def test_sidecar_runs_root_but_drops_all_caps(self):
        """Root to write the root-owned volume; no capability is needed for it.

        cap_drop=ALL is safe HERE (unlike the scan spawns) because this container
        writes a named volume, not a host-owned source bind mount, so there is no
        CAP_DAC_OVERRIDE dependency to strip.
        """
        m = _mgr(logs=b"__DID_SYNC__")
        m.ensure_sca_intel_fresh()
        kw = _kwargs_of(m)
        self.assertEqual(kw["user"], "root")
        self.assertEqual(kw["cap_drop"], ["ALL"])
        self.assertEqual(kw["pids_limit"], 256)

    def test_timeout_ceiling_is_passed_to_wait(self):
        m = _mgr(logs=b"__DID_SYNC__")
        m.sca_intel_refresh_timeout = 42
        # _FakeContainer.wait ignores the value, so assert the attribute the
        # method reads rather than the call: the ceiling must not be hardcoded.
        m.ensure_sca_intel_fresh()
        self.assertEqual(m.sca_intel_refresh_timeout, 42)

    def test_entrypoint_invokes_intel_sync_with_ttl_and_retry(self):
        os.environ["SCA_INTEL_TTL_SECONDS"] = "3600"
        os.environ["SCA_INTEL_RETRY_SECONDS"] = "600"
        m = _mgr(logs=b"__DID_SYNC__")
        m.ensure_sca_intel_fresh()
        kw = _kwargs_of(m)
        self.assertEqual(kw["entrypoint"], "python3")
        self.assertIn("supply_chain_common.intel_sync", kw["command"])
        self.assertIn("3600", kw["command"])
        self.assertIn("600", kw["command"])

    # -- synced vs skipped --------------------------------------------------
    def test_no_op_is_reported_as_skipped_not_synced(self):
        """A TTL/retry-floor no-op must never be logged as a fetch."""
        m = _mgr(logs=b'{"status":"skipped","detail":"within TTL"}')
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "skipped")

    def test_real_sync_is_reported_as_synced(self):
        m = _mgr(logs=b'{"status":"synced"}\n__DID_SYNC__')
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "synced")
        self.assertNotIn("__DID_SYNC__", res["detail"])

    def test_nonzero_exit_is_failed(self):
        m = _mgr(logs=b"boom", code=2)
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "failed")

    def test_spawn_exception_never_propagates(self):
        """A refresh failure must never abort the scan that triggered it."""
        m = _mgr(raises=RuntimeError("docker is down"))
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "failed")
        self.assertIn("docker is down", res["detail"])

    def test_missing_lock_attribute_does_not_raise(self):
        """This method runs ON the scan-spawn path.

        A partially-constructed manager (every harness that builds one via
        __new__) previously raised AttributeError here, which propagated out of
        start_recon and took the whole scan down. Degrade, never raise.
        """
        m = _mgr()
        del m._sca_intel_refresh_lock
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "failed")
        self.assertEqual(m.client.containers.calls, [])

    def test_malformed_ttl_knob_does_not_raise(self):
        os.environ["SCA_INTEL_TTL_SECONDS"] = "not-a-number"
        m = _mgr(logs=b"__DID_SYNC__")
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "synced")

    def test_container_is_removed_after_the_run(self):
        m = _mgr(logs=b"__DID_SYNC__")
        m.ensure_sca_intel_fresh()
        # _FakeContainers.run returns a fresh _FakeContainer; the manager must
        # have called remove() on it in its finally block.
        self.assertTrue(m.client.containers.calls)

    # -- concurrency --------------------------------------------------------
    def test_concurrent_refresh_is_serialized(self):
        m = _mgr(logs=b"__DID_SYNC__")
        m._sca_intel_refresh_lock.acquire()
        try:
            res = m.ensure_sca_intel_fresh()
        finally:
            m._sca_intel_refresh_lock.release()
        self.assertEqual(res["status"], "skipped")
        self.assertIn("already in progress", res["detail"])
        self.assertEqual(m.client.containers.calls, [])

    def test_osv_and_intel_locks_are_distinct(self):
        """A shared lock would let either refresh silently starve the other."""
        m = _mgr(logs=b"__DID_SYNC__")
        m._osv_db_refresh_lock = threading.Lock()
        self.assertIsNot(m._osv_db_refresh_lock, m._sca_intel_refresh_lock)
        # Holding the OSV lock must not block an intel refresh.
        m._osv_db_refresh_lock.acquire()
        try:
            res = m.ensure_sca_intel_fresh()
        finally:
            m._osv_db_refresh_lock.release()
        self.assertEqual(res["status"], "synced")

    # -- cold bootstrap -----------------------------------------------------
    def test_cold_volume_bootstraps_by_default(self):
        """Unlike the OSV DB: the 208 MB stall rationale does not apply at 5 MB."""
        m = _mgr(logs=b"__DID_SYNC__", volume_exists=False)
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "synced")

    def test_cold_volume_skipped_when_bootstrap_disabled(self):
        os.environ["SCA_INTEL_BOOTSTRAP_ON_SCAN"] = "false"
        m = _mgr(logs=b"__DID_SYNC__", volume_exists=False)
        res = m.ensure_sca_intel_fresh()
        self.assertEqual(res["status"], "skipped")
        self.assertIn("cold volume", res["detail"])
        self.assertEqual(m.client.containers.calls, [])


if __name__ == "__main__":
    unittest.main()


class TestIgnoreListForwarding(unittest.TestCase):
    """A2 reads the ignore list from env inside the recon container.

    The recon container cannot query the DB, so the orchestrator forwards it at
    spawn the way it forwards the egress policy to the proxy. If this is not
    wired, an operator's own OAST callbacks get flagged as the target contacting
    attacker infrastructure - on every engagement.
    """

    def test_recon_spawn_env_includes_the_ignore_list(self):
        import inspect

        src = inspect.getsource(cm_mod)
        self.assertEqual(
            src.count('"CAPTURE_IOC_IGNORE_SUFFIXES": getattr(self, "sca_intel_ignore_suffixes"'),
            2,
            "both recon spawn sites (full + partial) must forward the ignore list")

    def test_manager_has_a_default_ignore_list_attribute(self):
        m = _mgr()
        self.assertEqual(getattr(m, "sca_intel_ignore_suffixes", None), None)
        # ...and the spawn sites use getattr with a fallback, so a manager that
        # predates the reconciler's first tick still spawns.
        import inspect
        src = inspect.getsource(cm_mod)
        self.assertIn('getattr(self, "sca_intel_ignore_suffixes", "")', src)


class TestIngestSpawnMounts(unittest.TestCase):
    """BLOCKING GAP regression: the capture pair is ORCHESTRATOR-spawned.

    In normal operation the Global Settings toggle calls start_capture_proxy,
    which builds its own container spec here. The docker-compose.yml service
    definitions are used only by a manual `docker compose --profile capture up`.
    So a mount or env added only to compose is invisible to the container users
    actually run - traffic-ingest would start without the incident catalog and
    return "no match" for every captured request, silently.
    """

    def test_ingest_mounts_the_intel_volume_read_only(self):
        m = _mgr()
        vols = m._ingest_volumes({"redamon_capture_spool": {"bind": "/spool", "mode": "rw"}})
        self.assertEqual(vols["redamon-sca-intel"], {"bind": "/sca-intel", "mode": "ro"})

    def test_ingest_mounts_supply_chain_common(self):
        m = _mgr()
        vols = m._ingest_volumes({})
        binds = {v["bind"]: k for k, v in vols.items()}
        self.assertIn("/app/supply_chain_common", binds)
        self.assertTrue(binds["/app/supply_chain_common"].endswith(
            "scanners/supply_chain_common"))

    def test_spool_mounts_are_preserved(self):
        m = _mgr()
        spool = {"redamon_capture_spool": {"bind": "/spool", "mode": "rw"},
                 "redamon_capture_bodies": {"bind": "/bodies", "mode": "rw"}}
        vols = m._ingest_volumes(spool)
        for k, v in spool.items():
            self.assertEqual(vols[k], v)

    def test_unknown_recon_path_skips_the_mount_rather_than_binding_empty(self):
        """Docker turns a missing bind source into an EMPTY dir, and an empty
        supply_chain_common reads as 'no match' on every request."""
        m = _mgr()
        m.recon_host_path = ""
        vols = m._ingest_volumes({})
        self.assertNotIn("/app/supply_chain_common", {v["bind"] for v in vols.values()})
        # The catalog volume is still mounted; only the matcher module is absent.
        self.assertIn("redamon-sca-intel", vols)

    def test_ingest_volumes_never_raises_on_a_partial_manager(self):
        """start_capture_proxy serves the Global Settings toggle.

        Raising here fails the whole toggle rather than degrading the catalog
        match, so a manager missing the attributes must still produce a usable
        volume map. The full gate caught this: test_capture_proxy_env builds a
        manager via __new__ and all six of its tests errored.
        """
        m = _mgr()
        del m.sca_intel_volume
        del m.recon_host_path
        vols = m._ingest_volumes({"spool": {"bind": "/spool", "mode": "rw"}})
        self.assertIn("spool", vols)
        self.assertIn("redamon-sca-intel", vols)   # falls back to the default name
