"""Regression tests for the lazy-on-scan OSV DB auto-refresh (ensure_osv_db_fresh).

Named after the deep-review findings so they cannot come back:
  H1 - a cold/empty DB must NOT be bootstrapped on the scan path (a ~208 MB
       download would block the first recon spawn for a feature that is off by
       default); explicit bootstrap=True must still populate.
  H2 - OSV_DB_ECOSYSTEMS is interpolated into a shell script: anything off the
       allowlist must be REFUSED, never escaped.
  H3 - a TTL/cold no-op must report status=skipped, not "synced".
  H4 - concurrent scan starts must not spawn two sidecars on the same volume.
  H5 - the sidecar runs root (to write the root-owned DB) but with cap_drop=ALL.

container_manager needs docker/resource_governor/models, which are not installed
on the host, so they are stubbed (same pattern as the neo4j stub in the graph
tests). ContainerManager is built via __new__ so docker.from_env() never runs.

Run: python -m unittest tests.test_supply_chain_osv_refresh
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

# Stub the docker SDK as a real module tree (container_manager does
# `from docker.models.containers import Container`, which a MagicMock cannot
# satisfy - it is not a package). resource_governor / admission_ledger / models
# are real modules importable from recon_orchestrator/, so they load normally.
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

# models.py only needs pydantic.BaseModel to declare its state classes.
if "pydantic" not in sys.modules:
    _pyd = _mod("pydantic")
    _pyd.BaseModel = type("BaseModel", (), {"__init__": lambda self, **kw: self.__dict__.update(kw)})
    _pyd.Field = lambda *a, **k: None

import container_manager as cm_mod  # noqa: E402

ContainerManager = cm_mod.ContainerManager


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
    def __init__(self, logs=b"", code=0):
        self.calls = []
        self._logs = logs
        self._code = code

    def run(self, image, **kwargs):
        self.calls.append((image, kwargs))
        return _FakeContainer(self._logs, self._code)


def _mgr(logs=b"", code=0):
    """Build a ContainerManager without touching Docker."""
    m = ContainerManager.__new__(ContainerManager)
    m.client = types.SimpleNamespace(containers=_FakeContainers(logs, code))
    m.supply_chain_analyzer_image = "redamon-supply-chain-analyzer:latest"
    m.supply_chain_osv_db_volume = "redamon-osv-db"
    m.osv_db_refresh_timeout = 900
    m._osv_db_refresh_lock = threading.Lock()
    return m


def _script_of(m):
    """The shell script handed to the sidecar on the last run() call."""
    return m.client.containers.calls[-1][1]["command"][1]


class TestOsvRefreshRegressions(unittest.TestCase):
    def setUp(self):
        for k in ("OSV_DB_AUTO_REFRESH", "OSV_DB_ECOSYSTEMS", "OSV_DB_TTL_SECONDS"):
            os.environ.pop(k, None)

    # -- H1 ---------------------------------------------------------------
    def test_H1_scan_path_does_not_bootstrap_cold_db(self):
        m = _mgr(logs=b"cold-db: not populated, skipping auto-refresh")
        res = m.ensure_osv_db_fresh()  # scan-path default
        self.assertEqual(res["status"], "skipped")
        # the guard must be compiled into the script as BOOTSTRAP=0
        self.assertIn("BOOTSTRAP=0", _script_of(m))
        self.assertIn('[ ! -d "$DB/osv-scanner" ]', _script_of(m))

    def test_H1_explicit_bootstrap_is_allowed(self):
        m = _mgr(logs=b"synced npm\n__DID_SYNC__")
        res = m.ensure_osv_db_fresh(bootstrap=True)
        self.assertEqual(res["status"], "synced")
        self.assertIn("BOOTSTRAP=1", _script_of(m))

    # -- H2 ---------------------------------------------------------------
    def test_H2_shell_injection_via_ecosystems_refused(self):
        m = _mgr()
        res = m.ensure_osv_db_fresh(
            ecosystems='npm" ; touch /osv-db/PWNED ; echo "')
        # every token is off the allowlist -> nothing to do, no container spawned
        self.assertEqual(res["status"], "disabled")
        self.assertEqual(m.client.containers.calls, [])

    def test_H2_partial_injection_keeps_only_valid_ecosystems(self):
        m = _mgr(logs=b"skip npm")
        m.ensure_osv_db_fresh(ecosystems="npm,$(id),PyPI")
        script = _script_of(m)
        self.assertIn("npm,PyPI", script)
        self.assertNotIn("$(id)", script)

    def test_H2_allowlist_accepts_known_ecosystems(self):
        m = _mgr(logs=b"skip npm")
        m.ensure_osv_db_fresh(ecosystems=["npm", "PyPI", "crates.io"])
        self.assertIn("npm,PyPI,crates.io", _script_of(m))

    # -- H3 ---------------------------------------------------------------
    def test_H3_ttl_noop_reports_skipped_not_synced(self):
        m = _mgr(logs=b"skip npm (age 12s < 86400s)")
        res = m.ensure_osv_db_fresh(bootstrap=True)
        self.assertEqual(res["status"], "skipped")

    def test_H3_real_sync_reports_synced_and_strips_marker(self):
        m = _mgr(logs=b"sync npm ...\nsynced npm\n__DID_SYNC__")
        res = m.ensure_osv_db_fresh(bootstrap=True)
        self.assertEqual(res["status"], "synced")
        self.assertNotIn("__DID_SYNC__", res["detail"])

    def test_H3_nonzero_exit_reports_failed(self):
        m = _mgr(logs=b"boom", code=1)
        self.assertEqual(m.ensure_osv_db_fresh(bootstrap=True)["status"], "failed")

    # -- H4 ---------------------------------------------------------------
    def test_H4_concurrent_refresh_is_serialized(self):
        m = _mgr(logs=b"skip npm")
        m._osv_db_refresh_lock.acquire()  # simulate an in-flight refresh
        try:
            res = m.ensure_osv_db_fresh()
            self.assertEqual(res["status"], "skipped")
            self.assertIn("already in progress", res["detail"])
            self.assertEqual(m.client.containers.calls, [])  # no second sidecar
        finally:
            m._osv_db_refresh_lock.release()

    def test_H4_lock_released_after_run(self):
        m = _mgr(logs=b"skip npm")
        m.ensure_osv_db_fresh()
        self.assertTrue(m._osv_db_refresh_lock.acquire(blocking=False))
        m._osv_db_refresh_lock.release()

    def test_H4_lock_released_even_on_error(self):
        m = _mgr()
        m.client.containers.run = MagicMock(side_effect=RuntimeError("daemon down"))
        res = m.ensure_osv_db_fresh()
        self.assertEqual(res["status"], "failed")  # best-effort, never raises
        self.assertTrue(m._osv_db_refresh_lock.acquire(blocking=False))
        m._osv_db_refresh_lock.release()

    # -- H5 ---------------------------------------------------------------
    def test_H5_sidecar_is_hardened_and_holds_no_secrets(self):
        m = _mgr(logs=b"skip npm")
        m.ensure_osv_db_fresh()
        kwargs = m.client.containers.calls[-1][1]
        self.assertEqual(kwargs["cap_drop"], ["ALL"])
        self.assertEqual(kwargs["user"], "root")  # needed to write the DB tree
        self.assertEqual(kwargs["pids_limit"], 256)
        env = kwargs["environment"]
        for secret in ("NEO4J_PASSWORD", "INTERNAL_API_KEY", "SCANNER_API_KEY",
                       "GITHUB_ACCESS_TOKEN"):
            self.assertNotIn(secret, env)
        # DB volume mounted rw (this is the one writer)
        self.assertEqual(kwargs["volumes"][m.supply_chain_osv_db_volume]["mode"], "rw")

    # -- kill switch ------------------------------------------------------
    def test_auto_refresh_kill_switch(self):
        for val in ("false", "0", "no", "FALSE"):
            os.environ["OSV_DB_AUTO_REFRESH"] = val
            m = _mgr()
            res = m.ensure_osv_db_fresh()
            self.assertEqual(res["status"], "disabled", val)
            self.assertEqual(m.client.containers.calls, [])
        os.environ.pop("OSV_DB_AUTO_REFRESH", None)

    def test_ttl_env_reaches_script(self):
        os.environ["OSV_DB_TTL_SECONDS"] = "3600"
        m = _mgr(logs=b"skip npm")
        m.ensure_osv_db_fresh()
        self.assertIn("TTL=3600", _script_of(m))
        os.environ.pop("OSV_DB_TTL_SECONDS")


class TestEcosystemListsDoNotDrift(unittest.TestCase):
    """REGRESSION: three copies of the ecosystem list, two of them wrong.

    The set lived in three places that could not import each other:
      * scanners/supply_chain_common/osv_db_sync.py SEED_MANIFESTS  (redamon.sh path)
      * container_manager._OSV_SYNC_ECOSYSTEMS             (auto-refresh)
      * redamon.sh OSV_ALL_ECOSYSTEMS                      (install/update)

    The orchestrator was missing Maven and NuGet, so an operator could sync
    them by hand and then watch them silently go stale forever - the refresh
    would log "refusing unknown ecosystem" and move on. Meanwhile the project
    default advertised all eight in the scan header.
    """

    def _repo(self, *parts):
        return os.path.join(_REPO, *parts)

    def test_orchestrator_covers_every_seeded_ecosystem(self):
        from supply_chain_common.osv_db_sync import SEED_MANIFESTS
        src = open(self._repo("recon_orchestrator", "container_manager.py")).read()
        block = src[src.index("_OSV_SYNC_ECOSYSTEMS = ("):]
        block = block[:block.index(")")]
        for eco in SEED_MANIFESTS:
            self.assertIn('"%s"' % eco, block,
                          "%s is seedable but the orchestrator refuses it" % eco)

    def test_orchestrator_has_a_seed_manifest_for_each(self):
        """The allowlist is useless if the shell case has no branch for it."""
        from supply_chain_common.osv_db_sync import SEED_MANIFESTS
        src = open(self._repo("recon_orchestrator", "container_manager.py")).read()
        for eco in SEED_MANIFESTS:
            self.assertIn("%s)" % eco, src,
                          "no seed manifest branch for %s in the refresh script" % eco)

    def test_redamon_sh_lists_every_seeded_ecosystem(self):
        from supply_chain_common.osv_db_sync import SEED_MANIFESTS
        src = open(self._repo("redamon.sh")).read()
        line = [l for l in src.splitlines() if l.startswith("OSV_ALL_ECOSYSTEMS=")][0]
        for eco in SEED_MANIFESTS:
            self.assertIn(eco, line, "%s missing from redamon.sh" % eco)

    def test_compose_default_covers_every_seeded_ecosystem(self):
        """The auto-refresh only touches what OSV_DB_ECOSYSTEMS names."""
        from supply_chain_common.osv_db_sync import SEED_MANIFESTS
        src = open(self._repo("docker-compose.yml")).read()
        line = [l for l in src.splitlines() if "OSV_DB_ECOSYSTEMS:" in l][0]
        for eco in SEED_MANIFESTS:
            self.assertIn(eco, line, "%s missing from the compose default" % eco)

    def test_install_and_update_populate_the_db(self):
        """Cold-install must not leave the feature inert until someone finds
        the supply-chain-sync subcommand."""
        src = open(self._repo("redamon.sh")).read()
        self.assertIn("ensure_osv_db()", src)
        # called from install, update and up (plus the dev variant)
        self.assertGreaterEqual(src.count("\n    ensure_osv_db\n"), 3)


if __name__ == "__main__":
    unittest.main()
