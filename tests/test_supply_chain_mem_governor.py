"""Memory-governor integration for the supply-chain feature (L1 / L2 / L3).

Supply-chain is the only feature that spawns a SECOND heavy container per job:
the DIRTY analyzer (retire.js / GuardDog / osv over hostile bytes). That sibling
is created from three different processes, and only one of them (the
orchestrator) can import container_manager. The result was a security-sensitive
sandbox whose memory ceiling was a hardcoded "1500m" on two of the three paths -
the one container in RedAmon that never shrank on a starved host.

These tests pin the pieces that keep the three paths honest:
  * the analyzer's ceiling comes from ONE governed source, not a literal
  * an explicit operator override still wins
  * everything fails open when the governor is unavailable
  * the L2 import-mining budgets are reachable by apply_memory_governor at all

Run: python3 -m unittest tests.test_supply_chain_mem_governor
"""
import importlib
import importlib.util
import os
import sys
import unittest
import unittest.mock

ROOT = os.path.join(os.path.dirname(__file__), '..')
# graph_db dir on path so the dispatch module's `import resource_governor`
# fallback resolves (graph_db/__init__ pulls neo4j, unavailable on the host).
sys.path.insert(0, os.path.join(ROOT, 'graph_db'))
sys.path.insert(0, os.path.join(ROOT, 'recon'))
sys.path.insert(0, ROOT)

import resource_governor as rg
from supply_chain_common import analyzer_dispatch as ad

# Load recon/project_settings.py by PATH under a unique name. Several
# `project_settings.py` files exist in this repo (recon, agentic, and several
# scanners) and a bare `import project_settings` resolves to
# whichever one reached sys.modules first: green alone, wrong module in a full
# suite run. Same trick test_agent_mem_governor uses for the agentic copy.
_spec = importlib.util.spec_from_file_location(
    'recon_project_settings_scgov', os.path.join(ROOT, 'recon', 'project_settings.py'))
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)

GB = 1024 ** 3

# Force every lazy `import resource_governor` (analyzer_dispatch's and
# apply_memory_governor's) to happen NOW, so _all_governors() can see whichever
# copy each of them resolved.
ps.apply_memory_governor({})
ad._governed_mem()


def _all_governors():
    """Every resource_governor copy currently loaded.

    There are two maintained copies and several test modules that each put a
    DIFFERENT directory on sys.path before `import resource_governor`, so
    whichever ran first owns the bare module name for the whole process. A test
    that overrides only its own `rg` therefore silently reads REAL host RAM in a
    combined run: green alone, red in a suite. Fan out to every copy instead.
    """
    return [m for name, m in list(sys.modules.items())
            if m is not None and name.split('.')[-1] == 'resource_governor'
            and hasattr(m, 'set_mem_override')]


def _set_mem(total, avail):
    for m in _all_governors():
        m.set_mem_override(total, avail)


def _reset_governors():
    for m in _all_governors():
        m.set_mem_override(None, None)
        m.reset_profile_cache()


def _memory_flag(argv):
    """The value passed to `docker run --memory`."""
    return argv[argv.index("--memory") + 1]


class SupplyChainGovBase(unittest.TestCase):
    ENV = ("REDAMON_MEM_GOVERNOR", "SUPPLY_CHAIN_ANALYZER_MEM",
           "CONTAINER_CAP_HEADROOM", "PER_CONTAINER_MAX",
           "RESOURCE_PROFILE_PATH", "MEM_BUDGET_FRACTION")

    def setUp(self):
        for k in self.ENV:
            os.environ.pop(k, None)
        _reset_governors()

    def tearDown(self):
        for k in self.ENV:
            os.environ.pop(k, None)
        _reset_governors()

    def _argv(self, **kw):
        return ad.analyzer_docker_argv("/tmp/redamon/job", "/host/sc_common", **kw)


class TestAnalyzerMemoryIsGoverned(SupplyChainGovBase):
    def test_memory_comes_from_the_governor_not_a_literal(self):
        _set_mem(64 * GB, 32 * GB)
        expected = rg.container_cap(rg.tool_container_envelope("supply_chain_analyzer"))
        self.assertEqual(_memory_flag(self._argv()), str(expected))

    def test_shrinks_on_a_starved_host(self):
        """The regression this closes: the literal stayed at 1500m no matter how
        little RAM the host had, while every other RedAmon container shrank."""
        _set_mem(2 * GB, 256 * 1024 ** 2)
        starved = int(_memory_flag(self._argv()))
        _set_mem(64 * GB, 32 * GB)
        roomy = int(_memory_flag(self._argv()))
        self.assertLess(starved, roomy)

    def test_explicit_operator_override_still_wins(self):
        # An operator who sets the env var must not be silently overruled by a
        # profile figure; the governor only fills in when they have not chosen.
        os.environ["SUPPLY_CHAIN_ANALYZER_MEM"] = "700m"
        _set_mem(64 * GB, 32 * GB)
        self.assertEqual(ad._resolve_mem(), "700m")
        self.assertEqual(_memory_flag(self._argv()), "700m")

    def test_override_arriving_after_import_is_honoured(self):
        """REGRESSION. The override used to be snapshotted into a module constant
        at import time while the override *check* read os.environ at call time.
        An operator value that arrived later passed the check (governor stepped
        aside) and then hit the stale constant: they asked for 700m, docker got
        1500m, nothing logged. This module is imported once per process and the
        env is not guaranteed to be populated first, so it must resolve late."""
        _set_mem(64 * GB, 32 * GB)
        self.assertNotEqual(_memory_flag(self._argv()), "333m")   # not set yet
        os.environ["SUPPLY_CHAIN_ANALYZER_MEM"] = "333m"          # arrives late
        self.assertEqual(_memory_flag(self._argv()), "333m")

    def test_blank_override_does_not_win(self):
        # Compose writes `SUPPLY_CHAIN_ANALYZER_MEM=` for an unset var, which
        # arrives as an empty string. Empty must mean "unset", not "cap at ''".
        os.environ["SUPPLY_CHAIN_ANALYZER_MEM"] = "   "
        _set_mem(64 * GB, 32 * GB)
        self.assertEqual(_memory_flag(self._argv()),
                         str(rg.container_cap(rg.tool_container_envelope(
                             "supply_chain_analyzer"))))

    def test_precedence_chain_is_call_arg_then_env_then_governor(self):
        _set_mem(64 * GB, 32 * GB)
        governed = str(rg.container_cap(rg.tool_container_envelope("supply_chain_analyzer")))
        self.assertEqual(_memory_flag(self._argv()), governed)
        os.environ["SUPPLY_CHAIN_ANALYZER_MEM"] = "700m"
        self.assertEqual(_memory_flag(self._argv()), "700m")
        self.assertEqual(_memory_flag(self._argv(mem="256m")), "256m")

    def test_memory_value_is_a_format_docker_accepts(self):
        """The governed value is plain bytes, not a Docker size string. If it ever
        became something like '1.5g' or a float, `docker run` would reject the
        spawn at runtime - a failure no unit test asserting an integer would see."""
        import re
        _set_mem(64 * GB, 32 * GB)
        val = _memory_flag(self._argv())
        self.assertRegex(val, r"^(\d+|\d+[bkmgBKMG])$")
        self.assertGreaterEqual(int(re.sub(r"[^0-9]", "", val)), 6)  # docker's 6 MB floor

    def test_explicit_call_argument_wins_over_everything(self):
        _set_mem(64 * GB, 32 * GB)
        self.assertEqual(_memory_flag(self._argv(mem="256m")), "256m")

    def test_governor_disabled_falls_back_to_the_legacy_literal(self):
        os.environ["REDAMON_MEM_GOVERNOR"] = "off"
        _set_mem(64 * GB, 32 * GB)
        self.assertEqual(_memory_flag(self._argv()), ad._DEFAULT_MEM)

    def test_governor_import_failure_is_not_fatal(self):
        """The analyzer image mounts supply_chain_common but has no graph_db. An
        ImportError here must degrade to the literal, never break the spawn."""
        def boom(*_a, **_k):
            raise ImportError("no graph_db in this image")

        real = ad._governed_mem.__globals__["__builtins__"]["__import__"]
        ad._governed_mem.__globals__["__builtins__"]["__import__"] = boom
        try:
            self.assertIsNone(ad._governed_mem())
            self.assertEqual(_memory_flag(self._argv()), ad._DEFAULT_MEM)
            self.assertEqual(ad._DEFAULT_MEM, "1500m")   # the legacy literal
        finally:
            ad._governed_mem.__globals__["__builtins__"]["__import__"] = real

    def test_import_failure_still_honours_an_operator_override(self):
        """Fail-soft must not fail *shut*: with no governor reachable the operator
        remains the only voice, so their value must still be used."""
        def boom(*_a, **_k):
            raise ImportError("no graph_db in this image")

        os.environ["SUPPLY_CHAIN_ANALYZER_MEM"] = "700m"
        real = ad._governed_mem.__globals__["__builtins__"]["__import__"]
        ad._governed_mem.__globals__["__builtins__"]["__import__"] = boom
        try:
            self.assertEqual(_memory_flag(self._argv()), "700m")
        finally:
            ad._governed_mem.__globals__["__builtins__"]["__import__"] = real

    def test_hardening_flags_are_unchanged(self):
        # Sizing must not have disturbed the security boundary this argv encodes.
        _set_mem(64 * GB, 32 * GB)
        argv = self._argv()
        for flag in ("--cap-drop", "--read-only", "--pids-limit", "--memory"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")


class TestBothSpawnPathsAgree(SupplyChainGovBase):
    """The orchestrator uses the Docker SDK, recon and L1 shell out through the
    broker. analyzer_dispatch exists so those two never drift; before this they
    resolved memory from two unrelated sources."""

    def test_sdk_path_and_broker_path_resolve_the_same_ceiling(self):
        _set_mem(64 * GB, 32 * GB)
        broker_side = int(_memory_flag(self._argv()))
        # What ContainerManager._tool_container_mem_limit computes, without
        # importing docker (unavailable on the host).
        sdk_side = rg.container_cap(rg.tool_container_envelope("supply_chain_analyzer"))
        self.assertEqual(broker_side, sdk_side)

    def test_analyzer_is_sized_from_its_own_envelope_not_the_l1_scan(self):
        """An L3 GuardDog call has no L1 scan anywhere near it, yet used to be
        capped by the L1 scan's envelope. The two are different quantities."""
        _set_mem(64 * GB, 32 * GB)
        self.assertNotEqual(rg.tool_container_envelope("supply_chain_analyzer"),
                            rg.scan_job_envelope("supply_chain"))


class TestImportMiningBudgets(SupplyChainGovBase):
    """SUPPLY_CHAIN_IMPORT_MAX_* were module-level os.environ reads, so
    apply_memory_governor (which only walks the settings dict) could never see
    them: two real in-memory accumulators outside the governor entirely."""

    def test_keys_are_registered_as_byte_budget_keys(self):
        # The table moved into recon_settings/registry.yaml; project_settings
        # queries it rather than holding a second copy.
        budget = ps._gov_budget_keys()
        self.assertIn('SUPPLY_CHAIN_IMPORT_MAX_FILES', budget)
        self.assertIn('SUPPLY_CHAIN_IMPORT_MAX_BYTES', budget)

    def test_keys_have_shipped_defaults(self):
        self.assertEqual(ps.DEFAULT_SETTINGS['SUPPLY_CHAIN_IMPORT_MAX_FILES'], 200)
        self.assertEqual(ps.DEFAULT_SETTINGS['SUPPLY_CHAIN_IMPORT_MAX_BYTES'],
                         64 * 1024 * 1024)

    def test_throttled_on_a_starved_host(self):
        _set_mem(32 * GB, 32 * 1024 ** 2)
        out = ps.apply_memory_governor({
            'SUPPLY_CHAIN_IMPORT_MAX_FILES': 200,
            'SUPPLY_CHAIN_IMPORT_MAX_BYTES': 64 * 1024 * 1024,
        })
        self.assertLess(out['SUPPLY_CHAIN_IMPORT_MAX_FILES'], 200)
        self.assertLess(out['SUPPLY_CHAIN_IMPORT_MAX_BYTES'], 64 * 1024 * 1024)

    def test_byte_cap_keeps_a_usable_floor(self):
        # Throttled to nothing, import mining would silently harvest zero
        # packages and read as "target has no dependencies".
        # 16 MB available -> budget 1.6 MB, below the 4 MB floor, so the floor bites.
        _set_mem(32 * GB, 16 * 1024 ** 2)
        out = ps.apply_memory_governor({'SUPPLY_CHAIN_IMPORT_MAX_BYTES': 64 * 1024 * 1024})
        self.assertEqual(out['SUPPLY_CHAIN_IMPORT_MAX_BYTES'], 4 * 1024 * 1024)

    def test_full_value_survives_on_a_roomy_host(self):
        _set_mem(64 * GB, 48 * GB)
        out = ps.apply_memory_governor({
            'SUPPLY_CHAIN_IMPORT_MAX_FILES': 200,
            'SUPPLY_CHAIN_IMPORT_MAX_BYTES': 64 * 1024 * 1024,
        })
        self.assertEqual(out['SUPPLY_CHAIN_IMPORT_MAX_FILES'], 200)
        self.assertEqual(out['SUPPLY_CHAIN_IMPORT_MAX_BYTES'], 64 * 1024 * 1024)


class TestImportBudgetIsActuallyUsed(SupplyChainGovBase):
    """Registering the keys is half the job: the miner has to READ the governed
    value instead of its module-level constant, or the throttle is decorative."""

    def _module(self):
        sys.path.insert(0, os.path.join(ROOT, 'recon'))
        from main_recon_modules import supply_chain_recon as scr
        return scr

    def test_governed_settings_win_over_module_defaults(self):
        scr = self._module()
        files, byts = scr._import_budget({'SUPPLY_CHAIN_IMPORT_MAX_FILES': 7,
                                          'SUPPLY_CHAIN_IMPORT_MAX_BYTES': 1234})
        self.assertEqual((files, byts), (7, 1234))

    def test_missing_settings_fall_back_to_module_defaults(self):
        scr = self._module()
        self.assertEqual(scr._import_budget(None),
                         (scr._IMPORT_MAX_FILES, scr._IMPORT_MAX_BYTES))

    def test_bogus_settings_cannot_disable_the_cap(self):
        # A 0 / negative / bool value must not read as "unlimited": these caps
        # bound attacker-controlled text held in the recon process.
        scr = self._module()
        for bad in (0, -1, True, "200", None):
            files, byts = scr._import_budget({'SUPPLY_CHAIN_IMPORT_MAX_FILES': bad,
                                              'SUPPLY_CHAIN_IMPORT_MAX_BYTES': bad})
            self.assertEqual(files, scr._IMPORT_MAX_FILES)
            self.assertEqual(byts, scr._IMPORT_MAX_BYTES)

    def test_reader_honours_the_budget(self):
        import tempfile
        scr = self._module()
        work = tempfile.mkdtemp()
        self.addCleanup(__import__('shutil').rmtree, work, True)
        for i in range(5):
            with open(os.path.join(work, f"a{i}.js"), "w") as fh:
                fh.write("import 'lodash';")
        combined = {"js_recon": {"work_dir": work}}
        self.assertEqual(len(scr._read_js_contents(combined, {'SUPPLY_CHAIN_IMPORT_MAX_FILES': 2})), 2)
        self.assertEqual(len(scr._read_js_contents(combined, None)), 5)


class TestBlankEnvIsUnset(unittest.TestCase):
    """analyzer_dispatch's module constants are resolved at import, and the
    orchestrator now forwards the analyzer knobs into the containers this module
    runs in. Forwarding is filtered to keys the operator actually set, but the
    module is also imported in the orchestrator itself, where compose delivers
    every optional knob as an EMPTY STRING (`VAR: ${VAR:-}`). A plain
    os.environ.get would then bind an empty image name and an empty --network -
    a `docker run --network '' ''` at the first analyzer job."""

    def test_blank_is_treated_as_unset(self):
        with unittest.mock.patch.dict(os.environ, {"X_SC_KNOB": ""}):
            self.assertEqual(ad._env("X_SC_KNOB", "default"), "default")
        with unittest.mock.patch.dict(os.environ, {"X_SC_KNOB": "\t "}):
            self.assertEqual(ad._env("X_SC_KNOB", "default"), "default")

    def test_set_value_wins_and_is_stripped(self):
        with unittest.mock.patch.dict(os.environ, {"X_SC_KNOB": " custom "}):
            self.assertEqual(ad._env("X_SC_KNOB", "default"), "custom")

    def test_module_constants_are_never_empty(self):
        """Whatever the environment looked like at import, these must hold a
        usable value: they go straight into the docker argv."""
        self.assertTrue(ad.ANALYZER_IMAGE.strip())
        self.assertTrue(ad.ANALYZER_NETWORK.strip())
        self.assertTrue(str(ad._DEFAULT_PIDS).strip())
        int(ad._DEFAULT_PIDS)  # must stay parseable as a pids-limit

    def test_constants_survive_a_blank_environment_at_import(self):
        blank = {k: "" for k in ("SUPPLY_CHAIN_ANALYZER_IMAGE",
                                 "SUPPLY_CHAIN_ANALYZER_NETWORK",
                                 "SUPPLY_CHAIN_ANALYZER_PIDS")}
        with unittest.mock.patch.dict(os.environ, blank):
            reimported = importlib.reload(ad)
            try:
                self.assertEqual(reimported.ANALYZER_IMAGE,
                                 "redamon-supply-chain-analyzer:latest")
                self.assertEqual(reimported.ANALYZER_NETWORK, "redamon-supply-chain-net")
                self.assertEqual(reimported._DEFAULT_PIDS, "512")
            finally:
                importlib.reload(ad)  # restore the shared module for other tests


if __name__ == '__main__':
    unittest.main()
