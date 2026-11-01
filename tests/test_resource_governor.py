"""Unit tests for graph_db/resource_governor.py (dual-cap memory governor).

Pure-stdlib, host-runnable: injects synthetic memory via set_mem_override so it
never depends on the real host. Run: python3 -m unittest tests.test_resource_governor
"""
import importlib.util
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(__file__), '..')


def _load_governor(pkg_dir, mod_name):
    """Load one copy of the governor by explicit path, under a UNIQUE module name.

    There are two maintained copies (graph_db and recon_orchestrator) and three test
    modules that `import resource_governor` after putting a DIFFERENT directory on
    sys.path. Whichever ran first won the `sys.modules` slot for the whole process,
    so in a combined run this file silently tested the recon_orchestrator twin and
    the drift test compared that copy against itself. Loading by path pins it.
    Bypasses graph_db/__init__.py, which pulls in neo4j.
    """
    path = os.path.join(ROOT, pkg_dir, 'resource_governor.py')
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


g = _load_governor('graph_db', '_graphdb_resource_governor')

GB = 1024 ** 3
_F = g._FALLBACK_PROFILE


class GovernorTestBase(unittest.TestCase):
    def setUp(self):
        # Clean, deterministic env for every test.
        for k in ("REDAMON_MEM_GOVERNOR", "MEM_SCALE_HIGH", "MEM_SCALE_LOW",
                  "MEM_SCALE_FLOOR", "MEM_BUDGET_FRACTION", "MEM_SAFETY_TOLERANCE",
                  "MEM_READ_TTL_S", "RESOURCE_PROFILE_PATH",
                  "RESOURCE_PROFILE_DEFAULT_PATH"):
            os.environ.pop(k, None)
        g.set_mem_override(None, None)
        g.reset_profile_cache()
        g._cpu_last = None

    def tearDown(self):
        g.set_mem_override(None, None)
        g.reset_profile_cache()


class TestScale(GovernorTestBase):
    def test_full_scale_when_ample(self):
        g.set_mem_override(32 * GB, 20 * GB)  # ratio 0.625 >= HIGH 0.5
        self.assertEqual(g.scale(), 1.0)

    def test_floor_when_starved(self):
        g.set_mem_override(32 * GB, 2 * GB)  # ratio 0.0625 <= LOW 0.15
        self.assertAlmostEqual(g.scale(), 0.15, places=6)

    def test_linear_ramp_midband(self):
        # ratio exactly halfway between LOW(0.15) and HIGH(0.50) -> 0.325
        g.set_mem_override(100 * GB, 32.5 * GB)  # ratio 0.325
        s = g.scale()
        # frac=0.5 -> floor + 0.5*(1-floor) = 0.15 + 0.425 = 0.575
        self.assertAlmostEqual(s, 0.575, places=3)

    def test_monotonic_in_available(self):
        prev = -1.0
        for avail_gb in range(1, 33):
            g.set_mem_override(32 * GB, avail_gb * GB)
            s = g.scale()
            self.assertGreaterEqual(s, prev)
            prev = s

    def test_disabled_is_full(self):
        os.environ["REDAMON_MEM_GOVERNOR"] = "false"
        g.set_mem_override(32 * GB, 1 * GB)
        self.assertEqual(g.scale(), 1.0)

    def test_fail_open_when_unreadable(self):
        g.set_mem_override(None, None)
        orig = g._MEMINFO_PATH
        g._MEMINFO_PATH = "/proc/does-not-exist-xyz"
        g._mem_cache = None
        try:
            self.assertEqual(g.scale(), 1.0)  # fail open
            self.assertIsNone(g.read_mem())
        finally:
            g._MEMINFO_PATH = orig
            g._mem_cache = None


class TestScaled(GovernorTestBase):
    def test_never_exceeds_env(self):
        g.set_mem_override(32 * GB, 32 * GB)  # scale 1.0
        self.assertEqual(g.scaled(8, floor=1), 8)

    def test_reduces_under_pressure(self):
        g.set_mem_override(32 * GB, 2 * GB)  # scale 0.15
        # round(8 * 0.15) = round(1.2) = 1
        self.assertEqual(g.scaled(8, floor=1), 1)

    def test_respects_floor(self):
        g.set_mem_override(32 * GB, 2 * GB)  # scale 0.15
        self.assertEqual(g.scaled(8, floor=3), 3)

    def test_floor_capped_to_value(self):
        g.set_mem_override(32 * GB, 2 * GB)
        self.assertEqual(g.scaled(2, floor=10), 2)  # floor can't exceed value

    def test_zero_or_negative_passthrough(self):
        g.set_mem_override(32 * GB, 2 * GB)
        self.assertEqual(g.scaled(0), 0)

    def test_disabled_passthrough(self):
        os.environ["REDAMON_MEM_GOVERNOR"] = "0"
        g.set_mem_override(32 * GB, 1 * GB)
        self.assertEqual(g.scaled(50, floor=1), 50)


class TestScaledCap(GovernorTestBase):
    def test_fits_returns_env(self):
        # 2GB avail, 10% budget = ~214MB, /500 = ~429k >= 300k -> env
        g.set_mem_override(32 * GB, 2 * GB)
        self.assertEqual(g.scaled_cap(300000, 500, 0.10, 1000), 300000)

    def test_caps_when_tight(self):
        # 512MB avail, 10% = ~53.6MB, /500 = 107374 < 300000
        g.set_mem_override(32 * GB, 512 * 1024 * 1024)
        self.assertEqual(g.scaled_cap(300000, 500, 0.10, 1000), 107374)

    def test_never_exceeds_env_cap(self):
        g.set_mem_override(64 * GB, 64 * GB)
        self.assertEqual(g.scaled_cap(1000, 1, 0.10, 1), 1000)

    def test_respects_floor(self):
        g.set_mem_override(32 * GB, 1024)  # almost nothing free
        self.assertEqual(g.scaled_cap(300000, 500, 0.10, 1000), 1000)

    def test_bad_bytes_fail_open(self):
        g.set_mem_override(32 * GB, 512 * 1024 * 1024)
        self.assertEqual(g.scaled_cap(300000, 0, 0.10, 1000), 300000)
        self.assertEqual(g.scaled_cap(300000, -5, 0.10, 1000), 300000)

    def test_disabled_returns_env(self):
        os.environ["REDAMON_MEM_GOVERNOR"] = "false"
        g.set_mem_override(32 * GB, 512 * 1024 * 1024)
        self.assertEqual(g.scaled_cap(300000, 500, 0.10, 1000), 300000)


class TestPressure(GovernorTestBase):
    def test_ok(self):
        g.set_mem_override(32 * GB, 20 * GB)
        self.assertEqual(g.pressure(), "ok")

    def test_warn(self):
        g.set_mem_override(32 * GB, 10 * GB)  # ratio 0.3125 between LOW and HIGH
        self.assertEqual(g.pressure(), "warn")

    def test_critical(self):
        g.set_mem_override(32 * GB, 2 * GB)  # ratio 0.0625 <= LOW
        self.assertEqual(g.pressure(), "critical")


class TestMeminfoParser(GovernorTestBase):
    def test_parse_ok(self):
        text = "MemTotal:       32501176 kB\nMemFree: 100 kB\nMemAvailable:   21275704 kB\n"
        parsed = g._parse_meminfo(text)
        self.assertEqual(parsed, (32501176 * 1024, 21275704 * 1024))

    def test_parse_missing_available(self):
        self.assertIsNone(g._parse_meminfo("MemTotal: 100 kB\n"))

    def test_parse_garbage(self):
        self.assertIsNone(g._parse_meminfo("not meminfo at all"))


class TestCpu(GovernorTestBase):
    def test_first_call_zero(self):
        g._cpu_last = None
        # may read real /proc/stat; first call must be 0.0 regardless
        self.assertEqual(g.cpu_percent(), 0.0)

    def test_cores_positive(self):
        self.assertGreaterEqual(g.cpu_cores(), 1)


class TestProfile(GovernorTestBase):
    def test_fallback_used_when_no_file(self):
        os.environ["RESOURCE_PROFILE_PATH"] = "/tmp/nonexistent-profile-xyz.json"
        g.reset_profile_cache()
        self.assertEqual(g.bytes_per_unit("url"), 600)
        self.assertGreater(g.tool_container_envelope("katana"), 0)
        self.assertGreater(g.envelope("agent_session_envelope_bytes"), 0)

    def test_envelope_zero_profile_falls_back(self):
        import json
        import tempfile
        # A measured 0 (bad/rounded-to-zero) must NOT be used verbatim.
        prof = {"agent_session_envelope_bytes": 0}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(prof, fh)
            path = fh.name
        try:
            os.environ["RESOURCE_PROFILE_PATH"] = path
            g.reset_profile_cache()
            self.assertGreater(g.envelope("agent_session_envelope_bytes"), 0)
        finally:
            os.unlink(path)

    def test_measured_overrides_fallback(self):
        import json
        import tempfile
        prof = {"bytes_per_unit": {"url": 375}, "agent_session_envelope_bytes": 999}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(prof, fh)
            path = fh.name
        try:
            os.environ["RESOURCE_PROFILE_PATH"] = path
            g.reset_profile_cache()
            self.assertEqual(g.bytes_per_unit("url"), 375)          # overridden
            self.assertEqual(g.bytes_per_unit("js_file"), 65536)    # fallback kept
            self.assertEqual(g.envelope("agent_session_envelope_bytes"), 999)
        finally:
            os.unlink(path)


class TestParseSize(GovernorTestBase):
    def test_suffixes(self):
        self.assertEqual(g.parse_size("2g"), 2 * GB)
        self.assertEqual(g.parse_size("512m"), 512 * 1024 * 1024)
        self.assertEqual(g.parse_size("1024k"), 1024 * 1024)
        self.assertEqual(g.parse_size("123"), 123)

    def test_b_suffix_and_case(self):
        self.assertEqual(g.parse_size("512MB"), 512 * 1024 * 1024)
        self.assertEqual(g.parse_size(" 2G "), 2 * GB)

    def test_invalid(self):
        self.assertIsNone(g.parse_size(""))
        self.assertIsNone(g.parse_size(None))
        self.assertIsNone(g.parse_size("abc"))
        self.assertIsNone(g.parse_size("-5g"))

    def test_env_bytes(self):
        os.environ["SOME_MEM"] = "3g"
        self.assertEqual(g.env_bytes("SOME_MEM", 1 * GB), 3 * GB)
        os.environ.pop("SOME_MEM", None)
        self.assertEqual(g.env_bytes("SOME_MEM", 1 * GB), 1 * GB)
        os.environ["SOME_MEM"] = ""
        self.assertEqual(g.env_bytes("SOME_MEM", 1 * GB), 1 * GB)
        os.environ.pop("SOME_MEM", None)


class TestCapLogging(GovernorTestBase):
    def test_scaled_logged_emits_only_on_reduce(self):
        g.set_mem_override(32 * GB, 2 * GB)  # scale 0.15 -> reduces
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = g.scaled_logged(8, 1, "katana", "KATANA_PARALLELISM")
        self.assertEqual(out, 1)
        self.assertIn(g.RESOURCE_CAP_MARKER, buf.getvalue())
        self.assertIn("KATANA_PARALLELISM", buf.getvalue())

    def test_scaled_logged_silent_when_ample(self):
        g.set_mem_override(32 * GB, 32 * GB)  # scale 1.0 -> no reduction
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = g.scaled_logged(8, 1, "katana", "KATANA_PARALLELISM")
        self.assertEqual(out, 8)
        self.assertNotIn(g.RESOURCE_CAP_MARKER, buf.getvalue())

    def test_budget_logged_emits_on_cap(self):
        g.set_mem_override(32 * GB, 512 * 1024 * 1024)
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = g.budget_logged(300000, 500, "katana", "KATANA_MAX_URLS", 1000, 0.10)
        self.assertLess(out, 300000)
        self.assertIn(g.RESOURCE_CAP_MARKER, buf.getvalue())
        self.assertIn("KATANA_MAX_URLS", buf.getvalue())

    def test_budget_logged_silent_when_fits(self):
        g.set_mem_override(64 * GB, 40 * GB)
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = g.budget_logged(300000, 500, "katana", "KATANA_MAX_URLS", 1000, 0.10)
        self.assertEqual(out, 300000)
        self.assertNotIn(g.RESOURCE_CAP_MARKER, buf.getvalue())


class TestScanJobEnvelopes(GovernorTestBase):
    """Per-scan-type envelopes. One 4 GB number for every scan type made small
    hosts unable to admit ANY scan (an 8 GB box needs envelope + OS headroom free),
    so each type now carries its own figure in three places that must not drift."""

    SCAN_TYPES = ("full_recon", "partial_recon", "ai_attack", "gvm",
                  "github_hunt", "trufflehog", "supply_chain",
                  "partial_recon:SupplyChainRecon", "codefix")

    def test_every_scan_type_has_its_own_fallback(self):
        env = g._FALLBACK_PROFILE["scan_job_envelope_bytes"]
        for kind in self.SCAN_TYPES:
            self.assertIn(kind, env, f"{kind} would silently use _default")
            self.assertGreater(env[kind], 0)
            # Must stay under the old blanket 4 GB, or the small-host fix is undone.
            self.assertLess(env[kind], 4 * GB, f"{kind} envelope is back to worst-case")

    def test_partial_recon_is_cheaper_than_full(self):
        # A single discovery step must never be charged like a dozen-tool pipeline.
        self.assertLess(g.scan_job_envelope("partial_recon"),
                        g.scan_job_envelope("full_recon"))

    def test_unknown_type_uses_default(self):
        env = g._FALLBACK_PROFILE["scan_job_envelope_bytes"]
        self.assertEqual(g.scan_job_envelope("not_a_real_scan_type"), env["_default"])

    def test_shipped_default_json_matches_builtin_fallback(self):
        """resource_profile.default.json (git-tracked) and _FALLBACK_PROFILE are two
        copies of the same numbers on purpose (the file can be missing). Drift here
        means a host with the file behaves differently from one without it."""
        import json
        path = os.path.join(ROOT, 'recon_orchestrator', 'resource_profile.default.json')
        with open(path) as fh:
            shipped = json.load(fh)
        self.assertEqual(shipped["scan_job_envelope_bytes"],
                         g._FALLBACK_PROFILE["scan_job_envelope_bytes"])
        # Same contract for the SIBLING-tool table: the dirty supply-chain
        # analyzer is sized from it on all three of its spawn paths.
        self.assertEqual(shipped["tool_container_envelope_bytes"],
                         g._FALLBACK_PROFILE["tool_container_envelope_bytes"])

    def test_supply_chain_covers_its_analyzer_sibling(self):
        """The L1 scan dispatches the dirty analyzer, so its envelope must be
        larger than the analyzer alone. The original 900 MB was SMALLER, which
        meant a deep L1 scan reserved less than one of its own containers."""
        env = g._FALLBACK_PROFILE["scan_job_envelope_bytes"]
        analyzer = g.tool_container_envelope("supply_chain_analyzer")
        self.assertGreater(env["supply_chain"], analyzer)
        self.assertGreater(env["partial_recon:SupplyChainRecon"], analyzer)

    def test_supply_chain_partial_costs_more_than_a_plain_partial(self):
        # It re-runs the JS fetch AND spawns the analyzer; charging it the
        # generic single-step envelope under-reserved it by ~3x.
        self.assertGreater(g.scan_job_envelope("partial_recon:SupplyChainRecon"),
                           g.scan_job_envelope("partial_recon"))

    def test_unknown_tool_falls_back_to_its_base_kind_not_default(self):
        """A tool-qualified key with no entry must inherit its FAMILY's envelope.
        Falling through to _default would silently promote every ordinary partial
        from 768 MB to the 2 GB unknown-type figure and starve small hosts."""
        self.assertEqual(g.scan_job_envelope("partial_recon:Naabu"),
                         g.scan_job_envelope("partial_recon"))
        self.assertNotEqual(g.scan_job_envelope("partial_recon:Naabu"),
                            g._FALLBACK_PROFILE["scan_job_envelope_bytes"]["_default"])

    def test_qualified_envelope_is_floored_at_its_base_kind(self):
        """REGRESSION. A tool-qualified job is its base kind PLUS extra work, so it
        can never legitimately reserve less. Calibration raises measured envelopes,
        and once a measured `partial_recon` exceeded the shipped
        `partial_recon:SupplyChainRecon`, the heavier job reserved LESS than the
        lighter one - an under-reservation visible only on calibrated hosts."""
        import json
        import tempfile
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"scan_job_envelope_bytes": {"partial_recon": 3 * GB}}, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        os.environ["RESOURCE_PROFILE_PATH"] = fh.name
        g.reset_profile_cache()
        self.assertGreaterEqual(g.scan_job_envelope("partial_recon:SupplyChainRecon"),
                                g.scan_job_envelope("partial_recon"))

    def test_qualified_envelope_still_wins_when_it_is_larger(self):
        # The floor must not flatten a genuinely larger qualified value onto base.
        self.assertGreater(g.scan_job_envelope("partial_recon:SupplyChainRecon"),
                           g.scan_job_envelope("partial_recon"))

    def test_a_measured_qualified_value_is_honoured(self):
        import json
        import tempfile
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"scan_job_envelope_bytes":
                   {"partial_recon:SupplyChainRecon": 3 * GB}}, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        os.environ["RESOURCE_PROFILE_PATH"] = fh.name
        g.reset_profile_cache()
        self.assertEqual(g.scan_job_envelope("partial_recon:SupplyChainRecon"), 3 * GB)

    def test_qualified_key_with_extra_colons_uses_the_first_segment(self):
        # tool_id is caller-supplied; a colon in it must not derail the base lookup.
        self.assertEqual(g.scan_job_envelope("partial_recon:Weird:Tool:v2"),
                         g.scan_job_envelope("partial_recon"))

    def test_unknown_base_kind_still_reaches_default(self):
        self.assertEqual(g.scan_job_envelope("not_a_kind:SomeTool"),
                         g._FALLBACK_PROFILE["scan_job_envelope_bytes"]["_default"])

    def test_byte_family_is_identity(self):
        """SUPPLY_CHAIN_IMPORT_MAX_BYTES is already in bytes. Without an explicit
        'byte' family it would hit the 1024 default and be budgeted as if each
        byte cost a kilobyte, throttling a 64 MB cap to nothing."""
        self.assertEqual(g.bytes_per_unit("byte"), 1)

    def test_module_under_test_is_the_graph_db_copy(self):
        # Guards the fix above: if sys.modules ordering ever hijacks this module
        # again, every test in this file would silently exercise the wrong file.
        self.assertIn(os.path.join('graph_db', 'resource_governor.py'), g.__file__)

    def test_orchestrator_governor_copy_agrees(self):
        """graph_db/resource_governor.py (this module) and its recon_orchestrator
        twin are maintained copies; the envelope tables must match."""
        orch = _load_governor('recon_orchestrator', '_orch_resource_governor')
        self.assertNotEqual(orch.__file__, g.__file__, "not comparing two real copies")
        self.assertEqual(orch._FALLBACK_PROFILE["scan_job_envelope_bytes"],
                         g._FALLBACK_PROFILE["scan_job_envelope_bytes"])
        # The whole fallback table, not just the envelopes: the copies must not
        # diverge on bytes_per_unit or the agent/session envelopes either.
        self.assertEqual(orch._FALLBACK_PROFILE, g._FALLBACK_PROFILE)


class TestContainerCap(GovernorTestBase):
    """container_cap(): the hard per-container mem_limit derived from an envelope.

    It lives in the governor rather than in container_manager because THREE
    processes spawn capped containers and only one of them can import the
    orchestrator. When the clamp lived only there, supply_chain_common hardcoded
    a "1500m" literal that never shrank under pressure.
    """

    def setUp(self):
        super().setUp()
        for k in ("CONTAINER_CAP_HEADROOM", "PER_CONTAINER_MAX"):
            os.environ.pop(k, None)

    tearDown_env = ("CONTAINER_CAP_HEADROOM", "PER_CONTAINER_MAX")

    def tearDown(self):
        for k in self.tearDown_env:
            os.environ.pop(k, None)
        super().tearDown()

    def test_applies_headroom_over_the_envelope(self):
        g.set_mem_override(64 * GB, 32 * GB)   # PER_CONTAINER_MAX ~35 GB, no clamp
        self.assertEqual(g.container_cap(1 * GB), int(1 * GB * 1.5))

    def test_headroom_is_configurable(self):
        g.set_mem_override(64 * GB, 32 * GB)
        os.environ["CONTAINER_CAP_HEADROOM"] = "2.0"
        self.assertEqual(g.container_cap(1 * GB), 2 * GB)

    def test_headroom_below_one_is_ignored(self):
        # A cap BELOW the expected peak would OOM-kill every normal run.
        g.set_mem_override(64 * GB, 32 * GB)
        os.environ["CONTAINER_CAP_HEADROOM"] = "0.5"
        self.assertEqual(g.container_cap(1 * GB), 1 * GB)

    def test_clamped_by_per_container_max(self):
        # Ceiling sits between the envelope and envelope x headroom, so it bites.
        g.set_mem_override(64 * GB, 32 * GB)
        os.environ["PER_CONTAINER_MAX"] = "1200m"
        self.assertEqual(g.container_cap(1 * GB), 1200 * 1024 ** 2)

    def test_never_sized_below_the_envelope(self):
        # Even an absurdly low PER_CONTAINER_MAX must not produce a cap under the
        # expected peak: admission would already have refused such a host, and a
        # too-tight cap turns a normal run into an exit-137 mystery.
        g.set_mem_override(64 * GB, 32 * GB)
        os.environ["PER_CONTAINER_MAX"] = "100m"
        self.assertEqual(g.container_cap(3 * GB), 3 * GB)

    def test_floors_at_512mb(self):
        g.set_mem_override(64 * GB, 32 * GB)
        self.assertEqual(g.container_cap(1024), 512 * 1024 ** 2)

    def test_fails_open_when_governor_disabled(self):
        os.environ["REDAMON_MEM_GOVERNOR"] = "off"
        self.assertIsNone(g.container_cap(1 * GB))

    def test_none_for_unusable_envelope(self):
        g.set_mem_override(64 * GB, 32 * GB)
        self.assertIsNone(g.container_cap(0))
        self.assertIsNone(g.container_cap(-1))

    def test_analyzer_cap_reproduces_the_literal_it_replaced(self):
        """The hardcoded value was 1500m. The envelope (1 GB) x headroom (1.5)
        must land in the same neighbourhood, or swapping the literal for the
        governor would silently re-size a security-sensitive sandbox."""
        g.set_mem_override(64 * GB, 32 * GB)
        cap = g.container_cap(g.tool_container_envelope("supply_chain_analyzer"))
        self.assertGreaterEqual(cap, 1_500_000_000)
        self.assertLess(cap, 2 * GB)

    def test_shrinks_on_a_starved_host(self):
        """The whole point of routing the analyzer through the governor: on a
        small host PER_CONTAINER_MAX (55% of total) pulls the cap down, which the
        fixed literal never did."""
        g.set_mem_override(2 * GB, 512 * 1024 ** 2)
        cap = g.container_cap(g.tool_container_envelope("supply_chain_analyzer"))
        self.assertLess(cap, 1_500_000_000)


class TestProfileLayering(GovernorTestBase):
    """fallback < shipped default < host-specific (measured) profile."""

    def _write(self, obj):
        import json
        import tempfile
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(obj, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_default_layer_applies_when_no_host_profile(self):
        default_path = self._write({"scan_job_envelope_bytes": {"partial_recon": 111}})
        os.environ["RESOURCE_PROFILE_DEFAULT_PATH"] = default_path
        os.environ["RESOURCE_PROFILE_PATH"] = "/tmp/nonexistent-profile-xyz.json"
        g.reset_profile_cache()
        self.assertEqual(g.scan_job_envelope("partial_recon"), 111)

    def test_host_profile_wins_over_default_layer(self):
        default_path = self._write({"scan_job_envelope_bytes": {"partial_recon": 111,
                                                                "gvm": 222}})
        host_path = self._write({"scan_job_envelope_bytes": {"partial_recon": 999}})
        os.environ["RESOURCE_PROFILE_DEFAULT_PATH"] = default_path
        os.environ["RESOURCE_PROFILE_PATH"] = host_path
        g.reset_profile_cache()
        self.assertEqual(g.scan_job_envelope("partial_recon"), 999)  # measured wins
        self.assertEqual(g.scan_job_envelope("gvm"), 222)            # default kept
        # A partial host profile must not wipe types it never measured.
        self.assertEqual(g.scan_job_envelope("full_recon"),
                         g._FALLBACK_PROFILE["scan_job_envelope_bytes"]["full_recon"])

    def test_corrupt_layer_degrades_instead_of_breaking(self):
        import tempfile
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        fh.write("{ not json at all")
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        os.environ["RESOURCE_PROFILE_DEFAULT_PATH"] = fh.name
        os.environ["RESOURCE_PROFILE_PATH"] = fh.name
        g.reset_profile_cache()
        self.assertEqual(g.scan_job_envelope("partial_recon"),
                         g._FALLBACK_PROFILE["scan_job_envelope_bytes"]["partial_recon"])


class TestProfileRobustness(GovernorTestBase):
    """A profile file is now SHIPPED and documented as tunable, so hand edits are
    expected. Every malformed shape must fail SOFT (fall back), never crash the
    caller and never yield a zero/negative envelope, which would admit every scan."""

    def _profile(self, obj):
        import json
        import tempfile
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(obj, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        os.environ["RESOURCE_PROFILE_PATH"] = fh.name
        g.reset_profile_cache()

    def test_docker_style_size_string_accepted(self):
        # The env knobs take '768m'; a hand-edited profile must not crash on it.
        self._profile({"scan_job_envelope_bytes": {"partial_recon": "768m"}})
        self.assertEqual(g.scan_job_envelope("partial_recon"), 768 * 1024 ** 2)

    def test_scalar_where_a_map_belongs_is_ignored(self):
        # Would previously raise AttributeError out of admission -> 500 on start.
        self._profile({"scan_job_envelope_bytes": 12345, "bytes_per_unit": 5})
        self.assertEqual(g.scan_job_envelope("partial_recon"),
                         g._FALLBACK_PROFILE["scan_job_envelope_bytes"]["partial_recon"])
        self.assertEqual(g.bytes_per_unit("url"), 600)

    def test_unusable_values_never_produce_a_free_pass(self):
        # A 0/negative envelope sails through admission and admits every scan.
        for bad in (0, -1, -5_000_000, None, "lots", "-5g", True, [1, 2], {"a": 1}):
            with self.subTest(bad=bad):
                self._profile({"scan_job_envelope_bytes": {"partial_recon": bad}})
                self.assertGreater(g.scan_job_envelope("partial_recon"), 0)

    def test_bad_tool_envelope_falls_back(self):
        self._profile({"tool_container_envelope_bytes": {"naabu": -1}})
        self.assertGreater(g.tool_container_envelope("naabu"), 0)

    def test_bad_scalar_envelope_falls_back(self):
        self._profile({"agent_session_envelope_bytes": "not a size"})
        self.assertEqual(g.envelope("agent_session_envelope_bytes"),
                         _F["agent_session_envelope_bytes"])

    def test_unknown_scalar_key_still_returns_zero(self):
        # Pre-existing contract for a key nobody defines.
        self._profile({})
        self.assertEqual(g.envelope("no_such_envelope_bytes"), 0)

    def test_partial_layer_does_not_erase_sibling_types(self):
        self._profile({"scan_job_envelope_bytes": {"full_recon": 111}})
        self.assertEqual(g.scan_job_envelope("full_recon"), 111)
        for kind in ("partial_recon", "gvm", "ai_attack", "github_hunt", "trufflehog"):
            self.assertEqual(g.scan_job_envelope(kind),
                             _F["scan_job_envelope_bytes"][kind], kind)

    def test_fallback_table_is_never_mutated_by_a_layer(self):
        before = dict(_F["scan_job_envelope_bytes"])
        self._profile({"scan_job_envelope_bytes": {"partial_recon": 42}})
        g.scan_job_envelope("partial_recon")
        self.assertEqual(_F["scan_job_envelope_bytes"], before)



class TestJsReconTruffleHogEnvelopes(GovernorTestBase):
    """JS Recon's TruffleHog sidecar has its own tool envelope (the image is
    shared with the Secret Multiscanner, whose scans are sized separately), and
    a JS Recon partial reserves for the step plus that sidecar."""

    def test_the_sidecar_envelope_and_its_cap(self):
        self.assertEqual(g.tool_container_envelope("trufflehog_js"), 768 * 1024 ** 2)
        self.assertEqual(g.container_cap(g.tool_container_envelope("trufflehog_js")),
                         int(768 * 1024 ** 2 * 1.5))

    def test_a_js_recon_partial_reserves_more_than_a_plain_partial(self):
        self.assertEqual(g.scan_job_envelope("partial_recon:JsRecon"), int(1.5 * GB))
        self.assertGreater(g.scan_job_envelope("partial_recon:JsRecon"), g.scan_job_envelope("partial_recon"))


if __name__ == "__main__":
    unittest.main()
