"""
R-42: stealth mode and an excluded denial-of-service test keep graphql-cop off.

The pinned image (`dolevf/graphql-cop:1.14`) has no `-e` flag, so a per-test
toggle only filters graphql-cop's REPORT: the alias-overloading, batch,
directive-overloading and circular-introspection probes still reached the
target. Two controls replace that:

  * the stealth profile switches graphql-cop off (`graphqlCopEnabled`), and
  * `run_graphql_cop` builds no command at all while any of those four tests
    is excluded, whatever stealth says.

Both are a configuration choice, not a failure, so nothing is recorded as
degraded: graphql-cop's earlier findings are pruned as for any source that is
switched off (README "Degraded vs. switched off").

Run: python -m pytest recon/tests/test_graphql_cop_dos_skip.py -v
"""
from __future__ import annotations

from unittest import mock

import pytest

from recon import settings_registry as reg
from recon.graphql_scan import misconfig
from recon.graphql_scan.misconfig import HEAVY_TRAFFIC_TESTS, run_graphql_cop
from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides

ENDPOINT = "https://api.example.com/graphql"

DOS_TOGGLES = {
    "alias_overloading": "GRAPHQL_COP_TEST_ALIAS_OVERLOADING",
    "batch_query": "GRAPHQL_COP_TEST_BATCH_QUERY",
    "directive_overloading": "GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING",
    "circular_query_introspection": "GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION",
}


def _cop_settings(**over) -> dict:
    settings = dict(DEFAULT_SETTINGS)
    settings["GRAPHQL_COP_ENABLED"] = True
    settings.update(over)
    return settings


def _run(settings: dict):
    """Run the real wrapper with docker mocked; return (result, the built command or None)."""
    proc = mock.MagicMock(returncode=0, stdout="[]", stderr="")
    with mock.patch.object(misconfig.subprocess, "run", return_value=proc) as srun:
        out = run_graphql_cop(ENDPOINT, {}, settings)
    return out, (srun.call_args[0][0] if srun.called else None)


def test_the_toggle_table_covers_every_heavy_test():
    """A fifth DoS test added upstream must get a toggle here and a skip there."""
    assert set(DOS_TOGGLES) == set(HEAVY_TRAFFIC_TESTS)


# --- the stealth profile ------------------------------------------------------------------

def test_the_registry_switches_graphql_cop_off_in_stealth():
    assert reg.stealth_profile().get("GRAPHQL_COP_ENABLED") == {"set": False}


def test_stealth_mode_resolves_graphql_cop_off_even_when_the_project_turned_it_on():
    resolved = apply_stealth_overrides(_cop_settings(STEALTH_MODE=True))
    assert resolved["GRAPHQL_COP_ENABLED"] is False


def test_without_stealth_the_project_choice_stands():
    resolved = apply_stealth_overrides(_cop_settings(STEALTH_MODE=False))
    assert resolved["GRAPHQL_COP_ENABLED"] is True


def test_a_stealth_project_never_starts_a_graphql_cop_container():
    """The whole path: stealth profile, then the wrapper. No docker run."""
    out, cmd = _run(apply_stealth_overrides(_cop_settings(STEALTH_MODE=True)))
    assert cmd is None
    assert out is None


# --- the run-time skip ----------------------------------------------------------------------

@pytest.mark.parametrize("test_key", sorted(DOS_TOGGLES))
def test_any_excluded_dos_test_builds_no_command(test_key):
    """The image cannot leave one test out, so excluding one leaves graphql-cop out."""
    out, cmd = _run(_cop_settings(**{DOS_TOGGLES[test_key]: False}))
    assert cmd is None, f"graphql-cop ran with {test_key} excluded: {cmd}"
    # None, not an empty result: the scanner then records no `graphql_cop_ran`
    # for an endpoint graphql-cop never touched.
    assert out is None


def test_the_skip_is_not_recorded_as_degraded():
    """Switched off by configuration: pruned normally, never kept as 'could not check'."""
    from recon.helpers import circuit_breaker as cb
    with mock.patch.object(cb, "note_degraded") as noted:
        _run(_cop_settings(GRAPHQL_COP_TEST_BATCH_QUERY=False))
    noted.assert_not_called()


def test_excluding_only_non_dos_tests_still_runs_graphql_cop():
    """The shipped default excludes introspection (the native check covers it); that must still run."""
    settings = _cop_settings(GRAPHQL_COP_TEST_INTROSPECTION=False, GRAPHQL_COP_TEST_GRAPHIQL=False)
    out, cmd = _run(settings)
    assert cmd is not None
    assert cmd[:4] == ["docker", "run", "--rm", "--net=host"]
    assert cmd[cmd.index("-t") + 1] == ENDPOINT
    assert "-e" not in cmd
    assert out == {"findings": [], "raw": []}


def test_the_shipped_defaults_run_graphql_cop_as_before():
    out, cmd = _run(_cop_settings())
    assert cmd is not None
    assert out == {"findings": [], "raw": []}


def test_the_scanner_records_no_cop_run_for_a_skipped_endpoint():
    """The call site: no findings, no capability flags and no `graphql_cop_ran`."""
    from recon.graphql_scan.scanner import test_single_endpoint

    settings = _cop_settings(GRAPHQL_INTROSPECTION_TEST=False, GRAPHQL_COP_TEST_ALIAS_OVERLOADING=False)
    with mock.patch.object(misconfig.subprocess, "run") as srun:
        res = test_single_endpoint(ENDPOINT, {}, 30, settings)
    srun.assert_not_called()
    assert res is not None
    assert "graphql_cop_ran" not in res["endpoint_data"]
    assert not [v for v in res["vulnerabilities"] if v.get("source") == "graphql_cop"]
