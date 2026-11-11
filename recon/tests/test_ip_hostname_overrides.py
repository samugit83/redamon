"""
Hostnames on target IPs: the settings the mode forces (design §9, decision D-20).

In IP mode tlsx never sends a PTR answer as SNI (no mode scans a name it did not
select), and ip_only also stops Shodan's reverse DNS and the graph names vhost/SNI
would try (I-7: ip_only sends nothing name-related). The stored toggle keeps its
value; the run ignores it, the tool's effective-settings dump says why, and the
webapp's copy of the table (webapp/src/lib/ipHostnameOverrides.ts, read by MCP
get_recon_settings) is held equal to the Python one here.

Run it inside the recon image, never with host pytest: `./redamon.sh test unit`, or this
one file from the repo root:
    docker run --rm -v "$PWD":/repo -w /repo/recon -e PYTHONPATH=/repo/recon:/repo -e HOME=/tmp \\
      --entrypoint python redamon-recon:latest \\
      /repo/tooling/scripts/pytest_isolated.py unit tests/test_ip_hostname_overrides.py
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from recon import project_settings as ps
from recon import settings_registry as reg
from recon.helpers.log_helpers import print_effective_settings

REPO = Path(__file__).resolve().parents[2]
TS_TABLE = REPO / "webapp" / "src" / "lib" / "ipHostnameOverrides.ts"

FORCEABLE = ("TLSX_REV_PTR_SNI", "SHODAN_REVERSE_DNS", "VHOST_SNI_USE_GRAPH_CANDIDATES")


def _all_on(**extra) -> dict:
    """Every forceable toggle switched ON, as an operator could store it."""
    return {**ps.DEFAULT_SETTINGS, **{k: True for k in FORCEABLE}, **extra}


# --- the pure pass -------------------------------------------------------------------

def test_domain_mode_forces_nothing():
    s = _all_on(IP_MODE=False, IP_HOSTNAME_MODE="ip_only")
    assert ps.ip_hostname_overrides(s) == {}
    assert ps.apply_ip_hostname_overrides(s) is s


def test_ip_only_forces_every_name_lookup_off():
    out = ps.apply_ip_hostname_overrides(_all_on(IP_MODE=True, IP_HOSTNAME_MODE="ip_only"))
    assert {k: out[k] for k in FORCEABLE} == dict.fromkeys(FORCEABLE, False)


@pytest.mark.parametrize("mode", ["record_only", "record_filter", "scan_all"])
def test_recording_modes_force_only_the_ptr_sni(mode):
    out = ps.apply_ip_hostname_overrides(_all_on(IP_MODE=True, IP_HOSTNAME_MODE=mode))
    assert out["TLSX_REV_PTR_SNI"] is False
    assert out["SHODAN_REVERSE_DNS"] is True
    assert out["VHOST_SNI_USE_GRAPH_CANDIDATES"] is True


@pytest.mark.parametrize("mode", ["", None, "bogus"])
def test_an_unknown_mode_gets_the_strictest_row(mode):
    assert ps.ip_hostname_overrides({"IP_MODE": True, "IP_HOSTNAME_MODE": mode}) == \
        ps._IP_HOSTNAME_FORCED["ip_only"]


def test_a_value_already_forced_is_kept_and_not_logged(caplog):
    s = {**ps.DEFAULT_SETTINGS, "IP_MODE": True, "IP_HOSTNAME_MODE": "record_only", "TLSX_REV_PTR_SNI": False}
    with caplog.at_level("INFO", logger=ps.logger.name):
        out = ps.apply_ip_hostname_overrides(s)
    assert out["TLSX_REV_PTR_SNI"] is False
    assert "forces TLSX_REV_PTR_SNI" not in caplog.text


def test_the_pass_is_pure():
    s = _all_on(IP_MODE=True, IP_HOSTNAME_MODE="ip_only")
    before = dict(s)
    out = ps.apply_ip_hostname_overrides(s)
    assert s == before and out is not s


def test_the_forced_table_never_turns_anything_on():
    """Every forced value removes a lookup or a name sent to a target, which is
    what lets the RoE cap and the memory governor run after it unchanged."""
    for mode, row in ps._IP_HOSTNAME_FORCED.items():
        assert set(row) <= set(FORCEABLE), mode
        assert all(v is False for v in row.values()), mode
    assert set(ps._IP_HOSTNAME_FORCED) == {"ip_only", "record_only", "record_filter", "scan_all"}


# --- through get_settings: stealth and the mode together ----------------------------

class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _resolved(**row) -> dict:
    payload = {"userId": "u1", "targetDomain": "", "ipMode": True, "targetIps": ["203.0.113.10"],
               "tlsxRevPtrSni": True, "shodanReverseDns": True, "vhostSniUseGraphCandidates": True,
               **row}
    env = {"PROJECT_ID": "p1", "WEBAPP_API_URL": "http://webapp.invalid", "REDAMON_MEM_GOVERNOR": "0"}
    with patch.dict(os.environ, env, clear=False), patch("requests.get", return_value=_Resp(payload)):
        return ps.get_settings()


def test_get_settings_applies_the_mode():
    s = _resolved(ipHostnameMode="ip_only")
    assert [s[k] for k in FORCEABLE] == [False, False, False]


def test_get_settings_leaves_a_recording_mode_its_own_toggles():
    s = _resolved(ipHostnameMode="record_only")
    assert (s["TLSX_REV_PTR_SNI"], s["SHODAN_REVERSE_DNS"], s["VHOST_SNI_USE_GRAPH_CANDIDATES"]) == \
        (False, True, True)


def test_stealth_and_the_mode_together():
    """Stealth runs first; the mode is applied after it, so whatever stealth
    leaves on, the mode still forces off (and stealth's own choices stay)."""
    plain = _resolved(ipHostnameMode="ip_only", stealthMode=False)
    stealth = _resolved(ipHostnameMode="ip_only", stealthMode=True)
    assert [stealth[k] for k in FORCEABLE] == [False, False, False]
    assert stealth["STEALTH_MODE"] is True
    with patch.object(ps._registry, "stealth_profile",
                      return_value={"SHODAN_REVERSE_DNS": {"set": True}}):
        forced_on = _resolved(ipHostnameMode="ip_only", stealthMode=True)
    assert forced_on["SHODAN_REVERSE_DNS"] is False
    assert plain["SHODAN_REVERSE_DNS"] is False


def test_domain_projects_keep_their_toggles_through_get_settings():
    s = _resolved(ipMode=False, targetIps=[], targetDomain="example.com")
    assert [s[k] for k in FORCEABLE] == [True, True, True]


def test_the_pass_runs_right_after_stealth():
    """Ordering is load-bearing (README.SETTINGS_REGISTRY): stealth, then the
    mode, then the AI overrides, the RoE cap and the governor."""
    src = Path(ps.__file__).read_text(encoding="utf-8")
    body = src[src.index("def get_settings()"):src.index("# Singleton settings instance")]
    order = [body.index(f"settings = {fn}(settings)") for fn in (
        "apply_stealth_overrides", "apply_ip_hostname_overrides", "apply_ai_pipeline_overrides",
        "apply_roe_rate_cap", "apply_memory_governor")]
    assert order == sorted(order)


# --- the log marker -----------------------------------------------------------------

def test_the_effective_settings_dump_marks_a_forced_value(capsys):
    s = ps.apply_ip_hostname_overrides(_all_on(IP_MODE=True, IP_HOSTNAME_MODE="ip_only"))
    print_effective_settings("Shodan", s, [("SHODAN_REVERSE_DNS", "Lookups"), "SHODAN_ENABLED"])
    out = capsys.readouterr().out
    assert "SHODAN_REVERSE_DNS" in out
    line = next(ln for ln in out.splitlines() if "SHODAN_REVERSE_DNS " in ln)
    assert line.endswith("= False (forced by Hostnames on target IPs: ip_only)")
    other = next(ln for ln in out.splitlines() if "SHODAN_ENABLED" in ln)
    assert "forced" not in other


def test_the_dump_marks_nothing_the_mode_does_not_force(capsys):
    s = ps.apply_ip_hostname_overrides(_all_on(IP_MODE=True, IP_HOSTNAME_MODE="record_filter"))
    print_effective_settings("VhostSni", s, ["VHOST_SNI_USE_GRAPH_CANDIDATES", "TLSX_REV_PTR_SNI"])
    out = capsys.readouterr().out
    assert "VHOST_SNI_USE_GRAPH_CANDIDATES" in out and "= True" in out
    assert out.count("(forced by Hostnames on target IPs: record_filter)") == 1


def test_the_dump_marks_nothing_in_domain_mode(capsys):
    print_effective_settings("Shodan", _all_on(IP_MODE=False), ["SHODAN_REVERSE_DNS"])
    assert "forced" not in capsys.readouterr().out


def test_a_marker_failure_never_breaks_the_dump(capsys):
    with patch("recon.project_settings.ip_hostname_overrides", side_effect=RuntimeError("boom")):
        print_effective_settings("Shodan", _all_on(IP_MODE=True), ["SHODAN_REVERSE_DNS"])
    out = capsys.readouterr().out
    assert "SHODAN_REVERSE_DNS" in out and "forced" not in out


# --- the webapp copy ----------------------------------------------------------------

def _ts_table() -> dict[str, dict[str, bool]]:
    text = TS_TABLE.read_text(encoding="utf-8")
    block = re.search(r"export const IP_HOSTNAME_FORCED[^=]*=\s*\{(.*?)\n\}", text, re.S)
    assert block, f"IP_HOSTNAME_FORCED not found in {TS_TABLE}"
    table = {}
    for mode, body in re.findall(r"^\s*(\w+):\s*\{([^}]*)\}", block.group(1), re.M):
        table[mode] = {col: val == "true" for col, val in re.findall(r"(\w+):\s*(true|false)", body)}
    return table


def test_the_webapp_copy_equals_the_python_table():
    """get_recon_settings reports what the scan does only while both agree."""
    if not TS_TABLE.exists():
        pytest.skip(f"{TS_TABLE} is not in this checkout")
    ts = _ts_table()
    as_runtime = {
        mode: {reg.field(col)["runtime_key"]: val for col, val in row.items()}
        for mode, row in ts.items()
    }
    assert as_runtime == ps._IP_HOSTNAME_FORCED
