"""Partial recon: the orchestrator decides which project roots a run may touch.

Before this, start_partial_recon trusted `graph_inputs.domain` from the client:
it ran the hard guardrail on that one name and wrote it straight into the
container config, and a Domain-batch project got one arbitrary root scanned.
Now the roots come from the project row, re-validated, and the client may only
narrow them. These tests pin that contract at the pure helpers (batch_scope)
and at the endpoint itself, which must refuse before any container is asked for.

Fixture roots are alpha.test / beta.test / gamma.test only.
"""
import ast
import asyncio
import os
import types
from pathlib import Path
from unittest import mock

import pytest
from fastapi import HTTPException

import api
import batch_scope
import container_manager as cm
from batch_scope import (
    PARTIAL_OVERRIDE_KEYS,
    PartialScopeError,
    narrow_partial_roots,
    partial_project_roots,
    validate_partial_overrides,
)
from models import PartialReconStartRequest, PartialReconState, PartialReconStatus, ReconStatus

BATCH = {
    "domainBatchMode": True,
    "targetDomain": "",
    "domainBatchGroups": [
        {"rootDomain": "gamma.test", "prefixes": ["*"]},
        {"rootDomain": "alpha.test", "prefixes": ["www.", "."]},
        {"rootDomain": "beta.test", "prefixes": ["*"]},
    ],
}
SINGLE = {"targetDomain": "alpha.test", "subdomainList": []}
IP_MODE = {"ipMode": True, "targetDomain": "", "targetIps": ["192.0.2.10"]}


# --- partial_project_roots ----------------------------------------------------

class TestProjectRoots:
    def test_batch_mode_gives_every_group_root(self):
        assert partial_project_roots(BATCH, "p1") == ["gamma.test", "alpha.test", "beta.test"]

    def test_single_mode_gives_the_target(self):
        assert partial_project_roots(SINGLE, "p1") == ["alpha.test"]

    def test_single_mode_keeps_the_stored_spelling(self):
        # The Domain node carries the name exactly as saved (trimmed, not
        # lowercased); lowercasing here would match no node.
        assert partial_project_roots({"targetDomain": " Alpha.test "}, "p1") == ["Alpha.test"]

    def test_ip_mode_gives_the_synthetic_root(self):
        assert partial_project_roots(IP_MODE, "p1") == ["ip-targets.p1"]

    def test_a_batch_without_groups_is_refused(self):
        with pytest.raises(PartialScopeError) as ei:
            partial_project_roots({"domainBatchMode": True, "domainBatchGroups": []}, "p1")
        assert ei.value.status_code == 400

    def test_a_charset_invalid_root_is_dropped_not_repaired(self):
        project = {"domainBatchMode": True, "domainBatchGroups": [
            {"rootDomain": "alpha.test", "prefixes": ["*"]},
            {"rootDomain": "bad;name.test", "prefixes": ["*"]},
            {"rootDomain": "beta..test", "prefixes": ["*"]},
        ]}
        assert partial_project_roots(project, "p1") == ["alpha.test"]

    def test_a_single_target_that_fails_the_charset_is_refused(self):
        with pytest.raises(PartialScopeError) as ei:
            partial_project_roots({"targetDomain": "alpha.test;rm"}, "p1")
        assert ei.value.status_code == 400

    def test_no_target_at_all_is_refused(self):
        with pytest.raises(PartialScopeError):
            partial_project_roots({"targetDomain": ""}, "p1")


# --- narrow_partial_roots -----------------------------------------------------

ROOTS = ["gamma.test", "alpha.test", "beta.test"]


class TestNarrowing:
    def test_no_request_means_every_root_sorted(self):
        assert narrow_partial_roots(ROOTS, {}) == ["alpha.test", "beta.test", "gamma.test"]

    def test_a_subset_narrows(self):
        assert narrow_partial_roots(ROOTS, {"domains": ["beta.test"]}) == ["beta.test"]

    def test_a_client_superset_is_narrowed_to_project_roots(self):
        got = narrow_partial_roots(ROOTS, {"domains": ["alpha.test", "evil.test", "beta.test"]})
        assert got == ["alpha.test", "beta.test"]

    def test_matching_ignores_case_and_returns_the_project_spelling(self):
        assert narrow_partial_roots(["Alpha.test"], {"domains": ["ALPHA.TEST"]}) == ["Alpha.test"]

    def test_nothing_in_common_is_refused(self):
        with pytest.raises(PartialScopeError) as ei:
            narrow_partial_roots(ROOTS, {"domains": ["evil.test"]})
        assert ei.value.status_code == 400

    def test_an_empty_list_is_refused_not_widened(self):
        with pytest.raises(PartialScopeError):
            narrow_partial_roots(ROOTS, {"domains": []})

    @pytest.mark.parametrize("bad", ["alpha.test", [1, 2], [None], ["x.test"] * 51])
    def test_a_malformed_list_is_refused(self, bad):
        with pytest.raises(PartialScopeError) as ei:
            narrow_partial_roots(ROOTS, {"domains": bad})
        assert ei.value.status_code == 400

    def test_legacy_domain_inside_the_roots_narrows_to_it(self):
        assert narrow_partial_roots(ROOTS, {"domain": "beta.test"}) == ["beta.test"]

    def test_legacy_domain_outside_the_roots_is_refused(self):
        with pytest.raises(PartialScopeError) as ei:
            narrow_partial_roots(ROOTS, {"domain": "removed.test"})
        assert ei.value.status_code == 400

    def test_domains_wins_over_the_legacy_field(self):
        got = narrow_partial_roots(ROOTS, {"domains": ["gamma.test"], "domain": "alpha.test"})
        assert got == ["gamma.test"]


# --- validate_partial_overrides ----------------------------------------------

class TestOverrides:
    def test_the_modal_keys_pass(self):
        o = {"CVE_LOOKUP_ENABLED": False, "MITRE_ENABLED": True, "SECURITY_CHECK_ENABLED": False}
        assert validate_partial_overrides(o) == o

    def test_none_is_empty(self):
        assert validate_partial_overrides(None) == {}

    @pytest.mark.parametrize("key", ["ROE_ENABLED", "ROE_EXCLUDED_HOSTS", "TARGET_DOMAIN"])
    def test_any_other_key_is_refused(self, key):
        with pytest.raises(PartialScopeError) as ei:
            validate_partial_overrides({key: False})
        assert ei.value.status_code == 400
        assert key in ei.value.detail

    def test_a_non_boolean_value_is_refused(self):
        # "false" is truthy: applied as-is it would switch the feature ON.
        with pytest.raises(PartialScopeError):
            validate_partial_overrides({"CVE_LOOKUP_ENABLED": "false"})

    def test_the_allowlist_matches_the_containers(self):
        """Both ends must agree, or the orchestrator's 400 and the container's
        silent drop describe different contracts."""
        path = Path(__file__).resolve().parents[2] / "recon" / "partial_recon.py"
        if not path.exists():
            pytest.skip("recon/ is not mounted beside the orchestrator")
        tree = ast.parse(path.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.Assign)
                    and any(getattr(t, "id", "") == "ALLOWED_SETTINGS_OVERRIDES" for t in n.targets))
        container_keys = {elt.value for elt in node.value.args[0].elts}
        assert container_keys == set(PARTIAL_OVERRIDE_KEYS)


# --- the endpoint ---------------------------------------------------------------

class _SpyManager:
    def __init__(self):
        self.calls = []

    async def start_partial_recon(self, **kw):
        self.calls.append(kw)
        return PartialReconState(project_id=kw["project_id"], run_id="run-1",
                                 tool_id=kw["tool_id"], status=PartialReconStatus.RUNNING,
                                 roots=list(kw["config"].get("domains") or []))


def _request(**kw):
    base = dict(project_id="p1", user_id="u1", webapp_api_url="http://localhost:3000",
                tool_id="Tlsx", graph_inputs={})
    base.update(kw)
    return PartialReconStartRequest(**base)


@pytest.fixture
def spy(monkeypatch):
    s = _SpyManager()
    monkeypatch.setattr(api, "container_manager", s)
    return s


def _project(monkeypatch, project):
    fetched = []

    def _fetch(pid):
        fetched.append(pid)
        return project

    monkeypatch.setattr(api, "_fetch_project_for_preflight", _fetch)
    return fetched


def _start(req):
    return asyncio.run(api.start_partial_recon("p1", req))


class TestEndpoint:
    def test_a_batch_run_covers_every_root_and_returns_them(self, monkeypatch, spy):
        _project(monkeypatch, BATCH)
        state = _start(_request())
        config = spy.calls[0]["config"]
        assert config["domains"] == ["alpha.test", "beta.test", "gamma.test"]
        assert config["domain"] == "alpha.test"
        assert state.roots == ["alpha.test", "beta.test", "gamma.test"]

    def test_the_client_can_narrow_but_never_widen(self, monkeypatch, spy):
        _project(monkeypatch, BATCH)
        _start(_request(graph_inputs={"domains": ["beta.test", "evil.test"]}))
        assert spy.calls[0]["config"]["domains"] == ["beta.test"]

    def test_a_legacy_domain_outside_the_roots_is_a_400_and_spawns_nothing(self, monkeypatch, spy):
        _project(monkeypatch, BATCH)
        with pytest.raises(HTTPException) as ei:
            _start(_request(graph_inputs={"domain": "removed.test"}))
        assert ei.value.status_code == 400
        assert spy.calls == []

    def test_a_legacy_queued_job_still_starts_on_its_root(self, monkeypatch, spy):
        _project(monkeypatch, SINGLE)
        _start(_request(graph_inputs={"domain": "alpha.test"}))
        assert spy.calls[0]["config"]["domains"] == ["alpha.test"]

    def test_a_missing_webapp_url_is_a_400_before_any_fetch(self, monkeypatch, spy):
        fetched = _project(monkeypatch, BATCH)
        with pytest.raises(HTTPException) as ei:
            _start(_request(webapp_api_url=""))
        assert ei.value.status_code == 400
        assert fetched == [] and spy.calls == []

    def test_an_unknown_override_is_a_400_and_spawns_nothing(self, monkeypatch, spy):
        _project(monkeypatch, BATCH)
        with pytest.raises(HTTPException) as ei:
            _start(_request(settings_overrides={"ROE_ENABLED": False}))
        assert ei.value.status_code == 400
        assert spy.calls == []

    def test_allowed_overrides_reach_the_container(self, monkeypatch, spy):
        _project(monkeypatch, SINGLE)
        _start(_request(tool_id="Nuclei", settings_overrides={"MITRE_ENABLED": False}))
        assert spy.calls[0]["config"]["settings_overrides"] == {"MITRE_ENABLED": False}

    def test_the_guardrail_runs_on_every_root(self, monkeypatch, spy):
        _project(monkeypatch, BATCH)
        seen = []

        def _blocked(domain):
            seen.append(domain)
            return False, ""

        monkeypatch.setattr("hard_guardrail.is_hard_blocked", _blocked)
        _start(_request())
        # Each once; the order is the project's group order, not the sorted roots.
        assert sorted(seen) == ["alpha.test", "beta.test", "gamma.test"]

    def test_a_blocked_root_anywhere_refuses_the_run(self, monkeypatch, spy):
        project = {"domainBatchMode": True, "domainBatchGroups": [
            {"rootDomain": "alpha.test", "prefixes": ["*"]},
            {"rootDomain": "whitehouse.gov", "prefixes": ["www."]},
        ]}
        _project(monkeypatch, project)
        with pytest.raises(HTTPException) as ei:
            _start(_request())
        assert ei.value.status_code == 403
        assert spy.calls == []

    def test_a_host_under_a_government_name_refuses_the_run(self, monkeypatch, spy):
        # www.isa.org.jm groups under org.jm, which no rule names: only the
        # listed host is blocked, so checking the roots alone let it through.
        project = {"domainBatchMode": True, "domainBatchGroups": [
            {"rootDomain": "alpha.test", "prefixes": ["*"], "hosts": ["*.alpha.test"]},
            {"rootDomain": "org.jm", "prefixes": ["www.isa."], "hosts": ["www.isa.org.jm"]},
        ]}
        _project(monkeypatch, project)
        with pytest.raises(HTTPException) as ei:
            _start(_request())
        assert ei.value.status_code == 403
        assert "www.isa.org.jm" in ei.value.detail
        assert spy.calls == []

    def test_a_single_domain_prefix_that_makes_a_blocked_host_refuses_the_run(self, monkeypatch, spy):
        # The root org.jm is not blocked; the prefix host isa.org.jm is.
        _project(monkeypatch, {"targetDomain": "org.jm", "subdomainList": ["isa."]})
        with pytest.raises(HTTPException) as ei:
            _start(_request())
        assert ei.value.status_code == 403
        assert "isa.org.jm" in ei.value.detail
        assert spy.calls == []

    def test_out_of_scope_typed_urls_never_reach_the_container(self, monkeypatch, spy):
        _project(monkeypatch, {**SINGLE, "subdomainList": ["www."]})
        _start(_request(tool_id="Katana", user_targets={"urls": [
            "https://www.alpha.test/", "https://cdn.alpha.test/", "https://elsewhere.test/"]}))
        assert spy.calls[0]["config"]["user_targets"]["urls"] == ["https://www.alpha.test/"]

    def test_only_out_of_scope_typed_targets_and_no_graph_targets_is_a_400(self, monkeypatch, spy):
        _project(monkeypatch, {**SINGLE, "subdomainList": ["www."]})
        with pytest.raises(HTTPException) as ei:
            _start(_request(tool_id="Katana", include_graph_targets=False,
                            user_targets={"urls": ["https://elsewhere.test/"]}))
        assert ei.value.status_code == 400
        assert spy.calls == []

    def test_ip_mode_uses_the_synthetic_root_and_skips_the_guardrail(self, monkeypatch, spy):
        _project(monkeypatch, IP_MODE)
        monkeypatch.setattr("hard_guardrail.is_hard_blocked",
                            lambda d: pytest.fail("IP mode root was hard-guardrailed"))
        _start(_request())
        assert spy.calls[0]["config"]["domains"] == ["ip-targets.p1"]

    def test_ip_mode_guardrails_the_hostname_include_bases(self, monkeypatch, spy):
        """Design §9: the include entries' base names, never the synthetic root."""
        _project(monkeypatch, {**IP_MODE, "ipHostnameMode": "record_filter",
                               "ipHostnameInclude": ["*.alpha.test"]})
        seen = []

        def _blocked(name):
            seen.append(name)
            return False, ""

        monkeypatch.setattr("hard_guardrail.is_hard_blocked", _blocked)
        _start(_request())
        assert seen == ["alpha.test"]
        assert spy.calls[0]["config"]["domains"] == ["ip-targets.p1"]

    def test_ip_mode_with_a_blocked_include_entry_refuses_the_run(self, monkeypatch, spy):
        _project(monkeypatch, {**IP_MODE, "ipHostnameMode": "record_filter",
                               "ipHostnameInclude": ["*.alpha.test", "whitehouse.gov"]})
        with pytest.raises(HTTPException) as ei:
            _start(_request())
        assert ei.value.status_code == 403
        assert "whitehouse.gov" in ei.value.detail
        assert spy.calls == []

    def test_the_roe_window_is_still_enforced(self, monkeypatch, spy):
        _project(monkeypatch, {**SINGLE, "roeTimeWindowEnabled": True,
                               "roeTimeWindowTimezone": "UTC", "roeTimeWindowDays": []})
        with pytest.raises(HTTPException) as ei:
            _start(_request())
        assert ei.value.status_code == 403
        assert spy.calls == []

    def test_the_run_is_logged_with_its_roots(self, monkeypatch, spy, caplog):
        _project(monkeypatch, BATCH)
        with caplog.at_level("INFO"):
            _start(_request(graph_inputs={"domains": ["gamma.test"]}))
        line = next(r.getMessage() for r in caplog.records if "run-1" in r.getMessage())
        assert "p1" in line and "Tlsx" in line and "gamma.test" in line


# --- the real ContainerManager records the roots on the state -----------------

class TestStateCarriesRoots:
    def test_start_partial_recon_sets_roots_from_the_config(self):
        os.makedirs("/tmp/redamon", exist_ok=True)
        client = mock.MagicMock()
        client.containers.run.return_value = types.SimpleNamespace(id="cid")

        async def _go():
            with mock.patch.object(cm.docker, "from_env", return_value=client):
                mgr = cm.ContainerManager()
            mgr.get_status = mock.AsyncMock(
                return_value=types.SimpleNamespace(status=ReconStatus.IDLE))
            mgr._admit_scan = mock.AsyncMock(return_value=None)
            return await mgr.start_partial_recon(
                project_id="p1", tool_id="Tlsx",
                config={"tool_id": "Tlsx", "user_id": "u1",
                        "domains": ["alpha.test", "beta.test"], "domain": "alpha.test"},
                recon_path="/repo/recon",
            )

        state = asyncio.run(_go())
        assert state.roots == ["alpha.test", "beta.test"]
        # And the listing the webapp polls exposes them.
        assert "roots" in PartialReconState.model_fields
