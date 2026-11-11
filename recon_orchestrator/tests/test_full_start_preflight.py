"""
The full-start pre-flight (hard guardrail, RoE window) runs on every start.

It used to sit behind `if request.webapp_api_url:`, and the model allows an
empty string, so a start with an empty URL skipped the one check that cannot be
switched off. The fetch never used that URL anyway: it goes to the trusted
webapp base.
"""
import asyncio

import pytest
from fastapi import HTTPException

import api
from models import ReconStartRequest, ReconState, ReconStatus
from tests.job_credentials import job_credential, use_keys


class _SpyManager:
    def __init__(self):
        self.calls = []

    async def start_recon(self, **kw):
        self.calls.append(kw)
        return ReconState(project_id="p1", status=ReconStatus.STARTING)


@pytest.fixture
def spy(monkeypatch):
    s = _SpyManager()
    monkeypatch.setattr(api, "container_manager", s)
    return s


def _start(webapp_api_url, monkeypatch, project):
    fetched = []

    def _fetch(pid):
        fetched.append(pid)
        return project

    monkeypatch.setattr(api, "_fetch_project_for_preflight", _fetch)
    use_keys(monkeypatch)
    req = ReconStartRequest(project_id="p1", user_id="u1", webapp_api_url=webapp_api_url,
                            job_credential=job_credential("p1", "u1"))
    return fetched, (lambda: asyncio.run(api.start_recon("p1", req)))


@pytest.mark.parametrize("url", ["", "http://localhost:3000"])
def test_the_preflight_runs_whatever_the_request_url(url, monkeypatch, spy):
    fetched, run = _start(url, monkeypatch, {"targetDomain": "agency.gov.uk"})
    with pytest.raises(HTTPException) as ei:
        run()
    assert ei.value.status_code == 403
    assert fetched == ["p1"] and spy.calls == []


def test_a_batch_host_under_a_government_name_is_refused(monkeypatch, spy):
    project = {"domainBatchMode": True, "domainBatchGroups": [
        {"rootDomain": "example.com", "prefixes": ["www."], "hosts": ["www.example.com"]},
        {"rootDomain": "org.jm", "prefixes": ["www.isa."], "hosts": ["www.isa.org.jm"]},
    ]}
    _, run = _start("", monkeypatch, project)
    with pytest.raises(HTTPException) as ei:
        run()
    assert ei.value.status_code == 403
    assert "www.isa.org.jm" in ei.value.detail
    assert spy.calls == []


def test_a_clean_project_starts(monkeypatch, spy):
    _, run = _start("", monkeypatch, {"targetDomain": "example.com"})
    run()
    assert len(spy.calls) == 1


def test_a_scope_the_webapp_could_not_derive_refuses_the_start(monkeypatch, spy):
    _, run = _start("", monkeypatch, {"targetDomain": "co.uk", "scopeGroups": []})
    with pytest.raises(HTTPException) as ei:
        run()
    assert ei.value.status_code == 400
    assert spy.calls == []


# --- IP mode: the hostname include entries (design §9 "Hard guardrail") ---------

IP_PROJECT = {"ipMode": True, "targetDomain": "", "targetIps": ["203.0.113.10"]}


@pytest.mark.parametrize("include,expected", [
    ([], []),
    (["*.example.com", "app.example.org"], ["example.com", "app.example.org"]),
    (["*example.com", " *.EXAMPLE.com. ", "example.com"], ["example.com"]),
    (["", None, 7], ["7"]),
])
def test_ip_mode_guardrails_the_include_bases(include, expected):
    from batch_scope import guardrail_targets
    assert guardrail_targets({**IP_PROJECT, "ipHostnameInclude": include}) == expected


def test_ip_mode_without_an_include_list_has_nothing_to_guardrail():
    from batch_scope import guardrail_targets
    assert guardrail_targets(IP_PROJECT) == []
    assert guardrail_targets({**IP_PROJECT, "ipHostnameInclude": "*.agency.gov.uk"}) == []


def test_the_addresses_are_never_guardrail_names():
    from batch_scope import guardrail_targets
    names = guardrail_targets({**IP_PROJECT, "ipHostnameInclude": ["*.example.com"]})
    assert "203.0.113.10" not in names


@pytest.mark.parametrize("mode", ["record_filter", "record_only", "ip_only"])
def test_an_ip_project_with_a_blocked_include_entry_is_refused(mode, monkeypatch, spy):
    """Checked whatever the mode: a rescope to record_filter would scan under it
    without the list being written (and checked by the webapp) again."""
    project = {**IP_PROJECT, "ipHostnameMode": mode,
               "ipHostnameInclude": ["*.example.com", "*.agency.gov.uk"]}
    _, run = _start("", monkeypatch, project)
    with pytest.raises(HTTPException) as ei:
        run()
    assert ei.value.status_code == 403
    assert spy.calls == []


def test_an_ip_project_with_a_clean_include_list_starts(monkeypatch, spy):
    project = {**IP_PROJECT, "ipHostnameMode": "record_filter", "ipHostnameInclude": ["*.example.com"]}
    _, run = _start("", monkeypatch, project)
    run()
    assert len(spy.calls) == 1


def test_an_ip_project_never_guardrails_its_addresses(monkeypatch, spy):
    seen = []

    def _blocked(name):
        seen.append(name)
        return False, ""

    monkeypatch.setattr("hard_guardrail.is_hard_blocked", _blocked)
    _, run = _start("", monkeypatch, {**IP_PROJECT, "ipHostnameInclude": ["*.example.com"]})
    run()
    assert seen == ["example.com"]
