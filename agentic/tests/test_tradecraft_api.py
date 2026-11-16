"""The agent's Tradecraft 2.0 routes (T1.5): the master key on every route, the per-owner
rate limit on the routes that fetch or call a model (D-12), one request for a whole batch
(D-49), the contract's bodies, the deadlines, and 501 for the routes still to come.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import llm_guard  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tradecraft import api as tc_api  # noqa: E402
from tradecraft import net  # noqa: E402
from tradecraft import jobs  # noqa: E402
from tradecraft.contract import JobStartAnswer, JobStartBatch, PreviewResult, ROUTES  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

MASTER = "dummy-master-key-tradecraft-api"
SCANNER = "dummy-scanner-key-tradecraft-api"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract"


def fixture(name):
    return json.loads((FIXTURES / f"{name}.valid.json").read_text())


class FakeRunner:
    def __init__(self):
        self.batches: list[JobStartBatch] = []
        self.cancelled: list[str] = []
        self.users: list[str] = []
        self.fail = False

    async def submit(self, batch):
        if self.fail:
            raise OSError("database down")
        self.batches.append(batch)
        return JobStartAnswer(accepted=[j.job_id for j in batch.jobs], refused=[])

    async def cancel_job(self, job_id):
        self.cancelled.append(job_id)

    async def cancel_user(self, user_id):
        self.users.append(user_id)
        return 3


class Limits:
    """Records the keys the token bucket and the daily cap are asked about."""

    def __init__(self, refuse=()):
        self.rate, self.daily, self.refuse = [], [], set(refuse)

    def allow(self, key):
        self.rate.append(key)
        return key.split("|")[0] not in self.refuse


class Daily:
    def __init__(self, limits):
        self.limits = limits

    def allow(self, user):
        self.limits.daily.append(user)
        return True


class _TriageModel:
    """Answers the preview's title triage with no decision: every entry stays maybe."""

    async def ainvoke(self, prompt, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        return AIMessage(content='{"entries": []}')


async def _preview_model(owner, model):
    return _TriageModel()


@pytest.fixture
def client(monkeypatch):
    # A route that fetches (Check URL since T4.1) reads the fixture sites, never the network:
    # the TestClient runs the app in its own thread, so the double is the variable's default.
    monkeypatch.setattr(net, "_current", contextvars.ContextVar("tradecraft_fetcher", default=FixtureFetcher()))
    monkeypatch.setattr(jobs, "default_fetcher", FixtureFetcher)
    # The focus preview (since T5.3) builds the owner's model: a scripted one, never the webapp.
    monkeypatch.setattr("tradecraft.models.build_ingest_llm", _preview_model)
    monkeypatch.setenv("INTERNAL_API_KEY", MASTER)
    monkeypatch.setenv("SCANNER_API_KEY", SCANNER)
    runner = FakeRunner()
    jobs.set_runner_for_tests(runner)
    limits = Limits()
    monkeypatch.setattr(llm_guard, "_rate_limiter", limits)
    monkeypatch.setattr(llm_guard, "_daily_cap", Daily(limits))
    app = FastAPI()
    app.include_router(tc_api.router)
    c = TestClient(app)
    c.runner, c.limits = runner, limits
    yield c
    jobs.set_runner_for_tests(None)


H = {"x-internal-key": MASTER}

POSTS = [
    ("/tradecraft/v2/jobs", fixture("JobStartBatch")),
    ("/tradecraft/v2/jobs/job_fake_0001/cancel", {}),
    ("/tradecraft/v2/users/user_owner_fake/cancel", {}),
    ("/tradecraft/v2/check-url", fixture("CheckUrlRequest")),
    ("/tradecraft/v2/preview-focus", fixture("PreviewRequest")),
    ("/tradecraft/v2/read-now", fixture("ReadNowRequest")),
    ("/tradecraft/v2/users/user_owner_fake/convert", {}),
]


def test_the_routes_are_the_contracts():
    paths = {r.path for r in tc_api.router.routes}
    assert paths == set(ROUTES.values())


def test_auth_required(client, monkeypatch):
    for path, body in POSTS:
        assert client.post(path, json=body).status_code == 401, path
        assert client.post(path, json=body, headers={"x-internal-key": SCANNER}).status_code == 401, path
        assert client.post(path, json=body, headers=H).status_code in (200, 202, 501), path
    # No master key configured: every route refuses everyone (the port is public).
    for env in ({"INTERNAL_API_KEY": ""}, {"INTERNAL_API_KEY": "changeme"}):
        with mock.patch.dict(os.environ, env):
            for path, body in POSTS:
                for headers in ({}, {"x-internal-key": "changeme"}):
                    assert client.post(path, json=body, headers=headers).status_code == 503, (path, env)
    assert client.runner.cancelled == ["job_fake_0001"]


def test_every_route_takes_the_fail_closed_master_dependency():
    for route in tc_api.router.routes:
        assert isinstance(route, APIRoute)
        deps = {d.call for d in route.dependant.dependencies}
        assert llm_guard.require_configured_master_auth in deps, route.path


def test_rate_limited_routes(client):
    """D-12: the routes that fetch a site or call a model spend the owner's bucket."""
    limited = {"/tradecraft/v2/check-url": llm_guard.require_internal_auth,
               "/tradecraft/v2/preview-focus": llm_guard.require_internal_auth,
               "/tradecraft/v2/read-now": llm_guard.require_internal_auth,
               "/tradecraft/v2/jobs": tc_api.require_job_owner_limits}
    for route in tc_api.router.routes:
        deps = {d.call for d in route.dependant.dependencies}
        if route.path in limited:
            assert limited[route.path] in deps, route.path
        else:
            assert not deps & {llm_guard.require_internal_auth, tc_api.require_job_owner_limits}, route.path

    client.limits.refuse = {"user_owner_fake"}
    for path, body in POSTS:
        status = client.post(path, json=body, headers=H).status_code
        if path in limited:
            assert status == 429, path
        else:
            assert status != 429, path
    assert client.runner.batches == []


def test_bulk_start_one_request(client):
    """D-49: 200 jobs in one request cost one token of their owner's bucket."""
    one = fixture("JobStartBatch")["jobs"][0]
    batch = {"jobs": [dict(one, job_id=f"job_{i:03d}", resource_id=f"res_{i:03d}") for i in range(200)]}
    resp = client.post("/tradecraft/v2/jobs", json=batch, headers=H)
    assert resp.status_code == 202 and len(resp.json()["accepted"]) == 200
    assert [k.split("|")[0] for k in client.limits.rate] == ["user_owner_fake"]
    assert client.limits.daily == ["user_owner_fake"]
    assert len(client.runner.batches) == 1


def test_each_owner_of_a_batch_is_charged_once(client):
    jobs_ = fixture("JobStartBatch")["jobs"]
    other = dict(jobs_[0], job_id="job_other", user_id="user_other_fake", actor_user_id="user_other_fake")
    client.post("/tradecraft/v2/jobs", json={"jobs": jobs_ + [other]}, headers=H)
    assert sorted(k.split("|")[0] for k in client.limits.rate) == ["user_other_fake", "user_owner_fake"]


def test_job_carries_settings(client):
    body = fixture("JobStartBatch")
    body["jobs"][0]["settings"]["crawl.maxPages"] = 9999
    resp = client.post("/tradecraft/v2/jobs", json=body, headers=H)
    assert resp.status_code == 202
    sent = client.runner.batches[0].jobs[0]
    assert sent.settings["crawl.maxPages"] == 9999 and sent.settings_hash == body["jobs"][0]["settings_hash"]
    # The job runs with the agent's second clamp (the ceiling is 500).
    assert EffectiveSettings(sent.settings).int("crawl.maxPages") == 500
    assert EffectiveSettings(sent.settings).str("crawl.strategy") == "llm"


def test_the_runner_hands_the_settings_to_the_pipeline():
    store, seen = MemoryStore(), {}

    async def entry(ctx):
        seen["pages"] = ctx.settings.int("crawl.maxPages")
        seen["types"] = ctx.settings.list("knownTypes.githubFileTypes")
        from tradecraft.contract import JobOutcome
        return JobOutcome(status="failed", error_code="fetch_failed")

    body = fixture("JobStartBatch")
    spec = body["jobs"][0]
    spec["settings"]["crawl.maxPages"] = 120
    store.add_resource(spec["user_id"], spec["resource_id"], url=spec["resource"]["url"], storage_mode="stored")
    store.add_job(spec["user_id"], spec["resource_id"], spec["job_id"])

    async def go():
        runner = jobs.JobRunner(store, entry=entry, instance="i")
        await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
        await asyncio.wait_for(runner._running[spec["job_id"]].task, timeout=5)
        await runner.close()

    asyncio.run(go())
    assert seen == {"pages": 120, "types": [".md", ".txt", ".rst"]}


# Check URL left this list with T4.1 and the focus preview with T5.3: tests/test_tradecraft_check_url.py
# and tests/test_tradecraft_preview.py hold what they answer.
@pytest.mark.parametrize("path,body", [p for p in POSTS if p[0].endswith(("read-now", "convert"))])
def test_stubs_answer_501(client, path, body):
    resp = client.post(path, json=body, headers=H)
    assert resp.status_code == 501 and resp.json() == {"error_code": "not_implemented"}


def test_the_preview_answers_the_contract(client):
    resp = client.post("/tradecraft/v2/preview-focus", json=fixture("PreviewRequest"), headers=H)
    assert resp.status_code == 200
    answer = PreviewResult.model_validate(resp.json())
    assert answer.maybe == len(fixture("PreviewRequest")["entries"]) and answer.llm_calls == 1


def test_deadline_answers_timeout(client, monkeypatch):
    async def never(_request):
        await asyncio.Event().wait()

    monkeypatch.setattr(tc_api, "DEADLINES_SEC", {"check_url": 0, "preview_focus": 0, "read_now": 0})
    monkeypatch.setattr(tc_api.check_url_mod, "check_url", never)
    monkeypatch.setattr(tc_api.preview_mod, "preview_focus", never)
    monkeypatch.setattr(tc_api.read_now_mod, "read_now", never)
    check = client.post("/tradecraft/v2/check-url", json=fixture("CheckUrlRequest"), headers=H).json()
    assert check["ok"] is False and check["error_code"] == "timeout"
    assert client.post("/tradecraft/v2/preview-focus", json=fixture("PreviewRequest"), headers=H).json()["error_code"] == "timeout"
    assert client.post("/tradecraft/v2/read-now", json=fixture("ReadNowRequest"), headers=H).json()["error_code"] == "timeout"


def test_the_deadlines_are_the_contracts():
    assert tc_api.DEADLINES_SEC == {"check_url": 60, "preview_focus": 120, "read_now": 45}


def test_cancel_answers(client):
    assert client.post("/tradecraft/v2/jobs/job_x/cancel", json={}, headers=H).json() == {"ok": True}
    assert client.post("/tradecraft/v2/users/user_x/cancel", headers=H).json() == {"cancelled": 3}
    assert client.runner.users == ["user_x"]


def test_invalid_bodies_are_refused(client):
    body = fixture("JobStartBatch")
    body["jobs"][0]["kind"] = "convert"
    assert client.post("/tradecraft/v2/jobs", json=body, headers=H).status_code == 422
    body = fixture("JobStartBatch")
    body["jobs"][0]["secrets"]["github_token"] = "set"
    assert client.post("/tradecraft/v2/jobs", json=body, headers=H).status_code == 422
    assert client.post("/tradecraft/v2/jobs", json={"jobs": []}, headers=H).status_code == 422
    assert client.runner.batches == []


def test_store_unavailable_is_503(client):
    client.runner.fail = True
    resp = client.post("/tradecraft/v2/jobs", json=fixture("JobStartBatch"), headers=H)
    assert resp.status_code == 503 and resp.json() == {"error_code": "internal_error"}
    assert "database" not in resp.text


def test_router_is_mounted_on_the_agent():
    import api  # noqa: F401 - the agent app, as test_ghsa_8whg_master_key_fail_closed walks it

    found = set()

    def walk(routes):
        for route in routes:
            if isinstance(route, APIRoute):
                found.add(route.path)
            elif hasattr(route, "original_router"):
                walk(route.original_router.routes)

    walk(api.app.router.routes)
    assert set(ROUTES.values()) <= found
