"""Tradecraft's browser tier runs in the Kali sandbox of the right person (group 1, S12,
WI-S12-3; T5, I11).

Tradecraft renders a JavaScript page with the sandbox's Playwright (`execute_playwright`). Its
MCP manager (`tradecraft.jobs._agent_mcp_manager`) is now a facade whose tool resolves through
the sandbox router, at call time, for the person bound to the work:

- an ingestion job: the job's owner (`job.user_id`), bound in the job's own task;
- a chat run's read: the run's person (the run actor; `act_as` under act-as);
- a synchronous route (Check URL, Read now): the account its request names;
- no person: no browser at all (never someone else's sandbox, never the shared one by default).

Each render holds a `tradecraft` lease for its call (`using`, no project). In shared mode the
facade hands the call to the agent's own MCP manager, as before. A bound site login still
refuses the browser before anything is asked (`fetch.render`), so a login never reaches any
sandbox. Outside the agent process there is no orchestrator and no browser, as before.

The router's public functions are stubbed.

Run: ./agentic/run_tests.sh tests/test_tradecraft_browser_routing.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import types
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
from decision_check import RunActor, current_run_actor  # noqa: E402
from tradecraft import api as tc_api  # noqa: E402
from tradecraft import jobs, net  # noqa: E402
from tradecraft.contract import CheckUrlRequest, CheckUrlResult, Credentials, JobOutcome, JobStartBatch, ReadNowRequest, ReadNowResult  # noqa: E402
from tradecraft.ingest import fetch  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FakeClock  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract"
JOB_FIXTURE = json.loads((FIXTURES / "JobStartBatch.valid.json").read_text())["jobs"][0]
PAGE_HTML = "<html><body>rendered</body></html>"


def run(coro):
    return asyncio.run(coro)


def sandbox_handle(person, view, mode):
    return router.SandboxHandle(
        user_id=person, view=view, instance="a1b2c3",
        host=contract.container_name(person, view, "a1b2c3") if mode == contract.MODE_PER_USER else "kali-sandbox",
        token="t" * 24, tunnel_token="", ports=contract.PORTS, reverse_port=4444, mode=mode)


class Tool:
    def __init__(self, name, owner):
        self.name = name
        self.owner = owner
        self.calls = []

    async def ainvoke(self, args):
        self.calls.append(args)
        return f"rendered for {self.owner}"


class AgentManager:
    """The orchestrator's MCP manager (shared mode's browser)."""

    def __init__(self):
        self.tool = Tool("execute_playwright", "shared")
        self.asked = 0

    async def get_tools(self, *a, **k):
        self.asked += 1
        return [Tool("kali_shell", "shared"), self.tool]


class Router:
    def __init__(self, mode=contract.MODE_PER_USER, refuse=None):
        self.mode = mode
        self.refuse = refuse
        self.used = []
        self.released = []
        self.tools = []

    @asynccontextmanager
    async def using(self, user_id, *, project_id, kind, view=None):
        seen_view = router.sandbox_view() if view is None else view
        self.used.append({"user_id": user_id, "project_id": project_id, "kind": kind, "view": seen_view})
        if self.refuse:
            raise router.SandboxUnavailable(self.refuse)
        h = sandbox_handle(user_id, seen_view, self.mode)
        try:
            yield h
        finally:
            self.released.append(h)

    async def tool_for(self, name, h):
        tool = Tool(name, f"{h.user_id}/{h.view}")
        self.tools.append((h, tool))
        return tool

    @contextmanager
    def installed(self):
        with mock.patch.object(router, "using", self.using), \
                mock.patch.object(router, "tool_for", self.tool_for):
            yield self

    def people(self):
        return [u["user_id"] for u in self.used]


@pytest.fixture
def agent_process(monkeypatch):
    """The running agent: `api.orchestrator._mcp_manager` exists."""
    manager = AgentManager()
    fake_api = types.ModuleType("api")
    fake_api.orchestrator = types.SimpleNamespace(_mcp_manager=manager)
    monkeypatch.setitem(sys.modules, "api", fake_api)
    return manager


async def browse(script="print(1)"):
    """What GuardedFetcher.render does with its MCP manager."""
    return await net.GuardedFetcher(jobs._agent_mcp_manager()).run_browser_script(script)


def bound_actor(user_id, tenant_id, actor_id=None):
    return current_run_actor.set(RunActor(user_id=user_id, tenant_id=tenant_id, project_id="p1",
                                          session_id="s1", actor_id=actor_id))


# --------------------------------------------------------------------------------------
# A chat run's read: the run's person
# --------------------------------------------------------------------------------------

def test_a_chat_runs_render_uses_the_runs_person(agent_process):
    r = Router()

    async def go():
        token = bound_actor("bob", "alice")
        try:
            return await browse()
        finally:
            current_run_actor.reset(token)

    with r.installed():
        output, error = run(go())
    assert (output, error) == ("rendered for bob/own", "")
    assert r.used == [{"user_id": "bob", "project_id": None, "kind": "tradecraft", "view": "own"}]
    assert len(r.released) == 1, "the lease ends with the render"
    assert agent_process.asked == 0, "per-user mode never uses the agent's shared manager"


def test_an_act_as_chat_run_uses_the_persons_act_as_view(agent_process):
    r = Router()

    async def go():
        token = bound_actor("bob", "alice", actor_id="admin")
        try:
            return await browse()
        finally:
            current_run_actor.reset(token)

    with r.installed():
        output, _ = run(go())
    assert r.people() == ["bob"]
    assert r.used[0]["view"] == contract.VIEW_ACT_AS
    assert output == "rendered for bob/act_as"


# --------------------------------------------------------------------------------------
# An ingestion job: its owner
# --------------------------------------------------------------------------------------

class SteppedClock(FakeClock):
    def __init__(self):
        super().__init__(start=datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc))

    async def sleep(self, seconds):
        await asyncio.Event().wait()


def _job(job_id, user, real_actor=None):
    j = json.loads(json.dumps(JOB_FIXTURE))
    j.update(job_id=job_id, user_id=user, actor_user_id=user, real_actor_user_id=real_actor,
             resource_id=f"r-{job_id}")
    return j


def test_a_job_an_admin_started_acting_as_the_owner_uses_the_act_as_view(agent_process):
    """TD-26: work an admin does acting as the owner runs in the owner's act_as view, never
    the owner's own one (and never the admin's)."""
    r = Router()
    store = MemoryStore()
    spec = _job("jq", "alice", real_actor="admin")
    store.add_resource("alice", spec["resource_id"], url=spec["resource"]["url"],
                       storage_mode=spec["resource"]["storage_mode"])
    store.add_job("alice", spec["resource_id"], "jq")
    seen = []

    async def entry(ctx):
        await net.get_fetcher().run_browser_script("print(1)")
        seen.append((router.sandbox_user(), router.sandbox_view()))
        return JobOutcome(status="failed", error_code="fetch_failed")

    async def go():
        runner = jobs.JobRunner(store, entry=entry, instance="inst-test", clock=SteppedClock())
        await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
        for _ in range(200):
            if seen:
                break
            await asyncio.sleep(0.01)
        await runner.close()

    with r.installed():
        run(go())
    assert seen == [("alice", contract.VIEW_ACT_AS)]
    assert r.used == [{"user_id": "alice", "project_id": None, "kind": "tradecraft", "view": "act_as"}]


def test_each_jobs_render_uses_its_owners_sandbox(agent_process):
    """Two owners' jobs at once (one per owner, two at a time): each renders in its owner's."""
    r = Router()
    store = MemoryStore()
    specs = [_job("ja", "alice"), _job("jb", "bob")]
    for spec in specs:
        store.add_resource(spec["user_id"], spec["resource_id"], url=spec["resource"]["url"],
                           storage_mode=spec["resource"]["storage_mode"])
        store.add_job(spec["user_id"], spec["resource_id"], spec["job_id"])
    seen = {}

    async def entry(ctx):
        output, error = await net.get_fetcher().run_browser_script("print(1)")
        seen[ctx.request.job_id] = (router.sandbox_user(), output, error)
        return JobOutcome(status="failed", error_code="fetch_failed")

    async def go():
        runner = jobs.JobRunner(store, entry=entry, instance="inst-test", clock=SteppedClock())
        await runner.submit(JobStartBatch.model_validate({"jobs": specs}))
        for _ in range(200):
            if len(seen) == 2:
                break
            await asyncio.sleep(0.01)
        await runner.close()

    with r.installed():
        run(go())
    assert seen["ja"] == ("alice", "rendered for alice/own", "")
    assert seen["jb"] == ("bob", "rendered for bob/own", "")
    assert sorted(r.people()) == ["alice", "bob"]
    assert all(u["kind"] == "tradecraft" and u["project_id"] is None for u in r.used)


def test_a_job_never_inherits_the_person_of_whoever_submitted_it(agent_process):
    """The job is submitted from carol's request task, but runs as its owner."""
    r = Router()
    store = MemoryStore()
    spec = _job("jx", "alice")
    store.add_resource("alice", spec["resource_id"], url=spec["resource"]["url"],
                       storage_mode=spec["resource"]["storage_mode"])
    store.add_job("alice", spec["resource_id"], "jx")
    seen = []

    async def entry(ctx):
        await net.get_fetcher().run_browser_script("print(1)")
        seen.append(router.sandbox_user())
        return JobOutcome(status="failed", error_code="fetch_failed")

    async def go():
        token = bound_actor("carol", "carol")
        try:
            with router.for_person("carol"):
                runner = jobs.JobRunner(store, entry=entry, instance="inst-test", clock=SteppedClock())
                await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
                for _ in range(200):
                    if seen:
                        break
                    await asyncio.sleep(0.01)
                await runner.close()
        finally:
            current_run_actor.reset(token)

    with r.installed():
        run(go())
    assert seen == ["alice"]
    assert r.people() == ["alice"]


# --------------------------------------------------------------------------------------
# A synchronous route: the account its request names
# --------------------------------------------------------------------------------------

def test_check_url_renders_in_the_requests_accounts_sandbox(agent_process, monkeypatch):
    r = Router()
    seen = []

    async def check_url(body):
        output, error = await net.get_fetcher().run_browser_script("print(1)")
        seen.append((router.sandbox_user(), output, error))
        return CheckUrlResult(ok=True)

    monkeypatch.setattr(tc_api.check_url_mod, "check_url", check_url)
    body = CheckUrlRequest.model_validate(json.loads((FIXTURES / "CheckUrlRequest.valid.json").read_text()))
    with r.installed():
        answer = run(tc_api.check_url(body))
    assert answer["ok"] is True
    assert seen == [("user_owner_fake", "rendered for user_owner_fake/own", "")]
    assert r.people() == ["user_owner_fake"]


def test_read_now_renders_in_the_requests_accounts_sandbox(agent_process, monkeypatch):
    r = Router()
    seen = []

    async def read_now(body):
        await net.get_fetcher().run_browser_script("print(1)")
        seen.append(router.sandbox_user())
        return ReadNowResult(error_code="")

    monkeypatch.setattr(tc_api.read_now_mod, "read_now", read_now)
    body = ReadNowRequest.model_validate(json.loads((FIXTURES / "ReadNowRequest.valid.json").read_text()))
    with r.installed():
        run(tc_api.read_now(body))
    assert seen == ["user_owner_fake"]
    assert r.people() == ["user_owner_fake"]


def test_a_route_inside_someone_elses_context_still_uses_its_account(agent_process, monkeypatch):
    """The route's account wins over any run actor in the task."""
    r = Router()
    monkeypatch.setattr(tc_api.check_url_mod, "check_url", _render_then_ok)
    body = CheckUrlRequest.model_validate(json.loads((FIXTURES / "CheckUrlRequest.valid.json").read_text()))

    async def go():
        token = bound_actor("mallory", "mallory")
        try:
            return await tc_api.check_url(body)
        finally:
            current_run_actor.reset(token)

    with r.installed():
        run(go())
    assert r.people() == ["user_owner_fake"]


async def _render_then_ok(body):
    await net.get_fetcher().run_browser_script("print(1)")
    return CheckUrlResult(ok=True)


# --------------------------------------------------------------------------------------
# Never another person; no person, no browser
# --------------------------------------------------------------------------------------

def test_no_person_no_browser(agent_process):
    r = Router()
    with r.installed():
        output, error = run(browse())
    assert (output, error) == ("", "browser_unavailable")
    assert r.used == [] and r.tools == []
    assert agent_process.asked == 0


def test_concurrent_people_each_get_their_own(agent_process):
    r = Router()

    async def as_run_of(person):
        token = bound_actor(person, "owner")
        try:
            await asyncio.sleep(0)
            return await browse()
        finally:
            current_run_actor.reset(token)

    async def as_account(person):
        with jobs.sandbox_person(person):
            await asyncio.sleep(0)
            return await browse()

    async def go():
        return await asyncio.gather(as_run_of("bob"), as_account("alice"), as_run_of("carol"))

    with r.installed():
        outputs = run(go())
    assert [o for o, _e in outputs] == ["rendered for bob/own", "rendered for alice/own", "rendered for carol/own"]
    assert sorted(r.people()) == ["alice", "bob", "carol"]
    for h, tool in r.tools:
        assert tool.owner == f"{h.user_id}/{h.view}"


def test_an_unavailable_sandbox_is_a_browser_error_never_another_sandbox(agent_process):
    for reason in ("refused", "ram", "no_user", "error"):
        r = Router(refuse=reason)

        async def go():
            with jobs.sandbox_person("bob"):
                return await browse()

        with r.installed():
            output, error = run(go())
        assert output == "" and error in ("browser_error", "browser_unavailable"), reason
        assert r.tools == []
        assert agent_process.asked == 0, "never the shared sandbox instead"


def test_a_bound_login_never_reaches_any_sandbox(agent_process):
    r = Router()
    creds = Credentials(cookie="session=fake-session-cookie")

    async def go():
        with jobs.sandbox_person("alice"), net.use_fetcher(jobs.default_fetcher()), \
                fetch.use_login("https://wiki.example.invalid/", creds):
            return await fetch.render("https://wiki.example.invalid/page", EffectiveSettings({}))

    with r.installed():
        rendered = run(go())
    assert rendered.error == "browser_unavailable"
    assert r.used == [] and r.tools == []


# --------------------------------------------------------------------------------------
# Shared mode and outside the agent process
# --------------------------------------------------------------------------------------

def test_shared_mode_uses_the_agents_own_manager(agent_process):
    r = Router(mode=contract.MODE_SHARED)

    async def go():
        with jobs.sandbox_person("alice"):
            return await browse("print(2)")

    with r.installed():
        output, error = run(go())
    assert (output, error) == ("rendered for shared", "")
    assert agent_process.tool.calls == [{"script": "print(2)"}]
    assert r.tools == [], "no per-user client in shared mode"


def test_outside_the_agent_process_there_is_no_browser(monkeypatch):
    monkeypatch.delitem(sys.modules, "api", raising=False)
    assert jobs._agent_mcp_manager() is None
    r = Router()

    async def go():
        with jobs.sandbox_person("alice"):
            return await browse()

    with r.installed():
        assert run(go()) == ("", "browser_unavailable")
    assert r.used == []
