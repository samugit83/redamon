"""The 2.0 run binding (T1.9): the catalog is bound per run task and read nowhere else, the
person and the acting administrator go to the catalog route, a 1.x payload keeps the 1.x
path, and the run's settings fetch falls back to the 1.x route only on a page 404 (D-53).
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from decision_check import RunActor, bind_run_actor, current_run_actor  # noqa: E402
from prompts import tool_registry as tr  # noqa: E402
from tradecraft import net, runtime  # noqa: E402
from tradecraft.library import reader  # noqa: E402
from tradecraft_doubles import FAKE_COOKIE, FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract"
TRADECRAFT_DIR = Path(__file__).resolve().parent.parent / "tradecraft"


def v2_catalog(**over):
    c = json.loads((FIXTURES / "V2Catalog.valid.json").read_text())
    c.update(over)
    return c


def legacy_catalog():
    """The 1.x run payload a webapp of the switch era answered (``{"v2": false, "legacy": rows}``):
    since the cut-over (T9.2) no catalog, so it binds nothing."""
    return {"v2": False, "legacy": [{"id": "res_fake_0001", "userId": "user_owner_fake", "name": "Fake wiki",
                                     "slug": "fake-wiki", "url": "https://wiki.example.invalid/", "enabled": True,
                                     "resourceType": "mkdocs-wiki", "summary": "A synthetic wiki.", "sitemap": {}}]}


def in_fresh_context(fn, *args):
    return contextvars.Context().run(fn, *args)


# --------------------------------------------------------------------------------------

def test_catalog_bound_per_run():
    """Two runs, two catalogs: each task sees only its own, and its own registry entry."""
    first = v2_catalog()
    second = v2_catalog(owner_id="user_other_fake", person_id="user_other_fake")
    second["resources"] = [dict(first["resources"][0], slug="other-wiki", has_login=False, credentials=None)]

    async def run_one(catalog, seen, key):
        assert runtime.bind_run_catalog(catalog)
        await asyncio.sleep(0)
        seen[key] = (runtime.bound_catalog().owner_id, [r.slug for r in runtime.bound_catalog().resources],
                     tr.visible_registry()["tradecraft_lookup"]["description"])

    async def both():
        seen = {}
        await asyncio.gather(asyncio.create_task(run_one(first, seen, "a"), context=contextvars.Context()),
                             asyncio.create_task(run_one(second, seen, "b"), context=contextvars.Context()))
        return seen

    seen = asyncio.run(both())
    assert seen["a"][0] == "user_owner_fake" and seen["a"][1] == ["fake-wiki", "fake-private-kb"]
    assert seen["b"][0] == "user_other_fake" and seen["b"][1] == ["other-wiki"]
    assert "fake-private-kb" in seen["a"][2] and "fake-private-kb" not in seen["b"][2]
    # Nothing leaked into this (the test's own) context.
    assert runtime.bound_catalog() is None and "tradecraft_lookup" not in tr.visible_registry()


def test_registry_entry_wraps_the_summaries():
    def bound():
        runtime.bind_run_catalog(v2_catalog())
        return tr.visible_registry()

    entry = in_fresh_context(bound)["tradecraft_lookup"]
    assert set(entry) == {"purpose", "when_to_use", "args_format", "description"}
    desc = entry["description"]
    start = desc.index("<<<UNTRUSTED_TRADECRAFT_CATALOG")
    assert start < desc.index("A synthetic wiki.") < desc.index("<<<END_UNTRUSTED_TRADECRAFT_CATALOG")
    assert "cache" not in desc.lower()


def test_a_run_binds_its_own_entries_once():
    """A second run of the session replaces the first one's entries (T9.2: the 1.x entry and its
    swap are gone, the run's entries are the only tradecraft entries)."""
    def go():
        tr.swap_tradecraft_v2_entries({"tradecraft_lookup": {"purpose": "old", "when_to_use": "w", "args_format": "a",
                                                             "description": "an earlier run"}})
        runtime.bind_run_catalog(v2_catalog())
        reg = tr.visible_registry()
        return reg["tradecraft_lookup"]["description"], list(reg).count("tradecraft_lookup")

    desc, count = in_fresh_context(go)
    assert desc != "an earlier run" and count == 1


def test_actor_from_run_actor():
    def query(actor):
        bind_run_actor(actor)
        return runtime.catalog_query("proj-1")

    person = RunActor(user_id="person-1", tenant_id="owner-1", project_id="proj-1", session_id="s")
    assert in_fresh_context(query, person) == {"projectId": "proj-1", "personId": "person-1"}
    acting = RunActor(user_id="owner-1", tenant_id="owner-1", project_id="proj-1", session_id="s", actor_id="admin-1")
    assert in_fresh_context(query, acting) == {"projectId": "proj-1", "personId": "owner-1", "actorId": "admin-1"}


def test_no_actor_excludes():
    """R-155: with no run actor only the project goes (the webapp then leaves out every
    resource with a login); the owner is never sent."""
    assert current_run_actor.get() is None
    assert runtime.catalog_query("proj-1") == {"projectId": "proj-1"}


def test_legacy_payload_keeps_1x():
    def go(payload):
        runtime.bind_run_catalog(v2_catalog())
        answer = runtime.bind_run_catalog(payload)
        return answer, runtime.bound_catalog(), tr._tradecraft_v2_overlay.get(), runtime.v2_tool_for("tradecraft_lookup")

    for payload in (legacy_catalog(), None, {"v2": False, "legacy": []}, "garbage"):
        assert in_fresh_context(go, payload) == (False, None, None, None)
    # A 2.0 catalog the contract refuses (a login listed in a collaborator's run) is not bound.
    bad = v2_catalog(person_id="collaborator")
    assert in_fresh_context(go, bad)[0] is False


def test_v2_tool_for():
    def go():
        before = runtime.v2_tool_for("tradecraft_lookup")
        runtime.bind_run_catalog(v2_catalog())
        return before, runtime.v2_tool_for("tradecraft_lookup"), runtime.v2_tool_for("web_search")

    before, after, other = in_fresh_context(go)
    assert before is None and after is not None and after.name == "tradecraft_lookup" and other is None


def test_unbound_context_refuses():
    """D-47: after one task bound a catalog holding a fake cookie, a call from a fresh context
    answers "not available in this run" and makes no request."""
    fetcher, store = FixtureFetcher(), MemoryStore()
    catalog = v2_catalog()
    assert catalog["resources"][1]["credentials"]["cookie"] == "session=fake-session"

    async def bound_run():
        with net.use_fetcher(fetcher), runtime.use_store(store):
            runtime.bind_run_catalog(catalog)
            return runtime.bound_catalog() is not None

    assert asyncio.run(bound_run())

    async def stray_call():
        with net.use_fetcher(fetcher), runtime.use_store(store):
            return await reader.lookup(resource_id="fake-private-kb", query="anything")

    answer = contextvars.Context().run(asyncio.run, stray_call())
    assert answer == reader.NOT_AVAILABLE
    assert fetcher.requests == [] and fetcher.browser.renders == [] and store.calls == []
    assert FAKE_COOKIE not in answer


def test_no_get_setting_for_catalog():
    """The catalog, its token and its logins are never read through get_setting (whose
    fallback outside a task is another project's settings)."""
    offenders = []
    for f in sorted(TRADECRAFT_DIR.rglob("*.py")):
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r"get_settings?\(\s*['\"](TRADECRAFT_[A-Z_]+)", text):
            offenders.append((f.name, m.group(1)))
        if re.search(r"\bget_settings\(\)", text):
            offenders.append((f.name, "get_settings()"))
    assert offenders == []
    orchestrator = (TRADECRAFT_DIR.parent / "orchestrator.py").read_text()
    assert "bind_run_catalog((_ps._settings_ctx.get() or {}).get('TRADECRAFT_CATALOG'))" in orchestrator


def test_the_executor_routes_a_2x_run_to_the_2x_tool():
    tools_src = (TRADECRAFT_DIR.parent / "tools.py").read_text()
    # T2.6 widened the branch to the 2.0 tools that share it (TD-10); since the cut-over (T9.2)
    # every one of them is the registered 2.0 stand-in, so the branch calls it as it is.
    branch = tools_src[tools_src.index('elif tool_name in ("tradecraft_lookup", "tradecraft_search", "tradecraft_ask"):'):]
    branch = branch[:branch.index("elif tool_name ==", 10)]
    assert "output = await active_tool.ainvoke(tool_args)" in branch
    from tradecraft.tool_proxies import V2_TOOL_NAMES
    assert V2_TOOL_NAMES == ("tradecraft_lookup", "tradecraft_search", "tradecraft_ask")


# --------------------------------------------------------------------------------------
# The run's settings fetch (project_settings.fetch_agent_settings)
# --------------------------------------------------------------------------------------

class _Resp:
    def __init__(self, status=200, body=None, text=None):
        self.status_code, self._body, self.text = status, body, text if text is not None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def fetch_with(catalog_answer, legacy_answer=None, actor=None):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, dict(params or {})))
        if "/api/projects/" in url:
            return _Resp(200, {"userId": "owner-1"})
        if "/llm-providers" in url:
            return _Resp(200, [])
        if url.endswith("/settings?internal=true"):
            return _Resp(200, {})
        if "/api/internal/agent/tradecraft/catalog" in url:
            return catalog_answer
        if "/tradecraft-resources" in url:
            return legacy_answer or _Resp(500, None, "x")
        return _Resp(404, None, "<html>404</html>")

    def go():
        if actor is not None:
            bind_run_actor(actor)
        with mock.patch("requests.get", side_effect=fake_get):
            return ps.fetch_agent_settings("proj-1", "http://webapp")

    return contextvars.Context().run(go), calls


def test_settings_carry_the_catalog():
    settings, calls = fetch_with(_Resp(200, v2_catalog()),
                                 actor=RunActor(user_id="owner-1", tenant_id="owner-1", project_id="proj-1", session_id="s"))
    assert settings["TRADECRAFT_CATALOG"]["v2"] is True and settings["TRADECRAFT_V2"] is True
    assert "TRADECRAFT_RESOURCES" not in settings
    catalog_call = [c for c in calls if "/tradecraft/catalog" in c[0]][0]
    assert catalog_call[1] == {"projectId": "proj-1", "personId": "owner-1"}
    assert not any("/tradecraft-resources" in c[0] for c in calls)


def test_a_1x_payload_binds_nothing():
    """T9.2: a webapp that still answers the 1.x rows (mid-deployment) gives the run no catalog:
    the 1.x path is gone, so the run goes on without the tradecraft tools."""
    settings, _ = fetch_with(_Resp(200, legacy_catalog()))
    assert settings["TRADECRAFT_CATALOG"] is None and settings["TRADECRAFT_V2"] is False


def test_unknown_project_404_never_falls_back():
    """D-53: the route's own 404 binds nothing, and the unfiltered list is never asked."""
    settings, calls = fetch_with(_Resp(404, {"code": "project_not_found"}))
    assert settings["TRADECRAFT_CATALOG"] is None and settings["TRADECRAFT_V2"] is False
    assert not any("/tradecraft-resources" in c[0] for c in calls)


def test_an_older_webapp_is_never_asked_the_1x_way():
    """T9.2: the page-404 fallback to the 1.x list (and its unmasked internal GET) is gone."""
    rows = legacy_catalog()["legacy"]
    settings, calls = fetch_with(_Resp(404, None, "<html>This page could not be found</html>"),
                                 legacy_answer=_Resp(200, rows))
    assert settings["TRADECRAFT_CATALOG"] is None and settings["TRADECRAFT_V2"] is False
    assert not any("/tradecraft-resources" in c[0] for c in calls)


def test_a_failed_catalog_fetch_leaves_no_resource():
    settings, _ = fetch_with(_Resp(502, None, "bad gateway"))
    assert settings["TRADECRAFT_CATALOG"] is None and settings["TRADECRAFT_V2"] is False
