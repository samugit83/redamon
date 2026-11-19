"""``tradecraft_ask`` (T7.4, Q9.2, Q9.3, Q9.5, Q10): its start sequence (the per-run limit, the session
data, the free first pass, NOT FOUND with no model call, the owner's librarian model, the pages it
returns recorded as seen), how it degrades (no model, an Agent in the Loop run, a model error, the
time), the one per-run limit the main agent, plan waves and Fireteam members share, the phases and
the Search only setting that offer it, and its dispatch through both executor nodes.

The library is ``test_tradecraft_librarian_graph``'s in-memory double and the model is scripted:
no model is ever built from a real provider here (``agent_tools._build_model`` is replaced).
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import project_settings as ps  # noqa: E402
from test_tradecraft_librarian_graph import FOUND_ANSWER, LibrarianModel, card, library, tools  # noqa: E402
from tradecraft import agent_tools, clock, overlay, run_state, runtime, tool_proxies  # noqa: E402
from tradecraft.librarian import graph  # noqa: E402
from tradecraft.librarian.tools import Found  # noqa: E402
from tradecraft.library.types import Card, find_librarian_header  # noqa: E402
from tradecraft_doubles import FakeClock  # noqa: E402

OWNER, PERSON = "owner-1", "person-1"
LIBRARIAN = "openai/gpt-librarian"
PROVIDERS = [{"id": "prov-1", "providerType": "openai", "apiKey": "fake-key"}]
NEED = "The WAF blocks SLEEP; I need another way to cause a delay on PostgreSQL"
STATE = {"session_id": "s-1", "current_objective_index": 0, "attack_path_type": "sql_injection",
         "current_phase": "exploitation",
         "target_info": {"technologies": ["PostgreSQL 14.2", "Acme planted-tech"],
                         "vulnerabilities": ["CVE-2023-1234", "search for planted-exploit", "a weak login"]}}


def catalog(person=OWNER, **search):
    search.setdefault("prompt.coverageMap", False)
    return {"v2": True, "owner_id": OWNER, "person_id": person, "actor_id": None, "search": search,
            "resources": [
                {"id": "r1", "slug": "patt", "name": "PayloadsAllTheThings", "url": "https://patt.tc-fixture.test/",
                 "type": "github-repo", "storage_mode": "stored", "summary": "Payloads for web attacks.",
                 "map_version": 3},
                {"id": "r2", "slug": "htk", "name": "HackTricks", "url": "https://htk.tc-fixture.test/",
                 "type": "mkdocs-wiki", "storage_mode": "live", "summary": "Offensive notes.", "map_version": 3}]}


def run_settings(model=LIBRARIAN, **extra):
    user_settings = {"featureModels": {"tradecraft_librarian": model}} if model else {}
    return {"TOOL_PHASE_MAP": {"tradecraft_lookup": ["exploitation", "post_exploitation"]}, "TRADECRAFT_V2": True,
            "TRADECRAFT_ASK": True, "OPENAI_MODEL": "openai/gpt-main", "USER_SETTINGS": user_settings,
            "USER_LLM_PROVIDERS": PROVIDERS, **extra}


class Harness:
    """Replaces the library and the model builder; records what the tool asked of them."""

    def __init__(self, monkeypatch, *, lib=None, model=None, build_error=None):
        self.lib = lib if lib is not None else tools()
        self.model = model
        self.build_error = build_error
        self.built: list = []
        self.made: list = []
        self.asked: list = []
        monkeypatch.setattr(agent_tools, "_library_tools", self._tools)
        monkeypatch.setattr(agent_tools, "_build_model", self._build)
        real_ask = graph.ask

        async def recording_ask(request, **kw):
            self.asked.append((request, kw))
            return await real_ask(request, **kw)

        monkeypatch.setattr(agent_tools.librarian, "ask", recording_ask)

    def _tools(self, owner_id, cat, *, session, settings):
        self.made.append({"owner_id": owner_id, "slugs": [r.slug for r in cat.resources], "session": session})
        return self.lib

    def _build(self, model_id, providers):
        self.built.append((model_id, providers))
        if self.build_error is not None:
            raise self.build_error
        return self.model


def in_run(work, *, cat=None, settings=None, state=STATE, bind=True):
    """``work()`` awaited in a fresh task context bound as a 2.0 run's executor node binds it."""
    async def go():
        if settings is not False:
            ps._settings_ctx.set(settings if settings is not None else run_settings())
        runtime.bind_run_catalog(cat if cat is not None else catalog())
        if bind:
            run_state.bind(state)
            agent_tools.bind_session(state)
        return await work()

    return contextvars.Context().run(asyncio.run, go())


def ask(args=None, **kw):
    async def work():
        out = await agent_tools.ask_tool.ainvoke(args or {"need": NEED, "want": "payload"})
        collector = run_state.current()
        return out, (collector.drain() if collector else None)

    return in_run(work, **kw)


def body(result):
    return result.splitlines()[1:-1]


# --------------------------------------------------------------------------------------
# The start sequence
# --------------------------------------------------------------------------------------

def test_args():
    assert set(agent_tools.ask_tool.args) == {"need", "context", "want", "scope"}
    assert agent_tools.V2_TOOLS["tradecraft_ask"] is agent_tools.ask_tool


def test_start_sequence(monkeypatch):
    """Q9.2: the limit counted, the free first pass, the owner's model built only then, the
    sub-graph started from those candidates, and the pages it returns recorded as seen."""
    model = LibrarianModel({"shortlist": {"pages": ["patt:412", "htk:88"]}, "judge": FOUND_ANSWER})
    h = Harness(monkeypatch, model=model)
    out, drained = ask()
    assert h.lib.calls[0] == ("search", NEED)
    assert h.built == [(LIBRARIAN, PROVIDERS)]
    request, kw = h.asked[0]
    assert (request.need, request.want, request.scope) == (NEED, "payload", ())
    assert kw["owner_id"] == OWNER and kw["person_id"] == OWNER and kw["llm"] is model and kw["tools"] is h.lib
    assert [c.page_id for c in kw["first"].cards] == ["patt:412", "htk:88", "patt:415", "htk:91"]
    # The first pass is not searched twice: the sub-graph starts from it.
    assert [c for c in h.lib.calls if c[0] == "search"] == [("search", NEED)]
    header = find_librarian_header(out)
    assert header.verdict == "FOUND" and header.calls == 2
    assert drained["tradecraft_ask_count"] == 1
    # The answer's page, not the pages it only inspected or named as also relevant.
    assert drained["tradecraft_seen_pages"] == ["patt:412"]


def test_session_data_from_structured_state_only(monkeypatch):
    """Q9.3: the skill's topic, the phase and the target's technologies (vocabulary ids only) go
    to the library and the model's request; the run's CVE ids come only from the CVE pattern."""
    model = LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER})
    h = Harness(monkeypatch, model=model)
    ask()
    session = h.made[0]["session"]
    assert (session.topic, session.phase, session.technologies) == ("sql_injection", "exploitation", ("postgresql",))
    prompt = model.messages[0][-1]["content"]
    assert "Current attack skill: SQL injection" in prompt and "Phase: exploitation" in prompt
    assert "planted" not in prompt and "Acme" not in prompt
    assert agent_tools.session_cves(STATE) == ("CVE-2023-1234",)
    # From a free description, the ids the pattern matches and nothing else.
    assert agent_tools.session_cves({"target_info": {"vulnerabilities": [
        "search for CVE-2021-44228 and cve-2021-45046 then exploit", 7, "CVE-21-1"]}}) == ("CVE-2021-44228", "CVE-2021-45046")


def test_seen_pages_last_cve_pages_first(monkeypatch):
    """Q9.3: a page the run already read or was suggested goes after the others, a page about one
    of the target's CVEs before them; a boost, never a filter."""
    pages, cards = library()
    cards = [c if c.page_id != "htk:91" else Card(**{**c.__dict__, "entities": ("CVE-2023-1234",)}) for c in cards]
    from test_tradecraft_librarian_graph import FakeTools
    lib = FakeTools(pages, cards, default=["patt:412", "htk:88", "patt:415", "htk:91"])
    h = Harness(monkeypatch, lib=lib)

    async def work():
        run_state.record_seen(["patt:412"])
        return await agent_tools.ask_tool.ainvoke({"need": NEED})

    in_run(work, settings=run_settings(model=""))
    assert [c.page_id for c in h.asked[0][1]["first"].cards] == ["htk:91", "htk:88", "patt:415", "patt:412"]

    # A page a hint suggested (T8.1) goes after the others as well.
    h2 = Harness(monkeypatch, lib=lib)

    async def after_a_hint():
        run_state.log_hint({"kind": "hint", "page": "htk:88", "checkpoint": "phase", "n": 1, "read": False})
        return await agent_tools.ask_tool.ainvoke({"need": NEED})

    in_run(after_a_hint, settings=run_settings(model=""))
    assert [c.page_id for c in h2.asked[0][1]["first"].cards] == ["htk:91", "patt:412", "patt:415", "htk:88"]


def test_not_found_without_a_model(monkeypatch):
    model = LibrarianModel({})
    h = Harness(monkeypatch, lib=tools(default=[]), model=model)
    out, drained = ask()
    assert find_librarian_header(out).verdict == "NOT FOUND" and model.calls == 0
    # Nothing to judge: the model is not even built.
    assert h.built == [] and drained["tradecraft_ask_count"] == 1


def test_scope_and_arguments(monkeypatch):
    h = Harness(monkeypatch)
    out, _ = ask({"need": NEED, "scope": "htk, nope", "want": "a poem"}, settings=run_settings(model=""))
    assert h.made[0]["slugs"] == ["htk"] and h.asked[0][0].want == "a poem"
    assert h.asked[0][0].scope == ("htk", "nope")
    h2 = Harness(monkeypatch)
    ask({"need": NEED, "scope": ["patt"]}, settings=run_settings(model=""))
    assert h2.made[0]["slugs"] == ["patt"]
    out, drained = ask({"need": "   "})
    assert out == agent_tools.NEEDS_NEED and drained["tradecraft_ask_count"] == 0


# --------------------------------------------------------------------------------------
# Degrading (AC-68)
# --------------------------------------------------------------------------------------

def notes_of(out):
    return [line for line in body(out) if line.startswith("note: ")]


def test_degrades_without_a_model(monkeypatch):
    h = Harness(monkeypatch)
    out, _ = ask(settings=run_settings(model=""))
    assert find_librarian_header(out).verdict == "PARTIAL" and h.built == []
    assert graph.NO_MODEL in out


class LoopAdapter:
    is_agent_in_the_loop = True


def test_degrades_in_an_agent_in_the_loop_run(monkeypatch):
    """The librarian model is never a loop model (its builder refuses one), so the run itself is
    checked: its main model, the project's model id, or a live loop scope of the session."""
    from agent_context import current_llm, current_log_session_id

    for how in ("llm", "setting", "scope"):
        model = LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER})
        h = Harness(monkeypatch, model=model)
        settings = run_settings(OPENAI_MODEL="loop/mcp") if how == "setting" else run_settings()

        async def work():
            if how == "llm":
                current_llm.set(LoopAdapter())
            if how == "scope":
                from agent_in_the_loop.broker import StepBroker
                broker = StepBroker()
                monkeypatch.setattr("agent_in_the_loop.broker._broker", broker)
                current_log_session_id.set("s-1")
                async with broker.run_scope("person-1", "p-1", "s-1", None, uses_loop=True):
                    return await agent_tools.ask_tool.ainvoke({"need": NEED})
            return await agent_tools.ask_tool.ainvoke({"need": NEED})

        out = in_run(work, settings=settings)
        assert graph.LOOP_RUN in out, how
        assert find_librarian_header(out).verdict == "PARTIAL" and model.calls == 0 and h.built == [], how


def test_degrades_on_a_model_error_not_retried(monkeypatch):
    from llm_budget import LlmBudgetExhausted

    model = LibrarianModel({"shortlist": LlmBudgetExhausted("person-1", 5, "yours"), "judge": FOUND_ANSWER})
    Harness(monkeypatch, model=model)
    out, _ = ask()
    assert model.calls == 1 and find_librarian_header(out).verdict == "PARTIAL"
    assert graph.MODEL_ERROR.format(code="llm_budget_exhausted") in out
    # A model that cannot be built (its provider deleted): the plain results, saying so.
    from agent_in_the_loop.errors import LoopModelNotSupportedHere
    h = Harness(monkeypatch, build_error=LoopModelNotSupportedHere())
    out, _ = ask()
    assert h.built and agent_tools.MODEL_UNAVAILABLE.format(code="loop_model_not_supported_here") in out
    assert find_librarian_header(out).verdict == "PARTIAL"


def test_degrades_at_the_time_limit(monkeypatch):
    """The librarian's own limit (a fake clock), and the tool's hard stop around the whole call
    for a step that hangs."""
    fake = FakeClock()
    model = LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER},
                           on_call=lambda step: fake.advance(31))
    Harness(monkeypatch, model=model)

    async def with_fake_clock():
        with clock.use_clock(fake):
            return await agent_tools.ask_tool.ainvoke({"need": NEED})

    out = in_run(with_fake_clock)
    assert graph.TIME_UP.format(secs=30) in out and find_librarian_header(out).verdict == "PARTIAL"

    async def hold(step):
        await asyncio.Event().wait()

    hung = LibrarianModel({"shortlist": {"pages": ["patt:412"]}}, hold=hold)
    Harness(monkeypatch, model=hung)
    monkeypatch.setattr(agent_tools, "_hard_limit_sec", lambda settings: 0.2)
    out, drained = ask()
    assert agent_tools.HARD_TIME_UP.format(secs=30) in out and find_librarian_header(out).verdict == "PARTIAL"
    assert hung.calls == 1 and drained["tradecraft_ask_count"] == 1

    class HangingLibrary:
        async def search(self, query):
            await asyncio.Event().wait()

    Harness(monkeypatch, lib=HangingLibrary())
    out, _ = ask()
    assert out == agent_tools.LIBRARY_TIMEOUT.format(secs=30)


def test_a_library_error_is_said_plainly(monkeypatch):
    class Broken:
        async def search(self, query):
            raise RuntimeError("db down at 10.0.0.5")

    Harness(monkeypatch, lib=Broken())
    out, _ = ask()
    assert out == agent_tools.LIBRARY_ERROR and "10.0.0.5" not in out


# --------------------------------------------------------------------------------------
# The per-run limit
# --------------------------------------------------------------------------------------

def test_per_run_limit(monkeypatch):
    h = Harness(monkeypatch)

    async def work():
        outs = [await agent_tools.ask_tool.ainvoke({"need": f"{NEED} {n}"}) for n in range(3)]
        return outs, run_state.current().drain()

    outs, drained = in_run(work, cat=catalog(**{"librarian.questionsPerRun": 2}), settings=run_settings(model=""))
    assert [find_librarian_header(o) is not None for o in outs] == [True, True, False]
    assert outs[2] == agent_tools.ASK_LIMIT.format(limit=2)
    # Refused before anything runs: no search for the third, and the count stays at the limit.
    assert len([c for c in h.lib.calls if c[0] == "search"]) == 2 and drained["tradecraft_ask_count"] == 2


def test_the_limit_holds_for_asks_at_once(monkeypatch):
    """A plan wave's asks run at once: exactly the limit's number get through."""
    Harness(monkeypatch)

    async def work():
        outs = await asyncio.gather(*(agent_tools.ask_tool.ainvoke({"need": f"{NEED} {n}"}) for n in range(5)))
        return outs, run_state.current().drain()

    outs, drained = in_run(work, cat=catalog(**{"librarian.questionsPerRun": 3}), settings=run_settings(model=""))
    assert sum(o == agent_tools.ASK_LIMIT.format(limit=3) for o in outs) == 2 and drained["tradecraft_ask_count"] == 3


def test_incr_within_is_one_step():
    collector = run_state.RunCollector({"session_id": "s", "current_objective_index": 0}, "s")
    assert [collector.incr_within("ask", 2) for _ in range(3)] == [1, 2, None]
    assert collector.counts()["ask"] == 2
    with pytest.raises(ValueError):
        collector.incr_within("nope", 1)


deploy = importlib.import_module("orchestrator_helpers.nodes.fireteam_deploy_node")


class AskingMembers:
    """Fireteam members that bind the run state from their own state (as their executor nodes do)
    and ask the librarian twice each."""

    def __init__(self):
        self.answers: list = []

    def astream(self, member_state, config=None):
        return self._run(member_state)

    async def _run(self, member_state):
        run_state.bind(member_state)
        agent_tools.bind_session(member_state)
        for n in range(2):
            self.answers.append(await agent_tools.ask_tool.ainvoke({"need": f"{NEED} member {n}"}))
            await asyncio.sleep(0)
        yield {"fireteam_complete": {"task_complete": True, "completion_reason": "complete", "current_iteration": 1,
                                     "tokens_used": 0, "execution_trace": [], "target_info": {},
                                     "chain_findings_memory": []}}


def test_per_run_limit_across_members(monkeypatch):
    """D-48: the main agent and two Fireteam members stop at one limit of 3: one ask of the main
    agent, then four of the members, of which two are answered; the deploy node returns 3."""
    Harness(monkeypatch)
    members = AskingMembers()
    parent = {**STATE, "user_id": "u", "project_id": "p", "current_iteration": 4,
              "_current_fireteam_plan": {"plan_rationale": "r", "members": [
                  {"name": f"M{i}", "task": f"task {i}", "tools": [], "max_iterations": 5} for i in range(2)]}}

    async def work():
        main = await agent_tools.ask_tool.ainvoke({"need": NEED})
        with patch.object(deploy, "_persist_deploy", new=AsyncMock(return_value="id")), \
                patch.object(deploy, "_patch_member", new=AsyncMock()), \
                patch.object(deploy, "_patch_fireteam", new=AsyncMock()):
            out = await deploy.fireteam_deploy_node(parent, None, member_graph=members, streaming_callbacks={},
                                                    neo4j_creds=None)
        return main, out

    settings = run_settings(model="", FIRETEAM_MAX_MEMBERS=5, FIRETEAM_MAX_CONCURRENT=3, FIRETEAM_TIMEOUT_SEC=60,
                            FIRETEAM_MEMBER_MAX_ITERATIONS=5)
    main, out = in_run(work, cat=catalog(**{"librarian.questionsPerRun": 3}), settings=settings, state=parent)
    assert find_librarian_header(main) is not None
    refused = [a for a in members.answers if a == agent_tools.ASK_LIMIT.format(limit=3)]
    assert len(members.answers) == 4 and len(refused) == 2
    assert out["tradecraft_ask_count"] == 3


# --------------------------------------------------------------------------------------
# The owner's model, from the run's binding only
# --------------------------------------------------------------------------------------

def test_owner_model(monkeypatch):
    """Q10 "Shared projects": a collaborator's run uses the owner's librarian model (the run's
    USER_SETTINGS and providers are the owner's, ``fetch_agent_settings``); the searches are the
    owner's library, and the person is whom the model calls are charged to."""
    model = LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER})
    h = Harness(monkeypatch, model=model)
    out, _ = ask(cat=catalog(person=PERSON))
    assert h.built == [(LIBRARIAN, PROVIDERS)] and find_librarian_header(out).verdict == "FOUND"
    assert h.made[0]["owner_id"] == OWNER
    kw = h.asked[0][1]
    assert (kw["owner_id"], kw["person_id"]) == (OWNER, PERSON)
    meta = model.configs[0]["metadata"]
    assert (meta["user_id"], meta["owner_id"]) == (PERSON, OWNER)
    assert model.purposes[0]["purpose"] == "tradecraft_librarian"


def test_unbound_context_no_model(monkeypatch):
    """A call outside a run's task (no settings bound to it, or no run state) builds no model,
    even when the module-global settings of the last project loaded name one (R-405)."""
    Harness(monkeypatch)
    monkeypatch.setattr(ps, "_settings", run_settings(model="openai/another-owners-model"))
    for settings, bind in ((False, True), (None, False)):
        model = LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER})
        h = Harness(monkeypatch, model=model)
        out, _ = ask(settings=settings, bind=bind)
        assert h.built == [] and model.calls == 0
        assert agent_tools.OUTSIDE_RUN in out and find_librarian_header(out).verdict == "PARTIAL"


# --------------------------------------------------------------------------------------
# Where it is offered
# --------------------------------------------------------------------------------------

def allowed_in(settings):
    def go():
        ps._settings_ctx.set(settings)
        return ([p for p in ("informational", "exploitation", "post_exploitation")
                 if ps.is_tool_allowed_in_phase("tradecraft_ask", p)],
                [p for p in ("informational", "exploitation", "post_exploitation")
                 if "tradecraft_ask" in ps.get_allowed_tools_for_phase(p)])

    return contextvars.Context().run(go)


def test_follows_lookup_phases_and_the_librarian_use():
    both = ["exploitation", "post_exploitation"]
    assert allowed_in(run_settings()) == (both, both)
    assert allowed_in(run_settings(TRADECRAFT_ASK=False)) == ([], [])
    assert allowed_in(run_settings(TRADECRAFT_V2=False)) == ([], [])
    assert allowed_in({**run_settings(), "TOOL_PHASE_MAP": {"tradecraft_lookup": []}}) == ([], [])
    # No phase-map key of its own: a project's saved map never names it.
    assert allowed_in({**run_settings(), "TOOL_PHASE_MAP": {"tradecraft_ask": ["informational"]}}) == ([], [])
    from tool_offload_policy import OFFLOAD_POLICY
    assert OFFLOAD_POLICY["tradecraft_ask"] == "never"


def test_not_offered_with_search_only(monkeypatch):
    search_only = catalog(**{"librarian.use": "search_only"})
    from tradecraft.contract import V2Catalog
    entries = overlay.build_entries(V2Catalog.model_validate(search_only))
    assert "tradecraft_ask" not in entries
    assert all("tradecraft_ask" not in e["description"] for e in entries.values())
    # Called anyway, it answers that it is not available, and counts nothing.
    h = Harness(monkeypatch)
    out, drained = ask(cat=search_only, settings=run_settings(TRADECRAFT_ASK=False))
    assert out == agent_tools.ASK_NOT_AVAILABLE and h.lib.calls == [] and drained["tradecraft_ask_count"] == 0
    # A 1.x run, or no catalog bound.
    assert ask(cat={"v2": False, "legacy": []})[0] == agent_tools.ASK_NOT_AVAILABLE


def test_the_run_settings_carry_the_librarian_use():
    """``fetch_agent_settings``: TRADECRAFT_ASK is on for a 2.0 catalog whose Librarian use is Agent
    decides (the default), off for Search only, a 1.x catalog or a failed fetch."""
    from test_tradecraft_runtime import _Resp, fetch_with

    cases = ((catalog(), True), (catalog(**{"librarian.use": "search_only"}), False),
             ({**catalog(), "search": {}}, True), ({"v2": False, "legacy": []}, False))
    for answer, expected in cases:
        settings, _ = fetch_with(_Resp(200, answer))
        assert settings["TRADECRAFT_ASK"] is expected, answer.get("search")
    settings, _ = fetch_with(_Resp(500, None, "x"))
    assert settings["TRADECRAFT_ASK"] is False and settings["TRADECRAFT_V2"] is False


def test_registry_entry():
    from tradecraft.contract import V2Catalog

    entries = overlay.build_entries(V2Catalog.model_validate(catalog(**{"librarian.timeLimitSec": 45,
                                                                       "librarian.questionsPerRun": 7})))
    assert list(entries) == ["tradecraft_lookup", "tradecraft_search", "tradecraft_ask"]
    entry = entries["tradecraft_ask"]
    assert set(entry) == {"purpose", "when_to_use", "args_format", "description"}
    assert entry["description"].startswith("**tradecraft_ask**") and len(entry["description"]) >= 100
    assert '"need"' in entry["args_format"] and "45 s" in entry["description"] and "7 questions" in entry["description"]
    for name in ("tradecraft_lookup", "tradecraft_search"):
        assert "you cannot tell what fits, or search shows only related pages ... tradecraft_ask" in \
            entries[name]["description"]


# --------------------------------------------------------------------------------------
# Dispatch: the single tool and a plan wave, through the real executor nodes
# --------------------------------------------------------------------------------------

def test_registered_as_a_stand_in():
    assert "tradecraft_ask" in tool_proxies.V2_TOOL_NAMES
    assert set(tool_proxies.registered_tools()) == {"tradecraft_lookup", "tradecraft_search", "tradecraft_ask"}


def test_dispatch_single_and_plan(monkeypatch):
    """The executor registers the stand-in once; execute_tool_node and execute_plan_node bind the
    run state and the session, dispatch the real tool, and return the counts and pages."""
    from tools import PhaseAwareToolExecutor

    tool_node = importlib.import_module("orchestrator_helpers.nodes.execute_tool_node")
    plan_node = importlib.import_module("orchestrator_helpers.nodes.execute_plan_node")
    model = LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER})
    Harness(monkeypatch, model=model)
    config = {"configurable": {"user_id": OWNER, "project_id": "p-1", "session_id": "s-1"}}
    args = {"need": NEED, "want": "payload"}

    async def work():
        executor = PhaseAwareToolExecutor(None, graph_tool=None)
        single = await tool_node.execute_tool_node(
            {**STATE, "_current_step": {"tool_name": "tradecraft_ask", "tool_args": args}}, config,
            tool_executor=executor, streaming_callbacks={}, session_manager_base="")
        plan = {"plan_rationale": "two asks", "steps": [
            {"tool_name": "tradecraft_ask", "tool_args": {**args, "need": NEED + " (a)"}},
            {"tool_name": "tradecraft_ask", "tool_args": {**args, "need": NEED + " (b)"}}]}
        waved = await plan_node.execute_plan_node(
            {**STATE, **single, "_current_plan": plan}, config,
            tool_executor=executor, streaming_callbacks={}, session_manager_base="")
        return single, waved

    single, waved = in_run(work, bind=False)
    assert single["_tool_result"]["success"] is True
    assert find_librarian_header(single["_tool_result"]["output"]).verdict == "FOUND"
    assert single["tradecraft_ask_count"] == 1 and single["tradecraft_seen_pages"] == ["patt:412"]
    steps = waved["_current_plan"]["steps"]
    assert all(s["success"] and find_librarian_header(s["tool_output"]) for s in steps)
    assert waved["tradecraft_ask_count"] == 3
