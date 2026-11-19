"""Library now's notice for an announced read, against every real read form.

The last thought said "Library: read <page>." for a page a block showed: the next block carries
the fixed notice unless a read of that page ran. A read is what ``run_state.record_seen`` counts,
the way S15's ``no_read_page_shown_again`` matches reads: the real ``tradecraft_lookup`` by page ID
(with or without a section), by a resource's section path (its URL), by a query the free first pass
or today's title match turns into that page; a page the librarian returns; a read in a plan wave
(``execute_plan_node``) or by a Fireteam member (the deploy node returns the run's pages). A lookup
that is refused reads nothing, so the notice stays. Each test shows the notice first on the same
run without the read, then its absence after the read.

The store is ``MemoryStore`` with the fixture sites (``test_tradecraft_reader.Library``); the
search index is S05's fake (``test_tradecraft_search_tool.Index``), answering the block's pages.
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from test_tradecraft_hints import RUN_SETTINGS, STEP, UNREAD, announcing, now, pages_of, state, todo  # noqa: E402
from test_tradecraft_reader import PAGES, WIKI, Library, header, no_browser  # noqa: E402
from test_tradecraft_search_tool import Index, row  # noqa: E402
from tradecraft import net, run_state, runtime  # noqa: E402
from tradecraft.library import hints  # noqa: E402

UNION = PAGES["SQL injection: Union based"]
KERBEROAST = PAGES["Kerberos: Kerberoasting"]
GOLDEN = PAGES["Kerberos: Golden ticket"]
PAGE = "Intro words.\n\n## Error based\n\nUse errors to leak data.\n\n## Time based\n\nUse pg_sleep for a delay.\n"
deploy = importlib.import_module("orchestrator_helpers.nodes.fireteam_deploy_node")


def wiki():
    lib = Library().add("r1", "wiki", WIKI, mode="stored", read_settings=no_browser())
    return lib.entry("r1", UNION, PAGE).entry("r1", KERBEROAST, "## How\n\nkerberoast text") \
        .entry("r1", GOLDEN, "golden ticket text")


def pid(lib, url):
    return f"wiki:{lib.store.page_ids[('r1', url)]}"


def catalog_of(lib):
    return {**lib.catalog(), "search": {"prompt.coverageMap": False}}


def index_of(lib):
    """Every text search answers the three pages, the union page first."""
    urls = (UNION, KERBEROAST, GOLDEN)
    return Index({"entries_text": [row(n, page_id=lib.store.page_ids[("r1", u)], url=u) for n, u in enumerate(urls, 1)]})


def in_run(lib, work, *, index=None, settings=None):
    """``work()`` in a run's task: the run's catalog, store, fixture sites and index bound."""
    async def go():
        ps._settings_ctx.set(settings or RUN_SETTINGS)
        with net.use_fetcher(lib.fetcher), runtime.use_store(lib.store), \
                runtime.use_index(index_of(lib) if index is None else index or None):
            runtime.bind_run_catalog(catalog_of(lib))
            return await work()

    return contextvars.Context().run(asyncio.run, go())


def block(lib, st):
    """One Library now, as the main think node asks it: (the note, the state it leaves)."""
    note, updates = in_run(lib, lambda: hints.library_now(st, runtime.bound_catalog()))
    return note, {**st, **updates}


def shown(lib):
    """A run whose first block showed the union page, and the decision that announced it."""
    st = state(todo_list=[todo(STEP, "in_progress")])
    note, st = block(lib, st)
    assert pid(lib, UNION) in pages_of(note) and UNREAD not in note
    return {**st, "_decision": announcing(pid(lib, UNION))}


def lookup(lib, st, args, *, index=None):
    """The real tool the executor dispatches, the run state bound as the executor node binds it."""
    async def work():
        with run_state.bound(st):
            out = await runtime.v2_tool_for("tradecraft_lookup").ainvoke(args)
            return out, run_state.drain()

    out, drained = in_run(lib, work, index=index)
    return out, {**st, **drained}


def test_every_lookup_form_that_reads_the_page_takes_the_notice_away():
    lib = wiki()
    page = pid(lib, UNION)
    assert UNREAD in block(lib, shown(lib))[0]
    forms = {
        "page id": ({"page": page}, None),
        "page id and section": ({"page": page, "section": "Time based"}, None),
        "section path (the URL)": ({"resource_id": "wiki", "section_path": UNION}, None),
        "query, the free first pass": ({"resource_id": "wiki", "query": "pg_sleep delay"}, None),
        "query, today's title match": ({"resource_id": "wiki", "query": "union based"}, False),
    }
    for form, (args, index) in forms.items():
        out, st = lookup(lib, shown(lib), args, index=index)
        assert not out.startswith("Error") and (page in out or header(out, "url") == UNION), (form, out[:200])
        assert page in st["tradecraft_seen_pages"], form
        note, _ = block(lib, st)
        assert UNREAD not in (note or ""), form
        assert page not in pages_of(note), form


def test_a_refused_or_other_read_leaves_the_notice():
    """A lookup that refuses (a section the page does not have) or reads another page did not read
    the announced one: the notice says so, as it says nothing of the refusal."""
    lib = wiki()
    for args in ({"page": pid(lib, UNION), "section": "Out of band"}, {"page": pid(lib, KERBEROAST)}):
        out, st = lookup(lib, shown(lib), args)
        assert pid(lib, UNION) not in st["tradecraft_seen_pages"], args
        note, _ = block(lib, st)
        assert note.count(UNREAD) == 1, args


def test_a_read_in_a_plan_wave_takes_the_notice_away():
    from tools import PhaseAwareToolExecutor

    plan_node = importlib.import_module("orchestrator_helpers.nodes.execute_plan_node")
    lib = wiki()
    st = shown(lib)
    config = {"configurable": {"user_id": "u", "project_id": "p-1", "session_id": st["session_id"]}}
    plan = {"plan_rationale": "read the page and look for more", "steps": [
        {"tool_name": "tradecraft_lookup", "tool_args": {"page": pid(lib, UNION), "section": "Time based"}},
        {"tool_name": "tradecraft_search", "tool_args": {"query": "kerberoast"}}]}

    async def work():
        return await plan_node.execute_plan_node(
            {**st, "_current_plan": plan}, config, tool_executor=PhaseAwareToolExecutor(None, graph_tool=None),
            streaming_callbacks={}, session_manager_base="")

    st["_decision"] = {**st["_decision"], "action": "plan_tools", "tool_name": None}
    assert UNREAD in block(lib, st)[0]
    waved = in_run(lib, work)
    assert all(s["success"] for s in waved["_current_plan"]["steps"]), waved["_current_plan"]["steps"]
    after = {**st, **{k: v for k, v in waved.items() if k != "_current_plan"}}
    assert pid(lib, UNION) in after["tradecraft_seen_pages"]
    note, _ = block(lib, after)
    assert UNREAD not in (note or "")


class ReadingMember:
    """A Fireteam member that binds the run state from its own state (as its executor node does)
    and reads one page with the real tool."""

    def __init__(self, page):
        self.page, self.reads = page, []

    def astream(self, member_state, config=None):
        return self._run(member_state)

    async def _run(self, member_state):
        run_state.bind(member_state)
        self.reads.append(await runtime.v2_tool_for("tradecraft_lookup").ainvoke({"page": self.page}))
        yield {"fireteam_complete": {"task_complete": True, "completion_reason": "complete", "current_iteration": 1,
                                     "tokens_used": 0, "execution_trace": [], "target_info": {},
                                     "chain_findings_memory": []}}


def test_a_fireteam_members_read_takes_the_notice_away():
    lib = wiki()
    st = {**shown(lib), "user_id": "u", "project_id": "p-1", "current_iteration": 2,
          "_current_fireteam_plan": {"plan_rationale": "r", "members": [
              {"name": "M0", "task": "read the page", "tools": [], "max_iterations": 5}]}}
    st["_decision"] = {**st["_decision"], "action": "deploy_fireteam", "tool_name": None}
    assert UNREAD in block(lib, st)[0]
    member = ReadingMember(pid(lib, UNION))
    settings = {**RUN_SETTINGS, "FIRETEAM_MAX_MEMBERS": 5, "FIRETEAM_MAX_CONCURRENT": 3, "FIRETEAM_TIMEOUT_SEC": 60,
                "FIRETEAM_MEMBER_MAX_ITERATIONS": 5}

    async def work():
        with patch.object(deploy, "_persist_deploy", new=AsyncMock(return_value="id")), \
                patch.object(deploy, "_patch_member", new=AsyncMock()), \
                patch.object(deploy, "_patch_fireteam", new=AsyncMock()):
            return await deploy.fireteam_deploy_node(st, None, member_graph=member, streaming_callbacks={},
                                                     neo4j_creds=None)

    out = in_run(lib, work, settings=settings)
    assert member.reads and not member.reads[0].startswith("Error")
    after = {**st, **{k: out[k] for k in run_state.FIELDS}}
    assert pid(lib, UNION) in after["tradecraft_seen_pages"]
    note, _ = block(lib, after)
    assert UNREAD not in (note or "")
    # The run's Library now entry came back from the deploy node as the main think left it.
    assert [e for e in after["tradecraft_hint_log"] if e.get("kind") == "library_now"] == \
        [e for e in st["tradecraft_hint_log"] if e.get("kind") == "library_now"]


def test_a_page_the_librarian_returns_takes_the_notice_away(monkeypatch):
    from test_tradecraft_ask_tool import FOUND_ANSWER, NEED, Harness, LibrarianModel
    from test_tradecraft_ask_tool import catalog as ask_catalog
    from test_tradecraft_ask_tool import in_run as ask_in_run
    from tradecraft import agent_tools

    Harness(monkeypatch, model=LibrarianModel({"shortlist": {"pages": ["patt:412"]}, "judge": FOUND_ANSWER}))
    index = Index({"entries_text": [row(12), row(13), row(14)]})
    st = state(todo_list=[todo(STEP, "in_progress")])
    note, updates = now(st, cat=ask_catalog(), index=index)
    assert "patt:412" in pages_of(note)
    st = {**st, **updates, "_decision": {**announcing("patt:412"), "tool_name": "tradecraft_ask"}}
    assert UNREAD in now(st, cat=ask_catalog(), index=index)[0]

    async def work():
        await agent_tools.ask_tool.ainvoke({"need": NEED, "want": "payload"})
        return run_state.current().drain()

    st = {**st, **ask_in_run(work, state=st)}
    assert "patt:412" in st["tradecraft_seen_pages"]
    note, _ = now(st, cat=ask_catalog(), index=index)
    assert UNREAD not in (note or "")
