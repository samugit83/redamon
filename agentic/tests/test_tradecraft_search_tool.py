"""``tradecraft_search`` (T2.6): its arguments (R-370), the answer's format and size (R-371,
AC-65), browse (R-372), the phases it follows (R-321), its time limit (R-322), and a 1.x run that
neither offers nor answers it (TD-10, R-I5).

The library is a fake search index (the ranking itself: ``test_tradecraft_search*.py``).
"""

from __future__ import annotations

import ast
import asyncio
import contextvars
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from tradecraft import agent_tools, runtime  # noqa: E402
from tradecraft.library.types import find_librarian_header, parse_search_header  # noqa: E402

AGENTIC = Path(__file__).resolve().parent.parent
OWNER = "u-owner"


def catalog(map_version=3, **search):
    return {"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None, "search": search,
            "resources": [
                {"id": "r1", "slug": "patt", "name": "PayloadsAllTheThings", "url": "https://patt.tc-fixture.test/",
                 "type": "github-repo", "storage_mode": "stored", "summary": "Payloads for web attacks.",
                 "map_version": map_version},
                {"id": "r2", "slug": "cves", "name": "CVE PoCs", "url": "https://github.com/tc-fixture/cve",
                 "type": "cve-poc-db", "storage_mode": "live", "summary": "PoCs by CVE id.", "map_version": 3}]}


def row(n, **cols):
    base = {"id": n, "page_id": 400 + n, "resource_id": "r1", "url": f"https://patt.tc-fixture.test/{n}",
            "title": f"PostgreSQL time based payloads number {n} with a rather long descriptive page title",
            "title_source": "real", "breadcrumb": ["SQL Injection", "PostgreSQL"], "headings": [],
            "description": "pg_sleep, heavy queries and conditional delays for blind injection " * 3,
            "topics": ["sql_injection"], "kinds": ["payloads"], "technologies": ["postgresql"], "entities": [],
            "size_chars": 1000, "fetched_at": None, "stored": True, "rank": 1.0 / n}
    base.update(cols)
    return base


class Index:
    def __init__(self, answers=None, strong=True):
        self.answers, self.strong, self.calls = answers or {}, strong, []

    async def rows(self, name, params):
        self.calls.append((name, dict(params)))
        if name == "assess":
            return [{"id": i, "total": 1, "strong": int(self.strong), "anywhere": 1} for i in params["ids"]]
        answer = self.answers.get(name, [])
        return [dict(r) for r in (answer(params) if callable(answer) else answer)]


def call(cat, args, index=None, state=None):
    async def go():
        with runtime.use_store(object()), runtime.use_index(index or Index()):
            runtime.bind_run_catalog(cat) if cat is not None else None
            if state is not None:
                agent_tools.bind_session(state)
            return await agent_tools.search_tool.ainvoke(args)

    return contextvars.Context().run(asyncio.run, go())


def lines_of(result):
    return result.splitlines()[1:-1]


def test_args():
    schema = agent_tools.search_tool.args
    assert set(schema) == {"query", "resource", "topic", "kind", "technology", "path"}
    lookup = agent_tools.lookup_tool.args
    assert {"resource_id", "query", "cve_id", "section_path", "force_refresh", "page", "section", "part"} == set(lookup)
    index = Index({"entries_text": [row(1)]})
    call(catalog(), {"query": "time based", "resource": "patt", "topic": "SQL injection", "kind": "payloads",
                     "technology": "Postgres"}, index)
    sent = [p for n, p in index.calls if n == "entries_text"][0]
    assert (sent["rids"], sent["topic"], sent["kind"], sent["tech"]) == (["r1"], "sql_injection", "payloads", "postgresql")


def test_answer_format_size():
    index = Index({"entries_text": [row(n) for n in range(1, 21)]})
    result = call(catalog(), {"query": "time-based blind SQLi PostgreSQL"}, index)
    body = lines_of(result)
    head = parse_search_header(body[0])
    assert head == {"query": "time-based blind SQLi PostgreSQL", "verdict": "FOUND", "shown": 8, "total": 20}
    assert body[1].startswith(" 1. patt:401  PayloadsAllTheThings › SQL Injection › PostgreSQL › ")
    assert body[1].endswith("(payloads)") and " — pg_sleep" in body[1]
    assert body[9] == 'read: tradecraft_lookup(page="patt:401", section="")'
    # About 500 tokens: 8 long results stay under 2,400 characters.
    assert len(result) < 2400
    assert result.startswith("<<<UNTRUSTED_TRADECRAFT_RESULT id=") and find_librarian_header(result) is None


def test_the_read_hint_names_a_section_the_read_finds():
    """Review finding 4 (R-371, Q8): the hint carries the whole heading, so following it reads
    that section. A heading cut at 60 characters with "…", or one whose double quotes the hint
    changed, answered NO_SECTION."""
    import re

    from tradecraft.library import split

    long = "Exploiting time-based blind SQL injection on PostgreSQL with heavy queries"
    quoted = 'The "sleep" and "benchmark" delays'
    sections = split.split_markdown(f"# Intro\n\ntext\n\n## {long}\n\nbody one\n\n## {quoted}\n\nbody two\n")
    for heading in (long, quoted):
        result = call(catalog(), {"query": "pg sleep"}, Index({"sections_text": [row(1, section=heading)]}))
        hint = next(line for line in lines_of(result) if line.startswith("read: "))
        value = re.fullmatch(r'read: tradecraft_lookup\(page="patt:401", section="(.*)"\)', hint).group(1)
        assert '"' not in value
        chosen = split.pick_section(sections, value)
        assert chosen is not None and chosen.heading == heading
    # A hint already cut by an earlier answer still finds its section.
    assert split.pick_section(sections, long[:59] + "…").heading == long


def test_not_found_lists_the_wordings_tried():
    result = call(catalog(), {"query": "kerberoasting"}, Index())
    body = lines_of(result)
    assert parse_search_header(body[0])["verdict"] == "NOT FOUND"
    assert body[1] == "tried: kerberoasting | fuzzy titles" and "Do not retry" in body[2]


def test_related_and_unconverted_resources_are_said():
    result = call(catalog(map_version=1), {"query": "union"}, Index({"entries_fuzzy": [row(1, rank=0.6)]}, strong=False))
    assert "Related pages only" in result
    assert "Not searchable until converted to 2.0 (read with tradecraft_lookup(resource_id=..., query=...)): patt." in result


def test_browse():
    index = Index({"tree_level": [{"path": "SQL Injection/", "parent_path": "", "label": "SQL Injection",
                                   "page_count": 31, "description": "Payloads by database.", "kind": "folder",
                                   "total": 12}],
                   "kept_count": [{"n": 388}],
                   "pages_at": [dict(row(1, title="README", breadcrumb=[]), total=1)]})
    result = call(catalog(), {"resource": "patt", "path": ""}, index)
    body = lines_of(result)
    assert body[0] == "PayloadsAllTheThings · 388 pages" and body[1] == "summary: Payloads for web attacks."
    assert body[2] == " 1. SQL Injection/   (31)  Payloads by database."
    assert body[3] == " 2. patt:401  README" and body[4] == "… 11 more"
    assert 'tradecraft_search(resource="patt", path="SQL Injection/")' in result
    # A resource with no query browses its root too; a CVE archive says how it is read.
    assert "summary:" in call(catalog(), {"resource": "patt"}, Index({"kept_count": [{"n": 0}]}))
    cve = call(catalog(), {"resource": "cves", "path": ""}, Index({"kept_count": [{"n": 0}]}))
    assert 'cve_id="CVE-YYYY-NNNNN"' in cve


def test_errors_are_plain():
    assert call(catalog(), {}, Index()) == agent_tools.NEEDS_QUERY
    assert call(catalog(), {"query": "x", "resource": "nope"}, Index()).startswith("Error: no resource 'nope'")
    assert call(catalog(), {"resource": "patt", "path": "nowhere/"}, Index()).startswith("Error: no folder")


def test_session_from_structured_state_only():
    state = {"attack_path_type": "sql_injection", "current_phase": "exploitation",
             "target_info": {"technologies": ["PostgreSQL 14.2", "nginx/1.25", "Acme TargetServer planted-text"]}}
    session = agent_tools.session_from_state(state)
    assert session.topic == "sql_injection" and session.phase == "exploitation"
    assert session.technologies == ("postgresql", "nginx")
    assert agent_tools.session_from_state({"attack_path_type": "user_skill:abc"}).topic is None
    index = Index({"entries_text": [row(1)]})
    call(catalog(), {"query": "delay"}, index, state=state)
    techs = [p["techs"] for n, p in index.calls if n == "entries_text"]
    topics = [p["topic"] for n, p in index.calls if n == "entries_text"]
    assert ["postgresql", "nginx"] in techs and "sql_injection" in topics
    assert not any("Acme" in str(p) or "planted" in str(p) for _, p in index.calls)


def test_not_offered_in_1x_run():
    def allowed(v2):
        ps._settings_ctx.set({"TOOL_PHASE_MAP": {"tradecraft_lookup": ["exploitation", "post_exploitation"]},
                              "TRADECRAFT_V2": v2})
        return ([p for p in ("informational", "exploitation", "post_exploitation")
                 if ps.is_tool_allowed_in_phase("tradecraft_search", p)],
                "tradecraft_search" in ps.get_allowed_tools_for_phase("exploitation"))

    assert contextvars.Context().run(allowed, False) == ([], False)
    # Called anyway (a 1.x catalog, or none bound), it answers that it is not available.
    assert call(None, {"query": "x"}) == agent_tools.SEARCH_NOT_AVAILABLE
    assert call({"v2": False, "legacy": []}, {"query": "x"}) == agent_tools.SEARCH_NOT_AVAILABLE


def test_follows_lookup_phases():
    def allowed(phase_map):
        ps._settings_ctx.set({"TOOL_PHASE_MAP": phase_map, "TRADECRAFT_V2": True})
        return [p for p in ("informational", "exploitation", "post_exploitation")
                if ps.is_tool_allowed_in_phase("tradecraft_search", p)
                and "tradecraft_search" in ps.get_allowed_tools_for_phase(p)]

    run = contextvars.Context().run
    assert run(allowed, {"tradecraft_lookup": ["exploitation", "post_exploitation"]}) == ["exploitation", "post_exploitation"]
    assert run(allowed, {"tradecraft_lookup": []}) == []
    assert run(allowed, {}) == []
    # No phase-map key of its own: a project's saved map never names it.
    assert run(allowed, {"tradecraft_search": ["informational"], "tradecraft_lookup": []}) == []


def test_deadlines():
    tree = ast.parse((AGENTIC / "tools.py").read_text())
    deadlines = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "tradecraft_lookup"
                                              for k in node.keys):
            deadlines = {k.value: v.value for k, v in zip(node.keys, node.values)
                         if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)}
    assert deadlines["tradecraft_lookup"] == 240
    assert deadlines["tradecraft_search"] == 60 and deadlines["tradecraft_ask"] == 150
    from tool_offload_policy import OFFLOAD_POLICY
    assert OFFLOAD_POLICY["tradecraft_search"] == "never"


def test_registered_once_and_dispatched_like_lookup():
    source = (AGENTIC / "tools.py").read_text()
    assert 'elif tool_name in ("tradecraft_lookup", "tradecraft_search", "tradecraft_ask"):' in source
    assert "self._all_tools.update(_tradecraft_v2_tools())" in source
    assert agent_tools.V2_TOOLS["tradecraft_search"] is agent_tools.search_tool
    from mcp_registry import _builtin_tool_names
    assert {"tradecraft_lookup", "tradecraft_search", "tradecraft_ask"} <= _builtin_tool_names()


def test_the_executor_registers_stand_ins_that_import_nothing_heavy():
    """Building the executor imports no langchain or langgraph through tradecraft (the agent's
    tests stub them before they build one); a stand-in calls the real tool when invoked."""
    from tradecraft import tool_proxies
    tree = ast.parse(Path(tool_proxies.__file__).read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert imported <= {"__future__", "importlib", "typing"}
    source = (AGENTIC / "tools.py").read_text()
    assert "from tradecraft.tool_proxies import registered_tools as _tradecraft_v2_tools" in source
    proxies = tool_proxies.registered_tools()
    assert set(proxies) == {"tradecraft_search", "tradecraft_ask"} == set(tool_proxies.V2_TOOL_NAMES)

    async def go():
        with runtime.use_store(object()), runtime.use_index(Index()):
            return await proxies["tradecraft_search"].ainvoke({"query": "x"})

    # Not a 2.0 run: the stand-in answers what the real tool answers.
    assert contextvars.Context().run(asyncio.run, go()) == agent_tools.SEARCH_NOT_AVAILABLE
