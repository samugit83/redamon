"""Library search (T2.4), without Postgres: the free first pass's wordings and limits (R-373),
the merge and the boosts that never filter (Q7.2, R-412), the verdicts and their one knob
(R-374, R-418), synonyms (TD-14), and the statements' keys and bound query text (D-56, Q12).

The ranking, stemming, trigram and isolation on a real Postgres:
``test_tradecraft_search_integration.py``.
"""

from __future__ import annotations

import ast
import asyncio
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.contract import V2Catalog  # noqa: E402
from tradecraft.library import search, search_sql, synonyms  # noqa: E402
from tradecraft.settings import EffectiveSettings, load_spec  # noqa: E402

LIB = Path(__file__).resolve().parent.parent / "tradecraft" / "library"
OWNER = "u-owner"


def catalog(*resources, search_settings=None):
    rows = []
    for i, (rid, slug, priority) in enumerate(resources):
        rows.append({"id": rid, "slug": slug, "name": slug.upper(), "url": f"https://{slug}.tc-fixture.test/",
                     "type": "mkdocs-wiki", "storage_mode": "live", "summary": f"summary of {slug}",
                     "priority": priority, "map_version": 3})
    return V2Catalog.model_validate({"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None,
                                     "search": search_settings or {}, "resources": rows})


def row(entry_id, rid="r1", rank=1.0, **cols):
    base = {"id": entry_id, "page_id": entry_id, "resource_id": rid, "url": f"https://x.test/{entry_id}",
            "title": f"page {entry_id}", "title_source": "real", "breadcrumb": [], "headings": [], "description": "",
            "topics": [], "kinds": [], "technologies": [], "entities": [], "size_chars": 0, "fetched_at": None,
            "stored": False, "rank": rank}
    base.update(cols)
    return base


class FakeIndex:
    """Answers each statement from ``answers`` (a dict of name -> rows, or a function of the
    params), and records every call."""

    def __init__(self, answers=None, coverage=None):
        self.answers = answers or {}
        self.coverage = coverage or {}
        self.calls = []

    async def rows(self, name, params):
        assert name in search_sql.STATEMENTS
        self.calls.append((name, dict(params)))
        if name == "assess":
            out = []
            for i in params["ids"]:
                strong, anywhere, *total = self.coverage.get(i, (0, 0))
                out.append(dict(id=i, strong=strong, anywhere=anywhere, total=total[0] if total else 1))
            return out
        answer = self.answers.get(name, [])
        return [dict(r) for r in (answer(params) if callable(answer) else answer)]

    def names(self):
        return [n for n, _ in self.calls]


def run(coro):
    return asyncio.run(coro)


SESSION = search.Session(topic="sql_injection", phase="exploitation", technologies=("postgresql", "nginx"))


def test_wordings_and_limits():
    words = search.wordings_for("WAF blocks SLEEP delay Postgres CVE-2024-0001", session=SESSION)
    assert [w.kind for w in words] == ["words", "synonyms", "topic", "technologies", "entities", "fuzzy"]
    assert len(words) == search.WORDINGS == 6
    assert words[0].params == {"q": "waf or blocks or sleep or delay or postgres or cve or 2024 or 0001"}
    assert "web application firewall" in words[1].label and words[2].label == "+ topic SQL injection"
    assert words[3].params["techs"] == ["postgresql", "nginx"] and words[3].label == "+ PostgreSQL, nginx"
    assert words[4].params["ents"] == ["CVE-2024-0001", "postgresql"]
    assert search.PER_WORDING == 20 and search.MERGED == 40

    many = {name: [row(i, rank=1.0 / i) for i in range(1, 30)]
            for name in ("entries_text", "entries_entities", "entries_fuzzy")}
    many["entries_text"] = lambda p: [row(i + (100 if "techs" in p and p["techs"] else 0), rank=1.0 / i)
                                      for i in range(1, 30)]
    index = FakeIndex(many, coverage={i: (1, 1) for i in range(1, 200)})
    answer = run(search.search(OWNER, catalog(("r1", "wiki", "normal")), "waf blocks sleep delay postgres CVE-2024-0001",
                               session=SESSION, index=index))
    text_calls = [p for n, p in index.calls if n not in ("assess", "section_snippets")]
    assert text_calls and all(p["limit"] == 20 for p in text_calls)
    assessed = next(p for n, p in index.calls if n == "assess")
    assert len(assessed["ids"]) == 40
    assert answer.verdict == "FOUND" and len(answer.hits) == 8 and answer.total == 40
    fewer = run(search.search(OWNER, catalog(("r1", "wiki", "normal"), search_settings={"search.results": 3}),
                              "sleep", index=index))
    assert len(fewer.hits) == 3


def test_a_page_found_by_several_wordings_rises():
    answers = {"entries_text": lambda p: [row(1)] if p["topic"] else [row(2, rank=0.9), row(1, rank=0.5)]}
    cov = {1: (1, 1), 2: (1, 1)}
    cat = catalog(("r1", "wiki", "normal"))
    alone = run(search.search(OWNER, cat, "ab", index=FakeIndex(answers, cov)))
    assert [h.card.page_id for h in alone.hits] == ["wiki:2", "wiki:1"]
    both = run(search.search(OWNER, cat, "ab", session=search.Session(topic="xss"), index=FakeIndex(answers, cov)))
    assert [h.card.page_id for h in both.hits] == ["wiki:1", "wiki:2"]
    assert [h.wordings_matched for h in both.hits] == [2, 1]


def test_verdicts():
    cat = catalog(("r1", "wiki", "normal"))
    answers = {"entries_text": [row(1), row(2), row(3)]}
    strong = run(search.search(OWNER, cat, "kerberoasting", index=FakeIndex(answers, {1: (1, 1), 2: (0, 1)})))
    assert strong.verdict == "FOUND" and [h.card.page_id for h in strong.hits] == ["wiki:1", "wiki:2"]
    related = run(search.search(OWNER, cat, "kerberoasting", index=FakeIndex(answers, {2: (0, 1)})))
    assert related.verdict == "RELATED" and [h.card.page_id for h in related.hits] == ["wiki:2"]
    nothing = run(search.search(OWNER, cat, "kerberoasting", index=FakeIndex(answers, {})))
    assert nothing.verdict == "NOT FOUND" and nothing.hits == () and nothing.total == 0
    assert nothing.wordings == ("kerberoasting", "fuzzy titles")
    nothing_index = FakeIndex({})
    empty = run(search.search(OWNER, cat, "kerberoasting", index=nothing_index))
    assert empty.verdict == "NOT FOUND" and "assess" not in nothing_index.names()


def test_an_exact_cve_is_found_and_a_close_typo_is_related():
    cat = catalog(("r1", "cve", "normal"))
    found = run(search.search(OWNER, cat, "CVE-2024-23897",
                              index=FakeIndex({"entries_entities": [row(7, entities=["CVE-2024-23897"])]})))
    assert found.verdict == "FOUND" and found.hits[0].card.page_id == "cve:7"
    typo = run(search.search(OWNER, cat, "kerberaosting", index=FakeIndex({"entries_fuzzy": [row(3, rank=0.55)]})))
    assert typo.verdict == "RELATED" and typo.hits[0].card.page_id == "cve:3"


def test_strictness_only_knob():
    answers = {"entries_text": [row(1)]}
    cov = {1: (2, 2, 3)}  # two of three term groups, in the title: 0.67
    verdicts = {}
    for level in ("strict", "balanced", "loose"):
        settings = EffectiveSettings({"search.strictness": level}, scope="search")
        verdicts[level] = run(search.search(OWNER, catalog(("r1", "wiki", "normal")), "a b c", settings=settings,
                                            index=FakeIndex(answers, cov))).verdict
    assert verdicts == {"strict": "NOT FOUND", "balanced": "RELATED", "loose": "FOUND"}
    # The one control: no search setting names a weight, a threshold or the merge.
    keys = [s["key"] for s in load_spec()["settings"] if s["key"].startswith("search.")]
    assert sorted(keys) == ["search.results", "search.strictness", "search.useSession"]
    assert set(search.STRICTNESS) == set(next(s for s in load_spec()["settings"]
                                              if s["key"] == "search.strictness")["values"])


def test_priority_boost():
    cat = catalog(("r1", "low", "low"), ("r2", "normal", "normal"), ("r3", "high", "high"))
    answers = {"entries_text": [row(1, "r1"), row(2, "r2"), row(3, "r3")]}
    answer = run(search.search(OWNER, cat, "ssrf", index=FakeIndex(answers, {1: (1, 1), 2: (1, 1), 3: (1, 1)})))
    assert [h.card.page_id for h in answer.hits] == ["high:3", "normal:2", "low:1"]


def test_session_boosts_never_filter():
    answers = {"entries_text": lambda p: [] if p["topic"] or p["techs"] else
               [row(1), row(2, topics=["sql_injection"], kinds=["payloads"], technologies=["postgresql"])]}
    index = FakeIndex(answers, {1: (1, 1), 2: (1, 1)})
    answer = run(search.search(OWNER, catalog(("r1", "wiki", "normal")), "time based", session=SESSION, index=index))
    assert [h.card.page_id for h in answer.hits] == ["wiki:2", "wiki:1"]  # boosted, and the other still there
    # The session never narrows the agent's own wording: its words run without a topic or a technology.
    words = [p for n, p in index.calls if n == "entries_text" and p["q"] == "time or based"]
    assert any(p["topic"] is None and p["techs"] == [] for p in words)
    off = FakeIndex(answers, {1: (1, 1), 2: (1, 1)})
    run(search.search(OWNER, catalog(("r1", "wiki", "normal"), search_settings={"search.useSession": False}),
                      "time based", session=SESSION, index=off))
    assert all(p["topic"] is None and p["techs"] == [] for n, p in off.calls if n == "entries_text")


def test_explicit_filters_are_filters():
    index = FakeIndex({"entries_text": [row(1)]}, {1: (1, 1)})
    run(search.search(OWNER, catalog(("r1", "wiki", "normal")), "x y", topic="SQL injection", kind="methodology",
                      technology="Postgres", session=SESSION, index=index))
    sent = [p for n, p in index.calls if n == "entries_text"]
    assert sent and all(p["topic"] == "sql_injection" and p["kind"] == "techniques" and p["tech"] == "postgresql"
                        for p in sent)
    for bad in ({"topic": "gardening"}, {"kind": "recipes"}, {"technology": "AcmeServer"}):
        with pytest.raises(search.SearchError):
            run(search.search(OWNER, catalog(("r1", "wiki", "normal")), "x", index=FakeIndex(), **bad))


def test_only_the_catalogs_resources_are_searched():
    cat = catalog(("r1", "wiki", "normal"), ("r2", "book", "normal"))
    index = FakeIndex()
    run(search.search(OWNER, cat, "xss", index=index))
    assert all(p["uid"] == OWNER and p["rids"] == ["r1", "r2"] for n, p in index.calls)
    one = FakeIndex()
    run(search.search(OWNER, cat, "xss", resource="book", index=one))
    assert all(p["rids"] == ["r2"] for n, p in one.calls)
    with pytest.raises(search.SearchError, match="available: book, wiki"):
        run(search.search(OWNER, cat, "xss", resource="someone-elses", index=FakeIndex()))


def test_term_groups_and_synonyms():
    assert search.term_groups("sqli") == ['sqli or "sql injection"']
    assert search.term_groups("SQL injection") == ['"sql injection" or sqli']
    assert search.term_groups("blind SQL injection on postgres") == [
        "blind", '"sql injection" or sqli', "on", "postgres or postgresql"]
    assert search.expand("SQL injection") == ["sqli"]
    assert search.expand("WAF and sqli") == ["sql injection", "web application firewall", "bypass"]
    user = synonyms.parse_user(["PATT = PayloadsAllTheThings", {"term": "TCX", "expansions": ["tc example"]}, 3])
    assert search.expand("patt payloads", user) == ["payloadsallthethings"]
    assert search.expand("PayloadsAllTheThings", user) == ["patt"]
    assert search.expand("tcx", user) == ["tc example"]
    assert len(synonyms.parse_user([f"a{i} = b{i}" for i in range(500)])) == synonyms.MAX_USER_SYNONYMS


def test_user_synonyms_come_from_the_runs_search_settings():
    cat = catalog(("r1", "wiki", "normal"), search_settings={"synonyms": ["PATT = PayloadsAllTheThings"]})
    index = FakeIndex()
    answer = run(search.search(OWNER, cat, "patt", index=index))
    assert "synonyms: payloadsallthethings" in answer.wordings


def test_technologies_of_drops_unknown_names():
    assert search.technologies_of(["Apache httpd 2.4.49", "AcmeCorp TargetServer", "PostgreSQL 14"]) == (
        "apache", "postgresql")


def test_query_text_only_bound():
    """D-56: every statement is fixed at import from table names and fixed fragments; the query
    text reaches Postgres only as a bound parameter."""
    tree = ast.parse((LIB / "search_sql.py").read_text())
    allowed = {"E", "S", "T", "R", "CFG", "CARD", "LIVE_E", "LIVE_S", "LIVE_T", "KEYED_E", "FILTERS", "TSQ", "GROUP",
               "GROUPS"}
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    assert isinstance(part.value, ast.Name) and part.value.id in allowed, ast.dump(part.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            raise AssertionError("no %-formatting in search_sql.py")
        if isinstance(node, ast.Attribute) and node.attr == "format":
            raise AssertionError("no str.format in search_sql.py")
    for module in ("search.py", "synonyms.py"):
        source = (LIB / module).read_text()
        assert not re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", source), module
        assert "conn.execute(search_sql.STATEMENTS[name]" in source or module == "synonyms.py"

    hostile = "x' ; DROP TABLE users; -- :* & \\ \" ( ) <%"
    index = FakeIndex()
    run(search.search(OWNER, catalog(("r1", "wiki", "normal")), hostile, index=index))
    for name, params in index.calls:
        assert hostile not in search_sql.STATEMENTS[name]
    assert any(hostile[:200] == p.get("q") for n, p in index.calls if n == "entries_fuzzy")
    text = [p["q"] for n, p in index.calls if n == "entries_text"]
    assert text and all(re.fullmatch(r"[a-z0-9]+( or [a-z0-9]+)*", q) for q in text)


def test_every_statement_is_keyed_and_reads_the_live_generation():
    for name, sql in search_sql.STATEMENTS.items():
        assert "%(uid)s" in sql, name
        assert "%(rids)s" in sql or "%(rid)s" in sql, name
        if any(f"{table} " in sql for table in (search_sql.E, search_sql.S, search_sql.T)):
            assert "generation = r.generation" in sql or "generation = rs.generation" in sql, name
        assert "generation = %(" not in sql, name  # no caller names a generation
    for sql in search_sql.PRELUDES.values():
        assert "FROM" not in sql.upper().split("SELECT", 1)[1]


def test_a_long_query_is_cut_and_its_terms_capped():
    query = " ".join(f"word{i}" for i in range(3000))
    words = search.wordings_for(query)
    assert len(words[0].params["q"].split(" or ")) == search.MAX_TERMS
    assert len(words[-1].params["q"]) <= 200


def test_normalize_path():
    assert search.normalize_path(" /Windows & Active Directory/Kerberos ") == "Windows & Active Directory/Kerberos/"
    assert search.normalize_path("/") == "" and search.normalize_path(None) == ""


def test_browse_needs_a_catalog_resource():
    with pytest.raises(search.SearchError):
        run(search.browse(OWNER, catalog(("r1", "wiki", "normal")), "other", "", index=FakeIndex()))
    index = FakeIndex({"kept_count": [{"n": 0}]})
    level = run(search.browse(OWNER, catalog(("r1", "wiki", "normal")), "wiki", "", index=index))
    assert level.summary == "summary of wiki" and level.folders == () and level.pages == ()
    assert all(p["uid"] == OWNER and p["rid"] == "r1" for _, p in index.calls)
