"""The resource tree (T2.3, R-334): folders with page counts from GitHub folders or URL paths, a
virtual tree by topic for a flat website, and folder descriptions by the resource's model within
their call cap, labelled, never retried.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_core.messages import AIMessage  # noqa: E402

from agent_context import current_llm_purpose  # noqa: E402
from test_tradecraft_ingest_pipeline import RID, Harness  # noqa: E402
from tradecraft.ingest import tree  # noqa: E402
from tradecraft_memory_store import PipelineModel  # noqa: E402


class FolderModel:
    """Answers every folder-description prompt with a line per folder asked; records them."""

    def __init__(self, fail_with=None, answer=None):
        self.prompts, self.purposes = [], []
        self.fail_with, self.answer = fail_with, answer

    async def ainvoke(self, prompt, config=None, **kw):
        self.prompts.append(prompt)
        self.purposes.append(current_llm_purpose.get().get("purpose"))
        if self.fail_with is not None:
            raise self.fail_with
        if self.answer is not None:
            return AIMessage(content=self.answer)
        start = prompt.index("{", re.search(r"<<<UNTRUSTED_WEB_CONTENT id=", prompt).start())
        end = re.search(r"<<<END_UNTRUSTED_WEB_CONTENT id=", prompt).start()
        folders = json.loads(prompt[start:prompt.rindex("}", 0, end) + 1])
        return AIMessage(content=json.dumps({p: f"About {p}\nwith a second line" for p in folders}))


def _state(cards, model=None, site_type="github-repo"):
    async def build_model():
        return model

    return SimpleNamespace(cards=cards, tree=[], site_type=site_type, model=build_model, llm_calls=0,
                           errors={}, count_error=lambda code: _count(state, code),
                           check_cancelled=_nothing, request=SimpleNamespace(job_id="j1"))


def _count(state, code):
    state.errors[code] = state.errors.get(code, 0) + 1


async def _nothing():
    return None


state = None


def _run(cards, model=None, site_type="github-repo"):
    global state
    state = _state(cards, model, site_type)
    return asyncio.run(tree.build(state))


def _card(title, crumbs=(), topics=(), status="kept"):
    return {"title": title, "breadcrumb": list(crumbs), "topics": list(topics), "status": status}


def test_github_folders_with_counts():
    st = _run([_card("README"), _card("Union", ["SQL Injection"]), _card("Blind", ["SQL Injection"]),
               _card("PG", ["SQL Injection", "PostgreSQL"]), _card("Polyglots", ["XSS"]),
               _card("Dropped", ["XSS"], status="dropped")])
    assert [(n["path"], n["parent_path"], n["label"], n["page_count"], n["kind"]) for n in st.tree] == [
        ("SQL Injection/", "", "SQL Injection", 3, "folder"),
        ("SQL Injection/PostgreSQL/", "SQL Injection/", "PostgreSQL", 1, "folder"),
        ("XSS/", "", "XSS", 1, "folder")]


def test_url_path_tree_from_the_wiki(tmp_path):
    h = Harness(tmp_path, "https://wiki.tc-fixture.test/")
    assert h.run().status == "succeeded"
    nodes = {n["path"]: n for n in h.store.tree if n["resource_id"] == RID}
    assert nodes["kerberos/"]["page_count"] == 7 and nodes["kerberos/"]["kind"] == "folder"
    assert {"kerberos/", "ssrf/", "sqli/", "xss/"} <= set(nodes)


def test_virtual_topic_tree_for_the_blog(tmp_path, monkeypatch):
    """The blog's posts all sit under /posts/: a flat site, browsed by topic instead."""
    from tradecraft.ingest import crawl as crawl_mod
    from tradecraft.ingest import pipeline
    from tradecraft.ingest.builders import Candidate

    posts = sorted(p.parent.name for p in (Path(__file__).resolve().parent / "fixtures" / "tradecraft_sites" /
                                           "blog.tc-fixture.test" / "posts").glob("*/index.html"))
    base = "https://blog.tc-fixture.test/"
    entries = [Candidate(f"{base}posts/{p}/", f"Lab note {int(p[:2])}: {p.split('-')[1]}", "crawl", f"{base}posts/{p}/")
               for p in posts] + [Candidate(base + "about/", "About", "crawl", base + "about/")]

    async def fake_crawl(url, settings, **kw):
        return crawl_mod.CrawlResult(entries=entries, stop_reason="frontier_empty", stats={"pages_fetched": 1})

    monkeypatch.setattr(pipeline.crawl, "crawl", fake_crawl)
    h = Harness(tmp_path, base)
    assert h.run().status == "succeeded"
    nodes = [n for n in h.store.tree if n["resource_id"] == RID]
    assert len(posts) >= 50 and nodes and all(n["kind"] == "topic" and n["parent_path"] == "" for n in nodes)
    labels = [n["label"] for n in nodes]
    assert {"XSS", "SSRF", "SQL injection", "Active Directory", "Other"} <= set(labels) and "posts" not in labels
    live = h.store.live_entries(RID)
    xss = next(n for n in nodes if n["label"] == "XSS")
    assert xss["page_count"] == sum(1 for e in live if "xss" in e["topics"]) > 0
    other = next(n for n in nodes if n["label"] == "Other")
    assert other["page_count"] == sum(1 for e in live if not e["topics"]) > 0


def test_flat_rule():
    assert tree.is_flat([], 3)
    posts = tree.folder_tree([_card(str(i), ["posts"]) for i in range(9)] + [_card("about")])
    assert tree.is_flat(posts, 10)
    # One leaf folder holding most pages is flat however deep it sits (a blog's /posts/2024/).
    nested = tree.folder_tree([_card(str(i), ["posts", "2024"]) for i in range(9)] + [_card("about")])
    assert tree.is_flat(nested, 10)
    spread = tree.folder_tree([_card("a", ["x"]), _card("b", ["y"]), _card("c", ["z"])])
    assert not tree.is_flat(spread, 3)


def test_topic_tree_has_other_for_untagged_pages():
    st = _run([_card("a", topics=["xss"]), _card("b", topics=["xss", "ssrf"]), _card("c")], site_type="agentic-crawl")
    assert [(n["label"], n["page_count"]) for n in st.tree] == [("XSS", 2), ("SSRF", 1), ("Other", 1)]
    assert tree.topic_of_label("XSS") == "xss" and tree.topic_of_label("Other") is None


def test_no_tree_for_a_pdf_or_a_cve_archive():
    for site_type in ("pdf", "cve-poc-db"):
        assert _run([_card("p", ["x"]), _card("q", ["y"])], site_type=site_type).tree == []


def test_folder_descriptions_one_line_from_titles_untrusted():
    model = FolderModel()
    st = _run([_card("Union", ["SQL Injection"]), _card("Polyglots", ["XSS"]), _card("Other", ["XSS"])], model)
    assert [n["description"] for n in st.tree] == ["About SQL Injection/ with a second line",
                                                  "About XSS/ with a second line"]
    assert st.llm_calls == 1 and model.purposes == ["tradecraft_ingest"]
    prompt = model.prompts[0]
    opening = re.search(r"<<<UNTRUSTED_WEB_CONTENT id=[0-9a-f]+>>>", prompt).start()
    closing = re.search(r"<<<END_UNTRUSTED_WEB_CONTENT id=[0-9a-f]+>>>", prompt).start()
    assert opening < prompt.index("Polyglots") < closing


def test_folder_description_call_cap():
    model = FolderModel()
    cards = [_card(f"page {i}", [f"folder-{i:04d}"]) for i in range(600)]
    st = _run(cards, model)
    assert st.llm_calls == len(model.prompts) == 10
    described = [n for n in st.tree if n["description"]]
    assert len(described) == 500 and len(st.tree) == 600


def test_a_model_error_is_never_retried():
    class Budget(Exception):
        code = "llm_budget_exhausted"

    model = FolderModel(fail_with=Budget())
    cards = [_card(f"p{i}", [f"f{i:03d}"]) for i in range(120)]
    st = _run(cards, model)
    assert len(model.prompts) == 1 and st.errors == {"llm_budget_exhausted": 1}
    assert all(n["description"] == "" for n in st.tree)


def test_an_answer_that_is_not_json_describes_nothing():
    st = _run([_card("a", ["x"]), _card("b", ["y"])], FolderModel(answer="I cannot help with that"))
    assert st.errors == {"folder_descriptions_invalid": 1} and all(n["description"] == "" for n in st.tree)


def test_an_answer_cannot_describe_folders_it_was_not_asked_about():
    answer = json.dumps({"x/": "fine", "../evil/": "planted", "y/": 42})
    st = _run([_card("a", ["x"]), _card("b", ["y"])], FolderModel(answer=answer))
    assert {n["path"]: n["description"] for n in st.tree} == {"x/": "fine", "y/": ""}


def test_no_model_no_descriptions():
    st = _run([_card("a", ["x"]), _card("b", ["y"])], None)
    assert st.llm_calls == 0 and [n["description"] for n in st.tree] == ["", ""]
