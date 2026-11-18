"""The focus-aware crawl (T5.2, §6.14 step 4): keep and follow are separate decisions of one call,
the links that name the focus are offered and visited first, the page's excerpt reaches the model
only inside an untrusted block, and the focus costs no extra model call (R-177).

Sites are written into a temporary folder and served by ``FixtureFetcher``; the model is scripted.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import clock, net  # noqa: E402
from tradecraft.ingest import crawl as c  # noqa: E402
from tradecraft.ingest import focus  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FakeClock, FixtureFetcher, run  # noqa: E402

HOST = "focus.tc-fixture.test"
SITE = f"https://{HOST}"
TEXT = "Synthetic notes for the focus tests, long enough to be kept by the crawl's rules. " * 10
SQLI = focus.Focus(mode="focused", topics=("sql_injection",), kinds=("payloads",), keep="SQL injection payloads",
                   strictness="balanced")


def page(title, links=(), body=TEXT):
    anchors = "".join(f'<a href="{h}">{t}</a>' for h, t in links)
    return f"<html><head><title>{title}</title></head><body><main><p>{body}</p>{anchors}</main></body></html>"


def write_site(root: Path) -> Path:
    files = {
        "/": page("Web attacks index", [("/news/", "Site news"), ("/xss-basics/", "XSS basics"),
                                        ("/sqli-union/", "SQL injection union payloads"),
                                        ("/about-us/", "Who we are"), ("/sqli-blind/", "Blind SQLi payloads")],
                  body="Index of web attack pages. " * 30),
        "/news/": page("Site news", body="Our team went to a conference. " * 30),
        "/xss-basics/": page("XSS basics"),
        "/sqli-union/": page("SQL injection union payloads", [("/sqli-advanced/", "SQLi advanced payloads")],
                             body="UNION SELECT payloads. " * 40),
        "/sqli-advanced/": page("SQLi advanced payloads", body="Stacked query payloads. " * 40),
        "/about-us/": page("Who we are"),
        "/sqli-blind/": page("Blind SQLi payloads", body="Blind payloads with sleep. " * 40),
    }
    for path, text in files.items():
        target = root / HOST / path.lstrip("/") / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


class CrawlModel:
    """Answers each crawl prompt with ``decide(current_path, offered) -> dict``; records prompts."""

    def __init__(self, decide):
        self.decide = decide
        self.prompts: list[str] = []

    async def ainvoke(self, prompt, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        self.prompts.append(prompt)
        current = re.search(r"Just visited: (\S+)", prompt).group(1)
        offered = re.findall(r'^\s+(\d+)\. "([^"]*)" -> (\S+)$', prompt, re.M)
        return AIMessage(content=json.dumps(self.decide(current.replace(SITE, "") or "/", offered)))

    @property
    def calls(self):
        return len(self.prompts)


def settings(**values):
    return EffectiveSettings({"crawl.strategy": "llm", "fetching.browserEnabled": False, "crawl.parallel": 1,
                              "crawl.respectRobots": False, "crawl.minTextChars": 100, **values})


def crawl(tmp_path, model, focus_value=SQLI, **values):
    root = write_site(tmp_path / "sites")
    with clock.use_clock(FakeClock()), net.use_fetcher(FixtureFetcher(root)):
        return run(c.crawl(SITE + "/", settings(**values), llm=model, focus=focus_value))


def follow_all_then_judge(current, offered):
    keep = "sqli" in current
    return {"action": "follow", "indices": [int(n) for n, _t, _p in offered], "keep": keep,
            "reason": "SQL injection payloads" if keep else ("a hub of attack pages" if current == "/" else "not SQLi")}


def test_keep_and_follow_separate(tmp_path):
    """A hub page is followed without being kept: it stays as a dropped entry, its links are
    visited, and the pages they lead to are kept on their own decision."""
    model = CrawlModel(follow_all_then_judge)
    result = crawl(tmp_path, model)
    by_path = {e.url.replace(SITE, ""): e for e in result.entries}
    home = by_path["/"]
    assert home.extra["status"] == "dropped" and home.extra["drop_reason"] == "a hub of attack pages"
    assert home.extra["dropped_by"] == "focus"
    assert by_path["/sqli-union/"].extra["focus_decision"] == "keep"
    assert by_path["/sqli-union/"].extra.get("status", "kept") == "kept"
    # A page no call was made on (a leaf) carries no decision: the title triage judges it.
    assert "focus_decision" not in by_path["/sqli-advanced/"].extra
    assert set(by_path) >= {"/sqli-union/", "/sqli-blind/", "/news/"}


def test_relevant_links_first(tmp_path):
    """The links that name the focus are offered first and visited first."""
    model = CrawlModel(follow_all_then_judge)
    result = crawl(tmp_path, model)
    offered = re.findall(r'^\s+\d+\. "([^"]*)"', model.prompts[0], re.M)
    assert offered[:2] == ["SQL injection union payloads", "Blind SQLi payloads"]
    visited = [e.url.replace(SITE, "") for e in result.entries]
    assert visited[:3] == ["/", "/sqli-union/", "/sqli-blind/"]
    # Rule-based crawls with no model rank the same way.
    ruled = crawl(tmp_path / "rules", None, **{"crawl.strategy": "rules"})
    assert [e.url.replace(SITE, "") for e in ruled.entries][:3] == ["/", "/sqli-union/", "/sqli-blind/"]


def test_no_extra_calls(tmp_path):
    """The keep decision rides on the follow call: a focused crawl makes as many calls as the
    same crawl without a focus."""
    focused = CrawlModel(follow_all_then_judge)
    plain = CrawlModel(lambda current, offered: {"action": "follow", "indices": [int(n) for n, _t, _p in offered],
                                                 "reason": "x"})
    with_focus = crawl(tmp_path / "a", focused)
    without = crawl(tmp_path / "b", plain, focus.Focus())
    assert focused.calls == plain.calls == with_focus.llm_calls == without.llm_calls > 0
    assert all("focus_decision" not in e.extra for e in without.entries)


def test_the_prompt_carries_the_focus_and_a_wrapped_excerpt(tmp_path):
    model = CrawlModel(follow_all_then_judge)
    crawl(tmp_path, model)
    prompt = model.prompts[0]
    assert "The owner's focus" in prompt and "SQL injection payloads" in prompt and '"keep": false' in prompt
    m = re.search(r"Excerpt of the page just visited:\n<<<UNTRUSTED_WEB_CONTENT id=(\w+)>>>\n(.*?)\n"
                  r"<<<END_UNTRUSTED_WEB_CONTENT id=\1>>>", prompt, re.S)
    assert m and "Index of web attack pages." in m.group(2) and len(m.group(2)) <= c.EXCERPT_CHARS
    outside = re.sub(r"<<<UNTRUSTED_(\w+) id=(\w+)>>>.*?<<<END_UNTRUSTED_\1 id=\2>>>", "", prompt, flags=re.S)
    assert "Index of web attack pages" not in outside


def test_without_a_focus_the_prompt_is_unchanged(tmp_path):
    model = CrawlModel(lambda current, offered: {"action": "stop", "reason": "enough"})
    crawl(tmp_path, model, focus.Focus(mode="everything", topics=("sql_injection",)))
    prompt = model.prompts[0]
    assert "owner's focus" not in prompt and "Excerpt of the page" not in prompt and '"keep"' not in prompt
    assert prompt.rstrip().endswith('{"action": "follow", "indices": [1, 4, 7], "reason": "..."}')


def test_an_answer_without_keep_leaves_the_page_to_the_triage(tmp_path):
    model = CrawlModel(lambda current, offered: {"action": "follow", "indices": [1, 2], "keep": "yes",
                                                 "reason": "x"})
    result = crawl(tmp_path, model)
    assert result.entries and all("focus_decision" not in e.extra for e in result.entries)
