"""Sections (T2.3, R-335): a stored page split by its headings of levels 1-3, with stable
anchors, and a code block never split across two sections.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.ingest import sections  # noqa: E402
from tradecraft.ingest.storage import StoredPage  # noqa: E402

PAGE = """Intro line before any heading.

# PostgreSQL

Overview of the page.

## Time based

Use pg_sleep.

```sql
# not a heading: a comment inside code
SELECT pg_sleep(10);
## still code
```

#### A level-4 heading stays inside

more text

## Time based

The same heading again.

### Error based ###
Last words.
"""


def test_split_by_headings_levels_1_to_3():
    got = sections.split_markdown(PAGE)
    assert [(s.ord, s.heading, s.level) for s in got] == [
        (0, "", 0), (1, "PostgreSQL", 1), (2, "Time based", 2), (3, "Time based", 2), (4, "Error based", 3)]
    assert got[0].text == "Intro line before any heading."
    assert "#### A level-4 heading stays inside" in got[2].text


def test_code_blocks_never_split():
    time_based = sections.split_markdown(PAGE)[2]
    assert "# not a heading: a comment inside code" in time_based.text
    assert "## still code" in time_based.text
    assert time_based.text.count("```") == 2


def test_unclosed_fence_keeps_the_rest_as_code():
    got = sections.split_markdown("# A\n```\n# B\n")
    assert [s.heading for s in got] == ["A"] and "# B" in got[0].text


def test_stable_anchors():
    first = [s.anchor for s in sections.split_markdown(PAGE)]
    assert first == ["", "postgresql", "time-based", "time-based-2", "error-based"]
    assert [s.anchor for s in sections.split_markdown(PAGE)] == first


def test_no_intro_section_when_the_page_starts_with_a_heading():
    got = sections.split_markdown("# Only\ntext")
    assert [(s.ord, s.heading) for s in got] == [(0, "Only")] and got[0].chars == 4


def test_heading_markup_is_cleaned():
    got = sections.split_markdown("## The [*link*](https://x.test) `code`\nbody")
    assert got[0].heading == "The link code" and got[0].anchor == "the-link-code"


def test_headings_of():
    assert sections.headings_of(PAGE) == [{"level": 1, "text": "PostgreSQL"}, {"level": 2, "text": "Time based"},
                                          {"level": 2, "text": "Time based"}, {"level": 3, "text": "Error based"}]


async def _inline(fn, *args):
    return fn(*args)


def _stored(text):
    return StoredPage(text=text, bytes=len(text.encode()), text_hash="x" * 64,
                      fetched_at=datetime(2026, 11, 10, tzinfo=timezone.utc))


def test_stage_only_for_stored_pages():
    state = SimpleNamespace(texts={"https://w.test/a/": _stored(PAGE), "https://w.test/pdf#page=1": _stored("plain")},
                            sections={}, blocking=_inline)
    asyncio.run(sections.build(state))
    rows = state.sections["https://w.test/a/"]
    assert [r["ord"] for r in rows] == [0, 1, 2, 3, 4]
    assert set(rows[1]) == {"ord", "heading", "level", "anchor", "text", "chars"}
    assert all(r["chars"] == len(r["text"]) for r in rows)
    # A page without headings (a PDF page) is one section.
    assert state.sections["https://w.test/pdf#page=1"] == [
        {"ord": 0, "heading": "", "level": 0, "anchor": "", "text": "plain", "chars": 5}]
    live = SimpleNamespace(texts={}, sections={}, blocking=_inline)
    assert asyncio.run(sections.build(live)).sections == {}
