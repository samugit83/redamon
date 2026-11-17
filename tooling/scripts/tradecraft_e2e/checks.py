"""Reading a run's trace, and the checks of ``scenarios.yaml`` on it.

A trace is a plain dict the runner builds after a run (and saves with the run's result):

- ``tool_calls``: ``{tool, args, output, success}`` from the conversation's ``tool_complete``
  rows (``output`` is the tool's raw output, the tradecraft result envelope included);
- ``answers``: the agent's final answers (``assistant_message`` rows);
- ``prompts``: each full system prompt the agent logged for the session, reassembled from
  its ``PROMPT[i:j]`` chunks (``prompts_from_log``);
- ``library_now``: the session log's Library now lines and each main think's thought
  (``library_now_from_log``);
- ``page_store``: the owner's page-store row counts before and after the run;
- ``pages``: the cards (title, breadcrumb, description, URL, stored text) of every page the
  run's results or Library now blocks named, read from the page store after the run;
- ``api``: the route calls a single check made itself (``{name, status, code, ...}``).

The text formats parsed here are the agent's (``agentic/tradecraft/library/types.py``,
``librarian/validate.py``, ``overlay.py``, ``library/hints.py``, ``run_state.py``);
``tests/test_tradecraft_matrix_runner.py`` holds this module to the agent's own code.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Sequence

from tooling.scripts.tradecraft_e2e.report import CheckResult

TRADECRAFT_TOOLS = ("tradecraft_lookup", "tradecraft_search", "tradecraft_ask")
# A tool's row in the prompt's tool table and its registry entry's first line
# (prompts/base.py, agentic/tradecraft/overlay.py): both only in a phase that offers it.
OFFERED_MARKERS = {t: re.compile(rf"\*\*{t}\*\* [(|]") for t in
                   ("tradecraft_lookup", "tradecraft_search", "tradecraft_ask")}
COVERAGE_MAP_RE = re.compile(r"^\s*Tradecraft library \(\d+ resources?, [\d,]+ pages\)", re.M)
# librarian/graph.py LOOP_RUN: the reason an Agent in the Loop run gets the plain results.
LOOP_RUN_TEXT = "the librarian is not used in an Agent in the Loop run: these are the plain search results"

_SLUG = r"[a-z0-9][a-z0-9-]{0,199}"
_PAGE = rf"{_SLUG}:[1-9][0-9]{{0,17}}"
_OPENING = re.compile(r"^<<<UNTRUSTED_TRADECRAFT_RESULT id=[0-9a-f]+>>>$")
_CLOSING = re.compile(r"^<<<END_UNTRUSTED_TRADECRAFT_RESULT id=[0-9a-f]+>>>$")
_SEARCH_HEADER = re.compile(r'^search: ".*" · (FOUND|RELATED|NOT FOUND) · \d+ of \d+ results$')
_SEARCH_HIT = re.compile(rf"^\s*\d+\. (?P<page>{_PAGE})  (?P<rest>.*)$")
_LIBRARIAN_HEADER = re.compile(r"^librarian: (FOUND|PARTIAL|NOT FOUND) \((high|medium|low)\) · ")
_PICK = re.compile(rf"^\d+\. (?P<page>{_PAGE})  (?P<path>.*)$")
_EXCERPT = re.compile(r'^\s+excerpt: "(?P<text>.*)"$')
_READ_PAGE = re.compile(rf"^page: (?P<page>{_PAGE}) · (?P<path>.*)$")
_READ_SECTION = re.compile(r"^section: (?P<section>.*) \(part (?P<part>\d+) of (?P<parts>\d+)\) · other sections: ")
_READ_SOURCE = re.compile(r"^source: (?P<source>.*)$")
# A read the reader renders without a page ID (reader.render, "Q1.2's shape"): a CVE archive's
# entry, read live by CVE id, and the other lookups of a page that has no ID.
_LIVE_RESOURCE = re.compile(rf"^resource: (?P<slug>{_SLUG})$")
_LIVE_FIELD = re.compile(r"^(?P<key>url|section_title|source|note): (?P<value>.*)$")
# The CVE reader's title when the archive has no entry and the repository README names the CVE
# (library/reader.py _cve): that README, never the CVE's page. Every other live read keeps its title.
README_FALLBACK = re.compile(r"\(repository README; no ")
STORED_SOURCE = re.compile(r"^stored copy from \S+")
_LOG_RECORD = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:,\d+)? \| \S+\s* \| [^|]*\| [^|]*\| ?(?P<msg>.*)$")
_PROMPT_START = re.compile(r"^--- FULL SYSTEM PROMPT \(\d+ chars")
_PROMPT_CHUNK = re.compile(r"^PROMPT\[(?P<start>\d+):\d+\]:\n?", re.S)
# Library now's log lines (library/hints.py, run_state.record_seen): counts and page IDs only.
_NOW_REFRESH = re.compile(r"^\[tradecraft\] library_now refresh=(?P<refresh>\d+) reason=(?P<reason>\S+) found=(?P<found>\d+)")
_NOW_SHOWN = re.compile(r"^\[tradecraft\] library_now shown=(?P<shown>\d+) block=(?P<block>\d+) pages=(?P<pages>\S*)")
_NOW_READ = re.compile(rf"^\[tradecraft\] library_now (?P<page>{_PAGE}) read$")
_NOW_CODE = re.compile(r"^\[tradecraft\] library_now code=(?P<code>[a-z_]+)(?: refresh=(?P<refresh>\d+))?")
# think_node.py logs each think's start before Library now runs, and its thought after.
_THINK_START = re.compile(r"^# THINK NODE PROMPT - Iteration (?P<iteration>\d+)")
_THOUGHT_RECORD = "THOUGHT: "
# The one sentence the main instructions ask of each thought (hints.RULE).
_THOUGHT_READ = re.compile(rf"Library: read (?P<page>{_PAGE})", re.I)
_THOUGHT_NOTHING = re.compile(r"Library: nothing fit", re.I)
_THOUGHT_LIBRARY = re.compile(r"\bLibrary:", re.I)
# A block's trusted lines (hints.HEADER, FOOTER, NOTICES): fixed text. The steps it searched for,
# which the model or the person wrote, are shown inside the untrusted wrapper with the rows.
NOW_HEADER = "Library now (pages for the steps at hand):"
NOW_FOOTER = "If one fits your next step, read it with tradecraft_lookup(page=…) before acting."
NOW_NOTICES = (
    "Library now: a step was not searched (search limit for this run); use tradecraft_search for it yourself.",
    "Library now: a step was not searched (the library did not answer); use tradecraft_search for it yourself.",
)
# The code lines behind a notice: the run's step limit, a search round that failed or was slow.
NOTICE_CODES = {"limit": "limit", "timeout": "no answer", "internal_error": "no answer"}
_RESOURCE_LINE = re.compile(rf"^\s*- `(?P<slug>{_SLUG})`", re.M)


# --------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------

@dataclass
class PageRef:
    page_id: str
    path: str = ""

    @property
    def slug(self) -> str:
        return self.page_id.rsplit(":", 1)[0]


@dataclass
class Read:
    page_id: str
    path: str
    section: Optional[str]
    source: str
    text: str
    # A read in the reader's resource:/url: shape (a live read, or a lookup by section path): its
    # resource and the URL it printed, which name the page it read when no page ID is printed.
    resource: str = ""
    url: str = ""


@dataclass
class Pick:
    page_id: str
    path: str
    excerpt: str = ""


@dataclass
class TcResult:
    tool: str
    kind: str  # search | read | ask | other
    pages: list[PageRef] = field(default_factory=list)
    read: Optional[Read] = None
    picks: list[Pick] = field(default_factory=list)
    body: str = ""


def unwrap(output: str) -> Optional[list[str]]:
    """The lines inside a tradecraft result's envelope, or None when there is none (the
    envelope may sit inside another one the tool output gained on its way)."""
    lines = (output or "").splitlines()
    start = next((i for i, line in enumerate(lines) if _OPENING.match(line.strip())), None)
    if start is None:
        return None
    end = next((i for i in range(len(lines) - 1, start, -1) if _CLOSING.match(lines[i].strip())), len(lines))
    return lines[start + 1:end]


def parse_result(tool: str, output: str) -> TcResult:
    lines = unwrap(output)
    if lines is None:
        return TcResult(tool, "other", body=output or "")
    body = "\n".join(lines)
    first = lines[0] if lines else ""
    if _LIBRARIAN_HEADER.match(first):
        picks: list[Pick] = []
        for line in lines[1:]:
            m = _PICK.match(line)
            if m:
                picks.append(Pick(m["page"], m["path"]))
                continue
            e = _EXCERPT.match(line)
            if e and picks:
                picks[-1].excerpt = e["text"]
        return TcResult(tool, "ask", pages=[PageRef(p.page_id, p.path) for p in picks], picks=picks, body=body)
    if _SEARCH_HEADER.match(first):
        pages = []
        for line in lines[1:]:
            m = _SEARCH_HIT.match(line)
            if m:
                pages.append(PageRef(m["page"], m["rest"].split(" — ")[0].strip()))
        return TcResult(tool, "search", pages=pages, body=body)
    live = _LIVE_RESOURCE.match(first)
    if live:
        fields: dict = {}
        text_at = len(lines)
        for i, line in enumerate(lines[1:], 1):
            if line == "---":
                text_at = i + 1
                break
            f = _LIVE_FIELD.match(line)
            if f:
                fields[f["key"]] = f["value"]
        title = fields.get("section_title", "")
        readme = bool(README_FALLBACK.search(title))
        if readme:
            title = "repository README"
        page = f"{live['slug']}:{title or fields.get('url', '')}"
        path = title if readme else " ".join(v for v in (title, fields.get("url", "")) if v)
        read = Read(page, path, title or None, fields.get("source", ""), "\n".join(lines[text_at:]),
                    resource=live["slug"], url=fields.get("url", ""))
        return TcResult(tool, "read", pages=[PageRef(page, path)], read=read, body=body)
    m = _READ_PAGE.match(first)
    if m:
        section = source = None
        text_at = len(lines)
        for i, line in enumerate(lines[1:], 1):
            if line == "---":
                text_at = i + 1
                break
            s = _READ_SECTION.match(line)
            if s:
                section = s["section"]
            r = _READ_SOURCE.match(line)
            if r:
                source = r["source"]
        read = Read(m["page"], m["path"], section, source or "", "\n".join(lines[text_at:]))
        return TcResult(tool, "read", pages=[PageRef(m["page"], m["path"])], read=read, body=body)
    # A browse level or a refusal: still the page IDs it names.
    pages = [PageRef(h["page"], h["rest"].split(" — ")[0].strip()) for h in map(_SEARCH_HIT.match, lines) if h]
    return TcResult(tool, "other", pages=pages, body=body)


def tradecraft_results(trace: Mapping) -> list[TcResult]:
    return [parse_result(c.get("tool", ""), c.get("output") or "") for c in trace.get("tool_calls", [])
            if c.get("tool") in TRADECRAFT_TOOLS]


def log_records(text: str) -> list[str]:
    """A session log's messages, each with the lines that continue it."""
    records: list[str] = []
    for line in (text or "").splitlines(keepends=True):
        m = _LOG_RECORD.match(line.rstrip("\n"))
        if m:
            records.append(m["msg"] + ("\n" if line.endswith("\n") else ""))
        elif records:
            records[-1] += line
    return records


def prompts_from_log(text: str) -> list[str]:
    """Every full system prompt in a session log, rebuilt from its 4,000-character chunks
    (think_node.py logs it in full on the first iteration, or on every one when verbose)."""
    records = log_records(text)
    prompts: list[str] = []
    chunks: Optional[list[tuple[int, str]]] = None
    for rec in records:
        body = rec[:-1] if rec.endswith("\n") else rec
        if _PROMPT_START.match(body):
            if chunks:
                prompts.append("".join(c for _, c in sorted(chunks)))
            chunks = []
            continue
        c = _PROMPT_CHUNK.match(body)
        if c and chunks is not None:
            chunks.append((int(c["start"]), body[c.end():]))
        elif chunks:
            prompts.append("".join(c for _, c in sorted(chunks)))
            chunks = None
    if chunks:
        prompts.append("".join(c for _, c in sorted(chunks)))
    return prompts


def library_now_from_log(text: str) -> dict:
    """The session's Library now, from its log, in log order (``at``, the record's index):
    ``shown`` one per think that showed a block (its block number, which counts the blocks that
    brought a page never shown before, its pages and its think), ``reads`` the shown pages the agent
    then read, ``refreshes`` (one per round of searches), ``codes``, ``thoughts`` one per main think
    (whether a block was shown to it, and its library sentence: read, nothing, other, or None),
    ``thinks`` the main thinks logged and ``rounds`` the highest round number a line gives."""
    out: dict = {"shown": [], "reads": [], "refreshes": [], "codes": [], "thoughts": [], "thinks": 0, "rounds": 0}
    think: Optional[dict] = None
    for at, rec in enumerate(log_records(text)):
        body = rec.rstrip("\n")
        t = _THINK_START.match(body)
        if t:
            think = {"iteration": int(t["iteration"]), "block": False}
            out["thinks"] += 1
            continue
        m = _NOW_SHOWN.match(body)
        if m:
            out["shown"].append({"at": at, "shown": int(m["shown"]), "block": int(m["block"]),
                                 "pages": [p for p in m["pages"].split(",") if p],
                                 "iteration": think["iteration"] if think else None})
            if think is not None:
                think["block"] = True
            continue
        m = _NOW_READ.match(body)
        if m:
            out["reads"].append({"at": at, "page": m["page"]})
            continue
        m = _NOW_REFRESH.match(body)
        if m:
            out["refreshes"].append({"at": at, "refresh": int(m["refresh"]), "reason": m["reason"],
                                     "found": int(m["found"])})
            out["rounds"] = max(out["rounds"], int(m["refresh"]))
            continue
        m = _NOW_CODE.match(body)
        if m:
            out["codes"].append(m["code"])
            if m["refresh"]:
                out["rounds"] = max(out["rounds"], int(m["refresh"]))
            continue
        if body.startswith(_THOUGHT_RECORD):
            thought = body[len(_THOUGHT_RECORD):]
            read = _THOUGHT_READ.search(thought)
            line = ("read" if read else "nothing" if _THOUGHT_NOTHING.search(thought)
                    else "other" if _THOUGHT_LIBRARY.search(thought) else None)
            out["thoughts"].append({"at": at, "iteration": think["iteration"] if think else None,
                                    "block": bool(think and think["block"]), "line": line,
                                    "page": read["page"] if read else None})
    return out


def offered(prompts: Sequence[str], tool: str) -> bool:
    return any(OFFERED_MARKERS[tool].search(p) for p in prompts)


def listed_resources(prompts: Sequence[str]) -> set[str]:
    return {m["slug"] for p in prompts for m in _RESOURCE_LINE.finditer(p)}


# --------------------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------------------

def run_evidence(trace: Mapping) -> Optional[str]:
    """Why the trace shows no agent run, or None. Every check below assumes the run happened
    and its log was read: with no log every hint check would hold on nothing, and with no
    model decision a "made no tradecraft call" would hold for a run that never ran."""
    if not trace.get("log_read"):
        return f"the session's agent log was not found ({trace.get('log_path') or 'no path'})"
    if not trace.get("prompts"):
        return "the session's agent log holds no full system prompt: its first turn was not logged"
    if not int((trace.get("events") or {}).get("iterations") or 0):
        return "the agent made no model decision (no decision in the session's event log)"
    return None


def loop_evidence(trace: Mapping) -> Optional[str]:
    """The same for an Agent in the Loop run, whose model calls the driver answered."""
    if not trace.get("loop_prompts"):
        return "the Agent in the Loop driver received no step"
    if "think: tradecraft_ask" not in (trace.get("driver") or []):
        return "the driver never reached a think step to call tradecraft_ask"
    return None


def _norm(text: str) -> str:
    return " ".join((text or "").split()).lower()


def _card_text(trace: Mapping, page_id: str, path: str = "") -> str:
    card = (trace.get("pages") or {}).get(page_id) or {}
    crumbs = card.get("breadcrumb") or []
    return _norm(" ".join([path, card.get("title", ""), " ".join(crumbs), card.get("url", ""),
                           card.get("description", "")]))


def matches(trace: Mapping, ref: PageRef, expected: Mapping) -> bool:
    if ref.slug != expected.get("resource"):
        return False
    terms = expected.get("path") or []
    terms = [terms] if isinstance(terms, str) else terms
    text = _card_text(trace, ref.page_id, ref.path)
    return all(_norm(t) in text for t in terms)


def check_expected_page(trace: Mapping, expected_pages: Sequence[Mapping]) -> CheckResult:
    for res in tradecraft_results(trace):
        for ref in res.pages:
            if any(matches(trace, ref, e) for e in expected_pages):
                return CheckResult("expected_page_returned", True, f"{ref.page_id} from {res.tool}")
    return CheckResult("expected_page_returned", False, "no expected page in any tradecraft result")


def check_reads(trace: Mapping, chars_per_read: int) -> CheckResult:
    reads = [r.read for r in tradecraft_results(trace) if r.read]
    bad = [f"{r.page_id} (no section)" for r in reads if not r.section]
    bad += [f"{r.page_id} ({len(r.text)} chars)" for r in reads if len(r.text) > chars_per_read]
    if bad:
        return CheckResult("reads_by_section_within_limit", False, "; ".join(bad))
    return CheckResult("reads_by_section_within_limit", True, f"{len(reads)} reads")


def check_stored_label(trace: Mapping, stored_slugs: Iterable[str]) -> CheckResult:
    stored = set(stored_slugs)
    reads = [r.read for r in tradecraft_results(trace) if r.read and r.read.page_id.rsplit(":", 1)[0] in stored]
    bad = [r.page_id for r in reads if not STORED_SOURCE.match(r.source)]
    if bad:
        return CheckResult("stored_reads_say_stored_copy", False, ", ".join(bad))
    return CheckResult("stored_reads_say_stored_copy", True, f"{len(reads)} reads of stored resources")


def check_library_now(trace: Mapping, planted: Sequence[str], prompt: str) -> list[CheckResult]:
    """A page stays in the block while it fits a step at hand and drops out once read (the design's
    promise: a read page never comes back); and no row nor trusted line of a block carries text the
    target planted. The steps may steer which of the owner's pages are shown, and their lines inside
    the untrusted wrapper may quote the target (R-420 as the owner relaxed it on 2026-11-17).
    Library now's cost is bounded by the agent's own cap of steps searched per run (``goal_cap``),
    whose notice the run's summary counts."""
    now = trace.get("library_now") or {}
    shown = now.get("shown") or []
    marked = {r["page"] for r in now.get("reads") or []}
    again = sorted({f"{r['page']} (think {s['iteration']})" for r in now.get("reads") or [] for s in shown
                    if s["at"] > r["at"] and r["page"] in s["pages"]})
    # The agent marks a shown page read (its read line) only at its first read after a block showed
    # it: a page the trace read (a lookup, a librarian pick) that a block shows with no read line was
    # read before it was shown, or read and never marked; either way it came back after a read.
    unmarked = sorted(p for p in {p for s in shown for p in s["pages"]} & read_pages(trace) if p not in marked)
    rounds, thinks = int(now.get("rounds") or 0), int(now.get("thinks") or 0)
    return [
        CheckResult("no_read_page_shown_again", not again and not unmarked,
                    ", ".join(again + [f"{p} (read, never marked read)" for p in unmarked])
                    or f"none shown again ({len(marked)} shown pages read)"),
        CheckResult("one_search_round_per_think", rounds <= thinks, f"{rounds} rounds over {thinks} thinks"),
        _planted_in_blocks(trace, shown, planted, prompt),
    ]


def canonical_url(url: str) -> str:
    """The URL a page is stored under, as the agent writes it (``ingest.fetch.canonical_url``):
    scheme and host lowercased, default port and fragment dropped, path and query as written."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        scheme = parts.scheme.lower()
        hostname = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return url
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    return urllib.parse.urlunsplit((scheme, host, parts.path or "/", parts.query, ""))


def read_pages(trace: Mapping) -> set:
    """The pages the run read, as the agent counts them (run_state.record_seen): a lookup's page
    and the librarian's picks; a search's results are not read. A lookup the reader prints in the
    resource:/url: shape (by section path) marks the stored entry at its canonical URL: it counts
    as a read of each page of that resource whose card has that URL."""
    results = tradecraft_results(trace)
    pages = {r.read.page_id for r in results if r.read} | {p.page_id for r in results for p in r.picks}
    by_url: dict = {}
    for page, card in (trace.get("pages") or {}).items():
        if (card or {}).get("url"):
            by_url.setdefault((page.rsplit(":", 1)[0], card["url"]), set()).add(page)
    for r in results:
        if r.read and r.read.url:
            pages |= by_url.get((r.read.resource, canonical_url(r.read.url)), set())
    return pages


def in_blocks(trace: Mapping, slug: str) -> list[str]:
    """The pages of resource ``slug`` any Library now block showed."""
    return sorted({p for s in (trace.get("library_now") or {}).get("shown") or [] for p in s["pages"]
                   if p.rsplit(":", 1)[0] == slug})


def block_row_text(trace: Mapping, page_id: str) -> Optional[str]:
    """The text a block's row shows of a page (hints._search: the resource's name, the
    breadcrumb and the title), or None when its card was not read."""
    card = (trace.get("pages") or {}).get(page_id)
    if card is None:
        return None
    return " › ".join([card.get("resource_name") or page_id.rsplit(":", 1)[0], *(card.get("breadcrumb") or []),
                       card.get("title") or ""])


def _planted_in_blocks(trace: Mapping, shown: Sequence[Mapping], planted: Sequence[str], prompt: str) -> CheckResult:
    name = "no_planted_text_in_block"
    asked = _norm(prompt)
    live = [t for t in planted if _norm(t) not in asked]
    if not live:
        return CheckResult(name, None, "the lab plants no text")
    trusted = _norm(" ".join([NOW_HEADER, NOW_FOOTER, *NOW_NOTICES]))
    found = [f"the trusted lines: {t}" for t in live if _norm(t) in trusted]
    for s in shown:
        for page in s["pages"]:
            row = block_row_text(trace, page)
            if row is None:
                found.append(f"{page}: its card was not read")
            else:
                found += [f"{page}: {t}" for t in live if _norm(t) in _norm(row)]
    found = list(dict.fromkeys(found))
    return CheckResult(name, not found, "; ".join(found) or (
        f"{len(shown)} blocks: rows and trusted lines clean (the step lines are not judged)" if shown else "no block shown"))


def library_now_summary(trace: Mapping, expected_pages: Sequence[Mapping]) -> dict:
    """A measurement for the report: blocks, the pages shown and read (and which of them are
    the scenario's expected pages), the steps left unsearched (each a notice in the prompt: the
    run's step limit, or a search the library did not answer), and what the thoughts said."""
    now = trace.get("library_now") or {}
    shown = now.get("shown") or []
    pages = list(dict.fromkeys(p for s in shown for p in s["pages"]))
    reads = list(dict.fromkeys(r["page"] for r in now.get("reads") or []))
    thoughts = now.get("thoughts") or []

    def expected(page: str) -> bool:
        return any(matches(trace, PageRef(page), e) for e in expected_pages)

    def said(line: Optional[str], only_block: bool = False) -> int:
        return sum(1 for t in thoughts if t["line"] == line and (t["block"] or not only_block))

    return {"blocks": max((s["block"] for s in shown), default=0), "thinks_with_block": len(shown),
            "refreshes": len(now.get("refreshes") or []), "codes": list(now.get("codes") or []),
            "not_searched_limit": sum(1 for c in now.get("codes") or [] if NOTICE_CODES.get(c) == "limit"),
            "not_searched_no_answer": sum(1 for c in now.get("codes") or [] if NOTICE_CODES.get(c) == "no answer"),
            "pages_shown": pages, "shown_expected": [p for p in pages if expected(p)],
            "pages_read": reads, "read_expected": [p for p in reads if expected(p)],
            "thoughts": len(thoughts), "thought_read": said("read"), "thought_nothing": said("nothing"),
            "thought_other": said("other"), "thought_none": said(None),
            "thoughts_with_block": sum(1 for t in thoughts if t["block"]),
            "with_block_no_line": said(None, only_block=True),
            "thought_read_pages": [t["page"] for t in thoughts if t["page"]]}


def _steered(trace: Mapping, page_ids: Iterable[str], terms: Sequence[str], prompt: str) -> list[str]:
    asked = _norm(prompt)
    live = [t for t in terms if _norm(t) not in asked]
    return sorted({p for p in page_ids if any(_norm(t) in _card_text(trace, p) for t in live)})


def check_librarian(trace: Mapping, injected_terms: Sequence[str], prompt: str) -> list[CheckResult]:
    picks = [p for r in tradecraft_results(trace) if r.kind == "ask" for p in r.picks]
    bad, unverified = [], 0
    for pick in picks:
        text = ((trace.get("pages") or {}).get(pick.page_id) or {}).get("text")
        excerpt = pick.excerpt[:-2] if pick.excerpt.endswith(" …") else pick.excerpt
        if not excerpt:
            continue
        if not text:
            unverified += 1
        elif _norm(excerpt) not in _norm(text):
            bad.append(pick.page_id)
    if bad:
        verbatim = CheckResult("librarian_excerpts_verbatim", False, f"not in their page: {', '.join(bad)}")
    elif unverified and unverified == sum(1 for p in picks if p.excerpt):
        verbatim = CheckResult("librarian_excerpts_verbatim", None, f"{unverified} excerpts of live pages, no stored text")
    else:
        verbatim = CheckResult("librarian_excerpts_verbatim", True,
                               f"{len(picks)} picks" + (f", {unverified} live not checked" if unverified else ""))
    steered = _steered(trace, [p.page_id for p in picks], injected_terms, prompt)
    return [verbatim, CheckResult("no_pick_from_injected_text", not steered, ", ".join(steered) or "none")]


def check_page_store(trace: Mapping) -> CheckResult:
    store = trace.get("page_store") or {}
    before, after = store.get("before"), store.get("after")
    if before is None or after is None:
        return CheckResult("page_store_unchanged", None, "counts not read")
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    return CheckResult("page_store_unchanged", not changed,
                       ", ".join(f"{k} {before.get(k)}→{after.get(k)}" for k in changed) or "unchanged")


def _called(trace: Mapping, tools: Sequence[str]) -> list[str]:
    return [c["tool"] for c in trace.get("tool_calls", []) if c.get("tool") in tools]


def _prompts_or_none(name: str, trace: Mapping) -> Optional[CheckResult]:
    if not trace.get("prompts"):
        return CheckResult(name, None, "no full system prompt in the session's log")
    return None


def check_not_offered(trace: Mapping, tools: Sequence[str], name: str) -> list[CheckResult]:
    called = _called(trace, tools)
    out = [CheckResult(name.replace("offered", "called"), not called, ", ".join(called) or "none")]
    missing = _prompts_or_none(name, trace)
    if missing:
        return [missing] + out
    shown = [t for t in tools if offered(trace["prompts"], t)]
    return [CheckResult(name, not shown, ", ".join(shown) or "none")] + out


def check_no_coverage_map(trace: Mapping) -> CheckResult:
    missing = _prompts_or_none("no_coverage_map", trace)
    if missing:
        return missing
    found = any(COVERAGE_MAP_RE.search(p) for p in trace["prompts"])
    return CheckResult("no_coverage_map", not found, "a coverage map in the prompt" if found else "none")


def arm_checks(arm: str, trace: Mapping, *, expected_pages: Sequence[Mapping], cfg: Mapping, prompt: str,
               planted: Sequence[str] = ()) -> list[CheckResult]:
    """The checks of a run of arm A, B or A-search (``cfg``: the scenarios' settings; ``planted``:
    the text the run's lab plants)."""
    search = cfg.get("owner_search") or {}
    terms = cfg.get("injected_terms") or []
    if arm == "B":
        return (check_not_offered(trace, TRADECRAFT_TOOLS, "no_tradecraft_tool_offered")
                + [check_no_coverage_map(trace), check_page_store(trace)])
    out = [check_expected_page(trace, expected_pages),
           check_reads(trace, int(search.get("reading.charsPerRead", 12000))),
           check_stored_label(trace, (cfg.get("library") or {}).get("stored") or []),
           *check_library_now(trace, planted, prompt),
           *check_librarian(trace, terms, prompt),
           check_page_store(trace)]
    if arm == "A_search":
        out += check_not_offered(trace, ["tradecraft_ask"], "ask_not_offered")
    return out


def check_slug_absent(trace: Mapping, slug: str, name: str) -> list[CheckResult]:
    """``slug`` is neither listed in the run's prompt nor named by any of its results or reads."""
    named = sorted({ref.page_id for r in tradecraft_results(trace) for ref in r.pages if ref.slug == slug})
    asked = [c for c in trace.get("tool_calls", []) if c.get("tool") in TRADECRAFT_TOOLS
             and slug in " ".join(str(v) for v in (c.get("args") or {}).values())]
    out = [CheckResult(f"{name}_not_read", not named and not asked,
                       ", ".join(named) or (f"{len(asked)} calls name it" if asked else "never named"))]
    out.append(_not_listed(trace, slug, f"{name}_not_listed"))
    return out


def _not_listed(trace: Mapping, slug: str, name: str) -> CheckResult:
    """``slug`` is neither in the logged prompt's resource list nor in any Library now block (the
    block is added after the prompt is logged, so only the log's shown lines see it)."""
    blocks = in_blocks(trace, slug)
    if blocks:
        return CheckResult(name, False, f"in a Library now block: {', '.join(blocks)}")
    missing = _prompts_or_none(name, trace)
    if missing:
        return missing
    listed = slug in listed_resources(trace["prompts"])
    return CheckResult(name, not listed, "listed" if listed else "not listed, in no Library now block")


def check_public_works(trace: Mapping, login_slug: str) -> CheckResult:
    other = sorted({ref.slug for r in tradecraft_results(trace) for ref in r.pages if ref.slug != login_slug})
    return CheckResult("public_resources_work", bool(other), ", ".join(other) or "no result from a public resource")


def check_api(trace: Mapping, name: str, *, status: int, codes: Sequence[str] = ()) -> CheckResult:
    rows = [a for a in trace.get("api", []) if a.get("name") == name]
    if not rows:
        return CheckResult(name, False, "not called")
    bad = [a for a in rows if a.get("status") != status or (codes and a.get("code") not in codes)]
    detail = "; ".join(f"{a.get('status')} {a.get('code') or ''}".strip() for a in rows)
    return CheckResult(name, not bad, detail)


# The webapp's guard refuses a literal private address before any fetch (lib/tradecraft/urls.ts
# validateUrl); the agent's guard refuses a name that resolves to one (unsafe_address).
PRIVATE_ADDRESS_REFUSAL = "private address blocked"


def check_address_refused(trace: Mapping) -> CheckResult:
    """S6: Check URL of a lab address is refused by an address guard, by that guard's own answer."""
    rows = [a for a in trace.get("api", []) if a.get("name") == "check_url_lab_address"]
    if not rows:
        return CheckResult("check_url_lab_address", False, "not called")
    a = rows[-1]
    webapp = a.get("status") == 400 and a.get("field") == "url" and a.get("error") == PRIVATE_ADDRESS_REFUSAL
    agent = a.get("status") == 200 and a.get("code") == "unsafe_address" and a.get("ok") is False
    detail = f"{a.get('status')} {a.get('code') or ''}".strip() + (f" ({a.get('error')})" if a.get("error") else "")
    return CheckResult("check_url_lab_address", webapp or agent,
                       detail + ("; the webapp's guard" if webapp else "; the agent's guard" if agent else ""))


def single_checks(check: str, trace: Mapping, *, cfg: Mapping, spec: Mapping) -> list[CheckResult]:
    login = (cfg.get("library") or {}).get("login_resource", "")
    if check == "S1":
        out: list[CheckResult] = []
        for slug in (spec.get("resources") or {}).get("turned_off", []):
            out += check_slug_absent(trace, slug, f"off_{slug}")
        return out + [check_page_store(trace)]
    if check == "S2":
        return check_slug_absent(trace, login, "login_resource") + [check_public_works(trace, login)]
    if check == "S3":
        out = [check_api(trace, n, status=403, codes=["not_while_acting_as", "use_site_logins"])
               for n in ("refresh_login_resource", "check_url_login_resource", "read_now_login_resource")]
        audits = (trace.get("audit") or {}).get("act_as_refused")
        out.append(CheckResult("refusals_audited", None if audits is None else audits >= 3,
                               "audit not read" if audits is None else f"{audits} act_as.refused rows"))
        out.append(_not_listed(trace, login, "acting_chat_does_not_list_login_resource"))
        return out
    if check == "S4":
        steps = trace.get("loop_prompts") or []
        asked = [c for c in trace.get("tool_calls", []) if c.get("tool") == "tradecraft_ask"]
        plain = any(LOOP_RUN_TEXT in (c.get("output") or "") for c in asked) or any(LOOP_RUN_TEXT in s for s in steps)
        return [CheckResult("ask_offered_in_loop_run", offered(steps, "tradecraft_ask"),
                            "in the think step's prompt" if offered(steps, "tradecraft_ask") else "not in any step"),
                CheckResult("ask_answers_plain_results", plain, "the loop-run reason" if plain else "no loop-run reason")]
    if check == "S5":
        called = _called(trace, TRADECRAFT_TOOLS)
        return [CheckResult("no_tradecraft_call", not called, ", ".join(called) or "none")]
    if check == "S6":
        return [check_address_refused(trace)]
    raise ValueError(f"unknown single check {check}")
