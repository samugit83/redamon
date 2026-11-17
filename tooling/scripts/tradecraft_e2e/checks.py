"""Reading a run's trace, and the checks of ``scenarios.yaml`` on it.

A trace is a plain dict the runner builds after a run (and saves with the run's result):

- ``tool_calls``: ``{tool, args, output, success}`` from the conversation's ``tool_complete``
  rows (``output`` is the tool's raw output, the tradecraft result envelope included);
- ``answers``: the agent's final answers (``assistant_message`` rows);
- ``prompts``: each full system prompt the agent logged for the session, reassembled from
  its ``PROMPT[i:j]`` chunks (``prompts_from_log``);
- ``hints`` / ``hint_reads``: the ``[tradecraft] hint`` lines of the session's log;
- ``page_store``: the owner's page-store row counts before and after the run;
- ``pages``: the cards (title, breadcrumb, description, URL, stored text) of every page the
  run's results or hints named, read from the page store after the run;
- ``api``: the route calls a single check made itself (``{name, status, code, ...}``).

The text formats parsed here are the agent's (``agentic/tradecraft/library/types.py``,
``librarian/validate.py``, ``overlay.py``); ``tests/test_tradecraft_matrix_runner.py`` holds this
module to the agent's own constants.
"""
from __future__ import annotations

import re
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
STORED_SOURCE = re.compile(r"^stored copy from \S+")
_LOG_RECORD = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:,\d+)? \| \S+\s* \| [^|]*\| [^|]*\| ?(?P<msg>.*)$")
_PROMPT_START = re.compile(r"^--- FULL SYSTEM PROMPT \(\d+ chars")
_PROMPT_CHUNK = re.compile(r"^PROMPT\[(?P<start>\d+):\d+\]:\n?", re.S)
_HINT = re.compile(r"\[tradecraft\] hint n=(?P<n>\d+) checkpoint=(?P<cp>\S+) (?:pages=(?P<pages>\S*)|skill_line=(?P<skill>\S+))")
_HINT_READ = re.compile(rf"\[tradecraft\] hint (?P<page>{_PAGE}) read")
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


def prompts_from_log(text: str) -> list[str]:
    """Every full system prompt in a session log, rebuilt from its 4,000-character chunks
    (think_node.py logs it in full on the first iteration, or on every one when verbose)."""
    records: list[str] = []
    for line in (text or "").splitlines(keepends=True):
        m = _LOG_RECORD.match(line.rstrip("\n"))
        if m:
            records.append(m["msg"] + ("\n" if line.endswith("\n") else ""))
        elif records:
            records[-1] += line
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


def hints_from_log(text: str) -> tuple[list[dict], list[str]]:
    hints, reads = [], []
    for line in (text or "").splitlines():
        m = _HINT.search(line)
        if m:
            pages = [p for p in (m["pages"] or "").split(",") if p]
            hints.append({"n": int(m["n"]), "checkpoint": m["cp"], "pages": pages,
                          **({"skill_line": m["skill"]} if m["skill"] else {})})
            continue
        r = _HINT_READ.search(line)
        if r:
            reads.append(r["page"])
    return hints, reads


def offered(prompts: Sequence[str], tool: str) -> bool:
    return any(OFFERED_MARKERS[tool].search(p) for p in prompts)


def listed_resources(prompts: Sequence[str]) -> set[str]:
    return {m["slug"] for p in prompts for m in _RESOURCE_LINE.finditer(p)}


# --------------------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------------------

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


def check_hints(trace: Mapping, per_run: int, injected_terms: Sequence[str], prompt: str) -> list[CheckResult]:
    hints = trace.get("hints") or []
    pages = [p for h in hints for p in h.get("pages", [])]
    twice = sorted({p for p in pages if pages.count(p) > 1})
    steered = _steered(trace, pages, injected_terms, prompt)
    return [
        CheckResult("hints_within_limit", len(hints) <= per_run, f"{len(hints)} notes, limit {per_run}"),
        CheckResult("no_page_hinted_twice", not twice, ", ".join(twice) or "none twice"),
        CheckResult("no_hint_from_injected_text", not steered, ", ".join(steered) or "none"),
    ]


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


def arm_checks(arm: str, trace: Mapping, *, expected_pages: Sequence[Mapping], cfg: Mapping, prompt: str) -> list[CheckResult]:
    """The checks of a run of arm A, B or A-search (``cfg``: the scenarios' settings)."""
    search = cfg.get("owner_search") or {}
    terms = cfg.get("injected_terms") or []
    if arm == "B":
        return (check_not_offered(trace, TRADECRAFT_TOOLS, "no_tradecraft_tool_offered")
                + [check_no_coverage_map(trace), check_page_store(trace)])
    out = [check_expected_page(trace, expected_pages),
           check_reads(trace, int(search.get("reading.charsPerRead", 12000))),
           check_stored_label(trace, (cfg.get("library") or {}).get("stored") or []),
           *check_hints(trace, int(search.get("hints.perRun", 6)), terms, prompt),
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
    missing = _prompts_or_none(f"{name}_not_listed", trace)
    out.append(missing or CheckResult(f"{name}_not_listed", slug not in listed_resources(trace["prompts"]),
                                      "listed" if slug in listed_resources(trace.get("prompts") or []) else "not listed"))
    return out


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
        missing = _prompts_or_none("acting_chat_does_not_list_login_resource", trace)
        out.append(missing or CheckResult("acting_chat_does_not_list_login_resource",
                                          login not in listed_resources(trace["prompts"]), login))
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
        return [check_api(trace, "check_url_lab_address", status=200, codes=["unsafe_address"])]
    raise ValueError(f"unknown single check {check}")
