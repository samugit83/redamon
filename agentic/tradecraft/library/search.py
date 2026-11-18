"""Library search and browse (Q7, T2.4): what ``tradecraft_search`` answers, what the lookup's
``query`` picks a page with, and what the librarian and the hints start from.

The free first pass (Q7.2) runs up to ``constants.searchWordings`` (6) wordings of one need,
with no model:

    1. the agent's words                       full text over the cards and stored sections
    2. their synonyms and acronyms              the shipped list plus the user's pairs
    3. the words within the current skill's topic
    4. the words within the target's technologies
    5. the exact entities the request names     CVE ids, product and tool names
    6. a fuzzy match on titles                  typos and odd page names (trigram)

each at most ``constants.resultsPerWording`` (20) results, merged by reciprocal rank fusion (a
page found by several wordings rises), at most ``constants.mergedCandidates`` (40). The attack
session boosts and never filters: a page of the current skill's topic, of the phase's
preferred kind, or naming the target's technologies ranks higher, and so does a resource of
High priority (Low ranks lower). The verdict, FOUND, RELATED or NOT FOUND, measures how much of
the agent's need the best pages cover; ``search.strictness`` is the one control over it, and
the weights, thresholds and merge stay internal (Q11, R-418).

Every statement is in ``search_sql``: keyed by the owner and the catalog's resources, joined to
each resource's live generation, the query text bound as a parameter only. Wordings 3 and 4 add
only fixed vocabulary words (a topic, technology ids), never raw target text (Q12). The
statements of one search, first pass or browse run in one read-only snapshot (D-46): they are
tied together by entry ids, which a refresh's swap replaces, so each call reads the generation
that was live when it started, and the next call the new one.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from typing import Any, AsyncContextManager, AsyncIterator, Callable, Iterable, Mapping, Optional, Sequence

from tradecraft import db
from tradecraft.ingest import entities as entity_rules
from tradecraft.ingest.tags import PhraseMatcher, normalize, technology_words
from tradecraft.library import search_sql, synonyms
from tradecraft.library.types import BrowseFolder, BrowseLevel, Card, SearchAnswer, SearchHit
from tradecraft.settings import EffectiveSettings, constant
from tradecraft.vocab import load_vocab

WORDINGS = int(constant("searchWordings"))
PER_WORDING = int(constant("resultsPerWording"))
MERGED = int(constant("mergedCandidates"))
# A query longer than this is cut: no need is stated in more, and the words are bound
# parameters either way.
MAX_QUERY_CHARS = 1000
MAX_TERMS = 24
BROWSE_LINES = 20

# Internal ranking (Q11 "Kept internal"): reciprocal rank fusion's constant, the weight of a
# section's rank against a card's, and the session and priority boosts.
RRF_K = 60
SECTION_WEIGHT = 0.5
FUZZY_THRESHOLD = 0.4
BOOST_TOPIC = 1.25
BOOST_KIND = 1.15
BOOST_TECH = 1.15
PRIORITY_BOOST = {"high": 1.3, "normal": 1.0, "low": 0.75}


@dataclass(frozen=True)
class Thresholds:
    # The share of the agent's term groups a page must hold in its title, breadcrumb or
    # headings to be a strong match; how many wordings must agree on it instead; the share
    # found anywhere in the page that makes it related at all; and the title similarity that
    # makes a fuzzy match (a typo) related.
    strong: float
    agree: int
    related: float
    fuzzy: float


STRICTNESS = {
    "strict": Thresholds(strong=1.0, agree=4, related=0.75, fuzzy=0.7),
    "balanced": Thresholds(strong=0.75, agree=3, related=0.5, fuzzy=0.5),
    "loose": Thresholds(strong=0.5, agree=2, related=0.25, fuzzy=0.4),
}

_TOKEN = re.compile(r"[a-z0-9]+")


class SearchError(ValueError):
    """A request the agent can correct (an unknown resource, topic, kind or technology)."""


@dataclass(frozen=True)
class Session:
    """What search knows of the attack, from structured run data only: the current skill's
    topic, the phase, and the target's technologies as vocabulary ids."""

    topic: Optional[str] = None
    phase: Optional[str] = None
    technologies: tuple[str, ...] = ()


@dataclass(frozen=True)
class Wording:
    kind: str  # words | synonyms | topic | technologies | entities | fuzzy
    label: str
    params: Mapping[str, Any]


@dataclass
class Candidate:
    row: dict
    score: float = 0.0
    wordings: set = field(default_factory=set)
    section: Optional[str] = None
    entity_match: bool = False
    fuzzy: float = 0.0
    title: float = 0.0
    strong: float = 0.0
    anywhere: float = 0.0
    # How many of the need's term groups the page's title or breadcrumb holds: Library now's fit
    # reads it (``hints.fits``); the shares above, the verdict and the order do not.
    named: int = 0
    snippet: str = ""


# The first statement of a call's transaction: one snapshot for every statement after it, and
# no write. READ COMMITTED, the pool's level, takes a snapshot per statement.
SNAPSHOT = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"


class LibraryIndex:
    """Runs the statements of ``search_sql`` on the page store's pool (a test passes its own
    ``connect``, or replaces the whole index). ``snapshot()`` gives the same index on one
    connection whose statements all read one snapshot."""

    def __init__(self, connect: Optional[Callable[[], AsyncContextManager[Any]]] = None, *,
                 conn: Any = None) -> None:
        self._connect = connect or db.connection
        self._conn = conn

    @contextlib.asynccontextmanager
    async def snapshot(self) -> AsyncIterator["LibraryIndex"]:
        if self._conn is not None:
            yield self
            return
        async with self._connect() as conn:
            await conn.execute(SNAPSHOT)
            yield LibraryIndex(self._connect, conn=conn)

    async def rows(self, name: str, params: Mapping[str, Any]) -> list[dict]:
        if self._conn is not None:
            return await self._run(self._conn, name, params)
        async with self._connect() as conn:
            return await self._run(conn, name, params)

    @staticmethod
    async def _run(conn: Any, name: str, params: Mapping[str, Any]) -> list[dict]:
        if name in search_sql.PRELUDES:
            await conn.execute(search_sql.PRELUDES[name], dict(params))
        cur = await conn.execute(search_sql.STATEMENTS[name], dict(params))
        return list(await cur.fetchall())


@contextlib.asynccontextmanager
async def one_snapshot(index: Any) -> AsyncIterator[Any]:
    """``index`` in one snapshot for the statements of one call; an index that has none (a
    test's fake) as it is."""
    opener = getattr(index, "snapshot", None)
    if opener is None:
        yield index
        return
    async with opener() as bound:
        yield bound


# --------------------------------------------------------------------------------------
# Wordings
# --------------------------------------------------------------------------------------

def tokens(text: str) -> list[str]:
    out: list[str] = []
    for t in _TOKEN.findall(str(text or "").lower()[:MAX_QUERY_CHARS]):
        if t != "or" and t not in out:
            out.append(t)
    return out[:MAX_TERMS]


def _or(words: Iterable[str]) -> str:
    """Words joined for ``websearch_to_tsquery`` as alternatives: any of them may match, and the
    rank rewards pages that hold more of them. Each word is ``[a-z0-9]+``."""
    return " or ".join(words)


def _phrase(text: str) -> str:
    words = tokens(text)
    return '"' + " ".join(words) + '"' if len(words) > 1 else (words[0] if words else "")


def expand(query: str, user_synonyms: Iterable[synonyms.Synonym] = ()) -> list[str]:
    return synonyms.expand(query, user_synonyms)


def term_groups(query: str, user_synonyms: Sequence[synonyms.Synonym] = ()) -> list[str]:
    """The agent's need as term groups, each a word or a phrase or what it also means
    (``sqli or "sql injection"``, ``"sql injection" or sqli``), in the query's order; a page
    covers a group when it holds any of them, so "sqli" and "SQL injection" cover a page alike."""
    words = tokens(query)
    norm = normalize(query)
    found: dict[tuple[str, ...], list[str]] = {}
    for phrase, alternatives in synonyms.pairs(user_synonyms):
        if not synonyms.contains(norm, phrase):
            continue
        key = tuple(tokens(phrase))
        if not key:
            continue
        alts = found.setdefault(key, [_phrase(phrase)])
        alts += [p for p in (_phrase(a) for a in alternatives) if p and p not in alts]
    groups: list[tuple[int, list[str]]] = []
    covered: set[str] = set()
    # The longest phrases first, so "sql injection" is one group rather than two words.
    for key in sorted(found, key=len, reverse=True):
        if covered & set(key) or not set(key) <= set(words):
            continue
        covered |= set(key)
        groups.append((words.index(key[0]), found[key]))
    groups += [(i, [w]) for i, w in enumerate(words) if w not in covered]
    return [_or(alts) for _i, alts in sorted(groups, key=lambda g: g[0])]


def _tech_matcher() -> PhraseMatcher:
    global _TECH
    if _TECH is None:
        _TECH = PhraseMatcher(technology_words())
    return _TECH


_TECH: Optional[PhraseMatcher] = None


def resolve_topic(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    key = str(name).strip().lower()
    for t in load_vocab().topics:
        if key in (t["id"], t["label"].lower()):
            return t["id"]
    raise SearchError(f"unknown topic {name!r}: one of {', '.join(load_vocab().topic_ids)}")


def resolve_kind(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    kind = load_vocab().resolve_kind(str(name))
    if kind is None:
        raise SearchError(f"unknown kind {name!r}: one of {', '.join(load_vocab().kind_ids)}")
    return kind


def resolve_technology(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    found = _tech_matcher().find(str(name))
    if not found:
        raise SearchError(f"unknown technology {name!r}: use a product or tool name such as PostgreSQL or nginx")
    return found[0]


def technologies_of(names: Iterable[str]) -> tuple[str, ...]:
    """Technology names (from recon, or anywhere) as vocabulary ids: a name the shipped list
    does not know is dropped, so no raw target text reaches a wording."""
    out: list[str] = []
    for name in names or ():
        for tech in _tech_matcher().find(str(name)):
            if tech not in out:
                out.append(tech)
    return tuple(out)


def _topic_label(topic: str) -> str:
    return next((t["label"] for t in load_vocab().topics if t["id"] == topic), topic)


def _tech_name(tech: str) -> str:
    return next((t["name"] for t in load_vocab().technologies if t["id"] == tech), tech)


def wordings_for(query: str, *, session: Optional[Session] = None, use_session: bool = True,
                 user_synonyms: Sequence[synonyms.Synonym] = (), explicit_topic: Optional[str] = None,
                 explicit_tech: Optional[str] = None) -> list[Wording]:
    """The free first pass's wordings of one need, in order, the ones that do not apply left out."""
    query = " ".join(str(query or "").split())[:MAX_QUERY_CHARS]
    words = tokens(query)
    session = session or Session()
    out: list[Wording] = []
    if words:
        out.append(Wording("words", query, {"q": _or(words)}))
        expanded = expand(query, user_synonyms)
        phrases = [p for p in (_phrase(e) for e in expanded) if p]
        if phrases:
            out.append(Wording("synonyms", "synonyms: " + ", ".join(expanded), {"q": _or(phrases)}))
        if use_session and session.topic and not explicit_topic:
            out.append(Wording("topic", f"+ topic {_topic_label(session.topic)}", {"q": _or(words), "topic": session.topic}))
        techs = [t for t in session.technologies if t != explicit_tech]
        if use_session and techs:
            out.append(Wording("technologies", "+ " + ", ".join(_tech_name(t) for t in techs),
                               {"q": _or(words), "techs": list(techs)}))
    ents = entity_rules.find([query])
    if ents:
        out.append(Wording("entities", "entities: " + ", ".join(ents), {"ents": ents}))
    if len(query) >= 3:
        out.append(Wording("fuzzy", "fuzzy titles", {"q": query[:200], "threshold": str(FUZZY_THRESHOLD)}))
    return out[:WORDINGS]


# --------------------------------------------------------------------------------------
# The free first pass
# --------------------------------------------------------------------------------------

@dataclass
class FirstPass:
    wordings: tuple[Wording, ...]
    candidates: list[Candidate]
    groups: list[str]
    cves: frozenset
    # The term groups that have a lexeme (a stop word has none): the shares' denominator.
    total: int = 0


def _resources(catalog: Any) -> list[Any]:
    return list(getattr(catalog, "resources", None) or ())


def _scope(catalog: Any, resource: Optional[str]) -> list[Any]:
    """The catalog's resources to search: all of them, or the one the agent named."""
    allowed = _resources(catalog)
    if not resource:
        return allowed
    chosen = [r for r in allowed if r.slug == resource]
    if not chosen:
        available = ", ".join(sorted(r.slug for r in allowed)) or "(none)"
        raise SearchError(f"no resource {resource!r} in this run's library; available: {available}")
    return chosen


def _search_settings(catalog: Any, settings: Optional[EffectiveSettings]) -> EffectiveSettings:
    if settings is not None:
        return settings
    return EffectiveSettings(getattr(catalog, "search", None) or {}, scope="search")


def _user_synonyms(catalog: Any) -> list[synonyms.Synonym]:
    return synonyms.parse_user((getattr(catalog, "search", None) or {}).get("synonyms"))


async def _run_wording(index: Any, wording: Wording, base: Mapping[str, Any]) -> list[dict]:
    params = {**base, **wording.params}
    if wording.kind == "entities":
        return await index.rows("entries_entities", params)
    if wording.kind == "fuzzy":
        return await index.rows("entries_fuzzy", params)
    cards = await index.rows("entries_text", params)
    sections = await index.rows("sections_text", params)
    best: dict[int, dict] = {}
    for row in cards:
        best[row["id"]] = dict(row, rank=float(row["rank"] or 0), section=None)
    for row in sections:
        rank = SECTION_WEIGHT * float(row["rank"] or 0)
        held = best.get(row["id"])
        if held is None or rank > held["rank"]:
            best[row["id"]] = dict(row, rank=rank, section=row.get("section") or None)
        elif held.get("section") is None:
            held["section"] = row.get("section") or None
    ranked = sorted(best.values(), key=lambda r: (-r["rank"], r["page_id"]))
    return ranked[:PER_WORDING]


def _boost(row: Mapping[str, Any], priority: str, session: Optional[Session]) -> float:
    factor = PRIORITY_BOOST.get(priority or "normal", 1.0)
    if session is None:
        return factor
    if session.topic and session.topic in (row.get("topics") or ()):
        factor *= BOOST_TOPIC
    preferred = load_vocab().kind_preference_by_phase.get(session.phase or "", ())
    if preferred and set(preferred) & set(row.get("kinds") or ()):
        factor *= BOOST_KIND
    if session.technologies and set(session.technologies) & (set(row.get("technologies") or ()) |
                                                            set(row.get("entities") or ())):
        factor *= BOOST_TECH
    return factor


def merge(results: Sequence[tuple[Wording, list[dict]]], priorities: Mapping[str, str],
          session: Optional[Session], cves: Iterable[str] = ()) -> list[Candidate]:
    """Reciprocal rank fusion of the wordings' lists, then the boosts; the best
    ``constants.mergedCandidates``."""
    cves = set(cves)
    by_id: dict[int, Candidate] = {}
    for wording, rows in results:
        for position, row in enumerate(rows):
            cand = by_id.get(row["id"])
            if cand is None:
                cand = by_id[row["id"]] = Candidate(row=dict(row))
            cand.score += 1.0 / (RRF_K + position + 1)
            cand.wordings.add(wording.kind)
            if row.get("section") and not cand.section:
                cand.section = row["section"]
            if wording.kind == "entities" and cves & set(row.get("entities") or ()):
                cand.entity_match = True
            if wording.kind == "fuzzy":
                cand.fuzzy = max(cand.fuzzy, float(row.get("rank") or 0))
    for cand in by_id.values():
        cand.score *= _boost(cand.row, priorities.get(cand.row["resource_id"], "normal"), session)
    return sorted(by_id.values(), key=lambda c: (-c.score, c.row["page_id"]))[:MERGED]


async def free_first_pass(owner_id: str, catalog: Any, query: str, *, resource: Optional[str] = None,
                          topic: Optional[str] = None, kind: Optional[str] = None, technology: Optional[str] = None,
                          session: Optional[Session] = None, settings: Optional[EffectiveSettings] = None,
                          index: Any = None) -> FirstPass:
    """The merged candidates of one need, with their coverage of it; no model call."""
    scope = _scope(catalog, resource)
    settings = _search_settings(catalog, settings)
    topic, kind, technology = resolve_topic(topic), resolve_kind(kind), resolve_technology(technology)
    use_session = settings.bool("search.useSession")
    user_syn = _user_synonyms(catalog)
    wordings = wordings_for(query, session=session, use_session=use_session, user_synonyms=user_syn,
                            explicit_topic=topic, explicit_tech=technology)
    groups = term_groups(query, user_syn)
    cves = frozenset(entity_rules.cve_ids(query))
    if not scope or not wordings:
        return FirstPass(tuple(wordings), [], groups, cves)
    base = {"uid": owner_id, "rids": [r.id for r in scope], "topic": topic, "kind": kind, "tech": technology,
            "techs": [], "limit": PER_WORDING}
    async with one_snapshot(index or LibraryIndex()) as ix:
        results = [(w, await _run_wording(ix, w, base)) for w in wordings]
        priorities = {r.id: getattr(r, "priority", "normal") for r in scope}
        candidates = merge(results, priorities, session if use_session else None, cves)
        rows = []
        if candidates and groups:
            rows = await ix.rows("assess", {"uid": owner_id, "rids": base["rids"], "groups": groups,
                                            "ids": [c.row["id"] for c in candidates]})
    groups_total = 0
    if candidates and groups:
        coverage = {r["id"]: r for r in rows}
        for cand in candidates:
            got = coverage.get(cand.row["id"])
            total = int(got["total"]) if got else 0
            groups_total = max(groups_total, total)
            if total:
                cand.title = int(got.get("title") or 0) / total
                cand.strong = int(got["strong"]) / total
                cand.anywhere = int(got["anywhere"]) / total
                cand.named = int(got.get("named") or 0)
    return FirstPass(tuple(wordings), candidates, groups, cves, groups_total)


def is_related(cand: Candidate, th: Thresholds) -> bool:
    return (cand.entity_match or cand.anywhere >= th.related or cand.strong >= th.strong
            or cand.fuzzy >= th.fuzzy)


def is_strong(cand: Candidate, th: Thresholds) -> bool:
    return (cand.entity_match or cand.strong >= th.strong
            or (len(cand.wordings) >= th.agree and cand.anywhere >= th.related))


def card_of(row: Mapping[str, Any], resource: Any) -> Card:
    from tradecraft.library import page_ids
    fetched = row.get("fetched_at")
    return Card(
        page_id=page_ids.format(resource.slug, int(row["page_id"])),
        resource_slug=resource.slug,
        url=row.get("url") or "",
        title=row.get("title") or "",
        title_source=row.get("title_source") or "guessed",
        breadcrumb=tuple(row.get("breadcrumb") or ()),
        headings=tuple(h.get("text", "") if isinstance(h, Mapping) else str(h) for h in row.get("headings") or ()),
        description=row.get("description") or "",
        topics=tuple(row.get("topics") or ()),
        kinds=tuple(row.get("kinds") or ()),
        technologies=tuple(row.get("technologies") or ()),
        entities=tuple(row.get("entities") or ()),
        size_chars=int(row.get("size_chars") or 0),
        fetched_at=fetched.isoformat() if hasattr(fetched, "isoformat") else (fetched or None),
        storage_mode=getattr(resource, "storage_mode", "live"),
        stored=bool(row.get("stored")),
    )


async def _snippets(index: Any, owner_id: str, shown: Sequence[Candidate], groups: Sequence[str]) -> None:
    """The best matching stored section's words, for the hits shown that have sections."""
    rows = await index.rows("section_snippets", {
        "uid": owner_id, "rids": sorted({c.row["resource_id"] for c in shown}), "ids": [c.row["id"] for c in shown],
        "q": _or(groups)})
    by_id = {r["id"]: r for r in rows}
    for cand in shown:
        got = by_id.get(cand.row["id"])
        if got:
            cand.snippet = " ".join(str(got.get("snippet") or "").split())[:200]
            cand.section = cand.section or got.get("heading") or None


def _order(cand: Candidate) -> tuple:
    """Related pages, the ones that hold more of the need first: an exact CVE, then the share
    of the need found anywhere on the page, then in its title, then in its title and headings;
    among equals the fused rank with its boosts decides. The fuzzy title similarity is
    continuous: ahead of the fused rank it would leave priority, the session and the wordings'
    agreement nothing to decide, so it only breaks the fused rank's ties (it is in that rank
    already, as the fuzzy wording's list)."""
    return (not cand.entity_match, -round(cand.anywhere, 3), -round(cand.title, 3), -round(cand.strong, 3),
            -cand.score, -cand.fuzzy, cand.row["page_id"])


def verdict_of(candidates: Sequence[Candidate], strictness: str) -> tuple[str, list[Candidate]]:
    th = STRICTNESS.get(strictness, STRICTNESS["balanced"])
    related = sorted((c for c in candidates if is_related(c, th)), key=_order)
    if not related:
        return "NOT FOUND", []
    return ("FOUND" if any(is_strong(c, th) for c in related) else "RELATED"), related


async def search(owner_id: str, catalog: Any, query: str, *, resource: Optional[str] = None,
                 topic: Optional[str] = None, kind: Optional[str] = None, technology: Optional[str] = None,
                 session: Optional[Session] = None, settings: Optional[EffectiveSettings] = None,
                 index: Any = None) -> SearchAnswer:
    settings = _search_settings(catalog, settings)
    async with one_snapshot(index or LibraryIndex()) as ix:
        fp = await free_first_pass(owner_id, catalog, query, resource=resource, topic=topic, kind=kind,
                                   technology=technology, session=session, settings=settings, index=ix)
        verdict, ranked = verdict_of(fp.candidates, settings.str("search.strictness"))
        shown = ranked[:settings.int("search.results")]
        if shown and fp.groups:
            await _snippets(ix, owner_id, shown, fp.groups)
    by_id = {r.id: r for r in _resources(catalog)}
    hits = tuple(SearchHit(card=card_of(c.row, by_id[c.row["resource_id"]]), score=round(c.score, 6),
                           wordings_matched=len(c.wordings), section=c.section, snippet=c.snippet) for c in shown)
    return SearchAnswer(verdict=verdict, hits=hits, wordings=tuple(w.label for w in fp.wordings), total=len(ranked))


# --------------------------------------------------------------------------------------
# Browse
# --------------------------------------------------------------------------------------

def normalize_path(path: Optional[str]) -> str:
    """A folder path as the tree stores it: no leading slash, one trailing slash, "" for the root."""
    inner = "/".join(p.strip() for p in str(path or "").strip().strip("/").split("/") if p.strip())
    return inner + "/" if inner else ""


async def browse(owner_id: str, catalog: Any, resource: str, path: Optional[str] = "", *,
                 index: Any = None) -> BrowseLevel:
    """One level of a resource's tree: its folders with counts and descriptions, then the pages
    at that level, at most ``BROWSE_LINES`` lines; the root also shows the resource's summary."""
    res = _scope(catalog, resource)[0] if resource else None
    if res is None:
        raise SearchError("browsing needs a resource: tradecraft_search(resource=..., path=...)")
    path = normalize_path(path)
    async with one_snapshot(index or LibraryIndex()) as ix:
        return await _browse(ix, owner_id, res, path)


async def _browse(index: Any, owner_id: str, res: Any, path: str) -> BrowseLevel:
    from tradecraft.ingest.tree import topic_of_label

    key = {"uid": owner_id, "rid": res.id}
    node = None
    if path:
        found = await index.rows("tree_node", {**key, "path": path})
        if not found:
            raise SearchError(f"no folder {path!r} in resource {res.slug!r}; browse its root with path=\"\"")
        node = found[0]
    children = await index.rows("tree_level", {**key, "parent": path, "limit": BROWSE_LINES})
    virtual = (node is not None and node["kind"] == "topic") or any(c["kind"] == "topic" for c in children)
    if node is None:
        page_count = int((await index.rows("kept_count", key))[0]["n"])
        mode = ("none" if virtual else "folder") if children else "all"
    elif node["kind"] == "topic":
        page_count = int(node["page_count"])
        mode = "topic" if topic_of_label(node["label"]) else "other"
    else:
        page_count, mode = int(node["page_count"]), "folder"
    folders = tuple(BrowseFolder(path=c["path"], label=c["label"], page_count=int(c["page_count"]),
                                 description=c["description"] or "") for c in children)
    more = (int(children[0]["total"]) - len(children)) if children else 0
    pages: tuple[Card, ...] = ()
    if mode != "none":
        room = max(0, BROWSE_LINES - len(folders))
        params = {**key, "mode": mode, "crumbs": [p for p in path.rstrip("/").split("/") if p],
                  "topic": topic_of_label(node["label"]) if node is not None and node["kind"] == "topic" else None,
                  "limit": max(room, 1)}
        rows = await index.rows("pages_at", params)
        pages = tuple(card_of(r, res) for r in rows[:room])
        more += (int(rows[0]["total"]) - len(pages)) if rows else 0
    crumbs = tuple(p for p in path.rstrip("/").split("/") if p)
    return BrowseLevel(resource_slug=res.slug, path=path, breadcrumb=(res.name or res.slug, *crumbs),
                       page_count=page_count, folders=folders, pages=pages, more=max(0, more),
                       summary=(res.summary or "") if not path else None)
