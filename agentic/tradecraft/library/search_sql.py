"""Every SQL statement of library search and browse (T2.4).

Rules, held by ``tests/test_tradecraft_search.py``:

- Every statement is keyed by the owner (``%(uid)s``) and by the resources the run may read:
  the catalog's list (``%(rids)s``) or one resource of it (``%(rid)s``), checked against the
  catalog before the call. No row of another user, and no resource outside the catalog,
  can come back (Q12, R-324).
- Every read of entries, sections or the tree joins its resource row's live ``generation``:
  no caller names a generation, so a refresh that swaps during a run is read at the next call
  (D-46).
- The agent's query text and the expanded wordings travel only as bound parameters
  (``websearch_to_tsquery(..., %(q)s)``, ``%(q)s <% title``): the text is model output a target
  page may have shaped (D-56). The statements below are built once, at import, from table names
  and fixed fragments only; nothing at call time formats a value into them.
"""

from __future__ import annotations

from tradecraft import schema_columns as sc

E, S, T, R = sc.TABLE_ENTRIES, sc.TABLE_SECTIONS, sc.TABLE_TREE, sc.TABLE_RESOURCES
CFG = sc.TEXT_SEARCH_CONFIG

CARD = ("e.id, e.page_id, e.resource_id, e.url, e.title, e.title_source, e.breadcrumb, e.headings, "
        "e.description, e.topics, e.kinds, e.technologies, e.entities, e.size_chars, e.fetched_at, "
        "(e.stored_bytes > 0) AS stored")
LIVE_E = f"JOIN {R} r ON r.id = e.resource_id AND r.user_id = e.user_id AND e.generation = r.generation"
LIVE_S = f"JOIN {R} rs ON rs.id = s.resource_id AND rs.user_id = s.user_id AND s.generation = rs.generation"
LIVE_T = f"JOIN {R} r ON r.id = t.resource_id AND r.user_id = t.user_id AND t.generation = r.generation"
KEYED_E = "e.user_id = %(uid)s AND e.resource_id = ANY(%(rids)s::text[]) AND e.status = 'kept'"
# The agent's explicit filters (the tool's topic, kind and technology), and the technologies of
# a wording that adds the target's: each is a no-op when its parameter is NULL or empty.
FILTERS = (
    "(%(topic)s::text IS NULL OR %(topic)s::text = ANY(e.topics)) "
    "AND (%(kind)s::text IS NULL OR %(kind)s::text = ANY(e.kinds)) "
    "AND (%(tech)s::text IS NULL OR %(tech)s::text = ANY(e.technologies) OR %(tech)s::text = ANY(e.entities)) "
    "AND (cardinality(%(techs)s::text[]) = 0 OR e.technologies && %(techs)s::text[] "
    "OR e.entities && %(techs)s::text[])"
)
TSQ = f"(SELECT websearch_to_tsquery('{CFG}', %(q)s) AS tsq) q"
# A term group of the agent's words (a word or its synonyms) as one tsquery, and whether it has
# a lexeme at all (a stop word has none, and counts neither way).
GROUP = f"websearch_to_tsquery('{CFG}', g)"
GROUPS = "unnest(%(groups)s::text[]) AS gs(g)"

STATEMENTS: dict[str, str] = {
    # --- the free first pass: one statement per kind of wording ---------------------------
    "entries_text": (
        f"SELECT {CARD}, ts_rank_cd(e.search_vector, q.tsq) AS rank FROM {E} e {LIVE_E} CROSS JOIN {TSQ} "
        f"WHERE {KEYED_E} AND {FILTERS} AND e.search_vector @@ q.tsq "
        f"ORDER BY rank DESC, e.page_id LIMIT %(limit)s"
    ),
    "sections_text": (
        f"SELECT {CARD}, b.heading AS section, b.rank FROM ("
        f"SELECT DISTINCT ON (s.entry_id) s.entry_id, s.heading, ts_rank_cd(s.search_vector, q.tsq) AS rank "
        f"FROM {S} s {LIVE_S} CROSS JOIN {TSQ} "
        f"WHERE s.user_id = %(uid)s AND s.resource_id = ANY(%(rids)s::text[]) AND s.search_vector @@ q.tsq "
        f"ORDER BY s.entry_id, rank DESC, s.ord) b "
        f"JOIN {E} e ON e.id = b.entry_id {LIVE_E} "
        f"WHERE {KEYED_E} AND {FILTERS} ORDER BY b.rank DESC, e.page_id LIMIT %(limit)s"
    ),
    "entries_entities": (
        f"SELECT {CARD}, (SELECT count(*) FROM unnest(e.entities) AS x(v) WHERE x.v = ANY(%(ents)s::text[]))::float8 "
        f"AS rank FROM {E} e {LIVE_E} WHERE {KEYED_E} AND {FILTERS} AND e.entities && %(ents)s::text[] "
        f"ORDER BY rank DESC, e.page_id LIMIT %(limit)s"
    ),
    "entries_fuzzy": (
        f"SELECT {CARD}, word_similarity(%(q)s, e.title)::float8 AS rank FROM {E} e {LIVE_E} "
        f"WHERE {KEYED_E} AND {FILTERS} AND %(q)s <%% e.title "
        f"ORDER BY rank DESC, e.page_id LIMIT %(limit)s"
    ),
    # How much of the agent's need each candidate covers: its term groups found in the title,
    # breadcrumb and headings (weights A and B), and found anywhere (the card or a section).
    "assess": (
        f"SELECT e.id, "
        f"(SELECT count(*) FROM {GROUPS} WHERE numnode({GROUP}) > 0) AS total, "
        f"(SELECT count(*) FROM {GROUPS} WHERE numnode({GROUP}) > 0 "
        f"AND ts_filter(e.search_vector, '{{a,b}}') @@ {GROUP}) AS strong, "
        f"(SELECT count(*) FROM {GROUPS} WHERE numnode({GROUP}) > 0 AND (e.search_vector @@ {GROUP} "
        f"OR EXISTS (SELECT 1 FROM {S} s WHERE s.entry_id = e.id AND s.user_id = e.user_id "
        f"AND s.resource_id = e.resource_id AND s.generation = e.generation AND s.search_vector @@ {GROUP}))) "
        f"AS anywhere "
        f"FROM {E} e {LIVE_E} WHERE {KEYED_E} AND e.id = ANY(%(ids)s::bigint[])"
    ),
    # A few words of the stored section that matched best, for the hits shown (R-091).
    "section_snippets": (
        f"SELECT DISTINCT ON (s.entry_id) s.entry_id AS id, s.heading, ts_headline('{CFG}', s.text, q.tsq, "
        f"'MaxWords=18, MinWords=6, MaxFragments=1, StartSel=\"\", StopSel=\"\"') AS snippet "
        f"FROM {S} s {LIVE_S} CROSS JOIN {TSQ} WHERE s.user_id = %(uid)s AND s.resource_id = ANY(%(rids)s::text[]) "
        f"AND s.entry_id = ANY(%(ids)s::bigint[]) AND s.search_vector @@ q.tsq "
        f"ORDER BY s.entry_id, ts_rank_cd(s.search_vector, q.tsq) DESC, s.ord"
    ),
    # --- browse: one resource of the catalog ------------------------------------------
    "tree_level": (
        f"SELECT t.path, t.parent_path, t.label, t.page_count, t.description, t.kind, count(*) OVER () AS total "
        f"FROM {T} t {LIVE_T} WHERE t.user_id = %(uid)s AND t.resource_id = %(rid)s AND t.parent_path = %(parent)s "
        f"ORDER BY t.page_count DESC, t.label LIMIT %(limit)s"
    ),
    "tree_node": (
        f"SELECT t.path, t.parent_path, t.label, t.page_count, t.description, t.kind FROM {T} t {LIVE_T} "
        f"WHERE t.user_id = %(uid)s AND t.resource_id = %(rid)s AND t.path = %(path)s"
    ),
    "pages_at": (
        f"SELECT {CARD}, count(*) OVER () AS total FROM {E} e {LIVE_E} "
        f"WHERE e.user_id = %(uid)s AND e.resource_id = %(rid)s AND e.status = 'kept' AND ("
        f"(%(mode)s = 'folder' AND e.breadcrumb = %(crumbs)s::text[]) "
        f"OR (%(mode)s = 'topic' AND %(topic)s::text = ANY(e.topics)) "
        f"OR (%(mode)s = 'other' AND cardinality(e.topics) = 0) OR %(mode)s = 'all') "
        f"ORDER BY e.page_id LIMIT %(limit)s"
    ),
    "kept_count": (
        f"SELECT count(*) AS n FROM {E} e {LIVE_E} "
        f"WHERE e.user_id = %(uid)s AND e.resource_id = %(rid)s AND e.status = 'kept'"
    ),
}

# Run first in the same transaction: the fuzzy wording's similarity threshold, lower than
# pg_trgm's 0.6 default so that a typo ("kerberaosting") still meets its title. It reads no
# table and sets nothing beyond this transaction.
PRELUDES: dict[str, str] = {
    "entries_fuzzy": "SELECT set_config('pg_trgm.word_similarity_threshold', %(threshold)s, true)",
}
