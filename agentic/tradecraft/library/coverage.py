"""The coverage map and the skill line (Q5, T5.4): the library's menu in the agent's prompt.

``coverage_for(catalog)`` runs once per run start or resume, from ``runtime.bind_run_catalog``:
one statement over a short-lived connection, keyed by the catalog's owner and its resources (the
ones active in the project and allowed for the person), joined to each resource's live
generation, counting kept pages only. The binding runs on the agent's event loop, so the
connection gives up after ``CONNECT_TIMEOUT_SEC`` and the statement after
``STATEMENT_TIMEOUT_MS``; on a timeout or any error the run has no map (one
``[tradecraft] coverage code=...`` log line) and goes on.

The map (``render_map``) is built from counts and the fixed topic, kind and technology lists
only, never from a page title or text: per topic its pages, its largest kinds and technologies,
at most ``constants.coverageMapMaxTopics`` topics; "Not covered" for the fixed-list topics with
no page; one line per CVE archive; and the resources by slug and type (by number beyond
``constants.fullSummaryMaxResources``, where the one-line list follows). Its size depends on the
number of topics, not of pages. ``skill_line(topic)`` is the map's line for the skill the Intent
Router picked, added to that skill's prompt (``prompts.get_phase_tools``).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from logging_config import get_logger
from tradecraft import schema_columns as sc
from tradecraft.settings import EffectiveSettings, constant
from tradecraft.vocab import load_vocab

logger = get_logger(__name__)

MAX_TOPICS = int(constant("coverageMapMaxTopics"))
# The map's size depends on the topics only (Q5: 300-400 tokens): two kinds and two
# technologies a topic, and the resources by name only while the full summaries follow.
KINDS_PER_TOPIC = 2
TECHS_PER_TOPIC = 2
NAMED_RESOURCES = int(constant("fullSummaryMaxResources"))
CONNECT_TIMEOUT_SEC = 3
STATEMENT_TIMEOUT_MS = 2000

TYPE_LABELS = {"mkdocs-wiki": "wiki", "sphinx-docs": "docs", "gitbook": "GitBook", "github-repo": "GitHub",
               "cve-poc-db": "CVE archive", "pdf": "PDF", "agentic-crawl": "website"}

E, R = sc.TABLE_ENTRIES, sc.TABLE_RESOURCES
# Counts only: the total and per resource, per topic, per topic and kind, per topic and
# technology. Owner and resources are bound parameters; the live generation and kept pages only.
COVERAGE_SQL = (
    f"WITH live AS (SELECT e.resource_id, e.topics, e.kinds, e.technologies FROM {E} e "
    f"JOIN {R} r ON r.id = e.resource_id AND r.user_id = e.user_id AND e.generation = r.generation "
    f"WHERE e.user_id = %(uid)s AND e.resource_id = ANY(%(rids)s::text[]) AND e.status = 'kept') "
    "SELECT 'resource' AS k, resource_id AS a, NULL::text AS b, count(*) AS n FROM live GROUP BY resource_id "
    "UNION ALL SELECT 'topic', t, NULL, count(*) FROM live, unnest(topics) AS t GROUP BY t "
    "UNION ALL SELECT 'kind', t, k, count(*) FROM live, unnest(topics) AS t, unnest(kinds) AS k GROUP BY t, k "
    "UNION ALL SELECT 'tech', t, x, count(*) FROM live, unnest(topics) AS t, unnest(technologies) AS x GROUP BY t, x"
)


def _error_code(exc: BaseException) -> str:
    import psycopg

    from tradecraft import db

    if isinstance(exc, db.StoreUnavailable):
        return "store_unavailable"
    if isinstance(exc, (psycopg.errors.QueryCanceled, psycopg.errors.ConnectionTimeout)):
        return "timeout"
    if isinstance(exc, psycopg.OperationalError):
        return "unreachable"
    return "internal_error"


def query(owner_id: str, resource_ids: list[str]) -> list[dict]:
    """The statement's rows, on a connection of its own (never the pool of another loop). The
    driver is imported here: the prompt builder imports this module for ``skill_line`` in every
    run, 1.x ones included."""
    import psycopg
    from psycopg.rows import dict_row

    from tradecraft import db

    with psycopg.connect(db.dsn(), connect_timeout=CONNECT_TIMEOUT_SEC, autocommit=True, row_factory=dict_row,
                         options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}") as conn:
        return list(conn.execute(COVERAGE_SQL, {"uid": owner_id, "rids": resource_ids}).fetchall())


def coverage_for(catalog: Any) -> Optional[dict]:
    """The run's coverage counts, or None (a 1.x catalog, no resource, a timeout, any error)."""
    resources = list(getattr(catalog, "resources", None) or ())
    if getattr(catalog, "v2", False) is not True or not resources:
        return None
    searched = [r.id for r in resources if r.type != "cve-poc-db"]
    try:
        rows = query(catalog.owner_id, searched) if searched else []
    except Exception as exc:
        logger.warning(f"[tradecraft] coverage code={_error_code(exc)}")
        return None
    return aggregate(rows, resources)


def aggregate(rows: list[Mapping[str, Any]], resources: list[Any]) -> dict:
    """The counts by fixed-list ids only: a value the vocabulary does not know is left out."""
    vocab = load_vocab()
    topics_known, kinds_known = set(vocab.topic_ids), set(vocab.kind_ids)
    techs_known = {t["id"] for t in vocab.technologies}
    pages: dict[str, int] = {}
    topics: dict[str, dict] = {}
    for row in rows:
        kind, a, b, n = row["k"], row["a"], row["b"], int(row["n"])
        if kind == "resource":
            pages[a] = n
        elif a in topics_known:
            topic = topics.setdefault(a, {"pages": 0, "kinds": {}, "technologies": {}})
            if kind == "topic":
                topic["pages"] = n
            elif kind == "kind" and b in kinds_known:
                topic["kinds"][b] = n
            elif kind == "tech" and b in techs_known:
                topic["technologies"][b] = n
    return {
        "pages": sum(pages.values()),
        "resources": [{"slug": r.slug, "type": r.type, "pages": pages.get(r.id, 0)} for r in resources],
        "topics": {t: v for t, v in topics.items() if v["pages"]},
    }


def _top(counts: Mapping[str, int], n: int) -> list[tuple[str, int]]:
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def _topic_label(topic: str) -> str:
    return next((t["label"] for t in load_vocab().topics if t["id"] == topic), topic)


def topic_summary(entry: Mapping[str, Any]) -> str:
    """``412 pages · payloads 230, bypasses 40 · PostgreSQL, MSSQL``: counts and fixed names only."""
    vocab = load_vocab()
    kind_labels = {k["id"]: k["mapLabel"] for k in vocab.kinds}
    tech_names = {t["id"]: t["name"] for t in vocab.technologies}
    # Plain digits: a topic line is repeated up to 20 times, and every character counts (Q5).
    parts = [f"{entry['pages']} pages"]
    kinds = ", ".join(f"{kind_labels.get(k, k)} {n}" for k, n in _top(entry.get("kinds") or {}, KINDS_PER_TOPIC))
    if kinds:
        parts.append(kinds)
    techs = ", ".join(tech_names.get(t, t) for t, _n in _top(entry.get("technologies") or {}, TECHS_PER_TOPIC))
    if techs:
        parts.append(techs)
    return " · ".join(parts)


def render_map(coverage: Optional[Mapping[str, Any]], settings: Optional[EffectiveSettings] = None) -> str:
    """The map's text, or "" when there is none or ``prompt.coverageMap`` is off."""
    if not coverage or (settings is not None and not settings.bool("prompt.coverageMap")):
        return ""
    resources = coverage.get("resources") or []
    lines = [f"Tradecraft library ({len(resources)} resources, {int(coverage.get('pages') or 0):,} pages)"]
    topics = coverage.get("topics") or {}
    for topic, entry in sorted(topics.items(), key=lambda kv: (-kv[1]["pages"], kv[0]))[:MAX_TOPICS]:
        lines.append(f" {_topic_label(topic)}: {topic_summary(entry)}")
    for r in resources:
        if r["type"] == "cve-poc-db":
            lines.append(f" CVE archive {r['slug']} · look up by CVE ID")
    missing = [_topic_label(t) for t in load_vocab().topic_ids if t not in topics]
    if missing:
        lines.append(" Not covered: " + ", ".join(missing))
    if len(resources) <= NAMED_RESOURCES:
        lines.append("Resources: " + " · ".join(f"{r['slug']} ({TYPE_LABELS.get(r['type'], r['type'])})"
                                                for r in resources))
    else:
        # The list below names each of them with its type.
        lines.append(f"Resources: {len(resources)}, listed below")
    return "\n".join(lines)


def skill_line(topic: Optional[str]) -> Optional[str]:
    """The map's line for the skill the Intent Router picked: ``Library for SQL injection: …``;
    None outside a 2.0 run with a map, or for a skill whose topic has no page."""
    from tradecraft import runtime

    coverage = runtime.bound_coverage()
    entry = ((coverage or {}).get("topics") or {}).get(topic or "")
    if not entry:
        return None
    return f"Library for {_topic_label(topic)}: {topic_summary(entry)}"
