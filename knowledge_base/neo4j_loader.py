import logging
import re
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Cypher identifier allowlist — used to validate any string that gets
# interpolated into a Cypher query (labels, property keys, etc.).
# Anything that doesn't match this is rejected outright. Identifiers are
# never user-controlled today but this is defense-in-depth in case a future
# caller forwards untrusted input into upsert_chunks() or filter_chunks().
_CYPHER_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_cypher_identifier(value: str, field: str) -> str:
    """
    Reject any identifier that doesn't match a strict allowlist.

    Args:
        value: The candidate identifier (label name, property key, etc.).
        field: A human-readable name of the field being validated, used in
               the error message.

    Returns:
        The validated identifier (unchanged).

    Raises:
        ValueError: if the identifier is not a safe Cypher identifier.
    """
    if not isinstance(value, str) or not _CYPHER_IDENT_RE.fullmatch(value):
        raise ValueError(
            f"Refusing to interpolate unsafe Cypher identifier into "
            f"{field}: {value!r}"
        )
    return value

# Schema definitions per source label.
# Each entry: (label, [(index_name, property_name), ...])
SOURCE_SCHEMAS = {
    "NVDChunk": [
        ("nvd_cve_id", "cve_id"),
        ("nvd_cvss", "cvss_score"),
        ("nvd_severity", "severity"),
    ],
    "ExploitDBChunk": [
        ("edb_id", "edb_id"),
        ("edb_cve", "cve_id"),
        ("edb_platform", "platform"),
    ],
    "GTFOBinsChunk": [
        ("gtfo_binary", "binary_name"),
        ("gtfo_function", "function_type"),
    ],
    "LOLBASChunk": [
        ("lolbas_binary", "binary_name"),
        ("lolbas_category", "category"),
        ("lolbas_mitre", "mitre_id"),
    ],
    "OWASPChunk": [
        ("owasp_test_id", "test_id"),
        ("owasp_category", "category"),
    ],
    "NucleiChunk": [
        ("nuclei_template", "template_id"),
        ("nuclei_severity", "severity"),
        ("nuclei_cve_id",   "cve_id"),
        ("nuclei_cvss",     "cvss_score"),
        ("nuclei_protocol", "protocol"),
    ],
    "ToolDocChunk": [
        ("tooldoc_tool", "tool_name"),
    ],
}


class Neo4jLoader:
    """Manages KBChunk nodes in Neo4j with multi-label schema."""

    def __init__(self, driver):
        """
        Args:
            driver: Neo4j driver instance (shared with the rest of the app).
        """
        self.driver = driver

    def ensure_schema(self) -> None:
        """
        Create constraints and indexes for KBChunk + all source labels.

        Idempotent — uses IF NOT EXISTS on all operations.

        Also creates the fulltext (Lucene) index ``kb_chunk_fulltext`` over
        ``content`` and ``title``, used by ``fulltext_search()`` for the
        keyword half of hybrid retrieval.
        """
        statements = [
            # Base constraint
            "CREATE CONSTRAINT kb_chunk_id IF NOT EXISTS "
            "FOR (c:KBChunk) REQUIRE c.chunk_id IS UNIQUE",
            # Fulltext (Lucene) index for hybrid retrieval — backs
            # fulltext_search() / db.index.fulltext.queryNodes calls.
            "CREATE FULLTEXT INDEX kb_chunk_fulltext IF NOT EXISTS "
            "FOR (c:KBChunk) ON EACH [c.content, c.title]",
        ]

        # Per-source-label indexes. All three identifiers (label,
        # index_name, property) are validated against the Cypher
        # identifier allowlist before interpolation.
        for label, indexes in SOURCE_SCHEMAS.items():
            safe_label = _validate_cypher_identifier(label, "schema label")
            for index_name, prop in indexes:
                safe_index = _validate_cypher_identifier(
                    index_name, "schema index name"
                )
                safe_prop = _validate_cypher_identifier(
                    prop, "schema property name"
                )
                statements.append(
                    f"CREATE INDEX {safe_index} IF NOT EXISTS "
                    f"FOR (c:{safe_label}) ON (c.{safe_prop})"
                )

        with self.driver.session() as session:
            for stmt in statements:
                try:
                    session.run(stmt)
                except Exception as e:
                    logger.warning(f"Schema statement failed (may already exist): {e}")

        logger.info(
            f"KB schema ensured: 1 constraint + 1 fulltext index + "
            f"{sum(len(v) for v in SOURCE_SCHEMAS.values())} property indexes"
        )

    def upsert_chunks(self, chunks: list[dict], node_label: str) -> int:
        """
        MERGE KBChunk nodes by chunk_id, adding source-specific label.

        Each chunk dict must have: chunk_id, content, title, source.
        Additional keys become node properties.

        Args:
            chunks: List of chunk dicts.
            node_label: Source-specific Neo4j label (e.g., 'NVDChunk').

        Returns:
            Number of chunks upserted.
        """
        if not chunks:
            return 0

        _validate_cypher_identifier(node_label, "node_label")
        if node_label not in SOURCE_SCHEMAS:
            raise ValueError(
                f"Unknown node label {node_label!r}. "
                f"Known labels: {sorted(SOURCE_SCHEMAS.keys())}. "
                f"Add it to SOURCE_SCHEMAS in neo4j_loader.py before use."
            )

        now = datetime.now(timezone.utc).isoformat()
        count = 0

        with self.driver.session() as session:
            for chunk in chunks:
                chunk_id = chunk.get("chunk_id")
                if not chunk_id:
                    logger.warning("Skipping chunk without chunk_id")
                    continue

                # Build properties dict (exclude None values)
                props = {k: v for k, v in chunk.items() if v is not None}
                props["ingested_at"] = now

                # MERGE by chunk_id, SET all properties, add both labels
                cypher = (
                    f"MERGE (c:KBChunk {{chunk_id: $chunk_id}}) "
                    f"SET c += $props "
                    f"SET c:{node_label} "
                )
                try:
                    session.run(cypher, chunk_id=chunk_id, props=props)
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to upsert chunk {chunk_id}: {e}")

        logger.info(f"Upserted {count}/{len(chunks)} chunks as :{node_label}")
        return count

    def filter_chunks(
        self,
        chunk_ids: list[str],
        sources: Optional[list[str]] = None,
        min_cvss: Optional[float] = None,
        severity: Optional[str] = None,
        **filters,
    ) -> list[dict]:
        """
        Query KBChunk nodes matching chunk_ids + optional filters.

        Builds a dynamic Cypher WHERE clause. Does NOT apply tenant filtering.

        Args:
            chunk_ids: FAISS candidate chunk_ids to filter.
            sources: Optional list of source names to restrict to.
            min_cvss: Optional minimum CVSS score. Applies to any chunk that
                carries a `cvss_score` property (currently NVDChunk and
                NucleiChunk). Chunks without the field pass through
                unchanged — i.e. tool_docs, gtfobins, lolbas, owasp, and
                exploitdb chunks are NOT silently dropped just because they
                lack CVSS metadata.
            severity: Optional severity level filter. Applies to any chunk
                that carries a `severity` property (currently NVDChunk and
                NucleiChunk). Chunks without the field pass through
                unchanged, same semantics as min_cvss.
            **filters: Additional property filters (key=value).

        Returns:
            List of chunk dicts with all properties.
        """
        if not chunk_ids:
            return []

        where_clauses = ["c.chunk_id IN $chunk_ids"]
        params = {"chunk_ids": chunk_ids}

        if sources:
            where_clauses.append("c.source IN $sources")
            params["sources"] = sources

        # NULL-tolerant predicate: chunks without the field pass through
        # rather than being silently dropped. Without `IS NULL OR`, Cypher's
        # null-comparison semantics treat `null >= 7.0` as null/false in
        # WHERE, which would exclude every chunk from sources that don't
        # carry cvss_score (gtfobins, lolbas, owasp, exploitdb, tool_docs).
        if min_cvss is not None:
            where_clauses.append("(c.cvss_score IS NULL OR c.cvss_score >= $min_cvss)")
            params["min_cvss"] = min_cvss

        # Same NULL-tolerant pattern as min_cvss above.
        if severity:
            where_clauses.append("(c.severity IS NULL OR c.severity = $severity)")
            params["severity"] = severity

        # Validate filter keys against the Cypher identifier allowlist before
        # interpolating them into the query. The values are always parameterized,
        # but the property keys are not — so an unvalidated key like
        # `chunk_id} RETURN c //` would break out of the WHERE clause.
        for key, value in filters.items():
            _validate_cypher_identifier(key, "filter property key")
            param_name = f"filter_{key}"
            where_clauses.append(f"c.{key} = ${param_name}")
            params[param_name] = value

        where = " AND ".join(where_clauses)
        cypher = f"MATCH (c:KBChunk) WHERE {where} RETURN properties(c) AS props"

        with self.driver.session() as session:
            result = session.run(cypher, **params)
            chunks = [dict(record["props"]) for record in result]

        return chunks

    def fulltext_search(
        self,
        query: str,
        top_k: int = 30,
        sources: Optional[list[str]] = None,
    ) -> list[tuple[str, float]]:
        """
        Run a Lucene fulltext query against the kb_chunk_fulltext index.

        Used as the keyword half of hybrid retrieval — combined with FAISS
        vector results via Reciprocal Rank Fusion in the orchestrator.

        Args:
            query: User query string. Lucene syntax is supported but the
                   caller usually passes raw text. Special chars are escaped
                   defensively to avoid Lucene parser errors on punctuation.
            top_k: Maximum results to return.
            sources: Optional source filter to apply at query time. Faster
                     than filtering after the fact.

        Returns:
            List of (chunk_id, lucene_score) tuples sorted by score desc.
            Returns [] if Neo4j is unavailable, the index is missing, or
            the query is empty.
        """
        if not query or not query.strip():
            return []

        # Escape Lucene special chars so user queries don't blow up the
        # parser. The set is + - && || ! ( ) { } [ ] ^ " ~ * ? : \ /
        escaped = re.sub(r'[+\-!(){}\[\]^"~*?:\\/]', " ", query)
        # Strip stray double-ampersands and double-pipes that survived the
        # char-class regex.
        escaped = escaped.replace("&&", " ").replace("||", " ").strip()
        if not escaped:
            return []

        # Parameter name is `q_text` not `query` because Session.run()'s
        # first positional argument is also named `query`, and passing it via
        # **params would cause "got multiple values for argument 'query'".
        cypher = (
            "CALL db.index.fulltext.queryNodes("
            "'kb_chunk_fulltext', $q_text, {limit: $limit}"
            ") YIELD node, score "
        )
        params = {"q_text": escaped, "limit": top_k}

        if sources:
            cypher += "WHERE node.source IN $sources "
            params["sources"] = sources

        cypher += "RETURN node.chunk_id AS chunk_id, score ORDER BY score DESC"

        try:
            with self.driver.session() as session:
                result = session.run(cypher, **params)
                return [(r["chunk_id"], float(r["score"])) for r in result]
        except Exception as e:
            # Most common cause: fulltext index doesn't exist yet (older
            # KB built before this feature shipped). Log once and return empty
            # so the caller falls back to vector-only.
            logger.warning(
                f"Fulltext search failed (index may not exist — run "
                f"`ensure_schema()` once): {e}"
            )
            return []

    def get_stats(self) -> dict:
        """Count chunks by source. Returns {source_name: count, ...}."""
        cypher = (
            "MATCH (c:KBChunk) "
            "RETURN c.source AS source, count(c) AS cnt "
            "ORDER BY cnt DESC"
        )

        with self.driver.session() as session:
            result = session.run(cypher)
            return {record["source"]: record["cnt"] for record in result}

    def drop_source(self, source: str) -> int:
        """
        Delete all KBChunk nodes with the given source.

        Used for full rebuilds of a single source.

        Returns:
            Number of nodes deleted.
        """
        cypher = (
            "MATCH (c:KBChunk {source: $source}) "
            "WITH c LIMIT 10000 "
            "DETACH DELETE c "
            "RETURN count(*) AS deleted"
        )

        total_deleted = 0
        with self.driver.session() as session:
            while True:
                result = session.run(cypher, source=source)
                record = result.single()
                batch_deleted = record["deleted"] if record else 0
                total_deleted += batch_deleted
                if batch_deleted < 10000:
                    break

        logger.info(f"Dropped {total_deleted} KBChunk nodes with source='{source}'")
        return total_deleted

    def drop_all_chunks(self) -> int:
        """
        Delete every KBChunk node regardless of source.

        Used by the destructive rebuild path in data_ingestion.run_ingestion()
        to wipe the entire KB before re-ingesting the profile's sources for Neo4j.

        Source-agnostic by design: new KB sources don't need to be added to
        any hardcoded list. Anything with the :KBChunk label gets dropped.

        Batched at 10k per transaction to avoid holding a giant write lock
        across a multi-GB Neo4j dataset. Same pattern as drop_source().

        Returns:
            Number of nodes deleted across all sources.
        """
        cypher = (
            "MATCH (c:KBChunk) "
            "WITH c LIMIT 10000 "
            "DETACH DELETE c "
            "RETURN count(*) AS deleted"
        )

        total_deleted = 0
        with self.driver.session() as session:
            while True:
                result = session.run(cypher)
                record = result.single()
                batch_deleted = record["deleted"] if record else 0
                total_deleted += batch_deleted
                if batch_deleted < 10000:
                    break

        logger.info(f"Dropped {total_deleted} KBChunk nodes (full wipe)")
        return total_deleted
