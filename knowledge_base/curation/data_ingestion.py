import argparse
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from neo4j import GraphDatabase

from knowledge_base.atomic_io import ingest_lock, IngestLockError, atomic_write_json
from knowledge_base.kb_config import load_kb_config
from knowledge_base.embedder import create_embedder
from knowledge_base.faiss_indexer import FAISSIndexer
from knowledge_base.neo4j_loader import Neo4jLoader
from knowledge_base.curation.tool_docs_client import ToolDocsClient
from knowledge_base.curation.gtfobins_client import GTFOBinsClient
from knowledge_base.curation.lolbas_client import LOLBASClient
from knowledge_base.curation.owasp_client import OWASPClient
from knowledge_base.curation.nuclei_client import NucleiClient
from knowledge_base.curation.nvd_client import NVDClient
from knowledge_base.curation.exploitdb_client import ExploitDBClient

logger = logging.getLogger(__name__)

# Hardcoded fallback profile → source list mapping. Used ONLY when
# knowledge_base.kb_config can't be loaded (missing pyyaml, corrupt
# kb_config.yaml, tests running without the config module on the path,
# etc.). The authoritative source of truth is kb_config.yaml's
# ``ingestion.profiles`` block; this dict is just a safety net so that
# a broken config doesn't take down ingestion entirely.
#
# When editing profile membership, change kb_config.yaml FIRST and only
# mirror to this fallback if you need parity on broken-config paths.
_FALLBACK_PROFILE_SOURCES = {
    "cpu-lite":  ["tool_docs", "gtfobins", "lolbas"],
    "lite":      ["tool_docs", "gtfobins", "lolbas", "owasp", "exploitdb"],
    "standard":  ["tool_docs", "gtfobins", "lolbas", "owasp", "exploitdb", "nvd"],
    "full":      ["tool_docs", "gtfobins", "lolbas", "owasp", "exploitdb", "nvd", "nuclei"],
}


def _load_profile_sources() -> dict[str, list[str]]:
    """Return the profile → source list mapping from kb_config.yaml.

    Falls back to the hardcoded ``_FALLBACK_PROFILE_SOURCES`` if the
    config module can't be imported or ``ingestion.profiles`` is empty.
    Always returns a non-empty dict — callers can assume at least the
    three standard profiles are defined.
    """
    try:
        cfg_profiles = load_kb_config().ingestion.profiles
        if cfg_profiles:
            return cfg_profiles
        logger.warning(
            "kb_config.ingestion.profiles is empty; falling back to hardcoded defaults"
        )
    except Exception as e:
        logger.warning(
            f"Could not load profiles from kb_config.yaml ({e}); "
            f"falling back to hardcoded defaults"
        )
    return dict(_FALLBACK_PROFILE_SOURCES)


def _resolve_clients(profile: str = None, source: str = None) -> list:
    """
    Resolve which clients to run based on profile or single source.

    The profile → source list mapping is read from kb_config.yaml
    ``ingestion.profiles`` block, with a hardcoded fallback if the
    config can't be loaded.
    """

    client_map = {
        "tool_docs": ToolDocsClient,
        "gtfobins": GTFOBinsClient,
        "lolbas": LOLBASClient,
        "owasp": OWASPClient,
        "nuclei": NucleiClient,
        "nvd": NVDClient,
        "exploitdb": ExploitDBClient,
    }

    if source:
        if source not in client_map:
            raise ValueError(
                f"Unknown source '{source}'. "
                f"Available: {', '.join(client_map.keys())}"
            )
        return [client_map[source]()]

    profile_sources = _load_profile_sources()
    profile = profile or "lite"
    if profile not in profile_sources:
        raise ValueError(
            f"Unknown profile '{profile}'. "
            f"Available: {', '.join(sorted(profile_sources.keys()))}"
        )

    source_names = profile_sources[profile]
    # Validate every name resolves to a known client
    unknown = [n for n in source_names if n not in client_map]
    if unknown:
        raise ValueError(
            f"Profile '{profile}' references unknown sources: {unknown}. "
            f"Check kb_config.yaml. Known sources: {sorted(client_map.keys())}"
        )
    return [client_map[name]() for name in source_names]


def run_ingestion(
    profile: str = "lite",
    source: str = None,
    rebuild: bool = False,
    kb_path: str = None,
    nvd_api_key: str = None,
    nvd_days: int = None,
    neo4j_uri: str = None,
    neo4j_user: str = None,
    neo4j_password: str = None,
    model_name: str = None,
) -> dict:
    """
    Main ingestion entry point.

    Args:
        profile: Ingestion profile (lite/standard/full).
        source: Single source to ingest (overrides profile).
        rebuild: If True, drop existing data and rebuild from scratch.
        kb_path: Custom path for FAISS index files.
        nvd_api_key: NVD API key for higher rate limits.
        neo4j_uri: Neo4j connection URI.
        neo4j_user: Neo4j username.
        neo4j_password: Neo4j password.

    Returns:
        Dict with ingestion stats.
    """

    start_time = time.time()
    data_dir = Path(kb_path) if kb_path else Path(__file__).parent.parent / "data"

    # Acquire a process-level exclusive lock on the data dir before
    # touching cache files. Refuses to start (rather than waiting) if
    # another ingest is already running. Released automatically on exit.
    try:
        with ingest_lock(data_dir, wait=False):
            return _do_ingestion(
                data_dir=data_dir,
                profile=profile,
                source=source,
                rebuild=rebuild,
                nvd_api_key=nvd_api_key,
                nvd_days=nvd_days,
                neo4j_uri=neo4j_uri,
                neo4j_user=neo4j_user,
                neo4j_password=neo4j_password,
                model_name=model_name,
                start_time=start_time,
            )
    except IngestLockError as e:
        logger.error(str(e))
        raise


def _do_ingestion(
    data_dir: Path,
    profile: str,
    source: str,
    rebuild: bool,
    nvd_api_key: str,
    nvd_days: int,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    model_name: str,
    start_time: float,
) -> dict:
    """The actual ingestion body, executed inside the ingest_lock."""

    # Initialize components
    logger.info(f"Initializing KB ingestion (profile={profile}, rebuild={rebuild})")
    model = model_name or os.getenv("KB_EMBEDDING_MODEL", "intfloat/e5-large-v2")
    embedder = create_embedder(model_name=model)
    faiss_indexer = FAISSIndexer(
        index_path=str(data_dir), dimensions=embedder.dimensions
    )

    # Neo4j setup
    neo4j_loader = None
    neo4j_uri = neo4j_uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
    # NEO4J_PASSWORD must be provided explicitly via env var or function arg.
    neo4j_password = neo4j_password or os.getenv("NEO4J_PASSWORD")
    if not neo4j_password:
        raise RuntimeError(
            "NEO4J_PASSWORD must be set (env var or function argument). "
            "No default password is allowed — set NEO4J_PASSWORD before running."
        )

    try:
        driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        driver.verify_connectivity()
        neo4j_loader = Neo4jLoader(driver)
        neo4j_loader.ensure_schema()
        logger.info(f"Connected to Neo4j at {neo4j_uri}")
    except Exception as e:
        logger.warning(f"Neo4j not available ({e}) — ingesting FAISS only, no metadata filtering")

    # ─────────────────────────────────────────────────────────────────────
    # Rebuild: destructive reset of BOTH stores
    # ─────────────────────────────────────────────────────────────────────
    if not rebuild:
        faiss_indexer.load()
        # Guard against dimension mismatch when switching embedding models
        if (faiss_indexer.count() > 0
                and faiss_indexer.index is not None
                and faiss_indexer.index.d != embedder.dimensions):
            raise ValueError(
                f"Embedding dimensions mismatch: model produces "
                f"{embedder.dimensions}d vectors but existing index has "
                f"{faiss_indexer.index.d}d vectors. "
                f"Run with --rebuild to recreate the index with the new model."
            )
    else:
        _delete_stale_faiss_files(data_dir)

    # Load content hash manifest for dedup
    manifest = {} if rebuild else _load_manifest(data_dir)

    # On rebuild, clear file-level hash maps so clients re-process all files
    if rebuild:
        _clear_file_hashes(data_dir)

        # Wipe every :KBChunk from Neo4j in one source-agnostic batched sweep.
        # This replaces the old per-source drop inside the client loop, which
        # only dropped in-profile sources and left out-of-profile orphans.
        if neo4j_loader:
            neo4j_loader.drop_all_chunks()

        # Invalidate the incremental-update cursor. Without this, a
        # post-rebuild kb-update-nvd would fetch only CVEs modified since
        # the pre-rebuild timestamp and silently "restore" an almost-empty
        # NVD dataset.
        last_ingest_file = data_dir / ".last_ingest"
        if last_ingest_file.exists():
            try:
                last_ingest_file.unlink()
                logger.info(
                    "Deleted .last_ingest — next incremental update will do "
                    "a full-window fetch instead of an incremental delta"
                )
            except OSError as e:
                logger.warning(f"Could not delete .last_ingest: {e}")

    # Resolve clients
    clients = _resolve_clients(profile, source)
    stats = {"profile": profile, "sources": {}, "total_chunks": 0}

    for client in clients:
        source_name = client.SOURCE
        source_start = time.time()
        logger.info(f"--- Ingesting: {source_name} ({client.NODE_LABEL}) ---")

        # (Formerly: per-source Neo4j drop on rebuild. Now redundant
        # because drop_all_chunks() above wiped every source already.
        # Kept intentionally removed rather than left as a no-op so
        # future readers don't wonder why it's there.)

        # Fetch raw data
        fetch_kwargs = {}
        if rebuild:
            fetch_kwargs["force_download"] = True
        if source_name == "nvd":
            fetch_kwargs["nvd_api_key"] = nvd_api_key
            if nvd_days is not None:
                fetch_kwargs["nvd_days"] = nvd_days
            nvd_profile = profile if profile in ("standard", "full") else "standard"
            fetch_kwargs["profile"] = nvd_profile
            # Incremental: only if NVD data already exists in Neo4j
            if not rebuild and neo4j_loader:
                try:
                    stats_check = neo4j_loader.get_stats()
                    if stats_check.get("nvd", 0) > 0:
                        last_ingest = _read_last_ingest(data_dir)
                        if last_ingest:
                            fetch_kwargs["since"] = last_ingest
                            logger.info(f"NVD incremental update since {last_ingest}")
                except Exception:
                    pass

        try:
            raw_data = client.fetch(**fetch_kwargs)
        except Exception as e:
            logger.error(f"Failed to fetch {source_name}: {e}")
            stats["sources"][source_name] = {"error": str(e)}
            continue

        if not raw_data:
            logger.info(f"No data fetched for {source_name}")
            stats["sources"][source_name] = {"chunks": 0, "skipped": True}
            continue

        # Convert to chunks
        try:
            chunks = client.to_chunks(raw_data)
        except Exception as e:
            logger.error(f"Failed to chunk {source_name}: {e}")
            stats["sources"][source_name] = {"error": str(e)}
            continue

        if not chunks:
            logger.info(f"No chunks produced for {source_name}")
            stats["sources"][source_name] = {"chunks": 0}
            continue

        # Filter out unchanged chunks (skip re-embedding)
        total_before = len(chunks)
        chunks, manifest = _filter_unchanged(chunks, manifest)
        skipped = total_before - len(chunks)
        if skipped > 0:
            logger.info(f"Skipped {skipped}/{total_before} unchanged chunks for {source_name}")
        if not chunks:
            logger.info(f"All {total_before} chunks unchanged for {source_name} — skipping")
            stats["sources"][source_name] = {"chunks": 0, "unchanged": total_before}
            continue

        # Embed
        logger.info(f"Embedding {len(chunks)} chunks for {source_name} ({skipped} unchanged skipped)...")
        try:
            texts = [c["content"] for c in chunks]
            vectors = embedder.embed_documents_batch(texts)
        except Exception as e:
            logger.error(f"Embedding failed for {source_name}: {e}")
            stats["sources"][source_name] = {"error": str(e)}
            continue

        # Add to FAISS
        chunk_ids = [c["chunk_id"] for c in chunks]
        faiss_indexer.add(vectors, chunk_ids)

        # Upsert to Neo4j
        neo4j_count = 0
        if neo4j_loader:
            try:
                neo4j_count = neo4j_loader.upsert_chunks(chunks, client.NODE_LABEL)
            except Exception as e:
                logger.error(f"Neo4j upsert failed for {source_name}: {e}")

        elapsed = time.time() - source_start
        stats["sources"][source_name] = {
            "chunks": len(chunks),
            "neo4j_upserted": neo4j_count,
            "elapsed_seconds": round(elapsed, 1),
        }
        stats["total_chunks"] += len(chunks)
        logger.info(
            f"Ingested {source_name}: {len(chunks)} chunks, "
            f"{neo4j_count} Neo4j nodes, {elapsed:.1f}s"
        )

    # Save FAISS index
    faiss_indexer.save()

    # Save content hash manifest
    _save_manifest(data_dir, manifest)

    # Write last_ingest marker
    _write_last_ingest(data_dir, profile)

    total_elapsed = time.time() - start_time
    stats["total_elapsed_seconds"] = round(total_elapsed, 1)
    stats["faiss_total_vectors"] = faiss_indexer.count()

    logger.info(
        f"Ingestion complete: {stats['total_chunks']} chunks, "
        f"{faiss_indexer.count()} FAISS vectors, {total_elapsed:.1f}s total"
    )

    # Cleanup Neo4j driver
    if neo4j_loader and hasattr(neo4j_loader, "driver"):
        try:
            neo4j_loader.driver.close()
        except Exception:
            pass

    return stats


def print_stats(kb_path: str = None, neo4j_uri: str = None, neo4j_user: str = None, neo4j_password: str = None):
    """Print current KB index statistics."""
    import logging as _logging
    # Suppress noisy neo4j notifications for stats
    _logging.getLogger("neo4j.notifications").setLevel(_logging.WARNING)
    _logging.getLogger("neo4j").setLevel(_logging.WARNING)

    data_dir = Path(kb_path) if kb_path else Path(__file__).parent.parent / "data"

    print(f"\n{'='*50}")
    print("Knowledge Base Statistics")
    print(f"{'='*50}")

    # FAISS stats
    indexer = FAISSIndexer(index_path=str(data_dir))
    loaded = indexer.load()
    print(f"\nFAISS Index: {data_dir}")
    if loaded:
        print(f"  Vectors: {indexer.count()}")
    else:
        print("  Status: No index found")

    # Tolerate a malformed / truncated JSON
    last_ingest_file = data_dir / ".last_ingest"
    if last_ingest_file.exists():
        try:
            info = json.loads(last_ingest_file.read_text())
            print(f"  Last ingest: {info.get('timestamp', 'unknown')}")
            print(f"  Profile: {info.get('profile', 'unknown')}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Last ingest: <unreadable: {e}>")

    # Manifest stats
    manifest_file = data_dir / "cache" / ".manifest.json"
    if manifest_file.exists():
        try:
            manifest = json.loads(manifest_file.read_text())
            print(f"  Manifest entries: {len(manifest)}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Manifest: <unreadable: {e}>")

    # File cache stats
    cache_dir = data_dir / "cache"
    if cache_dir.exists():
        for source_dir in sorted(cache_dir.iterdir()):
            if source_dir.is_dir() and not source_dir.name.startswith("."):
                file_hashes = source_dir / ".file_hashes.json"
                if file_hashes.exists():
                    try:
                        hashes = json.loads(file_hashes.read_text())
                        print(f"  File cache [{source_dir.name}]: {len(hashes)} files")
                    except (json.JSONDecodeError, OSError) as e:
                        print(f"  File cache [{source_dir.name}]: <unreadable: {e}>")

    # Neo4j stats
    neo4j_uri = neo4j_uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
    # No default password fallback. Print clear error if not set.
    neo4j_password = neo4j_password or os.getenv("NEO4J_PASSWORD")
    if not neo4j_password:
        print("\nNeo4j: skipped (NEO4J_PASSWORD not set)")
        print()
        return

    try:
        driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        loader = Neo4jLoader(driver)
        stats = loader.get_stats()
        total = sum(stats.values())
        print(f"\nNeo4j KBChunk nodes: {total}")
        for source, count in sorted(stats.items(), key=lambda x: -x[1]):
            print(f"  {source}: {count}")
        driver.close()
    except Exception as e:
        print(f"\nNeo4j: not available ({e})")

    print(f"\n{'='*50}\n")


def _read_last_ingest(data_dir: Path) -> str | None:
    """Read the last ingestion timestamp."""
    path = data_dir / ".last_ingest"
    if not path.exists():
        return None
    try:
        info = json.loads(path.read_text())
        return info.get("timestamp")
    except Exception:
        return None


def _load_manifest(data_dir: Path) -> dict:
    """
    Load the chunk content hash manifest.

    Returns {chunk_id: content_hash} for all previously ingested chunks.
    """
    path = data_dir / "cache" / ".manifest.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_manifest(data_dir: Path, manifest: dict) -> None:
    """Save the chunk content hash manifest atomically."""
    path = data_dir / "cache" / ".manifest.json"
    atomic_write_json(path, manifest)


def _content_hash(text: str) -> str:
    """SHA256 hash of chunk content (first 16 hex chars)."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _filter_unchanged(chunks: list[dict], manifest: dict) -> tuple[list[dict], dict]:
    """
    Filter out chunks whose content hasn't changed since last ingest.

    Also deduplicates chunks by chunk_id within the incoming batch.
    Neo4j stores chunks via ``MERGE (c:KBChunk {chunk_id: $id})``, 
    which is idempotent: two chunks in the same batch that share a
    chunk_id collapse to a single Neo4j node (with the last writer's
    SET clause winning). FAISS has no such dedup; ``faiss_indexer.add``
    appends every vector unconditionally. Without this pass, every
    within-batch chunk_id collision leaks one extra FAISS vector that
    corresponds to no distinct Neo4j node, and ``FAISS.ntotal`` drifts
    above ``count(:KBChunk)`` by exactly the collision count.

    Upstream sources with observed collisions (as of 2026-04):
      - gtfobins: multiple `sudo` / `suid` exploitation variants listed
        under the same function-type key in a single binary's YAML
        (~11% collision rate).
      - lolbas: multiple commands sharing a category label on one
        binary (~3% rate).
      - exploitdb: the public files_exploits.csv mirror has genuine
        duplicate ``edb_id`` rows (~1% rate).

    This matches Neo4j's MERGE+SET semantics: last occurrence wins,
    earlier duplicates are dropped silently. The output order is stable
    with respect to first-seen position — a dropped duplicate does not
    reorder the chunks that follow it.

    Returns:
        (new_or_changed_chunks, updated_manifest)
    """
    # Within-batch dedup by chunk_id. Keep the *last* occurrence
    # so behavior matches Neo4j MERGE+SET (later writes overwrite earlier
    # ones for the same chunk_id). Stable with repect to first-seen order.
    last_index: dict[str, int] = {}
    for idx, chunk in enumerate(chunks):
        last_index[chunk["chunk_id"]] = idx
    if len(last_index) != len(chunks):
        deduped = [chunks[i] for i in sorted(last_index.values())]
        collisions = len(chunks) - len(deduped)
        logger.warning(
            f"Collapsed {collisions} duplicate chunk_ids within batch "
            f"(would have caused FAISS/Neo4j count drift)"
        )
    else:
        deduped = chunks  # no collisions, avoid the list rebuild

    # Filter against the persisted manifest
    new_chunks = []
    updated = dict(manifest)
    for chunk in deduped:
        cid = chunk["chunk_id"]
        h = _content_hash(chunk["content"])
        if manifest.get(cid) == h:
            continue  # unchanged
        new_chunks.append(chunk)
        updated[cid] = h
    return new_chunks, updated


def _delete_stale_faiss_files(data_dir: Path) -> list[Path]:
    """
    Remove the on-disk FAISS index and chunk_ids mapping.

    Args:
        data_dir: KB data directory containing index.faiss and chunk_ids.json.

    Returns:
        List of paths that were actually deleted (for logging/test assertions).
    """
    deleted = []
    # Wipe integrity manifest (index.faiss.manifest.json) and index on rebuild.
    for stale in (
        data_dir / "index.faiss",
        data_dir / "chunk_ids.json",
        data_dir / "index.faiss.manifest.json",
    ):
        if stale.exists():
            stale.unlink()
            deleted.append(stale)
            logger.info(f"Removed stale FAISS file: {stale}")
    return deleted


def _clear_file_hashes(data_dir: Path) -> None:
    """Remove all .file_hashes.json files from cache subdirectories."""
    cache_dir = data_dir / "cache"
    if not cache_dir.exists():
        return
    for fh in cache_dir.rglob(".file_hashes.json"):
        fh.unlink()
        logger.debug(f"Cleared file hashes: {fh}")


def _write_last_ingest(data_dir: Path, profile: str) -> None:
    """Write the ingestion timestamp marker (atomic)."""
    path = data_dir / ".last_ingest"
    info = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
    }
    atomic_write_json(path, info)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="RedAmon Knowledge Base ingestion pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --profile lite              Build lite KB (tool docs, GTFOBins, OWASP, Nuclei)
  %(prog)s --profile standard          Build standard KB (+ NVD recent CVEs)
  %(prog)s --profile full              Build full KB (+ all NVD + ExploitDB)
  %(prog)s --source nvd --nvd-key KEY  Incremental NVD update
  %(prog)s --source gtfobins           Update GTFOBins only
  %(prog)s --rebuild                   Full rebuild from scratch
  %(prog)s --stats                     Print current index stats
        """,
    )
    parser.add_argument(
        "--profile",
        choices=["cpu-lite", "lite", "standard", "full"],
        default="lite",
        help="Ingestion profile (default: lite)",
    )
    parser.add_argument(
        "--source",
        choices=[
            "tool_docs", "gtfobins", "lolbas",
            "owasp", "nuclei", "nvd", "exploitdb",
        ],
        help="Ingest a single source (overrides --profile)",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Drop existing data and rebuild from scratch",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print index stats and exit",
    )
    parser.add_argument("--nvd-key", help="NVD API key for higher rate limits")
    parser.add_argument(
        "--nvd-days",
        type=int,
        default=None,
        help="NVD lookback window in days for the standard profile (default: 730 = 2 years). "
             "Falls back to NVD_LOOKBACK_DAYS env var if not provided.",
    )
    parser.add_argument("--kb-path", help="Custom path for FAISS index files")
    parser.add_argument(
        "--model",
        default=None,
        help="Embedding model name (default: intfloat/e5-large-v2, use all-MiniLM-L6-v2 for fast local testing)",
    )
    parser.add_argument("--neo4j-uri", help="Neo4j connection URI")
    parser.add_argument("--neo4j-user", help="Neo4j username")
    parser.add_argument("--neo4j-password", help="Neo4j password")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose logging"
    )

    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.stats:
        print_stats(args.kb_path, args.neo4j_uri, args.neo4j_user, args.neo4j_password)
        return

    stats = run_ingestion(
        profile=args.profile,
        source=args.source,
        rebuild=args.rebuild,
        kb_path=args.kb_path,
        nvd_api_key=args.nvd_key,
        nvd_days=args.nvd_days,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        model_name=args.model,
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"Ingestion complete — {stats['total_chunks']} chunks, "
          f"{stats['faiss_total_vectors']} FAISS vectors")
    print(f"Elapsed: {stats['total_elapsed_seconds']}s")
    print(f"{'='*60}")
    for source_name, source_stats in stats.get("sources", {}).items():
        if "error" in source_stats:
            print(f"  {source_name}: ERROR — {source_stats['error']}")
        else:
            print(f"  {source_name}: {source_stats.get('chunks', 0)} chunks")
    print()


if __name__ == "__main__":
    main()
