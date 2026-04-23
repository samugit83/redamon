import json
from pathlib import Path

import pytest

from knowledge_base.curation.data_ingestion import (
    _clear_file_hashes,
    _content_hash,
    _delete_stale_faiss_files,
    _filter_unchanged,
    _load_manifest,
    _save_manifest,
    _read_last_ingest,
    _write_last_ingest,
)


# =============================================================================
# _delete_stale_faiss_files 
# =============================================================================

class TestDeleteStaleFaissFiles:
    """Ensure helper removes both index.faiss and chunk_ids.json 
    from the data dir."""

    def test_deletes_index_and_chunk_ids(self, tmp_path):
        # Pre-create both files with arbitrary content
        index_file = tmp_path / "index.faiss"
        ids_file = tmp_path / "chunk_ids.json"
        index_file.write_bytes(b"stale faiss bytes")
        ids_file.write_text(json.dumps(["stale", "ids"]))

        deleted = _delete_stale_faiss_files(tmp_path)

        assert not index_file.exists(), "index.faiss must be deleted"
        assert not ids_file.exists(), "chunk_ids.json must be deleted"
        assert set(deleted) == {index_file, ids_file}

    def test_idempotent_when_files_missing(self, tmp_path):
        # No files to start with
        deleted = _delete_stale_faiss_files(tmp_path)
        assert deleted == []

    def test_only_deletes_one_when_other_missing(self, tmp_path):
        # Only the index file exists; chunk_ids.json missing
        index_file = tmp_path / "index.faiss"
        index_file.write_bytes(b"stale")
        ids_file = tmp_path / "chunk_ids.json"
        assert not ids_file.exists()

        deleted = _delete_stale_faiss_files(tmp_path)

        assert not index_file.exists()
        assert deleted == [index_file]

    def test_does_not_touch_other_files(self, tmp_path):
        """Helper must NOT delete unrelated files in the data dir."""
        (tmp_path / "index.faiss").write_bytes(b"stale")
        (tmp_path / "chunk_ids.json").write_text("[]")
        # Other files that should survive — picked as an arbitrary
        # unrelated file, not tied to any specific KB source.
        (tmp_path / "cache").mkdir()
        (tmp_path / ".last_ingest").write_text("{}")
        (tmp_path / "cache" / ".manifest.json").write_text("{}")
        (tmp_path / "sources").mkdir()
        (tmp_path / "sources" / "notes.md").write_text("# notes")

        _delete_stale_faiss_files(tmp_path)

        # FAISS files gone
        assert not (tmp_path / "index.faiss").exists()
        assert not (tmp_path / "chunk_ids.json").exists()
        # Everything else intact
        assert (tmp_path / "cache").exists()
        assert (tmp_path / ".last_ingest").exists()
        assert (tmp_path / "cache" / ".manifest.json").exists()
        assert (tmp_path / "sources" / "notes.md").exists()


# =============================================================================
# Manifest read/write (atomic, Sec #9)
# =============================================================================

class TestManifest:

    def test_save_and_load_roundtrip(self, tmp_path):
        manifest = {"chunk_a": "hash1", "chunk_b": "hash2"}
        _save_manifest(tmp_path, manifest)
        loaded = _load_manifest(tmp_path)
        assert loaded == manifest

    def test_load_missing_returns_empty(self, tmp_path):
        assert _load_manifest(tmp_path) == {}

    def test_load_corrupted_returns_empty(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        (cache_dir / ".manifest.json").write_text("not json{{{")
        assert _load_manifest(tmp_path) == {}

    def test_save_creates_cache_dir(self, tmp_path):
        # data_dir starts empty
        _save_manifest(tmp_path, {"a": "b"})
        assert (tmp_path / "cache" / ".manifest.json").exists()

    def test_save_is_valid_json(self, tmp_path):
        _save_manifest(tmp_path, {"x": "y"})
        raw = (tmp_path / "cache" / ".manifest.json").read_text()
        parsed = json.loads(raw)
        assert parsed == {"x": "y"}


# =============================================================================
# _content_hash
# =============================================================================

class TestContentHash:

    def test_deterministic(self):
        assert _content_hash("hello") == _content_hash("hello")

    def test_different_content(self):
        assert _content_hash("a") != _content_hash("b")

    def test_length(self):
        assert len(_content_hash("anything")) == 16


# =============================================================================
# _filter_unchanged — chunk-level dedup
# =============================================================================

class TestFilterUnchanged:

    def test_all_new_when_no_manifest(self):
        chunks = [
            {"chunk_id": "a", "content": "alpha"},
            {"chunk_id": "b", "content": "beta"},
        ]
        new_chunks, updated = _filter_unchanged(chunks, {})
        assert len(new_chunks) == 2
        assert "a" in updated
        assert "b" in updated

    def test_all_unchanged_when_hashes_match(self):
        chunks = [
            {"chunk_id": "a", "content": "alpha"},
            {"chunk_id": "b", "content": "beta"},
        ]
        manifest = {
            "a": _content_hash("alpha"),
            "b": _content_hash("beta"),
        }
        new_chunks, updated = _filter_unchanged(chunks, manifest)
        assert new_chunks == []
        assert updated == manifest

    def test_modified_chunk_returned(self):
        chunks = [
            {"chunk_id": "a", "content": "alpha"},
            {"chunk_id": "b", "content": "MODIFIED"},
        ]
        manifest = {
            "a": _content_hash("alpha"),
            "b": _content_hash("beta"),
        }
        new_chunks, updated = _filter_unchanged(chunks, manifest)
        assert len(new_chunks) == 1
        assert new_chunks[0]["chunk_id"] == "b"
        assert updated["b"] == _content_hash("MODIFIED")
        # Unchanged chunk hash preserved
        assert updated["a"] == _content_hash("alpha")

    def test_within_batch_dedup_keeps_last(self):
        chunks = [
            {"chunk_id": "dup", "content": "first"},
            {"chunk_id": "dup", "content": "last"},
            {"chunk_id": "other", "content": "x"},
        ]
        new_chunks, updated = _filter_unchanged(chunks, {})
        # Two unique chunk_ids survive
        assert len(new_chunks) == 2
        # Last occurrence of the duplicated chunk_id wins
        assert any(c["content"] == "last" for c in new_chunks)
        assert not any(c["content"] == "first" for c in new_chunks)
        # Manifest reflects the surviving (last) content hash
        assert updated["dup"] == _content_hash("last")
        assert updated["other"] == _content_hash("x")

    def test_within_batch_dedup_preserves_emission_order(self):
        """Dedup must be stable: the output order of *surviving* chunks
        must match the order in which their chunk_ids were first seen."""
        chunks = [
            {"chunk_id": "a", "content": "alpha"},
            {"chunk_id": "b", "content": "beta-1"},   # will be dropped
            {"chunk_id": "c", "content": "gamma"},
            {"chunk_id": "b", "content": "beta-2"},   # wins on chunk_id b
        ]
        new_chunks, _ = _filter_unchanged(chunks, {})
        # Expect order [a, c, b] — "b" keeps its first-seen position even
        # though the winning row was emitted later in the input.
        ids = [c["chunk_id"] for c in new_chunks]
        assert ids == ["a", "c", "b"], (
            f"dedup should preserve first-seen position order, got {ids}"
        )
        # And the surviving b has the *last* content
        b_chunk = next(c for c in new_chunks if c["chunk_id"] == "b")
        assert b_chunk["content"] == "beta-2"

    def test_within_batch_dedup_with_existing_manifest(self):
        """Dedup pass 1 runs BEFORE the manifest filter, so a duplicate
        chunk_id whose LAST-wins content happens to match the manifest
        should be correctly dropped as unchanged."""
        chunks = [
            {"chunk_id": "dup", "content": "first-version"},
            {"chunk_id": "dup", "content": "cached-version"},
        ]
        manifest = {"dup": _content_hash("cached-version")}
        new_chunks, updated = _filter_unchanged(chunks, manifest)
        # The last-wins version matches the manifest → filtered out
        assert new_chunks == []
        assert updated == manifest

    def test_no_collisions_no_rebuild(self):
        """Fast path: a collision-free batch should not trigger the
        list rebuild (regression guard on the len() optimisation)."""
        chunks = [
            {"chunk_id": "a", "content": "x"},
            {"chunk_id": "b", "content": "y"},
            {"chunk_id": "c", "content": "z"},
        ]
        new_chunks, _ = _filter_unchanged(chunks, {})
        assert len(new_chunks) == 3
        assert [c["chunk_id"] for c in new_chunks] == ["a", "b", "c"]


# =============================================================================
# _clear_file_hashes — clears per-source hash files on rebuild
# =============================================================================

class TestClearFileHashes:

    def test_clears_all_hash_files(self, tmp_path):
        # Set up cache subdirectories with hash files
        for src in ("gtfobins", "lolbas", "owasp"):
            sub = tmp_path / "cache" / src
            sub.mkdir(parents=True)
            (sub / ".file_hashes.json").write_text("{}")
            # Also some normal cached files that should NOT be deleted
            (sub / "some_file.md").write_text("data")

        _clear_file_hashes(tmp_path)

        # All hash files removed
        for src in ("gtfobins", "lolbas", "owasp"):
            assert not (tmp_path / "cache" / src / ".file_hashes.json").exists()
            # But the actual cached data is still there
            assert (tmp_path / "cache" / src / "some_file.md").exists()

    def test_no_cache_dir_is_noop(self, tmp_path):
        # Should not raise even if cache/ doesn't exist
        _clear_file_hashes(tmp_path)


# =============================================================================
# Last-ingest marker
# =============================================================================

class TestLastIngest:

    def test_write_and_read_roundtrip(self, tmp_path):
        _write_last_ingest(tmp_path, "lite")
        timestamp = _read_last_ingest(tmp_path)
        assert timestamp is not None
        assert "T" in timestamp  # ISO 8601 format

    def test_read_missing_returns_none(self, tmp_path):
        assert _read_last_ingest(tmp_path) is None
