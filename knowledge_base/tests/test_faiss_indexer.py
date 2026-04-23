import json
import pytest
import numpy as np


@pytest.fixture
def index_path(tmp_path):
    return str(tmp_path / "test_kb")


@pytest.fixture
def indexer(index_path):
    from knowledge_base.faiss_indexer import FAISSIndexer
    return FAISSIndexer(index_path=index_path, dimensions=4)


def _random_vectors(n, dim=4):
    """Generate random normalized vectors."""
    vecs = np.random.randn(n, dim).astype(np.float32)
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    return (vecs / norms).tolist()


class TestFAISSIndexer:

    def test_add_and_search_roundtrip(self, indexer):
        vecs = _random_vectors(5)
        ids = ["chunk_a", "chunk_b", "chunk_c", "chunk_d", "chunk_e"]
        indexer.add(vecs, ids)

        results = indexer.search(vecs[0], top_k=3)
        assert len(results) == 3
        # First result should be the query vector itself (highest similarity)
        assert results[0][0] == "chunk_a"
        assert results[0][1] > 0.99  # cosine sim with itself ≈ 1.0

    def test_search_returns_chunk_ids_and_scores(self, indexer):
        vecs = _random_vectors(3)
        ids = ["a", "b", "c"]
        indexer.add(vecs, ids)

        results = indexer.search(vecs[1], top_k=2)
        assert len(results) == 2
        for chunk_id, score in results:
            assert isinstance(chunk_id, str)
            assert isinstance(score, float)

    def test_score_ordering(self, indexer):
        vecs = _random_vectors(10)
        ids = [f"chunk_{i}" for i in range(10)]
        indexer.add(vecs, ids)

        results = indexer.search(vecs[0], top_k=10)
        scores = [s for _, s in results]
        assert scores == sorted(scores, reverse=True)

    def test_empty_index_returns_empty(self, indexer):
        results = indexer.search([0.1, 0.2, 0.3, 0.4], top_k=5)
        assert results == []

    def test_count(self, indexer):
        assert indexer.count() == 0
        vecs = _random_vectors(3)
        indexer.add(vecs, ["a", "b", "c"])
        assert indexer.count() == 3

    def test_incremental_add(self, indexer):
        vecs1 = _random_vectors(3)
        indexer.add(vecs1, ["a", "b", "c"])
        assert indexer.count() == 3

        vecs2 = _random_vectors(2)
        indexer.add(vecs2, ["d", "e"])
        assert indexer.count() == 5

        results = indexer.search(vecs2[0], top_k=5)
        found_ids = {cid for cid, _ in results}
        assert "d" in found_ids

    def test_save_and_load(self, indexer, index_path):
        from knowledge_base.faiss_indexer import FAISSIndexer

        vecs = _random_vectors(5)
        ids = ["a", "b", "c", "d", "e"]
        indexer.add(vecs, ids)
        indexer.save()

        # Load into a new instance
        new_indexer = FAISSIndexer(index_path=index_path, dimensions=4)
        loaded = new_indexer.load()
        assert loaded is True
        assert new_indexer.count() == 5

        results = new_indexer.search(vecs[2], top_k=1)
        assert results[0][0] == "c"

    def test_load_missing_files(self, index_path):
        from knowledge_base.faiss_indexer import FAISSIndexer

        indexer = FAISSIndexer(index_path=index_path, dimensions=4)
        loaded = indexer.load()
        assert loaded is False
        assert indexer.count() == 0

    def test_mismatched_vectors_and_ids_raises(self, indexer):
        vecs = _random_vectors(3)
        with pytest.raises(ValueError, match="same length"):
            indexer.add(vecs, ["a", "b"])

    def test_wrong_dimensions_raises(self, indexer):
        vecs = [[0.1, 0.2]]  # dim=2, but indexer expects dim=4
        with pytest.raises(ValueError, match="dimension"):
            indexer.add(vecs, ["a"])

    def test_top_k_larger_than_index(self, indexer):
        vecs = _random_vectors(2)
        indexer.add(vecs, ["a", "b"])
        results = indexer.search(vecs[0], top_k=100)
        assert len(results) == 2


# =============================================================================
# Integrity manifest
# =============================================================================

class TestFaissIntegrityManifest:

    def test_save_writes_manifest(self, index_path):
        """After save(), a manifest file with algo + digest + size
        must exist alongside the index."""
        from knowledge_base.faiss_indexer import (
            FAISSIndexer,
            INDEX_MANIFEST_FILENAME,
        )
        idx = FAISSIndexer(index_path=index_path, dimensions=4)
        idx.add(_random_vectors(3), ["a", "b", "c"])
        idx.save()

        from pathlib import Path as _P
        manifest_path = _P(index_path) / INDEX_MANIFEST_FILENAME
        assert manifest_path.exists(), "integrity manifest not written"

        manifest = json.loads(manifest_path.read_text())
        assert manifest["schema_version"] == 1
        assert manifest["algo"] in ("sha256", "hmac-sha256")
        assert isinstance(manifest["digest"], str)
        assert len(manifest["digest"]) == 64  # SHA-256 hex
        assert manifest["size"] > 0

    def test_load_refuses_when_digest_mismatches(self, index_path, caplog):
        """Tamper with index.faiss after save — load() must refuse,
        log the mismatch, and return False (no index loaded)."""
        from knowledge_base.faiss_indexer import FAISSIndexer
        idx = FAISSIndexer(index_path=index_path, dimensions=4)
        idx.add(_random_vectors(3), ["a", "b", "c"])
        idx.save()

        # Flip a single byte in the middle of index.faiss to simulate
        # tampering. The manifest was written for the ORIGINAL bytes,
        # so the recomputed digest won't match.
        from pathlib import Path as _P
        faiss_file = _P(index_path) / "index.faiss"
        data = bytearray(faiss_file.read_bytes())
        # Flip a byte 64 bytes in (past any header), XOR is reversible
        # but we'll just re-write the file.
        data[64] ^= 0xFF
        faiss_file.write_bytes(bytes(data))

        idx2 = FAISSIndexer(index_path=index_path, dimensions=4)
        with caplog.at_level("ERROR"):
            loaded = idx2.load()

        assert loaded is False, "load should refuse a tampered index"
        assert idx2.index is None
        assert idx2.chunk_ids == []
        assert any(
            "integrity check FAILED" in rec.message or "size mismatch" in rec.message
            for rec in caplog.records
        )

    def test_load_refuses_when_size_mismatches(self, index_path, caplog):
        """Truncating the index file is an even cruder tamper — the
        size check trips before the digest check."""
        from knowledge_base.faiss_indexer import FAISSIndexer
        idx = FAISSIndexer(index_path=index_path, dimensions=4)
        idx.add(_random_vectors(3), ["a", "b", "c"])
        idx.save()

        from pathlib import Path as _P
        faiss_file = _P(index_path) / "index.faiss"
        data = faiss_file.read_bytes()
        faiss_file.write_bytes(data[: len(data) // 2])  # truncate

        idx2 = FAISSIndexer(index_path=index_path, dimensions=4)
        with caplog.at_level("ERROR"):
            loaded = idx2.load()

        assert loaded is False
        assert any(
            "size mismatch" in rec.message or "integrity check FAILED" in rec.message
            for rec in caplog.records
        )

    def test_load_succeeds_on_untampered_index(self, index_path):
        """Roundtrip: save + load with no tampering should succeed
        and return the same chunk_ids."""
        from knowledge_base.faiss_indexer import FAISSIndexer
        idx = FAISSIndexer(index_path=index_path, dimensions=4)
        idx.add(_random_vectors(3), ["a", "b", "c"])
        idx.save()

        idx2 = FAISSIndexer(index_path=index_path, dimensions=4)
        assert idx2.load() is True
        assert idx2.chunk_ids == ["a", "b", "c"]
        assert idx2.count() == 3

    def test_load_warns_but_allows_missing_manifest(self, index_path, caplog):
        """Backwards-compat: an index written by the pre-#1 version
        has no manifest. load() should log a WARNING (so operators
        notice) and proceed — the next save() writes a manifest."""
        from knowledge_base.faiss_indexer import (
            FAISSIndexer,
            INDEX_MANIFEST_FILENAME,
        )
        idx = FAISSIndexer(index_path=index_path, dimensions=4)
        idx.add(_random_vectors(3), ["a", "b", "c"])
        idx.save()

        # Delete the manifest to simulate a pre-upgrade index on disk
        from pathlib import Path as _P
        (_P(index_path) / INDEX_MANIFEST_FILENAME).unlink()

        idx2 = FAISSIndexer(index_path=index_path, dimensions=4)
        with caplog.at_level("WARNING"):
            loaded = idx2.load()

        assert loaded is True  # compat: loads without verification
        assert idx2.count() == 3
        assert any(
            "no integrity manifest" in rec.message
            for rec in caplog.records
        )

    def test_hmac_key_produces_hmac_manifest(self, index_path, monkeypatch):
        """With KB_INDEX_HMAC_KEY set, the manifest uses HMAC-SHA256
        and the digest depends on the key."""
        from knowledge_base.faiss_indexer import (
            FAISSIndexer,
            INDEX_MANIFEST_FILENAME,
        )

        monkeypatch.setenv("KB_INDEX_HMAC_KEY", "super-secret-build-key")

        idx = FAISSIndexer(index_path=index_path, dimensions=4)
        idx.add(_random_vectors(3), ["a", "b", "c"])
        idx.save()

        from pathlib import Path as _P
        manifest = json.loads(
            (_P(index_path) / INDEX_MANIFEST_FILENAME).read_text()
        )
        assert manifest["algo"] == "hmac-sha256"
        hmac_digest = manifest["digest"]

        # Re-save with a DIFFERENT key → different digest
        monkeypatch.setenv("KB_INDEX_HMAC_KEY", "a-different-key")
        idx.save()
        manifest2 = json.loads(
            (_P(index_path) / INDEX_MANIFEST_FILENAME).read_text()
        )
        assert manifest2["algo"] == "hmac-sha256"
        assert manifest2["digest"] != hmac_digest, (
            "HMAC digest must depend on the key"
        )

    def test_hmac_load_refuses_when_key_missing(self, index_path, monkeypatch, caplog):
        """Save with an HMAC key, then try to load WITHOUT the key
        in the env. load() must refuse rather than silently falling
        back to a weaker check."""
        from knowledge_base.faiss_indexer import FAISSIndexer

        monkeypatch.setenv("KB_INDEX_HMAC_KEY", "key-used-for-save")
        idx = FAISSIndexer(index_path=index_path, dimensions=4)
        idx.add(_random_vectors(3), ["a", "b", "c"])
        idx.save()

        # Simulate a loader that doesn't know the key
        monkeypatch.delenv("KB_INDEX_HMAC_KEY", raising=False)
        idx2 = FAISSIndexer(index_path=index_path, dimensions=4)
        with caplog.at_level("ERROR"):
            loaded = idx2.load()

        assert loaded is False
        assert any(
            "HMAC-signed" in rec.message and "not set" in rec.message
            for rec in caplog.records
        )
