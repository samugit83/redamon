import hashlib
import hmac
import json
import logging
import os
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

INDEX_MANIFEST_FILENAME = "index.faiss.manifest.json"
_MANIFEST_SCHEMA_VERSION = 1
_HMAC_KEY_ENV = "KB_INDEX_HMAC_KEY"


def _read_faiss_bytes(path: Path) -> bytes:
    """Read the index.faiss file as bytes, chunked to avoid a huge
    single allocation on large indexes."""
    chunks: list[bytes] = []
    with open(path, "rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            chunks.append(block)
    return b"".join(chunks)


def _compute_digest(data: bytes, hmac_key: bytes | None) -> tuple[str, str]:
    """
    Compute ``(algo, hex_digest)`` for ``data``.

    Uses HMAC-SHA256 if ``hmac_key`` is provided, otherwise plain SHA256.
    """
    if hmac_key:
        return ("hmac-sha256", hmac.new(hmac_key, data, hashlib.sha256).hexdigest())
    return ("sha256", hashlib.sha256(data).hexdigest())


def _load_hmac_key() -> bytes | None:
    """Return the HMAC key from ``KB_INDEX_HMAC_KEY`` as bytes, or None."""
    key = os.environ.get(_HMAC_KEY_ENV)
    if not key:
        return None
    return key.encode("utf-8")


class FAISSIndexer:
    """Manages a FAISS flat index: vectors + chunk_id mapping."""

    def __init__(self, index_path: str, dimensions: int = 1024):
        self.index_path = Path(index_path)
        self.dimensions = dimensions
        self.index = None  # faiss.IndexFlatIP — created on first add or load
        self.chunk_ids: list[str] = []  # Parallel: faiss_int_id → chunk_id string

    def _ensure_index(self):
        """Create the FAISS index if it doesn't exist yet."""
        if self.index is None:
            import faiss

            self.index = faiss.IndexFlatIP(self.dimensions)
            logger.debug(f"Created new FAISS IndexFlatIP (dim={self.dimensions})")

    def add(self, vectors: list[list[float]], chunk_ids: list[str]) -> None:
        """
        Add vectors to the index with corresponding chunk_ids.

        Args:
            vectors: List of embedding vectors (must match self.dimensions).
            chunk_ids: Parallel list of chunk_id strings.
        """
        if len(vectors) != len(chunk_ids):
            raise ValueError(
                f"vectors ({len(vectors)}) and chunk_ids ({len(chunk_ids)}) must have same length"
            )
        if not vectors:
            return

        self._ensure_index()

        arr = np.array(vectors, dtype=np.float32)
        if arr.shape[1] != self.dimensions:
            raise ValueError(
                f"Vector dimension {arr.shape[1]} != index dimension {self.dimensions}"
            )

        self.index.add(arr)
        self.chunk_ids.extend(chunk_ids)
        logger.debug(f"Added {len(vectors)} vectors to FAISS index (total: {self.index.ntotal})")

    def search(self, query_vector: list[float], top_k: int = 10) -> list[tuple[str, float]]:
        """
        Search the index for the most similar vectors.

        Args:
            query_vector: Query embedding vector.
            top_k: Number of results to return.

        Returns:
            List of (chunk_id, score) tuples sorted by score descending.
            Returns [] if index is empty or not loaded.
        """
        if self.index is None or self.index.ntotal == 0:
            return []

        arr = np.array([query_vector], dtype=np.float32)
        k = min(top_k, self.index.ntotal)
        scores, indices = self.index.search(arr, k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx == -1:
                continue
            if idx < len(self.chunk_ids):
                results.append((self.chunk_ids[idx], float(score)))

        return results

    def save(self) -> None:
        """
        Persist index and chunk_id mapping to disk atomically.

        Writes go to tempfiles in the same directory and are then
        renamed into place via os.replace(), so a crash mid-save doesn't
        leave a half-written index file. The chunk_ids.json file is also
        written atomically — both files become visible together (or not
        at all).
        """
        if self.index is None:
            logger.warning("No FAISS index to save")
            return

        import os
        import tempfile

        import faiss

        from knowledge_base.atomic_io import atomic_write_json

        self.index_path.mkdir(parents=True, exist_ok=True)

        faiss_path = self.index_path / "index.faiss"
        ids_path = self.index_path / "chunk_ids.json"

        # Atomic FAISS write: write to a sibling tempfile then rename.
        # FAISS only writes via filename (no bytes API), so managing the
        # tempfile here instead of using atomic_write_bytes().
        fd, tmp_name = tempfile.mkstemp(
            prefix=".index.faiss.",
            suffix=".tmp",
            dir=str(self.index_path),
        )
        os.close(fd)
        try:
            faiss.write_index(self.index, tmp_name)
            os.replace(tmp_name, faiss_path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

        # Atomic JSON write for the chunk_id mapping.
        atomic_write_json(ids_path, self.chunk_ids)

        self._write_manifest(faiss_path)

        logger.info(
            f"FAISS index saved: {self.index.ntotal} vectors, "
            f"{len(self.chunk_ids)} chunk_ids → {faiss_path}"
        )

    def _write_manifest(self, faiss_path: Path) -> None:
        """
        Compute and write the integrity manifest for ``faiss_path``.

        Manifest format::

            {
              "schema_version": 1,
              "algo": "hmac-sha256" | "sha256",
              "digest": "<hex>",
              "size": <bytes>
            }
        """
        from knowledge_base.atomic_io import atomic_write_json

        data = _read_faiss_bytes(faiss_path)
        algo, digest = _compute_digest(data, _load_hmac_key())
        manifest = {
            "schema_version": _MANIFEST_SCHEMA_VERSION,
            "algo": algo,
            "digest": digest,
            "size": len(data),
        }
        manifest_path = self.index_path / INDEX_MANIFEST_FILENAME
        atomic_write_json(manifest_path, manifest, indent=2)
        logger.debug(
            f"FAISS manifest written ({algo}, {len(data)} bytes) → {manifest_path}"
        )

    def _verify_manifest(self, faiss_path: Path) -> bool:
        """
        Verify the on-disk FAISS file against its manifest.

        Returns True if the manifest exists and matches the file. 
        Returns False only when a manifest exists but the
        digest does NOT match — that case refuses to load.
        """
        manifest_path = self.index_path / INDEX_MANIFEST_FILENAME
        if not manifest_path.exists():
            logger.warning(
                f"FAISS: no integrity manifest at {manifest_path} — "
                f"loading without verification (will be written on next save). "
                f"Rebuild the index to get integrity protection immediately."
            )
            return True

        try:
            manifest = json.loads(manifest_path.read_text())
        except Exception as e:
            logger.error(
                f"FAISS: manifest at {manifest_path} is unreadable ({e}); "
                f"refusing to load index"
            )
            return False

        expected_algo = manifest.get("algo")
        expected_digest = manifest.get("digest")
        expected_size = manifest.get("size")
        if not expected_algo or not expected_digest:
            logger.error(
                f"FAISS: manifest missing algo/digest fields; refusing to load"
            )
            return False

        data = _read_faiss_bytes(faiss_path)
        if expected_size is not None and len(data) != expected_size:
            logger.error(
                f"FAISS: size mismatch ({len(data)} vs {expected_size}); "
                f"refusing to load"
            )
            return False

        hmac_key = _load_hmac_key()
        if expected_algo == "hmac-sha256":
            if hmac_key is None:
                logger.error(
                    f"FAISS: manifest is HMAC-signed but {_HMAC_KEY_ENV} is not "
                    f"set in the environment; refusing to load"
                )
                return False
            _, actual = _compute_digest(data, hmac_key)
        elif expected_algo == "sha256":
            _, actual = _compute_digest(data, None)
        else:
            logger.error(
                f"FAISS: unknown manifest algo {expected_algo!r}; refusing to load"
            )
            return False

        # hmac.compare_digest is constant-time — use it for both HMAC
        # and plain SHA256 so timing side channels can't be used to
        # probe the digest.
        if not hmac.compare_digest(actual, expected_digest):
            logger.error(
                f"FAISS: integrity check FAILED ({expected_algo}); "
                f"refusing to load {faiss_path}. "
                f"This indicates tampering or corruption."
            )
            return False

        logger.debug(f"FAISS integrity verified ({expected_algo})")
        return True

    def load(self) -> bool:
        """
        Load index and chunk_id mapping from disk.

        Returns:
            True if loaded successfully, False if files not found.
        """
        import faiss

        faiss_path = self.index_path / "index.faiss"
        ids_path = self.index_path / "chunk_ids.json"

        if not faiss_path.exists() or not ids_path.exists():
            logger.info(f"No FAISS index found at {self.index_path} — KB will be in no-op state")
            return False

        # Verify the FAISS file against its manifest before
        # handing the bytes to faiss.read_index(). 
        # Then faiss.read_index()deserializes its input.
        if not self._verify_manifest(faiss_path):
            self.index = None
            self.chunk_ids = []
            return False

        self.index = faiss.read_index(str(faiss_path))

        # Tolerate malformed chunk_ids.json rather than crashing
        # with a raw JSONDecodeError.
        try:
            with open(ids_path) as f:
                self.chunk_ids = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(
                f"FAISS: chunk_ids.json at {ids_path} is unreadable ({e}); "
                f"treating as no-op, rebuild recommended"
            )
            self.index = None
            self.chunk_ids = []
            return False

        if self.index.ntotal != len(self.chunk_ids):
            logger.error(
                f"FAISS/chunk_ids mismatch: {self.index.ntotal} vectors vs "
                f"{len(self.chunk_ids)} chunk_ids — rebuilding recommended"
            )
            self.index = None
            self.chunk_ids = []
            return False

        logger.info(f"FAISS index loaded: {self.index.ntotal} vectors from {faiss_path}")
        return True

    def count(self) -> int:
        """Number of vectors in the index."""
        if self.index is None:
            return 0
        return self.index.ntotal
