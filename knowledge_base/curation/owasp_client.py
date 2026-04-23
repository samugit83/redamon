import io
import logging
import re
import tarfile
from pathlib import Path

from knowledge_base.chunking import ChunkStrategy
from knowledge_base.curation.base_client import BaseClient
from knowledge_base.curation.file_cache import (
    bounded_tar_iter,
    diff_files,
    load_file_hashes,
    safe_relative_path,
    safe_write_text,
    save_file_hashes,
)
from knowledge_base.curation.safe_http import MAX_TARBALL_BYTES, safe_get

logger = logging.getLogger(__name__)

WSTG_TARBALL_URL = (
    "https://github.com/OWASP/wstg/archive/refs/heads/master.tar.gz"
)

WSTG_TEST_DIR = "document/4-Web_Application_Security_Testing"

CATEGORY_MAP = {
    "01-": "Information Gathering",
    "02-": "Configuration and Deployment Management Testing",
    "03-": "Identity Management Testing",
    "04-": "Authentication Testing",
    "05-": "Authorization Testing",
    "06-": "Session Management Testing",
    "07-": "Input Validation Testing",
    "08-": "Testing for Error Handling",
    "09-": "Testing for Weak Cryptography",
    "10-": "Business Logic Testing",
    "11-": "Client-side Testing",
}


class OWASPClient(BaseClient):
    """Fetches and parses OWASP WSTG test cases from GitHub."""

    SOURCE = "owasp"
    NODE_LABEL = "OWASPChunk"

    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir) if cache_dir else (
            Path(__file__).parent.parent / "data" / "cache" / "owasp"
        )
        self.chunker = ChunkStrategy()

    def fetch(self, **kwargs) -> list[dict]:
        """Download OWASP WSTG repo tarball, diff against file cache, parse changed files.

        Returns list of dicts: [{filename, category, test_id, content}]
        Only returns entries for new/changed files.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        old_hashes = load_file_hashes(self.cache_dir)
        return_all = kwargs.get("_return_all", False)

        # Download tarball (~2MB, single request)
        try:
            logger.info("Downloading OWASP WSTG repo tarball...")
            resp = safe_get(
                WSTG_TARBALL_URL, timeout=60, max_bytes=MAX_TARBALL_BYTES
            )
            resp.raise_for_status()
            tarball_bytes = resp.content
            logger.info(f"Downloaded {len(tarball_bytes)} bytes")
        except Exception as e:
            # Network failure: fall back to whatever is already in the cache
            logger.error(f"Failed to download OWASP WSTG tarball: {e}")
            cached = self._load_all_from_cache()
            if cached:
                logger.warning(
                    f"OWASP: download failed — falling back to "
                    f"{len(cached)} cached entries"
                )
                return cached
            logger.error("OWASP: no cached data available either — returning empty")
            return []

        # Extract test case markdown files from tarball
        all_files = {}
        file_metadata = {}
        skipped_unsafe = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
                for member in bounded_tar_iter(tar, label="owasp-wstg"):
                    if WSTG_TEST_DIR not in member.name:
                        continue
                    if not member.name.endswith(".md"):
                        continue

                    filename = Path(member.name).name
                    if filename == "README.md":
                        continue

                    cat_dir_name = Path(member.name).parent.name
                    if not cat_dir_name or cat_dir_name == "..":
                        continue
                    rel_path = f"{cat_dir_name}/{filename}"

                    # Validate against tar slip / path traversal
                    safe_dest = safe_relative_path(rel_path, self.cache_dir)
                    if safe_dest is None:
                        skipped_unsafe += 1
                        logger.warning(
                            f"OWASP: skipping unsafe tar member {member.name!r} "
                            f"(rel_path={rel_path!r}) — would escape cache_dir"
                        )
                        continue

                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8")

                    all_files[rel_path] = content
                    file_metadata[rel_path] = {
                        "category": self._extract_category(member.name),
                        "filename": filename,
                    }
        except Exception as e:
            logger.error(f"Failed to extract OWASP WSTG tarball: {e}")
            cached = self._load_all_from_cache()
            if cached:
                logger.warning(
                    f"OWASP: extraction failed — falling back to "
                    f"{len(cached)} cached entries"
                )
                return cached
            return []

        if skipped_unsafe:
            logger.warning(f"OWASP: skipped {skipped_unsafe} unsafe tar members")

        # Diff against file cache
        changed_files, updated_hashes = diff_files(all_files, old_hashes)

        # Update cache for changed files (paths re-validated)
        for rel_path, content in changed_files.items():
            safe_dest = safe_relative_path(rel_path, self.cache_dir)
            if safe_dest is None:
                logger.error(f"OWASP: refusing to write unsafe cache path {rel_path!r}")
                continue
            safe_dest.parent.mkdir(parents=True, exist_ok=True)
            safe_write_text(safe_dest, content, encoding="utf-8")

        # Save updated file hashes
        save_file_hashes(self.cache_dir, updated_hashes)

        logger.info(
            f"OWASP: {len(all_files)} total, {len(changed_files)} changed, "
            f"{len(all_files) - len(changed_files)} unchanged"
        )

        # Build results for changed files (or all if return_all)
        files_to_process = all_files if return_all else changed_files
        results = []
        for rel_path, content in files_to_process.items():
            meta = file_metadata.get(rel_path, {})
            test_id = self._extract_test_id(content, rel_path)
            results.append({
                "filename": meta.get("filename", Path(rel_path).name),
                "category": meta.get("category", "Unknown"),
                "test_id": test_id,
                "content": content,
                "source_path": f"knowledge_base/data/cache/owasp/{rel_path}",
            })

        logger.info(f"Returning {len(results)} OWASP test cases for processing")
        return results

    def to_chunks(self, raw_data: list[dict]) -> list[dict]:
        """Chunk OWASP test cases by ## headers."""
        all_chunks = []
        for doc in raw_data:
            sections = self.chunker.chunk_markdown(doc["content"])
            category = doc["category"]
            test_id = doc.get("test_id", "")
            source_path = doc.get("source_path", "")

            for section in sections:
                section_title = section["title"]
                unique_key = f"{test_id or doc['filename']}:{section_title}"
                chunk_id = ChunkStrategy.generate_chunk_id(self.SOURCE, unique_key)

                title = section_title
                if test_id:
                    title = f"OWASP {test_id}: {title}"

                all_chunks.append({
                    "chunk_id": chunk_id,
                    "content": section["content"],
                    "title": title,
                    "source": self.SOURCE,
                    "test_id": test_id,
                    "category": category,
                    "section": section_title,
                    "source_path": source_path,
                })

        logger.info(f"Chunked OWASP docs into {len(all_chunks)} chunks")
        return all_chunks

    def _extract_category(self, tar_path: str) -> str:
        """Extract human-readable category from tarball path."""
        for prefix, name in CATEGORY_MAP.items():
            if prefix in tar_path:
                return name
        return "Unknown"

    def _extract_test_id(self, content: str, filename: str) -> str:
        """Extract WSTG test ID from content."""
        match = re.search(r"WSTG-[A-Z]+-\d+", content)
        if match:
            return match.group(0)
        return ""

    def _load_all_from_cache(self) -> list[dict]:
        """Load all cached markdown files (fallback when download fails)."""
        if not self.cache_dir.exists():
            return []
        results = []
        for cat_dir in sorted(self.cache_dir.iterdir()):
            if not cat_dir.is_dir() or cat_dir.name.startswith("."):
                continue
            category = "Unknown"
            for prefix, name in CATEGORY_MAP.items():
                if cat_dir.name.startswith(prefix):
                    category = name
                    break
            for md_file in sorted(cat_dir.glob("*.md")):
                if md_file.name == "README.md":
                    continue
                content = md_file.read_text(encoding="utf-8")
                test_id = self._extract_test_id(content, md_file.name)
                rel = md_file.relative_to(self.cache_dir).as_posix()
                results.append({
                    "filename": md_file.name,
                    "category": category,
                    "test_id": test_id,
                    "content": content,
                    "source_path": f"knowledge_base/data/cache/owasp/{rel}",
                })
        logger.info(f"Loaded {len(results)} OWASP test cases from cache")
        return results
