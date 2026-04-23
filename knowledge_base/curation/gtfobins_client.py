"""
GTFOBins client — downloads and parses privilege escalation data.

Source: https://github.com/GTFOBins/GTFOBins.github.io
Downloads repo tarball and extracts _gtfobins/ files.
Uses file-level hash map to skip re-parsing unchanged files.
"""

import io
import logging
import re
import tarfile
import yaml
from pathlib import Path

from knowledge_base.chunking import ChunkStrategy
from knowledge_base.curation.base_client import BaseClient
from knowledge_base.curation.file_cache import (
    YAMLTooComplexError,
    bounded_tar_iter,
    bounded_yaml_load,
    diff_files,
    load_file_hashes,
    safe_relative_path,
    safe_write_text,
    save_file_hashes,
)
from knowledge_base.curation.safe_http import MAX_TARBALL_BYTES, safe_get

logger = logging.getLogger(__name__)

GTFOBINS_TARBALL_URL = (
    "https://github.com/GTFOBins/GTFOBins.github.io/archive/refs/heads/master.tar.gz"
)


class GTFOBinsClient(BaseClient):
    """Fetches and parses GTFOBins priv-esc data from GitHub."""

    SOURCE = "gtfobins"
    NODE_LABEL = "GTFOBinsChunk"

    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir) if cache_dir else (
            Path(__file__).parent.parent / "data" / "cache" / "gtfobins"
        )

    def fetch(self, **kwargs) -> list[dict]:
        """
        Download GTFOBins repo tarball, diff against file cache, parse changed files.

        Returns list of dicts: [{binary_name, functions: [{type, description, code}]}]
        Only returns entries for new/changed files. Unchanged files are skipped.
        Pass _return_all=True in kwargs to return all entries (for full rebuild).
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        old_hashes = load_file_hashes(self.cache_dir)
        return_all = kwargs.get("_return_all", False)

        # Download tarball (~86KB, single request)
        try:
            logger.info("Downloading GTFOBins repo tarball...")
            resp = safe_get(
                GTFOBINS_TARBALL_URL, timeout=60, max_bytes=MAX_TARBALL_BYTES
            )
            resp.raise_for_status()
            tarball_bytes = resp.content
            logger.info(f"Downloaded {len(tarball_bytes)} bytes")
        except Exception as e:
            logger.error(f"Failed to download GTFOBins tarball: {e}")
            return self._load_all_from_cache() if return_all else []

        # Extract all _gtfobins/ files from tarball
        all_files = {}  # {binary_name: content}
        skipped_unsafe = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
                for member in bounded_tar_iter(tar, label="gtfobins"):
                    if "/_gtfobins/" not in member.name:
                        continue
                    binary_name = Path(member.name).name
                    if binary_name.startswith("."):
                        continue
                    if binary_name.endswith(".md"):
                        binary_name = binary_name[:-3]

                    # Validate the binary_name as a safe relative path against cache_dir
                    safe_dest = safe_relative_path(binary_name, self.cache_dir)
                    if safe_dest is None:
                        skipped_unsafe += 1
                        logger.warning(
                            f"GTFOBins: skipping unsafe tar member {member.name!r} "
                            f"(binary_name={binary_name!r})"
                        )
                        continue

                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8")
                    all_files[binary_name] = content
        except Exception as e:
            logger.error(f"Failed to extract GTFOBins tarball: {e}")
            return self._load_all_from_cache() if return_all else []

        if skipped_unsafe:
            logger.warning(f"GTFOBins: skipped {skipped_unsafe} unsafe tar members")

        # Diff against file cache
        changed_files, updated_hashes = diff_files(all_files, old_hashes)

        # Update cache for changed files (paths re-validated)
        for binary_name, content in changed_files.items():
            safe_dest = safe_relative_path(binary_name, self.cache_dir)
            if safe_dest is None:
                logger.error(f"GTFOBins: refusing to write unsafe cache path {binary_name!r}")
                continue
            safe_write_text(safe_dest, content, encoding="utf-8")

        # Save updated file hashes
        save_file_hashes(self.cache_dir, updated_hashes)

        logger.info(
            f"GTFOBins: {len(all_files)} total, {len(changed_files)} changed, "
            f"{len(all_files) - len(changed_files)} unchanged"
        )

        # Parse only changed files (or all if return_all)
        files_to_parse = all_files if return_all else changed_files
        results = []
        for binary_name, content in files_to_parse.items():
            parsed = self._parse_gtfobins_md(binary_name, content)
            if parsed:
                # Project-relative pointer to the cached MD file
                parsed["source_path"] = f"knowledge_base/data/cache/gtfobins/{binary_name}"
                results.append(parsed)

        logger.info(f"Parsed {len(results)} GTFOBins binaries")
        return results

    def to_chunks(self, raw_data: list[dict]) -> list[dict]:
        """Convert parsed GTFOBins data to chunks. One chunk per binary per function."""
        chunks = []
        for entry in raw_data:
            binary = entry["binary_name"]
            source_path = entry.get("source_path", "")
            for func in entry.get("functions", []):
                func_type = func["type"]
                description = func.get("description", "")
                code = func.get("code", "")
                contexts = func.get("contexts", [])
                comment = func.get("comment", "")

                content = f"{binary} — {func_type}"
                if description:
                    content += f": {description}"
                if contexts:
                    content += f"\nContexts: {', '.join(contexts)}"
                if code:
                    content += f"\nCommand: {code}"
                if comment:
                    content += f"\nNote: {comment}"

                chunk_id = ChunkStrategy.generate_chunk_id(
                    self.SOURCE, f"{binary}:{func_type}"
                )
                chunks.append({
                    "chunk_id": chunk_id,
                    "content": content,
                    "title": f"{binary} — {func_type}",
                    "source": self.SOURCE,
                    "binary_name": binary,
                    "function_type": func_type,
                    "contexts": contexts,
                    "source_path": source_path,
                })

        logger.info(f"Created {len(chunks)} GTFOBins chunks")
        return chunks

    def _parse_gtfobins_md(self, binary_name: str, content: str) -> dict | None:
        """Parse a GTFOBins file with YAML content."""
        # Try YAML document style (--- ... )
        match = re.match(r"^---\s*\n(.*?)\n\.\.\.", content, re.DOTALL)
        if not match:
            match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
        if not match:
            yaml_content = content.strip()
            if yaml_content.startswith("---"):
                yaml_content = yaml_content[3:].strip()
        else:
            yaml_content = match.group(1)

        try:
            frontmatter = bounded_yaml_load(
                yaml_content, label=f"gtfobins:{binary_name}"
            )
        except YAMLTooComplexError as e:
            logger.warning(f"GTFOBins: rejecting hostile YAML for {binary_name}: {e}")
            return None
        except yaml.YAMLError as e:
            logger.warning(f"Failed to parse YAML for {binary_name}: {e}")
            return None

        if not frontmatter or "functions" not in frontmatter:
            return None

        functions = []
        for func_type, func_data_list in frontmatter["functions"].items():
            if func_data_list is None:
                continue
            if not isinstance(func_data_list, list):
                func_data_list = [func_data_list]
            for func_data in func_data_list:
                if isinstance(func_data, dict):
                    code = func_data.get("code", "")
                    description = func_data.get("description", "")
                    comment = func_data.get("comment", "") or ""
                    if isinstance(comment, str):
                        comment = comment.strip()

                    raw_contexts = func_data.get("contexts", {}) or {}
                    contexts: list[str] = []
                    if isinstance(raw_contexts, dict):
                        for k, v in raw_contexts.items():
                            if v is False:
                                continue
                            contexts.append(str(k))
                    elif isinstance(raw_contexts, list):
                        contexts = [str(c) for c in raw_contexts if c]

                    functions.append({
                        "type": func_type,
                        "description": description,
                        "code": code,
                        "contexts": contexts,
                        "comment": comment,
                    })

        return {"binary_name": binary_name, "functions": functions}

    def _load_all_from_cache(self) -> list[dict]:
        """Load all cached files (fallback when download fails)."""
        if not self.cache_dir.exists():
            return []
        results = []
        for cached_file in sorted(self.cache_dir.iterdir()):
            if cached_file.is_dir() or cached_file.name.startswith("."):
                continue
            binary_name = cached_file.name
            if binary_name.endswith(".md"):
                binary_name = binary_name[:-3]
            content = cached_file.read_text(encoding="utf-8")
            parsed = self._parse_gtfobins_md(binary_name, content)
            if parsed:
                parsed["source_path"] = f"knowledge_base/data/cache/gtfobins/{cached_file.name}"
                results.append(parsed)
        logger.info(f"Loaded {len(results)} GTFOBins binaries from cache")
        return results
