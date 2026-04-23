import io
import logging
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

LOLBAS_TARBALL_URL = (
    "https://github.com/LOLBAS-Project/LOLBAS/archive/refs/heads/master.tar.gz"
)


class LOLBASClient(BaseClient):
    """Fetches and parses LOLBAS data from GitHub."""

    SOURCE = "lolbas"
    NODE_LABEL = "LOLBASChunk"

    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir) if cache_dir else (
            Path(__file__).parent.parent / "data" / "cache" / "lolbas"
        )

    def fetch(self, **kwargs) -> list[dict]:
        """
        Download LOLBAS repo tarball, diff against file cache, parse changed files.

        Returns list of dicts: [{name, description, commands: [...]}]
        Only returns entries for new/changed files.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        old_hashes = load_file_hashes(self.cache_dir)
        return_all = kwargs.get("_return_all", False)

        # Download tarball (single request)
        try:
            logger.info("Downloading LOLBAS repo tarball...")
            resp = safe_get(
                LOLBAS_TARBALL_URL, timeout=60, max_bytes=MAX_TARBALL_BYTES
            )
            resp.raise_for_status()
            tarball_bytes = resp.content
            logger.info(f"Downloaded {len(tarball_bytes)} bytes")
        except Exception as e:
            # Network failure: fall back to whatever is already in the cache
            logger.error(f"Failed to download LOLBAS tarball: {e}")
            cached = self._load_all_from_cache()
            if cached:
                logger.warning(
                    f"LOLBAS: download failed — falling back to "
                    f"{len(cached)} cached entries"
                )
                return cached
            logger.error("LOLBAS: no cached data available either — returning empty")
            return []

        # Extract yml/ files from tarball
        all_files = {}  # {safe_relative_path: content}
        skipped_unsafe = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
                for member in bounded_tar_iter(tar, label="lolbas"):
                    if "/yml/" not in member.name:
                        continue
                    if not member.name.endswith((".yml", ".yaml")):
                        continue

                    # Compute the intended relative path
                    parts = member.name.split("/yml/", 1)
                    rel_path = parts[1] if len(parts) == 2 else Path(member.name).name

                    # Validate the relative path against tar slip / path traversal
                    safe_dest = safe_relative_path(rel_path, self.cache_dir)
                    if safe_dest is None:
                        skipped_unsafe += 1
                        logger.warning(
                            f"LOLBAS: skipping unsafe tar member {member.name!r} "
                            f"(rel_path={rel_path!r}) — would escape cache_dir"
                        )
                        continue

                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8")
                    all_files[rel_path] = content
        except Exception as e:
            logger.error(f"Failed to extract LOLBAS tarball: {e}")
            cached = self._load_all_from_cache()
            if cached:
                logger.warning(
                    f"LOLBAS: extraction failed — falling back to "
                    f"{len(cached)} cached entries"
                )
                return cached
            return []

        if skipped_unsafe:
            logger.warning(f"LOLBAS: skipped {skipped_unsafe} unsafe tar members")

        # Diff against file cache
        changed_files, updated_hashes = diff_files(all_files, old_hashes)

        # Update cache for changed files (paths re-validated)
        for rel_path, content in changed_files.items():
            safe_dest = safe_relative_path(rel_path, self.cache_dir)
            if safe_dest is None:
                logger.error(f"LOLBAS: refusing to write unsafe cache path {rel_path!r}")
                continue
            safe_dest.parent.mkdir(parents=True, exist_ok=True)
            safe_write_text(safe_dest, content, encoding="utf-8")

        # Save updated file hashes
        save_file_hashes(self.cache_dir, updated_hashes)

        logger.info(
            f"LOLBAS: {len(all_files)} total, {len(changed_files)} changed, "
            f"{len(all_files) - len(changed_files)} unchanged"
        )

        # Parse only changed files (or all if return_all)
        files_to_parse = all_files if return_all else changed_files
        results = []
        for rel_path, content in files_to_parse.items():
            parsed = self._parse_lolbas_yaml(content)
            if parsed:
                # Project-relative pointer to the cached YAML.
                parsed["source_path"] = f"knowledge_base/data/cache/lolbas/{rel_path}"
                results.append(parsed)

        logger.info(f"Parsed {len(results)} LOLBAS entries")
        return results

    def to_chunks(self, raw_data: list[dict]) -> list[dict]:
        """Convert parsed LOLBAS data to chunks. One chunk per binary per command."""
        chunks = []
        for entry in raw_data:
            name = entry.get("name", "unknown")
            binary_description = entry.get("description", "")
            full_paths = entry.get("full_paths", [])
            source_path = entry.get("source_path", "")

            for cmd in entry.get("commands", []):
                command = cmd.get("command", "")
                description = cmd.get("description", "")
                usecase = cmd.get("usecase", "")
                category = cmd.get("category", "")
                mitre_id = cmd.get("mitre_id", "")
                privileges = cmd.get("privileges", "")
                operating_system = cmd.get("operating_system", "")
                tags = cmd.get("tags", [])

                content = f"{name} — {category}"
                if binary_description:
                    content += f"\n\n{binary_description}"
                if description:
                    content += f"\n\n{description}"
                if command:
                    content += f"\n\nCommand: {command}"
                if usecase:
                    content += f"\nUsecase: {usecase}"
                if privileges:
                    content += f"\nPrivileges: {privileges}"
                if operating_system:
                    content += f"\nOS: {operating_system}"
                if tags:
                    content += f"\nTags: {', '.join(tags)}"
                if mitre_id:
                    content += f"\nMITRE: {mitre_id}"
                if full_paths:
                    content += f"\nFull Path: {'; '.join(full_paths)}"

                chunk_id = ChunkStrategy.generate_chunk_id(
                    self.SOURCE, f"{name}:{category}:{command[:50]}"
                )
                chunks.append({
                    "chunk_id": chunk_id,
                    "content": content,
                    "title": f"{name} — {category}",
                    "source": self.SOURCE,
                    "binary_name": name,
                    "category": category,
                    "mitre_id": mitre_id,
                    "description": description,
                    "binary_description": binary_description,
                    "privileges": privileges,
                    "operating_system": operating_system,
                    "tags": tags,
                    "full_paths": full_paths,
                    "source_path": source_path,
                })

        logger.info(f"Created {len(chunks)} LOLBAS chunks")
        return chunks

    def _parse_lolbas_yaml(self, content: str) -> dict | None:
        """Parse a LOLBAS YAML file."""
        try:
            data = bounded_yaml_load(content, label="lolbas")
        except YAMLTooComplexError as e:
            logger.warning(f"LOLBAS: rejecting hostile YAML: {e}")
            return None
        except yaml.YAMLError as e:
            logger.warning(f"Failed to parse LOLBAS YAML: {e}")
            return None

        if not data or "Name" not in data:
            return None

        full_paths: list[str] = []
        for fp in data.get("Full_Path") or []:
            if isinstance(fp, dict):
                p = fp.get("Path")
                if isinstance(p, str) and p:
                    full_paths.append(p)
            elif isinstance(fp, str):
                full_paths.append(fp)

        commands = []
        for cmd in data.get("Commands", []):
            if not isinstance(cmd, dict):
                continue

            tags_raw = cmd.get("Tags") or []
            tags: list[str] = []
            if isinstance(tags_raw, list):
                for t in tags_raw:
                    if isinstance(t, dict):
                        for k, v in t.items():
                            tags.append(f"{k}: {v}")
                    elif isinstance(t, str):
                        tags.append(t)

            commands.append({
                "command": cmd.get("Command", ""),
                "description": cmd.get("Description", ""),
                "usecase": cmd.get("Usecase", ""),
                "category": cmd.get("Category", ""),
                "mitre_id": cmd.get("MitreID", ""),
                "privileges": cmd.get("Privileges", "") or "",
                "operating_system": cmd.get("OperatingSystem", "") or "",
                "tags": tags,
            })

        return {
            "name": data["Name"],
            "description": data.get("Description", "") or "",
            "full_paths": full_paths,
            "commands": commands,
        }

    def _load_all_from_cache(self) -> list[dict]:
        """Load all cached YAML files (fallback when download fails)."""
        if not self.cache_dir.exists():
            return []
        results = []
        for yml_file in sorted(self.cache_dir.rglob("*.yml")):
            content = yml_file.read_text(encoding="utf-8")
            parsed = self._parse_lolbas_yaml(content)
            if parsed:
                rel = yml_file.relative_to(self.cache_dir).as_posix()
                parsed["source_path"] = f"knowledge_base/data/cache/lolbas/{rel}"
                results.append(parsed)
        for yml_file in sorted(self.cache_dir.rglob("*.yaml")):
            content = yml_file.read_text(encoding="utf-8")
            parsed = self._parse_lolbas_yaml(content)
            if parsed:
                rel = yml_file.relative_to(self.cache_dir).as_posix()
                parsed["source_path"] = f"knowledge_base/data/cache/lolbas/{rel}"
                results.append(parsed)
        logger.info(f"Loaded {len(results)} LOLBAS entries from cache")
        return results
