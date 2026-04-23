import logging
import re
import os
from pathlib import Path

from knowledge_base.chunking import ChunkStrategy
from knowledge_base.curation.base_client import BaseClient
from knowledge_base.document_store import to_source_path

logger = logging.getLogger(__name__)

# Skill subdirectories to ingest and their category labels.
# Keep this list aligned with the actual subdirs under agentic/skills/.
SKILL_CATEGORIES = {
    "tooling": "tool",
    "vulnerabilities": "vulnerability",
    "frameworks": "framework",
    "protocols": "protocol",
    "technologies": "technology",
    "scan_modes": "scan_mode",
    "active_directory": "active_directory",
    "api_security": "api_security",
    "cloud": "cloud",
    "coordination": "coordination",
    "mobile": "mobile",
    "network": "network",
    "reporting": "reporting",
    "social_engineering": "social_engineering",
    "wireless": "wireless",
}

# Files to skip (not useful for KB embedding)
SKIP_FILES = {"root_agent.md"}


class ToolDocsClient(BaseClient):
    """Reads curated skill markdown files from agentic/skills/."""

    SOURCE = "tool_docs"
    NODE_LABEL = "ToolDocChunk"

    def __init__(self, skills_dir: str = None):
        """
        Args:
            skills_dir: Path to the skills/ directory. If not provided, the
                        client checks (in order):
                          1. KB_SKILLS_DIR env var
                          2. /app/skills (Docker flat layout — agentic/ contents
                             are flattened into /app by the Dockerfile COPY)
                          3. /app/agentic/skills (nested Docker layout, if
                             ever introduced)
                          4. <repo>/redamon/agentic/skills (source-tree layout)
                        and uses the first one that exists.
        """

        if skills_dir:
            self.skills_dir = Path(skills_dir)
        else:
            env_dir = os.getenv("KB_SKILLS_DIR")
            candidates = []
            if env_dir:
                candidates.append(Path(env_dir))
            candidates.extend([
                Path("/app/skills"),
                Path("/app/agentic/skills"),
                # Source-tree layout: knowledge_base/curation/ → agentic/skills/
                Path(__file__).parent.parent.parent / "agentic" / "skills",
            ])
            self.skills_dir = next(
                (p for p in candidates if p.exists()), candidates[-1]
            )
        self.chunker = ChunkStrategy()

    def fetch(self, **kwargs) -> list[dict]:
        """
        Read all skill .md files from the skills directory.

        Returns list of dicts: [{filename, category, tool_name, content}]
        """
        results = []
        if not self.skills_dir.exists():
            logger.warning(f"Skills directory not found: {self.skills_dir}")
            return results

        for category_dir_name, category_label in SKILL_CATEGORIES.items():
            category_dir = self.skills_dir / category_dir_name
            if not category_dir.exists():
                continue

            for md_file in sorted(category_dir.glob("*.md")):
                if md_file.name in SKIP_FILES:
                    continue

                content = md_file.read_text(encoding="utf-8")
                if not content.strip():
                    continue

                # Extract name from YAML frontmatter if present
                tool_name = self._extract_name(content, md_file.stem)

                results.append({
                    "filename": md_file.name,
                    "category": category_label,
                    "tool_name": tool_name,
                    "content": content,
                    "subdir": category_dir_name,
                    "source_path": to_source_path(md_file),
                })
                logger.debug(f"Read {category_dir_name}/{md_file.name} ({len(content)} chars)")

        counts = {k: sum(1 for r in results if r["subdir"] == k) for k in SKILL_CATEGORIES}
        counts_str = ", ".join(f"{k}: {v}" for k, v in counts.items() if v > 0)
        logger.info(f"Fetched {len(results)} skill files from {self.skills_dir} ({counts_str})")
        return results

    def to_chunks(self, raw_data: list[dict]) -> list[dict]:
        """
        Chunk each skill file by ## headers.

        Sets tool_name and section on each chunk.

        Special case: skill files under `tooling/` produce a SINGLE slim
        chunk containing only the tool's description, canonical syntax,
        and one example. The full CLI playbook (flags, patterns, recovery
        rules) is not embedded — agents reach for it on demand via
        source_path → document_store.load_document(). This avoids dense
        flag-table noise polluting the embedding space and eliminates
        the awkward "(part N)" artifacts the section chunker produces
        on long single-H1 reference docs.

        Other categories (vulnerabilities/, frameworks/, protocols/,
        technologies/, scan_modes/) keep the section-chunking behavior
        because their content is methodology prose that benefits from
        being indexed in detail.
        """
        all_chunks = []
        for doc in raw_data:
            tool_name = doc["tool_name"]
            category = doc["category"]
            source_path = doc.get("source_path", "")
            subdir = doc.get("subdir", "")

            # Tooling skills: one slim chunk per file. Bypass section chunking.
            if subdir == "tooling":
                chunk = self._make_tooling_summary_chunk(
                    tool_name=tool_name,
                    raw_content=doc["content"],
                    source_path=source_path,
                )
                if chunk:
                    all_chunks.append(chunk)
                continue

            # Strip YAML frontmatter before chunking
            content = self._strip_frontmatter(doc["content"])
            sections = self.chunker.chunk_markdown(content)

            if not sections:
                # Small file — treat as single chunk
                chunk_id = ChunkStrategy.generate_chunk_id(
                    self.SOURCE, f"{tool_name}:full"
                )
                all_chunks.append({
                    "chunk_id": chunk_id,
                    "content": content.strip(),
                    "title": tool_name,
                    "source": self.SOURCE,
                    "tool_name": tool_name,
                    "section": category,
                    "source_path": source_path,
                })
                continue

            for section in sections:
                section_title = section["title"]
                chunk_id = ChunkStrategy.generate_chunk_id(
                    self.SOURCE, f"{tool_name}:{section_title}"
                )

                # Avoid redundancy
                if tool_name.lower() in section_title.lower():
                    title = section_title
                else:
                    title = f"{tool_name} — {section_title}"

                all_chunks.append({
                    "chunk_id": chunk_id,
                    "content": section["content"],
                    "title": title,
                    "source": self.SOURCE,
                    "tool_name": tool_name,
                    "section": section_title,
                    "source_path": source_path,
                })

        logger.info(f"Chunked skill docs into {len(all_chunks)} chunks")
        return all_chunks

    def _extract_name(self, content: str, fallback: str) -> str:
        """Extract name from YAML frontmatter or use filename stem."""
        match = re.search(r"^name:\s*(.+)$", content, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return fallback.replace("_", " ")

    def _strip_frontmatter(self, content: str) -> str:
        """Remove YAML frontmatter (--- delimited) from markdown."""
        if content.startswith("---"):
            end = content.find("---", 3)
            if end != -1:
                return content[end + 3:].strip()
        return content

    def _extract_frontmatter_field(self, content: str, field: str) -> str:
        """
        Pull a single top-level field from a markdown file's YAML frontmatter.

        Naive line-based extraction — not a full YAML parser. Handles the
        common case of `field: value` on a single line. Multi-line values
        and nested fields are not supported (skill files don't use them).
        """
        if not content.startswith("---"):
            return ""
        end = content.find("---", 3)
        if end == -1:
            return ""
        front = content[3:end]
        match = re.search(rf"(?m)^{re.escape(field)}:\s*(.+)$", front)
        if not match:
            return ""
        return match.group(1).strip()

    def _extract_first_backtick_after(self, content: str, anchors: tuple[str, ...]) -> str:
        """
        Find the first inline-code (`...`) string that appears after any
        of the given anchor labels (e.g. 'Canonical syntax:', 'Example:').

        Returns the contents of the first backtick-delimited span on the
        line below the anchor, or empty string if not found.
        """
        for anchor in anchors:
            pattern = rf"{re.escape(anchor)}\s*:?\s*\n?\s*`([^`]+)`"
            match = re.search(pattern, content)
            if match:
                return match.group(1).strip()
        return ""

    def _make_tooling_summary_chunk(
        self,
        tool_name: str,
        raw_content: str,
        source_path: str,
    ) -> dict | None:
        """
        Build a single slim chunk for a tooling/ skill file.

        Composition (in order, only included if extracted):
            {tool_name} — {description from frontmatter}

            Syntax: `<canonical syntax>`

            Example: `<agent-safe baseline command>`

        Roughly 50–100 tokens depending on which parts are present. The
        full CLI playbook is reachable via source_path on the chunk;
        agents call document_store.load_document() to retrieve it.
        """
        description = self._extract_frontmatter_field(raw_content, "description")

        if not description:
            logger.warning(
                f"tooling/{tool_name}: no frontmatter description, "
                f"skipping slim chunk"
            )
            return None

        # Pull canonical syntax
        syntax = self._extract_first_backtick_after(
            raw_content,
            ("Canonical syntax", "Syntax", "Usage"),
        )

        # Pull a representative example command
        example = self._extract_first_backtick_after(
            raw_content,
            (
                "Agent-safe baseline for automation",
                "Agent-safe baseline",
                "Common usage",
                "Example",
            ),
        )

        # Compose the slim content
        parts = [f"{tool_name} — {description}"]
        if syntax:
            parts.append(f"Syntax: `{syntax}`")
        if example:
            parts.append(f"Example: `{example}`")
        content = "\n\n".join(parts)

        chunk_id = ChunkStrategy.generate_chunk_id(
            self.SOURCE, f"{tool_name}:summary"
        )
        return {
            "chunk_id": chunk_id,
            "content": content,
            "title": tool_name,
            "source": self.SOURCE,
            "tool_name": tool_name,
            "section": "summary",
            "source_path": source_path,
        }
