"""
Infosec-skills-compatible Skill Loader
==============================
Discovers and loads skill markdown files from agentic/skills/.

Skills are markdown files with YAML frontmatter:
  ---
  name: <skill-name>
  description: <one-line description>
  ---

Up to 5 skills can be injected into the agent system prompt per session.
"""

import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Root directory of all skill files (relative to this file)
_SKILLS_DIR = Path(__file__).parent / "skills"

# Maximum skills injected per session (matching Infosec-skills convention)
MAX_SKILLS = 5


def _parse_frontmatter(content: str) -> tuple[dict, str]:
    """
    Parse YAML frontmatter from markdown content.
    Returns (metadata_dict, body_without_frontmatter).
    """
    if not content.startswith("---"):
        return {}, content

    end = content.find("---", 3)
    if end == -1:
        return {}, content

    frontmatter = content[3:end].strip()
    body = content[end + 3:].strip()

    meta: dict = {}
    for line in frontmatter.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()

    return meta, body


def list_skills() -> list[dict]:
    """
    Discover all skill files and return their metadata catalog.

    Returns a list of dicts with keys:
      - id:          unique skill identifier (e.g. "vulnerabilities/ssrf")
      - name:        human-readable name from frontmatter
      - description: one-line description from frontmatter
      - category:    top-level directory name (e.g. "vulnerabilities")
      - file:        absolute path to the .md file
    """
    skills: list[dict] = []

    if not _SKILLS_DIR.exists():
        logger.warning(f"Skills directory not found: {_SKILLS_DIR}")
        return skills

    for md_file in sorted(_SKILLS_DIR.rglob("*.md")):
        # Build a stable ID from the relative path without extension
        rel = md_file.relative_to(_SKILLS_DIR)
        skill_id = str(rel.with_suffix("")).replace(os.sep, "/")

        try:
            content = md_file.read_text(encoding="utf-8")
            meta, _ = _parse_frontmatter(content)
        except Exception as exc:
            logger.warning(f"Failed to parse skill file {md_file}: {exc}")
            continue

        category = rel.parts[0] if len(rel.parts) > 1 else "general"

        skills.append({
            "id": skill_id,
            "name": meta.get("name") or md_file.stem.replace("_", " ").title(),
            "description": meta.get("description", ""),
            "category": category,
            "file": str(md_file),
        })

    return skills


def load_skill_content(skill_id: str) -> Optional[str]:
    """
    Load the full markdown content of a skill by its ID.
    Returns the content string or None if not found.
    """
    # Normalize separators
    normalized = skill_id.replace("/", os.sep).replace("\\", os.sep)
    skill_path = _SKILLS_DIR / (normalized + ".md")

    # Security: prevent path traversal outside skills directory
    if not skill_path.resolve().is_relative_to(_SKILLS_DIR.resolve()):
        logger.warning(f"Path traversal attempt blocked: {skill_id}")
        return None

    if not skill_path.exists():
        logger.warning(f"Skill not found: {skill_id} (looked at {skill_path})")
        return None

    try:
        return skill_path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.error(f"Failed to read skill {skill_id}: {exc}")
        return None

