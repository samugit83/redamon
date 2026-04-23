"""
Tests for skill_loader.py -- frontmatter parsing, skill discovery,
content loading, and path traversal protection.

Run with: python -m pytest tests/test_skill_loader.py -v
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from skill_loader import _parse_frontmatter, list_skills, load_skill_content, _SKILLS_DIR


class TestParseFrontmatter(unittest.TestCase):
    """Tests for _parse_frontmatter()."""

    def test_valid_frontmatter(self):
        content = "---\nname: SSRF\ndescription: Server-Side Request Forgery\n---\n\n# Body here"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta["name"], "SSRF")
        self.assertEqual(meta["description"], "Server-Side Request Forgery")
        self.assertEqual(body, "# Body here")

    def test_no_frontmatter(self):
        content = "# Just a heading\n\nSome content"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta, {})
        self.assertEqual(body, content)

    def test_empty_content(self):
        meta, body = _parse_frontmatter("")
        self.assertEqual(meta, {})
        self.assertEqual(body, "")

    def test_only_opening_dashes(self):
        content = "---\nname: test\nno closing dashes"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta, {})
        self.assertEqual(body, content)

    def test_colon_in_value(self):
        """The parser uses partition(':') which should handle colons in values."""
        content = "---\nname: SSRF\ndescription: SSRF: Server-Side Request Forgery\n---\n\nBody"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta["name"], "SSRF")
        # partition splits on FIRST colon only
        self.assertEqual(meta["description"], "SSRF: Server-Side Request Forgery")

    def test_empty_frontmatter(self):
        content = "---\n---\n\nBody content"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta, {})
        self.assertEqual(body, "Body content")

    def test_whitespace_in_keys_and_values(self):
        content = "---\n  name  :  ffuf  \n---\nBody"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta["name"], "ffuf")

    def test_line_without_colon_skipped(self):
        content = "---\nname: test\nno-colon-line\ndescription: desc\n---\nBody"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta["name"], "test")
        # "no-colon-line" has a colon in "no-colon-line" actually... let me fix
        # Actually "no-colon-line" DOES have colons (hyphens, not colons). Let me use a real no-colon line.

    def test_line_without_colon_is_skipped(self):
        content = "---\nname: test\njust some text\ndescription: desc\n---\nBody"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta["name"], "test")
        self.assertEqual(meta["description"], "desc")
        self.assertNotIn("just some text", meta)

    def test_multiline_body_preserved(self):
        content = "---\nname: test\n---\nLine 1\nLine 2\nLine 3"
        meta, body = _parse_frontmatter(content)
        self.assertEqual(meta["name"], "test")
        self.assertIn("Line 1", body)
        self.assertIn("Line 3", body)


class TestListSkills(unittest.TestCase):
    """Tests for list_skills() using the real skills directory."""

    def test_returns_list(self):
        skills = list_skills()
        self.assertIsInstance(skills, list)

    def test_skills_have_required_keys(self):
        skills = list_skills()
        if not skills:
            self.skipTest("No skills found in directory")
        for skill in skills:
            self.assertIn("id", skill)
            self.assertIn("name", skill)
            self.assertIn("description", skill)
            self.assertIn("category", skill)
            self.assertIn("file", skill)

    def test_skill_ids_are_slash_separated(self):
        skills = list_skills()
        if not skills:
            self.skipTest("No skills found")
        for skill in skills:
            # IDs should use forward slashes (e.g., "vulnerabilities/ssrf")
            self.assertNotIn("\\", skill["id"])

    def test_categories_are_valid(self):
        valid_categories = {
            "vulnerabilities", "tooling", "scan_modes", "frameworks",
            "technologies", "protocols", "coordination", "general",
            "cloud", "mobile", "api_security", "wireless",
            "network", "active_directory", "social_engineering", "reporting",
        }
        skills = list_skills()
        for skill in skills:
            self.assertIn(skill["category"], valid_categories,
                          f"Unexpected category '{skill['category']}' for skill '{skill['id']}'")

    def test_known_skills_exist(self):
        """Verify the shipped reference skill is discoverable."""
        skills = list_skills()
        skill_ids = {s["id"] for s in skills}
        expected = {"active_directory/ad_kill_chain"}
        for exp in expected:
            self.assertIn(exp, skill_ids, f"Expected skill '{exp}' not found")

    def test_no_duplicate_ids(self):
        skills = list_skills()
        ids = [s["id"] for s in skills]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate skill IDs found")

    def test_skill_count(self):
        skills = list_skills()
        self.assertGreaterEqual(len(skills), 1, "Expected at least 1 shipped skill")


class TestLoadSkillContent(unittest.TestCase):
    """Tests for load_skill_content() including path traversal protection."""

    def test_load_existing_skill(self):
        content = load_skill_content("active_directory/ad_kill_chain")
        self.assertIsNotNone(content)
        self.assertIn("AD", content)

    def test_load_nonexistent_skill(self):
        content = load_skill_content("active_directory/does_not_exist_xyz")
        self.assertIsNone(content)

    def test_path_traversal_blocked(self):
        """Attempting to escape the skills directory should return None."""
        content = load_skill_content("../../etc/passwd")
        self.assertIsNone(content)

    def test_path_traversal_dotdot_in_middle(self):
        content = load_skill_content("active_directory/../../../etc/passwd")
        self.assertIsNone(content)

    def test_absolute_path_blocked(self):
        """Absolute paths should fail (they won't resolve inside _SKILLS_DIR)."""
        content = load_skill_content("/etc/passwd")
        self.assertIsNone(content)

    def test_load_with_forward_slash(self):
        content = load_skill_content("active_directory/ad_kill_chain")
        self.assertIsNotNone(content)
        self.assertIn("kill chain", content.lower())

    def test_empty_skill_id(self):
        content = load_skill_content("")
        self.assertIsNone(content)

    def test_content_is_string(self):
        content = load_skill_content("active_directory/ad_kill_chain")
        if content is not None:
            self.assertIsInstance(content, str)
            self.assertGreater(len(content), 10)


class TestSkillLoaderIntegration(unittest.TestCase):
    """Integration tests: list_skills + load_skill_content work together."""

    def test_all_listed_skills_are_loadable(self):
        """Every skill returned by list_skills() should be loadable."""
        skills = list_skills()
        failures = []
        for skill in skills:
            content = load_skill_content(skill["id"])
            if content is None:
                failures.append(skill["id"])
        self.assertEqual(failures, [], f"These skills failed to load: {failures}")

    def test_frontmatter_name_matches_listed_name(self):
        """Skills with frontmatter should have consistent names."""
        skills = list_skills()
        for skill in skills:
            content = load_skill_content(skill["id"])
            if content and content.startswith("---"):
                meta, _ = _parse_frontmatter(content)
                if meta.get("name"):
                    self.assertEqual(skill["name"], meta["name"],
                                     f"Name mismatch for {skill['id']}")


if __name__ == "__main__":
    unittest.main()
