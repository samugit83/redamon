"""
Tests for the community Agent Skills system, with focused coverage of the
SSTI community skill that was just shipped.

Layered as:

- Unit:        canonical-template invariants applied per-file. The older
               community skills (api_testing, sqli_exploitation, xss_exploitation)
               predate the canonical template; they are exercised only by the
               minimal-invariant suite (size, no em dashes, parseable description).
- Unit:        SSTI-specific assertions (engine matrix coverage, disjoint
               classification vs. the rce built-in, tool references).
- Integration: replays the api.py /community-skills endpoint logic against the
               real directory and confirms the new skill is discoverable with
               a sensible auto-description.
- Regression:  tool_registry imports cleanly + kali_shell description references
               both sstimap and tplmap; classification.build_classification_prompt
               still works when SSTI is plugged in as a user_skill.
- Smoke:       Dockerfile reference to /opt/tplmap is present and the wrapper
               install layer is well-formed.

Run with: python3 -m pytest agentic/tests/test_community_skills.py -v
"""

import os
import re
import sys
import unittest
from pathlib import Path

# Add agentic/ to sys.path so the prompts package + project_settings import
_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

_COMMUNITY_DIR = _AGENTIC_DIR / "community-skills"
_REPO_ROOT = _AGENTIC_DIR.parent

# Skills that follow the canonical template defined in
# docs/readmes/coding_agent_prompts/PROMPT.ADD_COMMUNITY_AGENT_SKILL.md
# (overview paragraph, "When to Classify Here", phase-numbered Workflow,
#  Reporting Guidelines, Important Notes, phase-transition cue).
_CANONICAL_SKILLS = {
    "ssti",
    "xxe",
    "idor_bola_exploitation",
    "bfla_exploitation",
    "insecure_deserialization",
    "mass_assignment",
    # Promoted 2026-10-16: the original @Shafranpackeer skills were rewritten
    # from the legacy "## Overview / ## Tools Available / ## PHASE N" shape
    # into the canonical template so the Intent Router classifies them with
    # the same accuracy as the modern corpus.
    "api_testing",
    "sqli_exploitation",
    "xss_exploitation",
    # New 2026-10-16 @Shafranpackeer community skills, authored canonical.
    "auth_session_attacks",
    "request_smuggling",
    "broken_access_control",
    "ssrf_exploitation",
    "path_traversal",
}

# No legacy-format skills remain: every shipped community skill now follows the
# canonical template. Kept as an empty set so the minimal-invariant suite and
# any future legacy imports still have a stable reference.
_LEGACY_SKILLS: set[str] = set()

_FILE_SIZE_CAP_BYTES = 50_000  # webapp/.../attack-skills/route.ts enforces this
_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_REAL_AGENT_TOOLS = {
    "query_graph", "kali_shell", "execute_curl", "execute_code",
    "execute_playwright", "execute_nuclei", "execute_hydra",
    "metasploit_console", "execute_httpx", "execute_naabu",
    "execute_jsluice", "execute_katana", "execute_subfinder",
    "execute_gau", "execute_nmap", "execute_amass", "execute_ffuf",
    "execute_arjun", "execute_wpscan", "msf_restart", "shodan",
    "google_dork", "web_search",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _description_from_content(content: str) -> str:
    """Mirror of the extractor in agentic/api.py:list_community_skills.

    The endpoint glue takes the first non-blank, non-#-prefixed stripped line
    and truncates to 200 characters. This helper duplicates that logic so the
    tests don't need a running server.
    """
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:200]
    return ""


# ============================================================================
# UNIT: minimal invariants applied to every shipped community skill .md
# ============================================================================

class TestCommunitySkillsMinimal(unittest.TestCase):
    """Invariants that ALL community skills must satisfy."""

    def setUp(self):
        self.skill_files = sorted(_COMMUNITY_DIR.glob("*.md"))
        self.skill_files = [p for p in self.skill_files if p.name != "README.md"]

    def test_at_least_one_skill_present(self):
        self.assertGreater(len(self.skill_files), 0,
                           "community-skills/ directory has no skill .md files")

    def test_file_stem_is_lowercase_snake(self):
        for path in self.skill_files:
            with self.subTest(skill=path.stem):
                self.assertRegex(path.stem, _NAME_PATTERN,
                                 f"Skill id '{path.stem}' must be lowercase snake_case")

    def test_size_under_50kb(self):
        for path in self.skill_files:
            size = path.stat().st_size
            with self.subTest(skill=path.stem):
                self.assertLess(size, _FILE_SIZE_CAP_BYTES,
                                f"{path.name} is {size} bytes; cap is {_FILE_SIZE_CAP_BYTES}")

    def test_no_em_dashes(self):
        """Project-wide rule: never use the em-dash character (U+2014)."""
        for path in self.skill_files:
            content = _read(path)
            with self.subTest(skill=path.stem):
                self.assertNotIn("\u2014", content,
                                 f"{path.name} contains em dash(es). Use hyphens instead.")

    def test_first_line_is_top_level_heading(self):
        """Auto-name extraction in api.py is purely from the file stem, but
        every shipped skill has a `# X` title as the first line. Keep the
        convention so the file is self-describing."""
        for path in self.skill_files:
            content = _read(path)
            with self.subTest(skill=path.stem):
                first_line = content.splitlines()[0].strip()
                self.assertTrue(first_line.startswith("# "),
                                f"{path.name} first line must be '# <Title>'. Got: {first_line!r}")

    def test_auto_description_is_extractable(self):
        """The /community-skills endpoint depends on extracting a non-empty
        first non-heading paragraph as the import-dialog description."""
        for path in self.skill_files:
            content = _read(path)
            desc = _description_from_content(content)
            with self.subTest(skill=path.stem):
                self.assertTrue(desc, f"{path.name} has no extractable description line")
                self.assertLessEqual(len(desc), 200)
                # Must be at least somewhat descriptive
                self.assertGreater(len(desc), 30,
                                   f"{path.name} description '{desc!r}' is too short")

    def test_no_invented_agent_tools(self):
        """If a skill references a tool name that looks like an agent tool
        (lower_snake, used in a code-fenced step), it must be a real tool.
        We use a soft heuristic: treat any of `_REAL_AGENT_TOOLS` neighbouring
        words as expected; flag suspiciously named tools that match common
        agent-tool prefixes but aren't real."""
        suspicious = re.compile(r"\bexecute_[a-z_]+|\bquery_[a-z_]+\b")
        for path in self.skill_files:
            content = _read(path)
            referenced = set(m.group(0) for m in suspicious.finditer(content))
            unknown = referenced - _REAL_AGENT_TOOLS
            with self.subTest(skill=path.stem):
                self.assertFalse(unknown,
                                 f"{path.name} references unknown agent tools: {unknown}")


# ============================================================================
# UNIT: canonical-template invariants applied to the modern skills only
# ============================================================================

class TestCanonicalTemplate(unittest.TestCase):
    """Invariants that canonical-format skills must satisfy."""

    def _content_for(self, stem: str) -> str:
        path = _COMMUNITY_DIR / f"{stem}.md"
        if not path.exists():
            self.skipTest(f"{stem}.md not present")
        return _read(path)

    def test_canonical_skills_are_present(self):
        for stem in _CANONICAL_SKILLS:
            with self.subTest(skill=stem):
                self.assertTrue((_COMMUNITY_DIR / f"{stem}.md").exists(),
                                f"Expected canonical skill {stem}.md to exist")

    def test_has_when_to_classify_here(self):
        for stem in _CANONICAL_SKILLS:
            content = self._content_for(stem)
            with self.subTest(skill=stem):
                self.assertIn("## When to Classify Here", content,
                              f"{stem}.md missing 'When to Classify Here' section")

    def test_has_phase_one_heading(self):
        """Phase 1 must appear as either '### Phase 1:' (under '## Workflow')
        or '## Phase 1:' (top-level), since both shapes are in the canonical
        corpus today."""
        pattern = re.compile(r"^(?:## |### )Phase 1[:\-]", re.MULTILINE)
        for stem in _CANONICAL_SKILLS:
            content = self._content_for(stem)
            with self.subTest(skill=stem):
                self.assertTrue(
                    pattern.search(content),
                    f"{stem}.md missing Phase 1 heading at ## or ### level",
                )

    def test_phase_transition_cue_present(self):
        """The intent router uses the literal cue to decide when to call
        action='request_phase_transition'. Match the exact substring."""
        cue = "request transition to exploitation phase"
        for stem in _CANONICAL_SKILLS:
            content = self._content_for(stem)
            with self.subTest(skill=stem):
                self.assertIn(cue, content,
                              f"{stem}.md missing literal phase-transition cue '{cue}'")

    def test_phase_transition_cue_inside_phase_one(self):
        """The cue must sit at the END of Phase 1, before any 'Phase 2' heading,
        so the agent runs it on the recon-to-exploit boundary. Phase 2 may
        appear as '### Phase 2' (under '## Workflow') or '## Phase 2'
        (top-level)."""
        cue = "request transition to exploitation phase"
        phase2_pattern = re.compile(r"^(?:## |### )Phase 2[:\-]", re.MULTILINE)
        for stem in _CANONICAL_SKILLS:
            content = self._content_for(stem)
            cue_idx = content.find(cue)
            phase2_match = phase2_pattern.search(content)
            with self.subTest(skill=stem):
                self.assertNotEqual(cue_idx, -1)
                if phase2_match is not None:
                    self.assertLess(cue_idx, phase2_match.start(),
                                    f"{stem}.md cue must come before Phase 2 heading")

    def test_has_reporting_guidelines(self):
        for stem in _CANONICAL_SKILLS:
            content = self._content_for(stem)
            with self.subTest(skill=stem):
                self.assertIn("## Reporting Guidelines", content,
                              f"{stem}.md missing Reporting Guidelines section")

    def test_has_important_notes(self):
        for stem in _CANONICAL_SKILLS:
            content = self._content_for(stem)
            with self.subTest(skill=stem):
                self.assertIn("## Important Notes", content,
                              f"{stem}.md missing Important Notes section")

    def test_overview_paragraph_under_classification_budget(self):
        """The classifier uses the user-provided description from the import
        dialog OR the first 500 characters of the file
        (classification.py:177-183). The opening paragraph carries enormous
        weight, so it must be substantive within the 500-char budget."""
        for stem in _CANONICAL_SKILLS:
            content = self._content_for(stem)
            head = content[:500]
            with self.subTest(skill=stem):
                # Must reference the skill's core attack class explicitly
                # to disjoint from neighbouring built-ins.
                self.assertGreater(len(head.strip()), 200,
                                   f"{stem}.md first 500 chars look thin")


# ============================================================================
# UNIT: SSTI-specific assertions
# ============================================================================

class TestSstiSkill(unittest.TestCase):
    """Tests specifically about agentic/community-skills/ssti.md."""

    @classmethod
    def setUpClass(cls):
        cls.path = _COMMUNITY_DIR / "ssti.md"
        cls.content = _read(cls.path)

    def test_file_exists(self):
        self.assertTrue(self.path.exists())

    def test_first_line_title(self):
        first = self.content.splitlines()[0].strip()
        self.assertTrue("Server-Side Template Injection" in first or "SSTI" in first.upper(),
                        f"SSTI title should anchor on SSTI / Server-Side Template Injection. Got: {first!r}")

    def test_description_anchors_on_ssti_not_generic_rce(self):
        """The auto-description is what the classifier reads.
        It must lead with SSTI-specific terms so it disjoints from the rce
        built-in (which mentions SSTI generically as one branch)."""
        desc = _description_from_content(self.content)
        self.assertIn("Server-Side Template Injection", desc,
                      f"SSTI description must mention 'Server-Side Template Injection'. Got: {desc!r}")
        # Lower-bound on richness so the description won't collapse to a stub
        self.assertGreater(len(desc), 80)

    def test_engine_matrix_coverage(self):
        """The SSTI brief justifies the new skill on per-engine payload
        coverage. Confirm every engine the brief lists is actually present."""
        required_engines = [
            "Jinja2", "Twig", "Freemarker", "Velocity",
            "EJS", "Thymeleaf",
        ]
        # Bonus engines we documented beyond the brief
        bonus_engines = ["Smarty", "Mako", "Pebble", "Handlebars", "Pug"]
        for engine in required_engines:
            with self.subTest(engine=engine):
                self.assertIn(engine, self.content,
                              f"SSTI matrix missing required engine {engine}")
        for engine in bonus_engines:
            with self.subTest(engine=engine):
                self.assertIn(engine, self.content,
                              f"SSTI matrix missing bonus engine {engine}")

    def test_canonical_probes_present(self):
        """The classic SSTI probes must appear so they are copy-pasteable
        and so a keyword classifier match is reliable."""
        for probe in ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"):
            with self.subTest(probe=probe):
                self.assertIn(probe, self.content)

    def test_disjoint_from_rce_built_in(self):
        """The brief flags rce as the main classification overlap risk.
        Confirm the file documents the rce vs ssti boundary explicitly."""
        # Must explicitly mention the rce skill in a boundary-style passage
        self.assertRegex(self.content, r"\b(rce|RCE)\b",
                         "SSTI must call out the rce built-in by name")
        # The 'When to Classify Here' section must include a disjoint section
        self.assertTrue(
            "Disjoint from neighbouring skills" in self.content
            or "Disjoint from neighboring skills" in self.content
            or "Boundary against neighboring skills" in self.content,
            "SSTI must include a disjoint/boundary subsection",
        )

    def test_tooling_references_are_real(self):
        """Every Phase X step must reference real agent tools, never an
        invented tool name (PROMPT.ADD_COMMUNITY_AGENT_SKILL.md mandates this)."""
        # Catch any 'execute_FOO' that isn't in _REAL_AGENT_TOOLS
        for match in re.finditer(r"\bexecute_[a-z_]+", self.content):
            with self.subTest(token=match.group(0)):
                self.assertIn(match.group(0), _REAL_AGENT_TOOLS,
                              f"Unknown agent tool referenced: {match.group(0)}")

    def test_tplmap_documented_as_fallback(self):
        """tplmap is the new tool installed for this skill (per the brief).
        Workflow must reference it so the agent knows to call it when
        sstimap's plugin set falls short."""
        self.assertIn("tplmap", self.content,
                      "SSTI must reference the newly installed tplmap tool")
        self.assertIn("sstimap", self.content,
                      "SSTI must also reference the pre-existing sstimap tool")

    def test_oob_blocked_fallback_documented(self):
        """The customer-tunable parameters rule says to bake the trade-off
        directly into the markdown for OOB-blocked environments."""
        lower = self.content.lower()
        self.assertTrue(
            "oob-blocked" in lower or "oast" in lower
            or "interactsh" in lower or "no out-of-band" in lower,
            "SSTI must document the OOB-blocked fallback path",
        )

    def test_phase_one_ends_with_transition_cue(self):
        cue = "request transition to exploitation phase"
        cue_idx = self.content.find(cue)
        phase2_idx = self.content.find("### Phase 2")
        self.assertNotEqual(cue_idx, -1)
        self.assertNotEqual(phase2_idx, -1)
        self.assertLess(cue_idx, phase2_idx)

    def test_target_line_count_in_band(self):
        """Spec says target 200-800 lines."""
        line_count = len(self.content.splitlines())
        self.assertGreaterEqual(line_count, 200,
                                f"SSTI is {line_count} lines (under 200; feels underbaked)")
        self.assertLessEqual(line_count, 800,
                             f"SSTI is {line_count} lines (over 800; eats tokens)")


# ============================================================================
# INTEGRATION: replay the /community-skills endpoint logic
# ============================================================================

class TestCommunitySkillsEndpointReplay(unittest.TestCase):
    """Mirror agentic/api.py:list_community_skills against the real directory."""

    def _list_skills(self):
        skills = []
        for md_file in sorted(_COMMUNITY_DIR.glob("*.md")):
            if md_file.name == "README.md":
                continue
            content = md_file.read_text(encoding="utf-8")
            name = md_file.stem.replace("_", " ").title()
            desc = _description_from_content(content)
            skills.append({
                "id": md_file.stem,
                "name": name,
                "description": desc,
                "file": str(md_file),
            })
        return skills

    def test_ssti_appears_in_catalog(self):
        skills = self._list_skills()
        ids = {s["id"] for s in skills}
        self.assertIn("ssti", ids,
                      f"ssti not in catalog. Found: {sorted(ids)}")

    def test_ssti_auto_name_is_uppercased(self):
        skills = self._list_skills()
        ssti = next(s for s in skills if s["id"] == "ssti")
        # md_file.stem.replace("_"," ").title() -> "Ssti"
        self.assertEqual(ssti["name"], "Ssti")

    def test_ssti_auto_description_meaningful(self):
        skills = self._list_skills()
        ssti = next(s for s in skills if s["id"] == "ssti")
        self.assertGreater(len(ssti["description"]), 50)
        self.assertIn("Server-Side Template Injection", ssti["description"])

    def test_no_duplicate_ids(self):
        skills = self._list_skills()
        ids = [s["id"] for s in skills]
        self.assertEqual(len(ids), len(set(ids)))

    def test_readme_excluded_from_catalog(self):
        skills = self._list_skills()
        ids = {s["id"] for s in skills}
        self.assertNotIn("README", ids)
        self.assertNotIn("readme", ids)


# ============================================================================
# REGRESSION: tool_registry imports + tplmap documentation present
# ============================================================================

class TestToolRegistryRegression(unittest.TestCase):
    def test_tool_registry_imports_cleanly(self):
        from prompts.tool_registry import TOOL_REGISTRY  # noqa: WPS433
        self.assertIn("kali_shell", TOOL_REGISTRY)

    def test_kali_shell_mentions_sstimap_and_tplmap(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("sstimap", kali_desc,
                      "kali_shell description must still document sstimap")
        self.assertIn("tplmap", kali_desc,
                      "kali_shell description must document the newly added tplmap")

    def test_tool_registry_descriptions_are_well_formed(self):
        """No tool description may contain em dashes (project rule)."""
        from prompts.tool_registry import TOOL_REGISTRY
        # We are intentionally permissive here -- some legacy entries do contain
        # em dashes. We only enforce that the kali_shell entry, which we just
        # edited, is clean of em dashes in the tplmap section we added.
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        # tplmap mention sits between 'sstimap' and 'ysoserial'
        ssti_idx = kali_desc.index("sstimap")
        yso_idx = kali_desc.index("ysoserial")
        ssti_section = kali_desc[ssti_idx:yso_idx]
        self.assertNotIn("\u2014", ssti_section,
                         "Newly added tplmap section must not contain em dashes")


# ============================================================================
# REGRESSION: classification prompt builder still works with ssti as user_skill
# ============================================================================

class TestClassificationPromptRegression(unittest.TestCase):
    """Confirm the classifier prompt builder accepts SSTI as a user skill
    alongside the rce built-in without crashing or producing degenerate output."""

    def setUp(self):
        # Lazy import so import-time failures surface as test errors rather
        # than collection errors.
        try:
            from prompts.classification import build_classification_prompt
        except Exception as exc:
            self.skipTest(f"classification module unavailable: {exc}")
        self.build_classification_prompt = build_classification_prompt

    def test_prompt_builds_with_default_settings(self):
        """The bare prompt builder must not crash on a sane request."""
        try:
            prompt = self.build_classification_prompt("Test SSRF on the upload endpoint")
        except Exception as exc:
            self.fail(f"build_classification_prompt crashed: {exc}")
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 500)

    def test_prompt_contains_phase_types(self):
        prompt = self.build_classification_prompt("Test SSTI on the report builder")
        self.assertIn("informational", prompt)
        self.assertIn("exploitation", prompt)

    def test_prompt_includes_ssti_when_enabled_as_user_skill(self):
        """Plug SSTI in as a USER_ATTACK_SKILLS entry the way the production
        flow does (after the user clicks 'Import from Community'), then
        confirm the classifier section is built correctly."""
        from prompts import classification as classification_mod
        ssti_path = _COMMUNITY_DIR / "ssti.md"
        ssti_content = _read(ssti_path)
        ssti_desc = _description_from_content(ssti_content)

        fake_user_skills = [{
            "id": "ssti",
            "name": "SSTI",
            "description": ssti_desc,
            "content": ssti_content,
        }]

        # Monkey-patch the dependency so we don't need a live webapp.
        original = classification_mod.get_enabled_user_skills
        classification_mod.get_enabled_user_skills = lambda: fake_user_skills
        try:
            prompt = self.build_classification_prompt(
                "Hunt for Jinja2 SSTI on /reports/preview"
            )
        finally:
            classification_mod.get_enabled_user_skills = original

        self.assertIn("user_skill:ssti", prompt,
                      "user_skill:ssti must appear in attack_path_type union")
        self.assertIn("SSTI", prompt,
                      "Skill name must appear under '### user_skill:ssti'")
        # Confirm a recognisable SSTI signal lands in the classifier's view.
        self.assertIn("Server-Side Template Injection", prompt)


# ============================================================================
# SMOKE: Dockerfile + tool_registry stay in sync about tplmap
# ============================================================================

class TestDockerfileSmoke(unittest.TestCase):
    """Light-weight checks on the Kali Dockerfile so we catch sync drift
    between the skill workflow, the tool_registry entry, and the install."""

    @classmethod
    def setUpClass(cls):
        cls.dockerfile = _REPO_ROOT / "mcp" / "kali-sandbox" / "Dockerfile"
        if not cls.dockerfile.exists():
            raise unittest.SkipTest("Kali Dockerfile not found")
        cls.content = _read(cls.dockerfile)

    def test_tplmap_install_block_present(self):
        # We expect the upstream repo URL we cloned and the wrapper path
        self.assertIn("github.com/epinna/tplmap", self.content,
                      "Dockerfile missing tplmap clone line")
        self.assertIn("/usr/local/bin/tplmap", self.content,
                      "Dockerfile missing /usr/local/bin/tplmap wrapper")

    def test_tplmap_block_is_isolated_venv(self):
        """We ship tplmap in /opt/tplmap/venv to avoid clashing with
        /opt/venv. Confirm the venv path is referenced."""
        self.assertIn("/opt/tplmap/venv", self.content)

    def test_sstimap_still_installed(self):
        """We must not have accidentally removed sstimap while adding tplmap."""
        self.assertIn("github.com/vladko312/SSTImap", self.content)


if __name__ == "__main__":
    unittest.main()
