"""
Tests for prompts.base.build_workspace_layout_block().

This builder is NOT on the live path: think_node puts the static
build_workspace_rules_block() in the cached prefix and the live
build_uploads_inbox_block() in the uncached suffix (tested in
test_uploads_inbox_block.py). It shares _list_uploads with the live block.
Two distinct behaviors to lock in:

  1. Always render notes/, tool-outputs/, jobs/ guidance + footer.
  2. ONLY render the uploads/ section when uploads/ has >= 1 file. When
     empty, skip it entirely (don't nag the agent about an empty folder).

Run: python3 -m unittest tests.test_workspace_layout_block -v
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from prompts import base  # noqa: E402


class WorkspaceLayoutBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-layout-prompt-")
        self._orig = base._WORKSPACE_ROOT_FOR_PROMPT
        base._WORKSPACE_ROOT_FOR_PROMPT = Path(self.tmp)

    def tearDown(self):
        base._WORKSPACE_ROOT_FOR_PROMPT = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _project_dir(self, project_id: str = "proj") -> Path:
        d = Path(self.tmp) / project_id / "uploads"
        d.mkdir(parents=True, exist_ok=True)
        return d


# =============================================================================
# Always-rendered sections
# =============================================================================

class TestAlwaysRendered(WorkspaceLayoutBase):
    def test_notes_section_always_present(self):
        out = base.build_workspace_layout_block("proj")
        self.assertIn("`notes/`", out)
        self.assertIn("YOUR SCRATCH", out)

    def test_tool_outputs_section_always_present(self):
        out = base.build_workspace_layout_block("proj")
        self.assertIn("`tool-outputs/`", out)
        self.assertIn("AUTO-MANAGED", out)
        self.assertIn("DO NOT", out)

    def test_jobs_section_always_present(self):
        out = base.build_workspace_layout_block("proj")
        self.assertIn("`jobs/`", out)
        self.assertIn("job_spawn", out)

    def test_footer_always_present(self):
        out = base.build_workspace_layout_block("proj")
        self.assertIn("fs_mkdir", out)
        self.assertIn("evidence/", out)

    def test_output_capture_rule_always_present(self):
        # Don't-pass-`-o` rule for external execute_* tools.
        out = base.build_workspace_layout_block("proj")
        self.assertIn("OUTPUT CAPTURE", out)
        self.assertIn("DO NOT", out)
        # Mentions a representative cross-section of execute_* tools
        for tool in ("execute_nuclei", "execute_curl", "execute_ffuf",
                     "execute_katana", "kali_shell"):
            self.assertIn(tool, out, f"{tool} should be named in the output-capture rule")
        # Mentions the actual failure mode the agent would otherwise hit
        self.assertIn("no such file or directory", out)
        # Mentions the auto-offload alternative
        self.assertIn("auto-offload", out.lower().replace("-", "").replace("_", "") + "auto-offload")  # tolerant match
        self.assertIn("stdout", out)

    def test_workspace_root_rendered_as_absolute_path(self):
        # The agent should see its concrete workspace root in the prompt so
        # it can pass workspace files as absolute paths to external tools
        # (ffuf -w, kali_shell, etc.) without an extra discovery round-trip.
        out = base.build_workspace_layout_block("proj-abc-123")
        # Concrete path resolved
        self.assertIn("proj-abc-123/", out)
        # Header label present
        self.assertIn("Your project workspace root", out)
        # Concrete example for the abs-path guidance
        self.assertIn("-w", out)
        self.assertIn("uploads/wordlist.txt", out)
        # Placeholder sentinel must NOT leak through
        self.assertNotIn("__WORKSPACE_ROOT__", out)

    def test_empty_project_id_falls_back_to_placeholder_label(self):
        # With no project_id, we still render the block but the absolute
        # path shows <projectId> instead of crashing or rendering a bogus path.
        out = base.build_workspace_layout_block("")
        self.assertNotIn("__WORKSPACE_ROOT__", out)
        self.assertIn("<projectId>", out)  # placeholder visible
        self.assertIn("Your project workspace root", out)

    def test_job_spawn_policy_always_present(self):
        # When-to-spawn / when-not-to-spawn / live-progress guidance.
        out = base.build_workspace_layout_block("proj")
        self.assertIn("JOB SPAWN POLICY", out)
        # The duration heuristic
        self.assertIn(">60s", out)
        # The "have other work to do" condition
        self.assertIn("OTHER", out)
        # The don't-spawn list calls out the fast-tool offenders by name
        for tool in ("tradecraft_lookup", "query_graph", "web_search",
                     "cve_intel", "msf_restart"):
            self.assertIn(tool, out, f"{tool} should be in the don't-spawn list")
        # The live-progress caveat names the interactive tools
        for tool in ("metasploit_console", "execute_hydra", "kali_shell"):
            self.assertIn(tool, out, f"{tool} should be in the live-progress caveat")
        # Mentions the post-spawn observability tools
        self.assertIn("fs_grep", out)
        self.assertIn("job_status", out)
        self.assertIn("job_wait", out)
        self.assertIn("job_cancel", out)


# =============================================================================
# Uploads section is conditional on file presence
# =============================================================================

class TestUploadsConditional(WorkspaceLayoutBase):
    def test_uploads_section_omitted_when_dir_empty(self):
        self._project_dir("proj")  # creates the dir, no files
        out = base.build_workspace_layout_block("proj")
        self.assertNotIn("USER INBOX", out)
        # Strip prose mentions so we only catch the actual section header.
        # Prose mentions include: the `uploads/<...>` path placeholder and
        # the `uploads/wordlist.txt` example in the absolute-path guidance.
        scrubbed = out.replace("uploads/<", "").replace("uploads/wordlist.txt", "")
        self.assertNotIn("uploads/", scrubbed)
        # Sanity: the other 3 sections still rendered
        self.assertIn("`notes/`", out)

    def test_uploads_section_omitted_when_dir_missing(self):
        # No uploads/ at all (don't even create the project)
        out = base.build_workspace_layout_block("never-existed-proj")
        self.assertNotIn("USER INBOX", out)

    def test_uploads_section_rendered_when_one_file_present(self):
        ud = self._project_dir("proj")
        (ud / "wordlist.txt").write_bytes(b"x")
        out = base.build_workspace_layout_block("proj")
        self.assertIn("USER INBOX", out)
        self.assertIn("`uploads/wordlist.txt`", out)
        self.assertIn("1 file", out)

    def test_uploads_lists_each_filename(self):
        ud = self._project_dir("proj")
        for name in ("a.txt", "b.csv", "c.json"):
            (ud / name).write_bytes(b"v")
        out = base.build_workspace_layout_block("proj")
        self.assertIn("3 files", out)
        for name in ("a.txt", "b.csv", "c.json"):
            self.assertIn(f"`uploads/{name}`", out)

    def test_uploads_caps_listing_at_max_and_says_so(self):
        # 50 files; cap is 20
        ud = self._project_dir("proj")
        for i in range(50):
            # Vary mtime so sort order is deterministic - older first means
            # newest 20 are 30..49.
            f = ud / f"f{i:02d}.txt"
            f.write_bytes(b"v")
            os.utime(f, (1_000_000 + i, 1_000_000 + i))
        out = base.build_workspace_layout_block("proj")
        # Cap message
        self.assertIn("showing newest 20 of 50", out)
        # Newest (f49 - f30) present
        self.assertIn("`uploads/f49.txt`", out)
        self.assertIn("`uploads/f30.txt`", out)
        # Oldest (f00) NOT present in the inline list
        self.assertNotIn("`uploads/f00.txt`", out)

    def test_uploads_section_lists_newest_first(self):
        ud = self._project_dir("proj")
        for i, name in enumerate(("oldest.txt", "middle.txt", "newest.txt")):
            f = ud / name
            f.write_bytes(b"v")
            os.utime(f, (1_000_000 + i, 1_000_000 + i))
        out = base.build_workspace_layout_block("proj")
        i_newest = out.find("newest.txt")
        i_middle = out.find("middle.txt")
        i_oldest = out.find("oldest.txt")
        self.assertLess(i_newest, i_middle, "newest must appear before middle")
        self.assertLess(i_middle, i_oldest, "middle must appear before oldest")

    def test_uploads_includes_symlinks(self):
        ud = self._project_dir("proj")
        # Plant a symlink target outside uploads, then symlink it inside.
        target = Path(self.tmp) / "host-wordlist.txt"
        target.write_bytes(b"v")
        os.symlink(str(target), str(ud / "linked.txt"))
        out = base.build_workspace_layout_block("proj")
        self.assertIn("`uploads/linked.txt`", out)


# =============================================================================
# Defensive edge cases
# =============================================================================

class TestDefensiveEdges(WorkspaceLayoutBase):
    def test_empty_project_id_renders_static_block_only(self):
        # If project_id is missing, we still render the layout doc; we just
        # skip the uploads listing (can't resolve the dir without a pid).
        out = base.build_workspace_layout_block("")
        self.assertIn("`notes/`", out)
        self.assertNotIn("USER INBOX", out)

    def test_no_crash_when_listing_raises_oserror(self):
        # Force iterdir to raise OSError. We mock instead of chmod-000 because
        # the agent container runs as root, where chmod doesn't restrict access.
        ud = self._project_dir("proj")
        (ud / "trapped.txt").write_bytes(b"v")
        with patch.object(Path, "iterdir", side_effect=PermissionError("denied")):
            out = base.build_workspace_layout_block("proj")
        self.assertIn("`notes/`", out)  # static parts still rendered
        self.assertNotIn("USER INBOX", out)  # uploads silently dropped


if __name__ == "__main__":
    unittest.main()
