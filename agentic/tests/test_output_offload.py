"""
Unit tests for agentic/output_offload.py + tool_offload_policy.py.

Covers the executor-side decision tree:
  - policy: never -> always inline
  - policy: always -> offload regardless of size
  - policy: auto + below threshold -> inline
  - policy: auto + above threshold -> offload
  - per-call override (inline | file | auto) wins over policy
  - streaming-tee filename uses job_id prefix
  - stub format contains head + tail
  - strip_output_mode() removes the param without mutating original

Run with: python3 -m unittest tests.test_output_offload -v
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import output_offload  # noqa: E402
import tool_offload_policy  # noqa: E402


class OffloadTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-offload-")
        self._orig_root = output_offload.WORKSPACE_ROOT
        output_offload.WORKSPACE_ROOT = Path(self.tmp)

    def tearDown(self):
        output_offload.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _outputs(self, project="p1"):
        return Path(self.tmp) / project / "tool-outputs"

    def _ls_outputs(self, project="p1"):
        d = self._outputs(project)
        return sorted(p.name for p in d.iterdir()) if d.exists() else []


class TestPolicyMap(unittest.TestCase):
    def test_never_tools(self):
        for name in ("query_graph", "web_search", "cve_intel"):
            self.assertEqual(tool_offload_policy.get_offload_mode(name), "never")

    def test_always_tools(self):
        for name in ("execute_nuclei", "execute_playwright"):
            self.assertEqual(tool_offload_policy.get_offload_mode(name), "always")

    def test_unknown_defaults_to_auto(self):
        self.assertEqual(tool_offload_policy.get_offload_mode("brand_new_tool"), "auto")


class TestNeverPolicy(OffloadTestBase):
    def test_never_inlines_huge_output(self):
        huge = "x" * 200_000
        out = output_offload.maybe_offload("p1", "query_graph", huge)
        self.assertEqual(out, huge)
        self.assertFalse(self._outputs().exists())


class TestAlwaysPolicy(OffloadTestBase):
    def test_always_offloads_tiny_output(self):
        out = output_offload.maybe_offload("p1", "execute_nuclei", "small")
        self.assertIn("[Output offloaded:", out)
        self.assertIn("--- head ---", out)
        files = self._ls_outputs()
        self.assertEqual(len(files), 1)
        # Content on disk is the original, not the stub
        full = self._outputs() / files[0]
        self.assertEqual(full.read_text(), "small")


class TestAutoPolicy(OffloadTestBase):
    def test_auto_below_threshold_inline(self):
        text = "y" * 100
        out = output_offload.maybe_offload("p1", "kali_shell", text)
        self.assertEqual(out, text)
        self.assertFalse(self._outputs().exists())

    def test_auto_above_threshold_offloads(self):
        text = "z" * (tool_offload_policy.OFFLOAD_THRESHOLD + 1)
        out = output_offload.maybe_offload("p1", "kali_shell", text)
        self.assertIn("Output offloaded:", out)
        self.assertEqual(len(self._ls_outputs()), 1)

    def test_auto_at_threshold_inline(self):
        # Exactly at threshold: NOT > threshold, so inline.
        text = "a" * tool_offload_policy.OFFLOAD_THRESHOLD
        out = output_offload.maybe_offload("p1", "kali_shell", text)
        self.assertEqual(out, text)


class TestPerCallOverride(OffloadTestBase):
    def test_inline_override_beats_always_policy(self):
        out = output_offload.maybe_offload(
            "p1", "execute_nuclei", "small", override="inline"
        )
        self.assertEqual(out, "small")
        self.assertFalse(self._outputs().exists())

    def test_file_override_offloads_tiny(self):
        out = output_offload.maybe_offload(
            "p1", "web_search", "tiny", override="file"
        )
        self.assertIn("Output offloaded:", out)

    def test_unknown_override_falls_through_to_policy(self):
        # 'bogus' -> ignored; falls through to per-tool policy
        out = output_offload.maybe_offload(
            "p1", "query_graph", "tiny", override="bogus"
        )
        self.assertEqual(out, "tiny")


class TestStubFormat(OffloadTestBase):
    def test_stub_contains_head_and_tail(self):
        lines = [f"line{i}" for i in range(1, 201)]
        text = "\n".join(lines)
        out = output_offload.maybe_offload("p1", "execute_nuclei", text)
        self.assertIn("--- head ---", out)
        self.assertIn("--- tail ---", out)
        self.assertIn("line1", out)
        self.assertIn("line200", out)
        # And NOT every middle line (head is bounded)
        self.assertNotIn("line150", out)

    def test_stub_no_tail_when_short(self):
        text = "\n".join(f"l{i}" for i in range(1, 10))  # < HEAD_LINES
        out = output_offload.maybe_offload("p1", "execute_nuclei", text)
        self.assertIn("--- head ---", out)
        self.assertNotIn("--- tail ---", out)

    def test_streaming_tee_uses_job_id_filename(self):
        out = output_offload.maybe_offload(
            "p1", "execute_hydra", "data", override="file", job_id="abc123"
        )
        self.assertIn("abc123-execute_hydra.log", out)
        self.assertTrue((self._outputs() / "abc123-execute_hydra.log").exists())

    # --- Char-cap regression: prevents the "single-line blob" defeat ------

    def test_single_huge_line_stub_is_bounded(self):
        # 100KB single line (no newlines) - regression test for bug #6.
        # Without the char cap, head and tail would each contain the entire
        # blob and the stub would render ~100KB into the chat.
        text = "X" * 100_000
        out = output_offload.maybe_offload("p1", "execute_nuclei", text)
        # Stub should be far smaller than the input.
        self.assertLess(len(out), 10_000, msg=f"stub was {len(out)} chars")
        # And should advertise truncation
        self.assertIn("[head truncated]", out)

    def test_long_first_line_then_short_lines(self):
        # First line is huge; rest are tiny. Head should cap the first line,
        # tail (if rendered) should contain the short ones.
        long_line = "Y" * 10_000
        short = "\n".join(f"short{i}" for i in range(200))
        text = f"{long_line}\n{short}"
        out = output_offload.maybe_offload("p1", "execute_nuclei", text)
        self.assertIn("[head truncated]", out)
        # Tail is bounded by lines AND chars
        self.assertIn("--- tail ---", out)
        # Last short line must be present in tail
        self.assertIn("short199", out)

    def test_head_below_char_cap_not_truncated(self):
        # Several short lines - head should fit comfortably under HEAD_CHAR_CAP.
        text = "\n".join(f"normal line {i}" for i in range(1, 90))
        out = output_offload.maybe_offload("p1", "execute_nuclei", text)
        self.assertNotIn("[head truncated]", out)


class TestProjectScoping(OffloadTestBase):
    def test_no_project_id_inlines(self):
        # Without a project, can't safely offload - return as-is.
        out = output_offload.maybe_offload("", "execute_nuclei", "x" * 100_000)
        self.assertEqual(out, "x" * 100_000)

    def test_different_projects_different_dirs(self):
        output_offload.maybe_offload("p1", "execute_nuclei", "from-p1")
        output_offload.maybe_offload("p2", "execute_nuclei", "from-p2")
        self.assertEqual(len(self._ls_outputs("p1")), 1)
        self.assertEqual(len(self._ls_outputs("p2")), 1)


class TestStripOutputMode(unittest.TestCase):
    def test_strips_key_and_returns_override(self):
        args = {"foo": "bar", "output_mode": "file"}
        cleaned, override = output_offload.strip_output_mode(args)
        self.assertEqual(cleaned, {"foo": "bar"})
        self.assertEqual(override, "file")

    def test_no_key_no_override(self):
        args = {"foo": "bar"}
        cleaned, override = output_offload.strip_output_mode(args)
        self.assertEqual(cleaned, args)
        self.assertIsNone(override)

    def test_non_dict_passthrough(self):
        cleaned, override = output_offload.strip_output_mode("not a dict")
        self.assertEqual(cleaned, "not a dict")
        self.assertIsNone(override)

    def test_strips_inline_override(self):
        cleaned, override = output_offload.strip_output_mode({"output_mode": "inline"})
        self.assertEqual(cleaned, {})
        self.assertEqual(override, "inline")

    def test_strips_auto_override(self):
        cleaned, override = output_offload.strip_output_mode({"output_mode": "auto"})
        self.assertEqual(cleaned, {})
        self.assertEqual(override, "auto")

    def test_passes_through_fs_grep_content_value(self):
        # fs_grep owns `output_mode` natively with vocabulary
        # files_with_matches|content|count. Stripping it would silently
        # revert fs_grep to its default (`files_with_matches`) and return
        # only the filename — observed bug.
        args = {"pattern": "200", "path": "notes/x.json", "output_mode": "content"}
        cleaned, override = output_offload.strip_output_mode(args)
        self.assertEqual(cleaned, args)  # untouched
        self.assertIsNone(override)

    def test_passes_through_fs_grep_count_value(self):
        args = {"pattern": "foo", "output_mode": "count"}
        cleaned, override = output_offload.strip_output_mode(args)
        self.assertEqual(cleaned, args)
        self.assertIsNone(override)

    def test_passes_through_fs_grep_files_with_matches_value(self):
        args = {"pattern": "foo", "output_mode": "files_with_matches"}
        cleaned, override = output_offload.strip_output_mode(args)
        self.assertEqual(cleaned, args)
        self.assertIsNone(override)


class TestNonStringOutput(OffloadTestBase):
    def test_none_returns_empty(self):
        self.assertEqual(output_offload.maybe_offload("p1", "x", None), "")

    def test_dict_coerced_to_str(self):
        out = output_offload.maybe_offload("p1", "query_graph", {"k": "v"})
        self.assertIn("k", out)  # inlined (never policy), but coerced


# --- Gap-fill #3: write-failure fallback path --------------------------------

class TestWriteFailureFallback(OffloadTestBase):
    @unittest.skipIf(
        os.geteuid() == 0,
        "chmod-based write denial is a no-op for root (the container runs as "
        "root); the sibling test, which makes workspace_fs._write_file fail, covers this path "
        "root-safely",
    )
    def test_disk_write_failure_falls_back_to_inline(self):
        # Make the outputs dir un-writable (file with same name blocks mkdir,
        # OR remove permissions on the parent).
        os.chmod(self.tmp, 0o500)  # read+execute, no write -> mkdir fails
        try:
            text = "x" * 100_000  # would normally offload
            out = output_offload.maybe_offload("p1", "execute_nuclei", text)
            # Should NOT have emitted the offload stub; should fall back to
            # returning the raw output unchanged.
            self.assertNotIn("[Output offloaded:", out)
            self.assertEqual(out, text)
        finally:
            os.chmod(self.tmp, 0o700)  # restore so tearDown can rmtree

    def test_dir_writable_but_file_write_fails(self):
        # Different failure mode: dir is fine but writing the file fails. The
        # file is written through workspace_fs._write_file (the pinned-folder
        # writer), so that is where the failure is simulated.
        from unittest import mock
        calls = {"n": 0}

        def boom(*a, **kw):
            calls["n"] += 1
            raise PermissionError("simulated disk full")

        with mock.patch.object(output_offload.workspace_fs, "_write_file", boom):
            text = "x" * 100_000
            out = output_offload.maybe_offload("p1", "execute_nuclei", text)
        self.assertEqual(calls["n"], 1)
        self.assertEqual(out, text)  # fell back to inline


if __name__ == "__main__":
    unittest.main()
