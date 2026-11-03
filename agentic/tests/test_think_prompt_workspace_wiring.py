"""The workspace listings reach the prompt think_node actually builds, in the
uncached suffix, never in the cached prefix.

No test captures think_node's assembled prompt, so these read its source, as
test_deep_think.py does for the Deep Think instruction.
"""
from __future__ import annotations

import inspect
import shutil
import tempfile
import unittest
from pathlib import Path

from prompts import base


def _think_source() -> str:
    from orchestrator_helpers.nodes.think_node import think_node
    return inspect.getsource(think_node)


class ThinkNodeWiring(unittest.TestCase):
    def test_uploads_block_appended_after_template_format(self):
        src = _think_source()
        fmt = src.index("REACT_SYSTEM_PROMPT.format(")
        call = src.index("build_uploads_inbox_block(project_id)")
        self.assertGreater(call, fmt, "the uploads listing must stay out of the cached template")
        after = src[call:call + 300]
        self.assertIn("system_prompt += ", after)
        self.assertNotIn("build_uploads_inbox_block", src[:fmt])

    def test_layout_block_with_inline_inbox_is_not_on_the_live_path(self):
        self.assertNotIn("build_workspace_layout_block(", _think_source())


class RulesBlockIsStatic(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rules-"))
        self._orig = base._WORKSPACE_ROOT_FOR_PROMPT
        base._WORKSPACE_ROOT_FOR_PROMPT = self.tmp

    def tearDown(self):
        base._WORKSPACE_ROOT_FOR_PROMPT = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_workspace_rules_block_has_no_uploads(self):
        uploads = self.tmp / "proj" / "uploads"
        (uploads / "staged-folder").mkdir(parents=True)
        (uploads / "staged-file.txt").write_text("x")
        rules = base.build_workspace_rules_block("proj")
        self.assertNotIn("staged-folder", rules)
        self.assertNotIn("staged-file.txt", rules)
        self.assertIn("staged-folder", base.build_uploads_inbox_block("proj"))


if __name__ == "__main__":
    unittest.main()
