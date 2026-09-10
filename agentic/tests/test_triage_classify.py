"""LLM-response handling for the reduced Priority Board assist step.

Ranking is deterministic now (see test_triage_scoring.py); the LLM only clusters
duplicates and writes a one-line rationale for the top findings. The value at
risk here is the SEAM to `_call_llm`: its result is
`{"content": [{"type": "text", ...}], ...}` with no top-level "text" key, and a
run once produced zero output because that key was read. So the response-shape
contract and the JSON-array parsing are pinned here.

Pure Python: the graph-fed scoring path is proved in test_triage_scoring.py and
test_triage_scoring_graph_live.py.

Run: python -m pytest agentic/tests/test_triage_classify.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage.orchestrator import TriageOrchestrator  # noqa: E402
from cypherfix_triage.prompts.classify import (  # noqa: E402
    CLUSTER_SYSTEM_PROMPT,
    RATIONALE_SYSTEM_PROMPT,
    LLM_FINDING_FIELDS,
    build_cluster_prompt,
    build_rationale_prompt,
)


class TestResponseText(unittest.TestCase):
    """The exact envelope _call_llm returns; reading a nonexistent "text" key
    silently yielded "" and produced an empty run."""

    @staticmethod
    def envelope(text):
        return {"content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn", "tool_uses": []}

    def test_a_real_call_llm_result_yields_its_text(self):
        r = self.envelope('```json\n[{"id": "v1"}]\n```')
        self.assertEqual(
            TriageOrchestrator._extract_json_array(TriageOrchestrator._response_text(r)),
            [{"id": "v1"}])

    def test_no_top_level_text_key_exists(self):
        self.assertNotIn("text", self.envelope("x"))

    def test_multiple_blocks_concatenate(self):
        r = {"content": [{"type": "text", "text": '[{"id":'},
                         {"type": "text", "text": ' "v1"}]'}]}
        self.assertEqual(
            TriageOrchestrator._extract_json_array(TriageOrchestrator._response_text(r)),
            [{"id": "v1"}])

    def test_non_text_blocks_ignored(self):
        r = {"content": [{"type": "tool_use", "id": "t"}, {"type": "text", "text": "[]"}]}
        self.assertEqual(TriageOrchestrator._response_text(r).strip(), "[]")

    def test_degenerate_envelopes_do_not_raise(self):
        for r in ({}, {"content": []}, {"content": None}, "raw", None):
            self.assertIsInstance(TriageOrchestrator._response_text(r), str)


class TestExtractJsonArray(unittest.TestCase):
    def test_fenced(self):
        self.assertEqual(
            TriageOrchestrator._extract_json_array('pre ```json\n[{"id":"a"}]\n``` post'),
            [{"id": "a"}])

    def test_bare(self):
        self.assertEqual(TriageOrchestrator._extract_json_array('[{"id":"a"}]'), [{"id": "a"}])

    def test_prose_yields_empty(self):
        self.assertEqual(TriageOrchestrator._extract_json_array("could not"), [])

    def test_broken_json_yields_empty(self):
        self.assertEqual(TriageOrchestrator._extract_json_array('```json\n[{"id": ]\n```'), [])

    def test_object_not_mistaken_for_array(self):
        self.assertEqual(TriageOrchestrator._extract_json_array('{"id":"a"}'), [])

    def test_empty(self):
        self.assertEqual(TriageOrchestrator._extract_json_array(""), [])


class TestThePromptsAskOnlyForClusterAndRationale(unittest.TestCase):
    """The LLM must no longer be asked "is this real?" -- the graph decides."""

    def test_cluster_prompt_is_about_grouping_not_verdicts(self):
        self.assertIn("cluster_id", CLUSTER_SYSTEM_PROMPT)
        self.assertNotIn("needs_verification", CLUSTER_SYSTEM_PROMPT)
        self.assertNotIn("likely_noise", CLUSTER_SYSTEM_PROMPT)

    def test_rationale_prompt_asks_for_one_sentence(self):
        self.assertIn("reason", RATIONALE_SYSTEM_PROMPT)
        self.assertNotIn("real or noise", RATIONALE_SYSTEM_PROMPT)

    def test_builders_embed_the_payload(self):
        self.assertIn("PAYLOAD", build_cluster_prompt("PAYLOAD"))
        self.assertIn("PAYLOAD", build_rationale_prompt("PAYLOAD"))

    def test_llm_bundle_fields_exclude_raw_response(self):
        self.assertNotIn("raw_response", LLM_FINDING_FIELDS)
        self.assertIn("signals", LLM_FINDING_FIELDS)


if __name__ == "__main__":
    unittest.main()
