"""Step 1 — pure LATS engine (agentic/orchestrator_helpers/lats.py).

Covers value / UCT / select / backprop / expandability / budget / mutex-safe
waves / activation gate / structured expand parsing. All pure; the one async
expand test stubs retry_llm_call. See internal/LATS_integration.md §19 Step 1
and §20.14.
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import project_settings  # noqa: E402
from orchestrator_helpers import lats  # noqa: E402
from state import ExploitTree, ExploitTreeNode  # noqa: E402


def _step(error_class="success", tool_output="", tool_name="execute_curl",
          exploit_succeeded=False, verdict=None, step_index=None):
    s = {
        "error_class": error_class,
        "tool_output": tool_output,
        "tool_name": tool_name,
        "exploit_succeeded": exploit_succeeded,
        "duration_ms": 120,
    }
    if verdict is not None:
        s["verdict"] = verdict
    if step_index is not None:
        s["_step_index"] = step_index
    return s


def _analysis(verdict="new_info", exploit_succeeded=False, findings=None, per_step=None):
    return {
        "verdict": verdict,
        "productivity": {"verdict": verdict},
        "exploit_succeeded": exploit_succeeded,
        "chain_findings": findings or [],
        "per_step": per_step or [],
    }


class TestLatsValueWeb(unittest.TestCase):
    def test_exploit_success_is_max(self):
        self.assertEqual(
            lats.lats_value(_step(exploit_succeeded=True), _analysis(exploit_succeeded=True)),
            1.0,
        )

    def test_diagnostic_failures_are_neutral(self):
        for ec in ("shell_parser_error", "transport_error", "tool_internal_error",
                   "application_5xx_fast", "application_5xx_networked_fast"):
            v = lats.lats_value(_step(error_class=ec), _analysis(verdict="blocked"))
            self.assertAlmostEqual(v, 0.15, msg=f"{ec} should be neutral 0.15, got {v}")

    def test_4xx_blocked_penalized(self):
        v = lats.lats_value(_step(error_class="application_4xx", verdict="blocked"),
                            _analysis(verdict="blocked"))
        self.assertEqual(v, 0.0)   # -0.3 (blocked) -0.2 (4xx) clamped to 0

    def test_5xx_normal_new_info_high(self):
        v = lats.lats_value(_step(error_class="application_5xx_normal", verdict="new_info"),
                            _analysis(verdict="new_info"))
        # 0.3 (new_info) + 0.2 (5xx normal)
        self.assertAlmostEqual(v, 0.5)

    def test_finding_confidence_contributes(self):
        v = lats.lats_value(
            _step(error_class="success", verdict="new_info"),
            _analysis(verdict="new_info", findings=[{"confidence": 80}]),
        )
        # 0.5*0.8 (finding) + 0.3 (new_info)
        self.assertAlmostEqual(v, 0.7)

    def test_confirmation_small(self):
        v = lats.lats_value(_step(error_class="success", verdict="confirmation"),
                            _analysis(verdict="confirmation"))
        self.assertAlmostEqual(v, 0.1)

    def test_success_class_covered(self):
        # plain success with no_progress verdict -> penalized to 0
        v = lats.lats_value(_step(error_class="success", verdict="no_progress"),
                            _analysis(verdict="no_progress"))
        self.assertEqual(v, 0.0)


class TestLatsValuePostExpl(unittest.TestCase):
    def test_privilege_increase(self):
        before = {"finding_privilege_escalation": 0}
        after = {"finding_privilege_escalation": 1}
        v = lats.lats_value(_step(error_class="success"), _analysis(verdict="new_info"),
                            phase="post_exploitation", before=before, after=after)
        self.assertGreaterEqual(v, 0.6)

    def test_new_session_and_creds(self):
        before = {"sessions": [], "credentials": []}
        after = {"sessions": ["s1"], "credentials": ["c1"]}
        v = lats.lats_value(_step(), _analysis(verdict="new_info"),
                            phase="post_exploitation", before=before, after=after)
        self.assertAlmostEqual(v, min(1.0, 0.5 + 0.4), places=5)

    def test_diagnostic_neutral_post_expl(self):
        v = lats.lats_value(_step(error_class="tool_internal_error"), _analysis(),
                            phase="post_exploitation", before={}, after={})
        self.assertAlmostEqual(v, 0.15)


class TestUct(unittest.TestCase):
    def test_unvisited_is_infinite(self):
        n = ExploitTreeNode(visits=0, value=0.0)
        self.assertEqual(lats.uct(n, 10, 1.4), float("inf"))

    def test_exploit_explore_ordering(self):
        hi_value = ExploitTreeNode(visits=5, value=0.9)
        lo_value = ExploitTreeNode(visits=5, value=0.1)
        self.assertGreater(lats.uct(hi_value, 20, 1.4), lats.uct(lo_value, 20, 1.4))
        # fewer visits -> higher explore term at equal value
        few = ExploitTreeNode(visits=1, value=0.5)
        many = ExploitTreeNode(visits=10, value=0.5)
        self.assertGreater(lats.uct(few, 20, 1.4), lats.uct(many, 20, 1.4))


class TestSelectBackprop(unittest.TestCase):
    def _tree_with_root_children(self, child_specs):
        root = ExploitTreeNode(id="root", status="evaluated", depth=0)
        tree = ExploitTree(root_id="root", nodes={"root": root})
        for cid, status, value, visits in child_specs:
            n = ExploitTreeNode(id=cid, parent_id="root", depth=1,
                                status=status, value=value, visits=visits,
                                tool_name="execute_curl")
            tree.nodes[cid] = n
            root.children.append(cid)
        return tree

    def test_select_returns_parent_with_proposed_children(self):
        tree = self._tree_with_root_children([
            ("c1", "proposed", 0.0, 0),
            ("c2", "proposed", 0.0, 0),
        ])
        # root has proposed children -> select returns root (the wave parent)
        self.assertEqual(lats.lats_select(tree, 1.4), "root")

    def test_select_descends_to_hot_child(self):
        tree = self._tree_with_root_children([
            ("c1", "pruned", 0.0, 1),
            ("c2", "evaluated", 0.8, 1),   # hot, expandable (no children)
        ])
        # root fully evaluated (no proposed); descends to c2, which can expand
        self.assertEqual(lats.lats_select(tree, 1.4), "c2")

    def test_select_backtracks_after_prune(self):
        tree = self._tree_with_root_children([
            ("c1", "pruned", 0.0, 1),
            ("c2", "pruned", 0.0, 1),
            ("c3", "evaluated", 0.5, 1),
        ])
        self.assertEqual(lats.lats_select(tree, 1.4), "c3")

    def test_backprop_running_max_and_visits(self):
        root = ExploitTreeNode(id="root", status="evaluated")
        child = ExploitTreeNode(id="c1", parent_id="root", depth=1)
        tree = ExploitTree(root_id="root", nodes={"root": root, "c1": child})
        root.children.append("c1")
        lats.lats_backprop(tree, "c1", 0.8)
        self.assertEqual(tree.nodes["c1"].visits, 1)
        self.assertEqual(tree.nodes["root"].visits, 1)
        self.assertAlmostEqual(tree.nodes["root"].value, 0.8)
        # a lower subsequent value does not lower the running max
        lats.lats_backprop(tree, "c1", 0.2)
        self.assertAlmostEqual(tree.nodes["root"].value, 0.8)
        self.assertEqual(tree.nodes["root"].visits, 2)


class TestExpandabilityBudget(unittest.TestCase):
    def setUp(self):
        project_settings._settings = None

    def tearDown(self):
        project_settings._settings = None

    def test_can_expand_respects_depth_cap(self):
        n = ExploitTreeNode(status="evaluated", depth=6)   # LATS_MAX_DEPTH default 6
        self.assertFalse(lats._can_expand(n))
        n2 = ExploitTreeNode(status="evaluated", depth=3)
        self.assertTrue(lats._can_expand(n2))

    def test_can_expand_requires_evaluated_and_no_children(self):
        self.assertFalse(lats._can_expand(ExploitTreeNode(status="proposed", depth=0)))
        parent = ExploitTreeNode(status="evaluated", depth=0, children=["x"])
        self.assertFalse(lats._can_expand(parent))

    def test_budget_hit_on_rollouts(self):
        cap = project_settings.DEFAULT_AGENT_SETTINGS['LATS_MAX_ROLLOUTS']
        tree = ExploitTree(root_id="root", nodes={"root": ExploitTreeNode(id="root")})
        tree.rollouts = cap
        self.assertTrue(lats._budget_hit(tree))
        tree.rollouts = cap - 1
        self.assertFalse(lats._budget_hit(tree))

    def test_budget_hit_on_node_cap(self):
        cap = project_settings.DEFAULT_AGENT_SETTINGS['LATS_MAX_TREE_NODES']
        nodes = {f"n{i}": ExploitTreeNode(id=f"n{i}") for i in range(cap)}
        tree = ExploitTree(root_id="n0", nodes=nodes)
        self.assertTrue(lats._budget_hit(tree))

    def test_single_open_line(self):
        # A lone leaf that can still EXPAND is NOT a collapse (LATS deepens it).
        root = ExploitTreeNode(id="root", status="evaluated")
        c1 = ExploitTreeNode(id="c1", parent_id="root", depth=1, status="pruned")
        c2 = ExploitTreeNode(id="c2", parent_id="root", depth=1, status="evaluated", value=0.5)
        tree = ExploitTree(root_id="root", nodes={"root": root, "c1": c1, "c2": c2})
        root.children = ["c1", "c2"]
        tree.rollouts = 1
        self.assertFalse(lats._single_open_line(tree))   # c2 can expand -> not collapsed
        # A lone leaf at max depth CANNOT expand -> collapsed.
        c2.depth = 6   # LATS_MAX_DEPTH default
        self.assertTrue(lats._single_open_line(tree))
        # add a proposed node -> not collapsed (still work queued)
        c3 = ExploitTreeNode(id="c3", parent_id="c2", depth=2, status="proposed")
        tree.nodes["c3"] = c3
        c2.children = ["c3"]
        self.assertFalse(lats._single_open_line(tree))


class TestMutexSafeSubset(unittest.TestCase):
    def test_two_metasploit_only_one_enters_wave(self):
        kids = [
            ExploitTreeNode(id="a", tool_name="metasploit_console"),
            ExploitTreeNode(id="b", tool_name="metasploit_console"),
            ExploitTreeNode(id="c", tool_name="execute_curl"),
        ]
        wave = lats._mutex_safe_subset(kids)
        names = [k.tool_name for k in wave]
        self.assertEqual(names.count("metasploit_console"), 1)
        self.assertIn("execute_curl", names)
        self.assertEqual(len(wave), 2)

    def test_dangerous_tools_not_excluded(self):
        # execute_curl / kali_shell are in DANGEROUS_TOOLS but must fan out.
        kids = [
            ExploitTreeNode(id="a", tool_name="execute_curl"),
            ExploitTreeNode(id="b", tool_name="kali_shell"),
        ]
        wave = lats._mutex_safe_subset(kids)
        self.assertEqual(len(wave), 2)


class TestActivationGate(unittest.TestCase):
    def setUp(self):
        project_settings._settings = None

    def tearDown(self):
        project_settings._settings = None

    def _state(self, **over):
        base = {
            "current_phase": "exploitation",
            "target_info": {"services": ["http"]},
            "chain_findings_memory": [],
            "deep_think_ran_this_turn": True,
        }
        base.update(over)
        return base

    def test_disabled_by_default(self):
        self.assertFalse(lats.lats_active(self._state()))

    def test_enabled_all_gates_pass(self):
        project_settings._settings = dict(project_settings.DEFAULT_AGENT_SETTINGS)
        project_settings._settings["LATS_ENABLED"] = True
        self.assertTrue(lats.lats_active(self._state()))

    def test_wrong_phase_blocks(self):
        project_settings._settings = dict(project_settings.DEFAULT_AGENT_SETTINGS)
        project_settings._settings["LATS_ENABLED"] = True
        self.assertFalse(lats.lats_active(self._state(current_phase="informational")))

    def test_no_surface_blocks(self):
        project_settings._settings = dict(project_settings.DEFAULT_AGENT_SETTINGS)
        project_settings._settings["LATS_ENABLED"] = True
        self.assertFalse(lats.lats_active(self._state(target_info={}, chain_findings_memory=[])))

    def test_already_exploited_gated_by_setting(self):
        # Flag-hunt default (LATS_STOP_ON_FOOTHOLD off): a mid-chain foothold must
        # NOT block LATS — a foothold is a MEANS to the flag, so LATS should still
        # engage to push the chain through to the objective.
        project_settings._settings = dict(project_settings.DEFAULT_AGENT_SETTINGS)
        project_settings._settings["LATS_ENABLED"] = True
        s = self._state(chain_findings_memory=[{"finding_type": "access_gained"}])
        self.assertTrue(lats.lats_active(s), "foothold must not block activation on a flag-hunt")
        # Pentest mode (setting ON): a foothold means the exploit path is found,
        # so LATS hands back and does not activate.
        project_settings._settings["LATS_STOP_ON_FOOTHOLD"] = True
        self.assertFalse(lats.lats_active(s))

    def test_deep_think_not_fired_blocks(self):
        project_settings._settings = dict(project_settings.DEFAULT_AGENT_SETTINGS)
        project_settings._settings["LATS_ENABLED"] = True
        self.assertFalse(lats.lats_active(self._state(deep_think_ran_this_turn=False)))


class TestExpandParsing(unittest.TestCase):
    # execute_curl/kali_shell/metasploit_console require args/command respectively.
    ALLOWED = {"execute_curl", "kali_shell", "metasploit_console"}

    def test_valid_probes_parsed(self):
        text = ('{"probes": [{"tool_name": "execute_curl", "tool_args": {"args": "-s https://t/login"}, '
                '"rationale": "sqli"}, {"tool_name": "kali_shell", "tool_args": {"command": "id"}, "rationale": "enum"}]}')
        probes = lats._parse_expand_response(text, self.ALLOWED, 3)
        self.assertEqual(len(probes), 2)
        self.assertEqual(probes[0]["tool_name"], "execute_curl")
        self.assertEqual(probes[0]["tool_args"], {"args": "-s https://t/login"})

    def test_off_registry_dropped(self):
        text = '{"probes": [{"tool_name": "not_a_tool", "tool_args": {"args": "x"}}, {"tool_name": "execute_curl", "tool_args": {"args": "-s x"}}]}'
        probes = lats._parse_expand_response(text, self.ALLOWED, 3)
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]["tool_name"], "execute_curl")

    def test_missing_tool_name_dropped(self):
        text = '{"probes": [{"tool_args": {"x": 1}}, {"tool_name": "kali_shell", "tool_args": {"command": "id"}}]}'
        probes = lats._parse_expand_response(text, self.ALLOWED, 3)
        self.assertEqual([p["tool_name"] for p in probes], ["kali_shell"])

    def test_branching_cap(self):
        # DISTINCT probes so the cap is what bounds the count, not the hard dedup
        # (identical probes now collapse - see TestProbeDedup).
        items = ", ".join(
            f'{{"tool_name": "execute_curl", "tool_args": {{"args": "-s x{i}"}}}}'
            for i in range(6))
        text = f'{{"probes": [{items}]}}'
        probes = lats._parse_expand_response(text, self.ALLOWED, 3)
        self.assertEqual(len(probes), 3)

    def test_fenced_json(self):
        text = '```json\n{"probes": [{"tool_name": "execute_curl", "tool_args": {"args": "-s x"}}]}\n```'
        probes = lats._parse_expand_response(text, self.ALLOWED, 3)
        self.assertEqual(len(probes), 1)

    def test_malformed_returns_empty(self):
        self.assertEqual(lats._parse_expand_response("not json at all", self.ALLOWED, 3), [])
        self.assertEqual(lats._parse_expand_response("", self.ALLOWED, 3), [])

    def test_bad_args_type_dropped(self):
        text = '{"probes": [{"tool_name": "execute_curl", "tool_args": "notadict"}]}'
        self.assertEqual(lats._parse_expand_response(text, self.ALLOWED, 3), [])

    def test_malformed_arg_keys_dropped(self):
        # Fix #1: the LLM inventing url/flags instead of the real `args` key is
        # dropped pre-flight; a correctly-shaped probe survives.
        allowed = {"execute_curl", "proxy_brain", "execute_httpx"}
        text = ('{"probes": ['
                '{"tool_name": "proxy_brain", "tool_args": {"url": "http://t/"}},'          # wrong: needs code
                '{"tool_name": "execute_httpx", "tool_args": {"flags": "-title", "target": "t"}},'  # wrong: needs args
                '{"tool_name": "execute_curl", "tool_args": {"args": "-s http://t/"}}'      # correct
                ']}')
        probes = lats._parse_expand_response(text, allowed, 5)
        self.assertEqual([p["tool_name"] for p in probes], ["execute_curl"])

    def test_correctly_shaped_probes_kept(self):
        allowed = {"proxy_brain", "kali_shell"}
        text = ('{"probes": ['
                '{"tool_name": "proxy_brain", "tool_args": {"code": "print(1)"}},'
                '{"tool_name": "kali_shell", "tool_args": {"command": "whoami"}}'
                ']}')
        probes = lats._parse_expand_response(text, allowed, 5)
        self.assertEqual(len(probes), 2)


class TestArgValidator(unittest.TestCase):
    def test_primary_key_required_per_tool(self):
        self.assertTrue(lats._probe_args_valid("execute_curl", {"args": "-s x"}))
        self.assertFalse(lats._probe_args_valid("execute_curl", {"url": "x"}))
        self.assertTrue(lats._probe_args_valid("proxy_brain", {"code": "x"}))
        self.assertFalse(lats._probe_args_valid("proxy_brain", {"url": "x"}))
        self.assertTrue(lats._probe_args_valid("execute_httpx", {"args": "-title"}))
        self.assertFalse(lats._probe_args_valid("execute_httpx", {"flags": "-title", "target": "t"}))
        self.assertTrue(lats._probe_args_valid("kali_shell", {"command": "id"}))
        self.assertFalse(lats._probe_args_valid("kali_shell", {}))

    def test_unknown_tool_passes(self):
        # a tool with no registry schema can't be validated -> allowed
        self.assertTrue(lats._probe_args_valid("some_unknown_tool", {"whatever": 1}))

    def test_schema_block_lists_tool_arg_formats(self):
        block = lats._tool_schema_block({"execute_httpx", "proxy_brain"})
        self.assertIn("execute_httpx", block)
        self.assertIn("args", block)          # httpx schema mentions the args key
        self.assertIn("code", block)          # proxy_brain schema mentions code

    def test_expand_prompt_carries_schema_and_warning(self):
        state = {"current_phase": "exploitation",
                 "conversation_objectives": [{"content": "get the flag"}],
                 "current_objective_index": 0}
        msgs = lats._expand_prompt_messages(state, None, {"execute_httpx", "proxy_brain"}, 3)
        system = msgs[0]["content"]
        self.assertIn("EXACTLY", system)             # instructs exact keys
        self.assertIn("do NOT invent keys", system.replace("Do NOT", "do NOT"))
        self.assertIn("execute_httpx", system)       # per-tool schema present


class TestExpandAsync(unittest.TestCase):
    def setUp(self):
        project_settings._settings = dict(project_settings.DEFAULT_AGENT_SETTINGS)

    def tearDown(self):
        project_settings._settings = None

    def test_expand_uses_agent_model_and_never_reads_deep_think(self):
        state = {
            "current_phase": "exploitation",
            "conversation_objectives": [{"objective": "admin takeover"}],
            "current_objective_index": 0,
            # A poisoned deep_think_result: lats_expand must never parse it.
            "deep_think_result": "MARKDOWN THAT WOULD CRASH JSON PARSING {{{",
        }

        class _Resp:
            content = ('{"probes": [{"tool_name": "execute_curl", "tool_args": {"args": "-s http://t/login"}, "rationale": "login sqli"}, '
                       '{"tool_name": "execute_httpx", "tool_args": {"args": "-title -tech-detect"}, "rationale": "enum"}]}')

        fake = AsyncMock(return_value=_Resp())
        with patch("orchestrator_helpers.llm_retry.retry_llm_call", fake):
            probes = asyncio.run(lats.lats_expand(object(), state, None))
        self.assertEqual(len(probes), 2)
        self.assertEqual(probes[0]["tool_name"], "execute_curl")
        # retry_llm_call was invoked (the single agent model), and the messages
        # never embed deep_think_result.
        self.assertTrue(fake.called)
        sent_messages = fake.call_args[0][1]
        blob = " ".join(m["content"] for m in sent_messages)
        self.assertNotIn("MARKDOWN THAT WOULD CRASH", blob)


if __name__ == "__main__":
    unittest.main()
