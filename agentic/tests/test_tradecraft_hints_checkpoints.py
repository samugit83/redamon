"""When Library now searches again (owner decision 2026-11-17; it replaced T8.1's fixed checkpoints,
R-364): at a run's start, then only when the current goal or a structured fact of the session
changed (the skill, the phase, a new technology, CVE id or finding type, the last attempt's
outcome). Nothing else searches again: a name the vocabulary does not know, a finding type off the
list, a tool result's text, a resume on the saved state. A new message starts again.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_tradecraft_hints import entry_of, goal_line, library, now, pages_of, state, todo  # noqa: E402
from tradecraft.library import profile  # noqa: E402


def think(st, caplog=None, **kw):
    """One think: the block, the state as the think node leaves it, and why it searched (None
    when it did not)."""
    if caplog is not None:
        caplog.clear()
    note, updates = now(st, **kw)
    reasons = None
    if caplog is not None:
        found = [r.getMessage() for r in caplog.records if "library_now refresh=" in r.getMessage()]
        reasons = found[-1].split("reason=")[1].split()[0] if found else None
    return note, {**st, **updates}, reasons


def started(caplog):
    with caplog.at_level(logging.INFO):
        _, st, reasons = think(state(), caplog)
    assert reasons == "start"
    return st


def test_a_run_starts_with_a_search(caplog):
    with caplog.at_level(logging.INFO):
        note, st, reasons = think(state(), caplog)
    assert reasons == "start" and pages_of(note) == ["patt:401", "patt:402", "patt:403"]
    assert st["tradecraft_hint_count"] == 1
    # An unclassified run has a goal too: it searches with no topic.
    with caplog.at_level(logging.INFO):
        assert think(state(attack_path_type="user_skill:abc"), caplog)[2] == "start"


def test_a_new_goal(caplog):
    st = started(caplog)
    with caplog.at_level(logging.INFO):
        _, st, reasons = think({**st, "todo_list": [todo("Enumerate the database version", "in_progress")]}, caplog)
        assert reasons == "goal"
        # The same goal written again is no change; another step taken up is.
        assert think({**st, "todo_list": [todo("enumerate  the DATABASE version", "in_progress")]}, caplog)[2] is None
        assert think({**st, "todo_list": [todo("Enumerate the database version", "completed"),
                                          todo("Dump the users table", "in_progress")]}, caplog)[2] == "goal"


def test_each_fact(caplog):
    st = started(caplog)
    cases = {
        "skill": {"attack_path_type": "xss"},
        "phase": {"current_phase": "post_exploitation"},
        "technology": {"target_info": {"technologies": ["PostgreSQL 14", "nginx 1.25"], "vulnerabilities": []}},
        "cve+finding": {"chain_findings_memory": [{"finding_type": "vulnerability_confirmed",
                                                   "related_cves": ["CVE-2024-23897"]}]},
        "finding": {"chain_findings_memory": [{"finding_type": "vulnerability_confirmed", "title": "x"}]},
        "outcome": {"_current_step": {"step_id": "st-1", "tool_name": "execute_curl", "success": False,
                                      "tool_output": "connection refused"}},
    }
    with caplog.at_level(logging.INFO):
        for expected, change in cases.items():
            assert think({**st, **change}, caplog)[2] == expected, expected
        # A CVE id in a target's tool result is no fact (only the run's first attempt ran: "ok"), nor
        # one a finding names without confirming it.
        assert think({**st, "_current_step": {"step_id": "st-2", "tool_name": "execute_nuclei", "success": True,
                                              "tool_output": "[CVE-2021-44228] matched"}}, caplog)[2] == "outcome"
        assert think({**st, "chain_findings_memory": [{"finding_type": "custom",
                                                       "related_cves": ["CVE-2022-0001"]}]}, caplog)[2] is None


def test_what_is_no_fact(caplog):
    st = started(caplog)
    with caplog.at_level(logging.INFO):
        # The run's first attempt that ran is the outcome's first value.
        _, st, reasons = think({**st, "_current_step": {"step_id": "st-0", "tool_name": "execute_curl", "success": True,
                                                        "tool_output": "HTTP/1.1 200 OK"}}, caplog)
        assert reasons == "outcome"
        # A name the vocabulary does not know, a finding type off the list, a tool result's text.
        for change in ({"target_info": {"technologies": ["PostgreSQL 14.2", "AcmeServer 9"],
                                        "vulnerabilities": ["CVE-2024-0007"]}},
                       {"chain_findings_memory": [{"finding_type": "custom", "title": "pwned"},
                                                  {"finding_type": "made_up_type"}]},
                       {"_current_step": {"step_id": "st-1", "tool_name": "execute_curl", "success": True,
                                          "tool_output": "kerberoasting golden ticket WAF blocked"}}):
            assert think({**st, **change}, caplog)[2] is None, change
        # A library tool's result says nothing about the last attempt.
        assert think({**st, "_current_step": {"step_id": "st-3", "tool_name": "tradecraft_lookup", "success": False,
                                              "tool_output": "CVE-1999-1111"}}, caplog)[2] is None


def test_one_search_when_several_facts_change_together(caplog):
    st = started(caplog)
    index = library()
    with caplog.at_level(logging.INFO):
        note, st, reasons = think({**st, "current_phase": "post_exploitation", "attack_path_type": "xss",
                                   "todo_list": [todo("Steal the admin session", "in_progress")],
                                   "target_info": {"technologies": ["PostgreSQL", "MySQL"],
                                                   "vulnerabilities": ["CVE-2024-1111"]}}, caplog, index=index)
    assert reasons == "goal+skill+phase+technology"
    assert len([r for r in caplog.records if "library_now refresh=" in r.getMessage()]) == 1
    assert len(pages_of(note)) <= 3


def test_a_resume_searches_nothing(caplog):
    """A resume runs the think node again on the state saved with the run: the focus it saw is in
    the saved entry, so nothing is searched, and the same block is shown again."""
    st = started(caplog)
    index = library()
    with caplog.at_level(logging.INFO):
        note, resumed, reasons = think(st, caplog, index=index)
    assert reasons is None and index.calls == []
    assert pages_of(note) == ["patt:401", "patt:402", "patt:403"] and entry_of(resumed)["block"] == 1
    assert resumed["tradecraft_hint_count"] == 1 and entry_of(resumed)["shown"] == 2


def test_a_new_message_starts_again(caplog):
    st = started(caplog)
    with caplog.at_level(logging.INFO):
        note, st, reasons = think({**st, "current_objective_index": 1,
                                   "conversation_objectives": [{"content": "x"}, {"content": "now the admin panel"}]},
                                  caplog)
    assert reasons == "start" and goal_line(note) == '  goal: "now the admin panel"'
    assert st["tradecraft_hint_count"] == 1 and st["tradecraft_run_key"] == "objective:1"


def test_the_saved_focus_is_read_like_any_input():
    focus = profile.Focus.from_log({"goal": "a\nb" + "x" * 900, "topic": "not_a_topic", "skill": 7, "phase": None,
                                    "technologies": ["postgresql", 3, None], "cves": ["CVE-2024-1111", "nope"],
                                    "findings": ["access_gained", "made_up"], "outcome": "exploded",
                                    "results": "not a list"})
    assert focus.goal.startswith("a b") and len(focus.goal) == profile.GOAL_CHARS
    assert (focus.topic, focus.skill, focus.phase, focus.outcome, focus.results) == (None, "", "", "", ())
    assert focus.technologies == ("postgresql",) and focus.cves == ("CVE-2024-1111",)
    assert focus.findings == ("access_gained",)
    assert profile.Focus.from_log(None) is None and profile.Focus.from_log(focus.to_log()) == focus
