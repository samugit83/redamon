"""The hint checkpoints (T8.1, Q6, R-364): the skill chosen or changed, the phase changed, a new
technology or CVE, a tool result that shows a block, and none repeated after a resume, which keeps
the profile in the run's saved hint log; a new message starts again.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_tradecraft_hints import hint, library, state  # noqa: E402
from tradecraft.library import profile  # noqa: E402


def think(st, **kw):
    """One think: the note and the state as the think node leaves it."""
    note, updates = hint(st, **kw)
    return note, {**st, **updates}


def started():
    _, st = think(state())
    return st


def header(note):
    return note.splitlines()[0] if note else None


def test_skill_chosen_at_the_start():
    note, st = think(state())
    assert header(note) == "Library suggestions (SQL injection · PostgreSQL):"
    assert st["tradecraft_hint_count"] == 1
    # An unclassified run has no topic: nothing at the start.
    assert think(state(attack_path_type="user_skill:abc"))[0] is None


def test_skill_changes():
    st = started()
    note, st = think({**st, "attack_path_type": "xss"})
    assert header(note) == "Library suggestions (XSS · PostgreSQL):" and st["tradecraft_hint_count"] == 2
    assert profile.checkpoints(profile.build(state(), None), profile.build(state(attack_path_type="xss"), None)) \
        == ("skill",)


def test_phase_changes():
    st = started()
    note, st = think({**st, "current_phase": "post_exploitation"})
    assert note is not None and st["tradecraft_hint_count"] == 2


def test_new_technology_or_cve():
    st = started()
    note, st = think({**st, "target_info": {"technologies": ["PostgreSQL 14", "nginx 1.25"], "vulnerabilities": []}})
    assert header(note) == "Library suggestions (SQL injection · PostgreSQL · nginx):"
    # A name the vocabulary does not know is no technology, so no checkpoint.
    assert think({**st, "target_info": {"technologies": ["PostgreSQL 14", "nginx 1.25", "AcmeServer"],
                                        "vulnerabilities": []}})[0] is None
    note, st = think({**st, "target_info": {"technologies": ["PostgreSQL 14", "nginx 1.25"],
                                            "vulnerabilities": ["CVE-2024-23897"]}})
    assert header(note) == "Library suggestions (SQL injection · PostgreSQL · nginx · CVE-2024-23897):"
    # A CVE id in a target's tool result is one too.
    note, st = think({**st, "_current_step": {"step_id": "st-9", "tool_name": "execute_nuclei",
                                              "tool_output": "[CVE-2021-44228] matched"}})
    assert note is not None and "CVE-2021-44228" in header(note) and st["tradecraft_hint_count"] == 4


def test_a_block_seen():
    st = started()
    note, st = think({**st, "_current_step": {"step_id": "st-1", "tool_name": "execute_curl",
                                              "tool_output": "<title>Attention Required! | Cloudflare</title>"}})
    assert header(note) == "Library suggestions (SQL injection · PostgreSQL · WAF seen):"
    # The profile has the block now: a second one is no new checkpoint.
    assert think({**st, "_current_step": {"step_id": "st-2", "tool_name": "execute_curl",
                                          "tool_output": "HTTP/1.1 403 Forbidden"}})[0] is None


def test_no_repeat_after_a_resume():
    """A resume runs the think node again on the state saved with the run: the checkpoints it
    met are in the saved profile, so no note repeats and nothing changes."""
    st = started()
    st = {**st, "current_phase": "post_exploitation",
          "_current_step": {"step_id": "st-1", "tool_name": "execute_curl", "tool_output": "HTTP/1.1 403 Forbidden"}}
    note, resumed_from = think(st)
    assert note is not None
    assert hint(resumed_from) == (None, {})


def test_a_new_message_starts_again():
    st = started()
    note, st = think({**st, "current_objective_index": 1,
                      "conversation_objectives": [{"content": "x"}, {"content": "now the admin panel"}]})
    assert header(note) == "Library suggestions (SQL injection · PostgreSQL):"
    assert st["tradecraft_hint_count"] == 1 and st["tradecraft_run_key"] == "objective:1"


def test_one_note_when_checkpoints_meet():
    st = started()
    index = library(n=20)
    note, st = think({**st, "current_phase": "post_exploitation", "attack_path_type": "xss",
                      "target_info": {"technologies": ["PostgreSQL", "MySQL"], "vulnerabilities": ["CVE-2024-1111"]},
                      "_current_step": {"step_id": "st-1", "tool_name": "execute_curl", "tool_output": "blocked"}},
                     index=index)
    assert header(note) == "Library suggestions (XSS · PostgreSQL · MySQL · CVE-2024-1111 · WAF seen):"
    assert st["tradecraft_hint_count"] == 2
    assert len([ln for ln in note.splitlines()[1:] if ln.strip().startswith("patt:")]) <= 3 * 2
