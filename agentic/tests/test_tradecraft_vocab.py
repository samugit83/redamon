"""The agent's copy of the Tradecraft vocabulary loads, matches the webapp's file, and
its skill topics are the agent's built-in attack skills (so the Intent Router's choice
maps to a topic)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.vocab import load_vocab  # noqa: E402


def _known_attack_paths() -> set[str]:
    import re

    source = (Path(__file__).resolve().parent.parent / "state.py").read_text(encoding="utf-8")
    match = re.search(r"^KNOWN_ATTACK_PATHS\s*=\s*\{([^}]*)\}", source, re.MULTILINE)
    assert match, "KNOWN_ATTACK_PATHS not found in state.py"
    return set(re.findall(r'"([a-z_]+)"', match.group(1)))


def test_loads_with_every_list():
    vocab = load_vocab()
    assert len(vocab.topics) == 21
    assert vocab.kind_ids == ("payloads", "bypasses", "techniques", "tool_commands", "poc", "writeups", "theory", "detection")
    assert len(vocab.recipes) == 10
    assert vocab.technologies and vocab.synonyms
    assert set(vocab.keywords) == set(vocab.topic_ids)
    assert set(vocab.kind_keywords) == set(vocab.kind_ids)
    assert vocab.kind_preference_by_phase["exploitation"] == ("payloads", "poc")


def test_skill_topics_are_the_known_attack_paths():
    assert set(load_vocab().skill_topic_ids) == _known_attack_paths()
    assert len(load_vocab().skill_topic_ids) == 14


def test_resolve_kind():
    vocab = load_vocab()
    assert vocab.resolve_kind("misconfigurations") == "techniques"
    assert vocab.resolve_kind(" PoC ") == "poc"
    assert vocab.resolve_kind("blog") is None


def test_vocab_is_read_only():
    vocab = load_vocab()
    with pytest.raises(TypeError):
        vocab.keywords["sql_injection"] = ("x",)  # type: ignore[index]
    with pytest.raises(TypeError):
        vocab.topics[0]["id"] = "x"  # type: ignore[index]


def test_vocab_matches_the_webapp_copy():
    webapp = Path(__file__).resolve().parents[2] / "webapp" / "src" / "lib" / "tradecraft" / "vocab.json"
    if not webapp.exists():
        pytest.skip("webapp/ is not mounted next to agentic/")
    agent = Path(__file__).resolve().parent.parent / "tradecraft" / "vocab.json"
    assert webapp.read_bytes() == agent.read_bytes()
