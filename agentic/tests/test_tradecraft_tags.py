"""Tags by rules (T2.2): topics, kinds and technologies from the vocabulary's words, matched in a
card's title, breadcrumb and headings (Q4 "Every page is tagged", R-008, R-332, R-337).

The model pass for what the rules leave (``tag_by_model``) is T5.1's and is tested in
``test_tradecraft_title_triage.py``; here the rules run with no model to call.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.ingest import tags  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft.vocab import load_vocab  # noqa: E402


def test_sql_and_sqli_mean_sql_injection():
    for title in ("SQL Injection", "sqli cheat sheet", "Blind SQL tricks", "sql-injection/union", "SQLi"):
        assert "sql_injection" in tags.classify(title).topics, title


def test_kerberos_means_active_directory():
    assert tags.classify("Kerberos: Kerberoasting").topics == ("active_directory",)
    assert "active_directory" in tags.classify("Golden ticket", breadcrumb=["kerberos"]).topics


def test_breadcrumb_and_headings_count_too():
    found = tags.classify("Notes", breadcrumb=["Web", "SSRF"], headings=["Cloud metadata endpoints"])
    assert "ssrf" in found.topics


def test_kind_keywords():
    assert tags.classify("XSS cheat sheet").kinds == ("payloads",)
    assert "bypasses" in tags.classify("WAF bypass for SQLi").kinds
    assert "techniques" in tags.classify("Kerberoasting methodology").kinds
    assert "writeups" in tags.classify("A walkthrough of a lab").kinds
    assert "poc" in tags.classify("Proof of concept").kinds


def test_plural_forms_match():
    assert "payloads" in tags.classify("Payload").kinds
    assert "techniques" in tags.classify("Attacks on delegation").kinds
    assert "containers" in tags.classify("Pods and kubelets").topics


def test_technology_names_and_aliases():
    found = tags.classify("Time-based blind on Postgres", headings=["MSSQL", "Microsoft SQL Server stacked"])
    assert set(found.technologies) == {"postgresql", "mssql"}
    assert tags.classify("Apache Tomcat manager").technologies == ("apache", "tomcat")


def test_whole_words_only():
    assert "sql_injection" not in tags.classify("MySQL hardening").topics
    assert tags.classify("MySQL hardening").technologies == ("mysql",)
    assert tags.classify("Adobe products overview").topics == ()
    assert tags.classify("Strategies").kinds == ()


def test_every_tag_is_a_vocabulary_id():
    vocab = load_vocab()
    texts = ["SQL injection payloads", "Kerberos delegation abuse", "SSRF to cloud metadata on AWS", "XXE OOB",
             "Linux privilege escalation with sudo", "Docker container escape", "nmap usage"]
    for text in texts:
        found = tags.classify(text)
        assert set(found.topics) <= set(vocab.topic_ids)
        assert set(found.kinds) <= set(vocab.kind_ids)
        assert set(found.technologies) <= {t["id"] for t in vocab.technologies}


def _state(cards, tag_every_page="rules_model"):
    async def no_model():
        return None

    return SimpleNamespace(cards=cards, settings=EffectiveSettings({"focus.tagEveryPage": tag_every_page}),
                           llm_calls=0, model_calls=[], entries=[], model=no_model)


def test_stage_tags_every_card_and_keeps_existing_tags():
    cards = [
        {"url": "u1", "title": "SQLi union based", "breadcrumb": ["web"], "headings": [{"level": 2, "text": "WAF bypass"}]},
        {"url": "u2", "title": "About us", "breadcrumb": [], "headings": []},
        {"url": "u3", "title": "Kerberoasting", "topics": ["active_directory"], "kinds": ["poc"]},
    ]
    state = asyncio.run(tags.tag(_state(cards)))
    first, second, third = state.cards
    assert first["topics"] == ["sql_injection"] and first["kinds"] == ["bypasses"]
    # A page the rules cannot classify keeps no topic: the model pass (T5.1) tags it.
    assert second["topics"] == [] and second["kinds"] == []
    assert third["topics"] == ["active_directory"] and third["kinds"] == ["poc"]


def test_rules_only_never_builds_a_model():
    """R-338: "Rules only" asks no model, and a page the rules classify never needs one."""
    class NoModel:
        async def model(self):  # would be the resource's model
            raise AssertionError("the rules-only stage must not build a model")

    cases = (("rules", [{"url": "u", "title": "About us"}]),
             ("rules_model", [{"url": "u", "title": "SQLi union based"}]))
    for mode, cards in cases:
        state = _state(cards, mode)
        state.model = NoModel().model
        asyncio.run(tags.tag(state))
        assert state.llm_calls == 0


def test_headings_as_strings_or_dicts():
    assert tags.heading_texts([{"level": 1, "text": "SSRF"}, "XSS", {"level": 2}]) == ["SSRF", "XSS"]
