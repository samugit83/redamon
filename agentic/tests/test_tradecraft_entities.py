"""Entities (T2.2): CVE ids by pattern, and technology, product and tool names from the vocabulary
shipped with RedAmon only, never from a project's recon results (Q4 item 4, R-333).
"""

from __future__ import annotations

import ast
import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.ingest import entities  # noqa: E402
from tradecraft.vocab import load_vocab  # noqa: E402

MODULE = Path(__file__).resolve().parent.parent / "tradecraft" / "ingest" / "entities.py"


def test_cve_ids_upper_case_and_once():
    found = entities.find(["cve-2024-23897 and CVE-2024-23897", "see Cve-2021-44228"])
    assert found == ["CVE-2024-23897", "CVE-2021-44228"]


def test_cve_pattern_edge_cases():
    assert entities.cve_ids("CVE-2024-123") == []  # three digits: not an id
    assert entities.cve_ids("CVE-2024-12345678") == []  # eight digits: not an id
    assert entities.cve_ids("CVE-2024-1234567") == ["CVE-2024-1234567"]
    assert entities.cve_ids("XCVE-2024-1234") == []  # part of another word
    assert entities.cve_ids("CVE-2024-12345x") == []
    assert entities.cve_ids("CVE-1850-1234") == []  # no such year
    assert entities.cve_ids("2023/CVE-2023-0001.md") == ["CVE-2023-0001"]  # an archive path
    assert entities.cve_ids("(CVE-2022-0847)") == ["CVE-2022-0847"]


def test_names_come_from_the_vocabulary_lower_case():
    found = entities.find(["Exploiting Jenkins script console with Metasploit", "Postgres and nginx"])
    order = [t["id"] for t in load_vocab().technologies]
    assert found == sorted(["jenkins", "metasploit", "postgresql", "nginx"], key=order.index)
    assert all(f == f.lower() for f in found)


def test_never_from_recon():
    """A name that is not in the shipped vocabulary is ignored, whatever page or project says it;
    the module reads nothing but the vocabulary."""
    assert entities.find(["AcmeCorp TargetServer 3.1 on tc-planted-host"]) == []
    tree = ast.parse(MODULE.read_text())
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not {m for m in imported if m and any(w in m for w in ("graph", "recon", "neo4j", "project_settings"))}


def test_cap_per_card():
    many = " ".join(f"CVE-2024-{1000 + i}" for i in range(200))
    assert len(entities.find([many])) == entities.MAX_PER_CARD


def test_stage_fills_every_card_from_its_fields_and_url():
    cards = [
        {"url": "https://raw.githubusercontent.com/tc/cve/main/2024/CVE-2024-0001.md", "title": "Exploit",
         "breadcrumb": ["2024"], "headings": [{"level": 2, "text": "Jenkins"}], "description": ""},
        {"url": "https://wiki.tc-fixture.test/x/", "title": "Nothing here", "description": "plain words"},
        {"url": "https://wiki.tc-fixture.test/y/", "title": "Redis", "entities": ["CVE-2020-0001"]},
    ]
    state = asyncio.run(entities.extract(SimpleNamespace(cards=cards)))
    assert state.cards[0]["entities"] == ["CVE-2024-0001", "jenkins"]
    assert state.cards[1]["entities"] == []
    assert state.cards[2]["entities"] == ["CVE-2020-0001", "redis"]
