"""The readiness line of the ingestion report (Q4, T5.1): the share of kept pages with a real
title, headings, a description and a topic, and the suggestion when one is low.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.contract import IngestionReport  # noqa: E402
from tradecraft.ingest import report  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract"


def card(title_source="guessed", headings=(), description="", topics=(), status="kept"):
    return {"title_source": title_source, "headings": list(headings), "description": description,
            "topics": list(topics), "status": status}


FOUR = [
    card("real", [{"level": 1, "text": "A"}], "one line", ["sql_injection"]),
    card("renamed", [{"level": 2, "text": "B"}], "", ["xss"]),
    card("real", [], "", ["ssrf"]),
    card("guessed", [], "", ["rce"]),
    # A dropped page is not part of what search reads: it counts nowhere.
    card("guessed", [], "", [], status="dropped"),
]


def test_readiness_numbers():
    line = report.readiness(FOUR, "stored", "mkdocs-wiki")
    assert line["realTitlesPct"] == 75 and line["headingsPct"] == 50
    assert line["descriptionPct"] == 25 and line["taggedPct"] == 100


def test_suggestion_for_a_live_resource_is_stored_mode():
    line = report.readiness(FOUR, "live", "mkdocs-wiki")
    assert line["suggestStored"] == 1 and "suggestContentChecks" not in line


def test_suggestion_for_a_stored_resource_is_a_focus_with_content_checks():
    for mode, site in (("stored", "mkdocs-wiki"), ("live", "pdf")):
        line = report.readiness(FOUR, mode, site)
        assert line["suggestContentChecks"] == 1 and "suggestStored" not in line


def test_no_suggestion_when_every_share_is_at_least_half():
    good = [card("real", [{"level": 1, "text": "x"}], "d", ["xss"]), card("guessed", [{"level": 1, "text": "y"}], "d", [])]
    line = report.readiness(good, "live", "website")
    assert line == {"realTitlesPct": 50, "headingsPct": 100, "descriptionPct": 100, "taggedPct": 50}


def test_nothing_kept_has_no_line():
    assert report.readiness([], "live", "cve-poc-db") == {}
    assert report.readiness([card(status="dropped")], "live", "website") == {}


@pytest.mark.parametrize("cards", [FOUR, [card("real", [{"level": 1, "text": "x"}], "d", ["xss"])]])
def test_the_line_fits_the_contract(cards):
    """The contract's readiness holds numbers only, under the fixture's keys."""
    fixture = json.loads((FIXTURES / "IngestionReport.valid.json").read_text())
    line = report.readiness(cards, "live", "website")
    validated = IngestionReport.model_validate({**fixture, "readiness": line}).readiness
    assert validated == line
    assert set(fixture["readiness"]) <= set(line)
    assert all(isinstance(v, int) and 0 <= v <= 100 for v in line.values())
