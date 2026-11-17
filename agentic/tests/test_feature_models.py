"""`agentic/feature_models.py`, the Python mirror of the webapp's feature registry."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "agentic"))

from feature_models import FEATURE_IDS, feature_model  # noqa: E402

WEBAPP_REGISTRY = REPO_ROOT / "webapp" / "src" / "lib" / "llmFeatures.ts"


def test_the_ten_ids():
    # The section picker left with 1.x at the cut-over (T9.3, R-401), on both sides at once.
    assert FEATURE_IDS == (
        "roe_parse", "preset_generator", "triage", "codefix", "command_whisperer",
        "tradecraft_librarian", "report_narratives", "multi_mute", "skill_metadata", "navigator",
    )


def test_the_librarian_model_is_read_like_any_feature():
    """T7.1: the agent's librarian (T7.4) reads the owner's model under this id; none set is ""."""
    assert feature_model({"featureModels": {"tradecraft_librarian": " gpt-4o-mini "}}, "tradecraft_librarian") == "gpt-4o-mini"
    assert feature_model({"featureModels": {"tradecraft_section_picker": "m"}}, "tradecraft_librarian") == ""
    # A model a person saved for the 1.x section picker is no feature's any more.
    assert feature_model({"featureModels": {"tradecraft_section_picker": "m"}}, "tradecraft_section_picker") == ""


def test_the_ids_match_the_webapp_registry():
    """Two copies of one list drift; this is where they would."""
    if not WEBAPP_REGISTRY.exists():
        pytest.skip("webapp registry not present in this checkout")
    source = WEBAPP_REGISTRY.read_text(encoding="utf-8")
    union = re.search(r"type FeatureId\s*=((?:\s*\|?\s*'[a-z_]+')+)", source)
    assert union, "FeatureId union not found in llmFeatures.ts"
    webapp_ids = set(re.findall(r"'([a-z_]+)'", union.group(1)))
    assert webapp_ids == set(FEATURE_IDS)


def test_a_saved_model_is_returned():
    assert feature_model({"featureModels": {"triage": "gpt-5-mini"}}, "triage") == "gpt-5-mini"


@pytest.mark.parametrize("settings", [
    None, {}, {"featureModels": None}, {"featureModels": []},
    {"featureModels": {"triage": 3}}, {"featureModels": {"codefix": "x"}},
])
def test_unset_or_malformed_is_empty(settings):
    assert feature_model(settings, "triage") == ""


def test_an_unknown_feature_is_empty_even_when_stored():
    assert feature_model({"featureModels": {"graph_query": "x"}}, "graph_query") == ""
