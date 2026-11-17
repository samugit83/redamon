"""The agent's second clamp of the Tradecraft settings and the fixed constants.

Whatever a job carries, every numeric ends between its minimum and its ceiling, every
enum inside its values, every text and list inside its limits, and unknown keys are
dropped (§5 "A hard ceiling on every numeric setting ... enforced by the agent", R-122).
The constants are the §5, Q11 and Q12 values the plan fixes in code.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import settings  # noqa: E402
from tradecraft.settings import EffectiveSettings, clamp, constant, load_spec  # noqa: E402

SPEC = load_spec()
NUMERIC = [s for s in SPEC["settings"] if s["type"] in ("int", "number")]


def test_clamps_every_numeric():
    assert len(NUMERIC) > 40
    for s in NUMERIC:
        key = s["key"]
        assert clamp({key: s["ceiling"] + 1})[key] == s["ceiling"], key
        assert clamp({key: 10**12})[key] == s["ceiling"], key
        assert clamp({key: s["min"] - 1})[key] == s["min"], key
        assert clamp({key: s["default"]})[key] == s["default"], key


def test_numeric_of_the_wrong_type_is_dropped():
    for bad in ("200", None, True, float("nan"), float("inf"), [200]):
        assert clamp({"crawl.maxPages": bad}) == {}, bad
    assert clamp({"crawl.maxPages": 199.6}) == {"crawl.maxPages": 200}
    assert clamp({"crawl.delaySec": 0.5}) == {"crawl.delaySec": 0.5}


def test_enums_strings_lists_and_bools():
    assert clamp({"crawl.strategy": "magic"}) == {}
    assert clamp({"crawl.strategy": "rules"}) == {"crawl.strategy": "rules"}
    assert clamp({"fetching.userAgent": "x" * 500}) == {"fetching.userAgent": "x" * 200}
    assert clamp({"crawl.requireTitle": "yes"}) == {}
    excluded = clamp({"crawl.excludePaths": ["/a/", "/a/", "", 7, "y" * 300] + [f"/p{i}/" for i in range(300)]})
    paths = excluded["crawl.excludePaths"]
    assert paths[:2] == ["/a/", "y" * 200]
    assert len(paths) == 200
    detectors = clamp({"detection.enabledDetectors": ["github", "wordpress", "cve"]})
    assert detectors == {"detection.enabledDetectors": ["github", "cve"]}


def test_unknown_keys_dropped():
    # Keys no spec entry names (an old release's, or a typo) are dropped, never passed on.
    assert clamp({"crawl.lifetimeSec": 3600, "TRADECRAFT_SOMETHING_SEC": 1, "crawl.maxPages": 10}) == {"crawl.maxPages": 10}


def test_effective_settings_fills_defaults_and_types():
    eff = EffectiveSettings({"crawl.maxPages": 9999, "crawl.strategy": "auto", "search.results": 3})
    assert eff.int("crawl.maxPages") == 500
    assert eff.str("crawl.strategy") == "auto"
    assert eff.int("crawl.maxDepth") == 3
    assert eff.bool("crawl.requireTitle") is True
    assert eff.list("knownTypes.githubFileTypes") == [".md", ".txt", ".rst"]
    assert eff.number("crawl.delaySec") == 0.0
    # A search value does not leak into an ingestion job, and the other scope is not readable here.
    with pytest.raises(KeyError):
        eff.get("search.results")
    with pytest.raises(KeyError):
        eff.get("crawl.noSuchKey")
    with pytest.raises(TypeError):
        eff.int("crawl.strategy")


def test_effective_settings_values_are_copies():
    eff = EffectiveSettings()
    eff.list("crawl.excludePaths").append("mutated")
    eff.values["crawl.excludePaths"].append("mutated")
    assert "mutated" not in eff.list("crawl.excludePaths")
    assert "mutated" not in settings.default("crawl.excludePaths")


def test_search_scope():
    eff = EffectiveSettings({"search.results": 50, "hints.perRun": -3, "crawl.maxPages": 10}, scope="search")
    assert eff.int("search.results") == 20
    assert eff.int("hints.perRun") == 0
    assert eff.int("reading.charsPerRead") == 12000
    with pytest.raises(KeyError):
        eff.get("crawl.maxPages")


def test_crawl_default_pages_200():
    assert settings.default("crawl.maxPages") == 200
    assert EffectiveSettings().int("crawl.maxPages") == 200


def test_ceilings_are_constants():
    """Every limit is a value of the spec, never read from the environment (§2, R-003)."""
    for s in NUMERIC:
        assert isinstance(s["ceiling"], (int, float)) and s["max"] <= s["ceiling"], s["key"]
    for path in (Path(settings.__file__), Path(settings.__file__).with_name("vocab.py")):
        source = path.read_text(encoding="utf-8")
        assert not re.search(r"\bos\.environ\b|\bgetenv\b|\benviron\b", source), path.name
    # The ceilings named by the feature document (OQ-2, EX-2).
    ceilings = {s["key"]: s["ceiling"] for s in NUMERIC}
    assert ceilings["crawl.maxPages"] == 500
    assert ceilings["crawl.timeBudgetSec"] == 1800
    assert ceilings["crawl.parallel"] == 8
    assert ceilings["storage.maxPageKb"] == 2048
    assert ceilings["storage.maxResourceMb"] == 500
    assert ceilings["storage.maxPages"] == 20000
    assert ceilings["storage.userQuotaMb"] == 10240
    assert ceilings["fetching.browserMaxChars"] == 1_000_000


def test_security_constants():
    """§5's limits, the install's storage ceiling (OQ-26) and the synchronous deadlines (D-52)."""
    assert constant("maxRedirects") == 5
    assert constant("sitemapMaxBytes") == 10 * 1024 * 1024
    assert constant("sitemapMaxDepth") == 2
    assert constant("sitemapMaxChildren") == 20
    assert constant("githubArchiveMaxBytes") > 0
    assert constant("browserScriptMaxSec") == 60
    assert constant("userStoredBytesCeiling") == 10 * 1024**3
    assert constant("instanceStoredBytesCeiling") == 20 * 1024**3
    assert settings.setting("storage.userQuotaMb")["ceiling"] * 1024 * 1024 == constant("userStoredBytesCeiling")
    assert constant("checkUrlDeadlineSec") == 60
    assert constant("focusPreviewDeadlineSec") == 120
    assert constant("readNowDeadlineSec") == 45
    assert constant("webappDeadlineMarginSec") == 15
    assert constant("jobsPerAgent") == 2
    assert constant("jobLeaseSec") == 60
    assert constant("jobLeaseRenewSec") == 20
    assert constant("dbPoolSize") == 5
    assert constant("maxResourcesPerUser") == 200
    assert constant("purgeBatchRows") == 5000


def test_query_constants():
    """The values Q11 lists as "Fixed in code" and the plan's query limits (R-417)."""
    assert constant("searchWordings") == 6
    assert constant("resultsPerWording") == 20
    assert constant("mergedCandidates") == 40
    assert constant("librarianSectionChars") == 3000
    assert constant("librarianSecondTries") == 1
    assert constant("librarianPagesReturned") == 3
    assert constant("librarianAnswerMaxChars") == 6000
    assert constant("codeBlocksPerRead") == 5
    assert constant("coverageMapMaxTopics") == 20
    assert constant("fullSummaryMaxResources") == 10
    assert constant("pagesPerHint") == 3
    assert constant("cardPassMaxPages") == 500
    assert constant("folderDescriptionCalls") == 10
    assert constant("maxUserSynonyms") == 200
    assert constant("maxUserRecipes") == 50


def test_site_type_keys():
    assert settings.site_type_key("mkdocs-wiki") == "wiki"
    assert settings.site_type_key("agentic-crawl") == "website"
    assert settings.site_type_key("nope") is None


def test_spec_matches_the_webapp_copy():
    webapp = Path(__file__).resolve().parents[2] / "webapp" / "src" / "lib" / "tradecraft" / "settingsSpec.json"
    if not webapp.exists():
        pytest.skip("webapp/ is not mounted next to agentic/")
    assert webapp.read_bytes() == Path(settings.__file__).with_name("settings_spec.json").read_bytes()
