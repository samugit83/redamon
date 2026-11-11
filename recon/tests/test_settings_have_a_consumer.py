"""
L-17: every recon setting the registry declares is read by something that acts on it.

test_settings_mapping_coverage proves each runtime key is LOADED from its
column. That is not the same as being used: `JS_RECON_STANDALONE_CRAWL_DEPTH`
was loaded, documented, bounded, settable over MCP and shown in the form, and
no module ever read it. A key that only `project_settings.py` names is a control
that changes nothing, which is worse than no control: the operator believes the
scan obeys it.

The check is textual on purpose. A consumer reads a key by its literal name
(`settings.get('X')`, `settings['X']`, a module constant `X = _settings['X']`),
so a key whose name appears in no module besides the loader has no consumer.

Run: python -m pytest tests/test_settings_have_a_consumer.py -v
"""
from __future__ import annotations

from pathlib import Path

import pytest

from recon import settings_registry as reg

REPO = Path(__file__).resolve().parents[2]

# The trees a recon setting can be consumed in: the pipeline itself, the graph
# writers it calls, the orchestrator that spawns it, the registry passes
# (stealth, RoE cap, governor) and the scanners it hands values to.
CONSUMER_ROOTS = ("recon", "graph_db", "recon_orchestrator", "recon_settings", "scanners", "agentic")

# Files that name every key without acting on any: the loaders and the
# generated RoE prompt.
NOT_CONSUMERS = {"project_settings.py", "roe_parse_prompt.py"}

# Dead toggles found by this test outside the change that added it. Each is a
# real bug, pinned so fixing it turns the test red until the marker goes.
KNOWN_UNCONSUMED = {
    "RESOURCE_ENUM_AI_TOOL_ARG_PATH_ENABLED":
        "resource_enum.py says the tool-arg-path resolver is a stub; the toggle reaches nothing",
    "IP_HOSTNAME_INCLUDE": "consumed from P3/P4/P5 (ip_mode plan)",
    "IP_HOSTNAME_EXCLUDE": "consumed from P3/P4/P5 (ip_mode plan)",
    "IP_HOSTNAME_PASSIVE_EXPAND": "consumed from P3/P4/P5 (ip_mode plan)",
    "IP_HOSTNAME_SCAN_ALL_CONFIRMED": "consumed from P3/P4/P5 (ip_mode plan)",
    "IP_HOSTNAME_MAX_SCANNED": "consumed from P3/P4/P5 (ip_mode plan)",
    "IP_HOSTNAME_PASSIVE_MAX_NAMES": "consumed from P3/P4/P5 (ip_mode plan)",
}


def _consumer_text() -> str:
    parts = []
    for root in CONSUMER_ROOTS:
        for path in (REPO / root).rglob("*.py"):
            if path.name in NOT_CONSUMERS or "tests" in path.parts or path.name.startswith("test_"):
                continue
            if any(p.startswith(".") or p in ("node_modules", "__pycache__") for p in path.parts):
                continue
            parts.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(parts)


CONSUMERS = _consumer_text()
RUNTIME_KEYS = sorted(reg.by_runtime_key())


def test_the_scan_found_the_consumers():
    """An empty scan would make every key below look unconsumed, or every
    assertion vacuous if inverted."""
    assert len(RUNTIME_KEYS) > 400
    assert "KATANA_DEPTH" in CONSUMERS and "NUCLEI_RATE_LIMIT" in CONSUMERS


@pytest.mark.parametrize("key", [
    pytest.param(k, marks=pytest.mark.xfail(strict=True, reason=KNOWN_UNCONSUMED[k]))
    if k in KNOWN_UNCONSUMED else k
    for k in RUNTIME_KEYS
])
def test_every_registry_runtime_key_has_a_consumer(key):
    assert key in CONSUMERS, (
        f"{key} is loaded by project_settings.py and read by nothing: wire it to the "
        "module it configures, or remove the setting from every layer "
        "(registry, Prisma, project_settings, form, presets)."
    )


@pytest.mark.parametrize("column", [
    "katanaScope", "jsReconStandaloneCrawlDepth", "jsReconStandaloneCrawlScope",
    "aiSurfaceReconCacheEnabled",
])
def test_the_retired_columns_configure_nothing(column):
    """The four L-17 controls had no consumer and no safe one to give them.

    Their columns stay so an upgrade or a rollback drops no data, but no
    surface offers them: no runtime key, closed on MCP, no form input.
    """
    spec = reg.field(column)
    assert spec["runtime_key"] is None
    assert spec["mcp"] == "never"
    assert spec["form_section"] is None
    assert spec["group"] == "retired"
