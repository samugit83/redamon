"""The Tradecraft tools' default phases (owner decision 2026-11-17, FIX-PHASES; R-321).

A project created after the change offers ``tradecraft_lookup``, ``tradecraft_search`` and
``tradecraft_ask`` in every phase, informational included, while the run's owner has an active
resource, and in no phase without one. A project created without a map stores the Prisma default;
one created from the form stores the agent's ``/defaults`` (``DEFAULT_AGENT_SETTINGS``); both are
read here through ``fetch_agent_settings``, with the webapp's answers faked.

The agent reads the stored map as it is, never merged with the defaults: a project that kept the
old row offers nothing in informational, and a map with no row offers the tools in no phase.
"""

from __future__ import annotations

import contextvars
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from prompts.base import build_tool_name_enum  # noqa: E402
from tradecraft import runtime  # noqa: E402

REGISTRY = Path(__file__).resolve().parents[2] / "recon_settings" / "registry.json"
PHASES = ["informational", "exploitation", "post_exploitation"]
TOOLS = ["tradecraft_lookup", "tradecraft_search", "tradecraft_ask"]
OWNER = "u-owner"


def prisma_default() -> dict:
    """The map Postgres stores for a project created without one (the registry joins the
    Prisma @default; build.py --check keeps it equal to schema.prisma)."""
    if not REGISTRY.exists():
        pytest.skip("recon_settings/registry.json not in this checkout")
    return json.loads(json.load(open(REGISTRY, encoding="utf-8"))["fields"]["agentToolPhaseMap"]["default"])


def catalog(resources: int = 1):
    # The coverage map off: binding it would query the page store.
    return {"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None,
            "search": {"prompt.coverageMap": False, "librarian.use": "agent"},
            "resources": [{"id": f"r{i}", "slug": f"lib-{i}", "name": f"Library {i}",
                           "url": f"https://l{i}.tc-fixture.test/", "type": "mkdocs-wiki",
                           "storage_mode": "live", "summary": "Synthetic notes for lab targets.",
                           "map_version": 3} for i in range(resources)]}


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


def load(stored_map, cat) -> dict:
    """``fetch_agent_settings`` for a project holding ``stored_map``, its owner's run catalog ``cat``."""
    project = {"id": "p-1", "userId": OWNER, "agentToolPhaseMap": stored_map}

    def get(url, **_kw):
        if "/tradecraft/catalog" in url:
            return _Resp(cat)
        if "/api/projects/" in url:
            return _Resp(project)
        return _Resp([] if "/llm-providers" in url else {})

    with patch("requests.get", new=get):
        return ps.fetch_agent_settings("p-1", "http://webapp.tc-fixture.test")


def offered(settings: dict, phase: str) -> list[str]:
    """The Tradecraft tools a run of ``settings`` offers in ``phase``: in the model's tool enum (a
    phase's allowed tools that the run's registry describes) and let through the executor's phase gate."""
    def go():
        ps._settings_ctx.set(settings)
        runtime.bind_run_catalog(settings.get("TRADECRAFT_CATALOG"))
        enum = build_tool_name_enum(ps.get_allowed_tools_for_phase(phase)).split(", ")
        return [t for t in TOOLS if t in enum and ps.is_tool_allowed_in_phase(t, phase)]

    return contextvars.Context().run(go)


def test_a_project_created_after_the_change_offers_the_library_in_every_phase():
    for stored in (prisma_default(), ps.DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"]):
        settings = load(stored, catalog())
        assert settings["TOOL_PHASE_MAP"]["tradecraft_lookup"] == PHASES
        for phase in PHASES:
            assert offered(settings, phase) == TOOLS, phase


def test_no_active_resource_offers_none_in_any_phase():
    # No resource active for the run, and no 2.0 catalog at all.
    for cat in (catalog(resources=0), None):
        settings = load(prisma_default(), cat)
        for phase in PHASES:
            assert offered(settings, phase) == [], (phase, cat)


def test_a_project_that_kept_the_old_row_or_has_none_reads_as_stored():
    kept = load({**prisma_default(), "tradecraft_lookup": ["exploitation", "post_exploitation"]}, catalog())
    assert offered(kept, "informational") == []
    assert offered(kept, "exploitation") == TOOLS and offered(kept, "post_exploitation") == TOOLS
    no_row = load({k: v for k, v in prisma_default().items() if k != "tradecraft_lookup"}, catalog())
    assert "tradecraft_lookup" not in no_row["TOOL_PHASE_MAP"]
    for phase in PHASES:
        assert offered(no_row, phase) == [], phase
