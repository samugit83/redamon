"""An approved plugin override of an existing part still applies once the
route-exposure parts exist (plan §23.12).

The override's baseSha256 pins the factory text of the part it replaces, and
the growth bound is a multiple of the whole skill's factory size; adding parts
must change neither for the parts that were already there. The new parts render
factory text beside the override.
"""

import contextvars
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import project_settings  # noqa: E402
from prompts import skill_parts  # noqa: E402
from prompts import skill_part_seam as seam  # noqa: E402


def _load_recorder():
    spec = importlib.util.spec_from_file_location("record_skill_golden", _HERE / "tools" / "record_skill_golden.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recorder = _load_recorder()
GOLDEN = json.loads((_HERE / "fixtures" / "skill_workflow_golden.json").read_text(encoding="utf-8"))
ON = {"ROUTE_EXPOSURE_ENABLED": True}
NEW_PARTS = {
    "access_control": ("route_exposure_leads", "ROUTE EXPOSURE LEADS"),
    "path_traversal": ("exposed_files", "EXPOSED FILES RECON FOUND"),
    "rce": ("route_exposure_consoles", "DEBUG CONSOLES AND ENDPOINTS RECON FOUND"),
}


@pytest.fixture(autouse=True)
def _fresh_cache():
    seam._reset_cache()
    yield
    seam._reset_cache()


def _entry(part, value):
    return {"value": value, "baseSha256": part.sha256, "overrideId": f"ov-{part.key}",
            "changeSetId": "cs-1", "revision": 2, "pluginId": "fixture-plugin"}


def _render(skill, settings, overrides=None):
    bound = dict(settings)
    if overrides is not None:
        bound["SKILL_TEXT_OVERRIDES"] = overrides

    def run():
        project_settings._settings_ctx.set(bound)
        return recorder.render_workflow(skill, bound, recorder.ALL_TOOLS, False, [])
    return contextvars.copy_context().run(run)


# The factory hashes of the parts these skills had before the route-exposure
# parts, recorded from the tree before them. An approved override names one of
# these as its baseSha256; a different hash turns every such override stale.
FACTORY_SHA256 = {
    "access_control/tools": "ae1601af67b9721efea54c5710dc87695f630df2c4fb9876b4eae972cba3c852",
    "path_traversal/tools": "4654c31e2edf56c4cd24703d25a2f993f35b7c1b3821256d7903032d40a6b5ff",
    "path_traversal/php_wrappers": "74794daa59a6a4dd45114b3f71efad5b74a67fa15d62ae231a704001502211eb",
    "path_traversal/oob_workflow": "8b3540fdb1530e5e3defd4169775e67a9ae6a93e517d4c921a6f76af0d1a7728",
    "path_traversal/archive_extraction": "9390cd855453652867ead3e482631115b06d422789ff5768e7f070ec8170b95b",
    "path_traversal/payload_reference": "296e86b8e262e36700d5341432e4c1b2127515bbebeb96e607d0c1f3d03bb75e",
    "rce/tools": "274eef910d4834714c5f251a1631fc2fe0246f6e8b1914139030c269c76ef0d4",
    "rce/oob_workflow": "d25921a83abec9cb36423d2d2a73bd6df8e8f73b68f419b1295248f3a81c104d",
    "rce/deserialization_workflow": "38576f9059ea113b21681f339077ea9a12403a711b9706a387a52df0cb962c84",
    "rce/payload_reference": "3e28d8119f4e0497bb7872acdcca699d7e875909910ab495b1caee782e8c523a",
}


@pytest.mark.parametrize("key", sorted(FACTORY_SHA256))
def test_existing_parts_keep_their_factory_hash(key):
    skill_id, part_id = key.split("/", 1)
    assert skill_parts.get_part(skill_id, part_id).sha256 == FACTORY_SHA256[key]


def test_only_the_route_exposure_and_handling_parts_are_new():
    keys = {p.key for s in NEW_PARTS for p in skill_parts.parts_of(s)}
    assert keys - set(FACTORY_SHA256) == {
        "access_control/route_exposure_leads", "access_control/route_exposure_browser_leads",
        "path_traversal/exposed_files", "path_traversal/git_reconstruct",
        "path_traversal/validate_secrets", "rce/route_exposure_consoles", "rce/heapdump_analysis",
        "access_control/safe_values", "access_control/safe_state",
        "path_traversal/safe_values", "path_traversal/safe_state"}


@pytest.mark.parametrize("skill", sorted(NEW_PARTS))
def test_an_override_of_the_tools_part_applies_beside_the_new_part(skill):
    tools = skill_parts.get_part(skill, "tools")
    overrides = {tools.key: _entry(tools, tools.text + "\nOVERRIDE-MARK")}
    factory = _render(skill, ON)
    got = _render(skill, ON, overrides)
    assert any(p.endswith("OVERRIDE-MARK") for p in got)
    assert len(got) == len(factory)
    part_id, marker = NEW_PARTS[skill]
    new = [p for p in got if marker in p]
    assert new and new == [p for p in factory if marker in p]
    assert all("OVERRIDE-MARK" not in p for p in new)


@pytest.mark.parametrize("skill", sorted(NEW_PARTS))
def test_the_override_also_applies_with_the_module_off(skill):
    tools = skill_parts.get_part(skill, "tools")
    overrides = {tools.key: _entry(tools, tools.text + "\nOVERRIDE-MARK")}
    got = _render(skill, {}, overrides)
    assert any(p.endswith("OVERRIDE-MARK") for p in got)
    assert not any(NEW_PARTS[skill][1] in p for p in got)


@pytest.mark.parametrize("skill", sorted(NEW_PARTS))
def test_the_growth_bound_did_not_shrink(skill):
    """A value at the old bound must still fit: the new parts only add factory size."""
    tools = skill_parts.get_part(skill, "tools")
    others = sum(len(p.text) for p in skill_parts.parts_of(skill) if p.part_id != tools.part_id)
    room = skill_parts.skill_total_limit(skill) - others
    assert skill_parts.validate_skill_total(skill, {"tools": "x" * room}) == []
    assert skill_parts.validate_skill_total(skill, {"tools": "x" * (room + 1)}) != []
