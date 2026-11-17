"""The 2.0 registry entries (T2.6): the decision guide of Q3 (R-323), the resource list in Auto,
Full or One line (R-353, R-414), always inside an untrusted block, the shape every registry entry
has, and a 1.x run's prompt and tools unchanged (TD-10, R-I5).
"""

from __future__ import annotations

import contextvars
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from prompts import tool_registry as tr  # noqa: E402
from tradecraft import overlay, runtime  # noqa: E402
from tradecraft.contract import V2Catalog  # noqa: E402

OWNER = "u-owner"
LONG = ("A synthetic wiki of offensive notes covering SQL injection, XSS, SSRF and Kerberos attacks with "
        "payloads, cheat sheets and step by step methodology for lab targets only.")


def catalog(n, **search):
    return V2Catalog.model_validate({
        "v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None, "search": search,
        "resources": [{"id": f"r{i}", "slug": f"lib-{i:02d}", "name": f"Library {i}", "url": f"https://l{i}.tc-fixture.test/",
                       "type": "mkdocs-wiki", "storage_mode": "live", "summary": f"{LONG} ({i})", "map_version": 3}
                      for i in range(n)]})


def untrusted_block(desc):
    m = re.search(r"<<<UNTRUSTED_TRADECRAFT_CATALOG id=([0-9a-f]+)>>>\n(.*)\n<<<END_UNTRUSTED_TRADECRAFT_CATALOG id=\1>>>",
                  desc, re.DOTALL)
    assert m, "the resource list is inside its untrusted block"
    return m.group(2)


def test_decision_guide():
    entries = overlay.build_entries(catalog(2, **{"librarian.use": "search_only"}))
    for name in ("tradecraft_lookup", "tradecraft_search"):
        desc = entries[name]["description"]
        assert "How to choose" in desc
        assert "don't call; use web_search" in desc
        assert "tradecraft_lookup(page=...)" in desc and "tradecraft_search, then tradecraft_lookup" in desc
        # Library now (owner decision 2026-11-17): the block names the pages that fit the step.
        assert '"Library now" or an earlier result names a page that fits your step' in desc
        # Search only: the librarian is not in this run, and no line sends the agent to it.
        assert "tradecraft_ask" not in desc
    # Agent decides (the default): the librarian's branch (T7.4), with no trigger tied to a topic.
    for name, entry in overlay.build_entries(catalog(2)).items():
        assert not re.search(r"WAF|SLEEP|blocks", entry["description"]), name
        if name != "tradecraft_ask":
            assert "you cannot tell what fits, or search shows only related pages ... tradecraft_ask" in entry["description"]
    # Hints off: no Library now block in this run, so the guide does not name one.
    for entry in overlay.build_entries(catalog(2, **{"hints.enabled": False})).values():
        assert "Library now" not in entry["description"]


def test_auto_list():
    ten = untrusted_block(overlay.build_entries(catalog(10))["tradecraft_lookup"]["description"])
    assert LONG.split()[0] in ten and "(9)" in ten and ten.count("- `lib-") == 10
    assert "payloads, cheat sheets and step by step" in ten.replace("\n    ", " ")
    eleven_desc = overlay.build_entries(catalog(11))["tradecraft_lookup"]["description"]
    eleven = untrusted_block(eleven_desc)
    lines = eleven.splitlines()
    assert len(lines) == 11
    assert lines[0] == "- `lib-00` Library 0 (wiki): " + " ".join(LONG.split()[:12]) + "…"
    assert "full summary" in eleven_desc and 'path=""' in eleven_desc


def test_list_modes():
    full = untrusted_block(overlay.build_entries(catalog(15, **{"prompt.resourceList": "full"}))
                           ["tradecraft_lookup"]["description"])
    assert full.count("- `lib-") == 15 and "(14)" in full
    one = untrusted_block(overlay.build_entries(catalog(2, **{"prompt.resourceList": "one_line"}))
                          ["tradecraft_lookup"]["description"])
    assert len(one.splitlines()) == 2 and "(1)" not in one
    assert overlay.scope_of("") == "(no summary)" and overlay.scope_of("a b c") == "a b c"


def test_sixty_resources_stay_small():
    """AC-64 (the list's part): 60 resources on one line each, about 25 tokens a line."""
    block = untrusted_block(overlay.build_entries(catalog(60))["tradecraft_lookup"]["description"])
    lines = block.splitlines()
    assert len(lines) == 60 and max(len(line) for line in lines) <= 120
    assert len(block) / 4 <= 60 * 30


def test_entries_shape():
    """The rules of test_tool_registry_completeness.py for every overlay entry."""
    for name, entry in overlay.build_entries(catalog(3)).items():
        assert set(entry) == {"purpose", "when_to_use", "args_format", "description"}, name
        assert all(isinstance(v, str) and v for v in entry.values()), name
        assert len(entry["description"]) >= 100 and entry["description"].lstrip().startswith(f"**{name}**")
    assert '"page": "slug:N"' in overlay.lookup_entry(catalog(1))["args_format"]
    assert overlay.build_entries(catalog(0)) == {}


def test_registry_order_with_search():
    def go():
        runtime.bind_run_catalog(catalog(2).model_dump())
        return list(tr.visible_registry())

    names = contextvars.Context().run(go)
    assert names.count("tradecraft_lookup") == 1 and names.index("tradecraft_search") == names.index("tradecraft_lookup") + 1


def test_1x_run_unchanged(monkeypatch):
    """With a 1.x catalog (TRADECRAFT_V2 off) the prompt's registry and the allowed tools are
    what they were before the companion set existed."""
    def allowed(phase_map, v2):
        ps._settings_ctx.set({"TOOL_PHASE_MAP": phase_map, "TRADECRAFT_V2": v2})
        return {p: ps.get_allowed_tools_for_phase(p) for p in ("informational", "exploitation", "post_exploitation")}

    phase_map = {"tradecraft_lookup": ["exploitation", "post_exploitation"], "query_graph": ["informational"]}
    run = contextvars.Context().run
    now = run(allowed, phase_map, False)
    missing = contextvars.Context().run(lambda: (ps._settings_ctx.set({"TOOL_PHASE_MAP": phase_map}),
                                                 ps.get_allowed_tools_for_phase("exploitation"))[1])
    monkeypatch.setattr(ps, "TRADECRAFT_COMPANION_TOOLS", frozenset())
    before = run(allowed, phase_map, False)
    assert now == before and "tradecraft_search" not in missing
    assert contextvars.Context().run(lambda: tr.visible_registry()) is tr.TOOL_REGISTRY
