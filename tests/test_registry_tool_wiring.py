"""
T10, T11, T13: every module, wrapper and graph writer a tool claims is importable.

The TypeScript side checks the links it can see from a file listing: an image in
the pull list, a section file on disk, a partial-recon module by name. It cannot
import Python, so the half that matters most is here.

`isolated_fn` is the one worth stating plainly. It is the actual fan-out call
path: a tool wired without it works in single mode and silently never runs in a
parallel plan, which is the failure this whole alignment layer exists to make
loud. So the assertion is that the attribute exists AND is callable, not that
the import succeeded.

Runs in the `root-recon` section, which is the one with the recon package
importable.

Run: python -m pytest tests/test_registry_tool_wiring.py -v
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from recon import settings_registry as reg

REPO = Path(__file__).resolve().parents[1]
TOOLS = reg.tools()

WITH_MODULE = sorted(t for t, spec in TOOLS.items() if spec.get("module"))
WITH_ISOLATED = sorted(t for t, spec in TOOLS.items() if spec.get("isolated_fn"))
WITH_GRAPH_WRITER = sorted(t for t, spec in TOOLS.items() if spec.get("graph_writer"))
WITH_PARTIAL = sorted(t for t, spec in TOOLS.items() if spec.get("partial_recon_module"))


def test_the_registry_actually_wires_tools():
    """If these lists are empty the rest of the file passes while checking nothing."""
    assert len(WITH_MODULE) > 20, f"only {len(WITH_MODULE)} tools name a module"
    assert len(WITH_ISOLATED) > 10
    assert len(WITH_GRAPH_WRITER) > 5
    assert len(WITH_PARTIAL) > 25


# --- T11: the module, the wrapper and the writer ---------------------------------------

@pytest.mark.parametrize("tool", WITH_MODULE)
def test_every_tool_module_imports(tool):
    module_path = TOOLS[tool]["module"]
    try:
        importlib.import_module(module_path)
    except ImportError as exc:
        pytest.fail(f"{tool} names module '{module_path}', which does not import: {exc}")


@pytest.mark.parametrize("tool", WITH_ISOLATED)
def test_every_isolated_wrapper_is_callable(tool):
    """
    The isolated wrapper is what the parallel executor calls.

    Asserting it EXISTS is not enough: a module-level name that is not callable
    would pass an attribute check and fail at fan-out, which is precisely the
    "works alone, silently skipped in parallel" shape.
    """
    spec = TOOLS[tool]
    module = importlib.import_module(spec["module"])
    fn = getattr(module, spec["isolated_fn"], None)
    assert fn is not None, f"{tool}: {spec['module']} has no {spec['isolated_fn']}"
    assert callable(fn), f"{tool}: {spec['isolated_fn']} is not callable"


@pytest.mark.parametrize("tool", WITH_GRAPH_WRITER)
def test_every_graph_writer_is_callable(tool):
    """
    The graph writer is what turns a tool's output into nodes.

    A tool without a working one runs, produces output, and leaves the graph
    unchanged - which reads exactly like "found nothing".
    """
    from graph_db import Neo4jClient  # noqa: PLC0415

    name = TOOLS[tool]["graph_writer"]
    fn = getattr(Neo4jClient, name, None)
    assert fn is not None, f"{tool}: Neo4jClient has no {name}"
    assert callable(fn), f"{tool}: {name} is not callable"


# --- T10: the partial-recon modules ------------------------------------------------------

@pytest.mark.parametrize("tool", WITH_PARTIAL)
def test_every_partial_recon_module_exists(tool):
    name = TOOLS[tool]["partial_recon_module"]
    path = REPO / "recon" / "partial_recon_modules" / f"{name}.py"
    assert path.is_file(), f"{tool} names partial module '{name}', which is not a file"


def test_every_partial_recon_module_maps_back_to_a_tool():
    """
    The reverse direction. A partial-recon module nothing claims cannot be
    reached from the workflow graph, so it is dead code that still ships.
    """
    claimed = {spec["partial_recon_module"] for spec in TOOLS.values() if spec.get("partial_recon_module")}
    on_disk = {
        p.stem
        for p in (REPO / "recon" / "partial_recon_modules").glob("*.py")
        if not p.stem.startswith("_")
        # Not tool modules: shared helpers, the graph-building pass, the
        # user-input resolver the modal drives, and the IP-mode hostname scope
        # every partial run computes before its tool.
        and p.stem not in {"helpers", "graph_builders", "user_inputs", "endpoint_ai_classification",
                           "ip_hostname_scope"}
    }
    orphans = sorted(on_disk - claimed)
    assert orphans == [], f"partial-recon modules no tool maps to: {orphans}"


# --- T13: what a tool says it produces ----------------------------------------------------

def test_every_graph_label_has_a_producer():
    """
    The reverse of T13, and the more useful direction to have written down:
    "which tool has to run before this label appears" is the question an
    operator asks when the graph is empty, and a label nothing produces is one
    the answer does not exist for.
    """
    from graph_db.schema_catalog import LABELS  # noqa: PLC0415

    produced = {
        label
        for spec in TOOLS.values()
        for label in (spec.get("produces") or [])
    }
    # `produces` is derived from the partial-recon sections (SECTION_NODE_MAP, see
    # recon_settings/build.py), so a label written outside every section is named
    # here with its writer, rather than skipped, so a NEW unproduced label still
    # fails.
    WRITTEN_OUTSIDE_A_SECTION = {
        # The graph's own structure and the operator's own inputs.
        "UserInput": "user_inputs.py",
        # Written by the graph read-path reconcile, not by a scanner.
        "Traceroute": "the read-path reconcile",
        # The scan root: ensure_root_domains creates it when a run starts and the
        # sections only enrich it (SECTION_ENRICH_MAP).
        "Domain": "graph_db/mixins/recon/domain_mixin.py",
        # The agent's attack-chain record.
        "AttackChain": "agentic/orchestrator_helpers/chain_graph_writer.py",
        "ChainStep": "agentic/orchestrator_helpers/chain_graph_writer.py",
        "ChainFinding": "agentic/orchestrator_helpers/chain_graph_writer.py",
        "ChainDecision": "agentic/orchestrator_helpers/chain_graph_writer.py",
        "ChainFailure": "agentic/orchestrator_helpers/chain_graph_writer.py",
        # The TruffleHog ingest, which no partial-recon section runs.
        "MultiscannerScan": "graph_db/mixins/secret_mixin.py",
        "MultiscannerFinding": "graph_db/mixins/secret_mixin.py",
    }
    orphans = sorted(set(LABELS) - produced - set(WRITTEN_OUTSIDE_A_SECTION))
    assert orphans == [], f"graph labels no tool claims to produce: {orphans}"


def test_every_produced_label_is_in_the_graph_schema():
    """
    A tool that claims to write a node label the schema has never heard of is
    one whose output nothing will query.
    """
    produced = sorted({
        label
        for spec in TOOLS.values()
        for label in (spec.get("produces") or [])
    })
    if not produced:
        pytest.skip("no tool declares produces yet")

    from graph_db.schema_catalog import LABELS  # noqa: PLC0415

    unknown = [label for label in produced if label not in LABELS]
    assert unknown == [], f"tools claim node labels the schema does not have: {unknown}"


# --- the enable flags reach the pipeline ----------------------------------------------------

def test_every_enabled_key_is_a_real_setting():
    """
    A tool's enable flag has to be a key the pipeline reads, or the two-level
    model has a level that does nothing.
    """
    from recon.project_settings import DEFAULT_SETTINGS  # noqa: PLC0415

    problems = [
        f"{tool}: {spec['enabled_key']}"
        for tool, spec in sorted(TOOLS.items())
        if spec.get("enabled_key") and spec["enabled_key"] not in DEFAULT_SETTINGS
    ]
    assert problems == [], f"enable flags no scan reads: {problems}"


def test_every_tool_image_is_in_the_runtime_allowlist():
    """
    The image columns are OPEN and the runtime pins a non-allowlisted value to
    the shipped default. A tool whose own declared image is outside that set
    would be pinned away on every scan, silently.
    """
    from recon.project_settings import ALLOWED_TOOL_IMAGES  # noqa: PLC0415

    problems = [
        f"{tool}: {spec['image']}"
        for tool, spec in sorted(TOOLS.items())
        if spec.get("image") and spec["image"] not in ALLOWED_TOOL_IMAGES
    ]
    assert problems == [], f"tool images the runtime would reject: {problems}"
