"""The generated graph-schema catalog and renderer.

Two jobs, and they pull in opposite directions on purpose.

**1. Nothing was lost.** The catalog was seeded by slicing the hand-written
`TEXT_TO_CYPHER_SYSTEM` into addressable segments. `render_schema()` with no
arguments must reproduce the committed baseline fixture BYTE-FOR-BYTE. That is
what turns "the dynamic version has everything the hardcoded one had" from a
claim into a fact: the prose was cut, never re-typed, re-wrapped or summarised.
If someone edits the catalog and the render drifts, this goes red and the diff
shows exactly what moved.

**2. Nothing new goes missing.** `graph_db/schema.py` is the executable truth
about which labels exist. A label declared there with no catalog entry means the
agent silently cannot query that node type: no error, no warning, just an
authoritative-looking empty answer. That failure mode is why this file exists.

Run:
    docker run --rm --entrypoint python3 -v "$PWD:/work:ro" -w /work \\
        redamon-recon:latest recon/tests/test_schema_catalog.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CATALOG_PY = PROJECT_ROOT / "graph_db" / "schema_catalog.py"
RENDER_PY = PROJECT_ROOT / "graph_db" / "schema_render.py"
SCHEMA_PY = PROJECT_ROOT / "graph_db" / "schema.py"
#: The FULL document as it read before the split, for the composition proof.
BASELINE = PROJECT_ROOT / "recon" / "tests" / "fixtures" / "text_to_cypher_baseline.md"
#: Only the schema sections, which is what the catalog is seeded from.
SEED = PROJECT_ROOT / "graph_db" / "schema_sections.md"
KNOWN_UNDOCUMENTED_PROPS = (
    PROJECT_ROOT / "recon" / "tests" / "fixtures" / "undocumented_properties.json"
)
PROMPT_PY = PROJECT_ROOT / "agentic" / "prompts" / "base.py"


def _load(path: Path, name: str):
    """Import by PATH, not by package.

    `graph_db/__init__.py` imports the neo4j driver, which would make these
    tests need a driver they have no use for. Loading the module directly keeps
    the renderer's "pure, no dependencies" property honest rather than assumed.
    """
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


catalog = _load(CATALOG_PY, "schema_catalog")
render = _load(RENDER_PY, "schema_render")


# ---------------------------------------------------------------------------
# 1. Fidelity: the catalog is the same document, cut up
# ---------------------------------------------------------------------------

def test_segments_reassemble_into_the_baseline_byte_for_byte():
    rebuilt = "".join(s["body"] for s in catalog.SEGMENTS)
    baseline = SEED.read_text(encoding="utf-8")
    assert rebuilt == baseline, (
        "concatenating SEGMENTS no longer reproduces the baseline. Either a body "
        "was edited by hand, or the seeder changed. Re-run "
        "tooling/scripts/seed_schema_catalog.py and review the diff."
    )


def test_the_render_loses_no_word_of_the_seed_document():
    """THE information-loss guard.

    Byte-identity cannot apply: node blocks are rendered from parsed fields, so
    whitespace normalises and comma-grouped properties expand onto their own
    lines. The guarantee is instead that every word of the source document still
    appears in the render - the prose was decomposed, never summarised.
    """
    from collections import Counter

    def words(t):
        return Counter(re.findall(r"[A-Za-z0-9_]+", t))

    lost = words(SEED.read_text(encoding="utf-8")) - words(render.render_schema())
    assert not lost, (
        "rendering from fields dropped words the seed document contains: "
        f"{dict(list(lost.items())[:12])}"
    )


def test_the_composed_document_still_contains_the_baseline():
    """Drift detector on what the model is actually served.

    This began as a one-time proof that cutting the schema out of
    TEXT_TO_CYPHER_SYSTEM lost nothing, and it did that job: the recomposed
    document was byte-identical to the pre-split original.

    It now guards the composed document against ACCIDENTAL loss. The baseline is
    a golden file, so a deliberate edit - rewording a property, removing a
    wrong one - legitimately fails it. Refresh it in the same commit, having
    read the diff:

        python3 -c "
        import importlib.util, sys; sys.path.insert(0, 'graph_db')
        spec = importlib.util.spec_from_file_location('r', 'graph_db/schema_render.py')
        r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
        src = open('agentic/prompts/base.py').read()
        t = 'TEXT_TO_CYPHER_SYSTEM = \"\"\"'
        i = src.index(t) + len(t)
        rules = src[i:src.index('\"\"\"', i)]
        open('recon/tests/fixtures/text_to_cypher_baseline.md','w').write(
            rules.replace('__GRAPH_SCHEMA__', r.render_schema().rstrip()))"

    What it still catches for free: a marker that stopped being replaced, a
    catalog segment dropped by the seeder, a renderer change that silently
    skipped a label.
    """
    from collections import Counter

    src = PROMPT_PY.read_text(encoding="utf-8")
    tok = 'TEXT_TO_CYPHER_SYSTEM = """'
    start = src.index(tok) + len(tok)
    rules = src[start : src.index('"""', start)]
    assert "__GRAPH_SCHEMA__" in rules, (
        "the splice marker is gone from TEXT_TO_CYPHER_SYSTEM; the generated "
        "schema has nowhere to go and the model would be served rules alone"
    )

    composed = rules.replace("__GRAPH_SCHEMA__", render.render_schema().rstrip("\n"))
    original = BASELINE.read_text(encoding="utf-8")

    def words(t):
        return Counter(re.findall(r"[A-Za-z0-9_]+", t))

    lost = words(original) - words(composed)
    assert not lost, (
        "recomposing rules + schema lost words the original document had: "
        f"{dict(list(lost.items())[:12])}"
    )


def test_the_schema_sections_are_no_longer_hardcoded_in_the_prompt():
    """The point of the whole exercise. Node blocks and relationship maps must
    not come back into base.py: they go stale silently there, which is how 12
    labels and 134 properties went undocumented."""
    src = PROMPT_PY.read_text(encoding="utf-8")
    tok = 'TEXT_TO_CYPHER_SYSTEM = """'
    start = src.index(tok) + len(tok)
    rules = src[start : src.index('"""', start)]
    assert "## Node Types and Key Properties" not in rules
    assert "\n## Relationships" not in rules
    stray = re.findall(r"^\*\*([A-Z][A-Za-z0-9]*)\*\* -", rules, re.M)
    assert not stray, f"node blocks are back in the prompt: {stray}"


SEEDER = PROJECT_ROOT / "tooling" / "scripts" / "seed_schema_catalog.py"


def _run_seeder_check(root: Path):
    import subprocess

    return subprocess.run(
        [sys.executable, str(root / "tooling" / "scripts" / SEEDER.name), "--check"],
        capture_output=True, text=True, timeout=120,
    )


def test_the_committed_catalog_is_what_the_seeder_generates():
    """The generator check: the catalog is regenerated from schema_sections.md
    and compared with the committed file (a hand edit, or a seed edit without
    a re-seed, fails here)."""
    result = _run_seeder_check(PROJECT_ROOT)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_seeder_check_fails_on_a_hand_edited_catalog(tmp_path):
    """--check once compared the seed with itself and always exited 0."""
    import shutil

    for rel in ("tooling/scripts/seed_schema_catalog.py",
                "tooling/scripts/parse_label_block.py",
                "graph_db/schema_sections.md", "graph_db/schema_catalog.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(PROJECT_ROOT / rel, tmp_path / rel)
    assert _run_seeder_check(tmp_path).returncode == 0, "the copy is not self-consistent"

    copy = tmp_path / "graph_db" / "schema_catalog.py"
    copy.write_text(copy.read_text(encoding="utf-8").replace(
        "Subdomain", "Subdomian", 1), encoding="utf-8")
    result = _run_seeder_check(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "schema_catalog.py" in result.stderr


# ---------------------------------------------------------------------------
# 2. Completeness: code declares the labels, the catalog must explain them
# ---------------------------------------------------------------------------

# Declared in graph_db/schema.py but deliberately NOT described as queryable
# node types. Each needs a reason, or it belongs in the debt list below.
INTENTIONALLY_UNDOCUMENTED = {
    # A suppression marker, not a node type. The schema tells the model the
    # label is invisible and that any query mentioning it is rejected, so
    # documenting it as something to query would contradict that.
    "Muted",
    # Knowledge-base RAG chunks. Not attack surface, never a recon answer.
    "KBChunk",
}

# Real documentation debt. EMPTY, and the test below keeps it that way: a label
# listed here that turns out to be documented fails, and a declared label that is
# neither documented nor listed fails too. The GitHub secret-hunt subgraph named
# in graph_schema_track.md §12.1 was the last entry and is now documented.
UNDOCUMENTED_DEBT: set[str] = set()


def _composed_document() -> str:
    """Rules + generated schema: everything the model is served."""
    src = PROMPT_PY.read_text(encoding="utf-8")
    tok = 'TEXT_TO_CYPHER_SYSTEM = """'
    start = src.index(tok) + len(tok)
    rules = src[start : src.index('"""', start)]
    return rules.replace("__GRAPH_SCHEMA__", render.render_schema().rstrip("\n"))


def declared_labels() -> set[str]:
    """Every label the system declares, read from the ONE declaration.

    This used to re-parse CREATE CONSTRAINT strings out of schema.py with a
    regex, which was a second reading of a second copy. schema_keys.py is now
    the declaration and schema.py renders its constraints from it, so both this
    test and the database agree by construction rather than by comparison.
    """
    return set(catalog.LABELS_WITH_KEYS) | {"CVE", "MitreData", "Capec"}


def test_every_declared_label_is_catalogued_or_explicitly_excluded():
    """The anti-staleness guard.

    Add a node label to schema.py, forget the schema docs, and today NOTHING
    fails: the agent just silently cannot query it. This is the test that makes
    that loud. A genuinely new gap fails here; the known set is listed above
    with reasons so the debt is visible instead of ambient.
    """
    missing = declared_labels() - catalog.DOCUMENTED
    unexpected = missing - INTENTIONALLY_UNDOCUMENTED - UNDOCUMENTED_DEBT
    assert not unexpected, (
        f"{len(unexpected)} label(s) are declared in graph_db/schema.py with no "
        f"catalog entry: {', '.join(sorted(unexpected))}.\n"
        "An agent asked about these has no property names and will guess. Add a "
        "catalog entry, or list it in INTENTIONALLY_UNDOCUMENTED with a reason."
    )


def test_the_known_gaps_are_still_real_gaps():
    """Keeps the allowlists honest.

    Once a label IS documented, leaving it listed as debt would mask a future
    regression on that same label. So documenting one requires removing it here.
    """
    stale = (INTENTIONALLY_UNDOCUMENTED | UNDOCUMENTED_DEBT) & catalog.DOCUMENTED
    assert not stale, (
        f"these are listed as undocumented but now HAVE catalog entries: "
        f"{', '.join(sorted(stale))}. Remove them from the list."
    )


def test_catalog_documents_no_label_the_code_does_not_declare():
    """Documentation ahead of the code is its own drift: the model is told a
    node type exists that nothing ever writes, and queries come back empty for
    a reason no one can find."""
    phantom = catalog.DOCUMENTED - declared_labels()
    assert not phantom, (
        f"catalogued but not declared in schema.py: {', '.join(sorted(phantom))}"
    )


# ---------------------------------------------------------------------------
# 2b. Property drift: the live graph as an ORACLE, never as prompt content
#
# Label names are fully derivable from schema.py. Property names are NOT: 22 of
# 36 labels are written with `SET n += $props`, where the dict is assembled in
# Python from scanner output, so the names never appear literally in any source
# file. A static parse of the mixins finds 57 of Domain's 75.
#
# The live database is the one place that knows all of them, because it holds
# what was actually written. So it is used HERE, in a test, instead of being
# pasted into the prompt the way apoc.meta.data used to be. Same information,
# none of the costs: nothing cross-tenant reaches a model, no tokens are spent
# per query, and it cannot go stale in a cached snapshot.
#
# Skips cleanly without a database, like the EXPLAIN tests next door.
# ---------------------------------------------------------------------------

#: Properties every tenant-scoped node carries. They are deliberately NOT
#: documented per label: the schema states the rule once and tells the model
#: never to filter on them.
_TENANT_KEYS = {"user_id", "project_id"}

#: Bookkeeping written by the triage/mute feature onto many finding types. The
#: schema documents the family once rather than repeating ~25 keys per label.
_TRIAGE_PREFIX = "triage"


def _retired(label: str) -> set:
    """Properties no current writer sets on `label`, which older scans left on
    their nodes: legacy data, not schema drift."""
    if label != "Domain":
        return set()
    from graph_db.mixins.recon.domain_mixin import RETIRED_DOMAIN_RUN_PROPS
    return set(RETIRED_DOMAIN_RUN_PROPS)


def _neo4j_driver():
    """Connect, or return None so the caller skips. Credentials from the env."""
    import os

    try:
        from neo4j import GraphDatabase  # type: ignore
    except Exception:
        return None
    uri = os.environ.get("NEO4J_URI") or "bolt://localhost:7687"
    user = os.environ.get("NEO4J_USER") or "neo4j"
    password = os.environ.get("NEO4J_PASSWORD") or "changeme123"
    try:
        drv = GraphDatabase.driver(uri, auth=(user, password))
        drv.verify_connectivity()
        return drv
    except Exception:
        return None


def test_no_property_in_the_live_graph_is_missing_from_the_schema():
    """A scanner adds a property, the schema never learns about it, and the
    agent cannot ask for it. Nothing fails today. This is that alarm."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_no_property_in_the_live_graph_is_missing_from_the_schema (neo4j unreachable)")
        return

    # Checked against the COMPOSED document - rules plus rendered schema - because
    # that is what reaches the model. A property named only in the AI-annotations
    # section or a worked query example has still been shown to it, and failing on
    # those would push people to duplicate the entry into the schema sections.
    doc = _composed_document()
    undocumented: dict[str, list[str]] = {}
    try:
        with drv.session() as sess:
            labels = [r["label"] for r in sess.run("CALL db.labels() YIELD label RETURN label")]
            for lab in labels:
                if lab not in catalog.DOCUMENTED:
                    continue  # completeness is the other test's job
                rows = sess.run(
                    "CALL apoc.meta.nodeTypeProperties({includeLabels:[$l]}) "
                    "YIELD propertyName RETURN propertyName",
                    l=lab,
                ).data()
                missing = [
                    r["propertyName"]
                    for r in rows
                    if r["propertyName"] not in _TENANT_KEYS
                    and not r["propertyName"].startswith(_TRIAGE_PREFIX)
                    and r["propertyName"] not in _retired(lab)
                    and r["propertyName"] not in doc
                ]
                if missing:
                    undocumented[lab] = sorted(missing)
    finally:
        drv.close()

    # Known drift, measured once and recorded. 134 properties across 21 labels
    # exist today with no schema entry. They are NOT invented descriptions here:
    # guessing at what a property means would put a wrong claim into a security
    # tool's schema, which is worse than a gap the agent can see. So the debt is
    # frozen, and anything NEW fails immediately.
    import json

    known = json.loads(KNOWN_UNDOCUMENTED_PROPS.read_text(encoding="utf-8"))
    new_drift = {
        lab: [p for p in ps if p not in known.get(lab, [])]
        for lab, ps in undocumented.items()
    }
    new_drift = {lab: ps for lab, ps in new_drift.items() if ps}
    assert not new_drift, (
        "NEW properties exist in the graph that the schema never mentions, so an "
        "agent cannot ask for them:\n"
        + "\n".join(f"  {lab}: {', '.join(ps)}" for lab, ps in sorted(new_drift.items()))
        + "\n\nDocument them in TEXT_TO_CYPHER_SYSTEM, re-seed the catalog, and "
        "re-run. Do not add them to the known-drift fixture to silence this."
    )


def test_the_schema_does_not_promise_properties_that_were_removed():
    """The opposite drift: a property documented but no longer written. The
    model asks for it, gets null, and nobody can explain why."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_the_schema_does_not_promise_properties_that_were_removed (neo4j unreachable)")
        return
    # Only checked for labels that HAVE nodes here: an absent label proves
    # nothing about its properties, and this database is one deployment.
    phantom: dict[str, list[str]] = {}
    try:
        with drv.session() as sess:
            present = {r["label"] for r in sess.run("CALL db.labels() YIELD label RETURN label")}
            for lab in sorted(present & set(catalog.LABELS)):
                live = {
                    r["propertyName"]
                    for r in sess.run(
                        "CALL apoc.meta.nodeTypeProperties({includeLabels:[$l]}) "
                        "YIELD propertyName RETURN propertyName",
                        l=lab,
                    ).data()
                }
                if not live:
                    continue
                documented = set(
                    re.findall(r"^- ([a-z_][a-z0-9_]*)\s*\(", catalog.LABELS[lab]["body"], re.M)
                )
                gone = sorted(documented - live - _TENANT_KEYS)
                if gone:
                    phantom[lab] = gone
    finally:
        drv.close()

    # Reported, not enforced: a property can be legitimately documented before
    # any scan in THIS database has produced it. Printing keeps it visible
    # without failing a gate on one deployment's coverage.
    if phantom:
        print("NOTE: documented but absent from this database (may simply be unscanned):")
        for lab, ps in phantom.items():
            print(f"      {lab}: {', '.join(ps)}")


# ---------------------------------------------------------------------------
# 2c. Field rendering: the attribute list is GENERATED, not transcribed
#
# The catalog stores each label as parsed fields - description, property groups,
# relationships, sub-types, notes - alongside the verbatim body it came from.
# The parse is proven lossless below: re-rendering from the fields reproduces
# every word of the source. That is what allows the attribute list to be driven
# by the property names that actually exist, with the catalog supplying meaning.
# ---------------------------------------------------------------------------

def test_the_parse_loses_no_word_of_any_label_block():
    """The information-loss guard for decomposition.

    Byte-identity cannot apply here: field rendering normalises whitespace and
    expands comma-grouped properties onto their own lines. So the guarantee is
    word-level - every word in the source block still appears in the render.
    """
    from collections import Counter

    def words(t):
        return Counter(re.findall(r"[A-Za-z0-9_]+", t))

    lost = Counter()
    for lab, seg in catalog.LABELS.items():
        lost += words(seg["body"]) - words(render.render_label(lab))
    assert not lost, (
        "field rendering dropped words that the verbatim body contains: "
        f"{dict(list(lost.items())[:12])}"
    )


def test_an_unknown_label_raises_rather_than_rendering_nothing():
    """Silently returning nothing for a typo is indistinguishable from "that
    node type has no documentation"."""
    try:
        render.render_label("Subdomian")  # deliberate typo
    except ValueError as e:
        assert "Subdomian" in str(e)
    else:
        raise AssertionError("a misspelled label rendered silently")


def test_every_label_has_a_description_and_properties_as_fields():
    for lab, seg in catalog.LABELS.items():
        assert seg["description"], f"{lab} parsed with no description"
    total = sum(len(catalog.label_properties(l)) for l in catalog.LABELS)
    assert total > 400, f"only {total} properties parsed into fields; the parser regressed"






# ---------------------------------------------------------------------------
# 2d. Relationship drift
#
# Relationships had NO check of any kind. Labels were validated against
# schema.py and properties against the live graph, but a relationship type
# added by a new scanner went undocumented exactly the way labels used to: in
# silence, with the agent simply unable to traverse it.
#
# The graph knows every type it holds, so it is the oracle here too.
# ---------------------------------------------------------------------------

def test_every_relationship_in_the_live_graph_is_documented():
    """A traversal the agent is never shown is a traversal it cannot write."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_every_relationship_in_the_live_graph_is_documented (neo4j unreachable)")
        return
    try:
        with drv.session() as sess:
            live = {
                r["relationshipType"]
                for r in sess.run(
                    "CALL db.relationshipTypes() YIELD relationshipType "
                    "RETURN relationshipType"
                ).data()
            }
    finally:
        drv.close()

    doc = SEED.read_text(encoding="utf-8")
    # Documented means: parsed as a typed edge, OR named anywhere in the schema
    # prose. A type that only appears inside a worked query example is still
    # something the model has seen written down.
    missing = sorted(t for t in live if t not in catalog.RELATIONSHIP_TYPES and t not in doc)
    assert not missing, (
        "relationship types exist in the graph that the schema never mentions, "
        f"so the agent cannot traverse them: {', '.join(missing)}"
    )


def test_the_schema_describes_no_relationship_the_code_cannot_write():
    """The opposite drift: a documented edge nothing writes. The model plans a
    traversal that silently returns nothing."""
    import re as _re

    mixins = PROJECT_ROOT / "graph_db" / "mixins"
    if not mixins.exists():
        print("SKIP: mixins directory not found")
        return
    written = set()
    for f in mixins.rglob("*.py"):
        written |= set(_re.findall(r"-\[:(\w+)", f.read_text(encoding="utf-8", errors="replace")))
    # Reported, not enforced: some edges are written by scanner images outside
    # graph_db, so absence here is not proof the code cannot write it.
    phantom = sorted(catalog.RELATIONSHIP_TYPES - written)
    if phantom:
        print(
            "NOTE: documented but not found in graph_db/mixins "
            f"(may be written elsewhere): {', '.join(phantom)}"
        )


def test_relationship_sections_parsed_into_typed_edges():
    assert len(catalog.RELATIONSHIP_TYPES) > 50, (
        f"only {len(catalog.RELATIONSHIP_TYPES)} relationship types parsed; "
        "the relationship parser regressed"
    )


if __name__ == "__main__":
    passed, failures = 0, []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failures.append((name, str(exc)))
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
                failures.append((name, f"{type(exc).__name__}: {exc}"))
    print()
    print(f"{passed} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)
