"""
Surfaces 2 and 7: every registry runtime key is really wired to a column.

T1 makes the build fail when a Prisma column has no registry entry. T36 makes it
fail when a runtime key has no registry entry. Between them sat the gap this
closes: a column with a registry entry that names a `runtime_key` NOTHING READS.
The field is documented, bounded, validated and settable, and the pipeline never
sees the value.

That failure is invisible from every other angle. `describe_recon_settings`
advertises it, `update_recon_settings` accepts it, `get_recon_settings` echoes it
back, and the scan runs with the shipped default. A caller has no way to tell.

ASSERTED rather than generated, deliberately. Generating the 530-line mapping
block would give the same guarantee and a diff nobody can review; a test that
fails when a registry key has no mapping is the same control at a tenth of the
cost. The shapes are checked too, because `project.get(k) or D` and
`project.get(k, D)` differ on an empty value and the registry records which is
which.

Run: python -m pytest recon/tests/test_settings_mapping_coverage.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tooling" / "scripts"))

import pytest  # noqa: E402

from parse_settings_mappings import parse_mappings  # noqa: E402
from recon import settings_registry as reg  # noqa: E402

RECON_SETTINGS = REPO / "recon" / "project_settings.py"
AGENT_SETTINGS = REPO / "agentic" / "project_settings.py"

RECON_MAPPINGS = parse_mappings(RECON_SETTINGS)
AGENT_MAPPINGS = parse_mappings(AGENT_SETTINGS)
BY_RUNTIME_KEY = reg.by_runtime_key()

# Mapped in a shape the line parser cannot see: a two-line form that reads into
# a local first, or a helper call. Named individually rather than skipped by a
# pattern, so a NEW unmapped key still fails.
MULTILINE_MAPPINGS = {
    # settings['SUBDOMAIN_LIST'] = [s.strip() for s in raw_subs if s.strip()]
    "SUBDOMAIN_LIST",
    "TARGET_IPS",
    # Read into a local, filtered, then assigned.
    "JSLUICE_VERIFY_ACCEPT_STATUS",
    "JSLUICE_EXCLUDE_PATTERNS",
    # Parsed by a helper that validates the structure.
    "DOMAIN_BATCH_GROUPS",
    "DOMAIN_BATCH_MODE",
}

# Runtime keys that are DERIVED rather than mapped from their column.
#
# The distinction this file exists for is "documented but never read". A derived
# key is the opposite: it IS read, by more of the system than a mapped one, and
# the column it is named after is deliberately not consulted. So it is named
# here rather than left to fail as unmapped - and the assertion below checks the
# derivation is actually wired, which is the property that would otherwise go
# unchecked.
DERIVED_KEYS = {
    # recon_settings.engagement.derive_roe_enabled, called by recon, the agent
    # AND the orchestrator. A writable master switch was a bypass shipped as a
    # checkbox: one write of false and the ceiling, the exclusions and the time
    # window all stopped applying while every field still showed its value.
    "ROE_ENABLED",
}


def _all_mapped() -> set[str]:
    return set(RECON_MAPPINGS) | set(AGENT_MAPPINGS) | MULTILINE_MAPPINGS | DERIVED_KEYS


@pytest.mark.parametrize("key", sorted(DERIVED_KEYS))
def test_a_derived_key_is_derived_in_every_loader_that_sets_it(key):
    """Excusing a key from the mapping check has to cost something.

    Without this, adding a name to DERIVED_KEYS would silence the coverage
    failure for a key nothing computes either - which is the exact
    documented-but-inert state the file exists to catch, reached by a different
    route.
    """
    setters = [
        path for path in (RECON_SETTINGS, AGENT_SETTINGS)
        if f"settings['{key}']" in path.read_text(encoding="utf-8")
    ]
    assert setters, f"{key} is excused from the mapping check but nothing sets it"
    for path in setters:
        text = path.read_text(encoding="utf-8")
        line = next(l for l in text.split("\n") if f"settings['{key}']" in l)
        assert "derive_" in line, (
            f"{path.name} sets {key} from something other than a derivation: {line.strip()}"
        )
        assert "project.get(" not in line, (
            f"{path.name} reads the {key} COLUMN, which is what the derivation replaced"
        )


def test_the_parsers_found_the_mappings():
    """Empty parses would make every assertion below pass while checking nothing."""
    assert len(RECON_MAPPINGS) > 400, f"only {len(RECON_MAPPINGS)} recon mappings parsed"
    assert len(AGENT_MAPPINGS) > 100, f"only {len(AGENT_MAPPINGS)} agent mappings parsed"


def test_every_registry_runtime_key_is_actually_read():
    """
    The gap between T1 and T36.

    A field whose runtime_key nothing reads is documented, bounded, settable and
    inert. Every surface reports success and the scan runs on the default.
    """
    mapped = _all_mapped()
    unread = sorted(k for k in BY_RUNTIME_KEY if k not in mapped)
    assert unread == [], (
        f"{len(unread)} registry runtime key(s) no settings loader reads: {unread}. "
        "Either add the mapping, or set runtime_key: null if the pipeline genuinely "
        "does not use the column."
    )


# Read out of the same API response but NOT Project scalar columns. Each is
# either a relation or user-scoped data the endpoint includes alongside the
# project, so the registry has no field for it and should not.
NON_COLUMN_READS = {
    # A relation on purpose: GET /api/projects/[id] spreads every Project scalar
    # to the browser, so a credential stored as a column would leak.
    "authProfile",
    # The USER's skills and MCP servers, not the project's.
    "userAttackSkills",
    "userMcpServers",
}


def test_every_mapping_maps_a_column_the_registry_knows():
    """The reverse: a mapping for a column the registry has never heard of."""
    known = set(reg.fields()) | NON_COLUMN_READS
    ghosts = sorted(
        f"{key} -> {mapping.column}"
        for source in (RECON_MAPPINGS, AGENT_MAPPINGS)
        for key, mapping in source.items()
        if mapping.column not in known
    )
    assert ghosts == [], f"mappings for columns the registry does not have: {ghosts}"


def test_every_non_column_read_is_declared_runtime_only():
    """
    The exemptions above are only safe while the registry agrees they are not
    columns. One that quietly became a column would be documented nowhere and
    settable through no surface.
    """
    runtime = reg.runtime_only()
    undeclared = sorted(
        key for key, mapping in {**RECON_MAPPINGS, **AGENT_MAPPINGS}.items()
        if mapping.column in NON_COLUMN_READS and key not in runtime
    )
    assert undeclared == [], (
        f"these read non-column data and have no runtime_only entry: {undeclared}"
    )


def test_every_mapping_agrees_with_the_registry_about_its_column():
    """
    A mapping that reads a DIFFERENT column than the registry records is the
    worst shape of all: both look right in isolation and the value a caller
    writes lands somewhere else.
    """
    problems = []
    for source_name, source in (("recon", RECON_MAPPINGS), ("agent", AGENT_MAPPINGS)):
        for key, mapping in source.items():
            entry = BY_RUNTIME_KEY.get(key)
            if not entry:
                continue
            if entry["column"] != mapping.column:
                problems.append(
                    f"{source_name}: {key} reads '{mapping.column}', "
                    f"registry says '{entry['column']}'"
                )
    assert problems == [], problems


# --- the keys that exist because uniformity is a lie --------------------------------

def test_the_falsy_fallbacks_are_recorded():
    """
    `project.get(k) or D` replaces a stored empty value with the default;
    `project.get(k, D)` honours it. A few mappings use the first form (each one
    `fallback: falsy` in the registry), so an operator who sets an empty list
    gets the default back rather than an empty list, and a caller told otherwise
    would be surprised by a live scan.
    """
    problems = []
    for key, mapping in RECON_MAPPINGS.items():
        entry = BY_RUNTIME_KEY.get(key)
        if not entry:
            continue
        recorded = entry.get("fallback", "missing")
        if mapping.fallback != recorded:
            problems.append(f"{key}: code is '{mapping.fallback}', registry says '{recorded}'")
    assert problems == [], problems


def test_the_coercions_are_recorded():
    """`int(...)` and `.strip()` change the value the pipeline runs with."""
    problems = []
    for key, mapping in RECON_MAPPINGS.items():
        entry = BY_RUNTIME_KEY.get(key)
        if not entry:
            continue
        recorded = entry.get("coerce")
        if mapping.coerce != recorded:
            problems.append(f"{key}: code coerces '{mapping.coerce}', registry says '{recorded}'")
    assert problems == [], problems


def test_the_non_canonical_mappings_are_the_ones_the_registry_names():
    """
    All but a handful of the mappings are byte-identical in form, which is what
    would make generating them feasible (`python3
    tooling/scripts/parse_settings_mappings.py` prints the count and the
    exceptions). The registry has to carry the ones that are not,
    because a generator emitting the canonical form for them would change
    behaviour with nothing failing.
    """
    odd = sorted(k for k, m in RECON_MAPPINGS.items() if not m.canonical)
    recorded = sorted(
        k for k in odd
        if BY_RUNTIME_KEY.get(k, {}).get("fallback") == "falsy"
        or BY_RUNTIME_KEY.get(k, {}).get("coerce")
    )
    assert odd == recorded, (
        f"these mappings are non-canonical but the registry records nothing unusual "
        f"about them: {sorted(set(odd) - set(recorded))}"
    )


@pytest.mark.parametrize("key", sorted(MULTILINE_MAPPINGS))
def test_every_hand_listed_multiline_mapping_is_really_in_the_source(key):
    """
    The exemption list is only safe while each entry is genuinely mapped. A key
    left here after its mapping was deleted would be an exemption for a bug.
    """
    text = RECON_SETTINGS.read_text(encoding="utf-8")
    assert f"settings['{key}']" in text, (
        f"{key} is exempted as a multi-line mapping but nothing assigns it"
    )
