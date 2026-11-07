"""
T17: the resolved-settings golden master.

This is the test that decides whether the registry refactor is safe, and it is
worth more than the file-level drift tests combined.

Comparing generated FILES catches almost nothing: a generator can emit a
plausible `settings['X'] = project.get('y', D)` that is byte-different from the
original in a way no diff flags, and every risk in this work shows up only in
the VALUE a scan ends up running with. So this compares behaviour.

It is a gate on every phase, not a milestone. A red run here stops that phase
rather than being triaged afterwards, because a red run means some project's
scan is now configured differently and nobody asked for it.

When a change here IS intended, regenerate with
`python3 recon/tests/regen_golden_settings.py` and read the diff. Every line of
it is a value some scan will run with.

Run: python -m pytest recon/tests/test_golden_master.py -v
"""
from __future__ import annotations

import json

import pytest

from recon.tests.golden_settings import FIXTURE_DIR, cases
from recon.tests.golden_settings_runner import resolve

CASES = sorted(cases())


def _baseline(name: str) -> dict:
    path = FIXTURE_DIR / f"{name}.json"
    if not path.exists():
        pytest.fail(
            f"No golden baseline for case '{name}'. Create it deliberately with "
            f"python3 recon/tests/regen_golden_settings.py, then read the diff."
        )
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", CASES)
def test_resolved_settings_match_the_baseline(name):
    """Every key, every value, for one synthetic project."""
    expected = _baseline(name)
    actual = json.loads(json.dumps(resolve(cases()[name]), sort_keys=True, default=str))

    added = sorted(set(actual) - set(expected))
    removed = sorted(set(expected) - set(actual))
    assert not added, f"[{name}] settings keys APPEARED: {added}"
    assert not removed, f"[{name}] settings keys DISAPPEARED: {removed}"

    changed = {
        key: (expected[key], actual[key])
        for key in sorted(expected)
        if expected[key] != actual[key]
    }
    assert not changed, (
        f"[{name}] {len(changed)} setting(s) resolve differently than the baseline.\n"
        + "\n".join(f"  {k}: {was!r} -> {now!r}" for k, (was, now) in list(changed.items())[:25])
        + ("\n  ..." if len(changed) > 25 else "")
        + "\n\nIf this change is intended, run python3 recon/tests/regen_golden_settings.py "
        "and read the diff: every line of it is a value some scan will run with."
    )


def test_every_case_has_a_baseline():
    """A case with no baseline would pass by being skipped."""
    missing = [n for n in CASES if not (FIXTURE_DIR / f"{n}.json").exists()]
    assert missing == [], f"cases with no committed baseline: {missing}"


def test_no_stale_baseline():
    """A baseline whose case was deleted is a file nothing checks."""
    known = {f"{n}.json" for n in CASES}
    stale = sorted(p.name for p in FIXTURE_DIR.glob("*.json") if p.name not in known)
    assert stale == [], f"baselines for cases that no longer exist: {stale}"


# A case may legitimately resolve exactly like the baseline when the whole point
# of the case is that a guardrail ERASED its input. Named, so that a case which
# resolves identically for any OTHER reason still fails.
RESOLVES_TO_DEFAULTS = {
    # No image is a project setting: the loader never reads one from the row,
    # and sanitize_image_settings pins every key to its shipped default, so a
    # hostile row resolves to the default row. That identity IS the assertion,
    # and it is checked by name below.
    "hostile_docker_image",
    # Same shape: sanitize_project_file_settings drops a path that escapes its
    # allowed roots back to the shipped default.
    "escaping_wordlist",
    # Same shape again, one layer up. The row writes the OLD master switch true
    # with nothing behind it - no ceiling, no exclusions, no window - and the
    # derivation reads it as inert, which it always was. Resolving exactly like
    # the baseline IS the assertion, and it is checked by name below.
    "old_switch_on_with_no_limit",
}


def test_the_cases_actually_differ():
    """
    Sixteen identical cases would all pass and prove nothing.

    Each case exists to reach a corner, so each must resolve to something the
    baseline case does not, unless it is one of the named guardrail cases.
    """
    base = _baseline("all_defaults")
    same = [
        name
        for name in CASES
        if name != "all_defaults" and name not in RESOLVES_TO_DEFAULTS and _baseline(name) == base
    ]
    assert same == [], f"these cases resolve identically to all_defaults, so they test nothing: {same}"


def test_the_old_master_switch_buys_nothing_on_its_own():
    """`roeEnabled` is DERIVED, so the stored column decides nothing.

    Written true with no ceiling, no exclusion list and no time window, the row
    must resolve exactly like a project that set none of them. The value of the
    case is that identity: it is what "the column is not read" looks like from
    the outside.
    """
    resolved = _baseline("old_switch_on_with_no_limit")
    assert resolved["ROE_ENABLED"] is False
    assert resolved == _baseline("all_defaults")


def test_a_written_ceiling_applies_without_a_second_switch():
    """The one behaviour this change deliberately alters.

    A 3 rps ceiling written while the old switch was off used to cap nothing:
    the capper was gated on the flag, so the number sat there and an operator
    believed in a ceiling that was never applied. It applies now.
    """
    resolved = _baseline("ceiling_with_the_old_switch_off")
    assert resolved["ROE_ENABLED"] is True
    assert resolved["NAABU_RATE_LIMIT"] == 3
    assert resolved["NUCLEI_RATE_LIMIT"] == 3


def test_an_exclusion_list_alone_makes_the_limits_live():
    resolved = _baseline("exclusions_only")
    assert resolved["ROE_ENABLED"] is True
    assert resolved["ROE_EXCLUDED_HOSTS"] == ["pay.target.test"]


def test_a_time_window_alone_makes_the_limits_live():
    resolved = _baseline("time_window_only")
    assert resolved["ROE_ENABLED"] is True
    assert resolved["ROE_TIME_WINDOW_ENABLED"] is True


def test_a_hostile_docker_image_is_pinned_to_the_shipped_default():
    """
    The one case whose success looks like a no-op.

    `hostile_docker_image` puts `attacker/evil:latest` under two image keys on
    the project row, as an old export or a stale client could. Images are not
    settings, so the row's values never reach the resolved settings.
    """
    resolved = _baseline("hostile_docker_image")
    assert resolved["NUCLEI_DOCKER_IMAGE"] == "projectdiscovery/nuclei:latest"
    assert resolved["NAABU_DOCKER_IMAGE"] == "projectdiscovery/naabu:latest"
    assert "attacker/evil" not in json.dumps(resolved)


def test_an_escaping_wordlist_path_is_dropped_to_the_shipped_default():
    """
    The second case whose success looks like a no-op.

    ffuf sends each wordlist LINE as a URL path and records which ones
    responded, so a wordlist pointed at a file inside the scan container gets
    its contents reflected into the graph and the scan output. That is
    exfiltration, not just disclosure, and the deny list used to be the only
    thing standing in front of it.
    """
    resolved = _baseline("escaping_wordlist")
    assert resolved["FFUF_WORDLIST"] == "/usr/share/seclists/Discovery/Web-Content/common.txt"
    assert "/etc/shadow" not in json.dumps(resolved)


def test_the_exclude_tag_merge_is_deterministic():
    """
    The stealth pass de-duplicates tags through a set, and set order over
    strings varies per process. Two runs of the same project therefore built two
    different nuclei command lines, which makes any comparison between them
    unreliable for a reason that has nothing to do with the target.
    """
    row = cases()["stealth"]
    first = resolve(row)["NUCLEI_EXCLUDE_TAGS"]
    second = resolve(row)["NUCLEI_EXCLUDE_TAGS"]
    assert first == second
    assert first == sorted(first), "the merge must be sorted, not merely de-duplicated"
