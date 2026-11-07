"""
T6, T39, T40, T41: what the registry actually does at settings load.

The registry's own tests prove its structure. These prove its EFFECT, which is
the only thing a scope violation cares about. The distinction is not academic:
`PUREDNS_RATE_LIMIT` was in the shipped cap list and ran unlimited anyway,
because being in a list is not the same as being capped.

So every assertion here reads a RESOLVED value, and the exhaustive cases iterate
the registry rather than naming fields, because the registry is the list of
things that could regress.

Run: python -m pytest recon/tests/test_registry_runtime.py -v
"""
from __future__ import annotations

import pytest

from recon import settings_registry as reg
from recon.project_settings import (
    ALLOWED_TOOL_IMAGES,
    DEFAULT_SETTINGS,
    apply_memory_governor,
    apply_roe_rate_cap,
    apply_stealth_overrides,
    sanitize_image_settings,
)

CEILING = 3


def _with_roe(**over) -> dict:
    settings = dict(DEFAULT_SETTINGS)
    settings["ROE_ENABLED"] = True
    settings["ROE_GLOBAL_MAX_RPS"] = CEILING
    settings.update(over)
    return settings


CAPPED_KEYS = reg.roe_capped_runtime_keys()
NUMERIC_CAPPED = [k for k in CAPPED_KEYS if isinstance(DEFAULT_SETTINGS.get(k), (int, float))]


# --- T39: the exhaustive cap test ----------------------------------------------------

@pytest.mark.parametrize("key", NUMERIC_CAPPED)
@pytest.mark.parametrize("written", ["max", "min", "zero", "far_above"])
def test_every_capped_rate_resolves_at_or_below_the_ceiling(key, written):
    """
    For EVERY capped key, at its bound extremes and at zero.

    Iterating the registry beats example-based cases: a rate field added
    tomorrow is covered the day it is added, which is the property that would
    have stopped takeoverRateLimit shipping uncapped.
    """
    bounds = reg.bounds_for(key)
    if written == "max":
        value = int(bounds[1]) if bounds else 100000
    elif written == "min":
        value = int(bounds[0]) if bounds else 0
    elif written == "zero":
        value = 0
    else:
        value = 1_000_000

    resolved = apply_roe_rate_cap(_with_roe(**{key: value}))[key]
    assert resolved <= CEILING, (
        f"{key} written as {value} resolved to {resolved}, above the {CEILING} rps ceiling"
    )


@pytest.mark.parametrize("key", sorted(reg.unlimited_zero_runtime_keys()))
def test_a_zero_that_means_unlimited_becomes_the_ceiling(key):
    """
    The failure that is invisible to a `value > ceiling` test.

    0 is the FASTEST value these fields accept. Left alone under a 3 rps
    engagement they run without any limit at all, and nothing logs it.
    """
    if key not in DEFAULT_SETTINGS:
        pytest.skip(f"{key} is not a runtime setting in this build")
    assert apply_roe_rate_cap(_with_roe(**{key: 0}))[key] == CEILING


def test_the_three_shipped_bypasses_are_closed():
    """Named, so a future edit that drops one from the derived list fails here."""
    settings = apply_roe_rate_cap(_with_roe(
        TAKEOVER_RATE_LIMIT=500,
        JSLUICE_VERIFY_RATE_LIMIT=1000,
        WEB_CACHE_POISON_MAX_RPS_PER_HOST=0,
        PUREDNS_RATE_LIMIT=0,
    ))
    assert settings["TAKEOVER_RATE_LIMIT"] == CEILING
    assert settings["JSLUICE_VERIFY_RATE_LIMIT"] == CEILING
    assert settings["WEB_CACHE_POISON_MAX_RPS_PER_HOST"] == CEILING
    assert settings["PUREDNS_RATE_LIMIT"] == CEILING


# --- T6: the capper's gates ------------------------------------------------------------

def test_capping_does_not_apply_when_roe_is_off():
    """
    The ceiling is inert while roeEnabled is false, whatever the value says.

    Asserted rather than assumed, because the whole registry work leans on the
    RoE layer as its main control and a change that started capping unasked
    would be as surprising as one that stopped.
    """
    settings = dict(DEFAULT_SETTINGS)
    settings.update(ROE_ENABLED=False, ROE_GLOBAL_MAX_RPS=CEILING, NAABU_RATE_LIMIT=5000)
    assert apply_roe_rate_cap(settings)["NAABU_RATE_LIMIT"] == 5000


def test_capping_does_not_apply_when_the_ceiling_is_zero():
    settings = dict(DEFAULT_SETTINGS)
    settings.update(ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=0, NAABU_RATE_LIMIT=5000)
    assert apply_roe_rate_cap(settings)["NAABU_RATE_LIMIT"] == 5000


def test_a_rate_already_below_the_ceiling_is_left_alone():
    assert apply_roe_rate_cap(_with_roe(NAABU_RATE_LIMIT=1))["NAABU_RATE_LIMIT"] == 1


def test_a_boolean_is_never_treated_as_a_rate():
    """`True == 1` in Python, so a bool reaching the capper would be rewritten."""
    settings = _with_roe()
    settings["HAKRAWLER_THREADS"] = True
    assert apply_roe_rate_cap(settings)["HAKRAWLER_THREADS"] is True


def test_no_setting_outside_the_capped_list_is_touched():
    before = _with_roe(NAABU_RATE_LIMIT=5000)
    after = apply_roe_rate_cap(dict(before))
    moved = {k for k in before if before[k] != after[k]}
    assert moved <= set(CAPPED_KEYS), f"the capper changed keys it does not own: {moved - set(CAPPED_KEYS)}"


# --- T40: the pass ordering ---------------------------------------------------------------

def test_the_governor_never_raises_what_an_earlier_pass_lowered():
    """
    Documented ordering: stealth and RoE win first, then the governor tightens
    further under live memory pressure. A reordered generator produces different
    effective settings with nothing failing, so the direction is asserted.
    """
    settings = apply_stealth_overrides(_with_roe())
    lowered = {k: v for k, v in settings.items() if isinstance(v, int) and not isinstance(v, bool)}
    after = apply_memory_governor(dict(settings))
    raised = {
        k: (lowered[k], after[k])
        for k in lowered
        if isinstance(after.get(k), int) and after[k] > lowered[k]
    }
    assert raised == {}, f"the governor RAISED values an earlier pass had lowered: {raised}"


def test_the_governor_tables_are_registry_queries():
    """
    The lists used to live in two dicts in project_settings.py. They are the
    registry's now, and they must still name only real settings.
    """
    ratio = reg.governor_ratio_keys()
    budget = reg.governor_budget_keys()
    assert ratio and budget
    unknown = sorted(k for k in {**ratio, **budget} if k not in DEFAULT_SETTINGS)
    assert unknown == [], f"governed keys that no scan ever reads: {unknown}"
    overlap = sorted(set(ratio) & set(budget))
    assert overlap == [], f"a key cannot be both ratio-scaled and byte-budgeted: {overlap}"


def test_every_budget_key_declares_a_family():
    """A budget with no bytes-per-unit family cannot be budgeted at all."""
    missing = sorted(k for k, (family, _) in reg.governor_budget_keys().items() if not family)
    assert missing == [], f"budget keys with no family: {missing}"


# --- T41: the image guardrail across every image field --------------------------------------

IMAGE_KEYS = sorted(k for k in DEFAULT_SETTINGS if k.endswith("_DOCKER_IMAGE"))


@pytest.mark.parametrize("key", IMAGE_KEYS)
@pytest.mark.parametrize("value", ["attacker/evil:latest", "projectdiscovery/nuclei:latest"])
def test_any_other_image_resolves_to_the_keys_own_default(key, value):
    """
    Every key is pinned to ITS OWN shipped image, not merely to some shipped
    image: the naabu key carrying the nuclei image is as wrong as a foreign one.
    """
    if DEFAULT_SETTINGS[key] == value:
        pytest.skip("the value under test is this key's own default")
    settings = dict(DEFAULT_SETTINGS)
    settings[key] = value
    assert sanitize_image_settings(settings)[key] == DEFAULT_SETTINGS[key]


def test_every_image_key_is_internal_never_a_field():
    """
    An image field would put a column, a form control and an MCP write in front
    of `docker run` on the host daemon. Every image is an internal runtime key.
    """
    by_key = reg.by_runtime_key()
    runtime_only = reg.runtime_only()
    problems = []
    for key in IMAGE_KEYS:
        if key in by_key:
            problems.append(f"{key}: is a settings field")
        elif runtime_only.get(key, {}).get("source") != "internal":
            problems.append(f"{key}: not an internal runtime-only key")
    assert problems == [], problems


def test_the_shipped_image_defaults_are_the_allowlist():
    """
    `ALLOWED_TOOL_IMAGES` is derived from the defaults, so the two cannot
    disagree. Asserted because the guardrail's substitution target IS that set.
    """
    shipped = {DEFAULT_SETTINGS[k] for k in IMAGE_KEYS if DEFAULT_SETTINGS[k]}
    assert shipped == set(ALLOWED_TOOL_IMAGES)


# --- surface 6: the stealth profile ------------------------------------------------------

STEALTH_PROFILE = reg.stealth_profile()
STEALTH_KEYS = sorted(k for k in STEALTH_PROFILE if k in DEFAULT_SETTINGS)


def test_the_stealth_profile_is_not_empty():
    """An empty profile would make stealth mode a no-op that reports success."""
    assert len(STEALTH_KEYS) > 90, f"only {len(STEALTH_KEYS)} keys carry a stealth rule"


def test_stealth_is_inert_when_it_is_off():
    before = dict(DEFAULT_SETTINGS)
    after = apply_stealth_overrides(dict(before))
    assert after == before


@pytest.mark.parametrize("key", STEALTH_KEYS)
def test_every_set_rule_forces_its_value(key):
    """`set` wins whatever the operator chose. That is the point of stealth."""
    rule = STEALTH_PROFILE[key]
    if "set" not in rule:
        pytest.skip(f"{key} declares a ceiling, not a value")
    settings = dict(DEFAULT_SETTINGS)
    settings["STEALTH_MODE"] = True
    resolved = apply_stealth_overrides(settings)[key]
    assert resolved == rule["set"]


@pytest.mark.parametrize("key", [k for k in STEALTH_KEYS if "ceiling" in STEALTH_PROFILE[k]])
def test_a_ceiling_lowers_a_loud_value_and_leaves_a_quiet_one(key):
    """
    The distinction between `ceiling` and `set`, asserted rather than assumed.

    An operator who asked for 50 results keeps 50; one who asked for 5000 is
    brought down. Treating a ceiling as a value would RAISE the first case,
    which is the opposite of what stealth is for.
    """
    ceiling = STEALTH_PROFILE[key]["ceiling"]

    loud = dict(DEFAULT_SETTINGS)
    loud.update(STEALTH_MODE=True, **{key: ceiling * 10})
    assert apply_stealth_overrides(loud)[key] == ceiling

    quiet = dict(DEFAULT_SETTINGS)
    quiet.update(STEALTH_MODE=True, **{key: max(1, ceiling // 10)})
    assert apply_stealth_overrides(quiet)[key] == max(1, ceiling // 10)


def test_the_nuclei_exclude_tags_are_a_union_not_a_replacement():
    """
    The one override that is neither `set` nor `ceiling`.

    Expressing it as a value would discard whatever the operator excluded, which
    is a LOUDER scan than they asked for produced by a stealth pass.
    """
    settings = dict(DEFAULT_SETTINGS)
    settings.update(STEALTH_MODE=True, NUCLEI_EXCLUDE_TAGS=["my-own-tag"])
    resolved = apply_stealth_overrides(settings)["NUCLEI_EXCLUDE_TAGS"]
    assert "my-own-tag" in resolved
    for tag in ("dos", "fuzz", "intrusive", "sqli", "rce"):
        assert tag in resolved
    assert resolved == sorted(resolved), "the merge must be deterministic"


def test_a_set_rule_can_RAISE_a_rate_the_operator_had_lowered():
    """
    A property of stealth mode worth knowing about, asserted rather than
    assumed, because it is the opposite of what the name suggests.

    `set` forces its value. So a project that had already lowered
    NAABU_RATE_LIMIT to 1 gets 10 when stealth is switched on: LOUDER than it
    was. Every rule in the profile was an unconditional assignment before this
    became a registry query, so this is the shipped behaviour preserved exactly,
    not something the conversion introduced - and the golden master is what
    proves that.

    Whether `set` should become a ceiling for the rate fields is a product
    decision about what stealth means, not a refactor. Recording it here means
    the next person meets it in a test rather than in a scan.
    """
    settings = dict(DEFAULT_SETTINGS)
    settings.update(STEALTH_MODE=True, NAABU_RATE_LIMIT=1)
    assert apply_stealth_overrides(settings)["NAABU_RATE_LIMIT"] == 10


def test_stealth_lowers_far_more_than_it_raises():
    """
    The direction that matters in aggregate: from the shipped defaults, the
    stealth pass must move the scan quieter overall. A profile that mostly
    raised values would be misnamed whatever any single field does.
    """
    before = dict(DEFAULT_SETTINGS)
    after = apply_stealth_overrides({**before, "STEALTH_MODE": True})
    lowered = raised = 0
    for key, rule in STEALTH_PROFILE.items():
        if key not in before or "set" not in rule:
            continue
        old_value, new_value = before[key], after[key]
        if isinstance(old_value, bool) or not isinstance(old_value, (int, float)):
            continue
        if new_value < old_value:
            lowered += 1
        elif new_value > old_value:
            raised += 1
    assert lowered > raised * 3, f"stealth lowered {lowered} values and raised {raised}"


def test_every_stealth_key_is_a_real_setting():
    unknown = sorted(k for k in STEALTH_PROFILE if k not in DEFAULT_SETTINGS)
    assert unknown == [], f"stealth rules for settings no scan reads: {unknown}"
