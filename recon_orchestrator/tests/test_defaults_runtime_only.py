"""
Surface 11: `/defaults` excludes exactly what is not a project default.

The endpoint turns `DEFAULT_SETTINGS` into the camelCase blob a new project form
seeds itself from and a preset apply resets against. Anything in it that is NOT
a Project column is a key the form will try to write back, and the save fails
with a Prisma "Unknown argument" error.

The ProjectForm carries a workaround for exactly that, in a comment naming
`takeoverCnameValidationEnabled`: it only touches keys already present in the
form. That workaround is downstream of the bug. Deriving the exclusion list from
the registry removes the bug, because `source: internal` IS the set of keys with
no column.

The hand-written list had drifted in both directions: it named `FOFA_EMAIL`,
which no longer exists anywhere, and it missed two credential keys and seven
column-less settings.

Run: python -m pytest tests/test_defaults_runtime_only.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
for path in (str(REPO), str(REPO / "recon")):
    if path not in sys.path:
        sys.path.insert(0, path)

import pytest  # noqa: E402

from recon import settings_registry as reg  # noqa: E402
from recon.project_settings import DEFAULT_SETTINGS  # noqa: E402

sys.path.insert(0, str(REPO / "tooling" / "scripts"))
from parse_settings_mappings import parse_default_settings  # noqa: E402


def agent_default_settings() -> set[str]:
    """
    The agent's own settings keys.

    The registry spans both loaders. A few runtime-only keys - the user's
    imported attack skills and outbound MCP servers - exist only on the agent
    side, so checking an exclusion against the recon defaults alone would call
    them stale.
    """
    source = REPO / "agentic" / "project_settings.py"
    if not source.is_file():
        return set()
    return set(parse_default_settings(source, "DEFAULT_AGENT_SETTINGS"))


def derived_exclusions() -> set[str]:
    """The same query `/defaults` runs, so the two cannot disagree."""
    return set(reg.runtime_only()) | {
        "USER_ID", "TARGET_DOMAIN", "DOMAIN_BATCH_MODE", "DOMAIN_BATCH_GROUPS",
        "OWNERSHIP_TOKEN",
    }


def to_camel(snake: str) -> str:
    parts = snake.lower().split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def column_for() -> dict[str, str]:
    return {k: v["column"] for k, v in reg.by_runtime_key().items()}


def payload_keys() -> set[str]:
    """The same mapping the endpoint uses: the registry's column, not a guess."""
    excluded = derived_exclusions()
    columns = column_for()
    return {
        columns.get(k) or to_camel(k)
        for k in DEFAULT_SETTINGS
        if k not in excluded
    }


def prisma_columns() -> set[str]:
    sys.path.insert(0, str(REPO / "tooling" / "scripts"))
    from prisma_project_columns import project_columns  # noqa: PLC0415

    return set(project_columns())


def test_every_key_in_the_payload_is_a_real_project_column():
    """
    The defect this closes. A key with no column is written back by the form and
    the save fails, naming a field the operator never touched.
    """
    ghosts = sorted(payload_keys() - prisma_columns())
    assert ghosts == [], (
        f"/defaults would send {len(ghosts)} key(s) that are not Project columns: {ghosts}. "
        "Each needs a runtime_only entry in recon_settings/registry.yaml."
    )


def test_no_api_credential_reaches_the_payload():
    """
    Every `*_API_KEY` is fetched per scan from the user's account. The shipped
    list missed NVD and Vulners; their defaults are empty strings, so nothing
    leaked, but a credential key in a browser payload is the wrong shape whatever
    its current value.
    """
    leaked = sorted(
        k for k in DEFAULT_SETTINGS
        if k not in derived_exclusions()
        and (k.endswith("_API_KEY") or k.endswith("_API_TOKEN") or k.endswith("_KEY_ROTATOR"))
    )
    assert leaked == [], f"credential keys in the /defaults payload: {leaked}"


def test_the_authenticated_session_never_reaches_the_payload():
    """A per-project secret, deliberately a relation so it never spreads to the browser."""
    assert "AUTH_PROFILE" in derived_exclusions()


def test_the_targeting_columns_that_are_not_defaults_are_excluded():
    for key in ("TARGET_DOMAIN", "DOMAIN_BATCH_MODE", "DOMAIN_BATCH_GROUPS"):
        assert key in derived_exclusions()


def test_the_targeting_columns_that_ARE_defaults_are_included():
    """
    The other direction, so the exclusion does not quietly widen. An empty
    subdomain list and the shipped `_redamon-verify` TXT prefix are real
    defaults a new project form needs.
    """
    for key in ("SUBDOMAIN_LIST", "OWNERSHIP_TXT_PREFIX", "VERIFY_DOMAIN_OWNERSHIP", "IP_MODE"):
        assert key not in derived_exclusions(), f"{key} is a legitimate project default"


def test_the_exclusion_list_names_nothing_that_no_longer_exists():
    """
    `FOFA_EMAIL` sat in the hand-written list after the setting was removed. A
    stale name is harmless in itself and is the tell that nobody is checking.
    """
    known = set(DEFAULT_SETTINGS) | agent_default_settings()
    stale = sorted(k for k in derived_exclusions() if k not in known and k != "USER_ID")
    assert stale == [], f"exclusions for settings that do not exist: {stale}"


def test_the_conversion_alone_would_get_nine_columns_wrong():
    """
    Why the endpoint reads the registry instead of converting the key.

    A snake-to-camel conversion cannot recover an intercap: CRIMINALIP_ENABLED
    is the column `criminalIpEnabled`. Those settings never reached a new
    project form at all, because the form only applies a /defaults key it
    already has - the workaround that hid it.
    """
    columns = prisma_columns()
    naive = {
        to_camel(k) for k in DEFAULT_SETTINGS
        if k not in derived_exclusions()
    }
    wrong = sorted(naive - columns)
    assert len(wrong) >= 9, (
        "the naive conversion no longer disagrees with the columns; if the "
        "settings were renamed, this test has stopped documenting anything"
    )
    # And the registry-driven mapping gets every one of them right.
    assert sorted(payload_keys() - columns) == []


@pytest.mark.parametrize("key", sorted(reg.runtime_only()))
def test_every_runtime_only_key_really_has_no_column(key):
    """
    A runtime_only entry for a key that DOES have a column would silently drop
    that column's default out of the payload, and a new project form would show
    it empty.
    """
    columns = prisma_columns()
    assert to_camel(key) not in columns, (
        f"{key} is marked runtime_only but {to_camel(key)} is a real column"
    )


def test_the_payload_is_not_empty():
    """A derived list that excluded everything would pass every test above."""
    assert len(payload_keys()) > 400
