"""The agent side of the webapp <-> agent contract (T1.3).

Both sides parse every valid fixture of ``fixtures/tradecraft_contract/`` and refuse every
invalid one; both compare their enum lists with ``enums.json``. The webapp's half is
``webapp/src/lib/tradecraft/agentContract.test.ts``.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import contract as c  # noqa: E402
from tradecraft.settings import constant  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract"
ENUMS = json.loads((FIXTURES / "enums.json").read_text(encoding="utf-8"))
VALID = sorted(FIXTURES.glob("*.valid.json"))
INVALID = json.loads((FIXTURES / "invalid.json").read_text(encoding="utf-8"))


def model_of(path: Path):
    return c.MODELS[path.name.split(".", 1)[0]]


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.name)
def test_every_valid_fixture_parses_and_round_trips(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    parsed = model_of(path).model_validate(data)
    again = model_of(path).model_validate(parsed.model_dump(mode="json"))
    assert again == parsed


def test_every_model_has_a_valid_fixture():
    covered = {p.name.split(".", 1)[0] for p in VALID}
    # The nested models are covered inside their parents' fixtures.
    assert set(c.MODELS) - covered == {"JobStartRequest", "CatalogResource", "Credentials", "Secrets"}


@pytest.mark.parametrize("case", INVALID, ids=lambda case: f"{case['model']}: {case['why']}")
def test_every_invalid_fixture_is_refused(case):
    with pytest.raises(ValidationError):
        c.MODELS[case["model"]].model_validate(case["value"])


def _batch(n: int) -> dict:
    job = json.loads((FIXTURES / "JobStartBatch.valid.json").read_text())["jobs"][0]
    jobs = []
    for i in range(n):
        j = copy.deepcopy(job)
        j["job_id"] = f"job_fake_{i:04d}"
        jobs.append(j)
    return {"jobs": jobs}


def test_a_batch_holds_1_to_200_jobs():
    assert len(c.JobStartBatch.model_validate(_batch(200)).jobs) == 200
    with pytest.raises(ValidationError):
        c.JobStartBatch.model_validate(_batch(201))
    with pytest.raises(ValidationError):
        c.JobStartBatch.model_validate(_batch(0))


TRAILING_DASH_SLUG = "hacktricks-mirror-windows-local-privilege-escalation-and-active-"


def test_every_slug_the_webapp_makes_is_accepted():
    """slugify trims dashes before it cuts the name to 64 characters, and uniqueSlug adds "-2":
    a slug may end with a dash or hold two in a row."""
    import re

    for slug in ("hacktricks", "patt-2", "resource", "0day", TRAILING_DASH_SLUG, TRAILING_DASH_SLUG + "-2", "a"):
        assert re.fullmatch(c.SLUG_PATTERN, slug), slug
    for slug in ("", "-x", "Patt", "pa tt", "a:b", "a_b", "x" * 201):
        assert not re.fullmatch(c.SLUG_PATTERN, slug), slug


def test_a_catalog_over_the_resource_cap_parses():
    """OQ-20: the 200-resource cap is checked when a resource is added; an account already
    above it keeps every resource in its runs."""
    base = json.loads((FIXTURES / "V2Catalog.collaborator.valid.json").read_text())["resources"][0]
    resources = [{**base, "id": f"res_{i}", "slug": f"res-{i}"} for i in range(250)]
    parsed = c.V2Catalog.model_validate({"v2": True, "owner_id": "o", "person_id": "p", "resources": resources})
    assert len(parsed.resources) == 250


def test_enum_lists_equal_the_shared_file():
    assert c.CONTRACT_VERSION == ENUMS["contractVersion"]
    pairs = {
        "jobKinds": c.JOB_KINDS, "jobStatuses": c.JOB_STATUSES, "unfinishedJobStatuses": c.UNFINISHED_JOB_STATUSES,
        "jobStages": c.JOB_STAGES, "errorCodes": c.ERROR_CODES, "storageModes": c.STORAGE_MODES,
        "siteTypes": c.SITE_TYPES, "summarySources": c.SUMMARY_SOURCES, "priorities": c.PRIORITIES,
        "skipReasons": c.SKIP_REASONS, "indexKinds": c.INDEX_KINDS, "previewDecisions": c.PREVIEW_DECISIONS,
        "readSources": c.READ_SOURCES, "provenances": c.PROVENANCES, "purposes": c.PURPOSES,
    }
    assert set(pairs) | {"contractVersion"} == set(ENUMS)
    for name, mine in pairs.items():
        assert list(mine) == ENUMS[name], name


def test_the_card_error_codes_are_all_there():
    named = {
        "fetch_failed", "blocked_private_address", "homepage_http_error", "thin_homepage", "llm_budget_exhausted",
        "loop_model_not_supported_here", "model_unavailable", "agent_restarted", "agent_lost", "agent_unreachable",
        "cancelled", "resource_deleted", "resource_changed", "quota_reached", "timeout", "job_running", "userinfo_refused",
    }
    assert named <= set(c.ERROR_CODES)
    # The report's skip reasons are its own keys.
    assert set(c.SKIP_REASONS) == set(c.Skipped.model_fields)


def test_purposes_are_the_loop_labels():
    from agent_in_the_loop.purpose import ANSWER_FORMAT, PURPOSES
    for p in c.PURPOSES:
        assert p in PURPOSES and ANSWER_FORMAT[p] == "json"


def test_deadlines_are_the_spec_constants():
    assert c.DEADLINES_SEC == {"check_url": 60, "preview_focus": 120, "read_now": 45}
    assert c.WEBAPP_DEADLINE_MARGIN_SEC == 15
    assert c.DEADLINES_SEC["check_url"] == constant("checkUrlDeadlineSec")
    assert c.JOB_START_BATCH_MAX == 200


def test_routes():
    assert all(path.startswith("/tradecraft/v2/") for path in c.ROUTES.values())
    assert c.ROUTES["jobs"] == "/tradecraft/v2/jobs"


def test_parse_catalog_dispatches_on_v2():
    v2 = json.loads((FIXTURES / "V2Catalog.valid.json").read_text())
    legacy = json.loads((FIXTURES / "LegacyCatalog.valid.json").read_text())
    assert isinstance(c.parse_catalog(v2), c.V2Catalog)
    assert isinstance(c.parse_catalog(legacy), c.LegacyCatalog)
    with pytest.raises(ValidationError):
        c.parse_catalog({"v2": "yes"})


def test_the_owner_run_carries_logins_and_a_collaborator_run_does_not():
    owner = c.V2Catalog.model_validate(json.loads((FIXTURES / "V2Catalog.valid.json").read_text()))
    assert any(r.has_login and r.credentials is not None for r in owner.resources)
    collaborator = c.V2Catalog.model_validate(json.loads((FIXTURES / "V2Catalog.collaborator.valid.json").read_text()))
    assert not any(r.has_login for r in collaborator.resources)


def test_job_outcome_rules():
    assert c.JobOutcome(status="succeeded").error_code == ""
    assert c.JobOutcome(status="failed", error_code="fetch_failed", swapped=True).swapped
    for bad in (dict(status="succeeded", error_code="timeout"), dict(status="failed"),
                dict(status="failed", error_code="boom"), dict(status="running")):
        with pytest.raises(ValueError):
            c.JobOutcome(**bad)


def test_job_context_carries_the_request_and_clamped_settings():
    import asyncio

    from tradecraft.settings import EffectiveSettings

    request = c.JobStartBatch.model_validate(json.loads((FIXTURES / "JobStartBatch.valid.json").read_text())).jobs[0]
    stages = []

    async def is_cancelled() -> bool:
        return False

    async def set_stage(stage, progress):
        stages.append((stage, progress))

    ctx = c.JobContext(request=request, settings=EffectiveSettings({**request.settings, "crawl.maxPages": 10**6}),
                       target_generation=2, is_cancelled=is_cancelled, set_stage=set_stage)
    asyncio.run(ctx.set_stage("fetch_home", c.JobProgress(done=0, total=1, unit="pages")))
    assert ctx.settings.int("crawl.maxPages") == 500
    assert stages[0][0] in c.JOB_STAGES
    assert not asyncio.run(ctx.is_cancelled())
