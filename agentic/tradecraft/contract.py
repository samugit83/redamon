"""The Tradecraft 2.0 contract between the webapp and the agent (phase 1, T1.3).

Every body that crosses the boundary has one model here and one zod schema in
``webapp/src/lib/tradecraft/agentContract.ts``; both sides parse the shared fixtures of
``tests/fixtures/tradecraft_contract/`` and compare their enum lists with its
``enums.json``, so a field or a code changed on one side fails a test on both.

Agent routes (all under the master internal key, ``require_configured_master_auth``; those
that fetch a site or call a model also take ``require_internal_auth``):

==============================================  ================================================
``POST /tradecraft/v2/jobs``                     ``JobStartBatch`` -> 202 ``JobStartAnswer``
``POST /tradecraft/v2/jobs/{job_id}/cancel``     ``{}`` -> ``CancelAnswer``
``POST /tradecraft/v2/users/{user_id}/cancel``   ``{}`` -> ``UserCancelAnswer``
``POST /tradecraft/v2/check-url``                ``CheckUrlRequest`` -> ``CheckUrlResult``
``POST /tradecraft/v2/preview-focus``            ``PreviewRequest`` -> ``PreviewResult``
``POST /tradecraft/v2/read-now``                 ``ReadNowRequest`` -> ``ReadNowResult``
``POST /tradecraft/v2/users/{user_id}/convert``  ``{}`` -> ``ConvertAnswer``
==============================================  ================================================

The run catalog travels the other way (webapp -> agent, ``RunCatalog``). It names no
generation: readers take the live one from the resource row at each call (TD-9).

Secrets travel only from the webapp, read from the resource's row: a request carrying the
``"set"`` placeholder the browser sees is refused, so a masked value never reaches a site.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, Awaitable, Callable, Literal, Optional, Protocol, Union

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from tradecraft import settings as _settings

CONTRACT_VERSION = 1

JOB_KINDS = ("add", "refresh", "reingest", "bulk", "regenerate_summary", "convert", "pdf_convert")
JOB_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")
UNFINISHED_JOB_STATUSES = ("queued", "running")
# The pipeline's stage order (phase 1 "Jobs and the pipeline"); `convert` is the conversion job's.
JOB_STAGES = (
    "fetch_home", "detect", "build_map", "curation", "focus", "titles", "incremental", "store", "cards", "sections",
    "tags", "entities", "tree", "content_check", "write", "summary", "report", "legacy_map", "swap", "convert",
)
ERROR_CODES = (
    "fetch_failed", "blocked_private_address", "homepage_http_error", "thin_homepage", "llm_budget_exhausted",
    "loop_model_not_supported_here", "model_unavailable", "agent_restarted", "agent_lost", "agent_unreachable",
    "cancelled", "resource_deleted", "resource_changed", "quota_reached", "timeout", "job_running", "userinfo_refused",
    "job_not_claimed", "queue_full", "bad_url", "not_implemented", "page_blocked", "outside_map", "internal_error",
)
STORAGE_MODES = ("live", "stored")
SITE_TYPES = ("mkdocs-wiki", "sphinx-docs", "gitbook", "github-repo", "cve-poc-db", "pdf", "agentic-crawl")
SUMMARY_SOURCES = ("generated", "manual")
PRIORITIES = ("high", "normal", "low")
SKIP_REASONS = ("excluded", "outOfScope", "tooLittleText", "robots", "outsideFocus")
INDEX_KINDS = ("sitemap", "github_tree", "searchindex", "nav", "pdf", "none")
PREVIEW_DECISIONS = ("keep", "maybe", "drop")
# How the read path names where a text came from: `stored copy from <date>`, `live`, `live (not stored)`.
READ_SOURCES = ("stored", "live", "live_not_stored")
PROVENANCES = ("system", "user", "resource")
PURPOSES = ("tradecraft_ingest", "tradecraft_librarian")

# The browser shows "set" for a stored secret; a request carrying it is refused.
SECRET_PLACEHOLDER = "set"

# A resource ID (the slug): what the webapp's slugify makes, lowercase letters, digits and
# dashes from a letter or digit on; it may end with a dash (the name is cut after the dashes
# are trimmed) or hold two (a "-2" suffix). Page IDs (`<slug>:<n>`) use the same pattern.
SLUG_PATTERN = r"[a-z0-9][a-z0-9-]{0,199}"

_C = _settings.constants()
JOB_START_BATCH_MAX = _C["jobStartBatchMax"]
PREVIEW_MAX_ENTRIES = _C["previewEntries"]
CHECK_URL_SAMPLE_MAX = _C["checkUrlSampleEntries"]
# The agent ends each synchronous route at its deadline with error_code "timeout"; the
# webapp's agentFetch waits WEBAPP_DEADLINE_MARGIN_SEC longer (its default is 30 s).
DEADLINES_SEC = {
    "check_url": _C["checkUrlDeadlineSec"],
    "preview_focus": _C["focusPreviewDeadlineSec"],
    "read_now": _C["readNowDeadlineSec"],
}
WEBAPP_DEADLINE_MARGIN_SEC = _C["webappDeadlineMarginSec"]

ROUTES = {
    "jobs": "/tradecraft/v2/jobs",
    "cancel_job": "/tradecraft/v2/jobs/{job_id}/cancel",
    "cancel_user": "/tradecraft/v2/users/{user_id}/cancel",
    "check_url": "/tradecraft/v2/check-url",
    "preview_focus": "/tradecraft/v2/preview-focus",
    "read_now": "/tradecraft/v2/read-now",
    "convert": "/tradecraft/v2/users/{user_id}/convert",
}


def _one_of(values: tuple[str, ...], name: str, *, empty: bool = False):
    def check(v: str) -> str:
        if not (v in values or (empty and v == "")):
            raise ValueError(f"{name} must be {'empty or ' if empty else ''}one of {', '.join(values)}")
        return v
    return AfterValidator(check)


def _no_placeholder(v: str) -> str:
    if v.strip() == SECRET_PLACEHOLDER:
        raise ValueError('a masked "set" placeholder is not a secret')
    return v


IdStr = Annotated[str, StringConstraints(min_length=1, max_length=200)]
SlugStr = Annotated[str, StringConstraints(pattern=rf"^{SLUG_PATTERN}$")]
SecretText = Annotated[str, AfterValidator(_no_placeholder)]
StorageMode = Annotated[str, _one_of(STORAGE_MODES, "storage_mode")]
SiteTypeOrAuto = Annotated[str, _one_of(SITE_TYPES, "type", empty=True)]
ErrorCodeOrNone = Annotated[str, _one_of(ERROR_CODES, "error_code", empty=True)]


class _Model(BaseModel):
    # An unknown field is refused: a generation on a catalog resource, or a 2.0 column on
    # the 1.x path, must fail rather than travel unnoticed.
    model_config = ConfigDict(extra="forbid")



# --- secrets -------------------------------------------------------------------------

class Header(_Model):
    name: str = Field(min_length=1, max_length=200)
    value: SecretText = Field(max_length=8000)


class BasicAuth(_Model):
    username: str = Field(max_length=500)
    password: SecretText = Field(max_length=2000)


class Credentials(_Model):
    """A resource's login (phase 6): sent only to the resource's own host, never with the browser."""

    cookie: SecretText = Field(default="", max_length=8000)
    headers: list[Header] = Field(default_factory=list, max_length=50)
    basic_auth: Optional[BasicAuth] = None

    def is_empty(self) -> bool:
        return not self.cookie and not self.headers and self.basic_auth is None


class Secrets(_Model):
    github_token: Optional[SecretText] = Field(default=None, max_length=500)
    credentials: Optional[Credentials] = None


# --- jobs ----------------------------------------------------------------------------

class SettingsSnapshot(_Model):
    values: dict[str, Any]
    provenance: dict[str, str]

    @field_validator("provenance")
    @classmethod
    def _provenance(cls, v: dict[str, str]) -> dict[str, str]:
        for key, source in v.items():
            if source not in PROVENANCES:
                raise ValueError(f"provenance of {key} must be one of {', '.join(PROVENANCES)}")
        return v


class JobResource(_Model):
    """What the job builds from: the row as the webapp read it when it claimed the resource.
    The swap requires the row's url and storage_mode to be still these (resource_changed)."""

    url: str = Field(min_length=1, max_length=2048)
    slug: SlugStr
    name: str = Field(min_length=1, max_length=500)
    storage_mode: StorageMode
    forced_type: SiteTypeOrAuto = ""
    type_options: dict[str, Any] = Field(default_factory=dict)
    focus: dict[str, Any] = Field(default_factory=dict)
    summary: str = Field(default="", max_length=20000)
    summary_source: Annotated[str, _one_of(SUMMARY_SOURCES, "summary_source")] = "generated"
    summary_locked: bool = False
    model: str = Field(default="", max_length=300)


class JobStartRequest(_Model):
    job_id: IdStr
    user_id: IdStr
    resource_id: IdStr
    kind: str
    actor_user_id: IdStr
    real_actor_user_id: Optional[IdStr] = None
    bulk_id: Optional[IdStr] = None
    settings: dict[str, Any]
    settings_snapshot: SettingsSnapshot
    settings_hash: str = Field(pattern=r"^[0-9a-f]{16}$")
    resource: JobResource
    secrets: Secrets = Field(default_factory=Secrets)

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        # A conversion is a job of the whole account, started by its own route.
        if v not in JOB_KINDS or v == "convert":
            raise ValueError(f"kind must be one of {', '.join(k for k in JOB_KINDS if k != 'convert')}")
        return v


class JobStartBatch(_Model):
    """One request per action: a Refresh, or a whole Save & refresh all, so the per-user token
    bucket of require_internal_auth is spent once (D-49)."""

    jobs: list[JobStartRequest] = Field(min_length=1, max_length=JOB_START_BATCH_MAX)

    @model_validator(mode="after")
    def _distinct(self) -> "JobStartBatch":
        ids = [j.job_id for j in self.jobs]
        if len(set(ids)) != len(ids):
            raise ValueError("job_id must be unique in a batch")
        return self


class Refusal(_Model):
    job_id: IdStr
    code: Annotated[str, _one_of(ERROR_CODES, "code")]


class JobStartAnswer(_Model):
    accepted: list[str]
    refused: list[Refusal]


class CancelAnswer(_Model):
    ok: Literal[True]


class UserCancelAnswer(_Model):
    cancelled: int = Field(ge=0)


class ConvertAnswer(_Model):
    queued: int = Field(ge=0)


class JobProgress(_Model):
    """`tradecraft_ingestion_jobs.progress`: counts only, never page text or a URL."""

    done: int = Field(default=0, ge=0)
    total: Optional[int] = Field(default=None, ge=0)
    unit: Literal["pages", "entries", "files", "resources", ""] = ""


class Skipped(_Model):
    excluded: int = Field(default=0, ge=0)
    outOfScope: int = Field(default=0, ge=0)
    tooLittleText: int = Field(default=0, ge=0)
    robots: int = Field(default=0, ge=0)
    outsideFocus: int = Field(default=0, ge=0)


class StoredCounts(_Model):
    pages: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)
    notStoredQuota: int = Field(default=0, ge=0)
    notStoredSize: int = Field(default=0, ge=0)


class ReportError(_Model):
    """An error counted by code: no URL (it may carry a query string) and no page text."""

    code: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    count: int = Field(ge=1)


class IngestionReport(_Model):
    """`user_tradecraft_resources.ingestion_report`, the card's report (§3.3)."""

    visited: int = Field(default=0, ge=0)
    kept: int = Field(default=0, ge=0)
    skipped: Skipped = Field(default_factory=Skipped)
    stopReason: str = Field(default="", max_length=64)
    llmCalls: int = Field(default=0, ge=0)
    durationSec: float = Field(default=0, ge=0)
    stored: StoredCounts = Field(default_factory=StoredCounts)
    # Filled by the focus (T5.1) and the readiness line (Q4); counts and percentages only.
    focus: dict[str, Union[int, float, str]] = Field(default_factory=dict)
    readiness: dict[str, Union[int, float]] = Field(default_factory=dict)
    errors: list[ReportError] = Field(default_factory=list, max_length=50)


# --- synchronous routes --------------------------------------------------------------

class CheckUrlRequest(_Model):
    user_id: IdStr
    url: str = Field(min_length=1, max_length=2048)
    forced_type: SiteTypeOrAuto = ""
    type_options: dict[str, Any] = Field(default_factory=dict)
    settings: dict[str, Any] = Field(default_factory=dict)
    secrets: Secrets = Field(default_factory=Secrets)


class IndexInfo(_Model):
    kind: Annotated[str, _one_of(INDEX_KINDS, "kind")]
    url: str = Field(default="", max_length=2048)
    count: int = Field(default=0, ge=0)


class SampleEntry(_Model):
    url: str = Field(min_length=1, max_length=2048)
    title: str = Field(default="", max_length=500)


class GithubInfo(_Model):
    default_branch: str = Field(max_length=200)
    branches: list[str] = Field(default_factory=list, max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=500)
    top_folders: list[str] = Field(default_factory=list, max_length=500)


class CheckUrlResult(_Model):
    ok: bool
    error_code: ErrorCodeOrNone = ""
    final_url: str = Field(default="", max_length=2048)
    detected_type: SiteTypeOrAuto = ""
    needs_browser: bool = False
    robots_allows: Optional[bool] = None
    index: Optional[IndexInfo] = None
    sample_entries: list[SampleEntry] = Field(default_factory=list, max_length=CHECK_URL_SAMPLE_MAX)
    github: Optional[GithubInfo] = None
    pdf_pages: Optional[int] = Field(default=None, ge=0)
    recommended_storage: StorageMode = "live"
    estimated_bytes: int = Field(default=0, ge=0)
    cve_pattern: Optional[str] = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _ok_has_no_code(self) -> "CheckUrlResult":
        if self.ok == bool(self.error_code):
            raise ValueError("ok is true exactly when error_code is empty")
        return self


class PreviewRequest(_Model):
    user_id: IdStr
    model: str = Field(min_length=1, max_length=300)
    focus: dict[str, Any]
    entries: list[SampleEntry] = Field(min_length=1, max_length=PREVIEW_MAX_ENTRIES)


class PreviewExample(_Model):
    url: str = Field(min_length=1, max_length=2048)
    title: str = Field(default="", max_length=500)
    decision: Annotated[str, _one_of(PREVIEW_DECISIONS, "decision")]
    reason: str = Field(default="", max_length=300)
    topics: list[str] = Field(default_factory=list, max_length=30)
    kinds: list[str] = Field(default_factory=list, max_length=10)


class PreviewResult(_Model):
    kept: int = Field(default=0, ge=0)
    maybe: int = Field(default=0, ge=0)
    dropped: int = Field(default=0, ge=0)
    examples: list[PreviewExample] = Field(default_factory=list, max_length=PREVIEW_MAX_ENTRIES)
    llm_calls: int = Field(default=0, ge=0)
    error_code: ErrorCodeOrNone = ""


class ReadNowRequest(_Model):
    user_id: IdStr
    resource_id: IdStr
    url: str = Field(min_length=1, max_length=2048)
    read_settings: dict[str, Any] = Field(default_factory=dict)
    secrets: Secrets = Field(default_factory=Secrets)


class ReadNowResult(_Model):
    text: str = ""
    source: Annotated[str, _one_of(READ_SOURCES, "source")] = "live"
    # ISO 8601 date-time of the copy (stored) or of this read (live); "" when nothing was read.
    fetched_at: str = Field(default="", max_length=40)
    truncated: bool = False
    error_code: ErrorCodeOrNone = ""


# --- the run catalog (webapp -> agent) ----------------------------------------------

class LegacyResource(_Model):
    """A 1.x row: exactly the 7.7.2 columns of user_tradecraft_resources, so no 2.0 column
    (credentials above all) travels on the 1.x path."""

    id: str
    userId: str
    name: str
    slug: str
    url: str
    enabled: bool
    resourceType: str
    summary: str
    sitemap: Any
    crawlStoppedBecause: str
    crawlStats: Any
    llmModel: str
    githubTokenOverride: str
    cacheTtlSec: int
    lastVerifiedAt: Optional[str]
    lastRefreshedAt: Optional[str]
    lastError: str
    createdAt: str
    updatedAt: str


class LegacyCatalog(_Model):
    v2: Literal[False]
    legacy: list[LegacyResource]


class CatalogResource(_Model):
    id: IdStr
    slug: SlugStr
    name: str
    url: str = Field(min_length=1, max_length=2048)
    type: Annotated[str, _one_of(SITE_TYPES, "type")]
    storage_mode: StorageMode
    summary: str = ""
    has_login: bool = False
    priority: Annotated[str, _one_of(PRIORITIES, "priority")] = "normal"
    map_version: int = Field(ge=1, le=3)
    # The fetching and content values of the resource's snapshot (or the current effective ones).
    read_settings: dict[str, Any] = Field(default_factory=dict)
    github_token: Optional[SecretText] = Field(default=None, max_length=500)
    credentials: Optional[Credentials] = None

    @model_validator(mode="after")
    def _login_matches(self) -> "CatalogResource":
        if self.credentials is not None and not self.has_login:
            raise ValueError("credentials travel only on a resource with a login")
        return self


class V2Catalog(_Model):
    v2: Literal[True]
    owner_id: IdStr
    # Null for a request outside a person's run (R-155): it then lists no resource with a login.
    person_id: Optional[IdStr]
    # The administrator acting as the person; null otherwise.
    actor_id: Optional[IdStr] = None
    search: dict[str, Any] = Field(default_factory=dict)
    # No cap here: maxResourcesPerUser is checked when a resource is added (OQ-20), and an
    # account above it from before 2.0 keeps every resource in its runs.
    resources: list[CatalogResource] = Field(default_factory=list)

    @model_validator(mode="after")
    def _logins_only_for_the_owner(self) -> "V2Catalog":
        # §6.6: a resource with a login is removed completely from a run its owner does not
        # start alone (a collaborator, or an administrator acting as the owner).
        if self.person_id != self.owner_id or self.actor_id is not None:
            if any(r.has_login or r.credentials is not None for r in self.resources):
                raise ValueError("a resource with a login is listed only in its owner's own runs")
        return self


RunCatalog = Union[LegacyCatalog, V2Catalog]


def parse_catalog(data: Any) -> RunCatalog:
    """The catalog as the webapp sent it; raises pydantic.ValidationError otherwise."""
    if isinstance(data, dict) and data.get("v2") is True:
        return V2Catalog.model_validate(data)
    return LegacyCatalog.model_validate(data)


# --- the pipeline's entry (implemented by T1.8) ---------------------------------------

@dataclass
class JobContext:
    """What a running job hands the pipeline. The pipeline checks ``is_cancelled`` between
    pages and reports its stage through ``set_stage``; both write the job row."""

    request: JobStartRequest
    settings: _settings.EffectiveSettings
    target_generation: int
    is_cancelled: Callable[[], Awaitable[bool]]
    set_stage: Callable[[str, Optional[JobProgress]], Awaitable[None]]


@dataclass
class JobOutcome:
    status: Literal["succeeded", "failed", "cancelled"]
    error_code: str = ""
    report: Optional[IngestionReport] = None
    # True when the new generation became the live one (a failure with the "replace" policy swaps too).
    swapped: bool = False

    def __post_init__(self) -> None:
        if self.status not in ("succeeded", "failed", "cancelled"):
            raise ValueError("a finished job is succeeded, failed or cancelled")
        if self.error_code and self.error_code not in ERROR_CODES:
            raise ValueError(f"unknown error code {self.error_code}")
        if (self.status == "succeeded") == bool(self.error_code):
            raise ValueError("a succeeded job has no error code; a failed or cancelled one has one")


class PipelineEntry(Protocol):
    """``tradecraft.ingest.pipeline.run``: ``async def run(ctx: JobContext) -> JobOutcome``."""

    async def __call__(self, ctx: JobContext) -> JobOutcome: ...


MODELS: dict[str, type[_Model]] = {
    m.__name__: m
    for m in (
        JobStartBatch, JobStartRequest, JobStartAnswer, CancelAnswer, UserCancelAnswer, ConvertAnswer, JobProgress,
        IngestionReport, CheckUrlRequest, CheckUrlResult, PreviewRequest, PreviewResult, ReadNowRequest,
        ReadNowResult, LegacyCatalog, V2Catalog, CatalogResource, Credentials, Secrets,
    )
}
