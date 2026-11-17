/**
 * The Tradecraft 2.0 contract between the webapp and the agent (phase 1, T1.3): every body
 * that crosses the boundary, as zod schemas the webapp parses answers with and builds
 * requests against. agentic/tradecraft/contract.py holds the same models; both sides parse
 * the fixtures of agentic/tests/fixtures/tradecraft_contract/ and compare their enum lists
 * with its enums.json, so a change on one side fails a test on both.
 *
 * Secrets go to the agent only as the webapp read them from the resource's row: a body
 * carrying the "set" placeholder the browser sees is refused. The run catalog names no
 * generation (readers take the live one at each call, TD-9), and lists a resource with a
 * login only in its owner's own runs (§6.6).
 */
import { z } from 'zod'
import { SETTINGS_CONSTANTS } from './settingsSpec'

export const CONTRACT_VERSION = 1

export const JOB_KINDS = ['add', 'refresh', 'reingest', 'bulk', 'regenerate_summary', 'convert', 'pdf_convert'] as const
export const JOB_STATUSES = ['queued', 'running', 'succeeded', 'failed', 'cancelled'] as const
export const UNFINISHED_JOB_STATUSES = ['queued', 'running'] as const
export const JOB_STAGES = [
  'fetch_home', 'detect', 'build_map', 'curation', 'focus', 'titles', 'incremental', 'store', 'cards', 'sections',
  'tags', 'entities', 'tree', 'content_check', 'write', 'summary', 'report', 'legacy_map', 'swap', 'convert',
] as const
export const ERROR_CODES = [
  'fetch_failed', 'blocked_private_address', 'homepage_http_error', 'thin_homepage', 'llm_budget_exhausted',
  'loop_model_not_supported_here', 'model_unavailable', 'agent_restarted', 'agent_lost', 'agent_unreachable',
  'cancelled', 'resource_deleted', 'resource_changed', 'quota_reached', 'timeout', 'job_running', 'userinfo_refused',
  'job_not_claimed', 'queue_full', 'bad_url', 'not_implemented', 'page_blocked', 'outside_map', 'internal_error',
] as const
export const STORAGE_MODES = ['live', 'stored'] as const
export const SITE_TYPES = ['mkdocs-wiki', 'sphinx-docs', 'gitbook', 'github-repo', 'cve-poc-db', 'pdf', 'agentic-crawl'] as const
export const SUMMARY_SOURCES = ['generated', 'manual'] as const
export const PRIORITIES = ['high', 'normal', 'low'] as const
export const SKIP_REASONS = ['excluded', 'outOfScope', 'tooLittleText', 'robots', 'outsideFocus'] as const
export const INDEX_KINDS = ['sitemap', 'github_tree', 'searchindex', 'nav', 'pdf', 'none'] as const
export const PREVIEW_DECISIONS = ['keep', 'maybe', 'drop'] as const
export const READ_SOURCES = ['stored', 'live', 'live_not_stored'] as const
export const PROVENANCES = ['system', 'user', 'resource'] as const
export const PURPOSES = ['tradecraft_ingest', 'tradecraft_librarian'] as const

export type JobKind = (typeof JOB_KINDS)[number]
export type JobStatus = (typeof JOB_STATUSES)[number]
export type JobStage = (typeof JOB_STAGES)[number]
export type ErrorCode = (typeof ERROR_CODES)[number]
export type StorageMode = (typeof STORAGE_MODES)[number]
export type SiteType = (typeof SITE_TYPES)[number]

/** What the browser sees for a stored secret; never a secret itself. */
export const SECRET_PLACEHOLDER = 'set'

/**
 * A resource ID (the slug): what slugify makes, lowercase letters, digits and dashes from a
 * letter or digit on; it may end with a dash (the name is cut after the dashes are trimmed)
 * or hold two (a "-2" suffix). Page IDs (`<slug>:<n>`) use the same pattern on the agent side.
 */
export const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,199}$/

export const JOB_START_BATCH_MAX: number = SETTINGS_CONSTANTS.jobStartBatchMax
const PREVIEW_MAX_ENTRIES: number = SETTINGS_CONSTANTS.previewEntries
const CHECK_URL_SAMPLE_MAX: number = SETTINGS_CONSTANTS.checkUrlSampleEntries

/** The agent ends each synchronous route at its deadline with error_code "timeout". */
export const AGENT_DEADLINES_SEC = {
  checkUrl: SETTINGS_CONSTANTS.checkUrlDeadlineSec,
  previewFocus: SETTINGS_CONSTANTS.focusPreviewDeadlineSec,
  readNow: SETTINGS_CONSTANTS.readNowDeadlineSec,
} as const
/** agentFetch's timeout for each: the agent's deadline plus the margin (its default is 30 s). */
export const WEBAPP_TIMEOUTS_MS = {
  checkUrl: (AGENT_DEADLINES_SEC.checkUrl + SETTINGS_CONSTANTS.webappDeadlineMarginSec) * 1000,
  previewFocus: (AGENT_DEADLINES_SEC.previewFocus + SETTINGS_CONSTANTS.webappDeadlineMarginSec) * 1000,
  readNow: (AGENT_DEADLINES_SEC.readNow + SETTINGS_CONSTANTS.webappDeadlineMarginSec) * 1000,
} as const

export const AGENT_ROUTES = {
  jobs: '/tradecraft/v2/jobs',
  cancelJob: (jobId: string) => `/tradecraft/v2/jobs/${encodeURIComponent(jobId)}/cancel`,
  cancelUser: (userId: string) => `/tradecraft/v2/users/${encodeURIComponent(userId)}/cancel`,
  checkUrl: '/tradecraft/v2/check-url',
  previewFocus: '/tradecraft/v2/preview-focus',
  readNow: '/tradecraft/v2/read-now',
  convert: (userId: string) => `/tradecraft/v2/users/${encodeURIComponent(userId)}/convert`,
} as const

const id = z.string().min(1).max(200)
const slug = z.string().regex(SLUG_RE)
const url = z.string().min(1).max(2048)
const secret = z.string().refine(v => v.trim() !== SECRET_PLACEHOLDER, 'a masked "set" placeholder is not a secret')
const errorCodeOrNone = z.union([z.literal(''), z.enum(ERROR_CODES)])
const siteTypeOrAuto = z.union([z.literal(''), z.enum(SITE_TYPES)])
const record = z.record(z.string(), z.unknown())

// --- secrets -------------------------------------------------------------------------

export const Header = z.object({ name: z.string().min(1).max(200), value: secret.max(8000) }).strict()
export const BasicAuth = z.object({ username: z.string().max(500), password: secret.max(2000) }).strict()
export const Credentials = z.object({
  cookie: secret.max(8000).default(''),
  headers: z.array(Header).max(50).default([]),
  basic_auth: BasicAuth.nullable().default(null),
}).strict()
export const Secrets = z.object({
  github_token: secret.max(500).nullable().default(null),
  credentials: Credentials.nullable().default(null),
}).strict()

// --- jobs ----------------------------------------------------------------------------

export const SettingsSnapshot = z.object({
  values: record,
  provenance: z.record(z.string(), z.enum(PROVENANCES)),
}).strict()

export const JobResource = z.object({
  url,
  slug,
  name: z.string().min(1).max(500),
  storage_mode: z.enum(STORAGE_MODES),
  forced_type: siteTypeOrAuto.default(''),
  type_options: record.default({}),
  focus: record.default({}),
  summary: z.string().max(20000).default(''),
  summary_source: z.enum(SUMMARY_SOURCES).default('generated'),
  summary_locked: z.boolean().default(false),
  model: z.string().max(300).default(''),
}).strict()

export const JobStartRequest = z.object({
  job_id: id,
  user_id: id,
  resource_id: id,
  // A conversion is a job of the whole account, started by its own route.
  kind: z.enum(JOB_KINDS).refine(k => k !== 'convert', 'a conversion is started by /users/{user_id}/convert'),
  actor_user_id: id,
  real_actor_user_id: id.nullable().default(null),
  bulk_id: id.nullable().default(null),
  settings: record,
  settings_snapshot: SettingsSnapshot,
  settings_hash: z.string().regex(/^[0-9a-f]{16}$/),
  resource: JobResource,
  secrets: Secrets.default({ github_token: null, credentials: null }),
}).strict()

/** One request per action (a Refresh, or a whole Save & refresh all): one token of the agent's per-user bucket (D-49). */
export const JobStartBatch = z.object({
  jobs: z.array(JobStartRequest).min(1).max(JOB_START_BATCH_MAX),
}).strict().refine(b => new Set(b.jobs.map(j => j.job_id)).size === b.jobs.length, 'job_id must be unique in a batch')

export const Refusal = z.object({ job_id: id, code: z.enum(ERROR_CODES) }).strict()
export const JobStartAnswer = z.object({ accepted: z.array(z.string()), refused: z.array(Refusal) }).strict()
export const CancelAnswer = z.object({ ok: z.literal(true) }).strict()
export const UserCancelAnswer = z.object({ cancelled: z.number().int().min(0) }).strict()
export const ConvertAnswer = z.object({ queued: z.number().int().min(0) }).strict()

/** tradecraft_ingestion_jobs.progress: counts only, never page text or a URL. */
export const JobProgress = z.object({
  done: z.number().int().min(0).default(0),
  total: z.number().int().min(0).nullable().default(null),
  unit: z.enum(['pages', 'entries', 'files', 'resources', '']).default(''),
}).strict()

const count = z.number().int().min(0).default(0)
export const IngestionReport = z.object({
  visited: count,
  kept: count,
  skipped: z.object({ excluded: count, outOfScope: count, tooLittleText: count, robots: count, outsideFocus: count }).strict()
    .default({ excluded: 0, outOfScope: 0, tooLittleText: 0, robots: 0, outsideFocus: 0 }),
  stopReason: z.string().max(64).default(''),
  llmCalls: count,
  durationSec: z.number().min(0).default(0),
  stored: z.object({ pages: count, bytes: count, notStoredQuota: count, notStoredSize: count }).strict()
    .default({ pages: 0, bytes: 0, notStoredQuota: 0, notStoredSize: 0 }),
  focus: z.record(z.string(), z.union([z.number(), z.string()])).default({}),
  readiness: z.record(z.string(), z.number()).default({}),
  // Counted by code: no URL (it may carry a query string) and no page text.
  errors: z.array(z.object({ code: z.string().max(64).regex(/^[a-z][a-z0-9_]*$/), count: z.number().int().min(1) }).strict())
    .max(50).default([]),
}).strict()

// --- synchronous routes --------------------------------------------------------------

export const CheckUrlRequest = z.object({
  user_id: id,
  url,
  forced_type: siteTypeOrAuto.default(''),
  type_options: record.default({}),
  settings: record.default({}),
  secrets: Secrets.default({ github_token: null, credentials: null }),
}).strict()

export const SampleEntry = z.object({ url, title: z.string().max(500).default('') }).strict()

export const CheckUrlResult = z.object({
  ok: z.boolean(),
  error_code: errorCodeOrNone.default(''),
  final_url: z.string().max(2048).default(''),
  detected_type: siteTypeOrAuto.default(''),
  needs_browser: z.boolean().default(false),
  robots_allows: z.boolean().nullable().default(null),
  index: z.object({ kind: z.enum(INDEX_KINDS), url: z.string().max(2048).default(''), count }).strict().nullable().default(null),
  sample_entries: z.array(SampleEntry).max(CHECK_URL_SAMPLE_MAX).default([]),
  github: z.object({
    default_branch: z.string().max(200),
    branches: z.array(z.string()).max(500).default([]),
    tags: z.array(z.string()).max(500).default([]),
    top_folders: z.array(z.string()).max(500).default([]),
  }).strict().nullable().default(null),
  pdf_pages: z.number().int().min(0).nullable().default(null),
  recommended_storage: z.enum(STORAGE_MODES).default('live'),
  estimated_bytes: count,
  cve_pattern: z.string().max(200).nullable().default(null),
}).strict().refine(r => r.ok === (r.error_code === ''), 'ok is true exactly when error_code is empty')

export const PreviewRequest = z.object({
  user_id: id,
  model: z.string().min(1).max(300),
  focus: record,
  entries: z.array(SampleEntry).min(1).max(PREVIEW_MAX_ENTRIES),
  // The effective ingestion settings a refresh of the resource would carry (focus.alwaysSkip above
  // all): the agent reads the focus with them, as the refresh does. Optional, so a body sent
  // without them is unchanged; the agent then reads the defaults.
  settings: record.optional(),
}).strict()

export const PreviewResult = z.object({
  kept: count,
  maybe: count,
  dropped: count,
  examples: z.array(z.object({
    url,
    title: z.string().max(500).default(''),
    decision: z.enum(PREVIEW_DECISIONS),
    reason: z.string().max(300).default(''),
    topics: z.array(z.string()).max(30).default([]),
    kinds: z.array(z.string()).max(10).default([]),
  }).strict()).max(PREVIEW_MAX_ENTRIES).default([]),
  llm_calls: count,
  error_code: errorCodeOrNone.default(''),
}).strict()

export const ReadNowRequest = z.object({
  user_id: id,
  resource_id: id,
  url,
  read_settings: record.default({}),
  secrets: Secrets.default({ github_token: null, credentials: null }),
}).strict()

export const ReadNowResult = z.object({
  text: z.string().default(''),
  source: z.enum(READ_SOURCES).default('live'),
  fetched_at: z.string().max(40).default(''),
  truncated: z.boolean().default(false),
  error_code: errorCodeOrNone.default(''),
}).strict()

// --- the run catalog (webapp -> agent) ----------------------------------------------

/** A 1.x row: exactly the 7.7.2 columns, read with an explicit select so no 2.0 column travels. */
export const LegacyResource = z.object({
  id: z.string(),
  userId: z.string(),
  name: z.string(),
  slug: z.string(),
  url: z.string(),
  enabled: z.boolean(),
  resourceType: z.string(),
  summary: z.string(),
  sitemap: z.json(),
  crawlStoppedBecause: z.string(),
  crawlStats: z.json(),
  llmModel: z.string(),
  githubTokenOverride: z.string(),
  cacheTtlSec: z.number().int(),
  lastVerifiedAt: z.string().nullable(),
  lastRefreshedAt: z.string().nullable(),
  lastError: z.string(),
  createdAt: z.string(),
  updatedAt: z.string(),
}).strict()

/** The columns LegacyResource names, for the catalog's explicit Prisma select. */
export const LEGACY_RESOURCE_COLUMNS = Object.keys(LegacyResource.shape) as (keyof typeof LegacyResource.shape)[]

export const LegacyCatalog = z.object({ v2: z.literal(false), legacy: z.array(LegacyResource) }).strict()

export const CatalogResource = z.object({
  id,
  slug,
  name: z.string(),
  url,
  type: z.enum(SITE_TYPES),
  storage_mode: z.enum(STORAGE_MODES),
  summary: z.string().default(''),
  has_login: z.boolean().default(false),
  priority: z.enum(PRIORITIES).default('normal'),
  map_version: z.number().int().min(1).max(3),
  read_settings: record.default({}),
  github_token: secret.max(500).nullable().default(null),
  credentials: Credentials.nullable().default(null),
}).strict().refine(r => r.credentials === null || r.has_login, 'credentials travel only on a resource with a login')

export const V2Catalog = z.object({
  v2: z.literal(true),
  owner_id: id,
  // Null for a request outside a person's run (R-155): it then lists no resource with a login.
  person_id: id.nullable(),
  actor_id: id.nullable().default(null),
  search: record.default({}),
  // No cap here: maxResourcesPerUser is checked when a resource is added (OQ-20), and an
  // account above it from before 2.0 keeps every resource in its runs.
  resources: z.array(CatalogResource).default([]),
}).strict().refine(
  c => (c.person_id === c.owner_id && c.actor_id === null) || c.resources.every(r => !r.has_login && r.credentials === null),
  'a resource with a login is listed only in its owner\'s own runs',
)

export const RunCatalog = z.union([LegacyCatalog, V2Catalog])

export type Credentials = z.infer<typeof Credentials>
export type Secrets = z.infer<typeof Secrets>
export type JobResource = z.infer<typeof JobResource>
export type JobStartRequest = z.infer<typeof JobStartRequest>
export type JobStartBatch = z.infer<typeof JobStartBatch>
export type JobStartAnswer = z.infer<typeof JobStartAnswer>
export type JobProgress = z.infer<typeof JobProgress>
export type IngestionReport = z.infer<typeof IngestionReport>
export type CheckUrlRequest = z.infer<typeof CheckUrlRequest>
export type CheckUrlResult = z.infer<typeof CheckUrlResult>
export type PreviewRequest = z.infer<typeof PreviewRequest>
export type PreviewResult = z.infer<typeof PreviewResult>
export type ReadNowRequest = z.infer<typeof ReadNowRequest>
export type ReadNowResult = z.infer<typeof ReadNowResult>
export type LegacyResource = z.infer<typeof LegacyResource>
export type CatalogResource = z.infer<typeof CatalogResource>
export type V2Catalog = z.infer<typeof V2Catalog>
export type RunCatalog = z.infer<typeof RunCatalog>

/** Every top-level schema by its name in the fixtures (`<Name>.valid.json`, invalid.json's `model`). */
export const CONTRACT_SCHEMAS = {
  JobStartBatch, JobStartRequest, JobStartAnswer, CancelAnswer, UserCancelAnswer, ConvertAnswer, JobProgress, IngestionReport,
  CheckUrlRequest, CheckUrlResult, PreviewRequest, PreviewResult, ReadNowRequest, ReadNowResult, LegacyCatalog, V2Catalog,
  CatalogResource, Credentials, Secrets,
} as const
