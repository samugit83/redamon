/**
 * The browser's calls to the Tradecraft 2.0 routes. Every failure throws the ApiError of
 * `readApiError` (its message carries the code and the HTTP status), so a screen shows why.
 * The view types come from the server modules as types only: nothing server-side is bundled.
 */
import { fetchJson } from '@/lib/apiError'
import type { JobView } from './jobs'
import type { ResourceView } from './v2/list'
import type { IngestionSettingsView } from './userSettings'
import type { CheckUrlResult, PreviewResult } from './agentContract'
import type { Focus, UserRecipe } from './focus'

export type { IngestionSettingsView, JobView, ResourceView, UserRecipe }

/** How often a card's job view is read while its job runs. */
export const JOB_POLL_MS = 3000

const JSON_HEADERS = { 'Content-Type': 'application/json' }
const resources = (userId: string) => `/api/users/${encodeURIComponent(userId)}/tradecraft-resources`
const one = (userId: string, id: string) => `${resources(userId)}/${encodeURIComponent(id)}`

export interface ResourceInput {
  name?: string
  url?: string
  enabled?: boolean
  llmModel?: string
  githubTokenOverride?: string
  storageMode?: 'live' | 'stored'
  slug?: string
  forcedType?: string
  overrides?: Record<string, unknown>
  presetKey?: string
  /** `{}` is no focus (Everything). */
  focus?: Focus | Record<string, never>
}

/** The focus preview of a saved resource (its live map), or of the entries Check URL found. */
export type FocusPreviewInput =
  | { focus: Focus | Record<string, never>; resourceId: string; llmModel?: string }
  | { focus: Focus | Record<string, never>; entries: { url: string; title: string }[]; llmModel: string }

export type RecipeEdit =
  | { add: { name: string; topics: string[]; kinds: string[] } }
  | { rename: { id: string; name: string } }
  | { delete: string }

export interface CheckUrlInput {
  url?: string
  resourceId?: string
  forcedType?: string
  overrides?: Record<string, unknown>
  githubTokenOverride?: string
}

export interface SummaryInput {
  source?: 'generated' | 'manual'
  text?: string
  locked?: boolean
}

export interface SavedResource {
  resource: ResourceView | null
  job: JobView | null
  /** Set when the save succeeded but its ingestion did not start. */
  jobError?: string
}

export const tradecraftClient = {
  getSwitch: (userId: string) =>
    fetchJson<{ v2Enabled: boolean }>(`/api/users/${encodeURIComponent(userId)}/tradecraft-settings`, undefined, "Couldn't read the Tradecraft 2.0 switch"),
  setSwitch: (userId: string, v2Enabled: boolean) =>
    fetchJson<{ v2Enabled: boolean }>(`/api/users/${encodeURIComponent(userId)}/tradecraft-settings`, {
      method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify({ v2Enabled }),
    }, "Couldn't change the Tradecraft 2.0 switch"),
  getSettings: (userId: string) =>
    fetchJson<{ v2Enabled: boolean; ingestion?: IngestionSettingsView; recipes?: UserRecipe[] }>(
      `/api/users/${encodeURIComponent(userId)}/tradecraft-settings`, undefined, "Couldn't read your ingestion settings"),
  saveSettings: (userId: string, ingestion: Record<string, unknown>) =>
    fetchJson<{ v2Enabled: true; ingestion: IngestionSettingsView }>(`/api/users/${encodeURIComponent(userId)}/tradecraft-settings`, {
      method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify({ ingestion }),
    }, "Couldn't save your ingestion settings"),
  list: (userId: string) => fetchJson<ResourceView[]>(resources(userId), undefined, "Couldn't load your tradecraft resources"),
  create: (userId: string, input: ResourceInput) =>
    fetchJson<SavedResource>(resources(userId), { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(input) }, "Couldn't add the resource"),
  update: (userId: string, id: string, input: ResourceInput) =>
    fetchJson<SavedResource>(one(userId, id), { method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify(input) }, "Couldn't save the resource"),
  remove: (userId: string, id: string) =>
    fetchJson<{ success: true }>(one(userId, id), { method: 'DELETE' }, "Couldn't delete the resource"),
  refresh: (userId: string, id: string) =>
    fetchJson<{ job: JobView }>(`${one(userId, id)}/refresh`, { method: 'POST', headers: JSON_HEADERS, body: '{}' }, "Couldn't start the refresh"),
  editRecipes: (userId: string, edit: RecipeEdit) =>
    fetchJson<{ v2Enabled: true; recipes: UserRecipe[] }>(`/api/users/${encodeURIComponent(userId)}/tradecraft-settings`, {
      method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify({ recipes: edit }),
    }, "Couldn't save your recipes"),
  ownSkills: (userId: string) =>
    fetchJson<{ id: string; name: string }[]>(`/api/users/${encodeURIComponent(userId)}/attack-skills`, undefined, "Couldn't load your skills"),
  previewFocus: (userId: string, input: FocusPreviewInput) =>
    fetchJson<{ result: PreviewResult }>(`${resources(userId)}/focus-preview`, {
      method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(input),
    }, 'The focus preview failed'),
  checkUrl: (userId: string, input: CheckUrlInput) =>
    fetchJson<{ result: CheckUrlResult }>(`${resources(userId)}/check-url`, {
      method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(input),
    }, 'Check URL failed'),
  saveSummary: (userId: string, id: string, input: SummaryInput) =>
    fetchJson<{ resource: ResourceView | null }>(`${one(userId, id)}/summary`, {
      method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify(input),
    }, "Couldn't save the summary"),
  regenerateSummary: (userId: string, id: string) =>
    fetchJson<{ job: JobView }>(`${one(userId, id)}/summary/regenerate`, { method: 'POST', headers: JSON_HEADERS, body: '{}' }, "Couldn't start the summary job"),
  enabledImpact: (userId: string, id: string, next: boolean) =>
    fetchJson<{ next: boolean; projects: number; turnedOffIn: number }>(`${one(userId, id)}/enabled-impact?next=${next}`, undefined, "Couldn't read which projects follow"),
  job: (userId: string, id: string) =>
    fetchJson<{ job: JobView | null }>(`${one(userId, id)}/jobs`, undefined, "Couldn't read the job"),
  cancel: (userId: string, id: string) =>
    fetchJson<{ job: JobView | null }>(`${one(userId, id)}/jobs`, { method: 'DELETE' }, "Couldn't cancel the job"),
}

export function isRunning(job: Pick<JobView, 'status'> | null | undefined): boolean {
  return !!job && (job.status === 'queued' || job.status === 'running')
}

const STAGE_LABELS: Record<string, string> = {
  fetch_home: 'Reading the homepage', detect: 'Detecting the site type', build_map: 'Building the map',
  curation: 'Applying your curation', focus: 'Applying the focus', titles: 'Reading page titles',
  incremental: 'Checking what changed', store: 'Storing pages', cards: 'Writing page cards', sections: 'Splitting sections',
  tags: 'Tagging pages', entities: 'Finding names', tree: 'Building the folder tree', content_check: 'Checking content',
  write: 'Saving the map', summary: 'Writing the summary', report: 'Writing the report', legacy_map: 'Saving the map',
  swap: 'Switching to the new version', convert: 'Converting',
}

/** The card's words for a job: queued, the stage running, or how it ended. */
export function jobLabel(job: Pick<JobView, 'status' | 'stage' | 'cancelRequested' | 'errorCode'>): string {
  if (job.status === 'queued') return job.cancelRequested ? 'Cancelling…' : 'Queued'
  if (job.status === 'running') return job.cancelRequested ? 'Cancelling…' : (STAGE_LABELS[job.stage] ?? 'Starting')
  if (job.status === 'succeeded') return 'Ingested'
  if (job.status === 'cancelled') return 'Cancelled: the previous version is kept'
  return `Failed (${job.errorCode || 'unknown'}): the previous version is kept`
}

/**
 * When the resource was last refreshed, as the card and the project's accordion both say it. A
 * failed ingestion sets the 1.x verification time (TD-18): only a 2.0 swap, or a 1.x verify that
 * found nothing wrong, is a refresh worth naming.
 */
export function lastRefreshedOf(r: Pick<ResourceView, 'lastRefreshedAt' | 'lastVerifiedAt' | 'mapVersion' | 'lastError'>): string | null {
  return r.lastRefreshedAt ?? (r.mapVersion === 1 && !r.lastError ? r.lastVerifiedAt : null)
}

export function relTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'never'
  const t = new Date(iso).getTime()
  if (!Number.isFinite(t)) return 'never'
  const diff = now - t
  if (diff < 60_000) return 'just now'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return `${Math.floor(diff / 86_400_000)}d ago`
}
