/**
 * Whether a resource's live version was ingested as it is configured today (§3.3, §6.13): the
 * card's "Ingested with older settings" badge. Three things make it stale:
 *   - its effective settings changed (the account's or its own overrides, `type.*` included);
 *   - its forced site type changed, which is no setting but changes what ingestion builds;
 *   - it is Stored, and its last ingestion did not take the Stored path: its pages are stored at
 *     the next ingestion.
 * Stored → Live is never stale: the stored text is deleted at once (§6.13), and the report's
 * stored counts go with it (`v2/update.ts`), so a later Live → Stored is stale again.
 *
 * The hash the job request carries is `ingestionHash`, so the one the agent writes at the swap
 * is compared with today's here. What §6.13 marks stale joins it: the forced type, the focus (the
 * fields the agent reads, not the recipe that filled the chips), and access (a site login by its
 * shape: whether a cookie is set, the header names, the basic user name; and whether a GitHub token
 * override is set). Never a secret value: rotating a cookie, a password or a token changes what the
 * site lets in, not the map, so it is no reason to re-ingest. Auto, no focus and no access keep the
 * plain settings hash, so the resources ingested before these joined it stay current.
 */
import type { IngestionReport } from './agentContract'
import { canonicalJson, sha256Hex } from './effectiveSettings'
import { forcedStorageMode } from './storageModes'

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

// The fields the agent's focus stage reads (`focus_of`); the recipe is only the form's memory.
const FOCUS_READ_KEYS = ['mode', 'topics', 'kinds', 'keep', 'skip', 'skipMode', 'strictness'] as const

/** The focus as the agent reads it, or null for none (no focus, or Everything, which filters nothing). */
function focusPart(focus: unknown): string | null {
  if (!isRecord(focus) || focus.mode === undefined || focus.mode === 'everything') return null
  return canonicalJson(Object.fromEntries(FOCUS_READ_KEYS.filter(k => k in focus).map(k => [k, focus[k]])))
}

/** A login by its shape, never a value: null when there is none. */
function loginPart(credentials: unknown): string | null {
  const c = isRecord(credentials) ? credentials : {}
  const cookie = typeof c.cookie === 'string' && c.cookie !== ''
  const headers = (Array.isArray(c.headers) ? c.headers : [])
    .flatMap(h => (isRecord(h) && typeof h.name === 'string' ? [h.name.toLowerCase()] : []))
    .sort()
  const basic = isRecord(c.basic_auth) && typeof c.basic_auth.username === 'string' ? c.basic_auth.username : null
  if (!cookie && headers.length === 0 && basic === null) return null
  return canonicalJson({ cookie, headers, basic })
}

export interface IngestionInputs {
  forcedType?: string
  focus?: unknown
  credentials?: unknown
  githubTokenOverride?: string
}

export function ingestionHash(settingsHash: string, { forcedType = '', focus, credentials, githubTokenOverride = '' }: IngestionInputs = {}): string {
  const f = focusPart(focus)
  const login = loginPart(credentials)
  const parts = [
    ...(forcedType ? [`forced_type:${forcedType}`] : []),
    ...(f ? [`focus:${f}`] : []),
    ...(login ? [`login:${login}`] : []),
    ...(githubTokenOverride ? ['github_token:set'] : []),
  ]
  return parts.length > 0 ? sha256Hex([settingsHash, ...parts].join('|')).slice(0, 16) : settingsHash
}

/**
 * The ingestion stored its pages, or counted the ones the quota or a size limit left out. The
 * second case is current: a re-ingestion under the same limits stores nothing more, so a badge
 * there could never be cleared.
 */
function tookStoredPath(report: IngestionReport): boolean {
  const s = report.stored
  return s.pages + s.notStoredQuota + s.notStoredSize > 0
}

export function isStale(
  row: { settingsHash: string; forcedType: string; resourceType: string; storageMode: string; focus?: unknown; credentials?: unknown; githubTokenOverride?: string },
  currentSettingsHash: string,
  report: IngestionReport | null,
): boolean {
  // A resource 2.0 never ingested has no hash: it shows the "before 2.0" badge instead.
  if (row.settingsHash === '') return false
  const current = ingestionHash(currentSettingsHash, {
    forcedType: row.forcedType, focus: row.focus, credentials: row.credentials, githubTokenOverride: row.githubTokenOverride,
  })
  if (row.settingsHash !== current) return true
  if (row.storageMode !== 'stored' || !report || report.kept === 0) return false
  // A CVE archive never stores text, whatever its row says.
  if (forcedStorageMode(row.forcedType || row.resourceType) === 'live') return false
  return !tookStoredPath(report)
}
