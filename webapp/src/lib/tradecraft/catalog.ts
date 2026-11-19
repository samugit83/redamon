/**
 * Which tradecraft resources a run may use (TD-9): the one policy the agent's run catalog and
 * the project's counter badge (T4.8) both read, so they agree by construction.
 *
 * A resource is active in a project when it is enabled and nobody turned it off there (R-060,
 * AC-22, AC-23). A resource with a site login is listed only in its owner's own runs: the
 * person is the owner and no administrator acts as them (R-119, R-153); in any other run it is
 * left out entirely, and a run whose person is unknown counts as another person's (R-155).
 * A GitHub token serves the owner's own run only: the resource's override travels only there, and
 * the agent adds the run's account token (the project owner's) only there, and only for requests
 * inside the resource's own repository. Any other run reads public pages with no token.
 *
 * The catalog names no generation and no map: readers take the live generation from the row at
 * each call (TD-9, R-219).
 */
import type { UserTradecraftResource } from '@prisma/client'
import prisma from '@/lib/prisma'
import { CatalogResource, PRIORITIES, SITE_TYPES, V2Catalog, type SiteType } from './agentContract'
import { effectiveSettings } from './effectiveSettings'
import { hasStoredLogin } from './masking'
import { SETTINGS_CONSTANTS } from './settingsSpec'

export interface RunParties {
  /** The project's owner, read from the project row: whose library the run reads. */
  ownerId: string
  projectId: string
  /** The person the run acts for (the ticket's `sub`); null when unknown. */
  personId: string | null
  /** The administrator acting as that person (the ticket's `act`), or null. */
  actorId: string | null
}

/** The owner's own run: the only one a login may serve. */
export function isOwnerRun({ ownerId, personId, actorId }: Pick<RunParties, 'ownerId' | 'personId' | 'actorId'>): boolean {
  return personId !== null && personId === ownerId && !actorId
}

const ACTIVE_SELECT = {
  id: true, slug: true, name: true, url: true, resourceType: true, forcedType: true, storageMode: true, summary: true,
  hasLogin: true, priority: true, mapVersion: true, settingsSnapshot: true, overrides: true, githubTokenOverride: true,
  credentials: true,
} as const

type ActiveRow = Pick<UserTradecraftResource, keyof typeof ACTIVE_SELECT>

/** The owner's resources active in the project for this run, oldest first, logins already filtered. */
export async function activeResourcesFor(parties: RunParties): Promise<ActiveRow[]> {
  const [rows, offHere] = await Promise.all([
    prisma.userTradecraftResource.findMany({
      where: { userId: parties.ownerId, enabled: true },
      orderBy: { createdAt: 'asc' },
      select: ACTIVE_SELECT,
    }),
    prisma.tradecraftProjectChoice.findMany({ where: { projectId: parties.projectId }, select: { resourceId: true } }),
  ])
  const off = new Set(offHere.map(c => c.resourceId))
  const ownerRun = isOwnerRun(parties)
  return rows.filter(r => !off.has(r.id) && (ownerRun || !hasStoredLogin(r)))
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

const READ_KEY = /^(fetching|content)\./
// A CVE archive is read through its path patterns, branch and README fallback (§6.5, T4.2):
// the agent finds a CVE's file with them at every lookup.
const CVE_READ_KEY = /^type\.cve\./

/** The values a live read uses: those the resource was ingested with, else today's. Read now (T6.7) sends the same. */
export function readSettings(
  row: Pick<ActiveRow, 'settingsSnapshot' | 'overrides'>, user: { ingestion?: unknown } | null, type: string,
): Record<string, unknown> {
  const snapshot = isPlainObject(row.settingsSnapshot) && isPlainObject(row.settingsSnapshot.values) ? row.settingsSnapshot.values : null
  const values = snapshot && Object.keys(snapshot).length > 0 ? snapshot : effectiveSettings({ user, resource: row.overrides }).values
  const read = (k: string) => READ_KEY.test(k) || (type === 'cve-poc-db' && CVE_READ_KEY.test(k))
  return Object.fromEntries(Object.entries(values).filter(([k]) => read(k)))
}

function catalogEntry(row: ActiveRow, user: { ingestion?: unknown } | null, ownerRun: boolean): unknown {
  const type = row.forcedType || row.resourceType
  const login = hasStoredLogin(row)
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    url: row.url,
    type: ((SITE_TYPES as readonly string[]).includes(type) ? type : 'agentic-crawl') as SiteType,
    storage_mode: row.storageMode === 'stored' ? 'stored' : 'live',
    summary: row.summary,
    has_login: login,
    priority: (PRIORITIES as readonly string[]).includes(row.priority) ? row.priority : 'normal',
    map_version: row.mapVersion,
    read_settings: readSettings(row, user, type),
    github_token: ownerRun ? (row.githubTokenOverride || null) : null,
    credentials: ownerRun && login ? (row.credentials ?? {}) : null,
  }
}

/**
 * The account's own synonym pairs (Q11 "My synonyms", TD-14) as stored, at most
 * `maxUserSynonyms`: the agent's search expands them with the shipped list and skips any entry
 * it cannot read.
 */
function userSynonyms(user: { synonyms?: unknown } | null): unknown[] {
  return Array.isArray(user?.synonyms) ? user.synonyms.slice(0, SETTINGS_CONSTANTS.maxUserSynonyms) : []
}

export async function v2Catalog(parties: RunParties): Promise<V2Catalog> {
  const [rows, user] = await Promise.all([
    activeResourcesFor(parties),
    prisma.tradecraftUserSettings.findUnique({ where: { userId: parties.ownerId }, select: { ingestion: true, search: true, synonyms: true } }),
  ])
  const ownerRun = isOwnerRun(parties)
  // One row the contract refuses (a 1.x URL or token longer than 2.0 allows) is left out, not
  // the whole catalog; its log names the fields, never their values (R-K1, R-L3).
  const resources: CatalogResource[] = []
  for (const row of rows) {
    const parsed = CatalogResource.safeParse(catalogEntry(row, user, ownerRun))
    if (parsed.success) resources.push(parsed.data)
    else console.error(`[tradecraft] catalog_row_invalid resource=${row.id} fields=${[...new Set(parsed.error.issues.map(i => i.path.join('.')))].join(',')}`)
  }
  // Parsed before it leaves: the contract refuses a login in another person's run.
  return V2Catalog.parse({
    v2: true,
    owner_id: parties.ownerId,
    person_id: parties.personId,
    actor_id: parties.actorId,
    search: { ...effectiveSettings({ user, scope: 'search' }).values, synonyms: userSynonyms(user) },
    resources,
  })
}

/** The run catalog: since the cut-over (T9.3) every account's is the 2.0 catalog. */
export async function runCatalog(parties: RunParties): Promise<V2Catalog> {
  return v2Catalog(parties)
}
