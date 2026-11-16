/**
 * Which tradecraft resources a run may use (TD-9): the one policy the agent's run catalog and
 * the project's counter badge (T4.8) both read, so they agree by construction.
 *
 * A resource is active in a project when it is enabled and nobody turned it off there (R-060,
 * AC-22, AC-23). A resource with a site login is listed only in its owner's own runs: the
 * person is the owner and no administrator acts as them (R-119, R-153); in any other run it is
 * left out entirely, and a run whose person is unknown counts as another person's (R-155).
 * The GitHub token travels as it does today (R-156): the resource's own override in every run,
 * the agent adding the run's account token when there is none.
 *
 * The catalog names no generation and no map: readers take the live generation from the row at
 * each call (TD-9, R-219).
 */
import type { UserTradecraftResource } from '@prisma/client'
import prisma from '@/lib/prisma'
import {
  Credentials, PRIORITIES, SITE_TYPES, V2Catalog,
  type CatalogResource, type LegacyResource, type RunCatalog, type SiteType,
} from './agentContract'
import { effectiveSettings } from './effectiveSettings'
import { LEGACY_SELECT } from './resourceAccess'
import { tradecraftV2Enabled } from './switch'

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
  return rows.filter(r => !off.has(r.id) && (ownerRun || !r.hasLogin))
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

const READ_KEY = /^(fetching|content)\./

/** The values a live read uses: those the resource was ingested with, else today's. */
function readSettings(row: ActiveRow, user: { ingestion?: unknown } | null): Record<string, unknown> {
  const snapshot = isPlainObject(row.settingsSnapshot) && isPlainObject(row.settingsSnapshot.values) ? row.settingsSnapshot.values : null
  const values = snapshot && Object.keys(snapshot).length > 0 ? snapshot : effectiveSettings({ user, resource: row.overrides }).values
  return Object.fromEntries(Object.entries(values).filter(([k]) => READ_KEY.test(k)))
}

function catalogResource(row: ActiveRow, user: { ingestion?: unknown } | null, ownerRun: boolean): CatalogResource {
  const type = row.forcedType || row.resourceType
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    url: row.url,
    type: ((SITE_TYPES as readonly string[]).includes(type) ? type : 'agentic-crawl') as SiteType,
    storage_mode: row.storageMode === 'stored' ? 'stored' : 'live',
    summary: row.summary,
    has_login: row.hasLogin,
    priority: ((PRIORITIES as readonly string[]).includes(row.priority) ? row.priority : 'normal') as CatalogResource['priority'],
    map_version: row.mapVersion,
    read_settings: readSettings(row, user),
    github_token: row.githubTokenOverride || null,
    credentials: ownerRun && row.hasLogin ? Credentials.parse(row.credentials ?? {}) : null,
  }
}

/** The 1.x payload: the owner's rows with the 1.x columns, as the 1.x internal GET answers them. */
export async function legacyCatalog(ownerId: string): Promise<RunCatalog> {
  const legacy = await prisma.userTradecraftResource.findMany({ where: { userId: ownerId }, orderBy: { createdAt: 'asc' }, select: LEGACY_SELECT })
  return { v2: false, legacy: JSON.parse(JSON.stringify(legacy)) as LegacyResource[] }
}

export async function v2Catalog(parties: RunParties & { personId: string }): Promise<RunCatalog> {
  const [rows, user] = await Promise.all([
    activeResourcesFor(parties),
    prisma.tradecraftUserSettings.findUnique({ where: { userId: parties.ownerId }, select: { ingestion: true, search: true } }),
  ])
  const ownerRun = isOwnerRun(parties)
  // Parsed before it leaves: the contract refuses a login in another person's run.
  return V2Catalog.parse({
    v2: true,
    owner_id: parties.ownerId,
    person_id: parties.personId,
    actor_id: parties.actorId,
    search: effectiveSettings({ user, scope: 'search' }).values,
    resources: rows.map(r => catalogResource(r, user, ownerRun)),
  })
}

/** The run catalog: the 1.x payload while the owner's switch is off, else the 2.0 catalog. */
export async function runCatalog(parties: RunParties & { personId: string }): Promise<RunCatalog> {
  return (await tradecraftV2Enabled(parties.ownerId)) ? v2Catalog(parties) : legacyCatalog(parties.ownerId)
}
