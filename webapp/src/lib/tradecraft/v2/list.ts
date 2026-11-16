/**
 * The account's 2.0 resources as the Tradecraft tab shows them: no map, no secret value (a
 * secret reads as set or not), the number of map entries, the latest job, and whether the
 * resource was ingested with settings other than today's (the stale badge, R-029, R-192).
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { IngestionReport } from '../agentContract'
import { effectiveSettings } from '../effectiveSettings'
import { jobView, sweepLostJobs, type JobView } from '../jobs'
import { maskCredentials, secretState, type MaskedCredentials } from '../masking'
import { isStale } from '../staleness'

const VIEW_SELECT = {
  id: true, name: true, slug: true, url: true, enabled: true, resourceType: true, forcedType: true, storageMode: true,
  llmModel: true, githubTokenOverride: true, hasLogin: true, credentials: true, priority: true, mapVersion: true, generation: true,
  summary: true, summarySource: true, summaryLocked: true, settingsHash: true, overrides: true, ingestionReport: true, focus: true,
  lastVerifiedAt: true, lastRefreshedAt: true, lastError: true, createdAt: true, updatedAt: true,
} satisfies Prisma.UserTradecraftResourceSelect

type ViewRow = Prisma.UserTradecraftResourceGetPayload<{ select: typeof VIEW_SELECT }>

export interface ResourceView {
  id: string
  name: string
  slug: string
  url: string
  enabled: boolean
  resourceType: string
  forcedType: string
  storageMode: string
  llmModel: string
  githubTokenOverride: '' | 'set'
  hasLogin: boolean
  /** The site login masked (§6.6): header names and the user name, every value "set" or empty. */
  credentials: MaskedCredentials
  priority: string
  /** 1: a 1.x map only; 2: converted from 1.x; 3: ingested by 2.0. */
  mapVersion: number
  /** The resource's own settings (§6.1), for its Edit form; no secret is ever one. */
  overrides: Record<string, unknown>
  /** The ingestion focus (§6.14) as saved; `{}` is Everything. */
  focus: Record<string, unknown>
  summary: string
  summarySource: string
  summaryLocked: boolean
  report: IngestionReport | null
  lastVerifiedAt: string | null
  lastRefreshedAt: string | null
  lastError: string
  entryCount: number
  /** Ingested by 2.0 otherwise than it is configured today (staleness.ts). */
  stale: boolean
  job: JobView | null
  createdAt: string
  updatedAt: string
}

/** The entries of a 1.x map, counted as the 1.x list counts them. */
export function legacyEntryCount(sitemap: unknown): number {
  if (!sitemap || typeof sitemap !== 'object' || Array.isArray(sitemap)) return 0
  const s = sitemap as Record<string, unknown>
  return ['nav', 'tree', 'pages', 'links'].reduce((n, k) => n + (Array.isArray(s[k]) ? (s[k] as unknown[]).length : 0), 0)
}

function reportOf(stored: unknown): IngestionReport | null {
  if (!stored || typeof stored !== 'object' || Array.isArray(stored) || Object.keys(stored).length === 0) return null
  const parsed = IngestionReport.safeParse(stored)
  return parsed.success ? parsed.data : null
}

function view(row: ViewRow, extra: { entryCount: number; currentHash: string; job: JobView | null }): ResourceView {
  const report = reportOf(row.ingestionReport)
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    url: row.url,
    enabled: row.enabled,
    resourceType: row.resourceType,
    forcedType: row.forcedType,
    storageMode: row.storageMode,
    llmModel: row.llmModel,
    githubTokenOverride: secretState(row.githubTokenOverride),
    hasLogin: row.hasLogin,
    credentials: maskCredentials(row.credentials),
    priority: row.priority,
    mapVersion: row.mapVersion,
    overrides: row.overrides && typeof row.overrides === 'object' && !Array.isArray(row.overrides) ? row.overrides as Record<string, unknown> : {},
    focus: row.focus && typeof row.focus === 'object' && !Array.isArray(row.focus) ? row.focus as Record<string, unknown> : {},
    summary: row.summary,
    summarySource: row.summarySource,
    summaryLocked: row.summaryLocked,
    report,
    lastVerifiedAt: row.lastVerifiedAt?.toISOString() ?? null,
    lastRefreshedAt: row.lastRefreshedAt?.toISOString() ?? null,
    lastError: row.lastError,
    entryCount: extra.entryCount,
    stale: isStale(row, extra.currentHash, report),
    job: extra.job,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  }
}

async function views(ownerId: string, where: Prisma.UserTradecraftResourceWhereInput): Promise<ResourceView[]> {
  await sweepLostJobs(ownerId)
  const rows = await prisma.userTradecraftResource.findMany({ where: { ...where, userId: ownerId }, orderBy: { createdAt: 'asc' }, select: VIEW_SELECT })
  if (rows.length === 0) return []
  const ids = rows.map(r => r.id)
  const [user, counts, legacyMaps, jobs] = await Promise.all([
    prisma.tradecraftUserSettings.findUnique({ where: { userId: ownerId }, select: { ingestion: true } }),
    prisma.tradecraftEntry.groupBy({
      by: ['resourceId', 'generation'],
      where: { userId: ownerId, resourceId: { in: ids }, status: 'kept' },
      _count: { _all: true },
    }),
    // A 1.x map is read here only to count it; it is never answered.
    rows.some(r => r.mapVersion === 1)
      ? prisma.userTradecraftResource.findMany({ where: { userId: ownerId, id: { in: ids }, mapVersion: 1 }, select: { id: true, sitemap: true } })
      : Promise.resolve([]),
    prisma.tradecraftIngestionJob.findMany({
      where: { userId: ownerId, resourceId: { in: ids } }, orderBy: { createdAt: 'desc' }, distinct: ['resourceId'],
    }),
  ])
  const legacyCount = new Map(legacyMaps.map(m => [m.id, legacyEntryCount(m.sitemap)]))
  const liveCount = new Map(counts.map(c => [`${c.resourceId}|${c.generation}`, c._count._all]))
  const latest = new Map(jobs.map(j => [j.resourceId, jobView(j)]))
  return rows.map(row => view(row, {
    entryCount: row.mapVersion === 1 ? (legacyCount.get(row.id) ?? 0) : (liveCount.get(`${row.id}|${row.generation}`) ?? 0),
    currentHash: effectiveSettings({ user, resource: row.overrides }).hash,
    job: latest.get(row.id) ?? null,
  }))
}

export async function listResourcesV2(ownerId: string): Promise<ResourceView[]> {
  return views(ownerId, {})
}

export async function resourceViewOf(ownerId: string, resourceId: string): Promise<ResourceView | null> {
  return (await views(ownerId, { id: resourceId }))[0] ?? null
}
