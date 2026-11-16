/**
 * AI Navigator retention (plan §6.2, D13). A thread with no activity for the project's data retention
 * is deleted: `max(roeDataRetentionDays, NAVIGATOR_MIN_RETENTION_DAYS)` days, so a retention of 0
 * counts as one day and a conversation in use is never deleted. A thread with a live run is never
 * deleted. Lowering the value applies at the next purge.
 *
 * Two triggers: lazily when the person lists their threads on a project, and a part of the expiry
 * sweep (expirySweep.ts) for projects nobody opens, which also removes any thread that somehow has
 * no message (the API never creates one).
 */
import prisma from '@/lib/prisma'
import { EMPTY_THREAD_MAX_AGE_S, NAVIGATOR_DEFAULT_RETENTION_DAYS, NAVIGATOR_MIN_RETENTION_DAYS } from './constants'
import { navigatorRuns } from './runRegistry'

const DAY_MS = 86_400_000
const SWEEP_BATCH = 5000

export function effectiveRetentionDays(roeDataRetentionDays: number | null | undefined): number {
  const days = typeof roeDataRetentionDays === 'number' && Number.isFinite(roeDataRetentionDays)
    ? Math.trunc(roeDataRetentionDays) : NAVIGATOR_DEFAULT_RETENTION_DAYS
  return Math.max(days, NAVIGATOR_MIN_RETENTION_DAYS)
}

export async function projectRetentionDays(projectId: string): Promise<number> {
  const row = await prisma.project.findUnique({ where: { id: projectId }, select: { roeDataRetentionDays: true } })
  return effectiveRetentionDays(row?.roeDataRetentionDays)
}

function notLive(ids: string[]): string[] {
  const live = navigatorRuns().liveThreadIds()
  return ids.filter((id) => !live.has(id))
}

/** The lazy purge of one project's expired threads. Answers how many went. */
export async function purgeProjectThreads(projectId: string, now = new Date()): Promise<number> {
  const days = await projectRetentionDays(projectId)
  const stale = await prisma.navigatorThread.findMany({
    where: { projectId, lastMessageAt: { lt: new Date(now.getTime() - days * DAY_MS) } },
    select: { id: true },
    take: SWEEP_BATCH,
  })
  const ids = notLive(stale.map((t) => t.id))
  if (!ids.length) return 0
  return (await prisma.navigatorThread.deleteMany({ where: { id: { in: ids } } })).count
}

/**
 * The sweep part: every project's expired threads, and the empty-thread backstop. Purged project by
 * project, each with its own cutoff in the query: one batch read across every project could keep
 * answering the same unexpired threads of a long retention and never reach another's expired ones.
 */
export async function sweepNavigatorRetention(now = new Date()): Promise<number> {
  const projects = await prisma.navigatorThread.groupBy({
    by: ['projectId'],
    where: { lastMessageAt: { lt: new Date(now.getTime() - NAVIGATOR_MIN_RETENTION_DAYS * DAY_MS) } },
  })
  let removed = 0
  for (const { projectId } of projects) removed += await purgeProjectThreads(projectId, now)
  const empty = await prisma.navigatorThread.findMany({
    where: { messages: { none: {} }, createdAt: { lt: new Date(now.getTime() - EMPTY_THREAD_MAX_AGE_S * 1000) } },
    select: { id: true },
    take: SWEEP_BATCH,
  })
  const ids = notLive(empty.map((t) => t.id))
  if (!ids.length) return removed
  return removed + (await prisma.navigatorThread.deleteMany({ where: { id: { in: ids } } })).count
}
