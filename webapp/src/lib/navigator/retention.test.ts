/**
 * AI Navigator retention (plan §6.2): a retention of 0 counts as one day; lowering it applies at the
 * next purge; a thread with a live run is never deleted; the empty-thread backstop.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

type T = { id: string; projectId: string; lastMessageAt: Date; createdAt: Date; messages: number; retention: number }
const h = vi.hoisted(() => ({ threads: [] as T[] }))
vi.mock('@/lib/prisma', () => ({ default: {
  project: { findUnique: async ({ where }: { where: { id: string } }) => ({ roeDataRetentionDays: h.threads.find((t) => t.projectId === where.id)?.retention ?? 90 }) },
  navigatorThread: {
    findMany: async ({ where, take }: { where: Record<string, unknown>; take?: number }) => h.threads.filter((t) => {
      if (where.projectId && t.projectId !== where.projectId) return false
      const lm = where.lastMessageAt as { lt: Date } | undefined
      if (lm && !(t.lastMessageAt < lm.lt)) return false
      if (where.messages && t.messages !== 0) return false
      const ca = where.createdAt as { lt: Date } | undefined
      if (ca && !(t.createdAt < ca.lt)) return false
      return true
    }).slice(0, take ?? Infinity)
      .map((t) => ({ id: t.id, lastMessageAt: t.lastMessageAt, project: { roeDataRetentionDays: t.retention } })),
    groupBy: async ({ where }: { where: { lastMessageAt: { lt: Date } } }) =>
      [...new Set(h.threads.filter((t) => t.lastMessageAt < where.lastMessageAt.lt).map((t) => t.projectId))]
        .map((projectId) => ({ projectId })),
    deleteMany: async ({ where }: { where: { id: { in: string[] } } }) => {
      const n = h.threads.length
      h.threads = h.threads.filter((t) => !where.id.in.includes(t.id))
      return { count: n - h.threads.length }
    },
  },
} }))

import { effectiveRetentionDays, purgeProjectThreads, sweepNavigatorRetention } from './retention'
import { navigatorRuns, clearNavigatorRunsForTests, setStopNotifierForTests } from './runRegistry'

const NOW = new Date('2026-11-15T12:00:00Z')
const daysAgo = (d: number) => new Date(NOW.getTime() - d * 86_400_000)
const thread = (id: string, days: number, over: Partial<T> = {}): T => ({
  id, projectId: 'P1', lastMessageAt: daysAgo(days), createdAt: daysAgo(days), messages: 2, retention: 90, ...over,
})

beforeEach(() => {
  h.threads = []
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
})

describe('retention', () => {
  test('0 counts as one day; null is the default 90', () => {
    expect(effectiveRetentionDays(0)).toBe(1)
    expect(effectiveRetentionDays(30)).toBe(30)
    expect(effectiveRetentionDays(null)).toBe(90)
  })

  test('the lazy purge deletes only the project\'s expired threads', async () => {
    h.threads = [thread('old', 100), thread('new', 5), thread('elsewhere', 100, { projectId: 'P2' })]
    expect(await purgeProjectThreads('P1', NOW)).toBe(1)
    expect(h.threads.map((t) => t.id)).toEqual(['new', 'elsewhere'])
  })

  test('lowering the retention applies at the next purge; 0 keeps today\'s', async () => {
    h.threads = [thread('a', 3, { retention: 0 }), thread('b', 0.5, { retention: 0 })]
    expect(await purgeProjectThreads('P1', NOW)).toBe(1)
    expect(h.threads.map((t) => t.id)).toEqual(['b'])
  })

  test('a thread with a live run is never deleted', async () => {
    h.threads = [thread('busy', 200)]
    const r = navigatorRuns().reserve({ personId: 'alice', projectId: 'P1' })
    if (!r.ok) throw new Error()
    navigatorRuns().complete(r.runId, { threadId: 'busy', tenantId: 'o', actorId: null,
      login: { userId: 'alice', sessionVersion: 0, deviceSessionId: null, actAsStartId: null } })
    expect(await purgeProjectThreads('P1', NOW)).toBe(0)
    expect(await sweepNavigatorRetention(NOW)).toBe(0)
  })

  test('the sweep: every project, by its own retention, and the empty-thread backstop', async () => {
    h.threads = [
      thread('p1-old', 40, { retention: 30 }),
      thread('p2-young', 40, { projectId: 'P2', retention: 90 }),
      thread('empty-old', 0.2, { messages: 0, createdAt: new Date(NOW.getTime() - 2 * 3600_000) }),
      thread('empty-new', 0, { messages: 0, createdAt: new Date(NOW.getTime() - 60_000) }),
    ]
    expect(await sweepNavigatorRetention(NOW)).toBe(2)
    expect(h.threads.map((t) => t.id).sort()).toEqual(['empty-new', 'p2-young'])
  })

  test('more unexpired threads than one batch never hide an expired one of another project', async () => {
    // One batch read across every project kept answering the same 5000 threads still inside a long
    // retention, so a short-retention project's expired threads were never reached.
    h.threads = [
      ...Array.from({ length: 5001 }, (_, i) => thread(`p1-kept-${i}`, 10, { retention: 90 })),
      thread('p2-expired', 30, { projectId: 'P2', retention: 7 }),
    ]
    expect(await sweepNavigatorRetention(NOW)).toBe(1)
    expect(h.threads.some((t) => t.id === 'p2-expired')).toBe(false)
    expect(h.threads).toHaveLength(5001)
  })
})
