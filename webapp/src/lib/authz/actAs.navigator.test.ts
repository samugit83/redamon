/**
 * Ending act-as ends the AI Navigator answers opened under it (plan §5.6, §10.2 row 29): the runs
 * bound to that impersonation's start row, with or without `closeSockets`; a binding that names no
 * start ends the pair's runs only when this call ended the impersonation.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const h = vi.hoisted(() => ({ latest: null as null | { id: string; event: string; durationMinutes: number | null; createdAt: Date } }))
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/auditForward', () => ({
  auditedTransaction: async (_db: unknown, fn: (tx: unknown) => unknown) => fn({
    $executeRaw: async () => 1,
    $queryRaw: async () => [],
    actAsAudit: { findFirst: async () => h.latest },
  }),
  createActAsAuditRow: async () => ({}),
}))
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn(async () => ({ ok: true, closed: 0 })) }))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => {} }))

import { recordActAsEnd } from './actAs'
import { navigatorRuns, clearNavigatorRunsForTests, setStopNotifierForTests } from '@/lib/navigator/runRegistry'

function live(personId: string, adminId: string | null, startId: string | null) {
  const r = navigatorRuns().reserve({ personId, projectId: `P-${personId}-${startId}` })
  if (!r.ok) throw new Error()
  navigatorRuns().complete(r.runId, { threadId: `T-${r.runId}`, tenantId: 'owner', actorId: adminId,
    login: { userId: adminId ?? personId, sessionVersion: 0, deviceSessionId: null, actAsStartId: startId } })
  return navigatorRuns().get(r.runId)!
}

beforeEach(() => {
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})

describe('recordActAsEnd and AI Navigator', () => {
  test.each([true, false])('ends the runs bound to that start (closeSockets %s), not the person\'s own or another start\'s', async (closeSockets) => {
    h.latest = { id: 'start-1', event: 'start', durationMinutes: 60, createdAt: new Date() }
    const bound = live('alice', 'admin', 'start-1')
    const ownRun = live('alice', null, null)
    const older = live('bob', 'admin', 'start-0')
    expect(await recordActAsEnd({ adminId: 'admin', targetUserId: 'alice', endedBy: 'stopped', binding: { startId: 'start-1' }, closeSockets })).toBe(true)
    expect(bound.abort.signal.aborted).toBe(true)
    expect(ownRun.abort.signal.aborted).toBe(false)
    expect(older.abort.signal.aborted).toBe(false)
  })

  test('a start already ended elsewhere still ends its runs', async () => {
    h.latest = { id: 'start-1', event: 'end', durationMinutes: null, createdAt: new Date() }
    const bound = live('alice', 'admin', 'start-1')
    expect(await recordActAsEnd({ adminId: 'admin', targetUserId: 'alice', endedBy: 'expired', binding: { startId: 'start-1' } })).toBe(false)
    expect(bound.abort.signal.aborted).toBe(true)
  })

  test('an open binding ends the pair\'s runs only when this call ended it', async () => {
    const run = live('alice', 'admin', 'start-9')
    h.latest = { id: 'start-9', event: 'end', durationMinutes: null, createdAt: new Date() }
    await recordActAsEnd({ adminId: 'admin', targetUserId: 'alice', endedBy: 'stopped' })
    expect(run.abort.signal.aborted).toBe(false)
    h.latest = { id: 'start-9', event: 'start', durationMinutes: 60, createdAt: new Date() }
    await recordActAsEnd({ adminId: 'admin', targetUserId: 'alice', endedBy: 'stopped' })
    expect(run.abort.signal.aborted).toBe(true)
  })
})
