/**
 * Deferred work on a shared project re-checks its actor when it fires (step 5.5, DV-38, SH-12),
 * end to end through the queue dispatch and the schedule run routes with the real access check
 * (`actorScanRefusal`: can(), projectAccess(), capabilities, sharing policy over sharedProjectDb):
 * a Read collaborator's queued job is cancelled and their schedule paused, nothing starts; the
 * owner's job and schedule start as before, with every switch on and with every switch off.
 * The start paths themselves (dispatchStart, startFullScan) are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
  job: null as Record<string, unknown> | null,
  schedule: null as Record<string, unknown> | null,
  jobUpdates: [] as Array<{ where: unknown; data: Record<string, unknown> }>,
  scheduleUpdates: [] as Array<{ where: unknown; data: Record<string, unknown> }>,
  dispatchStart: vi.fn(),
  startFullScan: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  isInternalRequest: () => true,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/startScan', () => ({
  dispatchStart: (...a: unknown[]) => h.dispatchStart(...a),
  stopScan: async () => undefined,
}))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: (...a: unknown[]) => h.startFullScan(...a) }))
vi.mock('@/lib/jobFingerprint', () => ({ currentFingerprintFor: async (row: { settingsHash: string }) => row.settingsHash }))
vi.mock('@/lib/agentSessions', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentSessions')>()),
  checkAgentSessions: async () => 'idle',
}))

import '@/lib/authz/guards'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { COLLABORATOR, OWNER, SHARED_PROJECT, resetSharedProjectDb, shareWith } from '@/lib/authz/__testing__/sharedProjectDb'
import { POST as dispatch } from './job-queue/[id]/dispatch/route'
import { POST as runSchedule } from './scan-schedules/[scheduleId]/run/route'

function clearCaches() {
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
}

function seedModels() {
  h.db.models.user = {
    findMany: (args: unknown) =>
      (args as { where: { id: { in: string[] } } }).where.id.in.map((id) => ({ id, status: 'active' })),
  }
  h.db.models.jobQueue = {
    findUnique: () => (h.job ? { ...h.job } : null),
    findFirst: () => null,
    updateMany: (args: unknown) => {
      h.jobUpdates.push(args as { where: unknown; data: Record<string, unknown> })
      return { count: 1 }
    },
  }
  h.db.models.scanSchedule = {
    findUnique: () => (h.schedule ? { ...h.schedule } : null),
    update: (args: unknown) => {
      h.scheduleUpdates.push(args as { where: unknown; data: Record<string, unknown> })
      return {}
    },
  }
}

const queued = (userId: string) => ({
  id: 'j1', projectId: SHARED_PROJECT, userId, kind: 'gvm', payload: {}, settingsHash: 'h1',
  status: 'queued', attempts: 0, maxAttempts: 20,
})
const scheduled = (userId: string) => ({
  id: 's1', projectId: SHARED_PROJECT, userId, mode: 'interval', scanMode: 'new', intervalMinutes: 60,
  cronExpr: null, enabled: true, lastRunAt: null,
})

const dispatchIt = async () => (await dispatch(
  new NextRequest('http://x/api/internal/job-queue/j1/dispatch', { method: 'POST', body: '{}' }),
  { params: Promise.resolve({ id: 'j1' }) },
)).json()
const runIt = async () => (await runSchedule(
  new NextRequest('http://x/api/internal/scan-schedules/s1/run', { method: 'POST', body: '{}' }),
  { params: Promise.resolve({ scheduleId: 's1' }) },
)).json()

beforeEach(() => {
  resetSharedProjectDb(h.db)
  seedModels()
  h.job = null
  h.schedule = null
  h.jobUpdates.length = 0
  h.scheduleUpdates.length = 0
  h.dispatchStart.mockReset().mockResolvedValue({ ok: true, status: 200, runId: '', scanJobId: 'sj1' })
  h.startFullScan.mockReset().mockResolvedValue({ ok: true, versionId: 'v2', versionSeq: 2, scanJobId: 'sj2', frozenVersionId: 'v1' })
  h.audit.mockReset()
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearCaches()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  clearCaches()
  vi.restoreAllMocks()
})

describe('a Read collaborator\'s deferred work', () => {
  test('dispatch cancels a job whose actor lost access (a Read share cannot start scans)', async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    h.job = queued(COLLABORATOR)
    expect(await dispatchIt()).toMatchObject({ ok: false, canceled: true, blocked: 'actor_no_access' })
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jobUpdates.at(-1)?.data).toMatchObject({ status: 'canceled', blockedCode: 'actor_no_access' })
    expect(h.audit.mock.calls[0][0]).toMatchObject({
      action: 'job_queue.cancelled', after: { reason: 'actor_no_access', permission: 'scan:gvm', refusal: 'project_level' },
    })
  })

  test('a job queued before the share was revoked is cancelled when it fires (late)', async () => {
    h.job = queued(COLLABORATOR)
    expect(await dispatchIt()).toMatchObject({ canceled: true, blocked: 'actor_no_access' })
    expect(h.audit.mock.calls[0][0].after).toMatchObject({ refusal: 'project_not_visible' })
  })

  test('schedule paused with a reason; nothing starts', async () => {
    shareWith(h.db, COLLABORATOR)
    h.schedule = scheduled(COLLABORATOR)
    expect(await runIt()).toMatchObject({ ok: false, paused: true, code: 'actor_no_access' })
    expect(h.startFullScan).not.toHaveBeenCalled()
    expect(h.scheduleUpdates).toHaveLength(1)
    expect(h.scheduleUpdates[0].data).toMatchObject({ enabled: false })
    expect(h.audit.mock.calls[0][0]).toMatchObject({ action: 'scan_schedule.paused', projectId: SHARED_PROJECT })
  })
})

describe.each([
  ['every switch on', { identity: true, permissions: true, sharing: true }],
  ['every switch off', null],
] as const)('the owner\'s deferred work, %s (owner unchanged)', (_name, flags) => {
  beforeEach(() => {
    setFlagsForTests(flags)
    clearCaches()
  })

  test('a queued job starts as its actor', async () => {
    h.job = queued(OWNER)
    expect(await dispatchIt()).toMatchObject({ ok: true })
    expect(h.dispatchStart).toHaveBeenCalledWith('gvm', SHARED_PROJECT, { actorUserId: OWNER, payload: {} })
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('a schedule starts as its actor', async () => {
    h.schedule = scheduled(OWNER)
    expect(await runIt()).toMatchObject({ ok: true })
    expect(h.startFullScan.mock.calls[0][0]).toMatchObject({ actorUserId: OWNER, scheduleId: 's1' })
    expect(h.audit).not.toHaveBeenCalled()
  })
})
