/**
 * POST /api/projects/[id]/schedules/[scheduleId]/confirm (step 5.5, D-13): a schedule whose actor
 * lost access is paused when it fires, never re-attributed silently; the owner (or, once Phase 5's
 * Manage level exists, a co-owner) confirms it and becomes its actor. The confirmer needs
 * `recon:schedule` at the Manage level and every permission the schedule's scans need, since they
 * now run as them; the request is same-origin JSON; the change is audited
 * `scan_schedule.confirmed` with the actor before and after.
 *
 * Real guard, can(), projectAccess(), capabilities and sharing policy over sharedProjectDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  identity: null as unknown,
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
  schedule: null as Record<string, unknown> | null,
  project: {} as Record<string, unknown>,
  updates: [] as Array<{ where: unknown; data: Record<string, unknown> }>,
  audit: vi.fn(),
}))

vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  ...(await import('@/lib/authz/__testing__/sharedProjectDb')).sessionOf(h),
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import '@/lib/authz/guards'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import {
  COLLABORATOR, OWNER, SHARED_PROJECT, STRANGER, account, identityOf, resetSharedProjectDb, shareWith,
} from '@/lib/authz/__testing__/sharedProjectDb'
import { POST } from './route'

const FUTURE = new Date(Date.now() + 86_400_000)

const PAUSED = {
  id: 's1', projectId: SHARED_PROJECT, userId: COLLABORATOR, label: 'nightly', mode: 'interval', runAt: null,
  intervalMinutes: 60, cronExpr: null, scanMode: 'new', enabled: false, nextRunAt: null, lastRunAt: new Date(0),
  estimatedEnvelopeBytes: null, createdAt: new Date(0), updatedAt: new Date(0),
}

function clearCaches() {
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
}

function seed() {
  h.db.models.project = {
    findUnique: (args: unknown) => {
      const { where } = args as { where: { id: string } }
      return where.id === SHARED_PROJECT ? { ...h.project } : null
    },
  }
  h.db.models.scanSchedule = {
    findUnique: () => (h.schedule ? { ...h.schedule } : null),
    update: (args: unknown) => {
      const call = args as { where: unknown; data: Record<string, unknown> }
      h.updates.push(call)
      return { ...h.schedule, ...call.data }
    },
  }
}

function confirm(opts: { origin?: string; contentType?: string; scheduleId?: string; projectId?: string } = {}) {
  const projectId = opts.projectId ?? SHARED_PROJECT
  const scheduleId = opts.scheduleId ?? 's1'
  return POST(
    new NextRequest(`http://localhost:3000/api/projects/${projectId}/schedules/${scheduleId}/confirm`, {
      method: 'POST',
      headers: {
        'content-type': opts.contentType ?? 'application/json',
        host: 'localhost:3000',
        origin: opts.origin ?? 'http://localhost:3000',
      },
      body: '{}',
    }),
    { params: Promise.resolve({ id: projectId, scheduleId }) },
  )
}

beforeEach(() => {
  resetSharedProjectDb(h.db)
  seed()
  h.identity = identityOf(OWNER)
  h.schedule = { ...PAUSED }
  h.project = {
    id: SHARED_PROJECT, userId: OWNER, targetDomain: 'example.com', subdomainList: [], ipMode: false,
    domainBatchMode: false, domainBatchHosts: [], engagementKind: 'own',
  }
  h.updates.length = 0
  h.audit.mockReset()
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearCaches()
})
afterEach(() => {
  setFlagsForTests(null)
  clearCaches()
})

describe('confirm makes the confirmer the actor', () => {
  test("the owner takes over a paused collaborator's schedule: actor, enabled and next run, audited", async () => {
    const before = Date.now()
    const res = await confirm()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.schedule).toMatchObject({ id: 's1', userId: OWNER, enabled: true })
    expect(h.updates).toHaveLength(1)
    const { where, data } = h.updates[0]
    expect(where).toEqual({ id: 's1' })
    expect(data.userId).toBe(OWNER)
    expect(data.enabled).toBe(true)
    // An interval schedule counts from the confirmation, not from the missed occurrence.
    expect((data.nextRunAt as Date).getTime()).toBeGreaterThanOrEqual(before + 60 * 60_000)
    expect(h.audit).toHaveBeenCalledWith({
      actorId: OWNER, onBehalfOfUserId: null, actorEmail: `${OWNER}@example.test`,
      projectId: SHARED_PROJECT, permission: 'recon:schedule',
      action: 'scan_schedule.confirmed', targetType: 'scanSchedule', targetId: 's1',
      before: { userId: COLLABORATOR, enabled: false },
      after: { userId: OWNER, enabled: true, nextRunAt: data.nextRunAt },
    })
  })

  test('the same confirmation twice leaves the same schedule (same event twice)', async () => {
    expect((await confirm()).status).toBe(200)
    h.schedule = { ...PAUSED, userId: OWNER, enabled: true }
    expect((await confirm()).status).toBe(200)
    expect(h.updates.map((u) => [u.data.userId, u.data.enabled])).toEqual([[OWNER, true], [OWNER, true]])
  })

  test('a one-off whose time is still ahead keeps it', async () => {
    h.schedule = { ...PAUSED, mode: 'once', runAt: FUTURE, intervalMinutes: null, nextRunAt: FUTURE }
    expect((await confirm()).status).toBe(200)
    expect(h.updates[0].data.nextRunAt).toEqual(FUTURE)
  })

  test('a one-off whose time has passed cannot be confirmed (409 schedule_spent), nothing written', async () => {
    h.schedule = { ...PAUSED, mode: 'once', runAt: new Date(0), intervalMinutes: null }
    const res = await confirm()
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('schedule_spent')
    expect(h.updates).toHaveLength(0)
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('a saved scope the rules now refuse is fixed first (422 scope_invalid), nothing written', async () => {
    h.project = { ...h.project, targetDomain: 'not a domain!' }
    const res = await confirm()
    expect(res.status).toBe(422)
    expect((await res.json()).code).toBe('scope_invalid')
    expect(h.updates).toHaveLength(0)
  })
})

describe('who may confirm', () => {
  test('a Read collaborator is refused at the permission (403 recon:schedule), nothing written', async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    h.identity = identityOf(COLLABORATOR)
    const res = await confirm()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'recon:schedule' })
    expect(h.updates).toHaveLength(0)
  })

  test('a person with no access to the project gets 404', async () => {
    h.identity = identityOf(STRANGER)
    expect((await confirm()).status).toBe(404)
    expect(h.updates).toHaveLength(0)
  })

  test('the confirmer must hold what the schedule starts: an overwrite schedule needs recon:overwrite', async () => {
    h.schedule = { ...PAUSED, scanMode: 'overwrite' }
    const denied = account(OWNER, { permissionOverrides: [{ permission: 'recon:overwrite', effect: 'deny', expiresAt: null, reason: null }] })
    h.identity = { session: { userId: OWNER, role: 'standard' }, principal: denied, actingAs: null }
    h.db.models.user = { findUnique: () => denied }
    const res = await confirm()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ permission: 'recon:overwrite' })
    expect(h.updates).toHaveLength(0)
  })

  test("a schedule of another project is 404 (the id is the client's)", async () => {
    h.schedule = { ...PAUSED, projectId: 'P-other' }
    expect((await confirm()).status).toBe(404)
    expect(h.updates).toHaveLength(0)
  })

  test('a cross-origin request is refused, nothing written', async () => {
    const res = await confirm({ origin: 'https://evil.example' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
    expect(h.updates).toHaveLength(0)
  })

  test('a body that is not JSON is refused (415)', async () => {
    expect((await confirm({ contentType: 'text/plain' })).status).toBe(415)
    expect(h.updates).toHaveLength(0)
  })

  test('with every switch off the owner confirms as today', async () => {
    setFlagsForTests(null)
    clearCaches()
    expect((await confirm()).status).toBe(200)
    expect(h.updates[0].data.userId).toBe(OWNER)
  })
})
