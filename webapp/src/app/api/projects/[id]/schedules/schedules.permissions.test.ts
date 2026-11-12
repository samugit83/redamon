/**
 * Queue, schedules and the job queue ask for their permission (step 3.8; PE-19, PE-22): the schedule
 * list and run history `recon:read`; queueing a scan, creating, changing or deleting a schedule,
 * cancelling or re-confirming a queued job `recon:schedule`; clearing the run history
 * `scan:versions_delete` ("clear scan history", §5.5). Queueing or re-confirming a job also needs
 * the permission that starts its kind, a schedule `recon:scan` when it can run, and an overwrite run
 * `recon:overwrite` (requireAlso): a person never defers a scan they may not start.
 * Real guard, can() and registry; the session and Prisma are doubles (routePermissionCases.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), projects: new Map<string, { id: string; userId: string }>(),
  downstream: vi.fn(), upstream: vi.fn(), models: {} as Record<string, unknown>,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  // The routes read the effective user again after the guard: the same account the identity names.
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})
vi.mock('@/lib/enqueueJob', () => ({ enqueueJob: (...a: unknown[]) => h.upstream('enqueue', ...a) }))

import { describeRoutePermissions, denying, principal, OWNER, OWNED_PROJECT, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

const p = { id: OWNED_PROJECT }
const queuedJob = (over: Record<string, unknown> = {}) => (st: { models: Record<string, unknown> }) => {
  st.models.jobQueue = {
    findUnique: async () => ({ id: 'J1', projectId: OWNED_PROJECT, status: 'needs_review', kind: 'gvm', payload: {}, ...over }),
    update: async () => ({}), updateMany: async () => ({ count: 1 }),
  }
}
const job = { id: 'J1' }

const CASES: RouteCase[] = [
  { route: 'GET /api/projects/[id]/schedules', handler: async () => (await import('./route')).GET, permission: 'recon:read', params: p },
  { route: 'POST /api/projects/[id]/schedules', handler: async () => (await import('./route')).POST, permission: 'recon:schedule', params: p, body: { mode: 'once' } },
  { route: 'PATCH /api/projects/[id]/schedules/[scheduleId]', handler: async () => (await import('./[scheduleId]/route')).PATCH, permission: 'recon:schedule', params: { ...p, scheduleId: 'S1' }, body: { label: 'x' } },
  { route: 'DELETE /api/projects/[id]/schedules/[scheduleId]', handler: async () => (await import('./[scheduleId]/route')).DELETE, permission: 'recon:schedule', params: { ...p, scheduleId: 'S1' } },
  { route: 'DELETE /api/projects/[id]/schedules/history', handler: async () => (await import('./history/route')).DELETE, permission: 'scan:versions_delete', params: p, body: {} },
  { route: 'POST /api/projects/[id]/queue', handler: async () => (await import('../queue/route')).POST, permission: 'recon:schedule', params: p, body: { kind: 'gvm', payload: {} } },
  { route: 'POST /api/job-queue/[id]/cancel', handler: async () => (await import('@/app/api/job-queue/[id]/cancel/route')).POST, permission: 'recon:schedule', params: job, projectId: OWNED_PROJECT, arrange: queuedJob() },
  { route: 'POST /api/job-queue/[id]/reconfirm', handler: async () => (await import('@/app/api/job-queue/[id]/reconfirm/route')).POST, permission: 'recon:schedule', params: job, projectId: OWNED_PROJECT, arrange: queuedJob(), body: {} },
]

const clearCaches = () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() }
describeRoutePermissions('queue and schedules', CASES, h, { setFlags: setFlagsForTests, clearCaches })

describe('what the request starts later needs its own permission (requireAlso)', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true, permissions: true })
    clearCaches()
    h.projects.clear()
    h.projects.set(OWNED_PROJECT, { id: OWNED_PROJECT, userId: OWNER })
    h.upstream.mockReset()
    h.upstream.mockResolvedValue({ ok: true, id: 'J9' })
    h.downstream.mockReset()
    for (const k of Object.keys(h.models)) delete h.models[k]
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })
  afterEach(() => {
    setFlagsForTests(null)
    vi.restoreAllMocks()
  })
  const signIn = (who: ReturnType<typeof principal>) =>
    h.identity.mockResolvedValue({ session: { userId: who.id, role: who.role }, principal: who, actingAs: null })
  const call = async (path: string, mod: Promise<Record<string, unknown>>, method: string, params: Record<string, string>, body: unknown) => {
    const handler = (await mod)[method] as (r: NextRequest, c: never) => Promise<Response>
    return handler(new NextRequest(`http://localhost:3000${path}`, {
      method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    }), { params: Promise.resolve(params) } as never)
  }
  const refusedFor = async (res: Response, permission: PermissionId) => {
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission })
  }

  test.each([
    ['gvm', 'scan:gvm'], ['github_hunt', 'scan:secrets'], ['trufflehog', 'scan:secrets'], ['supply_chain_repo', 'scan:supply_chain'],
    ['ai_attack', 'scan:ai_attack'], ['partial_recon', 'recon:partial'], ['full_recon', 'recon:scan'],
  ] as const)('queueing a %s job needs %s; nothing is queued without it', async (kind, permission) => {
    signIn(denying(OWNER, permission))
    await refusedFor(await call('/api/projects/x/queue', import('../queue/route'), 'POST', p, { kind, payload: {} }), permission)
    expect(h.upstream).not.toHaveBeenCalled()
    signIn(principal(OWNER))
    expect((await call('/api/projects/x/queue', import('../queue/route'), 'POST', p, { kind, payload: {} })).status).toBe(201)
  })

  test('queueing a full recon in overwrite mode needs recon:overwrite', async () => {
    signIn(denying(OWNER, 'recon:overwrite'))
    await refusedFor(await call('/api/projects/x/queue', import('../queue/route'), 'POST', p, { kind: 'full_recon', payload: { mode: 'overwrite' } }), 'recon:overwrite')
    expect((await call('/api/projects/x/queue', import('../queue/route'), 'POST', p, { kind: 'full_recon', payload: { mode: 'new' } })).status).toBe(201)
  })

  test("re-confirming a held job needs the permission that starts its kind; the row is left as it was", async () => {
    const update = vi.fn(async () => ({}))
    queuedJob({ kind: 'trufflehog' })(h)
    ;(h.models.jobQueue as Record<string, unknown>).update = update
    signIn(denying(OWNER, 'scan:secrets'))
    await refusedFor(await call('/api/job-queue/J1/reconfirm', import('@/app/api/job-queue/[id]/reconfirm/route'), 'POST', job, {}), 'scan:secrets')
    expect(update).not.toHaveBeenCalled()
  })

  test('creating a schedule needs recon:scan, and recon:overwrite for an overwrite schedule', async () => {
    signIn(denying(OWNER, 'recon:scan'))
    await refusedFor(await call('/api/projects/x/schedules', import('./route'), 'POST', p, { mode: 'once' }), 'recon:scan')
    signIn(denying(OWNER, 'recon:overwrite'))
    await refusedFor(await call('/api/projects/x/schedules', import('./route'), 'POST', p, { mode: 'once', scanMode: 'overwrite' }), 'recon:overwrite')
    expect(h.downstream).not.toHaveBeenCalled()
  })

  test('turning a schedule on needs recon:scan, an overwrite mode recon:overwrite; a rename needs neither', async () => {
    const at = { ...p, scheduleId: 'S1' }
    h.models.scanSchedule = { findUnique: async () => ({ id: 'S1', projectId: OWNED_PROJECT, enabled: false, label: 'x', scanMode: 'new' }) }
    signIn(denying(OWNER, 'recon:scan'))
    await refusedFor(await call('/api/projects/x/schedules/S1', import('./[scheduleId]/route'), 'PATCH', at, { enabled: true }), 'recon:scan')
    signIn(denying(OWNER, 'recon:overwrite'))
    await refusedFor(await call('/api/projects/x/schedules/S1', import('./[scheduleId]/route'), 'PATCH', at, { scanMode: 'overwrite' }), 'recon:overwrite')
    signIn(principal(OWNER, { permissionOverrides: [
      { permission: 'recon:scan', effect: 'deny', expiresAt: null, reason: null },
      { permission: 'recon:overwrite', effect: 'deny', expiresAt: null, reason: null },
    ] }))
    const rename = await call('/api/projects/x/schedules/S1', import('./[scheduleId]/route'), 'PATCH', at, { label: 'nightly' })
    expect(rename.status).not.toBe(403)
  })
})
