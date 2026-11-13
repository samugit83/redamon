/**
 * GET|POST /api/users/[id]/deletion-plan (step 5.13; SH-16, SH-17): what deleting an account does, and the
 * actions that resolve each of its shared projects before the deletion. Write sharing switched on only
 * (404 before the session is read otherwise, DV-30); users:delete first; never one's own account; the
 * plan lists the shared and unshared projects with what runs on each, the shares the account holds
 * elsewhere, its conversations there, its live work and what ends with it. An offer takes the admin's own
 * password; a forced transfer takes projects:administer and then the confirmed Root's password; actions
 * reach only the account's own projects, never while acting as someone.
 *
 * The route, the plan (lib/authz/userDeletion.ts) and the offers list are real over the in-memory
 * deletionDb; the session, the permission answers, the Root and step-up checks, the transfer writers
 * (their own test: ownershipTransfer.deletion.test.ts), the live-work answers and the policy are doubles.
 *
 * Run: npx vitest run --no-file-parallelism 'src/app/api/users/[id]/deletion-plan/route.test.ts'
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown,
  session: { userId: 'admin-1', role: 'admin' } as { userId: string; role: string } | null,
  holds: new Set<string>(['users:delete']),
  standing: 'none' as 'confirmed' | 'unconfirmed' | 'none',
  inForce: true,
  getSession: vi.fn(),
  rootPower: vi.fn(async (): Promise<Response | null> => null),
  gate: vi.fn(async (): Promise<Response | { adminTarget: boolean }> => ({ adminTarget: false })),
  stepUp: vi.fn(async (): Promise<Response | null> => null),
  acting: vi.fn(async (): Promise<Response | null> => null),
  rootProtected: vi.fn(async (): Promise<Response | null> => null),
  offer: vi.fn(async () => new Response(JSON.stringify({ offer: { id: 't1' } }), { status: 201 })),
  force: vi.fn(async () => new Response(JSON.stringify({ transferred: {} }), { status: 200 })),
  cancel: vi.fn(async () => new Response(JSON.stringify({ withdrawn: true, status: 'cancelled' }), { status: 200 })),
}))

vi.mock('@/lib/prisma', async () => {
  const { createDeletionDb } = await import('@/lib/authz/__testing__/deletionDb')
  h.db = createDeletionDb()
  return { default: h.db }
})
vi.mock('@/lib/session', () => ({ getSession: (...a: unknown[]) => h.getSession(...a) }))
vi.mock('@/lib/authz/adminPermission', async () => {
  const { forbiddenResponse } = await import('@/lib/authz/guards')
  return {
    sessionHolds: async (_s: unknown, p: string) => h.holds.has(p),
    requireSessionPermission: async (_s: unknown, p: string) => (h.holds.has(p) ? null : forbiddenResponse(p as never)),
  }
})
vi.mock('@/lib/authz/rootPowers', () => ({
  rootStanding: async () => h.standing,
  requireRootPower: () => h.rootPower(),
  adminTargetGate: () => h.gate(),
}))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: () => h.stepUp() }))
vi.mock('@/lib/authz/actAsRefusals', () => ({ refuseWhileActingAs: () => h.acting() }))
vi.mock('@/lib/authz/rootProtection', () => ({ rootProtectedRefusal: () => h.rootProtected() }))
vi.mock('@/lib/authz/ownershipTransfer', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/ownershipTransfer')>()),
  writeSharingInForce: async () => h.inForce,
  offerForDeletion: (...a: unknown[]) => h.offer(...(a as [])),
  forceTransferForDeletion: (...a: unknown[]) => h.force(...(a as [])),
  cancelForDeletion: (...a: unknown[]) => h.cancel(...(a as [])),
}))
vi.mock('@/lib/graphWriters', () => ({
  describeLiveGraphWriters: async (projectId: string) => (projectId === 'P-shared' ? 'a full recon scan is running' : null),
}))
vi.mock('@/lib/authz/quotas', () => ({ agentRunCount: async () => 2 }))

import type { DeletionDb } from '@/lib/authz/__testing__/deletionDb'
import { setFlagsForTests, type RbacFlags } from '@/lib/authz/flags'
import { GET, POST } from './route'

const db = () => h.db as DeletionDb
const ALL_ON: Partial<RbacFlags> = { identity: true, permissions: true, sharing: true, sharingWrite: true }
const PAST = new Date('2026-01-01T00:00:00Z')
const FUTURE = new Date('2099-01-01T00:00:00Z')
const at = (n: number) => new Date(Date.UTC(2026, 9, 1, 0, n))
const params = (id = 'alice') => ({ params: Promise.resolve({ id }) })
const getPlan = (id = 'alice') => GET(new NextRequest(`http://x/api/users/${id}/deletion-plan`), params(id))
const post = (body: unknown, id = 'alice', origin = 'http://x') => POST(new NextRequest(`http://x/api/users/${id}/deletion-plan`, {
  method: 'POST', headers: { 'content-type': 'application/json', origin }, body: JSON.stringify(body),
}), params(id))
const answer = async (res: Response) => [res.status, await res.json()]

beforeEach(() => {
  db().seed({
    user: [
      { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', status: 'active' },
      { id: 'alice', name: 'Alice', email: 'alice@e2e.local', role: 'standard', status: 'active' },
      { id: 'bob', name: 'Bob', email: 'bob@e2e.local', role: 'standard', status: 'active' },
      { id: 'carla', name: 'Carla', email: 'carla@e2e.local', role: 'standard', status: 'active' },
      { id: 'dino', name: 'Dino', email: 'dino@e2e.local', role: 'standard', status: 'disabled' },
      { id: 'olga', name: 'Olga', email: 'olga@e2e.local', role: 'standard', status: 'active' },
    ],
    project: [
      { id: 'P-shared', userId: 'alice', name: 'Client shared', createdAt: at(1) },
      { id: 'P-expired', userId: 'alice', name: 'Share lapsed', createdAt: at(2) },
      { id: 'P-solo', userId: 'alice', name: 'Alone', createdAt: at(3) },
      { id: 'P-olga', userId: 'olga', name: "Olga's engagement", createdAt: at(4) },
    ],
    projectCollaborator: [
      { projectId: 'P-shared', userId: 'bob', access: 'write', expiresAt: null, createdAt: at(5) },
      { projectId: 'P-shared', userId: 'dino', access: 'read', expiresAt: FUTURE, createdAt: at(6) },
      { projectId: 'P-expired', userId: 'carla', access: 'read', expiresAt: PAST, createdAt: at(7) },
      { projectId: 'P-olga', userId: 'alice', access: 'write', expiresAt: null, createdAt: at(8) },
    ],
    projectTransfer: [],
    conversation: [
      { id: 'c-1', projectId: 'P-olga', userId: 'alice' },
      { id: 'c-2', projectId: 'P-solo', userId: 'alice' },
    ],
    jobQueue: [
      { id: 'j-1', projectId: 'P-olga', userId: 'alice', status: 'queued' },
      { id: 'j-2', projectId: 'P-olga', userId: 'alice', status: 'done' },
    ],
    scanSchedule: [{ id: 's-1', projectId: 'P-olga', userId: 'alice', enabled: true }, { id: 's-2', projectId: 'P-solo', userId: 'alice', enabled: false }],
    mcpAccessToken: [
      { id: 'm-1', userId: 'alice', revokedAt: null, expiresAt: null },
      { id: 'm-2', userId: 'alice', revokedAt: PAST, expiresAt: null },
    ],
    userSession: [
      { id: 'u-1', userId: 'alice', revokedAt: null, expiresAt: FUTURE },
      { id: 'u-2', userId: 'alice', revokedAt: null, expiresAt: PAST },
    ],
    nucleiTemplate: [{ path: 'alice/own.yaml', ownerUserId: 'alice' }],
    auditLog: [],
  })
  h.session = { userId: 'admin-1', role: 'admin' }
  h.getSession.mockReset()
  h.getSession.mockImplementation(async () => h.session)
  h.holds = new Set(['users:delete'])
  h.standing = 'none'
  h.inForce = true
  for (const f of [h.rootPower, h.gate, h.stepUp, h.acting, h.rootProtected, h.offer, h.force, h.cancel]) f.mockClear()
  h.rootPower.mockResolvedValue(null)
  h.gate.mockResolvedValue({ adminTarget: false })
  h.stepUp.mockResolvedValue(null)
  h.acting.mockResolvedValue(null)
  h.rootProtected.mockResolvedValue(null)
  setFlagsForTests(ALL_ON)
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('GET: the deletion plan', () => {
  test('plan lists shared and unshared: each shared project with its live collaborators and what runs on it', async () => {
    const [status, { plan }] = await answer(await getPlan())
    expect(status).toBe(200)
    expect(plan.account).toEqual({ id: 'alice', name: 'Alice', email: 'alice@e2e.local', role: 'standard', status: 'active' })
    expect(plan.sharedProjects).toEqual([{
      id: 'P-shared', name: 'Client shared', running: 'a full recon scan is running', offer: null,
      collaborators: [
        { id: 'bob', name: 'Bob', email: 'bob@e2e.local', access: 'write', active: true, expiresAt: null },
        { id: 'dino', name: 'Dino', email: 'dino@e2e.local', access: 'read', active: false, expiresAt: FUTURE.toISOString() },
      ],
    }])
    // A project whose only share has expired is unshared: the teardown takes it.
    expect(plan.unsharedProjects).toEqual([
      { id: 'P-expired', name: 'Share lapsed', running: null },
      { id: 'P-solo', name: 'Alone', running: null },
    ])
  })

  test('the shares it holds elsewhere, its conversations there, its live work and what ends with the account', async () => {
    const { plan } = await (await getPlan()).json()
    expect(plan.memberships).toEqual([{
      project: { id: 'P-olga', name: "Olga's engagement" }, owner: { id: 'olga', name: 'Olga', email: 'olga@e2e.local' }, access: 'write', expiresAt: null,
    }])
    expect(plan.conversationsReassigned).toBe(1)
    expect(plan.liveWork).toEqual({ agentRuns: 2, queuedScans: 1, schedules: 1 })
    expect(plan.endsWithAccount).toEqual({ mcpTokens: 1, deviceSessions: 1, nucleiTemplates: 1 })
    expect(plan.transfers).toEqual({ available: true, mayForce: false })
  })

  test("a shared project's open offer is shown; the confirmed Root holding projects:administer may force", async () => {
    db().rows('projectTransfer').push({
      id: 't-1', projectId: 'P-shared', fromUserId: 'alice', toUserId: 'bob', oldOwnerRole: 'leave', status: 'pending',
      error: null, createdAt: new Date(), decidedAt: null,
    })
    h.standing = 'confirmed'
    h.holds.add('projects:administer')
    const { plan } = await (await getPlan()).json()
    expect(plan.sharedProjects[0].offer).toMatchObject({ id: 't-1', to: { id: 'bob', name: 'Bob' }, status: 'pending', oldOwnerRole: 'leave' })
    expect(plan.transfers.mayForce).toBe(true)
    h.standing = 'unconfirmed'
    expect((await (await getPlan()).json()).plan.transfers.mayForce).toBe(false)
  })

  test('refusals: no session 401, users:delete missing 403 naming it, own account 400, Root 403, unknown account 404', async () => {
    h.session = null
    expect((await getPlan()).status).toBe(401)
    h.session = { userId: 'admin-1', role: 'admin' }
    h.holds = new Set()
    expect(await answer(await getPlan())).toEqual([403, expect.objectContaining({ code: 'forbidden', permission: 'users:delete' })])
    h.holds = new Set(['users:delete'])
    expect(await answer(await getPlan('admin-1'))).toEqual([400, expect.objectContaining({ code: 'own_account' })])
    h.rootProtected.mockResolvedValueOnce(NextResponse.json({ code: 'root_protected' }, { status: 403 }))
    expect((await getPlan()).status).toBe(403)
    expect((await getPlan('nobody')).status).toBe(404)
  })
})

describe('POST: resolving a shared project', () => {
  test("an offer takes the admin's own password, then reaches the writer for the account's project", async () => {
    h.stepUp.mockResolvedValueOnce(NextResponse.json({ code: 'step_up_required' }, { status: 403 }))
    expect((await post({ action: 'offer', projectId: 'P-shared', toUserId: 'bob' })).status).toBe(403)
    expect(h.offer).not.toHaveBeenCalled()
    const res = await post({ action: 'offer', projectId: 'P-shared', toUserId: 'bob', stepUpPassword: 'pw' })
    expect(res.status).toBe(201)
    expect(h.offer).toHaveBeenCalledWith({ session: h.session }, 'P-shared', 'alice', 'bob')
  })

  test("another admin's projects: the admin-target gate decides (with its own password), no second step-up", async () => {
    h.gate.mockResolvedValueOnce({ adminTarget: true })
    expect((await post({ action: 'offer', projectId: 'P-shared', toUserId: 'bob', stepUpPassword: 'pw' })).status).toBe(201)
    expect(h.stepUp).not.toHaveBeenCalled()
    h.gate.mockResolvedValueOnce(NextResponse.json({ code: 'root_only' }, { status: 403 }))
    expect((await post({ action: 'offer', projectId: 'P-shared', toUserId: 'bob', stepUpPassword: 'pw' })).status).toBe(403)
    expect(h.offer).toHaveBeenCalledTimes(1)
  })

  test('forced transfer needs projects:administer, then the confirmed Root with its password', async () => {
    const body = { action: 'force', projectId: 'P-shared', toUserId: 'bob', stepUpPassword: 'pw' }
    expect(await answer(await post(body))).toEqual([403, expect.objectContaining({ code: 'forbidden', permission: 'projects:administer' })])
    expect(h.rootPower).not.toHaveBeenCalled()
    h.holds.add('projects:administer')
    h.rootPower.mockResolvedValueOnce(NextResponse.json({ code: 'root_only' }, { status: 403 }))
    expect((await post(body)).status).toBe(403)
    expect(h.force).not.toHaveBeenCalled()
    expect((await post(body)).status).toBe(200)
    expect(h.force).toHaveBeenCalledWith({ session: h.session }, 'P-shared', 'alice', 'bob')
    expect(h.offer).not.toHaveBeenCalled()
  })

  test('a cancel of a member\'s offer takes no password', async () => {
    expect((await post({ action: 'cancel', projectId: 'P-shared' })).status).toBe(200)
    expect(h.cancel).toHaveBeenCalledWith({ session: h.session }, 'P-shared')
    expect(h.stepUp).not.toHaveBeenCalled()
  })

  test("only the account's own projects; the form before any password; transfers need write sharing in force", async () => {
    expect(await answer(await post({ action: 'offer', projectId: 'P-olga', toUserId: 'bob', stepUpPassword: 'pw' })))
      .toEqual([404, expect.objectContaining({ code: 'project_not_found' })])
    expect(await answer(await post({ action: 'transfer', projectId: 'P-shared' }))).toEqual([400, expect.objectContaining({ field: 'action' })])
    expect(await answer(await post({ action: 'offer', projectId: 'P-shared' }))).toEqual([400, expect.objectContaining({ field: 'toUserId' })])
    expect(h.stepUp).not.toHaveBeenCalled()
    h.inForce = false
    expect(await answer(await post({ action: 'force', projectId: 'P-shared', toUserId: 'bob' })))
      .toEqual([409, expect.objectContaining({ code: 'transfers_unavailable' })])
    expect((await post({ action: 'cancel', projectId: 'P-shared' })).status).toBe(200)
    expect(h.offer).not.toHaveBeenCalled()
    expect(h.force).not.toHaveBeenCalled()
  })

  test('refused while acting as someone, cross-origin, without users:delete, on one\'s own account', async () => {
    h.acting.mockResolvedValueOnce(NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 }))
    expect((await post({ action: 'cancel', projectId: 'P-shared' })).status).toBe(403)
    expect((await post({ action: 'cancel', projectId: 'P-shared' }, 'alice', 'https://evil.example')).status).toBe(403)
    expect((await post({ action: 'cancel', projectId: 'P-shared' }, 'admin-1')).status).toBe(400)
    h.holds = new Set()
    expect(await answer(await post({ action: 'cancel', projectId: 'P-shared' }))).toEqual([403, expect.objectContaining({ permission: 'users:delete' })])
    expect(h.cancel).not.toHaveBeenCalled()
  })
})

describe('with write sharing switched off the plan does not exist (DV-30)', () => {
  test.each([
    ['every switch off', {}],
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }],
  ] as Array<[string, Partial<RbacFlags>]>)('%s: GET and POST answer 404 before the session is read', async (_what, flags) => {
    setFlagsForTests(flags)
    expect((await getPlan()).status).toBe(404)
    expect((await post({ action: 'cancel', projectId: 'P-shared' })).status).toBe(404)
    expect(h.getSession).not.toHaveBeenCalled()
  })
})
