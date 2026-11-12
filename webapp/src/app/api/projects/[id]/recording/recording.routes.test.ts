/**
 * Recording start/stop/commit: owner-only, single-active (G10), activation lock
 * (G11), empty-capture guard (G3), write-only profile save.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const { db, mockGetEffectiveUser, mockAssertNotActivating, mockCaptureEnabled } = vi.hoisted(() => ({
  db: {
    project: { findUnique: vi.fn() },
    recordingSession: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
    projectAuthProfile: { upsert: vi.fn() },
  },
  mockGetEffectiveUser: vi.fn(),
  mockAssertNotActivating: vi.fn(),
  mockCaptureEnabled: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({ default: db }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => mockGetEffectiveUser() }
})
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: (...a: unknown[]) => mockAssertNotActivating(...a) }))
vi.mock('@/lib/captureStatus', () => ({ isCaptureGloballyEnabled: (...a: unknown[]) => mockCaptureEnabled(...a) }))

import { POST as START } from './start/route'
import { POST as COMMIT } from './commit/route'
import { POST as STOP } from './stop/route'
import { GET as STATUS } from './status/route'

const params = { params: Promise.resolve({ id: 'p1' }) }
const req = (body?: unknown) => new NextRequest('http://x', { method: 'POST', ...(body ? { body: JSON.stringify(body) } : {}) })

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACCESS_ENFORCE
  mockGetEffectiveUser.mockResolvedValue({ userId: 'owner' })
  db.project.findUnique.mockResolvedValue({
    id: 'p1', userId: 'owner', captureProxyEnabled: true, ipMode: false,
    targetDomain: 'target.test', subdomainList: [], targetIps: [], roeExcludedHosts: [],
  })
  mockAssertNotActivating.mockResolvedValue(null)
  mockCaptureEnabled.mockResolvedValue(true)
  db.recordingSession.findFirst.mockResolvedValue(null)
  db.recordingSession.create.mockImplementation(({ data }: { data: Record<string, unknown> }) =>
    Promise.resolve({ id: 'rec1', observedCount: 0, lastError: null, expiresAt: new Date('2099-01-01'), ...data }))
  db.recordingSession.update.mockImplementation(({ data }: { data: Record<string, unknown> }) =>
    Promise.resolve({ id: 'rec1', observedCount: 0, lastError: null, expiresAt: new Date('2099-01-01'), scopeHosts: [], state: 'x', ...data }))
})

describe('start', () => {
  test('happy path creates a session scoped to the target', async () => {
    const res = await START(req(), params)
    expect(res.status).toBe(200)
    expect(db.recordingSession.create.mock.calls[0][0].data.scopeHosts).toEqual(['*.target.test'])
  })

  test('a Domain-batch project records its scope groups, not nothing (B-7)', async () => {
    db.project.findUnique.mockResolvedValue({
      ...await db.project.findUnique(), targetDomain: '', domainBatchMode: true,
      domainBatchHosts: ['*.example.com', 'www.acme.test', 'shop.acme.test'],
    })
    await START(req(), params)
    expect(db.recordingSession.create.mock.calls[0][0].data.scopeHosts)
      .toEqual(['*.example.com', 'www.acme.test', 'shop.acme.test'])
    expect(db.project.findUnique.mock.calls.at(-1)![0].select).toMatchObject({ domainBatchMode: true, domainBatchHosts: true })
  })

  test('refused while graph is activating (G11)', async () => {
    mockAssertNotActivating.mockResolvedValue(new Response(null, { status: 409 }))
    expect((await START(req(), params)).status).toBe(409)
    expect(db.recordingSession.create).not.toHaveBeenCalled()
  })

  test('fails closed when the lock check throws (G11), and says why with a code', async () => {
    mockAssertNotActivating.mockRejectedValue(Object.assign(new Error('db down at 10.0.0.5'), { code: 'P1001' }))
    const res = await START(req(), params)
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'activation check failed; try again', code: 'P1001' })
  })

  test('a DB failure answers the fixed message and the Prisma code, never the raw text', async () => {
    db.project.findUnique.mockRejectedValue(Object.assign(new Error('Timed out fetching a new connection'), { code: 'P2024' }))
    const res = await START(req(), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to start recording', code: 'P2024' })
  })

  test('409 when another project holds the slot (G10)', async () => {
    db.recordingSession.findFirst.mockResolvedValue({ id: 'other', projectId: 'p2' })
    expect((await START(req(), params)).status).toBe(409)
    expect(db.recordingSession.create).not.toHaveBeenCalled()
  })

  test('409 when global capture is disabled', async () => {
    mockCaptureEnabled.mockResolvedValue(false)
    expect((await START(req(), params)).status).toBe(409)
  })

  test('a concurrent start that lost the race discards itself and 409s (G10 TOCTOU)', async () => {
    // Both requests pass the non-atomic pre-check; the older session wins and the
    // loser must not be left "active", or the capture-config emits one tag while
    // two modals claim to be recording.
    const older = { id: 'rec0', projectId: 'p2', startedAt: new Date(Date.now() - 5000) }
    db.recordingSession.findFirst
      .mockResolvedValueOnce(null)    // pre-check: slot looks free
      .mockResolvedValueOnce(older)   // post-create: a rival exists
    const res = await START(req(), params)
    expect(res.status).toBe(409)
    expect(db.recordingSession.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ state: 'discarded' }) }))
  })

  test('no rival → the created session is returned', async () => {
    db.recordingSession.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce(null)
    expect((await START(req(), params)).status).toBe(200)
  })

  test('409 when per-project capture is off', async () => {
    db.project.findUnique.mockResolvedValue({ ...await db.project.findUnique(), captureProxyEnabled: false })
    expect((await START(req(), params)).status).toBe(409)
  })
})

describe('commit', () => {
  test('save=true writes a recorded profile, response is masked', async () => {
    db.recordingSession.findFirst.mockResolvedValue({
      id: 'rec1', scopeHosts: ['target.test'], pendingMaterial: { cookie: 'sid=super-secret' },
    })
    db.projectAuthProfile.upsert.mockResolvedValue({
      authType: 'cookie', authHeaderName: '', authValue: 'sid=super-secret', extraHeaders: {},
      scopeHosts: ['target.test'], source: 'recorded', status: 'active', lastValidatedAt: new Date(), updatedAt: new Date(),
    })
    const res = await COMMIT(req({ save: true }), params)
    expect(res.status).toBe(200)
    expect(await res.text()).not.toContain('super-secret')
    expect(db.projectAuthProfile.upsert.mock.calls[0][0].create.source).toBe('recorded')
  })

  test('commit does NOT pin scopeHosts to the recording scope', async () => {
    // Pinning froze auth to the apex, so every discovered subdomain fell out of
    // scope and the "authenticated" scan silently ran logged-out.
    db.recordingSession.findFirst.mockResolvedValue({
      id: 'rec1', scopeHosts: ['target.test'], pendingMaterial: { cookie: 'sid=a' },
    })
    db.projectAuthProfile.upsert.mockResolvedValue({
      authType: 'cookie', authHeaderName: '', authValue: 'sid=a', extraHeaders: {},
      scopeHosts: [], source: 'recorded', status: 'active', lastValidatedAt: null, updatedAt: new Date(),
    })
    await COMMIT(req({ save: true }), params)
    const args = db.projectAuthProfile.upsert.mock.calls[0][0]
    expect(args.create).not.toHaveProperty('scopeHosts')
    expect(args.update).not.toHaveProperty('scopeHosts')
  })

  test('empty capture does NOT overwrite the profile (G3)', async () => {
    db.recordingSession.findFirst.mockResolvedValue({ id: 'rec1', scopeHosts: [], pendingMaterial: {} })
    const res = await COMMIT(req({ save: true }), params)
    expect(res.status).toBe(422)
    expect(db.projectAuthProfile.upsert).not.toHaveBeenCalled()
  })

  test('save=false discards without writing a profile', async () => {
    db.recordingSession.findFirst.mockResolvedValue({ id: 'rec1', scopeHosts: [], pendingMaterial: { cookie: 'sid=a' } })
    const res = await COMMIT(req({ save: false }), params)
    expect((await res.json()).discarded).toBe(true)
    expect(db.projectAuthProfile.upsert).not.toHaveBeenCalled()
  })
})

describe('failures carry a code', () => {
  test('stop: a DB failure is 500 with the Prisma code', async () => {
    db.recordingSession.findFirst.mockRejectedValue(Object.assign(new Error('pool'), { code: 'P2024' }))
    const res = await STOP(req(), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to stop recording', code: 'P2024' })
  })

  test('commit: a DB failure is 500 with the error class when there is no code', async () => {
    class PrismaClientUnknownRequestError extends Error { name = 'PrismaClientUnknownRequestError' }
    db.recordingSession.findFirst.mockRejectedValue(new PrismaClientUnknownRequestError('raw sql text'))
    const res = await COMMIT(req({ save: true }), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to commit recording', code: 'PrismaClientUnknownRequestError' })
  })

  test('status: a DB failure is 500 with the Prisma code', async () => {
    db.recordingSession.findFirst.mockRejectedValue(Object.assign(new Error('x'), { code: 'P1001' }))
    const res = await STATUS(new NextRequest('http://x'), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to read recording status', code: 'P1001' })
  })
})
