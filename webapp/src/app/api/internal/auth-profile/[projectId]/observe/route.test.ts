/**
 * observe endpoint: internal-only, tenant from the session (never the body),
 * accumulates onto pendingMaterial, bumps the counter.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockSessionFindFirst = vi.fn()
const mockSessionUpdate = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    recordingSession: {
      findFirst: (...a: unknown[]) => mockSessionFindFirst(...a),
      update: (...a: unknown[]) => mockSessionUpdate(...a),
    },
  },
}))
vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => mockIsInternal(...a) }))

import { POST } from './route'

const params = { params: Promise.resolve({ projectId: 'p1' }) }
const post = (body: unknown) => new NextRequest('http://x/api/internal/auth-profile/p1/observe', {
  method: 'POST', body: JSON.stringify(body),
})

beforeEach(() => {
  vi.clearAllMocks()
  mockIsInternal.mockReturnValue(true)
  mockSessionUpdate.mockResolvedValue({})
})

test('non-internal caller → 401', async () => {
  mockIsInternal.mockReturnValue(false)
  expect((await POST(post({}), params)).status).toBe(401)
})

test('no active session → applied:false, nothing written', async () => {
  mockSessionFindFirst.mockResolvedValue(null)
  const res = await POST(post({ material: { cookie: 'sid=a' } }), params)
  expect((await res.json()).applied).toBe(false)
  expect(mockSessionUpdate).not.toHaveBeenCalled()
})

test('usable material accumulates + bumps counter', async () => {
  mockSessionFindFirst.mockResolvedValue({ id: 'rec1', pendingMaterial: {} })
  const res = await POST(post({ sessionId: 'rec1', host: 'app.target.test', material: { cookie: 'sid=a' } }), params)
  expect((await res.json()).applied).toBe(true)
  const data = mockSessionUpdate.mock.calls[0][0].data
  expect(data.pendingMaterial.cookie).toBe('sid=a')
  expect(data.observedCount).toEqual({ increment: 1 })
})

test('unusable material records lastError, no counter bump', async () => {
  mockSessionFindFirst.mockResolvedValue({ id: 'rec1', pendingMaterial: {} })
  const res = await POST(post({ material: { cookie: 'sid=a\r\nX: 1' } }), params)
  expect((await res.json()).applied).toBe(false)
  expect(mockSessionUpdate.mock.calls[0][0].data).toHaveProperty('lastError')
})

test('REGRESSION observe-drops-late-record-after-stop: a just-stopped session still accepts', async () => {
  // The ingest worker polls the spool on a ~1s loop, so the final response of a
  // login (the Set-Cookie) routinely arrives AFTER the operator clicks Stop.
  // Admitting only state:'active' discarded exactly that record and the modal
  // then reported "no login detected".
  mockSessionFindFirst.mockResolvedValue({ id: 'rec1', pendingMaterial: {} })
  await POST(post({ material: { cookie: 'sid=late' } }), params)

  const where = mockSessionFindFirst.mock.calls[0][0].where
  const branches = where.OR as Array<Record<string, unknown>>
  expect(Array.isArray(branches)).toBe(true)

  const active = branches.find(b => b.state === 'active')
  const stopped = branches.find(b => b.state === 'stopped')
  expect(active).toBeTruthy()
  expect(stopped).toBeTruthy()

  // The stopped branch must be bounded by a grace window, not open-ended.
  const lowerBound = (stopped!.stoppedAt as { gt: Date }).gt
  const graceMs = Date.now() - lowerBound.getTime()
  expect(graceMs).toBeGreaterThan(0)
  expect(graceMs).toBeLessThanOrEqual(5 * 60 * 1000)
})

test('tenant is resolved from the session, body user id is ignored', async () => {
  mockSessionFindFirst.mockResolvedValue({ id: 'rec1', pendingMaterial: {} })
  await POST(post({ userId: 'attacker', material: { cookie: 'sid=a' } }), params)
  const where = mockSessionFindFirst.mock.calls[0][0].where
  expect(where).toMatchObject({ projectId: 'p1' })
  // State now lives in an OR (active, or recently stopped — see the late-record
  // regression test below); the tenant must still come from the session row.
  expect((where.OR as Array<{ state: string }>).map(b => b.state).sort()).toEqual(['active', 'stopped'])
  expect(where).not.toHaveProperty('userId')
})
