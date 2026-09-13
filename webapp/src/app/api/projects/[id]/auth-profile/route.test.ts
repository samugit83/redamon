/**
 * /api/projects/[id]/auth-profile: owner-only, write-only, tenant from the project.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockProjectFindUnique = vi.fn()
const mockProfileFindUnique = vi.fn()
const mockProfileUpsert = vi.fn()
const mockProfileDeleteMany = vi.fn()
const mockGetEffectiveUser = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProjectFindUnique(...a) },
    projectAuthProfile: {
      findUnique: (...a: unknown[]) => mockProfileFindUnique(...a),
      upsert: (...a: unknown[]) => mockProfileUpsert(...a),
      deleteMany: (...a: unknown[]) => mockProfileDeleteMany(...a),
    },
  },
}))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => mockGetEffectiveUser() }
})

import { GET, PUT, DELETE } from './route'

const SECRET = 'sid=stored-secret'
const params = { params: Promise.resolve({ id: 'proj-1' }) }
const put = (body: unknown) => new NextRequest('http://x/api/projects/proj-1/auth-profile', {
  method: 'PUT', body: typeof body === 'string' ? body : JSON.stringify(body),
})
const stored = (over: Record<string, unknown> = {}) => ({
  projectId: 'proj-1', userId: 'owner', authType: 'cookie', authHeaderName: '', authValue: SECRET,
  extraHeaders: {}, scopeHosts: [], source: 'recorded', status: 'active', lastValidatedAt: null,
  updatedAt: new Date(), ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACCESS_ENFORCE
  mockGetEffectiveUser.mockResolvedValue({ userId: 'owner' })
  mockProjectFindUnique.mockResolvedValue({ id: 'proj-1', userId: 'owner' })
  mockProfileUpsert.mockImplementation(({ create }: { create: Record<string, unknown> }) =>
    Promise.resolve(stored({ ...create })))
})

describe('authz', () => {
  test('cross-user caller → 404 and nothing written', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'attacker' })
    expect((await PUT(put({ authValue: 'x' }), params)).status).toBe(404)
    expect((await GET(new NextRequest('http://x'), params)).status).toBe(404)
    expect((await DELETE(new NextRequest('http://x'), params)).status).toBe(404)
    expect(mockProfileUpsert).not.toHaveBeenCalled()
    expect(mockProfileDeleteMany).not.toHaveBeenCalled()
  })
})

describe('GET', () => {
  test('metadata only', async () => {
    mockProfileFindUnique.mockResolvedValue(stored())
    const raw = await (await GET(new NextRequest('http://x'), params)).text()
    expect(raw).not.toContain(SECRET)
    expect(JSON.parse(raw).authProfile.hasValue).toBe(true)
  })
})

describe('PUT', () => {
  test('tenant comes from the project owner, never the body; response is masked', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'owner' })
    const res = await PUT(put({ authType: 'cookie', authValue: 'sid=new-secret', userId: 'someone-else' }), params)
    expect(res.status).toBe(200)
    const args = mockProfileUpsert.mock.calls[0][0]
    expect(args.create.userId).toBe('owner')
    expect(args.update).not.toHaveProperty('userId')
    expect(await res.text()).not.toContain('new-secret')
  })

  test('a hand edit marks the profile manual + unvalidated', async () => {
    await PUT(put({ authValue: 'sid=x' }), params)
    expect(mockProfileUpsert.mock.calls[0][0].update).toMatchObject({ source: 'manual', status: 'unknown' })
  })

  test('scope-only edit keeps a recorded profile recorded', async () => {
    await PUT(put({ scopeHosts: ['a.test'] }), params)
    const update = mockProfileUpsert.mock.calls[0][0].update
    expect(update).toEqual({ scopeHosts: ['a.test'] })
  })

  test('omitting authValue never blanks the stored value', async () => {
    await PUT(put({ authType: 'cookie' }), params)
    expect(mockProfileUpsert.mock.calls[0][0].update).not.toHaveProperty('authValue')
  })

  test('header-injection value → 400, nothing written', async () => {
    const res = await PUT(put({ authValue: 'a\r\nX-Evil: 1' }), params)
    expect(res.status).toBe(400)
    expect(mockProfileUpsert).not.toHaveBeenCalled()
  })

  test('invalid JSON → 400', async () => {
    expect((await PUT(put('{nope'), params)).status).toBe(400)
  })
})

test('DELETE clears the profile', async () => {
  const res = await DELETE(new NextRequest('http://x'), params)
  expect(res.status).toBe(200)
  expect(mockProfileDeleteMany).toHaveBeenCalledWith({ where: { projectId: 'proj-1' } })
})
