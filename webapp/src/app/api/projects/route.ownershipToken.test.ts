/**
 * POST /api/projects gives every new project its own ownership token (L-16).
 *
 * The token used to default to a constant printed in the source, and the form
 * seeded it from /defaults, so a TXT record published for one project verified
 * every other project that kept it. A create that sends no token, an empty one
 * or that constant now gets a fresh random one; a token the person typed is
 * kept as typed.
 *
 * Same harness as route.bounds.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockUserFindUnique = vi.fn()
const mockProjectCreate = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => mockUserFindUnique(...a) },
    project: { create: (...a: unknown[]) => mockProjectCreate(...a), update: vi.fn() },
    userLlmProvider: { findFirst: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() }),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { NextRequest } from 'next/server'
import { POST } from './route'

const LEGACY = 'your-secret-token-here'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

const postReq = (body: Record<string, unknown>) =>
  new NextRequest('http://localhost:3000/api/projects', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

// The soft guardrail is off so the test never waits on an agent.
const base = { name: 'test', targetDomain: 'example.invalid', targetGuardrailEnabled: false }

beforeEach(() => {
  vi.clearAllMocks()
  mockUserFindUnique.mockResolvedValue({ id: 'user-1' })
  mockProjectCreate.mockResolvedValue({ id: 'p1', name: 'test', userId: 'user-1', targetDomain: 'example.invalid' })
})

const tokenOf = (call: number) =>
  (mockProjectCreate.mock.calls[call][0].data as Record<string, unknown>).ownershipToken

describe('POST /api/projects: the ownership token', () => {
  test('a create that sends none gets a random one, different for each project', async () => {
    expect((await POST(postReq(base))).status).toBe(201)
    expect((await POST(postReq(base))).status).toBe(201)
    expect(tokenOf(0)).toMatch(UUID)
    expect(tokenOf(1)).toMatch(UUID)
    expect(tokenOf(0)).not.toBe(tokenOf(1))
  })

  test.each([
    ['the old shared default', LEGACY],
    ['an empty value', ''],
    ['whitespace', '   '],
  ])('%s is replaced by a fresh token', async (_label, value) => {
    expect((await POST(postReq({ ...base, verifyDomainOwnership: true, ownershipToken: value }))).status).toBe(201)
    expect(tokenOf(0)).toMatch(UUID)
  })

  test('a token the person chose is kept as typed', async () => {
    await POST(postReq({ ...base, verifyDomainOwnership: true, ownershipToken: 'k7-my-own-token' }))
    expect(tokenOf(0)).toBe('k7-my-own-token')
  })
})
