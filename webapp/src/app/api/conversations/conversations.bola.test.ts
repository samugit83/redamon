/**
 * BOLA wiring for conversations (A3-cont):
 *  - by-session routes honor the agent X-Internal-Key carve-out (chat persistence
 *    must keep working) but block cross-user browser callers
 *  - [id] routes block cross-user browser callers
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockConversationFindUnique = vi.fn()
const mockIsInternal = vi.fn()
const mockRequireEff = vi.fn()
const mockRequireConvAccess = vi.fn()
const mockRequireConvBySession = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: {
      findUnique: (...a: unknown[]) => mockConversationFindUnique(...a),
      delete: vi.fn().mockResolvedValue({}),
    },
  },
}))
vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => mockIsInternal(...a) }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overConversation()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
  requireConversationAccess: (...a: unknown[]) => mockRequireConvAccess(...a),
  requireConversationAccessBySession: (...a: unknown[]) => mockRequireConvBySession(...a),
}))

import { GET as GET_BY_SESSION } from './by-session/[sessionId]/route'
import { GET as GET_BY_ID } from './[id]/route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const sessParams = (sessionId: string) => ({ params: Promise.resolve({ sessionId }) })
const idParams = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  mockConversationFindUnique.mockResolvedValue({ id: 'c1', sessionId: 's1', userId: 'victim', projectId: 'p1', messages: [] })
})

describe('by-session GET — agent carve-out + BOLA', () => {
  test('internal-key caller (agent) → guard skipped, proceeds', async () => {
    mockIsInternal.mockReturnValue(true)
    const res = await GET_BY_SESSION(new NextRequest('http://x/api/conversations/by-session/s1'), sessParams('s1'))
    expect(res.status).toBe(200)
    expect(mockRequireConvBySession).not.toHaveBeenCalled()
    expect(mockConversationFindUnique).toHaveBeenCalled()
  })

  test('EXPLOIT: browser cross-user → 404 before any DB read', async () => {
    mockIsInternal.mockReturnValue(false)
    mockRequireEff.mockResolvedValue({ userId: 'attacker' })
    mockRequireConvBySession.mockResolvedValue(NOT_FOUND)
    const res = await GET_BY_SESSION(new NextRequest('http://x/api/conversations/by-session/s1'), sessParams('s1'))
    expect(res.status).toBe(404)
    expect(mockConversationFindUnique).not.toHaveBeenCalled()
  })

  test('browser owner → guard passes, proceeds', async () => {
    mockIsInternal.mockReturnValue(false)
    mockRequireEff.mockResolvedValue({ userId: 'victim' })
    mockRequireConvBySession.mockResolvedValue({ conversation: { id: 'c1', userId: 'victim', projectId: 'p1' } })
    const res = await GET_BY_SESSION(new NextRequest('http://x/api/conversations/by-session/s1'), sessParams('s1'))
    expect(res.status).toBe(200)
  })
})

describe('conversations/[id] GET — BOLA (browser-only)', () => {
  test('EXPLOIT: cross-user → 404 before DB read', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'attacker' })
    mockRequireConvAccess.mockResolvedValue(NOT_FOUND)
    const res = await GET_BY_ID(new NextRequest('http://x/api/conversations/c1'), idParams('c1'))
    expect(res.status).toBe(404)
    expect(mockConversationFindUnique).not.toHaveBeenCalled()
  })

  test('owner → 200', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'victim' })
    mockRequireConvAccess.mockResolvedValue({ conversation: { id: 'c1', userId: 'victim', projectId: 'p1' } })
    const res = await GET_BY_ID(new NextRequest('http://x/api/conversations/c1'), idParams('c1'))
    expect(res.status).toBe(200)
  })
})
