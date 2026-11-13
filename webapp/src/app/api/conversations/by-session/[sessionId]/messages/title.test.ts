/**
 * The agent persists a chat's first user_message through this route, and the
 * route titles an untitled conversation from it. A node-scoped first message
 * embeds the whole node context, so the title must come from the request, not
 * the context blob.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { wrapNodeContextQuery } from '@/lib/agentQueryEnvelope'

const mockFindUnique = vi.fn()
const mockConvUpdate = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockConvUpdate(...a),
    },
    chatMessage: {
      aggregate: vi.fn().mockResolvedValue({ _max: { sequenceNum: null } }),
      createMany: vi.fn().mockResolvedValue({ count: 1 }),
    },
  },
}))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => true }))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn(),
  requireConversationAccessBySession: vi.fn(),
}))

import { POST } from './route'

const params = { params: Promise.resolve({ sessionId: 's1' }) }
const post = (content: string) => POST(
  new NextRequest('http://x/api/conversations/by-session/s1/messages', {
    method: 'POST',
    // The agent names its run's person and project (runBinding.test.ts).
    body: JSON.stringify({ type: 'user_message', data: { content }, userId: 'u1', projectId: 'p1' }),
  }),
  params,
)
const titleWrites = () => mockConvUpdate.mock.calls
  .map(([arg]) => (arg as { data: { title?: string } }).data.title)
  .filter((t): t is string => t !== undefined)

beforeEach(() => {
  vi.clearAllMocks()
  mockFindUnique.mockResolvedValue({ id: 'c1', sessionId: 's1', title: null, userId: 'u1', projectId: 'p1' })
  mockConvUpdate.mockResolvedValue({})
})

describe('by-session messages POST — conversation title', () => {
  test('a node-scoped first message is titled "<node>: <request>"', async () => {
    const content = wrapNodeContextQuery('CVE: CVE-2000-0001', '## Properties\n'.repeat(50), 'Is this exploitable?')
    const res = await post(content)
    expect(res.status).toBe(201)
    expect(titleWrites()).toEqual(['CVE: CVE-2000-0001: Is this exploitable?'])
  })

  test('an ordinary first message keeps its first 100 chars as the title', async () => {
    await post('y'.repeat(150))
    expect(titleWrites()).toEqual(['y'.repeat(100)])
  })

  test('an already-titled conversation is not retitled', async () => {
    mockFindUnique.mockResolvedValue({ id: 'c1', sessionId: 's1', title: 'Existing', userId: 'u1', projectId: 'p1' })
    await post(wrapNodeContextQuery('IP: 192.0.2.1', 'ctx', 'q'))
    expect(titleWrites()).toEqual([])
  })
})
