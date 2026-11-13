/**
 * The session a ticket names must be new, or a conversation of the ticket's person on the ticket's
 * project: the session id comes from the ws-ticket body, and a reader of a shared project sees the
 * owner's sessions as attack-chain ids (review of RBAC step 5.3). The ws-ticket route calls this
 * after its project check.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ findUnique: vi.fn() }))
vi.mock('@/lib/prisma', () => ({ default: { conversation: { findUnique: (...a: unknown[]) => h.findUnique(...a) } } }))

import { sessionTicketRefusal } from './conversationRun'

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('sessionTicketRefusal', () => {
  test('a new session id is free', async () => {
    h.findUnique.mockResolvedValue(null)
    expect(await sessionTicketRefusal({ sessionId: 's-new', userId: 'reader', projectId: 'p-reader' })).toBeNull()
    expect(h.findUnique).toHaveBeenCalledWith({ where: { sessionId: 's-new' }, select: { userId: true, projectId: true } })
  })

  test("the person's own conversation on the project is theirs to reopen", async () => {
    h.findUnique.mockResolvedValue({ userId: 'owner', projectId: 'p-owner' })
    expect(await sessionTicketRefusal({ sessionId: 's-owner', userId: 'owner', projectId: 'p-owner' })).toBeNull()
  })

  test.each([
    ['another person on another project (the reader naming the owner\'s chain id)', 'reader', 'p-reader'],
    ['the same person on another project', 'owner', 'p-reader'],
    ['another person on the same project', 'reader', 'p-owner'],
  ])('%s is refused 403 session_not_yours, logged', async (_why, userId, projectId) => {
    h.findUnique.mockResolvedValue({ userId: 'owner', projectId: 'p-owner' })
    const res = await sessionTicketRefusal({ sessionId: 's-owner', userId, projectId })
    expect(res?.status).toBe(403)
    expect(await res!.json()).toMatchObject({ code: 'session_not_yours' })
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('[rbac] session_not_yours'))
  })

  test('a failed read throws (the route answers a coded 500), never a ticket', async () => {
    h.findUnique.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(sessionTicketRefusal({ sessionId: 's', userId: 'u', projectId: 'p' })).rejects.toThrow('db down')
  })
})
