/**
 * The agent appends to a conversation by session id with the internal key (chat messages and
 * Fireteam rows). A session id comes from the browser (the ws-ticket body), and a reader of a shared
 * project sees its sessions as chain ids, so a run of theirs on another project could name the
 * owner's session. The agent sends the run's person and project from its signed ticket: an existing
 * conversation takes the append only when both are its own (review of RBAC step 5.3).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  createMany: vi.fn(),
  fireteamCreate: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      create: (...a: unknown[]) => h.create(...a),
      update: (...a: unknown[]) => h.update(...a),
    },
    chatMessage: {
      aggregate: vi.fn().mockResolvedValue({ _max: { sequenceNum: null } }),
      createMany: (...a: unknown[]) => h.createMany(...a),
    },
    fireteam: { create: (...a: unknown[]) => h.fireteamCreate(...a) },
  },
}))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => true }))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn(),
  requireConversationAccessBySession: vi.fn(),
}))

import { POST as appendMessages } from './messages/route'
import { POST as createFireteam } from './fireteams/route'

const OWNER_CONV = { id: 'c-owner', sessionId: 's-owner', title: 'Owner chat', userId: 'owner', projectId: 'p-owner' }
const params = { params: Promise.resolve({ sessionId: 's-owner' }) }
const messages = (body: Record<string, unknown>) => appendMessages(
  new NextRequest('http://x/api/conversations/by-session/s-owner/messages', {
    method: 'POST',
    body: JSON.stringify({ type: 'assistant_message', data: { content: 'hi' }, ...body }),
  }),
  params,
)
const fireteam = (body: Record<string, unknown>) => createFireteam(
  new NextRequest('http://x/api/conversations/by-session/s-owner/fireteams', {
    method: 'POST',
    body: JSON.stringify({ fireteamIdKey: 'ft-1', members: [{ memberIdKey: 'm-1', name: 'm' }], ...body }),
  }),
  params,
)

beforeEach(() => {
  vi.clearAllMocks()
  h.findUnique.mockResolvedValue(OWNER_CONV)
  h.update.mockResolvedValue({})
  h.createMany.mockResolvedValue({ count: 1 })
  h.fireteamCreate.mockResolvedValue({ id: 'f-1', members: [{ id: 'fm-1' }] })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

const routes = [
  { name: 'messages', post: messages, wrote: () => h.createMany.mock.calls.length },
  { name: 'fireteams', post: fireteam, wrote: () => h.fireteamCreate.mock.calls.length },
]

describe.each(routes)('by-session $name POST: the run must be the conversation\'s', ({ post, wrote }) => {
  test("another project's run naming the owner's session is refused, nothing written", async () => {
    const res = await post({ userId: 'reader', projectId: 'p-reader' })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'conversation_run_mismatch' })
    expect(wrote()).toBe(0)
    expect(h.update).not.toHaveBeenCalled()
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('[rbac] conversation_run_mismatch'))
  })

  test('the right person on another project, or another person on the right project, is refused', async () => {
    expect((await post({ userId: 'owner', projectId: 'p-reader' })).status).toBe(403)
    expect((await post({ userId: 'reader', projectId: 'p-owner' })).status).toBe(403)
    expect(wrote()).toBe(0)
  })

  test('an append that names no person or project is refused for an existing conversation', async () => {
    expect((await post({})).status).toBe(403)
    expect((await post({ projectId: 'p-owner' })).status).toBe(403)
    expect(wrote()).toBe(0)
  })

  test("the conversation's own run appends as before", async () => {
    const res = await post({ userId: 'owner', projectId: 'p-owner' })
    expect(res.status).toBe(201)
    expect(wrote()).toBe(1)
  })

  test('a new session is created for the run that names it, as before', async () => {
    h.findUnique.mockResolvedValue(null)
    h.create.mockResolvedValue({ ...OWNER_CONV, id: 'c-new', userId: 'reader', projectId: 'p-reader', title: null })
    const res = await post({ userId: 'reader', projectId: 'p-reader' })
    expect(res.status).toBe(201)
    expect(h.create).toHaveBeenCalledWith({ data: expect.objectContaining({ userId: 'reader', projectId: 'p-reader', sessionId: 's-owner' }) })
    expect(wrote()).toBe(1)
  })
})
