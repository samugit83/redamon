/**
 * POST /api/internal/agent/decisions (step 3.9b; AU-02, IM-09): the agent posts each approval,
 * dangerous-tool confirmation and Fireteam member confirmation it accepted, and the route writes
 * the audit row. Its actor is the real person: the admin (`actorId`, the ticket's `act`) when an
 * admin answered acting as `userId`, which then goes in `onBehalfOfUserId`; else `userId`.
 *
 * The internal key is the only way in (the real isInternalRequest and middleware), and the route
 * is on the middleware's internal-key allowlist, so it still answers once
 * INTERNAL_KEY_ALLOWLIST_ENFORCE=true. Prisma is a double; lib/audit.ts is the real one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const KEY = 'internal-key-for-test'
vi.stubEnv('INTERNAL_API_KEY', KEY)
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))

const h = vi.hoisted(() => ({
  create: vi.fn(),
  findUser: vi.fn(),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    auditLog: { create: (...a: unknown[]) => h.create(...a) },
    user: { findUnique: (...a: unknown[]) => h.findUser(...a) },
  },
}))

import { POST } from './route'

const PATH = '/api/internal/agent/decisions'

function req(body: unknown, headers: Record<string, string> = { 'x-internal-key': KEY }, method = 'POST'): NextRequest {
  return new NextRequest(`http://localhost:3000${PATH}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

const APPROVAL = { kind: 'approval', sessionId: 'sess-1', projectId: 'proj-1', userId: 'member-b', decision: 'approve' }

beforeEach(() => {
  h.create.mockReset().mockResolvedValue({ id: 'row-1' })
  h.findUser.mockReset().mockImplementation(async ({ where }: { where: { id: string } }) => ({ email: `${where.id}@e2e.local` }))
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

const row = () => h.create.mock.calls[0][0].data

describe('internal key only', () => {
  test('no key, a wrong key or the scanner key: 401, nothing written', async () => {
    vi.stubEnv('SCANNER_API_KEY', 'scanner-key-for-test')
    const attempts: Record<string, string>[] = [{}, { 'x-internal-key': 'nope' }, { 'x-internal-key': 'scanner-key-for-test' }]
    for (const headers of attempts) {
      const res = await POST(req(APPROVAL, headers))
      expect(res.status).toBe(401)
    }
    expect(h.create).not.toHaveBeenCalled()
    expect(h.findUser).not.toHaveBeenCalled()
  })

  test('a signed-in browser has no way in: a session cookie without the key is 401', async () => {
    const res = await POST(req(APPROVAL, { cookie: 'redamon-auth=whatever' }))
    expect(res.status).toBe(401)
    expect(h.create).not.toHaveBeenCalled()
  })
})

describe('allowed with the allowlist enforced', () => {
  test('the middleware lets the agent through with INTERNAL_KEY_ALLOWLIST_ENFORCE=true', async () => {
    vi.stubEnv('INTERNAL_KEY_ALLOWLIST_ENFORCE', 'true')
    vi.resetModules()
    const { middleware, internalKeyRouteAllowed } = await import('@/middleware')
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(internalKeyRouteAllowed('POST', PATH)).toBe(true)
    const passed = await middleware(req(APPROVAL))
    expect(passed.status).toBe(200)
    expect(passed.headers.get('x-middleware-next')).toBe('1')
    // Only POST, and only this path: the key opens nothing next to it.
    expect(internalKeyRouteAllowed('GET', PATH)).toBe(false)
    expect(internalKeyRouteAllowed('POST', `${PATH}/x`)).toBe(false)
    expect(internalKeyRouteAllowed('POST', '/api/internal/agent')).toBe(false)
    const refused = await middleware(new NextRequest(`http://localhost:3000${PATH}`, { method: 'GET', headers: { 'x-internal-key': KEY } }))
    expect(refused.status).toBe(401)
  })
})

describe('the audit row', () => {
  test('audit row actor is the real human: the admin who answered acting as the member', async () => {
    const res = await POST(req({ ...APPROVAL, actorId: 'admin-a' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ recorded: true })
    expect(row()).toEqual({
      actorId: 'admin-a',
      onBehalfOfUserId: 'member-b',
      actorEmail: 'admin-a@e2e.local',
      projectId: 'proj-1',
      permission: 'agent:approve_phase',
      action: 'agent.approval',
      targetType: 'agent_session',
      targetId: 'sess-1',
      after: { decision: 'approve' },
      source: 'ui',
    })
    expect(h.findUser).toHaveBeenCalledWith({ where: { id: 'admin-a' }, select: { email: true } })
  })

  test('without act-as the member is the actor, with no on-behalf-of', async () => {
    await POST(req(APPROVAL))
    expect(row()).toMatchObject({ actorId: 'member-b', actorEmail: 'member-b@e2e.local', action: 'agent.approval' })
    expect(row()).not.toHaveProperty('onBehalfOfUserId')
  })

  test('a dangerous-tool confirmation and a Fireteam member confirmation are agent.tool_confirmation', async () => {
    await POST(req({ ...APPROVAL, kind: 'tool_confirmation', decision: 'reject' }))
    expect(row()).toMatchObject({ action: 'agent.tool_confirmation', permission: 'agent:approve_dangerous', after: { decision: 'reject' } })
    h.create.mockClear()
    await POST(req({ ...APPROVAL, kind: 'fireteam_member_confirmation', waveId: 'w-1', memberId: 'm-2' }))
    expect(row()).toMatchObject({
      action: 'agent.tool_confirmation',
      permission: 'agent:approve_dangerous',
      after: { decision: 'approve', fireteam: { waveId: 'w-1', memberId: 'm-2' } },
    })
  })

  test('an actor whose account is gone is still recorded, without an email', async () => {
    h.findUser.mockResolvedValue(null)
    expect((await POST(req({ ...APPROVAL, actorId: 'admin-gone' }))).status).toBe(200)
    expect(row()).toMatchObject({ actorId: 'admin-gone', onBehalfOfUserId: 'member-b' })
    expect(row()).not.toHaveProperty('actorEmail')
  })

  test('the same decision posted twice is two rows: each post is one accepted answer', async () => {
    await POST(req(APPROVAL))
    await POST(req(APPROVAL))
    expect(h.create).toHaveBeenCalledTimes(2)
  })
})

describe('what it refuses', () => {
  test.each([
    ['not JSON', '{'],
    ['an array', [APPROVAL]],
    ['an unknown kind', { ...APPROVAL, kind: 'question' }],
    ['no session', { ...APPROVAL, sessionId: '' }],
    ['no project', { ...APPROVAL, projectId: undefined }],
    ['no user', { ...APPROVAL, userId: null }],
    ['a decision that is not a word', { ...APPROVAL, decision: 'approve; drop table' }],
    ['a decision too long', { ...APPROVAL, decision: 'a'.repeat(33) }],
    ['an actor that is not a string', { ...APPROVAL, actorId: 7 }],
    ['an id too long', { ...APPROVAL, sessionId: 's'.repeat(201) }],
    ['a wave on an approval', { ...APPROVAL, waveId: 'w-1' }],
    ['a Fireteam answer without its member', { ...APPROVAL, kind: 'fireteam_member_confirmation', waveId: 'w-1' }],
  ])('%s: 400, nothing written', async (_name, body) => {
    const res = await POST(req(body))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('invalid_decision')
    expect(h.create).not.toHaveBeenCalled()
  })

  test('a failed write is a coded 500, so the agent logs it', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.create.mockRejectedValue(Object.assign(new Error('insert failed: member-b'), { code: 'P2003' }))
    const res = await POST(req(APPROVAL))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not record the agent decision', code: 'P2003' })
  })
})
