/**
 * The critical paths read the signed-in account fresh (step 2.2, ID-22, T3): the principal
 * cache may hold an account for RBAC_AUTHZ_CACHE_MS, so an action a stale role, status or
 * session version must never allow asks the session helpers for `fresh: true`: step-up, the
 * user-administration writes, the MCP token mint, starting act-as and the WebSocket ticket.
 * A read path keeps the cached read (the control).
 *
 * Each route is called with no session, so it stops right after the session read; what is
 * checked is the option it asked with. The session helpers are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  getSession: vi.fn(),
  getEffectiveUser: vi.fn(),
  requireAdmin: vi.fn(),
  requireSession: vi.fn(),
}))
vi.mock('@/lib/session', () => ({
  getSession: (...a: unknown[]) => h.getSession(...a),
  getEffectiveUser: (...a: unknown[]) => h.getEffectiveUser(...a),
  requireAdmin: (...a: unknown[]) => h.requireAdmin(...a),
  requireSession: (...a: unknown[]) => h.requireSession(...a),
  isInternalRequest: () => false,
  isScannerRequest: () => false,
  requireUserAccess: async () => null,
  requireAccountWrite: async () => null,
}))
// Nothing below may reach the database: every route stops at its session check.
vi.mock('@/lib/prisma', () => ({ default: {} }))

import { POST as createUser, GET as listUsers } from '@/app/api/users/route'
import { PUT as editUser, DELETE as deleteUser, GET as readUser } from '@/app/api/users/[id]/route'
import { PUT as changePassword } from '@/app/api/users/[id]/password/route'
import { POST as mintMcpToken } from '@/app/api/users/[id]/mcp-tokens/route'
import { POST as startActAs } from '@/app/api/auth/act-as/route'
import { POST as mintWsTicket } from '@/app/api/agent/ws-ticket/route'
import { checkStepUp } from './stepUp'

const FRESH = { fresh: true }
const params = (id = 'u2') => ({ params: Promise.resolve({ id }) })
function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://localhost:3000/api/x', {
    method,
    headers: { 'Content-Type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.getSession.mockResolvedValue(null)
  h.getEffectiveUser.mockResolvedValue(null)
  h.requireAdmin.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
  h.requireSession.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
})

describe('critical paths read the account fresh', () => {
  test('step-up', async () => {
    expect(await checkStepUp(req('POST'), 'pw')).toEqual({ outcome: 'wrong' })
    expect(h.getSession).toHaveBeenCalledWith(FRESH)
  })

  test('creating a user', async () => {
    expect((await createUser(req('POST', { name: 'n', email: 'e@x' }))).status).toBe(403)
    expect(h.getSession).toHaveBeenCalledWith(FRESH)
  })

  test('editing a user (name, email, role)', async () => {
    expect((await editUser(req('PUT', { role: 'admin' }), params())).status).toBe(401)
    expect(h.getSession).toHaveBeenCalledWith(FRESH)
  })

  test('deleting a user', async () => {
    expect((await deleteUser(req('DELETE'), params())).status).toBe(403)
    expect(h.getSession).toHaveBeenCalledWith(FRESH)
  })

  test("changing or resetting a password", async () => {
    expect((await changePassword(req('PUT', { newPassword: 'a-long-enough-password' }), params())).status).toBe(401)
    expect(h.getSession).toHaveBeenCalledWith(FRESH)
  })

  test('minting an MCP token', async () => {
    expect((await mintMcpToken(req('POST', { name: 't' }), params())).status).toBe(401)
    expect(h.getSession).toHaveBeenCalledWith(FRESH)
  })

  test('starting act-as', async () => {
    expect((await startActAs(req('POST', { targetUserId: 'u2' }))).status).toBe(401)
    expect(h.requireAdmin).toHaveBeenCalledWith(FRESH)
  })

  test('minting a WebSocket ticket', async () => {
    expect((await mintWsTicket(req('POST', { projectId: 'p', sessionId: 's' }))).status).toBe(401)
    expect(h.getEffectiveUser).toHaveBeenCalledWith(FRESH)
  })
})

describe('read paths keep the cached read (control)', () => {
  test('listing and reading users', async () => {
    await listUsers(req('GET'))
    await readUser(req('GET'), params())
    expect(h.getSession).toHaveBeenCalled()
    for (const call of h.getSession.mock.calls) expect(call).toEqual([])
  })
})
