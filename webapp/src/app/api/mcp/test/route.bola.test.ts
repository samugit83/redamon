/**
 * BOLA / secret-echo repro — POST /api/mcp/test.
 *
 * The bug: the route restored a saved MCP auth token from the DB using a
 * body-supplied `userId` WITHOUT checking the caller owns that userId, so a
 * logged-in user could echo another user's token to the agent spawn path.
 * Fix: requireUserAccess(request, userId) before any DB lookup, and forward
 * to the (now internal-auth-gated) agent with the internal key.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRequireUserAccess = vi.fn()
const mockUserSettingsFindUnique = vi.fn()
const mockFetch = vi.fn()

vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
}))
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (base: Record<string, string> = {}) => ({ ...base, 'x-internal-key': 'IK-TEST' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: { userSettings: { findUnique: (...a: unknown[]) => mockUserSettingsFindUnique(...a) } },
}))

import { POST } from './route'

const MASK = '••••'

function req(server: unknown, userId?: string): NextRequest {
  return new NextRequest('http://x/api/mcp/test', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ server, userId }),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', mockFetch)
  mockFetch.mockImplementation(async () => new Response(JSON.stringify({ ok: true, discovered_tools: [] }), { status: 200 }))
})

describe('POST /api/mcp/test — ownership + secret echo', () => {
  test('cross-user userId is rejected before any DB lookup or upstream call', async () => {
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'forbidden' }, { status: 403 }))
    const server = { id: 's1', name: 's1', transport: 'stdio', command: 'node', auth: { token: 'whatever' } }
    const res = await POST(req(server, 'victim'))
    expect(res.status).toBe(403)
    // the write rule (HD-23): an admin, who may read the account, cannot send its token anywhere
    expect(mockRequireUserAccess).toHaveBeenCalledWith(expect.anything(), 'victim', { mode: 'write' })
    expect(mockUserSettingsFindUnique).not.toHaveBeenCalled()
    expect(mockFetch).not.toHaveBeenCalled()
  })

  test('owner restores their masked token and forwards it with the internal key', async () => {
    mockRequireUserAccess.mockResolvedValue(null) // allowed
    mockUserSettingsFindUnique.mockResolvedValue({
      mcpServers: [{ id: 's1', auth: { token: 'REALTOKEN' } }],
    })
    const server = { id: 's1', name: 's1', transport: 'stdio', command: 'node', auth: { token: `${MASK}1234` } }
    const res = await POST(req(server, 'u1'))
    expect(res.status).toBe(200)
    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [, opts] = mockFetch.mock.calls[0]
    expect(JSON.parse(opts.body).auth.token).toBe('REALTOKEN')
    expect(opts.headers['x-internal-key']).toBe('IK-TEST')
  })

  test('no userId + literal token forwards directly (no ownership lookup)', async () => {
    const server = { id: 's1', name: 's1', transport: 'stdio', command: 'node', auth: { token: 'literal' } }
    const res = await POST(req(server, undefined))
    expect(res.status).toBe(200)
    expect(mockRequireUserAccess).not.toHaveBeenCalled()
    expect(mockUserSettingsFindUnique).not.toHaveBeenCalled()
    expect(mockFetch).toHaveBeenCalledTimes(1)
    expect(mockFetch.mock.calls[0][1].headers['x-internal-key']).toBe('IK-TEST')
  })

  test('masked token with a foreign userId never reaches the DB (denied first)', async () => {
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'forbidden' }, { status: 403 }))
    const server = { id: 's1', name: 's1', transport: 'stdio', command: 'node', auth: { token: `${MASK}9999` } }
    const res = await POST(req(server, 'victim'))
    expect(res.status).toBe(403)
    expect(mockUserSettingsFindUnique).not.toHaveBeenCalled()
    expect(mockFetch).not.toHaveBeenCalled()
  })
})
