/**
 * POST /api/mcp/reload is an administrator's, and the body never reaches the agent (HD-03).
 *
 * The route forwarded the caller's body as `userMcpServers`, and the agent's MCP
 * toolset is shared: any signed-in account replaced every user's MCP servers with a
 * list of its own, stdio commands included. Now an administrator (role read from the
 * database) asks the agent to reload from its own stored settings, with an empty body.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const session = vi.hoisted(() => ({ current: null as { userId: string; role: string } | null }))
vi.mock('@/lib/session', () => ({
  requireAdmin: vi.fn(async () => {
    if (!session.current) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    if (session.current.role !== 'admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    return session.current
  }),
}))
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (base: Record<string, string> = {}) => ({ ...base, 'x-internal-key': 'IK-TEST' }),
}))

import { POST } from './route'

const fetchMock = vi.fn()
const SMUGGLED = { userMcpServers: [{ id: 'x', transport: 'stdio', command: 'sh', args: ['-c', 'id'] }] }

function req(body: unknown = SMUGGLED): NextRequest {
  return new NextRequest('http://x/api/mcp/reload', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ servers: [], errors: [] }), { status: 200 }))
})

describe('POST /api/mcp/reload', () => {
  test('member 403: the agent is never called', async () => {
    session.current = { userId: 'u-member', role: 'standard' }
    const res = await POST(req())
    expect(res.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('no session 401', async () => {
    session.current = null
    expect((await POST(req())).status).toBe(401)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('admin 200 and the body is not forwarded: the agent gets an empty one, with the internal key', async () => {
    session.current = { userId: 'u-admin', role: 'admin' }
    const res = await POST(req())
    expect(res.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toMatch(/\/mcp\/reload$/)
    expect(JSON.parse(init.body)).toEqual({})
    expect(init.body).not.toContain('stdio')
    expect(init.headers['x-internal-key']).toBe('IK-TEST')
  })

  test('an unreachable agent is 502, with no exception text', async () => {
    session.current = { userId: 'u-admin', role: 'admin' }
    vi.spyOn(console, 'error').mockImplementation(() => {})
    fetchMock.mockRejectedValue(new TypeError('fetch failed: secret-ish detail'))
    const res = await POST(req())
    expect(res.status).toBe(502)
    expect(await res.text()).not.toContain('secret-ish')
  })
})
