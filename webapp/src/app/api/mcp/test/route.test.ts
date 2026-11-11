/**
 * POST /api/mcp/test acts only on the caller's own account, and a stdio draft is an
 * administrator's (NF-14, OQ-48, step 1.9).
 *
 * The test spawns the draft inside the agent: a stdio `command` runs as root next to
 * every tenant's data and the master secrets. The body's userId was checked only when
 * present, so any signed-in account ran any command; now the account is always the
 * caller's (or one it may write), and a stdio draft needs an administrator owner.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const session = vi.hoisted(() => ({ current: { userId: 'u-member', role: 'standard' } as { userId: string; role: string } | null }))
const mockRequireUserAccess = vi.hoisted(() => vi.fn())
const mockIsInternal = vi.hoisted(() => vi.fn(() => false))
vi.mock('@/lib/session', () => ({
  requireSession: vi.fn(async () => session.current ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })),
  getSession: vi.fn(async () => session.current),
  requireUserAccess: mockRequireUserAccess,
  isInternalRequest: mockIsInternal,
}))
const roles = vi.hoisted(() => new Map<string, string>([['u-member', 'standard'], ['u-admin', 'admin']]))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: vi.fn(async (id: string) => (roles.has(id) ? { id, role: roles.get(id) } : null)),
}))
const mockWriteAudit = vi.hoisted(() => vi.fn())
vi.mock('@/lib/audit', () => ({ writeAudit: mockWriteAudit }))
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (base: Record<string, string> = {}) => ({ ...base, 'x-internal-key': 'IK-TEST' }),
}))
const mockFindUnique = vi.hoisted(() => vi.fn())
vi.mock('@/lib/prisma', () => ({ default: { userSettings: { findUnique: mockFindUnique } } }))

import { POST } from './route'

const fetchMock = vi.fn()
const STDIO = { id: 'cmd', name: 'cmd', transport: 'stdio', command: 'sh', args: ['-c', 'id'] }
const HTTP = { id: 'web', name: 'web', transport: 'streamable_http', url: 'https://mcp.example.com/mcp' }

function req(body: unknown): NextRequest {
  return new NextRequest('http://x/api/mcp/test', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  session.current = { userId: 'u-member', role: 'standard' }
  mockIsInternal.mockReturnValue(false)
  mockRequireUserAccess.mockImplementation(async (_r: unknown, target: string) =>
    target === session.current?.userId ? null : NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
  mockFindUnique.mockResolvedValue({ mcpServers: [] })
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ ok: true, discovered_tools: [] }), { status: 200 }))
})

describe('POST /api/mcp/test: a stdio draft is an administrator\'s', () => {
  test('member stdio draft 403 stdio_admin_only: nothing reaches the agent, the refusal is audited', async () => {
    const res = await POST(req({ server: STDIO }))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({
      ok: false, code: 'stdio_admin_only', discovered_tools: [], warnings: [],
      error: "stdio servers run inside the agent with every user's data; ask an administrator",
    })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(mockWriteAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'mcp_server.stdio_refused', actorId: 'u-member', targetId: 'u-member',
      after: { serverId: 'cmd', via: 'test' },
    }))
  })

  test('member stdio draft naming their own userId: refused the same way', async () => {
    const res = await POST(req({ server: STDIO, userId: 'u-member' }))
    expect(res.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('member http draft allowed: it goes to the agent', async () => {
    const res = await POST(req({ server: HTTP }))
    expect(res.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).url).toBe(HTTP.url)
  })

  test('admin stdio draft allowed', async () => {
    session.current = { userId: 'u-admin', role: 'admin' }
    const res = await POST(req({ server: STDIO }))
    expect(res.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })
})

describe('POST /api/mcp/test acts on the caller\'s own account', () => {
  test('body userId of another account 403: no settings read, nothing sent', async () => {
    const res = await POST(req({ server: HTTP, userId: 'u-admin' }))
    expect(res.status).toBe(403)
    expect(mockRequireUserAccess).toHaveBeenCalledWith(expect.anything(), 'u-admin', { mode: 'write' })
    expect(mockFindUnique).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('an admin\'s stdio draft on a member\'s account is refused too: that account would never run it', async () => {
    session.current = { userId: 'u-admin', role: 'admin' }
    mockRequireUserAccess.mockResolvedValue(null) // e.g. acting as a managed member
    const res = await POST(req({ server: STDIO, userId: 'u-member' }))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('stdio_admin_only')
  })

  test('no userId means the caller: the write rule is checked and the masked token comes from their own settings', async () => {
    mockFindUnique.mockResolvedValue({ mcpServers: [{ ...HTTP, auth: { type: 'bearer', token: 'OWN-TOKEN' } }] })
    const res = await POST(req({ server: { ...HTTP, auth: { type: 'bearer', token: '••••••••OKEN' } } }))
    expect(res.status).toBe(200)
    expect(mockRequireUserAccess).toHaveBeenCalledWith(expect.anything(), 'u-member', { mode: 'write' })
    expect(mockFindUnique).toHaveBeenCalledWith(expect.objectContaining({ where: { userId: 'u-member' } }))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).auth.token).toBe('OWN-TOKEN')
  })

  test('no session: 401 before anything', async () => {
    session.current = null
    const res = await POST(req({ server: HTTP }))
    expect(res.status).toBe(401)
    expect(mockRequireUserAccess).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('the internal key must name the account', async () => {
    mockIsInternal.mockReturnValue(true)
    session.current = null
    const res = await POST(req({ server: HTTP }))
    expect(res.status).toBe(400)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('POST /api/mcp/test: a draft never names one of the agent\'s variables (OQ-R1)', () => {
  test('token_env_var 422, for an administrator too; nothing sent', async () => {
    for (const who of [{ userId: 'u-member', role: 'standard' }, { userId: 'u-admin', role: 'admin' }]) {
      session.current = who
      const res = await POST(req({ server: { ...HTTP, auth: { type: 'bearer', token_env_var: 'INTERNAL_API_KEY' } } }))
      expect(res.status).toBe(422)
      expect(await res.json()).toMatchObject({ ok: false, code: 'token_env_var_refused', field: 'auth.token_env_var' })
    }
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
