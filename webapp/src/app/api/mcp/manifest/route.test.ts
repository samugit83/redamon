/**
 * GET /api/mcp/manifest answers the caller's own MCP servers, secrets masked, from
 * their saved settings, with no agent call (HD-15).
 *
 * It proxied the agent's manifest: the servers of whichever account's project the
 * agent loaded last, so any signed-in account read another's server names, URLs and
 * tools.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const eff = vi.hoisted(() => ({ current: { userId: 'u-member' } as { userId: string } | null }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn(async () => eff.current ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })),
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: vi.fn(async (id: string) => ({ id, role: id === 'u-admin' ? 'admin' : 'standard' })),
}))
const mockFindUnique = vi.hoisted(() => vi.fn())
vi.mock('@/lib/prisma', () => ({ default: { userSettings: { findUnique: mockFindUnique } } }))

import { GET } from './route'

const fetchMock = vi.fn()
const OWN = [
  {
    id: 'web', name: 'Web', transport: 'streamable_http', url: 'https://mcp.example.com/mcp', enabled: true, tools: [],
    auth: { type: 'bearer', token: 'own-bearer-SECRET-1234' }, headers: { 'X-Api-Key': 'hdr-SECRET-5678' },
  },
  { id: 'cmd', name: 'Cmd', transport: 'stdio', command: 'npx', env: { API_KEY: 'env-SECRET-9012' }, enabled: true, tools: [] },
]

beforeEach(() => {
  vi.clearAllMocks()
  eff.current = { userId: 'u-member' }
  vi.stubGlobal('fetch', fetchMock)
  mockFindUnique.mockResolvedValue({ mcpServers: OWN })
})

describe('GET /api/mcp/manifest', () => {
  test("returns the caller's servers redacted", async () => {
    const res = await GET(new NextRequest('http://localhost/api/mcp/manifest'))
    expect(res.status).toBe(200)
    expect(mockFindUnique).toHaveBeenCalledWith(expect.objectContaining({ where: { userId: 'u-member' } }))
    const text = await res.text()
    for (const secret of ['own-bearer-SECRET-1234', 'hdr-SECRET-5678', 'env-SECRET-9012']) expect(text).not.toContain(secret)
    const body = JSON.parse(text)
    expect(body.servers.map((s: { id: string }) => s.id)).toEqual(['web', 'cmd'])
    expect(body.servers[0]).toMatchObject({ name: 'Web', transport: 'streamable_http', url: 'https://mcp.example.com/mcp' })
    expect(body.servers[0].auth.token.startsWith('••••')).toBe(true)
    expect(body).toMatchObject({ errors: [], warnings: [], stdioAllowed: false })
    expect(body.system_server_ids).toEqual(['metasploit', 'network_recon', 'nmap', 'nuclei', 'playwright'])
  })

  test('no agent call', async () => {
    await GET(new NextRequest('http://localhost/api/mcp/manifest'))
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('nothing saved: an empty list', async () => {
    mockFindUnique.mockResolvedValue(null)
    expect((await (await GET(new NextRequest('http://localhost/api/mcp/manifest'))).json()).servers).toEqual([])
  })

  test('no session 401, nothing read', async () => {
    eff.current = null
    expect((await GET(new NextRequest('http://localhost/api/mcp/manifest'))).status).toBe(401)
    expect(mockFindUnique).not.toHaveBeenCalled()
  })

  test('a database failure answers its code, not its text', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockFindUnique.mockRejectedValue(Object.assign(new Error('row user=u-member secret'), { code: 'P1001' }))
    const res = await GET(new NextRequest('http://localhost/api/mcp/manifest'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to read your MCP servers', code: 'P1001' })
  })
})
