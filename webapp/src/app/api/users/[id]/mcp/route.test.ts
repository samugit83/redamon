/**
 * MCP Tool Plugin writes and the agent reload that follows them.
 *
 * The reload used to be fire-and-forget: a save whose reload failed (agent
 * down, internal key mismatch, a tool collision the agent refused) read as
 * applied while the agent kept running the old list. The save still answers
 * 2xx, because the list is stored, and now says what did not happen in
 * `warnings`, as a code and a status: the agent answers a failed reload with
 * `str(exc)`, which is never forwarded.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpsert = vi.fn()
const mockUpdate = vi.fn()
const fetchMock = vi.fn()

vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn().mockResolvedValue(null) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      upsert: (...a: unknown[]) => mockUpsert(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
    },
  },
}))

import { GET, POST } from './route'
import { PUT, DELETE } from './[serverId]/route'

const SERVER = { id: 'probe', name: 'Probe', transport: 'stdio', command: 'echo' }
const RELOAD_FAILED = 'The agent did not reload its MCP Tool Plugins'

function json(method: string, url: string, body?: unknown): NextRequest {
  return new NextRequest(url, {
    method,
    headers: { 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const listParams = { params: Promise.resolve({ id: 'u1' }) }
const oneParams = { params: Promise.resolve({ id: 'u1', serverId: 'probe' }) }

function refused(code: string): TypeError {
  const err = new TypeError('fetch failed')
  ;(err as TypeError & { cause?: unknown }).cause = Object.assign(new Error(`connect ${code}`), { code })
  return err
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  mockFindUnique.mockResolvedValue({ mcpServers: [] })
  mockUpsert.mockResolvedValue({})
  mockUpdate.mockResolvedValue({})
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ servers: 1 }), { status: 200 }))
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('POST /api/users/[id]/mcp', () => {
  test('a reload the agent took: 201 and no warnings', async () => {
    const res = await POST(json('POST', 'http://x/api/users/u1/mcp', SERVER), listParams)
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.warnings).toBeUndefined()
    expect(String(fetchMock.mock.calls[0][0])).toContain('/mcp/reload')
  })

  test('a reload the agent refused: still saved, with a warning naming its status and no agent text', async () => {
    fetchMock.mockImplementation(async () =>
      new Response(JSON.stringify({ error: 'tool collision: header Authorization=Bearer ghp_secret' }), { status: 500 }))
    const res = await POST(json('POST', 'http://x/api/users/u1/mcp', SERVER), listParams)
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.warnings).toEqual([
      { service: 'agent', message: RELOAD_FAILED, code: 'agent_error', upstreamStatus: 500 },
    ])
    expect(JSON.stringify(body)).not.toContain('ghp_secret')
    expect(mockUpsert).toHaveBeenCalledTimes(1)
  })

  test('an agent that never answered: the warning carries the errno', async () => {
    fetchMock.mockRejectedValue(refused('ECONNREFUSED'))
    const body = await (await POST(json('POST', 'http://x/api/users/u1/mcp', SERVER), listParams)).json()
    expect(body.warnings).toEqual([
      { service: 'agent', message: RELOAD_FAILED, code: 'agent_unreachable', cause: 'ECONNREFUSED' },
    ])
  })

  test('a reload that timed out says so, since it may still finish', async () => {
    fetchMock.mockRejectedValue(new DOMException('The operation was aborted due to timeout', 'TimeoutError'))
    const body = await (await POST(json('POST', 'http://x/api/users/u1/mcp', SERVER), listParams)).json()
    expect(body.warnings[0]).toMatchObject({ code: 'agent_timeout' })
  })

  test('a database failure answers its code, not a bare fixed string', async () => {
    mockUpsert.mockRejectedValue(Object.assign(new Error('Timed out fetching a new connection'), { code: 'P2024' }))
    const res = await POST(json('POST', 'http://x/api/users/u1/mcp', SERVER), listParams)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to add MCP server', code: 'P2024' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('GET /api/users/[id]/mcp', () => {
  test('a database failure answers its code', async () => {
    mockFindUnique.mockRejectedValue(Object.assign(new Error("Can't reach database server"), { code: 'P1001' }))
    const res = await GET(json('GET', 'http://x/api/users/u1/mcp'), listParams)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to list MCP servers', code: 'P1001' })
  })
})

describe('PUT / DELETE /api/users/[id]/mcp/[serverId]', () => {
  beforeEach(() => {
    mockFindUnique.mockResolvedValue({ mcpServers: [{ ...SERVER, enabled: true, tools: [] }] })
  })

  test('an update whose reload failed is saved with a warning', async () => {
    fetchMock.mockImplementation(async () => new Response(JSON.stringify({ detail: 'Invalid internal key' }), { status: 401 }))
    const res = await PUT(json('PUT', 'http://x/api/users/u1/mcp/probe', { ...SERVER, enabled: false }), oneParams)
    expect(res.status).toBe(200)
    expect((await res.json()).warnings).toEqual([
      { service: 'agent', message: RELOAD_FAILED, code: 'agent_error', upstreamStatus: 401 },
    ])
    expect(mockUpdate).toHaveBeenCalledTimes(1)
  })

  test('a delete whose reload failed is saved with a warning', async () => {
    fetchMock.mockRejectedValue(refused('ENOTFOUND'))
    const res = await DELETE(json('DELETE', 'http://x/api/users/u1/mcp/probe'), oneParams)
    expect(res.status).toBe(200)
    expect((await res.json()).warnings[0]).toMatchObject({ code: 'agent_unreachable', cause: 'ENOTFOUND' })
  })

  test('a database failure on update answers its code', async () => {
    mockUpdate.mockRejectedValue(Object.assign(new Error('Transaction failed'), { code: 'P2034' }))
    const res = await PUT(json('PUT', 'http://x/api/users/u1/mcp/probe', SERVER), oneParams)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to update MCP server', code: 'P2034' })
  })

  test('a database failure on delete answers its code', async () => {
    mockUpdate.mockRejectedValue(Object.assign(new Error('Transaction failed'), { code: 'P2034' }))
    const res = await DELETE(json('DELETE', 'http://x/api/users/u1/mcp/probe'), oneParams)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to delete MCP server', code: 'P2034' })
  })
})

describe('DELETE never returns a stored token', () => {
  test('the servers left after a delete are masked, like every other answer', async () => {
    const TOKEN = 'ghp_literalStoredToken1234567890'
    mockFindUnique.mockResolvedValue({
      mcpServers: [
        { ...SERVER, enabled: true, tools: [] },
        {
          id: 'github', name: 'GitHub', transport: 'streamable_http', url: 'https://mcp.example/mcp',
          enabled: true, tools: [], auth: { type: 'bearer', token: TOKEN },
        },
      ],
    })
    const res = await DELETE(json('DELETE', 'http://x/api/users/u1/mcp/probe'), oneParams)
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain(TOKEN)
    const body = JSON.parse(text)
    expect(body.servers.map((s: { id: string }) => s.id)).toEqual(['github'])
    expect(body.servers[0].auth.token.startsWith('••••')).toBe(true)
    // The database keeps the literal: only the answer is masked.
    expect(JSON.stringify(mockUpdate.mock.calls[0][0])).toContain(TOKEN)
  })
})

describe('PUT /api/users/[id]/mcp/[serverId]: a new URL needs its secrets typed again (HD-24)', () => {
  const TOKEN = 'mcp-STORED-bearer-1234'
  const STORED = {
    id: 'probe', name: 'Probe', transport: 'streamable_http', url: 'https://mcp.example.com/mcp',
    enabled: true, tools: [], auth: { type: 'bearer', token: TOKEN }, headers: { 'X-Api-Key': 'hdr-STORED-9999' },
  }
  const put = (body: unknown) => PUT(json('PUT', 'http://x/api/users/u1/mcp/probe', body), oneParams)

  beforeEach(() => mockFindUnique.mockResolvedValue({ mcpServers: [STORED] }))

  test('a new URL with the masked token is 400 naming auth.token; nothing is written or reloaded', async () => {
    const res = await put({ ...STORED, url: 'https://elsewhere.example.net/mcp', auth: { type: 'bearer', token: '••••••••1234' }, headers: {} })
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(JSON.parse(text)).toMatchObject({ code: 'secret_reentry_required', field: 'auth.token', endpoint: 'url' })
    expect(text).not.toContain(TOKEN)
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('a masked header value counts as a stored secret', async () => {
    const res = await put({ ...STORED, url: 'https://elsewhere.example.net/mcp', auth: { type: 'bearer', token: 'typed-again' }, headers: { 'X-Api-Key': '••••••••9999' } })
    expect(res.status).toBe(400)
    expect((await res.json()).field).toBe('headers.X-Api-Key')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a new URL with the token and header typed again is saved as typed', async () => {
    const res = await put({ ...STORED, url: 'https://elsewhere.example.net/mcp', auth: { type: 'bearer', token: 'typed-again' }, headers: { 'X-Api-Key': 'hdr-new' } })
    expect(res.status).toBe(200)
    const saved = mockUpdate.mock.calls[0][0].data.mcpServers[0]
    expect(saved).toMatchObject({ url: 'https://elsewhere.example.net/mcp', auth: { token: 'typed-again' }, headers: { 'X-Api-Key': 'hdr-new' } })
  })

  test('the same URL keeps the masked token and header (every save from the form)', async () => {
    const res = await put({ ...STORED, enabled: false, auth: { type: 'bearer', token: '••••••••1234' }, headers: { 'X-Api-Key': '••••••••9999' } })
    expect(res.status).toBe(200)
    const saved = mockUpdate.mock.calls[0][0].data.mcpServers[0]
    expect(saved.auth.token).toBe(TOKEN)
    expect(saved.headers['X-Api-Key']).toBe('hdr-STORED-9999')
  })
})

describe('PUT /api/users/[id]/mcp/[serverId]: a new stdio command needs its env values typed again (review of 1.6)', () => {
  const ENV = 'env-STORED-5555'
  const STORED = {
    id: 'probe', name: 'Probe', transport: 'stdio', command: 'npx', args: ['shodan-mcp'],
    env: { SHODAN_API_KEY: ENV }, enabled: true, tools: [],
  }
  const put = (body: unknown) => PUT(json('PUT', 'http://x/api/users/u1/mcp/probe', body), oneParams)

  beforeEach(() => mockFindUnique.mockResolvedValue({ mcpServers: [STORED] }))

  test('a new command with the masked env value is 400 naming it; nothing is written or reloaded', async () => {
    const res = await put({ ...STORED, command: 'sh', args: ['-c', 'env'], env: { SHODAN_API_KEY: '••••••••5555' } })
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(JSON.parse(text)).toMatchObject({ code: 'secret_reentry_required', field: 'env.SHODAN_API_KEY', endpoint: 'command' })
    expect(text).not.toContain(ENV)
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('the same command keeps the masked env value (every save from the form)', async () => {
    const res = await put({ ...STORED, enabled: false, env: { SHODAN_API_KEY: '••••••••5555' } })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.mcpServers[0].env.SHODAN_API_KEY).toBe(ENV)
  })
})
