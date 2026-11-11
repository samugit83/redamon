/**
 * Issue #184 (MCP half) — when the agent container is down, POST /api/mcp/test
 * must say so instead of blaming the MCP server the operator just configured.
 *
 * The response SHAPE matters as much as the message: McpServersTab renders
 * `discovered_tools` / `warnings` unconditionally, so an outage body that omits
 * them would crash the panel instead of showing the reason.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockRequireUserAccess = vi.fn()
const mockUserSettingsFindUnique = vi.fn()
const fetchMock = vi.fn()

vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
  requireSession: async () => ({ userId: 'u1', role: 'admin' }),
  isInternalRequest: () => false,
}))
// SERVER is a stdio draft: its owner is an administrator, so the stdio rule (step 1.9,
// route.test.ts) lets it through to the outage handling this file covers.
vi.mock('@/lib/authz/principal', () => ({ loadPrincipal: async (id: string) => ({ id, role: 'admin' }) }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/prisma', () => ({
  default: { userSettings: { findUnique: (...a: unknown[]) => mockUserSettingsFindUnique(...a) } },
}))

import { POST } from './route'

const SERVER = { id: 's1', name: 'probe', transport: 'stdio', command: 'echo' }

function req(): NextRequest {
  return new NextRequest('http://x/api/mcp/test', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ server: SERVER, userId: 'u1' }),
  })
}

function dnsFailure(): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error('getaddrinfo ENOTFOUND agent') as NodeJS.ErrnoException
  cause.code = 'ENOTFOUND'
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', fetchMock)
  mockRequireUserAccess.mockResolvedValue(null)
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('POST /api/mcp/test — agent unreachable', () => {
  test('returns 503 naming the agent, not the MCP server', async () => {
    fetchMock.mockRejectedValue(dnsFailure())

    const res = await POST(req())
    const body = await res.json()

    expect(res.status).toBe(503)
    expect(body.ok).toBe(false)
    expect(body.error).toContain('RedAmon agent service')
    expect(body.error).toContain('agent container is not running')
    expect(body.error).not.toContain('fetch failed')
    expect(body.error).not.toContain('proxy failed')
  })

  test('keeps the full response shape so the panel can still render', async () => {
    fetchMock.mockRejectedValue(dnsFailure())

    const body = await (await POST(req())).json()

    expect(body).toMatchObject({
      ok: false,
      discovered_tools: [],
      warnings: [],
      elapsed_ms: 0,
    })
    expect(typeof body.error).toBe('string')
  })

  test('a non-transport failure still yields 502, not a false outage', async () => {
    // A malformed request body is a bug in the caller, not an agent outage.
    // Mislabelling it 503 would send the operator to inspect healthy containers.
    const malformed = new NextRequest('http://x/api/mcp/test', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not json',
    })

    const res = await POST(malformed)
    const body = await res.json()

    expect(res.status).toBe(502)
    expect(body.error).toBe('MCP test proxy failed')
    expect(body.code).toBe('SyntaxError')
    // The parser's own message quotes the body it choked on.
    expect(JSON.stringify(body)).not.toContain('not json')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('the outage answer carries the agent code and the errno', async () => {
    fetchMock.mockRejectedValue(dnsFailure())
    const body = await (await POST(req())).json()
    expect(body).toMatchObject({ code: 'agent_unreachable', cause: 'ENOTFOUND' })
  })

  test('does not reach the agent when the caller is not authorized', async () => {
    const { NextResponse } = await import('next/server')
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))

    const res = await POST(req())

    expect(res.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('POST /api/mcp/test — the agent answered with an error', () => {
  const SHAPE = { ok: false, discovered_tools: [], warnings: [], elapsed_ms: 0 }

  test('a FastAPI {detail} (bad internal key) keeps the panel shape and names the status', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'Invalid internal key' }), { status: 401 }))
    const res = await POST(req())
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({
      ...SHAPE, error: 'The agent could not run the MCP test', code: 'agent_error', upstreamStatus: 401,
    })
  })

  test('a plain-text 500 keeps the panel shape instead of an empty object', async () => {
    fetchMock.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const res = await POST(req())
    expect(res.status).toBe(502)
    expect(await res.json()).toMatchObject({ ...SHAPE, code: 'agent_error', upstreamStatus: 500 })
  })

  test('an agent exception text is not forwarded', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'reload failed: token ghp_secret' }), { status: 500 }))
    const body = await (await POST(req())).json()
    expect(JSON.stringify(body)).not.toContain('ghp_secret')
  })

  test('a test the agent ran is passed through, with any missing list filled', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ ok: false, error: 'stdio transport requires a `command`' }), { status: 200 }))
    const res = await POST(req())
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ...SHAPE, error: 'stdio transport requires a `command`' })
  })
})
