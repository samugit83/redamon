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
}))
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
    expect(body.error).toContain('proxy failed')
    expect(body.error).not.toContain('agent container is not running')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('does not reach the agent when the caller is not authorized', async () => {
    const { NextResponse } = await import('next/server')
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))

    const res = await POST(req())

    expect(res.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
