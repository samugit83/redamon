/**
 * Tests for POST /api/users/[id]/tradecraft-resources/[resourceId]/refresh.
 *
 * The route proxies to the agent's /tradecraft/verify with force=true. That
 * agent route requires the internal key (CVE-2026-111323), so a refresh that
 * forgets the header fails with 401 instead of refreshing. It must also send
 * the resource's model: without one the agent falls back to its default
 * model, which the user may have no key for, and the refresh fails with 503.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const mockFindFirst = vi.fn()
const mockUpdate = vi.fn()
const mockUserSettingsFindUnique = vi.fn()

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn().mockResolvedValue(null) }))

vi.mock('@/lib/prisma', () => ({
  default: {
    userTradecraftResource: {
      findFirst: (...a: unknown[]) => mockFindFirst(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
    },
    userSettings: {
      findUnique: (...a: unknown[]) => mockUserSettingsFindUnique(...a),
    },
  },
}))

import { NextRequest } from 'next/server'
import * as route from './route'

const PARAMS = { params: Promise.resolve({ id: 'user-1', resourceId: 'res-1' }) }

const EXISTING = {
  id: 'res-1', userId: 'user-1', slug: 'hacktricks',
  name: 'HackTricks', url: 'https://book.hacktricks.wiki',
  llmModel: 'gpt-4o', githubTokenOverride: '',
  resourceType: 'mkdocs-wiki', enabled: true, lastError: '',
}

let capturedFetch: { url: string; init: RequestInit } | null = null

beforeEach(() => {
  mockFindFirst.mockReset().mockResolvedValue(EXISTING)
  mockUpdate.mockReset().mockImplementation(async (args: unknown) => {
    const { where, data } = args as { where: { id: string }; data: Record<string, unknown> }
    return { id: where.id, ...data }
  })
  mockUserSettingsFindUnique.mockReset().mockResolvedValue(null)
  capturedFetch = null
  global.fetch = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    capturedFetch = { url: String(url), init: init ?? {} }
    return new Response(JSON.stringify({
      summary: 's', resource_type: 'mkdocs-wiki', sitemap: {},
      crawl_stopped_because: '', crawl_stats: {}, last_error: '',
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }) as typeof fetch
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
})

describe('refresh route calls the agent verify endpoint', () => {
  test('sends the internal key and force=true', async () => {
    vi.stubEnv('INTERNAL_API_KEY', 'test-internal-key')
    const req = new NextRequest(
      'http://webapp.test/api/users/user-1/tradecraft-resources/res-1/refresh',
      { method: 'POST' },
    )
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(200)
    expect(capturedFetch!.url).toContain('/tradecraft/verify')
    const headers = capturedFetch!.init.headers as Record<string, string>
    expect(headers['x-internal-key']).toBe('test-internal-key')
    expect(JSON.parse(String(capturedFetch!.init.body)).force).toBe(true)
  })

  test("forwards the resource's model", async () => {
    const req = new NextRequest(
      'http://webapp.test/api/users/user-1/tradecraft-resources/res-1/refresh',
      { method: 'POST' },
    )
    await route.POST(req as never, PARAMS as never)
    expect(JSON.parse(String(capturedFetch!.init.body)).model).toBe('gpt-4o')
  })

  test('a legacy row with no model sends model="" (the agent then uses its fallback)', async () => {
    mockFindFirst.mockResolvedValue({ ...EXISTING, llmModel: '' })
    const req = new NextRequest(
      'http://webapp.test/api/users/user-1/tradecraft-resources/res-1/refresh',
      { method: 'POST' },
    )
    await route.POST(req as never, PARAMS as never)
    expect(JSON.parse(String(capturedFetch!.init.body)).model).toBe('')
  })
})

describe('a refresh the agent could not do', () => {
  const refresh = () => route.POST(
    new NextRequest('http://webapp.test/api/users/user-1/tradecraft-resources/res-1/refresh', { method: 'POST' }) as never,
    PARAMS as never,
  )

  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  test('answers a reason, code and the agent status instead of the bare row', async () => {
    global.fetch = vi.fn(async () => new Response(
      JSON.stringify({ error: 'LLM not configured: Error code: 401 - key sk-live-abc invalid' }), { status: 503 },
    )) as typeof fetch
    const r = await refresh()
    expect(r.status).toBe(502)
    expect(await r.json()).toEqual({
      error: 'The agent could not refresh this resource', code: 'agent_error', upstreamStatus: 503,
    })
  })

  test('records the cause on the row without the agent text, so the list can show it', async () => {
    global.fetch = vi.fn(async () => new Response(
      JSON.stringify({ error: 'LLM not configured: key sk-live-abc invalid' }), { status: 503 },
    )) as typeof fetch
    await refresh()
    const { data } = mockUpdate.mock.calls[0][0] as { data: { lastError: string } }
    expect(data.lastError).toBe('refresh failed (agent_error, agent HTTP 503)')
    expect(data.lastError).not.toContain('sk-live')
  })

  test('an agent that never answered is a 503 naming it, with the errno', async () => {
    const err = new TypeError('fetch failed')
    ;(err as TypeError & { cause?: unknown }).cause = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })
    global.fetch = vi.fn(async () => { throw err }) as typeof fetch
    const r = await refresh()
    expect(r.status).toBe(503)
    expect(await r.json()).toEqual({
      error: 'Failed to refresh tradecraft resource', code: 'agent_unreachable', cause: 'ECONNREFUSED',
    })
  })

  test('a database failure answers its code', async () => {
    mockFindFirst.mockRejectedValue(Object.assign(new Error("Can't reach database server"), { code: 'P1001' }))
    const r = await refresh()
    expect(r.status).toBe(500)
    expect(await r.json()).toEqual({ error: 'Failed to refresh tradecraft resource', code: 'P1001' })
  })
})
