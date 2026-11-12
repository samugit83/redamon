/**
 * Regression + unit tests for the /api/models proxy route.
 *
 * Pre-fix: `GET /api/models?userId=xxx` fetched the user's UserLlmProvider rows
 * from Postgres and forwarded them — apiKey and all — as a URL-encoded
 * `?providers=...` query string on a GET to the agent's `/models` endpoint.
 * uvicorn's access log persisted the full URL (including the apiKey) to disk.
 *
 * Post-fix: `POST /api/models` reads `userId` from a JSON body and forwards
 * the providers list in a JSON POST body to the agent — never in a URL.
 *
 * Tests below would fail pre-fix:
 *   - "exports POST, not GET" — pre-fix only exported GET
 *   - "agent fetch is POST" — pre-fix used GET
 *   - "apiKey appears only in fetch body, never in URL" — pre-fix put it in URL
 *
 * Run: npx vitest run src/app/api/models/route.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const CANARY_KEY = 'sk-ant-api03-LEAK-CANARY-DO-NOT-LOG-XXXXXXXXXX'

// Mock Prisma before importing the route. Hoisted by vitest.
const mockFindMany = vi.fn()
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1' }) }))

vi.mock('@/lib/prisma', () => ({
  default: { userLlmProvider: { findMany: (...args: unknown[]) => mockFindMany(...args) } },
}))

// Import after mocks are registered. Vitest hoists vi.mock above this.
// Tests assert on URL shape (path + query), not the host, since the host isn't
// what leaks.
import * as route from './route'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(body: unknown | undefined): Request {
  const init: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }
  if (body !== undefined) init.body = JSON.stringify(body)
  return new Request('http://webapp.test/api/models', init)
}

/** Capture the last `fetch` call arguments for assertion. */
let capturedFetch: { url: string; init: RequestInit } | null = null

function installFetchStub(response: unknown, ok = true): void {
  capturedFetch = null
  global.fetch = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    capturedFetch = { url: String(url), init: init ?? {} }
    return new Response(JSON.stringify(response), {
      status: ok ? 200 : 503,
      headers: { 'Content-Type': 'application/json' },
    })
  }) as typeof fetch
}

beforeEach(() => {
  mockFindMany.mockReset()
  capturedFetch = null
})

afterEach(() => {
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Route exports — regression: GET must not exist anymore.
// ---------------------------------------------------------------------------

describe('route module exports', () => {
  test('exports POST, not GET (regression: pre-fix exported GET)', () => {
    expect(typeof route.POST).toBe('function')
    expect((route as Record<string, unknown>).GET).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// POST handler — happy paths
// ---------------------------------------------------------------------------

describe('POST /api/models', () => {
  test('with userId: fetches providers from DB and forwards to agent as POST body', async () => {
    const providerRow = {
      id: 'p1',
      userId: 'u1',
      providerType: 'anthropic',
      name: 'Anthropic',
      apiKey: CANARY_KEY,
    }
    mockFindMany.mockResolvedValueOnce([providerRow])
    installFetchStub({ anthropic: [{ id: 'claude-x' }] })

    const res = await route.POST(makeRequest({ userId: 'u1' }) as never)

    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ anthropic: [{ id: 'claude-x' }] })

    expect(mockFindMany).toHaveBeenCalledWith({ where: { userId: 'u1' } })

    expect(capturedFetch).not.toBeNull()
    // URL is path-suffix `/models` with NO query string.
    expect(capturedFetch!.url).toMatch(/\/models$/)
    expect(capturedFetch!.url).not.toContain('?')
    expect(capturedFetch!.init.method).toBe('POST')
    const sentBody = JSON.parse(capturedFetch!.init.body as string)
    expect(sentBody.providers).toEqual([providerRow])
  })

  test('without userId: no DB lookup, agent gets null providers', async () => {
    installFetchStub({})

    const res = await route.POST(makeRequest({}) as never)

    expect(res.status).toBe(200)
    expect(mockFindMany).not.toHaveBeenCalled()
    expect(capturedFetch!.init.method).toBe('POST')
    const sentBody = JSON.parse(capturedFetch!.init.body as string)
    expect(sentBody).toEqual({ providers: null })
  })

  test('with userId but no provider rows: null providers, no upstream leak', async () => {
    mockFindMany.mockResolvedValueOnce([])
    installFetchStub({})

    const res = await route.POST(makeRequest({ userId: 'u1' }) as never)

    expect(res.status).toBe(200)
    expect(mockFindMany).toHaveBeenCalled()
    const sentBody = JSON.parse(capturedFetch!.init.body as string)
    expect(sentBody).toEqual({ providers: null })
  })

  test('malformed body: handler treats it as empty (no DB lookup, no crash)', async () => {
    installFetchStub({})

    // Body that is not valid JSON.
    const bad = new Request('http://webapp.test/api/models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not-json',
    })
    const res = await route.POST(bad as never)

    expect(res.status).toBe(200)
    expect(mockFindMany).not.toHaveBeenCalled()
  })

  test('agent error response is propagated as 503, with the agent status', async () => {
    mockFindMany.mockResolvedValueOnce([])
    installFetchStub({ error: 'boom' }, false)
    vi.spyOn(console, 'error').mockImplementation(() => {})

    const res = await route.POST(makeRequest({}) as never)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Failed to fetch models from agent API',
      code: 'agent_error',
      upstreamStatus: 503,
    })
  })

  test('an agent that never answers is 503 agent_unreachable with the errno', async () => {
    global.fetch = vi.fn(async () => {
      throw Object.assign(new TypeError('fetch failed'), {
        cause: Object.assign(new Error('connect ECONNREFUSED 172.18.0.5:8080'), { code: 'ECONNREFUSED' }),
      })
    }) as typeof fetch
    vi.spyOn(console, 'error').mockImplementation(() => {})

    const res = await route.POST(makeRequest({}) as never)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({ error: 'Failed to connect to agent API', code: 'agent_unreachable', cause: 'ECONNREFUSED' })
  })

  test('an agent that never answers in time is 504 agent_timeout', async () => {
    global.fetch = vi.fn(async () => {
      throw new DOMException('The operation was aborted due to timeout', 'TimeoutError')
    }) as typeof fetch
    vi.spyOn(console, 'error').mockImplementation(() => {})

    const res = await route.POST(makeRequest({}) as never)
    expect(res.status).toBe(504)
    expect((await res.json()).code).toBe('agent_timeout')
  })

  test('a database failure is 500 with its Prisma code, and the agent is not called', async () => {
    mockFindMany.mockRejectedValueOnce(Object.assign(new Error('SELECT "apiKey" FROM ...'), { code: 'P1001' }))
    installFetchStub({})
    vi.spyOn(console, 'error').mockImplementation(() => {})

    const res = await route.POST(makeRequest({ userId: 'u1' }) as never)
    const text = await res.text()
    expect(res.status).toBe(500)
    expect(JSON.parse(text)).toEqual({ error: 'Failed to load the models', code: 'P1001' })
    expect(text).not.toContain('apiKey')
    expect(capturedFetch).toBeNull()
  })

  test('the agent call carries the internal key and a timeout', async () => {
    installFetchStub({})
    await route.POST(makeRequest({}) as never)
    expect(capturedFetch!.init.headers).toHaveProperty('x-internal-key')
    expect(capturedFetch!.init.signal).toBeInstanceOf(AbortSignal)
  })
})

// ---------------------------------------------------------------------------
// A non-chat key (TypeSafe Jev) lists no models and must not travel at all.
// ---------------------------------------------------------------------------

describe('non-chat provider rows', () => {
  const JEV_KEY = 'ts-JEV-CANARY-must-not-reach-the-agent-models-endpoint'

  test('a Jev row is dropped; chat rows are still forwarded', async () => {
    const chatRow = { id: 'p1', providerType: 'anthropic', apiKey: 'sk-ant' }
    mockFindMany.mockResolvedValueOnce([
      { id: 'p-jev', providerType: 'jev', apiKey: JEV_KEY },
      chatRow,
    ])
    installFetchStub({})

    await route.POST(makeRequest({ userId: 'u1' }) as never)

    const body = capturedFetch!.init.body as string
    expect(body).not.toContain(JEV_KEY)
    expect(JSON.parse(body).providers).toEqual([chatRow])
  })

  test('a Jev-only user sends null providers, like a user with none', async () => {
    mockFindMany.mockResolvedValueOnce([{ id: 'p-jev', providerType: 'jev', apiKey: JEV_KEY }])
    installFetchStub({})

    await route.POST(makeRequest({ userId: 'u1' }) as never)

    expect(JSON.parse(capturedFetch!.init.body as string)).toEqual({ providers: null })
  })
})

// ---------------------------------------------------------------------------
// Critical regression: apiKey is in BODY, never in URL.
// ---------------------------------------------------------------------------

describe('apiKey leakage — URL must never carry the key', () => {
  test('canary apiKey appears in fetch body but NOT in fetch URL', async () => {
    mockFindMany.mockResolvedValueOnce([
      { id: 'p1', userId: 'u1', providerType: 'anthropic', apiKey: CANARY_KEY },
    ])
    installFetchStub({})

    await route.POST(makeRequest({ userId: 'u1' }) as never)

    expect(capturedFetch).not.toBeNull()
    // URL must NOT contain the canary, the literal "apiKey" param name, nor
    // the URL-encoded `providers=` blob that leaked pre-fix.
    expect(capturedFetch!.url).not.toContain(CANARY_KEY)
    expect(capturedFetch!.url).not.toContain(encodeURIComponent(CANARY_KEY))
    expect(capturedFetch!.url).not.toContain('apiKey')
    expect(capturedFetch!.url).not.toContain('providers=')

    // Sanity: the body DOES contain it (so the agent can use it downstream).
    expect(capturedFetch!.init.body as string).toContain(CANARY_KEY)
  })

  test('canary in body survives JSON round-trip, parsed value matches', async () => {
    mockFindMany.mockResolvedValueOnce([
      { providerType: 'openai', apiKey: CANARY_KEY },
      { providerType: 'anthropic', apiKey: 'sk-ant-api03-OTHER-KEY' },
    ])
    installFetchStub({})

    await route.POST(makeRequest({ userId: 'u1' }) as never)

    const sentBody = JSON.parse(capturedFetch!.init.body as string)
    expect(sentBody.providers).toHaveLength(2)
    expect(sentBody.providers[0].apiKey).toBe(CANARY_KEY)
    expect(sentBody.providers[1].apiKey).toBe('sk-ant-api03-OTHER-KEY')
  })
})
