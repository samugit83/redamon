/**
 * Issue #184 — an unreachable agent must not be reported as a fault in the
 * provider the operator just configured.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindFirst = vi.fn()
const mockRequireUserAccess = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: { userLlmProvider: { findFirst: (...a: unknown[]) => mockFindFirst(...a) } },
}))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
}))

import { POST } from './route'
import { agentBaseUrl } from '@/lib/agentFetch'

const CONFIG = {
  providerType: 'openai_compatible',
  name: 'qwen',
  baseUrl: 'http://192.168.0.40:8000/v1',
  modelIdentifier: 'qwen',
  sslVerify: false,
}

function post(body: unknown): NextRequest {
  return new NextRequest('http://x/api/users/u1/llm-providers/unsaved/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
const params = (id: string, providerId: string) => ({ params: Promise.resolve({ id, providerId }) })

/** The exact shape Node throws when Docker's embedded DNS has no record for a
 *  compose service whose container is not running. */
function dnsFailure(): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error('getaddrinfo ENOTFOUND agent') as NodeJS.ErrnoException
  cause.code = 'ENOTFOUND'
  cause.syscall = 'getaddrinfo'
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

const fetchMock = vi.fn()

beforeEach(() => {
  mockFindFirst.mockReset().mockResolvedValue(null)
  mockRequireUserAccess.mockReset().mockResolvedValue(null)
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('POST llm-providers/[providerId]/test — agent down', () => {
  test('returns 503 with a message naming the agent, not the provider', async () => {
    fetchMock.mockRejectedValue(dnsFailure())

    const res = await POST(post(CONFIG), params('u1', 'unsaved'))
    const body = await res.json()

    expect(res.status).toBe(503)
    expect(body.success).toBe(false)
    expect(body.error).toContain('RedAmon agent service')
    expect(body.error).toContain('agent container is not running')
    expect(body.error).toContain('docker compose ps -a agent')
    // The regression: the operator must be told their Base URL is not at fault.
    expect(body.error).toContain('not a problem with the endpoint you configured')
  })

  test('the SERVER log also carries the actionable sentence, not just the stack', async () => {
    // Found by running the real flow: logging only `error.cause_` reproduced the
    // unreadable "TypeError: fetch failed" stack inside the container logs, so
    // an operator reading logs was no better off than the user in #184.
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    fetchMock.mockRejectedValue(dnsFailure())

    await POST(post(CONFIG), params('u1', 'unsaved'))

    const logged = errSpy.mock.calls.flat().filter((a) => typeof a === 'string').join(' ')
    expect(logged).toContain('agent unreachable')
    expect(logged).toContain('agent container is not running')
  })

  test('never leaks the raw "TypeError: fetch failed" to the UI', async () => {
    fetchMock.mockRejectedValue(dnsFailure())

    const body = await (await POST(post(CONFIG), params('u1', 'unsaved'))).json()

    expect(body.error).not.toContain('fetch failed')
    expect(body.error).not.toContain('TypeError')
    // ...and no minified Next.js stack frames either.
    expect(body.error).not.toContain('.next/server')
  })

  test('tenant isolation: user A cannot test user B\'s saved provider', async () => {
    // requireUserAccess passes (A is acting as themselves), but the provider id
    // belongs to B. The DB lookup is scoped by userId, so it must miss and the
    // route must 404 WITHOUT dialling the agent with B's restored secret.
    mockRequireUserAccess.mockResolvedValue(null)
    mockFindFirst.mockResolvedValue(null)  // scoped { id, userId } finds nothing

    const res = await POST(post(CONFIG), params('userA', 'provider-owned-by-B'))

    expect(res.status).toBe(404)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(mockFindFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 'provider-owned-by-B', userId: 'userA' } }),
    )
  })

  test('does not contact the agent before the caller is authorized', async () => {
    const { NextResponse } = await import('next/server')
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))

    const res = await POST(post(CONFIG), params('victim', 'unsaved'))

    expect(res.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('POST llm-providers/[providerId]/test — agent reachable', () => {
  test('forwards the config to the agent on the compose network', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ success: true, response_text: 'ok' }), { status: 200 }),
    )

    const res = await POST(post(CONFIG), params('u1', 'unsaved'))
    const body = await res.json()

    expect(res.status).toBe(200)
    expect(body.success).toBe(true)

    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(`${agentBaseUrl()}/llm-provider/test`)
    // The default must be the in-network service name, never the host-published
    // port (this route used to fall back to http://localhost:8090, where nothing
    // listens from inside the webapp container).
    expect(url).not.toContain('localhost:8090')
    expect(JSON.parse(init.body).baseUrl).toBe(CONFIG.baseUrl)
  })

  test('passes an agent-side failure through unchanged (not masked as an outage)', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ success: false, error: 'Connection refused by the model server' }), {
        status: 400,
      }),
    )

    const res = await POST(post(CONFIG), params('u1', 'unsaved'))
    const body = await res.json()

    expect(res.status).toBe(400)
    expect(body.error).toBe('Connection refused by the model server')
  })

  test('a saved provider keeps its stored secret when the form sends the mask', async () => {
    mockFindFirst.mockResolvedValue({ id: 'p1', userId: 'u1', apiKey: 'sk-REAL', baseUrl: 'http://old/v1' })
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))

    await POST(post({ ...CONFIG, apiKey: '••••1234' }), params('u1', 'p1'))

    const sent = JSON.parse(fetchMock.mock.calls[0][1].body)
    expect(sent.apiKey).toBe('sk-REAL')
    expect(sent.baseUrl).toBe(CONFIG.baseUrl)
  })
})

// ---------------------------------------------------------------------------
// Regression: named after the bug found in review.
// ---------------------------------------------------------------------------

describe('regression: 180s route cap overrides the provider\'s own timeout', () => {
  /** The wrapper's budget is the argument handed to AbortSignal.timeout. */
  function budgetMs(spy: ReturnType<typeof vi.spyOn>): number | undefined {
    const call = spy.mock.calls.at(-1)
    return call ? (call[0] as number) : undefined
  }

  test('a long user-configured timeout is not cut short by the hop budget', async () => {
    // The Timeout(s) field is a free integer (Prisma default 120) handed
    // straight to the LLM client. A fixed 180s hop budget aborts a legitimate
    // 600s test and blames the agent - the exact misattribution this feature
    // exists to remove.
    const spy = vi.spyOn(AbortSignal, 'timeout')
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))

    await POST(post({ ...CONFIG, timeout: 600 }), params('u1', 'unsaved'))

    expect(budgetMs(spy)).toBeGreaterThan(600_000)
  })

  test('a short user timeout still gets a usable floor, not 1s', async () => {
    const spy = vi.spyOn(AbortSignal, 'timeout')
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))

    await POST(post({ ...CONFIG, timeout: 1 }), params('u1', 'unsaved'))

    expect(budgetMs(spy)).toBeGreaterThanOrEqual(30_000)
  })

  test('an absurd or hostile timeout is capped so the route cannot hang forever', async () => {
    const spy = vi.spyOn(AbortSignal, 'timeout')
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))

    await POST(post({ ...CONFIG, timeout: 99_999_999 }), params('u1', 'unsaved'))

    const budget = budgetMs(spy)!
    expect(budget).toBeGreaterThan(0)
    expect(budget).toBeLessThanOrEqual(3_600_000)
  })

  test.each([
    ['missing', undefined],
    ['null', null],
    ['a string', '600'],
    ['negative', -5],
    ['zero', 0],
    ['NaN-producing garbage', 'abc'],
  ])('tolerates a %s timeout without producing an invalid budget', async (_label, timeout) => {
    const spy = vi.spyOn(AbortSignal, 'timeout')
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))

    const res = await POST(post({ ...CONFIG, timeout }), params('u1', 'unsaved'))

    expect(res.status).toBe(200)
    const budget = budgetMs(spy)!
    expect(Number.isFinite(budget)).toBe(true)
    expect(budget).toBeGreaterThanOrEqual(30_000)
  })
})
