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

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
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
    // Same type and base URL as stored: the masked key is the stored one (HD-24 only
    // stops it following an edited endpoint, below).
    mockFindFirst.mockResolvedValue({ id: 'p1', userId: 'u1', providerType: CONFIG.providerType, apiKey: 'sk-REAL', baseUrl: CONFIG.baseUrl })
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))

    await POST(post({ ...CONFIG, apiKey: '••••1234', temperature: 0.3 }), params('u1', 'p1'))

    const sent = JSON.parse(fetchMock.mock.calls[0][1].body)
    expect(sent.apiKey).toBe('sk-REAL')
    expect(sent.baseUrl).toBe(CONFIG.baseUrl)
    expect(sent.temperature).toBe(0.3)
  })

  // HD-24: this case used to send the stored key to the edited base URL.
  test('a masked key with an edited base URL is refused: the stored key never reaches the new endpoint', async () => {
    mockFindFirst.mockResolvedValue({ id: 'p1', userId: 'u1', providerType: CONFIG.providerType, apiKey: 'sk-REAL', baseUrl: 'http://old/v1' })

    const res = await POST(post({ ...CONFIG, apiKey: '••••1234' }), params('u1', 'p1'))

    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body).toMatchObject({ success: false, code: 'secret_reentry_required', field: 'apiKey', endpoint: 'baseUrl' })
    expect(JSON.stringify(body)).not.toContain('sk-REAL')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('an edited base URL with the key typed again tests that key', async () => {
    mockFindFirst.mockResolvedValue({ id: 'p1', userId: 'u1', providerType: CONFIG.providerType, apiKey: 'sk-REAL', baseUrl: 'http://old/v1' })
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))

    await POST(post({ ...CONFIG, apiKey: 'sk-typed-again' }), params('u1', 'p1'))

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toMatchObject({ apiKey: 'sk-typed-again', baseUrl: CONFIG.baseUrl })
  })

  test('a masked Extra Headers value is tested with the stored one, on the stored endpoint (review of 1.6)', async () => {
    mockFindFirst.mockResolvedValue({ id: 'p1', userId: 'u1', providerType: CONFIG.providerType, apiKey: '', baseUrl: CONFIG.baseUrl, defaultHeaders: { Authorization: 'Bearer hdr-REAL' } })
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))

    await POST(post({ ...CONFIG, defaultHeaders: { Authorization: '••••••••REAL', 'X-New': 'typed' } }), params('u1', 'p1'))

    expect(JSON.parse(fetchMock.mock.calls[0][1].body).defaultHeaders).toEqual({ Authorization: 'Bearer hdr-REAL', 'X-New': 'typed' })
  })

  test('a masked Extra Headers value with an edited base URL is refused (review of 1.6)', async () => {
    mockFindFirst.mockResolvedValue({ id: 'p1', userId: 'u1', providerType: CONFIG.providerType, apiKey: '', baseUrl: 'http://old/v1', defaultHeaders: { Authorization: 'Bearer hdr-REAL' } })

    const res = await POST(post({ ...CONFIG, defaultHeaders: { Authorization: '••••••••REAL' } }), params('u1', 'p1'))

    expect(res.status).toBe(400)
    const text = await res.text()
    expect(JSON.parse(text)).toMatchObject({ success: false, code: 'secret_reentry_required', field: 'defaultHeaders.Authorization' })
    expect(text).not.toContain('hdr-REAL')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('the test spends the account\'s key, so it asks for the write rule (HD-23)', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))
    await POST(post(CONFIG), params('u1', 'unsaved'))
    expect(mockRequireUserAccess).toHaveBeenCalledWith(expect.anything(), 'u1', { mode: 'write' })
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

describe('POST llm-providers/[providerId]/test - TypeSafe Jev lock', () => {
  const JEV_ROW = {
    id: 'jev1', userId: 'u1', providerType: 'jev', apiKey: 'apikey_stored_key',
    baseUrl: '', modelIdentifier: 'jev-1.13.0', defaultHeaders: {},
  }
  const sentToAgent = () => JSON.parse(fetchMock.mock.calls[0][1].body as string)

  test.each(['jev', 'jev_openrouter'])('a stored %s row cannot be redirected by type changes', async providerType => {
    mockFindFirst.mockResolvedValue({ ...JEV_ROW, providerType })
    const res = await POST(post({ providerType: 'openai_compatible', apiKey: '••••••••_key' }), params('u1', 'jev1'))
    expect(res.status).toBe(400)
    expect(fetchMock).not.toHaveBeenCalled()
  })
  test.each(['jev', 'jev_openrouter'])('saved %s ignores transport overrides', async providerType => {
    mockFindFirst.mockResolvedValue({ ...JEV_ROW, providerType, baseUrl: 'https://legacy-evil.example' })
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))
    await POST(post({ baseUrl: 'https://evil.example', modelIdentifier: 'chat', defaultHeaders: { leak: 'yes' }, timeout: 1000, sslVerify: false, apiKey: '••••••••_key' }), params('u1', 'jev1'))
    expect(sentToAgent()).toMatchObject({ providerType, apiKey: 'apikey_stored_key', baseUrl: providerType === 'jev' ? 'https://api.typesafe.ai' : 'https://openrouter.ai/api/v1', modelIdentifier: providerType === 'jev' ? 'jev-1.13.0' : 'typesafe/jev-1.13', defaultHeaders: {}, timeout: 5, sslVerify: true })
  })
  test.each(['jev', 'jev_openrouter'])('unsaved %s tests pin transport', async providerType => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))
    await POST(post({ providerType, apiKey: 'synthetic-key', baseUrl: 'https://evil.example', sslVerify: false }), params('u1', 'unsaved'))
    expect(sentToAgent()).toMatchObject({ providerType, defaultHeaders: {}, timeout: 5, sslVerify: true })
    expect(sentToAgent().baseUrl).not.toContain('evil.example')
  })
  test('a freshly typed Jev key is the one tested', async () => {
    mockFindFirst.mockResolvedValue(JEV_ROW)
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))
    await POST(post({ apiKey: 'apikey_new_key' }), params('u1', 'jev1'))
    expect(sentToAgent().apiKey).toBe('apikey_new_key')
  })

  test('a stored chat key can never be tested as Jev', async () => {
    mockFindFirst.mockResolvedValue({ ...JEV_ROW, providerType: 'openai', apiKey: 'sk-stored' })
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ success: true }), { status: 200 }))
    const res = await POST(post({ providerType: 'jev', apiKey: '••••••••ored' }), params('u1', 'jev1'))
    expect(res.status).toBe(400)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('POST llm-providers/[providerId]/test — the agent answered with an error', () => {
  test('a FastAPI {detail} (bad internal key) is a 502 with its status, not an empty red X', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'Invalid internal key' }), { status: 401 }))
    const res = await POST(post(CONFIG), params('u1', 'unsaved'))
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({
      success: false, error: 'The agent could not test this provider', code: 'agent_error', upstreamStatus: 401,
    })
  })

  test('a plain-text 500 is a 502 naming the status, never a SyntaxError', async () => {
    fetchMock.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const res = await POST(post(CONFIG), params('u1', 'unsaved'))
    const body = await res.json()
    expect(res.status).toBe(502)
    expect(body).toMatchObject({ success: false, code: 'agent_error', upstreamStatus: 500 })
    expect(JSON.stringify(body)).not.toContain('SyntaxError')
  })

  test('the agent\'s exception text is not forwarded', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'boom: key sk-live-123 rejected' }), { status: 500 }))
    const body = await (await POST(post(CONFIG), params('u1', 'unsaved'))).json()
    expect(JSON.stringify(body)).not.toContain('sk-live-123')
  })

  test('an unreachable agent also carries its code and errno', async () => {
    fetchMock.mockRejectedValue(dnsFailure())
    const body = await (await POST(post(CONFIG), params('u1', 'unsaved'))).json()
    expect(body).toMatchObject({ success: false, code: 'agent_unreachable', cause: 'ENOTFOUND' })
  })

  test('a 200 the agent could not have meant (no success flag) is not shown as a result', async () => {
    fetchMock.mockResolvedValue(new Response('<html>ok</html>', { status: 200 }))
    const res = await POST(post(CONFIG), params('u1', 'unsaved'))
    expect(res.status).toBe(502)
    expect(await res.json()).toMatchObject({ success: false, code: 'agent_error', upstreamStatus: 200 })
  })

  test('a failure inside the route answers a code, never String(error)', async () => {
    const malformed = new NextRequest('http://x/api/users/u1/llm-providers/unsaved/test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json',
    })
    const res = await POST(malformed, params('u1', 'unsaved'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to test LLM provider', code: 'SyntaxError', success: false })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
