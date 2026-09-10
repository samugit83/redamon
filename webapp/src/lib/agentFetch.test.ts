import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  agentFetch,
  describeAgentFailure,
  AgentUnreachableError,
  agentBaseUrl,
} from './agentFetch'

/** Build the shape undici actually throws: an opaque TypeError whose `.cause`
 *  carries the syscall errno. Getting this nesting wrong is precisely how
 *  "TypeError: fetch failed" reached the user in issue #184. */
function undiciFailure(code: string): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error(`${code} agent`) as NodeJS.ErrnoException
  cause.code = code
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

describe('describeAgentFailure', () => {
  it('names the agent, not the user endpoint, on ENOTFOUND', () => {
    const msg = describeAgentFailure(undiciFailure('ENOTFOUND'))
    expect(msg).toContain('RedAmon agent service')
    expect(msg).toContain(agentBaseUrl())
    expect(msg).toContain('agent container is not running')
    // The regression guard for #184: the operator must be told their own
    // configured endpoint is not the culprit.
    expect(msg).toContain('not a problem with the endpoint you configured')
    expect(msg).not.toContain('fetch failed')
  })

  it('gives a docker command to run', () => {
    expect(describeAgentFailure(undiciFailure('ENOTFOUND'))).toContain(
      'docker compose ps -a agent',
    )
  })

  it('distinguishes refused from unresolvable', () => {
    const refused = describeAgentFailure(undiciFailure('ECONNREFUSED'))
    expect(refused).toContain('connection refused')
    expect(refused).not.toContain('does not resolve')
  })

  it('distinguishes no-route (network split) from the others', () => {
    const msg = describeAgentFailure(undiciFailure('EHOSTUNREACH'))
    expect(msg).toContain('same Docker network')
  })

  it('reads an errno set directly on the error (not nested in cause)', () => {
    const err = new Error('boom') as NodeJS.ErrnoException
    err.code = 'ECONNREFUSED'
    expect(describeAgentFailure(err)).toContain('connection refused')
  })

  it('treats DNS temporary failure like a missing container', () => {
    expect(describeAgentFailure(undiciFailure('EAI_AGAIN'))).toContain(
      'agent container is not running',
    )
  })

  it('reports a reset connection as a restart / OOM', () => {
    expect(describeAgentFailure(undiciFailure('ECONNRESET'))).toContain(
      'out of memory',
    )
  })

  it('maps an abort/timeout signal to a timeout message', () => {
    const timeout = new Error('The operation was aborted due to timeout')
    timeout.name = 'TimeoutError'
    expect(describeAgentFailure(timeout)).toContain('did not respond in time')

    const abort = new Error('This operation was aborted')
    abort.name = 'AbortError'
    expect(describeAgentFailure(abort)).toContain('did not respond in time')
  })

  it('falls back to the original message for an unclassified error', () => {
    expect(describeAgentFailure(new Error('something odd'))).toContain('something odd')
  })

  it('never throws on a non-Error rejection', () => {
    expect(describeAgentFailure('plain string')).toContain('plain string')
    expect(describeAgentFailure(null)).toContain('null')
    expect(describeAgentFailure(undefined)).toBeTypeOf('string')
  })
})

describe('agentFetch', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    process.env.INTERNAL_API_KEY = 'test-internal-key'
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    delete process.env.INTERNAL_API_KEY
  })

  it('prefixes the agent base URL and attaches the internal key', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))
    await agentFetch('/llm-provider/test', { method: 'POST' })

    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(`${agentBaseUrl()}/llm-provider/test`)
    expect(init.method).toBe('POST')
    expect(init.headers['x-internal-key']).toBe('test-internal-key')
  })

  it('preserves caller headers alongside the internal key', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))
    await agentFetch('/x', { headers: { 'Content-Type': 'application/json' } })

    const init = fetchMock.mock.calls[0][1]
    expect(init.headers['Content-Type']).toBe('application/json')
    expect(init.headers['x-internal-key']).toBe('test-internal-key')
  })

  it('applies a default abort signal', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))
    await agentFetch('/x')
    expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
  })

  it('lets an explicit caller signal win over the default timeout', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))
    const controller = new AbortController()
    await agentFetch('/x', { signal: controller.signal })
    expect(fetchMock.mock.calls[0][1].signal).toBe(controller.signal)
  })

  it('disables the timeout when timeoutMs <= 0', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))
    await agentFetch('/x', {}, { timeoutMs: 0 })
    expect(fetchMock.mock.calls[0][1].signal).toBeUndefined()
  })

  it('wraps a transport failure in AgentUnreachableError with a readable message', async () => {
    fetchMock.mockRejectedValue(undiciFailure('ENOTFOUND'))
    await expect(agentFetch('/llm-provider/test')).rejects.toBeInstanceOf(
      AgentUnreachableError,
    )
    await expect(agentFetch('/llm-provider/test')).rejects.toThrow(
      /agent container is not running/,
    )
  })

  it('keeps the original error on the wrapper for the server log', async () => {
    const original = undiciFailure('ECONNREFUSED')
    fetchMock.mockRejectedValue(original)
    const err = await agentFetch('/x').catch((e) => e)
    expect(err).toBeInstanceOf(AgentUnreachableError)
    expect((err as AgentUnreachableError).cause_).toBe(original)
  })

  it('does NOT convert an HTTP error status into AgentUnreachableError', async () => {
    fetchMock.mockResolvedValue(new Response('{"error":"nope"}', { status: 400 }))
    const resp = await agentFetch('/llm-provider/test')
    expect(resp.status).toBe(400)
  })
})

// ---------------------------------------------------------------------------
// Regression tests, each named after a bug found in review. Every one of these
// fails against the implementation that shipped before the hardening pass.
// ---------------------------------------------------------------------------

describe('regression: NEXT_PUBLIC_AGENT_API_URL fallback silently dropped', () => {
  const saved = { agent: process.env.AGENT_API_URL, pub: process.env.NEXT_PUBLIC_AGENT_API_URL }
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    if (saved.agent === undefined) delete process.env.AGENT_API_URL
    else process.env.AGENT_API_URL = saved.agent
    if (saved.pub === undefined) delete process.env.NEXT_PUBLIC_AGENT_API_URL
    else process.env.NEXT_PUBLIC_AGENT_API_URL = saved.pub
  })

  it('uses NEXT_PUBLIC_AGENT_API_URL when AGENT_API_URL is unset', async () => {
    // 15+ agent-proxying routes honour this fallback, including the health
    // route this helper replaced. Dropping it turns a healthy split deployment
    // into a reported outage.
    delete process.env.AGENT_API_URL
    process.env.NEXT_PUBLIC_AGENT_API_URL = 'http://10.0.0.5:8090'

    expect(agentBaseUrl()).toBe('http://10.0.0.5:8090')
    await agentFetch('/health')
    expect(fetchMock.mock.calls[0][0]).toBe('http://10.0.0.5:8090/health')
  })

  it('prefers AGENT_API_URL over the public one when both are set', async () => {
    process.env.AGENT_API_URL = 'http://agent:8080'
    process.env.NEXT_PUBLIC_AGENT_API_URL = 'http://10.0.0.5:8090'
    expect(agentBaseUrl()).toBe('http://agent:8080')
  })

  it('falls back to the in-network service name when neither is set', async () => {
    delete process.env.AGENT_API_URL
    delete process.env.NEXT_PUBLIC_AGENT_API_URL
    expect(agentBaseUrl()).toBe('http://agent:8080')
  })

  it('names the resolved URL in the error, not a stale one', async () => {
    delete process.env.AGENT_API_URL
    process.env.NEXT_PUBLIC_AGENT_API_URL = 'http://10.0.0.5:8090'
    expect(describeAgentFailure(undiciFailure('ENOTFOUND'))).toContain('http://10.0.0.5:8090')
  })
})

describe('regression: non-plain-object headers silently dropped', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    process.env.INTERNAL_API_KEY = 'k'
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    delete process.env.INTERNAL_API_KEY
  })

  /** Read whatever shape the wrapper handed to fetch back as a plain object. */
  function sentHeaders(): Record<string, string> {
    const h = fetchMock.mock.calls[0][1].headers
    if (h instanceof Headers) return Object.fromEntries(h.entries())
    if (Array.isArray(h)) return Object.fromEntries(h)
    return h as Record<string, string>
  }

  it('keeps headers passed as a Headers instance', async () => {
    // A Headers object has no own enumerable properties, so spreading it yields
    // {} and the body's Content-Type vanishes - the agent then 422s on a body
    // it cannot type, which reads as a schema bug rather than a lost header.
    await agentFetch('/x', { headers: new Headers({ 'Content-Type': 'application/json' }) })
    const sent = sentHeaders()
    expect(sent['content-type'] ?? sent['Content-Type']).toBe('application/json')
    expect(sent['x-internal-key']).toBe('k')
  })

  it('keeps headers passed as an array of pairs', async () => {
    await agentFetch('/x', { headers: [['Content-Type', 'application/json'], ['X-Trace', 'abc']] })
    const sent = sentHeaders()
    expect(sent['content-type'] ?? sent['Content-Type']).toBe('application/json')
    expect(sent['x-trace'] ?? sent['X-Trace']).toBe('abc')
    expect(sent['x-internal-key']).toBe('k')
  })

  it('still accepts a plain object (the shape every current caller uses)', async () => {
    await agentFetch('/x', { headers: { 'Content-Type': 'application/json' } })
    const sent = sentHeaders()
    expect(sent['content-type'] ?? sent['Content-Type']).toBe('application/json')
    expect(sent['x-internal-key']).toBe('k')
  })

  it('never lets a caller override the internal key', async () => {
    await agentFetch('/x', { headers: { 'x-internal-key': 'attacker-supplied' } })
    expect(sentHeaders()['x-internal-key']).toBe('k')
  })
})

describe('regression: caller-cancelled request reported as an agent timeout', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('does not blame the agent when the CALLER aborted', async () => {
    // A streaming route passes request.signal; the user closes the tab. Saying
    // "the agent did not respond in time" sends the reader of that log to
    // investigate a healthy container.
    const controller = new AbortController()
    const abortErr = new Error('This operation was aborted')
    abortErr.name = 'AbortError'
    fetchMock.mockImplementation(async () => { controller.abort(); throw abortErr })

    const err = await agentFetch('/x', { signal: controller.signal }).catch((e) => e)

    expect(err).toBeInstanceOf(AgentUnreachableError)
    expect((err as Error).message).not.toContain('did not respond in time')
    expect((err as Error).message).toMatch(/cancell?ed|aborted/i)
  })

  it('still blames the agent when OUR timeout fired', async () => {
    const timeoutErr = new Error('The operation was aborted due to timeout')
    timeoutErr.name = 'TimeoutError'
    fetchMock.mockRejectedValue(timeoutErr)

    const err = await agentFetch('/x', {}, { timeoutMs: 5 }).catch((e) => e)
    expect((err as Error).message).toContain('did not respond in time')
  })
})
