// @vitest-environment node
import { describe, test, expect, vi, beforeEach } from 'vitest'
import {
  internalError, readUpstreamBody, safeErrorCode, upstreamErrorResponse, upstreamFailure,
  upstreamFailureResponse, withRouteErrors,
} from './routeErrors'

function withCode(name: string, code: string, message = 'secret value in the query'): Error {
  const e = new Error(message) as Error & { code: string }
  e.name = name
  e.code = code
  return e
}

function undiciFailure(code: string): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error(`connect ${code} 10.0.0.1:8080`) as NodeJS.ErrnoException
  cause.code = code
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('safeErrorCode', () => {
  test.each([
    ['a Prisma code', withCode('PrismaClientKnownRequestError', 'P2024'), 'P2024'],
    ['a Neo4j code', withCode('Neo4jError', 'Neo.TransientError.General.DatabaseUnavailable'), 'Neo.TransientError.General.DatabaseUnavailable'],
    ['a Neo4j driver code', withCode('Neo4jError', 'ServiceUnavailable'), 'ServiceUnavailable'],
    ['a Node errno', withCode('Error', 'ENOSPC'), 'ENOSPC'],
    ['an undici errno nested in cause', undiciFailure('ECONNREFUSED'), 'ECONNREFUSED'],
    ['an undici code', withCode('Error', 'UND_ERR_HEADERS_TIMEOUT'), 'UND_ERR_HEADERS_TIMEOUT'],
    ['an OpenSSL certificate code', withCode('Error', 'DEPTH_ZERO_SELF_SIGNED_CERT'), 'DEPTH_ZERO_SELF_SIGNED_CERT'],
    ['an expired certificate', withCode('Error', 'CERT_HAS_EXPIRED'), 'CERT_HAS_EXPIRED'],
    ['a class name without a code', Object.assign(new Error('x'), { name: 'PrismaClientValidationError' }), 'PrismaClientValidationError'],
    ['a plain Error', new Error('boom'), 'internal_error'],
    ['a string', 'boom', 'internal_error'],
    ['null', null, 'internal_error'],
  ])('%s', (_label, err, code) => {
    expect(safeErrorCode(err)).toBe(code)
  })

  test('a code that is free text is not trusted: the class name is used instead', () => {
    expect(safeErrorCode(withCode('Neo4jError', 'drop table users; --'))).toBe('Neo4jError')
  })
})

describe('internalError', () => {
  test('answers the fixed message and the code, never the error text', async () => {
    const res = internalError(withCode('PrismaClientKnownRequestError', 'P2028', 'value 4111-1111 quoted'), 'Failed to save')
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to save', code: 'P2028' })
    expect(JSON.stringify(body)).not.toContain('4111')
  })

  test('logs the full error under the log prefix', () => {
    const err = new Error('boom')
    internalError(err, 'Failed to save', { log: 'PUT /x failed' })
    expect(console.error).toHaveBeenCalledWith('PUT /x failed:', err)
  })

  // A Prisma validation error renders the whole call, its arguments included: an apiKey or an AWS
  // secret being written would reach the container log (fix of the 6.11 review, finding 4).
  test('a Prisma validation error is logged by its class alone, never its rendering of the arguments', async () => {
    const { Prisma } = await import('@prisma/client')
    const err = new Prisma.PrismaClientValidationError(
      'Invalid `prisma.userLlmProvider.create()` invocation:\n\n{\n  data: {\n    apiKey: "sk-LEAK-CANARY-123",\n    timeout: 99999999999\n  }\n}\n\nValue out of range for the type.',
      { clientVersion: 'test' },
    )
    const res = internalError(err, 'Failed to create LLM provider')
    expect(await res.json()).toEqual({ error: 'Failed to create LLM provider', code: 'PrismaClientValidationError' })
    const logged = (console.error as unknown as { mock: { calls: unknown[][] } }).mock.calls.flat().map((x) => (x instanceof Error ? `${x.message} ${x.stack}` : String(x))).join('\n')
    expect(logged).toContain('PrismaClientValidationError')
    expect(logged).not.toContain('sk-LEAK-CANARY-123')
  })

  test('takes a status and extra safe fields', async () => {
    const res = internalError(new Error('x'), 'Saved, but the audit failed', { status: 502, extra: { committed: true } })
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'Saved, but the audit failed', code: 'internal_error', committed: true })
  })
})

describe('withRouteErrors', () => {
  test('passes a normal answer through with its arguments', async () => {
    const handler = vi.fn(async (a: string, b: number) => new Response(`${a}${b}`))
    const res = await withRouteErrors('Failed', handler)('x', 1)
    expect(await res.text()).toBe('x1')
    expect(handler).toHaveBeenCalledWith('x', 1)
  })

  test('turns a throw into a readable 500 instead of an empty body', async () => {
    const res = await withRouteErrors('Failed to load presets', async () => {
      throw withCode('PrismaClientKnownRequestError', 'P1001')
    })()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to load presets', code: 'P1001' })
  })
})

describe('upstreamFailure', () => {
  test('a refused connection is 503 <service>_unreachable with the errno', () => {
    expect(upstreamFailure('orchestrator', undiciFailure('ECONNREFUSED'), 'Failed to start recon')).toEqual({
      status: 503,
      body: { error: 'Failed to start recon', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' },
    })
  })

  test('a timeout is 504 <service>_timeout, since a write may have happened', () => {
    const timeout = Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' })
    expect(upstreamFailure('agent', timeout, 'Failed')).toEqual({
      status: 504, body: { error: 'Failed', code: 'agent_timeout' },
    })
    expect(upstreamFailure('agent', undiciFailure('UND_ERR_HEADERS_TIMEOUT'), 'Failed').status).toBe(504)
    expect(upstreamFailure('agent', undiciFailure('ETIMEDOUT'), 'Failed').body.code).toBe('agent_timeout')
  })

  test('an error without an errno has no cause', () => {
    expect(upstreamFailure('agent', new TypeError('fetch failed'), 'Failed').body).toEqual({ error: 'Failed', code: 'agent_unreachable' })
  })

  test('the response form logs and answers the same body', async () => {
    const res = upstreamFailureResponse('kali', undiciFailure('ENOTFOUND'), 'Terminal unavailable')
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({ error: 'Terminal unavailable', code: 'kali_unreachable', cause: 'ENOTFOUND' })
    expect(console.error).toHaveBeenCalled()
  })
})

describe('readUpstreamBody', () => {
  const res = (body: string, status = 500) => new Response(body, { status })

  test('reads error, then a string detail, then an object detail', async () => {
    expect(await readUpstreamBody(res(JSON.stringify({ error: 'busy', code: 'scan_busy' })))).toMatchObject({ text: 'busy', code: 'scan_busy' })
    expect((await readUpstreamBody(res(JSON.stringify({ detail: 'Recon already running' })))).text).toBe('Recon already running')
    expect(await readUpstreamBody(res(JSON.stringify({ detail: { detail: 'spawn failed', code: 'spawn_failed' } }))))
      .toMatchObject({ text: 'spawn failed', code: 'spawn_failed' })
  })

  test('a FastAPI 422 array, a plain-text 500 and an empty body give no text', async () => {
    expect((await readUpstreamBody(res(JSON.stringify({ detail: [{ msg: 'field required' }] }), 422))).text).toBeUndefined()
    expect(await readUpstreamBody(res('Internal Server Error'))).toEqual({ json: null })
    expect(await readUpstreamBody(res(''))).toEqual({ json: null })
  })

  test('collapses whitespace, caps the text and ignores an unsafe code', async () => {
    const body = await readUpstreamBody(res(JSON.stringify({ error: `a\n\nb ${'x'.repeat(900)}`, code: 'Not A Code' })))
    expect(body.text?.startsWith('a b ')).toBe(true)
    expect(body.text?.length).toBe(500)
    expect(body.code).toBeUndefined()
  })
})

describe('upstreamErrorResponse', () => {
  test('keeps our message by default and reports the upstream status and code', async () => {
    const upstream = new Response(JSON.stringify({ error: 'Traceback: key sk-live-123' }), { status: 500 })
    const out = await upstreamErrorResponse('agent', upstream, 'The agent could not refresh the resource')
    expect(out.status).toBe(502)
    expect(await out.json()).toEqual({ error: 'The agent could not refresh the resource', code: 'agent_error', upstreamStatus: 500 })
  })

  test('forwards the service text only when asked, and keeps a 4xx status', async () => {
    const upstream = new Response(JSON.stringify({ detail: 'Recon already running', code: 'busy' }), { status: 409 })
    const out = await upstreamErrorResponse('orchestrator', upstream, 'Failed to start recon', { forwardText: true })
    expect(out.status).toBe(409)
    expect(await out.json()).toEqual({ error: 'Recon already running', code: 'busy', upstreamStatus: 409 })
  })

  test('a status override wins', async () => {
    const out = await upstreamErrorResponse('runner', new Response('', { status: 401 }), 'Runner refused', { status: 502 })
    expect(out.status).toBe(502)
    expect(await out.json()).toEqual({ error: 'Runner refused', code: 'runner_error', upstreamStatus: 401 })
  })
})
