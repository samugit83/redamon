/**
 * What the GVM routes answer when the orchestrator, the DB or the disk fails.
 *
 * The person sees these bodies: a status route that invents "idle" makes a
 * running scan look finished, a stop that only says "fetch failed" hides which
 * service is down, and a raw Prisma message can quote target data.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  guard: vi.fn(),
  orchestratorFetch: vi.fn(),
  reconcile: vi.fn(),
  findProject: vi.fn(),
  existsSync: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
// GET available reads the session first (HD-10); these tests are about a signed-in account.
vi.mock('@/lib/session', () => ({ requireSession: async () => ({ userId: 'u1', role: 'standard' }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/scanTimeline', () => ({ reconcileScanJobStatus: (...a: unknown[]) => h.reconcile(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('fs', async orig => ({
  ...(await orig<typeof import('fs')>()),
  existsSync: (...a: unknown[]) => h.existsSync(...a),
}))

const statusRoute = await import('./[projectId]/status/route')
const stopRoute = await import('./[projectId]/stop/route')
const pauseRoute = await import('./[projectId]/pause/route')
const resumeRoute = await import('./[projectId]/resume/route')
const logsRoute = await import('./[projectId]/logs/route')
const downloadRoute = await import('./[projectId]/download/route')
const availableRoute = await import('./available/route')

const params = { params: Promise.resolve({ projectId: 'p1' }) }
const req = () => ({ signal: undefined }) as never

function undiciFailure(code: string): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error(`connect ${code} 10.0.0.7:8010`) as NodeJS.ErrnoException
  cause.code = code
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

function timeout(): Error {
  const err = new Error('The operation was aborted due to timeout')
  err.name = 'TimeoutError'
  return err
}

const prismaDown = () => Object.assign(
  new Error("Can't reach database server at db:5432 while reading target acme.example.com"),
  { name: 'PrismaClientInitializationError', code: 'P1001' },
)

const answered = (status: number, body: unknown) => new Response(
  typeof body === 'string' ? body : JSON.stringify(body),
  { status, headers: { 'Content-Type': typeof body === 'string' ? 'text/plain' : 'application/json' } },
)

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.guard.mockResolvedValue(null)
  h.reconcile.mockResolvedValue(undefined)
})

describe('GET status', () => {
  test('an unreachable orchestrator is a 503 with its errno, not a synthetic idle', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toEqual({ error: 'GVM status unavailable', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    expect(body.status).toBeUndefined()
  })

  test('a hung orchestrator is a 504 orchestrator_timeout', async () => {
    h.orchestratorFetch.mockRejectedValue(timeout())
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(504)
    expect(await res.json()).toMatchObject({ code: 'orchestrator_timeout' })
  })

  test('an orchestrator 5xx is a 502 that keeps the upstream status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({
      error: 'GVM status unavailable', code: 'orchestrator_error', upstreamStatus: 500,
    })
  })

  test("a failed run's own reason is passed through untouched", async () => {
    const state = { status: 'error', error: 'Container exited with code 137 (killed: out of memory)' }
    h.orchestratorFetch.mockResolvedValue(answered(200, state))
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual(state)
    expect(h.reconcile).toHaveBeenCalledWith('p1', 'error', { kind: 'gvm' })
  })

  test('a DB failure answers its code, never the message', async () => {
    h.guard.mockRejectedValue(prismaDown())
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to get GVM status', code: 'P1001' })
    expect(JSON.stringify(body)).not.toContain('acme')
  })
})

describe.each([
  ['stop', stopRoute, 'Failed to stop GVM scan'],
  ['pause', pauseRoute, 'Failed to pause GVM scan'],
  ['resume', resumeRoute, 'Failed to resume GVM scan'],
])('POST %s', (action, route, message) => {
  test("forwards the orchestrator's refusal with its code and status", async () => {
    h.orchestratorFetch.mockResolvedValue(answered(409, { detail: { detail: `No running scan to ${action}`, code: 'not_running' } }))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: `No running scan to ${action}`, code: 'not_running', upstreamStatus: 409 })
  })

  test('a 5xx is a 502 with the fixed message when the body is not JSON', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: message, code: 'orchestrator_error', upstreamStatus: 500 })
  })

  test('an unreachable orchestrator names the service, not "fetch failed"', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toEqual({ error: message, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    expect(JSON.stringify(body)).not.toContain('fetch failed')
  })

  test('success still returns the new state', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { status: 'paused' }))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ status: 'paused' })
  })
})

describe('GET logs', () => {
  test('a throw is a 503 with a body, not an unhandled exception', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await logsRoute.GET(req(), params)
    expect(res.status).toBe(503)
    expect(await res.json()).toMatchObject({ error: 'Failed to connect to GVM log stream', code: 'orchestrator_unreachable' })
  })

  test('an orchestrator 404 keeps its status and detail', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(404, { detail: 'No GVM job found' }))
    const res = await logsRoute.GET(req(), params)
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'No GVM job found', code: 'orchestrator_error', upstreamStatus: 404 })
  })

  test('a live stream is forwarded as SSE', async () => {
    h.orchestratorFetch.mockResolvedValue(new Response('event: log\ndata: {}\n\n', { status: 200 }))
    const res = await logsRoute.GET(req(), params)
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('text/event-stream')
  })
})

describe('GET available', () => {
  test('installed', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { gvm_available: true }))
    expect(await (await availableRoute.GET()).json()).toEqual({ available: true })
  })

  test('not installed says gvm_absent', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { gvm_available: false }))
    expect(await (await availableRoute.GET()).json()).toEqual({ available: false, reason: 'gvm_absent' })
  })

  test('an unreachable orchestrator is not reported as GVM missing', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await availableRoute.GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ available: false, reason: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    expect(console.error).toHaveBeenCalled()
  })

  test('a timed-out /health says orchestrator_timeout', async () => {
    h.orchestratorFetch.mockRejectedValue(timeout())
    expect(await (await availableRoute.GET()).json()).toEqual({ available: false, reason: 'orchestrator_timeout' })
  })

  test('a non-OK /health says orchestrator_error with its status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(503, { detail: 'Service not initialized' }))
    expect(await (await availableRoute.GET()).json())
      .toEqual({ available: false, reason: 'orchestrator_error', upstreamStatus: 503 })
  })
})

describe('download', () => {
  test('a HEAD that fails is a bare 500 whose cause reaches the log', async () => {
    const err = prismaDown()
    h.findProject.mockRejectedValue(err)
    const res = await downloadRoute.HEAD(req(), params)
    expect(res.status).toBe(500)
    expect(console.error).toHaveBeenCalledWith('Error checking GVM scan data:', err)
  })

  test('a GET that fails answers the code, never the message', async () => {
    h.findProject.mockRejectedValue(prismaDown())
    const res = await downloadRoute.GET(req(), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to download GVM scan data', code: 'P1001' })
  })

  test('no artifact is still a 404, not a 500', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', name: 'P' })
    h.existsSync.mockReturnValue(false)
    expect((await downloadRoute.HEAD(req(), params)).status).toBe(404)
  })
})
