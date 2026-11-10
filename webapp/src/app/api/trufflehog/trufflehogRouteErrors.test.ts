/**
 * What the Secret Multiscanner (TruffleHog) run routes answer when the
 * orchestrator or the DB fails. `all` is read by the queue reconcile and the
 * version guards as well as the UI, so an empty run list on failure would let
 * them treat a source that is still writing findings as finished.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  guard: vi.fn(),
  orchestratorFetch: vi.fn(),
  reconcile: vi.fn(),
  reconcileRuns: vi.fn(),
  recordScanStart: vi.fn(),
  resolve: vi.fn(),
  findProject: vi.fn(),
  readdir: vi.fn(),
}))

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/scanTimeline', () => ({
  reconcileScanJobStatus: (...a: unknown[]) => h.reconcile(...a),
  reconcileRunScanJobs: (...a: unknown[]) => h.reconcileRuns(...a),
  recordScanStart: (...a: unknown[]) => h.recordScanStart(...a),
}))
vi.mock('@/lib/trufflehogStart', () => ({ resolveTrufflehogStart: (...a: unknown[]) => h.resolve(...a) }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1' }) }))
// A startable engagement: the R-11 gate has its own tests in start/route.test.ts.
vi.mock('@/lib/engagement', () => ({
  currentRoeTextSha256: vi.fn().mockResolvedValue(null),
  loadEngagement: vi.fn().mockResolvedValue({ blockers: [] }),
}))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: vi.fn().mockResolvedValue(null) }))
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('fs/promises', () => ({
  readdir: (...a: unknown[]) => h.readdir(...a),
  readFile: vi.fn(),
}))

const allRoute = await import('./[projectId]/all/route')
const statusRoute = await import('./[projectId]/[source]/status/route')
const stopRoute = await import('./[projectId]/[source]/stop/route')
const logsRoute = await import('./[projectId]/[source]/logs/route')
const startRoute = await import('./[projectId]/start/route')
const downloadRoute = await import('./[projectId]/download/route')

const params = { params: Promise.resolve({ projectId: 'p1' }) }
const sourceParams = { params: Promise.resolve({ projectId: 'p1', source: 'docker' }) }
const req = (body: unknown = {}) => ({ signal: undefined, json: async () => body }) as never

function undiciFailure(code: string): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error(`connect ${code} 10.0.0.7:8010`) as NodeJS.ErrnoException
  cause.code = code
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

const timeout = () => Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' })

const answered = (status: number, body: unknown) => new Response(
  typeof body === 'string' ? body : JSON.stringify(body), { status },
)

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.guard.mockResolvedValue(null)
  h.reconcile.mockResolvedValue(undefined)
  h.reconcileRuns.mockResolvedValue(undefined)
  h.recordScanStart.mockResolvedValue(undefined)
  h.resolve.mockResolvedValue({ ok: true, source: 'docker', body: { project_id: 'p1', source: 'docker' } })
})

describe('GET all', () => {
  test('an unreachable orchestrator is a 503, never an empty run list', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await allRoute.GET(req(), params)
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toEqual({
      error: 'Secret Multiscanner status unavailable', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    })
    expect(body.runs).toBeUndefined()
    expect(h.reconcileRuns).not.toHaveBeenCalled()
  })

  test('a hung orchestrator is a 504', async () => {
    h.orchestratorFetch.mockRejectedValue(timeout())
    const res = await allRoute.GET(req(), params)
    expect(res.status).toBe(504)
    expect((await res.json()).code).toBe('orchestrator_timeout')
  })

  test('a 5xx is a 502 with the upstream status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await allRoute.GET(req(), params)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({
      error: 'Secret Multiscanner status unavailable', code: 'orchestrator_error', upstreamStatus: 500,
    })
  })

  test("each failed run's own reason is passed through", async () => {
    const runs = [{ source: 'docker', status: 'error', error: 'Container exited with code 1' }]
    h.orchestratorFetch.mockResolvedValue(answered(200, { runs }))
    expect(await (await allRoute.GET(req(), params)).json()).toEqual({ runs })
    expect(h.reconcileRuns).toHaveBeenCalledWith('p1', 'trufflehog', runs)
  })
})

describe('GET [source]/status', () => {
  test('an unreachable orchestrator is a 503', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNRESET'))
    const res = await statusRoute.GET(req(), sourceParams)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Secret Multiscanner status unavailable', code: 'orchestrator_unreachable', cause: 'ECONNRESET',
    })
  })
})

describe('POST [source]/stop', () => {
  test("forwards the orchestrator's detail with its status", async () => {
    h.orchestratorFetch.mockResolvedValue(answered(404, { detail: 'No run for source docker' }))
    const res = await stopRoute.POST(req(), sourceParams)
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'No run for source docker', code: 'orchestrator_error', upstreamStatus: 404 })
  })

  test('a timeout says the outcome is unknown (504), not a raw abort text', async () => {
    h.orchestratorFetch.mockRejectedValue(timeout())
    const res = await stopRoute.POST(req(), sourceParams)
    expect(res.status).toBe(504)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to stop Secret Multiscanner scan', code: 'orchestrator_timeout' })
    expect(JSON.stringify(body)).not.toContain('aborted')
  })
})

describe('GET [source]/logs', () => {
  test('a throw is a 503 with a body', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await logsRoute.GET(req(), sourceParams)
    expect(res.status).toBe(503)
    expect((await res.json()).error).toBe('Failed to connect to Secret Multiscanner log stream')
  })

  test('an orchestrator 5xx is a 502', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await logsRoute.GET(req(), sourceParams)
    expect(res.status).toBe(502)
    expect((await res.json()).upstreamStatus).toBe(500)
  })
})

describe('POST start', () => {
  test('a non-JSON 500 keeps the status and a code', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await startRoute.POST(req({ source: 'docker' }), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'Failed to start Secret Multiscanner scan', code: 'orchestrator_error', upstreamStatus: 500,
    })
    expect(h.recordScanStart).not.toHaveBeenCalled()
  })

  test('not_configured from the orchestrator is passed through', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(400, { detail: { detail: 'Source is not configured', code: 'not_configured' } }))
    const body = await (await startRoute.POST(req({ source: 'docker' }), params)).json()
    expect(body).toMatchObject({ error: 'Source is not configured', code: 'not_configured', upstreamStatus: 400 })
  })

  test("the resolver's own refusal is unchanged", async () => {
    h.resolve.mockResolvedValue({ ok: false, status: 400, error: 'Unknown source' })
    const res = await startRoute.POST(req({ source: 'nope' }), params)
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'Unknown source' })
  })

  test('a DB failure answers its code, never the message', async () => {
    h.resolve.mockRejectedValue(Object.assign(
      new Error('Invalid `prisma.trufflehogScanProfile.findFirst()` invocation: bucket s3://acme-secrets'),
      { name: 'PrismaClientKnownRequestError', code: 'P2024' },
    ))
    const res = await startRoute.POST(req({ source: 'docker' }), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to start Secret Multiscanner scan', code: 'P2024' })
    expect(JSON.stringify(body)).not.toContain('acme')
  })

  test('an unreachable orchestrator is a 503', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await startRoute.POST(req({ source: 'docker' }), params)
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('orchestrator_unreachable')
  })
})

describe('download', () => {
  test('a HEAD that fails logs its cause', async () => {
    const err = new Error('denied')
    h.guard.mockRejectedValue(err)
    expect((await downloadRoute.HEAD(req(), params)).status).toBe(500)
    expect(console.error).toHaveBeenCalledWith('Error checking TruffleHog data:', err)
  })

  test('a GET that fails answers the code', async () => {
    h.findProject.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    expect(await (await downloadRoute.GET(req(), params)).json())
      .toEqual({ error: 'Failed to download Secret Multiscanner data', code: 'P1001' })
  })
})
