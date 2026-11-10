/**
 * What the GitHub Secret Hunt routes answer when the orchestrator or the DB
 * fails: the service and its errno, the orchestrator's own status and code, and
 * never a synthetic "idle" or a raw exception text.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  guard: vi.fn(),
  orchestratorFetch: vi.fn(),
  reconcile: vi.fn(),
  recordScanStart: vi.fn(),
  findProject: vi.fn(),
  existsSync: vi.fn(),
}))

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/scanTimeline', () => ({
  reconcileScanJobStatus: (...a: unknown[]) => h.reconcile(...a),
  recordScanStart: (...a: unknown[]) => h.recordScanStart(...a),
}))
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
vi.mock('fs', async orig => ({
  ...(await orig<typeof import('fs')>()),
  existsSync: (...a: unknown[]) => h.existsSync(...a),
}))

const statusRoute = await import('./[projectId]/status/route')
const stopRoute = await import('./[projectId]/stop/route')
const pauseRoute = await import('./[projectId]/pause/route')
const resumeRoute = await import('./[projectId]/resume/route')
const logsRoute = await import('./[projectId]/logs/route')
const startRoute = await import('./[projectId]/start/route')
const downloadRoute = await import('./[projectId]/download/route')

const params = { params: Promise.resolve({ projectId: 'p1' }) }
const req = () => ({ signal: undefined }) as never

function undiciFailure(code: string): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error(`connect ${code} 10.0.0.7:8010`) as NodeJS.ErrnoException
  cause.code = code
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

const prismaDown = () => Object.assign(
  new Error("Can't reach database server while reading target acme.example.com"),
  { name: 'PrismaClientInitializationError', code: 'P1001' },
)

const answered = (status: number, body: unknown) => new Response(
  typeof body === 'string' ? body : JSON.stringify(body), { status },
)

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.guard.mockResolvedValue(null)
  h.reconcile.mockResolvedValue(undefined)
  h.recordScanStart.mockResolvedValue(undefined)
  h.existsSync.mockReturnValue(true)
  h.findProject.mockResolvedValue({
    id: 'p1', userId: 'u1', name: 'P', targetDomain: 'example.com', ipMode: false, targetIps: [],
    domainBatchMode: false, domainBatchHosts: [],
  })
})

describe('GET status', () => {
  test('an unreachable orchestrator is a 503, not a synthetic idle', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'GitHub Hunt status unavailable', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    })
  })

  test('a hung orchestrator is a 504', async () => {
    h.orchestratorFetch.mockRejectedValue(Object.assign(new Error('aborted'), { name: 'TimeoutError' }))
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(504)
    expect((await res.json()).code).toBe('orchestrator_timeout')
  })

  test('a live state is reconciled and returned', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { status: 'running', error: null }))
    const res = await statusRoute.GET(req(), params)
    expect(await res.json()).toEqual({ status: 'running', error: null })
    expect(h.reconcile).toHaveBeenCalledWith('p1', 'running', { kind: 'github_hunt' })
  })
})

describe.each([
  ['stop', stopRoute, 'Failed to stop GitHub hunt'],
  ['pause', pauseRoute, 'Failed to pause GitHub hunt'],
  ['resume', resumeRoute, 'Failed to resume GitHub hunt'],
])('POST %s', (_action, route, message) => {
  test("forwards the orchestrator's detail with its status", async () => {
    h.orchestratorFetch.mockResolvedValue(answered(400, { detail: 'No GitHub hunt is running' }))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'No GitHub hunt is running', code: 'orchestrator_error', upstreamStatus: 400 })
  })

  test('a 5xx is a 502 with the upstream status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: message, code: 'orchestrator_error', upstreamStatus: 500 })
  })

  test('an unreachable orchestrator is a 503 with the errno', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ENOTFOUND'))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({ error: message, code: 'orchestrator_unreachable', cause: 'ENOTFOUND' })
  })
})

describe('GET logs', () => {
  test('a throw is a 503 with a body', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await logsRoute.GET(req(), params)
    expect(res.status).toBe(503)
    expect((await res.json()).error).toBe('Failed to connect to GitHub hunt log stream')
  })
})

describe('POST start', () => {
  test('a non-JSON 500 keeps the status and a code', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await startRoute.POST(req(), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'Failed to start GitHub Secret Hunt', code: 'orchestrator_error', upstreamStatus: 500,
    })
  })

  test('spawn_failed is passed through', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, { detail: { detail: 'Could not create the container', code: 'spawn_failed' } }))
    expect(await (await startRoute.POST(req(), params)).json())
      .toMatchObject({ error: 'Could not create the container', code: 'spawn_failed', upstreamStatus: 500 })
  })

  test('the existing precondition refusal is unchanged', async () => {
    h.existsSync.mockReturnValue(false)
    const res = await startRoute.POST(req(), params)
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({
      error: 'Recon data not found. Run a reconnaissance scan first before starting GitHub Secret Hunt.',
    })
  })

  test('a DB failure answers its code, never the message', async () => {
    h.findProject.mockRejectedValue(prismaDown())
    const res = await startRoute.POST(req(), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to start GitHub Secret Hunt', code: 'P1001' })
    expect(JSON.stringify(body)).not.toContain('acme')
  })

  test('an unreachable orchestrator is a 503 and records no run', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await startRoute.POST(req(), params)
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('orchestrator_unreachable')
    expect(h.recordScanStart).not.toHaveBeenCalled()
  })
})

describe('download', () => {
  test('a HEAD that fails logs its cause', async () => {
    const err = prismaDown()
    h.findProject.mockRejectedValue(err)
    expect((await downloadRoute.HEAD(req(), params)).status).toBe(500)
    expect(console.error).toHaveBeenCalledWith('Error checking GitHub hunt data:', err)
  })

  test('a GET that fails answers the code', async () => {
    h.findProject.mockRejectedValue(prismaDown())
    expect(await (await downloadRoute.GET(req(), params)).json())
      .toEqual({ error: 'Failed to download GitHub hunt data', code: 'P1001' })
  })
})
