/**
 * The recon routes that proxy the orchestrator say what failed and why.
 *
 * Before: a refused connection read as an idle recon (Start enabled over a scan
 * that may be running) or an empty partial list; a timeout leaked undici's bare
 * message; the log streams answered Next's empty 500; a stop/pause/resume
 * failure carried no status. Now an orchestrator that never answered is 503
 * `orchestrator_unreachable` or 504 `orchestrator_timeout`, one that answered
 * with an error keeps its own sentence plus `upstreamStatus`, and nothing
 * echoes an exception's text.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  orchestratorFetch: vi.fn(),
  reconcileStatus: vi.fn(),
  reconcileRuns: vi.fn(),
  findUnique: vi.fn(),
  run: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/scanTimeline', () => ({
  reconcileScanJobStatus: (...a: unknown[]) => h.reconcileStatus(...a),
  reconcileRunScanJobs: (...a: unknown[]) => h.reconcileRuns(...a),
}))
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => h.findUnique(...a) } } }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => h.run(...a), close: async () => {} }),
}))

import { GET as status } from './status/route'
import { POST as stop } from './stop/route'
import { POST as pause } from './pause/route'
import { POST as resume } from './resume/route'
import { GET as logs } from './logs/route'
import { GET as partialAll } from './partial/all/route'
import { GET as partialStatus } from './partial/[runId]/status/route'
import { POST as partialStop } from './partial/[runId]/stop/route'
import { GET as partialLogs } from './partial/[runId]/logs/route'
import { GET as download } from './download/route'
import { GET as graphInputs } from './graph-inputs/[toolId]/route'

const req = () => new NextRequest('http://x/api/recon/p1/status')
const project = { params: Promise.resolve({ projectId: 'p1' }) }
const run = { params: Promise.resolve({ projectId: 'p1', runId: 'r1' }) }

const refused = () => Object.assign(new TypeError('fetch failed'), {
  cause: Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:8010'), { code: 'ECONNREFUSED' }),
})
const timedOut = () => Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' })
const answered = (status: number, body: string) => new Response(body, { status })

beforeEach(() => {
  vi.resetAllMocks()
  h.reconcileStatus.mockResolvedValue(undefined)
  h.reconcileRuns.mockResolvedValue(undefined)
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('status reads never invent an idle recon or an empty run list', () => {
  test('a refused connection is 503 orchestrator_unreachable, not a 200 idle', async () => {
    h.orchestratorFetch.mockRejectedValue(refused())
    const res = await status(req(), project)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Recon status unavailable', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    })
  })

  test('a timeout is 504 orchestrator_timeout, without the abort message', async () => {
    h.orchestratorFetch.mockRejectedValue(timedOut())
    const res = await status(req(), project)
    expect(res.status).toBe(504)
    expect(await res.json()).toEqual({ error: 'Recon status unavailable', code: 'orchestrator_timeout' })
  })

  test('the partial run list is unavailable rather than empty', async () => {
    h.orchestratorFetch.mockRejectedValue(refused())
    const res = await partialAll(req(), project)
    expect(res.status).toBe(503)
    expect(await res.json()).toMatchObject({ error: 'Partial recon list unavailable', code: 'orchestrator_unreachable' })
  })

  test('one partial run status is unavailable rather than idle', async () => {
    h.orchestratorFetch.mockRejectedValue(timedOut())
    const res = await partialStatus(req(), run)
    expect(res.status).toBe(504)
    expect(await res.json()).toMatchObject({ error: 'Partial recon status unavailable', code: 'orchestrator_timeout' })
  })

  test('an orchestrator 500 with an HTML body is a 502 with its upstream status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await status(req(), project)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({
      error: 'Failed to get recon status', code: 'orchestrator_error', upstreamStatus: 500,
    })
  })

  test('a bookkeeping failure after a good read answers a code, never the Prisma text', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, JSON.stringify({ status: 'running' })))
    h.reconcileStatus.mockRejectedValue(
      Object.assign(new Error('update "scan_jobs" set ... where project_id = p1'), { code: 'P2034' }))
    const res = await status(req(), project)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to get recon status', code: 'P2034' })
  })

  test('a healthy read passes the state through', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, JSON.stringify({ project_id: 'p1', status: 'running' })))
    const res = await status(req(), project)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ project_id: 'p1', status: 'running' })
  })
})

describe('stop, pause and resume carry the cause', () => {
  test.each([
    ['stop', stop, 'Failed to stop recon'],
    ['pause', pause, 'Failed to pause recon'],
    ['resume', resume, 'Failed to resume recon'],
  ])('%s with no orchestrator is 503 orchestrator_unreachable, not "fetch failed"', async (_n, handler, message) => {
    h.orchestratorFetch.mockRejectedValue(refused())
    const res = await handler(req(), project)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({ error: message, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
  })

  test('the orchestrator refusal keeps its own sentence and status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(403, JSON.stringify({
      detail: 'RoE time window: current time 21:00 UTC is outside allowed window (09:00-18:00)',
    })))
    const res = await resume(req(), project)
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({
      error: 'RoE time window: current time 21:00 UTC is outside allowed window (09:00-18:00)',
      code: 'orchestrator_error', upstreamStatus: 403,
    })
  })

  test('a partial stop the orchestrator did not get says so', async () => {
    h.orchestratorFetch.mockRejectedValue(timedOut())
    const res = await partialStop(req(), run)
    expect(res.status).toBe(504)
    expect(await res.json()).toEqual({ error: 'Failed to stop partial recon', code: 'orchestrator_timeout' })
  })
})

describe('the log streams answer a readable error', () => {
  test('a refused connection is a JSON 503, not an empty 500', async () => {
    h.orchestratorFetch.mockRejectedValue(refused())
    const res = await logs(req(), project)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Failed to connect to recon log stream', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    })
  })

  test('an orchestrator refusal keeps its sentence and status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(404, JSON.stringify({ detail: 'No logs for run r1' })))
    const res = await partialLogs(req(), run)
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'No logs for run r1', code: 'orchestrator_error', upstreamStatus: 404 })
  })

  test('an open stream is forwarded as SSE', async () => {
    h.orchestratorFetch.mockResolvedValue(new Response('event: log\ndata: {}\n\n', { status: 200 }))
    const res = await logs(req(), project)
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('text/event-stream')
  })
})

describe('reads that are not the orchestrator', () => {
  test('a recon download that fails answers a fixed sentence and the code', async () => {
    h.findUnique.mockRejectedValue(Object.assign(new Error('connect to db at 10.0.0.9 failed'), { code: 'P1001' }))
    const res = await download(req(), project)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to read the recon data', code: 'P1001' })
  })

  test('graph inputs the graph could not give are flagged, not passed off as zero counts', async () => {
    h.findUnique.mockResolvedValue({ userId: 'u1', targetDomain: 'alpha.test' })
    h.run.mockRejectedValue(Object.assign(new Error('Database unavailable'), {
      code: 'Neo.TransientError.General.DatabaseUnavailable',
    }))
    const res = await graphInputs(req(), { params: Promise.resolve({ projectId: 'p1', toolId: 'Tlsx' }) })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toMatchObject({
      source: 'settings', degraded: 'graph_unavailable',
      code: 'Neo.TransientError.General.DatabaseUnavailable', existing_ports_count: 0,
    })
  })

  test('a tool with no graph query falls back without a degraded flag', async () => {
    h.findUnique.mockResolvedValue({ userId: 'u1', targetDomain: 'alpha.test' })
    const res = await graphInputs(req(), { params: Promise.resolve({ projectId: 'p1', toolId: 'NoSuchTool' }) })
    const body = await res.json()
    expect(body.source).toBe('settings')
    expect(body.degraded).toBeUndefined()
  })
})
