/**
 * Scan Timeline — POST /api/recon/[projectId]/start.
 *
 * The route itself is thin: authorize, validate `mode`, delegate to the shared
 * start path (covered in lib/startFullScan.test.ts), and shape the response. What
 * matters here is that an unknown mode never reaches the start path, and that the
 * default is the NON-destructive 'new' for a client that omits the field.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ guard: vi.fn(), start: vi.fn() }))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
// The route imports parseScanMode from the real scanTimeline module, which pulls
// in the Prisma client — stub it so no query engine is loaded in unit tests.
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'owner' }) }))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: (...a: unknown[]) => h.start(...a) }))

import { POST } from './route'

const params = { params: Promise.resolve({ projectId: 'p1' }) }
function post(body?: unknown): NextRequest {
  return new NextRequest('http://x/api/recon/p1/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.guard.mockResolvedValue(null)
  h.start.mockResolvedValue({
    ok: true,
    state: { project_id: 'p1', status: 'starting' },
    versionId: 'v3', versionSeq: 3, versionLabel: 'Scan 3',
    frozenVersionId: 'v2', frozenNodeCount: 120, scanJobId: 'job1',
  })
})

describe('mode handling', () => {
  test('unknown mode → 400, the scan is never started', async () => {
    const res = await POST(post({ mode: 'wipe-everything' }), params)
    expect(res.status).toBe(400)
    expect(h.start).not.toHaveBeenCalled()
  })

  test("a missing body defaults to the non-destructive 'new'", async () => {
    await POST(post(), params)
    expect(h.start).toHaveBeenCalledWith(expect.objectContaining({ mode: 'new', trigger: 'manual' }))
  })

  test("an empty body object also defaults to 'new'", async () => {
    await POST(post({}), params)
    expect(h.start).toHaveBeenCalledWith(expect.objectContaining({ mode: 'new' }))
  })

  test("'overwrite' is honored", async () => {
    await POST(post({ mode: 'overwrite' }), params)
    expect(h.start).toHaveBeenCalledWith(expect.objectContaining({ mode: 'overwrite' }))
  })
})

describe('responses', () => {
  test('success returns the orchestrator state plus the version it will fill', async () => {
    const res = await POST(post({ mode: 'new' }), params)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toMatchObject({
      status: 'starting',
      scanVersion: { id: 'v3', seq: 3, label: 'Scan 3' },
      frozenVersionId: 'v2',
      frozenNodeCount: 120,
      mode: 'new',
    })
  })

  test('a freeze failure is surfaced with its flag and status', async () => {
    h.start.mockResolvedValue({ ok: false, status: 500, error: 'Could not snapshot', snapshotFailed: true })
    const res = await POST(post({ mode: 'new' }), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toMatchObject({ snapshotFailed: true })
  })

  test('an admission limit keeps the structured payload the UI modal keys off', async () => {
    h.start.mockResolvedValue({
      ok: false, status: 429, error: 'RAM limit', limit: { limitType: 'ram', detail: 'no memory' },
    })
    const res = await POST(post({ mode: 'new' }), params)
    expect(res.status).toBe(429)
    expect((await res.json()).limit).toMatchObject({ limitType: 'ram' })
  })

  test('an in-flight activation is surfaced as 409', async () => {
    h.start.mockResolvedValue({ ok: false, status: 409, error: 'activation in progress', activationInProgress: true })
    const res = await POST(post({ mode: 'new' }), params)
    expect(res.status).toBe(409)
    expect((await res.json()).activationInProgress).toBe(true)
  })
})

describe('a refused start says why', () => {
  test('the orchestrator code, outcome and job reference reach the browser', async () => {
    h.start.mockResolvedValue({
      ok: false, status: 504, startOutcome: 'unknown', code: 'orchestrator_timeout', scanJobId: 'job9',
      error: 'The orchestrator did not answer, so it is unknown whether the scan started.',
    })
    const res = await POST(post({ mode: 'new' }), params)
    expect(res.status).toBe(504)
    expect(await res.json()).toEqual({
      error: 'The orchestrator did not answer, so it is unknown whether the scan started.',
      code: 'orchestrator_timeout', startOutcome: 'unknown', scanJobId: 'job9',
    })
  })

  test('a scope refusal keeps its invalid entries and an unreachable one its errno', async () => {
    h.start.mockResolvedValueOnce({
      ok: false, status: 422, code: 'scope_invalid', error: 'bad scope',
      invalidEntries: [{ value: 'alpha.test', reason: 'public suffix' }],
    })
    const scope = await (await POST(post({ mode: 'new' }), params)).json()
    expect(scope).toMatchObject({ code: 'scope_invalid', invalidEntries: [{ value: 'alpha.test' }] })

    h.start.mockResolvedValueOnce({
      ok: false, status: 503, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED', error: 'not reached',
    })
    expect(await (await POST(post({ mode: 'new' }), params)).json())
      .toMatchObject({ code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
  })

  test('an answered orchestrator error carries its status', async () => {
    h.start.mockResolvedValue({ ok: false, status: 500, upstreamStatus: 500, error: 'Failed to start recon' })
    expect(await (await POST(post({ mode: 'new' }), params)).json())
      .toMatchObject({ error: 'Failed to start recon', upstreamStatus: 500 })
  })

  test('an unexpected throw answers a fixed sentence and a code, never the exception text', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.start.mockRejectedValue(Object.assign(new Error('relation "scan_jobs" with secret value'), { code: 'P2024' }))
    const res = await POST(post({ mode: 'new' }), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to start recon', code: 'P2024' })
  })
})
