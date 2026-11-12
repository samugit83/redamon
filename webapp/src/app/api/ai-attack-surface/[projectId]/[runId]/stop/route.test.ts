/**
 * Stopping an AI Gauntlet run closes its ScanJob (the L-13 rule for partial
 * recon, applied to the other run-keyed kind).
 *
 * The orchestrator kills the run's container and drops the run from its
 * listing in the same call, so the list reconcile (which closes a row only on a
 * listed `completed` / `error`) never sees a stopped run end, and its row stayed
 * `running` for ever. The stop answer is the last word on that run.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  orchestratorFetch: vi.fn(),
  updateMany: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: { scanJob: { updateMany: (...a: unknown[]) => h.updateMany(...a) } },
}))

import { POST as stop } from './route'

const req = () => new NextRequest('http://x/api/ai-attack-surface/p1/r1/stop', { method: 'POST' })
const run = { params: Promise.resolve({ projectId: 'p1', runId: 'r1' }) }
const answered = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  vi.resetAllMocks()
  h.updateMany.mockResolvedValue({ count: 1 })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('an AI Gauntlet stop closes the run\'s ScanJob', () => {
  // The orchestrator answers `idle` once the container is gone.
  test('a stopped run is recorded canceled, and only that run of that project', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { project_id: 'p1', run_id: 'r1', status: 'idle' }))
    const res = await stop(req(), run)
    expect(res.status).toBe(200)
    expect((await res.json()).status).toBe('idle')
    expect(String(h.orchestratorFetch.mock.calls[0][0])).toMatch(/\/ai-attack-surface\/p1\/r1\/stop$/)
    expect(h.updateMany).toHaveBeenCalledTimes(1)
    const call = h.updateMany.mock.calls[0][0]
    expect(call.where).toEqual({ projectId: 'p1', kind: 'ai_attack', runId: 'r1', status: 'running' })
    expect(call.data.status).toBe('canceled')
    expect(call.data.finishedAt).toBeInstanceOf(Date)
  })

  test.each([
    ['stopping', 'canceled'],
    ['completed', 'completed'],
    // The container could not be removed: the orchestrator has dropped the run
    // all the same, so this answer is still the last one.
    ['error', 'failed'],
  ])('a run the orchestrator reports %s is recorded %s', async (status, expected) => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { run_id: 'r1', status }))
    await stop(req(), run)
    expect(h.updateMany.mock.calls[0][0].data.status).toBe(expected)
  })

  test('a status that is not an end leaves the row to the reconcile', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { run_id: 'r1', status: 'running' }))
    await stop(req(), run)
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('a stop the orchestrator refused writes nothing', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(503, { detail: 'Service not initialized' }))
    const res = await stop(req(), run)
    expect(res.status).toBe(502)
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('a stop that got no answer writes nothing', async () => {
    h.orchestratorFetch.mockRejectedValue(Object.assign(new Error('aborted'), { name: 'TimeoutError' }))
    const res = await stop(req(), run)
    expect(res.status).toBe(504)
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('a history write that fails does not fail the stop', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { run_id: 'r1', status: 'idle' }))
    h.updateMany.mockRejectedValue(new Error('db down'))
    const res = await stop(req(), run)
    expect(res.status).toBe(200)
    expect((await res.json()).status).toBe('idle')
  })
})
