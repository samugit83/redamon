/**
 * L-13: stopping a partial recon closes its ScanJob.
 *
 * The orchestrator drops a stopped run from its listing once the drain ends, so
 * the list reconcile (which closes a row only on a listed terminal status) never
 * sees it end, and the row stayed `running` forever. The stop answer is the last
 * word on that run: `stopping` (or `idle`, a run the orchestrator no longer
 * has) is canceled; a run that had already ended keeps its real outcome.
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

const req = () => new NextRequest('http://x/api/recon/p1/partial/r1/stop', { method: 'POST' })
const run = { params: Promise.resolve({ projectId: 'p1', runId: 'r1' }) }
const answered = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  vi.resetAllMocks()
  h.updateMany.mockResolvedValue({ count: 1 })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('a partial stop closes the run\'s ScanJob', () => {
  test('a run that is stopping is recorded canceled, and only that run of that project', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { project_id: 'p1', run_id: 'r1', status: 'stopping' }))
    const res = await stop(req(), run)
    expect(res.status).toBe(200)
    expect((await res.json()).status).toBe('stopping')
    expect(h.updateMany).toHaveBeenCalledTimes(1)
    const call = h.updateMany.mock.calls[0][0]
    expect(call.where).toEqual({ projectId: 'p1', kind: 'partial_recon', runId: 'r1', status: 'running' })
    expect(call.data.status).toBe('canceled')
    expect(call.data.finishedAt).toBeInstanceOf(Date)
  })

  test.each([
    ['idle', 'canceled'],
    ['completed', 'completed'],
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
    h.orchestratorFetch.mockResolvedValue(answered(404, { detail: 'No partial recon process found' }))
    const res = await stop(req(), run)
    expect(res.status).toBe(404)
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('a stop that got no answer writes nothing', async () => {
    h.orchestratorFetch.mockRejectedValue(Object.assign(new Error('aborted'), { name: 'TimeoutError' }))
    const res = await stop(req(), run)
    expect(res.status).toBe(504)
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('a history write that fails does not fail the stop', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { run_id: 'r1', status: 'stopping' }))
    h.updateMany.mockRejectedValue(new Error('db down'))
    const res = await stop(req(), run)
    expect(res.status).toBe(200)
    expect((await res.json()).status).toBe('stopping')
  })
})
