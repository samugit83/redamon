/**
 * "Add to queue" after a refused start: a failure answers a fixed sentence and
 * a code (the queue modal shows it), never the exception's text.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ enqueue: vi.fn() }))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'u1' }) }))
vi.mock('@/lib/enqueueJob', () => ({ enqueueJob: (...a: unknown[]) => h.enqueue(...a) }))

import { POST } from './route'

const post = () => POST(
  new NextRequest('http://x/api/projects/p1/queue', { method: 'POST', body: JSON.stringify({ kind: 'gvm', payload: {} }) }),
  { params: Promise.resolve({ id: 'p1' }) },
)

beforeEach(() => {
  vi.resetAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('POST /api/projects/[id]/queue', () => {
  test('an unexpected throw answers a fixed sentence and the code', async () => {
    h.enqueue.mockRejectedValue(Object.assign(new Error('insert into job_queue values (p1, ...)'), { code: 'P2002' }))
    const res = await post()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not add this scan to the queue', code: 'P2002' })
  })

  test('a refusal keeps its own sentence and status', async () => {
    h.enqueue.mockResolvedValue({ ok: false, status: 409, error: 'A GVM scan is already queued for this project' })
    const res = await post()
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'A GVM scan is already queued for this project' })
  })
})
