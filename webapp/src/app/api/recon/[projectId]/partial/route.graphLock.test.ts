/**
 * S-4: a partial recon pressed while a version save or an activation holds the
 * project's graph lock is refused with the same 409 every other start button
 * returns (the body compared as text, key order included, since the job queue
 * and the UI read it), and never reaches the orchestrator.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  orchestratorFetch: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'u1' }) }))
vi.mock('@/lib/scanTimeline', () => ({ recordScanStart: async () => undefined }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findUnique(...a) },
    engagementAuthorization: { count: async () => 0, findFirst: async () => null },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: async () => null }))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: async () => [],
}))

import { POST } from './route'
import { graphLockHolder, tryWithGraphLock, type ExclusiveGraphOp } from '@/lib/projectGraphLock'

function post() {
  return POST(
    new NextRequest('http://x/api/recon/p1/partial', {
      method: 'POST',
      body: JSON.stringify({ tool_id: 'Tlsx', graph_inputs: { domains: ['alpha.test'] } }),
    }),
    { params: Promise.resolve({ projectId: 'p1' }) },
  )
}

/** Press the partial-recon button while `op` holds the project's graph lock. */
async function postWhileHeld(op: ExclusiveGraphOp) {
  let release!: () => void
  const held = tryWithGraphLock('p1', op, () => new Promise<void>(r => { release = r }))
  expect(graphLockHolder('p1')).toBe(op)
  try {
    return await post()
  } finally {
    release()
    await held
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  h.findUnique.mockResolvedValue({ id: 'p1', userId: 'u1', targetDomain: '' })
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ run_id: 'r1', roots: ['alpha.test'] }) })
})

describe('partial recon start under the graph lock', () => {
  test('a version save holding the lock refuses the start as busy', async () => {
    const res = await postWhileHeld('version-save')
    expect(res.status).toBe(409)
    expect(res.headers.get('content-type')).toBe('application/json')
    expect(await res.text()).toBe(JSON.stringify({
      error: 'Cannot start a scan while the current graph is being saved as a version for this project. '
        + 'Try again once it finishes.',
      busy: 'the current graph is being saved as a version',
    }))
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('an activation holding the lock refuses the start as an activation in progress', async () => {
    const res = await postWhileHeld('activation')
    expect(res.status).toBe(409)
    expect(res.headers.get('content-type')).toBe('application/json')
    expect(await res.text()).toBe(JSON.stringify({
      error: 'A version activation is in progress for this project - the graph is being swapped. '
        + 'Try again once it finishes.',
      activationInProgress: true,
    }))
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('with the lock free the start reaches the orchestrator', async () => {
    const res = await post()
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
  })
})
