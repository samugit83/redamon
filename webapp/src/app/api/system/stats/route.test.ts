/**
 * GET /api/system/stats: an orchestrator that failed says how.
 *
 * Both failures used to answer a fixed 503 sentence, so "the orchestrator is
 * down" and "the orchestrator answered 500" read the same in the footer meter.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
// The route reads the session first (HD-10); these tests are about a signed-in account.
vi.mock('@/lib/session', () => ({ requireSession: async () => ({ userId: 'u1', role: 'standard' }) }))

const mockOrchestratorFetch = vi.fn()
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: (...a: unknown[]) => mockOrchestratorFetch(...a),
}))

import { GET } from './route'

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('GET /api/system/stats', () => {
  test('an orchestrator that answered an error: 503 with its status and code', async () => {
    mockOrchestratorFetch.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const res = await GET()
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Failed to fetch system stats', code: 'orchestrator_error', upstreamStatus: 500,
    })
  })

  test('an orchestrator that never answered: 503 with the errno', async () => {
    const err = new TypeError('fetch failed')
    ;(err as TypeError & { cause?: unknown }).cause = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })
    mockOrchestratorFetch.mockRejectedValue(err)
    const res = await GET()
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Failed to connect to backend services', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    })
  })

  test('an orchestrator that hung: 504', async () => {
    mockOrchestratorFetch.mockRejectedValue(new DOMException('The operation was aborted due to timeout', 'TimeoutError'))
    const res = await GET()
    expect(res.status).toBe(504)
    expect((await res.json()).code).toBe('orchestrator_timeout')
  })

  test('stats that came back are passed through', async () => {
    mockOrchestratorFetch.mockResolvedValue(new Response(JSON.stringify({ cpu: { percent: 5, cores: 4 } }), { status: 200 }))
    const res = await GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ cpu: { percent: 5, cores: 4 } })
  })
})
