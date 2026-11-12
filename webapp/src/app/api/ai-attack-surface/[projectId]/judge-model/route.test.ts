/**
 * drift-map #16: the judge model comes from the orchestrator's /local-llm/status
 * (LOCAL_LLM_MODEL), behind the project guard, and only its name leaves the route.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextResponse } from 'next/server'

const guardProject = vi.fn()
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => guardProject(...a) }))

import { GET } from './route'

const fetchMock = vi.fn()
const call = () => GET({} as never, { params: Promise.resolve({ projectId: 'proj1' }) } as never)

const STATUS = {
  available: true, running: true, containerId: 'c0ffee', baseUrl: 'http://127.0.0.1:11434',
  model: 'judge-under-test:7b', modelPresent: true, leases: 0, models: ['judge-under-test:7b'], warning: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  guardProject.mockResolvedValue(null)
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockResolvedValue(new Response(JSON.stringify(STATUS), { status: 200 }))
})
afterEach(() => vi.unstubAllGlobals())

describe('GET judge-model', () => {
  test('returns the orchestrator\'s model, and nothing else from its status', async () => {
    const res = await call()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ model: 'judge-under-test:7b' })
  })

  test('asks the orchestrator\'s status route with the orchestrator key', async () => {
    await call()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toMatch(/\/local-llm\/status$/)
    expect((init.headers as Record<string, string>)['X-Orchestrator-Key']).toBeTruthy()
    expect(init.method ?? 'GET').toBe('GET')
  })

  test('the project guard runs first; a denied caller reaches no orchestrator', async () => {
    guardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await call()
    expect(res.status).toBe(404)
    expect(guardProject).toHaveBeenCalledWith('proj1')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  // The three causes read differently on the page: no answer, a failed answer
  // (with its status), and an answer without a model.
  test('503 with no model, reason orchestrator_error and its status, when the orchestrator answers 503', async () => {
    fetchMock.mockResolvedValue(new Response('{"detail":"Local LLM manager not initialized"}', { status: 503 }))
    const res = await call()
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      model: null, error: 'The local judge model is unavailable',
      code: 'orchestrator_error', reason: 'orchestrator_error', upstreamStatus: 503,
    })
  })

  test('503 with no model, reason no_model, when the status has no model', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ ...STATUS, model: '' }), { status: 200 }))
    const res = await call()
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body.model).toBeNull()
    expect(body.reason).toBe('no_model')
    expect(body).not.toHaveProperty('upstreamStatus')
  })

  test('503 with no model, reason orchestrator_unreachable and the errno, when the orchestrator is down', async () => {
    fetchMock.mockRejectedValue(Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('connect'), { code: 'ECONNREFUSED' }),
    }))
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await call()
    spy.mockRestore()
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body.model).toBeNull()
    expect(body).toMatchObject({ reason: 'orchestrator_unreachable', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
  })

  test('504, reason orchestrator_timeout, when the status call times out', async () => {
    fetchMock.mockRejectedValue(Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }))
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await call()
    spy.mockRestore()
    expect(res.status).toBe(504)
    expect((await res.json()).reason).toBe('orchestrator_timeout')
  })
})
