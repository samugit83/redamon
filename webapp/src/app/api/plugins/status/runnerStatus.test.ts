/**
 * GET /api/plugins/status: the platform version this webapp runs and what the runner
 * reports, for the Plugins page's runner banner (D-21 runner-down half, D-74). A
 * signed-in session; never a 5xx when the runner is down.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockUser = vi.hoisted(() => ({ fn: vi.fn() }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => mockUser.fn() }))

import { GET } from './route'
import { startFakeRunner } from '@/lib/plugins/__testing__/fakeRunner'
import { closeAllFakeServers, startFakeServer } from '@/lib/plugins/__testing__/fakeHttpServer'
import { PLUGIN_PLATFORM_VERSION } from '@/lib/plugins/platformVersion'

const KEY = 'k'.repeat(64)

beforeEach(() => {
  vi.stubEnv('PLUGIN_RUNNER_KEY', KEY)
  mockUser.fn.mockResolvedValue({ userId: 'u1', role: 'standard' })
})
afterEach(async () => {
  vi.unstubAllEnvs()
  await closeAllFakeServers()
})

test('no session: the 401 of requireEffectiveUser', async () => {
  mockUser.fn.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
  expect((await GET(new NextRequest('http://localhost/api/plugins/status'))).status).toBe(401)
})

describe('runner states', () => {
  test('reachable and current', async () => {
    const r = await startFakeRunner({ runnerKey: KEY, bootId: 'boot-7' })
    vi.stubEnv('PLUGIN_RUNNER_URL', r.baseUrl)
    const res = await GET(new NextRequest('http://localhost/api/plugins/status'))
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.json()).toEqual({
      platformVersion: PLUGIN_PLATFORM_VERSION,
      runner: { reachable: true, platformVersion: '1.0.0', state: 'ok', workers: 0 },
    })
  })

  test('reachable but out of date', async () => {
    const r = await startFakeRunner({ runnerKey: KEY, platformVersion: '0.9.0', state: 'out_of_date' })
    vi.stubEnv('PLUGIN_RUNNER_URL', r.baseUrl)
    const body = await (await GET(new NextRequest('http://localhost/api/plugins/status'))).json()
    expect(body.runner).toEqual({ reachable: true, platformVersion: '0.9.0', state: 'out_of_date', workers: 0 })
  })

  test('down: 200 with reachable false, not a 5xx', async () => {
    const s = await startFakeServer({})
    const base = s.baseUrl
    await s.close()
    vi.stubEnv('PLUGIN_RUNNER_URL', base)
    const res = await GET(new NextRequest('http://localhost/api/plugins/status'))
    expect(res.status).toBe(200)
    // The reason tells a stopped runner from a slow one or a garbled answer.
    expect((await res.json()).runner).toEqual({ reachable: false, error: 'runner_unavailable', reason: 'unreachable' })
  })

  test('the proxy answering for a runner it could not reach: its code rides along', async () => {
    const s = await startFakeServer({ 'GET /runner/v1/health': { status: 504, body: { error: 'upstream timed out', code: 'upstream_timeout' } } })
    vi.stubEnv('PLUGIN_RUNNER_URL', s.baseUrl)
    const res = await GET(new NextRequest('http://localhost/api/plugins/status'))
    expect(res.status).toBe(200)
    expect((await res.json()).runner).toEqual({ reachable: false, error: 'runner_unavailable', reason: 'timeout', proxyCode: 'upstream_timeout' })
  })

  test.each([[{}], [{ platformVersion: '1.0.0', state: 'ok', workers: 'none' }], [[1, 2]]])(
    'a health answer of the wrong shape (%j): reachable false, not a 5xx', async (body) => {
      const s = await startFakeServer({ 'GET /runner/v1/health': { body } })
      vi.stubEnv('PLUGIN_RUNNER_URL', s.baseUrl)
      const res = await GET(new NextRequest('http://localhost/api/plugins/status'))
      expect(res.status).toBe(200)
      expect((await res.json()).runner).toEqual({ reachable: false, error: 'runner_unavailable', reason: 'bad_response' })
    })

  test('a runner with another key: reachable false, unauthorized', async () => {
    const r = await startFakeRunner({ runnerKey: 'o'.repeat(64) })
    vi.stubEnv('PLUGIN_RUNNER_URL', r.baseUrl)
    expect((await (await GET(new NextRequest('http://localhost/api/plugins/status'))).json()).runner).toEqual({ reachable: false, error: 'unauthorized', upstreamStatus: 401 })
  })

  test('no key configured: reachable false without a request', async () => {
    const r = await startFakeRunner({ runnerKey: KEY })
    vi.stubEnv('PLUGIN_RUNNER_URL', r.baseUrl)
    vi.stubEnv('PLUGIN_RUNNER_KEY', '')
    expect((await (await GET(new NextRequest('http://localhost/api/plugins/status'))).json()).runner).toEqual({ reachable: false, error: 'runner_not_configured', reason: 'not_configured' })
    expect(r.server.calls).toHaveLength(0)
  })
})
