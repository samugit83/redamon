/**
 * The action route against a cross-site page (R-29, D-52 CSRF half): the session cookie is
 * SameSite=lax, so a form on another site can still POST here. A foreign `Origin` and a
 * body that is not JSON (all a plain form can send) are refused before anything runs.
 *
 * @vitest-environment node
 */
import { test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown> }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => ({ userId: 'user-alice' }),
  getSession: async () => ({ userId: 'user-alice', role: 'standard' }),
}))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { CALL_SECRET, answer, seedWorld } from './__testing__/gatewayHarness'
import { APP, actionParams, actionRequest, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'

let db: FakePrisma
let runner: FakeRunner

beforeEach(async () => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  runner = await startEchoRunner({ 'echo/echo': () => ({ result: { ok: 1 } }) })
})
afterEach(async () => {
  await runner.close()
  delete process.env.PLUGIN_RUNNER_URL
  delete process.env.PLUGIN_RUNNER_KEY
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const post = async (opts: Parameters<typeof actionRequest>[3]) =>
  answer(await runAction(actionRequest('echo', 'echo', { params: {} }, opts), actionParams('echo', 'echo')))

test.each(['http://evil.example', 'http://localhost:3001', 'null'])('Origin %s: 403 cross_origin, the runner never called', async (origin) => {
  const res = await post({ origin })
  expect(res).toMatchObject({ status: 403, body: { code: 'cross_origin' } })
  // The refusal names the comparison that failed, with the page's origin.
  expect(res.body.error).toMatch(/^Cross-origin request refused: /)
  expect(res.body.error).toContain(origin === 'null' ? 'the Origin header "null" is not an origin' : `the page's host ${new URL(origin).host} is not the host`)
  expect(runner.actionCalls).toEqual([])
})

test.each(['application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', 'text/plain', null])(
  'a body sent as %s (what a form can send): 415',
  async (contentType) => {
    expect((await post({ origin: APP, contentType, rawBody: 'params=1' })).status).toBe(415)
    expect(runner.actionCalls).toEqual([])
  },
)

test('the same origin, and no Origin at all: the action runs', async () => {
  expect((await post({ origin: APP })).status).toBe(200)
  expect((await post({})).status).toBe(200)
})

test('behind nginx: the configured public origin passes although Host lost its port', async () => {
  vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', 'https://redamon.example.com:8443')
  expect((await post({ origin: 'https://redamon.example.com:8443' })).status).toBe(200)
  expect((await post({ origin: APP })).status).toBe(403)
})
