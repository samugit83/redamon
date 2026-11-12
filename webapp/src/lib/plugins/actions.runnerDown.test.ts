/**
 * The runner down or not ready (D-21, P4): the action route answers 503 with a code the UI
 * can show, never a 500, and an async job that could not be handed over is failed at once
 * with its lock released, so the next click can try again.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown> }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => ({ userId: 'user-alice' }),
  getSession: async () => ({ userId: 'user-alice', role: 'standard' }),
}))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ALICE_PROJECT, ALICE_SESSION, CALL_SECRET, answer, seedWorld } from './__testing__/gatewayHarness'
import { RUNNER_KEY, actionParams, actionRequest, jobGetRequest, jobParams, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { JOB_LOCKS_COLLECTION } from './jobs'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'
import { GET as getJob } from '@/app/api/plugins/jobs/[jobId]/route'

let db: FakePrisma
let runner: FakeRunner | null = null

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(async () => {
  await runner?.close()
  runner = null
  delete process.env.PLUGIN_RUNNER_URL
  delete process.env.PLUGIN_RUNNER_KEY
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const CONTEXT = { context: { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION }, params: {} }
const run = async (action: string) => answer(await runAction(actionRequest('echo', action, CONTEXT), actionParams('echo', action)))
const locks = () => db.rows('pluginData').filter((r) => r.collection === JOB_LOCKS_COLLECTION)

describe('nothing listening', () => {
  beforeEach(() => {
    process.env.PLUGIN_RUNNER_URL = 'http://127.0.0.1:1'
    process.env.PLUGIN_RUNNER_KEY = RUNNER_KEY
  })

  test('sync: 503 runner_unavailable, saying it was not reached', async () => {
    expect(await run('echo')).toEqual({
      status: 503,
      body: { error: 'The plugin runner could not be reached (unreachable); try again shortly.', code: 'runner_unavailable', reason: 'unreachable' },
    })
  })

  test('async: 503, the job failed with runner_unavailable, the lock released, a retry starts afresh', async () => {
    const r = await run('sleep')
    expect(r).toMatchObject({ status: 503, body: { code: 'runner_unavailable', jobId: expect.any(String) } })
    const job = await answer(await getJob(jobGetRequest(r.body.jobId as string), jobParams(r.body.jobId as string)))
    expect(job.body).toMatchObject({ status: 'failed', error: { code: 'runner_unavailable' } })
    expect(locks()).toEqual([])
    runner = await startEchoRunner({ 'echo/sleep': () => new Promise(() => {}) })
    expect((await run('sleep')).status).toBe(202)
  })
})

test('no runner key configured: 503 runner_unavailable, no request made', async () => {
  process.env.PLUGIN_RUNNER_URL = 'http://127.0.0.1:1'
  process.env.PLUGIN_RUNNER_KEY = ''
  // Not "try again": nothing changes until an administrator sets the key.
  expect(await run('echo')).toEqual({
    status: 503,
    body: {
      error: 'The plugin runner is not configured on this deployment: PLUGIN_RUNNER_KEY is not set (./redamon.sh up generates it).',
      code: 'runner_unavailable',
      reason: 'not_configured',
    },
  })
})

test.each<[string, number, string, string]>([
  ['the proxy timed out', 504, 'upstream_timeout', 'The plugin runner did not answer in time (upstream_timeout); the action may still have run.'],
  ['the proxy is full', 503, 'proxy_busy', 'The plugin-gateway proxy is busy (proxy_busy); try again shortly.'],
  ['the proxy could not reach the runner', 502, 'upstream_unreachable', 'The plugin runner could not be reached (upstream_unreachable); try again shortly.'],
])('%s: the reason and the proxy code', async (_n, status, code, error) => {
  runner = await startEchoRunner({ 'echo/echo': () => ({ status, body: { error: 'proxy', code } }) })
  const r = await run('echo')
  expect(r).toMatchObject({ status: 503, body: { error, code: 'runner_unavailable', proxyCode: code } })
})

test('the runner has not started this plugin yet (404 unknown_plugin): 503 plugin_not_running', async () => {
  runner = await startEchoRunner({ 'echo/echo': () => ({ result: {} }) }, { versions: { echo: ['0.9.0'] } })
  expect(await run('echo')).toMatchObject({ status: 503, body: { code: 'plugin_not_running' } })
})

test('a runner out of date: its own 503 code passes through', async () => {
  runner = await startEchoRunner({ 'echo/echo': () => ({ result: {} }) }, { state: 'out_of_date' })
  expect(await run('echo')).toMatchObject({ status: 503, body: { code: 'runner_out_of_date' } })
})

test.each([
  [429, 'plugin_busy', 'Too many actions at once.'],
  [504, 'action_timeout', 'The action did not finish within 30 seconds.'],
])('the runner answering %s %s: passed through with its code', async (status, code, error) => {
  runner = await startEchoRunner({ 'echo/echo': () => ({ status, body: { error, code } }) })
  expect(await run('echo')).toEqual({ status, body: { error, code } })
})
