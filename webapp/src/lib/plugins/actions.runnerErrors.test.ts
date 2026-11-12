/**
 * What the browser sees when the runner refuses or fails a call (D-21; phase 04 review):
 * the runner's 400, 401 and 403 mean the webapp's call or key is wrong, and a 5xx it does
 * not name is its own failure. None is the user's to fix: they become 502 with a code,
 * never a 401 the UI would read as a lost login, and never a bare 500. The runner's own
 * named answers (a busy or crashed worker, a timeout) pass through as they are.
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

import { createFakePrisma } from './__testing__/fakePrisma'
import { ALICE_PROJECT, ALICE_SESSION, CALL_SECRET, answer, seedWorld } from './__testing__/gatewayHarness'
import { actionParams, actionRequest, jobGetRequest, jobParams, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner, ActionScript } from './__testing__/fakeRunner'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'
import { GET as getJob } from '@/app/api/plugins/jobs/[jobId]/route'

let runner: FakeRunner | null = null

beforeEach(() => {
  const db = createFakePrisma()
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
const answering = (status: number, body: unknown): ActionScript => () => ({ status, body: body as object })

test('the runner refuses the webapp’s key: 502 runner_misconfigured, not 401', async () => {
  runner = await startEchoRunner({ 'echo/echo': () => ({ result: {} }) }, { runnerKey: 'z'.repeat(64) })
  expect(await run('echo')).toMatchObject({ status: 502, body: { code: 'runner_misconfigured', upstreamStatus: 401 } })
})

test.each<[string, number, unknown]>([
  ['a plain-text 500', 500, 'Internal Server Error'],
  ['a 500 with a code', 500, { error: 'boom', code: 'internal' }],
  ['a 400 about the webapp’s request', 400, { error: 'ctx.version is missing', code: 'bad_request' }],
  ['a 403', 403, { error: 'nope', code: 'forbidden' }],
])('%s: 502 runner_error, with the runner status and code', async (_n, status, body) => {
  runner = await startEchoRunner({ 'echo/echo': answering(status, body) })
  const runnerCode = typeof body === 'object' ? (body as { code: string }).code : 'runner_error'
  expect(await run('echo')).toEqual({
    status: 502,
    body: {
      error: `The plugin runner could not run this action (${runnerCode}); its log has the details.`,
      code: 'runner_error',
      upstreamStatus: status,
      runnerCode,
    },
  })
})

test('a runner code in another shape is not shown', async () => {
  runner = await startEchoRunner({ 'echo/echo': answering(500, { error: 'boom', code: 'Not A Code <b>' }) })
  expect(await run('echo')).toMatchObject({ status: 502, body: { runnerCode: 'runner_error', upstreamStatus: 500 } })
})

test('an async action the runner fails that way: 502, and the job failed with runner_error', async () => {
  runner = await startEchoRunner({ 'echo/sleep': () => new Promise(() => {}) })
  // The fake runner accepts every async start at once; the failure is the dispatch's answer.
  const realFetch = globalThis.fetch
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
    String(input).includes('/actions/sleep') ? new Response('Internal Server Error', { status: 500 }) : realFetch(input, init),
  )
  const r = await run('sleep')
  expect(r).toMatchObject({ status: 502, body: { code: 'runner_error', jobId: expect.any(String) } })
  const job = await answer(await getJob(jobGetRequest(r.body.jobId as string), jobParams(r.body.jobId as string)))
  expect(job.body).toMatchObject({ status: 'failed', error: { code: 'runner_error' } })
})

describe('the runner’s named answers pass through', () => {
  test.each<[number, string]>([
    [503, 'worker_unavailable'],
    [502, 'worker_crashed'],
    [504, 'timeout'],
    [404, 'unknown_action'],
  ])('%i %s', async (status, code) => {
    runner = await startEchoRunner({ 'echo/echo': answering(status, { error: 'x', code }) })
    expect(await run('echo')).toMatchObject({ status, body: { code } })
  })
})

describe('a deployment without a usable call-token secret', () => {
  test.each<[string, string, RegExp]>([
    ['missing', '', /: PLUGIN_CALL_TOKEN_SECRET is not configured \(at least \d+ characters; \.\/redamon\.sh up generates it\)\.$/],
    ['equal to AUTH_SECRET', 'a'.repeat(64), /: PLUGIN_CALL_TOKEN_SECRET must differ from AUTH_SECRET\.$/],
  ])('%s: 503 naming the setting and its rule, never its value', async (_n, value, rule) => {
    vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', value)
    const r = await run('echo')
    expect(r).toMatchObject({ status: 503, body: { code: 'plugins_not_configured' } })
    expect(r.body.error).toMatch(/^The plugin platform is not configured on this deployment: /)
    expect(r.body.error).toMatch(rule)
    expect(JSON.stringify(r.body)).not.toContain('a'.repeat(32))
  })
})
