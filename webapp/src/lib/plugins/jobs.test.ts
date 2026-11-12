/**
 * Async plugin actions as jobs (TD-22, D-63, R-65): one active job per (plugin, action,
 * user, session), a second click returns it; a job past its deadline, or taken by a runner
 * that has since restarted, reads as failed instead of waiting; a result that arrives after
 * a cancel, or twice, changes nothing; only the owner sees or cancels a job.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  eff: { userId: 'user-alice' } as { userId: string } | null,
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => h.eff,
  getSession: async () => (h.eff ? { userId: h.eff.userId, role: 'standard' } : null),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ALICE, ALICE_PROJECT, ALICE_SESSION, BOB, CALL_SECRET, answer, gatewayRequest, seedWorld } from './__testing__/gatewayHarness'
import { APP, actionParams, actionRequest, cancelRequest, jobGetRequest, jobParams, settle, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { setNowForTests } from './clock'
import { clearRunnerBootIdCache } from './jobs'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'
import { GET as getJob } from '@/app/api/plugins/jobs/[jobId]/route'
import { POST as cancelJob } from '@/app/api/plugins/jobs/[jobId]/cancel/route'
import { POST as jobProgress } from '@/app/api/plugin-gateway/v1/jobs/progress/route'
import { POST as jobComplete } from '@/app/api/plugin-gateway/v1/jobs/complete/route'

let db: FakePrisma
let runner: FakeRunner
let t = Date.parse('2026-10-09T10:00:00.000Z')

beforeEach(async () => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  h.eff = { userId: ALICE }
  t = Date.parse('2026-10-09T10:00:00.000Z')
  setNowForTests(() => new Date(t))
  clearRunnerBootIdCache()
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  // The async script never ends by itself: tests report or cancel it.
  runner = await startEchoRunner({ 'echo/sleep': () => new Promise(() => {}) })
})
afterEach(async () => {
  await runner.close()
  delete process.env.PLUGIN_RUNNER_URL
  delete process.env.PLUGIN_RUNNER_KEY
  setNowForTests(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const SLEEP = { context: { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION }, params: {} }
const start = async (body: unknown = SLEEP) => answer(await runAction(actionRequest('echo', 'sleep', body), actionParams('echo', 'sleep')))
const read = async (jobId: string) => answer(await getJob(jobGetRequest(jobId), jobParams(jobId)))
const cancel = async (jobId: string, origin?: string) => answer(await cancelJob(cancelRequest(jobId, { origin }), jobParams(jobId)))
const tokenOf = (i = 0) => runner.actionCalls[i].body.token as string
const locks = () => db.rows('pluginData').filter((r) => r.collection === '__jobs_active')

describe('one active job per action and session', () => {
  test('a second click returns the running job, and the runner is called once', async () => {
    const first = await start()
    const second = await start()
    expect(second).toEqual({ status: 200, body: { jobId: first.body.jobId, status: 'running', existing: true, pick: null } })
    expect(runner.actionCalls).toHaveLength(1)
  })

  test('another session, or no session, is another job', async () => {
    const a = await start()
    const b = await start({ context: { projectId: ALICE_PROJECT }, params: {} })
    expect(b.status).toBe(202)
    expect(b.body.jobId).not.toBe(a.body.jobId)
  })

  test('after the job ends, a click starts a new one', async () => {
    const a = await start()
    await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: {} }, { token: tokenOf() }))
    const b = await start()
    expect(b.status).toBe(202)
    expect(b.body.jobId).not.toBe(a.body.jobId)
    expect(locks()).toHaveLength(1)
  })
})

describe('reading a job', () => {
  test('past its deadline: failed timeout, and the lock is released', async () => {
    const { body } = await start()
    t += (120 + 60) * 1000 + 1000
    const r = await read(body.jobId as string)
    expect(r.body).toMatchObject({ status: 'failed', error: { code: 'timeout' } })
    expect(locks()).toEqual([])
  })

  test('taken by a runner that has since restarted: failed runner_restarted', async () => {
    const { body } = await start()
    runner.options.bootId = 'a-new-boot'
    clearRunnerBootIdCache()
    const r = await read(body.jobId as string)
    expect(r.body).toMatchObject({ status: 'failed', error: { code: 'runner_restarted' } })
    expect(locks()).toEqual([])
  })

  test('a boot id cached from before a restart never fails a job the new runner took', async () => {
    runner.options.bootId = 'boot-old'
    clearRunnerBootIdCache()
    const first = await start({ context: { projectId: ALICE_PROJECT }, params: {} })
    expect((await read(first.body.jobId as string)).body.status).toBe('running')
    // The runner restarts; the cache still holds boot-old for a few seconds.
    runner.options.bootId = 'boot-new'
    const second = await start()
    expect((await read(second.body.jobId as string)).body.status).toBe('running')
    expect((await read(first.body.jobId as string)).body).toMatchObject({ status: 'failed', error: { code: 'runner_restarted' } })
  })

  test('the runner unreachable on read: the job stays running (nothing proves it died)', async () => {
    const { body } = await start()
    process.env.PLUGIN_RUNNER_URL = 'http://127.0.0.1:1'
    clearRunnerBootIdCache()
    expect((await read(body.jobId as string)).body.status).toBe('running')
  })

  test("another user's job: 404, and so is an unknown or malformed id", async () => {
    const { body } = await start()
    h.eff = { userId: BOB }
    expect((await read(body.jobId as string)).status).toBe(404)
    expect((await cancel(body.jobId as string)).status).toBe(404)
    h.eff = { userId: ALICE }
    expect((await read('00000000-0000-0000-0000-000000000000')).status).toBe(404)
    expect((await read('../x')).status).toBe(404)
  })

  test('no session: 401', async () => {
    const { body } = await start()
    h.eff = null
    expect((await read(body.jobId as string)).status).toBe(401)
  })
})

describe('cancel', () => {
  test('cancelled at once, the runner asked to stop it, the lock released', async () => {
    const { body } = await start()
    await settle()
    expect(await cancel(body.jobId as string)).toMatchObject({ status: 200, body: { status: 'cancelled' } })
    expect(runner.cancels).toEqual([{ pluginId: 'echo', jobId: body.jobId }])
    expect((await read(body.jobId as string)).body.status).toBe('cancelled')
    expect(locks()).toEqual([])
  })

  test('a result that arrives after the cancel is ignored', async () => {
    const { body } = await start()
    await cancel(body.jobId as string)
    const late = await answer(await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: { late: true } }, { token: tokenOf() })))
    expect(late).toEqual({ status: 200, body: { ok: true, ignored: true } })
    expect((await read(body.jobId as string)).body).toMatchObject({ status: 'cancelled', result: null })
  })

  test('the runner reporting the cancel it was asked for keeps the job cancelled', async () => {
    const { body } = await start()
    await cancel(body.jobId as string)
    await jobComplete(gatewayRequest('jobs/complete', { status: 'cancelled', error: { code: 'cancelled', message: 'The action was cancelled.' } }, { token: tokenOf() }))
    expect((await read(body.jobId as string)).body.status).toBe('cancelled')
  })

  test('cancelling a finished job changes nothing', async () => {
    const { body } = await start()
    await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: { done: 1 } }, { token: tokenOf() }))
    expect(await cancel(body.jobId as string)).toMatchObject({ status: 200, body: { status: 'succeeded' } })
    expect(runner.cancels).toEqual([])
  })

  test('the runner unreachable: still cancelled here (a late result is then ignored)', async () => {
    const { body } = await start()
    process.env.PLUGIN_RUNNER_URL = 'http://127.0.0.1:1'
    expect((await cancel(body.jobId as string)).body.status).toBe('cancelled')
  })

  test('cross-origin: 403, and the job keeps running', async () => {
    const { body } = await start()
    expect((await cancel(body.jobId as string, 'http://evil.example')).status).toBe(403)
    expect((await read(body.jobId as string)).body.status).toBe('running')
    expect((await cancel(body.jobId as string, APP)).status).toBe(200)
  })
})

describe('jobs/complete and jobs/progress', () => {
  test('a second completion is ignored; the first one stands', async () => {
    const { body } = await start()
    await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: { n: 1 } }, { token: tokenOf() }))
    const again = await answer(await jobComplete(gatewayRequest('jobs/complete', { status: 'failed', error: { code: 'x', message: 'y' } }, { token: tokenOf() })))
    expect(again.body).toEqual({ ok: true, ignored: true })
    expect((await read(body.jobId as string)).body).toMatchObject({ status: 'succeeded', result: { n: 1 } })
  })

  test('a result over 2 MB fails the job with result_too_large', async () => {
    const { body } = await start()
    await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: { blob: 'x'.repeat(2 * 1024 * 1024) } }, { token: tokenOf() }))
    expect((await read(body.jobId as string)).body).toMatchObject({ status: 'failed', error: { code: 'result_too_large' }, result: null })
  })

  test.each<[string, Record<string, unknown>]>([
    ['an unknown status', { status: 'done' }],
    ['succeeded without a result object', { status: 'succeeded', result: [1] }],
    ['failed without an error', { status: 'failed' }],
    ['an error without a code', { status: 'failed', error: { message: 'm' } }],
  ])('%s: 400 invalid_report, and the job fails with the refusal instead of waiting out its deadline', async (_n, report) => {
    const { body } = await start()
    expect(await answer(await jobComplete(gatewayRequest('jobs/complete', report, { token: tokenOf() })))).toMatchObject({
      status: 400,
      body: { code: 'invalid_report' },
    })
    // The runner does not retry a 4xx, so without this the job would read as timed out.
    expect((await read(body.jobId as string)).body).toMatchObject({
      status: 'failed',
      error: { code: 'report_refused:invalid_report', message: expect.stringContaining('HTTP 400') },
    })
  })

  test('a result over the body limit: 413, and the job fails as report_refused:body_too_large', async () => {
    const { body } = await start()
    const big = { status: 'succeeded', result: { text: 'x'.repeat(8 * 1024 * 1024 + 1) } }
    expect(await answer(await jobComplete(gatewayRequest('jobs/complete', big, { token: tokenOf() })))).toMatchObject({
      status: 413,
      body: { code: 'body_too_large' },
    })
    expect((await read(body.jobId as string)).body).toMatchObject({ status: 'failed', error: { code: 'report_refused:body_too_large' } })
  })

  test.each<[string, Record<string, unknown>]>([
    ['a message over 300 characters', { message: 'm'.repeat(301) }],
    ['a message that is not text', { message: 7 }],
    ['21 fields', { message: 'm', fields: Object.fromEntries(Array.from({ length: 21 }, (_, i) => [`f${i}`, 'v'])) }],
    ['a field value that is not text', { message: 'm', fields: { a: { b: 1 } } }],
  ])('progress with %s: 400', async (_n, progress) => {
    await start()
    expect((await answer(await jobProgress(gatewayRequest('jobs/progress', progress, { token: tokenOf() })))).status).toBe(400)
  })

  test('progress after the end is refused: the job token ended with its job', async () => {
    const { body } = await start()
    await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: {} }, { token: tokenOf() }))
    expect(await answer(await jobProgress(gatewayRequest('jobs/progress', { message: 'late' }, { token: tokenOf() })))).toMatchObject({
      status: 403,
      body: { code: 'job_ended' },
    })
    expect((await read(body.jobId as string)).body.progress).toBeNull()
  })

  test('jobs/complete is not counted against the call budget: a busy job still reports its result', async () => {
    vi.stubEnv('PLUGIN_GATEWAY_CALLS_PER_TOKEN', '2')
    const { body } = await start()
    for (let i = 0; i < 2; i++) await jobProgress(gatewayRequest('jobs/progress', { message: `p${i}` }, { token: tokenOf() }))
    expect((await answer(await jobProgress(gatewayRequest('jobs/progress', { message: 'p3' }, { token: tokenOf() })))).status).toBe(429)
    expect((await answer(await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: {} }, { token: tokenOf() })))).status).toBe(200)
    expect((await read(body.jobId as string)).body.status).toBe('succeeded')
  })
})
