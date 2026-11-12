/**
 * How async plugin actions end (TD-22, R-21, RV-21, RV-39; phase 04 review): the end of a
 * job is recorded even when the plugin or the job's context lapsed while it ran; repeated
 * reports have their own small allowance; a job's token stops working when the job ends;
 * a cancel that lands before the runner has the job still stops it; plugin code cannot
 * pass its own end off as the user's cancel; a result Postgres cannot store ends the job
 * instead of leaving it running; one active job per action, project and session.
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
import { ALICE, ALICE_CONV, ALICE_OTHER_PROJECT, ALICE_PROJECT, ALICE_SESSION, CALL_SECRET, answer, gatewayRequest, seedWorld } from './__testing__/gatewayHarness'
import { actionParams, actionRequest, cancelRequest, jobGetRequest, jobParams, settle, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { setNowForTests } from './clock'
import { clearRunnerBootIdCache } from './jobs'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'
import { GET as getJob } from '@/app/api/plugins/jobs/[jobId]/route'
import { POST as cancelJob } from '@/app/api/plugins/jobs/[jobId]/cancel/route'
import { POST as jobProgress } from '@/app/api/plugin-gateway/v1/jobs/progress/route'
import { POST as jobComplete } from '@/app/api/plugin-gateway/v1/jobs/complete/route'
import { POST as dataGet } from '@/app/api/plugin-gateway/v1/data/get/route'

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
const read = async (jobId: string) => (await answer(await getJob(jobGetRequest(jobId), jobParams(jobId)))).body
const tokenOf = (i = 0) => runner.actionCalls[i].body.token as string
const complete = async (report: Record<string, unknown>, i = 0) =>
  answer(await jobComplete(gatewayRequest('jobs/complete', report, { token: tokenOf(i) })))
const locks = () => db.rows('pluginData').filter((r) => r.collection === '__jobs_active')
const SUCCEEDED = { status: 'succeeded', result: { found: 3 } }

describe('the end of a job is recorded although the plugin or the context lapsed mid-job', () => {
  test('the plugin is being updated (its version still running): the result is kept', async () => {
    const { body } = await start()
    await db.pluginInstall.update({ where: { pluginId: 'echo' }, data: { status: 'updating' } })
    expect(await complete(SUCCEEDED)).toEqual({ status: 200, body: { ok: true } })
    expect(await read(body.jobId as string)).toMatchObject({ status: 'succeeded', result: { found: 3 } })
    expect(locks()).toEqual([])
  })

  test.each<[string, Record<string, unknown>]>([
    ['disabled', { enabled: false }],
    ['revoked', { revokedReason: 'catalog revoked it' }],
    ['switched to another version', { activeVersion: '1.1.0' }],
  ])('the plugin was %s: failed plugin_unavailable, the result dropped, the lock released', async (_n, change) => {
    const { body } = await start()
    await db.pluginInstall.update({ where: { pluginId: 'echo' }, data: change })
    expect((await complete(SUCCEEDED)).status).toBe(200)
    expect(await read(body.jobId as string)).toMatchObject({ status: 'failed', error: { code: 'plugin_unavailable' }, result: null })
    expect(locks()).toEqual([])
  })

  test('the chat session was deleted: failed context_gone, the lock released', async () => {
    const { body } = await start()
    await db.conversation.delete({ where: { id: ALICE_CONV } })
    expect((await complete(SUCCEEDED)).status).toBe(200)
    expect(await read(body.jobId as string)).toMatchObject({ status: 'failed', error: { code: 'context_gone' }, result: null })
    expect(locks()).toEqual([])
  })
})

describe('jobs/complete has a small allowance of its own', () => {
  test('past the call budget the end is still recorded; a reporting loop is refused after 10 reports', async () => {
    vi.stubEnv('PLUGIN_GATEWAY_CALLS_PER_TOKEN', '1')
    const { body } = await start()
    await jobProgress(gatewayRequest('jobs/progress', { message: 'p' }, { token: tokenOf() }))
    expect((await answer(await jobProgress(gatewayRequest('jobs/progress', { message: 'p2' }, { token: tokenOf() })))).status).toBe(429)
    expect((await complete(SUCCEEDED)).status).toBe(200)
    expect((await read(body.jobId as string)).status).toBe('succeeded')
    for (let i = 2; i <= 10; i++) expect((await complete(SUCCEEDED)).body).toEqual({ ok: true, ignored: true })
    expect(await complete(SUCCEEDED)).toMatchObject({ status: 429, body: { code: 'call_budget_exceeded' } })
  })
})

describe('a job token stops working when its job ends', () => {
  test.each([
    ['cancelled by the user', async (jobId: string) => void (await answer(await cancelJob(cancelRequest(jobId), jobParams(jobId))))],
    ['completed', async () => void (await complete(SUCCEEDED))],
  ])('%s: every Gateway call with its token is refused, except the end report', async (_n, end) => {
    const { body } = await start()
    expect((await answer(await dataGet(gatewayRequest('data/get', { collection: 'notes', key: 'k', owner: 'user' }, { token: tokenOf() })))).status).toBe(200)
    await end(body.jobId as string)
    expect(await answer(await dataGet(gatewayRequest('data/get', { collection: 'notes', key: 'k', owner: 'user' }, { token: tokenOf() })))).toMatchObject({
      status: 403,
      body: { code: 'job_ended' },
    })
    expect((await answer(await jobProgress(gatewayRequest('jobs/progress', { message: 'late' }, { token: tokenOf() })))).body).toMatchObject({ code: 'job_ended' })
    expect((await complete({ status: 'failed', error: { code: 'x', message: 'late' } })).body).toEqual({ ok: true, ignored: true })
  })
})

describe('a sync action’s token ends when the action returns', () => {
  test('plugin code that left a thread running cannot go on calling with it', async () => {
    await runner.close()
    runner = await startEchoRunner({ 'echo/echo': () => ({ result: { ok: 1 } }) })
    const r = await answer(await runAction(actionRequest('echo', 'echo', SLEEP), actionParams('echo', 'echo')))
    expect(r).toMatchObject({ status: 200, body: { ok: true } })
    expect(await answer(await dataGet(gatewayRequest('data/get', { collection: 'notes', key: 'k', owner: 'user' }, { token: tokenOf() })))).toMatchObject({
      status: 403,
      body: { code: 'action_ended' },
    })
  })
})

describe('a cancel that lands before the runner has the job', () => {
  test('the runner is told to stop it once it answers, and a new click starts a new job', async () => {
    const realFetch = globalThis.fetch
    let release!: () => void
    const gate = new Promise<void>((resolve) => (release = resolve))
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (String(input).includes('/actions/sleep')) await gate
      return realFetch(input, init)
    })
    const first = start()
    await vi.waitFor(() => expect(db.rows('pluginData').filter((r) => r.collection === '__jobs')).toHaveLength(1))
    const jobId = db.rows('pluginData').find((r) => r.collection === '__jobs')!.key as string
    expect((await answer(await cancelJob(cancelRequest(jobId), jobParams(jobId)))).body.status).toBe('cancelled')
    release()
    expect((await first).status).toBe(202)
    await settle()
    expect(runner.cancels).toEqual([{ pluginId: 'echo', jobId }])
    expect((await read(jobId)).status).toBe('cancelled')
  })
})

describe('plugin code cannot pass its own end off as the user’s cancel', () => {
  test('a cancelled report for a job nobody cancelled is recorded as failed', async () => {
    const { body } = await start()
    expect((await complete({ status: 'cancelled', error: { code: 'cancelled', message: 'Cancelled by the user.' } })).status).toBe(200)
    expect(await read(body.jobId as string)).toMatchObject({ status: 'failed', error: { code: 'cancelled', message: 'Cancelled by the user.' } })
  })
})

describe('what Postgres cannot store ends the job instead of failing the report', () => {
  test.each([
    ['a NUL character', { out: 'a\u0000b' }],
    ['an unpaired surrogate', { out: 'a\ud800b' }],
    ['a key with a NUL character', { 'k\u0000': 1 }],
  ])('a result with %s: failed invalid_result, the lock released', async (_n, result) => {
    const { body } = await start()
    expect((await complete({ status: 'succeeded', result })).status).toBe(200)
    expect(await read(body.jobId as string)).toMatchObject({ status: 'failed', error: { code: 'invalid_result' }, result: null })
    expect(locks()).toEqual([])
  })

  test('an error message with them is stored with U+FFFD in their place', async () => {
    const { body } = await start()
    expect((await complete({ status: 'failed', error: { code: 'e\u0000', message: 'bad \u0000 and \udc80' } })).status).toBe(200)
    expect((await read(body.jobId as string)).error).toEqual({ code: 'e�', message: 'bad � and �' })
  })
})

describe('one active job per action, project and session', () => {
  test('no session: the same action in two projects is two jobs', async () => {
    const a = await start({ context: { projectId: ALICE_PROJECT }, params: {} })
    const b = await start({ context: { projectId: ALICE_OTHER_PROJECT }, params: {} })
    expect([a.status, b.status]).toEqual([202, 202])
    expect(b.body.jobId).not.toBe(a.body.jobId)
  })
})
