/**
 * POST /api/plugins/[pluginId]/actions/[actionId] (README.PLUGINS.md §7.7, D-63, TD-22):
 * a signed-in user runs a plugin action from the UI. The webapp checks the plugin, the
 * action, the project and session (strictly: they must be the effective user's), mints a
 * call token and hands the action to the runner: a sync action answers its result, an
 * async one becomes a job the worker reports on through the Gateway.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  eff: { userId: 'user-alice' } as { userId: string } | null,
  session: { userId: 'user-alice', role: 'standard' } as { userId: string; role: string } | null,
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => h.eff,
  getSession: async () => h.session,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ALICE, ALICE_CONV, ALICE_OTHER_SESSION, ALICE_PROJECT, ALICE_SESSION, BOB_PROJECT, BOB_SESSION, CALL_SECRET, answer, echoInstall, echoManifest, gatewayRequest, seedWorld } from './__testing__/gatewayHarness'
import { actionParams, actionRequest, jobGetRequest, jobParams, settle, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { verifyCallToken } from './callToken'
import * as ov from './overrides'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'
import { GET as getJob } from '@/app/api/plugins/jobs/[jobId]/route'
import { POST as jobProgress } from '@/app/api/plugin-gateway/v1/jobs/progress/route'
import { POST as jobComplete } from '@/app/api/plugin-gateway/v1/jobs/complete/route'

let db: FakePrisma
let runner: FakeRunner

beforeEach(async () => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  h.eff = { userId: ALICE }
  h.session = { userId: ALICE, role: 'standard' }
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.stubEnv('ACCESS_ENFORCE', '')
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  runner = await startEchoRunner({
    'echo/echo': (call) => ({ result: { echo: call.body.params } }),
    'echo/fails': () => ({ status: 200, body: { ok: false, error: { code: 'no_target', message: 'Pick a target first.' } } }),
    'echo/sleep': () => new Promise((resolve) => setTimeout(() => resolve({ result: {} }), 50)),
    'echo/think': () => ({ result: { thought: true } }),
  })
})
afterEach(async () => {
  await runner.close()
  delete process.env.PLUGIN_RUNNER_URL
  delete process.env.PLUGIN_RUNNER_KEY
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const MANIFEST_ACTIONS = [
  { id: 'echo', entry: 'engine/main.py:echo', timeoutSeconds: 30 },
  { id: 'fails', entry: 'engine/main.py:fails', timeoutSeconds: 30 },
  { id: 'sleep', entry: 'engine/main.py:sleep', timeoutSeconds: 120, async: true },
  { id: 'think', entry: 'engine/main.py:think', timeoutSeconds: 3600, llm: true },
]
function install(over: Record<string, unknown> = {}) {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db, { install: echoInstall({ manifest: echoManifest({ actions: MANIFEST_ACTIONS }), ...over }) })
}
beforeEach(() => install())

const run = async (action: string, body: unknown = { context: { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION }, params: { hello: 'world' } }) =>
  answer(await runAction(actionRequest('echo', action, body), actionParams('echo', action)))

describe('a sync action', () => {
  test('the runner gets a call token and the context; the answer is the result', async () => {
    const r = await run('echo')
    expect(r).toEqual({ status: 200, body: { ok: true, result: { echo: { hello: 'world' } } } })
    const call = runner.actionCalls[0]
    expect(call.pluginId).toBe('echo')
    expect(call.body).toMatchObject({
      params: { hello: 'world' },
      ctx: { pluginId: 'echo', version: '1.0.0', userId: ALICE, projectId: ALICE_PROJECT, sessionId: ALICE_SESSION, conversationId: ALICE_CONV },
      timeoutSeconds: 30,
      async: false,
    })
    const claims = await verifyCallToken(call.body.token as string, { kinds: ['action'] })
    expect(claims).toMatchObject({ pid: 'echo', ver: '1.0.0', sub: ALICE, prj: ALICE_PROJECT, ses: ALICE_SESSION, conv: ALICE_CONV, kind: 'action' })
    expect(claims!.act).toBeUndefined()
    expect(claims!.perms.sort()).toEqual(['llm:invoke', 'override:skill.text', 'session:read'])
    expect(claims!.exp - claims!.iat).toBe(90)
  })

  test("a plugin's own error is an answer, not a failure", async () => {
    expect(await run('fails')).toEqual({ status: 200, body: { ok: false, error: { code: 'no_target', message: 'Pick a target first.' } } })
  })

  test('no context: the action runs for the user alone', async () => {
    expect((await run('echo', { params: {} })).status).toBe(200)
    const claims = await verifyCallToken(runner.actionCalls[0].body.token as string, { kinds: ['action'] })
    expect(claims).toMatchObject({ sub: ALICE })
    expect(claims!.prj).toBeUndefined()
    expect(runner.actionCalls[0].body.ctx).toEqual({ pluginId: 'echo', version: '1.0.0', userId: ALICE })
  })

  test('the token only carries permissions both granted and declared', async () => {
    install({ grantedPermissions: ['session:read'], manifest: echoManifest({ actions: MANIFEST_ACTIONS, permissions: ['session:read', 'llm:invoke'], llmFeature: { description: 'x' } }) })
    await run('echo')
    const claims = await verifyCallToken(runner.actionCalls[0].body.token as string, { kinds: ['action'] })
    expect(claims!.perms).toEqual(['session:read'])
  })

  test('the timeout is capped by PLUGIN_ACTION_MAX_TIMEOUT', async () => {
    vi.stubEnv('PLUGIN_ACTION_MAX_TIMEOUT', '300')
    await db.userSettings.create({ data: { userId: ALICE, featureModels: { 'plugin:echo': 'm' } } })
    await run('think')
    expect(runner.actionCalls[0].body.timeoutSeconds).toBe(300)
  })
})

describe('refusals before the runner is called', () => {
  test.each<[string, unknown]>([
    ["another user's project", { context: { projectId: BOB_PROJECT }, params: {} }],
    ["another user's session in that project", { context: { projectId: BOB_PROJECT, sessionId: BOB_SESSION }, params: {} }],
    ["another user's session in my project", { context: { projectId: ALICE_PROJECT, sessionId: BOB_SESSION }, params: {} }],
    ['my session of another project', { context: { projectId: ALICE_PROJECT, sessionId: ALICE_OTHER_SESSION }, params: {} }],
    ['a session without its project', { context: { sessionId: ALICE_SESSION }, params: {} }],
    ['an unknown project', { context: { projectId: 'project-nobody' }, params: {} }],
  ])('%s: 404, also with ACCESS_ENFORCE=0', async (_n, body) => {
    for (const enforce of ['', '0']) {
      vi.stubEnv('ACCESS_ENFORCE', enforce)
      const r = await run('echo', body)
      expect(r.status).toBe(404)
    }
    expect(runner.actionCalls).toEqual([])
  })

  test.each<[string, unknown, number, string]>([
    ['params that are not an object', { params: ['x'] }, 400, 'invalid_params'],
    ['params over 64 KB', { params: { blob: 'x'.repeat(66_000) } }, 413, 'params_too_large'],
    ['a context that is not an object', { context: 'p', params: {} }, 400, 'invalid_context'],
    ['a project id that is not text', { context: { projectId: 7 }, params: {} }, 400, 'invalid_context'],
  ])('%s: %s %s', async (_n, body, status, code) => {
    expect(await run('echo', body)).toMatchObject({ status, body: { code } })
    expect(runner.actionCalls).toEqual([])
  })

  test('an action the manifest does not declare: 404 unknown_action', async () => {
    expect(await run('nope')).toMatchObject({ status: 404, body: { code: 'unknown_action' } })
  })

  test.each([
    ['not installed', null, 404, 'not_found'],
    ['disabled', { enabled: false }, 409, 'plugin_unavailable'],
    ['revoked', { revokedReason: 'revoked' }, 409, 'plugin_unavailable'],
    ['failed', { status: 'failed' }, 409, 'plugin_unavailable'],
    ['updating', { status: 'updating' }, 409, 'plugin_updating'],
  ])('a plugin %s: %s %s', async (_n, over, status, code) => {
    if (over === null) {
      db = createFakePrisma()
      h.db = db as unknown as Record<string, unknown>
      seedWorld(db, { install: null })
    } else install(over as Record<string, unknown>)
    expect(await run('echo')).toMatchObject({ status, body: { code } })
    expect(runner.actionCalls).toEqual([])
  })

  test('a malformed plugin or action id: 404', async () => {
    expect((await runAction(actionRequest('Bad', 'echo', {}), actionParams('Bad', 'echo'))).status).toBe(404)
    expect((await runAction(actionRequest('echo', 'Bad-Id', {}), actionParams('echo', 'Bad-Id'))).status).toBe(404)
  })

  test('llm: true and no model chosen: 409 model_required for plugin:echo, the runner never called', async () => {
    expect(await run('think')).toEqual({
      status: 409,
      body: { error: 'Choose a model for this plugin in Models by feature.', code: 'model_required', featureId: 'plugin:echo' },
    })
    expect(runner.actionCalls).toEqual([])
    await db.userSettings.create({ data: { userId: ALICE, featureModels: { 'plugin:echo': 'openai/gpt-test' } } })
    expect((await run('think')).status).toBe(200)
  })

  test('no session: 401', async () => {
    h.eff = null
    expect((await run('echo')).status).toBe(401)
    expect(runner.actionCalls).toEqual([])
  })
})

describe('an async action: job, progress, completion', () => {
  test('202 {jobId}; the worker reports progress and its result through the Gateway', async () => {
    const r = await run('sleep')
    expect(r.status).toBe(202)
    const jobId = r.body.jobId as string
    expect(jobId).toMatch(/^[0-9a-f-]{36}$/)
    const call = runner.actionCalls[0]
    expect(call.body).toMatchObject({ async: true, jobId, ctx: { jobId }, timeoutSeconds: 120 })
    const token = call.body.token as string
    expect(await verifyCallToken(token, { kinds: ['job'] })).toMatchObject({ kind: 'job', jid: jobId, sub: ALICE })

    let job = await answer(await getJob(jobGetRequest(jobId), jobParams(jobId)))
    expect(job.body).toMatchObject({ jobId, pluginId: 'echo', actionId: 'sleep', status: 'running', progress: null, result: null, error: null })

    const progress = await answer(await jobProgress(gatewayRequest('jobs/progress', { message: 'Reading the session', fields: { Stage: '1 of 3' } }, { token })))
    expect(progress).toEqual({ status: 200, body: { ok: true } })
    job = await answer(await getJob(jobGetRequest(jobId), jobParams(jobId)))
    expect(job.body.progress).toEqual({ message: 'Reading the session', fields: { Stage: '1 of 3' } })

    const done = await answer(await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: { slept: 0.1 } }, { token })))
    expect(done).toEqual({ status: 200, body: { ok: true } })
    job = await answer(await getJob(jobGetRequest(jobId), jobParams(jobId)))
    expect(job.body).toMatchObject({ status: 'succeeded', result: { slept: 0.1 }, error: null })
    expect(db.rows('pluginData').filter((row) => row.collection === '__jobs_active')).toEqual([])
    await settle()
  })

  test('a failed job keeps its error code and message', async () => {
    const { body } = await run('sleep')
    const token = runner.actionCalls[0].body.token as string
    await jobComplete(gatewayRequest('jobs/complete', { status: 'failed', error: { code: 'action_timeout', message: 'The action did not finish within 30 seconds.' } }, { token }))
    const job = await answer(await getJob(jobGetRequest(body.jobId as string), jobParams(body.jobId as string)))
    expect(job.body).toMatchObject({ status: 'failed', error: { code: 'action_timeout', message: 'The action did not finish within 30 seconds.' } })
    await settle()
  })

  test('a sync action token cannot report a job; a job token cannot report another job', async () => {
    const { body } = await run('sleep')
    await run('echo')
    const actionToken = runner.actionCalls[1].body.token as string
    expect((await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: {} }, { token: actionToken }))).status).toBe(401)
    const job = await answer(await getJob(jobGetRequest(body.jobId as string), jobParams(body.jobId as string)))
    expect(job.body.status).toBe('running')
    await settle()
  })
})

describe('reviewProposal is checked (RV-21)', () => {
  async function changeSet(pluginId: string, scope: ov.OverrideScope) {
    const { changeSetId } = await ov.propose({
      pluginId,
      point: 'skill.text',
      scope,
      targetGroup: 'xxe',
      parts: [{ targetKey: 'xxe/tools', value: 'v', baseSha256: 'a'.repeat(64) }],
      createdBy: ALICE,
    })
    return changeSetId
  }

  beforeEach(() => {
    db.seed('pluginInstall', [echoInstall({ pluginId: 'other', manifest: echoManifest({ id: 'other' }) })])
  })

  test('in a sync result: kept when it is this plugin’s, in the caller’s scope; dropped otherwise', async () => {
    const own = await changeSet('echo', { type: 'user', id: ALICE })
    const ownProject = await changeSet('echo', { type: 'project', id: ALICE_PROJECT })
    const others = await changeSet('other', { type: 'user', id: ALICE })
    const bobs = await changeSet('echo', { type: 'user', id: 'user-bob' })
    const answers = [own, ownProject, others, bobs, 'not-a-set']
    let i = 0
    runner.options.actions!['echo/echo'] = () => ({ result: { reviewProposal: { extensionPoint: 'skill.text', changeSetId: answers[i++] }, note: 'kept' } })
    const results = []
    for (let k = 0; k < answers.length; k++) results.push((await run('echo')).body.result as Record<string, unknown>)
    expect(results.map((r) => r.reviewProposal ?? null)).toEqual([
      { extensionPoint: 'skill.text', changeSetId: own },
      { extensionPoint: 'skill.text', changeSetId: ownProject },
      null,
      null,
      null,
    ])
    expect(results.every((r) => r.note === 'kept')).toBe(true)
  })

  test('in jobs/complete: the same check', async () => {
    const others = await changeSet('other', { type: 'user', id: ALICE })
    const { body } = await run('sleep')
    const token = runner.actionCalls[0].body.token as string
    await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: { reviewProposal: { extensionPoint: 'skill.text', changeSetId: others }, n: 1 } }, { token }))
    const job = await answer(await getJob(jobGetRequest(body.jobId as string), jobParams(body.jobId as string)))
    expect(job.body.result).toEqual({ n: 1 })
    await settle()
  })
})
