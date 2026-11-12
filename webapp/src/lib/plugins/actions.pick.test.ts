/**
 * The `session.skill` pick at the action start (sessionPick.ts, actions.ts, jobs.ts;
 * platform 1.1.0): the server re-derives the pick from the session and hands the plugin
 * only its own `{kind, point, target, ref}`; a pick it cannot re-derive (an action that
 * takes none, a skill of another user or one the session never ran, a point the plugin is
 * not granted, a skill that cannot be picked, no session) is 400 `invalid_pick` before the
 * runner is called. A job records the pick; a second start names the running job's pick;
 * without a pick, 1.0.0 behaviour.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { createHash } from 'crypto'

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
import { ALICE, ALICE_CONV, ALICE_OTHER_PROJECT, ALICE_OTHER_SESSION, ALICE_PROJECT, ALICE_SESSION, BOB, CALL_SECRET, answer, echoInstall, echoManifest, gatewayRequest, seedWorld } from './__testing__/gatewayHarness'
import { actionParams, actionRequest, jobGetRequest, jobParams, settle, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { JOBS_COLLECTION, jobView, startJob, type Job } from './jobs'
import * as ov from './overrides'
import { actionPicksSessionSkill, pickablePoints, pickableSessionSkills, resolvePick, InvalidPickError } from './sessionPick'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'
import { GET as getJob } from '@/app/api/plugins/jobs/[jobId]/route'
import { POST as jobComplete } from '@/app/api/plugin-gateway/v1/jobs/complete/route'

const sha16 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 16)
const ALL = ['session:read', 'llm:invoke', 'override:skill.text', 'override:user_skill.text']
const ACTIONS = [
  { id: 'echo', entry: 'engine/main.py:echo', timeoutSeconds: 30 },
  { id: 'plain', entry: 'engine/main.py:plain', timeoutSeconds: 30 },
  { id: 'sleep', entry: 'engine/main.py:sleep', timeoutSeconds: 120, async: true },
]
const CONTRIBUTES = {
  'chat.session.actions': [
    { label: 'Echo a skill', action: 'echo', pick: 'session.skill' },
    { label: 'Improve a skill', action: 'sleep', pick: 'session.skill' },
    { label: 'Plain', action: 'plain' },
  ],
}

let db: FakePrisma
let runner: FakeRunner

function install(over: { grantedPermissions?: string[]; permissions?: string[]; contributes?: unknown } = {}) {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db, {
    install: echoInstall({
      grantedPermissions: over.grantedPermissions ?? ALL,
      manifest: echoManifest({ permissions: over.permissions ?? ALL, actions: ACTIONS, contributes: over.contributes ?? CONTRIBUTES }),
    }),
  })
  db.seed('userAttackSkill', [
    { id: 'skalice', userId: ALICE, name: 'My SQLi flow', content: 'Enumerate example.com.' },
    { id: 'skcreds', userId: ALICE, name: 'Creds', content: 'Sign with AKIAIOSFODNN7EXAMPLE.' },
    { id: 'skquar', userId: ALICE, name: 'Quarantined', content: 'x', quarantinedAt: new Date('2026-10-01T00:00:00Z'), quarantineReason: 'plugin_version_revoked' },
    { id: 'skunused', userId: ALICE, name: 'Unused', content: 'Never ran.' },
    { id: 'skbob', userId: BOB, name: 'Bob flow', content: 'Bob only.' },
  ])
  const turns: [number, Record<string, unknown>][] = [
    [1, { attack_path_type: 'sql_injection' }],
    [2, { attack_path_type: 'sql_injection' }],
    [3, { skill_workflow: { skillId: 'user_skill:skalice', kind: 'user', contentSha256: sha16('Enumerate example.com.') } }],
    [4, { skill_workflow: { skillId: 'user_skill:skcreds', kind: 'user', contentSha256: 'x' } }],
    [5, { skill_workflow: { skillId: 'user_skill:skquar', kind: 'user', contentSha256: 'x' } }],
    [6, { skill_workflow: { skillId: 'user_skill:skgone', kind: 'user', contentSha256: 'x' } }],
    [7, { skill_workflow: { skillId: 'user_skill:skbob', kind: 'user', contentSha256: 'x' } }],
  ]
  db.seed('chatMessage', turns.map(([n, data]) => ({
    conversationId: ALICE_CONV, sequenceNum: n, type: 'phase_update', createdAt: new Date(Date.UTC(2026, 9, 9, 10, 0, n)),
    data: { current_phase: 'informational', iteration_count: n, ...data },
  })))
}

let release: () => void = () => {}
beforeEach(async () => {
  install()
  h.eff = { userId: ALICE }
  h.session = { userId: ALICE, role: 'standard' }
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  const gate = new Promise<void>((r) => (release = r))
  runner = await startEchoRunner({
    'echo/echo': (call) => ({ result: { params: call.body.params } }),
    'echo/plain': (call) => ({ result: { params: call.body.params } }),
    'echo/sleep': () => gate.then(() => ({ result: {} })),
  })
})
afterEach(async () => {
  release()
  await settle()
  await runner.close()
  delete process.env.PLUGIN_RUNNER_URL
  delete process.env.PLUGIN_RUNNER_KEY
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const CONTEXT = { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION }
const run = async (action: string, body: unknown) => answer(await runAction(actionRequest('echo', action, body), actionParams('echo', action)))
const pick = (ref: string, extra: Record<string, unknown> = {}) => ({ kind: 'session.skill', ref, ...extra })
const jobRows = () => db.rows('pluginData').filter((r) => r.collection === JOBS_COLLECTION)

describe('a valid pick', () => {
  test('a user skill: the plugin receives the server\'s normalized pick, never what the browser claimed', async () => {
    const r = await run('echo', {
      context: CONTEXT,
      params: { pick: pick('user_skill:skalice', { point: 'skill.text', target: 'sql_injection', name: 'Forged', extra: true }), depth: 2 },
    })
    expect(r.status).toBe(200)
    expect(runner.actionCalls).toHaveLength(1)
    expect(runner.actionCalls[0].body.params).toEqual({
      pick: { kind: 'session.skill', point: 'user_skill.text', target: 'skalice', ref: 'user_skill:skalice' },
      depth: 2,
    })
  })

  test('a built-in skill', async () => {
    await run('echo', { context: CONTEXT, params: { pick: pick('sql_injection') } })
    expect(runner.actionCalls[0].body.params).toEqual({
      pick: { kind: 'session.skill', point: 'skill.text', target: 'sql_injection', ref: 'sql_injection' },
    })
  })

  test('an async action: the job records the pick, with the name, and its view shows it', async () => {
    const r = await run('sleep', { context: CONTEXT, params: { pick: pick('user_skill:skalice') } })
    expect(r.status).toBe(202)
    const jobId = r.body.jobId as string
    expect(runner.actionCalls[0].body.params).toEqual({
      pick: { kind: 'session.skill', point: 'user_skill.text', target: 'skalice', ref: 'user_skill:skalice' },
    })
    const stored = { kind: 'session.skill', point: 'user_skill.text', target: 'skalice', ref: 'user_skill:skalice', name: 'My SQLi flow' }
    expect((jobRows()[0].value as Record<string, unknown>).pick).toEqual(stored)
    const job = await answer(await getJob(jobGetRequest(jobId), jobParams(jobId)))
    expect(job.body).toMatchObject({ jobId, status: 'running', pick: stored })
  })

  test("a second start in the same session: 200 existing, naming the running job's pick, the runner not called again", async () => {
    const first = await run('sleep', { context: CONTEXT, params: { pick: pick('user_skill:skalice') } })
    const second = await run('sleep', { context: CONTEXT, params: { pick: pick('sql_injection') } })
    expect(second).toEqual({
      status: 200,
      body: {
        jobId: first.body.jobId,
        status: 'running',
        existing: true,
        pick: { kind: 'session.skill', point: 'user_skill.text', target: 'skalice', ref: 'user_skill:skalice', name: 'My SQLi flow' },
      },
    })
    expect(runner.actionCalls).toHaveLength(1)
    expect(jobRows()).toHaveLength(1)
  })

  test('a second start while a pick-less job runs: pick null', async () => {
    const first = await run('sleep', { context: CONTEXT, params: {} })
    const second = await run('sleep', { context: CONTEXT, params: { pick: pick('sql_injection') } })
    expect(second.body).toEqual({ jobId: first.body.jobId, status: 'running', existing: true, pick: null })
  })
})

describe('without a pick: the 1.0.0 behaviour', () => {
  test('params reach the plugin unchanged; a job records pick null', async () => {
    await run('echo', { context: CONTEXT, params: { hello: 'world' } })
    expect(runner.actionCalls[0].body.params).toEqual({ hello: 'world' })
    const r = await run('sleep', { context: CONTEXT })
    expect(runner.actionCalls[1].body.params).toEqual({})
    expect((jobRows()[0].value as Record<string, unknown>).pick).toBeNull()
    const job = await answer(await getJob(jobGetRequest(r.body.jobId as string), jobParams(r.body.jobId as string)))
    expect(job.body.pick).toBeNull()
  })

  test('an action whose item takes a pick still runs without one (an older UI)', async () => {
    expect((await run('echo', { context: CONTEXT, params: {} })).status).toBe(200)
  })
})

describe('a forged pick: 400 invalid_pick, the runner never called, no job', () => {
  const refused = async (action: string, body: unknown) => {
    const r = await run(action, body)
    expect(r.status).toBe(400)
    expect(r.body.code).toBe('invalid_pick')
    expect(runner.actionCalls).toEqual([])
    expect(jobRows()).toEqual([])
    return r
  }

  test('an action no chat item asks a pick for', async () => {
    await refused('plain', { context: CONTEXT, params: { pick: pick('sql_injection') } })
  })

  test("a pick on a plugin whose manifest has no pick item at all", async () => {
    install({ contributes: { 'chat.session.actions': [{ label: 'Echo', action: 'echo' }] } })
    await refused('echo', { context: CONTEXT, params: { pick: pick('sql_injection') } })
  })

  test("another user's skill (an imported session naming it)", async () => {
    await refused('echo', { context: CONTEXT, params: { pick: pick('user_skill:skbob') } })
  })

  test('a skill of the user that this session never used', async () => {
    await refused('echo', { context: CONTEXT, params: { pick: pick('user_skill:skunused') } })
    await refused('echo', { context: CONTEXT, params: { pick: pick('xss') } })
  })

  test("a skill the session used, asked from another of the user's sessions", async () => {
    await refused('echo', { context: { projectId: ALICE_OTHER_PROJECT, sessionId: ALICE_OTHER_SESSION }, params: { pick: pick('user_skill:skalice') } })
  })

  test.each([
    ['holding credentials', 'user_skill:skcreds'],
    ['quarantined', 'user_skill:skquar'],
    ['deleted', 'user_skill:skgone'],
  ])('a skill that cannot be picked (%s)', async (_n, ref) => {
    await refused('echo', { context: CONTEXT, params: { pick: pick(ref) } })
  })

  test('a point the admin did not grant: the user skill is refused, a built-in one still passes', async () => {
    install({ grantedPermissions: ['session:read', 'llm:invoke', 'override:skill.text'] })
    await refused('echo', { context: CONTEXT, params: { pick: pick('user_skill:skalice') } })
    expect((await run('echo', { context: CONTEXT, params: { pick: pick('sql_injection') } })).status).toBe(200)
  })

  test('a point granted but not declared by the manifest', async () => {
    install({ permissions: ['session:read', 'llm:invoke', 'override:skill.text'] })
    await refused('echo', { context: CONTEXT, params: { pick: pick('user_skill:skalice') } })
  })

  test('no session in the context', async () => {
    await refused('echo', { context: { projectId: ALICE_PROJECT }, params: { pick: pick('sql_injection') } })
    await refused('echo', { params: { pick: pick('sql_injection') } })
  })

  test.each([
    ['not an object', 'sql_injection'],
    ['null', null],
    ['another kind', { kind: 'session.target', ref: 'sql_injection' }],
    ['no ref', { kind: 'session.skill' }],
    ['a ref that is not text', { kind: 'session.skill', ref: 42 }],
  ])('a malformed pick (%s)', async (_n, p) => {
    await refused('echo', { context: CONTEXT, params: { pick: p } })
  })

  test('an async action: no job is left behind', async () => {
    await refused('sleep', { context: CONTEXT, params: { pick: pick('user_skill:skbob') } })
    expect(db.rows('pluginData')).toEqual([])
  })
})

describe('a result naming a user-skill proposal to review', () => {
  async function userSkillSet(owner = ALICE) {
    const { changeSetId } = await ov.propose({
      pluginId: 'echo', point: 'user_skill.text', scope: { type: 'user', id: owner }, targetGroup: 'skalice',
      parts: [{ targetKey: 'skalice/body', value: 'better', baseSha256: 'a'.repeat(64) }], createdBy: owner,
    })
    return changeSetId
  }

  test('kept when it is this plugin\'s set at that point in the caller\'s scope; dropped at another point or scope', async () => {
    const own = await userSkillSet()
    const bobs = await userSkillSet(BOB)
    const answers = [
      { extensionPoint: 'user_skill.text', changeSetId: own },
      { extensionPoint: 'skill.text', changeSetId: own },
      { extensionPoint: 'user_skill.text', changeSetId: bobs },
    ]
    let i = 0
    runner.options.actions!['echo/echo'] = () => ({ result: { reviewProposal: answers[i++] } })
    const results = []
    for (let k = 0; k < answers.length; k++) results.push((await run('echo', { context: CONTEXT, params: {} })).body.result as Record<string, unknown>)
    expect(results.map((r) => r.reviewProposal ?? null)).toEqual([{ extensionPoint: 'user_skill.text', changeSetId: own }, null, null])
  })

  test('in jobs/complete: the same check', async () => {
    const own = await userSkillSet()
    const { body } = await run('sleep', { context: CONTEXT, params: { pick: pick('user_skill:skalice') } })
    const token = runner.actionCalls[0].body.token as string
    await jobComplete(gatewayRequest('jobs/complete', { status: 'succeeded', result: { reviewProposal: { extensionPoint: 'user_skill.text', changeSetId: own } } }, { token }))
    const job = await answer(await getJob(jobGetRequest(body.jobId as string), jobParams(body.jobId as string)))
    expect(job.body).toMatchObject({ status: 'succeeded', result: { reviewProposal: { extensionPoint: 'user_skill.text', changeSetId: own } } })
    // The pick stays on the finished job, for the job window and Retry.
    expect(job.body.pick).toMatchObject({ ref: 'user_skill:skalice', name: 'My SQLi flow' })
  })
})

describe('sessionPick helpers', () => {
  const plugin = () => db.rows('pluginInstall').find((r) => r.pluginId === 'echo') as never

  test('pickablePoints: granted AND declared', () => {
    expect(pickablePoints(plugin())).toEqual(['skill.text', 'user_skill.text'])
    expect(pickablePoints({ grantedPermissions: ['override:user_skill.text'], manifest: { permissions: ALL } } as never)).toEqual(['user_skill.text'])
    expect(pickablePoints({ grantedPermissions: ALL, manifest: { permissions: ['override:skill.text'] } } as never)).toEqual(['skill.text'])
    expect(pickablePoints({ grantedPermissions: ALL, manifest: null } as never)).toEqual([])
  })

  test('actionPicksSessionSkill: only an item that names the action and asks the pick', () => {
    expect(actionPicksSessionSkill(plugin(), 'echo')).toBe(true)
    expect(actionPicksSessionSkill(plugin(), 'plain')).toBe(false)
    expect(actionPicksSessionSkill(plugin(), 'nope')).toBe(false)
    expect(actionPicksSessionSkill({ manifest: { contributes: { 'chat.session.actions': [{ action: 'echo', pick: 'other' }] } } } as never, 'echo')).toBe(false)
  })

  test("pickableSessionSkills: the session's skills of the plugin's points only", async () => {
    install({ grantedPermissions: ['session:read', 'override:user_skill.text'] })
    const skills = await pickableSessionSkills(plugin(), ALICE_CONV, ALICE)
    expect(skills.map((s) => s.ref).sort()).toEqual(['user_skill:skalice', 'user_skill:skbob', 'user_skill:skcreds', 'user_skill:skgone', 'user_skill:skquar'])
  })

  test('resolvePick throws InvalidPickError with a code', async () => {
    const e = await resolvePick(plugin(), 'echo', pick('user_skill:skunused'), ALICE_CONV, ALICE).catch((x: unknown) => x)
    expect(e).toBeInstanceOf(InvalidPickError)
    expect((e as InvalidPickError).code).toBe('invalid_pick')
    expect(await resolvePick(plugin(), 'echo', pick('sql_injection'), ALICE_CONV, ALICE)).toEqual({
      kind: 'session.skill', point: 'skill.text', target: 'sql_injection', ref: 'sql_injection', name: 'SQL Injection',
    })
  })
})

describe('jobs: the pick in the record', () => {
  test('startJob stores it; a record from before 1.1.0 (no pick key) reads as null', async () => {
    const p = { kind: 'session.skill' as const, point: 'user_skill.text', target: 'skalice', ref: 'user_skill:skalice', name: 'My SQLi flow' }
    const { job } = await startJob({
      pluginId: 'echo', userId: ALICE, actionId: 'sleep',
      context: { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION, conversationId: ALICE_CONV },
      deadline: new Date(Date.now() + 60_000), pick: p,
    })
    expect(job.pick).toEqual(p)
    expect(jobView(job).pick).toEqual(p)
    const legacy = { ...job } as Partial<Job>
    delete legacy.pick
    expect(jobView(legacy as Job).pick).toBeNull()
  })
})
