/**
 * A plugin action started on a project shared with the person (step 5.10, SH-35). The action start
 * asks projectAccess() for the effective user at the levels the plugin's permissions need (Read +
 * Write; Use AI agent too for a plugin that may call a model; the owner's alone for one that declares
 * none) and answers a collaborator below them 403 naming the level, anyone else 404. The call token
 * names the person (`sub`) and the project's owner (`ten`); a model-calling action needs the
 * owner's model choice, never the person's; a session is the person's own; a proposal on the
 * project's scope opens the review window only for someone who decides it (Manage).
 *
 * The policy answer is doubled (its own tests prove how a share reads); the level table, the route,
 * the token, the runner client (a fake runner) and the stores are real.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  eff: { userId: 'user-bob' } as { userId: string } | null,
  session: { userId: 'user-bob', role: 'standard' } as { userId: string; role: string } | null,
  actingAs: null as null | { id: string },
}))
vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_request: Request, permission: string) =>
    h.eff ? { permission, actingAs: h.actingAs, effective: h.eff } : NextResponse.json({ error: 'Unauthorized' }, { status: 401 }),
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => h.eff,
  getSession: async () => h.session,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/authz/projectAccess', async (orig) => {
  const actual = await orig<typeof import('@/lib/authz/projectAccess')>()
  return { ...actual, projectAccess: vi.fn(actual.projectAccess) }
})

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ALICE, ALICE_PROJECT, ALICE_SESSION, BOB, CALL_SECRET, answer, echoInstall, echoManifest, seedWorld } from './__testing__/gatewayHarness'
import { actionParams, actionRequest, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { verifyCallToken } from './callToken'
import * as ov from './overrides'
import { projectAccess, type ProjectAccess, type ProjectAccessToggles } from '@/lib/authz/projectAccess'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'
import { GET as sessionSkills } from '@/app/api/plugins/[pluginId]/session-skills/route'
import { NextRequest } from 'next/server'

const BOB_ON_ALICE = 'session-bob-on-alice'
const MODEL = 'openai/gpt-test'
const policy = vi.mocked(projectAccess)

const access = (level: ProjectAccess['level'], toggles: Partial<ProjectAccessToggles> = {}, via: ProjectAccess['via'] = 'share'): ProjectAccess =>
  Object.freeze({
    project: Object.freeze({ id: ALICE_PROJECT, userId: ALICE }),
    level,
    toggles: Object.freeze({ rawData: level !== 'read', ...toggles }),
    via,
  }) as ProjectAccess
const editor = (toggles: Partial<ProjectAccessToggles> = {}) => access('write', toggles)

let db: FakePrisma
let runner: FakeRunner

function install(over: Record<string, unknown> = {}) {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db, {
    install: echoInstall({
      manifest: echoManifest({
        actions: [
          { id: 'echo', entry: 'engine/main.py:echo', timeoutSeconds: 30 },
          { id: 'think', entry: 'engine/main.py:think', timeoutSeconds: 60, llm: true },
        ],
      }),
      ...over,
    }),
  })
  db.seed('conversation', [{ id: 'conv-bob-on-alice', sessionId: BOB_ON_ALICE, userId: BOB, projectId: ALICE_PROJECT }])
}

beforeEach(async () => {
  install()
  h.eff = { userId: BOB }
  h.session = { userId: BOB, role: 'standard' }
  h.actingAs = null
  policy.mockReset()
  policy.mockResolvedValue(editor({ useAgent: true }))
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  runner = await startEchoRunner({
    'echo/echo': () => ({ result: { done: true } }),
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

const run = async (action = 'echo', context: Record<string, unknown> = { projectId: ALICE_PROJECT, sessionId: BOB_ON_ALICE }) =>
  answer(await runAction(actionRequest('echo', action, { context, params: {} }), actionParams('echo', action)))

describe('a collaborator with access', () => {
  test('runs the action as themself; the token names them and the project owner as tenant', async () => {
    const r = await run()
    expect(r).toEqual({ status: 200, body: { ok: true, result: { done: true } } })
    const claims = await verifyCallToken(runner.actionCalls[0].body.token as string, { kinds: ['action'] })
    expect(claims).toMatchObject({ sub: BOB, ten: ALICE, prj: ALICE_PROJECT, ses: BOB_ON_ALICE, conv: 'conv-bob-on-alice' })
    expect(claims).not.toHaveProperty('act')
    expect(runner.actionCalls[0].body.ctx).toMatchObject({ userId: BOB, projectId: ALICE_PROJECT })
    expect(policy).toHaveBeenCalledWith({ userId: BOB }, ALICE_PROJECT)
  })

  test("the owner's own run names the owner as tenant", async () => {
    h.eff = { userId: ALICE }
    h.session = { userId: ALICE, role: 'standard' }
    policy.mockResolvedValue(access('owner', {}, 'owner'))
    expect((await run('echo', { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION })).status).toBe(200)
    const claims = await verifyCallToken(runner.actionCalls[0].body.token as string, { kinds: ['action'] })
    expect(claims).toMatchObject({ sub: ALICE, ten: ALICE })
  })

  test('outside a project the tenant is the person', async () => {
    expect((await run('echo', {})).status).toBe(200)
    const claims = await verifyCallToken(runner.actionCalls[0].body.token as string, { kinds: ['action'] })
    expect(claims).toMatchObject({ sub: BOB, ten: BOB })
    expect(policy).not.toHaveBeenCalled()
  })
})

describe('below the plugin\'s levels', () => {
  test('a model-calling plugin without Use AI agent: 403 naming W+A, the runner never called', async () => {
    policy.mockResolvedValue(editor({ useAgent: false, exploit: true, manage: true }))
    expect(await run()).toEqual({
      status: 403,
      body: { error: expect.stringMatching(/plugins:use, level W\+A/), code: 'forbidden', permission: 'plugins:use', level: 'W+A' },
    })
    expect(runner.actionCalls).toEqual([])
  })

  test('a plugin that calls no model runs at Read + Write without Use AI agent', async () => {
    install({ grantedPermissions: ['session:read', 'override:skill.text'] })
    policy.mockResolvedValue(editor())
    expect((await run()).status).toBe(200)
  })

  test('a read share: 403 naming W', async () => {
    policy.mockResolvedValue(access('read', { rawData: true }))
    expect(await run()).toMatchObject({ status: 403, body: { code: 'forbidden', level: 'W' } })
    expect(runner.actionCalls).toEqual([])
  })

  test("a plugin that declares no permission stays the owner's: 403 naming O", async () => {
    install({ grantedPermissions: [], manifest: echoManifest({ permissions: [], llmFeature: undefined, actions: [{ id: 'echo', entry: 'engine/main.py:echo', timeoutSeconds: 30 }] }) })
    policy.mockResolvedValue(editor({ useAgent: true, runScans: true, exploit: true, manage: true }))
    expect(await run()).toMatchObject({ status: 403, body: { level: 'O' } })
  })

  test.each([
    ['oversight', access('read', {}, 'oversight')],
    ['break-glass', access('read', { rawData: true }, 'break_glass')],
  ])('%s never runs a plugin: 404 like an unknown project', async (_what, reached) => {
    policy.mockResolvedValue(reached)
    expect(await run()).toMatchObject({ status: 404, body: { code: 'not_found' } })
  })

  test('no access: 404', async () => {
    policy.mockResolvedValue(null)
    expect(await run()).toMatchObject({ status: 404 })
  })
})

describe('the session', () => {
  test("the owner's session on the shared project is a 404 to the collaborator, whatever their toggles", async () => {
    policy.mockResolvedValue(editor({ useAgent: true, runScans: true, exploit: true, manage: true }))
    expect(await run('echo', { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION })).toMatchObject({ status: 404 })
    expect(runner.actionCalls).toEqual([])
  })

  test('the skill picker follows the same levels and the same session rule', async () => {
    const pick = (sessionId: string) =>
      sessionSkills(new NextRequest(`http://localhost:3000/api/plugins/echo/session-skills?sessionId=${sessionId}&projectId=${ALICE_PROJECT}`), { params: Promise.resolve({ pluginId: 'echo' }) })
    policy.mockResolvedValue(editor({ useAgent: false }))
    expect(await answer(await pick(BOB_ON_ALICE))).toMatchObject({ status: 403, body: { level: 'W+A' } })
    policy.mockResolvedValue(editor({ useAgent: true, manage: true }))
    expect(await answer(await pick(ALICE_SESSION))).toMatchObject({ status: 404 })
  })
})

describe('the model a model-calling action spends', () => {
  test("the owner's choice opens it, whatever the collaborator chose", async () => {
    db.seed('userSettings', [{ userId: ALICE, featureModels: { 'plugin:echo': MODEL } }])
    expect(await run('think')).toEqual({ status: 200, body: { ok: true, result: { thought: true } } })
  })

  test('the owner chose none: 409 owner_model_required (not the model gate), though the collaborator chose one', async () => {
    db.seed('userSettings', [{ userId: BOB, featureModels: { 'plugin:echo': MODEL } }])
    expect(await run('think')).toEqual({
      status: 409,
      body: { error: expect.stringMatching(/owner has not chosen a model/), code: 'owner_model_required', featureId: 'plugin:echo' },
    })
    expect(runner.actionCalls).toEqual([])
  })
})

describe('an admin acting as the collaborator', () => {
  test('the share is asked as acted (read at most, D-22): refused, the token never minted', async () => {
    h.session = { userId: 'user-admin', role: 'admin' }
    h.actingAs = { id: BOB }
    policy.mockResolvedValue(access('read'))
    expect(await run()).toMatchObject({ status: 403, body: { level: 'W' } })
    expect(policy).toHaveBeenCalledWith({ userId: BOB }, ALICE_PROJECT, { actingAs: true })
    expect(runner.actionCalls).toEqual([])
  })
})

describe('a proposal on the project scope', () => {
  async function projectSet() {
    const { changeSetId } = await ov.propose({
      pluginId: 'echo',
      point: 'skill.text',
      scope: { type: 'project', id: ALICE_PROJECT },
      targetGroup: 'xxe',
      parts: [{ targetKey: 'xxe/tools', value: 'v', baseSha256: 'a'.repeat(64) }],
      createdBy: BOB,
    })
    return changeSetId
  }

  test('opens the review window only for someone who decides it (Manage)', async () => {
    const id = await projectSet()
    runner.options.actions!['echo/echo'] = () => ({ result: { reviewProposal: { extensionPoint: 'skill.text', changeSetId: id }, note: 'kept' } })
    policy.mockResolvedValue(editor({ useAgent: true }))
    expect((await run()).body.result).toEqual({ note: 'kept' })
    policy.mockResolvedValue(editor({ useAgent: true, manage: true }))
    expect((await run()).body.result).toEqual({ note: 'kept', reviewProposal: { extensionPoint: 'skill.text', changeSetId: id } })
  })
})
