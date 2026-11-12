/**
 * An admin acting as a user (R-07, R-68): the action runs as the effective user, whose
 * projects, sessions, data and model it reaches; the call token names the admin in `act`,
 * so what the plugin then proposes is audited with the admin as the actor.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  // The admin's own login, simulating Alice.
  getEffectiveUser: async () => ({ userId: 'user-alice' }),
  getSession: async () => ({ userId: 'user-admin', role: 'admin' }),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async (e: Record<string, unknown>) => void h.audits.push(e)) }))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ALICE, ALICE_PROJECT, ALICE_SESSION, CALL_SECRET, answer, seedWorld } from './__testing__/gatewayHarness'
import { actionParams, actionRequest, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { verifyCallToken } from './callToken'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'

let db: FakePrisma
let runner: FakeRunner

beforeEach(async () => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  db.seed('project', [{ id: 'project-admin', userId: 'user-admin', name: 'admin' }])
  h.audits = []
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  runner = await startEchoRunner({ 'echo/echo': () => ({ result: {} }) })
})
afterEach(async () => {
  await runner.close()
  delete process.env.PLUGIN_RUNNER_URL
  delete process.env.PLUGIN_RUNNER_KEY
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const run = async (context: Record<string, unknown>) =>
  answer(await runAction(actionRequest('echo', 'echo', { context, params: {} }), actionParams('echo', 'echo')))

test('the token acts for Alice and names the admin; the runner context is Alice', async () => {
  expect((await run({ projectId: ALICE_PROJECT, sessionId: ALICE_SESSION })).status).toBe(200)
  const claims = await verifyCallToken(runner.actionCalls[0].body.token as string, { kinds: ['action'] })
  expect(claims).toMatchObject({ sub: ALICE, act: 'user-admin', prj: ALICE_PROJECT })
  expect(runner.actionCalls[0].body.ctx).toMatchObject({ userId: ALICE })
})

describe.each(['', '0'])('ACCESS_ENFORCE=%j', (enforce) => {
  beforeEach(() => vi.stubEnv('ACCESS_ENFORCE', enforce))
  test("the admin's own project is not Alice's: 404", async () => {
    expect((await run({ projectId: 'project-admin' })).status).toBe(404)
    expect(runner.actionCalls).toEqual([])
  })
})

test('what the plugin proposes with that token is audited with the admin as the actor', async () => {
  await run({ projectId: ALICE_PROJECT })
  const token = runner.actionCalls[0].body.token as string
  const { auditPlugin } = await import('./audit')
  const claims = await verifyCallToken(token, { kinds: ['action'] })
  // The Gateway's override operations audit `act ?? sub` (overrideOps.ts).
  await auditPlugin('plugin.override.propose', { actorId: claims!.act ?? claims!.sub, pluginId: 'echo', targetType: 'plugin_change_set', targetId: 'cs' })
  expect(h.audits[0]).toMatchObject({ actorId: 'user-admin' })
})
