/**
 * Per-plugin allowlists (GV-16, step 6.9): a plugin with no rule is available to everyone holding
 * plugins:use; with rules, only to the people holding one of the listed permission sets, and always
 * to whoever holds platform:plugins. Asked for the account the plugin works for: the effective user
 * of an action start, the call token's user on every Gateway call. With RBAC_GOVERNANCE_ENABLED
 * off the rules are ignored and nothing is read (DV-30).
 *
 * The rule store and the account loader are doubles; the capability resolution (sets, profiles,
 * the instance default), the Gateway frame and the action route are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

type SetRow = { id: string; kind: string; name: string; permissions: string[] }
const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  rules: [] as { pluginId: string; setId: string }[],
  rulesFail: false,
  principals: new Map<string, Record<string, unknown>>(),
  sets: new Map<string, { id: string; kind: string; name: string; permissions: string[] }>(),
  eff: { userId: 'user-alice' } as { userId: string } | null,
}))
const readRules = vi.fn(async (pluginId?: string) => {
  if (h.rulesFail) throw Object.assign(new Error('db down'), { code: 'P1001' })
  return h.rules.filter((r) => pluginId === undefined || r.pluginId === pluginId)
})
const loadPrincipal = vi.fn(async (id: string) => h.principals.get(id) ?? null)
// The plugin world is the fake below; the capability resolution also reads the instance row and
// the custom sets, which the fake does not hold.
const extra: Record<string, unknown> = {
  instanceSettings: { findUnique: async () => null },
  permissionSet: {
    findMany: async ({ where }: { where: { id: { in: string[] } } }) =>
      where.id.in.flatMap((id) => (h.sets.has(id) ? [{ ...h.sets.get(id)! }] : [])),
  },
}
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => extra[k as string] ?? h.db[k as string] }) }))
vi.mock('./accessRuleStore', () => ({ readAccessRules: (pluginId?: string) => readRules(pluginId) }))
vi.mock('@/lib/authz/principal', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  loadPrincipal: (id: string) => loadPrincipal(id),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then((m) => m.overSessionEffectiveUser()))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => h.eff,
  getSession: async () => (h.eff ? { userId: h.eff.userId, role: 'standard' } : null),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ALICE, ALICE_PROJECT, ALICE_SESSION, BOB, CALL_SECRET, answer, echoInstall, echoManifest, gatewayRequest, seedWorld, token } from './__testing__/gatewayHarness'
import { actionParams, actionRequest, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { pluginAccessFor, pluginAllowedFor } from './accessRules'
import { withGateway } from './gateway'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { POST as dataGet } from '@/app/api/plugin-gateway/v1/data/get/route'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'

const CAROL = 'user-carol'
const ADMIN = 'user-admin'
const AUDITOR = 'user-auditor'
const DAVE = 'user-dave'
const RED: SetRow = { id: 'set-red', kind: 'member', name: 'Red team', permissions: ['plugins:use', 'project:create'] }

function account(id: string, over: Record<string, unknown> = {}) {
  return {
    id, email: `${id}@example.com`, name: id, role: 'standard', status: 'active', sessionVersion: 0,
    mustChangePassword: false, adminProfileId: null, hasPassword: true, createdAt: new Date(0), lastLoginAt: null,
    legacyGrants: [], permissionSets: [], permissionOverrides: [], ...over,
  }
}

const GOVERNANCE_ON = { identity: true, permissions: true, governance: true }
let db: FakePrisma

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  h.rules = []
  h.rulesFail = false
  h.eff = { userId: ALICE }
  h.sets = new Map([[RED.id, RED]])
  h.principals = new Map(Object.entries({
    [ALICE]: account(ALICE, { permissionSets: [RED.id] }),
    [BOB]: account(BOB, { permissionSets: ['builtin:recon-operator'] }),
    // Never assigned: the instance default set, none here, so Default member.
    [CAROL]: account(CAROL),
    [ADMIN]: account(ADMIN, { role: 'admin' }),
    [AUDITOR]: account(AUDITOR, { role: 'admin', adminProfileId: 'builtin:security-auditor' }),
    [DAVE]: account(DAVE, { status: 'disabled', permissionSets: [RED.id] }),
  }))
  readRules.mockClear()
  loadPrincipal.mockClear()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  setFlagsForTests(GOVERNANCE_ON)
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const limit = (pluginId: string, ...setIds: string[]) => {
  h.rules.push(...setIds.map((setId) => ({ pluginId, setId })))
}

describe('who may use a plugin', () => {
  test('no rule → everyone, and no account is read', async () => {
    for (const user of [ALICE, BOB, CAROL, AUDITOR]) expect(await pluginAllowedFor(user, 'echo')).toBe(true)
    expect(readRules).toHaveBeenCalledWith('echo')
    expect(loadPrincipal).not.toHaveBeenCalled()
  })

  test('rule → only holders of a listed set; a plugin without rules stays everyone’s', async () => {
    limit('echo', RED.id)
    expect(await pluginAllowedFor(ALICE, 'echo')).toBe(true)
    expect(await pluginAllowedFor(BOB, 'echo')).toBe(false)
    expect(await pluginAllowedFor(CAROL, 'echo')).toBe(false)
    expect(await pluginAllowedFor(BOB, 'other')).toBe(true)
  })

  test('holding any one of several listed sets is enough, a built-in set included', async () => {
    limit('echo', RED.id, 'builtin:recon-operator')
    expect(await pluginAllowedFor(BOB, 'echo')).toBe(true)
    expect(await pluginAllowedFor(CAROL, 'echo')).toBe(false)
  })

  test('the set a person resolves to counts: Default member for an account never assigned', async () => {
    limit('echo', 'builtin:default-member')
    expect(await pluginAllowedFor(CAROL, 'echo')).toBe(true)
    expect(await pluginAllowedFor(ALICE, 'echo')).toBe(false)
  })

  test('admin always: platform:plugins passes every rule; an admin profile without it does not', async () => {
    limit('echo', RED.id)
    expect(await pluginAllowedFor(ADMIN, 'echo')).toBe(true)
    expect(await pluginAllowedFor(AUDITOR, 'echo')).toBe(false)
    limit('echo', 'builtin:security-auditor')
    expect(await pluginAllowedFor(AUDITOR, 'echo')).toBe(true)
  })

  test('an account that is gone or disabled holds no set', async () => {
    limit('echo', RED.id)
    expect(await pluginAllowedFor('user-gone', 'echo')).toBe(false)
    expect(await pluginAllowedFor(DAVE, 'echo')).toBe(false)
    expect(await pluginAllowedFor(DAVE, 'other')).toBe(true)
  })

  test('a list reads every rule once and answers per plugin', async () => {
    limit('echo', RED.id)
    limit('beta', 'builtin:recon-operator')
    const access = await pluginAccessFor(BOB)
    expect([access.allows('echo'), access.allows('beta'), access.allows('gamma')]).toEqual([false, true, true])
    expect(readRules).toHaveBeenCalledTimes(1)
    expect(readRules).toHaveBeenCalledWith(undefined)
  })

  test('a failed read throws: it never reads as allowed', async () => {
    h.rulesFail = true
    await expect(pluginAllowedFor(ALICE, 'echo')).rejects.toThrow('db down')
    await expect(pluginAccessFor(ALICE)).rejects.toThrow('db down')
  })

  test.each([
    ['governance off', { identity: true, permissions: true }],
    ['every switch off', {}],
  ])('switch off → ignored (%s): every plugin, nothing read', async (_name, flags) => {
    setFlagsForTests(flags)
    limit('echo', RED.id)
    expect(await pluginAllowedFor(BOB, 'echo')).toBe(true)
    expect((await pluginAccessFor(BOB)).allows('echo')).toBe(true)
    expect(readRules).not.toHaveBeenCalled()
    expect(loadPrincipal).not.toHaveBeenCalled()
  })
})

describe('the Gateway re-asks on every call, for the call token’s user', () => {
  const handler = vi.fn(async () => ({ ok: true }))
  const call = async (t: string) => {
    handler.mockClear()
    const r = await answer(await withGateway(gatewayRequest('x', {}, { token: t }), { op: 'x' }, handler))
    return { ...r, ran: handler.mock.calls.length > 0 }
  }

  test('Gateway refuses a non-holder’s session: 403 plugin_not_allowed, the handler never runs', async () => {
    limit('echo', 'builtin:recon-operator')
    const r = await call(await token())
    expect(r).toMatchObject({ status: 403, body: { code: 'plugin_not_allowed' }, ran: false })
    const viaRoute = await answer(await dataGet(gatewayRequest('data/get', { collection: 'notes', key: 'k1', owner: 'user' }, { token: await token() })))
    expect(viaRoute).toMatchObject({ status: 403, body: { code: 'plugin_not_allowed' } })
  })

  test('a holder’s session passes', async () => {
    limit('echo', RED.id)
    expect(await call(await token())).toMatchObject({ status: 200, ran: true })
  })

  test('a rule added while an action runs refuses its next call', async () => {
    const t = await token()
    expect((await call(t)).status).toBe(200)
    limit('echo', 'builtin:recon-operator')
    expect(await call(t)).toMatchObject({ status: 403, body: { code: 'plugin_not_allowed' }, ran: false })
  })

  test('the token’s user decides, not an admin behind an act-as call', async () => {
    limit('echo', 'builtin:recon-operator')
    expect((await call(await token({ act: ADMIN }))).status).toBe(403)
    expect((await call(await token({ sub: BOB, prj: undefined, ses: undefined, conv: undefined }))).status).toBe(200)
  })

  test('a job’s end report is kept as lapsed, not refused, so the job ends now', async () => {
    limit('echo', 'builtin:recon-operator')
    const t = await token({ kind: 'job', jid: 'job-1' })
    let lapsed: unknown = 'unset'
    const res = await withGateway(gatewayRequest('jobs/complete', {}, { token: t }), { op: 'jobs/complete', jobEnd: true }, async (ctx) => {
      lapsed = ctx.lapsed
      return { ok: true }
    })
    expect(res.status).toBe(200)
    expect(lapsed).toMatchObject({ code: 'plugin_not_allowed' })
  })

  test('switch off → ignored: the rule refuses nothing and is not read', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    limit('echo', 'builtin:recon-operator')
    expect((await call(await token())).status).toBe(200)
    expect(readRules).not.toHaveBeenCalled()
  })
})

describe('an action start, for the effective user', () => {
  let runner: FakeRunner
  beforeEach(async () => {
    vi.stubEnv('ACCESS_ENFORCE', '')
    db = createFakePrisma()
    h.db = db as unknown as Record<string, unknown>
    seedWorld(db, { install: echoInstall({ manifest: echoManifest({ actions: [{ id: 'echo', entry: 'engine/main.py:echo', timeoutSeconds: 30 }] }) }) })
    runner = await startEchoRunner({ 'echo/echo': (c) => ({ result: { echo: c.body.params } }) })
  })
  afterEach(async () => {
    await runner.close()
    delete process.env.PLUGIN_RUNNER_URL
    delete process.env.PLUGIN_RUNNER_KEY
  })

  const start = async () =>
    answer(await runAction(
      actionRequest('echo', 'echo', { context: { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION }, params: {} }),
      actionParams('echo', 'echo'),
    ))

  test('a non-holder is refused before a call token exists or the runner is asked', async () => {
    limit('echo', 'builtin:recon-operator')
    const r = await start()
    expect(r).toMatchObject({ status: 403, body: { code: 'plugin_not_allowed' } })
    expect(runner.actionCalls).toHaveLength(0)
  })

  test('a holder runs it', async () => {
    limit('echo', RED.id)
    expect(await start()).toMatchObject({ status: 200, body: { ok: true } })
    expect(runner.actionCalls).toHaveLength(1)
  })

  test('switch off → ignored', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    limit('echo', 'builtin:recon-operator')
    expect((await start()).status).toBe(200)
  })
})
