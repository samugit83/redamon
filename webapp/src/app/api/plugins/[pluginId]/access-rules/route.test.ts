/**
 * GET and PUT /api/plugins/[pluginId]/access-rules (GV-16, step 6.9): whoever holds
 * platform:plugins reads and replaces the member permission sets a plugin is limited to. Only
 * member sets that exist may be named; a replacement commits with its audit row under the
 * permissions lock (the one deleteSet takes), or not at all; saving the same sets writes nothing.
 * The account is read again on every request (a demotion applies at once). With
 * RBAC_GOVERNANCE_ENABLED off the routes do not exist.
 *
 * Real session helpers, tokens and resolution; the database is the in-memory accountDb
 * (transactions roll back).
 *
 * Run: npx vitest run --no-file-parallelism 'src/app/api/plugins/[pluginId]/access-rules/route.test.ts'
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { MAX_RULE_SETS } from '@/lib/plugins/accessRuleAdmin'
import { GET, PUT } from './route'

const db = () => h.db as AccountDb
const ROOT = 'root-1'

function req(method: string, body?: unknown, origin?: string): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json' }
  if (origin) headers.origin = origin
  return new NextRequest('http://redamon.test/api/plugins/echo/access-rules', {
    method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (pluginId: string) => ({ params: Promise.resolve({ pluginId }) })

async function as(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

type Answer = { status: number; body: Record<string, unknown> }
const answer = async (res: Response): Promise<Answer> => ({ status: res.status, body: await res.json().catch(() => ({})) })
const read = async (actor: string, pluginId = 'echo') => { await as(actor); return answer(await GET(req('GET'), params(pluginId))) }
const save = async (actor: string, body: unknown, opts: { pluginId?: string; origin?: string } = {}) => {
  await as(actor)
  return answer(await PUT(req('PUT', body, opts.origin), params(opts.pluginId ?? 'echo')))
}
const rulesOf = (pluginId: string) => db().pluginRules().filter((r) => r.pluginId === pluginId).map((r) => r.setId).sort()

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin' },
    { id: 'admin-1', role: 'admin' },
    { id: 'admin-p', role: 'admin', adminProfileId: 'builtin:platform-operator' },
    { id: 'admin-u', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'member-1' },
  ])
  db().seedSet({ id: 'set-red', kind: 'member', name: 'Red team', permissions: ['plugins:use'] })
  db().seedSet({ id: 'set-blue', kind: 'member', name: 'Blue team', permissions: ['plugins:use'] })
  db().seedSet({ id: 'set-manager', kind: 'admin', name: 'Manager', permissions: ['users:read'] })
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true, governance: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('GET', () => {
  test('a plugin admin reads the rules and the member sets a rule may name (built-ins first, no admin profile)', async () => {
    db().seedPluginRule('echo', 'set-red')
    db().seedPluginRule('other', 'set-blue')
    const { status, body } = await read('admin-p')
    expect(status).toBe(200)
    expect(body.pluginId).toBe('echo')
    expect(body.setIds).toEqual(['set-red'])
    const sets = body.sets as Array<{ id: string; name: string; builtin: boolean }>
    expect(sets.map((s) => s.id)).toEqual([
      'builtin:default-member', 'builtin:read-only-analyst', 'builtin:recon-operator', 'builtin:red-team-operator',
      'builtin:automation', 'builtin:no-access', 'set-blue', 'set-red',
    ])
    expect(sets.find((s) => s.id === 'set-red')).toEqual({ id: 'set-red', name: 'Red team', builtin: false })
  })

  test('no rule: an empty list, the plugin is everyone’s', async () => {
    expect((await read('admin-1')).body.setIds).toEqual([])
  })

  test('without platform:plugins: 403 naming it; signed out: 401; a malformed plugin id: 404', async () => {
    expect(await read('admin-u')).toMatchObject({ status: 403, body: { permission: 'platform:plugins' } })
    expect(await read('member-1')).toMatchObject({ status: 403, body: { permission: 'platform:plugins' } })
    h.jar = {}
    expect((await answer(await GET(req('GET'), params('echo')))).status).toBe(401)
    expect((await read('admin-1', 'Not A Plugin')).status).toBe(404)
  })
})

describe('PUT', () => {
  test('replaces the rules with exactly the sets given, with one audit row naming before and after', async () => {
    db().seedPluginRule('echo', 'set-blue')
    const r = await save('admin-p', { setIds: ['set-red', 'builtin:recon-operator', 'set-red'] })
    expect(r).toMatchObject({ status: 200, body: { pluginId: 'echo', setIds: ['builtin:recon-operator', 'set-red'] } })
    expect(rulesOf('echo')).toEqual(['builtin:recon-operator', 'set-red'])
    expect(db().pluginRules().find((x) => x.setId === 'set-red')).toMatchObject({ createdById: 'admin-p' })
    expect(db().audit()).toEqual([expect.objectContaining({
      action: 'plugin.access_rules_changed', actorId: 'admin-p', targetType: 'plugin', targetId: 'echo', permission: 'platform:plugins',
      before: { setIds: ['set-blue'] }, after: { setIds: ['builtin:recon-operator', 'set-red'] },
    })])
    expect(db().rawCalls.some((sql) => /pg_advisory_xact_lock/.test(sql))).toBe(true)
  })

  test('a kept set keeps its row (author and date); saving the same sets writes no audit row', async () => {
    db().seedPluginRule('echo', 'set-red')
    expect((await save('admin-1', { setIds: ['set-red', 'set-blue'] })).status).toBe(200)
    expect(db().pluginRules().find((x) => x.setId === 'set-red')).toMatchObject({ createdById: 'admin-1', createdAt: new Date(0) })
    const rows = db().audit().length
    expect((await save('admin-1', { setIds: ['set-blue', 'set-red'] })).status).toBe(200)
    expect(db().audit()).toHaveLength(rows)
  })

  test('an empty list opens the plugin to everyone again; other plugins keep their rules', async () => {
    db().seedPluginRule('echo', 'set-red', 'set-blue')
    db().seedPluginRule('other', 'set-red')
    expect(await save('admin-1', { setIds: [] })).toMatchObject({ status: 200, body: { setIds: [] } })
    expect(rulesOf('echo')).toEqual([])
    expect(rulesOf('other')).toEqual(['set-red'])
  })

  test('only member sets that exist: an admin profile, a missing set or an unknown built-in is 400 and changes nothing', async () => {
    db().seedPluginRule('echo', 'set-red')
    for (const bad of ['set-manager', 'set-gone', 'builtin:full-admin', 'builtin:nope']) {
      expect(await save('admin-1', { setIds: ['set-blue', bad] })).toMatchObject({ status: 400, body: { code: 'unknown_set', setIds: [bad] } })
    }
    expect(rulesOf('echo')).toEqual(['set-red'])
    expect(db().audit()).toEqual([])
  })

  test.each([
    ['not a list', { setIds: 'set-red' }],
    ['a non-string id', { setIds: [7] }],
    ['an empty id', { setIds: [''] }],
    ['no setIds', {}],
    ['too many sets', { setIds: Array.from({ length: MAX_RULE_SETS + 1 }, (_, i) => `set-${i}`) }],
  ])('a malformed body (%s): 400 invalid_set_ids', async (_name, body) => {
    expect(await save('admin-1', body)).toMatchObject({ status: 400, body: { code: 'invalid_set_ids' } })
  })

  test('the audit row failing rolls the change back', async () => {
    db().seedPluginRule('echo', 'set-red')
    db().failAudit('plugin.access_rules_changed')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect((await save('admin-1', { setIds: ['set-blue'] })).status).toBe(500)
    err.mockRestore()
    expect(rulesOf('echo')).toEqual(['set-red'])
  })

  test('without platform:plugins: 403 and nothing written; cross-origin refused; a demotion applies at once', async () => {
    expect(await save('admin-u', { setIds: ['set-red'] })).toMatchObject({ status: 403, body: { permission: 'platform:plugins' } })
    expect(await save('member-1', { setIds: ['set-red'] })).toMatchObject({ status: 403 })
    expect((await save('admin-1', { setIds: ['set-red'] }, { origin: 'https://evil.example' })).body.code).toBe('cross_origin')
    expect(rulesOf('echo')).toEqual([])
    await as('admin-p')
    const token = h.jar.auth
    await db().user.update({ where: { id: 'admin-p' }, data: { adminProfileId: 'builtin:user-manager' } })
    clearPrincipalCacheForTests()
    h.jar.auth = token
    expect((await answer(await PUT(req('PUT', { setIds: ['set-red'] }), params('echo')))).status).toBe(403)
    expect(rulesOf('echo')).toEqual([])
  })
})

describe('switch off: the routes do not exist', () => {
  test.each([
    ['governance off', { identity: true, permissions: true }],
    ['every switch off', {}],
  ])('%s: 404 for GET and PUT, nothing read or written', async (_name, flags) => {
    setFlagsForTests(flags)
    db().seedPluginRule('echo', 'set-red')
    expect((await read('admin-1')).status).toBe(404)
    expect((await save('admin-1', { setIds: [] })).status).toBe(404)
    expect(rulesOf('echo')).toEqual(['set-red'])
    expect(db().audit()).toEqual([])
  })
})
