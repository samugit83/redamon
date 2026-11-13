/**
 * Per-plugin allowlists (GV-16, step 6.9) at the plugin screens: the Plugins page and a plugin's
 * entry hide a plugin from a person who may not use it (who manages plugins still sees every one),
 * its icon and its nav page answer 404, the contributions and the Models-by-feature tiles leave it
 * out, a job of it is not readable, and its skill picker refuses with 403 `plugin_not_allowed`.
 * With RBAC_GOVERNANCE_ENABLED off every plugin shows, as before.
 *
 * The rule store, the account loader and the Plugins page model are doubles; the decision
 * (accessRules.ts over the real capability resolution) and the routes are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  rules: [] as { pluginId: string; setId: string }[],
  principals: new Map<string, Record<string, unknown>>(),
  eff: { userId: 'user-alice' } as { userId: string } | null,
  manages: false,
}))
const readRules = vi.fn(async (pluginId?: string) => h.rules.filter((r) => pluginId === undefined || r.pluginId === pluginId))
const extra: Record<string, unknown> = {
  instanceSettings: { findUnique: async () => null },
  permissionSet: { findMany: async () => [] },
}
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => extra[k as string] ?? h.db[k as string] }) }))
vi.mock('@/lib/plugins/accessRuleStore', () => ({ readAccessRules: (pluginId?: string) => readRules(pluginId) }))
vi.mock('@/lib/authz/principal', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  loadPrincipal: async (id: string) => h.principals.get(id) ?? null,
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then((m) => m.overEffectiveUser()))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => h.eff,
  getSession: async () => (h.eff ? { userId: h.eff.userId, role: 'standard' } : null),
}))
vi.mock('@/lib/plugins/pageModel', async (orig) => {
  const entry = (id: string) => ({ id, displayName: id, description: '', inCatalog: true, state: 'enabled', installed: null, available: null, update: null, installBlocked: null })
  return {
    ...((await orig()) as Record<string, unknown>),
    viewerIsAdmin: async () => h.manages,
    buildPluginsPage: async (manages: boolean) => ({
      platformVersion: '1.1.0', managesPlugins: manages, catalog: { state: 'ok' }, plugins: [entry('beta'), entry('echo')],
    }),
    buildPluginDetail: async (id: string) => ({ plugin: entry(id) }),
  }
})
vi.mock('@/lib/plugins/pluginIcon', () => ({
  loadPluginIcon: async () => ({ bytes: Buffer.from('png'), type: 'image/png', sha256: 'ab'.repeat(32) }),
}))
vi.mock('next/navigation', () => ({
  notFound: () => {
    throw new Error('NEXT_NOT_FOUND')
  },
}))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { ALICE, BOB, echoInstall, echoManifest } from '@/lib/plugins/__testing__/gatewayHarness'
import { startJob } from '@/lib/plugins/jobs'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { GET as listRoute } from './route'
import { GET as detailRoute } from './[pluginId]/route'
import { GET as iconRoute } from './[pluginId]/icon/route'
import { GET as contributionsRoute } from './contributions/route'
import { GET as llmFeaturesRoute } from './llm-features/route'
import { GET as jobRoute } from './jobs/[jobId]/route'
import { GET as sessionSkillsRoute } from './[pluginId]/session-skills/route'
import PluginNavPage from '@/app/plugins/[pluginId]/[[...screen]]/page'

const APP = 'http://localhost:3000'
const ADMIN = 'user-admin'
let db: FakePrisma

function account(id: string, over: Record<string, unknown> = {}) {
  return {
    id, email: `${id}@example.com`, name: id, role: 'standard', status: 'active', sessionVersion: 0,
    mustChangePassword: false, adminProfileId: null, hasPassword: true, createdAt: new Date(0), lastLoginAt: null,
    legacyGrants: [], permissionSets: [], permissionOverrides: [], ...over,
  }
}

const withScreens = (id: string) =>
  echoInstall({
    pluginId: id,
    manifest: echoManifest({
      id,
      displayName: id,
      screens: ['ui/home.json'],
      contributes: { nav: { label: `${id} page`, icon: 'puzzle', screen: 'ui/home.json' } },
    }),
  })

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  db.seed('user', [{ id: ALICE, email: 'alice@example.com', role: 'standard' }, { id: BOB, email: 'bob@example.com', role: 'standard' }])
  db.seed('pluginInstall', [withScreens('beta'), withScreens('echo')])
  h.rules = []
  readRules.mockClear()
  h.eff = { userId: BOB }
  h.manages = false
  h.principals = new Map(Object.entries({
    [ALICE]: account(ALICE, { permissionSets: ['builtin:red-team-operator'] }),
    [BOB]: account(BOB, { permissionSets: ['builtin:recon-operator'] }),
    [ADMIN]: account(ADMIN, { role: 'admin' }),
  }))
  clearCapabilityCachesForTests()
  setFlagsForTests({ identity: true, permissions: true, governance: true })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

/** `echo` only for the red-team operator set. */
const limitEcho = () => h.rules.push({ pluginId: 'echo', setId: 'builtin:red-team-operator' })
const json = async (res: Response) => ({ status: res.status, body: (await res.json()) as unknown })
const ids = (body: unknown) => (body as { id?: string; pluginId?: string }[]).map((x) => x.id ?? x.pluginId)
const pluginParams = (pluginId: string) => ({ params: Promise.resolve({ pluginId }) })

describe('the Plugins page and a plugin’s entry', () => {
  const list = async () => json(await listRoute(new NextRequest(`${APP}/api/plugins`)))
  const detail = async (id: string) => json(await detailRoute(new NextRequest(`${APP}/api/plugins/${id}`), pluginParams(id)))

  test('no rule → everyone sees every plugin', async () => {
    expect(ids(((await list()).body as { plugins: unknown }).plugins)).toEqual(['beta', 'echo'])
    expect((await detail('echo')).status).toBe(200)
  })

  test('rule → a non-holder sees neither the card nor the entry (404, as an unknown plugin)', async () => {
    limitEcho()
    expect(ids(((await list()).body as { plugins: unknown }).plugins)).toEqual(['beta'])
    expect(await detail('echo')).toMatchObject({ status: 404, body: { code: 'not_found' } })
    expect((await detail('beta')).status).toBe(200)
  })

  test('rule → a holder sees it', async () => {
    limitEcho()
    h.eff = { userId: ALICE }
    expect(ids(((await list()).body as { plugins: unknown }).plugins)).toEqual(['beta', 'echo'])
    expect((await detail('echo')).status).toBe(200)
  })

  test('whoever manages plugins sees every plugin, to manage it', async () => {
    limitEcho()
    h.manages = true
    expect(ids(((await list()).body as { plugins: unknown }).plugins)).toEqual(['beta', 'echo'])
    expect((await detail('echo')).status).toBe(200)
  })

  test('switch off → ignored', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    limitEcho()
    expect(ids(((await list()).body as { plugins: unknown }).plugins)).toEqual(['beta', 'echo'])
    expect(readRules).not.toHaveBeenCalled()
  })
})

describe('the icon', () => {
  const icon = async (id: string) => (await iconRoute(new NextRequest(`${APP}/api/plugins/${id}/icon`), pluginParams(id))).status

  test('a non-holder gets 404 (the card falls back); a holder, an admin and everyone without a rule get it', async () => {
    expect(await icon('echo')).toBe(200)
    limitEcho()
    expect(await icon('echo')).toBe(404)
    expect(await icon('beta')).toBe(200)
    h.manages = true
    expect(await icon('echo')).toBe(200)
    h.manages = false
    h.eff = { userId: ALICE }
    expect(await icon('echo')).toBe(200)
  })
})

describe('what a plugin contributes to the UI', () => {
  test('the contributions leave out a plugin the person may not use; the admin exemption is the account’s', async () => {
    const items = async () => ids((await json(await contributionsRoute(new NextRequest(`${APP}/api/plugins/contributions`)))).body)
    expect(await items()).toEqual(['beta', 'echo'])
    limitEcho()
    expect(await items()).toEqual(['beta'])
    h.eff = { userId: ADMIN }
    expect(await items()).toEqual(['beta', 'echo'])
  })

  test('the Models-by-feature tiles too', async () => {
    const tiles = async () => ids((await json(await llmFeaturesRoute(new NextRequest(`${APP}/api/plugins/llm-features`)))).body)
    expect(await tiles()).toEqual(['beta', 'echo'])
    limitEcho()
    expect(await tiles()).toEqual(['beta'])
  })

  test('the nav page is a 404 for a non-holder and opens for a holder; switch off → it opens', async () => {
    const open = (id: string) => PluginNavPage({ params: Promise.resolve({ pluginId: id }), searchParams: Promise.resolve({}) })
    limitEcho()
    await expect(open('echo')).rejects.toThrow('NEXT_NOT_FOUND')
    await expect(open('beta')).resolves.toBeTruthy()
    h.eff = { userId: ALICE }
    await expect(open('echo')).resolves.toBeTruthy()
    h.eff = { userId: BOB }
    setFlagsForTests({ identity: true, permissions: true })
    await expect(open('echo')).resolves.toBeTruthy()
  })
})

describe('jobs and the skill picker', () => {
  test('a job of a plugin the person lost reads as not found', async () => {
    const { job } = await startJob({
      pluginId: 'echo', userId: BOB, actionId: 'sleep',
      context: { projectId: null, sessionId: null, conversationId: null }, deadline: new Date(Date.now() + 3_600_000),
    })
    const read = async () => (await jobRoute(new NextRequest(`${APP}/api/plugins/jobs/${job.jobId}`), { params: Promise.resolve({ jobId: job.jobId }) })).status
    expect(await read()).toBe(200)
    limitEcho()
    expect(await read()).toBe(404)
  })

  test('the skill picker refuses a non-holder with 403 plugin_not_allowed, before any session is read', async () => {
    limitEcho()
    const res = await sessionSkillsRoute(new NextRequest(`${APP}/api/plugins/echo/session-skills?sessionId=s1&projectId=p1`), pluginParams('echo'))
    expect(await json(res)).toMatchObject({ status: 403, body: { code: 'plugin_not_allowed' } })
  })
})
