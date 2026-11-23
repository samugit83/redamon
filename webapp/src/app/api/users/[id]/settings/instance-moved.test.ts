/**
 * With RBAC_IDENTITY_ENABLED on, the TrafficMind capture policy is an instance setting
 * (step 2.4): the user settings PUT refuses a REAL change of it with 409
 * `moved_to_instance_settings` before anything is written or pushed, and lets through the
 * unchanged values the Global Settings page sends with every save. The GET tells the page to
 * use the instance settings for it. The tunnel is not moved: it is every person's own, run in
 * their own Kali sandbox (group 1), whatever the switch. With the switch off nothing of this
 * applies (Phase 1 rules). The capture gate reads the role fresh (T3).
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/users/[id]/settings/instance-moved.test.ts"
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
const h = vi.hoisted(() => ({
  ensureSandbox: vi.fn(),
  sandboxStatus: vi.fn(),
  push: vi.fn(),
  agentFetch: vi.fn(),
  findUnique: vi.fn(),
  upsert: vi.fn(),
  getSession: vi.fn(),
  fetch: vi.fn(),
  orch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      upsert: (...a: unknown[]) => h.upsert(...a),
      updateMany: vi.fn(async () => ({ count: 0 })),
    },
    instanceSettings: { findUnique: vi.fn(async () => null) },
    apiKeyRotationConfig: { findMany: vi.fn().mockResolvedValue([]), deleteMany: vi.fn(), upsert: vi.fn() },
    // The tunnel gate reads the account getSession answered (sharedToolAccess, step 3.9).
    user: { findUnique: async ({ where }: { where: { id: string } }) => { const s = await h.getSession(); return s && s.userId === where.id ? { id: s.userId, email: `${s.userId}@e2e.local`, role: s.role, password: 'x', createdAt: new Date(0), legacyGrants: [] } : null } },
    auditLog: { findFirst: vi.fn(async () => null), create: vi.fn(async () => ({})) },
  },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: vi.fn().mockResolvedValue(null),
  isInternalRequest: vi.fn(() => false),
  isScannerRequest: vi.fn(() => false),
  getSession: (...a: unknown[]) => h.getSession(...a),
  authzIdentityOf: async (s: unknown) => ({ session: s, principal: {}, actingAs: null }),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orch(...a) }))
vi.mock('@/lib/sandbox/gateway', () => ({
  ensureSandbox: (...a: unknown[]) => h.ensureSandbox(...a),
  sandboxStatus: (...a: unknown[]) => h.sandboxStatus(...a),
}))
vi.mock('@/lib/sandbox/agentCalls', () => ({ pushSandboxTunnel: (...a: unknown[]) => h.push(...a) }))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig() as Record<string, unknown>),
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
}))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: async () => null }))

import { GET, PUT } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { buildTemplate, templateToJson, validateAndParse, isValidationError } from '@/lib/apiKeysTemplate'

const STORED = {
  userId: 'admin-a', shodanApiKey: 'fake-shodan-1111', tunnelsEnabled: true,
  ngrokAuthtoken: 'fake-ngrok-token-1234', chiselServerUrl: '', chiselAuth: '',
  captureProxyEnabled: true, captureProxyPort: 8888, captureEgressBlockPrivate: true,
  captureProxyBodyRules: {},
}

// What the Global Settings page sends with every save: every key, the four tunnel fields as
// it read them (masked), no capture field.
const FULL_FORM = {
  shodanApiKey: '••••••••1111', tavilyApiKey: 'fake-new-tavily',
  tunnelsEnabled: true, ngrokAuthtoken: '••••••••1234', chiselServerUrl: '', chiselAuth: '',
  rotationConfigs: {},
}

const params = { params: Promise.resolve({ id: 'admin-a' }) }
const put = (body: unknown) => PUT(new NextRequest('http://redamon.test/api/users/admin-a/settings', {
  method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
}), params)

beforeEach(() => {
  for (const fn of Object.values(h)) fn.mockReset()
  h.findUnique.mockResolvedValue({ ...STORED })
  h.upsert.mockImplementation(async ({ update }: { update: Record<string, unknown> }) => ({ ...STORED, ...update }))
  h.getSession.mockResolvedValue({ userId: 'admin-a', role: 'admin' })
  h.fetch.mockResolvedValue(new Response('{}', { status: 200 }))
  h.orch.mockResolvedValue(new Response('{}', { status: 200 }))
  h.ensureSandbox.mockResolvedValue({ state: 'running', fresh: false, instance: 'a1b2c3' })
  h.sandboxStatus.mockResolvedValue({ instances: [{ instance: 'a1b2c3', view: 'own', state: 'running' }] })
  h.push.mockResolvedValue({ ok: true, status: 200 })
  h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ ngrok: { active: true }, chisel: { active: false } })))
  vi.stubGlobal('fetch', h.fetch)
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('switch on', () => {
  beforeEach(() => setFlagsForTests({ identity: true }))

  test.each([
    ['the capture switch', { captureProxyEnabled: false }, ['captureProxyEnabled']],
    ['an egress toggle', { captureEgressBlockPrivate: false }, ['captureEgressBlockPrivate']],
    ['the SCA ignore list', { scaIntelIgnoreSuffixes: 'example.test' }, ['scaIntelIgnoreSuffixes']],
  ])('a real change of a moved field refused with the switch on: %s', async (_name, change, fields) => {
    const res = await put({ ...FULL_FORM, ...change })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'moved_to_instance_settings', fields })
    expect(h.upsert).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
    expect(h.push).not.toHaveBeenCalled()
    expect(h.orch).not.toHaveBeenCalled()
  })

  test.each([
    ['a tunnel credential', { ngrokAuthtoken: 'fake-other-token' }, { ngrokAuthtoken: 'fake-other-token', chiselServerUrl: '', chiselAuth: '' }],
    ['the tunnel switch', { tunnelsEnabled: false }, { ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }],
  ])('a tunnel change is the person\'s own, never moved: %s is saved in their row and pushed to their own sandbox', async (_name, change, pushed) => {
    const res = await put({ ...FULL_FORM, ...change })
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].update).toMatchObject(change)
    expect(h.push.mock.calls).toEqual([['admin-a', pushed]])
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('a member\'s real change is refused the same way, before the capture fields are dropped', async () => {
    h.getSession.mockResolvedValue({ userId: 'admin-a', role: 'standard' })
    const res = await put({ captureEgressBlockPrivate: false })
    expect(res.status).toBe(409)
  })

  test('a full-form save with unchanged tunnel fields succeeds: the keys are saved, nothing is pushed', async () => {
    const res = await put(FULL_FORM)
    expect(res.status).toBe(200)
    const update = h.upsert.mock.calls[0][0].update
    expect(update).toMatchObject({ tavilyApiKey: 'fake-new-tavily', shodanApiKey: 'fake-shodan-1111' })
    expect(h.fetch).not.toHaveBeenCalled()
    expect(h.push).not.toHaveBeenCalled()
  })

  test('a capture field sent with its stored value is no change', async () => {
    expect((await put({ captureProxyPort: '8888', captureEgressBlockPrivate: true, captureProxyBodyRules: {} })).status).toBe(200)
  })

  test('the API-keys template import succeeds: its tunneling part is the importing person\'s own tunnel', async () => {
    const template = templateToJson(buildTemplate(
      { shodanApiKey: 'fake-shodan-imported' },
      { ngrokAuthtoken: 'fake-template-token', chiselServerUrl: 'https://chisel.template.test', chiselAuth: '' },
    ))
    const parsed = validateAndParse(template, template.length)
    if (isValidationError(parsed)) throw new Error(parsed.message)
    const hint = await (await GET(new NextRequest('http://redamon.test/api/users/admin-a/settings'), params)).json()
    expect(hint).toMatchObject({ canManageTunnels: true, tunnelScope: 'own_sandbox' })
    // The page's confirmImport: the tunneling part only when it may manage the tunnel.
    const merged = { ...FULL_FORM, ...parsed.keys, ...(hint.canManageTunnels ? parsed.tunneling : {}) }
    const res = await put({ ...merged, stepUpPassword: 'x' })
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].update).toMatchObject({ shodanApiKey: 'fake-shodan-imported', ngrokAuthtoken: 'fake-template-token' })
    expect(h.push.mock.calls.map((c) => c[0])).toEqual(['admin-a'])
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('the GET sends the page to the instance settings for the capture, and says the tunnel is the person\'s own', async () => {
    const body = await (await GET(new NextRequest('http://redamon.test/api/users/admin-a/settings'), params)).json()
    expect(body).toMatchObject({ canManageTunnels: true, sharedSettingsAt: 'instance', tunnelScope: 'own_sandbox' })
  })
})

describe('switch off: Phase 1 rules', () => {
  beforeEach(() => setFlagsForTests({ identity: false }))

  test('an admin\'s tunnel change is saved and pushed to their own sandbox, no 409', async () => {
    const res = await put({ ...FULL_FORM, tunnelsEnabled: false })
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].update).toMatchObject({ tunnelsEnabled: false })
    expect(h.push.mock.calls).toEqual([['admin-a', { ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }]])
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('an admin\'s capture change is saved; the capture gate reads the role fresh (T3)', async () => {
    const res = await put({ captureEgressBlockPrivate: false })
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].update).toMatchObject({ captureEgressBlockPrivate: false })
    expect(h.getSession).toHaveBeenCalledWith({ fresh: true })
    expect(h.getSession.mock.calls.every(([opts]) => opts?.fresh === true)).toBe(true)
  })

  test('the GET hint has no instance settings pointer', async () => {
    const body = await (await GET(new NextRequest('http://redamon.test/api/users/admin-a/settings'), params)).json()
    expect(body.canManageTunnels).toBe(true)
    expect(body).not.toHaveProperty('sharedSettingsAt')
  })
})
