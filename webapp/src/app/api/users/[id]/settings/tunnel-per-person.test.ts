/**
 * Per-user Kali sandboxes (group 1, S17, I9; OD-G1-i, OQ-G1-2 default A): a person's tunnel is
 * their own row's four fields, pushed to their own sandbox only.
 *
 * The settings PUT keeps the tunnel fields in the person's own row whatever the identity switch
 * (never routed to the instance settings), and pushes them through the agent to that person's
 * sandbox, never to a fixed Kali address and never another person's fields.
 * Turning a tunnel on or changing its fields still takes platform:tunnels through the fresh
 * sharedToolAccess(principal, 'tunnels') of today's rule: only who may open the instance tunnel
 * today may open one from their own sandbox. Under act-as on a managed account the sandbox is that
 * account's, so the account must hold it too. Turning one's own tunnel off needs nothing. The GET
 * hint says the tunnel is the person's own.
 *
 * The session is mocked; the principal, the shared-tools rule, the audit row and the push logic
 * are the real code over a mocked Prisma, gateway and agent.
 *
 * Run: npx vitest run "src/app/api/users/[id]/settings/tunnel-per-person.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  upsert: vi.fn(),
  updateMany: vi.fn(),
  auditCreate: vi.fn(),
  cutoff: vi.fn(),
  ensureSandbox: vi.fn(),
  sandboxStatus: vi.fn(),
  pushSandboxTunnel: vi.fn(),
  agentFetch: vi.fn(),
}))

interface Account { role: string; legacyGrants: string[]; createdAt: Date; password?: string | null }
const accounts = new Map<string, Account>()
const userFindUnique = vi.fn(async (args: { where: { id: string } }) => {
  const a = accounts.get(args.where.id)
  return a ? { id: args.where.id, email: `${args.where.id}@e2e.local`, password: 'h', ...a } : null
})

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      upsert: (...a: unknown[]) => h.upsert(...a),
      updateMany: (...a: unknown[]) => h.updateMany(...a),
    },
    apiKeyRotationConfig: {
      findMany: vi.fn().mockResolvedValue([]),
      findUnique: vi.fn(),
      update: vi.fn(),
      deleteMany: vi.fn(),
      upsert: vi.fn(),
    },
    instanceSettings: { updateMany: vi.fn().mockResolvedValue({ count: 0 }), findUnique: vi.fn().mockResolvedValue(null) },
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    auditLog: {
      findFirst: (...a: unknown[]) => h.cutoff(...a),
      create: (...a: unknown[]) => h.auditCreate(...a),
    },
  },
}))

let session: { userId: string; role: string } | null = { userId: 'u1', role: 'admin' }
/** The account the signed-in admin acts as, or null. */
let actingAs: string | null = null
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: vi.fn().mockResolvedValue(null),
  isInternalRequest: vi.fn(() => false),
  isScannerRequest: vi.fn().mockReturnValue(false),
  getSession: vi.fn(async () => session),
  authzIdentityOf: vi.fn(async (s: unknown) => ({ session: s, principal: {}, actingAs: actingAs ? { id: actingAs } : null })),
}))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: vi.fn(async () => null) }))
vi.mock('@/lib/sandbox/gateway', () => ({
  ensureSandbox: (...a: unknown[]) => h.ensureSandbox(...a),
  sandboxStatus: (...a: unknown[]) => h.sandboxStatus(...a),
}))
vi.mock('@/lib/sandbox/agentCalls', () => ({ pushSandboxTunnel: (...a: unknown[]) => h.pushSandboxTunnel(...a) }))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig() as Record<string, unknown>),
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
}))

import { GET, PUT } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { resetTunnelEffectsForTests } from '@/lib/sharedSettingsEffects'

const EMPTY = { ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }
const AFTER_CUTOFF = new Date('2026-11-12T00:00:00.000Z')

function put(id: string, body: unknown): NextRequest {
  return new NextRequest(`http://x/api/users/${id}/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

/** Each account's own row; upsert echoes the merged row. */
const rows = new Map<string, Record<string, unknown>>()
function storeRow(id: string, row: Record<string, unknown>) {
  rows.set(id, { userId: id, tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', ...row })
}

function signInMember(id: string, legacyGrants: string[] = []) {
  accounts.set(id, { role: 'standard', legacyGrants, createdAt: AFTER_CUTOFF })
  session = { userId: id, role: 'standard' }
}

let fetchSpy: ReturnType<typeof vi.fn>
/** Anything sent to a fixed address instead of through the agent: never, after group 1. */
const directCalls = () => fetchSpy.mock.calls
const auditRows = (action: string) =>
  h.auditCreate.mock.calls.map(c => (c[0] as { data: Record<string, unknown> }).data).filter(d => d.action === action)

beforeEach(() => {
  for (const fn of Object.values(h)) fn.mockReset()
  resetTunnelEffectsForTests()
  resetSharedToolsForTests()
  rows.clear()
  accounts.clear()
  accounts.set('u1', { role: 'admin', legacyGrants: [], createdAt: AFTER_CUTOFF })
  session = { userId: 'u1', role: 'admin' }
  actingAs = null
  h.findUnique.mockImplementation(async ({ where }: { where: { userId: string } }) => rows.get(where.userId) ?? null)
  h.upsert.mockImplementation(async ({ where, update, create }: { where: { userId: string }; update: Record<string, unknown>; create: Record<string, unknown> }) => {
    const prev = rows.get(where.userId)
    rows.set(where.userId, prev ? { ...prev, ...update } : { tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', ...create })
    return rows.get(where.userId)
  })
  h.updateMany.mockImplementation(async ({ where, data }: { where: { userId: string; tunnelsEnabled?: boolean }; data: Record<string, unknown> }) => {
    const row = rows.get(where.userId)
    if (!row || (where.tunnelsEnabled !== undefined && row.tunnelsEnabled !== where.tunnelsEnabled)) return { count: 0 }
    rows.set(where.userId, { ...row, ...data })
    return { count: 1 }
  })
  h.auditCreate.mockResolvedValue({})
  h.cutoff.mockResolvedValue(null)
  h.ensureSandbox.mockResolvedValue({ state: 'running', fresh: false, instance: 'a1b2c3' })
  h.sandboxStatus.mockResolvedValue({ instances: [{ instance: 'a1b2c3', view: 'own', state: 'running' }] })
  h.pushSandboxTunnel.mockResolvedValue({ ok: true, status: 200 })
  h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ ngrok: { active: true }, chisel: { active: false } })))
  fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
  vi.stubGlobal('fetch', fetchSpy)
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  setFlagsForTests(null)
})

describe('the tunnel is the person\'s own row, pushed to their own sandbox', () => {
  test.each([['off', false], ['on', true]])('identity switch %s: saved in the person\'s row and pushed to their sandbox only', async (_n, identity) => {
    setFlagsForTests({ identity })
    storeRow('u1', {})
    const res = await PUT(put('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'ng-own' }), params('u1'))
    expect(res.status).toBe(200)
    expect(rows.get('u1')).toMatchObject({ tunnelsEnabled: true, ngrokAuthtoken: 'ng-own' })
    expect(h.pushSandboxTunnel.mock.calls).toEqual([['u1', { ngrokAuthtoken: 'ng-own', chiselServerUrl: '', chiselAuth: '' }]])
    expect(directCalls()).toEqual([])
    expect(auditRows('settings.tunnel_changed')[0]).toMatchObject({ targetId: 'u1', after: { fields: ['ngrokAuthtoken', 'tunnelsEnabled'] } })
  })

  test('identity switch on: a capture change is still moved to the instance settings', async () => {
    setFlagsForTests({ identity: true })
    storeRow('u1', {})
    const res = await PUT(put('u1', { captureProxyPort: 9999, tunnelsEnabled: true }), params('u1'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'moved_to_instance_settings', fields: ['captureProxyPort'] })
    expect(h.upsert).not.toHaveBeenCalled()
  })

  test('another person\'s credentials never reach the saving person\'s sandbox', async () => {
    storeRow('u1', {})
    storeRow('other', { tunnelsEnabled: true, ngrokAuthtoken: 'OTHER-person-token', chiselServerUrl: 'http://other.example' })
    await PUT(put('u1', { tunnelsEnabled: true, chiselServerUrl: 'http://mine.example:9090' }), params('u1'))
    expect(h.pushSandboxTunnel.mock.calls.map(c => c[0])).toEqual(['u1'])
    expect(JSON.stringify(h.pushSandboxTunnel.mock.calls)).not.toMatch(/OTHER|other\.example/)
    expect(JSON.stringify(fetchSpy.mock.calls)).not.toMatch(/OTHER/)
  })

  test('a stored "on" whose sandbox runs no tunnel (a lost reset): a credential change turns it off and says so', async () => {
    storeRow('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'old' })
    h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ ngrok: { active: false }, chisel: { active: false } })))
    const res = await PUT(put('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'new-token' }), params('u1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.tunnelsEnabled).toBe(false)
    expect(body.warnings).toEqual([expect.objectContaining({ code: 'tunnel_off_sandbox_restarted' })])
    expect(rows.get('u1')!.tunnelsEnabled).toBe(false)
    expect(JSON.stringify(h.pushSandboxTunnel.mock.calls)).not.toContain('new-token')
    expect(JSON.stringify(body)).not.toContain('new-token')
  })
})

// The agent's /tunnel-status answer: `active` says the tunnel process runs, `status` whether it
// forwards; host and port come only with "on". The lost-reset check reads `active`, so a tunnel that
// is still connecting or has failed is not mistaken for a sandbox that restarted (round 3).
describe('a tunnel that is connecting or failing is still running', () => {
  test.each([
    ['connecting', { ngrok: { active: true, status: 'connecting' }, chisel: { active: false, status: 'off' } }],
    ['error: <reason>', { ngrok: { active: false, status: 'off' }, chisel: { active: true, status: 'error: server rejected the remote port' } }],
  ])('a stored "on" whose tunnel is %s: an edit is pushed, never stored off, no restart warning', async (_state, answer) => {
    storeRow('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'old' })
    h.agentFetch.mockResolvedValue(new Response(JSON.stringify(answer)))
    const res = await PUT(put('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'new-token' }), params('u1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.tunnelsEnabled).toBe(true)
    expect(JSON.stringify(body.warnings ?? [])).not.toContain('tunnel_off_sandbox_restarted')
    expect(rows.get('u1')!.tunnelsEnabled).toBe(true)
    expect(h.pushSandboxTunnel.mock.calls.at(-1)).toEqual(['u1', { ngrokAuthtoken: 'new-token', chiselServerUrl: '', chiselAuth: '' }])
  })

  test('the no-sandbox answer ({active: false, status: "off"}) is still a lost reset: stored off, with the warning', async () => {
    storeRow('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'old' })
    h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ ngrok: { active: false, status: 'off' }, chisel: { active: false, status: 'off' } })))
    const body = await (await PUT(put('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'new-token' }), params('u1'))).json()
    expect(body.tunnelsEnabled).toBe(false)
    expect(body.warnings).toEqual([expect.objectContaining({ code: 'tunnel_off_sandbox_restarted' })])
    expect(rows.get('u1')!.tunnelsEnabled).toBe(false)
  })
})

describe('who may change their own tunnel', () => {
  test('a member without platform:tunnels cannot turn one on or change its fields: the existing refusal, naming their own sandbox', async () => {
    signInMember('m1')
    for (const change of [{ tunnelsEnabled: true }, { ngrokAuthtoken: 'm-tok' }, { chiselServerUrl: 'http://m.example:9090' }]) {
      storeRow('m1', {})
      const res = await PUT(put('m1', change), params('m1'))
      expect(res.status, JSON.stringify(change)).toBe(403)
      const body = await res.json()
      expect(body).toMatchObject({ code: 'tunnels_admin_only', fields: Object.keys(change) })
      expect(body.error).toMatch(/your own Kali sandbox/)
    }
    expect(h.upsert).not.toHaveBeenCalled()
    expect(h.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(h.ensureSandbox).not.toHaveBeenCalled()
  })

  test('turning one\'s own tunnel off needs no permission, and reaches their sandbox', async () => {
    signInMember('m1')
    storeRow('m1', { tunnelsEnabled: true, ngrokAuthtoken: 'm-tok' })
    const res = await PUT(put('m1', { tunnelsEnabled: false }), params('m1'))
    expect(res.status).toBe(200)
    expect(rows.get('m1')!.tunnelsEnabled).toBe(false)
    expect(h.pushSandboxTunnel.mock.calls).toEqual([['m1', EMPTY]])
  })

  test('turning it off while changing a credential still needs the permission', async () => {
    signInMember('m1')
    storeRow('m1', { tunnelsEnabled: true, ngrokAuthtoken: 'm-tok' })
    expect((await PUT(put('m1', { tunnelsEnabled: false, ngrokAuthtoken: 'm-new' }), params('m1'))).status).toBe(403)
    expect(h.upsert).not.toHaveBeenCalled()
  })

  test('the legacy holder turns their own on', async () => {
    signInMember('m2', ['tunnels'])
    storeRow('m2', { ngrokAuthtoken: 'm2-tok' })
    expect((await PUT(put('m2', { tunnelsEnabled: true }), params('m2'))).status).toBe(200)
    expect(h.pushSandboxTunnel.mock.calls).toEqual([['m2', { ngrokAuthtoken: 'm2-tok', chiselServerUrl: '', chiselAuth: '' }]])
  })

  test('under act-as turning a tunnel on is refused (it would run in the member\'s own sandbox, not the act_as one); turning it off is allowed', async () => {
    accounts.set('managed', { role: 'standard', legacyGrants: ['tunnels'], createdAt: AFTER_CUTOFF, password: null })
    actingAs = 'managed'
    storeRow('managed', { ngrokAuthtoken: 'managed-tok' })
    for (const change of [{ tunnelsEnabled: true }, { ngrokAuthtoken: 'other-tok' }]) {
      const res = await PUT(put('managed', change), params('managed'))
      expect(res.status, JSON.stringify(change)).toBe(403)
      expect((await res.json()).code).toBe('tunnels_act_as_refused')
    }
    expect(h.upsert).not.toHaveBeenCalled()
    expect(h.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(h.ensureSandbox).not.toHaveBeenCalled()
    storeRow('managed', { tunnelsEnabled: true, ngrokAuthtoken: 'managed-tok' })
    expect((await PUT(put('managed', { tunnelsEnabled: false }), params('managed'))).status).toBe(200)
    expect(h.pushSandboxTunnel.mock.calls).toEqual([['managed', EMPTY]])
  })
})

describe('the GET hint', () => {
  async function hint(id: string) {
    storeRow(id, {})
    const res = await GET(new NextRequest(`http://x/api/users/${id}/settings`), params(id))
    expect(res.status).toBe(200)
    const body = await res.json()
    return { canManageTunnels: body.canManageTunnels, tunnelScope: body.tunnelScope, sharedSettingsAt: body.sharedSettingsAt }
  }

  test('names the person\'s own sandbox; whether they may change it is their permission, whatever the identity switch', async () => {
    expect(await hint('u1')).toEqual({ canManageTunnels: true, tunnelScope: 'own_sandbox', sharedSettingsAt: undefined })
    setFlagsForTests({ identity: true })
    // The capture settings still live in the instance settings.
    expect(await hint('u1')).toEqual({ canManageTunnels: true, tunnelScope: 'own_sandbox', sharedSettingsAt: 'instance' })
    signInMember('m1')
    expect(await hint('m1')).toEqual({ canManageTunnels: false, tunnelScope: 'own_sandbox', sharedSettingsAt: 'instance' })
  })

  test('under act-as the tunnel controls are never offered, and the page is told the tunnel is the member\'s (gap G-23)', async () => {
    accounts.set('managed', { role: 'standard', legacyGrants: ['tunnels'], createdAt: AFTER_CUTOFF, password: null })
    actingAs = 'managed'
    storeRow('managed', { tunnelsEnabled: true })
    const body = await (await GET(new NextRequest('http://x/api/users/managed/settings'), params('managed'))).json()
    // The admin holds platform:tunnels, but what the page shows is the member's own tunnel.
    expect(body.canManageTunnels).toBe(false)
    expect(body.tunnelActingAs).toBe(true)
    actingAs = null
    const own = await (await GET(new NextRequest('http://x/api/users/u1/settings'), params('u1'))).json()
    expect(own.canManageTunnels).toBe(true)
    expect(own.tunnelActingAs).toBeUndefined()
  })

})

describe('an explicit "off" is always sent (review C3/F4)', () => {
  test('stored off already (a stop that was not delivered): the stop config is sent again', async () => {
    storeRow('u1', { tunnelsEnabled: false, ngrokAuthtoken: 'tok' })
    const res = await PUT(put('u1', { tunnelsEnabled: false }), params('u1'))
    expect(res.status).toBe(200)
    expect(h.pushSandboxTunnel.mock.calls).toEqual([['u1', EMPTY]])
    // Nothing changed, so no tunnel_changed row.
    expect(auditRows('settings.tunnel_changed')).toEqual([])
  })

  test('a stop that is not delivered says so', async () => {
    storeRow('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'tok' })
    h.pushSandboxTunnel.mockResolvedValue({ ok: false, status: 0, code: 'agent_unreachable' })
    const body = await (await PUT(put('u1', { tunnelsEnabled: false }), params('u1'))).json()
    expect(body.tunnelsEnabled).toBe(false)
    expect(body.warnings).toEqual([expect.objectContaining({ code: 'agent_unreachable' })])
  })

})

describe('one person\'s tunnel saves do not overtake each other (review C2/F6)', () => {
  test('an "off" sent while an earlier "on" waits for a cold start wins: stored off, the last push the stop config', async () => {
    storeRow('u1', { ngrokAuthtoken: 'tok' })
    let startDone!: () => void
    h.ensureSandbox.mockImplementation(() => new Promise((resolve) => {
      startDone = () => {
        // The gateway's fresh-start rule (B.16): the start turns the person's tunnels off.
        const row = rows.get('u1')!
        if (row.tunnelsEnabled) rows.set('u1', { ...row, tunnelsEnabled: false })
        resolve({ state: 'running', fresh: true, instance: 'a1b2c3' })
      }
    }))
    const on = PUT(put('u1', { tunnelsEnabled: true }), params('u1'))
    await vi.waitFor(() => expect(h.ensureSandbox).toHaveBeenCalled())
    const off = PUT(put('u1', { tunnelsEnabled: false }), params('u1'))
    await new Promise((r) => setTimeout(r, 30))
    startDone()
    const [a, b] = await Promise.all([on, off])
    expect([a.status, b.status]).toEqual([200, 200])
    expect(rows.get('u1')!.tunnelsEnabled).toBe(false)
    expect(h.pushSandboxTunnel.mock.calls.at(-1)).toEqual(['u1', EMPTY])
  })
})
