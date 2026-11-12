/**
 * STRIDE I19 — settings PUT is the tunnel ACTIVATION path. Tunnels come up ONLY
 * when the operator explicitly enables them; a credential edit while disabled
 * must NOT start a tunnel; disabling pushes a stop config; and the push carries
 * the TUNNEL_AUTH_TOKEN.
 *
 * HD-06 (F-05) — the tunnel is one listener for the whole instance, so changing it
 * (`ngrokAuthtoken`, `chiselServerUrl`, `chiselAuth`, `tunnelsEnabled`) takes
 * `sharedToolAccess(principal, 'tunnels')`: an admin, the member who kept the legacy
 * grant, or a pre-upgrade account under the escape hatch. Everyone else gets 403
 * `tunnels_admin_only` before anything is written or pushed; a full-form save that
 * sends the four fields back unchanged or masked is not a change. The GET tells the
 * page whether to offer the controls, without counting as a use of the escape hatch.
 *
 * The session is mocked; the principal, the shared-tools rule and the audit row are
 * the real code over a mocked Prisma.
 *
 * Run: npx vitest run "src/app/api/users/[id]/settings/tunnel-gating.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpsert = vi.fn()
const mockAuditCreate = vi.fn()
const mockCutoff = vi.fn()

interface Account { role: string; legacyGrants: string[]; createdAt: Date }
const accounts = new Map<string, Account>()
const mockUserFindUnique = vi.fn(async (args: { where: { id: string } }) => {
  const a = accounts.get(args.where.id)
  return a ? { id: args.where.id, email: `${args.where.id}@e2e.local`, password: 'h', ...a } : null
})

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      upsert: (...a: unknown[]) => mockUpsert(...a),
    },
    apiKeyRotationConfig: {
      findMany: vi.fn().mockResolvedValue([]),
      findUnique: vi.fn(),
      update: vi.fn(),
      deleteMany: vi.fn(),
      upsert: vi.fn(),
    },
    user: { findUnique: (a: { where: { id: string } }) => mockUserFindUnique(a) },
    auditLog: {
      findFirst: (...a: unknown[]) => mockCutoff(...a),
      create: (...a: unknown[]) => mockAuditCreate(...a),
    },
  },
}))

let session: { userId: string; role: string } | null = { userId: 'u1', role: 'admin' }
let internal = false
// Ownership is exercised separately in settings.access.test.ts; here we stub the
// guard open so these tests stay focused on the tunnel logic.
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: vi.fn().mockResolvedValue(null),
  isInternalRequest: vi.fn(() => internal),
  // Mocking the module wholesale means every export the route reaches for has
  // to be listed; a missing one fails inside the handler as a 500, which reads
  // like a route bug rather than a test-setup one.
  isScannerRequest: vi.fn().mockReturnValue(false),
  getSession: vi.fn(async () => session),
}))

// The step-up's own outcomes are proved in stepUp.test.ts; here the double answers as
// requireStepUp does: no password 403 step_up_required, a wrong one 403 step_up_failed.
const mockStepUp = vi.hoisted(() => vi.fn(async (_req: unknown, password: unknown) => {
  const { NextResponse } = await import('next/server')
  if (password === 'right-password') return null
  return password
    ? NextResponse.json({ error: 'Password is incorrect', code: 'step_up_failed' }, { status: 403 })
    : NextResponse.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })
}))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: mockStepUp }))

import { GET, PUT } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'

const WORKER_URL = 'http://kali-sandbox:8015/tunnel/configure'
const CUTOFF = new Date('2026-11-11T08:00:00.000Z')
const BEFORE_CUTOFF = new Date('2026-01-01T00:00:00.000Z')
const AFTER_CUTOFF = new Date('2026-11-12T00:00:00.000Z')

function put(id: string, body: unknown): NextRequest {
  return new NextRequest(`http://x/api/users/${id}/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

/** upsert echoes the resulting row from create/update payloads. */
function wireUpsert(existing: Record<string, unknown> | null) {
  mockFindUnique.mockResolvedValue(existing)
  mockUpsert.mockImplementation(({ create, update }: { create: Record<string, unknown>; update: Record<string, unknown> }) =>
    Promise.resolve({
      ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', tunnelsEnabled: false,
      ...(existing ?? {}), ...(existing ? update : create),
    }),
  )
}

function lastPush(fetchSpy: ReturnType<typeof vi.fn>) {
  const call = fetchSpy.mock.calls.find(c => c[0] === WORKER_URL)
  if (!call) return null
  const opts = call[1] as RequestInit
  return { headers: opts.headers as Record<string, string>, body: JSON.parse(opts.body as string) }
}

const auditRows = (action: string) =>
  mockAuditCreate.mock.calls.map(c => (c[0] as { data: Record<string, unknown> }).data).filter(d => d.action === action)

/** Signs `id` in as a member with these grants, created at `createdAt`. */
function signInMember(id: string, legacyGrants: string[] = [], createdAt = AFTER_CUTOFF) {
  accounts.set(id, { role: 'standard', legacyGrants, createdAt })
  session = { userId: id, role: 'standard' }
}

let fetchSpy: ReturnType<typeof vi.fn>

beforeEach(() => {
  mockFindUnique.mockReset()
  mockUpsert.mockReset()
  mockAuditCreate.mockReset().mockResolvedValue({})
  mockCutoff.mockReset().mockResolvedValue({ createdAt: CUTOFF })
  mockUserFindUnique.mockClear()
  accounts.clear()
  accounts.set('u1', { role: 'admin', legacyGrants: [], createdAt: AFTER_CUTOFF })
  session = { userId: 'u1', role: 'admin' }
  internal = false
  resetSharedToolsForTests()
  process.env.TUNNEL_AUTH_TOKEN = 'ttok'
  fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
  vi.stubGlobal('fetch', fetchSpy)
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  setFlagsForTests(null)
  delete process.env.TUNNEL_AUTH_TOKEN
})

describe('settings PUT tunnel activation gating — I19', () => {
  test('enable + creds → activates with real creds and Authorization header', async () => {
    wireUpsert({ tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })

    await PUT(put('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'ng-tok' }), params('u1'))

    const push = lastPush(fetchSpy)
    expect(push).not.toBeNull()
    expect(push!.body).toEqual({ ngrokAuthtoken: 'ng-tok', chiselServerUrl: '', chiselAuth: '' })
    expect(push!.headers['Authorization']).toBe('Bearer ttok')
  })

  test('credential edit while DISABLED → pushes empty stop config (no activation)', async () => {
    wireUpsert({ tunnelsEnabled: false, ngrokAuthtoken: 'old', chiselServerUrl: '', chiselAuth: '' })

    await PUT(put('u1', { ngrokAuthtoken: 'new-secret' }), params('u1'))

    const push = lastPush(fetchSpy)
    expect(push).not.toBeNull()
    expect(push!.body).toEqual({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
  })

  test('disable → pushes empty stop config', async () => {
    wireUpsert({ tunnelsEnabled: true, ngrokAuthtoken: 'ng', chiselServerUrl: '', chiselAuth: '' })

    await PUT(put('u1', { tunnelsEnabled: false }), params('u1'))

    const push = lastPush(fetchSpy)
    expect(push).not.toBeNull()
    expect(push!.body).toEqual({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
  })

  test('non-tunnel settings change → NO push at all', async () => {
    wireUpsert({ tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })

    await PUT(put('u1', { shodanApiKey: 'x' }), params('u1'))

    expect(lastPush(fetchSpy)).toBeNull()
  })
})

describe('who may change the tunnel — HD-06', () => {
  const STORED = { tunnelsEnabled: false, ngrokAuthtoken: 'ngrok-STORED-tok', chiselServerUrl: 'http://vps.example:9090', chiselAuth: 'user:STORED-pass' }

  test('member change refused', async () => {
    signInMember('m1')
    const changes: Record<string, unknown>[] = [
      { chiselServerUrl: 'http://member-vps.example:9090' },
      { ngrokAuthtoken: 'member-ngrok-tok' },
      { chiselAuth: 'member:pass' },
      { tunnelsEnabled: true },
    ]
    for (const change of changes) {
      wireUpsert({ ...STORED, userId: 'm1' })
      const res = await PUT(put('m1', change), params('m1'))
      expect(res.status, JSON.stringify(change)).toBe(403)
      const body = await res.json()
      expect(body).toMatchObject({ code: 'tunnels_admin_only', fields: Object.keys(change) })
      expect(JSON.stringify(body)).not.toMatch(/STORED|member-ngrok-tok|member:pass/)
    }
    expect(mockUpsert).not.toHaveBeenCalled()
    expect(lastPush(fetchSpy)).toBeNull()
    expect(auditRows('settings.tunnel_changed')).toEqual([])
  })

  test('the refusal comes before the endpoint checks and before anything is written', async () => {
    signInMember('m1')
    wireUpsert({ ...STORED, userId: 'm1' })
    const res = await PUT(put('m1', {
      chiselServerUrl: 'http://member-vps.example:9090', chiselAuth: '••••••••pass',
      githubEnterpriseHost: '127.0.0.1', shodanApiKey: 'member-shodan',
    }), params('m1'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('tunnels_admin_only')
    expect(mockUpsert).not.toHaveBeenCalled()
  })

  test('legacy holder allowed', async () => {
    signInMember('m1', ['kali_terminal', 'tunnels'])
    wireUpsert({ ...STORED, userId: 'm1' })
    // ID-25: re-pointing the configured chisel server also takes the holder's password.
    const res = await PUT(put('m1', { chiselServerUrl: 'http://vps2.example:9090', chiselAuth: 'user:typed-again', stepUpPassword: 'right-password' }), params('m1'))
    expect(res.status).toBe(200)
    expect(mockUpsert.mock.calls[0][0].update).toMatchObject({ chiselServerUrl: 'http://vps2.example:9090' })
    expect(lastPush(fetchSpy)).not.toBeNull()
    const rows = auditRows('settings.tunnel_changed')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      actorId: 'm1', targetType: 'user', targetId: 'm1',
      after: { fields: ['chiselServerUrl', 'chiselAuth'], via: 'legacy' },
    })
    // Which fields, never their values.
    expect(JSON.stringify(rows[0])).not.toMatch(/vps2|typed-again|STORED/)
  })

  test('a re-pointed chisel server without the password is refused after the tunnel check: nothing written, pushed or audited (ID-25)', async () => {
    signInMember('m1', ['kali_terminal', 'tunnels'])
    wireUpsert({ ...STORED, userId: 'm1' })
    const res = await PUT(put('m1', { chiselServerUrl: 'http://vps2.example:9090', chiselAuth: 'user:typed-again' }), params('m1'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('step_up_required')
    expect(mockUpsert).not.toHaveBeenCalled()
    expect(lastPush(fetchSpy)).toBeNull()
    expect(auditRows('settings.tunnel_changed')).toEqual([])
  })

  test('another grant is not the tunnel grant', async () => {
    signInMember('m1', ['kali_terminal', 'shell_sessions'])
    wireUpsert({ ...STORED, userId: 'm1' })
    expect((await PUT(put('m1', { tunnelsEnabled: true }), params('m1'))).status).toBe(403)
  })

  test('admin allowed', async () => {
    wireUpsert({ ...STORED, userId: 'u1' })
    const res = await PUT(put('u1', { tunnelsEnabled: true }), params('u1'))
    expect(res.status).toBe(200)
    expect(lastPush(fetchSpy)!.body).toEqual({
      ngrokAuthtoken: 'ngrok-STORED-tok', chiselServerUrl: 'http://vps.example:9090', chiselAuth: 'user:STORED-pass',
    })
    expect(auditRows('settings.tunnel_changed')[0]).toMatchObject({
      actorId: 'u1', targetId: 'u1', after: { fields: ['tunnelsEnabled'], via: 'admin' },
    })
  })

  test('compat pre-upgrade member allowed', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    signInMember('m-pre', [], BEFORE_CUTOFF)
    wireUpsert({ ...STORED, userId: 'm-pre' })
    const res = await PUT(put('m-pre', { tunnelsEnabled: true }), params('m-pre'))
    expect(res.status).toBe(200)
    expect(auditRows('settings.tunnel_changed')[0]).toMatchObject({ after: { fields: ['tunnelsEnabled'], via: 'compat' } })
    expect(auditRows('rbac.compat_used')).toHaveLength(1)
  })

  test('the escape hatch does not reach an account created after the upgrade', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    signInMember('m-post', [], AFTER_CUTOFF)
    wireUpsert({ ...STORED, userId: 'm-post' })
    expect((await PUT(put('m-post', { tunnelsEnabled: true }), params('m-post'))).status).toBe(403)
  })

  test('unchanged and masked fields ignored', async () => {
    signInMember('m1')
    wireUpsert({ ...STORED, userId: 'm1' })
    const res = await PUT(put('m1', {
      tunnelsEnabled: false, ngrokAuthtoken: '••••••••-tok', chiselServerUrl: 'http://vps.example:9090',
      chiselAuth: '••••••••pass', shodanApiKey: 'member-shodan',
    }), params('m1'))
    expect(res.status).toBe(200)
    expect(mockUpsert.mock.calls[0][0].update).toMatchObject({
      ngrokAuthtoken: 'ngrok-STORED-tok', chiselAuth: 'user:STORED-pass', shodanApiKey: 'member-shodan',
    })
    expect(lastPush(fetchSpy)).toBeNull()
    expect(auditRows('settings.tunnel_changed')).toEqual([])
    // Nothing to decide, so no account read beyond the session.
    expect(mockUserFindUnique).not.toHaveBeenCalled()
  })

  test("a member's ordinary full-form save still succeeds", async () => {
    signInMember('m1')
    wireUpsert(null)
    const res = await PUT(put('m1', {
      tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', shodanApiKey: 'member-shodan',
    }), params('m1'))
    expect(res.status).toBe(200)
    expect(mockUpsert.mock.calls[0][0].create).toMatchObject({ userId: 'm1', shodanApiKey: 'member-shodan', tunnelsEnabled: false })
    expect(lastPush(fetchSpy)).toBeNull()
  })

  test('the internal key changes it with no session, audited without an actor', async () => {
    internal = true
    session = null
    wireUpsert({ ...STORED, userId: 'm1' })
    const res = await PUT(put('m1', { tunnelsEnabled: true }), params('m1'))
    expect(res.status).toBe(200)
    expect(auditRows('settings.tunnel_changed')[0]).toMatchObject({
      actorId: null, targetId: 'm1', after: { fields: ['tunnelsEnabled'], via: 'internal' },
    })
  })
})

describe('the GET says whether to offer the tunnel controls', () => {
  async function hint(id: string): Promise<unknown> {
    mockFindUnique.mockResolvedValue({ userId: id, tavilyApiKey: '', tunnelsEnabled: false })
    const res = await GET(new NextRequest(`http://x/api/users/${id}/settings`), params(id))
    expect(res.status).toBe(200)
    return (await res.json()).canManageTunnels
  }

  test('false for a member, true for the legacy holder and the admin', async () => {
    signInMember('m1')
    expect(await hint('m1')).toBe(false)
    signInMember('m2', ['tunnels'])
    expect(await hint('m2')).toBe(true)
    session = { userId: 'u1', role: 'admin' }
    expect(await hint('u1')).toBe(true)
  })

  test('true for a pre-upgrade member under the escape hatch, which the hint does not count as a use', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    signInMember('m-pre', [], BEFORE_CUTOFF)
    expect(await hint('m-pre')).toBe(true)
    expect(auditRows('rbac.compat_used')).toEqual([])
    expect(console.warn).not.toHaveBeenCalledWith(expect.stringContaining('shared-tools compat used'))
  })

  test('the no-row answer carries it too', async () => {
    signInMember('m1')
    mockFindUnique.mockResolvedValue(null)
    const res = await GET(new NextRequest('http://x/api/users/m1/settings'), params('m1'))
    expect((await res.json()).canManageTunnels).toBe(false)
  })

  test('absent for the internal key, which is no browser', async () => {
    internal = true
    session = null
    expect(await hint('m1')).toBeUndefined()
  })

  test('a failed account read leaves it out; the settings still load', async () => {
    signInMember('m1')
    mockUserFindUnique.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    expect(await hint('m1')).toBeUndefined()
  })
})
