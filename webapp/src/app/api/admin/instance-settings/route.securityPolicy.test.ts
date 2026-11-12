/**
 * The instance security policy is Root's (step 2.6, ID-03 powers, ID-25; feature document §4.4):
 * with the identity switch on, the password policy, the session and link lifetimes, the
 * impersonation settings and the public base URL of /api/admin/instance-settings change only by
 * the confirmed Root, with its password. An admin, the tunnel holder and an unconfirmed Root get
 * 403 `root_only` and nothing is written; a value out of bounds is 400 `invalid_field` before
 * anything. A save that sends the policy unchanged (a whole form) needs neither. Admins read the
 * policy; the tunnel holder does not see it. The change is audited (field names) with the rest.
 *
 * Same doubles as route.test.ts: real session, principal, Root and audit helpers over an
 * in-memory Prisma; the step-up is a double (its own tests prove it).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/instance-settings/route.securityPolicy.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

type Row = Record<string, unknown>
const h = vi.hoisted(() => ({
  cookies: new Map<string, string>(),
  accounts: new Map<string, Record<string, unknown>>(),
  instance: null as Record<string, unknown> | null,
  userSettings: new Map<string, Record<string, unknown>>(),
  audit: [] as Record<string, unknown>[],
  failAudit: false,
  orch: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (h.cookies.has(name) ? { value: h.cookies.get(name) } : undefined),
    delete: (name: string) => { h.cookies.delete(name) },
  })),
}))

vi.mock('@/lib/prisma', () => {
  const clone = <T,>(v: T): T => structuredClone(v)
  const client = {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => clone(h.accounts.get(where.id) ?? null),
      findFirst: async ({ where, orderBy }: { where: { role: string }; orderBy: unknown }) => {
        expect(orderBy).toEqual([{ createdAt: 'asc' }, { id: 'asc' }])
        const admins = [...h.accounts.values()].filter((a) => a.role === where.role)
          .sort((x, y) => (x.createdAt as Date).getTime() - (y.createdAt as Date).getTime() || String(x.id).localeCompare(String(y.id)))
        return admins[0] ? { id: admins[0].id } : null
      },
    },
    instanceSettings: {
      findUnique: async () => clone(h.instance),
      update: async ({ data }: { data: Row }) => {
        h.instance = { ...h.instance!, ...clone(data), updatedAt: new Date() }
        return clone(h.instance)
      },
    },
    userSettings: {
      upsert: async ({ where, update, create }: { where: { userId: string }; update: Row; create: Row }) => {
        const prev = h.userSettings.get(where.userId)
        h.userSettings.set(where.userId, prev ? { ...prev, ...clone(update) } : clone(create))
        return clone(h.userSettings.get(where.userId))
      },
    },
    auditLog: {
      // The legacy-grants cutoff the escape hatch reads.
      findFirst: async ({ where }: { where: { action: string } }) =>
        clone(h.audit.find((r) => r.action === where.action) ?? null),
      create: async ({ data }: { data: Row }) => {
        if (h.failAudit && data.action === 'instance.settings_changed') throw new Error('audit table unavailable')
        h.audit.push(clone(data))
        return data
      },
    },
    $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
      const snapshot = { instance: clone(h.instance), settings: clone([...h.userSettings]), audit: clone(h.audit) }
      try {
        return await fn(client)
      } catch (err) {
        h.instance = snapshot.instance
        h.userSettings = new Map(snapshot.settings)
        h.audit = snapshot.audit
        throw err
      }
    },
  }
  return { default: client }
})

vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orch(...a) }))
vi.mock('@/lib/authz/stepUp', () => ({
  requireStepUp: async (_req: unknown, password: unknown) => {
    const { NextResponse } = await import('next/server')
    return password === 'right-password'
      ? null
      : NextResponse.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })
  },
}))

import { GET, PUT } from './route'
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { CAPTURE_DEFAULTS } from '@/lib/sharedInstanceSettings'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'

const CUTOFF = new Date('2026-11-11T08:00:00Z')

function account(id: string, role: string, over: Row = {}) {
  h.accounts.set(id, {
    id, email: `${id}@e2e.local`, name: id, role, password: 'hash', createdAt: new Date('2026-01-01T00:00:00Z'),
    legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null,
    lastLoginAt: null, ...over,
  })
}

async function signIn(id: string, actAs?: string) {
  const a = h.accounts.get(id)!
  h.cookies.set('redamon-auth', await createToken(id, a.role as string))
  if (actAs) h.cookies.set('redamon-act-as', await createActAsToken(id, actAs))
}

const POLICY = {
  passwordMinLength: 12, passwordAskChangeIfShort: false, memberSessionTtlHours: 168, adminSessionTtlHours: 12,
  adminIdleMinutes: 60, inviteTtlHours: 168, resetTtlHours: 4, publicBaseUrl: null,
  impersonationMaxMinutes: 720, impersonationReasonRequired: false, impersonationNotifyTarget: true,
}

function instanceRow(over: Row = {}): Row {
  return {
    id: 'instance', rootUserId: null, rootConfirmedAt: null,
    tunnelsEnabled: false, ngrokAuthtoken: 'fake-ngrok-token-1234', chiselServerUrl: 'https://chisel.old.test',
    chiselAuth: 'user:fake-pass-9876', tunnelSourceUserId: 'member-tun',
    ...structuredClone(CAPTURE_DEFAULTS), captureSourceUserId: 'admin-a', updatedById: null, ...POLICY, ...over,
  }
}

const put = (body: unknown, headers: Record<string, string> = {}) =>
  PUT(new NextRequest('http://redamon.test/api/admin/instance-settings', {
    method: 'PUT',
    headers: { host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }))
const get = () => GET(new NextRequest('http://redamon.test/api/admin/instance-settings'))
const changes = () => h.audit.filter((r) => r.action === 'instance.settings_changed')

beforeEach(() => {
  h.cookies.clear(); h.accounts.clear(); h.userSettings.clear()
  h.audit = [{ action: 'system.rbac_legacy_grants_cutoff', createdAt: CUTOFF }]
  h.failAudit = false
  h.instance = instanceRow({ rootUserId: 'root-1', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  h.orch.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
  h.fetch.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', h.fetch)
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  resetSharedToolsForTests()
  account('root-1', 'admin', { createdAt: new Date('2026-01-01T00:00:00Z') })
  account('admin-a', 'admin', { createdAt: new Date('2026-01-05T00:00:00Z') })
  account('member-tun', 'standard', { legacyGrants: ['tunnels'] })
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const policyOf = () => Object.fromEntries(Object.keys(POLICY).map((k) => [k, h.instance![k]]))

describe('Root changes the security policy', () => {
  test('with its password: written, audited by field name, answered', async () => {
    await signIn('root-1')
    const res = await put({ passwordMinLength: 14, adminIdleMinutes: 30, publicBaseUrl: 'https://redamon.example.test/', stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.securityPolicy).toMatchObject({ passwordMinLength: 14, adminIdleMinutes: 30, publicBaseUrl: 'https://redamon.example.test' })
    expect(body.canManageSecurityPolicy).toBe(true)
    expect(h.instance).toMatchObject({ passwordMinLength: 14, adminIdleMinutes: 30, publicBaseUrl: 'https://redamon.example.test', updatedById: 'root-1' })
    expect(changes()).toMatchObject([{ actorId: 'root-1', after: { fields: ['passwordMinLength', 'adminIdleMinutes', 'publicBaseUrl'] } }])
    expect(JSON.stringify(changes())).not.toContain('right-password')
    expect(h.orch).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test.each([721, 1440])('the impersonation limit above 720 minutes (%i, §12 OQ-32): 400 invalid_field, nothing written', async (minutes) => {
    await signIn('root-1')
    const res = await put({ impersonationMaxMinutes: minutes, stepUpPassword: 'right-password' })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field: 'impersonationMaxMinutes' })
    expect(policyOf()).toEqual(POLICY)
    expect(changes()).toEqual([])
  })

  test('the impersonation limit: Root lowers it, and 720 is accepted back', async () => {
    await signIn('root-1')
    expect((await put({ impersonationMaxMinutes: 60, stepUpPassword: 'right-password' })).status).toBe(200)
    expect(h.instance!.impersonationMaxMinutes).toBe(60)
    expect((await put({ impersonationMaxMinutes: 720, stepUpPassword: 'right-password' })).status).toBe(200)
    expect(h.instance!.impersonationMaxMinutes).toBe(720)
    expect(changes()).toMatchObject([
      { after: { fields: ['impersonationMaxMinutes'] } }, { after: { fields: ['impersonationMaxMinutes'] } },
    ])
  })

  test('without its password: step_up_required, nothing written', async () => {
    await signIn('root-1')
    const res = await put({ passwordMinLength: 14 })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('step_up_required')
    expect(policyOf()).toEqual(POLICY)
    expect(changes()).toEqual([])
  })
})

describe('anyone else: root_only, nothing written', () => {
  test.each([
    ['an admin', 'admin-a', undefined],
    ['an admin acting as the tunnel holder', 'admin-a', 'member-tun'],
    ['the tunnel holder', 'member-tun', undefined],
  ])('%s', async (_who, id, actAs) => {
    await signIn(id, actAs)
    const res = await put({ memberSessionTtlHours: 24, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_only')
    expect(body.error).toMatch(/Only Root/)
    expect(policyOf()).toEqual(POLICY)
    expect(changes()).toEqual([])
  })

  test('an unconfirmed Root, told the host must confirm it', async () => {
    h.instance = instanceRow({ rootUserId: 'root-1', rootConfirmedAt: null })
    await signIn('root-1')
    const res = await put({ impersonationNotifyTarget: false, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_only')
    expect(body.error).toMatch(/set-root/)
    expect(h.instance!.impersonationNotifyTarget).toBe(true)
  })

  test('the refusal comes before the tunnel part is written: an admin changing both changes neither', async () => {
    await signIn('admin-a')
    const res = await put({ tunnelsEnabled: true, resetTtlHours: 2, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    expect(h.instance!.tunnelsEnabled).toBe(false)
    expect(changes()).toEqual([])
  })
})

describe('what needs neither', () => {
  test('an admin saving the policy unchanged with a tunnel change (a whole form)', async () => {
    await signIn('admin-a')
    const res = await put({ ...POLICY, tunnelsEnabled: true })
    expect(res.status).toBe(200)
    expect(h.instance!.tunnelsEnabled).toBe(true)
    expect(changes()).toMatchObject([{ after: { fields: ['tunnelsEnabled'] } }])
  })

  test('a value out of bounds: 400 invalid_field naming it, before any other check', async () => {
    await signIn('member-tun')
    const res = await put({ passwordMinLength: 8 })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field: 'passwordMinLength' })
    expect(policyOf()).toEqual(POLICY)
  })
})

describe('reading the policy', () => {
  test('an admin reads it, and learns it cannot change it', async () => {
    await signIn('admin-a')
    const body = await (await get()).json()
    expect(body.securityPolicy).toEqual(POLICY)
    expect(body.canManageSecurityPolicy).toBe(false)
  })

  test('Root reads it and may change it', async () => {
    await signIn('root-1')
    expect((await (await get()).json()).canManageSecurityPolicy).toBe(true)
  })

  test('the tunnel holder does not see it', async () => {
    await signIn('member-tun')
    const body = await (await get()).json()
    expect(body).not.toHaveProperty('securityPolicy')
    expect(body).not.toHaveProperty('canManageSecurityPolicy')
  })
})
