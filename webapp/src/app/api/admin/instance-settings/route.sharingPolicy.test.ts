/**
 * The instance sharing policy is Root's (step 4.2, SH-21; feature document §6.5): with
 * RBAC_SHARING_ENABLED on, `sharingPolicy` of /api/admin/instance-settings (on or off for the
 * instance, the highest level a share may have, whether members may grant Exploitation, the
 * default expiry, whether admins see every share) changes only by the confirmed Root, with its
 * password, as the security policy does. An admin, the tunnel holder and an unconfirmed Root get
 * 403 `root_only` and nothing is written; an unknown setting or a bad value is 400 `invalid_field`
 * naming it, before anything. A save that sends the policy unchanged needs neither. Admins read
 * the policy as it is in force (the stored `{}` reads as the defaults); the tunnel holder does not
 * see it. The change is audited (field names, never values) with the rest, and the policy cached
 * in this process is dropped. The stored value keeps every setting, and a later release's.
 *
 * With the switch off the route is the one before this step: the policy is neither shown nor
 * read from the body (sharing.flags.off.test.ts points here).
 *
 * Same doubles as route.securityPolicy.test.ts: real session, principal, Root, policy and audit
 * helpers over an in-memory Prisma; the step-up is a double (its own tests prove it).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/instance-settings/route.sharingPolicy.test.ts
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
import { clearSharingPolicyCacheForTests, sharingPolicyInForce } from '@/lib/authz/sharingPolicy'

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
    ...structuredClone(CAPTURE_DEFAULTS), captureSourceUserId: 'admin-a', updatedById: null, ...POLICY,
    sharingPolicy: {}, ...over,
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
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
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

const DEFAULTS = {
  enabled: false, maxLevel: 'write', membersMayGrantExploit: false, defaultExpiryDays: null, adminsSeeAllShares: true,
}
const stored = () => h.instance!.sharingPolicy

describe('Root changes the sharing policy', () => {
  test('with its password: the whole policy written, audited by field name, answered, the cache dropped', async () => {
    expect((await sharingPolicyInForce())!.enabled).toBe(false)
    await signIn('root-1')
    const res = await put({ sharingPolicy: { enabled: true, defaultExpiryDays: 30 }, stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.sharingPolicy).toEqual({ ...DEFAULTS, enabled: true, defaultExpiryDays: 30 })
    expect(body.canManageSharingPolicy).toBe(true)
    expect(stored()).toEqual({ ...DEFAULTS, enabled: true, defaultExpiryDays: 30 })
    expect(h.instance!.updatedById).toBe('root-1')
    expect(changes()).toMatchObject([
      { actorId: 'root-1', after: { fields: ['sharingPolicy'], changedKeys: { sharingPolicy: ['enabled', 'defaultExpiryDays'] } } },
    ])
    expect(JSON.stringify(changes())).not.toMatch(/right-password|"defaultExpiryDays":30/)
    expect(h.userSettings.size).toBe(0)
    expect(h.orch).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
    expect((await sharingPolicyInForce())!.enabled).toBe(true)
  })

  test('a later release\'s setting in the stored value is kept', async () => {
    h.instance!.sharingPolicy = { enabled: true, laterSetting: 'kept' }
    await signIn('root-1')
    expect((await put({ sharingPolicy: { maxLevel: 'read' }, stepUpPassword: 'right-password' })).status).toBe(200)
    expect(stored()).toEqual({ ...DEFAULTS, enabled: true, maxLevel: 'read', laterSetting: 'kept' })
  })

  test('an invalid stored value reads as the defaults and the save repairs it', async () => {
    h.instance!.sharingPolicy = { enabled: 'yes' }
    await signIn('root-1')
    expect((await (await get()).json()).sharingPolicy).toEqual(DEFAULTS)
    expect((await put({ sharingPolicy: { enabled: true }, stepUpPassword: 'right-password' })).status).toBe(200)
    expect(stored()).toEqual({ ...DEFAULTS, enabled: true })
  })

  test('with the security policy in the same save: both written, one audit row', async () => {
    await signIn('root-1')
    const res = await put({ passwordMinLength: 14, sharingPolicy: { enabled: true }, stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    expect(h.instance!.passwordMinLength).toBe(14)
    expect(stored()).toMatchObject({ enabled: true })
    expect(changes()).toMatchObject([{ after: { fields: ['passwordMinLength', 'sharingPolicy'] } }])
  })

  test('without its password: step_up_required, nothing written', async () => {
    await signIn('root-1')
    const res = await put({ sharingPolicy: { enabled: true } })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('step_up_required')
    expect(stored()).toEqual({})
    expect(changes()).toEqual([])
  })

  test('a failed audit write rolls the change back', async () => {
    h.failAudit = true
    await signIn('root-1')
    const res = await put({ sharingPolicy: { enabled: true }, stepUpPassword: 'right-password' })
    expect(res.status).toBe(500)
    expect(stored()).toEqual({})
    expect((await sharingPolicyInForce())!.enabled).toBe(false)
  })
})

describe('anyone else: root_only, nothing written', () => {
  test.each([
    ['an admin', 'admin-a', undefined],
    ['an admin acting as the tunnel holder', 'admin-a', 'member-tun'],
    ['the tunnel holder', 'member-tun', undefined],
  ])('%s', async (_who, id, actAs) => {
    await signIn(id, actAs)
    const res = await put({ sharingPolicy: { enabled: true }, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_only')
    expect(body.error).toMatch(/Only Root can change the instance sharing policy/)
    expect(stored()).toEqual({})
    expect(changes()).toEqual([])
  })

  test('an unconfirmed Root, told the host must confirm it', async () => {
    h.instance = instanceRow({ rootUserId: 'root-1', rootConfirmedAt: null, sharingPolicy: {} })
    await signIn('root-1')
    const res = await put({ sharingPolicy: { enabled: true }, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_only')
    expect(body.error).toMatch(/set-root/)
    expect(stored()).toEqual({})
  })

  test('the refusal comes before the tunnel part is written: an admin changing both changes neither', async () => {
    await signIn('admin-a')
    const res = await put({ tunnelsEnabled: true, sharingPolicy: { adminsSeeAllShares: false }, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    expect(h.instance!.tunnelsEnabled).toBe(false)
    expect(changes()).toEqual([])
  })
})

describe('what needs neither', () => {
  test('an admin saving the policy as it reads (the defaults over the stored {}) with a tunnel change', async () => {
    await signIn('admin-a')
    const res = await put({ sharingPolicy: DEFAULTS, tunnelsEnabled: true })
    expect(res.status).toBe(200)
    expect(h.instance!.tunnelsEnabled).toBe(true)
    expect(stored()).toEqual({})
    expect(changes()).toMatchObject([{ after: { fields: ['tunnelsEnabled'] } }])
  })

  test.each([
    [{ enabled: 'true' }, 'sharingPolicy.enabled'],
    [{ maxLevel: 'owner' }, 'sharingPolicy.maxLevel'],
    [{ defaultExpiryDays: 0 }, 'sharingPolicy.defaultExpiryDays'],
    [{ directoryVisible: true }, 'sharingPolicy.directoryVisible'],
    ['on', 'sharingPolicy'],
  ])('%j: 400 invalid_field naming %s, before any other check', async (sharingPolicy, field) => {
    await signIn('member-tun')
    const res = await put({ sharingPolicy })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field })
    expect(stored()).toEqual({})
  })
})

describe('reading the sharing policy', () => {
  test('an admin reads it as in force (the stored {} as the defaults), and learns it cannot change it', async () => {
    await signIn('admin-a')
    const body = await (await get()).json()
    expect(body.sharingPolicy).toEqual(DEFAULTS)
    expect(body.canManageSharingPolicy).toBe(false)
  })

  test('Root reads it and may change it', async () => {
    h.instance!.sharingPolicy = { enabled: true, maxLevel: 'read' }
    await signIn('root-1')
    const body = await (await get()).json()
    expect(body.sharingPolicy).toEqual({ ...DEFAULTS, enabled: true, maxLevel: 'read' })
    expect(body.canManageSharingPolicy).toBe(true)
  })

  test('the tunnel holder does not see it', async () => {
    await signIn('member-tun')
    const body = await (await get()).json()
    expect(body).not.toHaveProperty('sharingPolicy')
    expect(body).not.toHaveProperty('canManageSharingPolicy')
  })
})

describe('RBAC_SHARING_ENABLED off: the route is the one before step 4.2', () => {
  beforeEach(() => setFlagsForTests({ identity: true, permissions: true }))

  test('an admin\'s view carries no sharing policy', async () => {
    h.instance!.sharingPolicy = { enabled: true }
    await signIn('root-1')
    const body = await (await get()).json()
    expect(body).not.toHaveProperty('sharingPolicy')
    expect(body).not.toHaveProperty('canManageSharingPolicy')
    expect(body).toHaveProperty('securityPolicy')
  })

  test.each([
    ['Root with its password', 'root-1', 'right-password'],
    ['an admin', 'admin-a', undefined],
  ])('%s sending a policy, even an invalid one: ignored, 200, nothing written or audited', async (_who, id, password) => {
    await signIn(id)
    for (const sharingPolicy of [{ enabled: true }, { enabled: 'bad' }, 'bad']) {
      const res = await put({ sharingPolicy, ...(password ? { stepUpPassword: password } : {}) })
      expect(res.status).toBe(200)
    }
    expect(stored()).toEqual({})
    expect(changes()).toEqual([])
  })
})
