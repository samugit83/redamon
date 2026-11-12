/**
 * GET/PUT /api/admin/instance-settings (step 2.4, ID-32, F-15): the tunnel and the
 * TrafficMind capture policy as instance settings, with RBAC_IDENTITY_ENABLED on.
 *
 * Who: an admin changes everything; the tunnel also the member holding the `tunnels`
 * legacy grant and a pre-upgrade account under the escape hatch (HD-06, T27, OQ-R3 (a));
 * anyone else 403. The person is the signed-in one, never the account an admin acts as.
 * A write keeps the tunnel rules of the settings PUT (re-entry, step-up), mirrors each
 * changed group into a user row (the source, else the confirmed Root, else the oldest
 * admin), audits field names only, and applies the change (capture proxy, sandbox push).
 *
 * Real session, principal, shared-tools rule and audit helpers over an in-memory Prisma;
 * the step-up and the two outbound calls are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/instance-settings/route.test.ts
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
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { CAPTURE_DEFAULTS, CAPTURE_FIELDS } from '@/lib/sharedInstanceSettings'

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

function instanceRow(over: Row = {}): Row {
  return {
    id: 'instance', rootUserId: null, rootConfirmedAt: null,
    tunnelsEnabled: false, ngrokAuthtoken: 'fake-ngrok-token-1234', chiselServerUrl: 'https://chisel.old.test',
    chiselAuth: 'user:fake-pass-9876', tunnelSourceUserId: 'member-tun',
    ...structuredClone(CAPTURE_DEFAULTS), captureSourceUserId: 'admin-a', updatedById: null, ...over,
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
  h.instance = instanceRow()
  h.orch.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
  h.fetch.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', h.fetch)
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  resetSharedToolsForTests()
  account('admin-a', 'admin', { createdAt: new Date('2026-01-05T00:00:00Z') })
  account('admin-b', 'admin', { createdAt: new Date('2026-02-05T00:00:00Z') })
  account('member', 'standard')
  account('member-tun', 'standard', { legacyGrants: ['tunnels'] })
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the identity switch', () => {
  test('off: GET and PUT answer 404, as before the route existed, and read nothing', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-a')
    expect((await get()).status).toBe(404)
    expect((await put({ tunnelsEnabled: true })).status).toBe(404)
    expect(h.instance).toEqual(instanceRow())
    expect(changes()).toEqual([])
  })

  test('on, before the boot backfill filled the row: 503 with a fixed code', async () => {
    h.instance = null
    await signIn('admin-a')
    const res = await get()
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('instance_settings_unavailable')
    expect((await put({ tunnelsEnabled: true })).status).toBe(503)
  })
})

describe('who', () => {
  test('member 403: no read, no write', async () => {
    await signIn('member')
    for (const res of [await get(), await put({ tunnelsEnabled: true, captureProxyEnabled: false })]) {
      expect(res.status).toBe(403)
      expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'instance:settings' })
    }
    expect(h.instance).toEqual(instanceRow())
  })

  test('no session 401', async () => {
    expect((await get()).status).toBe(401)
    expect((await put({})).status).toBe(401)
  })

  test('an admin reads everything, secrets masked', async () => {
    await signIn('admin-a')
    const body = await (await get()).json()
    expect(body).toMatchObject({
      tunnelsEnabled: false, ngrokAuthtoken: '••••••••1234', chiselServerUrl: 'https://chisel.old.test',
      chiselAuth: '••••••••9876', canManageTunnels: true, canManageCapture: true,
    })
    for (const f of CAPTURE_FIELDS) expect(body, f).toHaveProperty(f)
    expect(JSON.stringify(body)).not.toMatch(/fake-ngrok-token|fake-pass/)
  })

  test('the tunnels legacy holder reads and changes only the tunnel (OQ-R3 (a))', async () => {
    await signIn('member-tun')
    const body = await (await get()).json()
    expect(body).toMatchObject({ canManageTunnels: true, canManageCapture: false })
    expect(body).not.toHaveProperty('captureProxyEnabled')
    const ok = await put({ tunnelsEnabled: true })
    expect(ok.status).toBe(200)
    expect(h.instance!.tunnelsEnabled).toBe(true)
    expect(changes()[0].after).toMatchObject({ fields: ['tunnelsEnabled'], tunnelVia: 'legacy' })
    const refused = await put({ captureEgressBlockPrivate: false })
    expect(refused.status).toBe(403)
    expect(await refused.json()).toMatchObject({
      code: 'forbidden', permission: 'platform:traffic_capture', fields: ['captureEgressBlockPrivate'],
    })
    expect(h.instance!.captureEgressBlockPrivate).toBe(true)
  })

  test('a pre-upgrade member under the escape hatch changes the tunnel; the use is recorded once it changes something', async () => {
    setFlagsForTests({ identity: true, sharedToolsCompat: true })
    account('member-old', 'standard', { createdAt: new Date('2026-11-01T00:00:00Z') })
    await signIn('member-old')
    expect((await get()).status).toBe(200)
    expect(h.audit.filter((r) => r.action === 'rbac.compat_used')).toEqual([])
    expect((await put({ tunnelsEnabled: true })).status).toBe(200)
    expect(changes()[0].after).toMatchObject({ tunnelVia: 'compat' })
    expect(h.audit.filter((r) => r.action === 'rbac.compat_used')).toHaveLength(1)
  })

  test('a demoted admin\'s cached account changes nothing: the write reads the account fresh', async () => {
    await signIn('admin-b')
    expect((await get()).status).toBe(200)
    h.accounts.get('admin-b')!.role = 'standard'
    setFlagsForTests({ identity: true })
    const res = await put({ captureProxyEnabled: false })
    expect(res.status).toBe(403)
    expect(h.instance!.captureProxyEnabled).toBe(true)
  })

  test('act-as: a TrafficMind save while acting writes the singleton under the admin, not the member\'s row', async () => {
    await signIn('admin-a', 'member')
    const res = await put({ captureEgressBlockPrivate: false })
    expect(res.status).toBe(200)
    expect(h.instance).toMatchObject({ captureEgressBlockPrivate: false, updatedById: 'admin-a' })
    expect(h.userSettings.has('member')).toBe(false)
    expect(changes()[0]).toMatchObject({ actorId: 'admin-a', actorEmail: 'admin-a@e2e.local' })
    expect(changes()[0]).not.toHaveProperty('onBehalfOfUserId')
  })
})

describe('the request', () => {
  beforeEach(() => signIn('admin-a'))

  test('another origin 403 cross_origin, nothing written', async () => {
    const res = await put({ tunnelsEnabled: true }, { origin: 'https://evil.test' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
    expect(h.instance!.tunnelsEnabled).toBe(false)
  })

  test('a body that is not JSON 415', async () => {
    expect((await put('tunnelsEnabled=true', { 'content-type': 'application/x-www-form-urlencoded' })).status).toBe(415)
  })

  test('a tunnel field that is not text 400', async () => {
    const res = await put({ chiselServerUrl: 42 })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field: 'chiselServerUrl' })
  })

  test('unchanged and masked values change nothing: no write, no audit, no call', async () => {
    const res = await put({
      tunnelsEnabled: false, ngrokAuthtoken: '••••••••1234', chiselServerUrl: 'https://chisel.old.test',
      chiselAuth: '••••••••9876', captureProxyEnabled: true, captureProxyPort: 8888, captureProxyBodyRules: {},
    })
    expect(res.status).toBe(200)
    expect(h.instance).toEqual(instanceRow())
    expect(changes()).toEqual([])
    expect(h.orch).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('the tunnel', () => {
  beforeEach(() => signIn('admin-a'))

  test('tunnel push called: enabling sends the stored credentials with the tunnel bearer', async () => {
    vi.stubEnv('TUNNEL_AUTH_TOKEN', 'fake-tunnel-bearer')
    expect((await put({ tunnelsEnabled: true })).status).toBe(200)
    const [url, init] = h.fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://kali-sandbox:8015/tunnel/configure')
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer fake-tunnel-bearer')
    expect(JSON.parse(init.body as string)).toEqual({
      ngrokAuthtoken: 'fake-ngrok-token-1234', chiselServerUrl: 'https://chisel.old.test', chiselAuth: 'user:fake-pass-9876',
    })
    vi.unstubAllEnvs()
    vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
  })

  test('a credential edit while disabled pushes the stop config', async () => {
    expect((await put({ ngrokAuthtoken: 'fake-new-token-5555' })).status).toBe(200)
    expect(JSON.parse((h.fetch.mock.calls[0] as [string, RequestInit])[1].body as string))
      .toEqual({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
    expect(h.instance!.ngrokAuthtoken).toBe('fake-new-token-5555')
  })

  test('a new chisel URL needs its auth typed again (HD-24), then the password (ID-25)', async () => {
    const reentry = await put({ chiselServerUrl: 'https://chisel.new.test', chiselAuth: '••••••••9876' })
    expect(reentry.status).toBe(400)
    expect((await reentry.json()).code).toBe('secret_reentry_required')
    const stepUp = await put({ chiselServerUrl: 'https://chisel.new.test', chiselAuth: 'user:fake-new-pass' })
    expect(stepUp.status).toBe(403)
    expect((await stepUp.json()).code).toBe('step_up_required')
    expect(h.instance!.chiselServerUrl).toBe('https://chisel.old.test')
    const ok = await put({ chiselServerUrl: 'https://chisel.new.test', chiselAuth: 'user:fake-new-pass', stepUpPassword: 'right-password' })
    expect(ok.status).toBe(200)
    expect(h.instance).toMatchObject({ chiselServerUrl: 'https://chisel.new.test', chiselAuth: 'user:fake-new-pass' })
    expect(h.instance).not.toHaveProperty('stepUpPassword')
  })

  test('audit: the field names and the right used, never a value', async () => {
    await put({ ngrokAuthtoken: 'fake-new-token-5555', tunnelsEnabled: true })
    expect(changes()).toHaveLength(1)
    expect(changes()[0]).toMatchObject({
      action: 'instance.settings_changed', targetType: 'instance', targetId: 'instance', actorId: 'admin-a',
      after: { fields: ['ngrokAuthtoken', 'tunnelsEnabled'], tunnelVia: 'admin', mirroredTo: { tunnel: 'member-tun' } },
    })
    expect(JSON.stringify(h.audit)).not.toContain('fake-new-token')
  })
})

describe('the mirror', () => {
  beforeEach(() => signIn('admin-a'))

  test('mirror into the source row: the whole group, the other group untouched', async () => {
    await put({ tunnelsEnabled: true })
    expect(h.userSettings.get('member-tun')).toEqual({
      userId: 'member-tun', tunnelsEnabled: true, ngrokAuthtoken: 'fake-ngrok-token-1234',
      chiselServerUrl: 'https://chisel.old.test', chiselAuth: 'user:fake-pass-9876',
    })
    expect(h.userSettings.has('admin-a')).toBe(false)
    await put({ captureProxyRetentionDays: 30 })
    expect(h.userSettings.get('admin-a')).toEqual({
      userId: 'admin-a', ...structuredClone(CAPTURE_DEFAULTS), captureProxyRetentionDays: 30,
    })
    expect(h.instance).toMatchObject({ tunnelSourceUserId: 'member-tun', captureSourceUserId: 'admin-a' })
  })

  test('mirror falls back when the source account is gone: the confirmed Root, and the source follows', async () => {
    h.instance = instanceRow({ tunnelSourceUserId: 'deleted-user', rootUserId: 'admin-b', rootConfirmedAt: new Date() })
    await put({ tunnelsEnabled: true })
    expect(h.userSettings.get('admin-b')).toMatchObject({ tunnelsEnabled: true })
    expect(h.instance).toMatchObject({ tunnelSourceUserId: 'admin-b' })
    expect(changes()[0].after).toMatchObject({ mirroredTo: { tunnel: 'admin-b' } })
  })

  test('with no confirmed Root the oldest admin takes it; with no admin nobody does', async () => {
    h.instance = instanceRow({ captureSourceUserId: null, rootUserId: 'admin-b', rootConfirmedAt: null })
    await put({ captureProxyPort: 9443, stepUpPassword: 'right-password' })
    expect(h.userSettings.get('admin-a')).toMatchObject({ captureProxyPort: 9443 })
    expect(h.instance).toMatchObject({ captureSourceUserId: 'admin-a' })

    // No admin left: the legacy holder's change is saved, mirrored nowhere, and no source is named.
    h.userSettings.clear()
    h.instance = instanceRow({ tunnelSourceUserId: 'gone' })
    h.accounts.delete('admin-a'); h.accounts.delete('admin-b')
    h.cookies.clear()
    await signIn('member-tun')
    expect((await put({ tunnelsEnabled: true })).status).toBe(200)
    expect(h.userSettings.size).toBe(0)
    expect(h.instance).toMatchObject({ tunnelsEnabled: true, tunnelSourceUserId: null })
    expect(changes().at(-1)!.after).toMatchObject({ mirroredTo: { tunnel: null } })
  })

  test('a failed audit write rolls the change and the mirror back', async () => {
    h.failAudit = true
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await put({ tunnelsEnabled: true })
    expect(res.status).toBe(500)
    expect(h.instance).toEqual(instanceRow())
    expect(h.userSettings.size).toBe(0)
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('the capture proxy', () => {
  beforeEach(() => signIn('admin-a'))

  test('capture enable starts the proxy; disable stops it', async () => {
    h.instance = instanceRow({ captureProxyEnabled: false })
    await put({ captureProxyEnabled: true })
    expect(h.orch.mock.calls[0][0]).toMatch(/\/capture-proxy\/start$/)
    await put({ captureProxyEnabled: false })
    expect(h.orch.mock.calls[1][0]).toMatch(/\/capture-proxy\/stop$/)
  })

  test('port change recreates it with the saved values; an egress change alone does not', async () => {
    await put({ captureEgressBlockPrivate: false })
    expect(h.orch).not.toHaveBeenCalled()
    await put({ captureProxyPort: 9443 })
    const [url, init] = h.orch.mock.calls[0] as [string, RequestInit]
    expect(url).toMatch(/\/capture-proxy\/start$/)
    expect(JSON.parse(init.body as string)).toMatchObject({ port: 9443, egressBlockPrivate: false })
  })

  test('the orchestrator unreachable: saved, and a warning says it is not live', async () => {
    h.orch.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }))
    const res = await put({ captureProxyPort: 9443 })
    expect(res.status).toBe(200)
    expect(h.instance!.captureProxyPort).toBe(9443)
    expect((await res.json()).warnings[0]).toMatchObject({ service: 'orchestrator', message: 'The capture proxy was not started' })
  })

  test('values are validated as the settings PUT validates them', async () => {
    await put({ captureProxyRetentionDays: 0, captureProxyScope: 'everything', scaIntelIgnoreSuffixes: 'Good.TEST, bad_value!' })
    expect(h.instance).toMatchObject({ captureProxyRetentionDays: 1, captureProxyScope: 'both', scaIntelIgnoreSuffixes: 'good.test' })
  })
})

// Review of step 3.7: with RBAC_IDENTITY_ENABLED on this PUT is the only TrafficMind write (the
// user settings route answers 409 moved_to_instance_settings), so the capture fields ask
// platform:traffic_capture of the real person, not the administrator account alone.
describe('the capture write asks platform:traffic_capture (permissions switch on)', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true, permissions: true })
    clearCapabilityCachesForTests()
    account('admin-um', 'admin', { adminProfileId: 'builtin:user-manager' })
    account('admin-po', 'admin', { adminProfileId: 'builtin:platform-operator' })
    h.instance = instanceRow({ captureProxyEnabled: false })
  })

  test('an admin whose profile lacks it is refused 403 naming it: nothing written, nothing started', async () => {
    await signIn('admin-um')
    const res = await put({ captureProxyEnabled: true })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'platform:traffic_capture', fields: ['captureProxyEnabled'] })
    expect(h.instance).toEqual(instanceRow({ captureProxyEnabled: false }))
    expect(changes()).toEqual([])
    expect(h.orch).not.toHaveBeenCalled()
  })

  test('a profile holding it changes it', async () => {
    await signIn('admin-po')
    expect((await put({ captureProxyEnabled: true })).status).toBe(200)
    expect(h.instance!.captureProxyEnabled).toBe(true)
    expect(h.orch.mock.calls[0][0]).toMatch(/\/capture-proxy\/start$/)
  })

  test('switch off: every admin changes it, as before', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await signIn('admin-um')
    expect((await put({ captureProxyEnabled: true })).status).toBe(200)
    expect(h.instance!.captureProxyEnabled).toBe(true)
  })
})
