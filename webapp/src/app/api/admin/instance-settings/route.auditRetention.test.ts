/**
 * The audit retention is the confirmed Root's (step 6.6; AU-04, OQ-40; E2E P6-05's Root half): with
 * RBAC_GOVERNANCE_ENABLED on, every administrator reads `auditRetention` of /api/admin/instance-settings
 * (the days in force, a change waiting with its date, the floor and the delay); `auditRetentionDays`
 * changes only by the confirmed Root, with its password, and never at once: it waits 7 days as a
 * pending change, audited when asked, cancelled by asking for the value in force, in force by itself
 * once its date has passed (read lazily, before the sweep moves it). Below the 90-day floor, a fraction
 * or text is 400 `invalid_field`. An admin, the tunnel holder and an unconfirmed Root get 403
 * `root_only` and nothing is written. With the switch off the route is the one before this step: the
 * retention is neither shown nor read from the body (governance.flags.off.test.ts points here).
 *
 * Same doubles as route.sharingPolicy.test.ts: the real session, principal, Root, route and
 * lib/authz/auditRetention.ts over an in-memory Prisma; the step-up and the clock are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/instance-settings/route.auditRetention.test.ts
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
  audit: [] as Record<string, unknown>[],
  failAudit: null as string | null,
  locks: [] as string[],
}))

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (h.cookies.has(name) ? { value: h.cookies.get(name) } : undefined),
    delete: (name: string) => { h.cookies.delete(name) },
  })),
}))

vi.mock('@/lib/prisma', async () => {
  const { Prisma } = await import('@prisma/client')
  const clone = <T,>(v: T): T => structuredClone(v)
  const stored = (data: Row): Row =>
    Object.fromEntries(Object.entries(data).map(([k, v]) => [k, v === Prisma.DbNull ? null : clone(v)]))
  const client = {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => clone(h.accounts.get(where.id) ?? null),
      findFirst: async () => null,
      findMany: async () => [],
    },
    // The quotas editor's names (a Full admin holds instance:quotas): none here.
    permissionSet: { findMany: async () => [] },
    instanceSettings: {
      findUnique: async () => clone(h.instance),
      update: async ({ data }: { data: Row }) => {
        h.instance = { ...h.instance!, ...stored(data), updatedAt: new Date() }
        return clone(h.instance)
      },
    },
    userSettings: { upsert: async () => ({}) },
    auditLog: {
      findFirst: async ({ where }: { where: { action: string } }) => clone(h.audit.find((r) => r.action === where.action) ?? null),
      create: async ({ data }: { data: Row }) => {
        if (h.failAudit && data.action === h.failAudit) throw Object.assign(new Error('audit table unavailable'), { code: 'P1001' })
        h.audit.push(clone(data))
        return data
      },
    },
    $executeRaw: async (sql: TemplateStringsArray, ...values: unknown[]) => {
      h.locks.push(`${sql.join('?')}|${values.join(',')}`)
      return 1
    },
    $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
      const snapshot = { instance: clone(h.instance), audit: clone(h.audit) }
      try {
        return await fn(client)
      } catch (err) {
        h.instance = snapshot.instance
        h.audit = snapshot.audit
        throw err
      }
    },
  }
  return { default: client }
})

vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn(async () => new Response('{}')) }))
vi.mock('@/lib/authz/stepUp', () => ({
  requireStepUp: async (_req: unknown, password: unknown) => {
    const { NextResponse } = await import('next/server')
    return password === 'right-password'
      ? null
      : NextResponse.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })
  },
}))

import { GET, PUT } from './route'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { CAPTURE_DEFAULTS } from '@/lib/sharedInstanceSettings'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'

const NOW = new Date('2026-11-13T12:00:00.000Z')
const DAY = 86_400_000
const LATER = (days: number) => new Date(NOW.getTime() + days * DAY)
const GOV = { identity: true, permissions: true, governance: true }

function account(id: string, role: string, over: Row = {}) {
  h.accounts.set(id, {
    id, email: `${id}@e2e.local`, name: id, role, password: 'hash', createdAt: new Date('2026-01-01T00:00:00Z'),
    legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null,
    lastLoginAt: null, ...over,
  })
}

async function signIn(id: string) {
  h.cookies.set('redamon-auth', await createToken(id, h.accounts.get(id)!.role as string))
}

const POLICY = {
  passwordMinLength: 12, passwordAskChangeIfShort: false, memberSessionTtlHours: 168, adminSessionTtlHours: 12,
  adminIdleMinutes: 60, inviteTtlHours: 168, resetTtlHours: 4, publicBaseUrl: null,
  impersonationMaxMinutes: 720, impersonationReasonRequired: false, impersonationNotifyTarget: true,
}

function instanceRow(over: Row = {}): Row {
  return {
    id: 'instance', rootUserId: 'root-1', rootConfirmedAt: new Date('2026-11-12T08:00:00Z'),
    tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', tunnelSourceUserId: null,
    ...structuredClone(CAPTURE_DEFAULTS), captureSourceUserId: null, updatedById: null, ...POLICY,
    sharingPolicy: {}, quotas: {}, auditRetentionDays: null, auditRetentionPending: null, ...over,
  }
}

const put = (body: unknown) =>
  PUT(new NextRequest('http://redamon.test/api/admin/instance-settings', {
    method: 'PUT',
    headers: { host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }))
const get = () => GET(new NextRequest('http://redamon.test/api/admin/instance-settings'))
const rows = (action: string) => h.audit.filter((r) => r.action === action)
const retentionRows = () => h.audit.filter((r) => String(r.action).startsWith('instance.audit_retention'))

beforeEach(() => {
  h.cookies.clear(); h.accounts.clear()
  h.audit = [{ action: 'system.rbac_legacy_grants_cutoff', createdAt: new Date('2026-11-11T08:00:00Z') }]
  h.failAudit = null
  h.locks = []
  h.instance = instanceRow()
  setFlagsForTests(GOV)
  setNowForTests(() => NOW)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  resetSharedToolsForTests()
  account('root-1', 'admin')
  account('admin-a', 'admin', { createdAt: new Date('2026-01-05T00:00:00Z') })
  account('member-tun', 'standard', { legacyGrants: ['tunnels'] })
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

const EMPTY = { days: null, pending: null, minDays: 90, delayDays: 7 }

describe('who reads the audit retention', () => {
  test('every administrator reads it as it is in force; only the confirmed Root may change it', async () => {
    await signIn('admin-a')
    expect(await (await get()).json()).toMatchObject({ auditRetention: EMPTY, canManageAuditRetention: false })
    await signIn('root-1')
    expect(await (await get()).json()).toMatchObject({ auditRetention: EMPTY, canManageAuditRetention: true })
  })

  test('the tunnel holder, a member, does not see it', async () => {
    await signIn('member-tun')
    const body = await (await get()).json()
    expect(body.canManageTunnels).toBe(true)
    expect('auditRetention' in body).toBe(false)
    expect('canManageAuditRetention' in body).toBe(false)
  })
})

describe('retention floor and values (P6-05: 30 refused)', () => {
  test.each([[30], [89], [36_501], [120.5], ['120'], [true], [{ days: 120 }]])('%j: 400 invalid_field, nothing written, no password asked', async (value) => {
    await signIn('root-1')
    const res = await put({ auditRetentionDays: value })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field: 'auditRetentionDays' })
    expect(h.instance!.auditRetentionPending).toBeNull()
    expect(retentionRows()).toEqual([])
  })
})

describe('pending change applies after 7 days (P6-05: 120 pending 7 days)', () => {
  test('Root asks for 120 days with its password: stored as pending, audited, answered; nothing in force changes', async () => {
    await signIn('root-1')
    const res = await put({ auditRetentionDays: 120, stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    const pending = { days: 120, requestedAt: NOW.toISOString(), effectiveAt: LATER(7).toISOString() }
    expect((await res.json()).auditRetention).toEqual({ ...EMPTY, pending })
    expect(h.instance!.auditRetentionDays).toBeNull()
    expect(h.instance!.auditRetentionPending).toEqual({ ...pending, requestedById: 'root-1' })
    expect(rows('instance.audit_retention_requested')).toMatchObject([{
      actorId: 'root-1', targetType: 'instance', targetId: 'instance', source: 'api',
      before: { days: null }, after: { days: 120, effectiveAt: LATER(7).toISOString() },
    }])
    expect(rows('instance.settings_changed')).toEqual([])
    expect(h.locks).toEqual([expect.stringContaining('pg_advisory_xact_lock')])
    expect(JSON.stringify(h.audit)).not.toContain('right-password')
  })

  test('a day before its date the change still waits; from its date it is in force, before any sweep moves it', async () => {
    await signIn('root-1')
    await put({ auditRetentionDays: 120, stepUpPassword: 'right-password' })
    setNowForTests(() => new Date(LATER(7).getTime() - 1))
    expect((await (await get()).json()).auditRetention).toMatchObject({ days: null, pending: { days: 120 } })
    setNowForTests(() => LATER(7))
    expect((await (await get()).json()).auditRetention).toEqual({ ...EMPTY, days: 120 })
    expect(h.instance!.auditRetentionDays).toBeNull()
  })

  test('back to keep forever is a change too: it waits its 7 days', async () => {
    h.instance = instanceRow({ auditRetentionDays: 365 })
    await signIn('root-1')
    const body = await (await put({ auditRetentionDays: null, stepUpPassword: 'right-password' })).json()
    expect(body.auditRetention).toMatchObject({ days: 365, pending: { days: null, effectiveAt: LATER(7).toISOString() } })
  })

  test('a new value while one waits replaces it, with a new date; the audit row names what it replaced', async () => {
    await signIn('root-1')
    await put({ auditRetentionDays: 120, stepUpPassword: 'right-password' })
    setNowForTests(() => LATER(2))
    const body = await (await put({ auditRetentionDays: 180, stepUpPassword: 'right-password' })).json()
    expect(body.auditRetention.pending).toMatchObject({ days: 180, effectiveAt: LATER(9).toISOString() })
    expect(rows('instance.audit_retention_requested').at(-1)).toMatchObject({
      before: { days: null, replaced: { days: 120, effectiveAt: LATER(7).toISOString() } }, after: { days: 180 },
    })
  })

  test('asking for the value in force while one waits cancels it (audited); asking again for the waiting value changes nothing', async () => {
    await signIn('root-1')
    await put({ auditRetentionDays: 120, stepUpPassword: 'right-password' })
    const again = await put({ auditRetentionDays: 120 })
    expect(again.status).toBe(200)
    expect(rows('instance.audit_retention_requested')).toHaveLength(1)
    const res = await put({ auditRetentionDays: null, stepUpPassword: 'right-password' })
    expect((await res.json()).auditRetention).toEqual(EMPTY)
    expect(h.instance!.auditRetentionPending).toBeNull()
    expect(rows('instance.audit_retention_cancelled')).toMatchObject([{
      actorId: 'root-1', before: { days: 120, effectiveAt: LATER(7).toISOString() }, after: { days: null },
    }])
  })

  test('a new request after a change came into force (not yet moved by the sweep): it is moved and audited first', async () => {
    h.instance = instanceRow({
      auditRetentionDays: null,
      auditRetentionPending: { days: 120, requestedAt: LATER(-10).toISOString(), effectiveAt: LATER(-3).toISOString(), requestedById: 'root-1' },
    })
    await signIn('root-1')
    const body = await (await put({ auditRetentionDays: 200, stepUpPassword: 'right-password' })).json()
    expect(body.auditRetention).toMatchObject({ days: 120, pending: { days: 200 } })
    expect(h.instance!.auditRetentionDays).toBe(120)
    expect(retentionRows().map((r) => r.action)).toEqual(['instance.audit_retention_activated', 'instance.audit_retention_requested'])
  })

  test('the value in force with nothing waiting: no change, no password, no audit row', async () => {
    await signIn('root-1')
    const res = await put({ auditRetentionDays: null })
    expect(res.status).toBe(200)
    expect(retentionRows()).toEqual([])
  })

  test('with a security policy change in the same save: both written, each audited', async () => {
    await signIn('root-1')
    const res = await put({ passwordMinLength: 14, auditRetentionDays: 120, stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    expect(h.instance!.passwordMinLength).toBe(14)
    expect((await res.json()).auditRetention.pending).toMatchObject({ days: 120 })
    expect(rows('instance.settings_changed')).toMatchObject([{ after: { fields: ['passwordMinLength'] } }])
    expect(rows('instance.audit_retention_requested')).toHaveLength(1)
  })

  test('fail-closed: when the audit row cannot be written nothing is stored (500)', async () => {
    h.failAudit = 'instance.audit_retention_requested'
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('root-1')
    const res = await put({ auditRetentionDays: 120, stepUpPassword: 'right-password' })
    expect(res.status).toBe(500)
    expect(h.instance!.auditRetentionPending).toBeNull()
    expect(retentionRows()).toEqual([])
  })
})

describe('only the confirmed Root changes it', () => {
  test('without its password: step_up_required, nothing written', async () => {
    await signIn('root-1')
    const res = await put({ auditRetentionDays: 120 })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('step_up_required')
    expect(h.instance!.auditRetentionPending).toBeNull()
  })

  test.each([
    ['an admin', 'admin-a', false],
    ['the tunnel holder', 'member-tun', false],
    ['an unconfirmed Root', 'root-1', true],
  ])('%s: 403 root_only, nothing written, even with a password', async (_who, id, unconfirmed) => {
    if (unconfirmed) h.instance = instanceRow({ rootConfirmedAt: null, rootAssignedBy: 'automatic' })
    await signIn(id)
    const res = await put({ auditRetentionDays: 120, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_only')
    expect(body.error).toContain('Only Root can change the audit retention.')
    expect(h.instance!.auditRetentionPending).toBeNull()
    expect(retentionRows()).toEqual([])
  })
})

describe('with RBAC_GOVERNANCE_ENABLED off the route is the one before this step', () => {
  test('the retention is neither shown nor read from a body', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    await signIn('root-1')
    const body = await (await get()).json()
    expect('auditRetention' in body).toBe(false)
    expect('canManageAuditRetention' in body).toBe(false)
    const res = await put({ auditRetentionDays: 120, stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    expect(h.instance!.auditRetentionPending).toBeNull()
    expect(retentionRows()).toEqual([])
    expect(h.locks).toEqual([])
    // Not even a bad value is looked at.
    expect((await put({ auditRetentionDays: 'soon' })).status).toBe(200)
  })
})
