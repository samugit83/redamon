/**
 * Impersonation under RBAC (step 3.14; IM-03, IM-04, IM-11, AU-03): the act-as rule, the instance
 * policy (reason, duration, the 720-minute ceiling), and the end rows, each written once.
 *
 * Real capability resolution; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'd'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  h.db = db
  return { default: db, prisma: db }
})
// An ended impersonation closes its agent sockets (actAs.sockets.test.ts): no agent here.
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn(async () => ({ ok: true, closed: 0, stoppedRuns: 0 })) }))

import { SignJWT } from 'jose'
import type { AccountDb } from './__testing__/accountDb'
import { createActAsToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearPrincipalCacheForTests, loadPrincipal } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'
import {
  DEFAULT_IMPERSONATION_MINUTES,
  IMPERSONATION_MAX_MINUTES,
  actAsRuleRefusal,
  endForRefusal,
  endPresentedActAs,
  impersonationPolicy,
  parseActAsRequest,
  recordActAsEnd,
  settleExpiredActAs,
} from './actAs'

const db = () => h.db as AccountDb
const principal = async (id: string) => (await loadPrincipal(id, { fresh: true }))!

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-1', role: 'admin' },
    { id: 'admin-2', role: 'admin' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'member-1' },
    { id: 'member-off', status: 'disabled' },
  ])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('targets: who may act as whom (IM-03)', () => {
  test('an admin holding users:impersonate acts as a member', async () => {
    expect(await actAsRuleRefusal(await principal('admin-1'), await principal('member-1'))).toBeNull()
  })

  test('an admin never acts as another admin', async () => {
    expect(await actAsRuleRefusal(await principal('admin-1'), await principal('admin-2'))).toBe('admin_target')
  })

  test('the confirmed Root acts as an admin', async () => {
    expect(await actAsRuleRefusal(await principal('root-1'), await principal('admin-2'))).toBeNull()
  })

  test('an unconfirmed Root does not act as an admin, but does as a member', async () => {
    db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'automatic', rootConfirmedAt: null })
    clearInstanceRootCacheForTests()
    expect(await actAsRuleRefusal(await principal('root-1'), await principal('admin-2'))).toBe('admin_target')
    expect(await actAsRuleRefusal(await principal('root-1'), await principal('member-1'))).toBeNull()
  })

  test('nobody acts as Root', async () => {
    expect(await actAsRuleRefusal(await principal('admin-1'), await principal('root-1'))).toBe('root_target')
  })

  test('an admin whose profile lacks users:impersonate acts as nobody (User manager)', async () => {
    expect(await actAsRuleRefusal(await principal('admin-um'), await principal('member-1'))).toBe('no_permission')
  })

  test('a member acts as nobody', async () => {
    expect(await actAsRuleRefusal(await principal('member-1'), await principal('member-off'))).toBe('not_an_admin')
  })

  test('nobody acts as a disabled account', async () => {
    expect(await actAsRuleRefusal(await principal('admin-1'), await principal('member-off'))).toBe('target_disabled')
  })

  test('acting as oneself is no act-as', async () => {
    expect(await actAsRuleRefusal(await principal('admin-um'), await principal('admin-um'))).toBeNull()
  })

  test('an actor known only by id and role holds nothing with the switch on (fail closed)', async () => {
    expect(await actAsRuleRefusal({ id: 'admin-1', role: 'admin' }, await principal('member-1'))).toBe('no_permission')
  })

  test.each([true, false])('switch off: Phase 2\'s rule, whatever the profile (identity %s)', async (identity) => {
    setFlagsForTests({ identity, permissions: false })
    clearPrincipalCacheForTests()
    clearInstanceRootCacheForTests()
    expect(await actAsRuleRefusal({ id: 'admin-um', role: 'admin' }, { id: 'member-1', role: 'standard' })).toBeNull()
    expect(await actAsRuleRefusal({ id: 'admin-1', role: 'admin' }, { id: 'admin-2', role: 'admin' })).toBeNull()
    expect(await actAsRuleRefusal({ id: 'admin-1', role: 'admin' }, { id: 'member-off', role: 'standard', status: 'disabled' })).toBeNull()
    expect(await actAsRuleRefusal({ id: 'admin-1', role: 'admin' }, { id: 'root-1', role: 'admin' })).toBe(identity ? 'root_target' : null)
    expect(await actAsRuleRefusal({ id: 'member-1', role: 'standard' }, { id: 'member-off', role: 'standard' })).toBe('not_an_admin')
  })

  test('how a refused cookie ends: promoted only for a cookie of this rule, a forbidden pair otherwise', () => {
    expect(endForRefusal('admin_target', true)).toBe('target_promoted')
    expect(endForRefusal('admin_target', false)).toBe('refused')
    expect(endForRefusal('root_target', true)).toBe('refused')
    expect(endForRefusal('no_permission', true)).toBe('invalidated')
    expect(endForRefusal('target_disabled', false)).toBe('target_disabled')
  })
})

describe('the instance policy (IM-04, OQ-32)', () => {
  test('no row: 720 minutes, no reason required, the account is told', async () => {
    db().seedInstance(null)
    expect(await impersonationPolicy()).toEqual({ maxMinutes: 720, reasonRequired: false, notifyTarget: true })
  })

  test('the stored values, the limit held to 720 whatever is stored', async () => {
    db().seedInstance({ impersonationMaxMinutes: 30, impersonationReasonRequired: true, impersonationNotifyTarget: false })
    expect(await impersonationPolicy()).toEqual({ maxMinutes: 30, reasonRequired: true, notifyTarget: false })
    db().seedInstance({ impersonationMaxMinutes: 1440, impersonationReasonRequired: false, impersonationNotifyTarget: true })
    expect((await impersonationPolicy()).maxMinutes).toBe(IMPERSONATION_MAX_MINUTES)
    for (const bad of [0, -5, 1.5, null]) {
      db().seedInstance({ impersonationMaxMinutes: bad })
      expect((await impersonationPolicy()).maxMinutes).toBe(720)
    }
  })

  const policy = { maxMinutes: 720, reasonRequired: false, notifyTarget: true }

  test('duration: 60 minutes by default, held to the limit, a whole number from 1', () => {
    expect(parseActAsRequest({}, policy)).toEqual({ reason: null, durationMinutes: DEFAULT_IMPERSONATION_MINUTES })
    expect(parseActAsRequest({ durationMinutes: 721 }, policy)).toEqual({ reason: null, durationMinutes: 720 })
    expect(parseActAsRequest({ durationMinutes: 90 }, { ...policy, maxMinutes: 30 })).toEqual({ reason: null, durationMinutes: 30 })
    expect(parseActAsRequest({}, { ...policy, maxMinutes: 30 })).toEqual({ reason: null, durationMinutes: 30 })
    for (const bad of [0, -1, 2.5, '60', true]) {
      expect(parseActAsRequest({ durationMinutes: bad }, policy)).toMatchObject({ status: 400, code: 'invalid_field', field: 'durationMinutes' })
    }
  })

  test('reason: required when Root says so, trimmed, at most 500 characters', () => {
    const required = { ...policy, reasonRequired: true }
    expect(parseActAsRequest({}, required)).toMatchObject({ status: 400, code: 'reason_required', field: 'reason' })
    expect(parseActAsRequest({ reason: '   ' }, required)).toMatchObject({ code: 'reason_required' })
    expect(parseActAsRequest({ reason: '  ticket #42 ' }, required)).toEqual({ reason: 'ticket #42', durationMinutes: 60 })
    expect(parseActAsRequest({ reason: 'x'.repeat(501) }, policy)).toMatchObject({ code: 'invalid_field', field: 'reason' })
    expect(parseActAsRequest({ reason: 42 }, policy)).toMatchObject({ code: 'invalid_field', field: 'reason' })
  })
})

describe('end rows: one per impersonation, with how it ended (AU-03, IM-11)', () => {
  const start = (over: Record<string, unknown> = {}) => db().seedActAs({
    adminId: 'admin-1', targetUserId: 'member-1', event: 'start', createdAt: new Date('2026-11-12T09:00:00Z'),
    reason: 'ticket #42', durationMinutes: 60, ...over,
  })

  test('the first end is written with its cause; a second one is not', async () => {
    start()
    expect(await recordActAsEnd({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'stopped' })).toBe(true)
    expect(await recordActAsEnd({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'expired' })).toBe(false)
    expect(db().actAs().filter((r) => r.event === 'end')).toEqual([
      expect.objectContaining({ adminId: 'admin-1', targetUserId: 'member-1', event: 'end', endedBy: 'stopped' }),
    ])
    expect(db().rawValues.some((v) => v[0] === 'rbac-act-as:admin-1')).toBe(true)
  })

  test('two at once write one end row (the per-admin lock)', async () => {
    start()
    const results = await Promise.all([
      recordActAsEnd({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'target_disabled' }),
      recordActAsEnd({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'target_disabled' }),
    ])
    expect(results.sort()).toEqual([false, true])
    expect(db().actAs().filter((r) => r.event === 'end')).toHaveLength(1)
  })

  test('a forbidden pair also writes act_as.refused, naming the admin as actor', async () => {
    start({ targetUserId: 'admin-2', durationMinutes: null, reason: null })
    await recordActAsEnd({ adminId: 'admin-1', targetUserId: 'admin-2', endedBy: 'refused', adminEmail: 'admin-1@e2e.local' })
    expect(db().audit()).toEqual([expect.objectContaining({
      action: 'act_as.refused', actorId: 'admin-1', actorEmail: 'admin-1@e2e.local', targetType: 'user', targetId: 'admin-2',
      permission: 'users:impersonate',
    })])
  })

  test('expiry: an impersonation past its limit with no end row gets `expired`, once; a running one does not', async () => {
    start({ createdAt: new Date('2026-11-12T09:00:00Z'), durationMinutes: 60 })
    start({ targetUserId: 'member-off', createdAt: new Date('2026-11-12T09:30:00Z'), durationMinutes: 60 })
    setNowForTests(() => new Date('2026-11-12T10:05:00Z'))
    expect(await settleExpiredActAs({ adminId: 'admin-1' })).toBe(1)
    expect(await settleExpiredActAs({ adminId: 'admin-1' })).toBe(0)
    expect(db().actAs().filter((r) => r.event === 'end')).toEqual([
      expect.objectContaining({ targetUserId: 'member-1', endedBy: 'expired' }),
    ])
  })

  test('a start row from before the switch carries no duration and is never settled', async () => {
    start({ durationMinutes: null, createdAt: new Date('2026-01-01T00:00:00Z') })
    setNowForTests(() => new Date('2026-11-12T10:05:00Z'))
    expect(await settleExpiredActAs({ targetUserId: 'member-1' })).toBe(0)
  })

  test('the presented cookie of this admin ends with the cause given, an expired one with `expired`', async () => {
    start()
    await endPresentedActAs('admin-1', await createActAsToken('admin-1', 'member-1', 600, { asv: 0 }), 'logout')
    expect(db().actAs().at(-1)).toMatchObject({ event: 'end', endedBy: 'logout' })

    start({ createdAt: new Date() })
    const iat = Math.floor(Date.now() / 1000) - 7200
    const expired = await new SignJWT({ sub: 'admin-1', act: 'member-1', asv: 0 }).setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(iat).setExpirationTime(iat + 60).sign(new TextEncoder().encode('d'.repeat(64)))
    await endPresentedActAs('admin-1', expired, 'stopped')
    expect(db().actAs().at(-1)).toMatchObject({ event: 'end', endedBy: 'expired' })
  })

  test("another admin's cookie ends nothing", async () => {
    start()
    await endPresentedActAs('admin-2', await createActAsToken('admin-1', 'member-1', 600, { asv: 0 }), 'stopped')
    expect(db().actAs().filter((r) => r.event === 'end')).toEqual([])
  })
})
