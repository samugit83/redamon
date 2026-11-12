/**
 * GET /api/account/activity (step 2.11, UI-09, ID-19, ID-30): "My activity" on the My account page.
 * The signed-in account (the real one, never an account an admin is acting as) reads its notices
 * (pending and already shown, step 2.10's list) and the audit rows about it from a safe list:
 * credentials resets and the first sign-in after one, email changes, act-as on it, Root changes.
 * Each row shows only its safe fields and who did it by name and email, never an account id, a
 * token, a hash or a password. Identity switch on only (404 without it, nothing read).
 *
 * Real session helpers and tokens; Prisma is a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))

type Row = Record<string, unknown>
const h = vi.hoisted(() => ({
  jar: {} as { auth?: string; actAs?: string },
  users: {} as Record<string, Record<string, unknown>>,
  audit: [] as Row[],
  actAs: [] as Row[],
  calls: [] as { model: string; args: unknown }[],
  fail: false,
}))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', () => {
  const pick = (r: Row, select?: Row) =>
    select ? Object.fromEntries(Object.keys(select).filter((k) => select[k]).map((k) => [k, r[k]])) : { ...r }
  return {
    default: {
      user: {
        findUnique: async (a: { where: { id: string }; select?: Row }) => {
          h.calls.push({ model: 'user.findUnique', args: a })
          const r = h.users[a.where.id]
          return r ? pick(r, a.select) : null
        },
        findMany: async (a: { where: { id: { in: string[] } }; select?: Row }) => {
          h.calls.push({ model: 'user.findMany', args: a })
          return a.where.id.in.filter((id) => h.users[id]).map((id) => pick(h.users[id], a.select))
        },
      },
      auditLog: {
        findMany: async (a: unknown) => {
          h.calls.push({ model: 'auditLog.findMany', args: a })
          if (h.fail) throw Object.assign(new Error('relation "audit_log" quoted secret'), { code: 'P2021' })
          return h.audit
        },
      },
      actAsAudit: {
        findMany: async (a: unknown) => {
          h.calls.push({ model: 'actAsAudit.findMany', args: a })
          return h.actAs
        },
      },
    },
  }
})

import { createToken, createActAsToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { SAFE_ACTIVITY_ACTIONS } from '@/lib/authz/accountActivity'
import { GET } from './route'

const account = (id: string, role: string, over: Row = {}) => ({
  id, name: id === 'admin-1' ? 'Laura' : 'Marco', email: `${id}@e2e.local`, role, password: 'hash', createdAt: new Date(0),
  legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null, lastLoginAt: null,
  pendingNotices: [], ...over,
})
const get = () => GET()
async function signIn(id: string, actingAs?: string) {
  h.jar.auth = await createToken(id, String(h.users[id].role), 0)
  h.jar.actAs = actingAs ? await createActAsToken(id, actingAs) : undefined
}
const at = (iso: string) => new Date(iso)

beforeEach(() => {
  h.jar = {}
  h.users = { 'admin-1': account('admin-1', 'admin'), 'member-1': account('member-1', 'standard') }
  h.audit = []
  h.actAs = []
  h.calls = []
  h.fail = false
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
})
afterEach(() => setFlagsForTests(null))

describe('activity lists only safe actions about me', () => {
  test('asks the audit log for the safe actions targeting the account, newest first, a bounded page', async () => {
    await signIn('member-1')
    expect((await get()).status).toBe(200)
    const audit = h.calls.find((c) => c.model === 'auditLog.findMany')!.args as Row
    expect(audit).toMatchObject({
      where: { targetType: 'user', targetId: 'member-1', action: { in: [...SAFE_ACTIVITY_ACTIONS] } },
      orderBy: { createdAt: 'desc' },
      take: 50,
    })
    const actAs = h.calls.find((c) => c.model === 'actAsAudit.findMany')!.args as Row
    expect(actAs).toMatchObject({ where: { targetUserId: 'member-1' }, orderBy: { createdAt: 'desc' }, take: 50 })
  })

  test('the safe list: resets, the sign-in after one, email changes, Root changes; no other account action', () => {
    expect([...SAFE_ACTIVITY_ACTIONS].sort()).toEqual([
      'auth.login.after_reset',
      'root.confirmed_by_host',
      'root.set_by_host',
      'root.transfer',
      'root.transfer_cancelled',
      'root.transfer_declined',
      'root.transfer_offered',
      'system.rbac_root_assigned',
      'user.credentials_reset',
      'user.email_changed',
    ])
  })

  test('each row shows its safe fields and who did it by name and email, never an id or a secret', async () => {
    h.audit = [
      {
        id: 'a1', action: 'user.credentials_reset', createdAt: at('2026-11-12T10:00:00Z'), actorId: 'admin-1', actorEmail: 'admin-1@e2e.local',
        before: null, after: { mode: 'link', reason: 'Locked out', mustChangePassword: false, sessionVersion: 4, revokedMcpTokens: 2, cancelledLinks: 1, expiresAt: '2026-11-12T14:00:00Z' },
      },
      {
        id: 'a2', action: 'user.email_changed', createdAt: at('2026-11-12T11:00:00Z'), actorId: 'member-1', actorEmail: 'old@e2e.local',
        before: { email: 'old@e2e.local' }, after: { email: 'member-1@e2e.local', actingAsUserId: 'x' },
      },
      {
        id: 'a3', action: 'auth.login.after_reset', createdAt: at('2026-11-12T12:00:00Z'), actorId: 'member-1', actorEmail: null,
        before: null, after: { ip: '203.0.113.9', ipTrusted: true, userAgent: 'Firefox', resetAt: '2026-11-12T10:00:00Z', resetMode: 'link' },
      },
      // A row the query should never return: dropped all the same.
      { id: 'a4', action: 'user.update', createdAt: at('2026-11-12T13:00:00Z'), actorId: 'admin-1', before: { name: 'M' }, after: { name: 'N' } },
    ]
    await signIn('member-1')
    const body = await (await get()).json()
    expect(body.events).toEqual([
      { id: 'a3', at: '2026-11-12T12:00:00.000Z', action: 'auth.login.after_reset', by: { name: 'Marco', email: 'member-1@e2e.local' }, details: { ip: '203.0.113.9', userAgent: 'Firefox' } },
      { id: 'a2', at: '2026-11-12T11:00:00.000Z', action: 'user.email_changed', by: { name: 'Marco', email: 'old@e2e.local' }, details: { from: 'old@e2e.local', to: 'member-1@e2e.local' } },
      { id: 'a1', at: '2026-11-12T10:00:00.000Z', action: 'user.credentials_reset', by: { name: 'Laura', email: 'admin-1@e2e.local' }, details: { mode: 'link', reason: 'Locked out', mustChangePassword: false } },
    ])
    expect(JSON.stringify(body)).not.toContain('admin-1"')
    expect(JSON.stringify(body)).not.toMatch(/sessionVersion|revokedMcpTokens|expiresAt|actingAsUserId|actorId/)
  })

  test('act-as on me: who acted and when, from the act-as log', async () => {
    h.actAs = [
      { id: 'x2', adminId: 'admin-1', event: 'end', createdAt: at('2026-11-12T09:30:00Z'), source: 'api' },
      { id: 'x1', adminId: 'admin-1', event: 'start', createdAt: at('2026-11-12T09:00:00Z'), source: 'api' },
      { id: 'x0', adminId: 'gone-admin', event: 'start', createdAt: at('2026-11-11T09:00:00Z'), source: 'api' },
    ]
    await signIn('member-1')
    const body = await (await get()).json()
    expect(body.events).toEqual([
      { id: 'x2', at: '2026-11-12T09:30:00.000Z', action: 'act_as.end', by: { name: 'Laura', email: 'admin-1@e2e.local' }, details: {} },
      { id: 'x1', at: '2026-11-12T09:00:00.000Z', action: 'act_as.start', by: { name: 'Laura', email: 'admin-1@e2e.local' }, details: {} },
      { id: 'x0', at: '2026-11-11T09:00:00.000Z', action: 'act_as.start', by: null, details: {} },
    ])
  })

  test('Root changes: by the host or the system name nobody', async () => {
    h.audit = [
      { id: 'r1', action: 'system.rbac_root_assigned', createdAt: at('2026-11-12T08:00:00Z'), actorId: null, before: null, after: { userId: 'admin-1', rule: 'oldest_admin', candidateCount: 2 } },
      { id: 'r2', action: 'root.transfer', createdAt: at('2026-11-12T09:00:00Z'), actorId: 'admin-1', actorEmail: 'admin-1@e2e.local', before: { rootUserId: 'other' }, after: { rootUserId: 'admin-1', previousRootUserId: 'other', rootAssignedBy: 'transfer' } },
    ]
    await signIn('admin-1')
    const body = await (await get()).json()
    expect(body.events).toEqual([
      { id: 'r2', at: '2026-11-12T09:00:00.000Z', action: 'root.transfer', by: { name: 'Laura', email: 'admin-1@e2e.local' }, details: {} },
      { id: 'r1', at: '2026-11-12T08:00:00.000Z', action: 'system.rbac_root_assigned', by: null, details: { rule: 'oldest_admin' } },
    ])
  })

  test('the notices, pending and shown, newest first, without the admin id', async () => {
    h.users['member-1'].pendingNotices = [
      { id: 'n1', type: 'credentials_reset', at: '2026-11-10T10:00:00.000Z', by: { id: 'admin-1', name: 'Laura', email: 'admin-1@e2e.local' }, reason: null, mode: 'temporary', shownAt: '2026-11-10T11:00:00.000Z' },
      { id: 'n2', type: 'email_changed', at: '2026-11-12T10:00:00.000Z', by: { id: 'admin-1', name: 'Laura', email: 'admin-1@e2e.local' }, from: 'a@e2e.local', to: 'member-1@e2e.local', self: false },
      { type: 'garbage' },
    ]
    await signIn('member-1')
    const body = await (await get()).json()
    expect(body.notices).toEqual([
      { id: 'n2', type: 'email_changed', at: '2026-11-12T10:00:00.000Z', by: { name: 'Laura', email: 'admin-1@e2e.local' }, from: 'a@e2e.local', to: 'member-1@e2e.local', self: false, shownAt: null },
      { id: 'n1', type: 'credentials_reset', at: '2026-11-10T10:00:00.000Z', by: { name: 'Laura', email: 'admin-1@e2e.local' }, reason: null, mode: 'temporary', shownAt: '2026-11-10T11:00:00.000Z' },
    ])
    expect(JSON.stringify(body.notices)).not.toContain('"admin-1"')
  })

  test('nothing yet: two empty lists', async () => {
    await signIn('member-1')
    expect(await (await get()).json()).toEqual({ notices: [], events: [] })
  })
})

describe('whose activity', () => {
  test('an admin acting as a member reads its own activity, not the member\'s', async () => {
    await signIn('admin-1', 'member-1')
    await get()
    const audit = h.calls.find((c) => c.model === 'auditLog.findMany')!.args as { where: Row }
    expect(audit.where.targetId).toBe('admin-1')
  })

  test('signed out: 401, nothing read beyond the session', async () => {
    const res = await get()
    expect(res.status).toBe(401)
    expect(h.calls.filter((c) => c.model !== 'user.findUnique')).toEqual([])
  })

  test('a failed read answers 500 with its code only', async () => {
    h.fail = true
    await signIn('member-1')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const res = await get()
      expect(res.status).toBe(500)
      const body = await res.json()
      expect(body.code).toBe('P2021')
      expect(JSON.stringify(body)).not.toContain('quoted secret')
    } finally {
      err.mockRestore()
    }
  })
})

describe('switch off', () => {
  test('404 to everyone and nothing read', async () => {
    setFlagsForTests({ identity: false })
    for (const who of ['member-1', 'admin-1', null]) {
      if (who) await signIn(who)
      else h.jar = {}
      expect((await get()).status).toBe(404)
    }
    expect(h.calls).toEqual([])
  })
})
