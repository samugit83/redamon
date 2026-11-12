/**
 * The legacy access review with RBAC_PERMISSIONS_ENABLED on (step 3.15, HD-02, OQ-26): the
 * card's decisions write the member's overrides through the account permission writer of step
 * 3.11 (its rules, step-up, `user.permissions_changed` row and sign-out on a removal) before the
 * review records them as before. A Keep is an override grant of the platform permission with the
 * reason "kept from 7.7.x" and a 90-day end; a Remove takes the override and the column grant.
 * With the switch off the same decisions are Phase 1's (route.test.ts holds them).
 *
 * Real session helpers, tokens, bcrypt, step-up, resolution, hierarchy and writer; the database
 * is the in-memory accountDb (transactions roll back), with the audit reads and the column's
 * `hasSome` filter the review sends added here; the agent is a fetch double. The conversion's
 * marker is seeded: the boot has converted, so the column no longer counts.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/legacy-grants/route.overrides.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')
vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests, loadPrincipal } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests, resolveCapabilities } from '@/lib/authz/capabilities'
import { setNowForTests } from '@/lib/authz/clock'
import { KEEP_ACTION, REMOVE_ACTION } from '@/lib/authz/updateReview'
import { LEGACY_OVERRIDES_MARKER } from '@/lib/authz/legacyOverrides'
import { __resetThrottle } from '@/lib/loginThrottle'
import { GET, POST } from './route'

type Row = Record<string, unknown>
const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const ROOT = 'root-1'
const ACCOUNTS = [ROOT, 'admin-1', 'admin-u', 'member-1', 'member-2']
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries(ACCOUNTS.map((id) => [id, bcrypt.hashSync(pw(id), 4)]))
const NOW = new Date('2026-11-12T10:00:00Z')
const DAY = 86_400_000
const ENDS = new Date(NOW.getTime() + 90 * DAY)

/** The audit reads and the `hasSome` filter the review and the conversion check send, on accountDb's rows. */
function teachAccountDb(d: AccountDb): void {
  const matches = (r: Row, where: Row = {}) => Object.entries(where).every(([k, c]) => {
    if (c === undefined) return true
    if (c !== null && typeof c === 'object' && !(c instanceof Date)) {
      const cond = c as Row
      if ('path' in cond) return ((r[k] ?? {}) as Row)[(cond.path as string[])[0]] === cond.equals
      if ('in' in cond) return (cond.in as unknown[]).includes(r[k])
    }
    return r[k] === c
  })
  const pick = (r: Row, select?: Row) => (select ? Object.fromEntries(Object.keys(select).map((k) => [k, r[k] ?? null])) : r)
  Object.assign(d.auditLog as unknown as Row, {
    findFirst: async (a: { where?: Row; select?: Row }) => {
      const r = d.audit().find((x) => matches(x, a.where))
      return r ? pick(r, a.select) : null
    },
    findMany: async (a: { where?: Row; select?: Row }) => d.audit().filter((x) => matches(x, a.where)).map((x) => pick(x, a.select)),
  })
  const findMany = d.user.findMany
  Object.assign(d.user, {
    findMany: async (a: { where?: Row; select?: Row } = {}) => {
      const some = (a.where?.legacyGrants as { hasSome?: string[] } | undefined)?.hasSome
      const rows = await findMany(a)
      return some ? rows.filter((r) => ((d.account(String(r.id))?.legacyGrants as string[]) ?? []).some((g) => some.includes(g))) : rows
    },
  })
}

function req(body: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/admin/legacy-grants', {
    method: 'POST', headers: { host: 'redamon.test', 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}

async function signIn(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

async function post(actor: string, body: Record<string, unknown>) {
  await signIn(actor)
  const res = await POST(req(body))
  return { res, body: await res.clone().json().catch(() => ({})) as Row }
}

async function list(actor: string) {
  await signIn(actor)
  const res = await GET()
  return { res, body: await res.clone().json() as Row }
}

const audit = (action: string) => db().audit().filter((a) => a.action === action)
const grantsOf = (id: string) => db().account(id)!.legacyGrants as string[]
const wsCloses = () => fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/ws/close'))

async function held(userId: string): Promise<readonly string[]> {
  clearPrincipalCacheForTests()
  return (await resolveCapabilities((await loadPrincipal(userId, { fresh: true }))!, { fresh: true })).held
}

/** Everything a refused decision could have touched. */
const state = () => JSON.stringify({ users: ACCOUNTS.map((id) => db().account(id)), overrides: db().overrides(), audit: db().audit() })

teachAccountDb(db())

beforeEach(async () => {
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin', password: HASH[ROOT] },
    { id: 'admin-1', role: 'admin', password: HASH['admin-1'] },
    { id: 'admin-u', role: 'admin', password: HASH['admin-u'], adminProfileId: 'builtin:user-manager' },
    { id: 'member-1', password: HASH['member-1'], legacyGrants: ['kali_terminal', 'shell_sessions'] },
    { id: 'member-2', password: HASH['member-2'], legacyGrants: ['tunnels'] },
  ])
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  await db().auditLog.create({ data: { action: LEGACY_OVERRIDES_MARKER, targetType: 'system', source: 'system', after: {} } })
  setFlagsForTests({ identity: true, permissions: true })
  setNowForTests(() => NOW)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetThrottle()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ closed: 1 }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(console, 'info').mockImplementation(() => {})
})

afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Keep with the switch on (card writes overrides)', () => {
  test('an override grant with the reason and a 90-day end, through the permission writer and its audit, then the Keep row', async () => {
    const without = await post('admin-1', { action: 'keep', userId: 'member-1', grant: 'kali_terminal' })
    expect([without.res.status, without.body.code]).toEqual([403, 'step_up_required'])
    expect(db().overrides()).toEqual([])
    expect(audit(KEEP_ACTION)).toEqual([])

    const { res, body } = await post('admin-1', { action: 'keep', userId: 'member-1', grant: 'kali_terminal', stepUpPassword: pw('admin-1') })
    expect([res.status, body]).toEqual([200, { action: 'keep', userId: 'member-1', grant: 'kali_terminal', changed: true }])
    expect(db().overrides()).toEqual([expect.objectContaining({
      userId: 'member-1', permission: 'platform:kali_terminal', effect: 'grant', expiresAt: ENDS,
      reason: 'kept from 7.7.x', grantedById: 'admin-1',
    })])
    const [change] = audit('user.permissions_changed')
    expect(change).toMatchObject({ actorId: 'admin-1', targetId: 'member-1', permission: 'users:assign_permissions', source: 'api' })
    expect((change.after as Row).added).toEqual(['platform:kali_terminal'])
    expect((change.after as Row).overrides).toEqual([
      { permission: 'platform:kali_terminal', effect: 'grant', expiresAt: ENDS.toISOString(), reason: 'kept from 7.7.x' },
    ])
    expect(audit(KEEP_ACTION).map((a) => [a.targetId, (a.after as Row).grant])).toEqual([['member-1', 'kali_terminal']])
    // The column is left as it is: with the switch off again Phase 1 reads it.
    expect(grantsOf('member-1')).toEqual(['kali_terminal', 'shell_sessions'])
    // The kept tool is held through the override; the undecided one lapsed.
    expect(await held('member-1')).toContain('platform:kali_terminal')
    expect(await held('member-1')).not.toContain('platform:shell_sessions')
  })

  test('the listing shows it kept until its end, the others pending; past the end it is pending again', async () => {
    await post('admin-1', { action: 'keep', userId: 'member-1', grant: 'kali_terminal', stepUpPassword: pw('admin-1') })
    const { res, body } = await list('admin-1')
    expect(res.status).toBe(200)
    expect(body).toEqual({
      overrides: true, keepDays: 90, pending: 2,
      holders: [
        expect.objectContaining({ id: 'member-1', grants: [
          { grant: 'kali_terminal', state: 'kept', expiresAt: ENDS.toISOString() },
          { grant: 'shell_sessions', state: 'pending' },
        ] }),
        expect.objectContaining({ id: 'member-2', grants: [{ grant: 'tunnels', state: 'pending' }] }),
      ],
    })
    setNowForTests(() => ENDS)
    const later = await list('admin-1')
    expect((later.body.holders as Row[])[0].grants).toEqual([
      { grant: 'kali_terminal', state: 'pending' }, { grant: 'shell_sessions', state: 'pending' },
    ])
  })

  test('a person who does not hold the tool cannot keep it (User manager): refused, nothing written', async () => {
    const before = state()
    const { res, body } = await post('admin-u', { action: 'keep', userId: 'member-1', grant: 'tunnels', stepUpPassword: pw('admin-u') })
    expect(res.status).toBe(409)
    expect(body.code).toBe('not_held')
    const own = await post('admin-u', { action: 'keep', userId: 'member-2', grant: 'tunnels', stepUpPassword: pw('admin-u') })
    expect([own.res.status, own.body.code]).toEqual([403, 'not_held'])
    expect(own.body.permissions).toEqual(['platform:tunnels'])
    expect(state()).toBe(before)
  })

  test('a deny override in force refuses the Keep: a person chose it on the account', async () => {
    db().seedOverride({ userId: 'member-1', permission: 'platform:kali_terminal', effect: 'deny' })
    const before = state()
    const { res, body } = await post('admin-1', { action: 'keep', userId: 'member-1', grant: 'kali_terminal', stepUpPassword: pw('admin-1') })
    expect([res.status, body.code, body.permission]).toEqual([409, 'overridden', 'platform:kali_terminal'])
    expect(state()).toBe(before)
  })

  test('a grant override in force is left as it is; the Keep row is recorded', async () => {
    db().seedOverride({ userId: 'member-1', permission: 'platform:kali_terminal', effect: 'grant', reason: 'on call' })
    const { res } = await post('admin-1', { action: 'keep', userId: 'member-1', grant: 'kali_terminal' })
    expect(res.status).toBe(200)
    expect(db().overrides()).toEqual([expect.objectContaining({ permission: 'platform:kali_terminal', expiresAt: null, reason: 'on call' })])
    expect(audit('user.permissions_changed')).toEqual([])
    expect(audit(KEEP_ACTION)).toHaveLength(1)
  })
})

describe('Remove with the switch on', () => {
  test('the override and the column grant go; the member loses the tool and is signed out', async () => {
    await post('admin-1', { action: 'keep', userId: 'member-1', grant: 'kali_terminal', stepUpPassword: pw('admin-1') })
    fetchMock.mockClear()
    const { res, body } = await post('admin-1', { action: 'remove', userId: 'member-1', grant: 'kali_terminal' })
    expect(res.status).toBe(200)
    expect(body).toMatchObject({ action: 'remove', changed: true, terminal: { closed: 1 } })
    expect(db().overrides()).toEqual([])
    expect(grantsOf('member-1')).toEqual(['shell_sessions'])
    expect(audit(REMOVE_ACTION).map((a) => (a.after as Row).grant)).toEqual(['kali_terminal'])
    const changes = audit('user.permissions_changed')
    expect((changes[1].after as Row).removed).toEqual(['platform:kali_terminal'])
    expect(db().account('member-1')!.sessionVersion).toBe(1)
    expect(wsCloses().length).toBeGreaterThan(0)
    expect(await held('member-1')).not.toContain('platform:kali_terminal')
  })

  test('a lapsed grant has no override: only the column and its Remove row change', async () => {
    const { res } = await post('admin-1', { action: 'remove', userId: 'member-1', grant: 'shell_sessions' })
    expect(res.status).toBe(200)
    expect(audit('user.permissions_changed')).toEqual([])
    expect(grantsOf('member-1')).toEqual(['kali_terminal'])
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })

  test('a deny override stays', async () => {
    db().seedOverride({ userId: 'member-1', permission: 'platform:kali_terminal', effect: 'deny' })
    await post('admin-1', { action: 'remove', userId: 'member-1', grant: 'kali_terminal' })
    expect(db().overrides()).toEqual([expect.objectContaining({ permission: 'platform:kali_terminal', effect: 'deny' })])
  })
})

describe('Keep all and Remove all with the switch on', () => {
  test('one writer change per member, then the review rows', async () => {
    const without = await post('admin-1', { action: 'keep_all' })
    expect([without.res.status, without.body.code]).toEqual([403, 'step_up_required'])
    expect(db().overrides()).toEqual([])

    const keep = await post('admin-1', { action: 'keep_all', stepUpPassword: pw('admin-1') })
    expect([keep.res.status, keep.body]).toEqual([200, { action: 'keep_all', changed: 3 }])
    expect(db().overrides().map((o) => [o.userId, o.permission, o.reason, o.expiresAt]).sort()).toEqual([
      ['member-1', 'platform:kali_terminal', 'kept from 7.7.x', ENDS],
      ['member-1', 'platform:shell_sessions', 'kept from 7.7.x', ENDS],
      ['member-2', 'platform:tunnels', 'kept from 7.7.x', ENDS],
    ])
    expect(audit('user.permissions_changed').map((a) => a.targetId)).toEqual(['member-1', 'member-2'])
    expect(audit(KEEP_ACTION)).toHaveLength(3)
    expect((await list('admin-1')).body.pending).toBe(0)

    const remove = await post('admin-1', { action: 'remove_all' })
    expect(remove.res.status).toBe(200)
    expect(remove.body).toMatchObject({ action: 'remove_all', changed: 3 })
    expect(db().overrides()).toEqual([])
    expect(grantsOf('member-1')).toEqual([])
    expect(grantsOf('member-2')).toEqual([])
    expect(audit(REMOVE_ACTION)).toHaveLength(3)
  })
})

describe('the switch off', () => {
  test('the same Keep writes only the review row (Phase 1); the listing has no override fields', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    clearPrincipalCacheForTests()
    const { res, body } = await post('admin-1', { action: 'keep', userId: 'member-1', grant: 'kali_terminal' })
    expect([res.status, body.changed]).toEqual([200, true])
    expect(db().overrides()).toEqual([])
    expect(audit('user.permissions_changed')).toEqual([])
    expect(audit(KEEP_ACTION)).toHaveLength(1)
    const listing = await list('admin-1')
    expect(listing.body).not.toHaveProperty('overrides')
    expect((listing.body.holders as Row[])[0].grants).toEqual([
      { grant: 'kali_terminal', state: 'kept' }, { grant: 'shell_sessions', state: 'pending' },
    ])
  })
})
