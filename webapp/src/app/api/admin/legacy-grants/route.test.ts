/**
 * The admin review of legacy grants (HD-29, step 1.18): GET lists the members that kept a
 * shared tool at the upgrade; POST keeps or removes one grant, or all of them. Admins only
 * (role read from the database), same origin, JSON; no way to ADD a grant; every decision
 * is an audit row written with the change; removing the Kali terminal grant closes the
 * holder's open terminal through the agent's POST /ws/close, and the removal stands when
 * the agent cannot be reached.
 *
 * Real session helpers and tokens; the database is the in-memory fakePrisma (real advisory
 * lock and rollback semantics); the agent is a fetch double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createFakePrisma } = await import('@/lib/plugins/__testing__/fakePrisma')
  h.db = createFakePrisma()
  return { default: h.db, prisma: h.db }
})

import type { FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { createToken, createActAsToken } from '@/lib/auth'
import {
  KEEP_ACTION, LEGACY_GRANTS, LEGACY_GRANTS_LOCK_KEY, REMOVE_ACTION,
} from '@/lib/authz/updateReview'
import { pendingLegacyGrantCount } from '@/lib/authz/updateReview'
import {
  CUTOFF_ACTION, LEGACY_GRANTS as BACKFILL_GRANTS, LOCK_KEY as BACKFILL_LOCK_KEY, MARKER_ACTION,
  REMOVE_ACTION as BACKFILL_REMOVE_ACTION, backfillRbacLegacyGrants,
} from '../../../../../scripts/backfill-rbac-legacy-grants.mjs'
import { GET, POST } from './route'

const db = () => h.db as FakePrisma
const UPDATED = new Date('2026-03-01T09:00:00.000Z')
const BEFORE = new Date('2026-01-01T09:00:00.000Z')
const PW = '$2a$12$hash'
const fetchMock = vi.fn()

function seedUsers() {
  db().seed('user', [
    { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', password: PW, createdAt: BEFORE, updatedAt: UPDATED, legacyGrants: [] },
    { id: 'member-1', name: 'Marco', email: 'marco@e2e.local', role: 'standard', password: PW, createdAt: BEFORE, updatedAt: UPDATED,
      legacyGrants: ['kali_terminal', 'shell_sessions'] },
    { id: 'member-2', name: 'Anna', email: 'anna@e2e.local', role: 'standard', password: PW, createdAt: BEFORE, updatedAt: UPDATED,
      legacyGrants: ['kali_terminal', 'shell_sessions', 'tunnels', 'future_grant'] },
    { id: 'member-3', name: 'Nuovo', email: 'nuovo@e2e.local', role: 'standard', password: PW, createdAt: BEFORE, updatedAt: UPDATED, legacyGrants: [] },
    // Promoted after the upgrade: an admin reaches every tool by role, so it is not reviewed.
    { id: 'admin-2', name: 'Pia', email: 'pia@e2e.local', role: 'admin', password: PW, createdAt: BEFORE, updatedAt: UPDATED,
      legacyGrants: ['kali_terminal'] },
  ])
}

async function signIn(userId: string, role = 'admin', actingAs?: string) {
  h.jar.auth = await createToken(userId, role)
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

function post(body: unknown, opts: { origin?: string; contentType?: string; cookie?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': opts.contentType ?? 'application/json' }
  if (opts.origin !== undefined) headers.origin = opts.origin
  if (opts.cookie) headers.cookie = opts.cookie
  return new NextRequest('http://redamon.test/api/admin/legacy-grants', {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

const grantsOf = (id: string) => db().rows('user').find(u => u.id === id)!.legacyGrants as string[]
const auditRows = (action: string) => db().rows('auditLog').filter(r => r.action === action)
const closeCalls = () => fetchMock.mock.calls.filter(c => String(c[0]).endsWith('/ws/close'))

beforeEach(() => {
  for (const t of Object.values(db().tables)) t.clear()
  seedUsers()
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(
    JSON.stringify({ closed: 1, stopped_runs: 0, by_kind: { 'kali-terminal': 1 } }), { status: 200 },
  ))
  vi.stubGlobal('fetch', fetchMock)
  h.jar = {}
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the shared constants', () => {
  test('equal the backfill script\'s', () => {
    expect([...LEGACY_GRANTS]).toEqual(BACKFILL_GRANTS)
    expect(LEGACY_GRANTS_LOCK_KEY).toBe(BACKFILL_LOCK_KEY)
    expect(REMOVE_ACTION).toBe(BACKFILL_REMOVE_ACTION)
  })
})

describe('who may review', () => {
  test('no session 401', async () => {
    expect((await GET()).status).toBe(401)
    expect((await POST(post({ action: 'remove_all' }))).status).toBe(401)
    expect(grantsOf('member-1')).toEqual(['kali_terminal', 'shell_sessions'])
  })

  test('member 403: a coded refusal naming the permission, and nothing written', async () => {
    await signIn('member-1', 'standard')
    const res = await GET()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:assign_permissions' })
    for (const body of [{ action: 'remove_all' }, { action: 'keep_all' }, { action: 'remove', userId: 'member-2', grant: 'tunnels' }]) {
      const r = await POST(post(body))
      expect(r.status).toBe(403)
      expect((await r.json()).code).toBe('forbidden')
    }
    expect(grantsOf('member-2')).toContain('tunnels')
    expect(db().rows('auditLog')).toHaveLength(0)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('a member whose token still says admin is refused: the role comes from the database', async () => {
    await signIn('member-1', 'admin')
    expect((await GET()).status).toBe(403)
  })

  test('a cross-origin POST is refused before any write', async () => {
    await signIn('admin-1')
    const res = await POST(post({ action: 'remove_all' }, { origin: 'https://evil.example' }))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
    expect(grantsOf('member-1')).toEqual(['kali_terminal', 'shell_sessions'])
  })

  test('a form post (not JSON) is refused', async () => {
    await signIn('admin-1')
    const res = await POST(post('action=remove_all', { contentType: 'application/x-www-form-urlencoded' }))
    expect(res.status).toBe(415)
    expect(db().rows('auditLog')).toHaveLength(0)
  })
})

describe('GET lists the holders', () => {
  test('non-admin holders with each grant pending, unknown values left out, sorted by email', async () => {
    await signIn('admin-1')
    const res = await GET()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.pending).toBe(5)
    expect(body.holders).toEqual([
      { id: 'member-2', name: 'Anna', email: 'anna@e2e.local', grants: [
        { grant: 'kali_terminal', state: 'pending' }, { grant: 'shell_sessions', state: 'pending' }, { grant: 'tunnels', state: 'pending' },
      ] },
      { id: 'member-1', name: 'Marco', email: 'marco@e2e.local', grants: [
        { grant: 'kali_terminal', state: 'pending' }, { grant: 'shell_sessions', state: 'pending' },
      ] },
    ])
  })

  test('card hidden without grants: an install with no holder lists nobody', async () => {
    for (const t of Object.values(db().tables)) t.clear()
    db().seed('user', [{ id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', password: PW, createdAt: BEFORE, updatedAt: UPDATED, legacyGrants: [] }])
    await signIn('admin-1')
    expect(await (await GET()).json()).toEqual({ holders: [], pending: 0 })
  })

  test('an admin acting as a member still reviews as the admin', async () => {
    await signIn('admin-1', 'admin', 'member-3')
    expect((await GET()).status).toBe(200)
  })
})

describe('keep and remove audited', () => {
  test('remove takes the grant away, keeps the other values and updatedAt, and writes one remove row', async () => {
    await signIn('admin-1')
    const res = await POST(post({ action: 'remove', userId: 'member-2', grant: 'tunnels' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ action: 'remove', userId: 'member-2', grant: 'tunnels', changed: true })
    expect(grantsOf('member-2')).toEqual(['kali_terminal', 'shell_sessions', 'future_grant'])
    expect(db().rows('user').find(u => u.id === 'member-2')!.updatedAt).toEqual(UPDATED)
    const rows = auditRows(REMOVE_ACTION)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ actorId: 'admin-1', targetType: 'user', targetId: 'member-2', after: { grant: 'tunnels' } })
  })

  test('keep leaves the grant and writes one keep row; it is no longer pending', async () => {
    await signIn('admin-1')
    const res = await POST(post({ action: 'keep', userId: 'member-1', grant: 'shell_sessions' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ changed: true })
    expect(grantsOf('member-1')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(auditRows(KEEP_ACTION)).toEqual([
      expect.objectContaining({ actorId: 'admin-1', targetId: 'member-1', after: { grant: 'shell_sessions' } }),
    ])
    const listed = (await (await GET()).json()).holders.find((x: { id: string }) => x.id === 'member-1')
    expect(listed.grants).toEqual([{ grant: 'kali_terminal', state: 'pending' }, { grant: 'shell_sessions', state: 'kept' }])
    expect(await pendingLegacyGrantCount()).toBe(4)
  })

  test('the decision is taken under the backfill\'s lock, in one transaction with its row', async () => {
    await signIn('admin-1')
    const seen = db().rawCalls.length
    const transactions = db().transactions
    await POST(post({ action: 'remove', userId: 'member-1', grant: 'shell_sessions' }))
    expect(db().transactions - transactions).toBe(1)
    const locks = db().rawCalls.slice(seen).filter(c => /pg_advisory_xact_lock\(hashtext\(\?\)\)/.test(c.sql))
    expect(locks.map(c => c.values[0])).toEqual([LEGACY_GRANTS_LOCK_KEY])
  })

  test('a failed audit write rolls the removal back: no removal without its row', async () => {
    await signIn('admin-1')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const original = db().$transaction
    const tx = original.bind(db())
    ;(db() as unknown as Record<string, unknown>).$transaction = (fn: (t: FakePrisma) => Promise<unknown>) =>
      tx(async (t) => {
        (t.auditLog as unknown as Record<string, unknown>).create = async () => { throw new Error('connection reset') }
        return fn(t)
      })
    try {
      const res = await POST(post({ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }))
      expect(res.status).toBe(500)
      expect((await res.json()).code).toBeTruthy()
    } finally {
      (db() as unknown as Record<string, unknown>).$transaction = original
    }
    expect(grantsOf('member-1')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(db().rows('auditLog')).toHaveLength(0)
    expect(closeCalls()).toHaveLength(0)
  })

  test('an admin acting as a member is recorded as the admin, naming the member', async () => {
    await signIn('admin-1', 'admin', 'member-3')
    const cookie = `redamon-act-as=${h.jar.actAs}`
    await POST(post({ action: 'keep', userId: 'member-1', grant: 'kali_terminal' }, { cookie }))
    expect(auditRows(KEEP_ACTION)[0]).toMatchObject({ actorId: 'admin-1', after: { grant: 'kali_terminal', actingAsUserId: 'member-3' } })
  })

  test('the same decision twice writes one row', async () => {
    await signIn('admin-1')
    expect(await (await POST(post({ action: 'keep', userId: 'member-1', grant: 'kali_terminal' }))).json()).toMatchObject({ changed: true })
    expect(await (await POST(post({ action: 'keep', userId: 'member-1', grant: 'kali_terminal' }))).json()).toMatchObject({ changed: false })
    expect(auditRows(KEEP_ACTION)).toHaveLength(1)
    expect(await (await POST(post({ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }))).json()).toMatchObject({ changed: true })
    const second = await POST(post({ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }))
    expect(second.status).toBe(200)
    expect(await second.json()).toMatchObject({ changed: false })
    expect(auditRows(REMOVE_ACTION)).toHaveLength(1)
    expect(closeCalls()).toHaveLength(1)
  })

  test('two admins removing the same grant at once: one removal, one row', async () => {
    await signIn('admin-1')
    const [a, b] = await Promise.all([
      POST(post({ action: 'remove', userId: 'member-2', grant: 'kali_terminal' })),
      POST(post({ action: 'remove', userId: 'member-2', grant: 'kali_terminal' })),
    ])
    const changed = [await a.json(), await b.json()].map(x => x.changed).sort()
    expect(changed).toEqual([false, true])
    expect(auditRows(REMOVE_ACTION)).toHaveLength(1)
  })

  test('an unknown account 404', async () => {
    await signIn('admin-1')
    const res = await POST(post({ action: 'remove', userId: 'nobody', grant: 'tunnels' }))
    expect(res.status).toBe(404)
    expect(db().rows('auditLog')).toHaveLength(0)
  })
})

describe('no add path', () => {
  test('an action that would add a grant is refused, and nothing changes', async () => {
    await signIn('admin-1')
    for (const action of ['add', 'grant', 'set', 'restore', undefined]) {
      const res = await POST(post({ action, userId: 'member-3', grant: 'kali_terminal', legacyGrants: ['kali_terminal'] }))
      expect(res.status, String(action)).toBe(400)
      expect((await res.json()).code).toBe('invalid_action')
    }
    expect(grantsOf('member-3')).toEqual([])
    expect(db().rows('auditLog')).toHaveLength(0)
  })

  test('keeping a grant the account does not hold is refused (409), so a keep never puts one back', async () => {
    await signIn('admin-1')
    const res = await POST(post({ action: 'keep', userId: 'member-3', grant: 'kali_terminal' }))
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('not_held')
    expect(grantsOf('member-3')).toEqual([])
    await POST(post({ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }))
    expect((await POST(post({ action: 'keep', userId: 'member-1', grant: 'kali_terminal' }))).status).toBe(409)
    expect(grantsOf('member-1')).toEqual(['shell_sessions'])
  })

  test('a grant outside the three, or no account, is refused', async () => {
    await signIn('admin-1')
    for (const body of [
      { action: 'keep', userId: 'member-1', grant: 'emergency_stop_all' },
      { action: 'remove', userId: 'member-1', grant: 'future_grant' },
      { action: 'remove', grant: 'tunnels' },
      { action: 'remove', userId: 42, grant: 'tunnels' },
    ]) {
      const res = await POST(post(body))
      expect(res.status, JSON.stringify(body)).toBe(400)
    }
    expect(db().rows('auditLog')).toHaveLength(0)
  })
})

describe('remove closes the terminal (agent call made)', () => {
  test('removing kali_terminal calls the agent\'s /ws/close for that user\'s terminals, scope access, with the master key', async () => {
    await signIn('admin-1')
    const res = await POST(post({ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }))
    expect(await res.json()).toMatchObject({ changed: true, terminal: { closed: 1 } })
    expect(closeCalls()).toHaveLength(1)
    const [url, init] = closeCalls()[0]
    expect(url).toBe('http://agent.test:8080/ws/close')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({ user_id: 'member-1', kinds: ['kali-terminal'], scope: 'access' })
    expect(new Headers(init.headers).get('x-internal-key')).toBe('ik-test-master-0001')
  })

  test('removing another grant opens no agent call: the sessions console re-reads the grant on every poll', async () => {
    await signIn('admin-1')
    await POST(post({ action: 'remove', userId: 'member-1', grant: 'shell_sessions' }))
    await POST(post({ action: 'remove', userId: 'member-2', grant: 'tunnels' }))
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('the agent unreachable: the removal stands, the answer says so, [rbac] socket-close failed is logged', async () => {
    await signIn('admin-1')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    fetchMock.mockRejectedValue(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }))
    const res = await POST(post({ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ changed: true, terminal: { error: 'agent_unreachable' } })
    expect(grantsOf('member-1')).toEqual(['shell_sessions'])
    expect(auditRows(REMOVE_ACTION)).toHaveLength(1)
    expect(err.mock.calls.map(c => String(c[0])).join('\n'))
      .toMatch(/\[rbac\] socket-close failed user=member-1 project=- kinds=kali-terminal: agent_unreachable/)
  })

  test('the agent refusing the close: the removal stands and the status is named', async () => {
    await signIn('admin-1')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    fetchMock.mockResolvedValue(new Response('{}', { status: 503 }))
    const res = await POST(post({ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }))
    expect(await res.json()).toMatchObject({ changed: true, terminal: { error: 'agent_http_503' } })
    expect(grantsOf('member-1')).toEqual(['shell_sessions'])
  })
})

describe('remove_all and keep_all', () => {
  test('remove_all: every reviewed grant, one row per account and grant, terminals closed, unknown values and admins left alone', async () => {
    await signIn('admin-1')
    const res = await POST(post({ action: 'remove_all' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ action: 'remove_all', changed: 5, terminals: { closed: 2, failed: 0 } })
    expect(grantsOf('member-1')).toEqual([])
    expect(grantsOf('member-2')).toEqual(['future_grant'])
    expect(grantsOf('admin-2')).toEqual(['kali_terminal'])
    const rows = auditRows(REMOVE_ACTION).map(r => `${r.targetId}:${(r.after as { grant: string }).grant}`).sort()
    expect(rows).toEqual([
      'member-1:kali_terminal', 'member-1:shell_sessions',
      'member-2:kali_terminal', 'member-2:shell_sessions', 'member-2:tunnels',
    ])
    expect(auditRows(REMOVE_ACTION).every(r => r.actorId === 'admin-1' && (r.after as { bulk?: boolean }).bulk === true)).toBe(true)
    expect(closeCalls().map(c => JSON.parse(c[1].body).user_id).sort()).toEqual(['member-1', 'member-2'])
    expect(await (await GET()).json()).toEqual({ holders: [], pending: 0 })
  })

  test('after remove_all the backfill never gives a grant back, also when it re-derives', async () => {
    // A first upgrade recorded the holders (member-3 came later); then the admin removes them all.
    db().seed('auditLog', [
      { action: CUTOFF_ACTION, targetType: 'system', source: 'system', createdAt: new Date('2026-02-01T00:00:00.000Z') },
      { action: MARKER_ACTION, targetType: 'system', source: 'system', after: { kali_terminal: 2, shell_sessions: 2, tunnels: 1 } },
    ])
    await db().user.update({ where: { id: 'member-3' }, data: { createdAt: new Date('2026-06-01T00:00:00.000Z') } })
    await db().user.update({ where: { id: 'admin-2' }, data: { legacyGrants: [] } })
    await signIn('admin-1')
    await POST(post({ action: 'remove_all' }))
    // No account holds a grant under a marker that recorded some: the next boot re-derives.
    const result = await backfillRbacLegacyGrants(db())
    expect(result).toMatchObject({ done: true, kali_terminal: 0, shell_sessions: 0, tunnels: 0, usersChanged: 0 })
    expect(grantsOf('member-1')).toEqual([])
    expect(grantsOf('member-2')).toEqual(['future_grant'])
    expect(grantsOf('member-3')).toEqual([])
  })

  test('remove_all with the agent unreachable still removes everything and counts the failures', async () => {
    await signIn('admin-1')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    fetchMock.mockRejectedValue(new TypeError('fetch failed'))
    const res = await POST(post({ action: 'remove_all' }))
    expect(await res.json()).toMatchObject({ changed: 5, terminals: { closed: 0, failed: 2 } })
    expect(grantsOf('member-1')).toEqual([])
  })

  test('keep_all keeps the pending grants once; a second keep_all writes nothing', async () => {
    await signIn('admin-1')
    await POST(post({ action: 'keep', userId: 'member-1', grant: 'kali_terminal' }))
    const res = await POST(post({ action: 'keep_all' }))
    expect(await res.json()).toMatchObject({ action: 'keep_all', changed: 4 })
    expect(auditRows(KEEP_ACTION)).toHaveLength(5)
    expect(grantsOf('member-2')).toEqual(['kali_terminal', 'shell_sessions', 'tunnels', 'future_grant'])
    expect(await (await POST(post({ action: 'keep_all' }))).json()).toMatchObject({ changed: 0 })
    expect(auditRows(KEEP_ACTION)).toHaveLength(5)
    expect(await pendingLegacyGrantCount()).toBe(0)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('a kept grant can still be removed', async () => {
    await signIn('admin-1')
    await POST(post({ action: 'keep_all' }))
    await POST(post({ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }))
    expect(grantsOf('member-1')).toEqual(['shell_sessions'])
    expect(closeCalls()).toHaveLength(1)
  })
})
