/**
 * GET /api/global/tunnel-config returns the tunnel credentials unmasked, so only the
 * internal key reads it (HD-05, F-04): the agent's chisel lookup (agentic/utils.py) is
 * its one caller. Every other caller, a signed-in admin included, gets 404 before
 * anything is read. It answers the named person's own row while their tunnel is on, so
 * the chisel host the agent reports is the one that person's sandbox was pushed.
 *
 * Real tokens are signed; the cookie store and Prisma are mocked.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 't'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-key-tunnel-config')

let authCookie: string | undefined
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && authCookie ? { value: authCookie } : undefined),
  })),
}))

interface Row {
  id: string
  ngrokAuthtoken: string
  chiselServerUrl: string
  chiselAuth: string
  tunnelsEnabled: boolean
  updatedAt: Date
}
type Order = Partial<Record<keyof Row, 'asc' | 'desc'>>

let rows: Row[] = []

const sortable = (v: Row[keyof Row]) => (v instanceof Date ? v.getTime() : typeof v === 'boolean' ? Number(v) : v)

/** findFirst over `rows` with the route's where (any credential set) and its orderBy list. */
const settingsFindFirst = vi.fn(async (args: { where: unknown; orderBy?: Order[]; select: Record<string, true> }) => {
  const candidates = rows.filter(r => r.ngrokAuthtoken !== '' || r.chiselServerUrl !== '')
  const order = args.orderBy ?? []
  const sorted = [...candidates].sort((a, b) => {
    for (const o of order) {
      const [[key, dir]] = Object.entries(o) as [keyof Row, 'asc' | 'desc'][]
      const av = sortable(a[key])
      const bv = sortable(b[key])
      if (av === bv) continue
      const lt = av < bv ? -1 : 1
      return dir === 'asc' ? lt : -lt
    }
    return 0
  })
  const hit = sorted[0]
  if (!hit) return null
  return Object.fromEntries(Object.keys(args.select).map(k => [k, hit[k as keyof Row]]))
})
const userFindUnique = vi.fn(async (args: { where: { id: string } }) => ({
  id: args.where.id, email: `${args.where.id}@e2e.local`, role: args.where.id === 'admin' ? 'admin' : 'standard',
  password: 'h', createdAt: new Date(0), legacyGrants: ['tunnels'],
}))
const auditFindFirst = vi.fn(async () => ({ createdAt: new Date('2030-01-01T00:00:00Z') }))

/** findUnique by the account: here a row's id is its account's id. */
const settingsFindUnique = vi.fn(async (args: { where: { userId: string }; select: Record<string, true> }) => {
  const hit = rows.find(r => r.id === args.where.userId)
  return hit ? Object.fromEntries(Object.keys(args.select).map(k => [k, hit[k as keyof Row]])) : null
})

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findFirst: (a: Parameters<typeof settingsFindFirst>[0]) => settingsFindFirst(a),
      findUnique: (a: Parameters<typeof settingsFindUnique>[0]) => settingsFindUnique(a),
    },
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    auditLog: { findFirst: () => auditFindFirst(), create: vi.fn() },
  },
}))

import { GET } from './route'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'

const KEY = 'internal-key-tunnel-config'
const get = (headers: Record<string, string> = {}, query = '') =>
  GET(new NextRequest(`http://localhost:3000/api/global/tunnel-config${query}`, { headers }))

const row = (id: string, over: Partial<Row>): Row => ({
  id, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', tunnelsEnabled: false,
  updatedAt: new Date('2026-11-01T00:00:00Z'), ...over,
})

beforeEach(() => {
  settingsFindUnique.mockClear()
  authCookie = undefined
  rows = [row('only', { tunnelsEnabled: true, ngrokAuthtoken: 'fake-ngrok-token', chiselServerUrl: 'http://vps.example:9090', chiselAuth: 'u:p' })]
  settingsFindFirst.mockClear()
  userFindUnique.mockClear()
  auditFindFirst.mockClear()
  resetSharedToolsForTests()
})
afterEach(() => {
  setFlagsForTests(null)
})

describe('only the internal key reads the tunnel credentials (HD-05)', () => {
  test('member 404', async () => {
    authCookie = await createToken('member', 'standard')
    const res = await get()
    expect(res.status).toBe(404)
    const text = await res.text()
    expect(text).not.toContain('fake-ngrok-token')
    expect(text).not.toContain('u:p')
    expect(settingsFindFirst).not.toHaveBeenCalled()
  })

  test('an admin signed in is refused the same way: the browser never needs the credentials', async () => {
    authCookie = await createToken('admin', 'admin')
    expect((await get()).status).toBe(404)
    expect(settingsFindFirst).not.toHaveBeenCalled()
  })

  test('no cookie and a wrong key are 404, and no account is read', async () => {
    expect((await get()).status).toBe(404)
    expect((await get({ 'x-internal-key': 'wrong' })).status).toBe(404)
    expect(settingsFindFirst).not.toHaveBeenCalled()
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test('the escape hatch never opens it (F-04): a pre-upgrade member with compat on is 404', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    authCookie = await createToken('member', 'standard')
    expect((await get()).status).toBe(404)
    expect(auditFindFirst).not.toHaveBeenCalled()
    expect(settingsFindFirst).not.toHaveBeenCalled()
  })

  test('internal key 200', async () => {
    const res = await get({ 'x-internal-key': KEY }, '?userId=only')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      ngrokAuthtoken: 'fake-ngrok-token', chiselServerUrl: 'http://vps.example:9090', chiselAuth: 'u:p',
    })
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test('internal key with no tunnel configured anywhere answers empty values', async () => {
    rows = [row('none', {})]
    const res = await get({ 'x-internal-key': KEY }, '?userId=none')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
  })
})

describe('one person\'s own tunnel (group 1, OQ-G1-2 A), never the instance\'s or another\'s', () => {
  const EMPTY = { ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }
  const internal = { 'x-internal-key': KEY }

  beforeEach(() => {
    rows = [
      row('alice', { tunnelsEnabled: true, ngrokAuthtoken: 'alice-ngrok', chiselServerUrl: 'http://alice.example:9090', chiselAuth: 'a:p' }),
      row('bob', { tunnelsEnabled: false, chiselServerUrl: 'http://bob.example:9090' }),
    ]
  })
  test('the person named answers their own row while their tunnel is on', async () => {
    const res = await get(internal, '?userId=alice')
    expect(await res.json()).toEqual({ ngrokAuthtoken: 'alice-ngrok', chiselServerUrl: 'http://alice.example:9090', chiselAuth: 'a:p' })
    expect(settingsFindFirst).not.toHaveBeenCalled()
  })

  test('a person whose tunnel is off answers empty values, never another person\'s', async () => {
    expect(await (await get(internal, '?userId=bob')).json()).toEqual(EMPTY)
    expect(await (await get(internal, '?userId=nobody')).json()).toEqual(EMPTY)
  })

  test('no person, or one that is not an account id, answers empty values: no row is picked for everybody', async () => {
    for (const query of ['', '?userId=', '?userId=..%2Falice', '?userId=a%20b']) {
      expect(await (await get(internal, query)).json(), query).toEqual(EMPTY)
    }
    expect(settingsFindFirst).not.toHaveBeenCalled()
  })

  test('identity switch on: the unused instance row is never answered', async () => {
    setFlagsForTests({ identity: true })
    expect(await (await get(internal, '?userId=bob')).json()).toEqual(EMPTY)
    expect(await (await get(internal)).json()).toEqual(EMPTY)
  })

  test('no row is ever picked for everybody: never alice\'s tunnel for a caller who names nobody', async () => {
    expect(await (await get(internal)).json()).toEqual(EMPTY)
    expect(settingsFindFirst).not.toHaveBeenCalled()
    expect(settingsFindUnique).not.toHaveBeenCalled()
  })

  test('still the internal key only', async () => {
    expect((await get({}, '?userId=alice')).status).toBe(404)
    expect(settingsFindUnique).not.toHaveBeenCalled()
  })
})
