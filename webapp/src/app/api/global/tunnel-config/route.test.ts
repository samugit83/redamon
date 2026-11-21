/**
 * GET /api/global/tunnel-config returns the tunnel credentials unmasked, so only the
 * internal key reads it (HD-05, F-04): the agent's chisel lookup (agentic/utils.py) is
 * its one caller. Every other caller, a signed-in admin included, gets 404 before
 * anything is read. Its row is picked by a fixed order, so the chisel host the agent
 * reports is the one the sandbox was last pushed.
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

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: { findFirst: (a: Parameters<typeof settingsFindFirst>[0]) => settingsFindFirst(a) },
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    auditLog: { findFirst: () => auditFindFirst(), create: vi.fn() },
  },
}))

import { GET } from './route'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'

const KEY = 'internal-key-tunnel-config'
const get = (headers: Record<string, string> = {}) =>
  GET(new NextRequest('http://localhost:3000/api/global/tunnel-config', { headers }))

const row = (id: string, over: Partial<Row>): Row => ({
  id, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', tunnelsEnabled: false,
  updatedAt: new Date('2026-11-01T00:00:00Z'), ...over,
})

beforeEach(() => {
  authCookie = undefined
  rows = [row('only', { ngrokAuthtoken: 'fake-ngrok-token', chiselServerUrl: 'http://vps.example:9090', chiselAuth: 'u:p' })]
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
    const res = await get({ 'x-internal-key': KEY })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      ngrokAuthtoken: 'fake-ngrok-token', chiselServerUrl: 'http://vps.example:9090', chiselAuth: 'u:p',
    })
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test('internal key with no tunnel configured anywhere answers empty values', async () => {
    rows = [row('none', {})]
    const res = await get({ 'x-internal-key': KEY })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
  })
})

describe('the row it answers with', () => {
  const pick = async () => ((await (await get({ 'x-internal-key': KEY })).json()) as { chiselServerUrl: string }).chiselServerUrl

  test('the pick is deterministic with two candidate rows', async () => {
    const enabledOlder = row('b-enabled', {
      chiselServerUrl: 'http://enabled.example:9090', tunnelsEnabled: true, updatedAt: new Date('2026-11-01T00:00:00Z'),
    })
    const disabledNewer = row('a-disabled', {
      chiselServerUrl: 'http://disabled.example:9090', updatedAt: new Date('2026-11-10T00:00:00Z'),
    })
    rows = [enabledOlder, disabledNewer]
    expect(await pick()).toBe('http://enabled.example:9090')
    rows = [disabledNewer, enabledOlder]
    expect(await pick()).toBe('http://enabled.example:9090')
  })

  test('with none enabled the most recent save wins, then the lowest id', async () => {
    const older = row('a', { chiselServerUrl: 'http://older.example:9090', updatedAt: new Date('2026-11-01T00:00:00Z') })
    const newer = row('b', { chiselServerUrl: 'http://newer.example:9090', updatedAt: new Date('2026-11-05T00:00:00Z') })
    rows = [older, newer]
    expect(await pick()).toBe('http://newer.example:9090')
    rows = [newer, older]
    expect(await pick()).toBe('http://newer.example:9090')

    const sameTime = new Date('2026-11-05T00:00:00Z')
    const low = row('a-low', { chiselServerUrl: 'http://low.example:9090', updatedAt: sameTime })
    const high = row('z-high', { chiselServerUrl: 'http://high.example:9090', updatedAt: sameTime })
    rows = [high, low]
    expect(await pick()).toBe('http://low.example:9090')
  })

  test('the query states the order: enabled first, then the latest save, then the lowest id', async () => {
    await get({ 'x-internal-key': KEY })
    expect(settingsFindFirst).toHaveBeenCalledTimes(1)
    expect(settingsFindFirst.mock.calls[0][0].orderBy).toEqual([
      { tunnelsEnabled: 'desc' }, { updatedAt: 'desc' }, { id: 'asc' },
    ])
  })
})
