/**
 * GET/PUT /api/users/[id]/tradecraft-settings: the account's Tradecraft 2.0 switch.
 *
 * The real session helpers run over signed tokens, so the account rule is the one every
 * `/api/users/[id]/**` write follows (requireUserAccess, HD-23): the account itself writes,
 * an admin acting as an account that signs in for itself does not. The self-service
 * permission is the real one, spied on where a test needs it to refuse. Prisma is a double
 * that keeps the switch rows and the audit rows.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 't'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-tradecraft-0001')

const h = vi.hoisted(() => ({
  auth: undefined as string | undefined,
  actAs: undefined as string | undefined,
  rows: new Map<string, { v2Enabled: boolean; v2EnabledAt: Date | null }>(),
  audits: [] as Record<string, unknown>[],
  writes: [] as string[],
  reads: 0,
  readError: null as Error | null,
}))

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.auth) return { value: h.auth }
      if (name === 'redamon-act-as' && h.actAs) return { value: h.actAs }
      return undefined
    },
  })),
}))

const ACCOUNTS: Record<string, { role: string; password: string }> = {
  'admin-1': { role: 'admin', password: 'hash' },
  victim: { role: 'standard', password: 'hash' },
  managed: { role: 'standard', password: '' },
}

vi.mock('@/lib/prisma', () => {
  const READS = new Set(['findUnique', 'findFirst', 'findMany', 'count', 'aggregate', 'groupBy', 'findUniqueOrThrow', 'findFirstOrThrow'])
  const settings = {
    findUnique: async ({ where }: { where: { userId: string } }) => {
      h.reads += 1
      if (h.readError) throw h.readError
      const r = h.rows.get(where.userId)
      return r ? { ...r } : null
    },
    upsert: async ({ where, create, update }: { where: { userId: string }; create: { v2Enabled: boolean; v2EnabledAt: Date | null }; update: { v2Enabled: boolean; v2EnabledAt: Date | null } }) => {
      h.writes.push(`tradecraftUserSettings.upsert ${where.userId}`)
      h.rows.set(where.userId, h.rows.has(where.userId) ? { ...h.rows.get(where.userId)!, ...update } : { ...create })
      return h.rows.get(where.userId)
    },
  }
  const auditLog = {
    create: async ({ data }: { data: Record<string, unknown> }) => { h.audits.push(data); return { id: 'a1', ...data } },
  }
  const model = (name: string) => new Proxy({}, {
    get: (_t, op: string) => {
      if (name === 'user' && op === 'findUnique') {
        return async ({ where }: { where: { id: string } }) => ACCOUNTS[where.id]
          ? { id: where.id, email: `${where.id}@e2e.local`, name: where.id, createdAt: new Date(0), ...ACCOUNTS[where.id] }
          : null
      }
      if (READS.has(op)) return async () => (op === 'findMany' || op === 'groupBy' ? [] : op === 'count' ? 0 : null)
      return async () => { h.writes.push(`${name}.${op}`); throw new Error(`unexpected write ${name}.${op}`) }
    },
  })
  const db: Record<string, unknown> = new Proxy({}, {
    get: (_t, key: string) => {
      if (key === 'tradecraftUserSettings') return settings
      if (key === '$queryRaw') return async () => []
      if (key === '$transaction') {
        // The switch's advisory lock is a no-op here: switch.test.ts holds the lock's behaviour.
        return async (fn: (tx: unknown) => Promise<unknown>) => fn({ tradecraftUserSettings: settings, auditLog, $executeRaw: async () => 1 })
      }
      return key.startsWith('$') ? async () => { throw new Error(`unexpected ${key}`) } : model(key)
    },
  })
  return { default: db, prisma: db }
})

vi.mock('@/lib/authz/selfService', async (orig) => {
  const real = (await orig()) as typeof import('@/lib/authz/selfService')
  return { ...real, requireSelfPermission: vi.fn(real.requireSelfPermission) }
})

import { createActAsToken, createToken } from '@/lib/auth'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { GET, PUT } from './route'

const URL_FOR = (id: string) => `http://localhost:3000/api/users/${id}/tradecraft-settings`
const params = (id: string) => ({ params: Promise.resolve({ id }) })

function get(id: string, headers: Record<string, string> = {}) {
  return GET(new NextRequest(URL_FOR(id), { headers: { host: 'localhost:3000', ...headers } }), params(id))
}
function put(id: string, body: unknown, headers: Record<string, string> = {}) {
  return PUT(new NextRequest(URL_FOR(id), {
    method: 'PUT',
    headers: { host: 'localhost:3000', 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }), params(id))
}
async function answer(res: Response) {
  return { status: res.status, body: await res.json().catch(() => ({})) as Record<string, unknown> }
}

beforeEach(async () => {
  h.auth = await createToken('victim', 'standard')
  h.actAs = undefined
  h.rows.clear()
  h.audits = []
  h.writes = []
  h.reads = 0
  h.readError = null
  vi.mocked(requireSelfPermission).mockClear()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  vi.restoreAllMocks()
})

describe('GET /api/users/[id]/tradecraft-settings', () => {
  test('the account reads its switch, off without a row', async () => {
    expect(await answer(await get('victim'))).toEqual({ status: 200, body: { v2Enabled: false } })
    h.rows.set('victim', { v2Enabled: true, v2EnabledAt: new Date() })
    expect(await answer(await get('victim'))).toEqual({ status: 200, body: { v2Enabled: true } })
  })

  test('get_requires_self_permission', async () => {
    vi.mocked(requireSelfPermission).mockResolvedValueOnce(
      NextResponse.json({ error: 'Forbidden', permission: 'self:tradecraft' }, { status: 403 }),
    )
    const r = await answer(await get('victim'))
    expect(r.status).toBe(403)
    expect(vi.mocked(requireSelfPermission).mock.calls[0].slice(1)).toEqual(['victim', 'self:tradecraft'])
    expect(h.reads).toBe(0)
  })

  test('without a session: 401, nothing read', async () => {
    h.auth = undefined
    expect((await get('victim')).status).toBe(401)
    expect(h.reads).toBe(0)
  })
})

describe('PUT /api/users/[id]/tradecraft-settings', () => {
  test('put_writes_and_answers_new_value', async () => {
    expect(await answer(await put('victim', { v2Enabled: true }))).toEqual({ status: 200, body: { v2Enabled: true } })
    expect(h.rows.get('victim')!.v2Enabled).toBe(true)
    expect(h.audits).toEqual([expect.objectContaining({
      action: 'tradecraft.v2_switched', actorId: 'victim', targetType: 'user', targetId: 'victim',
      after: { v2Enabled: true },
    })])
    expect(vi.mocked(requireSelfPermission).mock.calls.at(-1)!.slice(1)).toEqual(['victim', 'self:tradecraft'])
    expect(await answer(await get('victim'))).toEqual({ status: 200, body: { v2Enabled: true } })
    expect(await answer(await put('victim', { v2Enabled: false }))).toEqual({ status: 200, body: { v2Enabled: false } })
    expect(h.audits).toHaveLength(2)
  })

  test.each([
    ['a string', { v2Enabled: 'true' }],
    ['a number', { v2Enabled: 1 }],
    ['null', { v2Enabled: null }],
    ['an empty body', {}],
    ['an unknown key', { v2Enabled: true, ingestion: {} }],
    ['an array', [true]],
  ])('put_refuses_non_boolean: %s is a 400 with a fixed message, nothing written', async (_name, body) => {
    const r = await answer(await put('victim', body))
    expect(r.status).toBe(400)
    expect(r.body.error).toMatch(/^Body must be/)
    expect(h.writes).toEqual([])
    expect(h.audits).toEqual([])
  })

  test('a body that is not JSON is refused before anything is read', async () => {
    expect((await put('victim', 'v2Enabled=true', { 'content-type': 'application/x-www-form-urlencoded' })).status).toBe(415)
    expect((await put('victim', '{not json')).status).toBe(400)
    expect(h.writes).toEqual([])
  })

  test('put_refused_while_acting_as_account_that_signs_in', async () => {
    h.auth = await createToken('admin-1', 'admin')
    h.actAs = await createActAsToken('admin-1', 'victim')
    const r = await answer(await put('victim', { v2Enabled: true }))
    expect(r.status).toBe(403)
    expect(r.body.code).toBe('own_account_only')
    expect(h.writes).toEqual([])
    expect(h.audits).toEqual([])
  })

  test('an admin on another account, not acting, is refused too', async () => {
    h.auth = await createToken('admin-1', 'admin')
    const r = await answer(await put('victim', { v2Enabled: true }))
    expect(r.status).toBe(403)
    expect(h.writes).toEqual([])
  })

  test('an admin acting as a passwordless managed account writes, audited as the admin on its behalf', async () => {
    h.auth = await createToken('admin-1', 'admin')
    h.actAs = await createActAsToken('admin-1', 'managed')
    expect((await put('managed', { v2Enabled: true })).status).toBe(200)
    expect(h.audits[0]).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: 'managed', targetId: 'managed' })
  })

  test('the internal key never flips a switch: no person, no write', async () => {
    h.auth = undefined
    const r = await put('victim', { v2Enabled: true }, { 'x-internal-key': 'ik-test-tradecraft-0001' })
    expect(r.status).toBe(401)
    expect(h.writes).toEqual([])
  })

  test('errors_use_fixed_message', async () => {
    h.readError = Object.assign(new Error('connection to db-host:5432 failed for user secret_user'), { code: 'P1001' })
    const g = await answer(await get('victim'))
    expect(g).toEqual({ status: 500, body: { error: 'Failed to read the Tradecraft settings', code: 'P1001' } })
    const p = await answer(await put('victim', { v2Enabled: true }))
    expect(p).toEqual({ status: 500, body: { error: 'Failed to save the Tradecraft settings', code: 'P1001' } })
    expect(JSON.stringify([g, p])).not.toContain('secret_user')
  })
})
