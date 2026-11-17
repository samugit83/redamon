/**
 * GET/PUT /api/users/[id]/tradecraft-settings: the account's Tradecraft 2.0 switch and, while
 * it is on, the account's ingestion settings (Configure ingestion, T3.4).
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
  rows: new Map<string, { v2Enabled: boolean; v2EnabledAt: Date | null; ingestion?: Record<string, unknown>; recipes?: unknown; search?: Record<string, unknown>; synonyms?: unknown; bulkRefreshOfferedAt?: Date | null }>(),
  audits: [] as Record<string, unknown>[],
  writes: [] as string[],
  reads: 0,
  readError: null as Error | null,
  convertCalls: [] as string[],
  convertAnswer: { status: 200, body: { queued: 2 } as unknown } as { status: number; body: unknown } | 'unreachable',
  converted: 0,
}))

vi.mock('@/lib/agentFetch', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  agentFetch: vi.fn(async (path: string) => {
    h.convertCalls.push(path)
    if (h.convertAnswer === 'unreachable') throw new Error('connect ECONNREFUSED')
    return new Response(JSON.stringify(h.convertAnswer.body), { status: h.convertAnswer.status })
  }),
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
    upsert: async ({ where, create, update }: { where: { userId: string }; create: { v2Enabled: boolean; v2EnabledAt: Date | null }; update: Record<string, unknown> }) => {
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
      if (name === 'userTradecraftResource' && op === 'count') return async () => h.converted
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
  h.convertCalls = []
  h.convertAnswer = { status: 200, body: { queued: 2 } }
  h.converted = 0
  vi.mocked(requireSelfPermission).mockClear()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  vi.restoreAllMocks()
})

describe('GET /api/users/[id]/tradecraft-settings', () => {
  test('the account reads its switch, off without a row; the ingestion section only while on', async () => {
    expect(await answer(await get('victim'))).toEqual({ status: 200, body: { v2Enabled: false } })
    h.rows.set('victim', { v2Enabled: true, v2EnabledAt: new Date() })
    const on = await answer(await get('victim'))
    expect(on.status).toBe(200)
    expect(on.body.v2Enabled).toBe(true)
    expect(Object.keys(on.body.ingestion as object).sort()).toEqual(['changed', 'defaults', 'values'])
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
    expect(await answer(await get('victim'))).toMatchObject({ status: 200, body: { v2Enabled: true } })
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

describe('the ingestion settings (T3.4)', () => {
  type View = { values: Record<string, unknown>; changed: string[]; defaults: Record<string, unknown> }
  const on = () => h.rows.set('victim', { v2Enabled: true, v2EnabledAt: new Date() })

  test('get_values_changed_defaults: values, the changed keys and the defaults', async () => {
    on()
    h.rows.get('victim')!.ingestion = { 'crawl.maxPages': 50 }
    const r = await answer(await get('victim'))
    const view = r.body.ingestion as View
    expect(view.values['crawl.maxPages']).toBe(50)
    expect(view.defaults['crawl.maxPages']).toBe(200)
    expect(view.changed).toEqual(['crawl.maxPages'])
  })

  test('put_stores_only_changed, and answers the new view', async () => {
    on()
    const r = await answer(await put('victim', { ingestion: { 'crawl.maxPages': 120 } }))
    expect(r.status).toBe(200)
    expect((r.body.ingestion as View).changed).toEqual(['crawl.maxPages'])
    expect(h.rows.get('victim')!.ingestion).toEqual({ 'crawl.maxPages': 120 })
    expect(h.rows.get('victim')!.v2Enabled).toBe(true)
  })

  test('put_default_removes_key', async () => {
    on()
    h.rows.get('victim')!.ingestion = { 'crawl.maxPages': 120, 'summary.titles': 10 }
    await put('victim', { ingestion: { 'crawl.maxPages': 200 } })
    expect(h.rows.get('victim')!.ingestion).toEqual({ 'summary.titles': 10 })
  })

  test('refuses_out_of_range: 400 naming the key and its range, nothing written', async () => {
    on()
    const r = await answer(await put('victim', { ingestion: { 'crawl.maxPages': 9000 } }))
    expect(r.status).toBe(400)
    expect(r.body.code).toBe('invalid_settings')
    expect(r.body.error).toBe('crawl.maxPages must be an integer from 1 to 500')
    expect(r.body.errors).toEqual([{ key: 'crawl.maxPages', code: 'bad_value', message: 'crawl.maxPages must be an integer from 1 to 500' }])
    expect(h.writes).toEqual([])
  })

  test('resource_only_keys_refused and user_only_keys_accepted', async () => {
    on()
    const bad = await answer(await put('victim', { ingestion: { 'content.bodySelector': 'main' } }))
    expect(bad.status).toBe(400)
    expect((bad.body.errors as { key: string; code: string }[])[0]).toMatchObject({ key: 'content.bodySelector', code: 'resource_only' })
    const good = await answer(await put('victim', { ingestion: { 'storage.userQuotaMb': 2048 } }))
    expect(good.status).toBe(200)
    expect(h.rows.get('victim')!.ingestion).toEqual({ 'storage.userQuotaMb': 2048 })
  })

  test('reset_section and reset_all', async () => {
    on()
    h.rows.get('victim')!.ingestion = { 'crawl.maxPages': 120, 'crawl.parallel': 3, 'summary.titles': 10 }
    const r = await answer(await put('victim', { reset: 'crawl' }))
    expect(r.status).toBe(200)
    expect(h.rows.get('victim')!.ingestion).toEqual({ 'summary.titles': 10 })
    await put('victim', { reset: 'all' })
    expect(h.rows.get('victim')!.ingestion).toEqual({})
    const bad = await answer(await put('victim', { reset: 'nope' }))
    expect(bad.status).toBe(400)
    expect(bad.body.code).toBe('invalid_settings')
  })

  test('switch_off_404: with 2.0 off the section neither reads nor writes', async () => {
    for (const body of [{ ingestion: { 'crawl.maxPages': 120 } }, { reset: 'all' }]) {
      const r = await answer(await put('victim', body))
      expect(r).toEqual({ status: 404, body: { error: 'Tradecraft 2.0 is off for this account', code: 'tradecraft_v2_off' } })
    }
    expect(h.writes).toEqual([])
    expect((await answer(await get('victim'))).body).toEqual({ v2Enabled: false })
  })

  test.each([
    ['two sections at once', { ingestion: {}, reset: 'all' }],
    ['ingestion that is not an object', { ingestion: [1] }],
    ['reset that is not a string', { reset: 1 }],
  ])('a malformed body is a 400 before anything is written: %s', async (_name, body) => {
    on()
    const r = await answer(await put('victim', body))
    expect(r.status).toBe(400)
    expect(h.writes).toEqual([])
  })

  test('isolated (AC-04): an account cannot read or write another account\'s settings', async () => {
    h.rows.set('managed', { v2Enabled: true, v2EnabledAt: new Date(), ingestion: { 'crawl.maxPages': 7 } })
    expect((await get('managed')).status).toBe(403)
    expect((await put('managed', { ingestion: { 'crawl.maxPages': 9 } })).status).toBe(403)
    expect(h.rows.get('managed')!.ingestion).toEqual({ 'crawl.maxPages': 7 })
  })

  test('the internal key alone saves no setting', async () => {
    on()
    h.auth = undefined
    const r = await put('victim', { ingestion: { 'crawl.maxPages': 9 } }, { 'x-internal-key': 'ik-test-tradecraft-0001' })
    expect(r.status).toBe(401)
    expect(h.rows.get('victim')!.ingestion).toBeUndefined()
  })
})

describe('the focus recipes (T5.5)', () => {
  const on = () => h.rows.set('victim', { v2Enabled: true, v2EnabledAt: new Date() })
  type Recipe = { id: string; name: string; topics: string[]; kinds: string[] }

  test('GET lists them while 2.0 is on; PUT adds, renames and deletes one, answering the list', async () => {
    on()
    expect((await answer(await get('victim'))).body.recipes).toEqual([])
    const added = await answer(await put('victim', { recipes: { add: { name: 'Web', topics: ['xss'], kinds: ['payloads'] } } }))
    expect(added).toMatchObject({ status: 200, body: { v2Enabled: true, recipes: [{ name: 'Web', topics: ['xss'], kinds: ['payloads'] }] } })
    const id = (added.body.recipes as Recipe[])[0].id
    expect((await answer(await get('victim'))).body.recipes).toEqual(added.body.recipes)
    expect((await answer(await put('victim', { recipes: { rename: { id, name: 'Web 2' } } }))).body.recipes).toMatchObject([{ id, name: 'Web 2' }])
    expect((await answer(await put('victim', { recipes: { delete: id } }))).body.recipes).toEqual([])
    expect(h.rows.get('victim')!.recipes).toEqual([])
  })

  test('a refused recipe answers its code, field and status; nothing written', async () => {
    on()
    const bad = await answer(await put('victim', { recipes: { add: { name: 'x', topics: ['sqli'] } } }))
    expect(bad).toMatchObject({ status: 400, body: { code: 'bad_recipe', field: 'topics' } })
    const missing = await answer(await put('victim', { recipes: { delete: 'nope' } }))
    expect(missing).toMatchObject({ status: 404, body: { code: 'recipe_not_found' } })
    expect(h.writes).toEqual([])
  })

  test('with 2.0 off: 404, nothing read or written; the internal key alone saves none', async () => {
    expect(await answer(await put('victim', { recipes: { add: { name: 'x', kinds: ['poc'] } } })))
      .toEqual({ status: 404, body: { error: 'Tradecraft 2.0 is off for this account', code: 'tradecraft_v2_off' } })
    on()
    h.auth = undefined
    expect((await put('victim', { recipes: { add: { name: 'x', kinds: ['poc'] } } }, { 'x-internal-key': 'ik-test-tradecraft-0001' })).status).toBe(401)
    expect(h.writes).toEqual([])
  })

  test('recipes and another section at once is a 400', async () => {
    on()
    expect((await put('victim', { recipes: { delete: 'x' }, reset: 'all' })).status).toBe(400)
    expect(h.writes).toEqual([])
  })
})

describe('the search settings (Configure search, T7.2)', () => {
  type View = { values: Record<string, unknown>; changed: string[]; defaults: Record<string, unknown>; synonyms: { term: string; expansion: string }[] }
  const on = () => h.rows.set('victim', { v2Enabled: true, v2EnabledAt: new Date() })

  test('GET answers the search section beside ingestion and recipes: values, changed, defaults, my synonyms', async () => {
    on()
    h.rows.get('victim')!.search = { 'librarian.use': 'search_only', 'search.results': 12 }
    h.rows.get('victim')!.synonyms = [{ term: 'PATT', expansions: ['PayloadsAllTheThings'] }, 'junk']
    const r = await answer(await get('victim'))
    const view = r.body.search as View
    expect(view.values).toMatchObject({ 'librarian.use': 'search_only', 'search.results': 12, 'librarian.maxModelCalls': 5, 'reading.charsPerRead': 12000 })
    expect(view.changed).toEqual(['librarian.use', 'search.results'])
    expect(view.defaults['search.results']).toBe(8)
    expect(view.synonyms).toEqual([{ term: 'PATT', expansion: 'PayloadsAllTheThings' }])
  })

  test('search_section_ranges: a value out of its range is a 400 naming the key; nothing written', async () => {
    on()
    for (const [key, value] of [['librarian.maxModelCalls', 11], ['librarian.timeLimitSec', 9], ['search.results', 2], ['reading.charsPerRead', 40001], ['hints.perRun', 21], ['librarian.use', 'never']] as const) {
      const r = await answer(await put('victim', { search: { [key]: value } }))
      expect(r.status, key).toBe(400)
      expect(r.body.code).toBe('invalid_settings')
      expect((r.body.errors as { key: string }[])[0].key).toBe(key)
    }
    // An ingestion key is not a search setting.
    expect((await answer(await put('victim', { search: { 'crawl.maxPages': 50 } }))).status).toBe(400)
    expect(h.rows.get('victim')!.search).toBeUndefined()
  })

  test('PUT stores only what differs from the defaults, with the synonym pairs in the agent\'s shape', async () => {
    on()
    const r = await answer(await put('victim', { search: {
      'librarian.maxModelCalls': 3, 'search.results': 8, 'prompt.resourceList': 'one_line',
      synonyms: [{ term: ' PATT ', expansion: 'PayloadsAllTheThings' }],
    } }))
    expect(r.status).toBe(200)
    expect((r.body.search as View).changed).toEqual(['librarian.maxModelCalls', 'prompt.resourceList'])
    expect(h.rows.get('victim')!.search).toEqual({ 'librarian.maxModelCalls': 3, 'prompt.resourceList': 'one_line' })
    expect(h.rows.get('victim')!.synonyms).toEqual([{ term: 'PATT', expansions: ['PayloadsAllTheThings'] }])
    // Settings without synonyms keep the stored pairs.
    await put('victim', { search: { 'hints.enabled': false } })
    expect(h.rows.get('victim')!.synonyms).toEqual([{ term: 'PATT', expansions: ['PayloadsAllTheThings'] }])
  })

  test('synonyms_cap_200: 200 pairs are taken, 201 refused; a malformed or doubled pair refuses the save', async () => {
    on()
    const pairs = (n: number) => Array.from({ length: n }, (_, i) => ({ term: `t${i}`, expansion: `expansion ${i}` }))
    expect((await answer(await put('victim', { search: { synonyms: pairs(200) } }))).status).toBe(200)
    expect((h.rows.get('victim')!.synonyms as unknown[]).length).toBe(200)
    for (const synonyms of [pairs(201), [{ term: 'a', expansion: '' }], [{ term: 'a', expansion: 'A' }], [{ term: 'a', expansion: 'b' }, { term: 'A', expansion: 'B' }], [{ term: 'a\n', expansion: 'b' }], 'a = b']) {
      const r = await answer(await put('victim', { search: { synonyms } }))
      expect(r.status, JSON.stringify(synonyms).slice(0, 40)).toBe(400)
      expect((r.body.errors as { key: string }[])[0].key).toBe('synonyms')
    }
    expect((h.rows.get('victim')!.synonyms as unknown[]).length).toBe(200)
  })

  test('reset: every search setting back to its default; the synonym pairs stay', async () => {
    on()
    h.rows.get('victim')!.search = { 'search.results': 12, 'some.future.key': 1 }
    h.rows.get('victim')!.synonyms = [{ term: 'a', expansions: ['b'] }]
    const r = await answer(await put('victim', { reset: 'search' }))
    expect(r.status).toBe(200)
    expect((r.body.search as View).changed).toEqual([])
    expect(h.rows.get('victim')!.search).toEqual({ 'some.future.key': 1 })
    expect(h.rows.get('victim')!.synonyms).toEqual([{ term: 'a', expansions: ['b'] }])
  })

  test('with 2.0 off: 404, nothing written; the internal key alone saves none; another account is refused', async () => {
    for (const body of [{ search: { 'search.results': 9 } }, { reset: 'search' }]) {
      expect((await answer(await put('victim', body))).status).toBe(404)
    }
    expect(h.writes).toEqual([])
    on()
    h.auth = undefined
    expect((await put('victim', { search: { 'search.results': 9 } }, { 'x-internal-key': 'ik-test-tradecraft-0001' })).status).toBe(401)
    h.auth = await createToken('victim', 'standard')
    h.rows.set('managed', { v2Enabled: true, v2EnabledAt: new Date() })
    expect((await put('managed', { search: { 'search.results': 9 } })).status).toBe(403)
    expect(h.rows.get('managed')!.search).toBeUndefined()
    expect((await put('victim', { search: { 'search.results': 9 }, reset: 'search' })).status).toBe(400)
  })
})

describe('the conversion of 1.x resources (T9.1)', () => {
  test('switch_on_triggers_convert: turning 2.0 on asks the agent to convert the account; off asks nothing', async () => {
    expect(await answer(await put('victim', { v2Enabled: true }))).toEqual({ status: 200, body: { v2Enabled: true } })
    expect(h.convertCalls).toEqual(['/tradecraft/v2/users/victim/convert'])
    expect(await answer(await put('victim', { v2Enabled: false }))).toEqual({ status: 200, body: { v2Enabled: false } })
    expect(h.convertCalls).toHaveLength(1)
  })

  test('the conversion is best effort: a refusing or unreachable agent never fails the switch', async () => {
    h.convertAnswer = { status: 503, body: { error_code: 'internal_error' } }
    expect(await answer(await put('victim', { v2Enabled: true }))).toEqual({ status: 200, body: { v2Enabled: true } })
    h.rows.get('victim')!.v2Enabled = false
    h.convertAnswer = 'unreachable'
    expect(await answer(await put('victim', { v2Enabled: true }))).toEqual({ status: 200, body: { v2Enabled: true } })
    expect(h.rows.get('victim')!.v2Enabled).toBe(true)
    expect(h.convertCalls).toHaveLength(2)
  })

  test('a request the switch refuses asks for no conversion', async () => {
    h.auth = undefined
    expect((await put('victim', { v2Enabled: true })).status).toBe(401)
    expect(h.convertCalls).toEqual([])
  })

  test('offer_once: offered while a converted resource exists and the person never answered; either answer ends it', async () => {
    h.rows.set('victim', { v2Enabled: true, v2EnabledAt: new Date() })
    expect((await answer(await get('victim'))).body.offerBulkRefresh).toBe(false)
    h.converted = 3
    expect((await answer(await get('victim'))).body.offerBulkRefresh).toBe(true)
    expect(await answer(await put('victim', { bulkRefreshOffered: true }))).toEqual({ status: 200, body: { v2Enabled: true, offerBulkRefresh: false } })
    const at = h.rows.get('victim')!.bulkRefreshOfferedAt
    expect(at).toBeInstanceOf(Date)
    expect((await answer(await get('victim'))).body.offerBulkRefresh).toBe(false)
    await put('victim', { bulkRefreshOffered: true })
    expect(h.rows.get('victim')!.bulkRefreshOfferedAt).toBe(at)
  })

  test('the answer needs 2.0 on, a person and the account; anything but true is a 400', async () => {
    expect((await answer(await put('victim', { bulkRefreshOffered: true }))).status).toBe(404)
    h.rows.set('victim', { v2Enabled: true, v2EnabledAt: new Date() })
    expect((await answer(await put('victim', { bulkRefreshOffered: false }))).status).toBe(400)
    expect((await answer(await put('victim', { bulkRefreshOffered: true }, {}))).status).toBe(200)
    h.auth = await createToken('admin-1', 'admin')
    expect((await put('victim', { bulkRefreshOffered: true })).status).toBe(403)
  })
})
