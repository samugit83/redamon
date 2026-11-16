/**
 * GET/POST /api/users/[id]/tradecraft-resources/[resourceId]/map (§6.10, T6.7; R-161, R-165,
 * R-167, AC-39): the Map view's list and curation behind the account's guards. The rules
 * themselves are `lib/tradecraft/curation.test.ts`'s; here: the guards, the query's bounds, ids as
 * strings, another account's resource, the 409 of a changed count, and titles and URLs only for
 * a resource with a login while an administrator acts as the account.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'

const h = vi.hoisted(() => ({
  db: null as unknown as TradecraftDb, denied: null as Response | null, person: 'owner' as string | null, actingAs: false,
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => ({ requireSelfPermission: vi.fn(async () => null) }))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => h.denied), isInternalRequest: vi.fn(() => false) }))
vi.mock('@/lib/auditActor', async orig => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  auditActor: async () => ({ actorId: h.person, onBehalfOfUserId: null }),
}))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  actingAsOn: vi.fn(async () => h.actingAs),
  refuseWhileActingAsOn: vi.fn(async () => (h.actingAs ? NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 }) : null)),
}))

import { requireSelfPermission } from '@/lib/authz/selfService'
import { GET, POST } from './route'

const PR = (resourceId = 'r1') => ({ params: Promise.resolve({ id: 'owner', resourceId }) })
const get = (qs = '', resourceId = 'r1') => GET(new NextRequest(`http://webapp.test/api/users/owner/tradecraft-resources/${resourceId}/map${qs}`), PR(resourceId))
const post = (body: unknown, resourceId = 'r1') => POST(new NextRequest(`http://webapp.test/api/users/owner/tradecraft-resources/${resourceId}/map`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), PR(resourceId))
async function answer(res: Response) {
  return { status: res.status, body: await res.json() }
}

beforeEach(() => {
  h.db = createTradecraftDb()
  h.denied = null
  h.person = 'owner'
  h.actingAs = false
  h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
  h.db.seed('userTradecraftResource', { id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', generation: 1 })
  h.db.seed('userTradecraftResource', {
    id: 'kb', userId: 'owner', name: 'KB', slug: 'kb', url: 'https://kb.example.test/', generation: 1, credentials: { cookie: 'session=fake' }, hasLogin: true,
  })
  h.db.seed('userTradecraftResource', { id: 'theirs', userId: 'other', name: 'X', slug: 'x', url: 'https://x.example.test/', generation: 1 })
  for (const [n, resourceId, userId] of [[9007199254740993n, 'r1', 'owner'], [2n, 'r1', 'owner'], [3n, 'kb', 'owner'], [4n, 'theirs', 'other']] as const) {
    h.db.seed('tradecraftEntry', {
      id: n, userId, resourceId, generation: 1, pageId: Number(n % 1000n), url: `https://${resourceId}.example.test/p${n}`, title: `Page ${n}`,
      description: 'A one-line description', status: 'kept',
    })
  }
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

describe('GET map', () => {
  test('bigint_as_string: ids beyond a JSON number travel as strings; the total; no text', async () => {
    const r = await answer(await get())
    expect(r.status).toBe(200)
    expect(r.body.total).toBe(2)
    expect(r.body.entries.map((e: { id: string }) => e.id)).toEqual(['2', '9007199254740993'])
    expect(r.body.entries[0]).toMatchObject({ pageId: 'wiki:2', description: 'A one-line description' })
  })

  test("owner_only: another account's resource is not found; the account rule and self:tradecraft run first", async () => {
    expect((await get('', 'theirs')).status).toBe(404)
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await get()).status).toBe(403)
    expect(vi.mocked(requireSelfPermission).mock.calls[0].slice(1)).toEqual(['owner', 'self:tradecraft'])
  })

  test.each([['?status=gone', 'status'], [`?query=${'q'.repeat(201)}`, 'query'], ['?cursor=abc', 'cursor'], ['?limit=0', 'limit'], ['?limit=101', 'limit']])(
    'a bad query is a 400 naming it: %s', async (qs, field) => {
      expect(await answer(await get(qs))).toMatchObject({ status: 400, body: { field } })
    })

  test('act_as_login_refused (R-161): acting as the account, a resource with a login shows titles and URLs only', async () => {
    h.actingAs = true
    const kb = await answer(await get('', 'kb'))
    expect(kb.body.entries).toEqual([expect.objectContaining({ title: 'Page 3', url: 'https://kb.example.test/p3', description: '' })])
    expect((await answer(await get())).body.entries[0].description).toBe('A one-line description')
  })

  test('with 2.0 off: 404, nothing read', async () => {
    h.db.rows('tradecraftUserSettings')[0].v2Enabled = false
    expect(await answer(await get())).toMatchObject({ status: 404, body: { code: 'tradecraft_v2_off' } })
  })
})

describe('POST map', () => {
  test('an operation answers its count; a refused one its status, code and field', async () => {
    expect(await answer(await post({ op: 'pin', url: 'https://wiki.example.test/new' }))).toEqual({ status: 200, body: { op: 'pin', count: 1 } })
    expect(await answer(await post({ op: 'pin', url: 'http://10.0.0.1/' }))).toMatchObject({ status: 400, body: { field: 'url' } })
    expect(await answer(await post({ op: 'block', matching: { query: 'page' }, expectedCount: 7 }))).toMatchObject({ status: 409, body: { code: 'count_changed', count: 2 } })
    expect(await answer(await post({ op: 'block', matching: { query: 'page' }, expectedCount: 2 }))).toEqual({ status: 200, body: { op: 'block', count: 2 } })
    expect(h.db.rows('tradecraftCuration', { resourceId: 'r1', blocked: true })).toHaveLength(2)
  })

  test("another account's resource: 404, nothing written; a person is needed; 2.0 off is a 404", async () => {
    expect((await post({ op: 'pin', url: 'https://x.example.test/a' }, 'theirs')).status).toBe(404)
    h.person = null
    expect((await post({ op: 'pin', url: 'https://wiki.example.test/a' })).status).toBe(401)
    h.person = 'owner'
    h.db.rows('tradecraftUserSettings')[0].v2Enabled = false
    expect((await post({ op: 'pin', url: 'https://wiki.example.test/a' })).status).toBe(404)
    expect(h.db.rows('tradecraftCuration')).toEqual([])
  })
})
