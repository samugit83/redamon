/**
 * POST /api/users/[id]/attack-skills/import-community (plan 0.C.2, 0.D): the bulk import
 * follows the upload's rules through the same writer. The name a skill is CREATED with is
 * the one checked (case- and space-insensitive, against existing skills and those created
 * earlier in the same import), the 1000 cap is counted under the per-user lock, and each
 * skip is counted by its reason.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { createHash } from 'crypto'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  session: null as { userId: string; role: string } | null,
  denied: null as unknown,
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', () => ({
  requireUserAccess: async () => h.denied,
  getSession: async () => h.session,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { MAX_CONTENT_SIZE } from '@/lib/userSkills'
import { POST } from './route'

let db: FakePrisma
const mockFetch = vi.fn()

type Entry = { id: string; name: string; description?: string }
type Detail = { name?: string; description?: string; content?: unknown } | 'http_error' | 'throws'

const params = (id: string) => ({ params: Promise.resolve({ id }) })
const run = async (id = 'alice') => {
  const res = await POST(new NextRequest(`http://localhost:3000/api/users/${id}/attack-skills/import-community`, { method: 'POST' }), params(id))
  return { status: res.status, body: await res.json() }
}
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')
const skills = () => db.rows('userAttackSkill').filter((r) => r.userId === 'alice')

function wire(catalog: Entry[], details: Record<string, Detail>, { catalogOk = true } = {}) {
  mockFetch.mockImplementation(async (url: string) => {
    if (/\/community-skills$/.test(url)) {
      return catalogOk
        ? new Response(JSON.stringify({ skills: catalog }), { status: 200 })
        : new Response('Internal Server Error', { status: 500 })
    }
    const id = decodeURIComponent(url.split('/').pop() as string)
    const d = details[id]
    if (d === 'throws') throw new Error('ECONNRESET')
    if (d === 'http_error') return { ok: false, status: 500, json: async () => ({}) }
    return { ok: true, json: async () => d ?? {} }
  })
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.session = { userId: 'alice', role: 'standard' }
  h.denied = null
  h.audits = []
  mockFetch.mockReset()
  vi.stubGlobal('fetch', mockFetch)
})

describe('POST attack-skills/import-community', () => {
  test('imports every entry with its created name, under the per-user lock', async () => {
    wire(
      [{ id: 'sqli', name: 'SQLi' }, { id: 'xss', name: 'XSS' }],
      { sqli: { name: 'SQL injection', content: 'Body A', description: 'About A' }, xss: { content: 'Body B' } },
    )
    const { status, body } = await run()
    expect(status).toBe(200)
    expect(body).toMatchObject({ imported: 2, skipped: 0, total: 2 })
    expect(skills().map((s) => s.name).sort()).toEqual(['SQL injection', 'XSS'])
    expect(body.importedIds.sort()).toEqual(skills().map((s) => s.id).sort())
    expect(db.rawCalls.some((c) => c.sql.includes('pg_advisory_xact_lock') && c.values[0] === 'user_attack_skills:alice')).toBe(true)
  })

  test('content over MAX_CONTENT_SIZE is skipped as tooLarge', async () => {
    wire(
      [{ id: 'big', name: 'Big' }, { id: 'ok', name: 'Ok' }],
      { big: { content: 'X'.repeat(MAX_CONTENT_SIZE + 1) }, ok: { content: 'small' } },
    )
    const { body } = await run()
    expect(body.imported).toBe(1)
    expect(body.skippedBy).toEqual({ duplicate: 0, limit: 0, fetchFailed: 0, tooLarge: 1, invalid: 0 })
    expect(skills().map((s) => s.name)).toEqual(['Ok'])
  })

  test('stops at the 1000 ceiling: with 999 existing, one is imported and the rest are limit', async () => {
    db.seed('userAttackSkill', Array.from({ length: 999 }, (_, i) => ({ userId: 'alice', name: `Existing ${i}`, content: 'x' })))
    wire(
      [{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }, { id: 'c', name: 'C' }],
      { a: { content: 'x' }, b: { content: 'y' }, c: { content: 'z' } },
    )
    const { body } = await run()
    expect(body).toMatchObject({ imported: 1, skipped: 2, total: 3 })
    expect(body.skippedBy.limit).toBe(2)
    expect(skills()).toHaveLength(1000)
  })

  test('another user at the cap does not limit this one', async () => {
    db.seed('userAttackSkill', Array.from({ length: 1000 }, (_, i) => ({ userId: 'bob', name: `B ${i}`, content: 'x' })))
    wire([{ id: 'a', name: 'A' }], { a: { content: 'x' } })
    expect((await run()).body.imported).toBe(1)
  })

  test('the description is truncated to 500 characters', async () => {
    wire([{ id: 'a', name: 'A' }], { a: { description: 'D'.repeat(600), content: 'ok' } })
    await run()
    expect(skills()[0].description).toHaveLength(500)
  })

  test("the catalog's description is the fallback, truncated too", async () => {
    wire([{ id: 'a', name: 'A', description: 'C'.repeat(700) }], { a: { content: 'ok' } })
    await run()
    expect(skills()[0].description).toBe('C'.repeat(500))
  })

  test('a name equal to an existing skill but for case and spacing is a duplicate', async () => {
    db.seed('userAttackSkill', [{ id: 'mine', userId: 'alice', name: 'SQL Injection', content: 'My own text' }])
    wire([{ id: 'sqli', name: 'sql  injection' }, { id: 'new', name: 'New one' }], { sqli: { content: 'x' }, new: { content: 'y' } })
    const { body } = await run()
    expect(body).toMatchObject({ imported: 1, skipped: 1 })
    expect(body.skippedBy.duplicate).toBe(1)
    expect(skills().find((s) => s.id === 'mine')!.content).toBe('My own text')
  })

  test('two entries that create the same name in one import: only the first is created', async () => {
    wire(
      [{ id: 'one', name: 'Recon' }, { id: 'two', name: 'RECON ' }, { id: 'three', name: 'Other' }],
      { one: { content: 'first' }, two: { content: 'second' }, three: { content: 'third' } },
    )
    const { body } = await run()
    expect(body).toMatchObject({ imported: 2, skipped: 1 })
    expect(body.skippedBy.duplicate).toBe(1)
    expect(skills().find((s) => s.name === 'Recon')!.content).toBe('first')
  })

  test("the created name (skillData.name) is what's checked, not the catalog's", async () => {
    db.seed('userAttackSkill', [{ id: 'mine', userId: 'alice', name: 'Taken name', content: 'x' }])
    wire(
      [{ id: 'renamed_away', name: 'Taken name' }, { id: 'renamed_onto', name: 'Fresh catalog name' }],
      { renamed_away: { name: 'A different name', content: 'a' }, renamed_onto: { name: 'TAKEN  name', content: 'b' } },
    )
    const { body } = await run()
    expect(body).toMatchObject({ imported: 1, skipped: 1 })
    expect(body.skippedBy.duplicate).toBe(1)
    expect(skills().map((s) => s.name).sort()).toEqual(['A different name', 'Taken name'])
  })

  test('names are stored normalized', async () => {
    wire([{ id: 'a', name: '  Spaced\t\tout  ' }], { a: { content: 'x' } })
    await run()
    expect(skills()[0].name).toBe('Spaced out')
  })

  test('a failed or thrown fetch of one entry is counted as fetchFailed', async () => {
    wire(
      [{ id: 'down', name: 'Down' }, { id: 'boom', name: 'Boom' }, { id: 'ok', name: 'Ok' }],
      { down: 'http_error', boom: 'throws', ok: { content: 'x' } },
    )
    const { body } = await run()
    expect(body).toMatchObject({ imported: 1, skipped: 2, total: 3 })
    expect(body.skippedBy.fetchFailed).toBe(2)
  })

  test('an entry with no usable text is counted as invalid', async () => {
    wire([{ id: 'empty', name: 'Empty' }, { id: 'obj', name: 'Obj' }], { empty: { content: '   ' }, obj: { content: { not: 'text' } } })
    const { body } = await run()
    expect(body.skippedBy.invalid).toBe(2)
    expect(skills()).toHaveLength(0)
  })

  test('skippedBy is split by reason and skipped is its total', async () => {
    db.seed('userAttackSkill', [{ id: 'mine', userId: 'alice', name: 'Dup', content: 'x' }])
    wire(
      [
        { id: 'dup', name: 'dup' }, { id: 'big', name: 'Big' }, { id: 'down', name: 'Down' },
        { id: 'empty', name: 'Empty' }, { id: 'ok', name: 'Ok' },
      ],
      { dup: { content: 'x' }, big: { content: 'x'.repeat(MAX_CONTENT_SIZE + 1) }, down: 'http_error', empty: { content: '' }, ok: { content: 'x' } },
    )
    const { body } = await run()
    expect(body.skippedBy).toEqual({ duplicate: 1, limit: 0, fetchFailed: 1, tooLarge: 1, invalid: 1 })
    expect(body.skipped).toBe(4)
    expect(body.imported).toBe(1)
    expect(body.total).toBe(5)
    expect(body.importedIds).toEqual([skills().find((s) => s.name === 'Ok')!.id])
  })

  test('one user_attack_skill.import audit per created skill, with the hash and never the text', async () => {
    wire(
      [{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }, { id: 'dup', name: 'a' }],
      { a: { content: 'TEXT-A' }, b: { content: 'TEXT-B' }, dup: { content: 'TEXT-C' } },
    )
    const { body } = await run()
    expect(h.audits).toHaveLength(2)
    const byId = new Map(skills().map((s) => [s.id, s]))
    for (const a of h.audits) {
      const s = byId.get(a.targetId as string)!
      expect(a).toEqual({
        actorId: 'alice',
        action: 'user_attack_skill.import',
        targetType: 'user_attack_skill',
        targetId: s.id,
        after: { name: s.name, contentSha256: sha(s.content as string), userId: 'alice', source: 'community', communityId: s.name === 'A' ? 'a' : 'b' },
        source: 'ui',
      })
    }
    expect(h.audits.map((a) => a.targetId).sort()).toEqual([...body.importedIds].sort())
    expect(JSON.stringify(h.audits)).not.toMatch(/TEXT-/)
  })

  test('an admin importing for the user is audited on behalf of the owner', async () => {
    h.session = { userId: 'admin1', role: 'admin' }
    wire([{ id: 'a', name: 'A' }], { a: { content: 'x' } })
    await run()
    expect(h.audits).toEqual([expect.objectContaining({ actorId: 'admin1', after: expect.objectContaining({ onBehalfOf: 'alice' }) })])
  })

  test('the catalog failing is 502 with the agent status, and nothing is created', async () => {
    wire([], {}, { catalogOk: false })
    const { status, body } = await run()
    expect(status).toBe(502)
    expect(body).toEqual({
      error: 'Failed to fetch community skills catalog from agent service',
      code: 'agent_error',
      upstreamStatus: 500,
    })
    expect(skills()).toHaveLength(0)
  })

  test('an agent that never answers is 503 agent_unreachable with the errno, and nothing is created', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockFetch.mockRejectedValue(Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('connect ECONNREFUSED 172.18.0.5:8080'), { code: 'ECONNREFUSED' }),
    }))
    const { status, body } = await run()
    expect(status).toBe(503)
    expect(body).toEqual({
      error: 'Failed to fetch community skills catalog from agent service',
      code: 'agent_unreachable',
      cause: 'ECONNREFUSED',
    })
    expect(skills()).toHaveLength(0)
    vi.restoreAllMocks()
  })

  test('the catalog is read from the agent with the internal key', async () => {
    wire([], {})
    await run()
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toMatch(/\/community-skills$/)
    expect(init.headers).toHaveProperty('x-internal-key')
  })

  test('a database failure is 500 with its Prisma code, never its message', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    wire([{ id: 'a', name: 'A' }], { a: { content: 'x' } })
    h.db = new Proxy(db as unknown as Record<string, unknown>, {
      get: (t, k) => (k === '$transaction'
        ? async () => { throw Object.assign(new Error('Transaction API error: SELECT secret'), { code: 'P2028' }) }
        : t[k as string]),
    })
    const res = await POST(
      new NextRequest('http://localhost:3000/api/users/alice/attack-skills/import-community', { method: 'POST' }),
      { params: Promise.resolve({ id: 'alice' }) },
    )
    const text = await res.text()
    expect(res.status).toBe(500)
    expect(JSON.parse(text)).toEqual({ error: 'Failed to import community attack skills', code: 'P2028' })
    expect(text).not.toContain('SELECT')
    vi.restoreAllMocks()
  })

  test('a cross-user caller is refused before any fetch, and nothing is created', async () => {
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    wire([{ id: 'a', name: 'A' }], { a: { content: 'x' } })
    const { status } = await run('bob')
    expect(status).toBe(403)
    expect(mockFetch).not.toHaveBeenCalled()
    expect(db.rows('userAttackSkill')).toHaveLength(0)
    expect(h.audits).toEqual([])
  })
})
