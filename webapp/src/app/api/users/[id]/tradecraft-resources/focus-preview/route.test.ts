/**
 * POST /api/users/[id]/tradecraft-resources/focus-preview (§6.14 "Preview", T5.5): how a focus
 * would sort a sample of at most 100 map entries, answered by the agent with the resource's
 * model. Nothing is saved (AC-09's rule for the synchronous routes). A saved resource is read
 * by its id and its account, and its sample comes from its live generation, never from the
 * body (D-54); entries from a Check URL result are bounded and checked like resource URLs. The
 * login rule is asked first (§6.6), and the route waits the agent's deadline plus a margin (D-52).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { json, refused, stubAgent, timedOut } from '@/lib/tradecraft/__testing__/agentDouble'

const h = vi.hoisted(() => ({
  db: null as unknown as TradecraftDb, denied: null as Response | null, person: 'owner' as string | null,
  loginRefusal: null as Response | null, order: [] as string[],
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => ({ requireSelfPermission: vi.fn(async () => null) }))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => h.denied), isInternalRequest: vi.fn(() => false) }))
vi.mock('@/lib/auditActor', async orig => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  auditActor: async () => ({ actorId: h.person, onBehalfOfUserId: null }),
}))
vi.mock('@/lib/tradecraft/actAs', () => ({
  loginUseRefusal: vi.fn(async () => { h.order.push('loginUseRefusal'); return h.loginRefusal }),
}))

import { PreviewRequest, WEBAPP_TIMEOUTS_MS } from '@/lib/tradecraft/agentContract'
import { loginUseRefusal } from '@/lib/tradecraft/actAs'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { POST } from './route'

const FOCUS = { mode: 'focused', topics: ['sql_injection'], kinds: ['payloads'], keep: 'SQL injection payloads', skip: '', skipMode: 'add', strictness: 'balanced' }
const RESULT = {
  kept: 1, maybe: 0, dropped: 1, llm_calls: 1, error_code: '',
  examples: [
    { url: 'https://wiki.tc-fixture.test/sqli', title: 'SQLi', decision: 'keep', reason: 'payloads', topics: ['sql_injection'], kinds: ['payloads'] },
    { url: 'https://wiki.tc-fixture.test/news', title: 'News', decision: 'drop', reason: 'news', topics: [], kinds: [] },
  ],
}
const ENTRIES = [{ url: 'https://wiki.tc-fixture.test/sqli', title: 'SQLi' }, { url: 'https://wiki.tc-fixture.test/news', title: 'News' }]

const previewAgent = (result: unknown = RESULT) => stubAgent((path) => (path === '/tradecraft/v2/preview-focus' ? json(result) : json({}, 404)))
const post = (body: unknown) => POST(new NextRequest('http://webapp.test/api/users/owner/tradecraft-resources/focus-preview', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), { params: Promise.resolve({ id: 'owner' }) })
async function answer(res: Response) {
  return { status: res.status, body: await res.json() }
}
const writes = () => h.db.calls.filter(c => !/\.(findFirst|findUnique|findMany|count)$/.test(c))
const sent = (agent: ReturnType<typeof stubAgent>, i = 0) => PreviewRequest.parse(agent.calls[i].body)

function seedEntries(resourceId: string, generation: number, n: number, from = 1) {
  for (let i = from; i < from + n; i++) {
    h.db.seed('tradecraftEntry', {
      id: BigInt(resourceId === 'r1' ? i : 100_000 + i), userId: resourceId === 'r-x' ? 'other' : 'owner', resourceId, generation,
      pageId: i, url: `https://wiki.tc-fixture.test/p${i}`, title: `Page ${i}`,
    })
  }
}

beforeEach(() => {
  h.db = createTradecraftDb()
  h.denied = null
  h.person = 'owner'
  h.loginRefusal = null
  h.order = []
  h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
  h.db.seed('userTradecraftResource', { id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.tc-fixture.test/', llmModel: 'gpt-4o-mini', generation: 2 })
  h.db.seed('userTradecraftResource', { id: 'r-x', userId: 'other', name: 'X', slug: 'x', url: 'https://x.tc-fixture.test/', llmModel: 'gpt-4o', generation: 1 })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

describe('the focus preview', () => {
  test('preview_saves_nothing: Check URL entries go to the agent with the focus and the model; its result is answered', async () => {
    const agent = previewAgent()
    const timeout = vi.spyOn(AbortSignal, 'timeout')
    const r = await answer(await post({ focus: FOCUS, entries: ENTRIES, llmModel: 'gpt-4o' }))
    expect(r).toEqual({ status: 200, body: { result: RESULT } })
    expect(writes()).toEqual([])
    expect(h.db.raw).toEqual([])
    expect(sent(agent)).toEqual({ user_id: 'owner', model: 'gpt-4o', focus: FOCUS, entries: ENTRIES })
    // The agent's 120 s deadline plus the margin.
    expect(timeout).toHaveBeenCalledWith(WEBAPP_TIMEOUTS_MS.previewFocus)
    expect(WEBAPP_TIMEOUTS_MS.previewFocus).toBe(135_000)
  })

  test('preview_samples_100: a saved resource\'s live map is sampled, spread over it; older generations and other resources never', async () => {
    seedEntries('r1', 2, 250)
    seedEntries('r1', 1, 30, 1000)
    seedEntries('r-x', 1, 20)
    const agent = previewAgent()
    expect((await post({ focus: FOCUS, resourceId: 'r1' })).status).toBe(200)
    const req = sent(agent)
    expect(req.model).toBe('gpt-4o-mini')
    expect(req.entries).toHaveLength(100)
    const numbers = req.entries.map(e => Number(e.url.split('/p')[1]))
    expect(numbers.every(n => n >= 1 && n <= 250)).toBe(true)
    expect(new Set(numbers).size).toBe(100)
    expect(numbers[0]).toBe(1)
    expect(Math.max(...numbers)).toBeGreaterThan(240)
    expect(writes()).toEqual([])
  })

  test('a map of at most 100 entries goes whole; a long title is cut to 300 characters', async () => {
    seedEntries('r1', 2, 3)
    h.db.rows('tradecraftEntry', { pageId: 2 })[0].title = 't'.repeat(400)
    const agent = previewAgent()
    await post({ focus: FOCUS, resourceId: 'r1', llmModel: 'gpt-4o' })
    const req = sent(agent)
    expect(req.entries.map(e => e.url)).toEqual(['https://wiki.tc-fixture.test/p1', 'https://wiki.tc-fixture.test/p2', 'https://wiki.tc-fixture.test/p3'])
    expect(req.entries[1].title).toHaveLength(300)
    expect(req.model).toBe('gpt-4o')
  })

  test('a resource with no page list yet: 409, the agent never called', async () => {
    const agent = previewAgent()
    expect(await answer(await post({ focus: FOCUS, resourceId: 'r1' }))).toMatchObject({ status: 409, body: { code: 'no_entries' } })
    expect(agent.calls).toEqual([])
  })

  test("preview_foreign_resource_404: another account's resource is not found, its map never read", async () => {
    seedEntries('r-x', 1, 20)
    const agent = previewAgent()
    expect((await post({ focus: FOCUS, resourceId: 'r-x' })).status).toBe(404)
    expect(h.db.calls.filter(c => c.startsWith('tradecraftEntry'))).toEqual([])
    expect(agent.calls).toEqual([])
  })

  test('the login refusal is asked first for a saved resource, before its row is read', async () => {
    seedEntries('r1', 2, 3)
    const agent = previewAgent()
    h.loginRefusal = NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 })
    h.db.calls.length = 0
    expect((await post({ focus: FOCUS, resourceId: 'r1' })).status).toBe(403)
    expect(vi.mocked(loginUseRefusal)).toHaveBeenCalledWith({ ownerId: 'owner', resourceId: 'r1' })
    expect(h.db.calls.filter(c => c.startsWith('userTradecraftResource') || c.startsWith('tradecraftEntry'))).toEqual([])
    expect(agent.calls).toEqual([])
  })

  test.each([
    ['no entries', []],
    ['101 entries', Array.from({ length: 101 }, (_, i) => ({ url: `https://wiki.tc-fixture.test/p${i}`, title: 'x' }))],
    ['a title over 300 characters', [{ url: 'https://wiki.tc-fixture.test/a', title: 't'.repeat(301) }]],
    ['a private address', [{ url: 'http://127.0.0.1/admin', title: 'x' }]],
    ['a login in the URL', [{ url: 'https://u:p@wiki.tc-fixture.test/a', title: 'x' }]],
    ['not a URL', [{ url: 'javascript:alert(1)', title: 'x' }]],
    ['an entry that is not an object', ['https://wiki.tc-fixture.test/a']],
    ['entries not a list', 'https://wiki.tc-fixture.test/a'],
  ])('preview_entries_bounded: %s is a 400, the agent never called', async (_why, entries) => {
    const agent = previewAgent()
    const r = await answer(await post({ focus: FOCUS, entries, llmModel: 'gpt-4o' }))
    expect(r.status).toBe(400)
    expect(r.body.field).toMatch(/^entries/)
    expect(agent.calls).toEqual([])
  })

  test.each([
    ['no focus', { entries: ENTRIES, llmModel: 'gpt-4o' }, 'focus'],
    ['an empty focus', { focus: {}, entries: ENTRIES, llmModel: 'gpt-4o' }, 'focus'],
    ['mode Everything', { focus: { mode: 'everything' }, entries: ENTRIES, llmModel: 'gpt-4o' }, 'focus.mode'],
    ['a bad focus', { focus: { ...FOCUS, keep: 'k'.repeat(1001) }, entries: ENTRIES, llmModel: 'gpt-4o' }, 'focus.keep'],
    ['a foreign skill', { focus: { ...FOCUS, topics: ['user_skill:theirs'] }, entries: ENTRIES, llmModel: 'gpt-4o' }, 'focus.topics'],
    ['entries without a model', { focus: FOCUS, entries: ENTRIES }, 'llmModel'],
    ['a loop model', { focus: FOCUS, entries: ENTRIES, llmModel: 'loop/mcp' }, 'llmModel'],
    ['both a resource and entries', { focus: FOCUS, entries: ENTRIES, resourceId: 'r1', llmModel: 'gpt-4o' }, 'resourceId'],
    ['neither', { focus: FOCUS, llmModel: 'gpt-4o' }, 'resourceId'],
  ])('%s: 400 naming the field, the agent never called', async (_why, body, field) => {
    h.db.seed('userAttackSkill', { id: 'theirs', userId: 'other', name: 'Theirs' })
    const agent = previewAgent()
    const r = await answer(await post(body))
    expect(r.status).toBe(400)
    expect(r.body.field).toBe(field)
    expect(agent.calls).toEqual([])
  })

  test('the agent\'s deadline passes: 504 with a fixed text; unreachable 503; an error 502; a malformed answer 502', async () => {
    stubAgent(() => timedOut())
    expect(await answer(await post({ focus: FOCUS, entries: ENTRIES, llmModel: 'gpt-4o' }))).toMatchObject({ status: 504, body: { code: 'timeout' } })
    stubAgent(() => refused())
    expect(await answer(await post({ focus: FOCUS, entries: ENTRIES, llmModel: 'gpt-4o' }))).toMatchObject({ status: 503, body: { code: 'agent_unreachable' } })
    stubAgent(() => json({ detail: 'boom' }, 500))
    expect(await answer(await post({ focus: FOCUS, entries: ENTRIES, llmModel: 'gpt-4o' }))).toMatchObject({ status: 502, body: { code: 'agent_error' } })
    previewAgent({ kept: 'many' })
    expect(await answer(await post({ focus: FOCUS, entries: ENTRIES, llmModel: 'gpt-4o' }))).toMatchObject({ status: 502, body: { code: 'internal_error' } })
    expect(writes()).toEqual([])
  })

  test('the guards: the account rule, self:tradecraft, a person, 2.0 on', async () => {
    const agent = previewAgent()
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await post({ focus: FOCUS, entries: ENTRIES, llmModel: 'gpt-4o' })).status).toBe(403)
    h.denied = null
    h.person = null
    expect((await post({ focus: FOCUS, entries: ENTRIES, llmModel: 'gpt-4o' })).status).toBe(401)
    h.person = 'owner'
    h.db.rows('tradecraftUserSettings')[0].v2Enabled = false
    expect(await answer(await post({ focus: FOCUS, entries: ENTRIES, llmModel: 'gpt-4o' }))).toMatchObject({ status: 404, body: { code: 'tradecraft_v2_off' } })
    expect(vi.mocked(requireSelfPermission).mock.calls.at(-1)!.slice(1)).toEqual(['owner', 'self:tradecraft'])
    expect(agent.calls).toEqual([])
  })
})
