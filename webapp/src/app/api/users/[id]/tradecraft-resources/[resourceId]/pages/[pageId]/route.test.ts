/**
 * GET/POST /api/users/[id]/tradecraft-resources/[resourceId]/pages/[pageId] (§6.10, T6.7; R-161,
 * R-166, AC-38, D-54): View page answers the stored text with its date, or "not stored"; Read now
 * asks the agent for the URL of the entry the page ID names, with the row's secrets, never the
 * body's. While an administrator acts as the account, a resource with a login is refused both.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { json, refused, stubAgent, timedOut } from '@/lib/tradecraft/__testing__/agentDouble'

const h = vi.hoisted(() => ({
  db: null as unknown as TradecraftDb, denied: null as Response | null, person: 'owner' as string | null, actingAs: false,
  loginRefusal: null as Response | null,
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => ({ requireSelfPermission: vi.fn(async () => null) }))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => h.denied), isInternalRequest: vi.fn(() => false) }))
vi.mock('@/lib/auditActor', async orig => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  auditActor: async () => ({ actorId: h.person, onBehalfOfUserId: null }),
}))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async (_o: string, action: string) => (h.actingAs ? NextResponse.json({ code: 'not_while_acting_as', action }, { status: 403 }) : null)),
}))
vi.mock('@/lib/tradecraft/actAs', () => ({ loginUseRefusal: vi.fn(async () => h.loginRefusal) }))

import { ReadNowRequest, WEBAPP_TIMEOUTS_MS } from '@/lib/tradecraft/agentContract'
import { loginUseRefusal } from '@/lib/tradecraft/actAs'
import { GET, POST } from './route'

const READ = { text: 'The page as the tool reads it', source: 'live', fetched_at: '2026-11-16T10:00:00Z', truncated: false, error_code: '' }
const P = (pageId: string, resourceId = 'r1') => ({ params: Promise.resolve({ id: 'owner', resourceId, pageId }) })
const url = (resourceId: string, pageId: string) => `http://webapp.test/api/users/owner/tradecraft-resources/${resourceId}/pages/${encodeURIComponent(pageId)}`
const get = (pageId: string, resourceId = 'r1') => GET(new NextRequest(url(resourceId, pageId)), P(pageId, resourceId))
const post = (pageId: string, body: unknown = {}, resourceId = 'r1') => POST(new NextRequest(url(resourceId, pageId), {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), P(pageId, resourceId))
async function answer(res: Response) {
  return { status: res.status, body: await res.json() }
}
const readAgent = () => stubAgent(path => (path === '/tradecraft/v2/read-now' ? json(READ) : json({}, 404)))

beforeEach(() => {
  h.db = createTradecraftDb()
  h.denied = null
  h.person = 'owner'
  h.actingAs = false
  h.loginRefusal = null
  h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
  h.db.seed('userSettings', { userId: 'owner', githubAccessToken: '' })
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', generation: 2, storageMode: 'stored',
    credentials: { cookie: 'session=fake-session' }, hasLogin: true, settingsSnapshot: { values: { 'fetching.userAgent': 'Probe/1.0', 'crawl.maxPages': 9 } },
  })
  h.db.seed('userTradecraftResource', { id: 'theirs', userId: 'other', name: 'X', slug: 'x', url: 'https://x.example.test/', generation: 1 })
  h.db.seed('tradecraftEntry', {
    id: 1n, userId: 'owner', resourceId: 'r1', generation: 2, pageId: 412, url: 'https://wiki.example.test/sqli', title: 'SQLi',
    storedText: '# SQLi\n<script>alert(1)</script> union select', fetchedAt: new Date('2026-11-15T08:00:00Z'),
  })
  h.db.seed('tradecraftEntry', { id: 2n, userId: 'owner', resourceId: 'r1', generation: 2, pageId: 413, url: 'https://wiki.example.test/live', title: 'Live page' })
  h.db.seed('tradecraftEntry', { id: 3n, userId: 'owner', resourceId: 'r1', generation: 1, pageId: 414, url: 'https://wiki.example.test/old', title: 'Old', storedText: 'old' })
  h.db.seed('tradecraftEntry', { id: 4n, userId: 'other', resourceId: 'theirs', generation: 1, pageId: 500, url: 'https://x.example.test/a', storedText: 'theirs' })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

describe('View page', () => {
  test('pages_plain_text: the stored text as it is, with its date; the browser shows it as plain text', async () => {
    const r = await answer(await get('wiki:412'))
    expect(r).toEqual({ status: 200, body: {
      pageId: 'wiki:412', url: 'https://wiki.example.test/sqli', title: 'SQLi', blocked: false, stored: true,
      text: '# SQLi\n<script>alert(1)</script> union select', fetchedAt: '2026-11-15T08:00:00.000Z', storageMode: 'stored',
    } })
  })

  test('not stored: a page with no text; a blocked page shows none', async () => {
    expect((await answer(await get('wiki:413'))).body).toMatchObject({ stored: false, text: '', fetchedAt: null })
    h.db.seed('tradecraftCuration', { resourceId: 'r1', url: 'https://wiki.example.test/sqli', blocked: true })
    expect((await answer(await get('wiki:412'))).body).toMatchObject({ blocked: true, stored: false, text: '' })
  })

  test("owner_only: another account's resource, another resource's slug, an older generation, a bad ID: 404", async () => {
    expect((await get('x:500', 'theirs')).status).toBe(404)
    expect((await get('x:412')).status).toBe(404)
    expect((await get('wiki:414')).status).toBe(404)
    expect((await get('wiki:500')).status).toBe(404)
    for (const id of ['412', 'wiki:', 'wiki:0', 'wiki:-1', 'Wiki:412', 'wiki:412:1']) expect((await get(id)).status, id).toBe(404)
  })

  test('act_as_login_refused (R-161): the login rule is asked first and its refusal answered, nothing read', async () => {
    h.loginRefusal = NextResponse.json({ code: 'not_while_acting_as', action: 'use_site_logins' }, { status: 403 })
    h.db.calls.length = 0
    expect((await get('wiki:412')).status).toBe(403)
    expect((await post('wiki:412')).status).toBe(403)
    expect(vi.mocked(loginUseRefusal)).toHaveBeenCalledWith({ ownerId: 'owner', resourceId: 'r1' })
    expect(h.db.calls.filter(c => c.startsWith('tradecraftEntry'))).toEqual([])
  })
})

describe('Read now', () => {
  test('read_now_url_from_entry: the entry\'s URL and the row\'s secrets; a body naming another URL or a "set" login is ignored', async () => {
    const agent = readAgent()
    const timeout = vi.spyOn(AbortSignal, 'timeout')
    const r = await answer(await post('wiki:412', { url: 'https://evil.example.test/', secrets: { credentials: { cookie: 'set' } } }))
    expect(r).toEqual({ status: 200, body: { result: READ } })
    const sent = ReadNowRequest.parse(agent.calls[0].body)
    expect(sent).toMatchObject({ user_id: 'owner', resource_id: 'r1', url: 'https://wiki.example.test/sqli' })
    expect(sent.secrets.credentials).toEqual({ cookie: 'session=fake-session', headers: [], basic_auth: null })
    expect(sent.read_settings).toEqual({ 'fetching.userAgent': 'Probe/1.0' })
    expect(JSON.stringify(agent.calls[0].body)).not.toMatch(/evil|"set"/)
    expect(timeout).toHaveBeenCalledWith(WEBAPP_TIMEOUTS_MS.readNow)
    expect(h.db.calls.filter(c => !/\.(findFirst|findUnique|findMany|count)$/.test(c))).toEqual([])
  })

  test('a blocked page is refused; the GitHub token is refused while acting as the account', async () => {
    const agent = readAgent()
    h.db.seed('tradecraftCuration', { resourceId: 'r1', url: 'https://wiki.example.test/sqli', blocked: true })
    expect(await answer(await post('wiki:412'))).toMatchObject({ status: 409, body: { code: 'page_blocked' } })
    h.db.rows('userSettings')[0].githubAccessToken = 'ghp_fake_account'
    h.actingAs = true
    expect(await answer(await post('wiki:413'))).toMatchObject({ status: 403, body: { action: 'use_github_token' } })
    expect(agent.calls).toEqual([])
  })

  test('the agent late, down, failing or answering nonsense: fixed errors', async () => {
    stubAgent(() => timedOut())
    expect(await answer(await post('wiki:412'))).toMatchObject({ status: 504, body: { code: 'timeout' } })
    stubAgent(() => refused())
    expect(await answer(await post('wiki:412'))).toMatchObject({ status: 503, body: { code: 'agent_unreachable' } })
    stubAgent(() => json({ detail: 'Not Implemented' }, 501))
    expect(await answer(await post('wiki:412'))).toMatchObject({ status: 502, body: { code: 'agent_error', upstreamStatus: 501 } })
    stubAgent(() => json({ text: 7 }))
    expect(await answer(await post('wiki:412'))).toMatchObject({ status: 502, body: { code: 'internal_error' } })
  })

  test('the guards: a person, 2.0 on', async () => {
    const agent = readAgent()
    h.person = null
    expect((await post('wiki:412')).status).toBe(401)
    h.person = 'owner'
    h.db.rows('tradecraftUserSettings')[0].v2Enabled = false
    expect(await answer(await post('wiki:412'))).toMatchObject({ status: 404, body: { code: 'tradecraft_v2_off' } })
    expect(agent.calls).toEqual([])
  })
})
