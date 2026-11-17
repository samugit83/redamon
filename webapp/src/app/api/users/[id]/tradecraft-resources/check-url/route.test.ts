/**
 * POST /api/users/[id]/tradecraft-resources/check-url (§6.3, T4.5): the agent's Check URL behind
 * the account's guards. Nothing is written (AC-09); a saved resource's URL and secrets come from
 * its row, never from the body or a "set" placeholder (D-54); the agent's deadline plus a margin,
 * and a fixed error when it passes (D-52).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { json, refused, stubAgent, timedOut } from '@/lib/tradecraft/__testing__/agentDouble'

const h = vi.hoisted(() => ({
  db: null as unknown as TradecraftDb, denied: null as Response | null, person: 'owner' as string | null,
  actingAs: false, loginRefusal: null as Response | null, order: [] as string[],
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => ({ requireSelfPermission: vi.fn(async () => null) }))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => h.denied), isInternalRequest: vi.fn(() => false) }))
vi.mock('@/lib/auditActor', async orig => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  auditActor: async () => ({ actorId: h.person, onBehalfOfUserId: null }),
}))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async () => (h.actingAs ? NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 }) : null)),
}))
vi.mock('@/lib/tradecraft/actAs', () => ({
  loginUseRefusal: vi.fn(async () => { h.order.push('loginUseRefusal'); return h.loginRefusal }),
}))

import { CheckUrlRequest, WEBAPP_TIMEOUTS_MS } from '@/lib/tradecraft/agentContract'
import { loginUseRefusal } from '@/lib/tradecraft/actAs'
import { POST } from './route'

const RESULT = {
  ok: true, error_code: '', final_url: 'https://wiki.tc-fixture.test/', detected_type: 'mkdocs-wiki', needs_browser: false,
  robots_allows: true, index: { kind: 'sitemap', url: 'https://wiki.tc-fixture.test/sitemap.xml', count: 412 }, sample_entries: [],
  github: null, pdf_pages: null, recommended_storage: 'stored', estimated_bytes: 6_000_000, cve_pattern: null,
}
const checkUrlAgent = (result: unknown = RESULT) => stubAgent((path) => (path === '/tradecraft/v2/check-url' ? json(result) : json({}, 404)))
const post = (body: unknown) => POST(new NextRequest('http://webapp.test/api/users/owner/tradecraft-resources/check-url', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), { params: Promise.resolve({ id: 'owner' }) })
async function answer(res: Response) {
  return { status: res.status, body: await res.json() }
}
const writes = () => h.db.calls.filter(c => !/\.(findFirst|findUnique|findMany|count)$/.test(c))

beforeEach(() => {
  h.db = createTradecraftDb()
  h.denied = null
  h.person = 'owner'
  h.actingAs = false
  h.loginRefusal = null
  h.order = []
  h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true, ingestion: { 'crawl.maxPages': 90 } })
  h.db.seed('userSettings', { userId: 'owner', githubAccessToken: '' })
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.tc-fixture.test/', githubTokenOverride: 'ghp_stored_fake_0001',
    forcedType: 'github-repo', overrides: { 'type.github.branch': 'dev' },
  })
  h.db.seed('userTradecraftResource', { id: 'r-x', userId: 'other', name: 'X', slug: 'x', url: 'https://x.tc-fixture.test/', githubTokenOverride: 'ghp_other_fake_0002' })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

describe('Check URL', () => {
  test('check_url_saves_nothing: the agent\'s result is answered, and nothing is written', async () => {
    const agent = checkUrlAgent()
    const r = await answer(await post({ url: 'https://wiki.tc-fixture.test/' }))
    expect(r).toEqual({ status: 200, body: { result: RESULT } })
    expect(writes()).toEqual([])
    expect(h.db.raw).toEqual([])
    const sent = CheckUrlRequest.parse(agent.calls[0].body)
    expect(sent).toMatchObject({ user_id: 'owner', url: 'https://wiki.tc-fixture.test/', forced_type: '', secrets: { github_token: null, credentials: null } })
    expect(sent.settings['crawl.maxPages']).toBe(90)
  })

  test('the form\'s type and overrides travel; the type options among them as type_options', async () => {
    const agent = checkUrlAgent()
    await post({ url: 'https://github.com/org/repo', forcedType: 'github-repo', overrides: { 'type.github.branch': 'main', 'crawl.maxPages': 10 } })
    const sent = CheckUrlRequest.parse(agent.calls[0].body)
    expect(sent.forced_type).toBe('github-repo')
    expect(sent.settings).toMatchObject({ 'type.github.branch': 'main', 'crawl.maxPages': 10 })
    expect(sent.type_options['type.github.branch']).toBe('main')
    expect(Object.keys(sent.type_options).every(k => k.startsWith('type.'))).toBe(true)
  })

  test('check_url_stored_secrets_from_row: a saved resource\'s URL and token come from its row, never "set" or the body', async () => {
    const agent = checkUrlAgent()
    await post({ resourceId: 'r1', url: 'https://evil.tc-fixture.test/', githubTokenOverride: 'set' })
    const sent = CheckUrlRequest.parse(agent.calls[0].body)
    expect(sent.url).toBe('https://wiki.tc-fixture.test/')
    expect(sent.secrets.github_token).toBe('ghp_stored_fake_0001')
    expect(sent.forced_type).toBe('github-repo')
    expect(sent.settings['type.github.branch']).toBe('dev')
    expect(JSON.stringify(agent.calls[0].body)).not.toMatch(/"set"|evil/)
  })

  test('a token typed in the form now wins over the stored one; the account token is the last resort', async () => {
    const agent = checkUrlAgent()
    await post({ resourceId: 'r1', githubTokenOverride: 'ghp_typed_now_0003' })
    expect(CheckUrlRequest.parse(agent.calls[0].body).secrets.github_token).toBe('ghp_typed_now_0003')
    h.db.rows('userSettings')[0].githubAccessToken = 'ghp_account_fake_0004'
    await post({ url: 'https://github.com/org/repo', githubTokenOverride: '••••••••0001' })
    expect(CheckUrlRequest.parse(agent.calls[1].body).secrets.github_token).toBe('ghp_account_fake_0004')
  })

  test("another account's resource id: 404, the agent never called", async () => {
    const agent = checkUrlAgent()
    expect((await post({ resourceId: 'r-x' })).status).toBe(404)
    expect(agent.calls).toEqual([])
  })

  test('the login refusal is asked first for a saved resource, before its row is read', async () => {
    const agent = checkUrlAgent()
    h.loginRefusal = NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 })
    h.db.calls.length = 0
    expect((await post({ resourceId: 'r1' })).status).toBe(403)
    expect(vi.mocked(loginUseRefusal)).toHaveBeenCalledWith({ ownerId: 'owner', resourceId: 'r1' })
    expect(h.db.calls.filter(c => c.startsWith('userTradecraftResource'))).toEqual([])
    expect(agent.calls).toEqual([])
  })

  test('act-as: a token would be sent, so it is refused; without one the check runs', async () => {
    h.actingAs = true
    const agent = checkUrlAgent()
    expect((await post({ resourceId: 'r1' })).status).toBe(403)
    expect(agent.calls).toEqual([])
    expect((await post({ url: 'https://wiki.tc-fixture.test/' })).status).toBe(200)
  })

  test('check_url_timeout_fixed_error: past the deadline, a fixed 504; the agent waited its deadline plus the margin', async () => {
    stubAgent(() => timedOut())
    const r = await answer(await post({ url: 'https://slow.tc-fixture.test/' }))
    expect(r).toEqual({ status: 504, body: { code: 'timeout', error: 'The check took too long: the site may be slow or unreachable' } })
    expect(WEBAPP_TIMEOUTS_MS.checkUrl).toBe(75_000)
  })

  test('the agent down, an error answer, a malformed answer: fixed errors, no agent text', async () => {
    stubAgent(() => refused())
    expect(await answer(await post({ url: 'https://wiki.tc-fixture.test/' }))).toMatchObject({ status: 503, body: { code: 'agent_unreachable' } })
    stubAgent(() => json({ detail: 'secret detail at 10.0.0.5' }, 500))
    const e = await answer(await post({ url: 'https://wiki.tc-fixture.test/' }))
    expect(e).toEqual({ status: 502, body: { code: 'agent_error', error: 'Check URL failed', upstreamStatus: 500 } })
    stubAgent(() => json({ ok: 'yes' }))
    expect(await answer(await post({ url: 'https://wiki.tc-fixture.test/' }))).toMatchObject({ status: 502, body: { code: 'internal_error' } })
  })

  test('the URL is checked as an edit checks it: a private address and a login in the URL never reach the agent', async () => {
    const agent = checkUrlAgent()
    expect(await answer(await post({ url: 'http://127.0.0.1/' }))).toMatchObject({ status: 400, body: { field: 'url', code: 'bad_url' } })
    expect(await answer(await post({ url: 'https://u:p@wiki.tc-fixture.test/' }))).toMatchObject({ status: 400, body: { code: 'userinfo_refused' } })
    expect(await answer(await post({}))).toMatchObject({ status: 400, body: { field: 'url' } })
    expect(await answer(await post({ url: 'https://wiki.tc-fixture.test/', overrides: { 'storage.userQuotaMb': 1 } }))).toMatchObject({ status: 400, body: { code: 'user_only' } })
    expect(agent.calls).toEqual([])
  })

  test('guards: the account rule, self:tradecraft, a person', async () => {
    const agent = checkUrlAgent()
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await post({ url: 'https://wiki.tc-fixture.test/' })).status).toBe(403)
    h.denied = null
    h.person = null
    expect((await post({ url: 'https://wiki.tc-fixture.test/' })).status).toBe(401)
    h.person = 'owner'
    expect(agent.calls).toEqual([])
  })

  describe('a site login (§6.6, T6.5)', () => {
    test('a login typed for a URL being added travels to the agent, after the login rule was asked with it', async () => {
      const agent = checkUrlAgent()
      const login = { cookie: 'session=fake-typed', headers: [{ name: 'X-Api-Key', value: 'fake-key-1' }] }
      const r = await answer(await post({ url: 'https://kb.tc-fixture.test/', credentials: login }))
      expect(r.status).toBe(200)
      expect(vi.mocked(loginUseRefusal)).toHaveBeenCalledWith({ ownerId: 'owner', credentials: { ...login, basic_auth: null } })
      expect(CheckUrlRequest.parse(agent.calls[0].body).secrets.credentials).toEqual({ ...login, basic_auth: null })
      expect(JSON.stringify(r.body)).not.toMatch(/fake-/)
    })

    test('use_refused: the login rule refuses a typed login (acting as the account): the agent never called', async () => {
      const agent = checkUrlAgent()
      h.loginRefusal = NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 })
      expect((await post({ url: 'https://kb.tc-fixture.test/', credentials: { cookie: 'session=fake-typed' } })).status).toBe(403)
      expect(agent.calls).toEqual([])
    })

    test('a saved resource: "set" keeps the stored value, a typed header joins it; never the placeholder', async () => {
      Object.assign(h.db.rows('userTradecraftResource', { id: 'r1' })[0], { credentials: { cookie: 'session=fake-stored' }, hasLogin: true })
      const agent = checkUrlAgent()
      await post({ resourceId: 'r1', credentials: { cookie: 'set', headers: [{ name: 'X-Team', value: 'fake-team' }] } })
      expect(CheckUrlRequest.parse(agent.calls[0].body).secrets.credentials).toEqual({
        cookie: 'session=fake-stored', headers: [{ name: 'X-Team', value: 'fake-team' }], basic_auth: null,
      })
      await post({ resourceId: 'r1' })
      expect(CheckUrlRequest.parse(agent.calls[1].body).secrets.credentials).toEqual({ cookie: 'session=fake-stored', headers: [], basic_auth: null })
      await post({ resourceId: 'r1', credentials: null })
      expect(CheckUrlRequest.parse(agent.calls[2].body).secrets.credentials).toBeNull()
      expect(JSON.stringify(agent.calls.map(c => c.body))).not.toMatch(/"set"/)
      expect(writes()).toEqual([])
    })

    test('a login the rules refuse is a 400 naming its field; the agent never called', async () => {
      const agent = checkUrlAgent()
      const r = await answer(await post({ url: 'https://kb.tc-fixture.test/', credentials: { cookie: 'a=1\r\nX-Evil: 1' } }))
      expect(r).toMatchObject({ status: 400, body: { field: 'credentials.cookie', code: 'bad_credentials' } })
      expect(agent.calls).toEqual([])
    })
  })
})
