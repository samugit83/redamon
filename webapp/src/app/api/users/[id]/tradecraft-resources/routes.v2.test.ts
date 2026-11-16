/**
 * Every tradecraft resource route in both states of the account's Tradecraft 2.0 switch: the
 * switch read from its real row, Prisma the in-memory double, the agent a `fetch` double.
 *  - switch off: today's behaviour, except that Refresh and Verify answers are masked (U1, R-152),
 *    a login in a URL is refused, and no answer, browser or internal, carries a 2.0 column (D-44);
 *  - switch on: the 2.0 modules, whose writes start background jobs answered at once (R-097).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { json, stubAgent } from '@/lib/tradecraft/__testing__/agentDouble'

const h = vi.hoisted(() => ({
  db: null as unknown as TradecraftDb,
  internal: false,
  denied: null as Response | null,
  actor: { actorId: 'owner', onBehalfOfUserId: null as string | null, actorEmail: null },
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: vi.fn(async () => h.denied),
  isInternalRequest: vi.fn(() => h.internal),
}))
vi.mock('@/lib/auditActor', () => ({ auditActor: vi.fn(async () => h.actor) }))

import { setNowForTests } from '@/lib/authz/clock'
import { LEGACY_RESOURCE_COLUMNS } from '@/lib/tradecraft/agentContract'
import { USERINFO_REFUSED } from '@/lib/tradecraft/urls'
import * as list from './route'
import * as one from './[resourceId]/route'
import * as refreshRoute from './[resourceId]/refresh/route'
import * as verifyRoute from './[resourceId]/verify/route'

const BASE = 'http://webapp.test/api/users/owner/tradecraft-resources'
const P = { params: Promise.resolve({ id: 'owner' }) }
const PR = { params: Promise.resolve({ id: 'owner', resourceId: 'r1' }) }
const TOKEN = 'ghp_TRADECRAFT_fake_7777'
const LOGIN = 'session=fake-session-cookie'

function req(path: string, method = 'GET', body?: unknown): NextRequest {
  return new NextRequest(`${BASE}${path}`, {
    method,
    ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  })
}
const setSwitch = (on: boolean) => h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: on })
const row = () => h.db.rows('userTradecraftResource', { id: 'r1' })[0]
const legacyVerifyAnswer = { summary: 's', resource_type: 'mkdocs-wiki', sitemap: { nav: [] }, crawl_stopped_because: '', crawl_stats: {}, last_error: '' }
const agent1x = (path: string, body: unknown) => (path === '/tradecraft/verify' ? json(legacyVerifyAnswer) : json({ accepted: (body as { jobs?: { job_id: string }[] })?.jobs?.map(j => j.job_id) ?? [], refused: [] }, 202))

beforeEach(() => {
  h.db = createTradecraftDb()
  h.internal = false
  h.denied = null
  h.actor = { actorId: 'owner', onBehalfOfUserId: null, actorEmail: null }
  setNowForTests(() => new Date('2026-11-16T10:00:00Z'))
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o',
    githubTokenOverride: TOKEN, credentials: { cookie: LOGIN }, hasLogin: true, overrides: { 'crawl.maxPages': 50 },
    settingsSnapshot: { values: { 'crawl.maxPages': 50 }, provenance: { 'crawl.maxPages': 'resource' } }, settingsHash: 'abcdef0123456789',
    storageMode: 'stored', ingestionReport: { visited: 3 }, mapVersion: 3, generation: 1,
  })
  // T7.1: an add needs the librarian model while the librarian is in use; this account has one.
  h.db.seed('userSettings', { userId: 'owner', featureModels: { tradecraft_librarian: 'gpt-4o-mini' } })
  h.db.seed('userTradecraftResource', {
    id: 'r2', userId: 'owner', name: 'Blog', slug: 'blog', url: 'https://blog.example.test/', llmModel: 'gpt-4o',
    githubTokenOverride: 'ghp_BLOG_fake_8888', createdAt: new Date('2026-11-16T11:00:00Z'),
  })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { setNowForTests(null); vi.restoreAllMocks() })

/** Every answer of the 1.x routes, with the switch off. */
async function legacyAnswers(): Promise<[string, unknown][]> {
  stubAgent(agent1x)
  const out: [string, unknown][] = []
  out.push(['GET list (browser)', await (await list.GET(req(''), P)).json()])
  h.internal = true
  out.push(['GET list (internal)', await (await list.GET(req('?internal=true'), P)).json()])
  out.push(['GET one (internal)', await (await one.GET(req('/r1'), PR)).json()])
  h.internal = false
  out.push(['GET one (browser)', await (await one.GET(req('/r1'), PR)).json()])
  out.push(['PUT', await (await one.PUT(req('/r1', 'PUT', { name: 'Wiki 2' }), PR)).json()])
  out.push(['refresh', await (await refreshRoute.POST(req('/r1/refresh', 'POST'), PR)).json()])
  out.push(['verify', await (await verifyRoute.POST(req('/r1/verify', 'POST', {}), PR)).json()])
  out.push(['POST', await (await list.POST(req('?skipVerify=true', 'POST', { name: 'New', url: 'https://new.example.test/', llmModel: 'gpt-4o' }), P)).json()])
  return out
}

describe('switch off: the 1.x routes', () => {
  test('switch_off_answers_only_1x_columns: no answer, browser or internal, names a 2.0 column (D-44)', async () => {
    setSwitch(false)
    const allowed = new Set<string>(LEGACY_RESOURCE_COLUMNS)
    for (const [name, answer] of await legacyAnswers()) {
      const rows = (Array.isArray(answer) ? answer : [answer]) as Record<string, unknown>[]
      expect(rows.length, name).toBeGreaterThan(0)
      for (const r of rows) expect(Object.keys(r).filter(k => !allowed.has(k)), name).toEqual([])
      expect(JSON.stringify(answer), name).not.toMatch(/fake-session|abcdef0123456789|"crawl\.maxPages"/)
    }
  })

  test('an account without a switch row is off', async () => {
    stubAgent(agent1x)
    const answer = await (await list.GET(req(''), P)).json()
    expect(answer[0]).toHaveProperty('sitemap')
    expect(answer[0]).not.toHaveProperty('entryCount')
  })

  test.each([
    ['refresh', () => refreshRoute.POST(req('/r1/refresh', 'POST'), PR)],
    ['verify', () => verifyRoute.POST(req('/r1/verify', 'POST', {}), PR)],
  ])('refresh_answer_masked_switch_off (%s): the GitHub token is masked as the other answers mask it (U1, R-152)', async (_name, call) => {
    setSwitch(false)
    const agent = stubAgent(agent1x)
    const res = await call()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.githubTokenOverride).toBe('••••••••7777')
    expect(JSON.stringify(body)).not.toContain(TOKEN)
    expect(agent.calls[0].body).toMatchObject({ github_token: TOKEN })
  })

  test('switch_off_unchanged: Refresh still calls the 1.x verify and waits for it', async () => {
    setSwitch(false)
    const agent = stubAgent(agent1x)
    await refreshRoute.POST(req('/r1/refresh', 'POST'), PR)
    expect(agent.calls.map(c => c.path)).toEqual(['/tradecraft/verify'])
    expect(row().summary).toBe('s')
    expect(h.db.rows('tradecraftIngestionJob')).toHaveLength(0)
  })

  test('userinfo_refused (switch off): on add, and on an edit of the URL', async () => {
    setSwitch(false)
    const add = await list.POST(req('?skipVerify=true', 'POST', { name: 'X', url: 'https://u:p@x.example.test/', llmModel: 'gpt-4o' }), P)
    expect(add.status).toBe(400)
    expect(await add.json()).toEqual({ error: USERINFO_REFUSED, code: 'userinfo_refused' })
    const edit = await one.PUT(req('/r1', 'PUT', { url: 'https://u:p@wiki.example.test/' }), PR)
    expect(edit.status).toBe(400)
    expect(row().url).toBe('https://wiki.example.test/')
  })
})

describe("the agent's 1.x list names no person: a resource with a login stays out (R-155)", () => {
  test.each([false, true])('switch %s', async (on) => {
    setSwitch(on)
    h.internal = true
    const internal = await (await list.GET(req('?internal=true'), P)).json()
    expect(internal.map((r: { id: string }) => r.id)).toEqual(['r2'])
    expect(JSON.stringify(internal)).not.toMatch(/fake-session|7777/)
    h.internal = false
    if (!on) expect((await (await list.GET(req(''), P)).json()).map((r: { id: string }) => r.id)).toEqual(['r1', 'r2'])
  })
})

describe('M1: an account that turned 2.0 off sees a lost 2.0 add as failed, not "verifying" (TD-18)', () => {
  test('the 1.x list ends the lost job and answers the error with a verification time', async () => {
    setSwitch(false)
    Object.assign(row(), { lastVerifiedAt: null, lastError: '', activeJobId: 'j-lost' })
    h.db.seed('tradecraftIngestionJob', { id: 'j-lost', userId: 'owner', resourceId: 'r1', kind: 'add', status: 'running', leaseUntil: new Date('2026-11-16T09:59:00Z') })
    stubAgent(agent1x)
    const listed = (await (await list.GET(req(''), P)).json()) as Record<string, unknown>[]
    const r1 = listed.find(r => r.id === 'r1')!
    expect(r1).toMatchObject({ lastError: 'verify failed (agent_lost)', lastVerifiedAt: '2026-11-16T10:00:00.000Z' })
    expect(h.db.rows('tradecraftIngestionJob', { id: 'j-lost' })[0]).toMatchObject({ status: 'failed', errorCode: 'agent_lost' })
  })
})

describe('switch on: the 2.0 modules', () => {
  beforeEach(() => setSwitch(true))

  test.each([
    ['refresh', () => refreshRoute.POST(req('/r1/refresh', 'POST'), PR)],
    ['verify', () => verifyRoute.POST(req('/r1/verify', 'POST', {}), PR)],
  ])('returns_job_at_once (%s): 202 with the queued job; the agent only queued it', async (_name, call) => {
    const agent = stubAgent(agent1x)
    const res = await call()
    expect(res.status).toBe(202)
    const body = await res.json()
    expect(Object.keys(body)).toEqual(['job'])
    expect(body.job).toMatchObject({ kind: 'refresh', status: 'queued' })
    expect(agent.calls.map(c => c.path)).toEqual(['/tradecraft/v2/jobs'])
    expect(row()).toMatchObject({ activeJobId: body.job.id, lastRefreshedAt: null })
  })

  test('refresh_answer_masked_switch_on: the answer is the job, no secret of the resource', async () => {
    stubAgent(agent1x)
    const text = await (await refreshRoute.POST(req('/r1/refresh', 'POST'), PR)).text()
    expect(text).not.toMatch(/ghp_|fake-session|7777/)
  })

  test('the browser gets the 2.0 list; the agent\'s internal 1.x fetch still gets the 1.x rows, 1.x columns only', async () => {
    stubAgent(agent1x)
    const browser = await (await list.GET(req(''), P)).json()
    expect(browser[0]).toMatchObject({ id: 'r1', githubTokenOverride: 'set', hasLogin: true, mapVersion: 3, stale: true })
    expect(browser[0]).not.toHaveProperty('sitemap')
    h.internal = true
    const internal = await (await list.GET(req('?internal=true'), P)).json()
    expect(internal.map((r: { id: string }) => r.id)).toEqual(['r2'])
    expect(Object.keys(internal[0]).sort()).toEqual([...LEGACY_RESOURCE_COLUMNS].sort())
    expect(internal[0].githubTokenOverride).toBe('ghp_BLOG_fake_8888')
  })

  test('GET one: the 2.0 view; 404 for a resource of another account', async () => {
    h.db.seed('userTradecraftResource', { id: 'r-x', userId: 'other', name: 'X', slug: 'x', url: 'https://x.example.test/' })
    expect(await (await one.GET(req('/r1'), PR)).json()).toMatchObject({ id: 'r1', storageMode: 'stored' })
    expect((await one.GET(req('/r-x'), { params: Promise.resolve({ id: 'owner', resourceId: 'r-x' }) })).status).toBe(404)
  })

  test('POST adds and starts the add job; PUT with a new URL re-ingests; DELETE removes', async () => {
    const agent = stubAgent(agent1x)
    const added = await list.POST(req('', 'POST', { name: 'Docs', url: 'https://docs.example.test/', llmModel: 'gpt-4o' }), P)
    expect(added.status).toBe(201)
    const { resource } = await added.json()
    const edited = await one.PUT(req('/r1', 'PUT', { url: 'https://wiki2.example.test/' }), PR)
    expect(edited.status).toBe(200)
    expect((await edited.json()).job.kind).toBe('reingest')
    expect(agent.calls.filter(c => c.path === '/tradecraft/v2/jobs')).toHaveLength(2)
    const removed = await one.DELETE(req(`/${resource.id}`, 'DELETE'), { params: Promise.resolve({ id: 'owner', resourceId: resource.id }) })
    expect(removed.status).toBe(200)
    expect(h.db.rows('userTradecraftResource', { id: resource.id })).toHaveLength(0)
  })

  test('userinfo_refused (switch on)', async () => {
    const res = await list.POST(req('', 'POST', { name: 'X', url: 'https://u:p@x.example.test/', llmModel: 'gpt-4o' }), P)
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ field: 'url', code: 'userinfo_refused', error: USERINFO_REFUSED })
  })

  test.each([
    ['POST', () => list.POST(req('', 'POST', { name: 'X', url: 'https://x.example.test/', llmModel: 'gpt-4o' }), P)],
    ['PUT', () => one.PUT(req('/r1', 'PUT', { url: 'https://wiki2.example.test/' }), PR)],
    ['refresh', () => refreshRoute.POST(req('/r1/refresh', 'POST'), PR)],
    ['verify', () => verifyRoute.POST(req('/r1/verify', 'POST', {}), PR)],
  ])('%s: a job names a person, so the internal key alone writes nothing (401)', async (_name, call) => {
    h.internal = true
    h.actor = { actorId: null as unknown as string, onBehalfOfUserId: null, actorEmail: null }
    const agent = stubAgent(agent1x)
    expect((await call()).status).toBe(401)
    expect(h.db.rows('tradecraftIngestionJob')).toHaveLength(0)
    expect(row().url).toBe('https://wiki.example.test/')
    expect(agent.calls).toHaveLength(0)
  })

  test('the act-as person is recorded on the job, the acting administrator beside them', async () => {
    h.actor = { actorId: 'admin-1', onBehalfOfUserId: 'owner', actorEmail: null }
    stubAgent(agent1x)
    await refreshRoute.POST(req('/r1/refresh', 'POST'), PR)
    expect(h.db.rows('tradecraftIngestionJob')[0]).toMatchObject({ actorUserId: 'owner', realActorUserId: 'admin-1' })
  })
})

describe('both states: the guards run first', () => {
  test.each([true, false])('a refused account rule stops every route before any read (switch %s)', async (on) => {
    setSwitch(on)
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    const agent = stubAgent(agent1x)
    const before = h.db.calls.length
    for (const res of [
      await list.GET(req(''), P), await list.POST(req('', 'POST', {}), P),
      await one.GET(req('/r1'), PR), await one.PUT(req('/r1', 'PUT', {}), PR), await one.DELETE(req('/r1', 'DELETE'), PR),
      await refreshRoute.POST(req('/r1/refresh', 'POST'), PR), await verifyRoute.POST(req('/r1/verify', 'POST', {}), PR),
    ]) expect(res.status).toBe(403)
    expect(h.db.calls.slice(before)).toEqual([])
    expect(agent.calls).toHaveLength(0)
  })
})
