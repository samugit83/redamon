/**
 * Every tradecraft resource route, on the 2.0 modules only since the cut-over (T9.3: the switch,
 * the 1.x paths and the agent's unmasked internal list are gone): Prisma the in-memory double, the
 * agent a `fetch` double. Writes start background jobs answered at once (R-097).
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
const row = () => h.db.rows('userTradecraftResource', { id: 'r1' })[0]
// The agent queues every job it is sent.
const agent1x = (_path: string, body: unknown) => json({ accepted: (body as { jobs?: { job_id: string }[] })?.jobs?.map(j => j.job_id) ?? [], refused: [] }, 202)

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

describe('the 2.0 modules', () => {
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

  test('every caller gets the masked 2.0 list: the internal key and ?internal=true no longer unmask (T9.3)', async () => {
    stubAgent(agent1x)
    const browser = await (await list.GET(req(''), P)).json()
    expect(browser[0]).toMatchObject({ id: 'r1', githubTokenOverride: 'set', hasLogin: true, mapVersion: 3, stale: true })
    expect(browser[0]).not.toHaveProperty('sitemap')
    h.internal = true
    const internal = await (await list.GET(req('?internal=true'), P)).json()
    expect(internal).toEqual(browser)
    expect(JSON.stringify(internal)).not.toMatch(/ghp_|fake-session|7777|8888/)
    const one1 = await (await one.GET(req('/r1'), PR)).json()
    expect(JSON.stringify(one1)).not.toMatch(/ghp_|fake-session|7777/)
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

  test('userinfo_refused', async () => {
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

describe('the guards run first', () => {
  test('a refused account rule stops every route before any read', async () => {
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
