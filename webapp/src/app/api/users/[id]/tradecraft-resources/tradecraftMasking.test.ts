/**
 * No answer of a Tradecraft route carries a secret value (§6.6, R-152, D-44, T6.5): a resource
 * holding a GitHub token and every kind of site login (a cookie, a header, basic authentication),
 * and an account GitHub token, then every handler of every route under `tradecraft-resources/`,
 * `tradecraft-settings/` and `projects/[id]/tradecraft`, in both states of the account's 2.0
 * switch (the 1.x branches answer from the same row). The route list comes from the generated
 * route manifest, so a new route fails here until it is called below. The internal catalog is the
 * one answer allowed to carry the values, to the agent's key only: its tests are T1.12's.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { json, stubAgent } from '@/lib/tradecraft/__testing__/agentDouble'
import manifest from '@/lib/authz/routeManifest.json'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => null), isInternalRequest: vi.fn(() => false) }))
vi.mock('@/lib/auditActor', async orig => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  auditActor: vi.fn(async () => ({ actorId: 'owner', onBehalfOfUserId: null, actorEmail: null })),
}))
vi.mock('@/lib/authz/actAsRefusals', () => ({ refuseWhileActingAsOn: vi.fn(async () => null), actingAsOn: vi.fn(async () => false) }))
vi.mock('@/lib/authz/guards', () => ({
  requirePermission: vi.fn(async () => ({
    principal: { id: 'owner' }, actingAs: null, effective: { userId: 'owner' },
    access: { project: { id: 'proj-1', userId: 'owner' }, level: 'owner', via: 'owner', toggles: {} },
  })),
}))

import { setNowForTests } from '@/lib/authz/clock'
import * as list from './route'
import * as one from './[resourceId]/route'
import * as enabledImpact from './[resourceId]/enabled-impact/route'
import * as jobs from './[resourceId]/jobs/route'
import * as mapRoute from './[resourceId]/map/route'
import * as pages from './[resourceId]/pages/[pageId]/route'
import * as refreshRoute from './[resourceId]/refresh/route'
import * as summary from './[resourceId]/summary/route'
import * as regenerate from './[resourceId]/summary/regenerate/route'
import * as verify from './[resourceId]/verify/route'
import * as checkUrl from './check-url/route'
import * as focusPreview from './focus-preview/route'
import * as refreshAll from './refresh-all/route'
import * as settings from '../tradecraft-settings/route'
import * as projectTradecraft from '@/app/api/projects/[id]/tradecraft/route'

const TOKEN = 'ghp_RESOURCE_fake_7777'
const ACCOUNT_TOKEN = 'ghp_ACCOUNT_fake_6666'
const COOKIE = 'session=fake-cookie-value-1'
const HEADER = 'fake-header-value-2'
const PASSWORD = 'fake-password-value-3'
const NEW_TOKEN = 'ghp_NEW_fake_5555'
const NEW_COOKIE = 'session=fake-new-cookie-4'
const SECRETS = [TOKEN, ACCOUNT_TOKEN, COOKIE, HEADER, PASSWORD, NEW_TOKEN, NEW_COOKIE, 'fake-', 'ghp_']

const LOGIN = { cookie: COOKIE, headers: [{ name: 'X-Api-Key', value: HEADER }], basic_auth: { username: 'bob', password: PASSWORD } }
const BASE = 'http://webapp.test/api/users/owner'
const P = { params: Promise.resolve({ id: 'owner' }) }
const PR = { params: Promise.resolve({ id: 'owner', resourceId: 'r1' }) }
const PAGE = { params: Promise.resolve({ id: 'owner', resourceId: 'r1', pageId: 'wiki:1' }) }

function req(path: string, method = 'GET', body?: unknown): NextRequest {
  return new NextRequest(`${BASE}${path}`, {
    method,
    ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  })
}

/** Every handler, by its manifest path and method. DELETE of the resource runs last. */
const CALLS: Record<string, () => Promise<Response>> = {
  'GET /api/users/[id]/tradecraft-resources': () => list.GET(req('/tradecraft-resources'), P),
  'POST /api/users/[id]/tradecraft-resources': () => list.POST(req('/tradecraft-resources?skipVerify=true', 'POST', {
    name: 'New', url: 'https://new.example.test/', llmModel: 'gpt-4o', githubTokenOverride: NEW_TOKEN, credentials: { cookie: NEW_COOKIE },
  }), P),
  'GET /api/users/[id]/tradecraft-resources/[resourceId]': () => one.GET(req('/tradecraft-resources/r1'), PR),
  'PUT /api/users/[id]/tradecraft-resources/[resourceId]': () => one.PUT(req('/tradecraft-resources/r1', 'PUT', {
    name: 'Wiki 2', githubTokenOverride: '••••••••7777', credentials: { cookie: 'set', headers: [{ name: 'X-Api-Key', value: 'set' }] },
  }), PR),
  'GET /api/users/[id]/tradecraft-resources/[resourceId]/enabled-impact': () => enabledImpact.GET(req('/tradecraft-resources/r1/enabled-impact?next=false'), PR),
  'GET /api/users/[id]/tradecraft-resources/[resourceId]/jobs': () => jobs.GET(req('/tradecraft-resources/r1/jobs'), PR),
  'DELETE /api/users/[id]/tradecraft-resources/[resourceId]/jobs': () => jobs.DELETE(req('/tradecraft-resources/r1/jobs', 'DELETE'), PR),
  'GET /api/users/[id]/tradecraft-resources/[resourceId]/map': () => mapRoute.GET(req('/tradecraft-resources/r1/map'), PR),
  'POST /api/users/[id]/tradecraft-resources/[resourceId]/map': () => mapRoute.POST(req('/tradecraft-resources/r1/map', 'POST', {
    op: 'pin', url: 'https://wiki.example.test/pinned',
  }), PR),
  'GET /api/users/[id]/tradecraft-resources/[resourceId]/pages/[pageId]': () => pages.GET(req('/tradecraft-resources/r1/pages/wiki%3A1'), PAGE),
  'POST /api/users/[id]/tradecraft-resources/[resourceId]/pages/[pageId]': () => pages.POST(req('/tradecraft-resources/r1/pages/wiki%3A1', 'POST', {}), PAGE),
  'POST /api/users/[id]/tradecraft-resources/[resourceId]/refresh': () => refreshRoute.POST(req('/tradecraft-resources/r1/refresh', 'POST'), PR),
  'PUT /api/users/[id]/tradecraft-resources/[resourceId]/summary': () => summary.PUT(req('/tradecraft-resources/r1/summary', 'PUT', { source: 'manual', text: 'Mine' }), PR),
  'POST /api/users/[id]/tradecraft-resources/[resourceId]/summary/regenerate': () => regenerate.POST(req('/tradecraft-resources/r1/summary/regenerate', 'POST'), PR),
  'POST /api/users/[id]/tradecraft-resources/[resourceId]/verify': () => verify.POST(req('/tradecraft-resources/r1/verify', 'POST', {}), PR),
  'POST /api/users/[id]/tradecraft-resources/check-url': () => checkUrl.POST(req('/tradecraft-resources/check-url', 'POST', { resourceId: 'r1' }), P),
  'POST /api/users/[id]/tradecraft-resources/focus-preview': () => focusPreview.POST(req('/tradecraft-resources/focus-preview', 'POST', {
    resourceId: 'r1', focus: { mode: 'focused', topics: ['xss'] },
  }), P),
  'POST /api/users/[id]/tradecraft-resources/refresh-all': () => refreshAll.POST(req('/tradecraft-resources/refresh-all', 'POST', { resourceIds: ['r1'] }), P),
  'GET /api/users/[id]/tradecraft-settings': () => settings.GET(req('/tradecraft-settings'), P),
  'PUT /api/users/[id]/tradecraft-settings': () => settings.PUT(req('/tradecraft-settings', 'PUT', { ingestion: { 'crawl.maxPages': 90 } }), P),
  'GET /api/projects/[id]/tradecraft': () => projectTradecraft.GET(
    new NextRequest('http://webapp.test/api/projects/proj-1/tradecraft'), { params: Promise.resolve({ id: 'proj-1' }) },
  ),
  'DELETE /api/users/[id]/tradecraft-resources/[resourceId]': () => one.DELETE(req('/tradecraft-resources/r1', 'DELETE'), PR),
}

const PREFIXES = ['/api/users/[id]/tradecraft-resources', '/api/users/[id]/tradecraft-settings', '/api/projects/[id]/tradecraft']
const MANIFEST_CALLS = (manifest as { path: string; methods: string[] }[])
  .filter(e => PREFIXES.some(p => e.path === p || e.path.startsWith(`${p}/`)))
  .flatMap(e => e.methods.map(m => `${m} ${e.path}`))

const agentAnswers = (path: string, body: unknown) => {
  if (path === '/tradecraft/verify') return json({ summary: 's', resource_type: 'mkdocs-wiki', sitemap: { nav: [] }, crawl_stopped_because: '', crawl_stats: {}, last_error: '' })
  if (path === '/tradecraft/v2/check-url') {
    return json({ ok: true, error_code: '', final_url: 'https://wiki.example.test/', detected_type: 'mkdocs-wiki', recommended_storage: 'stored' })
  }
  if (path === '/tradecraft/v2/read-now') return json({ text: 'page text', source: 'live', fetched_at: '', truncated: false, error_code: '' })
  if (path === '/tradecraft/v2/preview-focus') return json({ kept: 1, maybe: 0, dropped: 0, examples: [], llm_calls: 1, error_code: '' })
  if (path === '/tradecraft/v2/jobs') return json({ accepted: (body as { jobs: { job_id: string }[] }).jobs.map(j => j.job_id), refused: [] }, 202)
  if (/\/cancel$/.test(path)) return json({ ok: true })
  return json({ detail: 'Not Found' }, 404)
}

function seed(v2: boolean) {
  h.db = createTradecraftDb()
  h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: v2 })
  h.db.seed('userSettings', { userId: 'owner', githubAccessToken: ACCOUNT_TOKEN, featureModels: { tradecraft_librarian: 'gpt-4o-mini' } })
  h.db.seed('project', { id: 'proj-1', userId: 'owner', attackSkillConfig: { builtIn: {}, user: {} } })
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o', resourceType: 'mkdocs-wiki',
    githubTokenOverride: TOKEN, credentials: LOGIN, hasLogin: true, storageMode: 'stored', mapVersion: 3, generation: 1,
    summary: 'A wiki', settingsHash: 'abcdef0123456789', ingestionReport: { visited: 1, kept: 1 },
  })
  h.db.seed('tradecraftEntry', { id: BigInt(1), userId: 'owner', resourceId: 'r1', generation: 1, pageId: 1, url: 'https://wiki.example.test/a', title: 'A' })
}

beforeEach(() => {
  setNowForTests(() => new Date('2026-11-16T10:00:00Z'))
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => { setNowForTests(null); vi.restoreAllMocks() })

describe('tradecraftMasking (R-152)', () => {
  test('the table calls every handler the route manifest lists under the three prefixes, and no other', () => {
    expect(Object.keys(CALLS).sort()).toEqual([...MANIFEST_CALLS].sort())
  })

  test.each([true, false])('no answer carries a secret value (2.0 on: %s)', async (v2) => {
    seed(v2)
    stubAgent(agentAnswers)
    const answered: string[] = []
    for (const [name, call] of Object.entries(CALLS)) {
      const res = await call()
      const text = await res.text()
      answered.push(`${name} ${res.status}`)
      for (const secret of SECRETS) expect(text, `${name} (${res.status})`).not.toContain(secret)
    }
    // The calls reached their handlers, not a guard: each answered something other than a 401/403.
    expect(answered.filter(a => / 40[13]$/.test(a))).toEqual([])
    // The writes kept the stored secrets: the masked placeholders the PUT sent back changed nothing.
    if (v2) expect(h.db.rows('userTradecraftResource', { slug: 'new' })[0]).toMatchObject({ hasLogin: true, githubTokenOverride: NEW_TOKEN })
  })

  test('2.0 on: the resource answers show the login as names and "set"', async () => {
    seed(true)
    stubAgent(agentAnswers)
    const listed = await (await CALLS['GET /api/users/[id]/tradecraft-resources']()).json()
    expect(listed[0]).toMatchObject({
      githubTokenOverride: 'set', hasLogin: true,
      credentials: { cookie: 'set', headers: [{ name: 'X-Api-Key', value: 'set' }], basic_auth: { username: 'bob', password: 'set' } },
    })
    await CALLS['PUT /api/users/[id]/tradecraft-resources/[resourceId]']()
    expect(h.db.rows('userTradecraftResource', { id: 'r1' })[0]).toMatchObject({ githubTokenOverride: TOKEN, credentials: LOGIN })
  })
})
