/**
 * A resource's site login while an administrator acts as the account (§6.6, T6.5; R-120,
 * R-158-R-160, D-37), through the real routes, session helpers and act-as tokens:
 *  - not changeable: adding, changing or removing a login is refused as `change_site_logins`,
 *    also on a passwordless managed account, whose other writes act-as allows;
 *  - not usable: Add (a login typed with it), Refresh, Save & re-ingest (a new URL), Check URL and
 *    the focus preview are refused as `use_site_logins` on a resource with a login;
 *  - every refusal answers 403 `not_while_acting_as` and writes its `act_as.refused` row;
 *  - with the permissions switch off nothing is refused, and the login stays masked.
 * Accounts and audit rows live in the account double, the tradecraft tables in the tradecraft one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', '7'.repeat(64))

const h = vi.hoisted(() => ({ accounts: null as unknown, tc: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const accounts = createAccountDb()
  h.accounts = accounts
  const TRADECRAFT = new Set([
    'userTradecraftResource', 'tradecraftUserSettings', 'tradecraftIngestionJob', 'tradecraftEntry', 'tradecraftSection',
    'tradecraftCuration', 'tradecraftPageId', 'tradecraftTreeNode', 'tradecraftProjectChoice', 'userAttackSkill', 'userSettings',
    '$queryRaw', '$executeRaw',
  ])
  const tc = () => (h.tc as { prisma: Record<string | symbol, unknown> }).prisma
  const db = new Proxy({}, {
    get: (_t, k) => {
      if (typeof k === 'string' && TRADECRAFT.has(k)) return tc()[k]
      if (k === '$transaction') {
        // A write's audit row goes where the act-as refusals write theirs.
        return async (fn: (tx: unknown) => Promise<unknown>) => (tc().$transaction as (f: (tx: unknown) => Promise<unknown>) => Promise<unknown>)(
          (tx) => fn(new Proxy(tx as object, { get: (t, kk) => (kk === 'auditLog' ? (accounts as Record<string, unknown>).auditLog : (t as Record<string | symbol, unknown>)[kk]) })),
        )
      }
      return (accounts as Record<string | symbol, unknown>)[k]
    },
  })
  return { default: db, prisma: db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { setNowForTests } from '@/lib/authz/clock'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'
import { json, stubAgent } from './__testing__/agentDouble'
import * as list from '@/app/api/users/[id]/tradecraft-resources/route'
import * as one from '@/app/api/users/[id]/tradecraft-resources/[resourceId]/route'
import * as refreshRoute from '@/app/api/users/[id]/tradecraft-resources/[resourceId]/refresh/route'
import * as checkUrl from '@/app/api/users/[id]/tradecraft-resources/check-url/route'
import * as preview from '@/app/api/users/[id]/tradecraft-resources/focus-preview/route'
import * as mapRoute from '@/app/api/users/[id]/tradecraft-resources/[resourceId]/map/route'
import * as pages from '@/app/api/users/[id]/tradecraft-resources/[resourceId]/pages/[pageId]/route'

const accounts = () => h.accounts as AccountDb
const tc = () => h.tc as TradecraftDb
const LOGIN = { cookie: 'session=fake-kb-session', headers: [{ name: 'X-Api-Key', value: 'fake-kb-key' }], basic_auth: null }
const FOCUS = { mode: 'focused', topics: ['sql_injection'] }
const CHECK_RESULT = {
  ok: true, error_code: '', final_url: 'https://kb.example.test/', detected_type: 'agentic-crawl', needs_browser: false, robots_allows: true,
  index: null, sample_entries: [], github: null, pdf_pages: null, recommended_storage: 'live', estimated_bytes: 0, cve_pattern: null,
}
const PREVIEW_RESULT = { kept: 1, maybe: 0, dropped: 0, examples: [], llm_calls: 1, error_code: '' }

function req(path: string, method = 'GET', body?: unknown): NextRequest {
  return new NextRequest(`http://redamon.test/api/users/member-1/tradecraft-resources${path}`, {
    method,
    headers: { host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const P = (id = 'member-1') => ({ params: Promise.resolve({ id }) })
const PR = (resourceId: string, id = 'member-1') => ({ params: Promise.resolve({ id, resourceId }) })

async function as(userId: string, actingAs?: string) {
  h.jar.auth = await createToken(userId, String(accounts().account(userId)!.role), 0)
  if (!actingAs) {
    h.jar.actAs = undefined
    return
  }
  const jti = `start-${userId}-${actingAs}-${accounts().actAs().length + 1}`
  accounts().seedActAs({ id: jti, adminId: userId, targetUserId: actingAs, event: 'start', createdAt: new Date(), durationMinutes: 60 })
  h.jar.actAs = await createActAsToken(userId, actingAs, 3600, { asv: 0, jti })
}

const refusals = () => accounts().audit().filter(r => r.action === 'act_as.refused')
const loginAudits = () => accounts().audit().filter(r => r.action === 'tradecraft.credentials_changed')
const resource = (id: string) => tc().rows('userTradecraftResource', { id })[0]

async function expectRefused(res: Response, action: 'use_site_logins' | 'change_site_logins') {
  expect(res.status).toBe(403)
  expect(await res.json()).toEqual({
    error: expect.stringMatching(/^Not available while acting as Marco: .+ stays with them\./),
    code: 'not_while_acting_as',
    action,
  })
  expect(refusals().at(-1)).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: 'member-1', targetId: 'member-1', after: { action } })
}

const agent = () => stubAgent((path, body) => {
  if (path === '/tradecraft/v2/check-url') return json(CHECK_RESULT)
  if (path === '/tradecraft/v2/preview-focus') return json(PREVIEW_RESULT)
  if (path === '/tradecraft/v2/read-now') return json({ text: 'live text', source: 'live', fetched_at: '', truncated: false, error_code: '' })
  if (path === '/tradecraft/v2/jobs') return json({ accepted: (body as { jobs: { job_id: string }[] }).jobs.map(j => j.job_id), refused: [] }, 202)
  return json({ detail: 'Not Found' }, 404)
})

beforeEach(() => {
  accounts().reset()
  accounts().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-1', role: 'admin', name: 'Laura' },
    // A passwordless managed account: run only through act-as, which step 1.6 lets write its data.
    { id: 'member-1', name: 'Marco', password: '' },
    { id: 'member-2', name: 'Nina' },
  ])
  accounts().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  h.tc = createTradecraftDb()
  for (const userId of ['member-1', 'member-2']) tc().seed('tradecraftUserSettings', { userId, v2Enabled: true })
  tc().seed('userTradecraftResource', {
    id: 'kb', userId: 'member-1', name: 'Company KB', slug: 'kb', url: 'https://kb.example.test/', llmModel: 'gpt-4o', credentials: LOGIN, hasLogin: true, generation: 1,
  })
  tc().seed('userTradecraftResource', { id: 'pub', userId: 'member-1', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o', generation: 1 })
  tc().seed('tradecraftEntry', {
    id: BigInt(1), userId: 'member-1', resourceId: 'kb', generation: 1, pageId: 1, url: 'https://kb.example.test/a', title: 'A',
    topics: ['sql_injection'], kinds: ['payloads'], technologies: ['postgresql'], description: 'Private one-liner', source: 'crawl',
    storedText: 'private text', storedBytes: 12,
  })
  tc().seed('tradecraftEntry', {
    id: BigInt(2), userId: 'member-1', resourceId: 'kb', generation: 1, pageId: 2, url: 'https://kb.example.test/b', title: 'B',
    status: 'dropped', dropReason: 'the model read: internal salaries',
  })
  tc().seed('tradecraftEntry', { id: BigInt(3), userId: 'member-1', resourceId: 'pub', generation: 1, pageId: 3, url: 'https://wiki.example.test/a', title: 'Pub A', storedText: 'public text', storedBytes: 11 })
  tc().seed('tradecraftEntry', { id: BigInt(4), userId: 'member-2', resourceId: 'own', generation: 1, pageId: 4, url: 'https://notes.example.test/a', title: 'Notes A' })
  tc().seed('userTradecraftResource', { id: 'own', userId: 'member-2', name: 'Notes', slug: 'notes', url: 'https://notes.example.test/', llmModel: 'gpt-4o', generation: 1 })
  setFlagsForTests({ identity: true, permissions: true })
  setNowForTests(() => new Date('2026-11-16T10:00:00Z'))
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('credential_writes_refused (D-37): a login is never added, changed or removed while acting', () => {
  test('on a passwordless managed account: change, removal, a new login, an add with one; nothing written', async () => {
    await as('admin-1', 'member-1')
    const calls = agent().calls
    await expectRefused(await one.PUT(req('/kb', 'PUT', { credentials: { cookie: 'session=fake-other' } }), PR('kb')), 'change_site_logins')
    await expectRefused(await one.PUT(req('/kb', 'PUT', { credentials: null }), PR('kb')), 'change_site_logins')
    await expectRefused(await one.PUT(req('/pub', 'PUT', { name: 'Wiki 2', credentials: { basic_auth: { username: 'bob', password: 'fake-pw' } } }), PR('pub')), 'change_site_logins')
    await expectRefused(await list.POST(req('', 'POST', { name: 'New KB', url: 'https://new.example.test/', llmModel: 'gpt-4o', credentials: { cookie: 'a=fake' } }), P()), 'change_site_logins')
    expect(resource('kb')).toMatchObject({ credentials: LOGIN, hasLogin: true })
    expect(resource('pub')).toMatchObject({ name: 'Wiki', credentials: {}, hasLogin: false })
    expect(tc().rows('userTradecraftResource', { userId: 'member-1' })).toHaveLength(2)
    expect(loginAudits()).toEqual([])
    expect(calls).toEqual([])
  })

  test('the acting administrator still saves what is not the login, and the login sent back masked', async () => {
    await as('admin-1', 'member-1')
    agent()
    const res = await one.PUT(req('/kb', 'PUT', { name: 'KB (renamed)', credentials: { cookie: 'set', headers: [{ name: 'X-Api-Key', value: 'set' }] } }), PR('kb'))
    expect(res.status).toBe(200)
    expect(resource('kb')).toMatchObject({ name: 'KB (renamed)', credentials: LOGIN })
    expect(refusals()).toEqual([])
  })

  test('the account itself changes its own login, audited with field names only', async () => {
    await as('member-2')
    agent()
    const res = await one.PUT(req('/own', 'PUT', { credentials: { cookie: 'session=fake-own' } }), PR('own', 'member-2'))
    expect(res.status).toBe(200)
    expect(resource('own')).toMatchObject({ hasLogin: true })
    expect(loginAudits()).toEqual([expect.objectContaining({
      actorId: 'member-2', targetType: 'tradecraft_resource', targetId: 'own', after: { hasLogin: true, changed: ['cookie'] },
    })])
    expect(JSON.stringify(accounts().audit())).not.toMatch(/fake-own/)
  })
})

describe('use_refused: nothing sends a login while acting', () => {
  test('Refresh, Save & re-ingest, Check URL (saved and typed) and the preview on a login', async () => {
    await as('admin-1', 'member-1')
    const calls = agent().calls
    await expectRefused(await refreshRoute.POST(req('/kb/refresh', 'POST'), PR('kb')), 'use_site_logins')
    await expectRefused(await one.PUT(req('/kb', 'PUT', { url: 'https://kb2.example.test/' }), PR('kb')), 'use_site_logins')
    await expectRefused(await checkUrl.POST(req('/check-url', 'POST', { resourceId: 'kb' }), P()), 'use_site_logins')
    await expectRefused(await checkUrl.POST(req('/check-url', 'POST', { url: 'https://other.example.test/', credentials: { cookie: 'a=fake-typed' } }), P()), 'use_site_logins')
    await expectRefused(await preview.POST(req('/focus-preview', 'POST', { resourceId: 'kb', focus: FOCUS }), P()), 'use_site_logins')
    expect(refusals()).toHaveLength(5)
    expect(tc().rows('tradecraftIngestionJob')).toEqual([])
    expect(resource('kb').url).toBe('https://kb.example.test/')
    expect(calls).toEqual([])
  })

  test('a public resource is used as usual while acting', async () => {
    await as('admin-1', 'member-1')
    const calls = agent().calls
    expect((await refreshRoute.POST(req('/pub/refresh', 'POST'), PR('pub'))).status).toBe(202)
    expect((await checkUrl.POST(req('/check-url', 'POST', { resourceId: 'pub' }), P())).status).toBe(200)
    expect(refusals()).toEqual([])
    expect(calls.map(c => c.path)).toEqual(['/tradecraft/v2/jobs', '/tradecraft/v2/check-url'])
  })
})

describe('switch_off_masks_only (R-160): with the permissions switch off nothing is refused; the login stays masked', () => {
  test('the acting administrator changes and uses the login; every answer masks it', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    clearCapabilityCachesForTests()
    await as('admin-1', 'member-1')
    agent()
    const put = await one.PUT(req('/kb', 'PUT', { credentials: { cookie: 'session=fake-rotated', headers: [{ name: 'X-Api-Key', value: 'set' }] } }), PR('kb'))
    expect(put.status).toBe(200)
    const refresh = await refreshRoute.POST(req('/kb/refresh', 'POST'), PR('kb'))
    expect(refresh.status).toBe(202)
    const listed = await list.GET(req(''), P())
    const answers = JSON.stringify([await put.json(), await refresh.json(), await listed.json()])
    expect(answers).not.toMatch(/fake-/)
    expect(answers).toContain('"cookie":"set"')
    expect(refusals()).toEqual([])
    expect(resource('kb').credentials).toMatchObject({ cookie: 'session=fake-rotated' })
  })
})

describe('page text and the map are the account\'s own (R-161, R-067, §6.6; review A, B, D)', () => {
  const mapGet = (resourceId: string, account = 'member-1', qs = '') =>
    mapRoute.GET(new NextRequest(`http://redamon.test/api/users/${account}/tradecraft-resources/${resourceId}/map${qs}`, { headers: { host: 'redamon.test' } }),
      { params: Promise.resolve({ id: account, resourceId }) })
  const pageCall = (method: 'GET' | 'POST', resourceId: string, pageId: string, account = 'member-1') =>
    pages[method](new NextRequest(`http://redamon.test/api/users/${account}/tradecraft-resources/${resourceId}/pages/${encodeURIComponent(pageId)}`, {
      method, headers: { host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json' }, ...(method === 'POST' ? { body: '{}' } : {}),
    }), { params: Promise.resolve({ id: account, resourceId, pageId }) })

  test('an administrator who does not act as the account reads neither its page text nor its map, login or not', async () => {
    await as('admin-1')
    const calls = agent().calls
    for (const res of [await pageCall('GET', 'kb', 'kb:1'), await pageCall('GET', 'pub', 'wiki:3'), await mapGet('kb'), await mapGet('pub'), await pageCall('POST', 'pub', 'wiki:3')]) {
      expect(res.status).toBe(403)
      expect(JSON.stringify(await res.json())).not.toMatch(/private|Private|salaries|public text/)
    }
    expect(calls).toEqual([])
    // The directory read of the resource list is unchanged: names and masked secrets only.
    expect((await list.GET(req(''), P())).status).toBe(200)
  })

  test('the account itself reads its pages and its map', async () => {
    await as('member-2')
    agent()
    expect((await pageCall('GET', 'own', 'notes:4', 'member-2')).status).toBe(200)
    expect((await mapGet('own', 'member-2')).status).toBe(200)
  })

  test('acting as an account that signs in for itself: a public resource\'s pages, map and Read now as usual (review D)', async () => {
    await as('admin-1', 'member-2')
    const calls = agent().calls
    expect((await mapGet('own', 'member-2')).status).toBe(200)
    expect((await pageCall('GET', 'own', 'notes:4', 'member-2')).status).toBe(200)
    const read = await pageCall('POST', 'own', 'notes:4', 'member-2')
    expect(read.status).toBe(200)
    expect(await read.json()).toMatchObject({ result: { text: 'live text' } })
    expect(calls.map(c => c.path)).toEqual(['/tradecraft/v2/read-now'])
    expect(refusals()).toEqual([])
  })

  test('acting as the account, a login resource\'s page text and Read now are refused as use_site_logins', async () => {
    await as('admin-1', 'member-1')
    const calls = agent().calls
    await expectRefused(await pageCall('GET', 'kb', 'kb:1'), 'use_site_logins')
    await expectRefused(await pageCall('POST', 'kb', 'kb:1'), 'use_site_logins')
    expect(calls).toEqual([])
  })

  test('acting as the account, a login resource\'s map answers titles and URLs only, every other field empty (review B)', async () => {
    await as('admin-1', 'member-1')
    agent()
    for (const status of ['kept', 'dropped']) {
      const res = await mapGet('kb', 'member-1', `?status=${status}`)
      expect(res.status).toBe(200)
      const body = await res.json() as { entries: Record<string, unknown>[] }
      expect(body.entries).toHaveLength(1)
      for (const e of body.entries) {
        expect(e).toEqual({
          id: expect.any(String), pageId: expect.stringMatching(/^kb:/), title: expect.any(String), url: expect.stringMatching(/^https:\/\/kb\./),
          status, pinned: false, renamed: false,
          topics: [], kinds: [], technologies: [], description: '', source: '', reason: '', stored: false,
        })
      }
      expect(JSON.stringify(body)).not.toMatch(/Private|salaries|sql_injection|postgresql|crawl/)
    }
    // A tag cannot be used to learn the page's tags either: the filter is not applied.
    expect((await (await mapGet('kb', 'member-1', '?tag=sql_injection')).json()).total).toBe(1)
    expect((await (await mapGet('kb', 'member-1', '?tag=nothing')).json()).total).toBe(1)
    // A public resource of the same account shows its tags and descriptions as usual.
    const pub = await (await mapGet('pub')).json() as { entries: Record<string, unknown>[] }
    expect(pub.entries[0]).toMatchObject({ title: 'Pub A', stored: true })
  })
})
